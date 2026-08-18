//! The standing attach task: discover, dial out, prove, answer.
//!
//! One connection per membership domain, each with its own retry clock. The
//! tunnel is long-lived but expendable — on any failure the task starts over
//! from discovery, because the endpoint may have moved and the nonce certainly
//! has.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt};
use synch_core::{EntryKind, Hash, OriginId};
use synch_store::{VersionPolicy, VersionSet};
use tokio::sync::{mpsc, Semaphore};
use tokio_tungstenite::tungstenite::Message;

use crate::{
    cloud::frame::{
        attach_signing_input, encode_chunk, Down, EntryJson, Up, VersionJson, MAX_CHUNK, NONCE_LEN,
        PROTOCOL_VERSION,
    },
    error::{EngineError, Result},
    node::Node,
};

/// The path the attach connection is made against, appended to the URL the
/// zone published. Fixed by the protocol version, so the record names an
/// origin and never a path a compromised zone could point at something else.
const ATTACH_PATH: &str = "/agent/v1/attach";

/// The environment override that replaces discovery.
///
/// A test hook in the mould of `CP_REKOR_URL`, not a configuration knob:
/// production learns its endpoint from the zone it already validates, and
/// there is deliberately no `--url` for an operator to be talked into.
const URL_ENV: &str = "SYNCH_CLOUD_URL";

/// How often the supervisor re-reads the settings and the domain list.
const SUPERVISE_INTERVAL: Duration = Duration::from_secs(5);

/// The first reconnect delay, doubled per failure up to [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_secs(2);

/// The longest a disconnected node waits before trying again.
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// How often each side sends a heartbeat.
const HEARTBEAT: Duration = Duration::from_secs(30);

/// How many heartbeats may go unanswered before the session is dead.
const HEARTBEAT_MISSES: u32 = 2;

/// How many frames may wait for the socket writer.
///
/// Small on purpose: content is credit-governed and everything else is one
/// frame, so a deep queue would only hide a stalled socket.
const WRITE_AHEAD: usize = 8;

/// How many entries one listing page carries.
const PAGE_LIMIT: usize = 500;

/// How many flat rows one listing pass pulls from the store at a time.
const SCAN_BATCH: usize = 500;

impl Node {
    /// Runs cloud attach until the daemon stops.
    ///
    /// The loop supervises rather than connects: one child task per configured
    /// membership domain, started when the operator enables the feature and
    /// stopped when they disable it or remove the domain. With the feature off
    /// it costs one settings read per interval and opens nothing at all.
    pub async fn run_cloud(
        &self,
        resolver: Option<Arc<synch_net::DnssecResolver>>,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        let shutdown = std::pin::pin!(shutdown);
        let mut shutdown = shutdown;
        let mut running: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            let wanted = self.attach_targets();
            running.retain(|domain, task| {
                let keep = wanted.iter().any(|d| d == domain) && !task.is_finished();
                if !keep {
                    task.abort();
                    self.forget_cloud_status(domain);
                }
                keep
            });
            for domain in wanted {
                if running.contains_key(&domain) {
                    continue;
                }
                let node = self.clone();
                let resolver = resolver.clone();
                let name = domain.clone();
                running.insert(
                    domain,
                    tokio::spawn(async move { attach_forever(node, resolver, name).await }),
                );
            }
            tokio::select! {
                _ = &mut shutdown => break,
                _ = tokio::time::sleep(SUPERVISE_INTERVAL) => {}
            }
        }
        for (_, task) in running {
            task.abort();
        }
    }

    /// The membership domains a tunnel should be open for right now.
    ///
    /// Empty whenever the feature is off, and empty for a node with no
    /// membership domains: there is no apex to take a control plane from, so
    /// there is nothing to discover and nothing to attach to.
    fn attach_targets(&self) -> Vec<String> {
        match self.cloud_settings() {
            Ok(settings) if settings.enabled => self.domains().unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

/// Keeps one domain's tunnel up, with exponential backoff and jitter.
async fn attach_forever(
    node: Node,
    resolver: Option<Arc<synch_net::DnssecResolver>>,
    domain: String,
) {
    let mut backoff = MIN_BACKOFF;
    loop {
        let started = Instant::now();
        match attach_once(&node, resolver.as_deref(), &domain).await {
            Ok(()) => tracing::info!(domain, "cloud attach closed cleanly"),
            Err(e) => {
                tracing::debug!(domain, error = %e, "cloud attach failed");
                let endpoint = node
                    .cloud_slot()
                    .get(&domain)
                    .and_then(|status| status.endpoint.clone());
                node.set_cloud_status(&domain, endpoint, false, Some(e.to_string()));
            }
        }
        // A session that stood for a while was healthy; only repeated fast
        // failures are worth backing off from.
        if started.elapsed() > MAX_BACKOFF {
            backoff = MIN_BACKOFF;
        }
        tokio::time::sleep(jittered(backoff)).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Spreads reconnects so a control plane restart is not answered by every
/// node in the fleet at the same instant.
fn jittered(base: Duration) -> Duration {
    let span = base.as_millis() as u64 / 2;
    if span == 0 {
        return base;
    }
    let noise = (synch_core::now_ns() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) % span;
    base + Duration::from_millis(noise)
}

/// Discovers, connects, proves, and serves one session to its end.
async fn attach_once(
    node: &Node,
    resolver: Option<&synch_net::DnssecResolver>,
    domain: &str,
) -> Result<()> {
    let base = discover(node, resolver, domain).await?;
    let url = format!("{base}{ATTACH_PATH}");
    node.set_cloud_status(domain, Some(base.clone()), false, None);

    let (socket, _) = tokio_tungstenite::connect_async(websocket_url(&url))
        .await
        .map_err(|e| EngineError::invalid(format!("{url}: {e}")))?;
    let (mut sink, mut stream) = socket.split();

    let settings = node.cloud_settings()?;
    send(
        &mut sink,
        &Up::Hello {
            v: PROTOCOL_VERSION,
            network: domain.to_string(),
            origin: node.origin().canonical(),
            device: node.node_id().to_z32(),
            spaces: settings.spaces.clone(),
        },
    )
    .await?;

    let nonce = match receive(&mut stream).await? {
        Down::Challenge { nonce } => decode_nonce(&nonce)?,
        Down::Err { code, message, .. } => {
            return Err(EngineError::invalid(format!("{code}: {message}")))
        }
        other => {
            return Err(EngineError::invalid(format!(
                "expected a challenge, got {other:?}"
            )))
        }
    };
    // Signed here, in the process that holds the key: no RPC exists that would
    // hand this capability to another program on the node.
    let signature = node.sign_attach(&url, &nonce);
    send(
        &mut sink,
        &Up::Proof {
            sig: hex::encode(signature.to_bytes()),
            key: node.node_id().to_z32(),
        },
    )
    .await?;

    match receive(&mut stream).await? {
        Down::Attached { session, v } if v == PROTOCOL_VERSION => {
            tracing::info!(domain, session, url, "cloud attach established");
        }
        Down::Attached { v, .. } => {
            return Err(EngineError::invalid(format!(
                "tunnel protocol mismatch: this daemon speaks v{PROTOCOL_VERSION}, \
                 the control plane settled on v{v}"
            )))
        }
        Down::Err { code, message, .. } => {
            return Err(EngineError::invalid(format!("{code}: {message}")))
        }
        other => {
            return Err(EngineError::invalid(format!(
                "expected an attach, got {other:?}"
            )))
        }
    }
    node.set_cloud_status(domain, Some(base), true, None);

    let outcome = serve(node, sink, stream).await;
    let endpoint = node
        .cloud_slot()
        .get(domain)
        .and_then(|status| status.endpoint.clone());
    node.set_cloud_status(
        domain,
        endpoint,
        false,
        outcome.as_ref().err().map(|e| e.to_string()),
    );
    outcome
}

impl Node {
    /// Signs an attach challenge with the active device key.
    ///
    /// The context is domain-separated from every other signature this key
    /// makes: an attach proof is not a head signature and cannot be made to
    /// verify as one.
    pub(crate) fn sign_attach(&self, url: &str, nonce: &[u8]) -> iroh_base::Signature {
        self.secret().sign(&attach_signing_input(url, nonce))
    }
}

/// The endpoint this domain's base attaches to.
///
/// From the zone or from nowhere: no validated record means no connection
/// attempt at all, which is the shape a resolver outage has to degrade to.
async fn discover(
    node: &Node,
    resolver: Option<&synch_net::DnssecResolver>,
    domain: &str,
) -> Result<String> {
    if let Ok(url) = std::env::var(URL_ENV) {
        let url = url.trim_end_matches('/').to_string();
        if url.is_empty() {
            return Err(EngineError::invalid(format!("{URL_ENV} is empty")));
        }
        return Ok(url);
    }
    let resolver = resolver.ok_or_else(|| {
        EngineError::invalid(
            "this daemon runs no DNSSEC resolver, so it cannot discover a control plane",
        )
    })?;
    let (record, ttl) = resolver
        .control_plane(domain)
        .await
        .map_err(|e| EngineError::invalid(format!("{domain}: {e}")))?;
    tracing::debug!(
        domain,
        url = record.url,
        ttl = ttl.as_secs(),
        "discovered a control plane"
    );
    node.set_cloud_status(domain, Some(record.url.clone()), false, None);
    Ok(record.url)
}

/// The WebSocket scheme for an HTTP origin.
fn websocket_url(url: &str) -> String {
    match url.split_once("://") {
        Some(("https", rest)) => format!("wss://{rest}"),
        Some(("http", rest)) => format!("ws://{rest}"),
        _ => url.to_string(),
    }
}

fn decode_nonce(text: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(text)
        .map_err(|e| EngineError::invalid(format!("the challenge nonce is not hex: {e}")))?;
    if bytes.len() != NONCE_LEN {
        return Err(EngineError::invalid(format!(
            "the challenge nonce is {} bytes, not {NONCE_LEN}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// One end of the socket, as the tasks that write to it see it.
type Writer = mpsc::Sender<Message>;

/// A stream in flight: its credit, and the task producing for it.
#[derive(Debug)]
struct Stream {
    credit: Arc<Semaphore>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        // Closing the semaphore is what a cancelled read notices: the producer
        // is blocked on a permit far more often than it is between chunks.
        self.credit.close();
        self.task.abort();
    }
}

/// Answers frames until the connection ends.
async fn serve<S, R>(node: &Node, mut sink: S, mut stream: R) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin + Send,
    R: futures_util::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    let (writes, mut outgoing) = mpsc::channel::<Message>(WRITE_AHEAD);
    let mut streams: HashMap<u32, Stream> = HashMap::new();
    let mut beat = tokio::time::interval(HEARTBEAT);
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut unanswered = 0u32;

    loop {
        tokio::select! {
            // Writing first: a full write channel is backpressure on every
            // producer, and it must drain before anything else is accepted.
            biased;
            message = outgoing.recv() => {
                let Some(message) = message else { return Ok(()) };
                sink.send(message)
                    .await
                    .map_err(|e| EngineError::invalid(format!("the tunnel write failed: {e}")))?;
            }
            _ = beat.tick() => {
                if unanswered >= HEARTBEAT_MISSES {
                    return Err(EngineError::invalid(format!(
                        "the control plane missed {unanswered} heartbeats; the session is dead"
                    )));
                }
                unanswered += 1;
                if writes.send(text(&Up::Ping)?).await.is_err() {
                    return Ok(());
                }
            }
            incoming = stream.next() => {
                let Some(incoming) = incoming else { return Ok(()) };
                let incoming = incoming
                    .map_err(|e| EngineError::invalid(format!("the tunnel read failed: {e}")))?;
                match incoming {
                    Message::Text(body) => {
                        unanswered = 0;
                        let frame: Down = serde_json::from_str(&body).map_err(|e| {
                            EngineError::invalid(format!("malformed tunnel frame: {e}"))
                        })?;
                        handle(node, &writes, &mut streams, frame).await?;
                    }
                    // Content only ever travels upward, so a binary frame from
                    // the control plane is a protocol violation rather than a
                    // request to interpret.
                    Message::Binary(_) => {
                        return Err(EngineError::invalid(
                            "the control plane sent a content frame; nothing travels down this \
                             tunnel but control frames",
                        ))
                    }
                    Message::Close(_) => return Ok(()),
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => unanswered = 0,
                }
            }
        }
    }
}

/// Serves one control frame.
async fn handle(
    node: &Node,
    writes: &Writer,
    streams: &mut HashMap<u32, Stream>,
    frame: Down,
) -> Result<()> {
    match frame {
        Down::Ping => {
            let _ = writes.send(text(&Up::Pong)?).await;
        }
        Down::Pong => {}
        Down::Err { id, code, message } => {
            tracing::debug!(?id, code, message, "the control plane refused a request");
            if let Some(id) = id {
                streams.remove(&id);
            }
        }
        Down::Credit { id, n } => {
            if let Some(stream) = streams.get(&id) {
                stream.credit.add_permits(n as usize);
            }
        }
        Down::Cancel { id } => {
            streams.remove(&id);
        }
        Down::Ls {
            id,
            space,
            path,
            cursor,
            all,
        } => {
            let node = node.clone();
            let writes = writes.clone();
            tokio::spawn(async move {
                let page = list_page(&node, &space, &path, cursor, all)
                    .await
                    .map(|frame| with_id(frame, id));
                answer(&writes, id, page).await;
            });
        }
        Down::Stat { id, space, path } => {
            let node = node.clone();
            let writes = writes.clone();
            tokio::spawn(async move {
                answer(&writes, id, stat(&node, id, &space, &path).await).await;
            });
        }
        Down::Resolve {
            id,
            space,
            path,
            from,
        } => {
            let node = node.clone();
            let writes = writes.clone();
            tokio::spawn(async move {
                answer(&writes, id, resolve(&node, id, &space, &path, from).await).await;
            });
        }
        Down::Read {
            id,
            root,
            size,
            start,
            len,
            credit,
        } => {
            // A second stream on a live id is a protocol error, not a
            // replacement: the old one's chunks would be read as the new
            // one's. Refusing keeps the id space the control plane's problem.
            if streams.contains_key(&id) {
                let _ = writes
                    .send(text(&Up::Err {
                        id: Some(id),
                        code: "invalid".into(),
                        message: format!("request {id} is already streaming"),
                    })?)
                    .await;
                return Ok(());
            }
            let permits = Arc::new(Semaphore::new(credit as usize));
            let task = {
                let node = node.clone();
                let writes = writes.clone();
                let permits = permits.clone();
                tokio::spawn(async move {
                    if let Err(e) = read(&node, &writes, id, &root, size, start, len, permits).await
                    {
                        let _ = writes
                            .send(Message::text(
                                serde_json::to_string(&Up::Err {
                                    id: Some(id),
                                    code: code_of(&e).to_string(),
                                    message: e.to_string(),
                                })
                                .unwrap_or_default(),
                            ))
                            .await;
                    }
                })
            };
            streams.insert(
                id,
                Stream {
                    credit: permits,
                    task,
                },
            );
        }
        // Handshake frames after the handshake are noise, not instructions.
        Down::Challenge { .. } | Down::Attached { .. } => {}
    }
    Ok(())
}

/// Sends one request's answer, or the coded refusal it failed with.
async fn answer(writes: &Writer, id: u32, outcome: Result<Up>) {
    let frame = match outcome {
        Ok(frame) => frame,
        Err(e) => Up::Err {
            id: Some(id),
            code: code_of(&e).to_string(),
            message: e.to_string(),
        },
    };
    if let Ok(message) = text(&frame) {
        let _ = writes.send(message).await;
    }
}

/// The stable code an engine failure travels as.
///
/// The same vocabulary the local control socket puts in `x-synch-error-code`,
/// so a refusal reads the same whether it reached the caller over the socket
/// or over the tunnel.
fn code_of(e: &EngineError) -> &'static str {
    match e {
        EngineError::NotFound(_) => "not-found",
        EngineError::Divergent { .. } => "divergent",
        EngineError::InRecovery { .. } => "unavailable",
        EngineError::Invalid(_) | EngineError::Key(_) => "invalid",
        EngineError::NotInitialized => "not-initialized",
        _ => "internal",
    }
}

fn text(frame: &Up) -> Result<Message> {
    serde_json::to_string(frame)
        .map(Message::text)
        .map_err(|e| EngineError::invalid(format!("could not encode a tunnel frame: {e}")))
}

async fn send<S>(sink: &mut S, frame: &Up) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    sink.send(text(frame)?)
        .await
        .map_err(|e| EngineError::invalid(format!("the tunnel write failed: {e}")))
}

async fn receive<R>(stream: &mut R) -> Result<Down>
where
    R: futures_util::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    loop {
        let message = stream
            .next()
            .await
            .ok_or_else(|| EngineError::invalid("the control plane closed the connection"))?
            .map_err(|e| EngineError::invalid(format!("the tunnel read failed: {e}")))?;
        match message {
            Message::Text(body) => {
                return serde_json::from_str(&body)
                    .map_err(|e| EngineError::invalid(format!("malformed tunnel frame: {e}")))
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            Message::Binary(_) | Message::Close(_) => {
                return Err(EngineError::invalid(
                    "the control plane ended the handshake early",
                ))
            }
        }
    }
}

/// Refuses a space the operator did not name, on every frame that names one.
///
/// Re-read from the settings each time rather than captured at attach: that is
/// what makes `synch cloud disable` and a narrowed allowlist take effect on
/// the next request instead of the next reconnect.
fn permitted(node: &Node, space: &str) -> Result<()> {
    if node.cloud_settings()?.exposes(space) {
        return Ok(());
    }
    Err(EngineError::not_found(format!(
        "{space} is not exposed to the control plane"
    )))
}

/// One page of a directory of the unified tree.
async fn list_page(
    node: &Node,
    space: &str,
    path: &str,
    cursor: Option<String>,
    all: bool,
) -> Result<Up> {
    permitted(node, space)?;
    let node = node.clone();
    let space = space.to_string();
    let prefix = directory_prefix(path);
    crate::blocking::offload(move || collapse(&node, &space, &prefix, cursor, all)).await
}

/// The listing prefix for a directory, which always ends at a boundary.
fn directory_prefix(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

/// Folds a flat listing into one directory's entries.
///
/// The unified tree is a flat set of paths, so a directory view is a fold over
/// it: paths with a separator left collapse into one entry for the
/// subdirectory. Because the flat listing is path-ordered, a subdirectory's
/// rows are contiguous — so once its entry is emitted the cursor can be
/// advanced *past the whole subtree* rather than through it, and no
/// subdirectory is ever emitted on two pages.
fn collapse(
    node: &Node,
    space: &str,
    prefix: &str,
    cursor: Option<String>,
    all: bool,
) -> Result<Up> {
    let mut entries: Vec<EntryJson> = Vec::new();
    let mut start_after = cursor;
    // The subtree whose rows this pass has already accounted for with one
    // directory entry, and is walking past.
    let mut inside: Option<String> = None;
    // Whether the listing stopped at the page limit rather than at its end.
    let mut more = false;
    'pages: loop {
        let batch =
            node.unified_listing(space, prefix, start_after.as_deref(), Some(SCAN_BATCH))?;
        let exhausted = batch.len() < SCAN_BATCH;
        for set in &batch {
            if inside
                .as_ref()
                .is_some_and(|subtree| set.path.starts_with(subtree))
            {
                continue;
            }
            inside = None;
            start_after = Some(set.path.clone());
            if !set.exists() {
                // Every publisher has tombstoned it: the path has left the
                // tree, so the tree does not list it.
                continue;
            }
            let Some(rest) = set.path.strip_prefix(prefix) else {
                continue;
            };
            match rest.split_once('/') {
                Some((child, _)) => {
                    let full = format!("{prefix}{child}");
                    entries.push(EntryJson {
                        name: child.to_string(),
                        path: full.clone(),
                        kind: "dir".into(),
                        size: 0,
                        mtime_ns: 0,
                        versions: 0,
                        origin: String::new(),
                        root: None,
                        all: Vec::new(),
                    });
                    // The successor of `<full>/`: every path in the subtree
                    // sorts below it, and the next sibling sorts above. The
                    // rows already in hand are walked past rather than
                    // re-queried, and the cursor skips the rest of them — so a
                    // subdirectory is never emitted on two pages.
                    inside = Some(format!("{full}/"));
                    start_after = Some(format!("{full}0"));
                }
                None => {
                    // A path the policy refuses is left out rather than shown
                    // with one side's metadata, exactly as `List` does; a
                    // direct stat of it still says what is wrong.
                    let Ok(row) = node.resolve_set(set, &VersionPolicy::Newest) else {
                        continue;
                    };
                    entries.push(EntryJson {
                        name: rest.to_string(),
                        path: set.path.clone(),
                        kind: kind_name(row.kind).into(),
                        size: row.size,
                        mtime_ns: row.mtime_ns,
                        versions: set.version_count() as u32,
                        origin: row.origin.canonical(),
                        root: row.content.map(|root| root.to_hex().to_string()),
                        all: if all { versions_json(set) } else { Vec::new() },
                    });
                }
            }
            if entries.len() >= PAGE_LIMIT {
                more = true;
                break 'pages;
            }
        }
        if exhausted {
            break;
        }
    }
    Ok(Up::Page {
        // The id is filled in by the caller; this shape exists so the fold can
        // run on the blocking pool without carrying it.
        id: 0,
        entries,
        // Where the next page resumes: the seek key the last entry left
        // behind, which is past a subdirectory's whole subtree when the page
        // ended on one.
        cursor: more.then(|| start_after.clone()).flatten(),
    })
}

fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Dir => "dir",
        EntryKind::Symlink => "symlink",
        EntryKind::Tombstone => "tombstone",
    }
}

fn versions_json(set: &VersionSet) -> Vec<VersionJson> {
    set.versions
        .iter()
        .map(|version| VersionJson {
            root: version.content.map(|root| root.to_hex().to_string()),
            kind: kind_name(version.kind).into(),
            symlink_target: version.symlink_target.clone(),
            size: version.size,
            mtime_ns: version.mtime_ns,
            seq: version.seq,
            attestors: version
                .attestors
                .iter()
                .map(|origin| origin.canonical())
                .collect(),
        })
        .collect()
}

/// Every version of one path, with its attestors — `synch status` as frames.
async fn stat(node: &Node, id: u32, space: &str, path: &str) -> Result<Up> {
    permitted(node, space)?;
    let set = node.versions(space, path)?;
    Ok(Up::Versions {
        id,
        versions: versions_json(&set),
    })
}

/// Pins a path to one content root and names who holds it.
async fn resolve(
    node: &Node,
    id: u32,
    space: &str,
    path: &str,
    from: Option<String>,
) -> Result<Up> {
    permitted(node, space)?;
    let policy = match &from {
        Some(origin) => VersionPolicy::Origin(
            origin
                .parse::<OriginId>()
                .map_err(|e| EngineError::invalid(e.to_string()))?,
        ),
        None => VersionPolicy::Newest,
    };
    let row = node.resolve(space, path, &policy)?;
    if row.kind == EntryKind::Tombstone {
        return Err(EngineError::not_found(format!(
            "{space}/{path} was deleted at seq {}",
            row.seq
        )));
    }
    let root = row
        .content
        .ok_or_else(|| EngineError::invalid(format!("{space}/{path} selects no content")))?;
    // Straight out of the replicated `b:` records: a routing hint the control
    // plane may act on or ignore, never a correctness input.
    let mut holders: Vec<String> = node
        .providers_for(&root, 0, row.size.max(1))?
        .into_iter()
        .map(|provider| provider.origin.canonical())
        .collect();
    if node.store().blob(&root)?.is_some_and(|blob| blob.complete) {
        holders.push(node.origin().canonical());
    }
    Ok(Up::Resolved {
        id,
        origin: row.origin.canonical(),
        root: root.to_hex().to_string(),
        size: row.size,
        seq: row.seq,
        holders,
    })
}

/// Streams a byte range of a pinned content root under credit flow control.
///
/// Addressed by root rather than by path, so a publish landing between the
/// resolve and the read cannot swap the bytes mid-download: the reader gets
/// exactly the version the resolve named, or a clean error if it has gone.
#[allow(clippy::too_many_arguments)]
async fn read(
    node: &Node,
    writes: &Writer,
    id: u32,
    root: &str,
    size: u64,
    start: u64,
    len: Option<u64>,
    credit: Arc<Semaphore>,
) -> Result<()> {
    let root: Hash = root
        .parse()
        .map_err(|_| EngineError::invalid(format!("{root} is not an object root")))?;
    // The allowlist is enforced on the *root*, not on a space the frame
    // claims: a root reachable only through a space the operator did not
    // expose is not readable however the request is spelled.
    let exposed = {
        let settings = node.cloud_settings()?;
        node.store()
            .paths_naming(&root)?
            .iter()
            .filter_map(|reference| reference.split_once('/'))
            .any(|(space, _)| settings.exposes(space))
    };
    if !exposed {
        return Err(EngineError::not_found(format!(
            "no exposed space names {root}"
        )));
    }
    if start > size {
        return Err(EngineError::invalid(format!(
            "offset {start} is past the end of a {size}-byte object"
        )));
    }
    let end = match len {
        Some(len) => start.saturating_add(len).min(size),
        None => size,
    };
    // Whatever of the window this node does not hold is fetched from peers
    // first, bao-verified per range, so every byte below is verified content.
    let report = node.fetch_range(&root, size, start, end).await?;
    if !report.complete {
        return Err(EngineError::not_found(format!(
            "no provider could serve bytes {start}..{end} of {root}"
        )));
    }
    let _ = writes
        .send(text(&Up::Meta {
            id,
            size: end - start,
            root: root.to_hex().to_string(),
        })?)
        .await;

    let mut offset = start;
    let mut seq = 0u32;
    while offset < end {
        // Read-ahead happens only while credit is available: a browser that
        // stops reading stalls the read here, at the source, rather than
        // filling a buffer at any hop between.
        let permit = credit
            .acquire()
            .await
            .map_err(|_| EngineError::invalid("the stream was cancelled"))?;
        permit.forget();
        let take = (MAX_CHUNK as u64).min(end - offset);
        let store = node.store().clone();
        let bytes =
            crate::blocking::offload(move || Ok(store.read_range(&root, offset, take)?)).await?;
        if bytes.is_empty() {
            break;
        }
        offset += bytes.len() as u64;
        if writes
            .send(Message::binary(encode_chunk(id, seq, &bytes)))
            .await
            .is_err()
        {
            return Ok(());
        }
        seq = seq.wrapping_add(1);
    }
    let _ = writes.send(text(&Up::Done { id })?).await;
    Ok(())
}

/// Fills in a page's request id, which the blocking fold does not carry.
fn with_id(frame: Up, id: u32) -> Up {
    match frame {
        Up::Page {
            entries, cursor, ..
        } => Up::Page {
            id,
            entries,
            cursor,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cloud::frame::decode_chunk, config::NodeConfig};
    use synch_core::{FileEntry, Hash};

    async fn node() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        (dir, node)
    }

    fn origin(name: &str) -> OriginId {
        OriginId::named(name, "x.example").unwrap()
    }

    /// No validated record, no connection: a resolver outage degrades the
    /// feature to off, never to "attach somewhere else".
    #[tokio::test]
    async fn discovery_without_a_resolver_attempts_nothing() {
        let (_d, node) = node().await;
        let e = discover(&node, None, "cluster.example").await.unwrap_err();
        assert!(e.to_string().contains("no DNSSEC resolver"), "{e}");
        node.shutdown().await.unwrap();
    }

    /// The task list is empty until the operator says otherwise, and empty
    /// again the moment they take it back.
    #[tokio::test]
    async fn attach_targets_follow_the_operator() {
        let (dir, node) = node().await;
        assert!(node.attach_targets().is_empty());
        node.add_space("media", dir.path().join("media")).unwrap();
        node.enable_cloud(&["media".to_string()]).unwrap();
        // Enabled, but with no membership domain there is no apex to take a
        // control plane from, so there is still nothing to attach to.
        assert!(node.attach_targets().is_empty());
        node.add_domain("cluster.example").unwrap();
        assert_eq!(node.attach_targets(), ["cluster.example"]);
        node.disable_cloud().unwrap();
        assert!(node.attach_targets().is_empty());
        node.shutdown().await.unwrap();
    }

    /// Every frame that names a space is checked against the allowlist, and
    /// the check reads the operator's current answer rather than the one that
    /// was true when the tunnel opened.
    #[tokio::test]
    async fn every_frame_rechecks_the_allowlist() {
        let (dir, node) = node().await;
        node.add_space("media", dir.path().join("media")).unwrap();
        node.add_space("private", dir.path().join("private"))
            .unwrap();
        node.enable_cloud(&["media".to_string()]).unwrap();

        assert!(permitted(&node, "media").is_ok());
        assert!(permitted(&node, "private").is_err());
        assert!(list_page(&node, "private", "", None, false).await.is_err());
        assert!(stat(&node, 1, "private", "a").await.is_err());
        assert!(resolve(&node, 1, "private", "a", None).await.is_err());

        // Disabling closes the tunnel's view before the tunnel itself closes.
        node.disable_cloud().unwrap();
        assert!(permitted(&node, "media").is_err());
        node.shutdown().await.unwrap();
    }

    /// A read is addressed by root, so the allowlist is enforced on the root:
    /// a blob only an unexposed space names is not readable however the
    /// request spells itself.
    #[tokio::test]
    async fn a_read_of_an_unexposed_root_is_refused() {
        let (dir, node) = node().await;
        node.add_space("media", dir.path().join("media")).unwrap();
        node.add_space("private", dir.path().join("private"))
            .unwrap();
        node.enable_cloud(&["media".to_string()]).unwrap();
        let secret = Hash::new(b"secret");
        node.store()
            .put_entry(
                &origin("nas"),
                "private",
                "f",
                &FileEntry::file(1, 6, secret, 1),
            )
            .unwrap();

        let (writes, _rx) = mpsc::channel(4);
        let e = read(
            &node,
            &writes,
            1,
            &secret.to_hex().to_string(),
            6,
            0,
            None,
            Arc::new(Semaphore::new(4)),
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("no exposed space"), "{e}");
        node.shutdown().await.unwrap();
    }

    /// Credit is the whole of the read-ahead bound: with none granted, no
    /// chunk is produced, however much of the object is already local.
    #[tokio::test]
    async fn a_read_produces_nothing_without_credit() {
        let (dir, node) = node().await;
        node.add_space("media", dir.path().join("media")).unwrap();
        node.enable_cloud(&["media".to_string()]).unwrap();
        let payload = vec![7u8; MAX_CHUNK * 3];
        let root = node
            .store()
            .ingest_bytes(&payload, synch_core::now_ns())
            .unwrap();
        node.store()
            .put_entry(
                &origin("nas"),
                "media",
                "f",
                &FileEntry::file(payload.len() as u64, 1, root, 1),
            )
            .unwrap();

        let (writes, mut rx) = mpsc::channel(16);
        let credit = Arc::new(Semaphore::new(0));
        let reading = {
            let node = node.clone();
            let writes = writes.clone();
            let credit = credit.clone();
            tokio::spawn(async move {
                read(
                    &node,
                    &writes,
                    3,
                    &root.to_hex().to_string(),
                    payload.len() as u64,
                    0,
                    None,
                    credit,
                )
                .await
            })
        };
        // The header, and then nothing: the producer is parked on a permit.
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, Message::Text(_)), "{first:?}");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "a chunk was produced with no credit granted"
        );

        // One credit, one chunk, and then parked again.
        credit.add_permits(1);
        let chunk = tokio::time::timeout(Duration::from_millis(2000), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let Message::Binary(bytes) = chunk else {
            panic!("expected a content frame, got {chunk:?}")
        };
        let (id, seq, data) = decode_chunk(&bytes).unwrap();
        assert_eq!((id, seq, data.len()), (3, 0, MAX_CHUNK));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "the second chunk was produced on the first chunk's credit"
        );

        // And a cancelled stream ends the producer rather than leaking it.
        credit.close();
        assert!(reading.await.unwrap().is_err());
        node.shutdown().await.unwrap();
    }

    /// A directory view is a fold over the flat tree, and a subdirectory is
    /// one row however many paths sit under it.
    #[tokio::test]
    async fn a_listing_collapses_subdirectories() {
        let (dir, node) = node().await;
        node.add_space("media", dir.path().join("media")).unwrap();
        node.enable_cloud(&["media".to_string()]).unwrap();
        for path in [
            "a.txt",
            "photos/1.jpg",
            "photos/2.jpg",
            "photos/trips/x.jpg",
        ] {
            node.store()
                .put_entry(
                    &origin("nas"),
                    "media",
                    path,
                    &FileEntry::file(1, 4, Hash::new(path.as_bytes()), 1),
                )
                .unwrap();
        }
        let Up::Page {
            entries, cursor, ..
        } = list_page(&node, "media", "", None, false).await.unwrap()
        else {
            panic!("expected a page")
        };
        assert_eq!(cursor, None);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a.txt", "photos"]);
        assert_eq!(entries[1].kind, "dir");

        // And one level down, the nested directory collapses in turn.
        let Up::Page { entries, .. } = list_page(&node, "media", "photos", None, false)
            .await
            .unwrap()
        else {
            panic!("expected a page")
        };
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["1.jpg", "2.jpg", "trips"]);
        node.shutdown().await.unwrap();
    }

    /// Divergence is data the listing carries, not something it resolves.
    #[tokio::test]
    async fn a_listing_reports_every_version_of_a_divergent_path() {
        let (dir, node) = node().await;
        node.add_space("media", dir.path().join("media")).unwrap();
        node.enable_cloud(&["media".to_string()]).unwrap();
        for (name, content) in [("nas", b"a"), ("laptop", b"b")] {
            node.store()
                .put_entry(
                    &origin(name),
                    "media",
                    "split",
                    &FileEntry::file(1, 1, Hash::new(content), 1),
                )
                .unwrap();
        }
        let Up::Page { entries, .. } = list_page(&node, "media", "", None, true).await.unwrap()
        else {
            panic!("expected a page")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].versions, 2);
        assert_eq!(entries[0].all.len(), 2);

        let Up::Versions { versions, .. } = stat(&node, 1, "media", "split").await.unwrap() else {
            panic!("expected versions")
        };
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().all(|v| v.attestors.len() == 1));
        node.shutdown().await.unwrap();
    }

    #[test]
    fn websocket_urls_follow_the_scheme_they_were_discovered_under() {
        assert_eq!(
            websocket_url("https://sync.example/agent/v1/attach"),
            "wss://sync.example/agent/v1/attach"
        );
        assert_eq!(
            websocket_url("http://127.0.0.1:8080/agent/v1/attach"),
            "ws://127.0.0.1:8080/agent/v1/attach"
        );
    }

    #[test]
    fn directory_prefixes_end_at_a_boundary() {
        assert_eq!(directory_prefix(""), "");
        assert_eq!(directory_prefix("/"), "");
        assert_eq!(directory_prefix("photos"), "photos/");
        assert_eq!(directory_prefix("photos/"), "photos/");
        assert_eq!(directory_prefix("/photos/2026/"), "photos/2026/");
    }
}
