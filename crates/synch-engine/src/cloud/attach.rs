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
        attach_signing_input, encode_chunk, DelegationJson, Down, EntryJson, Up, VersionJson,
        MAX_CHUNK, NONCE_LEN, PROTOCOL_VERSION,
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

/// How long one write to the socket may take before the session is torn down.
///
/// A control plane that stops reading (a zero-window stall, or a hostile peer
/// that never drains) blocks the writer; without this bound the write would
/// hang forever. Set above the heartbeat window so a merely slow-but-live link
/// is not killed, but finite so a wedged one is.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// The most requests and streams one session may have in flight at once.
///
/// A hostile control plane can otherwise open unbounded LS/STAT/RESOLVE tasks
/// and READ streams, each doing blocking-pool store work. Over the cap a
/// request is refused with a coded error rather than queued. The control
/// plane's per-user cap does not protect the daemon — that is a different
/// process trusting a different thing — so the daemon holds its own ceiling.
const MAX_INFLIGHT: usize = 64;

/// How long discovery, the dial, and the three handshake frames get in total.
///
/// The heartbeat only starts once the session is serving, so without this a
/// control plane that accepts the connection and then says nothing holds the
/// attach task — and its domain's only slot — forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest frame and message this daemon will read from the control plane.
///
/// Every `Down` frame is small control JSON; content flows the other way. The
/// tungstenite defaults (64 MiB message, 16 MiB frame) are sized for general
/// use and would let the peer make the daemon buffer far more than the
/// protocol ever needs.
const MAX_DOWN_FRAME: usize = 1 << 20;

/// The most unspent chunk credits one stream may hold.
///
/// Credit is a promise to read, not a buffer — the writer channel is what
/// bounds memory — so the cap exists to keep a peer from adding permits until
/// the semaphore's own ceiling panics the daemon.
const MAX_CREDIT: usize = 4096;

/// How many entries one listing page carries.
const PAGE_LIMIT: usize = 500;

/// How many flat rows one listing pass pulls from the store at a time.
const SCAN_BATCH: usize = 500;

impl Node {
    /// Runs cloud attach until the daemon stops.
    ///
    /// The loop supervises rather than connects: one child task per membership
    /// domain the node holds, stopped when the operator opts the feature out
    /// or the domain goes away. For an opted-out node it costs one settings
    /// read per interval and opens nothing at all.
    pub async fn run_cloud(
        &self,
        resolver: Option<Arc<synch_net::DnssecResolver>>,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        let shutdown = std::pin::pin!(shutdown);
        let mut shutdown = shutdown;
        let mut running: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            let wanted = self.attach_targets().await;
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
    /// The zone that names this node, unless the operator has opted the feature
    /// out — which is the only thing that empties the list, there being no
    /// enablement to require. Empty for a key-identified node: there is no apex
    /// to take a control plane from, so there is nothing to discover and
    /// nothing to attach to.
    ///
    /// The settings read goes over to the blocking pool: this runs on the
    /// supervisor's runtime worker once per [`SUPERVISE_INTERVAL`], and a
    /// `config` read waits on the same connection mutex a publish batch or a GC
    /// pass holds (§10). The zone itself is the origin's, held in memory.
    async fn attach_targets(&self) -> Vec<String> {
        let node = self.clone();
        crate::blocking::offload(move || {
            Ok(match node.cloud_settings() {
                Ok(settings) if !settings.disabled => node.resolving_domains(),
                _ => Vec::new(),
            })
        })
        .await
        .unwrap_or_default()
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

    // The whole handshake under one clock: the heartbeat that would otherwise
    // notice a silent peer does not start until the session is serving.
    let handshake = async {
        let mut config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
        config.max_message_size = Some(MAX_DOWN_FRAME);
        config.max_frame_size = Some(MAX_DOWN_FRAME);
        let (socket, _) =
            tokio_tungstenite::connect_async_with_config(websocket_url(&url), Some(config), false)
                .await
                .map_err(|e| EngineError::invalid(format!("{url}: {e}")))?;
        let (mut sink, mut stream) = socket.split();

        // Two store reads, so they go over together (§10).
        let held = {
            let node = node.clone();
            crate::blocking::offload(move || held_spaces(&node)).await?
        };
        send(
            &mut sink,
            &Up::Hello {
                v: PROTOCOL_VERSION,
                network: domain.to_string(),
                origin: node.origin().canonical(),
                device: node.node_id().to_z32(),
                spaces: held,
            },
        )
        .await?;

        let nonce = match receive(&mut stream).await? {
            Down::Challenge { nonce } => decode_nonce(&nonce)?,
            Down::Err { code, message, .. } => {
                return Err(EngineError::invalid(brief(&format!("{code}: {message}"))))
            }
            other => {
                return Err(EngineError::invalid(brief(&format!(
                    "expected a challenge, got {other:?}"
                ))))
            }
        };
        // Signed here, in the process that holds the key: no RPC exists that
        // would hand this capability to another program on the node.
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
                return Err(EngineError::invalid(brief(&format!("{code}: {message}"))))
            }
            other => {
                return Err(EngineError::invalid(brief(&format!(
                    "expected an attach, got {other:?}"
                ))))
            }
        }
        Ok((sink, stream))
    };
    let (sink, stream) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| {
            EngineError::invalid(format!("{url}: the handshake did not finish in time"))
        })??;
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

/// The spaces this node claims to hold, as they stood when the session opened.
///
/// A publish root and a mirror hold a space equally — both leave the unified
/// tree and its content local — so both claim it, and a node that only mirrors
/// a space is routable for it rather than a bystander. The claim is taken once
/// per session: a space added after attach is not routable until the next
/// reconnect, which is the same grain the whole tunnel works at — the control
/// plane may ask for anything, and this says what it will find.
fn held_spaces(node: &Node) -> Result<Vec<String>> {
    let mut held: Vec<String> = node
        .store()
        .spaces()?
        .into_iter()
        .map(|space| space.id)
        .collect();
    held.extend(
        node.store()
            .mirrors()?
            .into_iter()
            .map(|mirror| mirror.space),
    );
    held.sort_unstable();
    held.dedup();
    Ok(held)
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
/// Renders text the control plane chose, for a log line or an error message.
///
/// The peer picks these strings. Control characters would steer a terminal
/// reading the daemon's log, and the length is bounded by the frame size
/// rather than by anything the protocol needs, so both are cut here.
fn brief(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

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

/// A message from a spawned task back to the session loop.
///
/// This is what keeps the session's bookkeeping truthful: a one-shot request
/// or a stream that has ended tells the loop so, rather than leaving a map
/// entry or an in-flight count that no longer means anything.
#[derive(Debug)]
enum Internal {
    /// A READ stream ended — success, error, or cancellation — so its map
    /// entry can go. Without this the entry leaks per completed download and
    /// the reused-id guard refuses the id forever.
    ReadDone(u32),
    /// A one-shot LS/STAT/RESOLVE task finished, so the in-flight count drops.
    RequestDone,
    /// The writer task gave up on the socket — a failed or stalled write — so
    /// the session is over.
    WriterFailed(String),
}

/// Aborts the writer task when the session ends, whichever way it ends.
#[derive(Debug)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Answers frames until the connection ends.
///
/// The socket write lives in a dedicated task, not in the select loop: a write
/// blocked on backpressure from a control plane that has stopped reading would
/// otherwise stall every other branch — the heartbeat that is meant to kill a
/// dead session could not fire, and the whole task would hang holding the read
/// half, the streams, and their blob handles. With the writer split off, the
/// loop keeps polling the heartbeat and the read half no matter how wedged the
/// write direction is, and the writer's own timeout tears the session down.
async fn serve<S, R>(node: &Node, sink: S, mut stream: R) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin
        + Send
        + 'static,
    R: futures_util::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    let (writes, mut outgoing) = mpsc::channel::<Message>(WRITE_AHEAD);
    let (internal, mut events) = mpsc::channel::<Internal>(WRITE_AHEAD);

    // The writer owns the sink. Each write is bounded by `WRITE_TIMEOUT`, so a
    // peer that stops reading is a session that ends rather than a task that
    // hangs. When the loop returns, `writes` drops, `outgoing.recv()` yields
    // `None`, and the writer exits — the `AbortOnDrop` is only the backstop for
    // a write still in progress at that moment.
    let writer = {
        let internal = internal.clone();
        let mut sink = sink;
        tokio::spawn(async move {
            while let Some(message) = outgoing.recv().await {
                match tokio::time::timeout(WRITE_TIMEOUT, sink.send(message)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        let _ = internal
                            .send(Internal::WriterFailed(format!(
                                "the tunnel write failed: {e}"
                            )))
                            .await;
                        return;
                    }
                    Err(_) => {
                        let _ = internal
                            .send(Internal::WriterFailed(
                                "the control plane stopped reading; the write stalled".into(),
                            ))
                            .await;
                        return;
                    }
                }
            }
        })
    };
    let _writer_guard = AbortOnDrop(writer);

    let mut streams: HashMap<u32, Stream> = HashMap::new();
    // One-shot LS/STAT/RESOLVE tasks in flight; streams are counted separately
    // by the map, and the cap is on the sum.
    let mut requests: usize = 0;
    // First tick one period out, not immediately: a `tokio` interval fires at
    // once otherwise, which would ping on connect and, worse, spend a miss
    // before any time had passed — making the two-miss window 30s, not 60s.
    let mut beat = tokio::time::interval_at(tokio::time::Instant::now() + HEARTBEAT, HEARTBEAT);
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut unanswered = 0u32;

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(Internal::WriterFailed(why)) => return Err(EngineError::invalid(why)),
                    // On completion, however it completed: the entry goes and
                    // the id is free to be reused.
                    Some(Internal::ReadDone(id)) => { streams.remove(&id); }
                    Some(Internal::RequestDone) => requests = requests.saturating_sub(1),
                    // The loop holds a sender, so this only happens at shutdown.
                    None => return Ok(()),
                }
            }
            _ = beat.tick() => {
                if unanswered >= HEARTBEAT_MISSES {
                    return Err(EngineError::invalid(format!(
                        "the control plane missed {unanswered} heartbeats; the session is dead"
                    )));
                }
                unanswered += 1;
                // `try_send`, never `await`: a full channel means the writer is
                // behind, which the write timeout already covers — the loop must
                // not block here, or it stops polling the very branches that
                // detect a dead peer.
                let _ = writes.try_send(text(&Up::Ping)?);
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
                        handle(node, &writes, &internal, &mut streams, &mut requests, frame)?;
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
///
/// Never awaits: every answer is produced in a spawned task and delivered
/// through the writer channel, so serving a frame cannot block the session
/// loop. A `try_send` that finds the channel full is treated as backpressure
/// on the offending request, not on the session.
fn handle(
    node: &Node,
    writes: &Writer,
    internal: &mpsc::Sender<Internal>,
    streams: &mut HashMap<u32, Stream>,
    requests: &mut usize,
    frame: Down,
) -> Result<()> {
    match frame {
        Down::Ping => {
            let _ = writes.try_send(text(&Up::Pong)?);
        }
        Down::Pong => {}
        Down::Err { id, code, message } => {
            let (code, message) = (brief(&code), brief(&message));
            tracing::debug!(?id, code, message, "the control plane refused a request");
            if let Some(id) = id {
                streams.remove(&id);
            }
        }
        Down::Credit { id, n } => {
            if let Some(stream) = streams.get(&id) {
                let room = MAX_CREDIT.saturating_sub(stream.credit.available_permits());
                stream.credit.add_permits((n as usize).min(room));
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
            if over_capacity(writes, streams, *requests, id) {
                return Ok(());
            }
            *requests += 1;
            let node = node.clone();
            let writes = writes.clone();
            let internal = internal.clone();
            tokio::spawn(async move {
                let page = list_page(&node, &space, &path, cursor, all)
                    .await
                    .map(|frame| with_id(frame, id));
                answer(&writes, id, page).await;
                let _ = internal.send(Internal::RequestDone).await;
            });
        }
        Down::Delegations { id } => {
            if over_capacity(writes, streams, *requests, id) {
                return Ok(());
            }
            *requests += 1;
            let node = node.clone();
            let writes = writes.clone();
            let internal = internal.clone();
            tokio::spawn(async move {
                answer(&writes, id, delegations(&node, id).await).await;
                let _ = internal.send(Internal::RequestDone).await;
            });
        }
        Down::Stat { id, space, path } => {
            if over_capacity(writes, streams, *requests, id) {
                return Ok(());
            }
            *requests += 1;
            let node = node.clone();
            let writes = writes.clone();
            let internal = internal.clone();
            tokio::spawn(async move {
                answer(&writes, id, stat(&node, id, &space, &path).await).await;
                let _ = internal.send(Internal::RequestDone).await;
            });
        }
        Down::Resolve {
            id,
            space,
            path,
            from,
        } => {
            if over_capacity(writes, streams, *requests, id) {
                return Ok(());
            }
            *requests += 1;
            let node = node.clone();
            let writes = writes.clone();
            let internal = internal.clone();
            tokio::spawn(async move {
                answer(&writes, id, resolve(&node, id, &space, &path, from).await).await;
                let _ = internal.send(Internal::RequestDone).await;
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
                let _ = writes.try_send(text(&Up::Err {
                    id: Some(id),
                    code: "invalid".into(),
                    message: format!("request {id} is already streaming"),
                })?);
                return Ok(());
            }
            if over_capacity(writes, streams, *requests, id) {
                return Ok(());
            }
            let permits = Arc::new(Semaphore::new((credit as usize).min(MAX_CREDIT)));
            let task = {
                let node = node.clone();
                let writes = writes.clone();
                let internal = internal.clone();
                let permits = permits.clone();
                tokio::spawn(async move {
                    if let Err(e) = read(&node, &writes, id, &root, size, start, len, permits).await
                    {
                        let _ = writes.try_send(Message::text(
                            serde_json::to_string(&Up::Err {
                                id: Some(id),
                                code: code_of(&e).to_string(),
                                message: e.to_string(),
                            })
                            .unwrap_or_default(),
                        ));
                    }
                    // Whichever way it ended, the session loop drops the entry.
                    let _ = internal.send(Internal::ReadDone(id)).await;
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

/// Whether a new request would exceed the per-session ceiling, refusing it with
/// a coded error if so.
fn over_capacity(
    writes: &Writer,
    streams: &HashMap<u32, Stream>,
    requests: usize,
    id: u32,
) -> bool {
    if streams.len() + requests < MAX_INFLIGHT {
        return false;
    }
    if let Ok(message) = text(&Up::Err {
        id: Some(id),
        code: "unavailable".into(),
        message: format!("this session already has {MAX_INFLIGHT} requests in flight"),
    }) {
        let _ = writes.try_send(message);
    }
    true
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

/// One page of a directory of the unified tree.
async fn list_page(
    node: &Node,
    space: &str,
    path: &str,
    cursor: Option<String>,
    all: bool,
) -> Result<Up> {
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
///
/// Answered on the blocking pool, like every other request below: these run in
/// tasks spawned onto the daemon's runtime, and the store reads under them wait
/// on the same connection mutex the publisher and the anti-entropy rounds do
/// (§10).
async fn stat(node: &Node, id: u32, space: &str, path: &str) -> Result<Up> {
    let node = node.clone();
    let (space, path) = (space.to_string(), path.to_string());
    crate::blocking::offload(move || {
        let set = node.versions(&space, &path)?;
        Ok(Up::Versions {
            id,
            versions: versions_json(&set),
        })
    })
    .await
}

/// Every delegation this node honors, with the cascade already applied (§3.5).
///
/// Answers for the cluster rather than for this node: a delegation is a `d:`
/// record in its issuer's trie, replicated to every member, so whichever node
/// the control plane happens to be attached to holds them all. That is the
/// transitive-trust concession made legible — an operator can see from one
/// place who was admitted, by whom, and to what.
///
/// Lapsed rows travel alongside live ones, marked. A dashboard that showed
/// only what is live could not distinguish "never delegated" from "delegated,
/// and the issuer is gone", and those call for different actions.
async fn delegations(node: &Node, id: u32) -> Result<Up> {
    let node = node.clone();
    // One hop for both reads: the live set is the same query filtered by the
    // cascade, and nothing between them awaits.
    crate::blocking::offload(move || {
        let now = synch_core::now_ns();
        let live: std::collections::HashSet<(Vec<u8>, String)> = node
            .store()
            .delegations(now)?
            .into_iter()
            .map(|b| {
                (
                    b.node_id.as_bytes().to_vec(),
                    b.issuer.map(|i| i.canonical()).unwrap_or_default(),
                )
            })
            .collect();
        let delegations = node
            .delegations()?
            .into_iter()
            .map(|b| {
                let issuer = b.issuer.map(|i| i.canonical()).unwrap_or_default();
                DelegationJson {
                    key: b.node_id.to_z32(),
                    live: live.contains(&(b.node_id.as_bytes().to_vec(), issuer.clone())),
                    issuer,
                    spaces: b.spaces,
                    not_after: b.expires_at,
                    added_at: b.added_at,
                    note: b.note,
                }
            })
            .collect();
        Ok(Up::Delegations { id, delegations })
    })
    .await
}

/// Pins a path to one content root and names who holds it.
async fn resolve(
    node: &Node,
    id: u32,
    space: &str,
    path: &str,
    from: Option<String>,
) -> Result<Up> {
    let policy = match &from {
        Some(origin) => VersionPolicy::Origin(
            origin
                .parse::<OriginId>()
                .map_err(|e| EngineError::invalid(e.to_string()))?,
        ),
        None => VersionPolicy::Newest,
    };
    // One hop for the selection, the provider list and the local completeness
    // check together: they are three reads on the connection the first one
    // takes, and nothing between them awaits.
    let node = node.clone();
    let (space, path) = (space.to_string(), path.to_string());
    crate::blocking::offload(move || {
        let row = node.resolve(&space, &path, &policy)?;
        if row.kind == EntryKind::Tombstone {
            return Err(EngineError::not_found(format!(
                "{space}/{path} was deleted at seq {}",
                row.seq
            )));
        }
        let root = row
            .content
            .ok_or_else(|| EngineError::invalid(format!("{space}/{path} selects no content")))?;
        // Straight out of the replicated `b:` records: a routing hint the
        // control plane may act on or ignore, never a correctness input.
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
    })
    .await
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

    /// Encodes one control frame as the control plane would put it on the wire.
    fn down_msg(frame: &Down) -> Message {
        Message::text(serde_json::to_string(frame).unwrap())
    }

    /// The next text frame the node sent, decoded — skipping binary chunks so a
    /// caller waiting for a control answer is not tripped by content.
    async fn next_up(rx: &mut mpsc::UnboundedReceiver<Message>) -> Up {
        loop {
            match rx.recv().await.expect("the node sent a frame") {
                Message::Text(body) => {
                    let up: Up = serde_json::from_str(&body).expect("a valid Up");
                    // Skip the node's own heartbeat pings; a Pong answering the
                    // test's ping is a real frame and is returned.
                    if matches!(up, Up::Ping) {
                        continue;
                    }
                    return up;
                }
                Message::Binary(_) => continue,
                other => panic!("unexpected frame {other:?}"),
            }
        }
    }

    /// Plants a delegated binding as materializing an issuer's `d:` record does.
    fn delegate(node: &Node, issuer: &OriginId, subject: synch_core::NodeId, spaces: &[&str]) {
        node.store()
            .put_binding(&synch_store::Binding {
                origin: OriginId::Key(subject),
                node_id: subject,
                source: synch_store::BindingSource::Delegated,
                domain: None,
                issuer: Some(issuer.clone()),
                spaces: spaces.iter().map(|s| s.to_string()).collect(),
                note: Some("planted".into()),
                added_at: 1,
                expires_at: Some(synch_core::now_ns() + 86_400_000_000_000),
            })
            .unwrap();
    }

    /// The control plane can ask who the cluster admits, and is told which
    /// grants still hold (§3.5).
    ///
    /// The cascade is the whole point of the answer: both rows below are inside
    /// their own expiry, and they differ only in whether the origin that issued
    /// them is still trusted here. A dashboard reading dates alone would show
    /// them identically, which is exactly the reporting hole the delegation
    /// work closed locally — this is that hole closed over the tunnel.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_answers_a_delegations_query_with_the_cascade_applied() {
        let _blocking = synch_core::BlockingScope::enter();
        let (_dir, node) = node().await;

        // A rooted issuer, and one this node holds no binding for at all.
        let rooted = origin("nas");
        let rooted_key = iroh_base::SecretKey::generate().public();
        node.store()
            .put_binding(&synch_store::Binding {
                origin: rooted.clone(),
                node_id: rooted_key,
                source: synch_store::BindingSource::Static,
                domain: None,
                issuer: None,
                spaces: Vec::new(),
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        let stranger = origin("gone");

        let held = iroh_base::SecretKey::generate().public();
        let orphaned = iroh_base::SecretKey::generate().public();
        delegate(&node, &rooted, held, &["photos"]);
        delegate(&node, &stranger, orphaned, &["finance"]);

        let (to_node, node_rx) = mpsc::unbounded_channel::<Message>();
        let (node_tx, mut from_node) = mpsc::unbounded_channel::<Message>();
        let stream = Box::pin(futures_util::stream::unfold(node_rx, |mut rx| async move {
            rx.recv()
                .await
                .map(|m| (Ok::<Message, tokio_tungstenite::tungstenite::Error>(m), rx))
        }));
        let sink = Box::pin(futures_util::sink::unfold(
            node_tx,
            |tx, m: Message| async move {
                tx.send(m)
                    .map_err(|_| tokio_tungstenite::tungstenite::Error::ConnectionClosed)?;
                Ok::<_, tokio_tungstenite::tungstenite::Error>(tx)
            },
        ));
        let served = {
            let node = node.clone();
            tokio::spawn(async move {
                let _ = serve(&node, sink, stream).await;
            })
        };

        to_node
            .send(down_msg(&Down::Delegations { id: 7 }))
            .unwrap();
        let Up::Delegations { id, delegations } = next_up(&mut from_node).await else {
            panic!("expected a delegations answer")
        };
        assert_eq!(id, 7);
        assert_eq!(delegations.len(), 2, "{delegations:?}");

        let live = delegations
            .iter()
            .find(|d| d.key == held.to_z32())
            .expect("the rooted issuer's delegation");
        assert!(live.live, "a rooted issuer's grant holds");
        assert_eq!(live.issuer, rooted.canonical());
        assert_eq!(live.spaces, ["photos"]);
        assert_eq!(live.note.as_deref(), Some("planted"));
        assert!(live.not_after.is_some(), "the end date travels too");

        let lapsed = delegations
            .iter()
            .find(|d| d.key == orphaned.to_z32())
            .expect("the stranger's delegation");
        assert!(
            !lapsed.live,
            "an issuer this node does not trust vouches for nobody, whatever the date says"
        );
        // Reported rather than hidden: "never delegated" and "delegated by
        // someone since cut off" are different states and call for different
        // actions.
        assert_eq!(lapsed.issuer, stranger.canonical());
        assert_eq!(lapsed.spaces, ["finance"]);

        drop(to_node);
        let _ = served.await;
        node.shutdown().await.unwrap();
    }

    /// Runs `serve` end to end against an in-process socket, exercising the real
    /// framing: JSON control frames, the binary CHUNK codec, credit flow, and
    /// the request-id multiplexing across LS → RESOLVE → READ → PING. The
    /// attach handshake itself is `attach_once`, tested for its signing bytes
    /// against the control plane's; this covers everything downstream of it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_answers_ls_resolve_and_read_over_the_wire() {
        let _blocking = synch_core::BlockingScope::enter();
        let (dir, node) = node().await;
        node.add_space("media", dir.path().join("media")).unwrap();
        // Larger than one chunk, so the CHUNK framing and the multi-chunk
        // credit path both run rather than fitting in a single frame.
        let payload = vec![0xABu8; MAX_CHUNK + 4321];
        let root = node
            .store()
            .ingest_bytes(&payload, synch_core::now_ns())
            .unwrap();
        node.store()
            .put_entry(
                &origin("nas"),
                "media",
                "big.bin",
                &FileEntry::file(payload.len() as u64, 1, root, 1),
            )
            .unwrap();

        // Two halves of one socket: `to_node` carries Down frames in, `from_node`
        // collects Up frames out.
        let (to_node, node_rx) = mpsc::unbounded_channel::<Message>();
        let (node_tx, mut from_node) = mpsc::unbounded_channel::<Message>();
        let stream = Box::pin(futures_util::stream::unfold(node_rx, |mut rx| async move {
            rx.recv()
                .await
                .map(|m| (Ok::<Message, tokio_tungstenite::tungstenite::Error>(m), rx))
        }));
        let sink = Box::pin(futures_util::sink::unfold(
            node_tx,
            |tx, m: Message| async move {
                tx.send(m)
                    .map_err(|_| tokio_tungstenite::tungstenite::Error::ConnectionClosed)?;
                Ok::<_, tokio_tungstenite::tungstenite::Error>(tx)
            },
        ));
        let served = {
            let node = node.clone();
            tokio::spawn(async move {
                let _ = serve(&node, sink, stream).await;
            })
        };

        // LS: the directory lists the file.
        to_node
            .send(down_msg(&Down::Ls {
                id: 1,
                space: "media".into(),
                path: String::new(),
                cursor: None,
                all: false,
            }))
            .unwrap();
        let Up::Page { id, entries, .. } = next_up(&mut from_node).await else {
            panic!("expected a page")
        };
        assert_eq!(id, 1);
        assert!(entries.iter().any(|e| e.name == "big.bin"));

        // RESOLVE: pin the version to its content root.
        to_node
            .send(down_msg(&Down::Resolve {
                id: 2,
                space: "media".into(),
                path: "big.bin".into(),
                from: None,
            }))
            .unwrap();
        let Up::Resolved { id, root, size, .. } = next_up(&mut from_node).await else {
            panic!("expected a resolution")
        };
        assert_eq!(id, 2);
        assert_eq!(size, payload.len() as u64);

        // READ by pinned root: META, then the content in ≤64 KiB chunks under
        // the initial credit, then DONE. The bytes must match exactly.
        to_node
            .send(down_msg(&Down::Read {
                id: 3,
                root: root.clone(),
                size,
                start: 0,
                len: None,
                credit: 8,
            }))
            .unwrap();
        let Up::Meta {
            id,
            size: meta_size,
            root: meta_root,
        } = next_up(&mut from_node).await
        else {
            panic!("expected a meta frame before content")
        };
        assert_eq!(id, 3);
        assert_eq!(meta_size, payload.len() as u64);
        assert_eq!(meta_root, root);

        let mut got = Vec::new();
        loop {
            match from_node.recv().await.expect("a frame") {
                Message::Binary(bytes) => {
                    let (chunk_id, _seq, data) = decode_chunk(&bytes).expect("a content frame");
                    assert_eq!(chunk_id, 3);
                    assert!(data.len() <= MAX_CHUNK);
                    got.extend_from_slice(data);
                }
                Message::Text(body) => {
                    if let Up::Done { id } = serde_json::from_str(&body).unwrap() {
                        assert_eq!(id, 3);
                        break;
                    }
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }
        assert_eq!(got, payload, "the streamed bytes match the file");

        // PING/PONG multiplexes over the same connection.
        to_node.send(down_msg(&Down::Ping)).unwrap();
        assert!(matches!(next_up(&mut from_node).await, Up::Pong));

        // Closing the Down half ends the session cleanly.
        drop(to_node);
        let _ = served.await;
        node.shutdown().await.unwrap();
    }

    /// No validated record, no connection: a resolver outage degrades the
    /// feature to off, never to "attach somewhere else".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discovery_without_a_resolver_attempts_nothing() {
        let _blocking = synch_core::BlockingScope::enter();
        let (_d, node) = node().await;
        let e = discover(&node, None, "cluster.example").await.unwrap_err();
        assert!(e.to_string().contains("no DNSSEC resolver"), "{e}");
        node.shutdown().await.unwrap();
    }

    /// The task list follows the domains without being asked — the feature
    /// needs no enabling — and empties only when the operator opts out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attach_targets_follow_the_zone_and_the_opt_out() {
        let _blocking = synch_core::BlockingScope::enter();
        // A key-identified node names no zone, so there is no apex to take a
        // control plane from — nothing to attach to, tunnel or no tunnel.
        let (_d, node) = node().await;
        assert!(node.attach_targets().await.is_empty());
        node.shutdown().await.unwrap();

        // A node named by its zone attaches to that zone, and only the opt-out
        // empties the list.
        let dir = tempfile::tempdir().unwrap();
        Node::init_named_by_zone(
            dir.path(),
            OriginId::named("nas", "cluster.example").unwrap(),
        )
        .unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        assert_eq!(node.attach_targets().await, ["cluster.example"]);
        node.disable_cloud().unwrap();
        assert!(node.attach_targets().await.is_empty());
        node.enable_cloud().unwrap();
        assert_eq!(node.attach_targets().await, ["cluster.example"]);
        node.shutdown().await.unwrap();
    }

    /// A mirror leaves a space as local as a publish root does — its tree and
    /// its bytes are both on this node — so the attach claim names it, and a
    /// mirror-only node is routable for what it mirrors.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_claim_covers_mirrored_spaces_too() {
        let _blocking = synch_core::BlockingScope::enter();
        let (dir, node) = node().await;
        node.add_space("docs", dir.path().join("docs")).unwrap();
        let mirror = tempfile::tempdir().unwrap();
        node.add_mirror("media", mirror.path(), &VersionPolicy::Newest)
            .unwrap();
        assert_eq!(held_spaces(&node).unwrap(), ["docs", "media"]);

        // A space both published and mirrored is one claim, not two.
        node.add_space("media", dir.path().join("media")).unwrap();
        assert_eq!(held_spaces(&node).unwrap(), ["docs", "media"]);
        node.shutdown().await.unwrap();
    }

    /// Credit is the whole of the read-ahead bound: with none granted, no
    /// chunk is produced, however much of the object is already local.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_read_produces_nothing_without_credit() {
        let _blocking = synch_core::BlockingScope::enter();
        let (dir, node) = node().await;
        node.add_space("media", dir.path().join("media")).unwrap();
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

    /// Credit is a promise to read, and the control plane may promise more
    /// than the semaphore can hold. Repeated grants stop at the ceiling
    /// instead of overflowing it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn credit_grants_stop_at_the_ceiling() {
        let _blocking = synch_core::BlockingScope::enter();
        let (_dir, node) = node().await;
        let (writes, _rx) = mpsc::channel(16);
        let (internal, _drain) = mpsc::channel(16);
        let credit = Arc::new(Semaphore::new(0));
        let mut streams = HashMap::from([(
            7,
            Stream {
                credit: credit.clone(),
                task: tokio::spawn(std::future::pending()),
            },
        )]);
        let mut requests = 0;
        for _ in 0..4 {
            handle(
                &node,
                &writes,
                &internal,
                &mut streams,
                &mut requests,
                Down::Credit { id: 7, n: u32::MAX },
            )
            .unwrap();
        }
        assert_eq!(credit.available_permits(), MAX_CREDIT);
        // An unopened stream is not a place to bank credit either.
        handle(
            &node,
            &writes,
            &internal,
            &mut streams,
            &mut requests,
            Down::Credit { id: 9, n: 1 },
        )
        .unwrap();
        streams.clear();
        node.shutdown().await.unwrap();
    }

    /// Log lines and error text carry strings the control plane chose, so
    /// escape sequences and unbounded length are cut before they land.
    #[test]
    fn peer_text_is_stripped_and_bounded() {
        assert_eq!(brief("plain \u{1b}[31mred\n"), "plain [31mred");
        assert_eq!(brief(&"x".repeat(10_000)).len(), 200);
    }

    /// A directory view is a fold over the flat tree, and a subdirectory is
    /// one row however many paths sit under it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_listing_collapses_subdirectories() {
        let _blocking = synch_core::BlockingScope::enter();
        let (dir, node) = node().await;
        node.add_space("media", dir.path().join("media")).unwrap();
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_listing_reports_every_version_of_a_divergent_path() {
        let _blocking = synch_core::BlockingScope::enter();
        let (dir, node) = node().await;
        node.add_space("media", dir.path().join("media")).unwrap();
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
