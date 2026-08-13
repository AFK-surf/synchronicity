//! The daemon side of the control socket (§9.3).
//!
//! One connection carries one command. The daemon checks the protocol version
//! and the datadir token before it looks at the request, then streams the
//! response back as `Line`, `Chunk`, and `Progress` frames terminated by `End`,
//! or a structured `Error`.

use std::{str::FromStr, sync::Arc};

use synch_core::{now_ns, Hash, NodeId, OriginId};
use synch_engine::{EntryRef, Node, VersionPolicy};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::broadcast,
};

use crate::{
    control::{
        proto::{
            read_frame, tokens_match, write_frame, ControlError, ErrorCode, Hello, Request,
            Response, CHUNK_SIZE, CONTROL_VERSION,
        },
        transport::{self, Listener},
    },
    render,
};

/// The shortest gap between recovery collection rounds.
///
/// A quiesce measured in seconds still sleeps between rounds rather than
/// spinning on the peers it is polling.
const POLL_FLOOR: std::time::Duration = std::time::Duration::from_secs(1);

/// The control server: a bound listener plus the node it serves.
///
/// Binding is separate from running so a daemon can report that it is (or is
/// not) able to listen before it announces itself.
#[derive(Debug)]
pub struct Server {
    node: Node,
    listener: Listener,
    token: Arc<Vec<u8>>,
    stop: broadcast::Sender<()>,
    /// Subscribed at bind time, not at run time: a stop sent between the two
    /// would otherwise be sent to nobody and the server would wait forever.
    stopping: broadcast::Receiver<()>,
}

impl Server {
    /// Binds the control socket for `node`'s data directory and mints a fresh
    /// token.
    ///
    /// Fails if another daemon is already listening for this datadir; a stale
    /// socket from a crashed one is removed first.
    pub async fn bind(node: Node, stop: broadcast::Sender<()>) -> std::io::Result<Server> {
        let data_dir = node.config().data_dir.clone();
        let listener = Listener::bind(&data_dir).await?;
        let token = Arc::new(transport::write_token(&data_dir)?);
        let stopping = stop.subscribe();
        Ok(Server {
            node,
            listener,
            token,
            stop,
            stopping,
        })
    }

    /// The socket path or pipe name this server listens on.
    pub fn endpoint_name(&self) -> String {
        transport::endpoint_name(&self.node.config().data_dir)
    }

    /// Serves until `stop` fires — which `synch daemon stop` does by sending on
    /// the same channel.
    pub async fn run(mut self) -> std::io::Result<()> {
        loop {
            tokio::select! {
                _ = self.stopping.recv() => break,
                accepted = self.listener.accept() => {
                    let stream = match accepted {
                        Ok(stream) => stream,
                        Err(e) => {
                            tracing::warn!(error = %e, "control accept failed");
                            continue;
                        }
                    };
                    let node = self.node.clone();
                    let token = self.token.clone();
                    let stop = self.stop.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle(node, token, stop, stream).await {
                            // A client that walked away mid-response is
                            // ordinary, not a daemon fault.
                            tracing::debug!(error = %e, "control connection ended");
                        }
                    });
                }
            }
        }
        transport::remove_token(&self.node.config().data_dir);
        Ok(())
    }
}

/// Runs one connection: handshake, request, streamed response.
async fn handle<S>(
    node: Node,
    token: Arc<Vec<u8>>,
    stop: broadcast::Sender<()>,
    mut stream: S,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello: Hello = read_frame(&mut stream).await?;
    if hello.version != CONTROL_VERSION {
        let error = ControlError::new(
            ErrorCode::VersionMismatch,
            format!(
                "control protocol mismatch: the client speaks v{}, this daemon speaks v{}. \
                 Restart the daemon so both are the same build",
                hello.version, CONTROL_VERSION
            ),
        );
        write_frame(&mut stream, &Response::Error(error)).await?;
        return linger(&mut stream).await;
    }
    if !tokens_match(&hello.token, &token) {
        let error = ControlError::new(
            ErrorCode::Unauthorized,
            format!(
                "control token mismatch: re-read {} from this datadir",
                transport::TOKEN_FILE
            ),
        );
        write_frame(&mut stream, &Response::Error(error)).await?;
        return linger(&mut stream).await;
    }
    write_frame(&mut stream, &Response::Ready).await?;

    let request: Request = read_frame(&mut stream).await?;
    let mut out = Frames { stream };
    let (outcome, result) = match dispatch(&node, request, &mut out).await {
        Ok(outcome) => (outcome, out.end().await),
        Err(error) => (Outcome::default(), out.error(error).await),
    };
    let mut stream = out.stream;
    linger(&mut stream).await?;
    drop(stream);
    // The daemon comes down only once its answer has landed, so `synch daemon
    // stop` reports what happened instead of losing the connection under itself.
    if outcome.stop_daemon {
        let _ = stop.send(());
    }
    result
}

/// Waits for the client to hang up before the connection is dropped.
///
/// Closing a Windows named-pipe server handle can discard bytes the client
/// has not read yet, so the last frames of a response are only safely
/// delivered once the *client* has closed. The wait is bounded: a client that
/// never hangs up costs one idle task for the timeout and no more.
async fn linger<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut scratch = [0u8; 1];
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncReadExt::read(stream, &mut scratch),
    )
    .await;
    Ok(())
}

/// The response side of one connection.
struct Frames<S> {
    stream: S,
}

impl<S: AsyncWrite + Unpin> Frames<S> {
    async fn line(&mut self, text: impl Into<String>) -> std::io::Result<()> {
        write_frame(&mut self.stream, &Response::Line(text.into())).await
    }

    async fn chunk(&mut self, bytes: Vec<u8>) -> std::io::Result<()> {
        write_frame(&mut self.stream, &Response::Chunk(bytes)).await
    }

    async fn progress(&mut self, text: impl Into<String>) -> std::io::Result<()> {
        write_frame(&mut self.stream, &Response::Progress(text.into())).await
    }

    async fn end(&mut self) -> std::io::Result<()> {
        write_frame(&mut self.stream, &Response::End).await
    }

    async fn error(&mut self, error: ControlError) -> std::io::Result<()> {
        write_frame(&mut self.stream, &Response::Error(error)).await
    }
}

/// What handling a request leaves for the connection to do afterwards.
#[derive(Debug, Default, Clone, Copy)]
struct Outcome {
    /// `synch daemon stop`: bring the daemon down once this response is out.
    stop_daemon: bool,
}

type Handled = std::result::Result<Outcome, ControlError>;

/// What a helper that only writes frames returns.
type Done = std::result::Result<(), ControlError>;

/// Serves one request.
async fn dispatch<S: AsyncWrite + Unpin>(
    node: &Node,
    request: Request,
    out: &mut Frames<S>,
) -> Handled {
    let mut outcome = Outcome::default();
    match request {
        Request::Id => {
            out.line(format!("origin: {}", node.origin())).await?;
            for key in node.device_keys()? {
                out.line(format!(
                    "  {} ({})",
                    key.node_id.to_z32(),
                    key.state.as_str()
                ))
                .await?;
            }
            out.line(format!(
                "address: {}",
                render::addr(&node.net().direct_addr())
            ))
            .await?;
        }

        Request::KeyLs => {
            // §3.4 step 3: the switch-over judgement is "have my peers picked
            // up the new binding yet?", which this node cannot answer from its
            // own view of DNS. So each reachable peer is asked what it holds
            // bound for us, and the tally is reported per key.
            let peers = node.peer_bindings(node.origin()).await?;
            let reachable: Vec<&synch_engine::PeerBindings> =
                peers.iter().filter(|p| p.reachable()).collect();
            for key in node.device_keys()? {
                let holding = reachable.iter().filter(|p| p.holds(&key.node_id)).count();
                out.line(format!(
                    "{} {:<8} bound by {} of {} reachable peer(s)",
                    key.node_id.to_z32(),
                    key.state.as_str(),
                    holding,
                    reachable.len()
                ))
                .await?;
                for peer in &peers {
                    let verdict = match &peer.keys {
                        Ok(_) if peer.holds(&key.node_id) => "holds it".to_string(),
                        Ok(_) => "does not hold it yet".to_string(),
                        Err(e) => format!("unreachable: {e}"),
                    };
                    out.line(format!("    {} {verdict}", peer.peer.to_z32()))
                        .await?;
                }
            }
            if peers.is_empty() {
                out.line("  no trusted peers to ask").await?;
            } else if reachable.is_empty() {
                out.line("  no peer could be reached; the tallies above count nobody")
                    .await?;
            }
        }

        Request::KeyRotate => {
            let plan = node.rotate_key()?;
            out.line(format!("generated device key {}", plan.new_key.to_z32()))
                .await?;
            // A key-identified origin is refused by `rotate_key` itself, so
            // the record is always there by the time we get here.
            if let Some(record) = plan.txt_record() {
                out.line("publish alongside the existing record:").await?;
                out.line(record).await?;
                out.line(format!(
                    "then, once it has propagated, run `synch key activate {}`",
                    plan.new_key.to_z32()
                ))
                .await?;
            }
        }

        Request::KeyActivate { key } => {
            let key = parse_key(&key)?;
            let activation = node.activate_key(&key).await?;
            out.line(format!(
                "signing as {} from seq {}",
                activation.new_key.to_z32(),
                activation.head.seq
            ))
            .await?;
            out.line(format!(
                "{} still serves until you run `synch key retire {}`",
                activation.previous_key.to_z32(),
                activation.previous_key.to_z32()
            ))
            .await?;
            out.line(format!(
                "address: {}",
                render::addr(&node.net().direct_addr())
            ))
            .await?;
            // Peers learn the re-signed head at the next round anyway; pushing
            // makes the switch visible immediately where reachable.
            if let Err(e) = node.push_head(&activation.head).await {
                tracing::debug!(error = %e, "could not push the re-signed head");
            }
        }

        Request::KeyRetire { key } => {
            let key = parse_key(&key)?;
            node.retire_key(&key).await?;
            out.line(format!(
                "retired {}: endpoint closed and secret deleted",
                key.to_z32()
            ))
            .await?;
        }

        Request::Recover { wait, gap } => recover(node, out, wait, gap).await?,

        Request::DaemonStatus | Request::Doctor { rebuild: false } => {
            for line in render::doctor(node)? {
                out.line(line).await?;
            }
        }

        Request::Doctor { rebuild: true } => {
            let n = node.rebuild_views()?;
            out.line(format!("rebuilt {n} derived rows from the trie"))
                .await?;
            for line in render::doctor(node)? {
                out.line(line).await?;
            }
        }

        Request::DaemonStop => {
            out.line("stopping").await?;
            outcome.stop_daemon = true;
        }

        Request::TrustAdd {
            key,
            name,
            domain,
            note,
            addr,
        } => {
            let key = parse_key(&key)?;
            let origin =
                node.trust_add(key, name.as_deref(), domain.as_deref(), note.as_deref())?;
            if let Some(addr) = addr {
                let socket = addr
                    .parse()
                    .map_err(|_| ControlError::invalid("--addr wants HOST:PORT"))?;
                node.remember_peer(&iroh::EndpointAddr::new(key).with_ip_addr(socket))?;
            }
            out.line(format!("trusted {} as {origin}", key.to_z32()))
                .await?;
        }

        Request::TrustRebind { origin, key } => {
            let origin = parse_origin(&origin)?;
            let key = parse_key(&key)?;
            node.trust_rebind(&origin, key)?;
            out.line(format!("{origin} now also accepts {}", key.to_z32()))
                .await?;
        }

        Request::TrustRm { origin } => {
            let origin = parse_origin(&origin)?;
            let removed = node.store().remove_origin_bindings(&origin)?;
            out.line(format!("removed {removed} binding(s) for {origin}"))
                .await?;
        }

        Request::TrustLs => {
            let now = now_ns();
            for binding in node.store().bindings()? {
                out.line(format!(
                    "{:<32} {} {:<7} {}{}",
                    binding.origin.canonical(),
                    binding.node_id.to_z32(),
                    binding.source.as_str(),
                    if binding.is_live(now) {
                        "live"
                    } else {
                        "lapsed"
                    },
                    binding
                        .note
                        .as_ref()
                        .map(|n| format!("  ({n})"))
                        .unwrap_or_default(),
                ))
                .await?;
            }
        }

        Request::DomainAdd { domain } => {
            node.add_domain(&domain)?;
            out.line(format!("added {domain}")).await?;
            refresh_domains(node, out, Some(&domain)).await?;
        }

        Request::DomainRm { domain } => {
            node.remove_domain(&domain)?;
            out.line(format!("removed {domain} and its bindings"))
                .await?;
        }

        Request::DomainLs => {
            for domain in node.domains()? {
                out.line(domain).await?;
            }
        }

        Request::DomainRefresh { domain } => refresh_domains(node, out, domain.as_deref()).await?,

        Request::Peers => {
            let now = now_ns();
            for peer in node.store().peers_seen()? {
                let origins = node.store().live_origins_for_key(&peer.node_id, now)?;
                let names: Vec<String> = origins.iter().map(|o| o.canonical()).collect();
                out.line(format!(
                    "{}  {}  last-seen {}  last-sync {}  rtt {}µs",
                    peer.node_id.to_z32(),
                    if names.is_empty() {
                        "(untrusted)".to_string()
                    } else {
                        names.join(",")
                    },
                    render::ago(peer.last_seen),
                    render::ago(peer.last_sync),
                    peer.latency_ewma_us,
                ))
                .await?;
            }
        }

        Request::SpaceAdd { id, path } => {
            node.add_space(&id, &path)?;
            out.line(format!("indexing {path} as {id}")).await?;
        }

        Request::SpaceLs => {
            for space in node.store().spaces()? {
                out.line(format!("{:<20} {}", space.id, space.local_path))
                    .await?;
            }
        }

        Request::SpaceRm { id } => {
            let staged = node.remove_space(&id)?;
            let removed = staged.len();
            // Explicit commands publish before they answer, so the count they
            // report is one that peers can already see (§7.1).
            node.stage(staged);
            node.flush_staged().await?;
            out.line(format!("removed {id} and unpublished {removed} record(s)"))
                .await?;
        }

        Request::Scan => {
            // Refuse before hashing rather than after: a scan records what it
            // hashed, so a scan whose publish is refused would leave the node
            // believing it had published files it never did (§3.4).
            node.ensure_publishable()?;
            // Hashing a tree is long and blocking, so it runs off the runtime
            // — the daemon keeps serving other requests — and each space is
            // reported as a Progress frame while the scan is still going.
            let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
            let scanning = {
                let node = node.clone();
                tokio::task::spawn_blocking(move || {
                    node.scan_all_with(|space, report| {
                        let _ = progress_tx.send(format!(
                            "scanned {space}: hashed {} · unchanged {} · deleted {}",
                            report.hashed, report.unchanged, report.deleted
                        ));
                    })
                })
            };
            while let Some(line) = progress_rx.recv().await {
                out.progress(line).await?;
            }
            let report = scanning
                .await
                .map_err(|e| ControlError::internal(format!("the scan task failed: {e}")))??;
            // An explicit scan is already one batch, so it stages and then
            // flushes rather than waiting out the quiesce: the "published seq"
            // line below is true by the time the client reads it (§7.1).
            node.stage(report.staged.clone());
            let head = node.flush_staged().await?;
            let mut summary = format!(
                "hashed {} · unchanged {} · deleted {} · ignored {}",
                report.hashed, report.unchanged, report.deleted, report.ignored
            );
            if report.expired > 0 {
                // Only when there is something to say: tombstone expiry is
                // rare and worth naming when it happens (§4.2).
                summary.push_str(&format!(" · expired {}", report.expired));
            }
            out.line(summary).await?;
            for (path, reason) in &report.skipped {
                out.progress(format!("skipped {path}: {reason}")).await?;
            }
            match head {
                Some(head) => {
                    out.line(format!("published seq {} root {}", head.seq, head.root))
                        .await?
                }
                None => out.line("nothing changed").await?,
            }
        }

        Request::Ls { reference, all } => {
            let reference = parse_reference(&reference)?;
            match &reference.origin {
                // The origin-prefixed form lists exactly one origin's view,
                // which is the old per-origin listing (§9.2).
                Some(origin) => {
                    let rows = node.store().list_entries(
                        Some(origin),
                        &reference.space,
                        &reference.dir_prefix(),
                        None,
                        None,
                    )?;
                    for row in &rows {
                        out.line(render::entry_line(row, None)).await?;
                    }
                }
                // The unified tree: one line per path, divergence marked with
                // the number of versions the path carries (§8).
                None => {
                    let listing = node.unified_listing(
                        &reference.space,
                        &reference.dir_prefix(),
                        None,
                        None,
                    )?;
                    for set in &listing {
                        if !set.exists() {
                            // Every publisher has tombstoned it: the path has
                            // left the tree, so the tree does not list it.
                            continue;
                        }
                        for line in render::unified_line(node, set, all)? {
                            out.line(line).await?;
                        }
                    }
                }
            }
        }

        Request::Status { reference } => {
            let (space, path) = match reference {
                Some(text) => {
                    let reference = parse_reference(&text)?;
                    (Some(reference.space), reference.path)
                }
                None => (None, String::new()),
            };
            let spaces = match space {
                Some(space) => vec![space],
                None => node.store().known_spaces()?,
            };
            for space in spaces {
                for set in node.unified_listing(&space, &path, None, None)? {
                    for line in render::version_set(&set) {
                        out.line(line).await?;
                    }
                }
            }
        }

        Request::Cat {
            reference,
            range,
            from,
            strict,
        } => {
            let reference = parse_reference(&reference)?;
            let policy = policy_for(&reference, from.as_deref(), strict)?;
            let range = match &range {
                Some(text) => crate::cli::ByteRange::parse(text)
                    .map_err(|e| ControlError::invalid(e.to_string()))?,
                None => crate::cli::ByteRange {
                    start: 0,
                    end: None,
                },
            };
            stream_entry(
                node,
                out,
                &reference.space,
                &reference.path,
                &policy,
                range.start,
                range.length(),
            )
            .await?;
        }

        Request::Get {
            reference,
            from,
            strict,
        } => {
            let reference = parse_reference(&reference)?;
            let policy = policy_for(&reference, from.as_deref(), strict)?;
            stream_entry(
                node,
                out,
                &reference.space,
                &reference.path,
                &policy,
                0,
                None,
            )
            .await?;
        }

        Request::Take { reference } => {
            let reference = parse_reference(&reference)?;
            let origin = reference.origin.clone().ok_or_else(|| {
                ControlError::invalid("take needs an explicit <origin>:<space>/<path>")
            })?;
            if origin == *node.origin() {
                return Err(ControlError::invalid(
                    "that is already this node's own entry",
                ));
            }
            // A tombstone is an assertion like any other, and §8 makes it
            // adoptable the same way: take the deletion, and let the next scan
            // publish our own.
            let theirs = node.resolve(
                &reference.space,
                &reference.path,
                &VersionPolicy::Origin(origin.clone()),
            )?;
            if theirs.kind == synch_core::EntryKind::Tombstone {
                match node.adopt_deletion(&reference.space, &reference.path)? {
                    Some(path) => {
                        out.line(format!("removed {}", path.display())).await?;
                    }
                    None => {
                        out.line(format!(
                            "{}/{} is already absent here",
                            reference.space, reference.path
                        ))
                        .await?;
                    }
                }
            } else {
                let bytes = node
                    .read_entry(&origin, &reference.space, &reference.path)
                    .await?;
                let path = node.adopt(&reference.space, &reference.path, &bytes)?;
                out.line(format!("adopted into {}", path.display())).await?;
            }
            // `take` publishes before it answers, for the same reason
            // `scan` does: the seq it prints has to be a real one (§7.1).
            match node.scan_publish_push().await? {
                Some(head) => out.line(format!("published seq {}", head.seq)).await?,
                None => {
                    out.line("nothing to publish: this node had no version of that path")
                        .await?
                }
            }
        }

        Request::Log { reference } => {
            let reference = parse_reference(&reference)?;
            if reference.path.is_empty() {
                return Err(ControlError::invalid("log needs a path, not just a space"));
            }
            for line in render::log(node, &reference)? {
                out.line(line).await?;
            }
        }

        Request::MirrorAdd {
            space,
            path,
            policy,
        } => {
            let policy = parse_policy(policy.as_deref())?;
            let stored = node.add_mirror(&space, &path, &policy)?;
            out.line(format!("mirroring {space} into {stored} ({policy})"))
                .await?;
        }

        Request::MirrorRm { path } => {
            if node.remove_mirror(&path)? {
                out.line("removed").await?;
            } else {
                out.line("no such mirror").await?;
            }
        }

        Request::MirrorLs => {
            for mirror in node.store().mirrors()? {
                out.line(format!(
                    "{:<20} {:<24} {}",
                    mirror.space,
                    mirror.policy.render(),
                    mirror.local_path
                ))
                .await?;
            }
        }

        Request::MirrorSync => {
            // One mirror at a time, so the report of each arrives while the
            // next is still being materialized.
            for mirror in node.store().mirrors()? {
                out.progress(format!("{} …", mirror.local_path)).await?;
                let report = node.sync_mirror(&mirror.local_path).await?;
                out.line(format!(
                    "{}  written {} · current {} · removed {} · skipped {}",
                    mirror.local_path,
                    report.written,
                    report.current,
                    report.removed,
                    report.skipped.len()
                ))
                .await?;
                for (path, reason) in &report.skipped {
                    out.progress(format!("  skipped {path}: {reason}")).await?;
                }
            }
        }

        Request::PinAdd { target } => {
            let root = pin_target(node, &target)?;
            node.store().set_pinned(&root, true)?;
            out.line(format!("pinned {root}")).await?;
        }

        Request::PinRm { target } => {
            let root = pin_target(node, &target)?;
            node.store().set_pinned(&root, false)?;
            out.line(format!("unpinned {root}")).await?;
        }

        Request::PinLs => {
            for root in node.store().pinned_blobs()? {
                out.line(root.to_string()).await?;
            }
        }
    }
    Ok(outcome)
}

/// Streams a verified byte range out of the CAS as `Chunk` frames.
///
/// The fetch runs first, so every byte is verified against the object's bao
/// tree before it is committed; the read then walks the window in
/// [`CHUNK_SIZE`] pieces, so neither process ever holds the whole payload.
async fn stream_entry<S: AsyncWrite + Unpin>(
    node: &Node,
    out: &mut Frames<S>,
    space: &str,
    path: &str,
    policy: &VersionPolicy,
    start: u64,
    len: Option<u64>,
) -> Done {
    let range = node.prepare_range(space, path, policy, start, len).await?;
    let mut offset = range.start;
    while offset < range.end {
        let take = (CHUNK_SIZE as u64).min(range.end - offset);
        let bytes = node.store().read_range(&range.root, offset, take)?;
        if bytes.is_empty() {
            break;
        }
        offset += bytes.len() as u64;
        out.chunk(bytes).await?;
    }
    Ok(())
}

/// Runs `synch recover`, streaming a line per collection round (§3.4, §9.3).
///
/// The quiesce is an hour by default, so it must not look like a hung command:
/// each round reports what it reached and how much of the wait is left. The
/// recovery itself runs as a task, and a client that walks away takes it down
/// with it — the floor is set once, deliberately, or not at all.
async fn recover<S: AsyncWrite + Unpin>(
    node: &Node,
    out: &mut Frames<S>,
    wait: Option<String>,
    gap: Option<u64>,
) -> Done {
    let mut options = node.recovery_options();
    if let Some(text) = &wait {
        options.wait = crate::cli::parse_duration(text)
            .map_err(|e| ControlError::invalid(format!("--wait: {e}")))?;
    }
    if let Some(gap) = gap {
        options.gap = gap;
    }
    // Never sleep past the end of the wait, and keep short waits responsive.
    options.poll = options.poll.min(options.wait).max(POLL_FLOOR);

    let state = node.recovery_state()?;
    if state.in_recovery {
        out.line(format!(
            "{} is in recovery: peers advertise a head at seq {}",
            state.origin,
            state
                .observed_seq
                .map(|seq| seq.to_string())
                .unwrap_or_else(|| "-".into())
        ))
        .await?;
    }
    out.line(format!(
        "collecting head summaries from every reachable peer for {}s",
        options.wait.as_secs()
    ))
    .await?;

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
    let recovering = {
        let node = node.clone();
        tokio::spawn(async move { node.recover(options, progress_tx).await })
    };
    while let Some(update) = progress_rx.recv().await {
        if let Err(e) = out.progress(update.to_string()).await {
            // The client hung up mid-quiesce: stop the collection rather than
            // finish an hour of it for nobody.
            recovering.abort();
            return Err(e.into());
        }
    }
    let report = recovering
        .await
        .map_err(|e| ControlError::internal(format!("the recovery task failed: {e}")))??;

    out.line(format!(
        "{} round(s) over {}s · {} peer(s) answered, {} unreachable",
        report.rounds,
        report.waited.as_secs(),
        report.reached,
        report.unreachable
    ))
    .await?;
    match (report.observed_seq, report.floor) {
        (Some(observed), Some(floor)) => {
            out.line(format!(
                "highest seq peers advertised: {observed}; publishing resumes at seq {floor} \
                 ({observed} + gap {})",
                report.gap
            ))
            .await?;
            out.line(
                "peers that were unreachable throughout may still hold newer pre-recovery \
                 history; `synch doctor` reports it as a fork if they return",
            )
            .await?;
        }
        _ => {
            out.line(format!(
                "no peer advertises a head for {}: nothing to recover, publishing starts at seq 1",
                report.origin
            ))
            .await?
        }
    }
    Ok(())
}

async fn refresh_domains<S: AsyncWrite + Unpin>(
    node: &Node,
    out: &mut Frames<S>,
    domain: Option<&str>,
) -> Done {
    // A domain the node was never told about is a typo, and it is refused
    // before a resolver is even built.
    let domain = domain.map(|d| node.configured_domain(d)).transpose()?;
    let resolver = match synch_net::DnssecResolver::from_system() {
        Ok(resolver) => resolver,
        Err(e) => {
            out.progress(format!("no DNSSEC resolver available: {e}"))
                .await?;
            return Ok(());
        }
    };
    match node
        .refresh_domains_named(&resolver, domain.as_deref())
        .await
    {
        Ok(refreshes) => {
            for refresh in refreshes {
                out.line(format!(
                    "{}: {} binding(s), {} rejected record(s), ttl {}s",
                    refresh.domain,
                    refresh.bindings,
                    refresh.rejected,
                    refresh.ttl.as_secs()
                ))
                .await?;
                for key in &refresh.ambiguous {
                    out.progress(format!(
                        "  ambiguous: {} appears under more than one id; \
                         an explicit --id is required",
                        key.to_z32()
                    ))
                    .await?;
                }
            }
        }
        Err(e) => out.progress(format!("refresh failed: {e}")).await?,
    }
    Ok(())
}

fn parse_key(text: &str) -> std::result::Result<NodeId, ControlError> {
    NodeId::from_z32(text)
        .map_err(|_| ControlError::invalid(format!("{text} is not a z-base-32 device key")))
}

fn parse_origin(text: &str) -> std::result::Result<OriginId, ControlError> {
    OriginId::from_str(text).map_err(|e| ControlError::invalid(e.to_string()))
}

fn parse_reference(text: &str) -> std::result::Result<EntryRef, ControlError> {
    text.parse()
        .map_err(|e: synch_engine::EngineError| ControlError::from(e))
}

/// Builds the version policy a read runs under, from the reference and the
/// flags (§8).
///
/// An origin-pinned reference *is* an origin policy, and `--from` is the same
/// thing spelled as a flag, so naming both is a contradiction rather than a
/// preference and is refused.
fn policy_for(
    reference: &EntryRef,
    from: Option<&str>,
    strict: bool,
) -> std::result::Result<VersionPolicy, ControlError> {
    if let Some(origin) = &reference.origin {
        if from.is_some() {
            return Err(ControlError::invalid(
                "the reference already pins an origin; drop --from or the <origin>: prefix",
            ));
        }
        if strict {
            return Err(ControlError::invalid(
                "an origin-pinned reference already names one version; --strict has nothing to refuse",
            ));
        }
        return Ok(VersionPolicy::Origin(origin.clone()));
    }
    match (from, strict) {
        (Some(_), true) => Err(ControlError::invalid(
            "--from and --strict are two answers to the same question; use one",
        )),
        (Some(origin), false) => Ok(VersionPolicy::Origin(parse_origin(origin)?)),
        (None, true) => Ok(VersionPolicy::Strict),
        (None, false) => Ok(VersionPolicy::Newest),
    }
}

/// Parses a stored or typed version policy, defaulting to `newest`.
fn parse_policy(text: Option<&str>) -> std::result::Result<VersionPolicy, ControlError> {
    match text {
        None => Ok(VersionPolicy::Newest),
        Some(text) => text
            .parse()
            .map_err(|e: synch_store::StoreError| ControlError::invalid(e.to_string())),
    }
}

/// What `synch pin add|rm` names: a hex object root, or a path whose selected
/// version supplies one (§8).
///
/// A pin is about bytes, and the bytes a path stands for are whichever version
/// the reading policy picks — the same selection every other read goes
/// through, so a pin and a `synch cat` of the same reference always mean the
/// same object. An `<origin>:` prefix pins that origin's version.
fn pin_target(node: &Node, text: &str) -> std::result::Result<Hash, ControlError> {
    if let Ok(root) = Hash::from_str(text) {
        return Ok(root);
    }
    // A reference always carries a path, so anything without a separator was
    // meant to be a root and is reported as one rather than as a bad space.
    let malformed = || {
        ControlError::invalid(format!(
            "{text} is neither a 64-character hex object root nor a <space>/<path>"
        ))
    };
    if !text.contains('/') {
        return Err(malformed());
    }
    let reference = parse_reference(text).map_err(|_| malformed())?;
    if reference.is_space_root() {
        return Err(malformed());
    }
    let policy = policy_for(&reference, None, false)?;
    let entry = node.resolve(&reference.space, &reference.path, &policy)?;
    entry.content.ok_or_else(|| {
        ControlError::invalid(format!("{text} selects a version with no content to pin"))
    })
}
