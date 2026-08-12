//! The daemon side of the control socket (§9.3).
//!
//! One connection carries one command. The daemon checks the protocol version
//! and the datadir token before it looks at the request, then streams the
//! response back as `Line`, `Chunk`, and `Progress` frames terminated by `End`,
//! or a structured `Error`.

use std::{str::FromStr, sync::Arc};

use synch_core::{now_ns, Hash, NodeId, OriginId};
use synch_engine::{EntryRef, Node};
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
    let result = match dispatch(&node, &stop, request, &mut out).await {
        Ok(()) => out.end().await,
        Err(error) => out.error(error).await,
    };
    let mut stream = out.stream;
    linger(&mut stream).await?;
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

type Handled = std::result::Result<(), ControlError>;

/// Serves one request.
async fn dispatch<S: AsyncWrite + Unpin>(
    node: &Node,
    stop: &broadcast::Sender<()>,
    request: Request,
    out: &mut Frames<S>,
) -> Handled {
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
            for key in node.device_keys()? {
                out.line(format!("{} {}", key.node_id.to_z32(), key.state.as_str()))
                    .await?;
            }
        }

        Request::KeyRotate => {
            let plan = node.rotate_key()?;
            out.line(format!("generated device key {}", plan.new_key.to_z32()))
                .await?;
            match plan.txt_record() {
                Some(record) => {
                    out.line("publish alongside the existing record:").await?;
                    out.line(record).await?;
                    out.line(format!(
                        "then, once it has propagated, run `synch key activate {}`",
                        plan.new_key.to_z32()
                    ))
                    .await?;
                }
                None => {
                    out.line(
                        "this origin is key-identified and cannot rotate; \
                         re-init with --id or have peers `synch trust add --as <name>`",
                    )
                    .await?
                }
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
            let _ = stop.send(());
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
            refresh_domains(node, out).await?;
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

        Request::DomainRefresh => refresh_domains(node, out).await?,

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
            node.publish(staged)?;
            out.line(format!("removed {id} and unpublished {removed} record(s)"))
                .await?;
        }

        Request::Scan => {
            let (report, head) = node.scan_and_publish()?;
            out.line(format!(
                "hashed {} · unchanged {} · deleted {} · ignored {}",
                report.hashed, report.unchanged, report.deleted, report.ignored
            ))
            .await?;
            for (path, reason) in &report.skipped {
                out.progress(format!("skipped {path}: {reason}")).await?;
            }
            match head {
                Some(head) => {
                    out.line(format!("published seq {} root {}", head.seq, head.root))
                        .await?;
                    if let Err(e) = node.push_head(&head).await {
                        tracing::debug!(error = %e, "could not push the new head");
                    }
                }
                None => out.line("nothing changed").await?,
            }
        }

        Request::Ls { reference, all } => {
            let reference = parse_reference(&reference)?;
            let rows = node.store().list_entries(
                reference.origin.as_ref(),
                &reference.space,
                &reference.dir_prefix(),
                None,
                None,
            )?;
            let mut seen: Vec<&str> = Vec::new();
            for row in &rows {
                if !all {
                    if seen.contains(&row.path.as_str()) {
                        continue;
                    }
                    seen.push(&row.path);
                }
                out.line(format!(
                    "{:>12}  {:<8}  {}  {}",
                    row.size,
                    render::kind_name(row.kind),
                    row.path,
                    row.origin.short()
                ))
                .await?;
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
                let rows = node.store().list_entries(None, &space, &path, None, None)?;
                let mut paths: Vec<String> = rows.iter().map(|r| r.path.clone()).collect();
                paths.sort();
                paths.dedup();
                for path in paths {
                    let views = node.store().entries_for_path(&space, &path)?;
                    let roots: std::collections::BTreeSet<Option<Hash>> =
                        views.iter().map(|v| v.content).collect();
                    let agreement = if roots.len() <= 1 {
                        "agree"
                    } else {
                        "DIVERGED"
                    };
                    out.line(format!("{space}/{path}  [{agreement}]")).await?;
                    for view in views {
                        out.line(format!(
                            "    {:<28} seq {:<6} {:>12}  {}",
                            view.origin.short(),
                            view.seq,
                            view.size,
                            view.content
                                .map(|h| h.to_hex()[..16].to_string())
                                .unwrap_or_else(|| render::kind_name(view.kind).to_string()),
                        ))
                        .await?;
                    }
                }
            }
        }

        Request::Cat { reference, range } => {
            let reference = parse_reference(&reference)?;
            let origin = reference.origin.clone().ok_or_else(|| {
                ControlError::invalid("cat needs an explicit <origin>:<space>/<path>")
            })?;
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
                &origin,
                &reference.space,
                &reference.path,
                range.start,
                range.length(),
            )
            .await?;
        }

        Request::Get { reference } => {
            let reference = parse_reference(&reference)?;
            let origin = reference.origin.clone().ok_or_else(|| {
                ControlError::invalid("get needs an explicit <origin>:<space>/<path>")
            })?;
            stream_entry(
                node,
                out,
                &origin,
                &reference.space,
                &reference.path,
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
            let bytes = node
                .read_entry(&origin, &reference.space, &reference.path)
                .await?;
            let path = node.adopt(&reference.space, &reference.path, &bytes)?;
            out.line(format!("adopted into {}", path.display())).await?;
            let (_report, head) = node.scan_and_publish()?;
            if let Some(head) = head {
                if let Err(e) = node.push_head(&head).await {
                    tracing::debug!(error = %e, "could not push the new head");
                }
                out.line(format!("published seq {}", head.seq)).await?;
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

        Request::MirrorAdd { reference, path } => {
            let reference = parse_reference(&reference)?;
            let origin = reference
                .origin
                .clone()
                .ok_or_else(|| ControlError::invalid("mirror add needs <origin>:<space>"))?;
            node.add_mirror(&origin, &reference.space, &path)?;
            out.line(format!(
                "mirroring {origin}:{} into {path}",
                reference.space
            ))
            .await?;
        }

        Request::MirrorRm { reference } => {
            let reference = parse_reference(&reference)?;
            let origin = reference
                .origin
                .clone()
                .ok_or_else(|| ControlError::invalid("mirror rm needs <origin>:<space>"))?;
            if node.remove_mirror(&origin, &reference.space)? {
                out.line("removed").await?;
            } else {
                out.line("no such mirror").await?;
            }
        }

        Request::MirrorLs => {
            for mirror in node.store().mirrors()? {
                out.line(format!(
                    "{}:{:<20} {}",
                    mirror.origin.canonical(),
                    mirror.space,
                    mirror.local_path
                ))
                .await?;
            }
        }

        Request::MirrorSync => {
            for (origin, space, report) in node.sync_all_mirrors().await? {
                out.progress(format!("{origin}:{space} synced")).await?;
                out.line(format!(
                    "{origin}:{space}  written {} · current {} · removed {}",
                    report.written, report.current, report.removed
                ))
                .await?;
                for (path, reason) in &report.skipped {
                    out.progress(format!("  skipped {path}: {reason}")).await?;
                }
            }
        }

        Request::PinAdd { root } => {
            let root = parse_root(&root)?;
            node.store().set_pinned(&root, true)?;
            out.line(format!("pinned {root}")).await?;
        }

        Request::PinRm { root } => {
            let root = parse_root(&root)?;
            node.store().set_pinned(&root, false)?;
            out.line(format!("unpinned {root}")).await?;
        }

        Request::PinLs => {
            for root in node.store().pinned_blobs()? {
                out.line(root.to_string()).await?;
            }
        }
    }
    Ok(())
}

/// Streams a verified byte range out of the CAS as `Chunk` frames.
///
/// The fetch runs first, so every byte is verified against the object's bao
/// tree before it is committed; the read then walks the window in
/// [`CHUNK_SIZE`] pieces, so neither process ever holds the whole payload.
async fn stream_entry<S: AsyncWrite + Unpin>(
    node: &Node,
    out: &mut Frames<S>,
    origin: &OriginId,
    space: &str,
    path: &str,
    start: u64,
    len: Option<u64>,
) -> Handled {
    let range = node
        .prepare_entry_range(origin, space, path, start, len)
        .await?;
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

async fn refresh_domains<S: AsyncWrite + Unpin>(node: &Node, out: &mut Frames<S>) -> Handled {
    let resolver = match synch_net::DnssecResolver::from_system() {
        Ok(resolver) => resolver,
        Err(e) => {
            out.progress(format!("no DNSSEC resolver available: {e}"))
                .await?;
            return Ok(());
        }
    };
    match node.refresh_domains(&resolver).await {
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

fn parse_root(text: &str) -> std::result::Result<Hash, ControlError> {
    Hash::from_str(text)
        .map_err(|_| ControlError::invalid(format!("{text} is not a 64-character hex object root")))
}
