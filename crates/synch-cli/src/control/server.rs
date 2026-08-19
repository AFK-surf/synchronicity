//! The daemon side of the control service (§9.3).
//!
//! Every call is authenticated by the interceptor below — the protocol version
//! and the datadir token, both headers — before a handler sees it. Handlers
//! stream their answer back as it is produced and report a failure as a coded
//! status, so a client renders a daemon-side refusal as its own exit code
//! rather than as a transport error.

use std::{
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

use synch_core::{now_ns, Hash, NodeId, OriginId};
use synch_engine::{EntryRef, Node, VersionPolicy};
use synch_store::{EntryRow, VersionSet};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{
    service::{interceptor::InterceptedService, Interceptor},
    Request, Response, Status, Streaming,
};

use crate::{
    control::{
        proto::{
            pb::{
                self,
                control_server::{Control, ControlServer},
            },
            tokens_match, Command, ControlError, EntryInfo, ErrorCode, PutPart, CHUNK_SIZE,
            CONTROL_VERSION, MAX_MESSAGE_LEN, TOKEN_HEADER, VERSION_HEADER,
        },
        transport::{self, Accepted, Listener},
    },
    render,
};

/// How many accepted connections may wait for the server to pick them up.
const ACCEPT_BACKLOG: usize = 16;

/// How many produced messages may wait for the client to read them.
///
/// The point of the bound is that it exists: a reader that stalls stops the
/// handler that is producing for it within a message or two, so a slow client
/// costs bounded memory rather than a buffered response.
const SEND_AHEAD: usize = 4;

/// Runs a blocking store or filesystem operation off the runtime.
///
/// The daemon serves this service on the same runtime that carries the endpoint,
/// the scanner, and every timer in the process (§9.1). A request that streams an
/// object, rebuilds the derived views, or unpublishes a space does real disk
/// work, and doing it on the worker thread that polled the connection stops that
/// worker from polling anything else for as long as it takes (§10). Requests
/// that only read a handful of indexed rows stay inline.
async fn offload<T, F>(f: F) -> Result<T, ControlError>
where
    F: FnOnce() -> Result<T, ControlError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(e) => Err(ControlError::internal(format!(
            "a blocking task did not complete: {e}"
        ))),
    }
}

/// The shortest gap between recovery collection rounds.
///
/// A quiesce measured in seconds still sleeps between rounds rather than
/// spinning on the peers it is polling.
const POLL_FLOOR: std::time::Duration = std::time::Duration::from_secs(1);

/// How long a stopping daemon waits for its calls to finish before it closes
/// their connections anyway.
///
/// Every handler already ends itself when the stop arrives, so this is only the
/// window their last frame flushes through — the backstop for one that cannot
/// end itself, not a budget anything is expected to spend. The daemon's exit
/// waits on it, so it is small on purpose: `synch daemon stop` competes with
/// every other shutdown task for the operator's patience.
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Runs a handler's work, giving it up when the daemon starts stopping.
///
/// A call must not be able to hold the shutdown open: `synch recover` waits an
/// hour by default, and a gateway read lasts as long as its HTTP client cares
/// to keep reading. Both would otherwise still be running — and still being
/// waited for — long after the operator asked the daemon to stop.
async fn until_stopped<F>(mut stopping: broadcast::Receiver<()>, work: F) -> Done
where
    F: std::future::Future<Output = Done>,
{
    tokio::select! {
        done = work => done,
        _ = stopping.recv() => Err(stopped()),
    }
}

/// A spawned task that is cancelled when the handle goes out of scope.
///
/// Dropping a [`tokio::task::JoinHandle`] detaches its task instead of ending
/// it, which is the wrong default for work that exists only to answer one
/// call: a handler that is cancelled — the client hung up, the daemon is
/// stopping — would leave it running against a node that is being shut down.
#[derive(Debug)]
struct Cancelling<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for Cancelling<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

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
    /// One receiver per job that has to react to it.
    stopping: broadcast::Receiver<()>,
    /// The loop that owns the listener.
    accepting: broadcast::Receiver<()>,
    /// The bound on how long the drain that follows may take.
    draining: broadcast::Receiver<()>,
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
        let accepting = stop.subscribe();
        let draining = stop.subscribe();
        Ok(Server {
            node,
            listener,
            token,
            stop,
            stopping,
            accepting,
            draining,
        })
    }

    /// The socket path or pipe name this server listens on.
    pub fn endpoint_name(&self) -> String {
        transport::endpoint_name(&self.node.config().data_dir)
    }

    /// Serves until `stop` fires — which `synch daemon stop` does by sending on
    /// the same channel.
    ///
    /// The shutdown drains rather than severs: a response on its way out
    /// reaches its client before the connection carrying it closes. Draining is
    /// bounded twice over — each handler gives up when the stop arrives, and a
    /// grace period caps whatever that misses — so `run` returns, and the
    /// daemon exits, however long the call it was serving would have taken.
    pub async fn run(self) -> std::io::Result<()> {
        let Server {
            node,
            mut listener,
            token,
            stop,
            mut stopping,
            mut accepting,
            mut draining,
        } = self;

        let (connections, incoming) = mpsc::channel::<std::io::Result<Accepted>>(ACCEPT_BACKLOG);
        let accepts = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = accepting.recv() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(stream) => {
                            if connections.send(Ok(Accepted::new(stream))).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "control accept failed"),
                    },
                }
            }
            // Handed back rather than dropped: the socket file goes with it,
            // and it must outlive the drain below.
            listener
        });

        let service = InterceptedService::new(
            ControlServer::new(ControlService {
                node: node.clone(),
                stop,
            })
            .max_decoding_message_size(MAX_MESSAGE_LEN)
            .max_encoding_message_size(MAX_MESSAGE_LEN),
            Authenticate { token },
        );

        // Scoped, so that whichever way the drain ends the server future is
        // dropped here rather than left pinned. Giving up on it is not the same
        // as ending it: it owns the connection tasks and the receiving half of
        // `incoming`, and leaving it alive would strand the accept loop below
        // in a send nobody will ever read.
        let served = {
            let serving = tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(ReceiverStream::new(incoming), async move {
                    let _ = stopping.recv().await;
                });
            tokio::pin!(serving);
            tokio::select! {
                served = &mut serving => served,
                _ = async {
                    let _ = draining.recv().await;
                    tokio::time::sleep(DRAIN_GRACE).await;
                } => {
                    tracing::warn!(
                        "a control call was still running {}s after the stop; closing anyway",
                        DRAIN_GRACE.as_secs()
                    );
                    Ok(())
                }
            }
        };

        // The token goes first and the socket last, so the two are never both
        // available to a replacement daemon: while `control.token` exists this
        // socket is still bound, and a `Listener::bind` for this datadir is
        // refused until the last of it is gone. The other order lets a
        // replacement bind, mint its own token, and have this process delete it.
        transport::remove_token(&node.config().data_dir);
        drop(accepts.await);
        served.map_err(std::io::Error::other)
    }
}

/// The version and token check every call passes through.
#[derive(Clone)]
struct Authenticate {
    token: Arc<Vec<u8>>,
}

impl Interceptor for Authenticate {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let claimed = request
            .metadata()
            .get(VERSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u32>().ok());
        if claimed != Some(CONTROL_VERSION) {
            return Err(ControlError::new(
                ErrorCode::VersionMismatch,
                format!(
                    "control protocol mismatch: the client speaks v{}, this daemon speaks v{}. \
                     Restart the daemon so both are the same build",
                    claimed
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".to_string()),
                    CONTROL_VERSION
                ),
            )
            .into());
        }
        let presented = request
            .metadata()
            .get_bin(TOKEN_HEADER)
            .and_then(|value| value.to_bytes().ok());
        match presented {
            Some(bytes) if tokens_match(&bytes, &self.token) => Ok(request),
            _ => Err(ControlError::new(
                ErrorCode::Unauthorized,
                format!(
                    "control token mismatch: re-read {} from this datadir",
                    transport::TOKEN_FILE
                ),
            )
            .into()),
        }
    }
}

/// The service the daemon exposes.
#[derive(Debug)]
struct ControlService {
    node: Node,
    stop: broadcast::Sender<()>,
}

/// Brings the daemon down once the response it is attached to has been
/// delivered.
///
/// `synch daemon stop` has to report what happened, so the stop is tied to the
/// life of the answer rather than sent from the handler that produced it.
#[derive(Debug)]
struct StopOnDrop(broadcast::Sender<()>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

/// A command's output, plus whatever the command left for the connection to do
/// once it has all been read.
#[derive(Debug)]
pub struct RunStream {
    inner: ReceiverStream<Result<pb::Frame, Status>>,
    /// Dropped with the stream, once tonic has delivered the last frame.
    stop: Option<StopOnDrop>,
}

impl Stream for RunStream {
    type Item = Result<pb::Frame, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl Drop for RunStream {
    /// tonic drops the response stream once it has delivered every frame, so
    /// this is the moment a `daemon stop` has been answered.
    fn drop(&mut self) {
        drop(self.stop.take());
    }
}

/// The stream every other streaming call answers with.
type Items<T> = ReceiverStream<Result<T, Status>>;

#[tonic::async_trait]
impl Control for ControlService {
    type RunStream = RunStream;
    type ListStream = Items<pb::Entry>;
    type ReadStream = Items<pb::Chunk>;
    type PutStream = Items<pb::Written>;

    async fn run(
        &self,
        request: Request<pb::Command>,
    ) -> Result<Response<Self::RunStream>, Status> {
        let command = request
            .into_inner()
            .kind
            .ok_or_else(|| Status::from(ControlError::invalid("the request named no command")))?;
        // Known before the command runs, so the answer and the shutdown it
        // triggers are wired together rather than raced.
        let stops = matches!(command, Command::DaemonStop(_));
        let (tx, rx) = mpsc::channel(SEND_AHEAD);
        let node = self.node.clone();
        let stopping = self.stop.subscribe();
        tokio::spawn(async move {
            let failed = {
                let mut out = Frames { tx: tx.clone() };
                until_stopped(stopping, dispatch(&node, command, &mut out)).await
            };
            if let Err(error) = failed {
                let _ = tx.send(Err(error.into())).await;
            }
        });
        Ok(Response::new(RunStream {
            inner: ReceiverStream::new(rx),
            stop: stops.then(|| StopOnDrop(self.stop.clone())),
        }))
    }

    async fn list(
        &self,
        request: Request<pb::ListRequest>,
    ) -> Result<Response<Self::ListStream>, Status> {
        let request = request.into_inner();
        let policy = parse_policy(request.policy.as_deref())?;
        let node = self.node.clone();
        let listing = node
            .unified_listing(
                &request.space,
                &request.prefix,
                request.start_after.as_deref(),
                request.limit.map(|n| n as usize),
            )
            .map_err(ControlError::from)?;
        let (tx, rx) = mpsc::channel(SEND_AHEAD);
        let mut stopping = self.stop.subscribe();
        tokio::spawn(async move {
            for set in &listing {
                // A listing of a large space outlives a stop otherwise.
                if stopping.try_recv() != Err(broadcast::error::TryRecvError::Empty) {
                    let _ = tx.send(Err(stopped().into())).await;
                    return;
                }
                if !set.exists() {
                    // Every publisher has tombstoned it: the path has left the
                    // tree, so the tree does not list it.
                    continue;
                }
                // A listing has no way to answer one path with an error, so a
                // path the policy refuses is left out rather than reported with
                // one side's metadata. Resolving that path still says exactly
                // what is wrong.
                let Ok(row) = node.resolve_set(set, &policy) else {
                    continue;
                };
                if tx.send(Ok(entry_info(&row, set).into())).await.is_err() {
                    return;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn resolve(
        &self,
        request: Request<pb::ResolveRequest>,
    ) -> Result<Response<pb::Entry>, Status> {
        let request = request.into_inner();
        let policy = parse_policy(request.policy.as_deref())?;
        let set = self
            .node
            .versions(&request.space, &request.path)
            .map_err(ControlError::from)?;
        let row = self
            .node
            .resolve_set(&set, &policy)
            .map_err(ControlError::from)?;
        Ok(Response::new(entry_info(&row, &set).into()))
    }

    async fn read(
        &self,
        request: Request<pb::ReadRequest>,
    ) -> Result<Response<Self::ReadStream>, Status> {
        let request = request.into_inner();
        let policy = parse_policy(request.policy.as_deref())?;
        let node = self.node.clone();
        // Resolved before the response opens, so "no provider for the content"
        // or a strict policy's refusal is the call's own answer rather than a
        // stream that dies after the caller has committed to a success.
        let range = node
            .prepare_range(
                &request.space,
                &request.path,
                &policy,
                request.start,
                request.len,
            )
            .await
            .map_err(ControlError::from)?;
        let (tx, rx) = mpsc::channel(SEND_AHEAD);
        let stopping = self.stop.subscribe();
        tokio::spawn(async move {
            let read = async {
                let mut out = Bytes::Chunks(&tx);
                stream_range(&node, &mut out, range).await
            };
            if let Err(error) = until_stopped(stopping, read).await {
                let _ = tx.send(Err(error.into())).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Receives a streamed write and publishes it (§7.1, §9.4).
    ///
    /// The recovery gate is taken before a byte is written, for the reason
    /// `scan` takes it before hashing: a node that cannot publish would
    /// otherwise accept the upload, write it into the space, and lose it
    /// (§3.4). Taking it before the response opens is what lets the refusal
    /// reach a client that has not started streaming yet.
    async fn put(
        &self,
        request: Request<Streaming<pb::PutRequest>>,
    ) -> Result<Response<Self::PutStream>, Status> {
        let mut incoming = request.into_inner();
        let header = match incoming.message().await?.and_then(|first| first.part) {
            Some(PutPart::Header(header)) => header,
            _ => return Err(ControlError::invalid("a write opens with its space and path").into()),
        };
        self.node.ensure_publishable().map_err(ControlError::from)?;
        let adoption = self
            .node
            .open_adoption(&header.space, &header.path)
            .map_err(ControlError::from)?;

        let (tx, rx) = mpsc::channel(1);
        let node = self.node.clone();
        let mut stopping = self.stop.subscribe();
        tokio::spawn(async move {
            // A write the daemon gives up on is one it keeps nothing of: the
            // staging file goes with the dropped `Adoption`, exactly as an
            // abandoned upload's does.
            let written = tokio::select! {
                written = receive(&node, incoming, adoption, &header) => written,
                _ = stopping.recv() => Err(stopped()),
            };
            match written {
                Ok(written) => {
                    let _ = tx.send(Ok(written)).await;
                }
                Err(error) => {
                    let _ = tx.send(Err(error.into())).await;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_config(
        &self,
        request: Request<pb::GetConfigRequest>,
    ) -> Result<Response<pb::GetConfigResponse>, Status> {
        let request = request.into_inner();
        let key = gateway_config_key(&request.key)?;
        let records = match self.node.store().config(key).map_err(ControlError::from)? {
            Some(value) => value.lines().map(str::to_string).collect(),
            None => Vec::new(),
        };
        Ok(Response::new(pb::GetConfigResponse { records }))
    }

    async fn append_config(
        &self,
        request: Request<pb::AppendConfigRequest>,
    ) -> Result<Response<pb::AppendConfigResponse>, Status> {
        let request = request.into_inner();
        let key = gateway_config_key(&request.key)?;
        if request.record.contains('\n') {
            return Err(ControlError::invalid(
                "a config record is one line: newlines separate records",
            )
            .into());
        }
        self.node
            .store()
            .append_config(key, &request.record)
            .map_err(ControlError::from)?;
        Ok(Response::new(pb::AppendConfigResponse {}))
    }
}

/// The output side of a running command.
#[derive(Debug)]
struct Frames {
    tx: mpsc::Sender<Result<pb::Frame, Status>>,
}

impl Frames {
    async fn line(&mut self, text: impl Into<String>) -> Done {
        self.send(pb::frame::Payload::Line(text.into())).await
    }

    async fn chunk(&mut self, bytes: Vec<u8>) -> Done {
        self.send(pb::frame::Payload::Chunk(bytes)).await
    }

    async fn progress(&mut self, text: impl Into<String>) -> Done {
        self.send(pb::frame::Payload::Progress(text.into())).await
    }

    async fn send(&mut self, payload: pb::frame::Payload) -> Done {
        self.tx
            .send(Ok(pb::Frame {
                payload: Some(payload),
            }))
            .await
            .map_err(|_| gone())
    }
}

/// Where a streamed byte payload goes: into a command's output, or into a
/// structured read's own stream.
enum Bytes<'a> {
    Frames(&'a mut Frames),
    Chunks(&'a mpsc::Sender<Result<pb::Chunk, Status>>),
}

impl Bytes<'_> {
    async fn chunk(&mut self, bytes: Vec<u8>) -> Done {
        match self {
            Bytes::Frames(frames) => frames.chunk(bytes).await,
            Bytes::Chunks(tx) => tx
                .send(Ok(pb::Chunk { data: bytes }))
                .await
                .map_err(|_| gone()),
        }
    }
}

/// The daemon is stopping, which ends the work it was doing for a client.
fn stopped() -> ControlError {
    ControlError::new(
        ErrorCode::Unavailable,
        "the daemon is shutting down; this request did not finish",
    )
}

/// The client stopped reading, which ends the work being done for it.
fn gone() -> ControlError {
    ControlError::new(
        ErrorCode::Unavailable,
        "the client stopped reading the response",
    )
}

/// What a helper that only writes output returns.
type Done = Result<(), ControlError>;

/// Serves one CLI subcommand.
async fn dispatch(node: &Node, command: Command, out: &mut Frames) -> Done {
    match command {
        Command::Id(pb::Id {}) => {
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

        Command::KeyLs(pb::KeyLs {}) => {
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

        Command::KeyRotate(pb::KeyRotate {}) => {
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

        Command::KeyActivate(pb::KeyActivate { key, bind }) => {
            let key = parse_key(&key)?;
            let bind = bind
                .map(|text| {
                    text.parse::<std::net::SocketAddr>()
                        .map_err(|_| ControlError::invalid("--bind wants HOST:PORT"))
                })
                .transpose()?;
            let had_fixed_bind = bind.is_none()
                && node
                    .config()
                    .net
                    .bind_addr
                    .is_some_and(|addr| addr.port() != 0);
            let activation = node.activate_key(&key, bind).await?;
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
            if had_fixed_bind {
                // The configured address stayed with the retiring endpoint; a
                // static-address deployment that expected the daemon's --bind
                // to keep meaning "this node" has to be told it moved.
                out.line(
                    "note: the configured bind address still serves the retiring key; \
                     the new key took an ephemeral port. Pass `--bind` to \
                     `synch key activate` to choose it, and update peers' \
                     `trust add --addr` to the address above",
                )
                .await?;
            }
            // Peers learn the re-signed head at the next round anyway; pushing
            // makes the switch visible immediately where reachable.
            if let Err(e) = node.push_head(&activation.head).await {
                tracing::debug!(error = %e, "could not push the re-signed head");
            }
        }

        Command::KeyRetire(pb::KeyRetire { key }) => {
            let key = parse_key(&key)?;
            node.retire_key(&key).await?;
            out.line(format!(
                "retired {}: endpoint closed and secret deleted",
                key.to_z32()
            ))
            .await?;
        }

        Command::Recover(pb::Recover { wait, gap }) => recover(node, out, wait, gap).await?,

        // Status is the glance, doctor is the examination: two commands with
        // the same output would make one of them a lie of emphasis.
        Command::DaemonStatus(pb::DaemonStatus {}) => {
            let origin = node.origin();
            out.line(format!(
                "origin {origin} · signing as {}",
                node.node_id().fmt_short()
            ))
            .await?;
            out.line(format!(
                "address: {}",
                render::addr(&node.net().direct_addr())
            ))
            .await?;
            let spaces = node.store().spaces()?;
            let names: Vec<&str> = spaces.iter().map(|s| s.id.as_str()).collect();
            out.line(format!(
                "spaces: {} ({}) · mirrors: {}",
                spaces.len(),
                names.join(", "),
                node.store().mirrors()?.len()
            ))
            .await?;
            let head = node.store().complete_head(origin)?;
            out.line(format!(
                "head: {} · peers seen: {}",
                head.map(|h| format!("seq {}", h.seq))
                    .unwrap_or_else(|| "none published yet".into()),
                node.store().peers_seen()?.len()
            ))
            .await?;
            // Which trust this daemon is actually enforcing. Every knob here
            // is settable by environment variable, so this line is what
            // distinguishes a `require` daemon from a `--rekor off` one.
            out.line(format!(
                "trust: {}",
                render::trust_summary(&node.resolver_status())
            ))
            .await?;
            let clock = node.store().clock_status(now_ns())?;
            if !clock.trusted {
                out.line(
                    "CLOCK UNUSABLE: the host clock cannot date a trust decision, so no DNS \
                     binding is honored and membership is not extended; static trust is \
                     unaffected. Set the clock (see `synch doctor`)",
                )
                .await?;
            } else if clock.stepped_back {
                out.line(
                    "CLOCK STEPPED BACK: trust decisions are dated by the highest reading this \
                     node recorded, not by the current one (see `synch doctor`)",
                )
                .await?;
            }
            let recovery = node.recovery_state()?;
            if recovery.in_recovery {
                out.line(format!(
                    "IN RECOVERY: a peer advertises seq {} for {origin}; run `synch recover`",
                    recovery.observed_seq.unwrap_or_default()
                ))
                .await?;
            }
            out.line("(`synch doctor` for the full examination)")
                .await?;
        }

        Command::Doctor(pb::Doctor { rebuild }) => {
            if rebuild {
                // A rebuild re-materializes every leaf of every origin's trie.
                let rebuilding = node.clone();
                let n = offload(move || Ok(rebuilding.rebuild_views()?)).await?;
                out.line(format!("rebuilt {n} derived rows from the trie"))
                    .await?;
            }
            // The examination asks the trie whether each origin's root is held
            // whole — a full walk the first time it is asked of a root — and
            // counts every entry of every space to do it.
            let examining = node.clone();
            for line in offload(move || render::doctor(&examining)).await? {
                out.line(line).await?;
            }
        }

        Command::DaemonStop(pb::DaemonStop {}) => {
            out.line("stopping").await?;
        }

        Command::TrustAdd(pb::TrustAdd {
            key,
            name,
            domain,
            note,
            addr,
        }) => {
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

        Command::TrustRebind(pb::TrustRebind { origin, key }) => {
            let origin = parse_origin(&origin)?;
            let key = parse_key(&key)?;
            let earlier: Vec<String> = node
                .store()
                .bindings()?
                .into_iter()
                .filter(|b| b.origin == origin && b.node_id != key)
                .map(|b| b.node_id.to_z32())
                .collect();
            node.trust_rebind(&origin, key)?;
            out.line(format!("{origin} now also accepts {}", key.to_z32()))
                .await?;
            // Rebinding is additive on purpose — the rotation window needs
            // both keys live — but the old binding will stall every dial once
            // its endpoint dies, and nothing else says whose job that is.
            for old in earlier {
                out.line(format!(
                    "{old} stays bound through the rotation window; drop it with \
                     `synch trust rm {origin} --key {old}` once the peer retires it"
                ))
                .await?;
            }
        }

        Command::TrustRm(pb::TrustRm { origin, key }) => {
            let origin = parse_origin(&origin)?;
            match key {
                Some(key) => {
                    let key = parse_key(&key)?;
                    if !node.store().remove_key_binding(&origin, &key)? {
                        return Err(ControlError::new(
                            ErrorCode::NotFound,
                            format!("{origin} has no binding to {}", key.to_z32()),
                        ));
                    }
                    out.line(format!("removed {origin}'s binding to {}", key.to_z32()))
                        .await?;
                }
                None => {
                    let removed = node.store().remove_origin_bindings(&origin)?;
                    // "removed 0 binding(s)" with exit 0 is the cheerful lie
                    // the rest of the rm family refuses to tell.
                    if removed == 0 {
                        return Err(ControlError::new(
                            ErrorCode::NotFound,
                            format!("no bindings for {origin}"),
                        ));
                    }
                    out.line(format!("removed {removed} binding(s) for {origin}"))
                        .await?;
                }
            }
        }

        Command::TrustLs(pb::TrustLs {}) => {
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
                    // "(self)" is a status; an operator's --note is quoted so
                    // the two can never be misread as each other.
                    binding
                        .note
                        .as_ref()
                        .map(|n| {
                            if n == "self" {
                                "  (self)".to_string()
                            } else {
                                format!("  note {n:?}")
                            }
                        })
                        .unwrap_or_default(),
                ))
                .await?;
            }
        }

        Command::DomainAdd(pb::DomainAdd { domain }) => {
            node.add_domain(&domain)?;
            out.line(format!("added {domain}")).await?;
            // Lenient: the add stands even when the first refresh fails —
            // configuring a domain before its records are published is a
            // legitimate order of operations.
            refresh_domains(node, out, Some(&domain), false).await?;
        }

        Command::DomainRm(pb::DomainRm { domain }) => {
            if !node.remove_domain(&domain)? {
                return Err(ControlError::new(
                    ErrorCode::NotFound,
                    format!("{domain} is not a configured membership domain"),
                ));
            }
            out.line(format!("removed {domain} and its bindings"))
                .await?;
        }

        Command::DomainLs(pb::DomainLs {}) => {
            let domains = node.domain_health()?;
            if domains.is_empty() {
                out.progress("(no membership domains configured; static trust only)")
                    .await?;
            }
            for health in domains {
                out.line(render::domain_health(&health, now_ns())).await?;
            }
        }

        // Strict: a failed refresh is a failed command. Scripts and
        // monitoring read the exit code, not the prose.
        Command::DomainRefresh(pb::DomainRefresh { domain }) => {
            refresh_domains(node, out, domain.as_deref(), true).await?
        }

        Command::Peers(pb::Peers {}) => {
            let now = now_ns();
            let seen = node.store().peers_seen()?;
            if seen.is_empty() {
                // On stderr, as every empty listing here is: a human learns
                // the silence is "nothing yet", a script still gets clean
                // stdout to parse.
                out.progress("(no peers seen yet)").await?;
            }
            for peer in seen {
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

        Command::SpaceAdd(pb::SpaceAdd { id, path }) => {
            // A typo'd path otherwise becomes a fresh empty directory with no
            // signal; creating it is a feature, doing so silently is not.
            let created = !std::path::Path::new(&path).is_dir();
            node.add_space(&id, &path)?;
            out.line(format!("indexing {path} as {id}")).await?;
            if created {
                out.line(format!("note: created {path}, which did not exist"))
                    .await?;
            }
        }

        Command::SpaceLs(pb::SpaceLs {}) => {
            let spaces = node.store().spaces()?;
            if spaces.is_empty() {
                out.progress("(no local spaces; add one with `synch space add`)")
                    .await?;
            }
            for space in spaces {
                out.line(format!("{:<20} {}", space.id, space.local_path))
                    .await?;
            }
        }

        Command::SpaceRm(pb::SpaceRm { id }) => {
            // Unpublishing a space scans its whole prefix out of the trie.
            let removing = node.clone();
            let removed_id = id.clone();
            let staged = offload(move || Ok(removing.remove_space(&removed_id)?)).await?;
            let removed = staged.len();
            // Explicit commands publish before they answer, so the count they
            // report is one that peers can already see (§7.1).
            node.stage(staged);
            node.flush_staged().await?;
            out.line(format!("removed {id} and unpublished {removed} record(s)"))
                .await?;
        }

        Command::Scan(pb::Scan {}) => {
            // Refuse before hashing rather than after: a scan records what it
            // hashed, so a scan whose publish is refused would leave the node
            // believing it had published files it never did (§3.4).
            node.ensure_publishable()?;
            // Hashing a tree is long and blocking, so it runs off the runtime
            // — the daemon keeps serving other requests — and each space is
            // reported as a progress message while the scan is still going.
            let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
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

        Command::Ls(pb::Ls { reference, all }) => {
            let reference = parse_reference(&reference)?;
            // An unknown space and an empty listing print the same nothing,
            // and only one of them is fine: silence must mean "empty", never
            // "you misspelled it and nobody said so".
            ensure_known_space(node, &reference.space)?;
            if let Some(origin) = &reference.origin {
                ensure_known_origin(node, origin)?;
            }
            match &reference.origin {
                // The origin-prefixed form lists exactly one origin's view,
                // which is the per-origin listing (§9.2).
                Some(origin) => {
                    // Unlimited, so the query is the size of the space.
                    let store = node.store().clone();
                    let origin = origin.clone();
                    let space = reference.space.clone();
                    let prefix = reference.dir_prefix();
                    let rows = offload(move || {
                        Ok(store.list_entries(Some(&origin), &space, &prefix, None, None)?)
                    })
                    .await?;
                    for row in &rows {
                        out.line(render::entry_line(row, None)).await?;
                    }
                }
                // The unified tree: one line per path, divergence marked with
                // the number of versions the path carries (§8).
                None => {
                    let listing = {
                        let listing = node.clone();
                        let space = reference.space.clone();
                        let prefix = reference.dir_prefix();
                        offload(move || Ok(listing.unified_listing(&space, &prefix, None, None)?))
                            .await?
                    };
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

        Command::Status(pb::Status { reference }) => {
            let (space, path) = match reference {
                Some(text) => {
                    let reference = parse_reference(&text)?;
                    (Some(reference.space), reference.path)
                }
                None => (None, String::new()),
            };
            let explicit = space.is_some();
            let spaces = match space {
                Some(space) => {
                    ensure_known_space(node, &space)?;
                    vec![space]
                }
                None => node.store().known_spaces()?,
            };
            let mut printed = false;
            for space in &spaces {
                for set in node.unified_listing(space, &path, None, None)? {
                    for line in render::version_set(&set) {
                        out.line(line).await?;
                        printed = true;
                    }
                }
            }
            // A named path that matches nothing is an answer, not a shrug: an
            // empty exit-0 status is indistinguishable from "fine". A bare
            // space stays quiet when empty — the space check above already
            // vouched that it exists.
            if explicit && !path.is_empty() && !printed {
                return Err(ControlError::new(
                    ErrorCode::NotFound,
                    format!(
                        "no origin publishes {}/{path}",
                        spaces.first().map(String::as_str).unwrap_or_default()
                    ),
                ));
            }
        }

        Command::Cat(pb::Cat {
            reference,
            range,
            from,
            strict,
        }) => {
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
            let prepared = node
                .prepare_range(
                    &reference.space,
                    &reference.path,
                    &policy,
                    range.start,
                    range.length(),
                )
                .await?;
            stream_range(node, &mut Bytes::Frames(out), prepared).await?;
        }

        Command::Get(pb::Get {
            reference,
            from,
            strict,
        }) => {
            let reference = parse_reference(&reference)?;
            let policy = policy_for(&reference, from.as_deref(), strict)?;
            let prepared = node
                .prepare_range(&reference.space, &reference.path, &policy, 0, None)
                .await?;
            stream_range(node, &mut Bytes::Frames(out), prepared).await?;
        }

        Command::Take(pb::Take { reference }) => {
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
                // Streamed into the space directly out of the CAS: `take` of a
                // multi-gigabyte file costs a chunk of memory, not a copy of
                // the object (§9.4).
                let path = node
                    .adopt_from(&origin, &reference.space, &reference.path)
                    .await?;
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

        Command::Log(pb::Log { reference }) => {
            let reference = parse_reference(&reference)?;
            if reference.path.is_empty() {
                return Err(ControlError::invalid("log needs a path, not just a space"));
            }
            for line in render::log(node, &reference)? {
                out.line(line).await?;
            }
        }

        Command::Compare(pb::Compare {
            reference,
            from,
            to,
            json,
        }) => {
            let reference = parse_reference(&reference)?;
            // Origins are named by --from/--to, never on the reference itself:
            // an origin-pinned reference would be a third, contradictory way to
            // say the same thing.
            if reference.origin.is_some() {
                return Err(ControlError::invalid(
                    "compare takes a space, not an origin-pinned reference; name origins with --from and --to",
                ));
            }
            let from = match &from {
                Some(text) => parse_origin(text)?,
                None => node.origin().clone(),
            };
            let to = parse_origin(&to)?;
            if from == to {
                return Err(ControlError::invalid(
                    "--from and --to name the same origin; nothing to compare",
                ));
            }
            // A comparison materializes both origins' listings in full.
            let comparing = node.clone();
            let space = reference.space.clone();
            let prefix = reference.dir_prefix();
            let report =
                offload(move || Ok(comparing.compare(&space, &prefix, &from, &to)?)).await?;
            for line in render::compare(&report, json) {
                out.line(line).await?;
            }
        }

        Command::MirrorAdd(pb::MirrorAdd {
            space,
            path,
            policy,
        }) => {
            let policy = parse_policy(policy.as_deref())?;
            let stored = node.add_mirror(&space, &path, &policy)?;
            out.line(format!("mirroring {space} into {stored} ({policy})"))
                .await?;
            // Configuring the mirror before the space first syncs is a
            // legitimate order of operations; doing it to a typo'd id is not,
            // and nothing else in the exchange tells the two apart.
            if ensure_known_space(node, &space).is_err() {
                out.line(format!(
                    "note: no origin publishes {space} yet; the mirror stays empty until one does"
                ))
                .await?;
            }
        }

        Command::MirrorRm(pb::MirrorRm { path }) => {
            if !node.remove_mirror(&path)? {
                return Err(ControlError::new(
                    ErrorCode::NotFound,
                    format!("no mirror at {path}"),
                ));
            }
            out.line("removed").await?;
        }

        Command::MirrorLs(pb::MirrorLs {}) => {
            let mirrors = node.store().mirrors()?;
            if mirrors.is_empty() {
                out.progress("(no mirrors configured)").await?;
            }
            for mirror in mirrors {
                out.line(format!(
                    "{:<20} {:<24} {}",
                    mirror.space,
                    mirror.policy.render(),
                    mirror.local_path
                ))
                .await?;
            }
        }

        Command::MirrorSync(pb::MirrorSync {}) => {
            // One mirror at a time, so the report of each arrives while the
            // next is still being materialized.
            for mirror in node.store().mirrors()? {
                out.progress(format!("{} …", mirror.local_path)).await?;
                let report = node.sync_mirror(&mirror.local_path).await?;
                out.line(format!(
                    "{}  written {} · current {} · retouched {} · removed {} · skipped {}",
                    mirror.local_path,
                    report.written,
                    report.current,
                    report.retouched,
                    report.removed,
                    report.skipped.len()
                ))
                .await?;
                if report.reused_bytes > 0 || report.reflinked > 0 {
                    // Only when there is something to say: a pass that reused
                    // nothing and shared nothing is the ordinary case and needs
                    // no extra line.
                    out.line(format!(
                        "{}  reused {} B · fetched {} B · reflinked {}",
                        mirror.local_path,
                        report.reused_bytes,
                        report.fetched_bytes,
                        report.reflinked
                    ))
                    .await?;
                }
                for (path, reason) in &report.skipped {
                    out.progress(format!("  skipped {path}: {reason}")).await?;
                }
            }
        }

        Command::PinAdd(pb::PinAdd { target }) => {
            let (root, size) = pin_target(node, &target)?;
            node.pin_object(&root, size).await?;
            out.line(format!("pinned {root}")).await?;
        }

        Command::PinRm(pb::PinRm { target }) => {
            let (root, _) = pin_target(node, &target)?;
            if !node.store().set_pinned(&root, false)? {
                return Err(ControlError::new(
                    ErrorCode::NotFound,
                    format!("no object {root} in the local store"),
                ));
            }
            out.line(format!("unpinned {root}")).await?;
        }

        Command::PinLs(pb::PinLs {}) => {
            let pinned = node.store().pinned_blobs()?;
            if pinned.is_empty() {
                out.progress("(nothing pinned)").await?;
            }
            for root in pinned {
                // A bare hash answers "what is pinned" without answering
                // "what is it": the size and the paths currently naming the
                // object are what make the list reviewable.
                let size = node
                    .store()
                    .blob(&root)?
                    .map(|b| format!("{} B", b.size))
                    .unwrap_or_else(|| "(bytes not held)".into());
                let paths = node.store().paths_naming(&root)?;
                out.line(format!(
                    "{root}  {size}  {}",
                    if paths.is_empty() {
                        "(no current entry names it)".to_string()
                    } else {
                        paths.join(" · ")
                    }
                ))
                .await?;
            }
        }

        Command::CloudEnable(pb::CloudEnable {}) => {
            node.enable_cloud()?;
            let spaces = node.store().spaces()?;
            out.line(format!(
                "cloud attach enabled: serving the control plane's requests for {}",
                if spaces.is_empty() {
                    "(no local spaces)".to_string()
                } else {
                    spaces
                        .iter()
                        .map(|s| s.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ))
            .await?;
            let domains = node.domains()?;
            if domains.is_empty() {
                // Nothing to attach to and nothing that will change that on
                // its own: the endpoint comes from a membership zone, so a
                // node with no membership domain has nowhere to look.
                out.line(
                    "note: no membership domains are configured, so there is no zone to \
                     discover a control plane from; `synch domain add <domain>` first",
                )
                .await?;
            }
            for domain in domains {
                out.line(format!(
                    "{domain}: discovering _synchronicity-cp at its apex (`synch cloud status`)"
                ))
                .await?;
            }
        }

        Command::CloudDisable(pb::CloudDisable {}) => {
            node.disable_cloud()?;
            out.line("cloud attach disabled; any open tunnel is dropped")
                .await?;
        }

        Command::CloudStatus(pb::CloudStatus {}) => {
            let settings = node.cloud_settings()?;
            let state = if settings.disabled {
                "disabled (opted out)"
            } else {
                "enabled"
            };
            out.line(format!("cloud: {state}")).await?;
            let status = node.cloud_status();
            if status.is_empty() {
                out.progress("(no attach attempts yet)").await?;
            }
            for domain in status {
                out.line(format!(
                    "{:<32} {:<10} {}{}",
                    domain.domain,
                    if domain.attached {
                        "attached"
                    } else {
                        "detached"
                    },
                    domain
                        .endpoint
                        .as_deref()
                        .unwrap_or("(no validated _synchronicity-cp record)"),
                    domain
                        .last_error
                        .as_ref()
                        .map(|why| format!("  last error: {why}"))
                        .unwrap_or_default(),
                ))
                .await?;
            }
        }

        Command::SyncNow(pb::SyncNow {}) => {
            let peers = node.dialable_peers()?;
            if peers.is_empty() {
                out.line("no dialable peers: nothing to sync with").await?;
            }
            // All dials go out together: a dead peer costs its own connect
            // timeout, not a serial stall for every peer queued behind it.
            let attempted = peers.len();
            let mut rounds = tokio::task::JoinSet::new();
            for peer in peers {
                let node = node.clone();
                rounds.spawn(async move {
                    let outcome = node.sync_with_peer(&peer).await;
                    (peer, outcome)
                });
            }
            // Streamed in completion order, not sorted: ten seconds of
            // silence while the fast peers' answers wait on the slowest dial
            // reads as a hang, and every line names its peer anyway.
            let mut reached = 0usize;
            let now = now_ns();
            while let Some(joined) = rounds.join_next().await {
                let (peer, outcome) =
                    joined.map_err(|e| ControlError::internal(format!("sync round: {e}")))?;
                // The peer as the operator knows it — the origins its key is
                // bound to — with the key for disambiguation, not as the name.
                let origins = node.store().live_origins_for_key(&peer, now)?;
                let name = if origins.is_empty() {
                    "(unnamed key)".to_string()
                } else {
                    origins
                        .iter()
                        .map(|o| o.canonical())
                        .collect::<Vec<_>>()
                        .join(",")
                };
                match outcome {
                    Ok(report) => {
                        reached += 1;
                        // §12 makes an origin this node cannot apply fail that
                        // origin and no other, and says the count of origins
                        // left behind is in the sync report. Counted but not
                        // printed, the one visible sign of a peer publishing
                        // something unapplicable would be a `warn!` line in the
                        // daemon log. Only shown when non-zero: a healthy sync
                        // should not grow a column of zeroes.
                        let left_behind = if report.heads_failed > 0 {
                            format!(" · {} origin(s) left behind", report.heads_failed)
                        } else {
                            String::new()
                        };
                        out.line(format!(
                            "{name} ({})  accepted {} head(s) · completed {} origin trie(s) · pushed {}{left_behind}",
                            peer.fmt_short(),
                            report.heads_accepted,
                            report.tries_completed,
                            report.heads_pushed,
                        ))
                        .await?;
                    }
                    // One unreachable peer must not hide what the others said.
                    Err(e) => {
                        out.line(format!("{name} ({})  unreachable: {e}", peer.fmt_short()))
                            .await?
                    }
                }
            }
            // Nothing to sync with is fine; reaching nothing is not, and
            // scripts read the exit code, not the prose.
            if attempted > 0 && reached == 0 {
                return Err(ControlError::new(
                    ErrorCode::Unavailable,
                    format!("none of the {attempted} dialable peer(s) could be reached"),
                ));
            }
        }
    }
    Ok(())
}

/// Consumes an upload, commits it, and publishes what it wrote (§7.1, §9.4).
async fn receive(
    node: &Node,
    mut incoming: Streaming<pb::PutRequest>,
    mut adoption: synch_engine::Adoption,
    header: &pb::PutHeader,
) -> Result<pb::Written, ControlError> {
    let mut committed = false;
    while !committed {
        let part = match incoming.message().await {
            Ok(Some(request)) => request.part,
            // The client stopped sending without committing. That is an
            // abandoned write however it came about — a dropped handle, a
            // process that died — and the staging file goes with the dropped
            // `Adoption`: a partly received body must never be mistaken for a
            // complete object.
            Ok(None) => {
                return Err(ControlError::invalid(format!(
                    "the write was abandoned after {} byte(s): it was never committed",
                    adoption.written()
                )))
            }
            // The same, with the transport's account of what went wrong.
            Err(status) => {
                return Err(ControlError::invalid(format!(
                    "the write was abandoned after {} byte(s): {}",
                    adoption.written(),
                    status.message()
                )))
            }
        };
        match part {
            // Each piece is a write to the staging file, so it goes off the
            // runtime: the upload is the size of the object, and the worker
            // thread polling this connection is also serving every other one.
            // The staging handle travels into the blocking pool and back.
            Some(PutPart::Chunk(bytes)) => {
                adoption = offload(move || {
                    adoption.write(&bytes)?;
                    Ok(adoption)
                })
                .await?;
            }
            Some(PutPart::Commit(pb::Commit {})) => committed = true,
            Some(PutPart::Abort(why)) => {
                return Err(ControlError::invalid(format!(
                    "the write was abandoned after {} byte(s): {why}",
                    adoption.written()
                )))
            }
            Some(PutPart::Header(_)) => {
                return Err(ControlError::invalid(
                    "a write names its space and path once",
                ))
            }
            None => continue,
        }
    }
    // The commit fsyncs the payload and renames it into place.
    let target = offload(move || Ok(adoption.commit()?)).await?;

    // The ordinary indexing pipeline takes it from here: hash, CAS, stage,
    // publish. A write answers with a published seq for the same reason `scan`
    // does — the entry it reports has to be one peers can already see.
    node.scan_publish_push().await?;
    let ours = VersionPolicy::Origin(node.origin().clone());
    let set = node.versions(&header.space, &header.path)?;
    let row = node.resolve_set(&set, &ours)?;
    Ok(pb::Written {
        path: target.display().to_string(),
        entry: Some(entry_info(&row, &set).into()),
    })
}

/// Renders one selected entry as the metadata a structured client reads.
fn entry_info(row: &EntryRow, set: &VersionSet) -> EntryInfo {
    EntryInfo {
        origin: row.origin.canonical(),
        space: row.space.clone(),
        path: row.path.clone(),
        kind: row.kind,
        size: row.size,
        mtime_ns: row.mtime_ns,
        content: row.content,
        seq: row.seq,
        symlink_target: row.symlink_target.clone(),
        versions: set.version_count() as u32,
    }
}

/// The config namespace a control client may read and append to (§9.4).
///
/// The `config` table also holds this node's identity and its schema version,
/// so the gateway's buckets and access keys cannot live there unfenced: a
/// client that could name any key could read one row to reach another. `s3.` is
/// the whole of the fence, and it is checked here rather than at each call site
/// so there is one place to be wrong.
fn gateway_config_key(key: &str) -> Result<&str, ControlError> {
    if key.starts_with("s3.") && key.len() > 3 {
        Ok(key)
    } else {
        Err(ControlError::invalid(format!(
            "{key} is not in the s3.* config namespace"
        )))
    }
}

/// Streams a verified byte range out of the CAS.
///
/// The fetch has already run, so every byte is verified against the object's
/// bao tree before it is committed; the read then walks the window in
/// [`CHUNK_SIZE`] pieces, so neither process ever holds the whole payload.
async fn stream_range(
    node: &Node,
    out: &mut Bytes<'_>,
    range: synch_engine::PreparedRange,
) -> Done {
    let mut offset = range.start;
    while offset < range.end {
        let take = (CHUNK_SIZE as u64).min(range.end - offset);
        // Every piece is a verified read out of the CAS — payload and outboard
        // off disk — so it runs on the blocking pool rather than on the worker
        // polling this connection.
        let store = node.store().clone();
        let root = range.root;
        let bytes = offload(move || Ok(store.read_range(&root, offset, take)?)).await?;
        if bytes.is_empty() {
            break;
        }
        offset += bytes.len() as u64;
        out.chunk(bytes).await?;
    }
    Ok(())
}

/// Runs `synch recover`, reporting each collection round (§3.4, §9.3).
///
/// The quiesce is an hour by default, so it must not look like a hung command:
/// each round reports what it reached and how much of the wait is left. The
/// recovery itself runs as a task, and a client that walks away takes it down
/// with it — the floor is set once, deliberately, or not at all.
async fn recover(node: &Node, out: &mut Frames, wait: Option<String>, gap: Option<u64>) -> Done {
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

    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    // Cancelled with this call rather than detached: an hour of collection is
    // worth nobody's time once whoever asked for it has gone — the client hung
    // up mid-quiesce, or the daemon is stopping.
    let mut recovering = Cancelling({
        let node = node.clone();
        tokio::spawn(async move { node.recover(options, progress_tx).await })
    });
    while let Some(update) = progress_rx.recv().await {
        out.progress(update.to_string()).await?;
    }
    let report = (&mut recovering.0)
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

/// Refuses a space no local configuration and no origin's entries know.
///
/// An unknown space and an empty one print the same nothing; this is what
/// keeps that silence meaning "empty" rather than "misspelled".
fn ensure_known_space(node: &Node, space: &str) -> Result<(), ControlError> {
    if node.store().spaces()?.iter().any(|s| s.id == space)
        || node.store().known_spaces()?.iter().any(|s| s == space)
    {
        return Ok(());
    }
    Err(ControlError::new(
        ErrorCode::NotFound,
        format!("no space {space}: not a local space, and no origin publishes one"),
    ))
}

/// Refuses an origin this node holds no binding for and is not itself.
fn ensure_known_origin(node: &Node, origin: &OriginId) -> Result<(), ControlError> {
    if node.origin() == origin || node.store().bindings()?.iter().any(|b| &b.origin == origin) {
        return Ok(());
    }
    Err(ControlError::new(
        ErrorCode::NotFound,
        format!("unknown origin {origin}: no binding for it (see `synch trust ls`)"),
    ))
}

async fn refresh_domains(
    node: &Node,
    out: &mut Frames,
    domain: Option<&str>,
    strict: bool,
) -> Done {
    // A domain the node was never told about is a typo, and it is refused
    // before a resolver is even built.
    let domain = domain.map(|d| node.configured_domain(d)).transpose()?;
    let requested = match &domain {
        Some(domain) => vec![domain.clone()],
        None => node.domains()?,
    };
    if requested.is_empty() {
        out.line("no membership domains configured; nothing to refresh (static trust only)")
            .await?;
        return Ok(());
    }
    // The daemon's own resolver — the same object its scheduled refreshes use,
    // not a fresh one per request. A resolver carries when it last walked the
    // TUF repository, and that "once a day even when the repository is down"
    // bound only holds if the resolver outlives the request (§10.2): a fresh one
    // here would re-attempt the whole walk at 30 s per file with Sigstore
    // unreachable, blocking the request for minutes.
    let resolver = match node.dns_resolver() {
        Some(resolver) => resolver,
        None => {
            let why = match node.resolver_status() {
                synch_engine::ResolverStatus::Failed(why) => {
                    format!("no DNSSEC resolver available: {why}")
                }
                _ => "this process runs no membership resolver".into(),
            };
            out.line(why.clone()).await?;
            if strict {
                return Err(ControlError::new(ErrorCode::Unavailable, why));
            }
            return Ok(());
        }
    };
    let outcomes = node
        .refresh_domains_named(resolver.as_ref(), domain.as_deref())
        .await?;
    let mut failed = 0usize;
    for outcome in &outcomes {
        match &outcome.result {
            Ok(refresh) => {
                out.line(format!(
                    "{}: {} binding(s), {} rejected record(s), ttl {}s",
                    refresh.domain,
                    refresh.bindings,
                    refresh.rejected,
                    refresh.ttl.as_secs()
                ))
                .await?;
                // Lines, not progress: an ambiguity drops every binding the key
                // would have created, so it is a result of the refresh and not
                // a note about how it went. `synch doctor` holds it too, since
                // the scheduled refreshes have nobody to tell.
                for key in &refresh.ambiguous {
                    out.line(format!(
                        "  AMBIGUOUS: {} appears under more than one id; every binding it \
                         would create was dropped and that member is not trusted",
                        key.to_z32()
                    ))
                    .await?;
                }
                if let Some(origin) = &refresh.self_origin_mismatch {
                    out.line(format!(
                        "  MISMATCH: this node's device key is published as {origin}, but it \
                         publishes as {} — one of the two has to change or it syncs nothing",
                        node.origin()
                    ))
                    .await?;
                }
            }
            // The reason itself, not a pointer at the daemon log: "DNSSEC
            // bogus", "no records", and "resolver down" each demand a
            // different response from whoever is reading.
            Err(why) => {
                failed += 1;
                out.line(format!("{}: {why} — cached bindings kept", outcome.domain))
                    .await?;
            }
        }
    }
    if strict && failed > 0 {
        return Err(ControlError::new(
            ErrorCode::Unavailable,
            format!("{failed} of {} domain(s) failed to refresh", outcomes.len()),
        ));
    }
    Ok(())
}

fn parse_key(text: &str) -> Result<NodeId, ControlError> {
    NodeId::from_z32(text)
        .map_err(|_| ControlError::invalid(format!("{text} is not a z-base-32 device key")))
}

fn parse_origin(text: &str) -> Result<OriginId, ControlError> {
    OriginId::from_str(text).map_err(|e| ControlError::invalid(e.to_string()))
}

fn parse_reference(text: &str) -> Result<EntryRef, ControlError> {
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
) -> Result<VersionPolicy, ControlError> {
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
fn parse_policy(text: Option<&str>) -> Result<VersionPolicy, ControlError> {
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
fn pin_target(node: &Node, text: &str) -> Result<(Hash, Option<u64>), ControlError> {
    if let Ok(root) = Hash::from_str(text) {
        return Ok((root, None));
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
    let root = entry.content.ok_or_else(|| {
        ControlError::invalid(format!("{text} selects a version with no content to pin"))
    })?;
    Ok((root, Some(entry.size)))
}
