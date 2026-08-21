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
use synch_engine::{replica::UNREACHABLE_ATTEMPTS, EntryRef, Node, VersionPolicy};
use synch_store::{EntryRow, ReplicaPolicy, VersionSet};
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
            tokens_match, Command, ControlError, EntryInfo, ErrorCode, PutPart, UploadPartPart,
            CHUNK_SIZE, CONTROL_VERSION, MAX_MESSAGE_LEN, TOKEN_HEADER, VERSION_HEADER,
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
/// worker from polling anything else for as long as it takes (§10). What stays
/// on the runtime worker is what touches neither the store nor the disk:
/// in-memory node state, and selection over a version set already in hand.
async fn offload<T, F>(f: F) -> Result<T, ControlError>
where
    F: FnOnce() -> Result<T, ControlError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        f()
    })
    .await
    {
        Ok(result) => result,
        Err(e) => Err(ControlError::internal(format!(
            "a blocking task did not complete: {e}"
        ))),
    }
}

/// Reads node or store state on the blocking pool.
///
/// Every `Store` acquisition waits on the one global connection mutex, so a
/// read here parks a runtime worker for as long as whatever is writing holds
/// it — however few rows the read itself touches (§10). The daemon serves this
/// service on the same runtime as the endpoint and the anti-entropy timers, so
/// that worker is one the cluster is waiting on. There is deliberately no
/// "short enough to stay inline" exception: which reads are short is a
/// judgement, and `Store::conn`'s own assertion is what makes the rule
/// checkable instead.
async fn read<T, F>(node: &Node, f: F) -> Result<T, ControlError>
where
    F: FnOnce(Node) -> Result<T, ControlError> + Send + 'static,
    T: Send + 'static,
{
    let node = node.clone();
    offload(move || f(node)).await
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
    served: Served,
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
        Server::bind_served(Served::Named(node), stop).await
    }

    /// Binds the socket for a node whose zone has not named it yet (§3.1).
    ///
    /// The reduced service: enough to explain the state and to change the zone
    /// this node waits on, and a refusal naming both for everything else.
    pub async fn bind_pending(
        pending: Pending,
        stop: broadcast::Sender<()>,
    ) -> std::io::Result<Server> {
        Server::bind_served(Served::Pending(pending), stop).await
    }

    async fn bind_served(served: Served, stop: broadcast::Sender<()>) -> std::io::Result<Server> {
        let data_dir = served.data_dir();
        let listener = Listener::bind(&data_dir).await?;
        let token = Arc::new(transport::write_token(&data_dir)?);
        let stopping = stop.subscribe();
        let accepting = stop.subscribe();
        let draining = stop.subscribe();
        Ok(Server {
            served,
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
        transport::endpoint_name(&self.served.data_dir())
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
            served: serving,
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
                served: serving.clone(),
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
        transport::remove_token(&serving.data_dir());
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
    served: Served,
    stop: broadcast::Sender<()>,
}

/// What a control service has to serve with.
///
/// A node whose zone has not named it yet holds no [`Node`] — there is no
/// origin to key anything by — but it must still answer the control socket
/// (§3.1). Without that, the one command that can lift the state,
/// `synch domain set`, would need the socket that the state prevents binding:
/// a data directory whose configured zone is wrong could never be corrected,
/// and its key, its published history and its content would be unreachable.
#[derive(Debug, Clone)]
enum Served {
    /// The node is named and everything is available.
    Named(Node),
    /// The node is waiting for its zone to name it: only the commands that do
    /// not need an identity are answered (§3.1).
    Pending(Pending),
}

/// The little a daemon knows about itself before its zone has named it.
#[derive(Debug, Clone)]
pub struct Pending {
    /// The data directory, which is where the socket lives.
    pub data_dir: std::path::PathBuf,
    /// The store, for the config reads and writes `domain set` needs.
    pub store: std::sync::Arc<synch_store::Store>,
    /// This node's active device key, which is what a record must name.
    pub node_id: synch_core::NodeId,
    /// The zone that has not named it.
    pub domain: String,
    /// Rung by `synch domain refresh` so the wait is re-checked at once
    /// rather than on its next tick (§3.1).
    pub recheck: std::sync::Arc<tokio::sync::Notify>,
}

impl Served {
    /// The node, or a refusal naming the state and the way out of it.
    fn node(&self) -> Result<&Node, ControlError> {
        match self {
            Served::Named(node) => Ok(node),
            Served::Pending(pending) => Err(pending.refusal()),
        }
    }

    /// The data directory, which both states have.
    fn data_dir(&self) -> std::path::PathBuf {
        match self {
            Served::Named(node) => node.config().data_dir.clone(),
            Served::Pending(pending) => pending.data_dir.clone(),
        }
    }
}

impl Pending {
    /// The refusal every command that needs an identity gets.
    fn refusal(&self) -> ControlError {
        ControlError::new(
            ErrorCode::Unavailable,
            format!(
                "{} has not named this node yet, so it has no identity to act under. \
                 Publish a record for it:\n  _synchronicity.{}. IN TXT \
                 \"v=sync1 id=<name> nk={} apex=<apex>\"\nor point this node at another \
                 zone with `synch domain set <domain>`",
                self.domain,
                self.domain,
                self.node_id.to_z32()
            ),
        )
    }
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
        let served = self.served.clone();
        let stopping = self.stop.subscribe();
        tokio::spawn(async move {
            let failed = {
                let mut out = Frames { tx: tx.clone() };
                match &served {
                    Served::Named(node) => {
                        until_stopped(stopping, dispatch(node, command, &mut out)).await
                    }
                    Served::Pending(pending) => {
                        until_stopped(stopping, dispatch_pending(pending, command, &mut out)).await
                    }
                }
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
        let node = self.served.node()?.clone();
        // The listing and the instant its rows select against, together: the
        // resolve below runs on a runtime worker, where a store read aborts
        // (§10), and one reading per page keeps every path in it consistent.
        let (listing, now) = {
            let space = request.space.clone();
            let prefix = request.prefix.clone();
            let after = request.start_after.clone();
            let limit = request.limit.map(|n| n as usize);
            read(&node, move |n| {
                Ok((
                    n.unified_listing(&space, &prefix, after.as_deref(), limit)?,
                    n.store().read_instant()?,
                ))
            })
            .await?
        };
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
                let Ok(row) = node.resolve_set(set, &policy, now) else {
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
        let (set, now) = read(self.served.node()?, move |n| {
            Ok((
                n.versions(&request.space, &request.path)?,
                n.store().read_instant()?,
            ))
        })
        .await?;
        // Selection itself reads nothing: the version set and the instant it
        // selects against are both already in hand, so it stays on this task.
        let row = self
            .served
            .node()?
            .resolve_set(&set, &policy, now)
            .map_err(ControlError::from)?;
        Ok(Response::new(entry_info(&row, &set).into()))
    }

    async fn read(
        &self,
        request: Request<pb::ReadRequest>,
    ) -> Result<Response<Self::ReadStream>, Status> {
        let request = request.into_inner();
        let policy = parse_policy(request.policy.as_deref())?;
        let node = self.served.node()?.clone();
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
        read(self.served.node()?, |n| Ok(n.ensure_publishable()?)).await?;
        let adoption = {
            let (space, path) = (header.space.clone(), header.path.clone());
            read(self.served.node()?, move |n| {
                Ok(n.open_adoption(&space, &path)?)
            })
            .await?
        };

        let (tx, rx) = mpsc::channel(1);
        let node = self.served.node()?.clone();
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

    // ---- multipart upload (§9.4) -----------------------------------------

    async fn create_upload(
        &self,
        request: Request<pb::CreateUploadRequest>,
    ) -> Result<Response<pb::CreateUploadResponse>, Status> {
        let request = request.into_inner();
        // The publish gate first: a node that cannot publish cannot finish this
        // upload, and telling the client now is better than telling it after it
        // has streamed the object (§3.4).
        let node = self.served.node()?.clone();
        node.ensure_publishable().map_err(ControlError::from)?;
        // The target is resolved now, so a path outside every space, or one
        // `normalize_path` refuses, fails here rather than after the bytes.
        let target = node
            .upload_target(&request.space, &request.path)
            .map_err(ControlError::from)?;
        let (space, path) = (request.space.clone(), request.path.clone());
        let principal = principal(&request.principal);
        let id = offload(move || {
            Ok(node.create_upload(&space, &path, principal.as_deref(), &target)?)
        })
        .await?;
        Ok(Response::new(pb::CreateUploadResponse { upload_id: id }))
    }

    type UploadPartStream =
        Pin<Box<dyn Stream<Item = Result<pb::UploadPartResponse, Status>> + Send>>;

    async fn upload_part(
        &self,
        request: Request<Streaming<pb::UploadPartRequest>>,
    ) -> Result<Response<Self::UploadPartStream>, Status> {
        let mut incoming = request.into_inner();
        let header = match incoming.message().await?.and_then(|first| first.part) {
            Some(UploadPartPart::Header(header)) => header,
            _ => {
                return Err(ControlError::invalid("a part opens with its upload and number").into())
            }
        };
        let reference = header.upload.unwrap_or_default();
        // No publish gate: a part publishes nothing. What it does need is an
        // upload that is still open and a part number S3 defines, both taken
        // before the response opens so a refusal reaches a client that has not
        // started streaming yet.
        let staging = self
            .served
            .node()?
            .open_part(
                &reference.upload_id,
                &reference.space,
                &reference.path,
                principal(&reference.principal).as_deref(),
                header.number,
            )
            .map_err(ControlError::from)?;

        let (tx, rx) = mpsc::channel(1);
        let node = self.served.node()?.clone();
        let mut stopping = self.stop.subscribe();
        tokio::spawn(async move {
            // A part the daemon gives up on is one it keeps nothing of: the
            // staging file goes with the dropped `Adoption`.
            let recorded = tokio::select! {
                recorded = receive_part(&node, incoming, staging) => recorded,
                _ = stopping.recv() => Err(stopped()),
            };
            match recorded {
                Ok(part) => {
                    let _ = tx.send(Ok(part)).await;
                }
                Err(error) => {
                    let _ = tx.send(Err(error.into())).await;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn delete(
        &self,
        request: Request<pb::DeleteRequest>,
    ) -> Result<Response<pb::DeleteResponse>, Status> {
        let request = request.into_inner();
        let node = self.served.node()?.clone();
        let deleted = node
            .delete_object(&request.space, &request.path)
            .await
            .map_err(ControlError::from)?;
        Ok(Response::new(pb::DeleteResponse {
            removed: deleted.removed,
            still_published: deleted.still_published,
        }))
    }

    async fn complete_upload(
        &self,
        request: Request<pb::CompleteUploadRequest>,
    ) -> Result<Response<pb::CompleteUploadResponse>, Status> {
        let request = request.into_inner();
        let reference = request.upload.unwrap_or_default();
        // Taken again here, not only at creation: an upload may have been open
        // for days, and a node that entered recovery in the meantime must not
        // publish what it collected before (§3.4).
        let node = self.served.node()?.clone();
        node.ensure_publishable().map_err(ControlError::from)?;
        let mut named = Vec::with_capacity(request.parts.len());
        for part in &request.parts {
            let root = match part.root.len() {
                0 => None,
                32 => Some(Hash::from(
                    <[u8; 32]>::try_from(part.root.as_slice()).expect("32"),
                )),
                other => {
                    return Err(ControlError::invalid(format!(
                        "part {} named a {other}-byte root",
                        part.number
                    ))
                    .into())
                }
            };
            named.push((part.number, root));
        }
        // Spawned, not awaited in place. A completion runs a full assembly and a
        // publish, and the caller's socket timing out mid-way is routine — and
        // would drop this future, leaving the latch set with no error path to
        // clear it and an assembly still running on a blocking thread that
        // nothing is waiting for. Detaching it means the state machine always
        // reaches one of its ends, whatever the client does.
        let (upload_id, space, path) = (
            reference.upload_id.clone(),
            reference.space.clone(),
            reference.path.clone(),
        );
        let principal = principal(&reference.principal);
        let completing = tokio::spawn(async move {
            node.complete_upload(&upload_id, &space, &path, principal.as_deref(), &named)
                .await
        });
        let completed = completing
            .await
            .map_err(|e| ControlError::internal(format!("the completion did not finish: {e}")))?
            .map_err(ControlError::from)?;
        Ok(Response::new(pb::CompleteUploadResponse {
            etag: completed.root.as_bytes().to_vec(),
            size: completed.size,
            replayed: completed.replayed,
        }))
    }

    async fn abort_upload(
        &self,
        request: Request<pb::AbortUploadRequest>,
    ) -> Result<Response<pb::AbortUploadResponse>, Status> {
        let reference = request.into_inner().upload.unwrap_or_default();
        let existed = self
            .served
            .node()?
            .abort_upload_durable(
                &reference.upload_id,
                &reference.space,
                &reference.path,
                principal(&reference.principal).as_deref(),
            )
            .await
            .map_err(ControlError::from)?;
        Ok(Response::new(pb::AbortUploadResponse { existed }))
    }

    type ListUploadsStream = Pin<Box<dyn Stream<Item = Result<pb::UploadInfo, Status>> + Send>>;

    async fn list_uploads(
        &self,
        request: Request<pb::ListUploadsRequest>,
    ) -> Result<Response<Self::ListUploadsStream>, Status> {
        let request = request.into_inner();
        let node = self.served.node()?.clone();
        let uploads = offload(move || {
            Ok(node.open_uploads(
                &request.space,
                &request.prefix,
                principal(&request.principal).as_deref(),
            )?)
        })
        .await?;
        let stream = tokio_stream::iter(uploads.into_iter().map(|upload| {
            Ok(pb::UploadInfo {
                upload_id: upload.id,
                path: upload.path,
                created_ns: upload.created_ns,
            })
        }));
        Ok(Response::new(Box::pin(stream)))
    }

    type ListPartsStream = Pin<Box<dyn Stream<Item = Result<pb::PartInfo, Status>> + Send>>;

    async fn list_parts(
        &self,
        request: Request<pb::ListPartsRequest>,
    ) -> Result<Response<Self::ListPartsStream>, Status> {
        let reference = request.into_inner().upload.unwrap_or_default();
        let node = self.served.node()?.clone();
        let parts = offload(move || {
            Ok(node.upload_parts(
                &reference.upload_id,
                &reference.space,
                &reference.path,
                principal(&reference.principal).as_deref(),
            )?)
        })
        .await?;
        let stream = tokio_stream::iter(parts.into_iter().map(|part| {
            Ok(pb::PartInfo {
                number: part.number,
                size: part.size,
                root: part.root.as_bytes().to_vec(),
                created_ns: part.created_ns,
            })
        }));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_config(
        &self,
        request: Request<pb::GetConfigRequest>,
    ) -> Result<Response<pb::GetConfigResponse>, Status> {
        let request = request.into_inner();
        let key = gateway_config_key(&request.key)?.to_string();
        let records = match read(self.served.node()?, move |n| Ok(n.store().config(&key)?)).await? {
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
        let key = gateway_config_key(&request.key)?.to_string();
        if request.record.contains('\n') {
            return Err(ControlError::invalid(
                "a config record is one line: newlines separate records",
            )
            .into());
        }
        let record = request.record;
        read(self.served.node()?, move |n| {
            Ok(n.store().append_config(&key, &record)?)
        })
        .await?;
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

/// Serves the commands that mean something to a node with no name yet (§3.1).
///
/// Everything else is refused with the record that would settle the state and
/// the command that would point the node at a different zone. `domain set` is
/// the one that matters: without it here, a data directory whose configured
/// zone is wrong could not be corrected at all, because the socket that carries
/// the correction is the socket this state would otherwise never bind.
async fn dispatch_pending(pending: &Pending, command: Command, out: &mut Frames) -> Done {
    /// The store reads and writes below go to the blocking pool like every
    /// other one (§10).
    async fn store<T, F>(pending: &Pending, f: F) -> Result<T, ControlError>
    where
        F: FnOnce(&synch_store::Store) -> Result<T, ControlError> + Send + 'static,
        T: Send + 'static,
    {
        let store = pending.store.clone();
        offload(move || f(&store)).await
    }

    match command {
        Command::DomainSet(pb::DomainSet { domain, delegate }) => {
            let name = synch_core::origin::normalize_domain(&domain)
                .map_err(|e| ControlError::invalid(e.to_string()))?;
            let stored = name.clone();
            store(pending, move |s| {
                s.set_membership_domain(Some(&stored))
                    .map_err(|e| ControlError::new(ErrorCode::Internal, e.to_string()))?;
                s.set_membership_expects_name(!delegate)
                    .map_err(|e| ControlError::new(ErrorCode::Internal, e.to_string()))
            })
            .await?;
            out.line(format!("membership domain is {name}")).await?;
            out.line("takes effect at the next `synch daemon run`")
                .await?;
            for line in domain_set_advice(&name, pending.node_id, delegate) {
                out.line(line).await?;
            }
        }

        Command::DomainClear(pb::DomainClear {}) => {
            store(pending, move |s| {
                s.set_membership_domain(None)
                    .map_err(|e| ControlError::new(ErrorCode::Internal, e.to_string()))
            })
            .await?;
            out.line("membership domain cleared").await?;
            out.line("the device key names this node at the next `synch daemon run`")
                .await?;
        }

        Command::DomainLs(pb::DomainLs {}) => {
            let configured = store(pending, |s| {
                s.membership_domain()
                    .map_err(|e| ControlError::new(ErrorCode::Internal, e.to_string()))
            })
            .await?;
            match configured {
                Some(domain) => {
                    out.line(format!("pending: {domain} at the next `synch daemon run`"))
                        .await?
                }
                None => {
                    out.progress("(no membership domain; static trust only)")
                        .await?
                }
            }
        }

        Command::Id(pb::Id {}) => {
            out.line("origin: none — this node has no name yet").await?;
            out.line(format!("  {} (active)", pending.node_id.to_z32()))
                .await?;
            out.line(format!("waiting on: {}", pending.domain)).await?;
        }

        // What `doctor` can say here is the state itself, which is the whole
        // of what is wrong.
        Command::Doctor(pb::Doctor { .. }) | Command::DaemonStatus(pb::DaemonStatus {}) => {
            out.line(format!("waiting for {} to name this node", pending.domain))
                .await?;
            out.line(format!(
                "  _synchronicity.{}. IN TXT \"v=sync1 id=<name> nk={} apex=<apex>\"",
                pending.domain,
                pending.node_id.to_z32()
            ))
            .await?;
            out.line("or `synch domain set <domain>` to wait on another zone")
                .await?;
        }

        Command::DomainRefresh(pb::DomainRefresh {}) => {
            // There is nothing to refresh *bindings* from until this node has
            // a name, so what this asks for here is the identity check itself.
            pending.recheck.notify_one();
            out.line(format!("re-asking {} now", pending.domain))
                .await?;
        }

        Command::DaemonStop(pb::DaemonStop {}) => {
            out.line("stopping").await?;
        }

        _ => return Err(pending.refusal()),
    }
    Ok(())
}

/// What an operator has to do about a membership domain they just set (§3.1).
///
/// A zone names its members; setting the domain does not ask to be named. So a
/// node pointed at a zone with no record for its key comes back up with no
/// name and waits — correctly, and unhelpfully, if the operator has already
/// walked away. Both handlers say this, because a node without a name serves
/// the reduced socket and a node with one serves the full one.
///
/// Except for a delegate, which is *defined* by that zone not naming it
/// (§3.5). Telling it to publish a record would contradict the flag the
/// operator just passed, so it is told what its own case actually needs.
fn domain_set_advice(domain: &str, node_id: NodeId, delegate: bool) -> Vec<String> {
    if delegate {
        return vec![
            format!("this node is a delegate of {domain}: it resolves that zone's members and"),
            "expects no record naming itself, so it keeps its device key as its name".into(),
            format!(
                "an issuer in {domain} grants it spaces with `synch delegate add {}`",
                node_id.to_z32()
            ),
            "`synch domain set <domain>` without --delegate if it should be named after all".into(),
        ];
    }
    vec![
        format!("{domain} must name this key, or this node comes up with no name and waits:"),
        format!(
            "  _synchronicity.{domain}. IN TXT \"v=sync1 id=<name> nk={} apex=<apex>\"",
            node_id.to_z32()
        ),
        "  (or `synch domain set {domain} --delegate` if it is not meant to be named)"
            .replace("{domain}", domain),
        "`synch domain clear` returns this node to its device key as its name".into(),
    ]
}

/// Serves one CLI subcommand.
async fn dispatch(node: &Node, command: Command, out: &mut Frames) -> Done {
    match command {
        Command::Id(pb::Id {}) => {
            out.line(format!("origin: {}", node.origin())).await?;
            for key in read(node, |n| Ok(n.device_keys()?)).await? {
                out.line(format!(
                    "  {} ({})",
                    key.node_id.to_z32(),
                    key.state.as_str()
                ))
                .await?;
            }
            // Where the name came from, and every name before it. A zone can
            // relabel this node unattended (§3.1), so the trail is the only
            // place that says it happened.
            match node.origin().domain() {
                Some(domain) => out.line(format!("named by: {domain}")).await?,
                None => {
                    out.line("named by: this device key (no membership domain)")
                        .await?
                }
            }
            for adoption in read(node, |n| Ok(n.identity_history()?)).await? {
                out.line(match &adoption.previous {
                    Some(previous) => format!(
                        "  adopted {} from {} {} (was {previous})",
                        adoption.adopted,
                        adoption.domain,
                        render::ago(adoption.at)
                    ),
                    None => format!(
                        "  adopted {} from {} {}",
                        adoption.adopted,
                        adoption.domain,
                        render::ago(adoption.at)
                    ),
                })
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
            for key in read(node, |n| Ok(n.device_keys()?)).await? {
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
            let plan = read(node, |n| Ok(n.rotate_key()?)).await?;
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
            let spaces = read(node, |n| Ok(n.store().spaces()?)).await?;
            let names: Vec<&str> = spaces.iter().map(|s| s.id.as_str()).collect();
            out.line(format!(
                "spaces: {} ({}) · mirrors: {}",
                spaces.len(),
                names.join(", "),
                read(node, |n| Ok(n.store().mirrors()?.len())).await?
            ))
            .await?;
            let head = {
                let origin = origin.clone();
                read(node, move |n| Ok(n.store().complete_head(&origin)?)).await?
            };
            out.line(format!(
                "head: {} · peers seen: {}",
                head.map(|h| format!("seq {}", h.seq))
                    .unwrap_or_else(|| "none published yet".into()),
                read(node, |n| Ok(n.store().peers_seen()?.len())).await?
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
            let clock = read(node, |n| Ok(n.store().clock_status(now_ns())?)).await?;
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
            let recovery = read(node, |n| Ok(n.recovery_state()?)).await?;
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

        Command::TrustAdd(pb::TrustAdd { key, note, addr }) => {
            let key = parse_key(&key)?;
            let origin = read(node, move |n| Ok(n.trust_add(key, note.as_deref())?)).await?;
            if let Some(addr) = addr {
                let socket = addr
                    .parse()
                    .map_err(|_| ControlError::invalid("--addr wants HOST:PORT"))?;
                read(node, move |n| {
                    Ok(n.remember_peer(&iroh::EndpointAddr::new(key).with_ip_addr(socket))?)
                })
                .await?;
            }
            out.line(format!("trusted {} as {origin}", key.to_z32()))
                .await?;
        }

        Command::TrustRm(pb::TrustRm { origin, key }) => {
            let origin = parse_origin(&origin)?;
            match key {
                Some(key) => {
                    let key = parse_key(&key)?;
                    let owned = origin.clone();
                    if !read(node, move |n| {
                        Ok(n.store().remove_key_binding(&owned, &key)?)
                    })
                    .await?
                    {
                        return Err(ControlError::new(
                            ErrorCode::NotFound,
                            format!("{origin} has no binding to {}", key.to_z32()),
                        ));
                    }
                    out.line(format!("removed {origin}'s binding to {}", key.to_z32()))
                        .await?;
                }
                None => {
                    let owned = origin.clone();
                    let removed = read(node, move |n| {
                        Ok(n.store().remove_origin_bindings(&owned)?)
                    })
                    .await?;
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
            // Liveness comes from the cascade, not from the date alone: a
            // delegated binding whose issuer has been removed is dead, and
            // printing it as live is the invisible half of the hole §3.5
            // exists to close. Both reads travel together, on the one hop off
            // the runtime this command owes the store.
            type LiveKey = (String, Vec<u8>, &'static str);
            let (live, bindings) = read(node, move |n| {
                let live: std::collections::HashSet<LiveKey> = n
                    .store()
                    .live_bindings(now)?
                    .into_iter()
                    .map(|b| {
                        (
                            b.origin.canonical(),
                            b.node_id.as_bytes().to_vec(),
                            b.source.as_str(),
                        )
                    })
                    .collect();
                Ok((live, n.store().bindings()?))
            })
            .await?;
            for binding in bindings {
                out.line(format!(
                    "{:<32} {} {:<7} {}{}",
                    binding.origin.canonical(),
                    binding.node_id.to_z32(),
                    binding.source.as_str(),
                    if live.contains(&(
                        binding.origin.canonical(),
                        binding.node_id.as_bytes().to_vec(),
                        binding.source.as_str(),
                    )) {
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

        Command::DelegateAdd(pb::DelegateAdd {
            key,
            spaces,
            until,
            note,
        }) => {
            let subject = parse_key(&key)?;
            let ttl = match until.as_deref() {
                Some(text) => crate::cli::parse_duration(text)
                    .map_err(|e| ControlError::invalid(e.to_string()))?,
                None => DEFAULT_DELEGATION_TTL,
            };
            let not_after = now_ns().saturating_add(ttl.as_nanos().min(i64::MAX as u128) as i64);
            // Writing the record and publishing the head are both store work,
            // so they go to the blocking pool (§10).
            let head = {
                let spaces = spaces.clone();
                let note = note.clone();
                read(node, move |n| {
                    let change = n.delegate_add(subject, &spaces, not_after, note.as_deref())?;
                    Ok(n.publish(&[change])?)
                })
                .await?
            };
            out.line(format!(
                "delegated {} for {}",
                subject.to_z32(),
                crate::render::remaining(not_after, now_ns())
            ))
            .await?;
            for space in &spaces {
                out.line(format!("  {space}")).await?;
            }
            if let Some(head) = head {
                out.line(format!("published at seq {}", head.seq)).await?;
            }
            // What the subject will and will not see, said at the moment the
            // operator can still choose otherwise.
            out.line(format!(
                "this node will serve it a projection of every trie covering {}, \
                 and nothing else — it will not learn that any other space exists",
                spaces.join(", ")
            ))
            .await?;
        }

        Command::DelegateRm(pb::DelegateRm { key }) => {
            let subject = parse_key(&key)?;
            let head = read(node, move |n| {
                let change = n.delegate_remove(&subject)?;
                Ok(n.publish(&[change])?)
            })
            .await?;
            out.line(format!("removed the delegation of {}", subject.to_z32()))
                .await?;
            if let Some(head) = head {
                out.line(format!(
                    "published at seq {} — every reachable peer within one push",
                    head.seq
                ))
                .await?;
            }
        }

        Command::DelegateLs(pb::DelegateLs {}) => {
            let now = now_ns();
            let own = node.origin().clone();
            let mut any = false;
            // Both of these take the store connection, so both go to the
            // blocking pool — together, in one hop, since the rendering below
            // touches neither (§10).
            let (live, bindings) = read(node, move |n| {
                let live: std::collections::HashSet<Vec<u8>> = n
                    .store()
                    .delegations(now)?
                    .into_iter()
                    .map(|b| b.node_id.as_bytes().to_vec())
                    .collect();
                Ok((live, n.delegations()?))
            })
            .await?;
            for binding in bindings {
                any = true;
                let issuer = binding
                    .issuer
                    .as_ref()
                    .map(|i| match i == &own {
                        true => "this node".to_string(),
                        false => i.canonical(),
                    })
                    .unwrap_or_else(|| "<unknown>".to_string());
                out.line(format!(
                    "{} {:<28} {:<10} ← {issuer}",
                    binding.node_id.to_z32(),
                    binding.spaces.join(","),
                    match binding.expires_at {
                        // Dated fine, but cut off: its issuer holds no live
                        // rooted binding here any more.
                        _ if !live.contains(binding.node_id.as_bytes().as_slice()) => {
                            "cut off".to_string()
                        }
                        Some(at) => crate::render::remaining(at, now),
                        None => "never".to_string(),
                    },
                ))
                .await?;
            }
            if !any {
                out.line("no delegations").await?;
            }
        }

        Command::DomainSet(pb::DomainSet { domain, delegate }) => {
            let warning = {
                let node = node.clone();
                let domain = domain.clone();
                read(&node, move |n| {
                    let warning = delegation_warning(&n);
                    n.set_domain(&domain)?;
                    n.store().set_membership_expects_name(!delegate)?;
                    Ok(warning)
                })
                .await?
            };
            out.line(format!("membership domain is {domain}")).await?;
            if let Some(warning) = warning {
                out.line(warning).await?;
            }
            // Deliberately no refresh here: this process goes on resolving the
            // zone its current name came from, and pulling bindings out of a
            // zone that has not named this node yet would leave it holding
            // membership from an authority with no say in what it is called
            // (§3.1). The next start resolves the new zone and migrates.
            out.line("takes effect at the next `synch daemon run`")
                .await?;
            // Said here, while the operator is still at the keyboard, because
            // the consequence lands at the next start — and what that
            // consequence *is* depends on the flag they just passed, which is
            // why the advice takes it.
            for line in domain_set_advice(&domain, node.node_id(), delegate) {
                out.line(line).await?;
            }
        }

        Command::DomainClear(pb::DomainClear {}) => {
            let (dropped, warning) = {
                let node = node.clone();
                read(&node, move |n| {
                    let warning = delegation_warning(&n);
                    Ok((n.clear_domain()?, warning))
                })
                .await?
            };
            if !dropped {
                return Err(ControlError::new(
                    ErrorCode::NotFound,
                    "no membership domain is configured".to_string(),
                ));
            }
            out.line("membership domain cleared").await?;
            out.line(
                "the device key names this node at the next `synch daemon run`, \
                 which is also what drops the zone's bindings",
            )
            .await?;
            if let Some(warning) = warning {
                out.line(warning).await?;
            }
        }

        Command::DomainLs(pb::DomainLs {}) => {
            let (health, configured) =
                read(node, |n| Ok((n.domain_health()?, n.domain()?))).await?;
            if health.is_empty() {
                out.progress("(no membership domain; static trust only)")
                    .await?;
            }
            for entry in &health {
                out.line(render::domain_health(entry, now_ns())).await?;
            }
            // The configured slot and the zone in force differ between a
            // `domain set` and the next start; saying so is the difference
            // between a pending change and a broken one.
            let resolving = health.first().map(|h| h.domain.clone());
            if configured != resolving {
                out.line(match &configured {
                    Some(domain) => format!("pending: {domain} at the next `synch daemon run`"),
                    None => "pending: no domain at the next `synch daemon run`".to_string(),
                })
                .await?;
            }
        }

        // Strict: a failed refresh is a failed command. Scripts and
        // monitoring read the exit code, not the prose.
        Command::DomainRefresh(pb::DomainRefresh {}) => {
            refresh_domains(node, out, None, true).await?
        }

        Command::Peers(pb::Peers {}) => {
            let now = now_ns();
            let seen = read(node, |n| Ok(n.store().peers_seen()?)).await?;
            if seen.is_empty() {
                // On stderr, as every empty listing here is: a human learns
                // the silence is "nothing yet", a script still gets clean
                // stdout to parse.
                out.progress("(no peers seen yet)").await?;
            }
            for peer in seen {
                let key = peer.node_id;
                let origins = read(node, move |n| {
                    Ok(n.store().live_origins_for_key(&key, now)?)
                })
                .await?;
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

        Command::SpaceAdd(pb::SpaceAdd {
            id,
            path,
            detached,
            replicate,
            grace,
            budget,
        }) => {
            // A typo'd path otherwise becomes a fresh empty directory with no
            // signal; creating it is a feature, doing so silently is not.
            //
            // The `stat` goes over with the store work rather than inline: on a
            // hung mount it blocks for the mount's timeout, and a runtime
            // worker that stops polling is the thing §10 exists to prevent.
            // A space asked to replicate with no path is detached by
            // construction: replication materializes nothing, so there is no
            // third state between "a directory is indexed here" and "there
            // isn't one" for it to occupy.
            if detached || (path.is_empty() && replicate.is_some()) {
                let detached_id = id.clone();
                read(node, move |n| {
                    n.add_detached_space(&detached_id)?;
                    Ok(())
                })
                .await?;
                out.line(format!("holding detached space {id}")).await?;
                apply_replication(node, &id, replicate.as_deref(), grace, budget, out).await?;
                return Ok(());
            }
            let created = {
                let (id, path) = (id.clone(), path.clone());
                read(node, move |n| {
                    let created = !std::path::Path::new(&path).is_dir();
                    n.add_space(&id, &path)?;
                    Ok(created)
                })
                .await?
            };
            out.line(format!("indexing {path} as {id}")).await?;
            if created {
                out.line(format!("note: created {path}, which did not exist"))
                    .await?;
            }
            apply_replication(node, &id, replicate.as_deref(), grace, budget, out).await?;
        }

        Command::SpaceLs(pb::SpaceLs { id }) => {
            // Naming one space asks a different question from listing them —
            // "what is this node doing about `media`" rather than "what is this
            // node for" — and answers at a different length.
            if !id.is_empty() {
                let reporting = id.clone();
                let status = read(node, move |n| Ok(n.replica_status(&reporting)?)).await?;
                for line in crate::render::replica_status(&status)? {
                    out.line(line).await?;
                }
                return Ok(());
            }
            let spaces = read(node, |n| {
                let spaces = n.store().spaces()?;
                let mut out = Vec::new();
                for space in spaces {
                    let coverage = space.replicate.map(|_| {
                        n.store()
                            .replica_coverage(&space.holder(), UNREACHABLE_ATTEMPTS)
                    });
                    out.push((space, coverage.transpose()?));
                }
                Ok(out)
            })
            .await?;
            if spaces.is_empty() {
                out.progress("(no local spaces; add one with `synch space add`)")
                    .await?;
            }
            for (space, coverage) in spaces {
                out.line(crate::render::space_line(&space, coverage.as_ref()))
                    .await?;
            }
        }

        Command::SpaceSet(pb::SpaceSet {
            id,
            replicate,
            no_replicate,
            release,
            grace,
            budget,
        }) => {
            if no_replicate {
                let (space, dropping) = (id.clone(), release);
                read(node, move |n| {
                    Ok(n.set_space_replication(&space, None, None, None, dropping)?)
                })
                .await?;
                out.line(match release {
                    true => format!("{id} is no longer replicated; its content was released"),
                    false => format!(
                        "{id} is no longer replicated; what it held stays pinned \
                         (`--release` drops it)"
                    ),
                })
                .await?;
                return Ok(());
            }
            if replicate.is_none() && grace.is_none() && budget.is_none() {
                return Err(ControlError::invalid(
                    "space set needs something to set: --replicate, --no-replicate, \
                     --grace or --budget",
                ));
            }
            apply_replication(node, &id, replicate.as_deref(), grace, budget, out).await?;
        }

        Command::SpaceSync(pb::SpaceSync { id }) => {
            let sweeping = node.clone();
            let only = (!id.is_empty()).then(|| id.clone());
            let reports = offload(move || Ok(sweeping.sweep_replicas(only.as_deref())?)).await?;
            if reports.is_empty() {
                out.progress(match id.is_empty() {
                    true => "(no replicated spaces; add one with `synch space set --replicate`)"
                        .to_string(),
                    false => format!("({id} is not replicated here)"),
                })
                .await?;
                return Ok(());
            }
            for (space, report) in reports {
                out.line(format!(
                    "{space}  wanted {} · reprieved {} · scheduled {} · released {}",
                    report.wanted, report.reprieved, report.scheduled, report.released
                ))
                .await?;
            }
            // The sweep only decides; the fetching is what takes time, and an
            // explicit sync should not answer before it has done a pass of it.
            let fetched = node.fetch_replica_wants().await?;
            out.line(format!(
                "held {} · failed {} · fetched {} B · reused {} B",
                fetched.held, fetched.failed, fetched.fetched_bytes, fetched.reused_bytes
            ))
            .await?;
            // What this node says it holds should not be left behind by a sync
            // the operator ran deliberately: the standing loop publishes its
            // claims at the end of a pass, and this is the same pass by hand.
            node.publish_material_claims().await;
        }

        Command::SpaceRm(pb::SpaceRm { id, release }) => {
            // Unpublishing a space scans its whole prefix out of the trie.
            let removing = node.clone();
            let removed_id = id.clone();
            let dropping = release;
            let staged = offload(move || Ok(removing.remove_space(&removed_id, dropping)?)).await?;
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
            read(node, |n| Ok(n.ensure_publishable()?)).await?;
            // The engine owns the blocking handoff and the selected CAS
            // backend. Keeping the old synchronous scanner here would bypass a
            // cloud backend and publish scratch-only content.
            let (report, spaces) = node.scan_and_stage_async_with_reports().await?;
            for (space, one) in spaces {
                out.progress(format!(
                    "scanned {space}: hashed {} · unchanged {} · deleted {}",
                    one.hashed, one.unchanged, one.deleted
                ))
                .await?;
            }
            // An explicit scan is already one batch, so it stages and then
            // flushes rather than waiting out the quiesce: the "published seq"
            // line below is true by the time the client reads it (§7.1).
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
            ensure_known_space(node, &reference.space).await?;
            if let Some(origin) = &reference.origin {
                ensure_known_origin(node, origin).await?;
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
                    let (listing, now) = {
                        let listing = node.clone();
                        let space = reference.space.clone();
                        let prefix = reference.dir_prefix();
                        offload(move || {
                            Ok((
                                listing.unified_listing(&space, &prefix, None, None)?,
                                listing.store().read_instant()?,
                            ))
                        })
                        .await?
                    };
                    for set in &listing {
                        if !set.exists() {
                            // Every publisher has tombstoned it: the path has
                            // left the tree, so the tree does not list it.
                            continue;
                        }
                        for line in render::unified_line(node, set, all, now)? {
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
                    ensure_known_space(node, &space).await?;
                    vec![space]
                }
                None => read(node, |n| Ok(n.store().known_spaces()?)).await?,
            };
            let mut printed = false;
            for space in &spaces {
                let sets = {
                    let (space, path) = (space.clone(), path.clone());
                    read(node, move |n| {
                        Ok(n.unified_listing(&space, &path, None, None)?)
                    })
                    .await?
                };
                for set in sets {
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
            root,
        }) => {
            let range = match &range {
                Some(text) => crate::cli::ByteRange::parse(text)
                    .map_err(|e| ControlError::invalid(e.to_string()))?,
                None => crate::cli::ByteRange {
                    start: 0,
                    end: None,
                },
            };
            let prepared = match &root {
                Some(root) => {
                    node.prepare_root_range(&parse_root(root)?, range.start, range.length())
                        .await?
                }
                None => {
                    let reference = parse_reference(&reference)?;
                    let policy = policy_for(&reference, from.as_deref(), strict)?;
                    node.prepare_range(
                        &reference.space,
                        &reference.path,
                        &policy,
                        range.start,
                        range.length(),
                    )
                    .await?
                }
            };
            stream_range(node, &mut Bytes::Frames(out), prepared).await?;
        }

        Command::Get(pb::Get {
            reference,
            from,
            strict,
            root,
        }) => {
            let prepared = match &root {
                Some(root) => node.prepare_root_range(&parse_root(root)?, 0, None).await?,
                None => {
                    let reference = parse_reference(&reference)?;
                    let policy = policy_for(&reference, from.as_deref(), strict)?;
                    node.prepare_range(&reference.space, &reference.path, &policy, 0, None)
                        .await?
                }
            };
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
            let theirs = {
                let (space, path, pinned) = (
                    reference.space.clone(),
                    reference.path.clone(),
                    VersionPolicy::Origin(origin.clone()),
                );
                read(node, move |n| Ok(n.resolve(&space, &path, &pinned)?)).await?
            };
            if theirs.kind == synch_core::EntryKind::Tombstone {
                let (space, path) = (reference.space.clone(), reference.path.clone());
                match read(node, move |n| Ok(n.adopt_deletion(&space, &path)?)).await? {
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
            let lines = {
                let reference = reference.clone();
                read(node, move |n| render::log(&n, &reference)).await?
            };
            for line in lines {
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

        Command::Fill(pb::Fill {
            reference,
            from,
            strict,
            force,
            dry_run,
        }) => {
            let reference = parse_reference(&reference)?;
            let policy = policy_for(&reference, from.as_deref(), strict)?;
            // Space first and origin second, the order `ls` states its reason
            // for: one typo should be reported as the same mistake whichever
            // command met it.
            //
            // A space nobody publishes and a space nobody indexes fail for
            // different reasons, and the second is the one `fill` is picky
            // about: it writes into the directory `synch space add` named, so
            // an unindexed space has nowhere to put anything. `fill_space`
            // says so; this is the other half, so a typo'd id does not report
            // "no local space" when the real answer is "no such space at all".
            ensure_known_space(node, &reference.space).await?;
            // The policy's origin, not the reference's: `--from nsa` and
            // `nsa:media` are the same typo, and only one of them was being
            // checked. A fill of an origin nobody has heard of selects nothing
            // for every path, and `Absent` is silent by design — so the typo
            // reported as a complete, clean fill of nothing.
            if let VersionPolicy::Origin(origin) = &policy {
                ensure_known_origin(node, origin).await?;
            }
            let options = synch_engine::FillOptions { force, dry_run };
            let report = node
                .fill_space(&reference.space, &reference.dir_prefix(), &policy, options)
                .await?;
            let mut summary = format!(
                "{} {} · current {} · differing {} · skipped {}",
                if report.dry_run {
                    "would fill"
                } else {
                    "filled"
                },
                report.filled,
                report.current,
                report.differing.len(),
                report.skipped.len()
            );
            // Counted apart from `differing` rather than folded into it: under
            // `--force` nothing can be differing, so a folded count of 3 would
            // read as three paths `--force` is about to fix, when they are three
            // it deliberately did not touch.
            if !report.appeared.is_empty() {
                summary.push_str(&format!(" · appeared {}", report.appeared.len()));
            }
            if report.ignored > 0 {
                summary.push_str(&format!(" · ignored {}", report.ignored));
            }
            if !report.replaced.is_empty() {
                summary.push_str(&format!(
                    " · {} {}",
                    if report.dry_run {
                        "would replace"
                    } else {
                        "replaced"
                    },
                    report.replaced.len()
                ));
            }
            out.line(summary).await?;
            if report.reused_bytes > 0 || report.reflinked > 0 {
                out.line(format!(
                    "reused {} B · fetched {} B · reflinked {}",
                    report.reused_bytes, report.fetched_bytes, report.reflinked
                ))
                .await?;
            }
            // Every per-path line here goes to stdout, unlike the per-path
            // lines of `scan` and `mirror sync`. Those report how a pass went,
            // path by path; these are the paths the operator has to decide
            // about — under `--dry-run` the list *is* the command's answer, and
            // under `--strict` the skipped paths are the entire reason the
            // command was run. Splitting one decision list across two streams
            // so that `synch fill media --strict > plan` wrote the count and
            // dropped the paths would be the worst of both.
            for path in &report.replaced {
                out.line(format!(
                    "{} {}/{path}",
                    if report.dry_run {
                        "would replace"
                    } else {
                        "replaced"
                    },
                    reference.space
                ))
                .await?;
            }
            for path in &report.differing {
                out.line(format!(
                    "differing {}/{path} (local content differs; --force replaces it)",
                    reference.space
                ))
                .await?;
            }
            // Kept apart from `differing` because the advice is the opposite:
            // these are paths that are no longer what the fill was shown, so
            // `--force` — which answers for the file it was pointed at —
            // neither caused this nor resolves it.
            for path in &report.appeared {
                out.line(format!(
                    "appeared {}/{path} (not the file this fill was shown; left alone)",
                    reference.space
                ))
                .await?;
            }
            for (path, reason) in &report.skipped {
                out.line(format!("skipped {}/{path}: {reason}", reference.space))
                    .await?;
            }
            // Written, but not wholly: kept out of the skipped count so that
            // `filled` and `skipped` never describe the same path.
            for (path, reason) in &report.warnings {
                out.line(format!("filled {}/{path}, but {reason}", reference.space))
                    .await?;
            }
            // A prefix that names nothing is almost always a typo, and it
            // reports exactly what an already-full directory reports. `status`
            // refuses to let a named path that matches nothing pass as silence;
            // a fill that writes nothing because of a typo is the same trap.
            if !reference.is_space_root() && report.considered == 0 {
                out.line(format!(
                    "note: no path in {} starts with {}",
                    reference.space,
                    reference.dir_prefix()
                ))
                .await?;
            }
            if report.filled > 0 && !report.dry_run {
                out.line("the next scan publishes what was filled as this node's own view")
                    .await?;
            }
        }

        Command::MirrorAdd(pb::MirrorAdd {
            space,
            path,
            policy,
        }) => {
            let policy = parse_policy(policy.as_deref())?;
            let stored = {
                let (space, path, policy) = (space.clone(), path.clone(), policy.clone());
                read(node, move |n| Ok(n.add_mirror(&space, &path, &policy)?)).await?
            };
            out.line(format!("mirroring {space} into {stored} ({policy})"))
                .await?;
            // Configuring the mirror before the space first syncs is a
            // legitimate order of operations; doing it to a typo'd id is not,
            // and nothing else in the exchange tells the two apart.
            if ensure_known_space(node, &space).await.is_err() {
                out.line(format!(
                    "note: no origin publishes {space} yet; the mirror stays empty until one does"
                ))
                .await?;
            }
        }

        Command::MirrorRm(pb::MirrorRm { path }) => {
            let dropped = {
                let path = path.clone();
                read(node, move |n| Ok(n.remove_mirror(&path)?)).await?
            };
            if !dropped {
                return Err(ControlError::new(
                    ErrorCode::NotFound,
                    format!("no mirror at {path}"),
                ));
            }
            out.line("removed").await?;
        }

        Command::MirrorLs(pb::MirrorLs {}) => {
            let mirrors = read(node, |n| Ok(n.store().mirrors()?)).await?;
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
            for mirror in read(node, |n| Ok(n.store().mirrors()?)).await? {
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
            let (root, size) = pin_target(node, &target).await?;
            node.pin_object(&root, size).await?;
            out.line(format!("pinned {root}")).await?;
        }

        Command::PinRm(pb::PinRm { target }) => {
            let (root, _) = pin_target(node, &target).await?;
            if !node.unpin_object(&root).await? {
                return Err(ControlError::new(
                    ErrorCode::NotFound,
                    format!("no operator pin on {root}"),
                ));
            }
            // What remains decides whether anything actually leaves, and the
            // operator asked about the bytes rather than about the row. A
            // command that answered "unpinned" flat, while a replica went on
            // holding the object for another month, would be describing its own
            // bookkeeping instead of the outcome.
            let remaining = read(node, move |n| Ok(n.store().pins_for(&root)?)).await?;
            out.line(match remaining.as_slice() {
                [] => format!("unpinned {root}"),
                held => format!("unpinned {root} (still held by {})", render_holders(held)),
            })
            .await?;
        }

        Command::PinLs(pb::PinLs {}) => {
            let pinned = read(node, |n| Ok(n.store().pinned_blobs()?)).await?;
            if pinned.is_empty() {
                out.progress("(nothing pinned)").await?;
            }
            for root in pinned {
                // A bare hash answers "what is pinned" without answering
                // "what is it": the size, who holds it, and the paths currently
                // naming the object are what make the list reviewable.
                let (size, holders, paths) = read(node, move |n| {
                    let size = n
                        .store()
                        .blob(&root)?
                        .map(|b| format!("{} B", b.size))
                        .unwrap_or_else(|| "(bytes not held)".into());
                    Ok((
                        size,
                        n.store().pins_for(&root)?,
                        n.store().paths_naming(&root)?,
                    ))
                })
                .await?;
                out.line(format!(
                    "{root}  {size}  {}  {}",
                    render_holders(&holders),
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
            // One trip for the write and both reads, like every other handler
            // here: `config` and `spaces` go through `Store::conn`, which
            // aborts the process outright when it is touched from a runtime
            // worker (§10).
            let (spaces, domains) = read(node, |n| {
                n.enable_cloud()?;
                Ok((n.store().spaces()?, n.domain()?))
            })
            .await?;
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
            let domains: Vec<String> = domains.into_iter().collect();
            if domains.is_empty() {
                // Nothing to attach to and nothing that will change that on
                // its own: the endpoint comes from a membership zone, so a
                // node with no membership domain has nowhere to look.
                out.line(
                    "note: no membership domains are configured, so there is no zone to \
                     discover a control plane from; `synch domain set <domain>` first",
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
            read(node, |n| Ok(n.disable_cloud()?)).await?;
            out.line("cloud attach disabled; any open tunnel is dropped")
                .await?;
        }

        Command::CloudStatus(pb::CloudStatus {}) => {
            // `cloud_status` below is in-memory; only the opt-out flag is a
            // store read, and it is the one that has to go over (§10).
            let settings = read(node, |n| Ok(n.cloud_settings()?)).await?;
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
            // One line per endpoint, not per domain: an apex names every
            // node of its control plane and this daemon holds a tunnel to
            // each, so one replica being down is its own line rather than a
            // verdict on the whole domain.
            for endpoint in status {
                out.line(format!(
                    "{:<32} {:<10} {}{}",
                    endpoint.domain,
                    if endpoint.attached {
                        "attached"
                    } else {
                        "detached"
                    },
                    endpoint
                        .endpoint
                        .as_deref()
                        .unwrap_or("(no validated _synchronicity-cp record)"),
                    endpoint
                        .last_error
                        .as_ref()
                        .map(|why| format!("  last error: {why}"))
                        .unwrap_or_default(),
                ))
                .await?;
            }
        }

        Command::SyncNow(pb::SyncNow {}) => {
            let peers = read(node, |n| Ok(n.dialable_peers()?)).await?;
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
                let origins = read(node, move |n| {
                    Ok(n.store().live_origins_for_key(&peer, now)?)
                })
                .await?;
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

/// One message of a streamed write, whichever call carries it.
///
/// `Put` and `UploadPart` differ only in where the payload lands and what
/// happens once it is whole; the loop that receives it is the same loop, and
/// the rules it enforces — nothing is kept without an explicit commit, a
/// second header is a protocol error — are the same rules.
enum Piece {
    Chunk(Vec<u8>),
    Commit,
    Abort(String),
    Header,
}

/// Streams a payload into a staging file, returning it once the client commits.
///
/// The client stopping without committing is a failure, not an end: a partly
/// received body must never be indistinguishable from a complete one, because
/// what this node does with a complete one is sign it and broadcast it.
async fn drain<T>(
    mut incoming: Streaming<T>,
    mut adoption: synch_engine::Adoption,
    mut classify: impl FnMut(T) -> Option<Piece>,
) -> Result<synch_engine::Adoption, ControlError> {
    loop {
        let message = match incoming.message().await {
            Ok(Some(message)) => message,
            // A dropped handle, a process that died, a truncated body: however
            // it came about, the staging file goes with the dropped `Adoption`.
            Ok(None) => {
                return Err(ControlError::invalid(format!(
                    "the write was abandoned after {} byte(s): it was never committed",
                    adoption.written()
                )))
            }
            Err(status) => {
                return Err(ControlError::invalid(format!(
                    "the write was abandoned after {} byte(s): {}",
                    adoption.written(),
                    status.message()
                )))
            }
        };
        match classify(message) {
            // Each piece is a write to the staging file, so it goes off the
            // runtime: the upload is the size of the payload, and the worker
            // thread polling this connection is also serving every other one.
            Some(Piece::Chunk(bytes)) => {
                adoption = offload(move || {
                    adoption.write(&bytes)?;
                    Ok(adoption)
                })
                .await?;
            }
            Some(Piece::Commit) => return Ok(adoption),
            Some(Piece::Abort(why)) => {
                return Err(ControlError::invalid(format!(
                    "the write was abandoned after {} byte(s): {why}",
                    adoption.written()
                )))
            }
            Some(Piece::Header) => {
                return Err(ControlError::invalid(
                    "a write names its space and path once",
                ))
            }
            None => continue,
        }
    }
}

/// Consumes an upload, commits it, and publishes what it wrote (§7.1, §9.4).
async fn receive(
    node: &Node,
    incoming: Streaming<pb::PutRequest>,
    adoption: synch_engine::Adoption,
    header: &pb::PutHeader,
) -> Result<pb::Written, ControlError> {
    let adoption = drain(incoming, adoption, |request| match request.part {
        Some(PutPart::Chunk(bytes)) => Some(Piece::Chunk(bytes)),
        Some(PutPart::Commit(pb::Commit {})) => Some(Piece::Commit),
        Some(PutPart::Abort(why)) => Some(Piece::Abort(why)),
        Some(PutPart::Header(_)) => Some(Piece::Header),
        None => None,
    })
    .await?;
    // Re-taken immediately before the rename, not trusted from the header
    // exchange that opened this write. The gates are taken there too, but the
    // body streams in a spawned task for as long as the client cares to take,
    // and an inbound `Hello` can floor this node anywhere in that window — at
    // which point a commit destroys the file that was there and nothing can
    // publish the replacement: no version, no `prev`, no trace. `Adoption`
    // holds no `Node`, so `commit` cannot ask on its own; `complete_upload`
    // re-takes the same gate immediately before its own assembly write.
    {
        let (space, path) = (header.space.clone(), header.path.clone());
        read(node, move |n| Ok(n.ensure_adoptable(&space, &path)?)).await?;
    }
    // The commit fsyncs the payload and renames it into place.
    let target = offload(move || Ok(adoption.commit()?)).await?;

    let detached = {
        let space = header.space.clone();
        read(node, move |n| Ok(n.is_detached_space(&space)?)).await?
    };
    let reported_path = if detached {
        let (committing, space, path, source) = (
            node.clone(),
            header.space.clone(),
            header.path.clone(),
            target.clone(),
        );
        let result = committing
            .commit_detached_file(&space, &path, &source, synch_core::now_ns())
            .await;
        // The content-addressed payload is durable now, or the operation
        // failed and the client owns the retry. The pre-hash scratch is never
        // part of the acknowledged state.
        let _ = tokio::fs::remove_file(&source).await;
        result?;
        format!("{}/{}", header.space, header.path)
    } else {
        target.display().to_string()
    };

    // Path-backed writes enter through the scanner; detached writes already
    // staged their CAS-direct `f:`/`b:` pair above. `scan_publish_push` skips
    // detached spaces but flushes the shared batch in either case.
    node.scan_publish_push().await?;
    let ours = VersionPolicy::Origin(node.origin().clone());
    let (set, now) = {
        let (space, path) = (header.space.clone(), header.path.clone());
        read(node, move |n| {
            Ok((n.versions(&space, &path)?, n.store().read_instant()?))
        })
        .await?
    };
    let row = node.resolve_set(&set, &ours, now)?;
    Ok(pb::Written {
        path: reported_path,
        entry: Some(entry_info(&row, &set).into()),
    })
}

/// Reads a principal off the wire.
///
/// Empty means anonymous, which is a principal in its own right — every
/// anonymous caller shares one, and on a loopback-only gateway that is the
/// intended shape rather than a gap.
fn principal(wire: &str) -> Option<String> {
    Some(wire).filter(|p| !p.is_empty()).map(str::to_string)
}

/// Consumes one part of a multipart upload and records it (§9.4).
async fn receive_part(
    node: &Node,
    incoming: Streaming<pb::UploadPartRequest>,
    staging: synch_engine::PartStaging,
) -> Result<pb::UploadPartResponse, ControlError> {
    let adoption = synch_engine::Adoption::at(&staging.path)?;
    let adoption = drain(incoming, adoption, |request| match request.part {
        Some(UploadPartPart::Chunk(bytes)) => Some(Piece::Chunk(bytes)),
        Some(UploadPartPart::Commit(pb::Commit {})) => Some(Piece::Commit),
        Some(UploadPartPart::Abort(why)) => Some(Piece::Abort(why)),
        Some(UploadPartPart::Header(_)) => Some(Piece::Header),
        None => None,
    })
    .await?;
    let part = node.commit_part_durable(staging, adoption).await?;
    Ok(pb::UploadPartResponse {
        number: part.number,
        size: part.size,
        root: part.root.as_bytes().to_vec(),
        created_ns: part.created_ns,
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
        // Every piece is a trusted backend read, so local filesystem work runs
        // on the blocking pool rather than on the worker polling this connection.
        let root = range.root;
        let bytes = node.cas_backend().read_range(root, offset, take).await?;
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

    let state = read(node, |n| Ok(n.recovery_state()?)).await?;
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
async fn ensure_known_space(node: &Node, space: &str) -> Result<(), ControlError> {
    let owned = space.to_string();
    let known = read(node, move |n| {
        Ok(n.store().spaces()?.iter().any(|s| s.id == owned)
            || n.store().known_spaces()?.iter().any(|s| s == &owned))
    })
    .await?;
    if known {
        return Ok(());
    }
    Err(ControlError::new(
        ErrorCode::NotFound,
        format!("no space {space}: not a local space, and no origin publishes one"),
    ))
}

/// Refuses an origin this node holds no binding for and is not itself.
async fn ensure_known_origin(node: &Node, origin: &OriginId) -> Result<(), ControlError> {
    let owned = origin.clone();
    let known = read(node, move |n| {
        Ok(n.origin() == &owned || n.store().bindings()?.iter().any(|b| b.origin == owned))
    })
    .await?;
    if known {
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
    let domain = match domain {
        Some(d) => {
            let d = d.to_string();
            Some(read(node, move |n| Ok(n.configured_domain(&d)?)).await?)
        }
        None => None,
    };
    let requested = match &domain {
        Some(domain) => vec![domain.clone()],
        None => read(node, |n| Ok(n.domain()?.into_iter().collect::<Vec<_>>())).await?,
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
/// How long a delegation lasts when `--until` is not given.
///
/// Expiry has one job here (§3.5): bounding how long a member that was
/// partitioned when a delegation was withdrawn can go on honoring it.
/// Revocation is a deletion that propagates on the ordinary push, so on a
/// connected cluster this number never comes into it — it is the backstop for
/// the case where the push cannot arrive.
/// What a pending rename will cost in delegated trust, as a line to print.
///
/// The rename revokes what the old name vouched for (§3.5), and it happens at
/// the next start — so this is said here, where the operator can still choose
/// otherwise, rather than only in the log line the migration writes.
fn delegation_warning(node: &Node) -> Option<String> {
    let own = node.origin().clone();
    let issued: Vec<synch_store::Binding> = node
        .delegations()
        .ok()?
        .into_iter()
        .filter(|b| b.issuer.as_ref() == Some(&own))
        .collect();
    match issued.len() {
        0 => None,
        n => Some(format!(
            "this revokes {n} delegation{} this node issued ({}); re-issue them \
             with `synch delegate add` once the new name is in use",
            match n {
                1 => "",
                _ => "s",
            },
            issued
                .iter()
                .map(|b| b.node_id.fmt_short().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

const DEFAULT_DELEGATION_TTL: std::time::Duration =
    std::time::Duration::from_secs(30 * 24 * 60 * 60);

/// Parses a stored or typed version policy, defaulting to `newest`.
fn parse_policy(text: Option<&str>) -> Result<VersionPolicy, ControlError> {
    match text {
        None => Ok(VersionPolicy::Newest),
        Some(text) => text
            .parse()
            .map_err(|e: synch_store::StoreError| ControlError::invalid(e.to_string())),
    }
}

/// Applies the replication half of `space add` and `space set`.
///
/// Shared because the two commands mean the same thing by the same flags, and
/// because the reply is the part worth getting right: an operator turning this
/// on for a large space has just committed the node to fetching all of it, and
/// under the default policy has also just decided how long a deletion stays
/// recoverable.
async fn apply_replication(
    node: &Node,
    id: &str,
    policy: Option<&str>,
    grace: Option<i64>,
    budget: Option<u64>,
    out: &mut Frames,
) -> Result<(), ControlError> {
    let Some(policy) = policy else {
        // `--grace`/`--budget` alone tune a space that is already replicating,
        // and must not go near its policy. Reading the policy and writing it
        // back would look equivalent and is not: a value this build cannot
        // parse reads as "not replicated", so tuning the grace window on a
        // space configured by a newer build would silently turn replication
        // off.
        if grace.is_some() || budget.is_some() {
            let space = id.to_string();
            read(node, move |n| {
                Ok(n.set_space_tunables(&space, grace, budget)?)
            })
            .await?;
        }
        return Ok(());
    };
    let policy: ReplicaPolicy = policy
        .parse()
        .map_err(|e: synch_store::error::StoreError| ControlError::invalid(e.to_string()))?;
    let (space, applied) = (id.to_string(), policy);
    read(node, move |n| {
        Ok(n.set_space_replication(&space, Some(applied), grace, budget, false)?)
    })
    .await?;
    let configured = {
        let space = id.to_string();
        read(node, move |n| {
            Ok(n.store()
                .space(&space)?
                .ok_or_else(|| synch_engine::error::EngineError::not_found(space))?)
        })
        .await?
    };
    out.line(format!(
        "replicating {id} ({policy}), holding every version of every path",
    ))
    .await?;
    match policy {
        ReplicaPolicy::Tree => {
            out.line(format!(
                "a deleted version stays recoverable here for {} — that is the whole \
                 recovery story under this policy",
                crate::render::duration(configured.grace_secs())
            ))
            .await?;
        }
        ReplicaPolicy::Archive => {
            out.line(
                "nothing is ever released, so this space costs the sum of every version \
                 ever published rather than the size of the tree"
                    .to_string(),
            )
            .await?;
        }
    }
    if let Some(budget) = configured.budget {
        out.line(format!(
            "budget {budget} B: reaching it stops fetching and never releases anything"
        ))
        .await?;
    }
    Ok(())
}

/// Reads a `--root` argument.
///
/// Its own function because the error an operator gets for a typo'd hash should
/// say what the argument wanted, not what `Hash::from_str` happened to dislike.
fn parse_root(text: &str) -> Result<Hash, ControlError> {
    Hash::from_str(text)
        .map_err(|_| ControlError::invalid(format!("{text} is not a 64-character hex object root")))
}

/// Renders who holds an object, and which of those claims are on their way out.
///
/// A scheduled release is the interesting half: "held by replica:media" and
/// "held by replica:media, leaving in 3d" are different answers to "can I
/// delete the original yet".
fn render_holders(pins: &[synch_store::PinRow]) -> String {
    let now = synch_core::now_ns();
    pins.iter()
        .map(|pin| match pin.release_after {
            None => pin.holder.render(),
            Some(at) => format!(
                "{} (leaving in {})",
                pin.holder,
                crate::render::remaining(at, now)
            ),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// What `synch pin add|rm` names: a hex object root, or a path whose selected
/// version supplies one (§8).
///
/// A pin is about bytes, and the bytes a path stands for are whichever version
/// the reading policy picks — the same selection every other read goes
/// through, so a pin and a `synch cat` of the same reference always mean the
/// same object. An `<origin>:` prefix pins that origin's version.
async fn pin_target(node: &Node, text: &str) -> Result<(Hash, Option<u64>), ControlError> {
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
    let entry = read(node, move |n| {
        Ok(n.resolve(&reference.space, &reference.path, &policy)?)
    })
    .await?;
    let root = entry.content.ok_or_else(|| {
        ControlError::invalid(format!("{text} selects a version with no content to pin"))
    })?;
    Ok((root, Some(entry.size)))
}
