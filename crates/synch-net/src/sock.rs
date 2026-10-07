//! The `sync/sock/1` ALPN: one invocation per incoming stream
//! (`docs/SOCKETS.md` §4).
//!
//! This module carries bytes and nothing else. It does not know what a socket
//! is, where a program comes from, or what makes one runnable — those live
//! behind [`SocketService`], which the engine implements. What is here is the
//! part that is genuinely the network's: the accept gate, the `Open` handshake,
//! the control uni-stream, and the decision to let a stream live as long as it
//! likes.
//!
//! That last one is why this ALPN does not reuse `serve::serve_connection`
//! the way the other two do. Their connection loop bounds a stream at two
//! minutes and a connection at eight in flight, and both are right for a
//! request/response protocol and wrong here: a socket that proxies is
//! *supposed* to be long-lived, and its concurrency bound is the socket's
//! own armed `max_streams` rather than a number this layer picks.
//!
//! The two bounds still apply to the one phase they are right for. A stream
//! that never finishes its `Open` handshake is not an invocation — it has no
//! runtime, no admission, and no deadline of its own, and without a bound it
//! owns a task and a buffer for as long as the peer keeps the connection. So
//! the handshake is covered by the shared accept path's per-stream timeout
//! and per-connection in-flight cap, and the bound ends the moment the
//! invocation is admitted.
//!
//! Where both nodes opted in, an invocation's bytes travel over a direct TCP
//! connection rather than its QUIC stream (`docs/DIRECT-TCP.md`, "Sockets"):
//! the caller asks with `OpenDirect`, the callee offers a ticket and a key in
//! its answer, and the QUIC stream stays open, carrying nothing, as the
//! invocation's identity. Everything else here — admission, the control
//! stream, the caller's departure — is the same on either path.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use synch_core::{
    DirectSecret, NodeId, RefuseCode, SockClosed, SockEntry, SockListed, SockOpen, SockOpened,
    SockRequest, SockStatus, MAX_OPENED_FRAME_LEN, MAX_OPEN_FRAME_LEN,
};
use synch_sock::{Admission, DuplexStream};
use synch_store::Store;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use crate::{
    direct::{
        stream::{DirectRead, DirectWrite, SockKeys, CONFIRM_TIMEOUT},
        DirectListener, DirectMemo, RecordKey,
    },
    error::NetError,
    frame,
    serve::MAX_CONCURRENT_STREAMS,
};

/// Makes the control uni-stream observable before the first invocation ends.
/// QUIC does not announce an opened uni-stream to its receiver until bytes are
/// sent on it, so without this preamble both sides wait forever: the client for
/// `control()`, the server for an invocation whose status it could write.
const CONTROL_READY: &[u8] = b"sync/sock/control/1\0";

/// What the engine has to supply for this ALPN to serve anything.
///
/// Two calls rather than one, because the reply to an `Open` has to name the
/// content root that is about to run — so resolution and authorization finish
/// *before* the stream becomes the guest's, and an admission is what travels
/// between those two moments.
#[async_trait::async_trait]
pub trait SocketService: std::fmt::Debug + Send + Sync + 'static {
    /// Resolves and authorizes an `Open`, or says why not.
    async fn admit(
        &self,
        peer: NodeId,
        addr: String,
        stream_index: u64,
        open: &SockOpen,
    ) -> Result<Admission, (RefuseCode, String)>;

    /// The sockets this caller may open, for [`SockRequest::List`].
    ///
    /// Needs no runtime and takes no slot: a node that cannot serve sockets
    /// can still say which ones it has. It applies the same scope rule
    /// `admit` does, so a socket the caller could not open is one it is not
    /// shown, and it has no refusal frame — a caller the callee will not
    /// answer for is shown nothing.
    async fn list(&self, peer: NodeId) -> Vec<SockEntry>;

    /// Runs an admitted invocation to completion.
    ///
    /// `peer_gone` fires when the caller's connection closes. The invocation
    /// must end on it: the stream itself may never fail — after a clean FIN
    /// the runtime's reader has already exited, so a connection that closes
    /// afterwards leaves the guest's stream looking open — but the caller is
    /// gone all the same, and an invocation that keeps running is a slot held
    /// for nobody.
    async fn run(
        &self,
        admission: Admission,
        stream: DuplexStream,
        peer_gone: tokio::sync::oneshot::Receiver<SockStatus>,
    ) -> SockStatus;
}

/// Serves `sync/sock/1`.
#[derive(Clone)]
pub(crate) struct SockProtocol {
    store: Arc<Store>,
    service: Arc<dyn SocketService>,
    on_unknown_key: Option<Arc<tokio::sync::Notify>>,
    state: Arc<ProtocolState>,
    /// How long a stream may take to complete its `Open` handshake.
    ///
    /// The shared accept path's per-stream bound, applied to the handshake
    /// only: a stream that never becomes an invocation has no runtime of its
    /// own, and without this it owns a task and a buffer for as long as the
    /// peer keeps the connection. An admitted invocation runs unbounded —
    /// the socket runtime's own deadlines govern it.
    open_timeout: Duration,
    /// The endpoint-wide in-flight gate, shared with every other ALPN mounted
    /// on this endpoint (`crate::serve::Inflight`).
    ///
    /// Taken around the accept gate only, never around an admitted
    /// invocation. A socket invocation is *supposed* to be long-lived, so
    /// holding an endpoint-wide slot for its whole run would make one
    /// `--listen` client's open sessions a ceiling on every other peer's
    /// requests. What the gate is for is the unbounded thing — the store call
    /// an unauthenticated dialer reaches by completing a handshake.
    inflight: crate::serve::Inflight,
    /// The direct-TCP listener, when this node offers direct streams
    /// (`docs/DIRECT-TCP.md`).
    direct: Option<Arc<DirectListener>>,
}

/// An invocation's TCP connection, authenticated and handed over, with the
/// keys it reads and writes under.
struct Accepted {
    socket: TcpStream,
    read: RecordKey,
    write: RecordKey,
}

#[derive(Debug, Default)]
struct ProtocolState {
    stopping: AtomicBool,
    active_streams: AtomicUsize,
    changed: tokio::sync::Notify,
}

impl ProtocolState {
    fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    fn enter(self: &Arc<Self>) -> Option<ActiveStream> {
        if self.is_stopping() {
            return None;
        }
        self.active_streams.fetch_add(1, Ordering::AcqRel);
        if self.is_stopping() {
            self.leave();
            return None;
        }
        Some(ActiveStream {
            state: self.clone(),
        })
    }

    fn leave(&self) {
        if self.active_streams.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.changed.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.is_stopping() {
                return;
            }
            changed.await;
        }
    }

    async fn drained(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active_streams.load(Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    }
}

#[derive(Debug)]
struct ActiveStream {
    state: Arc<ProtocolState>,
}

impl Drop for ActiveStream {
    fn drop(&mut self) {
        self.state.leave();
    }
}

impl std::fmt::Debug for SockProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SockProtocol")
    }
}

impl SockProtocol {
    /// Builds a handler over a store and a service.
    pub(crate) fn new(
        store: Arc<Store>,
        service: Arc<dyn SocketService>,
        open_timeout: Duration,
    ) -> Self {
        SockProtocol {
            store,
            service,
            on_unknown_key: None,
            state: Arc::new(ProtocolState::default()),
            open_timeout,
            inflight: None,
            direct: None,
        }
    }

    /// Answers `OpenDirect` with offers on `listener`.
    pub(crate) fn direct(mut self, listener: Option<Arc<DirectListener>>) -> Self {
        self.direct = listener;
        self
    }

    /// Gates this handler's accept path on the endpoint-wide semaphore.
    pub(crate) fn inflight(mut self, gate: crate::serve::Inflight) -> Self {
        self.inflight = gate;
        self
    }

    /// Rings `wake` whenever a connection is refused for an unknown key (§3.4).
    pub(crate) fn on_unknown_key(mut self, wake: Option<Arc<tokio::sync::Notify>>) -> Self {
        self.on_unknown_key = wake;
        self
    }

    /// Refuses new socket streams and wakes incomplete handshakes.
    pub(crate) fn stop(&self) {
        self.state.stop();
    }

    /// Waits until every stream accepted before [`stop`](Self::stop) has
    /// delivered its final response or refusal.
    pub(crate) async fn drain(&self) {
        if self.state.is_stopping() {
            self.state.drained().await;
        }
    }
}

impl ProtocolHandler for SockProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();

        if self.state.is_stopping() {
            connection.close(0u32.into(), b"shutdown");
            return Ok(());
        }

        // The same accept gate as the other two ALPNs — literally: the §3.2
        // rule is membership policy, and this file's own rationale for
        // `serve_connection` is "one implementation, because two drift".
        {
            let Ok(_admission) = crate::serve::slot(&self.inflight).await else {
                return Ok(());
            };
            crate::serve::admit(
                &self.store,
                &connection,
                &remote,
                self.on_unknown_key.as_ref(),
            )
            .await?;
        }

        // One uni-stream per connection, opened before anything is served, so
        // that a status always has somewhere to go. A trailer on the data
        // stream would cost a length prefix on every proxied byte, and a
        // RESET_STREAM would discard output the program had already written.
        let control = match connection.open_uni().await {
            Ok(mut stream) => {
                if let Err(e) = stream.write_all(CONTROL_READY).await {
                    tracing::debug!(peer = %remote.fmt_short(), "control preamble failed: {e}");
                    return Err(AcceptError::from_err(std::io::Error::other(e)));
                }
                Arc::new(tokio::sync::Mutex::new(stream))
            }
            Err(e) => {
                tracing::debug!(peer = %remote.fmt_short(), "no control stream: {e}");
                return Err(AcceptError::from_err(std::io::Error::other(e)));
            }
        };

        let mut index = 0u64;
        // The shared accept path's in-flight cap, scoped to handshakes. A
        // permit is held only until the `Open` is admitted: from then on the
        // stream is an invocation governed by the socket runtime's own
        // bounds, and a `--listen` client multiplexing many long-lived
        // invocations over one connection must not be capped by this layer.
        let handshake = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS));
        loop {
            let accepted = tokio::select! {
                _ = self.state.cancelled() => break,
                accepted = connection.accept_bi() => accepted,
            };
            let Ok((mut send, mut recv)) = accepted else {
                break;
            };
            let Some(active) = self.state.enter() else {
                let _ = frame::write_frame(
                    &mut send,
                    &SockOpened::Refused {
                        code: RefuseCode::Busy,
                        message: "the node is shutting down".into(),
                    },
                )
                .await;
                let _ = send.finish();
                break;
            };
            // Per stream, not just per connection: a binding revoked
            // mid-session must stop the next invocation. A stream already
            // running is left alone — cutting it would be a partial write to
            // whatever the program is talking to.
            if !crate::serve::still_admitted(&self.store, &connection, &remote).await {
                break;
            }
            // A stream whose handshake never completes must not pile up
            // beyond the shared path's cap. The permit is taken before the
            // task, so the stream sits unread in the accept queue rather
            // than owning a task, once the cap is reached.
            let permit = tokio::select! {
                _ = self.state.cancelled() => break,
                permit = handshake.clone().acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
            };

            let stream_id = send.id().index();
            // The endpoint id rather than a socket address: iroh may be
            // carrying this connection over a relay or over any of several
            // paths, and `sy_peer_addr` says as much. What a program can rely
            // on is the device key, which is what authenticated the peer.
            let addr = remote.to_string();
            let handler = self.clone();
            let control = control.clone();
            let conn = connection.clone();
            let this_index = index;
            index += 1;

            tokio::spawn(async move {
                let _active = active;
                // The handshake is bounded: an `Open` that never arrives is
                // dropped after `open_timeout`, permit and all. What is
                // dropped is a stream that was never an invocation — nothing
                // is on the control stream for it, and nothing is owed.
                let (admission, direct) = match tokio::time::timeout(
                    handler.open_timeout,
                    handler.open_stream(remote, addr, this_index, &conn, &mut send, &mut recv),
                )
                .await
                {
                    Ok(Some(admitted)) => admitted,
                    // A refusal is already on the wire, or an offer the
                    // caller did not take up.
                    Ok(None) => return,
                    Err(_) => {
                        tracing::debug!(
                            peer = %remote.fmt_short(),
                            "socket Open timed out; the stream never became an invocation"
                        );
                        return;
                    }
                };
                drop(permit);
                // The caller's connection closing must end the invocation
                // even when the stream itself never fails — after a clean
                // FIN the runtime's reader has already exited, so the
                // connection dying afterwards leaves the guest's stream
                // looking open, and nothing else would ever end it. The
                // watcher only sends: the invocation's ending status is the
                // same non-fault `Deadline` a failed stream produces, and the
                // receiver lives or dies with the run below.
                //
                // On the direct path the QUIC stream carries nothing, so the
                // caller stopping it is the other way it says it has gone, and
                // the same event destroys the stream's keys.
                let peer_gone = caller_gone(conn.clone(), direct.is_some().then(|| send.stopped()));
                let stream = match direct {
                    Some(accepted) => {
                        let stream_gone = caller_gone(conn.clone(), Some(send.stopped()));
                        let split = crate::direct::stream::split(
                            accepted.socket,
                            accepted.read,
                            accepted.write,
                            stream_gone,
                            (send, recv),
                        );
                        let confirmed = match split {
                            Ok((read, mut write)) => match write.confirm().await {
                                Ok(()) => Ok((read, write)),
                                Err(e) => Err(NetError::Direct(format!("confirming: {e}"))),
                            },
                            Err(e) => Err(e),
                        };
                        match confirmed {
                            Ok((read, write)) => DuplexStream::new(read, write),
                            Err(e) => {
                                tracing::debug!(
                                    peer = %remote.fmt_short(),
                                    "direct socket stream failed: {e}"
                                );
                                return;
                            }
                        }
                    }
                    None => DuplexStream::new(recv, send),
                };
                let (peer_gone_tx, peer_gone_rx) = tokio::sync::oneshot::channel();
                let watcher = tokio::spawn(async move {
                    peer_gone.await;
                    let _ = peer_gone_tx.send(SockStatus::Deadline);
                });
                let status = handler.service.run(admission, stream, peer_gone_rx).await;
                watcher.abort();
                let mut control = control.lock().await;
                let _ = frame::write_frame(&mut control, &SockClosed { stream_id, status }).await;
            });
        }
        // Router treats the handler future as the lifetime of the connection.
        // Keep it alive until the detached stream tasks have written their
        // completion frames; returning here earlier closes the control stream
        // underneath them.
        if self.state.is_stopping() {
            self.state.drained().await;
        }
        Ok(())
    }
}

impl SockProtocol {
    /// The request handshake: read the frame, then admit and answer, or list
    /// and answer.
    ///
    /// Returns the admission, with its TCP connection when its bytes travel
    /// over one, or `None` when the stream never became an invocation — a
    /// refusal, or a `List` reply, is already on the wire in its own frame,
    /// and repeating it as a status would say the same thing twice in two
    /// vocabularies. So is a direct offer the caller never took up: nothing
    /// ran, and the caller asks again. This is the phase the caller's timeout
    /// and in-flight permit cover: a stream that never completes it has no
    /// runtime of its own, so it must not own a task for as long as the peer
    /// likes.
    async fn open_stream(
        &self,
        peer: NodeId,
        addr: String,
        index: u64,
        connection: &Connection,
        send: &mut iroh::endpoint::SendStream,
        recv: &mut iroh::endpoint::RecvStream,
    ) -> Option<(Admission, Option<Accepted>)> {
        let request = match tokio::select! {
            _ = self.state.cancelled() => {
                let _ = frame::write_frame(
                    send,
                    &SockOpened::Refused {
                        code: RefuseCode::Busy,
                        message: "the node is shutting down".into(),
                    },
                ).await;
                let _ = send.finish();
                return None;
            }
            request = read_request(recv) => request,
        } {
            Ok(request) => request,
            Err(e) => {
                tracing::debug!(peer = %peer.fmt_short(), "bad socket request: {e}");
                let _ = frame::write_frame(
                    send,
                    &SockOpened::Refused {
                        code: RefuseCode::NoSuchPath,
                        message: format!("malformed request: {e}"),
                    },
                )
                .await;
                let _ = send.finish();
                return None;
            }
        };
        let (open, wants_direct) = match request {
            SockRequest::Open(open) => (open, false),
            SockRequest::OpenDirect(open) => (open, true),
            SockRequest::List => {
                let sockets = tokio::select! {
                    _ = self.state.cancelled() => Vec::new(),
                    sockets = self.service.list(peer) => sockets,
                };
                let _ = frame::write_frame(send, &SockListed { sockets }).await;
                let _ = send.finish();
                return None;
            }
        };

        let admission = match tokio::select! {
            _ = self.state.cancelled() => {
                let _ = frame::write_frame(
                    send,
                    &SockOpened::Refused {
                        code: RefuseCode::Busy,
                        message: "the node is shutting down".into(),
                    },
                ).await;
                let _ = send.finish();
                return None;
            }
            admission = self.service.admit(peer, addr, index, &open) => admission,
        } {
            Ok(admission) => admission,
            Err((code, message)) => {
                tracing::debug!(
                    peer = %peer.fmt_short(),
                    socket = open.socket,
                    "socket refused: {} ({message})", code.as_str()
                );
                let _ = frame::write_frame(send, &SockOpened::Refused { code, message }).await;
                let _ = send.finish();
                return None;
            }
        };

        if wants_direct {
            if let Some(listener) = &self.direct {
                if crate::direct::direct_path(connection).is_some() {
                    let accepted = self
                        .offer_direct(listener, connection, send, &open, &admission)
                        .await;
                    return accepted.map(|accepted| (admission, Some(accepted)));
                }
            }
        }

        let accepted = SockOpened::Ok {
            program: admission.program_root,
            program_path: admission.program_path.clone(),
            invocation: admission.id,
        };
        if frame::write_frame(send, &accepted).await.is_err() {
            return None;
        }
        Some((admission, None))
    }

    /// Answers an admitted `OpenDirect` with an offer and waits for the
    /// caller's TCP connection, as a streamed run's provider does.
    ///
    /// `None` when the caller did not take the offer up — its connection
    /// never came, it stopped the stream, the QUIC connection closed, the
    /// node began shutting down — and then the admission is dropped with
    /// nothing run. The key and the ticket live in this future until the
    /// connection is handed over, and are dropped with it otherwise.
    async fn offer_direct(
        &self,
        listener: &DirectListener,
        connection: &Connection,
        send: &mut iroh::endpoint::SendStream,
        open: &SockOpen,
        admission: &Admission,
    ) -> Option<Accepted> {
        let drawn = crate::direct::draw().and_then(|ticket| {
            let secret = DirectSecret::from_bytes(crate::direct::draw()?);
            let keys = SockKeys::derive(&secret, &ticket, open, admission.id)?;
            Ok((ticket, secret, keys))
        });
        let (ticket, secret, keys) = match drawn {
            Ok(drawn) => drawn,
            Err(e) => {
                tracing::warn!("no direct offer for a socket: {e}");
                return None;
            }
        };
        let (ticket_held, delivered) = listener.register(ticket, keys.hello);
        let offer = SockOpened::Direct {
            program: admission.program_root,
            program_path: admission.program_path.clone(),
            invocation: admission.id,
            port: listener.port(),
            ticket,
            secret,
        };
        crate::direct::write_offer(send, &offer, MAX_OPENED_FRAME_LEN)
            .await
            .ok()?;
        drop(offer);

        let socket = tokio::select! {
            delivered = tokio::time::timeout(crate::direct::accept_timeout(), delivered) => {
                delivered.ok()?.ok()?
            }
            _ = send.stopped() => return None,
            _ = connection.closed() => return None,
            _ = self.state.cancelled() => return None,
        };
        drop(ticket_held);
        Some(Accepted {
            socket,
            read: keys.up,
            write: keys.down,
        })
    }
}

/// Resolves when the caller has gone: its connection closed, or — when given
/// the invocation's stream being stopped — it dropped that stream.
async fn caller_gone<F: std::future::Future>(connection: Connection, stopped: Option<F>) {
    match stopped {
        Some(stopped) => tokio::select! {
            _ = connection.closed() => {}
            _ = stopped => {}
        },
        None => {
            connection.closed().await;
        }
    }
}

/// Reads and validates the request frame.
///
/// The frame bound is applied by the framing layer before the decode, so an
/// oversized request never becomes an allocation. Validation runs before the
/// service sees it, so nothing downstream has to reason about a name with
/// `..` in it.
async fn read_request(recv: &mut iroh::endpoint::RecvStream) -> Result<SockRequest, NetError> {
    let bytes = frame::read_bounded(recv, MAX_OPEN_FRAME_LEN).await?;
    let request: SockRequest =
        postcard::from_bytes(&bytes).map_err(|e| NetError::Decode(format!("request: {e}")))?;
    if let SockRequest::Open(open) = &request {
        open.validate()
            .map_err(|e| NetError::Unexpected(e.to_string()))?;
    }
    Ok(request)
}

/// The connecting side: one QUIC connection, one stream per invocation.
#[derive(Debug)]
pub struct SockClient {
    connection: Connection,
    /// Present when this node asks for direct streams, with the peers whose
    /// direct path did not work (`docs/DIRECT-TCP.md`).
    direct: Option<Arc<DirectMemo>>,
}

/// A live invocation on the caller's side.
#[derive(Debug)]
pub struct SockStream {
    /// The content root the callee says is running, so the caller can audit
    /// what it actually reached.
    pub program: synch_core::Hash,
    /// `<space>/<path>` of that program on the callee, so a caller that can
    /// read the program's space can `synch cat` it and compare roots.
    pub program_path: String,
    /// The callee's id for this invocation.
    pub invocation: u64,
    /// Bytes to the program.
    pub send: SockSend,
    /// Bytes from the program.
    pub recv: SockRecv,
}

impl SockStream {
    /// Whether the bytes travel over a direct TCP connection rather than the
    /// QUIC stream (`docs/DIRECT-TCP.md`).
    pub fn is_direct(&self) -> bool {
        matches!(self.recv, SockRecv::Direct(_))
    }
}

/// Bytes to the program: the invocation's QUIC stream, or its direct TCP
/// connection. Shutting it down is the half-close the program reads as EOF.
#[derive(Debug)]
pub enum SockSend {
    /// On the QUIC stream.
    Quic(iroh::endpoint::SendStream),
    /// Sealed into records on the direct connection.
    Direct(DirectSend),
}

/// Bytes from the program: the invocation's QUIC stream, or its direct TCP
/// connection.
#[derive(Debug)]
pub enum SockRecv {
    /// On the QUIC stream.
    Quic(iroh::endpoint::RecvStream),
    /// Opened from records on the direct connection.
    Direct(DirectRecv),
}

/// The writing half of a direct socket stream.
#[derive(Debug)]
pub struct DirectSend(Box<DirectWrite>);

/// The reading half of a direct socket stream.
#[derive(Debug)]
pub struct DirectRecv(Box<DirectRead>);

impl AsyncWrite for SockSend {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            // The trait's, not the stream's own `poll_write`, which reports
            // a QUIC error rather than an I/O one.
            SockSend::Quic(send) => AsyncWrite::poll_write(std::pin::Pin::new(send), cx, buf),
            SockSend::Direct(DirectSend(send)) => {
                std::pin::Pin::new(&mut **send).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SockSend::Quic(send) => std::pin::Pin::new(send).poll_flush(cx),
            SockSend::Direct(DirectSend(send)) => std::pin::Pin::new(&mut **send).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SockSend::Quic(send) => std::pin::Pin::new(send).poll_shutdown(cx),
            SockSend::Direct(DirectSend(send)) => std::pin::Pin::new(&mut **send).poll_shutdown(cx),
        }
    }
}

impl AsyncRead for SockRecv {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            SockRecv::Quic(recv) => AsyncRead::poll_read(std::pin::Pin::new(recv), cx, buf),
            SockRecv::Direct(DirectRecv(recv)) => {
                std::pin::Pin::new(&mut **recv).poll_read(cx, buf)
            }
        }
    }
}

/// How an `OpenDirect` went.
enum Direct {
    /// An invocation, over TCP or — when the callee could not offer — QUIC.
    Opened(SockStream),
    /// The callee refused it, or could not read it.
    Refused(Refused),
    /// The callee offered, and its offer could not be taken up.
    Unreachable(NetError),
}

/// Why an `Open` did not become an invocation.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{}: {message}", code.as_str())]
pub struct Refused {
    /// The machine-readable reason.
    pub code: RefuseCode,
    /// What the callee said about it.
    pub message: String,
}

impl SockClient {
    /// Wraps an established connection on this ALPN.
    pub fn new(connection: Connection) -> Self {
        SockClient {
            connection,
            direct: None,
        }
    }

    /// The same client, asking for direct streams where it can.
    pub(crate) fn with_direct(mut self, memo: Option<Arc<DirectMemo>>) -> Self {
        self.direct = memo;
        self
    }

    /// Opens one invocation.
    ///
    /// Over a direct TCP connection when this node asks for them, the callee
    /// offers one, and the connection has a direct path to dial
    /// (`docs/DIRECT-TCP.md`); on the QUIC stream otherwise. A callee whose
    /// offer could not be taken up, or that predates direct streams, is asked
    /// again on QUIC, and not asked for a direct stream for a while.
    pub async fn open(&self, open: &SockOpen) -> Result<Result<SockStream, Refused>, NetError> {
        open.validate()
            .map_err(|e| NetError::Unexpected(e.to_string()))?;
        let peer = self.connection.remote_id();
        let direct = self
            .direct
            .as_ref()
            .filter(|memo| !memo.refused(&peer))
            .and_then(|memo| Some((memo, crate::direct::direct_path(&self.connection)?)));
        let Some((memo, addr)) = direct else {
            return self.open_quic(open).await;
        };
        match self.open_direct(open, addr).await? {
            Direct::Opened(stream) => Ok(Ok(stream)),
            // A callee that cannot decode `OpenDirect` refuses it as a
            // malformed frame, under the code an unknown socket gets. Asking
            // again with `Open` tells the two apart: a callee that admits
            // the same socket that way is one to stop asking.
            Direct::Refused(refused) if refused.code == RefuseCode::NoSuchPath => {
                let answer = self.open_quic(open).await?;
                if answer.is_ok() {
                    memo.refuse(peer);
                }
                Ok(answer)
            }
            Direct::Refused(refused) => Ok(Err(refused)),
            Direct::Unreachable(error) => {
                tracing::debug!(peer = %peer.fmt_short(), "no direct socket stream: {error}");
                memo.refuse(peer);
                self.open_quic(open).await
            }
        }
    }

    /// Opens one invocation on its QUIC stream.
    async fn open_quic(&self, open: &SockOpen) -> Result<Result<SockStream, Refused>, NetError> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| NetError::Unexpected(e.to_string()))?;
        frame::write_frame(&mut send, &SockRequest::Open(open.clone())).await?;

        let answer: SockOpened = frame::read_frame(&mut recv).await?;
        match answer {
            SockOpened::Ok {
                program,
                program_path,
                invocation,
            } => Ok(Ok(SockStream {
                program,
                program_path,
                invocation,
                send: SockSend::Quic(send),
                recv: SockRecv::Quic(recv),
            })),
            SockOpened::Refused { code, message } => Ok(Err(Refused { code, message })),
            SockOpened::Direct { .. } => Err(NetError::Unexpected(
                "the callee offered a direct stream that was not asked for".into(),
            )),
        }
    }

    /// Asks for one invocation over a direct TCP connection to `addr`'s IP,
    /// and takes up the offer if one comes.
    ///
    /// The offer's key arrives on this connection and lives no longer than
    /// it: closing the connection, or the callee dropping the invocation's
    /// stream, destroys the key and fails the stream.
    async fn open_direct(&self, open: &SockOpen, mut addr: SocketAddr) -> Result<Direct, NetError> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| NetError::Unexpected(e.to_string()))?;
        frame::write_frame(&mut send, &SockRequest::OpenDirect(open.clone())).await?;

        let answer = crate::direct::read_offer(&mut recv, MAX_OPENED_FRAME_LEN)
            .await?
            .ok_or_else(|| NetError::Read("the callee answered nothing".into()))?;
        let (program, program_path, invocation, port, ticket, secret) = match answer {
            SockOpened::Ok {
                program,
                program_path,
                invocation,
            } => {
                return Ok(Direct::Opened(SockStream {
                    program,
                    program_path,
                    invocation,
                    send: SockSend::Quic(send),
                    recv: SockRecv::Quic(recv),
                }))
            }
            SockOpened::Refused { code, message } => {
                return Ok(Direct::Refused(Refused { code, message }))
            }
            SockOpened::Direct {
                program,
                program_path,
                invocation,
                port,
                ticket,
                secret,
            } => (program, program_path, invocation, port, ticket, secret),
        };
        let keys = SockKeys::derive(&secret, &ticket, open, invocation)?;
        drop(secret);
        addr.set_port(port);
        // Dropping the stream on the way out stops it, which drops the
        // admission on the callee before anything runs.
        let socket = match crate::direct::dial(addr, &ticket, &keys.hello).await {
            Ok(socket) => socket,
            Err(error) => return Ok(Direct::Unreachable(error)),
        };
        let gone = {
            let connection = self.connection.clone();
            async move {
                connection.closed().await;
            }
        };
        let (mut read, write) =
            match crate::direct::stream::split(socket, keys.down, keys.up, gone, (send, recv)) {
                Ok(halves) => halves,
                Err(error) => return Ok(Direct::Unreachable(error)),
            };
        match tokio::time::timeout(CONFIRM_TIMEOUT, read.confirmed()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Ok(Direct::Unreachable(NetError::Direct(format!(
                    "the stream was not confirmed: {error}"
                ))))
            }
            Err(_) => {
                return Ok(Direct::Unreachable(NetError::Direct(format!(
                    "the stream was not confirmed within {}s",
                    CONFIRM_TIMEOUT.as_secs()
                ))))
            }
        }
        Ok(Direct::Opened(SockStream {
            program,
            program_path,
            invocation,
            send: SockSend::Direct(DirectSend(Box::new(write))),
            recv: SockRecv::Direct(DirectRecv(Box::new(read))),
        }))
    }

    /// Asks which sockets this caller may open (`docs/SOCKET-PROGRAMS.md` §5).
    ///
    /// One bi-stream, one frame each way, and the stream is done: `List`
    /// never becomes an invocation.
    pub async fn list(&self) -> Result<Vec<SockEntry>, NetError> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| NetError::Unexpected(e.to_string()))?;
        frame::write_frame(&mut send, &SockRequest::List).await?;
        let _ = send.finish();
        let bytes = frame::read_bounded(&mut recv, synch_core::MAX_LIST_FRAME_LEN).await?;
        let listed: SockListed =
            postcard::from_bytes(&bytes).map_err(|e| NetError::Decode(format!("Listed: {e}")))?;
        Ok(listed.sockets)
    }

    /// Reads the next completed-invocation notice from the control stream.
    ///
    /// Best effort: a caller that only pipes bytes never has to touch this, and
    /// one that wants an exit status waits on it after its stream ends.
    pub async fn next_closed(
        &self,
        control: &mut iroh::endpoint::RecvStream,
    ) -> Result<SockClosed, NetError> {
        frame::read_frame(control).await
    }

    /// Accepts the callee's control uni-stream.
    pub async fn control(&self) -> Result<iroh::endpoint::RecvStream, NetError> {
        let mut control = self
            .connection
            .accept_uni()
            .await
            .map_err(|e| NetError::Unexpected(e.to_string()))?;
        let mut ready = [0u8; CONTROL_READY.len()];
        control.read_exact(&mut ready).await?;
        if ready != CONTROL_READY {
            return Err(NetError::Unexpected(
                "socket control stream has an invalid preamble".into(),
            ));
        }
        Ok(control)
    }

    /// The underlying connection, for callers that want to close it.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        endpoint::NetOptions,
        testing::{test_store, trusting_pair},
    };
    use synch_core::{Hash, OriginId};
    use synch_sock::{EffectivePolicy, HostError, ObjectInfo, PeerIdentity, SocketHost, SocketId};

    #[derive(Debug)]
    struct NoTree;

    #[async_trait::async_trait]
    impl SocketHost for NoTree {
        fn open(&self, _origin: Option<&str>, _path: &str) -> Result<ObjectInfo, HostError> {
            Err(HostError::NotFound)
        }

        fn open_root(&self, _root: &Hash) -> Result<ObjectInfo, HostError> {
            Err(HostError::NotFound)
        }

        fn list_page(
            &self,
            _prefix: &str,
            _start_after: Option<&str>,
            _limit: usize,
        ) -> Result<synch_sock::ListPage, HostError> {
            Err(HostError::NotFound)
        }

        async fn pread(&self, _root: Hash, _offset: u64, _len: u64) -> Result<Vec<u8>, HostError> {
            Err(HostError::NotFound)
        }
    }

    #[derive(Debug, Default)]
    struct ShutdownService {
        release: tokio::sync::Notify,
    }

    fn admission(peer: NodeId, addr: String, stream_index: u64, open: &SockOpen) -> Admission {
        Admission {
            program: Arc::new(Vec::new()),
            program_root: Hash::EMPTY,
            program_path: "code/hold.o".into(),
            socket: SocketId::new(&open.socket),
            peer: PeerIdentity {
                origin: OriginId::Key(peer),
                device_key: peer,
                spaces: None,
                addr,
                stream_index,
            },
            policy: EffectivePolicy::default(),
            meta: open.meta.clone(),
            self_origin: open.origin.clone(),
            host: Arc::new(NoTree),
            id: 7,
            slot: None,
        }
    }

    #[async_trait::async_trait]
    impl SocketService for ShutdownService {
        async fn admit(
            &self,
            peer: NodeId,
            addr: String,
            stream_index: u64,
            open: &SockOpen,
        ) -> Result<Admission, (RefuseCode, String)> {
            Ok(admission(peer, addr, stream_index, open))
        }

        async fn list(&self, _peer: NodeId) -> Vec<synch_core::SockEntry> {
            vec![synch_core::SockEntry {
                name: "hold".into(),
                program: Hash::EMPTY,
                program_path: "code/hold.o".into(),
                note: String::new(),
            }]
        }

        async fn run(
            &self,
            _admission: Admission,
            _stream: DuplexStream,
            _peer_gone: tokio::sync::oneshot::Receiver<SockStatus>,
        ) -> SockStatus {
            self.release.notified().await;
            SockStatus::Shutdown
        }
    }

    #[tokio::test]
    async fn drain_flushes_shutdown_status_before_endpoint_close() {
        let (_server_dir, store) = test_store();
        let service = Arc::new(ShutdownService::default());
        let options = NetOptions {
            sockets: Some(service.clone()),
            ..NetOptions::loopback()
        };
        let (server, client, _client_dir) = trusting_pair(store, options).await;
        let socket = client.connect_sock(server.direct_addr()).await.unwrap();
        let open = SockOpen::new(OriginId::Key(server.id()), "hold", vec![]);
        let mut control = socket.control().await.unwrap();
        let stream = socket.open(&open).await.unwrap().unwrap();
        assert_eq!(stream.program_path, "code/hold.o");

        // `List` is answered on a stream of its own and never becomes an
        // invocation, so nothing about it reaches the control stream and it is
        // not what the drain below has to flush.
        let listed = socket.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "hold");
        assert_eq!(listed[0].program_path, "code/hold.o");

        server.stop_socket_admission();
        service.release.notify_one();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.drain_socket_streams(),
        )
        .await
        .expect("accepted socket streams drain");

        let closed = socket.next_closed(&mut control).await.unwrap();
        assert_eq!(closed.status, SockStatus::Shutdown);
        assert_eq!(closed.stream_id, 0);

        drop(stream);
        drop(control);
        drop(socket);
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    /// Echoes what it reads until EOF, then half-closes; or ends when its
    /// caller goes. Refuses its first `refuse` admissions as an unknown
    /// socket, as a callee that cannot read `OpenDirect` refuses that.
    #[derive(Debug, Default)]
    struct EchoService {
        refuse: std::sync::Mutex<usize>,
        admitted: AtomicUsize,
        ended: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SocketService for EchoService {
        async fn admit(
            &self,
            peer: NodeId,
            addr: String,
            stream_index: u64,
            open: &SockOpen,
        ) -> Result<Admission, (RefuseCode, String)> {
            {
                let mut refuse = self.refuse.lock().unwrap();
                if *refuse > 0 {
                    *refuse -= 1;
                    return Err((RefuseCode::NoSuchPath, "malformed request".into()));
                }
            }
            self.admitted.fetch_add(1, Ordering::AcqRel);
            Ok(admission(peer, addr, stream_index, open))
        }

        async fn list(&self, _peer: NodeId) -> Vec<synch_core::SockEntry> {
            Vec::new()
        }

        async fn run(
            &self,
            _admission: Admission,
            stream: DuplexStream,
            peer_gone: tokio::sync::oneshot::Receiver<SockStatus>,
        ) -> SockStatus {
            use tokio::io::AsyncWriteExt;
            let DuplexStream {
                mut reader,
                mut writer,
            } = stream;
            let status = tokio::select! {
                copied = tokio::io::copy(&mut reader, &mut writer) => match copied {
                    Ok(n) => match writer.shutdown().await {
                        Ok(()) => SockStatus::Ok(n as i64),
                        Err(_) => SockStatus::Deadline,
                    },
                    Err(_) => SockStatus::Deadline,
                },
                gone = peer_gone => gone.unwrap_or(SockStatus::Deadline),
            };
            self.ended.fetch_add(1, Ordering::AcqRel);
            status
        }
    }

    /// A callee serving `service`, offering direct streams when `offers`,
    /// and a caller connected to it that asks for them.
    async fn direct_pair(
        service: Arc<EchoService>,
        offers: bool,
    ) -> (
        crate::endpoint::Net,
        crate::endpoint::Net,
        tempfile::TempDir,
        tempfile::TempDir,
        SockClient,
        Arc<DirectMemo>,
    ) {
        let (server_dir, store) = test_store();
        let options = NetOptions {
            sockets: Some(service),
            direct_listen: offers.then(|| "127.0.0.1:0".parse().unwrap()),
            ..NetOptions::loopback()
        };
        let (server, client, client_dir) = trusting_pair(store, options).await;
        let memo = Arc::new(DirectMemo::default());
        let socket = client
            .connect_sock(server.direct_addr())
            .await
            .unwrap()
            .with_direct(Some(memo.clone()));
        (server, client, server_dir, client_dir, socket, memo)
    }

    /// Writes `sent` and half-closes while reading everything back.
    async fn echo(stream: SockStream, sent: &[u8]) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let SockStream {
            mut send, mut recv, ..
        } = stream;
        let (written, echoed) = tokio::join!(
            async {
                send.write_all(sent).await?;
                send.shutdown().await
            },
            async {
                let mut echoed = Vec::new();
                recv.read_to_end(&mut echoed).await.map(|_| echoed)
            }
        );
        written.unwrap();
        echoed.unwrap()
    }

    /// Waits up to five seconds for `done` to hold.
    async fn eventually(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..500 {
            if done() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        done()
    }

    /// An invocation's bytes go over TCP where the callee offers it, and on
    /// the QUIC stream where it does not — the same bytes, the same
    /// half-close, the same status either way, and a callee that answers on
    /// QUIC is asked again next time.
    #[tokio::test]
    async fn a_socket_stream_goes_direct_where_the_callee_offers_and_on_quic_where_not() {
        let sent: Vec<u8> = (0..crate::direct::RECORD_LEN * 3 + 1000)
            .map(|i| (i % 251) as u8)
            .collect();
        for offers in [true, false] {
            let (server, client, _server_dir, _client_dir, socket, memo) =
                direct_pair(Arc::new(EchoService::default()), offers).await;
            let mut control = socket.control().await.unwrap();
            let open = SockOpen::new(OriginId::Key(server.id()), "echo", vec![]);
            let stream = socket.open(&open).await.unwrap().unwrap();
            assert_eq!(stream.is_direct(), offers);
            assert_eq!(stream.program_path, "code/hold.o");

            assert!(echo(stream, &sent).await == sent);
            let closed = socket.next_closed(&mut control).await.unwrap();
            assert_eq!(closed.status, SockStatus::Ok(sent.len() as i64));
            assert!(!memo.refused(&server.id()));

            drop(control);
            drop(socket);
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
        }
    }

    /// An offer the caller cannot take up — the port does not accept — costs
    /// one try: the admission it held is dropped with nothing run, the same
    /// socket opens on QUIC, and the caller stops asking that callee.
    #[tokio::test]
    async fn a_direct_offer_that_cannot_be_taken_up_opens_on_quic() {
        let service = Arc::new(EchoService::default());
        let (server, client, _server_dir, _client_dir, socket, memo) =
            direct_pair(service.clone(), true).await;
        let port = server.direct_port().unwrap();
        server.stop_direct();
        assert!(
            eventually(|| std::net::TcpStream::connect(("127.0.0.1", port)).is_err()).await,
            "the stopped listener still accepts"
        );

        let open = SockOpen::new(OriginId::Key(server.id()), "echo", vec![]);
        let stream = socket.open(&open).await.unwrap().unwrap();
        assert!(!stream.is_direct());
        assert!(echo(stream, b"over quic").await == b"over quic");
        assert!(memo.refused(&server.id()));
        assert_eq!(service.admitted.load(Ordering::Acquire), 2);
        assert!(
            eventually(|| service.ended.load(Ordering::Acquire) == 1).await,
            "only the invocation that was taken up ran"
        );
        assert_eq!(server.direct_pending(), 0);

        drop(socket);
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    /// A callee that cannot read `OpenDirect` refuses it as a malformed
    /// frame, under the code an unknown socket gets: asked again with `Open`,
    /// it admits the socket, and is not asked for a direct stream again. A
    /// socket that really is unknown is refused both ways, and that is no
    /// reason to stop asking.
    #[tokio::test]
    async fn a_callee_that_cannot_read_open_direct_is_asked_with_open() {
        let service = Arc::new(EchoService::default());
        let (server, client, _server_dir, _client_dir, socket, memo) =
            direct_pair(service.clone(), true).await;
        let open = SockOpen::new(OriginId::Key(server.id()), "echo", vec![]);

        *service.refuse.lock().unwrap() = 2;
        let refused = socket.open(&open).await.unwrap().unwrap_err();
        assert_eq!(refused.code, RefuseCode::NoSuchPath);
        assert!(!memo.refused(&server.id()));

        *service.refuse.lock().unwrap() = 1;
        let stream = socket.open(&open).await.unwrap().unwrap();
        assert!(!stream.is_direct());
        assert!(echo(stream, b"old callee").await == b"old callee");
        assert!(memo.refused(&server.id()));

        drop(socket);
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    /// A direct stream lives no longer than the QUIC connection that carried
    /// its keys: when it closes, a read waiting on the TCP connection fails
    /// at once — never an EOF the caller could take for the program's — and
    /// the callee's invocation ends.
    #[tokio::test]
    async fn a_direct_stream_ends_with_its_quic_connection() {
        use tokio::io::AsyncReadExt;
        let service = Arc::new(EchoService::default());
        let (server, client, _server_dir, _client_dir, socket, _memo) =
            direct_pair(service.clone(), true).await;
        let open = SockOpen::new(OriginId::Key(server.id()), "echo", vec![]);
        let stream = socket.open(&open).await.unwrap().unwrap();
        assert!(stream.is_direct());
        let SockStream {
            send: _send,
            mut recv,
            ..
        } = stream;

        socket.connection().close(0u32.into(), b"done");
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut byte))
            .await
            .expect("the read ends with the connection");
        assert!(read.is_err(), "a closed connection is not an EOF: {read:?}");
        assert!(
            eventually(|| service.ended.load(Ordering::Acquire) == 1).await,
            "the callee's invocation ends with the connection"
        );

        drop(socket);
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }
}
