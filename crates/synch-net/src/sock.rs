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
//! That last one is why this ALPN does not reuse [`serve_connection`] the way
//! the other two do. Their connection loop bounds a stream at two minutes and a
//! connection at eight in flight, and both are right for a request/response
//! protocol and wrong here: a socket that proxies is *supposed* to be
//! long-lived, and its concurrency bound is the socket's own armed
//! `max_streams` rather than a number this layer picks.

use std::sync::Arc;

use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use synch_core::{
    NodeId, RefuseCode, SockClosed, SockOpen, SockOpened, SockStatus, MAX_OPEN_FRAME_LEN,
};
use synch_sock::{Admission, DuplexStream};
use synch_store::Store;

use crate::{error::NetError, frame};

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

    /// Runs an admitted invocation to completion.
    async fn run(&self, admission: Admission, stream: DuplexStream) -> SockStatus;
}

/// Serves `sync/sock/1`.
#[derive(Clone)]
pub struct SockProtocol {
    store: Arc<Store>,
    service: Arc<dyn SocketService>,
    on_unknown_key: Option<Arc<tokio::sync::Notify>>,
}

impl std::fmt::Debug for SockProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SockProtocol")
    }
}

impl SockProtocol {
    /// Builds a handler over a store and a service.
    pub fn new(store: Arc<Store>, service: Arc<dyn SocketService>) -> Self {
        SockProtocol {
            store,
            service,
            on_unknown_key: None,
        }
    }

    /// Rings `wake` whenever a connection is refused for an unknown key (§3.4).
    pub fn on_unknown_key(mut self, wake: Option<Arc<tokio::sync::Notify>>) -> Self {
        self.on_unknown_key = wake;
        self
    }
}

impl ProtocolHandler for SockProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();

        // The same accept gate the other two ALPNs use, and for the same
        // reason: a device key with no live binding is not a peer.
        if !crate::serve::trusted(&self.store, &remote).await {
            tracing::debug!(peer = %remote.fmt_short(), "refusing socket connection: no live binding");
            if let Some(wake) = &self.on_unknown_key {
                wake.notify_waiters();
            }
            connection.close(0u32.into(), b"untrusted");
            return Err(AcceptError::from_err(std::io::Error::other(
                "peer has no live binding",
            )));
        }

        // One uni-stream per connection, opened before anything is served, so
        // that a status always has somewhere to go. A trailer on the data
        // stream would cost a length prefix on every proxied byte, and a
        // RESET_STREAM would discard output the program had already written.
        let control = match connection.open_uni().await {
            Ok(stream) => Arc::new(tokio::sync::Mutex::new(stream)),
            Err(e) => {
                tracing::debug!(peer = %remote.fmt_short(), "no control stream: {e}");
                return Err(AcceptError::from_err(std::io::Error::other(e)));
            }
        };

        let mut index = 0u64;
        while let Ok((send, recv)) = connection.accept_bi().await {
            // Per stream, not just per connection: a binding revoked mid-session
            // must stop the next invocation rather than linger for the life of
            // the QUIC connection. A stream already running is left alone — it
            // is a conversation in progress, and cutting it here would be a
            // partial write to whatever the program is talking to.
            if !crate::serve::trusted(&self.store, &remote).await {
                tracing::debug!(peer = %remote.fmt_short(), "closing socket connection: binding lapsed");
                connection.close(0u32.into(), b"untrusted");
                break;
            }

            let stream_id = send.id().index();
            // The endpoint id rather than a socket address: iroh may be
            // carrying this connection over a relay or over any of several
            // paths, and `sy_peer_addr` says as much. What a program can rely
            // on is the device key, which is what authenticated the peer.
            let addr = remote.to_string();
            let handler = self.clone();
            let control = control.clone();
            let this_index = index;
            index += 1;

            tokio::spawn(async move {
                let status = handler
                    .serve_stream(remote, addr, this_index, send, recv)
                    .await;
                if let Some(status) = status {
                    let mut control = control.lock().await;
                    let _ =
                        frame::write_frame(&mut control, &SockClosed { stream_id, status }).await;
                }
            });
        }
        Ok(())
    }
}

impl SockProtocol {
    /// Handles one stream: the handshake, then the guest.
    ///
    /// Returns the status to publish on the control stream, or `None` when the
    /// stream never became an invocation — a refusal is already on the wire in
    /// its own frame, and repeating it as a status would say the same thing
    /// twice in two vocabularies.
    async fn serve_stream(
        &self,
        peer: NodeId,
        addr: String,
        index: u64,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) -> Option<SockStatus> {
        let open = match read_open(&mut recv).await {
            Ok(open) => open,
            Err(e) => {
                tracing::debug!(peer = %peer.fmt_short(), "bad socket Open: {e}");
                let _ = frame::write_frame(
                    &mut send,
                    &SockOpened::Refused {
                        code: RefuseCode::NoSuchPath,
                        message: format!("malformed Open: {e}"),
                    },
                )
                .await;
                let _ = send.finish();
                return None;
            }
        };

        let admission = match self.service.admit(peer, addr, index, &open).await {
            Ok(admission) => admission,
            Err((code, message)) => {
                tracing::debug!(
                    peer = %peer.fmt_short(),
                    socket = format!("{}/{}", open.space, open.path),
                    "socket refused: {} ({message})", code.as_str()
                );
                let _ = frame::write_frame(&mut send, &SockOpened::Refused { code, message }).await;
                let _ = send.finish();
                return None;
            }
        };

        let accepted = SockOpened::Ok {
            program: admission.program_root,
            invocation: admission.id,
        };
        if frame::write_frame(&mut send, &accepted).await.is_err() {
            return None;
        }

        // From here the stream is opaque bytes in both directions. Nothing in
        // this layer looks at them again.
        let status = self
            .service
            .run(admission, DuplexStream::new(recv, send))
            .await;
        Some(status)
    }
}

/// Reads and validates the `Open` frame.
///
/// The frame bound is applied by the framing layer before the decode, so an
/// oversized `Open` never becomes an allocation. Validation runs before the
/// service sees it, so nothing downstream has to reason about a path with `..`
/// in it.
async fn read_open(recv: &mut iroh::endpoint::RecvStream) -> Result<SockOpen, NetError> {
    let bytes = frame::read_bounded(recv, MAX_OPEN_FRAME_LEN).await?;
    let open: SockOpen =
        postcard::from_bytes(&bytes).map_err(|e| NetError::Decode(format!("Open: {e}")))?;
    open.validate()
        .map_err(|e| NetError::Unexpected(e.to_string()))?;
    Ok(open)
}

/// The connecting side: one QUIC connection, one stream per invocation.
#[derive(Debug)]
pub struct SockClient {
    connection: Connection,
}

/// A live invocation on the caller's side.
#[derive(Debug)]
pub struct SockStream {
    /// The content root the callee says is running, so the caller can audit
    /// what it actually reached.
    pub program: synch_core::Hash,
    /// The callee's id for this invocation.
    pub invocation: u64,
    /// Bytes to the program.
    pub send: iroh::endpoint::SendStream,
    /// Bytes from the program.
    pub recv: iroh::endpoint::RecvStream,
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
        SockClient { connection }
    }

    /// Opens one invocation.
    pub async fn open(&self, open: &SockOpen) -> Result<Result<SockStream, Refused>, NetError> {
        open.validate()
            .map_err(|e| NetError::Unexpected(e.to_string()))?;
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| NetError::Unexpected(e.to_string()))?;
        frame::write_frame(&mut send, open).await?;

        let answer: SockOpened = frame::read_frame(&mut recv).await?;
        match answer {
            SockOpened::Ok {
                program,
                invocation,
            } => Ok(Ok(SockStream {
                program,
                invocation,
                send,
                recv,
            })),
            SockOpened::Refused { code, message } => Ok(Err(Refused { code, message })),
        }
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
        self.connection
            .accept_uni()
            .await
            .map_err(|e| NetError::Unexpected(e.to_string()))
    }

    /// The underlying connection, for callers that want to close it.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}
