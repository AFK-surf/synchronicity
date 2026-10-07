//! `sync/lock/1`: the cluster-lock claim exchange (`docs/LOCKS.md` §3, §9.2).
//!
//! The protocol is one request frame and one answer per stream, served under
//! the same membership gate and stream deadline as the other ALPNs
//! (`crate::serve`). What a request *means* — the lock table, authorization by
//! space, the decision — belongs to the engine, which hands the endpoint a
//! [`LockService`] the way it hands it a head sink.

use std::sync::Arc;

use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use synch_core::{LockMessage, NodeId};
use synch_store::Store;

use crate::{
    endpoint::under_deadline,
    error::NetError,
    frame::{read_frame, request, write_frame},
};

/// What answers lock requests: the engine's lock manager.
pub trait LockService: Send + Sync + std::fmt::Debug + 'static {
    /// Answers one request from the peer holding device key `peer`.
    ///
    /// Called on the blocking pool, because authorizing a request reads the
    /// bindings. The request has already passed [`LockMessage::check`].
    fn serve(&self, peer: NodeId, request: LockMessage) -> LockMessage;
}

/// The serve side of `sync/lock/1`.
#[derive(Debug, Clone)]
pub(crate) struct LockProtocol {
    store: Arc<Store>,
    service: Arc<dyn LockService>,
    on_unknown_key: Option<Arc<tokio::sync::Notify>>,
    inflight: crate::serve::Inflight,
}

impl LockProtocol {
    pub(crate) fn new(store: Arc<Store>, service: Arc<dyn LockService>) -> Self {
        LockProtocol {
            store,
            service,
            on_unknown_key: None,
            inflight: None,
        }
    }

    /// Rings `wake` when a connection is refused for an unknown key (§3.4).
    pub(crate) fn on_unknown_key(mut self, wake: Option<Arc<tokio::sync::Notify>>) -> Self {
        self.on_unknown_key = wake;
        self
    }

    /// Shares the endpoint-wide in-flight gate.
    pub(crate) fn inflight(mut self, gate: crate::serve::Inflight) -> Self {
        self.inflight = gate;
        self
    }
}

impl ProtocolHandler for LockProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let service = self.service.clone();
        crate::serve::serve_connection(
            &self.store,
            connection,
            self.on_unknown_key.as_ref(),
            &self.inflight,
            |_| async {},
            move |peer, mut send, mut recv, _progress| {
                let service = service.clone();
                async move {
                    let answer = match answer(&service, peer, &mut recv).await {
                        Ok(answer) => answer,
                        Err(e) => {
                            tracing::debug!(peer = %peer.fmt_short(), error = %e, "lock stream ended");
                            LockMessage::Refused {
                                reason: e.to_string(),
                            }
                        }
                    };
                    let _ = write_frame(&mut send, &answer).await;
                    let _ = send.finish();
                }
            },
        )
        .await
    }
}

async fn answer(
    service: &Arc<dyn LockService>,
    peer: NodeId,
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<LockMessage, NetError> {
    let request: LockMessage = read_frame(recv).await?;
    request.check().map_err(NetError::Unexpected)?;
    let service = service.clone();
    crate::blocking::offload(move || Ok(service.serve(peer, request))).await
}

/// The client side of `sync/lock/1`, over one held session.
#[derive(Debug, Clone)]
pub struct LockClient {
    connection: Connection,
}

impl LockClient {
    pub(crate) fn new(connection: Connection) -> Self {
        LockClient { connection }
    }

    /// The peer's device key.
    pub fn remote_id(&self) -> NodeId {
        self.connection.remote_id()
    }

    /// Sends one request and reads its answer within `deadline`.
    ///
    /// A peer's refusal comes back as [`LockMessage::Refused`] rather than as
    /// an error: a peer that refuses has answered — it cannot contend — and a
    /// claimant must not count it among the peers it waited on. An answer
    /// that breaks the protocol's bounds is refused like a malformed frame.
    pub async fn request(
        &self,
        message: &LockMessage,
        deadline: std::time::Duration,
    ) -> Result<LockMessage, NetError> {
        let answer: LockMessage = under_deadline(deadline, "a lock request", async {
            let mut recv = request(&self.connection, message).await?;
            read_frame(&mut recv).await
        })
        .await?;
        answer.check().map_err(NetError::Unexpected)?;
        Ok(answer)
    }
}
