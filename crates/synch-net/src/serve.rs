//! The connection lifecycle both ALPNs are served under (§3.2, §6.3).
//!
//! Everything either protocol does around a request is the same: refuse a
//! connection whose device key has no live binding and ring the §3.4 bell,
//! re-check the binding on every message rather than once per session, bound how
//! many requests one connection may have in flight, and bound how long any one
//! of them may take. What differs is only what a stream *carries*, which is the
//! closure each handler passes in.
//!
//! One implementation, because two drift: a stream deadline that exists on one
//! ALPN and not the other is not a policy, it is an oversight with a second
//! home to hide in.

use std::sync::Arc;

use iroh::{
    endpoint::{Connection, RecvStream, SendStream},
    protocol::AcceptError,
};
use synch_core::{now_ns, NodeId};
use synch_store::Store;

/// How many requests one connection may have in flight at once.
///
/// Handling streams one at a time to completion bounds nothing — a peer can
/// open more connections — while bounding throughput: the work behind a request
/// runs on the blocking pool, so a connection serializing its streams cannot
/// accept the next one while a window is being built, and §6.3's swarm
/// behaviour does not survive a client that pipelines.
///
/// Per connection, and only per connection — nothing caps how many connections
/// one peer opens, so this is not a bound on a node's concurrent work. It is
/// not meant to be: reaching this code at all requires a live binding, and §12
/// places a member that opens connections abusively under `synch trust rm`
/// rather than under a rate limiter. What this does bound is the cost of one
/// connection, which is what keeps an ordinary peer's pipelining from being
/// mistaken for that.
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 8;

/// How long one request may take, start to finish.
///
/// Covers the read as well as the work. iroh's transport already tears down a
/// peer that has crashed or been partitioned away — it keeps a 5 s keep-alive
/// against a 15 s idle timeout — so what this bounds is a peer that holds its
/// session open deliberately and sends nothing: without it that stream owns a
/// task for as long as the peer likes, and the per-message binding re-check
/// above never comes round again. Generous, because one window of a large
/// object is real disk work.
pub(crate) const STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Serves one accepted connection until the peer closes it or its binding
/// lapses.
///
/// `on_request` is called once when the connection is admitted and again for
/// every stream accepted on it, which is where a handler that tracks peer
/// sightings does its bookkeeping. `dispatch` handles one stream — under the
/// peer's cryptographically established device key, which the handshake settled
/// — reports its own failures to the peer in its own vocabulary, and finishes
/// the send side.
pub(crate) async fn serve_connection<D, F>(
    store: &Arc<Store>,
    connection: Connection,
    on_unknown_key: Option<&Arc<tokio::sync::Notify>>,
    mut on_request: impl FnMut(NodeId),
    dispatch: D,
) -> Result<(), AcceptError>
where
    D: Fn(NodeId, SendStream, RecvStream) -> F + Clone + Send + 'static,
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let remote = connection.remote_id();
    // Enforcement at connection-accept time (§3.2): connections from device
    // keys with no live binding are closed immediately after the handshake.
    match store.is_trusted_key(&remote, now_ns()) {
        Ok(true) => {}
        _ => {
            tracing::debug!(peer = %remote.fmt_short(), "refusing connection: no live binding");
            if let Some(wake) = on_unknown_key {
                wake.notify_waiters();
            }
            connection.close(0u32.into(), b"untrusted");
            return Err(AcceptError::from_err(std::io::Error::other(
                "peer has no live binding",
            )));
        }
    }
    on_request(remote);

    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS));
    while let Ok((send, recv)) = connection.accept_bi().await {
        // §3.2 enforcement is per message, not just per connection: a binding
        // revoked or expired mid-connection must cut off further requests, not
        // linger for the life of the QUIC session.
        if !matches!(store.is_trusted_key(&remote, now_ns()), Ok(true)) {
            tracing::debug!(peer = %remote.fmt_short(), "closing connection: binding lapsed");
            connection.close(0u32.into(), b"untrusted");
            break;
        }
        on_request(remote);
        let Ok(permit) = limit.clone().acquire_owned().await else {
            break;
        };
        let dispatch = dispatch.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if tokio::time::timeout(STREAM_TIMEOUT, dispatch(remote, send, recv))
                .await
                .is_err()
            {
                tracing::debug!(peer = %remote.fmt_short(), "stream timed out");
            }
        });
    }
    Ok(())
}
