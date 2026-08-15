//! Running store work off the async runtime.
//!
//! Both ALPN handlers run inside iroh's connection tasks, on the same runtime
//! workers that drive every other connection, timer, and control request in the
//! process. Serving a slice reads a payload and an outboard off disk; receiving
//! one decodes into sparse files and fsyncs them; a head offer walks a trie in
//! SQLite. All of it is blocking, and all of it is bounded by object or tree
//! size rather than by anything the runtime can interrupt — so a single large
//! transfer served inline would stall every other connection this node has.
//!
//! [`offload`] moves those operations to tokio's blocking pool. Bounded
//! metadata lookups — `is_trusted_key` on one indexed row, recording a peer
//! sighting — stay inline, where the handoff would cost more than the work.

use crate::error::NetError;

/// Runs a blocking store operation on the blocking pool and awaits its result.
pub(crate) async fn offload<T, F>(f: F) -> Result<T, NetError>
where
    F: FnOnce() -> Result<T, NetError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        // Either the closure panicked or the runtime is going down under it.
        // Neither leaves the caller anything to salvage, but a fetch that
        // silently kept none of what it verified would be worse than an error.
        Err(e) => Err(NetError::Blocking(e.to_string())),
    }
}
