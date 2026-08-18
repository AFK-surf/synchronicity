//! The blocking-pool handoff, pinned to this crate's error type.
//!
//! The implementation is [`crate::blocking::offload`], shared with every other crate
//! that needs it. This is only the type pin: without it each call site has to
//! annotate the error type, since the generic helper cannot infer it from a
//! bare `Ok(())`.
//!
//! Why anything is offloaded at all: both ALPN handlers run inside iroh's
//! connection tasks, on the same workers that drive every other connection,
//! timer, and control request in the process. Serving a slice reads a payload
//! and an outboard off disk; receiving one decodes into sparse files and fsyncs
//! them; a head offer walks a trie in SQLite. All of it is blocking and bounded
//! by object or tree size rather than by anything the runtime can interrupt, so
//! a single large transfer served inline would stall every other connection
//! this node has. What stays inline is the per-connection and per-stream binding
//! check in `serve`: one indexed row, on a path that runs before a request is
//! even read, where the handoff would cost more than the work. Everything a
//! *request* costs is offloaded, including the two metadata handlers —
//! `FindProviders` and `GetBindings` — that used to be judged small enough to
//! run here: `providers` holds the one connection mutex across a row loop and a
//! postcard decode per row, which is not a bounded lookup at all when an origin
//! chooses what is in those rows (§12).

use crate::error::NetError;

/// Runs a blocking store operation on the blocking pool and awaits its result.
pub(crate) async fn offload<T, F>(f: F) -> Result<T, NetError>
where
    F: FnOnce() -> Result<T, NetError> + Send + 'static,
    T: Send + 'static,
{
    synch_core::offload(f).await
}
