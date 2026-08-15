//! Running the blocking half of the node off the async runtime (§10).
//!
//! Almost everything the node does to durable state is blocking: the scanner
//! walks directories and hashes files, the publisher writes a trie and commits
//! one SQLite transaction, the CAS reads and fsyncs payloads, mirrors copy
//! objects out of it. None of that is async, and none of it should be — the
//! store is deliberately runtime-agnostic (§10, "single writer task"), and
//! `tokio::fs` would only hide the same blocking calls behind a slower façade.
//!
//! What matters is *where* it runs. A tokio worker thread that is hashing a
//! 10 GB file is not polling anything: the endpoint stops answering peers, the
//! control socket stops answering `synch status`, and the timers that drive
//! anti-entropy fire late. The multi-thread runtime has one worker per core, so
//! a handful of concurrent scans is enough to stall the daemon outright.
//!
//! So every long or unbounded blocking operation reachable from an async
//! context goes through [`offload`], which moves it to tokio's blocking pool —
//! a separate, elastic set of threads meant for exactly this. Short bounded
//! metadata lookups (a single indexed `SELECT`, one `stat`) stay inline: the
//! handoff would cost more than the work.

use crate::error::{EngineError, Result};

/// Runs a blocking operation on the blocking pool and awaits its result.
///
/// The closure owns everything it touches, which is why [`Node`](crate::Node)
/// is cheap to clone: callers clone the handle into the closure rather than
/// borrowing across the await.
pub(crate) async fn offload<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        // The pool only fails a task by losing it: the closure panicked, or the
        // runtime is shutting down. Neither is something a caller can retry
        // into success, but both have to be reported rather than swallowed —
        // a publish that silently did not happen is the worst outcome here.
        Err(e) => Err(EngineError::Blocking(e.to_string())),
    }
}
