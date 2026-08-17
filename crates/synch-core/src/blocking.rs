//! Running blocking work off the async runtime (§10).
//!
//! Almost everything this system does to durable state is blocking, and
//! deliberately so: the store is runtime-agnostic, the scanner hashes files, the
//! CAS fsyncs payloads, a head offer walks a trie inside a SQLite transaction.
//! `tokio::fs` would only hide the same blocking calls behind a slower façade.
//!
//! What matters is *where* it runs. A worker thread hashing a 10 GB file is not
//! polling anything: the endpoint stops answering peers, the control socket
//! stops answering `synch status`, and the timers driving anti-entropy fire
//! late. The multi-thread runtime has one worker per core, so a handful of
//! concurrent scans stalls the daemon outright.
//!
//! So every long or unbounded blocking operation reachable from an async
//! context goes through [`offload`]. Short bounded metadata lookups — one
//! indexed `SELECT`, one `stat` — stay inline, where the handoff costs more
//! than the work.
//!
//! One helper, generic over the caller's error. There were three
//! near-identical copies of this — one per crate that needed it — differing
//! only in which error type they built on failure, which is what [`TaskLost`]
//! now abstracts.

/// An error type that can report a blocking task the pool lost.
///
/// The pool fails a task in exactly two ways: the closure panicked, or the
/// runtime is shutting down under it. Neither tells the caller what state the
/// operation was midway through, which is why it is surfaced rather than
/// treated as a no-op — a publish that silently did not happen is the worst
/// outcome available.
pub trait TaskLost {
    /// Builds the error for a task that did not run to completion.
    fn task_lost(reason: String) -> Self;
}

/// Runs a blocking operation on the blocking pool and awaits its result.
///
/// The closure owns everything it touches, so callers clone their handle into
/// it rather than borrowing across the await.
pub async fn offload<T, E, F>(f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: TaskLost + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(e) => Err(E::task_lost(e.to_string())),
    }
}
