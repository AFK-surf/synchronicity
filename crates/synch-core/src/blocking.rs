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
//! The helper is generic over the caller's error: each crate pins it to its
//! own error type, and [`TaskLost`] is how the pool's two failure modes are
//! expressed in each of them.

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

/// The stack a deep-recursion worker runs with: 64 MiB.
///
/// Trie inserts and removes recurse one frame per nibble of key, and a legal
/// key is up to [`MAX_KEY_LEN`](crate::MAX_KEY_LEN) bytes — 8 192 frames, each
/// carrying a branch node's sixteen child slots. That does not fit the 2 MiB
/// stack a blocking-pool thread runs with, and a stack overflow is a process
/// abort rather than an error, so deep trie mutations get a stack sized for
/// the deepest legal key rather than the typical one.
const DEEP_STACK_BYTES: usize = 64 * 1024 * 1024;

/// Runs a blocking operation that needs deep recursion on a dedicated
/// big-stack thread, and awaits its result.
///
/// Same contract as [`offload`], except the work runs on a thread spawned for
/// the task with [`DEEP_STACK_BYTES`] of stack. Use it for work whose depth
/// scales with attacker-influenceable input — trie insert/remove over legal
/// maximal keys — not for ordinary blocking calls, which belong on the pool.
pub async fn offload_deep<T, E, F>(f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: TaskLost + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("deep-trie-work".into())
        .stack_size(DEEP_STACK_BYTES)
        .spawn(move || {
            let _ = tx.send(f());
        });
    match spawned {
        // The join handle is deliberately not awaited: the result channel is
        // the completion signal, and a detached thread finishes on its own.
        Ok(_) => match rx.await {
            Ok(result) => result,
            Err(_) => Err(E::task_lost("the deep-stack worker died mid-task".into())),
        },
        Err(e) => Err(E::task_lost(format!(
            "could not spawn a deep-stack worker: {e}"
        ))),
    }
}
