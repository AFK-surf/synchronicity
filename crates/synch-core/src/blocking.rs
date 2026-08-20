//! Running blocking work off the async runtime (§10).
//!
//! Almost everything this system does to durable state is blocking, and
//! deliberately so: the store is runtime-agnostic, the scanner hashes files, the
//! CAS fsyncs payloads. What matters is *where* it runs. A worker thread hashing
//! a 10 GB file is not polling anything: the endpoint stops answering peers, the
//! control socket stops answering `synch status`, and the timers driving
//! anti-entropy fire late. So every blocking operation reachable from an async
//! context goes through [`offload`]. What a store call costs on a worker includes
//! waiting for the one connection mutex, which a publish batch or a GC pass may
//! hold for its entire run.
//!
//! # Making the rule checkable
//!
//! [`offload`] marks its thread with a [`BlockingScope`], and
//! [`assert_off_runtime`] turns "am I allowed to block here?" into a question
//! code can ask — the same shape as the `reentry::Scope` guard that made "no
//! `Store::conn()` inside a transaction" checkable. The check fires only on a
//! **multi-thread** runtime, which is what the daemon runs and what makes a
//! parked worker matter.

use std::cell::Cell;

thread_local! {
    /// How many [`BlockingScope`]s this thread is inside.
    static BLOCKING_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Marks its thread as running work that is allowed to block, until dropped.
///
/// Nested rather than boolean: a blocking closure may call another helper that
/// enters its own scope, and the inner one's end must not un-mark the thread.
#[derive(Debug)]
pub struct BlockingScope(());

impl BlockingScope {
    /// Enters a scope on the current thread.
    pub fn enter() -> BlockingScope {
        BLOCKING_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        BlockingScope(())
    }
}

impl Drop for BlockingScope {
    fn drop(&mut self) {
        BLOCKING_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// True if blocking work may run on this thread.
///
/// Three ways it may: the thread is inside a [`BlockingScope`] (so it is a
/// blocking-pool thread running an [`offload`]ed closure), there is no runtime
/// here at all (a CLI command, a plain `#[test]`, the store's own threads), or
/// the runtime is the single-threaded flavour a test drives by hand.
pub fn blocking_is_allowed() -> bool {
    if BLOCKING_DEPTH.with(Cell::get) > 0 {
        return true;
    }
    match tokio::runtime::Handle::try_current() {
        Err(_) => true,
        Ok(handle) => handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread,
    }
}

/// Ends the process in debug builds when blocking work is about to run on a
/// runtime worker.
///
/// `what` names the operation, so the report says which rule was broken rather
/// than only where. Release builds pay nothing: the whole check compiles away.
///
/// A panic inside a detached Tokio task only kills that task, so it may not reach
/// libtest or restart a standing loop. A violated invariant in a debug build is
/// not recoverable; aborting makes the failure visible at the offending stack.
///
#[track_caller]
pub fn assert_off_runtime(what: &str) {
    if cfg!(debug_assertions) && !blocking_is_allowed() {
        eprintln!(
            "{what} ran on a multi-thread runtime worker, at {}.\n\
             Blocking work belongs on the blocking pool (§10): wrap it in `blocking::offload`, \
             or enter a `BlockingScope` if this thread really is dedicated to blocking work.\n{}",
            std::panic::Location::caller(),
            std::backtrace::Backtrace::force_capture(),
        );
        std::process::abort();
    }
}

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
    match tokio::task::spawn_blocking(move || {
        let _scope = BlockingScope::enter();
        f()
    })
    .await
    {
        Ok(result) => result,
        Err(e) => Err(E::task_lost(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thread_with_no_runtime_may_block() {
        assert!(blocking_is_allowed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_multi_thread_worker_may_not_block_but_an_offloaded_closure_may() {
        assert!(
            !blocking_is_allowed(),
            "the test body itself is on a runtime worker"
        );
        let inside: Result<bool, Lost> = offload(|| Ok(blocking_is_allowed())).await;
        assert!(inside.unwrap(), "an offloaded closure is allowed to block");
        assert!(
            !blocking_is_allowed(),
            "and the scope ends with the closure"
        );
    }

    #[derive(Debug)]
    struct Lost(#[allow(dead_code)] String);

    impl TaskLost for Lost {
        fn task_lost(reason: String) -> Self {
            Lost(reason)
        }
    }
}
