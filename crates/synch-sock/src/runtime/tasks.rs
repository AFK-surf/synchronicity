//! One place to track spawned work whose lifetime is bound to something else's.

use std::sync::Mutex;

use tokio::task::AbortHandle;

/// Abort handles for tasks that must not outlive their owner.
///
/// Tracking exists so teardown can cancel work that has not finished. A handle
/// for a task that *has* finished cancels nothing and is not free: tokio keeps
/// the task's cell — and with it the future's storage — alive for as long as an
/// `AbortHandle` names it. A set that only ever grows is therefore a leak
/// wearing a cancellation mechanism's clothes, and one bounded by how many
/// helper calls a guest makes rather than by how much work is actually live.
///
/// That is not hypothetical: `Inner::spawn` used to push and never prune, and
/// helpers that spawn once per call (`sy_pread`, `sy_tcp_connect`,
/// `sy_ssh_exit_status`) let a single invocation retain hundreds of megabytes
/// while `synch socket ps` reported a footprint under 1 MiB. `SshState` had the
/// pruning and `Inner` did not, which is the argument for one type rather than
/// one convention.
///
/// Finished handles are dropped on every insert, so the set stays proportional
/// to live work.
#[derive(Debug, Default)]
pub(crate) struct TaskSet(Mutex<Vec<AbortHandle>>);

impl TaskSet {
    /// Tracks one task, first dropping the handles of tasks that have ended.
    pub(crate) fn track(&self, handle: AbortHandle) {
        let mut tasks = self.lock();
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
    }

    /// Cancels everything still running and forgets all of it.
    pub(crate) fn abort_all(&self) {
        for task in self.lock().drain(..) {
            task.abort();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<AbortHandle>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
