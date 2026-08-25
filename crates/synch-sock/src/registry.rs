//! The live-invocation registry (`docs/SOCKETS.md` §9, §10).
//!
//! Four things want to know what is running right now, and none of them could
//! be built without somewhere to ask: `synch socket ps`, `synch socket kill`,
//! `synch socket log`, and the concurrency cap that turns a socket at its limit
//! into [`RefuseCode::Busy`](synch_core::RefuseCode::Busy) rather than into one
//! more invocation.
//!
//! It is deliberately *not* the worker's own bookkeeping. An invocation is
//! placed on a worker and stays there, so a worker knows its own and nothing
//! else; this is shared across the pool, behind a mutex, and every field an
//! operator reads is either written once at admission or lives in an atomic the
//! running invocation updates as it goes.
//!
//! Nothing here is durable. A restart has no live invocations by definition,
//! and recent log lines and fault history are working state, not a record: the
//! record of what a socket did is what it wrote to whatever it was talking to.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use synch_core::{Hash, NodeId};

use crate::limits::{FAULT_QUARANTINE, FAULT_WINDOW};

/// Recent `sy_log` lines kept per socket.
///
/// Small on purpose. This is a tail for "what did it just say?", not a log
/// store: every line also goes to the daemon's own log, which is where history
/// lives and where an operator's log tooling already points.
pub(crate) const MAX_LOG_LINES: usize = 256;

/// Counters a running invocation updates and an operator reads.
///
/// Atomics rather than a lock: they are written on the worker thread in the
/// middle of an invocation's hot path, and read by whoever is running
/// `synch socket ps`. A torn read across two counters is not worth a mutex on
/// every `sy_read`.
#[derive(Debug, Default)]
pub struct LiveStats {
    /// Bytes the program has read from the caller.
    pub bytes_in: AtomicU64,
    /// Bytes the program has written to the caller.
    pub bytes_out: AtomicU64,
    /// Handles the program currently holds, `SY_SELF` included.
    pub handles: AtomicU64,
    /// How many times it has parked in `sy_poll`.
    pub polls: AtomicU64,
    /// Labels it set with `sy_label_set`.
    pub labels: Mutex<Vec<(String, String)>>,
    /// Counters it bumped with `sy_metric_add`.
    pub metrics: Mutex<Vec<(String, i64)>>,
}

impl LiveStats {
    /// Replaces the label set, which the invocation owns.
    pub(crate) fn set_labels(&self, labels: Vec<(String, String)>) {
        *self.labels.lock().expect("live stats") = labels;
    }

    /// Replaces the metric set, which the invocation owns.
    pub(crate) fn set_metrics(&self, metrics: Vec<(String, i64)>) {
        *self.metrics.lock().expect("live stats") = metrics;
    }
}

/// One live invocation, as `synch socket ps` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationInfo {
    /// The callee's id for it — what `synch socket kill` takes.
    pub id: u64,
    /// `<space>/<path>`.
    pub socket: String,
    /// The caller's origin.
    pub peer: String,
    /// The caller's device key.
    pub peer_key: NodeId,
    /// The content root running.
    pub program: Hash,
    /// How long it has been running.
    pub age: Duration,
    /// Bytes read from the caller.
    pub bytes_in: u64,
    /// Bytes written to the caller.
    pub bytes_out: u64,
    /// Handles held.
    pub handles: u64,
    /// Times parked in `sy_poll`.
    pub polls: u64,
    /// Labels the program set.
    pub labels: Vec<(String, String)>,
    /// Counters the program bumped.
    pub metrics: Vec<(String, i64)>,
}

/// One remembered log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Unix nanoseconds when it was written.
    pub at: i64,
    /// Which invocation wrote it.
    pub invocation: u64,
    /// The line, already stripped of anything a terminal should not render.
    pub text: String,
}

struct Live {
    socket: String,
    peer: String,
    peer_key: NodeId,
    program: Hash,
    started: Instant,
    stats: Arc<LiveStats>,
    /// Dropping this ends the invocation. `None` once it has been used, or for
    /// an invocation nobody can cancel.
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Everything running, everything just said, and what has been failing.
#[derive(Debug, Default)]
pub struct Registry {
    live: Mutex<BTreeMap<u64, Live>>,
    logs: Mutex<HashMap<String, VecDeque<LogLine>>>,
    /// Per socket, whether each of the last [`FAULT_WINDOW`] invocations
    /// faulted. `true` is a fault.
    faults: Mutex<HashMap<(String, Hash), VecDeque<bool>>>,
    /// Sockets whose fault history has tripped the threshold and which nobody
    /// has acted on yet.
    ///
    /// A latch rather than a return value, because the two halves happen in
    /// different places: the worker sees the outcome and knows nothing about
    /// the store, and disarming is a store write. The worker sets it; the
    /// engine takes it and disarms.
    quarantined: Mutex<std::collections::HashSet<(String, Hash)>>,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live")
            .field("socket", &self.socket)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl Registry {
    /// A fresh, empty registry.
    pub fn new() -> Arc<Registry> {
        Arc::new(Registry::default())
    }

    /// Takes a concurrency slot for one invocation, or reports the socket full.
    ///
    /// Reserved at *admission*, not when the guest starts, and released when
    /// the guard drops. That is what makes the cap hold: the window between
    /// answering `Opened` and the first instruction running is a window a
    /// caller controls, and a cap checked at either end alone can be walked
    /// straight through by opening streams and not using them.
    #[allow(
        clippy::too_many_arguments,
        reason = "an entry is what it is: six facts about the caller and the \
                  program, and bundling them into a struct here would only move \
                  the argument list to its constructor"
    )]
    pub fn reserve(
        self: &Arc<Self>,
        id: u64,
        socket: &str,
        peer: &str,
        peer_key: NodeId,
        program: Hash,
        max_streams: usize,
        now: Instant,
    ) -> Option<SlotGuard> {
        let mut live = self.live.lock().expect("registry");
        let running = live.values().filter(|l| l.socket == socket).count();
        if running >= max_streams {
            return None;
        }
        let stats = Arc::new(LiveStats::default());
        live.insert(
            id,
            Live {
                socket: socket.to_string(),
                peer: peer.to_string(),
                peer_key,
                program,
                started: now,
                stats: stats.clone(),
                cancel: None,
            },
        );
        Some(SlotGuard {
            registry: self.clone(),
            id,
            socket: socket.to_string(),
            stats,
        })
    }

    /// Records the channel `synch socket kill` pulls.
    pub(crate) fn attach_cancel(&self, id: u64, cancel: tokio::sync::oneshot::Sender<()>) {
        if let Some(entry) = self.live.lock().expect("registry").get_mut(&id) {
            entry.cancel = Some(cancel);
        }
    }

    /// Ends one invocation, reporting whether there was one to end.
    ///
    /// The row is left in place: the invocation is still running until it
    /// notices, and a `ps` that hid it the instant a kill was asked for would
    /// be describing an intention rather than the state.
    pub fn kill(&self, id: u64) -> bool {
        let mut live = self.live.lock().expect("registry");
        match live.get_mut(&id).and_then(|entry| entry.cancel.take()) {
            Some(cancel) => cancel.send(()).is_ok(),
            None => false,
        }
    }

    /// Everything running, oldest first, optionally for one socket.
    pub fn snapshot(&self, socket: Option<&str>, now: Instant) -> Vec<InvocationInfo> {
        self.live
            .lock()
            .expect("registry")
            .iter()
            .filter(|(_, live)| socket.is_none_or(|want| live.socket == want))
            .map(|(id, live)| InvocationInfo {
                id: *id,
                socket: live.socket.clone(),
                peer: live.peer.clone(),
                peer_key: live.peer_key,
                program: live.program,
                age: now.saturating_duration_since(live.started),
                bytes_in: live.stats.bytes_in.load(Ordering::Relaxed),
                bytes_out: live.stats.bytes_out.load(Ordering::Relaxed),
                handles: live.stats.handles.load(Ordering::Relaxed),
                polls: live.stats.polls.load(Ordering::Relaxed),
                labels: live.stats.labels.lock().expect("live stats").clone(),
                metrics: live.stats.metrics.lock().expect("live stats").clone(),
            })
            .collect()
    }

    /// How many invocations of one socket are running.
    #[cfg(test)]
    pub fn running(&self, socket: &str) -> usize {
        self.live
            .lock()
            .expect("registry")
            .values()
            .filter(|l| l.socket == socket)
            .count()
    }

    /// Remembers a line one socket's program wrote.
    pub(crate) fn log_line(&self, socket: &str, invocation: u64, at: i64, text: String) {
        let mut logs = self.logs.lock().expect("registry logs");
        let ring = logs.entry(socket.to_string()).or_default();
        if ring.len() >= MAX_LOG_LINES {
            ring.pop_front();
        }
        ring.push_back(LogLine {
            at,
            invocation,
            text,
        });
    }

    /// The lines one socket has written recently, oldest first.
    pub fn logs(&self, socket: &str) -> Vec<LogLine> {
        self.logs
            .lock()
            .expect("registry logs")
            .get(socket)
            .map(|ring| ring.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Records how one invocation ended, and says whether the socket should be
    /// quarantined.
    ///
    /// A program that faults on most of what it is asked is broken rather than
    /// picky — a fault is a contained crash, not a refusal — and leaving it
    /// armed means every caller gets a reset instead of an answer. The window
    /// is short because the signal is unambiguous.
    ///
    /// The counter is cleared when it fires, so a socket that is re-armed and
    /// still broken gets a full window again rather than tripping on its first
    /// fault forever.
    pub(crate) fn record_outcome(&self, socket: &str, program: Hash, faulted: bool) -> bool {
        let mut faults = self.faults.lock().expect("registry faults");
        let key = (socket.to_string(), program);
        let ring = faults.entry(key.clone()).or_default();
        if ring.len() >= FAULT_WINDOW {
            ring.pop_front();
        }
        ring.push_back(faulted);
        let failing = ring.iter().filter(|f| **f).count();
        if failing >= FAULT_QUARANTINE {
            ring.clear();
            drop(faults);
            self.quarantined
                .lock()
                .expect("registry faults")
                .insert(key);
            return true;
        }
        false
    }

    /// Whether a socket is due to be disarmed, clearing the flag.
    ///
    /// Taken rather than read: the disarm happens once, and a second caller
    /// finding the flag still set would disarm a socket somebody has since
    /// repaired and re-armed.
    pub fn take_quarantine(&self, socket: &str, program: Hash) -> bool {
        self.quarantined
            .lock()
            .expect("registry faults")
            .remove(&(socket.to_string(), program))
    }

    /// Forgets a socket's remembered lines and fault history.
    ///
    /// What re-arming does: a different program's log tail and failure record
    /// are not this one's.
    pub fn forget(&self, socket: &str) {
        self.logs.lock().expect("registry logs").remove(socket);
        self.faults
            .lock()
            .expect("registry faults")
            .retain(|(name, _), _| name != socket);
        self.quarantined
            .lock()
            .expect("registry faults")
            .retain(|(name, _)| name != socket);
    }

    fn release(&self, id: u64) {
        self.live.lock().expect("registry").remove(&id);
    }
}

/// One invocation's place in the registry, released when it drops.
///
/// Held by the admission and then by the invocation, so a caller that opens a
/// stream and abandons it before a byte moves still gives its slot back — the
/// guard goes with the dropped admission.
#[derive(Debug)]
pub struct SlotGuard {
    registry: Arc<Registry>,
    id: u64,
    socket: String,
    stats: Arc<LiveStats>,
}

impl SlotGuard {
    /// The counters this invocation updates.
    pub fn stats(&self) -> Arc<LiveStats> {
        self.stats.clone()
    }

    /// The registry it belongs to.
    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// Its invocation id.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The socket it is serving.
    pub fn socket(&self) -> &str {
        &self.socket
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.registry.release(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> NodeId {
        NodeId::from_bytes(&crate::policy::NOBODY).expect("a valid key")
    }

    fn program() -> Hash {
        Hash::new(b"elf")
    }

    fn reserve(registry: &Arc<Registry>, id: u64, socket: &str, cap: usize) -> Option<SlotGuard> {
        registry.reserve(
            id,
            socket,
            "laptop@cluster.example",
            key(),
            Hash::new(b"elf"),
            cap,
            Instant::now(),
        )
    }

    #[test]
    fn a_socket_at_its_cap_refuses_the_next_one_until_a_slot_is_given_back() {
        let registry = Registry::new();
        let first = reserve(&registry, 1, "code/git.sock", 2).unwrap();
        let second = reserve(&registry, 2, "code/git.sock", 2).unwrap();
        assert!(
            reserve(&registry, 3, "code/git.sock", 2).is_none(),
            "the cap admitted a third"
        );
        // Another socket has its own budget.
        assert!(reserve(&registry, 4, "code/other.sock", 2).is_some());

        drop(second);
        assert!(
            reserve(&registry, 5, "code/git.sock", 2).is_some(),
            "a released slot was not reusable"
        );
        drop(first);
    }

    #[test]
    fn an_abandoned_admission_gives_its_slot_back() {
        // The case the guard exists for: a caller opens a stream, is admitted,
        // and vanishes before the guest runs. Nothing else would notice.
        let registry = Registry::new();
        {
            let _admitted = reserve(&registry, 1, "code/git.sock", 1).unwrap();
            assert_eq!(registry.running("code/git.sock"), 1);
        }
        assert_eq!(registry.running("code/git.sock"), 0);
        assert!(reserve(&registry, 2, "code/git.sock", 1).is_some());
    }

    #[test]
    fn a_snapshot_reports_what_the_invocation_is_doing() {
        let registry = Registry::new();
        let slot = reserve(&registry, 7, "code/git.sock", 4).unwrap();
        let stats = slot.stats();
        stats.bytes_in.store(120, Ordering::Relaxed);
        stats.bytes_out.store(4096, Ordering::Relaxed);
        stats.handles.store(2, Ordering::Relaxed);
        stats.set_labels(vec![("peer".into(), "zoe".into())]);
        stats.set_metrics(vec![("throttled".into(), 3)]);

        let seen = registry.snapshot(None, Instant::now());
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].id, 7);
        assert_eq!(seen[0].socket, "code/git.sock");
        assert_eq!((seen[0].bytes_in, seen[0].bytes_out), (120, 4096));
        assert_eq!(seen[0].handles, 2);
        assert_eq!(
            seen[0].labels,
            vec![("peer".to_string(), "zoe".to_string())]
        );
        assert_eq!(seen[0].metrics, vec![("throttled".to_string(), 3)]);

        assert_eq!(
            registry
                .snapshot(Some("code/other.sock"), Instant::now())
                .len(),
            0
        );
        drop(slot);
        assert!(registry.snapshot(None, Instant::now()).is_empty());
    }

    #[tokio::test]
    async fn a_kill_reaches_the_invocation_once() {
        let registry = Registry::new();
        let slot = reserve(&registry, 1, "code/git.sock", 4).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        registry.attach_cancel(1, tx);

        assert!(registry.kill(1));
        assert!(rx.await.is_ok(), "the cancel did not arrive");
        // A second kill has nothing left to pull, and says so rather than
        // reporting a success that did nothing.
        assert!(!registry.kill(1));
        assert!(!registry.kill(999));

        // The row stays until the invocation actually ends: it is still
        // running until it notices.
        assert_eq!(registry.running("code/git.sock"), 1);
        drop(slot);
    }

    #[test]
    fn the_log_tail_is_bounded_and_per_socket() {
        let registry = Registry::new();
        for i in 0..MAX_LOG_LINES + 50 {
            registry.log_line("code/git.sock", 1, i as i64, format!("line {i}"));
        }
        let lines = registry.logs("code/git.sock");
        assert_eq!(lines.len(), MAX_LOG_LINES);
        assert_eq!(
            lines.first().unwrap().text,
            format!("line {}", 50),
            "the tail should keep the newest lines"
        );
        assert!(registry.logs("code/other.sock").is_empty());

        registry.forget("code/git.sock");
        assert!(registry.logs("code/git.sock").is_empty());
    }

    #[test]
    fn a_socket_that_keeps_faulting_is_quarantined_and_then_given_a_clean_window() {
        let registry = Registry::new();
        for i in 0..FAULT_QUARANTINE - 1 {
            assert!(
                !registry.record_outcome("code/git.sock", program(), true),
                "quarantined after only {} faults",
                i + 1
            );
        }
        assert!(
            registry.record_outcome("code/git.sock", program(), true),
            "the threshold did not fire"
        );
        // Cleared when it fires, so a re-armed socket gets a full window rather
        // than tripping on its first fault forever.
        assert!(!registry.record_outcome("code/git.sock", program(), true));

        // The verdict latches until somebody acts on it, and then it is gone:
        // a second taker would disarm a socket that has since been repaired.
        assert!(registry.take_quarantine("code/git.sock", program()));
        assert!(!registry.take_quarantine("code/git.sock", program()));

        // And a re-arm clears the record the old program earned.
        registry.record_outcome("code/other.sock", program(), true);
        registry.forget("code/other.sock");
        assert!(!registry.take_quarantine("code/other.sock", program()));
    }

    #[test]
    fn occasional_faults_among_successes_do_not_quarantine() {
        // One in five, sustained well past the window. A socket that faults
        // sometimes is a socket meeting inputs it mishandles; the threshold is
        // for one that cannot run at all.
        let registry = Registry::new();
        for round in 0..FAULT_WINDOW * 4 {
            let faulted = round % 5 == 0;
            assert!(
                !registry.record_outcome("code/git.sock", program(), faulted),
                "a 20% fault rate was quarantined at round {round}"
            );
        }
    }

    #[test]
    fn fault_history_is_scoped_to_the_program_root() {
        let registry = Registry::new();
        let old = Hash::new(b"old program");
        let new = Hash::new(b"new program");

        for _ in 0..FAULT_QUARANTINE - 1 {
            assert!(!registry.record_outcome("code/git.sock", old, true));
        }
        assert!(
            !registry.record_outcome("code/git.sock", new, true),
            "a new root inherited the old root's fault history"
        );
        assert!(registry.record_outcome("code/git.sock", old, true));
        assert!(registry.take_quarantine("code/git.sock", old));
        assert!(!registry.take_quarantine("code/git.sock", new));
    }
}
