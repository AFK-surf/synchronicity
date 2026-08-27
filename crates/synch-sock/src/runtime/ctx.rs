//! The invocation context: everything a helper can reach.
//!
//! Handed to `Program::run` as a resource, so a helper — which is a bare `fn`
//! pointer and can capture nothing — reaches it through
//! `HelperScope::with_resource_mut`. The state itself hangs off an [`Rc`] so
//! that the one helper which suspends can clone a handle into the future it
//! posts, rather than trying to hold a borrow across an await.

use std::{
    cell::{Cell, RefCell},
    future::Future,
    rc::Rc,
    sync::Arc,
    time::Instant,
};

use synch_core::{Declaration, Hash};

use crate::{
    abi::{errno, poll},
    limits::{Limits, MAX_LABELS, MAX_METRIC_NAMES},
    policy::{EffectivePolicy, PeerIdentity, SocketId},
    runtime::{
        endpoint::{Endpoint, Readiness, State},
        map::SocketMaps,
    },
    ObjectInfo, SocketHost,
};

/// An object the guest opened for reading.
#[derive(Debug)]
pub(crate) struct ObjectSlot {
    pub(crate) info: ObjectInfo,
    /// A read is in flight.
    pub(crate) pending: Cell<bool>,
    /// What the last read produced: bytes, or the errno to report.
    pub(crate) result: RefCell<Option<Result<Vec<u8>, i64>>>,
    /// The `(offset, len)` the in-flight or completed read was for, so a guest
    /// that asks for a different range gets a fresh read rather than the
    /// previous answer.
    pub(crate) want: Cell<(u64, u64)>,
    pub(crate) ready: Rc<Readiness>,
}

impl ObjectSlot {
    fn revents(&self) -> u32 {
        match &*self.result.borrow() {
            Some(Ok(_)) => poll::IN,
            Some(Err(_)) => poll::ERR,
            None => 0,
        }
    }
}

/// A directory cursor.
#[derive(Debug)]
pub(crate) struct CursorSlot {
    pub(crate) names: Vec<String>,
    pub(crate) at: Cell<usize>,
}

/// What one handle refers to.
#[derive(Debug)]
pub(crate) enum Slot {
    Endpoint(Rc<Endpoint>),
    Object(Rc<ObjectSlot>),
    Cursor(Rc<CursorSlot>),
}

impl Slot {
    pub(crate) fn revents(&self) -> u32 {
        match self {
            Slot::Endpoint(ep) => ep.revents(),
            Slot::Object(obj) => obj.revents(),
            // A cursor is always ready: every answer it can give is already in
            // memory, so a program that polls one is told to go ahead.
            Slot::Cursor(_) => poll::IN,
        }
    }
}

/// The state behind every helper.
pub(crate) struct Inner {
    pub(crate) slots: RefCell<Vec<Option<Slot>>>,
    pub(crate) ready: Rc<Readiness>,
    pub(crate) policy: EffectivePolicy,
    pub(crate) peer: PeerIdentity,
    pub(crate) socket: SocketId,
    pub(crate) self_origin: String,
    pub(crate) meta: Vec<(String, String)>,
    pub(crate) host: Arc<dyn SocketHost>,
    pub(crate) maps: Arc<SocketMaps>,
    pub(crate) limits: Limits,
    pub(crate) started: Instant,
    /// When this invocation is considered idle.
    ///
    /// Pushed forward by [`Inner::made_progress`] whenever bytes move or a
    /// handle becomes ready, which is what makes it an *idle* deadline rather
    /// than a total wall-clock cap. There is deliberately no total cap: a
    /// socket that proxies is supposed to be long-lived, and its CPU is
    /// bounded by the timeslicer instead (`docs/SOCKETS.md` §10). The
    /// deadline is a real end for the invocation, not only a clamp on its
    /// poll waits: `run_job` selects on it, so an invocation that stops
    /// making progress is ended with `Deadline` rather than holding its slot
    /// and its worker for as long as its caller keeps the stream open.
    pub(crate) deadline: Cell<Instant>,
    pub(crate) program_root: Hash,
    pub(crate) id: u64,

    pub(crate) log_buf: RefCell<Vec<u8>>,
    pub(crate) metrics: RefCell<Vec<(String, i64)>>,
    pub(crate) labels: RefCell<Vec<(String, String)>>,
    pub(crate) footprint: Cell<u64>,
    pub(crate) egress_open: Cell<usize>,
    /// Endpoints the guest let go of that still owe bytes to the far side.
    ///
    /// A handle leaves the table the moment `sy_close` is called, but the
    /// endpoint behind it does not: what the guest queued is still draining,
    /// and the teardown gives it the rest of its window ([`Inner::begin_drain`]).
    /// The alternative is what this used to do — a program that closes its
    /// upstream and returns in the next line, which is the last two lines of
    /// every proxy ever written, losing whatever had not reached the wire yet.
    pub(crate) draining: RefCell<Vec<Rc<Endpoint>>>,
    /// Detached helper work owned by this invocation.
    pub(crate) async_tasks: RefCell<Vec<tokio::task::AbortHandle>>,

    /// Set while the `synchronicity.init` hook is running.
    ///
    /// The one flag that changes what a helper is allowed to be: a declaration
    /// helper called outside the hook, or an I/O helper called inside it, is
    /// `SY_EPERM`. The init hook runs with no endpoint table at all, so there
    /// is nothing for it to reach even if the check were missed.
    pub(crate) init_mode: bool,
    pub(crate) declaration: RefCell<Declaration>,

    /// Counters an operator reads while this is running.
    ///
    /// Written here on the worker thread and read by `synch socket ps` from
    /// another, which is why they are atomics rather than more `Cell`s.
    pub(crate) live: Arc<crate::registry::LiveStats>,
    /// Where `sy_log` lines are remembered for `synch socket log`.
    pub(crate) registry: Option<Arc<crate::registry::Registry>>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("id", &self.id)
            .field("socket", &self.socket)
            .field("program_root", &self.program_root)
            .field("init_mode", &self.init_mode)
            .finish_non_exhaustive()
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Belt and braces for a panic that escaped the teardown: the handles
        // are normally drained by `abort_tasks` on the way out, and aborting
        // an already-finished task is a no-op. What this catches is the
        // invocation that died mid-teardown, where a detached helper task —
        // a fetch, a connect pump — would otherwise keep running, and keep
        // its endpoint and its bytes alive, after the invocation it was
        // helping is gone.
        self.abort_tasks();
    }
}

/// The resource a helper looks up.
#[derive(Debug, Clone)]
pub(crate) struct Ctx {
    pub(crate) inner: Rc<Inner>,
}

/// How long a declaration run may run before it is abandoned.
///
/// The whole hook, not just its poll waits: the serving-side idle deadline is
/// consulted only by `sy_poll`, so a hook that never polls gets its bound
/// here, where `declare_here` enforces it with a timeout around the run.
pub(crate) const DECLARE_IDLE: std::time::Duration = std::time::Duration::from_secs(5);

/// A key-shaped placeholder for the declaration run, which has no caller.
///
/// The init hook has no peer — nobody has connected, and nothing about a
/// caller is knowable at arm time — so the identity helpers are given a
/// delegate with an empty space list rather than a member. A hook that asked
/// about its caller gets "not you", which is the true answer.
fn zero_key() -> synch_core::NodeId {
    synch_core::NodeId::from_bytes(&crate::policy::NOBODY).expect("the base point is a valid key")
}

impl Inner {
    /// A run over nothing: no handles, no caller, no output, an idle deadline
    /// `idle` from `started` — and the *serving*-mode flags, so the arming
    /// path is the one that must flip what it differs in ([`Inner::declaring`])
    /// and a forgotten override breaks the declaration run loudly rather than
    /// widening what a served guest may do.
    ///
    /// Both constructions build on this one base, so a new field gets one
    /// default here rather than one hand-written spelling per path — the
    /// divergence that would let arming show an operator one thing while
    /// serving runs another.
    pub(crate) fn bare(
        host: Arc<dyn SocketHost>,
        started: Instant,
        idle: std::time::Duration,
    ) -> Inner {
        Inner {
            slots: RefCell::new(Vec::new()),
            ready: Rc::new(Readiness::default()),
            policy: EffectivePolicy::default(),
            peer: PeerIdentity {
                origin: synch_core::OriginId::Key(zero_key()),
                device_key: zero_key(),
                spaces: Some(Vec::new()),
                addr: String::new(),
                stream_index: 0,
            },
            socket: SocketId::new("", ""),
            self_origin: String::new(),
            meta: Vec::new(),
            host,
            maps: SocketMaps::new(),
            limits: Limits::default(),
            started,
            deadline: Cell::new(started + idle),
            program_root: Hash::EMPTY,
            id: 0,
            log_buf: RefCell::new(Vec::new()),
            metrics: RefCell::new(Vec::new()),
            labels: RefCell::new(Vec::new()),
            footprint: Cell::new(0),
            egress_open: Cell::new(0),
            draining: RefCell::new(Vec::new()),
            async_tasks: RefCell::new(Vec::new()),
            init_mode: false,
            declaration: RefCell::new(Declaration::default()),
            live: Default::default(),
            // No registry: only a served invocation appears in `socket ps` and
            // keeps a log tail; the base is a run nobody is watching.
            registry: None,
        }
    }

    /// The declaration run's state: [`Inner::bare`] with the init hook's one
    /// flag set. What its hook logs belongs to the operator who asked for the
    /// arming rather than to a socket's tail, so the registry stays `None`.
    ///
    /// Built by mutation rather than struct update: `Inner` has a `Drop` that
    /// aborts its tasks, so moving fields out of another `Inner` is not
    /// allowed.
    pub(crate) fn declaring(host: Arc<dyn SocketHost>, started: Instant) -> Inner {
        let mut inner = Inner::bare(host, started, DECLARE_IDLE);
        inner.init_mode = true;
        inner
    }

    /// Starts helper work and makes invocation cleanup its owner.
    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + 'static) {
        let task = tokio::task::spawn_local(future);
        self.async_tasks.borrow_mut().push(task.abort_handle());
    }

    /// Cancels helper work that has not naturally finished.
    pub(crate) fn abort_tasks(&self) {
        for task in self.async_tasks.borrow_mut().drain(..) {
            task.abort();
        }
    }

    /// Namespace shared state by both socket path and armed program root.
    ///
    /// A NUL cannot occur in a normalized tree path, so this cannot collide
    /// with another socket whose path merely has this one as a prefix.
    pub(crate) fn map_namespace(&self) -> String {
        format!(
            "{}\0{}",
            self.socket.qualified(),
            self.program_root.to_hex()
        )
    }

    /// Looks a handle up.
    pub(crate) fn slot(&self, handle: i64) -> Option<Slot2> {
        if handle < 0 {
            return None;
        }
        let slots = self.slots.borrow();
        match slots.get(handle as usize).and_then(|s| s.as_ref()) {
            Some(Slot::Endpoint(ep)) => Some(Slot2::Endpoint(ep.clone())),
            Some(Slot::Object(obj)) => Some(Slot2::Object(obj.clone())),
            Some(Slot::Cursor(cur)) => Some(Slot2::Cursor(cur.clone())),
            None => None,
        }
    }

    /// The endpoint at `handle`, or `None` if it is something else.
    pub(crate) fn endpoint(&self, handle: i64) -> Option<Rc<Endpoint>> {
        match self.slot(handle) {
            Some(Slot2::Endpoint(ep)) => Some(ep),
            _ => None,
        }
    }

    /// Puts a slot in the table, returning its handle.
    ///
    /// Never handle zero, which `abi::SY_SELF` promises is "always present,
    /// never allocated". A guest may close the inbound stream and keep running
    /// (§7.3), and handing the slot it freed to the next `sy_tcp_connect` would
    /// hand an upstream a handle that every "is this the caller's stream?" test
    /// in this runtime answers yes to: its bytes counted as the caller's in
    /// `synch socket ps`, its place in the egress budget never given back, and
    /// the teardown drain skipping it because that is where the caller's stream
    /// lives.
    pub(crate) fn insert(&self, slot: Slot) -> Result<i64, i64> {
        let mut slots = self.slots.borrow_mut();
        if slots.is_empty() {
            // Only reachable off the served path — the arming run has no
            // endpoint table at all. Zero stays reserved there too, rather
            // than making an ABI promise depend on who built the table.
            slots.push(None);
        }
        if let Some(index) = slots.iter().skip(1).position(|s| s.is_none()) {
            let index = index + 1;
            slots[index] = Some(slot);
            return Ok(index as i64);
        }
        if slots.len() >= self.limits.max_handles {
            return Err(errno::ELIMIT);
        }
        slots.push(Some(slot));
        Ok(slots.len() as i64 - 1)
    }

    /// Drops a handle, releasing whatever it held.
    pub(crate) fn remove(&self, handle: i64) -> bool {
        if handle < 0 {
            return false;
        }
        let mut slots = self.slots.borrow_mut();
        let Some(entry) = slots.get_mut(handle as usize) else {
            return false;
        };
        match entry.take() {
            Some(Slot::Endpoint(ep)) => {
                // The handle is gone; the bytes behind it are not. The write
                // side drains and half-closes on its own from here.
                ep.close_flushing();
                if handle == crate::abi::SY_SELF {
                    // The caller's stream is not tracked below: `run` holds its
                    // writer's join handle and waits on that.
                    return true;
                }
                // An outbound endpoint frees its place in the egress budget:
                // the bound is on how many are open at once, not on how many
                // were ever opened.
                self.egress_open
                    .set(self.egress_open.get().saturating_sub(1));
                let mut draining = self.draining.borrow_mut();
                // Endpoints that have finished draining are let go of here
                // rather than at the end, so a program that opens and closes
                // one endpoint after another keeps one ring, not all of them.
                draining.retain(|held| !held.tx_done());
                if !ep.tx_done() {
                    // And the ones that have *not* finished are bounded like
                    // the open ones are. A program can close an endpoint whose
                    // peer stopped reading as often as it likes; without this
                    // it would be holding every one of their rings, which is a
                    // way to keep a quarter megabyte per close.
                    while draining.len() >= self.limits.max_egress {
                        draining.remove(0).close();
                    }
                    draining.push(ep);
                }
                true
            }
            Some(Slot::Object(obj)) => {
                let held = obj
                    .result
                    .borrow()
                    .as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .map(|b| b.len() as u64)
                    .unwrap_or(0);
                self.release(held);
                true
            }
            Some(Slot::Cursor(cur)) => {
                let held: u64 = cur.names.iter().map(|n| n.len() as u64).sum();
                self.release(held);
                true
            }
            None => false,
        }
    }

    /// Starts every endpoint's final flush, and says what to wait on.
    ///
    /// Both the endpoints still in the table and the ones the guest closed on
    /// its way out, and all of them at once rather than one after another: the
    /// teardown has a single window to spend, and endpoints draining in
    /// parallel spend it once instead of dividing it.
    ///
    /// `SY_SELF` is not among them. It has always had a window of its own, and
    /// `run` waits on its writer's join handle rather than on this.
    pub(crate) fn begin_drain(&self) -> Vec<Rc<Endpoint>> {
        let mut draining = std::mem::take(&mut *self.draining.borrow_mut());
        for slot in self.slots.borrow().iter().skip(1).flatten() {
            if let Slot::Endpoint(ep) = slot {
                ep.close_flushing();
                draining.push(ep.clone());
            }
        }
        draining.retain(|ep| !ep.tx_done());
        draining
    }

    /// Notes that something happened, and pushes the idle deadline out.
    ///
    /// Called from the places progress is observable: bytes copied in or out,
    /// and a poll that came back with a handle ready. A program blocked on a
    /// slow upstream is not idle, and one that has been parked in `sy_poll`
    /// for five minutes with nothing happening is.
    pub(crate) fn made_progress(&self) {
        self.deadline
            .set(Instant::now() + self.limits.idle_deadline);
    }

    /// Charges host-side bytes against this invocation's footprint.
    pub(crate) fn charge(&self, bytes: u64) -> Result<(), i64> {
        let next = self.footprint.get().saturating_add(bytes);
        if next > self.limits.max_footprint {
            return Err(errno::ELIMIT);
        }
        self.footprint.set(next);
        Ok(())
    }

    /// Gives bytes back.
    pub(crate) fn release(&self, bytes: u64) {
        self.footprint
            .set(self.footprint.get().saturating_sub(bytes));
    }

    /// Publishes the handle count, which only changes when the table does.
    pub(crate) fn publish_handles(&self) {
        let held = self.slots.borrow().iter().flatten().count() as u64;
        self.live
            .handles
            .store(held, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records a metric bump.
    pub(crate) fn metric(&self, name: &str, delta: i64) -> i64 {
        let mut metrics = self.metrics.borrow_mut();
        if let Some(slot) = metrics.iter_mut().find(|(n, _)| n == name) {
            slot.1 = slot.1.saturating_add(delta);
            drop(metrics);
            self.live.set_metrics(self.metrics.borrow().clone());
            return 0;
        }
        if metrics.len() >= MAX_METRIC_NAMES {
            return errno::ELIMIT;
        }
        metrics.push((name.to_string(), delta));
        drop(metrics);
        self.live.set_metrics(self.metrics.borrow().clone());
        0
    }

    /// Records a label.
    pub(crate) fn label(&self, key: &str, value: &str) -> i64 {
        let mut labels = self.labels.borrow_mut();
        if let Some(slot) = labels.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value.to_string();
            drop(labels);
            self.live.set_labels(self.labels.borrow().clone());
            return 0;
        }
        if labels.len() >= MAX_LABELS {
            return errno::ELIMIT;
        }
        labels.push((key.to_string(), value.to_string()));
        drop(labels);
        self.live.set_labels(self.labels.borrow().clone());
        0
    }

    /// Flushes whatever `sy_log` has buffered but not yet emitted.
    pub(crate) fn flush_log(&self) {
        let mut buf = self.log_buf.borrow_mut();
        if buf.is_empty() {
            return;
        }
        let line = sanitize(&buf);
        buf.clear();
        self.remember_log(&line);
    }

    /// Emits one log line: to the daemon's log, and to the socket's tail.
    ///
    /// Both, because they answer different questions. The daemon's log is the
    /// history an operator's tooling already points at; the tail is what
    /// `synch socket log` can show without asking them to go and find it.
    pub(crate) fn remember_log(&self, line: &str) {
        tracing::info!(
            socket = %self.socket.qualified(),
            invocation = self.id,
            "{line}"
        );
        if let Some(registry) = &self.registry {
            registry.log_line(
                &self.socket.qualified(),
                self.id,
                synch_core::now_ns(),
                line.to_string(),
            );
        }
    }

    /// True if every endpoint is terminal and no other handle has work coming.
    ///
    /// What the idle deadline is measured against: a program parked in
    /// `sy_poll` with nothing left that can ever become ready is not idle, it
    /// is finished, and it should be told so rather than waited out. Called
    /// only after current requested and unconditional readiness was checked.
    pub(crate) fn all_quiet(&self) -> bool {
        let slots = self.slots.borrow();
        slots.iter().flatten().all(|slot| match slot {
            Slot::Endpoint(ep) => match ep.state() {
                State::Failed | State::Closed => true,
                State::Connecting => false,
                State::Open => ep.poll_terminal(),
            },
            // An object with a fetch in flight is the loudest thing here: the
            // answer is on its way. Quiet means *nothing can ever become
            // ready*, and a program told that while its read is outstanding
            // gives up on a file it was about to get. This matters especially
            // after the stream endpoint has been fully shut or removed.
            Slot::Object(obj) => !obj.pending.get() && obj.revents() == 0,
            // A cursor with an answer waiting is not quiet either.
            other => other.revents() == 0,
        })
    }
}

/// A handle's target, cloned out of the table so the borrow can be dropped.
#[derive(Debug)]
pub(crate) enum Slot2 {
    Endpoint(Rc<Endpoint>),
    Object(Rc<ObjectSlot>),
    Cursor(Rc<CursorSlot>),
}

/// Replaces anything a terminal should not be asked to render.
///
/// A guest chooses these bytes, and they land in an operator's log: escape
/// sequences, and anything that is not printable ASCII, become `?`.
pub(crate) fn sanitize(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| match b {
            b'\t' => '\t',
            0x20..=0x7e => *b as char,
            _ => '?',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_line_cannot_carry_an_escape_sequence_into_a_terminal() {
        assert_eq!(sanitize(b"ok"), "ok");
        assert_eq!(sanitize(b"\x1b[31mred"), "?[31mred");
        assert_eq!(sanitize("héllo".as_bytes()), "h??llo");
        assert_eq!(sanitize(b"a\tb"), "a\tb");
    }
}
