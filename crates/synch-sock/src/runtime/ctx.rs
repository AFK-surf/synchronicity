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
        endpoint::{reader_task, writer_task, Endpoint, EndpointRole, Readiness, State},
        json::JsonSlot,
        map::SocketMaps,
        process::{ProcessSlot, PtySlot},
        ssh::SshState,
    },
    ObjectInfo, SocketHost,
};

/// The inbound stream before its first raw operation or SSH activation.
#[derive(Debug)]
pub(crate) struct UnselectedStream {
    pub(crate) stream: RefCell<Option<crate::DuplexStream>>,
    pub(crate) peer: String,
}

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
    pub(crate) ready: Arc<Readiness>,
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

/// What a tree writer's one commit or delete will do, once dispatched.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PutCommand {
    /// Publish the staged bytes, under a condition on the path's current
    /// state.
    Commit(crate::PutCondition),
    /// Publish this node's tombstone instead.
    Delete,
}

/// Which dispatch family a [`PutCommand`] belongs to, kept on the slot from
/// dispatch to collection: the helper collecting a parked answer must be the
/// one that asked, or a commit could collect a delete's bare success and hand
/// the guest an unwritten root buffer as a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PutKind {
    Commit,
    Delete,
}

impl PutCommand {
    pub(crate) fn kind(&self) -> PutKind {
        match self {
            PutCommand::Commit(_) => PutKind::Commit,
            PutCommand::Delete => PutKind::Delete,
        }
    }
}

/// A tree writer the guest opened with `sy_put_open`
/// (`docs/TREE-WRITES.md` §5).
///
/// The guest's half of the writer: a bounded staging buffer, the one command,
/// and the parked result. The host's half — the engine's staging file and the
/// commit — lives inside the writer's pump task, which drains the buffer in
/// order and performs the command once the buffer is empty. The pump owns the
/// [`SocketWriter`](crate::SocketWriter), so closing the handle drops it and
/// the staging behind it.
#[derive(Debug)]
pub(crate) struct WriterSlot {
    /// `space/path` being written, for `sy_errno` displays and logs.
    pub(crate) path: String,
    /// The armed grant this writer was opened under.
    pub(crate) capability: synch_core::TreeWriteCapability,
    /// Bytes accepted from the guest and not yet flushed to the host.
    pub(crate) buf: RefCell<std::collections::VecDeque<u8>>,
    /// Wakes the pump when bytes or the command arrive, or the handle closes.
    ///
    /// `notify_one` on every transition: the permit persists, so a wakeup
    /// posted while the pump is mid-write is consumed on its next wait rather
    /// than lost.
    pub(crate) work: Rc<tokio::sync::Notify>,
    /// The one commit or delete this writer will perform.
    pub(crate) command: Cell<Option<PutCommand>>,
    /// The dispatched operation's kind, from dispatch until its result is
    /// collected, so only the matching `sy_put_*` call can collect it.
    pub(crate) dispatched: Cell<Option<PutKind>>,
    /// True from dispatch until the result is parked.
    pub(crate) op_pending: Cell<bool>,
    /// What the operation produced: the published root (`None` for a delete),
    /// or the errno to report.
    pub(crate) result: RefCell<Option<Result<Option<synch_core::Hash>, i64>>>,
    /// A success was handed to the guest; the writer is spent.
    pub(crate) delivered: Cell<bool>,
    /// A sticky staging failure, or `0`.
    pub(crate) failed: Cell<i64>,
    /// Bytes accepted in total, checked against the grant's `max_bytes`.
    pub(crate) accepted: Cell<u64>,
    /// The guest let go of the handle; the pump exits and drops the staging.
    pub(crate) closed: Cell<bool>,
    pub(crate) ready: Arc<Readiness>,
}

impl WriterSlot {
    /// Buffer room left, which is what `SY_POLL_OUT` reports.
    pub(crate) fn room(&self) -> usize {
        crate::limits::WRITER_BUFFER_BYTES.saturating_sub(self.buf.borrow().len())
    }

    fn revents(&self) -> u32 {
        if self.failed.get() != 0 {
            return poll::ERR;
        }
        match &*self.result.borrow() {
            Some(Ok(_)) => return poll::IN,
            Some(Err(_)) => return poll::ERR,
            None => {}
        }
        if self.op_pending.get() || self.delivered.get() {
            return 0;
        }
        if self.room() > 0 {
            poll::OUT
        } else {
            0
        }
    }

    /// Filters readiness for one guest poll entry: `ERR` is unconditional,
    /// like every other handle's.
    pub(crate) fn poll_revents(&self, events: u32) -> u32 {
        self.revents() & (events | poll::ERR)
    }
}

/// A directory cursor.
#[derive(Debug)]
pub(crate) struct CursorSlot {
    pub(crate) names: Vec<String>,
    pub(crate) at: Cell<usize>,
}

impl CursorSlot {
    /// Host bytes this cursor holds, as the footprint meter counts them.
    ///
    /// The meter charges each entry at its name's length plus
    /// [`CURSOR_ENTRY_OVERHEAD`](crate::limits::CURSOR_ENTRY_OVERHEAD) —
    /// the `String` header in the vector and the per-name heap allocation
    /// that a name-byte sum ignores. Charging and releasing must agree, so
    /// both go through here.
    pub(crate) fn footprint(&self) -> u64 {
        self.names
            .iter()
            .map(|n| n.len() as u64 + crate::limits::CURSOR_ENTRY_OVERHEAD)
            .sum()
    }
}

/// What one handle refers to.
#[derive(Debug)]
pub(crate) enum Slot {
    Unselected(Rc<UnselectedStream>),
    Endpoint(Rc<Endpoint>),
    SshControl(Arc<SshState>),
    Process(Rc<ProcessSlot>),
    Object(Rc<ObjectSlot>),
    Cursor(Rc<CursorSlot>),
    Json(Rc<JsonSlot>),
    Writer(Rc<WriterSlot>),
}

impl Slot {
    pub(crate) fn revents(&self) -> u32 {
        match self {
            Slot::Unselected(_) => 0,
            Slot::Endpoint(ep) => ep.revents(),
            Slot::SshControl(ssh) => ssh.revents(),
            Slot::Process(process) => process
                .refresh()
                .map(|status| if status.exited { poll::IN } else { 0 })
                .unwrap_or(poll::ERR),
            Slot::Object(obj) => obj.revents(),
            // A cursor is always ready: every answer it can give is already in
            // memory, so a program that polls one is told to go ahead.
            Slot::Cursor(_) => poll::IN,
            // A JSON value is inert data: nothing about it will ever become
            // ready, so it reports nothing and never keeps a poll waiting.
            Slot::Json(_) => 0,
            Slot::Writer(writer) => writer.revents(),
        }
    }
}

/// The state behind every helper.
pub(crate) struct Inner {
    pub(crate) slots: RefCell<Vec<Option<Slot>>>,
    pub(crate) ready: Arc<Readiness>,
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
    /// Outbound TCP connections this invocation currently holds against
    /// [`Limits::max_egress`].
    ///
    /// Shared with the connect tasks rather than owned outright: the count is
    /// given back by [`EgressPermit`] when the task ends, not when the guest
    /// closes the handle. See that type for why.
    pub(crate) egress_open: Rc<Cell<usize>>,
    /// Commits and deletes dispatched through tree writers, against
    /// [`MAX_PUT_COMMITS`](crate::limits::MAX_PUT_COMMITS): every one is a
    /// published head, so the count is per invocation rather than per writer.
    pub(crate) put_commits: Cell<u32>,
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
    pub(crate) async_tasks: super::tasks::TaskSet,
    /// The pristine stream's writer is retained separately so invocation
    /// teardown can await bytes already removed from the userspace ring.
    pub(crate) raw_writer: RefCell<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) ptys: RefCell<std::collections::HashMap<i64, Rc<PtySlot>>>,

    /// Set while the `synchronicity.init` hook is running.
    ///
    /// The one flag that changes what a helper is allowed to be: a declaration
    /// helper called outside the hook, or an I/O helper called inside it, is
    /// `SY_EPERM`. The init hook runs with no endpoint table at all, so there
    /// is nothing for it to reach even if the check were missed.
    pub(crate) init_mode: bool,
    pub(crate) declaration: RefCell<Declaration>,
    pub(crate) ssh_host_key: Option<Arc<russh::keys::PrivateKey>>,
    /// Host-side auth-rejection throttle for SSH connections served by this
    /// invocation; `None` when the invocation cannot serve SSH.
    pub(crate) ssh_auth_throttle: Option<Arc<crate::runtime::ssh::AuthThrottle>>,

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
            ready: Arc::new(Readiness::default()),
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
            egress_open: Rc::new(Cell::new(0)),
            put_commits: Cell::new(0),
            draining: RefCell::new(Vec::new()),
            async_tasks: super::tasks::TaskSet::default(),
            raw_writer: RefCell::new(None),
            ptys: RefCell::new(std::collections::HashMap::new()),
            init_mode: false,
            declaration: RefCell::new(Declaration::default()),
            ssh_host_key: None,
            ssh_auth_throttle: None,
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
        self.async_tasks.track(task.abort_handle());
    }

    /// Cancels helper work that has not naturally finished.
    pub(crate) fn abort_tasks(&self) {
        self.async_tasks.abort_all();
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
            Some(Slot::Unselected(stream)) => Some(Slot2::Unselected(stream.clone())),
            Some(Slot::Endpoint(ep)) => Some(Slot2::Endpoint(ep.clone())),
            Some(Slot::SshControl(ssh)) => Some(Slot2::SshControl(ssh.clone())),
            Some(Slot::Process(process)) => Some(Slot2::Process(process.clone())),
            Some(Slot::Object(obj)) => Some(Slot2::Object(obj.clone())),
            Some(Slot::Cursor(cur)) => Some(Slot2::Cursor(cur.clone())),
            Some(Slot::Json(json)) => Some(Slot2::Json(json.clone())),
            Some(Slot::Writer(writer)) => Some(Slot2::Writer(writer.clone())),
            None => None,
        }
    }

    /// The endpoint at `handle`, or `None` if it is something else.
    ///
    /// Does not select a mode: `SY_SELF` is `None` here until something has
    /// chosen raw or SSH for it. Every helper that performs I/O wants
    /// [`Inner::endpoint_for_io`] instead.
    pub(crate) fn endpoint(&self, handle: i64) -> Option<Rc<Endpoint>> {
        match self.slot(handle) {
            Some(Slot2::Endpoint(ep)) => Some(ep),
            _ => None,
        }
    }

    /// The endpoint at `handle`, selecting raw mode if this is the pristine
    /// `SY_SELF` and nothing has chosen a mode for it yet.
    ///
    /// The single door for every helper that reads, writes, splices, polls,
    /// shuts down or inspects an endpoint. It exists because the dispatch used
    /// to be open-coded at each such helper, and `sy_splice` — the one that
    /// resolved both its handles with the bare [`Inner::endpoint`] — answered
    /// `SY_EBADF` on a handle the SDK calls "always open when your program
    /// starts". Which operations select a mode is part of the SSH contract
    /// (`docs/SSH-SOCKETS.md` §3.1), so it is one function rather than a rule
    /// each new helper has to remember.
    pub(crate) fn endpoint_for_io(&self, handle: i64) -> Result<Rc<Endpoint>, i64> {
        if handle == crate::abi::SY_SELF {
            self.select_raw()
        } else {
            self.endpoint(handle).ok_or(errno::EBADF)
        }
    }

    /// Selects raw mode for the pristine inbound stream and starts its pumps.
    pub(crate) fn select_raw(&self) -> Result<Rc<Endpoint>, i64> {
        match self.slot(crate::abi::SY_SELF) {
            Some(Slot2::Endpoint(endpoint)) => Ok(endpoint),
            Some(Slot2::SshControl(_)) => Err(errno::ESTATE),
            Some(Slot2::Unselected(unselected)) => {
                let stream = unselected.stream.borrow_mut().take().ok_or(errno::ESTATE)?;
                let endpoint = Endpoint::new(
                    self.limits.ring_bytes,
                    self.ready.clone(),
                    State::Open,
                    unselected.peer.clone(),
                    EndpointRole::RawInbound,
                );
                let mut slots = self.slots.borrow_mut();
                let Some(slot) = slots.get_mut(0) else {
                    return Err(errno::EBADF);
                };
                *slot = Some(Slot::Endpoint(endpoint.clone()));
                drop(slots);
                self.spawn(reader_task(endpoint.clone(), stream.reader));
                let writer = tokio::task::spawn_local(writer_task(endpoint.clone(), stream.writer));
                self.async_tasks.track(writer.abort_handle());
                *self.raw_writer.borrow_mut() = Some(writer);
                Ok(endpoint)
            }
            _ => Err(errno::EBADF),
        }
    }

    /// Atomically consumes the pristine inbound stream into SSH mode.
    pub(crate) fn select_ssh(&self, state: Arc<SshState>) -> Result<crate::DuplexStream, i64> {
        let Some(Slot2::Unselected(unselected)) = self.slot(crate::abi::SY_SELF) else {
            return Err(errno::ESTATE);
        };
        let stream = unselected.stream.borrow_mut().take().ok_or(errno::ESTATE)?;
        let mut slots = self.slots.borrow_mut();
        let Some(slot) = slots.get_mut(0) else {
            return Err(errno::EBADF);
        };
        *slot = Some(Slot::SshControl(state));
        drop(slots);
        Ok(stream)
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
        // Ring-bearing endpoints keep the pre-256 bound
        // ([`crate::limits::MAX_OPEN_ENDPOINTS`]): the per-role budgets can
        // be given back while their endpoints still hold rings, so the
        // endpoints themselves are counted at the one place they all enter
        // the table. The pristine slot-0 stream counts too — `select_raw`
        // turns it into the caller's endpoint in place, never through here,
        // and "`SY_SELF` included" must stay true either way.
        if matches!(slot, Slot::Endpoint(_)) {
            let open = slots
                .iter()
                .flatten()
                .filter(|held| matches!(held, Slot::Endpoint(_) | Slot::Unselected(_)))
                .count();
            if open >= crate::limits::MAX_OPEN_ENDPOINTS {
                return Err(errno::ELIMIT);
            }
        }
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
            Some(Slot::Unselected(_)) => true,
            Some(Slot::Endpoint(ep)) => {
                // The handle is gone; the bytes behind it are not. The write
                // side drains and half-closes on its own from here.
                ep.close_flushing();
                if handle == crate::abi::SY_SELF {
                    // The caller's stream is not tracked below: `close_flushing`
                    // has shut its write side and left the writer task to drain
                    // what is queued, and `run_job` unconditionally takes that
                    // task's join handle at teardown and waits on it inside the
                    // drain window. It does not matter that this slot is now
                    // empty — the wait is on the handle, not on the slot.
                    return true;
                }
                // The egress budget is *not* given back here. It belongs to
                // the connect task's `EgressPermit` and comes back when that
                // task ends, which is not the same moment as the guest letting
                // go of the handle.
                if let Some(Slot::SshControl(ssh)) = slots.first().and_then(Option::as_ref) {
                    ssh.remove_channel_fd(handle);
                }
                self.ptys.borrow_mut().remove(&handle);
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
            Some(Slot::SshControl(ssh)) => {
                // Closing the control fd is the SSH counterpart of closing the
                // raw stream: an orderly end of the whole connection. The
                // disconnect message goes out on a best-effort basis before
                // the local state is torn down.
                ssh.disconnect();
                ssh.close(0);
                true
            }
            Some(Slot::Process(process)) => {
                process.kill();
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
                let held = cur.footprint();
                self.release(held);
                true
            }
            Some(Slot::Json(json)) => {
                self.release(json.charged.get());
                true
            }
            Some(Slot::Writer(writer)) => {
                // The pump owns the host writer; telling it to stop is what
                // drops the staging file behind an uncommitted write. An
                // operation already dispatched still runs to completion —
                // commits are atomic engine-side — with its result discarded.
                writer.closed.set(true);
                writer.work.notify_one();
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
    /// `SY_SELF` is not among them, whether or not the guest closed it: it
    /// drains through its writer task's join handle, which `run_job` takes
    /// unconditionally and awaits inside the same window.
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
    /// Called from the places progress is observable: bytes copied in or out.
    /// Readiness alone — a poll that came back with a handle ready — is not
    /// progress: a terminal or bogus handle is ready forever, and counting
    /// that as progress would let a guest re-poll a dead handle and keep the
    /// deadline at arm's length indefinitely. A program blocked on a slow
    /// upstream is not idle, and one that has been parked in `sy_poll` for
    /// five minutes with nothing happening is.
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
            Slot::Unselected(_) => false,
            Slot::Endpoint(ep) => match ep.state() {
                State::Failed | State::Closed => true,
                State::Connecting => false,
                State::Open => ep.poll_terminal(),
            },
            // A live SSH connection can always become ready — the peer may
            // authenticate, open a channel, or disconnect — so a program
            // waiting on only the control fd is waiting, not finished. Quiet
            // begins at HUP, after which no event will ever arrive.
            Slot::SshControl(ssh) => ssh.revents() & poll::HUP != 0,
            // An object with a fetch in flight is the loudest thing here: the
            // answer is on its way. Quiet means *nothing can ever become
            // ready*, and a program told that while its read is outstanding
            // gives up on a file it was about to get. This matters especially
            // after the stream endpoint has been fully shut or removed.
            Slot::Object(obj) => !obj.pending.get() && obj.revents() == 0,
            // A writer is quiet only once its result was handed over: an open
            // one can always accept more, a full buffer will drain, and a
            // dispatched commit has an answer on its way.
            Slot::Writer(writer) => writer.delivered.get(),
            // A cursor with an answer waiting is not quiet either.
            other => other.revents() == 0,
        })
    }
}

/// A handle's target, cloned out of the table so the borrow can be dropped.
#[derive(Debug)]
pub(crate) enum Slot2 {
    Unselected(Rc<UnselectedStream>),
    Endpoint(Rc<Endpoint>),
    SshControl(Arc<SshState>),
    Process(Rc<ProcessSlot>),
    Object(Rc<ObjectSlot>),
    Cursor(Rc<CursorSlot>),
    Json(Rc<JsonSlot>),
    Writer(Rc<WriterSlot>),
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
