//! The worker: a pinned thread that owns programs and runs invocations.
//!
//! async-ebpf's `Program` is deliberately neither `Send` nor `Sync`. A guest
//! suspends inside a signal handler, so resuming it on another thread would run
//! the `sigreturn` on a thread that never took the signal — leaving SIGUSR1 and
//! SIGSEGV blocked on the one that did, with neither preemption nor fault
//! handling. That constraint, not a preference, is why this is a dedicated OS
//! thread running a current-thread runtime and a `LocalSet`, and why an
//! invocation is placed on a worker rather than scheduled across them.
//!
//! Each worker keeps its own `ProgramLoader` — the per-loader entropy is what
//! makes a helper index unforgeable — and its own cache of pinned programs,
//! keyed by content root. So a program JIT-compiles at most once per worker, and
//! a socket under load costs one compilation per worker rather than one per
//! stream.

pub(crate) mod ctx;
pub(crate) mod endpoint;
pub(crate) mod helpers;
pub(crate) mod map;

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use async_ebpf::program::{
    DummyProgramEventListener, GlobalEnv, PreemptionEnabled, Program, ProgramLoader, ThreadEnv,
    TimesliceConfig, Timeslicer, UnboundProgram,
};
use synch_core::{Declaration, FaultKind, Hash, SockStatus};
use tokio::sync::{mpsc, oneshot};

use crate::{
    abi::{SECTION_INIT, SECTION_STREAM, SY_SELF},
    limits::{Limits, PREEMPTION_INTERVAL, THROTTLE_AFTER, THROTTLE_FOR, YIELD_AFTER},
    runtime::{
        ctx::{Ctx, Inner, Slot},
        endpoint::{reader_task, writer_task, Endpoint, Readiness, State},
        map::SocketMaps,
    },
    Invocation, Outcome, SockError,
};

/// Ties yielding and sleeping to tokio.
struct TokioTimeslicer;

impl Timeslicer for TokioTimeslicer {
    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> {
        tokio::time::sleep(duration)
    }

    fn yield_now(&self) -> impl std::future::Future<Output = ()> {
        tokio::task::yield_now()
    }
}

fn timeslice() -> TimesliceConfig {
    TimesliceConfig {
        max_run_time_before_yield: YIELD_AFTER,
        max_run_time_before_throttle: THROTTLE_AFTER,
        throttle_duration: THROTTLE_FOR,
    }
}

/// Installs the process-wide signal handlers async-ebpf needs.
///
/// Idempotent, and deliberately called once at daemon start rather than lazily
/// on the first connection: the effect is process-wide — it replaces the
/// SIGSEGV disposition, including the one the standard library uses to report
/// stack overflow — and that is a thing to do while starting up, not while
/// serving.
fn global_env() -> GlobalEnv {
    use std::sync::OnceLock;
    static ENV: OnceLock<GlobalEnvHandle> = OnceLock::new();

    /// `GlobalEnv` is `Copy` but not nameable as `Sync`; this wrapper is what
    /// lets it live in a `OnceLock`. Sound because the value is a unit marker:
    /// everything it stands for is in process-global state already.
    struct GlobalEnvHandle(GlobalEnv);
    // SAFETY: `GlobalEnv` is a zero-sized marker for process-global signal
    // state. It carries no interior pointers and no thread affinity; the
    // thread affinity lives in `ThreadEnv`, which is created per worker.
    unsafe impl Sync for GlobalEnvHandle {}
    unsafe impl Send for GlobalEnvHandle {}

    // SAFETY: called once, at daemon start, in a process that installs its own
    // signal handlers.
    ENV.get_or_init(|| GlobalEnvHandle(unsafe { GlobalEnv::new() }))
        .0
}

/// One invocation, plus where to send the answer.
struct Job {
    invocation: Invocation,
    reply: oneshot::Sender<Result<Outcome, SockError>>,
    cancel: oneshot::Receiver<()>,
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Job")
            .field("invocation", &self.invocation)
            .finish_non_exhaustive()
    }
}

/// A handle onto one worker thread.
#[derive(Debug)]
pub struct Worker {
    jobs: mpsc::UnboundedSender<Job>,
    /// How many invocations this worker is carrying, for placement.
    load: Arc<AtomicU64>,
}

/// The pool the engine talks to.
#[derive(Debug, Clone)]
pub struct WorkerHandle {
    workers: Arc<Vec<Worker>>,
    maps: Arc<SocketMaps>,
    limits: Limits,
    next_id: Arc<AtomicU64>,
}

impl WorkerHandle {
    /// Starts `count` workers.
    ///
    /// Zero is rounded up to one: a pool that exists but can run nothing is a
    /// configuration mistake that would surface as a hang rather than an error.
    pub fn start(count: usize, limits: Limits) -> WorkerHandle {
        let count = count.max(1);
        // Installed before any worker exists, so no thread can start a guest
        // before the handlers that contain its faults are in place.
        let global = global_env();
        let maps = SocketMaps::new();
        let workers = (0..count)
            .map(|index| Worker::spawn(index, global, limits.clone(), maps.clone()))
            .collect();
        WorkerHandle {
            workers: Arc::new(workers),
            maps,
            limits,
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// The next invocation id, as `synch socket ps` prints it.
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// The limits every invocation in this pool runs under.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Drops everything a socket's map held — what re-arming does.
    pub fn clear_map(&self, socket: &str) {
        self.maps.clear(socket);
    }

    /// Runs one invocation on the least-loaded worker.
    ///
    /// Placement, not scheduling: the stream stays where it lands. There is no
    /// work stealing, by construction — see this module's header.
    pub async fn run(&self, invocation: Invocation) -> Result<Outcome, SockError> {
        let (_cancel_tx, cancel_rx) = oneshot::channel();
        self.run_cancellable(invocation, cancel_rx).await
    }

    /// Runs one invocation, with a channel that ends it early.
    ///
    /// The sender going away is what `synch socket kill` and a daemon shutdown
    /// both look like from in here.
    pub async fn run_cancellable(
        &self,
        invocation: Invocation,
        cancel: oneshot::Receiver<()>,
    ) -> Result<Outcome, SockError> {
        let worker = self
            .workers
            .iter()
            .min_by_key(|w| w.load.load(Ordering::Relaxed))
            .ok_or(SockError::NotRunning)?;
        let (reply, answer) = oneshot::channel();
        worker.load.fetch_add(1, Ordering::Relaxed);
        let load = worker.load.clone();
        let sent = worker.jobs.send(Job {
            invocation,
            reply,
            cancel,
        });
        if sent.is_err() {
            load.fetch_sub(1, Ordering::Relaxed);
            return Err(SockError::NotRunning);
        }
        let out = answer.await.unwrap_or(Err(SockError::NotRunning));
        load.fetch_sub(1, Ordering::Relaxed);
        out
    }
}

impl Worker {
    fn spawn(index: usize, global: GlobalEnv, limits: Limits, maps: Arc<SocketMaps>) -> Worker {
        let (jobs, mut rx) = mpsc::unbounded_channel::<Job>();
        let load = Arc::new(AtomicU64::new(0));
        std::thread::Builder::new()
            .name(format!("synch-sock-{index}"))
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(worker = index, "socket worker has no runtime: {e}");
                        return;
                    }
                };
                let thread_env = global.init_thread(PREEMPTION_INTERVAL);
                let loader = ProgramLoader::new(
                    &mut rand::thread_rng(),
                    Arc::new(DummyProgramEventListener),
                    &[helpers::HELPERS],
                );
                let cache: RefCell<HashMap<Hash, Rc<Program>>> = RefCell::new(HashMap::new());
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, async move {
                    while let Some(job) = rx.recv().await {
                        let outcome = run_job(
                            &loader,
                            &cache,
                            thread_env,
                            &limits,
                            &maps,
                            job.invocation,
                            job.cancel,
                        )
                        .await;
                        let _ = job.reply.send(outcome);
                    }
                });
            })
            .expect("spawning a socket worker thread");
        Worker { jobs, load }
    }
}

/// Compiles, or returns the compiled program for, one content root.
fn program_for(
    loader: &ProgramLoader,
    cache: &RefCell<HashMap<Hash, Rc<Program>>>,
    thread_env: ThreadEnv,
    root: &Hash,
    elf: &[u8],
) -> Result<Rc<Program>, SockError> {
    if let Some(program) = cache.borrow().get(root) {
        return Ok(program.clone());
    }
    let unbound: UnboundProgram = loader
        .load(&mut rand::thread_rng(), elf)
        .map_err(|e| SockError::Load(e.to_string()))?;
    let program = Rc::new(unbound.pin_to_current_thread(thread_env));
    if !program.has_section(SECTION_STREAM) {
        return Err(SockError::NoEntrypoint);
    }
    cache.borrow_mut().insert(*root, program.clone());
    Ok(program)
}

/// Builds the invocation state and runs the guest.
async fn run_job(
    loader: &ProgramLoader,
    cache: &RefCell<HashMap<Hash, Rc<Program>>>,
    thread_env: ThreadEnv,
    limits: &Limits,
    maps: &Arc<SocketMaps>,
    invocation: Invocation,
    mut cancel: oneshot::Receiver<()>,
) -> Result<Outcome, SockError> {
    let program = program_for(
        loader,
        cache,
        thread_env,
        &invocation.program_root,
        &invocation.program,
    )?;

    let ready = Rc::new(Readiness::default());
    let self_ep = Endpoint::new(
        limits.ring_bytes,
        ready.clone(),
        State::Open,
        invocation.peer.addr.clone(),
    );
    tokio::task::spawn_local(reader_task(self_ep.clone(), invocation.stream.reader));
    tokio::task::spawn_local(writer_task(self_ep.clone(), invocation.stream.writer));

    let started = Instant::now();
    let inner = Rc::new(Inner {
        slots: RefCell::new(vec![Some(Slot::Endpoint(self_ep.clone()))]),
        ready,
        policy: invocation.policy,
        peer: invocation.peer,
        socket: invocation.socket,
        self_origin: invocation.self_origin.canonical(),
        meta: invocation.meta,
        host: invocation.host,
        maps: maps.clone(),
        limits: limits.clone(),
        started,
        deadline: Cell::new(started + limits.idle_deadline),
        program_root: invocation.program_root,
        id: invocation.id,
        log_buf: RefCell::new(Vec::new()),
        metrics: RefCell::new(Vec::new()),
        labels: RefCell::new(Vec::new()),
        footprint: Cell::new(0),
        egress_open: Cell::new(0),
        init_mode: false,
        declaration: RefCell::new(Declaration::default()),
    });
    debug_assert_eq!(SY_SELF, 0, "SY_SELF must be the first slot");

    let mut ctx = Ctx {
        inner: inner.clone(),
    };
    let timeslice = timeslice();
    let preemption = PreemptionEnabled::new(thread_env);

    let mut resources: [&mut dyn std::any::Any; 1] = [&mut ctx];
    let status = {
        let run = program.run(
            &timeslice,
            &TokioTimeslicer,
            SECTION_STREAM,
            &mut resources,
            &[],
            &preemption,
        );
        tokio::pin!(run);
        tokio::select! {
            outcome = &mut run => match outcome {
                Ok(value) => SockStatus::Ok(value),
                Err(e) => {
                    tracing::warn!(
                        socket = %inner.socket.qualified(),
                        invocation = inner.id,
                        "socket program faulted: {e}"
                    );
                    SockStatus::Fault(classify(&e.to_string()))
                }
            },
            // A kill or a shutdown: the guest is dropped where it stands, which
            // is safe because everything it can hold is host-side and owned by
            // `inner`.
            _ = &mut cancel => SockStatus::Killed,
        }
    };

    inner.flush_log();
    // Let whatever the guest wrote reach the wire before the stream is torn
    // down: the program returning is not the same as its last write landing.
    self_ep.shutdown();
    drain(&self_ep).await;
    // The length is read into a local first: a `for` loop's iterator
    // expression keeps its temporaries alive for the whole loop, so borrowing
    // the table to bound the range would still be borrowing it when `remove`
    // asks to borrow it mutably.
    let open_handles = inner.slots.borrow().len() as i64;
    for handle in 0..open_handles {
        inner.remove(handle);
    }

    let (bytes_in, bytes_out) = (self_ep.bytes_in.get(), self_ep.bytes_out.get());
    let metrics = inner.metrics.borrow().clone();
    let labels = inner.labels.borrow().clone();
    Ok(Outcome {
        status,
        bytes_in,
        bytes_out,
        metrics,
        labels,
    })
}

/// Waits, briefly, for the writer task to push out what the guest left behind.
async fn drain(ep: &Rc<Endpoint>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while ep.pending_out() > 0 && Instant::now() < deadline {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Reads async-ebpf's error text as a fault class.
///
/// Text rather than a typed error because the runtime's `Error` deliberately
/// keeps its variants private; what reaches the caller is a classification, and
/// an unrecognized message is a fault either way.
fn classify(message: &str) -> FaultKind {
    if message.contains("memory fault") {
        FaultKind::Memory
    } else if message.contains("helper returned error") {
        FaultKind::Helper
    } else if message.contains("linker") || message.contains("elf") || message.contains("jit") {
        FaultKind::Load
    } else {
        FaultKind::Limit
    }
}

/// Runs a program's `synchronicity.init` hook and returns what it declared.
///
/// This is what `synch socket arm` shows an operator, and it runs in a context
/// with no endpoint table at all: an I/O helper called from here has nothing to
/// reach, and is refused before it tries.
///
/// It doubles as the dry run that forces compilation early. async-ebpf compiles
/// lazily, per function and per pointer signature, so a program that fails to
/// compile would otherwise surface that on the first stream that reaches the
/// bad path — a long way from the operator who armed it.
pub fn declare(elf: &[u8], host: Arc<dyn crate::SocketHost>) -> Result<Declaration, SockError> {
    let global = global_env();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| SockError::Load(e.to_string()))?;
    let thread_env = global.init_thread(PREEMPTION_INTERVAL);
    let loader = ProgramLoader::new(
        &mut rand::thread_rng(),
        Arc::new(DummyProgramEventListener),
        &[helpers::HELPERS],
    );
    let unbound = loader
        .load(&mut rand::thread_rng(), elf)
        .map_err(|e| SockError::Load(e.to_string()))?;
    let program = unbound.pin_to_current_thread(thread_env);
    if !program.has_section(SECTION_STREAM) {
        return Err(SockError::NoEntrypoint);
    }
    if !program.has_section(SECTION_INIT) {
        // No hook is a legitimate shape: a socket that reaches nothing and
        // reads nothing needs to declare nothing. It gets the empty
        // declaration, which grants exactly nothing.
        return Ok(Declaration::default());
    }

    let started = Instant::now();
    let inner = Rc::new(Inner {
        slots: RefCell::new(Vec::new()),
        ready: Rc::new(Readiness::default()),
        policy: crate::EffectivePolicy::default(),
        peer: crate::PeerIdentity {
            origin: synch_core::OriginId::Key(zero_key()),
            device_key: zero_key(),
            spaces: Some(Vec::new()),
            addr: String::new(),
            stream_index: 0,
        },
        socket: crate::SocketId::new("", ""),
        self_origin: String::new(),
        meta: Vec::new(),
        host,
        maps: SocketMaps::new(),
        limits: Limits::default(),
        started,
        deadline: Cell::new(started + Duration::from_secs(5)),
        program_root: Hash::EMPTY,
        id: 0,
        log_buf: RefCell::new(Vec::new()),
        metrics: RefCell::new(Vec::new()),
        labels: RefCell::new(Vec::new()),
        footprint: Cell::new(0),
        egress_open: Cell::new(0),
        init_mode: true,
        declaration: RefCell::new(Declaration::default()),
    });
    let mut ctx = Ctx {
        inner: inner.clone(),
    };
    let timeslice = timeslice();
    let preemption = PreemptionEnabled::new(thread_env);
    let mut resources: [&mut dyn std::any::Any; 1] = [&mut ctx];
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        program
            .run(
                &timeslice,
                &TokioTimeslicer,
                SECTION_INIT,
                &mut resources,
                &[],
                &preemption,
            )
            .await
            .map_err(|e| SockError::Fault(e.to_string()))
    })?;
    inner.flush_log();
    let declaration = inner.declaration.borrow().clone();
    Ok(declaration)
}

/// A key-shaped placeholder for the declaration run, which has no caller.
///
/// The init hook has no peer — nobody has connected, and nothing about a
/// caller is knowable at arm time — so the identity helpers are given a
/// delegate with an empty space list rather than a member. A hook that asked
/// about its caller gets "not you", which is the true answer.
fn zero_key() -> synch_core::NodeId {
    synch_core::NodeId::from_bytes(&crate::policy::NOBODY).expect("the base point is a valid key")
}

/// Every helper name, for the SDK-header agreement test.
#[cfg(test)]
pub(crate) fn helper_names() -> Vec<&'static str> {
    helpers::helper_names()
}
