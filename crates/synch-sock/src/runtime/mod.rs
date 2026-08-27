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
    cell::RefCell,
    collections::{HashMap, VecDeque},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
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
    limits::{
        Limits, PREEMPTION_INTERVAL, TEARDOWN_DRAIN, THROTTLE_AFTER, THROTTLE_FOR, YIELD_AFTER,
    },
    runtime::{
        ctx::{Ctx, DECLARE_IDLE, Inner, Slot},
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

/// Aborts the invocation's detached tasks when this drops — including on
/// unwinding.
///
/// A panic inside the guest or its helpers would otherwise leave the reader
/// and writer tasks pumping an invocation nobody is collecting, with its
/// rings and its stream held open. Aborting an already-finished task is a
/// no-op, so the normal path is unaffected: the teardown aborts or joins
/// these same tasks at its own pace, and this is the backstop.
struct TaskGuard {
    tasks: Vec<tokio::task::AbortHandle>,
}

impl TaskGuard {
    fn new() -> Self {
        TaskGuard { tasks: Vec::new() }
    }

    fn push(&mut self, task: &tokio::task::JoinHandle<()>) {
        self.tasks.push(task.abort_handle());
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

type StackConfig = (usize, bool);
type LoaderCache = RefCell<HashMap<StackConfig, Rc<ProgramLoader>>>;

/// How many compiled programs one worker may hold.
///
/// A bound on what content churn can make a worker accumulate: every distinct
/// content root ever served would otherwise stay JIT-compiled here forever,
/// one worker at a time (`--auto` re-arms make that a real stream). The
/// oldest is evicted first; an invocation that is still running holds its
/// program through its own `Rc`, so eviction only releases programs nothing
/// is executing.
const MAX_CACHED_PROGRAMS: usize = 32;

/// The compiled-program cache: insertion order alongside the entries, for
/// oldest-first eviction.
type ProgramCache = RefCell<(
    HashMap<(Hash, StackConfig), Rc<Program>>,
    VecDeque<(Hash, StackConfig)>,
)>;

fn host_page_size() -> Option<usize> {
    // SAFETY: `sysconf` reads a process-wide platform constant and has no
    // pointer or lifetime requirements.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).ok().filter(|size| *size > 0)
}

fn resolve_stack_config(
    frame_size: Option<usize>,
    guarded: Option<bool>,
) -> Result<StackConfig, SockError> {
    let page_size = host_page_size()
        .ok_or_else(|| SockError::Load("cannot determine the host page size".into()))?;
    resolve_stack_config_for_page(frame_size, guarded, page_size)
}

fn resolve_stack_config_for_page(
    frame_size: Option<usize>,
    guarded: Option<bool>,
    page_size: usize,
) -> Result<StackConfig, SockError> {
    let size = frame_size.unwrap_or(synch_core::DEFAULT_EBPF_STACK_FRAME_SIZE as usize);
    let default_size = synch_core::DEFAULT_EBPF_STACK_FRAME_SIZE as usize;
    let guarded = guarded.unwrap_or_else(|| default_size.is_multiple_of(page_size));
    let valid = u32::try_from(size)
        .ok()
        .is_some_and(synch_core::valid_ebpf_stack_frame_size);
    if !valid {
        return Err(SockError::Load(format!(
            "invalid declared stack frame size: {size}"
        )));
    }
    if guarded && !size.is_multiple_of(page_size) {
        return Err(SockError::Load(format!(
            "guarded stack frame size {size} is not aligned to the host's \
             {page_size}-byte pages; declare guarded stack frames disabled"
        )));
    }
    Ok((size, guarded))
}

fn warn_if_default_stack_is_contiguous() {
    let Some(page_size) = host_page_size() else {
        tracing::warn!("cannot determine the host page size; socket programs will fail to load");
        return;
    };
    let default_size = synch_core::DEFAULT_EBPF_STACK_FRAME_SIZE as usize;
    if page_size > default_size {
        tracing::warn!(
            page_size,
            frame_size = default_size,
            "host pages are larger than the default eBPF stack frame; using contiguous \
             stack frames unless the program explicitly requires guards"
        );
    }
}

fn guest_stack_size(frame_size: usize) -> Result<usize, SockError> {
    const DEFAULT_FRAME_COUNT: usize = 8;
    const CALLDATA_HEADROOM: usize = async_ebpf::program::DEFAULT_GUEST_STACK_SIZE
        - async_ebpf::program::DEFAULT_STACK_FRAME_SIZE * DEFAULT_FRAME_COUNT;

    frame_size
        .checked_mul(DEFAULT_FRAME_COUNT)
        .and_then(|size| size.checked_add(CALLDATA_HEADROOM))
        .map(|size| size.max(async_ebpf::program::DEFAULT_GUEST_STACK_SIZE))
        .ok_or_else(|| {
            SockError::Load("declared stack frame size overflows the guest stack".into())
        })
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
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[derive(Debug, Default)]
struct ShutdownSignal {
    stopping: AtomicBool,
    notify: tokio::sync::Notify,
}

impl ShutdownSignal {
    fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_stopping() {
                return;
            }
            notified.await;
        }
    }
}

/// The pool the engine talks to.
#[derive(Debug, Clone)]
pub struct WorkerHandle {
    workers: Arc<Vec<Worker>>,
    maps: Arc<SocketMaps>,
    registry: Arc<crate::registry::Registry>,
    limits: Limits,
    next_id: Arc<AtomicU64>,
    shutdown: Arc<ShutdownSignal>,
}

impl WorkerHandle {
    /// Starts `count` workers.
    ///
    /// Zero is rounded up to one: a pool that exists but can run nothing is a
    /// configuration mistake that would surface as a hang rather than an error.
    pub fn start(count: usize, limits: Limits) -> WorkerHandle {
        let count = count.max(1);
        warn_if_default_stack_is_contiguous();
        // Installed before any worker exists, so no thread can start a guest
        // before the handlers that contain its faults are in place.
        let global = global_env();
        let maps = SocketMaps::new();
        let registry = crate::registry::Registry::new();
        let shutdown = Arc::new(ShutdownSignal::default());
        let workers = (0..count)
            .map(|index| {
                Worker::spawn(
                    index,
                    global,
                    limits.clone(),
                    maps.clone(),
                    registry.clone(),
                    shutdown.clone(),
                )
            })
            .collect();
        WorkerHandle {
            workers: Arc::new(workers),
            maps,
            registry,
            limits,
            next_id: Arc::new(AtomicU64::new(1)),
            shutdown,
        }
    }

    /// What is running right now, and what it has just been saying.
    pub fn registry(&self) -> &Arc<crate::registry::Registry> {
        &self.registry
    }

    /// The next invocation id, as `synch socket ps` prints it.
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// The limits every invocation in this pool runs under.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Drops everything one socket held that a re-arm should not inherit: its
    /// map, its remembered log lines, and its fault history.
    ///
    /// A re-arm is a different program. A session table, a log tail and a
    /// record of failures minted by the old one are not state the new one
    /// agreed to inherit — and leaving the fault history in place would
    /// quarantine a fixed program on the strength of the broken one's record.
    pub fn clear_map(&self, socket: &str) {
        self.maps.clear(socket);
        self.registry.forget(socket);
    }

    /// Whether every worker is carrying its cap of invocations.
    ///
    /// The pool-wide bound that keeps one caller — who may reach every armed
    /// socket in the cluster — from filling the workers' queues past the
    /// documented daemon limit. The engine checks it at admission, so an
    /// over-capacity pool refuses with `Busy` rather than queueing.
    pub fn full(&self) -> bool {
        let cap = self.limits.max_streams as u64;
        self.workers
            .iter()
            .all(|worker| worker.load.load(Ordering::Relaxed) >= cap)
    }

    /// Runs one invocation on the least-loaded worker.
    ///
    /// Placement, not scheduling: the stream stays where it lands. There is no
    /// work stealing, by construction — see this module's header.
    pub async fn run(&self, invocation: Invocation) -> Result<Outcome, SockError> {
        // The registry holds the sender, so `synch socket kill` can reach an
        // invocation nobody else has a handle to.
        let (cancel_tx, cancel_rx) = oneshot::channel();
        if invocation.slot.is_some() {
            self.registry.attach_cancel(invocation.id, cancel_tx);
        }
        self.run_cancellable(invocation, cancel_rx).await
    }

    /// Runs one invocation, with a channel that ends it early.
    ///
    /// Operator cancellation is separate from the pool-wide shutdown signal,
    /// so callers can distinguish `Killed` from `Shutdown`.
    pub async fn run_cancellable(
        &self,
        invocation: Invocation,
        cancel: oneshot::Receiver<()>,
    ) -> Result<Outcome, SockError> {
        if self.shutdown.is_stopping() {
            return Ok(shutdown_outcome());
        }
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

    /// Cancels active work, drains queued work, and joins every worker thread.
    /// Safe to call through multiple cloned handles.
    pub async fn shutdown(&self) {
        self.shutdown.stop();
        let threads: Vec<_> = self
            .workers
            .iter()
            .filter_map(|worker| {
                worker
                    .thread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
            })
            .collect();
        if threads.is_empty() {
            return;
        }
        let _ = tokio::task::spawn_blocking(move || {
            for thread in threads {
                if thread.join().is_err() {
                    tracing::error!("socket worker thread panicked during shutdown");
                }
            }
        })
        .await;
    }
}

impl Worker {
    fn spawn(
        index: usize,
        global: GlobalEnv,
        limits: Limits,
        maps: Arc<SocketMaps>,
        registry: Arc<crate::registry::Registry>,
        shutdown: Arc<ShutdownSignal>,
    ) -> Worker {
        let (jobs, mut rx) = mpsc::unbounded_channel::<Job>();
        let load = Arc::new(AtomicU64::new(0));
        let worker_shutdown = shutdown.clone();
        let thread = std::thread::Builder::new()
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
                let loaders: Rc<LoaderCache> = Rc::new(RefCell::new(HashMap::new()));
                let cache: Rc<ProgramCache> =
                    Rc::new(RefCell::new((HashMap::new(), VecDeque::new())));
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, async move {
                    let mut running = tokio::task::JoinSet::new();
                    loop {
                        tokio::select! {
                            _ = worker_shutdown.cancelled() => break,
                            job = rx.recv() => match job {
                                Some(mut job) => {
                                    if worker_shutdown.is_stopping() {
                                        let _ = job.reply.send(Ok(shutdown_outcome()));
                                        continue;
                                    }
                                    // A kill that landed while the job queued
                                    // ends it before it starts: the cancel
                                    // receiver is otherwise only read once the
                                    // guest runs, so `synch socket kill` could
                                    // not reach a stream that was still waiting
                                    // for a worker.
                                    if job.cancel.try_recv().is_ok() {
                                        let _ = job.reply.send(Ok(killed_outcome()));
                                        continue;
                                    }
                                    let loaders = loaders.clone();
                                    let cache = cache.clone();
                                    let limits = limits.clone();
                                    let maps = maps.clone();
                                    let registry = registry.clone();
                                    let shutdown = worker_shutdown.clone();
                                    running.spawn_local(async move {
                                        let outcome = run_job(
                                            &loaders,
                                            &cache,
                                            thread_env,
                                            &limits,
                                            &maps,
                                            &registry,
                                            &shutdown,
                                            job.invocation,
                                            job.cancel,
                                        )
                                        .await;
                                        let _ = job.reply.send(outcome);
                                    });
                                }
                                None => break,
                            },
                            Some(result) = running.join_next(), if !running.is_empty() => {
                                if let Err(e) = result {
                                    tracing::error!(worker = index, "socket invocation task failed: {e}");
                                }
                            }
                        }
                    }
                    while let Ok(job) = rx.try_recv() {
                        let _ = job.reply.send(Ok(shutdown_outcome()));
                    }
                    while let Some(result) = running.join_next().await {
                        if let Err(e) = result {
                            tracing::error!(worker = index, "socket invocation task failed: {e}");
                        }
                    }
                });
            })
            .expect("spawning a socket worker thread");
        Worker {
            jobs,
            load,
            thread: Mutex::new(Some(thread)),
        }
    }
}

/// Builds the loader for one stack configuration.
///
/// Serving (`program_for`) and arming (`declare_here`) must load with the
/// same loader shape, or what the operator reviewed is not what runs.
fn stack_loader(config: StackConfig) -> Result<ProgramLoader, SockError> {
    Ok(ProgramLoader::new(
        &mut rand::thread_rng(),
        Arc::new(DummyProgramEventListener),
        &[helpers::HELPERS],
    )
    .with_stack_frame_size(config.0)
    .with_guest_stack_size(guest_stack_size(config.0)?)
    .with_guarded_stack_frames(config.1))
}

/// Loads an ELF, pins it to this thread, and requires the stream entrypoint.
fn load_pinned(
    loader: &ProgramLoader,
    elf: &[u8],
    thread_env: ThreadEnv,
) -> Result<Program, SockError> {
    let unbound: UnboundProgram = loader
        .load(&mut rand::thread_rng(), elf)
        .map_err(|e| SockError::Load(e.to_string()))?;
    let program = unbound.pin_to_current_thread(thread_env);
    if !program.has_section(SECTION_STREAM) {
        return Err(SockError::NoEntrypoint);
    }
    Ok(program)
}

/// Compiles, or returns the compiled program for, one content root.
fn program_for(
    loaders: &LoaderCache,
    cache: &ProgramCache,
    thread_env: ThreadEnv,
    root: &Hash,
    elf: &[u8],
    stack_frame_size: Option<usize>,
    guarded_stack_frames: Option<bool>,
) -> Result<Rc<Program>, SockError> {
    let config = resolve_stack_config(stack_frame_size, guarded_stack_frames)?;
    let key = (*root, config);
    if let Some(program) = cache.borrow().0.get(&key) {
        return Ok(program.clone());
    }
    let existing_loader = loaders.borrow().get(&config).cloned();
    let loader = if let Some(loader) = existing_loader {
        loader
    } else {
        let loader = Rc::new(stack_loader(config)?);
        loaders.borrow_mut().insert(config, loader.clone());
        loader
    };
    let program = Rc::new(load_pinned(&loader, elf, thread_env)?);
    let mut cache = cache.borrow_mut();
    cache.0.insert(key, program.clone());
    cache.1.push_back(key);
    while cache.1.len() > MAX_CACHED_PROGRAMS {
        let oldest = cache
            .1
            .pop_front()
            .expect("a non-empty eviction queue stays non-empty");
        cache.0.remove(&oldest);
    }
    Ok(program)
}

/// Builds the invocation state and runs the guest.
#[allow(
    clippy::too_many_arguments,
    reason = "everything a worker needs to run one invocation, and every one of               them is per-worker state a struct would only rename"
)]
async fn run_job(
    loaders: &LoaderCache,
    cache: &ProgramCache,
    thread_env: ThreadEnv,
    limits: &Limits,
    maps: &Arc<SocketMaps>,
    registry: &Arc<crate::registry::Registry>,
    shutdown: &Arc<ShutdownSignal>,
    invocation: Invocation,
    cancel: oneshot::Receiver<()>,
) -> Result<Outcome, SockError> {
    let program = program_for(
        loaders,
        cache,
        thread_env,
        &invocation.program_root,
        &invocation.program,
        invocation.policy.stack_frame_size,
        invocation.policy.guarded_stack_frames,
    )?;

    let ready = Rc::new(Readiness::default());
    let self_ep = Endpoint::new(
        limits.ring_bytes,
        ready.clone(),
        State::Open,
        invocation.peer.addr.clone(),
    );
    let started = Instant::now();
    // Built by mutation rather than struct update: `Inner` has a `Drop` that
    // aborts its tasks, so moving fields out of another `Inner` is not
    // allowed.
    let mut inner = Inner::bare(invocation.host, started, limits.idle_deadline);
    inner.slots = RefCell::new(vec![Some(Slot::Endpoint(self_ep.clone()))]);
    inner.ready = ready;
    inner.policy = invocation.policy;
    inner.peer = invocation.peer;
    inner.socket = invocation.socket;
    inner.self_origin = invocation.self_origin.canonical();
    inner.meta = invocation.meta;
    inner.maps = maps.clone();
    inner.limits = limits.clone();
    inner.program_root = invocation.program_root;
    inner.id = invocation.id;
    inner.live = invocation
        .slot
        .as_ref()
        .map(|slot| slot.stats())
        .unwrap_or_default();
    inner.registry = Some(registry.clone());
    let inner = Rc::new(inner);
    // The caller's pump tasks are the invocation's own: what the teardown
    // aborts or joins, and what must die with the invocation even if the
    // guest's execution panics somewhere it was not supposed to.
    let mut task_guard = TaskGuard::new();
    let self_reader =
        tokio::task::spawn_local(reader_task(self_ep.clone(), invocation.stream.reader));
    let mut self_writer =
        tokio::task::spawn_local(writer_task(self_ep.clone(), invocation.stream.writer));
    task_guard.push(&self_reader);
    task_guard.push(&self_writer);
    debug_assert_eq!(SY_SELF, 0, "SY_SELF must be the first slot");
    inner.publish_handles();

    let mut ctx = Ctx {
        inner: inner.clone(),
    };
    let timeslice = timeslice();
    let preemption = PreemptionEnabled::new(thread_env);

    let mut resources: [&mut dyn std::any::Any; 1] = [&mut ctx];
    // A *dropped* sender means nobody holds a way to cancel this invocation —
    // not that somebody just cancelled it. Reading the two the same way is how
    // a missing registry entry turns into every invocation being killed the
    // instant it starts, which is a failure that looks like the network.
    let cancelled = async move {
        if cancel.await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(cancelled);

    // The idle deadline ends the invocation itself, not just the next poll
    // wait. `made_progress` pushes the deadline out whenever bytes move or a
    // handle becomes ready, so a proxy with steady traffic never notices it —
    // but an invocation that stops making progress is a slot and a stream a
    // caller can hold open forever, spinning a throttled loop into the
    // worker. The deadline is re-read after every sleep, so progress made
    // while one was scheduled still postpones the ending.
    let idle = async {
        loop {
            let remaining = inner.deadline.get().saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            tokio::time::sleep(remaining).await;
        }
    };
    tokio::pin!(idle);

    // `biased` with the run branch first: a program that returns at the same
    // instant its idle deadline expires has ended itself, and its own ending
    // is the one the caller is told about.
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
            biased;
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
            // A kill or shutdown drops the guest where it stands. That is safe
            // because everything it can hold is host-side and owned by `inner`.
            _ = &mut cancelled => SockStatus::Killed,
            _ = &mut idle => SockStatus::Deadline,
            _ = shutdown.cancelled() => SockStatus::Shutdown,
        }
    };

    inner.flush_log();
    // Let whatever the guest wrote reach the wire before anything is torn
    // down: the program returning is not the same as its last write landing.
    // That holds for every endpoint it wrote to, not only for the caller's
    // stream — a proxy's last upstream bytes are as much accepted-and-owed as
    // its last reply, and the host told the guest so when it took them.
    //
    // One window for all of them, and the flushes run inside it at once, so
    // teardown costs what it always cost rather than a window per endpoint.
    let deadline = Instant::now() + TEARDOWN_DRAIN;
    self_ep.shutdown();
    let draining = inner.begin_drain();
    if tokio::time::timeout_at(deadline.into(), &mut self_writer)
        .await
        .is_err()
    {
        self_writer.abort();
    }
    for ep in draining {
        let left = deadline.saturating_duration_since(Instant::now());
        // Out of time is out of time: what has not reached the wire by here is
        // dropped, as it would be by a process that exited. The alternative is
        // an invocation whose slot an unreachable peer can hold open.
        if left.is_zero() || tokio::time::timeout(left, ep.wait_tx_done()).await.is_err() {
            break;
        }
    }
    self_reader.abort();
    inner.abort_tasks();
    // The length is read into a local first: a `for` loop's iterator
    // expression keeps its temporaries alive for the whole loop, so borrowing
    // the table to bound the range would still be borrowing it when `remove`
    // asks to borrow it mutably.
    let open_handles = inner.slots.borrow().len() as i64;
    for handle in 0..open_handles {
        inner.remove(handle);
    }

    // Held until here on purpose: the slot is what the concurrency cap counts,
    // and giving it back before the invocation has finished would let the cap
    // be exceeded by exactly the number of invocations that are shutting down.
    if let Some(slot) = &invocation.slot {
        registry.record_outcome(
            slot.socket(),
            inner.program_root,
            inner.peer.device_key,
            matches!(status, SockStatus::Fault(_)),
        );
    }
    drop(invocation.slot);

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

fn shutdown_outcome() -> Outcome {
    Outcome {
        status: SockStatus::Shutdown,
        bytes_in: 0,
        bytes_out: 0,
        metrics: Vec::new(),
        labels: Vec::new(),
    }
}

fn killed_outcome() -> Outcome {
    Outcome {
        status: SockStatus::Killed,
        bytes_in: 0,
        bytes_out: 0,
        metrics: Vec::new(),
        labels: Vec::new(),
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
    // Its own thread, for two reasons that point the same way. A `Program` is
    // pinned to the thread that loaded it, so a declaration run needs a thread
    // it can have to itself; and the runtime it needs cannot be *dropped*
    // inside an async context, which is where an arm or a scan calls this from.
    // A thread costs nothing here: this runs when an operator arms a socket,
    // not when a peer connects.
    let elf = elf.to_vec();
    std::thread::Builder::new()
        .name("synch-sock-declare".into())
        .spawn(move || declare_here(&elf, host))
        .map_err(|e| SockError::Load(e.to_string()))?
        .join()
        .map_err(|_| SockError::Fault("the declaration hook panicked".into()))?
}

fn declare_here(elf: &[u8], host: Arc<dyn crate::SocketHost>) -> Result<Declaration, SockError> {
    let global = global_env();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| SockError::Load(e.to_string()))?;
    let thread_env = global.init_thread(PREEMPTION_INTERVAL);
    let loader = stack_loader(resolve_stack_config(None, None)?)?;
    let program = load_pinned(&loader, elf, thread_env)?;
    if !program.has_section(SECTION_INIT) {
        // No hook is a legitimate shape: a socket that reaches nothing and
        // reads nothing needs to declare nothing. It gets the empty
        // declaration, which grants exactly nothing.
        return Ok(Declaration::default());
    }

    let inner = Rc::new(Inner::declaring(host, Instant::now()));
    let mut ctx = Ctx {
        inner: inner.clone(),
    };
    let timeslice = timeslice();
    let preemption = PreemptionEnabled::new(thread_env);
    let mut resources: [&mut dyn std::any::Any; 1] = [&mut ctx];
    let local = tokio::task::LocalSet::new();
    // A hard deadline on the whole hook, not just on its poll waits: the idle
    // deadline a declaration run carries is only consulted by `sy_poll`, and a
    // hook that never polls would otherwise spin past it and hang the arming
    // thread (and, with `--auto`, the scanner) forever.
    let outcome = local.block_on(&runtime, async {
        tokio::time::timeout(DECLARE_IDLE, program.run(
            &timeslice,
            &TokioTimeslicer,
            SECTION_INIT,
            &mut resources,
            &[],
            &preemption,
        ))
        .await
    });
    match outcome {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(SockError::Fault(e.to_string())),
        Err(_) => {
            return Err(SockError::Load(
                "the declaration hook exceeded its idle deadline".into(),
            ))
        }
    }
    inner.flush_log();
    let declaration = inner.declaration.borrow().clone();
    declaration
        .validate()
        .map_err(|e| SockError::Load(format!("invalid declaration: {e}")))?;
    resolve_stack_config(
        declaration.stack_frame_size.map(|size| size as usize),
        declaration.guarded_stack_frames,
    )?;
    Ok(declaration)
}

/// Every helper name, for the SDK-header agreement test.
#[cfg(test)]
pub(crate) fn helper_names() -> Vec<&'static str> {
    helpers::helper_names()
}

#[cfg(test)]
mod stack_tests {
    use super::*;

    #[test]
    fn stack_configuration_never_uses_automatic_guard_selection() {
        assert_eq!(
            resolve_stack_config_for_page(None, None, 4 * 1024).unwrap(),
            (16 * 1024, true)
        );
        assert_eq!(
            resolve_stack_config_for_page(None, None, 64 * 1024).unwrap(),
            (16 * 1024, false)
        );
        assert!(resolve_stack_config_for_page(Some(512), None, 4 * 1024).is_err());
        assert_eq!(
            resolve_stack_config_for_page(Some(512), None, 64 * 1024).unwrap(),
            (512, false)
        );
        assert_eq!(
            resolve_stack_config_for_page(Some(512), Some(false), 4 * 1024).unwrap(),
            (512, false)
        );
        assert!(resolve_stack_config_for_page(Some(16 * 1024), Some(true), 64 * 1024).is_err());
    }

    #[test]
    fn the_stack_keeps_at_least_eight_frames() {
        assert_eq!(guest_stack_size(512).unwrap(), 32 * 1024 + 512);
        assert_eq!(guest_stack_size(16 * 1024).unwrap(), 128 * 1024 + 512);
    }
}
