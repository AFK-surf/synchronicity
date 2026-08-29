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
pub(crate) mod process;
pub(crate) mod sftp;
pub(crate) mod ssh;
pub(crate) mod tasks;

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
        ctx::{Ctx, Inner, Slot, DECLARE_IDLE},
        endpoint::Readiness,
        map::SocketMaps,
    },
    Invocation, Outcome, SockError,
};

/// The persistent Ed25519 SSH host key shared by every socket invocation on a node.
#[derive(Clone)]
pub struct SshHostKey(russh::keys::PrivateKey);

impl std::fmt::Debug for SshHostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshHostKey")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl SshHostKey {
    /// Generates a fresh Ed25519 host key.
    pub fn generate() -> Result<Self, SockError> {
        ssh::generate_host_key()
            .map(Self)
            .map_err(|error| SockError::Load(format!("cannot generate SSH host key: {error}")))
    }

    /// Parses an unencrypted OpenSSH private-key document.
    pub fn from_openssh(encoded: &str) -> Result<Self, SockError> {
        let key = russh::keys::PrivateKey::from_openssh(encoded)
            .map_err(|error| SockError::Load(format!("invalid SSH host key: {error}")))?;
        if key.algorithm() != russh::keys::Algorithm::Ed25519 {
            return Err(SockError::Load("SSH host key is not Ed25519".into()));
        }
        Ok(Self(key))
    }

    /// Encodes the key for protected storage in the node database.
    pub fn to_openssh(&self) -> Result<String, SockError> {
        self.0
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .map(|encoded| encoded.to_string())
            .map_err(|error| SockError::Load(format!("cannot encode SSH host key: {error}")))
    }

    /// The conventional SHA-256 host-key fingerprint.
    pub fn fingerprint(&self) -> String {
        self.0
            .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
            .to_string()
    }
}

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
    ssh_host_key: Arc<russh::keys::PrivateKey>,
    ssh_auth_throttle: Arc<crate::runtime::ssh::AuthThrottle>,
    reply: oneshot::Sender<Result<Outcome, SockError>>,
    cancel: oneshot::Receiver<SockStatus>,
    peer_gone: oneshot::Receiver<SockStatus>,
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
    /// The pool's host-side ssh auth-failure throttle (one per pool, shared
    /// by every invocation this worker serves).
    ssh_auth_throttle: Arc<crate::runtime::ssh::AuthThrottle>,
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
    ssh_host_key: Arc<russh::keys::PrivateKey>,
}

impl WorkerHandle {
    /// Starts `count` workers.
    ///
    /// Zero is rounded up to one: a pool that exists but can run nothing is a
    /// configuration mistake that would surface as a hang rather than an error.
    pub fn start(count: usize, limits: Limits) -> WorkerHandle {
        let host_key =
            SshHostKey::generate().expect("the platform can generate an Ed25519 SSH key");
        Self::start_with_ssh_host_key(count, limits, host_key)
    }

    /// Starts workers with a persistent node-wide SSH host key.
    pub fn start_with_ssh_host_key(
        count: usize,
        limits: Limits,
        ssh_host_key: SshHostKey,
    ) -> WorkerHandle {
        let count = count.max(1);
        warn_if_default_stack_is_contiguous();
        // Installed before any worker exists, so no thread can start a guest
        // before the handlers that contain its faults are in place.
        let global = global_env();
        let maps = SocketMaps::new();
        // The daemon-wide admission ceiling: every worker's cap of
        // invocations, in flight or queued, before new admissions are
        // refused (`docs/SOCKETS.md` §10).
        let pool_cap = limits.max_streams.saturating_mul(count.max(1)) as u64;
        let registry = crate::registry::Registry::with_pool_cap(pool_cap);
        let shutdown = Arc::new(ShutdownSignal::default());
        // One throttle per pool: the auth-failure window is shared across
        // every connection the pool serves, so an attacker cannot reset it
        // with one fresh TCP connection per batch.
        let ssh_auth_throttle = Arc::new(crate::runtime::ssh::AuthThrottle::new());
        let workers = (0..count)
            .map(|index| {
                Worker::spawn(
                    index,
                    global,
                    limits.clone(),
                    maps.clone(),
                    registry.clone(),
                    shutdown.clone(),
                    ssh_auth_throttle.clone(),
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
            ssh_host_key: Arc::new(ssh_host_key.0),
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

    /// Whether the pool-wide admission ceiling has been reached.
    ///
    /// The ceiling is the registry's admission-token count (`docs/SOCKETS.md`
    /// §10): every admitted invocation holds a token from admission until it
    /// ends, so the check cannot be walked by opens that have not reached a
    /// worker yet. The engine refuses with `Busy` when it is reached; the
    /// registry's own `reserve` enforces the same ceiling atomically, so the
    /// check here only picks the refusal message.
    pub fn full(&self) -> bool {
        self.registry.pool_full()
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
        // No connection to watch: the peer-gone channel never fires.
        let (_, peer_gone) = oneshot::channel();
        self.run_cancellable(invocation, cancel_rx, peer_gone).await
    }

    /// Runs one invocation, with channels that end it early.
    ///
    /// `cancel` is what `synch socket kill` pulls, and ends the invocation
    /// with `Killed`. `peer_gone` is the caller's connection closing
    /// (`sync/sock/1` observes `Connection::closed`), which ends it with
    /// `Deadline` — the same non-fault ending as a failed stream, because the
    /// two say the same thing about the caller: it is gone, and nothing the
    /// guest produces can be delivered. Both are separate from the pool-wide
    /// shutdown signal, so callers can distinguish `Killed`, `Deadline` and
    /// `Shutdown`.
    pub async fn run_cancellable(
        &self,
        invocation: Invocation,
        cancel: oneshot::Receiver<SockStatus>,
        peer_gone: oneshot::Receiver<SockStatus>,
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
            ssh_host_key: self.ssh_host_key.clone(),
            ssh_auth_throttle: worker.ssh_auth_throttle.clone(),
            reply,
            cancel,
            peer_gone,
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
        ssh_auth_throttle: Arc<crate::runtime::ssh::AuthThrottle>,
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
                                            job.ssh_host_key,
                                            job.ssh_auth_throttle,
                                            job.cancel,
                                            job.peer_gone,
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
            ssh_auth_throttle,
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
    ssh_host_key: Arc<russh::keys::PrivateKey>,
    ssh_auth_throttle: Arc<crate::runtime::ssh::AuthThrottle>,
    cancel: oneshot::Receiver<SockStatus>,
    peer_gone: oneshot::Receiver<SockStatus>,
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

    let ready = Arc::new(Readiness::default());
    // Start reading before the guest selects raw or SSH mode. Besides applying
    // transport backpressure through a bounded buffer, this preserves the
    // caller-stream failure signal even for a guest that never touches
    // `SY_SELF`: a dead caller must not be able to keep an invocation alive by
    // making progress only on an upstream endpoint.
    let incoming_failed = Arc::new(AtomicBool::new(false));
    let (prefetched_reader, mut prefetch_writer) = tokio::io::duplex(limits.ring_bytes.max(1));
    let mut incoming_reader = invocation.stream.reader;
    let unselected = Rc::new(ctx::UnselectedStream {
        stream: RefCell::new(Some(crate::DuplexStream::new(
            prefetched_reader,
            invocation.stream.writer,
        ))),
        peer: invocation.peer.addr.clone(),
    });
    let started = Instant::now();
    // Built by mutation rather than struct update: `Inner` has a `Drop` that
    // aborts its tasks, so moving fields out of another `Inner` is not
    // allowed.
    let mut inner = Inner::bare(invocation.host, started, limits.idle_deadline);
    inner.slots = RefCell::new(vec![Some(Slot::Unselected(unselected))]);
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
    inner.ssh_host_key = Some(ssh_host_key);
    inner.ssh_auth_throttle = Some(ssh_auth_throttle);
    let inner = Rc::new(inner);
    let prefetch_failed = incoming_failed.clone();
    let prefetch_ready = inner.ready.clone();
    inner.spawn(async move {
        if tokio::io::copy(&mut incoming_reader, &mut prefetch_writer)
            .await
            .is_err()
        {
            prefetch_failed.store(true, Ordering::Release);
            prefetch_ready.bump();
        }
    });
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
    // instant it starts, which is a failure that looks like the network. The
    // payload is the ending to report: `synch socket kill` says `Killed`, and
    // the caller's connection closing says `Deadline` — both are endings the
    // select below turns into statuses directly.
    let cancelled = async move {
        match cancel.await {
            Ok(status) => status,
            Err(_) => std::future::pending::<SockStatus>().await,
        }
    };
    tokio::pin!(cancelled);

    // The caller's connection closing (`sync/sock/1` watches
    // `Connection::closed` and signals it here). The stream itself may never
    // fail — after a clean FIN the reader pump has already exited, so a
    // connection that closes afterwards leaves `SY_SELF` looking open — but
    // the caller is gone all the same, and the invocation must not hold its
    // slot for it. Same dropped-sender rule as `cancelled`.
    let peer_gone = async move {
        match peer_gone.await {
            Ok(status) => status,
            Err(_) => std::future::pending::<SockStatus>().await,
        }
    };
    tokio::pin!(peer_gone);

    // The idle deadline ends the invocation itself, not just the next poll
    // wait. `made_progress` pushes the deadline out whenever bytes move or a
    // handle becomes ready, so a proxy with steady traffic never notices it —
    // but an invocation that stops making progress is a slot and a stream a
    // caller can hold open forever, spinning a throttled loop into the
    // worker. The deadline is re-read after every sleep, so progress made
    // while one was scheduled still postpones the ending.
    let idle = async {
        loop {
            let remaining = inner
                .deadline
                .get()
                .saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            tokio::time::sleep(remaining).await;
        }
    };
    tokio::pin!(idle);

    // The caller's stream is the invocation's reason to exist. When the
    // transport fails it — the peer's connection died, a stream reset, a
    // relay that went away — nothing the guest is talking to can be
    // delivered anywhere, and an invocation that keeps running is a slot, a
    // worker placement and a set of rings held for a caller that is gone.
    // What triggers the end is a transport read error, and only that: a caller's
    // clean FIN is a normal half-close a proxy works past, and the guest's
    // own `sy_shutdown`/`sy_close` of `SY_SELF` must not end the invocation
    // either — its slot is deliberately not reused. The prefetch pump raises
    // the flag exactly when the stream underneath errors, so the state is the
    // transport's own verdict, not something the guest can provoke.
    let caller_gone = async {
        let ready = inner.ready.clone();
        loop {
            let epoch = ready.epoch();
            if incoming_failed.load(Ordering::Acquire) {
                return;
            }
            // The prefetch pump bumps readiness, so this wakes on the error;
            // the timeout is only a bound on how long a quiet invocation may
            // hold the worker before the check comes round again.
            let _ = ready.wait(epoch, Duration::from_millis(100)).await;
        }
    };
    tokio::pin!(caller_gone);

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
            // The payloads carry the ending: `synch socket kill` says `Killed`;
            // the caller's connection closing says `Deadline`.
            cancelled = &mut cancelled => cancelled,
            gone = &mut peer_gone => gone,
            _ = &mut idle => SockStatus::Deadline,
            // The caller is gone: nothing the guest produces can be
            // delivered, and holding the slot for it would let one caller
            // pin every stream on a socket and drop the connection. `Deadline`
            // is the non-fault ending — this is not a program fault, and it
            // must not feed the auto-disarm counter.
            _ = &mut caller_gone => SockStatus::Deadline,
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
    // The caller's stream flushes through its writer task's join handle, and it
    // does so whether or not the guest still holds the handle. `sy_close`
    // (`Inner::remove`) drops the slot but not the bytes already queued behind
    // it — it calls `close_flushing`, which shuts the write side down and lets
    // the writer drain on its own timing. Taking the handle only while the slot
    // was still occupied meant a program whose last act was
    // `sy_write(SY_SELF, …); sy_close(SY_SELF);` had nothing waiting on that
    // drain, and `abort_tasks()` below killed the writer mid-flush: the caller
    // got a clean, empty, successful stream. So the take is unconditional, and
    // the shutdown is what depends on the slot.
    if let Some(ctx::Slot2::Endpoint(endpoint)) = inner.slot(SY_SELF) {
        endpoint.shutdown();
    }
    let raw_writer = inner.raw_writer.borrow_mut().take();
    let draining = inner.begin_drain();
    if let Some(mut writer) = raw_writer {
        if tokio::time::timeout_at(deadline.into(), &mut writer)
            .await
            .is_err()
        {
            writer.abort();
        }
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
            inner.peer.origin.clone(),
            matches!(status, SockStatus::Fault(_)),
        );
    }
    drop(invocation.slot);

    let bytes_in = inner.live.bytes_in.load(Ordering::Relaxed);
    let bytes_out = inner.live.bytes_out.load(Ordering::Relaxed);
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
        tokio::time::timeout(
            DECLARE_IDLE,
            program.run(
                &timeslice,
                &TokioTimeslicer,
                SECTION_INIT,
                &mut resources,
                &[],
                &preemption,
            ),
        )
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

    #[test]
    fn an_ssh_host_key_round_trips_without_changing_identity() {
        let key = SshHostKey::generate().unwrap();
        let fingerprint = key.fingerprint();
        let encoded = key.to_openssh().unwrap();
        let decoded = SshHostKey::from_openssh(&encoded).unwrap();
        assert_eq!(decoded.fingerprint(), fingerprint);
    }
}
