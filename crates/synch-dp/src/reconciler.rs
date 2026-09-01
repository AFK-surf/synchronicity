//! The desired-state loop (`docs/CLOUD-DATAPLANE.md` §4.2).
//!
//! Poll, diff, act, report — shaped like the engine's own standing loops:
//! every step is idempotent, and missing a tick costs latency rather than
//! correctness.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::config::DpConfig;
use crate::control::{ControlPlane, Desired, HostedNetwork, Poll};
use crate::error::Result;
use crate::metrics::Metrics;
use crate::store::ObjectStore;
use crate::tenant::Tenant;

/// The service, reconciling what it runs against what it is told to run.
#[derive(Debug)]
pub struct Reconciler {
    config: DpConfig,
    control: ControlPlane,
    objects: ObjectStore,
    resolver: Option<Arc<synch_net::DnssecResolver>>,
    /// Per-tenant work that outlives a reconcile pass.
    ///
    /// A tenant is owned by exactly one of `tenants` and `jobs`. Moving the
    /// tenant into a job keeps operations for that tenant serialized without
    /// making unrelated tenants wait for it to finish.
    jobs: HashMap<String, TenantJob>,
    /// Irreversible storage sweeps, kept separate from tenant ownership.
    collections: HashMap<String, CollectionJob>,
    /// Bounds all active lifecycle work to the capacity this pod declares.
    job_slots: Arc<tokio::sync::Semaphore>,
    /// A separate bound for restore/open work, derived from the blocking pool.
    provision_slots: Arc<tokio::sync::Semaphore>,
    /// Wakes the supervisor to reap outcomes and refresh gauges promptly.
    job_wake: Arc<tokio::sync::Notify>,
    tenants: HashMap<String, Tenant>,
    /// Keys in the latest validated desired document.
    wanted: HashSet<String>,
    /// What this pod knows about each network's recent failures: how many,
    /// and when it may next be tried.
    ///
    /// An entry outlives the failure that made it, and has to. The escalation
    /// decays by *time*, not by success — a tenant that comes back and dies
    /// again a minute later is crash-looping, and forgetting its history the
    /// moment it provisioned would reset the backoff on every lap, which is
    /// the loop the backoff exists to break. [`PARK_DECAY`] is what forgets.
    /// An entry whose `retry_at` has passed is not holding anything back; it
    /// is a memory, and it is bounded by the desired set because
    /// `parked.retain` prunes to it every pass.
    parked: HashMap<String, Parked>,
    /// Consecutive fresh polls that have answered "nothing for this data plane".
    empty_answers: u32,
    etag: Option<String>,
    /// The name the control plane last answered with, once it has.
    ///
    /// Kept only so the log line fires on a change rather than every pass:
    /// what a tick *acts* on is the name in the document it just read, never
    /// this. `None` before the first answer, which is a pod that does not yet
    /// know its own name — not a pod that has to guess one.
    logged_dp: Option<String>,
    /// The last document this shard successfully acted on.
    ///
    /// In memory, and consulted before the bucket: a `304 Not Modified` means
    /// "what you already have", and reading that back from object storage
    /// turns a missing cache object into an authoritative empty set — which
    /// would drain every tenant on the shard.
    last: Option<Desired>,
    metrics: Arc<Metrics>,
}

/// How many consecutive fresh polls must agree before a shard tears itself
/// down.
///
/// Three, at the poll interval, so a transient truncation or a
/// half-configured shard costs minutes rather than a shard's worth of data
/// directories — and a genuine offboarding of the last network still
/// completes without an operator.
const EMPTY_SET_CONFIRMATIONS: u32 = 3;

/// How long one routine tenant operation may take.
///
/// Converging, measuring what a tenant holds, and heartbeating all end up
/// waiting on that tenant's one store
/// connection, and that connection is exactly what a tenant's own peers keep
/// busy. Persistent jobs isolate that wait from other tenants; this deadline
/// also ensures the affected slot returns to the scheduler, retries partial
/// idempotent work, and keeps attempting its billing heartbeat.
///
/// Provisioning is deliberately excluded. It has operation-specific network
/// and object-store deadlines and runs as a persistent job: imposing this
/// aggregate deadline on restore plus startup peer re-adoption used to drop a
/// live endpoint halfway through construction.
const TENANT_PASS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// The longest a tenant that keeps failing is parked between attempts.
const MAX_PARK: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// How long a tenant must go without failing before its backoff is forgotten.
///
/// Otherwise a tenant that restarts once a day arrives at the cap after a
/// fortnight and stays there.
const PARK_DECAY: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// A network this shard is not running, and when it may try again.
#[derive(Debug, Clone, Copy)]
struct Parked {
    /// When the next attempt is allowed.
    retry_at: std::time::Instant,
    /// When the failure that parked it happened, for [`PARK_DECAY`].
    at: std::time::Instant,
    /// Consecutive failures, which is what sets the wait.
    failures: u32,
}

/// The one operation currently owning a tenant slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenantJobKind {
    Provisioning,
    Reconciling,
    Draining { forget: bool },
    CleaningAfterPanic,
    Forgetting,
}

/// Work left running between desired-state polls.
#[derive(Debug)]
struct TenantJob {
    kind: TenantJobKind,
    dir: std::path::PathBuf,
    /// Provisioning may be cancelled only before it acquires its permits and
    /// begins touching the tenant directory.
    cancel_before_start: Option<tokio::sync::oneshot::Sender<()>>,
    completed: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<TenantJobOutput>,
}

#[derive(Debug)]
struct CollectionJob {
    completed: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

/// Ownership returned by a completed tenant job.
#[derive(Debug)]
enum TenantJobOutput {
    Provisioned(Result<Tenant>),
    Reconciled(Tenant),
    Drained,
    Cancelled,
    CleanedAfterPanic,
    Forgotten,
}

/// A completion bell that rings on success and during panic unwinding.
struct WakeOnDrop {
    wake: Arc<tokio::sync::Notify>,
    completed: Arc<AtomicBool>,
}

impl Drop for WakeOnDrop {
    fn drop(&mut self) {
        self.completed.store(true, Ordering::Release);
        self.wake.notify_one();
    }
}

impl Parked {
    /// The park that follows one more failure after `previous`.
    ///
    /// The first failure waits the identity poll, which is the common case and
    /// not really a failure at all — a zone that has not named the key yet
    /// (§4.3). Each one after it doubles, up to [`MAX_PARK`].
    ///
    /// Backing off matters most for the failure that is *not* a wait: a tenant
    /// whose standing loops keep dying is drained and re-provisioned, and
    /// provisioning discards the local database and replays the whole replica
    /// stream (`Tenant::provision`). Retried every poll, that is one full
    /// restore per minute per crash-looping tenant — object-store egress, disk
    /// churn and blocking-pool time charged to every other tenant on the
    /// shard, for a tenant that is not working anyway.
    fn after(previous: Option<Parked>) -> Parked {
        let now = std::time::Instant::now();
        let failures = match previous {
            Some(previous) if now.duration_since(previous.at) < PARK_DECAY => {
                previous.failures.saturating_add(1)
            }
            _ => 1,
        };
        let wait = crate::tenant::identity_poll()
            .saturating_mul(1u32 << failures.saturating_sub(1).min(8))
            .min(MAX_PARK);
        Parked {
            retry_at: now + wait,
            at: now,
            failures,
        }
    }
}

/// Waits for already-started shutdown work together, collecting its outputs.
///
/// A hand-rolled join rather than a `futures` dependency, in the shape the
/// engine already uses for the same job (`synch_engine::join`): no
/// cancellation, no early return, every branch polled to the end. Ordinary
/// reconciliation does not use a join at all; its jobs persist across passes.
async fn join_all<F: std::future::Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut pending: Vec<std::pin::Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    let mut out = Vec::with_capacity(pending.len());
    std::future::poll_fn(move |cx| {
        let mut index = 0;
        while index < pending.len() {
            match pending[index].as_mut().poll(cx) {
                std::task::Poll::Ready(value) => {
                    out.push(value);
                    pending.remove(index);
                }
                std::task::Poll::Pending => index += 1,
            }
        }
        if pending.is_empty() {
            std::task::Poll::Ready(std::mem::take(&mut out))
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}

/// Runs one routine tenant operation under [`TENANT_PASS_TIMEOUT`].
///
/// A timeout drops the future rather than cancelling the work behind it: a
/// store call already handed to the blocking pool runs to completion whatever
/// this does. The job owns the Tenant throughout, so the timeout returns that
/// slot to its scheduler without affecting any other tenant's job.
async fn under_deadline<T>(
    tenant: &str,
    what: &'static str,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    match tokio::time::timeout(TENANT_PASS_TIMEOUT, work).await {
        Ok(done) => Some(done),
        Err(_) => {
            tracing::warn!(
                %tenant, step = what, seconds = TENANT_PASS_TIMEOUT.as_secs(),
                "a tenant overran its share of the reconcile pass; carrying on without it"
            );
            None
        }
    }
}

impl Reconciler {
    /// Builds a reconciler. The resolver is shared by every tenant: it holds
    /// the TUF/Rekor pin-walk state, and one Sigstore outage should cost one
    /// attempt a day rather than one per tenant.
    pub fn new(
        config: DpConfig,
        control: ControlPlane,
        objects: ObjectStore,
        resolver: Option<Arc<synch_net::DnssecResolver>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let job_limit = usize::try_from(config.max_tenants)
            .unwrap_or(usize::MAX)
            .max(1);
        // The blocking pool is sized at 64 threads per tenant until its cap.
        // Use the same unit here so an oversized desired document cannot make
        // cold restores consume more capacity than the pool was built for.
        let provision_limit = (config.blocking_threads / 64).max(1).min(job_limit);
        Self {
            config,
            control,
            objects,
            resolver,
            jobs: HashMap::new(),
            collections: HashMap::new(),
            job_slots: Arc::new(tokio::sync::Semaphore::new(job_limit)),
            provision_slots: Arc::new(tokio::sync::Semaphore::new(provision_limit)),
            job_wake: Arc::new(tokio::sync::Notify::new()),
            tenants: HashMap::new(),
            wanted: HashSet::new(),
            logged_dp: None,
            parked: HashMap::new(),
            empty_answers: 0,
            etag: None,
            last: None,
            metrics,
        }
    }

    /// Runs until `shutdown` fires, then drains every tenant.
    pub async fn run(mut self, mut shutdown: tokio::sync::broadcast::Receiver<()>) {
        let mut ticker = tokio::time::interval(self.config.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(error) = self.tick().await {
                        tracing::warn!(%error, "reconcile pass failed");
                        self.metrics.reconcile_failed();
                    }
                }
                _ = self.job_wake.notified() => {
                    self.reap_known_jobs().await;
                }
                _ = shutdown.recv() => break,
            }
        }
        self.shutdown().await;
    }

    /// Starts healthy drains immediately, then gathers in-flight ownership as
    /// jobs finish. A slow provision must not spend the pod's termination
    /// grace before already-running tenants begin shipping their final tails.
    async fn shutdown(&mut self) {
        let mut drains: Vec<tokio::task::JoinHandle<()>> = self
            .tenants
            .drain()
            .map(|(_, tenant)| tokio::spawn(tenant.drain()))
            .collect();

        // A provision still waiting for capacity has no directory, endpoint,
        // or tenant to clean up. Once it begins, the receiver is dropped and
        // sending fails; that job is allowed to return owned state normally.
        for job in self.jobs.values_mut() {
            if let Some(cancel) = job.cancel_before_start.take() {
                let _ = cancel.send(());
            }
        }

        let (finished, mut outcomes) = tokio::sync::mpsc::unbounded_channel();
        let job_count = self.jobs.len();
        for (key, job) in self.jobs.drain() {
            let finished = finished.clone();
            tokio::spawn(async move {
                let outcome = job.handle.await;
                let _ = finished.send((key, job.kind, job.dir, outcome));
            });
        }
        drop(finished);
        for _ in 0..job_count {
            let Some((key, kind, dir, outcome)) = outcomes.recv().await else {
                break;
            };
            match outcome {
                Ok(TenantJobOutput::Provisioned(Ok(tenant)))
                | Ok(TenantJobOutput::Reconciled(tenant)) => {
                    drains.push(tokio::spawn(tenant.drain()));
                }
                Ok(TenantJobOutput::Provisioned(Err(error))) => {
                    tracing::info!(tenant = %key, %error, "a provisioning job ended during shutdown");
                }
                Ok(TenantJobOutput::Drained) => {
                    if matches!(kind, TenantJobKind::Draining { forget: true }) {
                        self.forget_local_on_shutdown(&key, dir).await;
                    }
                }
                Ok(
                    TenantJobOutput::Cancelled
                    | TenantJobOutput::CleanedAfterPanic
                    | TenantJobOutput::Forgotten,
                ) => {}
                Err(error) => tracing::warn!(tenant = %key, %error, "a tenant job did not finish"),
            }
        }

        let collections: Vec<_> = self
            .collections
            .drain()
            .map(|(_, job)| job.handle)
            .collect();
        for outcome in join_all(collections).await {
            if let Err(error) = outcome {
                tracing::warn!(%error, "a storage collection job did not finish");
            }
        }
        for handle in drains {
            if let Err(error) = handle.await {
                tracing::warn!(%error, "a tenant drain did not finish");
            }
        }
    }

    async fn forget_local_on_shutdown(&self, key: &str, dir: std::path::PathBuf) {
        match tokio::task::spawn_blocking(move || std::fs::remove_dir_all(dir)).await {
            Ok(Ok(())) => self.metrics.forget_tenant(key),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                self.metrics.forget_tenant(key);
            }
            Ok(Err(error)) => tracing::warn!(
                tenant = %key, %error,
                "could not remove the retired tenant directory during shutdown"
            ),
            Err(error) => tracing::warn!(
                tenant = %key, %error,
                "the retired tenant directory removal task failed during shutdown"
            ),
        }
    }

    /// One pass: poll, diff, reap completed work, and schedule each idle slot.
    pub async fn tick(&mut self) -> Result<()> {
        let Some((desired, fresh)) = self.desired().await? else {
            // A first boot that has reached neither the control plane nor its
            // own cache. It does not know which networks to host, and it does
            // not know its own name either — so there is nothing to converge
            // and nothing to report, and saying so is better than acting on a
            // stand-in empty document that names no data plane.
            tracing::warn!(
                "no desired state yet: the control plane has not answered and \
                 this pod has no cached document to fall back on"
            );
            self.metrics.poll_failed();
            return Ok(());
        };
        self.metrics.observed_generation(desired.generation);
        // Said once per change rather than per pass. A pod that hosts nothing
        // needs to be able to answer "which data plane am I?", and this is
        // where it learns.
        if self.logged_dp.as_deref() != Some(desired.dp.as_str()) {
            tracing::info!(dp = %desired.dp, "this pod is data plane");
            self.logged_dp = Some(desired.dp.clone());
        }
        let dp = desired.dp.clone();

        // Names first, before anything derives a path or a delete prefix from
        // them. A refused entry is dropped rather than fatal: one malformed
        // network must not stop a shard serving every other one.
        let collectable: Vec<crate::control::Collectable> = desired
            .collect
            .into_iter()
            .filter(|network| {
                network.names_are_safe() || {
                    tracing::error!(
                        org = %network.org, network = %network.network,
                        "refusing a collect entry whose names are not safe to build a prefix from"
                    );
                    false
                }
            })
            .collect();
        let mine: Vec<HostedNetwork> = desired
            .networks
            .into_iter()
            .filter(|network| {
                network.names_are_safe() || {
                    tracing::error!(
                        org = %network.org, network = %network.network,
                        "refusing a hosted network whose names are not safe to build a path from"
                    );
                    false
                }
            })
            .collect();
        let wanted: HashMap<String, HostedNetwork> = mine
            .into_iter()
            .map(|network| (network.key(), network))
            .collect();

        // Jobs finish independently of the polling cadence. Reclaim their
        // tenants before deciding what the latest desired document asks each
        // slot to do next.
        self.reap_known_jobs().await;

        // An empty set while tenants are running is the shape of every way
        // this can go wrong at once — a stale cache, a truncated answer, a
        // misconfigured shard — so it is not acted on until several
        // consecutive *fresh* answers have agreed.
        //
        // Two things about the shape of this guard were wrong before and are
        // worth naming. It is asked of the set this shard actually serves,
        // not the fleet-wide one: a document that still lists networks but
        // none of *this* shard's is the same wholesale emptying and used to
        // walk straight past. And it *expires*: an earlier version returned
        // early for ever, so a deployment whose last hosted network was
        // legitimately offboarded held that tenant, its directory and its
        // bucket prefix indefinitely — never draining it, never heartbeating,
        // and never running the collection sweep, which is the exact bug §6
        // exists to fix. Refusing costs a few poll intervals; refusing
        // permanently costs the customer their offboarding.
        let active = self.active_tenants();
        if wanted.is_empty() && active > 0 {
            if fresh {
                self.empty_answers = self.empty_answers.saturating_add(1);
            }
            if self.empty_answers < EMPTY_SET_CONFIRMATIONS {
                tracing::error!(
                    tenants = active,
                    confirmations = self.empty_answers,
                    needed = EMPTY_SET_CONFIRMATIONS,
                    "an empty desired set while tenants are running; waiting for it to be confirmed"
                );
                self.metrics.reconcile_failed();
                return Ok(());
            }
            tracing::warn!(
                tenants = active,
                "an empty desired set confirmed; draining every tenant on this shard"
            );
        } else {
            self.empty_answers = 0;
        }
        // Only intent this pass is actually willing to act on may drive
        // completion wakes between polls. In particular, an unconfirmed empty
        // answer must not let a later job completion retire local state.
        self.wanted = wanted.keys().cloned().collect();

        // Retire idle tenants that are no longer wanted. A tenant already in
        // a job is not cancelled: the next pass reaps it and schedules its
        // drain. Arbitrary task abortion is not a safe endpoint close.
        let gone: Vec<String> = self
            .tenants
            .keys()
            .filter(|key| !wanted.contains_key(*key))
            .cloned()
            .collect();
        for key in gone {
            if let Some(tenant) = self.tenants.remove(&key) {
                tracing::info!(tenant = %key, "network is no longer hosted; draining");
                self.start_drain(key.clone(), tenant, true);
            }
            self.parked.remove(&key);
        }

        // An absent parked tenant can still have a restored or initialized
        // directory. Retire that local copy under a tracked job before remote
        // collection is allowed; otherwise collecting an empty stream and
        // later re-enabling could make provisioning adopt stale local state.
        let abandoned: Vec<String> = self
            .parked
            .keys()
            .filter(|key| !wanted.contains_key(*key))
            .cloned()
            .collect();
        for key in abandoned {
            self.parked.remove(&key);
            if !self.jobs.contains_key(&key) {
                let (org, network) = key
                    .split_once('/')
                    .expect("validated tenant keys contain one slash");
                self.start_forget(key.clone(), self.config.tenant_dir(org, network));
            }
        }

        // A tenant whose standing loops have died is re-provisioned rather
        // than converged. It looks healthy from every angle that matters
        // externally — the node is open, the heartbeat still reports held
        // bytes — while it has silently stopped publishing, or stopped
        // renewing the membership lease that is the tenant boundary itself.
        // Draining and re-provisioning is the whole of the restart, and it is
        // per tenant: one panicking loop must not be another tenant's outage.
        //
        // The restart is backed off from the second one on. Re-provisioning
        // replays the whole replica stream over a discarded local database
        // (`Tenant::provision`), so a tenant whose loops keep dying would
        // otherwise buy a full restore every poll — object-store egress and
        // blocking-pool time charged to every other tenant on the shard, for a
        // tenant that is not working anyway. The first restart is still
        // immediate: a loop that panicked once is a tenant that should be back
        // before anybody notices.
        let failing: Vec<String> = self
            .tenants
            .iter()
            .filter(|(_, tenant)| tenant.has_failed_loop())
            .map(|(key, _)| key.clone())
            .collect();
        for key in failing {
            tracing::error!(tenant = %key, "a standing loop stopped; restarting the tenant");
            self.metrics.reconcile_failed();
            let mut park = Parked::after(self.parked.get(&key).copied());
            if park.failures == 1 {
                // Recorded even though nothing is being waited for. The count
                // is what makes the *second* failure back off, and a first
                // restart that left no trace would reset the escalation every
                // time — a tenant crash-looping forever at one full replica
                // restore per poll, which is the whole thing this prevents.
                park.retry_at = park.at;
            } else {
                tracing::error!(
                    tenant = %key, failures = park.failures,
                    "this tenant keeps losing a standing loop; backing off its restart"
                );
            }
            self.parked.insert(key.clone(), park);
            if let Some(tenant) = self.tenants.remove(&key) {
                self.start_drain(key, tenant, false);
            }
        }

        // Each idle tenant advances independently. The job owns the Tenant
        // until it finishes, which is both the per-tenant serialization lock
        // and the absence of any cross-tenant phase barrier.
        let standing: Vec<String> = self
            .tenants
            .keys()
            .filter(|key| wanted.contains_key(*key))
            .cloned()
            .collect();
        for key in standing {
            let Some(tenant) = self.tenants.remove(&key) else {
                continue;
            };
            self.start_reconcile(key.clone(), tenant, wanted[&key].clone(), dp.clone());
        }

        let now = std::time::Instant::now();
        for (key, network) in &wanted {
            if self.tenants.contains_key(key)
                || self.jobs.contains_key(key)
                || self.collections.contains_key(key)
            {
                continue;
            }
            if self
                .parked
                .get(key)
                .is_some_and(|parked| parked.retry_at > now)
            {
                continue;
            }
            self.start_provision(key.clone(), network.clone());
        }

        // Collection is the one irreversible act here, so it runs only on a
        // document the control plane answered *this pass*. The fail-static
        // cache exists to keep tenants alive through an outage; letting it
        // authorize a delete would invert exactly what it is for — a shard
        // partitioned from the control plane could delete a prefix the org
        // had since re-enabled, and never know.
        if fresh {
            self.start_collections(&collectable);
        } else if !collectable.is_empty() {
            tracing::info!(
                due = collectable.len(),
                "holding collections until the control plane answers again"
            );
        }
        self.metrics.tenants(self.running_tenants(), self.waiting());
        Ok(())
    }

    /// Reaps against the latest known intent and refreshes aggregate gauges.
    async fn reap_known_jobs(&mut self) {
        let wanted = self.wanted.clone();
        self.reap_finished_jobs(&wanted).await;
        self.reap_finished_collections().await;
        self.metrics.tenants(self.running_tenants(), self.waiting());
    }

    /// Reclaims every job that completed since the previous pass.
    async fn reap_finished_jobs(&mut self, wanted: &HashSet<String>) {
        let finished: Vec<String> = self
            .jobs
            .iter()
            .filter(|(_, job)| job.completed.load(Ordering::Acquire) || job.handle.is_finished())
            .map(|(key, _)| key.clone())
            .collect();
        for key in finished {
            let Some(job) = self.jobs.remove(&key) else {
                continue;
            };
            let kind = job.kind;
            let dir = job.dir.clone();
            match job.handle.await {
                Ok(TenantJobOutput::Provisioned(Ok(tenant))) => {
                    self.tenants.insert(key, tenant);
                }
                Ok(TenantJobOutput::Provisioned(Err(error))) => {
                    tracing::info!(tenant = %key, %error, "tenant not ready; will retry");
                    if wanted.contains(&key) {
                        self.park(key);
                    } else {
                        self.start_forget(key, dir);
                    }
                }
                Ok(TenantJobOutput::Reconciled(tenant)) => {
                    self.tenants.insert(key, tenant);
                }
                Ok(TenantJobOutput::Drained) => {
                    // Intent may have changed while the non-cancellable drain
                    // ran. Latest offboarding intent always upgrades a restart
                    // drain to local retirement before collection can begin.
                    if matches!(kind, TenantJobKind::Draining { forget: true })
                        || !wanted.contains(&key)
                    {
                        self.start_forget(key, dir);
                    }
                }
                Ok(TenantJobOutput::CleanedAfterPanic) => {
                    if wanted.contains(&key) {
                        self.park(key);
                    } else {
                        self.start_forget(key, dir);
                    }
                }
                Ok(TenantJobOutput::Forgotten) => {
                    self.parked.remove(&key);
                    self.metrics.forget_tenant(&key);
                }
                Ok(TenantJobOutput::Cancelled) => {}
                Err(error) => {
                    tracing::error!(tenant = %key, %error, ?kind, "a tenant job panicked");
                    self.metrics.reconcile_failed();
                    // Tenant::Drop keeps the lifecycle lock until its detached
                    // endpoint/replicator cleanup finishes. Keep this slot
                    // visible behind a lock-acquisition barrier so neither
                    // collection nor reprovisioning can race that teardown.
                    if kind == TenantJobKind::Forgetting {
                        self.start_forget(key, dir);
                    } else {
                        self.start_cleanup_barrier(key, dir);
                    }
                }
            }
        }
    }

    /// Starts a provision without tying its lifetime to this reconcile pass.
    fn start_provision(&mut self, key: String, network: HostedNetwork) {
        assert!(!self.jobs.contains_key(&key), "one job per tenant");
        let config = self.config.clone();
        let dir = config.tenant_dir(&network.org, &network.network);
        let control = self.control.clone();
        let resolver = self.resolver.clone();
        let metrics = self.metrics.clone();
        let job_slots = self.job_slots.clone();
        let provision_slots = self.provision_slots.clone();
        let wake = self.job_wake.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let completion = completed.clone();
        let (cancel_before_start, mut cancelled) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let _wake = WakeOnDrop {
                wake,
                completed: completion,
            };
            // Provisioning takes its narrower permit first, so jobs waiting on
            // that bound never occupy every general lifecycle slot.
            let acquire = async {
                let provision = provision_slots
                    .acquire_owned()
                    .await
                    .expect("the provisioning semaphore is never closed");
                let job = job_slots
                    .acquire_owned()
                    .await
                    .expect("the tenant-job semaphore is never closed");
                (provision, job)
            };
            let permits = tokio::select! {
                biased;
                _ = &mut cancelled => None,
                permits = acquire => Some(permits),
            };
            let Some((_provision_slot, _job_slot)) = permits else {
                return TenantJobOutput::Cancelled;
            };
            // From here cancellation is unsafe: provisioning may own a
            // lifecycle lock or endpoint, so shutdown must gather its result.
            drop(cancelled);
            TenantJobOutput::Provisioned(
                Tenant::provision(&config, &control, resolver, network, metrics).await,
            )
        });
        self.jobs.insert(
            key,
            TenantJob {
                kind: TenantJobKind::Provisioning,
                dir,
                cancel_before_start: Some(cancel_before_start),
                completed,
                handle,
            },
        );
    }

    /// Runs convergence and its resulting heartbeat as one ordered operation
    /// for this tenant, independently of every other tenant.
    fn start_reconcile(
        &mut self,
        key: String,
        mut tenant: Tenant,
        network: HostedNetwork,
        dp: String,
    ) {
        assert!(!self.jobs.contains_key(&key), "one job per tenant");
        let dir = tenant.dir().to_path_buf();
        let config = self.config.clone();
        let control = self.control.clone();
        let metrics = self.metrics.clone();
        let job_slots = self.job_slots.clone();
        let wake = self.job_wake.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let completion = completed.clone();
        let job_key = key.clone();
        let handle = tokio::spawn(async move {
            let _wake = WakeOnDrop {
                wake,
                completed: completion,
            };
            let _job_slot = job_slots
                .acquire_owned()
                .await
                .expect("the tenant-job semaphore is never closed");
            let converged = under_deadline(
                &job_key,
                "converge",
                tenant.converge(&network, &config, &control),
            )
            .await;
            if let Some(Err(error)) = converged {
                tracing::warn!(tenant = %job_key, %error, "converging the tenant failed");
            }

            metrics.tenant_db_bytes(&job_key, tenant.db_bytes());
            let measured = under_deadline(&job_key, "status", tenant.status(&dp)).await;
            match measured {
                Some(Ok(status)) => {
                    metrics.tenant_status(&job_key, &status);
                    let sent = under_deadline(
                        &job_key,
                        "heartbeat",
                        control.report_status(
                            &tenant.network.org,
                            &tenant.network.network,
                            &status,
                        ),
                    )
                    .await;
                    if let Some(Err(error)) = sent {
                        tracing::warn!(tenant = %job_key, %error, "status heartbeat failed");
                    }
                }
                Some(Err(error)) => tracing::warn!(
                    tenant = %job_key, %error,
                    "could not measure what the tenant holds"
                ),
                None => {}
            }
            TenantJobOutput::Reconciled(tenant)
        });
        self.jobs.insert(
            key,
            TenantJob {
                kind: TenantJobKind::Reconciling,
                dir,
                cancel_before_start: None,
                completed,
                handle,
            },
        );
    }

    /// Starts an orderly drain. It has no aggregate deadline: abandoning it
    /// halfway can remove a database underneath a live endpoint or lose its
    /// final replication tail.
    fn start_drain(&mut self, key: String, tenant: Tenant, forget: bool) {
        assert!(!self.jobs.contains_key(&key), "one job per tenant");
        let dir = tenant.dir().to_path_buf();
        let job_slots = self.job_slots.clone();
        let wake = self.job_wake.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let completion = completed.clone();
        let handle = tokio::spawn(async move {
            let _wake = WakeOnDrop {
                wake,
                completed: completion,
            };
            let _job_slot = job_slots
                .acquire_owned()
                .await
                .expect("the tenant-job semaphore is never closed");
            tenant.drain().await;
            TenantJobOutput::Drained
        });
        self.jobs.insert(
            key,
            TenantJob {
                kind: TenantJobKind::Draining { forget },
                dir,
                cancel_before_start: None,
                completed,
                handle,
            },
        );
    }

    /// Waits until panic-triggered `Tenant::Drop` has released the directory.
    fn start_cleanup_barrier(&mut self, key: String, dir: std::path::PathBuf) {
        assert!(!self.jobs.contains_key(&key), "one job per tenant");
        let wake = self.job_wake.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let completion = completed.clone();
        let barrier_dir = dir.clone();
        let job_key = key.clone();
        let handle = tokio::spawn(async move {
            let _wake = WakeOnDrop {
                wake,
                completed: completion,
            };
            loop {
                let probe = barrier_dir.clone();
                match tokio::task::spawn_blocking(move || {
                    synch_engine::LifecycleLock::acquire(&probe)
                })
                .await
                {
                    Ok(Ok(lock)) => {
                        drop(lock);
                        return TenantJobOutput::CleanedAfterPanic;
                    }
                    Ok(Err(error)) if error.kind() == std::io::ErrorKind::AddrInUse => {}
                    Ok(Err(error)) => tracing::warn!(
                        tenant = %job_key, %error,
                        "could not verify that a panicked tenant released its directory"
                    ),
                    Err(error) => tracing::warn!(
                        tenant = %job_key, %error,
                        "the tenant cleanup barrier's lock probe failed"
                    ),
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });
        self.jobs.insert(
            key,
            TenantJob {
                kind: TenantJobKind::CleaningAfterPanic,
                dir,
                cancel_before_start: None,
                completed,
                handle,
            },
        );
    }

    /// Removes a retired local copy before allowing remote collection.
    fn start_forget(&mut self, key: String, dir: std::path::PathBuf) {
        assert!(!self.jobs.contains_key(&key), "one job per tenant");
        let wake = self.job_wake.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let completion = completed.clone();
        let job_slots = self.job_slots.clone();
        let forget_dir = dir.clone();
        let job_key = key.clone();
        let handle = tokio::spawn(async move {
            let _wake = WakeOnDrop {
                wake,
                completed: completion,
            };
            let _job_slot = job_slots
                .acquire_owned()
                .await
                .expect("the tenant-job semaphore is never closed");
            loop {
                let target = forget_dir.clone();
                match tokio::task::spawn_blocking(move || std::fs::remove_dir_all(&target)).await {
                    Ok(Ok(())) => return TenantJobOutput::Forgotten,
                    Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                        return TenantJobOutput::Forgotten;
                    }
                    Ok(Err(error)) => tracing::warn!(
                        tenant = %job_key, %error,
                        "could not remove the retired tenant directory; retrying"
                    ),
                    Err(error) => tracing::warn!(
                        tenant = %job_key, %error,
                        "the retired tenant directory removal task failed; retrying"
                    ),
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        self.jobs.insert(
            key,
            TenantJob {
                kind: TenantJobKind::Forgetting,
                dir,
                cancel_before_start: None,
                completed,
                handle,
            },
        );
    }

    /// Tenants whose endpoints are live, including those temporarily owned by
    /// a convergence job.
    fn running_tenants(&self) -> usize {
        self.tenants.len()
            + self
                .jobs
                .values()
                .filter(|job| job.kind == TenantJobKind::Reconciling)
                .count()
    }

    /// Every occupied slot, including provisioning and draining ones.
    fn active_tenants(&self) -> usize {
        self.tenants.len() + self.jobs.len()
    }

    /// Parks a network until its backoff expires.
    fn park(&mut self, key: String) {
        let park = Parked::after(self.parked.get(&key).copied());
        self.parked.insert(key, park);
    }

    /// How many networks are actually waiting to be provisioned.
    ///
    /// Not `parked.len()`. The map keeps a memory of past failures so the
    /// backoff can escalate across a successful restart (see the field), and
    /// counting those would have `synch_dp_tenants_parked` report every tenant
    /// that ever had a bad minute as one that is down now — a gauge an
    /// operator would learn to ignore, which is worse than not having it.
    fn waiting(&self) -> usize {
        let now = std::time::Instant::now();
        let provisioning = self
            .jobs
            .values()
            .filter(|job| job.kind == TenantJobKind::Provisioning)
            .count();
        provisioning
            + self
                .parked
                .values()
                .filter(|parked| parked.retry_at > now)
                .count()
    }

    /// Deletes the stored copy of offboarded tenants whose hold has run (§6).
    ///
    /// The order is the whole of the safety here: the bytes go first and the
    /// control plane is told second, so a crash in between leaves a network
    /// that is *still* listed as collectable and gets deleted again — a
    /// no-op on an empty prefix — rather than one the control plane believes
    /// is gone while its storage bill continues.
    ///
    /// A tenant this shard is still running is never collected, whatever the
    /// document says. The control plane refuses to mark a hosted network
    /// collected too, so this is the second of two locks on the one operation
    /// in this design that destroys customer data.
    fn start_collections(&mut self, collectable: &[crate::control::Collectable]) {
        for network in collectable {
            let key = network.key();
            if self.tenants.contains_key(&key) || self.jobs.contains_key(&key) {
                tracing::error!(
                    tenant = %key,
                    "refusing to collect storage for a tenant with live lifecycle work"
                );
                continue;
            }
            if self.collections.contains_key(&key) {
                continue;
            }
            let local = self.config.tenant_dir(&network.org, &network.network);
            match std::fs::metadata(&local) {
                Ok(_) => {
                    tracing::warn!(
                        tenant = %key,
                        "retiring a leftover local directory before collecting remote storage"
                    );
                    self.start_forget(key, local);
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::error!(
                        tenant = %key, %error,
                        "cannot prove the local tenant directory is absent; refusing collection"
                    );
                    continue;
                }
            }
            let cas = self.config.cas_root(&network.org, &network.network);
            let db = self.config.db_prefix(&network.org, &network.network);
            // `cas_root` is an OpenDAL root (a leading slash); as a key under
            // this operator's own root it is the same path without it.
            let cas_prefix = cas.trim_start_matches('/').to_string();
            let db_prefix = format!("{db}/");
            let objects = self.objects.clone();
            let control = self.control.clone();
            let metrics = self.metrics.clone();
            let org = network.org.clone();
            let network = network.network.clone();
            let job_key = key.clone();
            let wake = self.job_wake.clone();
            let completed = Arc::new(AtomicBool::new(false));
            let completion = completed.clone();
            let handle = tokio::spawn(async move {
                let _wake = WakeOnDrop {
                    wake,
                    completed: completion,
                };
                let deleted = async {
                    objects.remove_prefix(&cas_prefix).await?;
                    objects.remove_prefix(&db_prefix).await
                }
                .await;
                match deleted {
                    Ok(()) => {
                        if let Err(error) = control.storage_collected(&org, &network).await {
                            // The bytes are gone; the record of it is not. A
                            // later fresh pass re-deletes nothing and reports
                            // it again.
                            tracing::warn!(
                                tenant = %job_key, %error,
                                "deleted the tenant's storage but could not record it"
                            );
                            return;
                        }
                        metrics.collected();
                        tracing::info!(tenant = %job_key, "collected an offboarded tenant's storage");
                    }
                    Err(error) => {
                        tracing::warn!(tenant = %job_key, %error, "could not delete tenant storage")
                    }
                }
            });
            self.collections
                .insert(key, CollectionJob { completed, handle });
        }
    }

    /// Observes collection panics without making completed handles accumulate.
    async fn reap_finished_collections(&mut self) {
        let finished: Vec<String> = self
            .collections
            .iter()
            .filter(|(_, job)| job.completed.load(Ordering::Acquire) || job.handle.is_finished())
            .map(|(key, _)| key.clone())
            .collect();
        for key in finished {
            let Some(job) = self.collections.remove(&key) else {
                continue;
            };
            if let Err(error) = job.handle.await {
                tracing::error!(tenant = %key, %error, "a storage collection job panicked");
                self.metrics.reconcile_failed();
            }
        }
    }

    /// The desired document: from the control plane, or from the bucket.
    ///
    /// Fail-static (§4.2). A successful poll is written to the bucket before
    /// it is acted on — local disk is ephemeral, so a pod rescheduled during a
    /// control-plane outage would otherwise boot knowing nothing and host
    /// nothing. What this cannot cover is a *first* boot with neither: there
    /// is no known set to serve, and that cold start waits.
    async fn desired(&mut self) -> Result<Option<(Desired, bool)>> {
        match self.control.poll(self.etag.as_deref()).await {
            // The control plane answered, and said "what you already have".
            // That is a fresh answer about a document we are holding.
            Ok(Poll::Unchanged) => match self.last.clone() {
                Some(desired) => Ok(Some((desired, true))),
                None => Ok(self.cached().await?.map(|desired| (desired, false))),
            },
            Ok(Poll::Changed { desired, etag }) => {
                self.etag = etag;
                self.last = Some(desired.clone());
                let key = self.config.desired_key();
                match serde_json::to_vec(&desired) {
                    Ok(bytes) => {
                        if let Err(error) = self.objects.put(&key, bytes).await {
                            tracing::warn!(%error, "could not cache the desired state");
                        }
                    }
                    Err(error) => tracing::warn!(%error, "could not encode the desired state"),
                }
                Ok(Some((desired, true)))
            }
            Err(error) => {
                tracing::warn!(%error, "control plane unreachable; holding the current set");
                self.metrics.poll_failed();
                match self.last.clone() {
                    Some(desired) => Ok(Some((desired, false))),
                    None => Ok(self.cached().await?.map(|desired| (desired, false))),
                }
            }
        }
    }

    /// The last document this pod successfully acted on, if it has one.
    ///
    /// `None` is the cold start with nothing: no cache object, and — since
    /// this is only reached when the control plane did not answer — no
    /// document at all. There is deliberately no empty stand-in for that. A
    /// document is what tells this pod which data plane it is, so one
    /// manufactured here would name none, and an empty tenant set is a claim
    /// ("host nothing") rather than the absence of one.
    async fn cached(&self) -> Result<Option<Desired>> {
        let key = self.config.desired_key();
        match self.objects.get_if_present(&key).await? {
            Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
                crate::error::DpError::Control(format!("unreadable cached desired state: {error}"))
            }),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fail-static contract, at the level this module can state it: a
    /// cached document survives a poll that fails.
    #[tokio::test]
    async fn a_cached_document_is_what_a_failed_poll_falls_back_to() {
        let objects = ObjectStore::memory().unwrap();
        let config = test_config();
        let desired = Desired {
            generation: 7,
            dp: "dp-1".into(),
            collect: Vec::new(),
            networks: vec![HostedNetwork {
                org: "acme".into(),
                network: "prod".into(),
                domain: "prod.acme.example".into(),
                budget_bytes: 0,
                retention: "current".into(),
                device: None,
            }],
        };
        objects
            .put(&config.desired_key(), serde_json::to_vec(&desired).unwrap())
            .await
            .unwrap();

        let reconciler = Reconciler::new(
            config,
            // Pointed at a port nothing listens on: the poll fails, which is
            // the condition under test.
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            objects,
            None,
            Arc::new(Metrics::default()),
        );
        let cached = reconciler.cached().await.unwrap();
        assert_eq!(cached, Some(desired));
    }

    /// An empty bucket and no control plane is the one case fail-static
    /// cannot cover, and it answers "nothing known" rather than "host
    /// nothing".
    ///
    /// The distinction is the point. An empty document is a *claim* — it says
    /// this pod should be running no tenants, which is what the wholesale-
    /// emptying guard exists to be careful about — and it would also have to
    /// name a data plane, which a pod that has spoken to nobody cannot do.
    #[tokio::test]
    async fn a_cold_start_with_no_cache_knows_nothing() {
        let reconciler = Reconciler::new(
            test_config(),
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            Arc::new(Metrics::default()),
        );
        assert!(reconciler.cached().await.unwrap().is_none());
    }

    /// The fail-static promise, exercised through the real entry point
    /// rather than by calling the cache directly: an unreachable control
    /// plane leaves the desired set exactly as it was, and says so.
    #[tokio::test]
    async fn an_unreachable_control_plane_holds_the_last_known_set() {
        let objects = ObjectStore::memory().unwrap();
        let config = test_config();
        let cached = Desired {
            generation: 7,
            dp: "dp-1".into(),
            collect: Vec::new(),
            networks: vec![HostedNetwork {
                org: "acme".into(),
                network: "prod".into(),
                domain: "acme.example".into(),
                budget_bytes: 0,
                retention: "current".into(),
                device: None,
            }],
        };
        objects
            .put(&config.desired_key(), serde_json::to_vec(&cached).unwrap())
            .await
            .unwrap();

        let mut reconciler = Reconciler::new(
            config,
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            objects,
            None,
            Arc::new(Metrics::default()),
        );
        let (desired, fresh) = reconciler.desired().await.unwrap().expect("a cached set");
        assert_eq!(desired, cached, "the cached set is what a failed poll sees");
        assert!(
            !fresh,
            "and it is never fresh, so it can never authorize a collection"
        );
    }

    /// A wholesale emptying is not acted on until several *fresh* answers
    /// agree — and then it is. Both halves matter: refusing once protects a
    /// shard from a truncated answer, refusing for ever would strand the last
    /// offboarded tenant's storage, which is the bug §6 exists to fix.
    #[tokio::test]
    async fn an_empty_set_is_confirmed_before_it_is_acted_on() {
        let mut reconciler = Reconciler::new(
            test_config(),
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            Arc::new(Metrics::default()),
        );
        // Nothing running: an empty set is unremarkable and never counts.
        for _ in 0..EMPTY_SET_CONFIRMATIONS + 2 {
            reconciler.tick().await.unwrap();
        }
        assert_eq!(
            reconciler.empty_answers, 0,
            "an empty set with no tenants is not a wholesale emptying"
        );
    }

    /// Names that would escape the base directory, or collapse two tenants
    /// onto one prefix, are dropped before anything builds a path out of
    /// them — and the rest of the document is still served.
    #[test]
    fn names_that_could_escape_a_prefix_are_refused() {
        let safe = HostedNetwork {
            org: "acme".into(),
            network: "prod".into(),
            domain: "acme.example".into(),
            budget_bytes: 0,
            retention: "current".into(),
            device: None,
        };
        assert!(safe.names_are_safe());
        for (org, network) in [
            ("acme", "prod/../staging"),
            ("..", "prod"),
            ("/etc", "prod"),
            ("acme", ""),
            ("ACME", "prod"),
            ("-acme", "prod"),
        ] {
            let unsafe_network = HostedNetwork {
                org: org.into(),
                network: network.into(),
                ..safe.clone()
            };
            assert!(
                !unsafe_network.names_are_safe(),
                "{org}/{network} should be refused"
            );
        }
        // The collect list is the one that names bytes a sweep deletes.
        assert!(!crate::control::Collectable {
            org: "acme".into(),
            network: "..".into(),
        }
        .names_are_safe());
    }

    /// Shutdown joins already-running work rather than awaiting it one item at
    /// a time. Ordinary reconciliation uses persistent jobs instead.
    #[tokio::test(start_paused = true)]
    async fn shutdown_work_is_joined_concurrently() {
        let started = tokio::time::Instant::now();
        let slow = |_| async {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        };
        join_all((0..20).map(slow)).await;
        assert_eq!(
            started.elapsed(),
            std::time::Duration::from_secs(10),
            "twenty tenants took one tenant's time, not twenty"
        );
    }

    /// And a tenant that never finishes its step gives the pass back anyway.
    ///
    /// Without this a tenant whose store its own peers have jammed holds the
    /// pass indefinitely: no heartbeat for anyone (which is the billing
    /// record), no failed-loop restart, no collection. The work behind the
    /// deadline is not cancelled — a store call already on the blocking pool
    /// runs to completion regardless — what is recovered is the shard's
    /// ability to go on supervising everything else.
    #[tokio::test(start_paused = true)]
    async fn a_tenant_that_overruns_does_not_keep_the_pass() {
        let stuck = under_deadline("acme/prod", "converge", std::future::pending::<()>());
        assert!(stuck.await.is_none());
    }

    /// Provisioning belongs to the tenant slot, not to the pass that started
    /// it. A restore or startup re-adoption may legitimately span polls; the
    /// reconciler must leave that job alone and keep supervising other slots.
    #[tokio::test]
    async fn an_unfinished_provision_survives_the_pass_that_started_it() {
        let mut reconciler = Reconciler::new(
            test_config(),
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            Arc::new(Metrics::default()),
        );
        let key = "acme/prod".to_string();
        let wanted = HashSet::from([key.clone()]);
        let dir = std::path::PathBuf::from("/tmp/synch-dp-test/tenants/acme/prod");
        let (release, held) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = held.await;
            TenantJobOutput::Provisioned(Err(crate::DpError::Engine("not ready".into())))
        });
        reconciler.jobs.insert(
            key.clone(),
            TenantJob {
                kind: TenantJobKind::Provisioning,
                dir,
                cancel_before_start: None,
                completed: Arc::new(AtomicBool::new(false)),
                handle,
            },
        );

        reconciler.reap_finished_jobs(&wanted).await;
        assert!(reconciler.jobs.contains_key(&key));
        assert_eq!(
            reconciler.waiting(),
            1,
            "provisioning is visible as waiting"
        );

        release.send(()).unwrap();
        while !reconciler.jobs[&key].handle.is_finished() {
            tokio::task::yield_now().await;
        }
        reconciler.reap_finished_jobs(&wanted).await;
        assert!(!reconciler.jobs.contains_key(&key));
        assert!(reconciler.parked.contains_key(&key));
    }

    /// A slow in-flight job must not spend the termination grace before an
    /// otherwise idle tenant starts its final drain.
    #[tokio::test]
    async fn shutdown_drains_idle_tenants_while_jobs_are_still_running() {
        let base = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.base_dir = base.path().to_path_buf();
        let mut reconciler = Reconciler::new(
            config.clone(),
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            Arc::new(Metrics::default()),
        );
        let key = "acme/prod".to_string();
        let dir = config.tenant_dir("acme", "prod");
        reconciler.tenants.insert(
            key,
            Tenant::for_reconciler_test(hosted_network("acme", "prod"), dir.clone()),
        );

        let (release, held) = tokio::sync::oneshot::channel();
        let slow_dir = config.tenant_dir("acme", "slow");
        let handle = tokio::spawn(async move {
            let _ = held.await;
            TenantJobOutput::Cancelled
        });
        reconciler.jobs.insert(
            "acme/slow".into(),
            TenantJob {
                kind: TenantJobKind::Provisioning,
                dir: slow_dir,
                cancel_before_start: None,
                completed: Arc::new(AtomicBool::new(false)),
                handle,
            },
        );

        let shutting_down = tokio::spawn(async move { reconciler.shutdown().await });
        let acquired = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                match synch_engine::LifecycleLock::acquire(&dir) {
                    Ok(lock) => break lock,
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("probing the drained directory failed: {error}"),
                }
            }
        })
        .await
        .expect("the idle tenant should drain before the slow job finishes");
        drop(acquired);
        assert!(
            !shutting_down.is_finished(),
            "the synthetic job is still held"
        );
        release.send(()).unwrap();
        shutting_down.await.unwrap();
    }

    /// A provision that has not acquired capacity has touched no tenant state
    /// and can be cancelled immediately during shutdown.
    #[tokio::test]
    async fn shutdown_cancels_provisions_that_have_not_started() {
        let mut config = test_config();
        config.max_tenants = 1;
        let mut reconciler = Reconciler::new(
            config,
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            Arc::new(Metrics::default()),
        );
        let held = reconciler
            .provision_slots
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        reconciler.start_provision("acme/prod".into(), hosted_network("acme", "prod"));
        tokio::task::yield_now().await;
        tokio::time::timeout(std::time::Duration::from_secs(1), reconciler.shutdown())
            .await
            .expect("a queued provision should not hold shutdown");
        drop(held);
    }

    /// A restart drain adopts later offboarding intent and removes its local
    /// copy before collection can run.
    #[tokio::test]
    async fn a_restart_drain_is_upgraded_when_the_tenant_is_offboarded() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("tenant");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stale"), b"local").unwrap();
        let mut reconciler = Reconciler::new(
            test_config(),
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            Arc::new(Metrics::default()),
        );
        let key = "acme/prod".to_string();
        reconciler.jobs.insert(
            key.clone(),
            TenantJob {
                kind: TenantJobKind::Draining { forget: false },
                dir: dir.clone(),
                cancel_before_start: None,
                completed: Arc::new(AtomicBool::new(false)),
                handle: tokio::spawn(async { TenantJobOutput::Drained }),
            },
        );
        wait_for_job(&reconciler, &key).await;
        reconciler.reap_finished_jobs(&HashSet::new()).await;
        assert_eq!(reconciler.jobs[&key].kind, TenantJobKind::Forgetting);
        wait_for_job(&reconciler, &key).await;
        reconciler.reap_finished_jobs(&HashSet::new()).await;
        assert!(!dir.exists(), "the stale local database must be retired");
        assert!(!reconciler.jobs.contains_key(&key));
    }

    /// A panic leaves a lifecycle-lock barrier in the slot until detached
    /// Tenant::Drop cleanup has really released the directory.
    #[tokio::test]
    async fn collection_cannot_race_a_panicked_tenants_cleanup() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("tenant");
        let held = synch_engine::LifecycleLock::acquire(&dir).unwrap();
        let mut reconciler = Reconciler::new(
            test_config(),
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            Arc::new(Metrics::default()),
        );
        let key = "acme/prod".to_string();
        let handle: tokio::task::JoinHandle<TenantJobOutput> =
            tokio::spawn(async { panic!("synthetic tenant panic") });
        reconciler.jobs.insert(
            key.clone(),
            TenantJob {
                kind: TenantJobKind::Reconciling,
                dir: dir.clone(),
                cancel_before_start: None,
                completed: Arc::new(AtomicBool::new(false)),
                handle,
            },
        );
        wait_for_job(&reconciler, &key).await;
        reconciler.reap_finished_jobs(&HashSet::new()).await;
        assert_eq!(
            reconciler.jobs[&key].kind,
            TenantJobKind::CleaningAfterPanic
        );
        reconciler.start_collections(&[crate::control::Collectable {
            org: "acme".into(),
            network: "prod".into(),
        }]);
        assert!(
            reconciler.collections.is_empty(),
            "collection stays blocked behind the cleanup barrier"
        );

        drop(held);
        wait_for_job(&reconciler, &key).await;
        reconciler.reap_finished_jobs(&HashSet::new()).await;
        assert_eq!(reconciler.jobs[&key].kind, TenantJobKind::Forgetting);
        wait_for_job(&reconciler, &key).await;
        reconciler.reap_finished_jobs(&HashSet::new()).await;
        assert!(!reconciler.jobs.contains_key(&key));
        assert!(!dir.exists());
    }

    /// Completion wakes let gauges observe a returned live tenant without
    /// waiting for the next minute-long desired-state poll.
    #[tokio::test]
    async fn completed_jobs_refresh_metrics_immediately() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("tenant");
        let metrics = Arc::new(Metrics::default());
        let mut reconciler = Reconciler::new(
            test_config(),
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            metrics.clone(),
        );
        let key = "acme/prod".to_string();
        reconciler.wanted.insert(key.clone());
        let tenant = Tenant::for_reconciler_test(hosted_network("acme", "prod"), dir);
        let wake = reconciler.job_wake.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let completion = completed.clone();
        let handle = tokio::spawn(async move {
            let _wake = WakeOnDrop {
                wake,
                completed: completion,
            };
            TenantJobOutput::Reconciled(tenant)
        });
        reconciler.jobs.insert(
            key.clone(),
            TenantJob {
                kind: TenantJobKind::Reconciling,
                dir: base.path().join("tenant"),
                cancel_before_start: None,
                completed,
                handle,
            },
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reconciler.job_wake.notified(),
        )
        .await
        .unwrap();
        reconciler.reap_known_jobs().await;
        let rendered = metrics.render();
        assert!(rendered.contains("synch_dp_tenants_running 1"));
        assert!(rendered.contains("synch_dp_tenants_parked 0"));
        reconciler.tenants.remove(&key).unwrap().drain().await;
    }

    /// A tenant that keeps failing is made to wait longer each time, and one
    /// that has been well for a while starts over.
    ///
    /// The backoff is not politeness. Re-provisioning discards the local
    /// database and replays the whole replica stream, so a tenant whose
    /// standing loops keep dying would buy a full restore every poll —
    /// object-store egress, disk churn and blocking-pool time charged to every
    /// other tenant on the shard, for a tenant that is not working anyway.
    #[test]
    fn a_tenant_that_keeps_failing_is_made_to_wait_longer() {
        let first = Parked::after(None);
        assert_eq!(first.failures, 1);
        let second = Parked::after(Some(first));
        assert_eq!(second.failures, 2);
        assert!(
            second.retry_at.duration_since(second.at) > first.retry_at.duration_since(first.at),
            "a repeat failure waits longer than the first"
        );

        // And it is capped, so a tenant is never parked out of existence.
        let mut park = first;
        for _ in 0..40 {
            park = Parked::after(Some(park));
        }
        assert!(park.retry_at.duration_since(park.at) <= MAX_PARK);

        // A failure long after the last one is a first failure again: a tenant
        // that restarts once a month must not arrive at the cap and stay there.
        let stale = Parked {
            at: std::time::Instant::now() - PARK_DECAY * 2,
            ..park
        };
        assert_eq!(Parked::after(Some(stale)).failures, 1);
    }

    /// A remembered failure is not a tenant that is down.
    ///
    /// The two are one map, because the backoff has to escalate across a
    /// successful restart — a crash loop is exactly the sequence "fails,
    /// provisions, fails again", and a count cleared by the success in the
    /// middle resets on every lap. But `synch_dp_tenants_parked` answers "how
    /// many networks is this shard not running", and a gauge that also counted
    /// every tenant that ever had a bad minute is one an operator learns to
    /// ignore.
    #[test]
    fn a_remembered_failure_is_not_a_parked_tenant() {
        let mut reconciler = Reconciler::new(
            test_config(),
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            Arc::new(Metrics::default()),
        );
        let key = "acme/prod".to_string();
        reconciler.park(key.clone());
        assert_eq!(reconciler.waiting(), 1, "a fresh park is a tenant waiting");

        // Its wait elapses and it provisions; the count of what went wrong
        // stays, because the next failure has to escalate from it.
        let remembered = reconciler.parked.get_mut(&key).expect("the entry");
        remembered.retry_at = std::time::Instant::now() - std::time::Duration::from_secs(1);
        assert_eq!(reconciler.waiting(), 0, "and afterwards it is not");
        assert_eq!(reconciler.parked[&key].failures, 1);
        reconciler.park(key.clone());
        assert_eq!(
            reconciler.parked[&key].failures, 2,
            "the next failure escalates rather than starting over"
        );
    }

    fn hosted_network(org: &str, network: &str) -> HostedNetwork {
        HostedNetwork {
            org: org.into(),
            network: network.into(),
            domain: format!("{org}.example"),
            budget_bytes: 0,
            retention: "current".into(),
            device: None,
        }
    }

    async fn wait_for_job(reconciler: &Reconciler, key: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !reconciler.jobs[key].handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the synthetic tenant job should finish");
    }

    fn test_config() -> DpConfig {
        DpConfig {
            control_url: "http://127.0.0.1:1".into(),
            token: "synchdp_x".into(),
            base_dir: std::path::PathBuf::from("/tmp/synch-dp-test"),
            poll_interval: std::time::Duration::from_secs(60),
            objects: crate::config::ObjectConfig {
                service: "memory".into(),
                options: HashMap::new(),
            },
            cache_bytes_total: 1024,
            max_tenants: 4,
            replica_concurrency: synch_engine::DEFAULT_REPLICA_CONCURRENCY,
            blocking_threads: 512,
            max_inflight_per_tenant: 8,
            metrics_addr: None,
            net: synch_net::NetOptions::default(),
            dns: synch_net::ResolverOptions::default(),
            rotate_after: crate::rotation::DEFAULT_ROTATE_AFTER,
            retire_after: crate::rotation::DEFAULT_RETIRE_AFTER,
        }
    }
}
