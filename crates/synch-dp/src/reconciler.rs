//! The desired-state loop (`docs/CLOUD-DATAPLANE.md` §4.2).
//!
//! Poll, diff, act, report — shaped like the engine's own standing loops:
//! every step is idempotent, and missing a tick costs latency rather than
//! correctness.

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::DpConfig;
use crate::control::{ControlPlane, Desired, HostedNetwork, Poll};
use crate::error::Result;
use crate::metrics::Metrics;
use crate::store::ObjectStore;
use crate::tenant::{State, Tenant};

/// The service, reconciling what it runs against what it is told to run.
#[derive(Debug)]
pub struct Reconciler {
    config: DpConfig,
    control: ControlPlane,
    objects: ObjectStore,
    resolver: Option<Arc<synch_net::DnssecResolver>>,
    tenants: HashMap<String, Tenant>,
    /// Networks that failed to provision, and when to try again.
    parked: HashMap<String, std::time::Instant>,
    /// Consecutive fresh polls that have answered "nothing on this shard".
    empty_answers: u32,
    etag: Option<String>,
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
        Self {
            config,
            control,
            objects,
            resolver,
            tenants: HashMap::new(),
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
                _ = shutdown.recv() => break,
            }
        }
        // Every tenant gets its drain, and they run concurrently: the pod's
        // termination grace is one budget shared by all of them, and a shard
        // holding hundreds of tenants cannot spend it one at a time — the
        // ones at the back of a sequential queue would be SIGKILLed before
        // shipping their tails, which is the loss the replicator exists to
        // prevent (§4.6).
        let drains: Vec<_> = self
            .tenants
            .drain()
            .map(|(_, tenant)| tokio::spawn(tenant.drain()))
            .collect();
        for handle in drains {
            if let Err(error) = handle.await {
                tracing::warn!(%error, "a tenant drain did not finish");
            }
        }
    }

    /// One pass: poll, diff, converge, report.
    pub async fn tick(&mut self) -> Result<()> {
        let (desired, fresh) = self.desired().await?;
        self.metrics.observed_generation(desired.generation);

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
            .filter(|network| self.config.serves(&network.key()))
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
            .filter(|network| self.config.serves(&network.key()))
            .collect();
        let wanted: HashMap<String, HostedNetwork> = mine
            .into_iter()
            .map(|network| (network.key(), network))
            .collect();

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
        if wanted.is_empty() && !self.tenants.is_empty() {
            if fresh {
                self.empty_answers = self.empty_answers.saturating_add(1);
            }
            if self.empty_answers < EMPTY_SET_CONFIRMATIONS {
                tracing::error!(
                    tenants = self.tenants.len(),
                    confirmations = self.empty_answers,
                    needed = EMPTY_SET_CONFIRMATIONS,
                    "an empty desired set while tenants are running; waiting for it to be confirmed"
                );
                self.metrics.reconcile_failed();
                return Ok(());
            }
            tracing::warn!(
                tenants = self.tenants.len(),
                "an empty desired set confirmed; draining every tenant on this shard"
            );
        } else {
            self.empty_answers = 0;
        }

        // Retire what is no longer wanted. Reaching here at all means a
        // *successful* poll said so — an unreachable control plane leaves the
        // set frozen rather than tearing anything down (§4.2).
        let gone: Vec<String> = self
            .tenants
            .keys()
            .filter(|key| !wanted.contains_key(*key))
            .cloned()
            .collect();
        for key in gone {
            if let Some(tenant) = self.tenants.remove(&key) {
                let dir = tenant.dir().to_path_buf();
                tracing::info!(tenant = %key, "network is no longer hosted; draining");
                tenant.drain().await;
                // The local copy only; the bucket prefix and the replica
                // stream keep their retention hold, which the control plane
                // owns and a scheduled job collects (§6).
                if let Err(error) = std::fs::remove_dir_all(&dir) {
                    tracing::warn!(tenant = %key, %error, "could not remove the tenant directory");
                }
            }
            self.parked.remove(&key);
            self.metrics.forget_tenant(&key);
        }

        // Parked entries for networks nobody wants any more. A network that
        // never provisioned successfully is by definition not in `tenants`,
        // so the loop above never reaches it: without this, one org disabling
        // hosting on a network this shard could never open leaves an entry
        // that outlives the process and keeps `synch_dp_tenants_parked` over-
        // reporting for ever.
        self.parked.retain(|key, _| wanted.contains_key(key));

        // A tenant whose standing loops have died is re-provisioned rather
        // than converged. It looks healthy from every angle that matters
        // externally — the node is open, the heartbeat still reports held
        // bytes — while it has silently stopped publishing, or stopped
        // renewing the membership lease that is the tenant boundary itself.
        // Draining and re-provisioning is the whole of the restart, and it is
        // per tenant: one panicking loop must not be another tenant's outage.
        let failed: Vec<String> = self
            .tenants
            .iter()
            .filter(|(_, tenant)| tenant.has_failed_loop())
            .map(|(key, _)| key.clone())
            .collect();
        for key in failed {
            if let Some(tenant) = self.tenants.remove(&key) {
                tracing::error!(tenant = %key, "a standing loop stopped; restarting the tenant");
                self.metrics.reconcile_failed();
                tenant.drain().await;
            }
        }

        for (key, network) in wanted {
            match self.tenants.get_mut(&key) {
                Some(tenant) => {
                    if let Err(error) = tenant.converge(&network, &self.config, &self.control).await
                    {
                        tracing::warn!(tenant = %key, %error, "converging the tenant failed");
                    }
                }
                None => self.provision(key, network).await,
            }
        }

        // Collection is the one irreversible act here, so it runs only on a
        // document the control plane answered *this pass*. The fail-static
        // cache exists to keep tenants alive through an outage; letting it
        // authorize a delete would invert exactly what it is for — a shard
        // partitioned from the control plane could delete a prefix the org
        // had since re-enabled, and never know.
        if fresh {
            self.collect(&collectable).await;
        } else if !collectable.is_empty() {
            tracing::info!(
                due = collectable.len(),
                "holding collections until the control plane answers again"
            );
        }
        self.report().await;
        self.metrics.tenants(self.tenants.len(), self.parked.len());
        Ok(())
    }

    /// Provisions one network, parking it on failure.
    async fn provision(&mut self, key: String, network: HostedNetwork) {
        if let Some(retry_at) = self.parked.get(&key) {
            if *retry_at > std::time::Instant::now() {
                return;
            }
        }
        match Tenant::provision(
            &self.config,
            &self.control,
            self.resolver.clone(),
            network,
            self.metrics.clone(),
        )
        .await
        {
            Ok(tenant) => {
                self.parked.remove(&key);
                self.tenants.insert(key, tenant);
            }
            Err(error) => {
                // The common case here is a zone that has not named the key
                // yet, which is a wait rather than a fault; the retry cadence
                // is the daemon's own (§4.3).
                tracing::info!(tenant = %key, %error, "tenant not ready; will retry");
                self.parked.insert(
                    key,
                    std::time::Instant::now() + crate::tenant::identity_poll(),
                );
            }
        }
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
    async fn collect(&mut self, collectable: &[crate::control::Collectable]) {
        for network in collectable {
            let key = network.key();
            if self.tenants.contains_key(&key) {
                tracing::error!(
                    tenant = %key,
                    "refusing to collect storage for a tenant this shard is running"
                );
                continue;
            }
            let cas = self.config.cas_root(&network.org, &network.network);
            let db = self.config.db_prefix(&network.org, &network.network);
            // `cas_root` is an OpenDAL root (a leading slash); as a key under
            // this operator's own root it is the same path without it.
            let cas_prefix = cas.trim_start_matches('/').to_string();
            let db_prefix = format!("{db}/");
            let deleted = async {
                self.objects.remove_prefix(&cas_prefix).await?;
                self.objects.remove_prefix(&db_prefix).await
            }
            .await;
            match deleted {
                Ok(()) => {
                    if let Err(error) = self
                        .control
                        .storage_collected(&network.org, &network.network)
                        .await
                    {
                        // The bytes are gone; the record of it is not. Next
                        // pass re-deletes nothing and re-reports.
                        tracing::warn!(
                            tenant = %key, %error,
                            "deleted the tenant's storage but could not record it"
                        );
                        continue;
                    }
                    self.metrics.collected();
                    tracing::info!(tenant = %key, "collected an offboarded tenant's storage");
                }
                Err(error) => {
                    tracing::warn!(tenant = %key, %error, "could not delete tenant storage")
                }
            }
        }
    }

    /// Sends each tenant's heartbeat.
    async fn report(&mut self) {
        for (key, tenant) in &self.tenants {
            if tenant.state != State::Running {
                continue;
            }
            match tenant.status(&self.config.shard_name).await {
                Ok(status) => {
                    self.metrics.tenant_status(key, &status);
                    if let Err(error) = self
                        .control
                        .report_status(&tenant.network.org, &tenant.network.network, &status)
                        .await
                    {
                        tracing::warn!(tenant = %key, %error, "status heartbeat failed");
                    }
                }
                Err(error) => {
                    tracing::warn!(tenant = %key, %error, "could not measure what the tenant holds")
                }
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
    async fn desired(&mut self) -> Result<(Desired, bool)> {
        match self.control.poll(self.etag.as_deref()).await {
            // The control plane answered, and said "what you already have".
            // That is a fresh answer about a document we are holding.
            Ok(Poll::Unchanged) => match self.last.clone() {
                Some(desired) => Ok((desired, true)),
                None => self.cached().await.map(|desired| (desired, false)),
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
                Ok((desired, true))
            }
            Err(error) => {
                tracing::warn!(%error, "control plane unreachable; holding the current set");
                self.metrics.poll_failed();
                match self.last.clone() {
                    Some(desired) => Ok((desired, false)),
                    None => self.cached().await.map(|desired| (desired, false)),
                }
            }
        }
    }

    /// The last document this shard successfully acted on.
    async fn cached(&self) -> Result<Desired> {
        let key = self.config.desired_key();
        match self.objects.get_if_present(&key).await? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                crate::error::DpError::Control(format!("unreadable cached desired state: {error}"))
            }),
            None => Ok(Desired {
                generation: 0,
                networks: Vec::new(),
                collect: Vec::new(),
            }),
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
        assert_eq!(cached, desired);
    }

    /// An empty bucket and no control plane is the one case fail-static cannot
    /// cover, and it must be an empty set rather than an error.
    #[tokio::test]
    async fn a_cold_start_with_no_cache_hosts_nothing() {
        let reconciler = Reconciler::new(
            test_config(),
            ControlPlane::new("http://127.0.0.1:1", "synchdp_x").unwrap(),
            ObjectStore::memory().unwrap(),
            None,
            Arc::new(Metrics::default()),
        );
        let cached = reconciler.cached().await.unwrap();
        assert!(cached.networks.is_empty());
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
        let (desired, fresh) = reconciler.desired().await.unwrap();
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

    fn test_config() -> DpConfig {
        DpConfig {
            control_url: "http://127.0.0.1:1".into(),
            token: "synchdp_x".into(),
            base_dir: std::path::PathBuf::from("/tmp/synch-dp-test"),
            shard: 0,
            shards: 1,
            shard_name: "dp-1".into(),
            poll_interval: std::time::Duration::from_secs(60),
            objects: crate::config::ObjectConfig {
                service: "memory".into(),
                options: HashMap::new(),
            },
            cache_bytes_total: 1024,
            max_tenants: 4,
            replica_concurrency: synch_engine::DEFAULT_REPLICA_CONCURRENCY,
            metrics_addr: None,
            net: synch_net::NetOptions::default(),
            dns: synch_net::ResolverOptions::default(),
            rotate_after: crate::rotation::DEFAULT_ROTATE_AFTER,
            retire_after: crate::rotation::DEFAULT_RETIRE_AFTER,
        }
    }
}
