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
    etag: Option<String>,
    metrics: Arc<Metrics>,
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
        Self {
            config,
            control,
            objects,
            resolver,
            tenants: HashMap::new(),
            parked: HashMap::new(),
            etag: None,
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
        // termination grace is one budget shared by all of them (§4.6).
        let drains: Vec<_> = self
            .tenants
            .drain()
            .map(|(_, tenant)| tenant.drain())
            .collect();
        futures_join_all(drains).await;
    }

    /// One pass: poll, diff, converge, report.
    pub async fn tick(&mut self) -> Result<()> {
        let desired = self.desired().await?;
        self.metrics.observed_generation(desired.generation);

        let mine: Vec<HostedNetwork> = desired
            .networks
            .into_iter()
            .filter(|network| self.config.serves(&network.key()))
            .collect();
        let wanted: HashMap<String, HostedNetwork> = mine
            .into_iter()
            .map(|network| (network.key(), network))
            .collect();

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
        }

        for (key, network) in wanted {
            match self.tenants.get_mut(&key) {
                Some(tenant) => {
                    if let Err(error) = tenant.converge(&network).await {
                        tracing::warn!(tenant = %key, %error, "converging the tenant failed");
                    }
                }
                None => self.provision(key, network).await,
            }
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
            &self.objects,
            &self.control,
            self.resolver.clone(),
            network,
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
    async fn desired(&mut self) -> Result<Desired> {
        match self.control.poll(self.etag.as_deref()).await {
            Ok(Poll::Unchanged) => self.cached().await,
            Ok(Poll::Changed { desired, etag }) => {
                self.etag = etag;
                let key = self.config.desired_key();
                match serde_json::to_vec(&desired) {
                    Ok(bytes) => {
                        if let Err(error) = self.objects.put(&key, bytes).await {
                            tracing::warn!(%error, "could not cache the desired state");
                        }
                    }
                    Err(error) => tracing::warn!(%error, "could not encode the desired state"),
                }
                Ok(desired)
            }
            Err(error) => {
                tracing::warn!(%error, "control plane unreachable; holding the current set");
                self.metrics.poll_failed();
                self.cached().await
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
            }),
        }
    }
}

/// Awaits every future, without pulling in a futures dependency for it.
async fn futures_join_all<F: std::future::Future<Output = ()>>(futures: Vec<F>) {
    for future in futures {
        future.await;
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
            db_key: None,
            cache_bytes_total: 1024,
            max_tenants: 4,
            metrics_addr: None,
        }
    }
}
