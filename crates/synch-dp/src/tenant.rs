//! One hosted network's whole life (`docs/CLOUD-DATAPLANE.md` §4.3, §4.4).
//!
//! A tenant is one full [`Node`](synch_engine::Node): its own data directory,
//! database, device key, endpoint and CAS prefix. Everything here is per
//! tenant, and nothing here is shared with another one except the process it
//! runs in — which is the isolation story §9 states, honestly, as ownership
//! rather than sandboxing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use synch_engine::{LifecycleLock, Node, NodeConfig};
use tokio::sync::broadcast;

use crate::config::{slot_label, DpConfig, SLOT};
use crate::control::{ControlPlane, HostedNetwork, Status};
use crate::dbrepl::{self, Replicator, ReplicatorConfig};
use crate::error::{DpError, Result};
use crate::spaces;
use crate::store::ObjectStore;

/// Where a tenant is in its life.
///
/// Cached, never authoritative: a fresh pod re-derives every one of these from
/// the desired document, the control plane's `device` field and what the
/// bucket holds (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Restoring or initializing.
    Provisioning,
    /// Open, but the zone has not named the key yet.
    Identifying,
    /// Replicating.
    Running,
    /// Shutting down for good.
    Draining,
    /// Gone; the directory is removed.
    Retired,
}

impl State {
    /// The label metrics and status output use.
    pub fn as_str(self) -> &'static str {
        match self {
            State::Provisioning => "provisioning",
            State::Identifying => "identifying",
            State::Running => "running",
            State::Draining => "draining",
            State::Retired => "retired",
        }
    }
}

/// How often a parked tenant re-checks whether the zone names it yet.
///
/// The daemon's own cadence, and for the daemon's own reason: the answer
/// changes when a DoH cache expires, not when we ask harder.
const IDENTITY_POLL: Duration = Duration::from_secs(30);

/// A running tenant.
#[derive(Debug)]
pub struct Tenant {
    /// Which network this is.
    pub network: HostedNetwork,
    /// Where it is in its life.
    pub state: State,
    node: Option<Node>,
    /// Held for as long as the tenant owns its data directory.
    _lock: LifecycleLock,
    shutdown: broadcast::Sender<()>,
    loops: Vec<tokio::task::JoinHandle<()>>,
    replicator: Option<Arc<tokio::sync::Mutex<Replicator>>>,
    replication_task: Option<tokio::task::JoinHandle<()>>,
    dir: PathBuf,
}

impl Tenant {
    /// Provisions a tenant: restore or initialize, register, open, identify.
    ///
    /// On an ephemeral pod every provisioning is potentially a
    /// *re*-provisioning, so the restore comes first and an init happens only
    /// when the stream holds nothing (§4.3).
    pub async fn provision(
        config: &DpConfig,
        objects: &ObjectStore,
        control: &ControlPlane,
        resolver: Option<Arc<synch_net::DnssecResolver>>,
        network: HostedNetwork,
    ) -> Result<Self> {
        let dir = config.tenant_dir(&network.org, &network.network);
        // Before anything opens the directory: two tenants configured onto one
        // data directory must fail here rather than interleave writes into one
        // database (`synch_engine::lifecycle`).
        let lock = LifecycleLock::acquire(&dir)
            .map_err(|error| DpError::io("locking the tenant data directory", error))?;

        let db_prefix = config.db_prefix(&network.org, &network.network);
        let restored = dbrepl::restore(objects, &db_prefix, &dir).await?;
        if restored.is_none() {
            // Nothing restorable: a network never hosted, or one whose stream
            // is gone. Either way this node needs an identity of its own, and
            // the registration below is what gets it named.
            tracing::info!(
                tenant = %network.key(),
                "no replica stream to restore; initializing a fresh node"
            );
            let init_dir = dir.clone();
            let domain = network.domain.clone();
            synch_core::offload(move || Node::init(&init_dir, Some(&domain)))
                .await
                .map_err(DpError::from)?;
        }

        let nk = {
            let dir = dir.clone();
            let key = synch_core::offload(move || {
                // Opened and closed before the node opens the same directory:
                // the registration has to happen first, because the zone is
                // what names the key the node will then look for.
                let store = synch_store::Store::open(&dir)?;
                store.active_device_key()
            })
            .await?;
            key.ok_or_else(|| {
                DpError::Engine("the tenant database holds no active device key".into())
            })?
            .node_id
            .to_string()
        };

        // Idempotent: a restore re-registers the key it already had and gets a
        // no-op; a fresh init registers a new one, which on a network whose
        // old key is unrecoverable is the key-replacement path (§3.3).
        control
            .register_device(&network.org, &network.network, &slot_label(), &nk)
            .await?;

        let mut tenant = Self {
            network,
            state: State::Provisioning,
            node: None,
            _lock: lock,
            shutdown: broadcast::channel(1).0,
            loops: Vec::new(),
            replicator: None,
            replication_task: None,
            dir,
        };
        tenant.open(config, objects, resolver).await?;
        Ok(tenant)
    }

    /// Opens the node and starts its standing work.
    async fn open(
        &mut self,
        config: &DpConfig,
        objects: &ObjectStore,
        resolver: Option<Arc<synch_net::DnssecResolver>>,
    ) -> Result<()> {
        let node_config = self.node_config(config)?;
        self.state = State::Identifying;
        let node = match Node::open(node_config).await {
            Ok(node) => node,
            Err(error) if is_unidentified(&error) => {
                // The zone has not named this key yet. Not a failure — the
                // supervisor re-provisions on the next tick, and the control
                // plane's commit is the publish, so this window is
                // DoH-cache-sized (§4.3).
                tracing::info!(
                    tenant = %self.network.key(),
                    "waiting for the zone to name this key"
                );
                return Err(DpError::from(error));
            }
            Err(error) => return Err(DpError::from(error)),
        };
        if let Some(resolver) = resolver {
            node.set_dns_resolver(Ok(resolver));
        }

        let replicator_config =
            ReplicatorConfig::new(config.db_prefix(&self.network.org, &self.network.network));
        let interval = replicator_config.interval;
        let replicator =
            Replicator::start(objects.clone(), replicator_config, node.store().clone()).await?;
        let replicator = Arc::new(tokio::sync::Mutex::new(replicator));

        self.spawn_loops(&node, replicator.clone(), interval);
        self.replicator = Some(replicator);
        self.node = Some(node);
        self.state = State::Running;
        tracing::info!(tenant = %self.network.key(), "tenant is replicating");
        Ok(())
    }

    /// The node configuration for this tenant.
    fn node_config(&self, config: &DpConfig) -> Result<NodeConfig> {
        let cloud = config.objects.cloud_config(
            &config.cas_root(&self.network.org, &self.network.network),
            self.dir.join("cloud"),
            config.cache_bytes_per_tenant(),
        )?;
        Ok(NodeConfig {
            cloud: Some(cloud),
            // The replicator owns the log, so no frame is recycled before it
            // has been shipped (§5.3).
            checkpointing: synch_store::Checkpointing::Embedder,
            // Storage, not compute: no socket pool, no SSH host key, and no
            // socket ALPN for a peer to dial (§4.4).
            socket_workers: 0,
            // The slot label, never the pod's hostname — which would publish
            // one name for every tenant on the shard.
            name: slot_label(),
            // Never release a root no other member still holds: the service
            // must not be what turns "left the current tree" into "gone".
            replica_release_floor: 1,
            ..NodeConfig::new(&self.dir)
        })
    }

    /// Starts the loop set (§4.4) and the replication ticker.
    ///
    /// The set is the subset a source-less, checkout-less, socket-less member
    /// needs. `run_scanner`/`run_watcher` have no filesystem source to watch,
    /// `run_checkouts` has nothing to materialize, and the uploads sweeper has
    /// no write surface to sweep after — v1 exposes none.
    fn spawn_loops(
        &mut self,
        node: &Node,
        replicator: Arc<tokio::sync::Mutex<Replicator>>,
        interval: Duration,
    ) {
        let tenant = self.network.key();
        self.spawn_loop("anti-entropy", node, |node, stop| async move {
            node.run_anti_entropy(stop).await
        });
        self.spawn_loop("maintenance", node, |node, stop| async move {
            node.run_maintenance(stop).await
        });
        self.spawn_loop("replicas", node, |node, stop| async move {
            node.run_replicas(stop).await
        });
        self.spawn_loop("publisher", node, |node, stop| async move {
            node.run_publisher(stop).await
        });

        // The replication ticker: ship WAL frames, forever.
        let mut stop = self.shutdown.subscribe();
        let tenant_name = tenant.clone();
        self.replication_task = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let mut replicator = replicator.lock().await;
                        if let Err(error) = replicator.tick().await {
                            // Retried on the next tick. A stream that stays
                            // stalled is what the operator alerts on (§10) —
                            // it is not something this loop can fix.
                            tracing::warn!(
                                tenant = %tenant_name, %error,
                                "shipping database frames failed"
                            );
                        }
                    }
                    _ = stop.recv() => return,
                }
            }
        }));
    }

    /// Spawns one standing loop.
    ///
    /// The engine's loops return nothing and stop only when their shutdown
    /// future fires, so the failure this guards against is a *panic*: it
    /// leaves the tenant quietly not doing part of its job — a dead publisher
    /// never advertises again. The join handle carries that, and the
    /// supervisor restarts *that tenant*, never the process: one tenant's
    /// panic must not be another tenant's outage (§4.4).
    fn spawn_loop<F, Fut>(&mut self, name: &'static str, node: &Node, run: F)
    where
        F: FnOnce(Node, BoxShutdown) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let node = node.clone();
        let mut stop = self.shutdown.subscribe();
        let tenant = self.network.key();
        self.loops.push(tokio::spawn(async move {
            let shutdown: BoxShutdown = Box::pin(async move {
                let _ = stop.recv().await;
            });
            run(node, shutdown).await;
            tracing::debug!(%tenant, loop_name = name, "tenant loop stopped");
        }));
    }

    /// Brings the tenant's replicas in line with what the network publishes,
    /// and with the org's policy.
    pub async fn converge(&mut self, network: &HostedNetwork) -> Result<()> {
        self.network = network.clone();
        let Some(node) = self.node.clone() else {
            return Ok(());
        };
        spaces::ensure_replicas(&node, network).await
    }

    /// What this tenant holds, for the metering heartbeat (§3.3).
    pub async fn status(&self, shard: &str) -> Result<Status> {
        let Some(node) = self.node.clone() else {
            return Ok(Status {
                shard: shard.to_string(),
                slot: SLOT,
                ..Status::default()
            });
        };
        let coverage = spaces::coverage(&node).await?;
        Ok(Status {
            held_roots: coverage.held_roots,
            held_bytes: coverage.held_bytes,
            wanted: coverage.wanted,
            last_sync_ns: coverage.last_sync_ns,
            shard: shard.to_string(),
            slot: SLOT,
        })
    }

    /// Stops the tenant: loops down, node closed, log tail shipped.
    ///
    /// The order matters and is the reverse of startup. The tail ship is last
    /// because everything before it can still write, and a frame written after
    /// the final ship would be a frame the stream never carried (§4.6).
    pub async fn drain(mut self) {
        self.state = State::Draining;
        let tenant = self.network.key();
        let _ = self.shutdown.send(());
        for handle in self.loops.drain(..) {
            if let Err(error) = handle.await {
                tracing::warn!(%tenant, %error, "a tenant loop did not stop cleanly");
            }
        }
        if let Some(task) = self.replication_task.take() {
            let _ = task.await;
        }
        if let Some(node) = self.node.take() {
            if let Err(error) = node.shutdown().await {
                tracing::warn!(%tenant, %error, "tenant node shutdown reported an error");
            }
        }
        if let Some(replicator) = self.replicator.take() {
            let mut replicator = replicator.lock().await;
            if let Err(error) = replicator.flush().await {
                // Worth shouting about: this is the window in which
                // acknowledged writes are lost, and it is supposed to be empty.
                tracing::error!(%tenant, %error, "failed to ship the final database frames");
            }
        }
        self.state = State::Retired;
        tracing::info!(%tenant, "tenant drained");
    }

    /// The tenant's data directory, removed after a drain.
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }
}

/// The shutdown future the engine's standing loops take.
type BoxShutdown = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Whether an open failed only because the zone has not named this key.
fn is_unidentified(error: &synch_engine::EngineError) -> bool {
    matches!(error, synch_engine::EngineError::Unidentified { .. })
}

/// How long a parked tenant waits before re-opening.
pub fn identity_poll() -> Duration {
    IDENTITY_POLL
}
