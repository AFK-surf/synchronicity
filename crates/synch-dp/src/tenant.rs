//! One hosted network's whole life (`docs/CLOUD-DATAPLANE.md` §4.3, §4.4).
//!
//! A tenant is one full [`Node`]: its own data directory,
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
use crate::rotation;
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
        if restored.is_none() && !initialized(&dir).await? {
            // Nothing restorable and nothing on disk: a network never hosted,
            // or one whose stream is gone. Either way this node needs an
            // identity of its own, and the registration below is what gets it
            // named.
            //
            // The disk check is not redundant with the restore. A pod that
            // died between `init` and the registration below leaves an
            // initialized directory that no stream describes — `init` refuses
            // an initialized directory, so without this the tenant would be
            // wedged at exactly the moment it is one call from working.
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
            // z-base-32, which is the encoding the zone publishes and the
            // control plane validates. `Display` on a key is hex, so this
            // must be spelled out: a hex `nk` is refused by the schema, and
            // the tenant would never be named.
            key.ok_or_else(|| {
                DpError::Engine("the tenant database holds no active device key".into())
            })?
            .node_id
            .to_z32()
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
        if let Some(resolver) = resolver.clone() {
            node.set_dns_resolver(Ok(resolver));
        }

        // Everything from here can fail, and the node is already open and
        // serving — so failures go through `started`, which shuts it down
        // before propagating. Without that, a failed open leaks an endpoint
        // and its tasks, and the retry 30 seconds later rewrites the database
        // file underneath them.
        match self.start(node.clone(), config, objects, resolver).await {
            Ok(()) => {
                self.state = State::Running;
                tracing::info!(tenant = %self.network.key(), "tenant is replicating");
                Ok(())
            }
            Err(error) => {
                if let Err(stop) = node.shutdown().await {
                    tracing::warn!(
                        tenant = %self.network.key(), %stop,
                        "could not shut down a node that failed to start"
                    );
                }
                Err(error)
            }
        }
    }

    /// Brings up the replicator and the standing loops on an open node.
    async fn start(
        &mut self,
        node: Node,
        config: &DpConfig,
        objects: &ObjectStore,
        resolver: Option<Arc<synch_net::DnssecResolver>>,
    ) -> Result<()> {
        // Before any publisher runs. A restored database can be behind what
        // peers already hold (§5.3), and publishing over that seq forks this
        // origin's own head — the one thing a node must never do. The daemon
        // opens with the same call for the same reason.
        node.readopt_self_on_startup().await?;

        let replicator_config =
            ReplicatorConfig::new(config.db_prefix(&self.network.org, &self.network.network));
        let interval = replicator_config.interval;
        let replicator =
            Replicator::start(objects.clone(), replicator_config, node.store().clone()).await?;
        let replicator = Arc::new(tokio::sync::Mutex::new(replicator));

        self.spawn_loops(&node, replicator.clone(), interval, resolver);
        self.replicator = Some(replicator);
        self.node = Some(node.clone());

        // Publishes this node's own trie once, now that re-adoption has
        // settled what its head should be.
        if let Err(error) = node.scan_publish_push().await {
            tracing::warn!(
                tenant = %self.network.key(), %error,
                "the tenant's first publish failed; the publisher loop will retry"
            );
        }
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
            net: config.net.clone(),
            // Identity settles inside `Node::open`, from a resolver it builds
            // out of these options — so a tenant that cannot resolve its zone
            // here never learns its name, whatever is installed afterwards.
            dns: config.dns.clone(),
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
        resolver: Option<Arc<synch_net::DnssecResolver>>,
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

        // Membership is the tenant boundary, and it is a *lease*: the same
        // maintenance loop above expires bindings on schedule, and this is
        // the only thing that renews them. Without it a tenant stops trusting
        // every customer device a TTL and a grace after it opened — silently,
        // while still reporting itself healthy.
        if let Some(resolver) = resolver.clone() {
            let node = node.clone();
            let mut stop = self.shutdown.subscribe();
            let tenant = tenant.clone();
            self.loops.push(tokio::spawn(async move {
                node.run_dns(resolver.as_ref(), async move {
                    let _ = stop.recv().await;
                })
                .await;
                tracing::debug!(%tenant, loop_name = "dns", "tenant loop stopped");
            }));
        } else {
            tracing::error!(
                %tenant,
                "no resolver: this tenant's membership will lapse and it will replicate nothing"
            );
        }

        // The control-plane tunnel, which is what puts this node in the org's
        // replication panel (§2, §10). Read-only by wire construction, and
        // refused outright by the control plane unless the org has browse
        // enabled — so running it costs nothing where it is not wanted.
        {
            let node = node.clone();
            let resolver = resolver.clone();
            let mut stop = self.shutdown.subscribe();
            let tenant = tenant.clone();
            self.loops.push(tokio::spawn(async move {
                node.run_cloud(resolver, async move {
                    let _ = stop.recv().await;
                })
                .await;
                tracing::debug!(%tenant, loop_name = "cloud", "tenant loop stopped");
            }));
        }

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
    /// and with the org's policy, and moves any owed key rotation along.
    pub async fn converge(
        &mut self,
        network: &HostedNetwork,
        config: &DpConfig,
        control: &ControlPlane,
    ) -> Result<()> {
        self.network = network.clone();
        let Some(node) = self.node.clone() else {
            return Ok(());
        };
        spaces::ensure_replicas(&node, network).await?;
        // A rotation failure is not a replication failure: the tenant keeps
        // holding and serving everything it held a moment ago, and the next
        // tick tries again. Reported rather than propagated, so one control
        // plane hiccup does not look like a tenant that stopped working.
        match rotation::tick(&node, control, network, config, synch_core::now_ns()).await {
            Ok(rotation::Outcome::Idle) => {}
            Ok(outcome) => tracing::info!(tenant = %network.key(), ?outcome, "rotation moved"),
            Err(error) => {
                tracing::warn!(tenant = %network.key(), %error, "rotation check failed")
            }
        }
        Ok(())
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

    /// The open node, once the tenant is running.
    pub fn node(&self) -> Option<&Node> {
        self.node.as_ref()
    }

    /// The tenant's data directory, removed after a drain.
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }
}

/// Whether `dir` already holds an initialized node.
///
/// The same question `Node::init` asks before refusing: an origin settled, or
/// a membership domain configured. Opening the store to ask is cheap and
/// closes it again before the node opens the directory for real.
async fn initialized(dir: &std::path::Path) -> Result<bool> {
    if !dir.join(synch_store::DB_FILE).exists() {
        return Ok(false);
    }
    let dir = dir.to_path_buf();
    let settled = synch_core::offload(move || {
        let store = synch_store::Store::open(&dir)?;
        Ok::<_, synch_store::StoreError>(
            store.self_origin()?.is_some() || store.membership_domain()?.is_some(),
        )
    })
    .await?;
    Ok(settled)
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
