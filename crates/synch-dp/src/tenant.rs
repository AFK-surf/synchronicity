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
use crate::dbrepl::{self, Replicator};
use crate::error::{DpError, Result};
use crate::rotation;
use crate::spaces;

/// Where a tenant is in its life.
///
/// Cached, never authoritative: a fresh pod re-derives every one of these
/// from the desired document and what the bucket holds (§4.2). The control
/// plane's `device` field is read too, on every converge — not to decide
/// state, but to notice a slot whose registration has been displaced.
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

/// How many times a draining tenant tries its final ship.
///
/// The pod's termination grace is 30 s and shared with every other tenant, so
/// this is bounded deliberately: enough to ride out a provider blip, not
/// enough to be the reason a drain gets SIGKILLed.
const FINAL_SHIP_ATTEMPTS: u32 = 3;

/// Backoff between those attempts, multiplied by the attempt number.
const FINAL_SHIP_BACKOFF: Duration = Duration::from_millis(250);

/// A running tenant.
#[derive(Debug)]
pub struct Tenant {
    /// Which network this is.
    pub network: HostedNetwork,
    /// Where it is in its life.
    pub state: State,
    node: Option<Node>,
    /// Held for as long as the tenant owns its data directory.
    ///
    /// An `Option` so [`Drop`] can move it into the task that closes a node
    /// nobody drained: the claim on the directory has to outlive the endpoint
    /// still writing to it.
    lock: Option<LifecycleLock>,
    shutdown: broadcast::Sender<()>,
    loops: Vec<tokio::task::JoinHandle<()>>,
    /// Tells the replication ticker to make its final ship and close.
    ///
    /// Separate from `shutdown` because the tail ship has to happen *after*
    /// the node is closed, not alongside the loops (see [`Tenant::drain`]).
    /// Dropping it says the same thing, so a tenant that is dropped rather
    /// than drained still ends its ticker.
    replication_finish: Option<tokio::sync::oneshot::Sender<()>>,
    replication_task: Option<tokio::task::JoinHandle<()>>,
    dir: PathBuf,
}

impl Tenant {
    #[cfg(test)]
    pub(crate) fn for_reconciler_test(network: HostedNetwork, dir: PathBuf) -> Self {
        let lock = LifecycleLock::acquire(&dir).expect("the test tenant owns its directory");
        Self {
            network,
            state: State::Running,
            node: None,
            lock: Some(lock),
            shutdown: broadcast::channel(1).0,
            loops: Vec::new(),
            replication_finish: None,
            replication_task: None,
            dir,
        }
    }

    /// Provisions a tenant: restore or initialize, register, open, identify.
    ///
    /// On an ephemeral pod every provisioning is potentially a
    /// *re*-provisioning, so the restore comes first and an init happens only
    /// when the stream holds nothing (§4.3).
    pub async fn provision(
        config: &DpConfig,
        control: &ControlPlane,
        resolver: Option<Arc<synch_net::DnssecResolver>>,
        network: HostedNetwork,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> Result<Self> {
        let dir = config.tenant_dir(&network.org, &network.network);
        // Before anything opens the directory: two tenants configured onto one
        // data directory must fail here rather than interleave writes into one
        // database (`synch_engine::lifecycle`).
        let lock = LifecycleLock::acquire(&dir)
            .map_err(|error| DpError::io("locking the tenant data directory", error))?;

        // **The stream is authoritative.** A database already on disk is not
        // evidence of anything: these pods have no durable storage, so the
        // only way one is here is debris — a drain whose directory removal
        // failed, or a reschedule onto a volume that outlived its last owner.
        // Keeping it would be actively dangerous, because nothing downstream
        // catches it: `celld-ltx`'s behind-replica check does not *refuse* a
        // database behind its stream, it seeds the remote's newest segment as
        // a local baseline so the next capture snapshots forward — which is
        // exactly right after a restore, and which silently promotes a stale
        // copy over a newer stream here. So the local copy goes and the
        // stream is replayed.
        //
        // What that costs is bounded and already accepted: writes this pod
        // made but had not shipped, which §5.3 caps at one replication
        // interval on any ungraceful stop.
        //
        // The one case where the local copy *is* the identity is a stream
        // that holds nothing — a pod that died between `Node::init` and the
        // registration below — so that case keeps what is on disk. `restore`
        // would refuse the existing path anyway; the point of asking first is
        // that "the stream is empty" and "the stream's head is missing" are
        // different answers, and only the first may initialize.
        let db_client = || config.db_client(&network.org, &network.network);
        let restored = if dir.join(synch_store::DB_FILE).exists() {
            if dbrepl::stream_is_empty(db_client()?).await? {
                tracing::info!(
                    tenant = %network.key(),
                    "a database is on disk and the replica stream is empty; \
                     keeping the local copy"
                );
                false
            } else {
                tracing::warn!(
                    tenant = %network.key(),
                    "discarding a leftover data directory: the replica stream \
                     is authoritative and this copy cannot be shown to be current"
                );
                clear_data_dir(&dir)?;
                dbrepl::restore(db_client()?, &dir).await?
            }
        } else {
            dbrepl::restore(db_client()?, &dir).await?
        };
        if !restored && !initialized(&dir).await? {
            // Nothing restorable and nothing settled on disk: a network never
            // hosted, or one whose stream is gone. Either way this node needs
            // an identity of its own, and the registration below is what gets
            // it named.
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
            lock: Some(lock),
            shutdown: broadcast::channel(1).0,
            loops: Vec::new(),
            replication_finish: None,
            replication_task: None,
            dir,
        };
        tenant.open(config, resolver, metrics).await?;
        Ok(tenant)
    }

    /// Opens the node and starts its standing work.
    async fn open(
        &mut self,
        config: &DpConfig,
        resolver: Option<Arc<synch_net::DnssecResolver>>,
        metrics: Arc<crate::metrics::Metrics>,
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

        // From this point the Tenant owns the live endpoint. Provisioning now
        // normally runs to completion in a persistent reconciler job, but this
        // ordering also makes a task panic or future cancellation safe while
        // the runtime is live: Drop can close the node instead of letting iroh
        // abort an unowned endpoint.
        self.node = Some(node.clone());

        // Everything from here can fail, and the node is already open and
        // serving — so the error branch shuts it down before propagating.
        // Without that, a failed start leaks an endpoint and its tasks, and
        // the retry 30 seconds later rewrites the database underneath them.
        match self.start(node.clone(), config, resolver, metrics).await {
            Ok(()) => {
                self.state = State::Running;
                tracing::info!(tenant = %self.network.key(), "tenant is replicating");
                Ok(())
            }
            Err(error) => {
                if let Some(node) = self.node.take() {
                    if let Err(stop) = node.shutdown().await {
                        tracing::warn!(
                            tenant = %self.network.key(), %stop,
                            "could not shut down a node that failed to start"
                        );
                    }
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
        resolver: Option<Arc<synch_net::DnssecResolver>>,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> Result<()> {
        // Before any publisher runs. A restored database can be behind what
        // peers already hold (§5.3), and publishing over that seq forks this
        // origin's own head — the one thing a node must never do. The daemon
        // opens with the same call for the same reason.
        node.readopt_self_on_startup().await?;

        let replicator = Replicator::start(
            &node.store().db_path(),
            config.db_client(&self.network.org, &self.network.network)?,
            self.network.key(),
        )
        .await?;

        self.spawn_loops(&node, config, resolver);
        self.spawn_replication(replicator, dbrepl::DEFAULT_INTERVAL, metrics);

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
            // The tenancy bound (§9). Everything else about this node is
            // per-tenant already — its directory, database, key, endpoint and
            // prefix — but its *inbound work* was not: every request handler
            // offloads onto the one blocking pool this process shares between
            // every tenant, and nothing capped how many requests one
            // network's devices could have in flight. A member of one org
            // could hold the pool and make every other org's tenant wait.
            // See `DpConfig::max_inflight_per_tenant`.
            net: synch_net::NetOptions {
                max_inflight_requests: Some(config.max_inflight_per_tenant),
                ..config.net.clone()
            },
            // Identity settles inside `Node::open`, from a resolver it builds
            // out of these options — so a tenant that cannot resolve its zone
            // here never learns its name, whatever is installed afterwards.
            dns: config.dns.clone(),
            // Storage, not compute: no socket pool, no SSH host key, and no
            // socket ALPN for a peer to dial (§4.4).
            socket_workers: 0,
            // The slot label, never the pod's hostname — which would publish
            // one name for every tenant on this data plane.
            name: slot_label(),
            // Never release a root no other member still holds: the service
            // must not be what turns "left the current tree" into "gone".
            replica_release_floor: 1,
            replica_concurrency: config.replica_concurrency,
            ..NodeConfig::new(&self.dir)
        })
    }

    /// Starts the loop set (§4.4).
    ///
    /// The set is the subset a source-less, checkout-less, socket-less member
    /// needs. `run_scanner`/`run_watcher` have no filesystem source to watch,
    /// `run_checkouts` has nothing to materialize, and the uploads sweeper has
    /// no write surface to sweep after — v1 exposes none.
    fn spawn_loops(
        &mut self,
        node: &Node,
        config: &DpConfig,
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

        // The write tunnel (`docs/CLOUD-WRITES.md` §6.1): the control plane's
        // file writes, taken by this node as `cloud-1`'s own assertions. For
        // every hosted tenant, because a hosted network is a writable one —
        // there is no second switch to consult.
        {
            let node = node.clone();
            let resolver = resolver.clone();
            let mut stop = self.shutdown.subscribe();
            let tenant = tenant.clone();
            let domain = self.network.domain.clone();
            let token = config.token.clone();
            let limits = crate::writes::WriteLimits {
                staging: crate::writes::StagingBudget::new(config.write_staging_bytes),
                budget_bytes: self.network.budget_bytes,
            };
            self.loops.push(tokio::spawn(async move {
                crate::writes::run_cloud_writes(
                    node,
                    resolver,
                    domain,
                    token,
                    limits,
                    async move {
                        let _ = stop.recv().await;
                    },
                )
                .await;
                tracing::debug!(%tenant, loop_name = "writes", "tenant loop stopped");
            }));
        }
    }

    /// Starts the replication ticker: ship what the database commits, forever.
    ///
    /// The ticker *owns* the replicator, and nothing else ever holds a
    /// reference to it. That is not tidiness — the replication library's
    /// replica owns a SQLite connection and so is `Send` but not `Sync`, and
    /// anything that shared it behind a lock would make this task's future
    /// unspawnable. Sole ownership also means the final ship cannot race a
    /// tick: the same task does both, in order.
    fn spawn_replication(
        &mut self,
        mut replicator: Replicator,
        interval: Duration,
        metrics: Arc<crate::metrics::Metrics>,
    ) {
        let (finish, mut finished) = tokio::sync::oneshot::channel();
        self.replication_finish = Some(finish);
        let tenant = self.network.key();
        self.replication_task = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let shipped = replicator.tick().await;
                        // Every attempt, so `synch_dp_replication_failures`
                        // shows a stream that is stuck *now*. Retried on the
                        // next tick; a run that keeps climbing is the
                        // operator's alert (§10), not something this loop can
                        // fix.
                        metrics.replication_attempt(&tenant, shipped.is_ok());
                        if let Err(error) = shipped {
                            tracing::warn!(
                                %tenant, %error,
                                "shipping database frames failed"
                            );
                        }
                    }
                    // Either the drain asked, or the tenant was dropped
                    // without draining. Both mean the same thing here.
                    _ = &mut finished => break,
                }
            }
            // The tail ship, retried. This is the window in which
            // acknowledged writes are lost, and a single attempt threw the
            // tenant's last second of writes away on one transient 503 — the
            // library's own retry budget is ~30 s, and a rolling restart is
            // exactly when a provider is most likely to blip. The attempts
            // are bounded because a drain cannot block a pod's termination
            // grace for ever.
            let mut shipped = Err(DpError::Engine("not attempted".into()));
            for attempt in 1..=FINAL_SHIP_ATTEMPTS {
                shipped = replicator.flush().await;
                match &shipped {
                    Ok(()) => break,
                    Err(error) => tracing::warn!(
                        %tenant, %error, attempt,
                        "the final database ship failed; retrying"
                    ),
                }
                tokio::time::sleep(FINAL_SHIP_BACKOFF * attempt).await;
            }
            if let Err(error) = shipped {
                tracing::error!(
                    %tenant, %error, attempts = FINAL_SHIP_ATTEMPTS,
                    "failed to ship the final database writes; \
                     acknowledged writes have been lost"
                );
            }
            // Releases the long-running read lock the replication library
            // holds on the database.
            if let Err(error) = replicator.close().await {
                tracing::warn!(%tenant, %error, "closing the replicated database failed");
            }
        }));
    }

    /// Whether any standing loop has stopped while the tenant is running.
    ///
    /// The engine's loops return only when their shutdown future fires, so
    /// while the tenant is `Running` a finished handle means one panicked —
    /// and a tenant that has quietly stopped publishing, or stopped renewing
    /// its membership lease, looks identical to a healthy one from outside.
    /// The reconciler asks this every pass and re-provisions the tenant that
    /// answers yes, which is the "restarts *that* tenant, never the process"
    /// of §4.4 — previously asserted by a comment and implemented by nothing.
    ///
    /// The replication ticker counts too: it is the one loop whose silence
    /// costs durability rather than freshness.
    pub fn has_failed_loop(&self) -> bool {
        if self.state != State::Running {
            return false;
        }
        self.loops.iter().any(|handle| handle.is_finished())
            || self
                .replication_task
                .as_ref()
                .is_some_and(|handle| handle.is_finished())
    }

    /// Spawns one standing loop.
    ///
    /// The engine's loops return nothing and stop only when their shutdown
    /// future fires, so the failure this guards against is a *panic*: it
    /// leaves the tenant quietly not doing part of its job — a dead publisher
    /// never advertises again. The join handle carries that, and
    /// [`has_failed_loop`](Self::has_failed_loop) is what the supervisor asks
    /// so it can restart *that tenant*, never the process: one tenant's panic
    /// must not be another tenant's outage (§4.4).
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
        self.check_registration(&node, network).await;
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

    /// Compares the key the control plane says this slot holds against the
    /// one this node is actually signing with.
    ///
    /// The control plane computes this field carefully — only the `active`
    /// key is reported, and a fully revoked device reports none — and until
    /// now nothing read it, so the data plane could never notice that its
    /// registration had been displaced. That is not hypothetical: the
    /// `cloud-<n>` label was reachable from customer-facing device routes,
    /// and a member who added their own key to the slot would leave this node
    /// serving under a key the zone no longer names while it went on
    /// reporting itself healthy.
    ///
    /// Reported rather than acted on. Re-registering would be a fight with
    /// whoever changed it, and initializing a new identity on a mismatch
    /// would turn one bad answer into a replaced node. An operator wants to
    /// know; the loud log and the reconcile-failure counter are how.
    async fn check_registration(&self, node: &Node, network: &HostedNetwork) {
        let read = {
            let node = node.clone();
            synch_core::offload(move || node.device_keys()).await
        };
        let held = match read {
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(tenant = %network.key(), %error, "could not read this node's keys");
                return;
            }
        };
        let active = held
            .iter()
            .find(|key| key.state == synch_store::KeyState::Active)
            .map(|key| key.node_id.to_z32());
        match (&network.device, &active) {
            // The ordinary case, and the only quiet one.
            (Some(device), Some(active)) if &device.nk == active => {}
            (Some(device), Some(active)) => tracing::error!(
                tenant = %network.key(),
                control_plane = %device.nk,
                held = %active,
                state = %device.state,
                "this slot's registered key is not the key this node signs with: \
                 the registration has been displaced"
            ),
            (None, Some(_)) => tracing::error!(
                tenant = %network.key(),
                "the control plane holds no live key for this slot; \
                 this node is serving under a key the zone does not name"
            ),
            (Some(device), None) => tracing::error!(
                tenant = %network.key(),
                control_plane = %device.nk,
                "this node holds no active key while the control plane names one"
            ),
            (None, None) => {}
        }
    }

    /// What this tenant holds, for the metering heartbeat (§3.3).
    pub async fn status(&self, dp: &str) -> Result<Status> {
        let Some(node) = self.node.clone() else {
            return Ok(Status {
                dp: dp.to_string(),
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
            dp: dp.to_string(),
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
        if let Some(node) = self.node.take() {
            if let Err(error) = node.shutdown().await {
                tracing::warn!(%tenant, %error, "tenant node shutdown reported an error");
            }
        }
        // Only now, with every writer stopped: the ticker's last act is the
        // tail ship, and it has to carry the writes the shutdown above made.
        if let Some(finish) = self.replication_finish.take() {
            let _ = finish.send(());
        }
        if let Some(task) = self.replication_task.take() {
            if let Err(error) = task.await {
                tracing::error!(%tenant, %error, "the replication ticker did not stop cleanly");
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

    /// How much of this pod's volume this tenant's database occupies.
    ///
    /// The one growth vector on a data plane that nothing budgets, and therefore
    /// the one an operator has to be able to see. `budget_bytes` (§4.5) is an
    /// admission ceiling on *content* — the CAS, whose local footprint is
    /// separately capped by `cache_bytes_per_tenant` (§5.2) — and the CAS is
    /// not what grows here. What grows here is metadata: the trie nodes,
    /// out-of-line values, heads and head history a network's members publish,
    /// which this node adopts in full because that is what replicating a
    /// network means, and which lands in one SQLite file on a volume every
    /// tenant on the pod shares. A member publishing a million tiny entries
    /// costs almost no content bytes, passes every budget the design has, and
    /// fills the disk out from under every other tenant.
    ///
    /// Reported rather than enforced, deliberately. A quota belongs where the
    /// plan does — the control plane already sizes `budget_bytes` per org, and
    /// extending it to cover metadata is its change to make — while a ceiling
    /// invented here would take a paying customer's tenant down for the crime
    /// of having a lot of files. So this is the alert:
    /// `synch_dp_tenant_db_bytes` climbing on one tenant against a flat
    /// `held_bytes` is a network inflating metadata, and it is visible before
    /// the volume fills rather than after.
    ///
    /// Three `stat` calls, so it is cheap enough for every pass. The file, its
    /// write-ahead log — which under `Checkpointing::Embedder` is held open by
    /// the replicator and can be the larger of the two — and the shared-memory
    /// index.
    pub fn db_bytes(&self) -> u64 {
        let db = self.dir.join(synch_store::DB_FILE);
        let sidecar = |suffix: &str| {
            let mut name = db.clone().into_os_string();
            name.push(suffix);
            PathBuf::from(name)
        };
        [db.clone(), sidecar("-wal"), sidecar("-shm")]
            .iter()
            .filter_map(|path| std::fs::metadata(path).ok())
            .map(|meta| meta.len())
            .fold(0u64, u64::saturating_add)
    }
}

impl Drop for Tenant {
    /// Closes a node nobody drained, and keeps the directory claimed until it
    /// is really shut.
    ///
    /// `drain` takes the node, so on the ordinary path this is a no-op. What
    /// it covers is the tenant dropped without one — `Reconciler::run`'s
    /// `select!` dropping a `tick()` future at shutdown, or a `provision` that
    /// fails after `Tenant::start` has stored the node. `Node` has no `Drop`
    /// of its own: only `shutdown` retires the endpoint and its tasks, so a
    /// dropped tenant otherwise leaves a live UDP socket and an open store for
    /// the life of the process.
    ///
    /// The lifecycle lock goes with it rather than being released here. That
    /// ordering is the point: releasing it while the endpoint is still up
    /// would let the next `provision` for the same network open a second store
    /// and a second replicator over the same database and stream — two writers
    /// on the one thing the lock exists to keep single.
    ///
    /// A drop cannot await, so the *whole* of [`drain`](Tenant::drain)'s
    /// ordering is moved into the spawned task rather than only the node
    /// close. Taking the pieces out here is what makes that possible, and it
    /// is not optional: the fields left behind drop in declaration order the
    /// moment this returns, and two of those drops are signals.
    /// `replication_finish` is a oneshot whose *drop* ends the ticker, so
    /// leaving it would start the tail ship immediately — concurrently with
    /// six standing loops still writing and a node still open. The tail ship
    /// is the last acknowledged write a tenant has; under
    /// `Checkpointing::Embedder` the replicator is also what pins the WAL, so
    /// once it closes, frames written after it can be recycled with no shipped
    /// copy. That is precisely the loss `drain` orders itself to avoid, and a
    /// `Drop` that only closed the node would reintroduce it on the one path
    /// this exists to cover.
    ///
    /// Off a runtime there is nothing to spawn onto. The node then stays open
    /// for the life of the process, so the lock is *leaked* rather than
    /// released: releasing it beside a live endpoint is the two-writers case
    /// above, and a lock this process never gives up is the honest
    /// representation of a directory this process never let go of.
    fn drop(&mut self) {
        let Some(node) = self.node.take() else {
            return;
        };
        let tenant = self.network.key();
        let lock = self.lock.take();
        // Same order as `drain`, for the same reason: loops down, node closed,
        // log tail shipped last.
        let _ = self.shutdown.send(());
        let loops = std::mem::take(&mut self.loops);
        let finish = self.replication_finish.take();
        let task = self.replication_task.take();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    for handle in loops {
                        if let Err(error) = handle.await {
                            tracing::warn!(%tenant, %error, "a dropped tenant's loop did not stop cleanly");
                        }
                    }
                    if let Err(error) = node.shutdown().await {
                        tracing::warn!(%tenant, %error, "closing a dropped tenant's node failed");
                    }
                    if let Some(finish) = finish {
                        let _ = finish.send(());
                    }
                    if let Some(task) = task {
                        if let Err(error) = task.await {
                            tracing::error!(%tenant, %error, "a dropped tenant's replication ticker did not stop cleanly");
                        }
                    }
                    drop(lock);
                });
            }
            Err(_) => {
                std::mem::forget(lock);
                tracing::error!(
                    %tenant,
                    "a tenant was dropped off a runtime; its node stays open, and its \
                     data directory stays locked, until the process ends"
                );
            }
        }
    }
}

/// Empties a tenant's data directory, keeping the lifecycle lock.
///
/// The lock file stays because this process is holding a lock *on it*.
/// Removing it would not release what we hold — the lock lives on the open
/// descriptor — but it would let a second process create a fresh file and
/// acquire that, which is the mutual exclusion gone precisely when two owners
/// are the thing being guarded against.
fn clear_data_dir(dir: &std::path::Path) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|error| DpError::io("reading the tenant data directory", error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| DpError::io("reading the tenant data directory", error))?;
        if entry.file_name() == synch_engine::LIFECYCLE_FILE {
            continue;
        }
        let path = entry.path();
        let removed = match entry.file_type() {
            Ok(kind) if kind.is_dir() => std::fs::remove_dir_all(&path),
            _ => std::fs::remove_file(&path),
        };
        removed.map_err(|error| DpError::io("clearing the tenant data directory", error))?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant nobody drained still runs the whole of `drain`'s teardown,
    /// in `drain`'s order.
    ///
    /// The path is real rather than hypothetical: `Reconciler::run`'s
    /// `select!` drops a `tick()` future at shutdown. [`Node`] has no `Drop`
    /// of its own — only `shutdown` retires the endpoint and its tasks — so
    /// without this the process would carry a live UDP socket and an open
    /// store until it exited.
    ///
    /// What is asserted is the *order*, because the release on its own proves
    /// nothing: `LifecycleLock` unlocks when it is dropped, so a `Tenant` with
    /// no `Drop` impl at all gives the directory back just as promptly. The
    /// claim that needs a test is the one `drain` spends its whole body on —
    /// that nothing still writing to the directory outlives the claim on it.
    /// So a standing loop is made to take a visible moment to finish, and the
    /// lock must not come back before it has.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_tenant_finishes_its_teardown_before_it_lets_go() {
        let _blocking = synch_core::BlockingScope::enter();
        let base = tempfile::tempdir().expect("a base dir");
        let dir = base.path().join("tenant");
        {
            let dir = dir.clone();
            synch_core::offload(move || Node::init(&dir, None))
                .await
                .expect("the tenant initializes");
        }
        let lock = LifecycleLock::acquire(&dir).expect("the lifecycle lock");
        let node = Node::open(NodeConfig::loopback(&dir))
            .await
            .expect("the tenant opens");

        // A stand-in for the six standing loops: it stops when the tenant says
        // so, and takes long enough about it that "did the drop wait?" is a
        // question with an observable answer.
        let (shutdown, mut signal) = broadcast::channel(1);
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let loop_done = Arc::clone(&stopped);
        let standing = tokio::spawn(async move {
            let _ = signal.recv().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            loop_done.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let tenant = Tenant {
            network: HostedNetwork {
                org: "acme".into(),
                network: "prod".into(),
                domain: "prod.acme.example".into(),
                budget_bytes: 0,
                retention: "current".into(),
                device: None,
            },
            state: State::Running,
            node: Some(node),
            lock: Some(lock),
            shutdown,
            loops: vec![standing],
            replication_finish: None,
            replication_task: None,
            dir: dir.clone(),
        };

        // While it is alive the directory is claimed, which is what makes the
        // assertion after the drop mean anything.
        assert!(
            LifecycleLock::acquire(&dir).is_err(),
            "a running tenant holds its data directory"
        );

        drop(tenant);

        let mut released = None;
        for _ in 0..200 {
            match LifecycleLock::acquire(&dir) {
                Ok(lock) => {
                    released = Some(lock);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        assert!(
            released.is_some(),
            "a dropped tenant must not hold its data directory for the life of \
             the process"
        );
        assert!(
            stopped.load(std::sync::atomic::Ordering::SeqCst),
            "the directory was handed back while a loop was still writing to \
             it — the next tenant to take this lock would be the second writer \
             the lock exists to prevent"
        );
    }
}
