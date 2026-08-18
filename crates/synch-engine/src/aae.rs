//! Anti-entropy scheduling (§5.3).
//!
//! Reactive: local publishes are pushed over every already-live session, and
//! a node adopting a pushed head as pending fetches its trie straight from
//! the pusher, which gives sub-second propagation among peers that are
//! already talking. Periodic: every `aae_interval` (±50 % jitter) one random
//! trusted peer gets a full `Hello` push-pull exchange, which repairs
//! anything the reactive path missed and is the mechanism that guarantees
//! convergence.

use std::time::Duration;

use crate::reconcile::SyncReport;
use synch_core::{now_ns, NodeId, SignedHead};

use crate::{error::Result, node::Node};

/// The outcome of one anti-entropy round.
#[derive(Debug, Clone, Default)]
pub struct RoundReport {
    /// The peer contacted, if any was reachable.
    pub peer: Option<NodeId>,
    /// What the exchange achieved.
    pub sync: SyncReport,
    /// Peers that could not be reached this round.
    pub unreachable: usize,
}

impl Node {
    /// Runs one `Hello` push-pull exchange with a specific peer.
    pub async fn sync_with_peer(&self, node_id: &NodeId) -> Result<SyncReport> {
        let addr = self
            .peer_addr(node_id)?
            .unwrap_or_else(|| iroh::EndpointAddr::new(*node_id));
        let started = std::time::Instant::now();
        let client = self.net().connect_mpt(addr).await?;
        let report = self.syncer().sync_with(&client).await?;
        let elapsed = started.elapsed().as_micros().min(i64::MAX as u128) as i64;
        self.store().record_peer_sync(node_id, now_ns(), elapsed)?;
        Ok(report)
    }

    /// The trusted device keys this node may dial, excluding its own.
    pub fn dialable_peers(&self) -> Result<Vec<NodeId>> {
        // Every key this node holds, not just the active one: through a
        // rotation window the retiring key is still bound to our own origin,
        // and filtering only the active key made the node dial itself and
        // report itself unreachable — in exactly the window where an operator
        // is watching `sync` and `key ls` the hardest (§3.4).
        let own: Vec<NodeId> = self
            .device_keys()?
            .into_iter()
            .map(|key| key.node_id)
            .collect();
        Ok(self
            .store()
            .trusted_keys(now_ns())?
            .into_iter()
            .filter(|k| !own.contains(k))
            .collect())
    }

    /// Runs one periodic round: pick one random trusted peer and sync with it.
    ///
    /// Picking randomly rather than round-robin is what makes the gossip
    /// converge in `O(log N)` rounds after a partition heals.
    pub async fn anti_entropy_round(&self) -> Result<RoundReport> {
        let peers = self.dialable_peers()?;
        if peers.is_empty() {
            return Ok(RoundReport::default());
        }
        let mut report = RoundReport::default();
        let mut draw = synch_core::xorshift_seed();
        let start = (synch_core::xorshift_next(&mut draw) % peers.len() as u64) as usize;
        for offset in 0..peers.len() {
            let peer = peers[(start + offset) % peers.len()];
            match self.sync_with_peer(&peer).await {
                Ok(sync) => {
                    report.peer = Some(peer);
                    report.sync = sync;
                    return Ok(report);
                }
                Err(e) => {
                    tracing::debug!(peer = %peer.fmt_short(), error = %e, "peer unreachable");
                    report.unreachable += 1;
                }
            }
        }
        Ok(report)
    }

    /// Pushes a head to every peer this node already holds a live session
    /// with (§5.3, reactive path).
    ///
    /// Live sessions only, and no dialing: a publish must not stall on peers
    /// that are away — each dead address costs a dial timeout — because the
    /// periodic round reaches them anyway. The pushes that do go out run
    /// together, so one slow session delays nobody else, and a failed push
    /// costs a debug log: the same periodic round is the repair.
    pub async fn push_head(&self, head: &SignedHead) -> Result<usize> {
        let mut pushes = Vec::new();
        for peer in self.dialable_peers()? {
            let Some(connection) = self.net().live(&peer, synch_core::ALPN_MPT) else {
                continue;
            };
            let client = synch_net::MptClient::new(connection);
            let head = head.clone();
            pushes.push(async move {
                let peer = client.remote_id();
                match client.push_head(&head).await {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::debug!(peer = %peer.fmt_short(), error = %e, "head push failed");
                        false
                    }
                }
            });
        }
        Ok(crate::join::futures_join(pushes)
            .await
            .into_iter()
            .filter(|pushed| *pushed)
            .count())
    }

    /// Fetches the tries of pushed heads this node adopted as pending,
    /// straight from the pusher (§5.3, reactive path).
    ///
    /// A pushed head arrives without its trie: the head names a root this
    /// node does not hold, and the pusher just demonstrated it does. Each
    /// notification is one (pusher, origin) pair; a fetch that fails — the
    /// pusher went away between the push and the fetch — is left for the
    /// next periodic round to repair.
    pub async fn run_pushed_fetches(&self, shutdown: impl std::future::Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let Some(mut rx) = self.pending_push_receiver() else {
            return shutdown.await;
        };
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                got = rx.recv() => {
                    let Some((peer, origin)) = got else { return };
                    let addr = match self.peer_addr(&peer) {
                        Ok(Some(addr)) => addr,
                        Ok(None) => iroh::EndpointAddr::new(peer),
                        Err(e) => {
                            tracing::debug!(error = %e, "peer address lookup failed");
                            continue;
                        }
                    };
                    let client = match self.net().connect_mpt(addr).await {
                        Ok(client) => client,
                        Err(e) => {
                            tracing::debug!(peer = %peer.fmt_short(), error = %e, "pusher unreachable");
                            continue;
                        }
                    };
                    if let Err(e) = self.syncer().fetch_pending(&client, &origin).await {
                        tracing::debug!(
                            origin = %origin,
                            error = %e,
                            "fetching a pushed head failed"
                        );
                    }
                }
            }
        }
    }

    /// Scans, publishes, and pushes the resulting head in one step.
    ///
    /// The scan stages into the publisher and then flushes it, so the result is
    /// one batch and one head — including anything a watcher-triggered rescan
    /// had already staged — and the head is out before this returns.
    pub async fn scan_publish_push(&self) -> Result<Option<SignedHead>> {
        self.scan_and_stage_off_runtime().await?;
        self.flush_staged().await
    }

    /// The next anti-entropy delay: the configured interval with ±50 % jitter.
    pub fn next_aae_delay(&self) -> Duration {
        jittered(self.config().aae_interval)
    }

    /// Runs the periodic anti-entropy loop until `shutdown` resolves.
    pub async fn run_anti_entropy(&self, shutdown: impl std::future::Future<Output = ()>) {
        let shutdown = std::pin::pin!(shutdown);
        let mut shutdown = shutdown;
        loop {
            let delay = self.next_aae_delay();
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(delay) => {
                    if let Err(e) = self.anti_entropy_round().await {
                        tracing::warn!(error = %e, "anti-entropy round failed");
                    }
                }
            }
        }
    }

    /// Runs the periodic maintenance loop: GC, binding expiry, and tombstone
    /// expiry (§5.4, §3.2, §4.2).
    pub async fn run_maintenance(&self, shutdown: impl std::future::Future<Output = ()>) {
        let shutdown = std::pin::pin!(shutdown);
        let mut shutdown = shutdown;
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                // On the blocking pool: a GC pass sweeps the trie and unlinks
                // every unreferenced payload, which is proportional to what
                // the store has accumulated since the last one (§5.4).
                _ = tokio::time::sleep(Duration::from_secs(300)) => {
                    let node = self.clone();
                    let pass = crate::blocking::offload(move || node.maintenance_pass()).await;
                    if let Err(e) = pass {
                        tracing::warn!(error = %e, "maintenance pass failed");
                    }
                }
            }
        }
    }

    /// One maintenance pass, exposed so tests and `synch doctor` can drive it.
    ///
    /// The order is the one §5.4 implies and it is not arbitrary. History is
    /// pruned to `root_retention` *first*, because the trie mark set is
    /// "complete + pending heads + remaining history roots" — marking from
    /// every root ever recorded means nothing is ever swept, which is exactly
    /// the state this pass exists to avoid. Then the trie sweep runs, and then
    /// content: an object drops out of `referenced_content` only once the
    /// entries naming it are gone, which is what the trie sweep produces.
    ///
    /// Tombstones past `tombstone_ttl` are *staged* here rather than published:
    /// the publisher turns them into one head like any other batch (§4.2).
    pub fn maintenance_pass(&self) -> Result<synch_store::GcStats> {
        let now = now_ns();
        // The pass that reaps expiring trust is also the one that records how
        // far the clock has got: a persisted floor is what stops a backwards
        // step from handing back trust that already lapsed (§3.2,
        // `synch_store::clock`). A reading that can date nothing advances
        // nothing and reaps nothing, and says so — membership stops being
        // extended, which is loud in `doctor` rather than silent here.
        if synch_core::clock_is_trusted(now) {
            self.store().advance_trust_floor(now)?;
        } else {
            tracing::warn!(
                reading = now,
                "the host clock cannot date a trust decision: no dns binding is honored and \
                 none is expired until it is set (see `synch doctor`)"
            );
        }
        let expired = self.store().expire_bindings(now)?;
        if expired > 0 {
            tracing::info!(expired, "dns bindings lapsed");
        }
        self.expire_tombstones()?;
        let abandoned = self.abandon_stale_pending_heads(now)?;
        if abandoned > 0 {
            tracing::info!(abandoned, "pending heads nobody could serve");
        }
        // Ads for objects content GC has since dropped. Staged before the
        // content sweep below rather than after, so a root that goes this pass
        // is retired next pass rather than lingering an interval — and so the
        // ad and the payload never disagree in the direction that has peers
        // dialling us for bytes we no longer have (§6.3).
        self.retire_ads()?;

        let retention = self
            .config()
            .root_retention
            .as_nanos()
            .min(i64::MAX as u128) as i64;
        let before = now.saturating_sub(retention);
        let mut pruned = 0;
        for origin in self.store().history_origins()? {
            pruned += self.store().prune_history_before(&origin, before)?;
        }
        if pruned > 0 {
            tracing::info!(pruned, "old roots dropped out of retention");
        }
        let stats = self.store().gc(before)?;
        if stats.nodes > 0 || stats.values > 0 || stats.blobs > 0 || stats.orphans > 0 {
            tracing::info!(
                nodes = stats.nodes,
                values = stats.values,
                blobs = stats.blobs,
                orphans = stats.orphans,
                "garbage collected"
            );
        }
        Ok(stats)
    }

    /// Clears pending heads that have sat past `pending_head_ttl` with an
    /// incomplete trie (§5.2).
    ///
    /// `head_floor` is the best of both slots, so a pending head nobody can
    /// serve holds the floor above every servable head for that origin: the
    /// node refuses a peer's older complete head and materializes nothing.
    /// Dropping the head drops the floor, and the older head becomes adoptable
    /// on the next exchange. A head whose trie *is* here is left alone — it is
    /// one promotion away from complete, not stranded.
    ///
    /// Returns how many were cleared.
    fn abandon_stale_pending_heads(&self, now: i64) -> Result<usize> {
        let ttl = self
            .config()
            .pending_head_ttl
            .as_nanos()
            .min(i64::MAX as u128) as i64;
        let before = now.saturating_sub(ttl);
        let trie = synch_mpt::Trie::new(self.store().as_ref());
        let mut cleared = 0;
        for stored in self.store().all_heads(synch_store::Slot::Pending)? {
            if stored.received_at > before || trie.is_complete(stored.head.root)? {
                continue;
            }
            tracing::warn!(
                origin = %stored.head.origin,
                seq = stored.head.seq,
                "abandoning a pending head nobody has served"
            );
            self.store()
                .clear_head(&stored.head.origin, synch_store::Slot::Pending)?;
            cleared += 1;
        }
        Ok(cleared)
    }
}

/// Applies ±50 % jitter to a duration.
///
/// Jitter is what keeps a cluster from synchronizing its rounds into a
/// thundering herd.
pub fn jittered(base: Duration) -> Duration {
    let base_ms = base.as_millis().max(1) as u64;
    let spread = base_ms; // ±50 % is a full base-width window centered on base
    let mut draw = synch_core::xorshift_seed();
    let offset = synch_core::xorshift_next(&mut draw) % spread.max(1);
    Duration::from_millis(base_ms / 2 + offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;

    #[test]
    fn jitter_stays_inside_the_window() {
        let base = Duration::from_secs(30);
        for _ in 0..200 {
            let d = jittered(base);
            assert!(d >= base / 2, "{d:?}");
            assert!(d <= base + base / 2, "{d:?}");
        }
    }

    #[test]
    fn jitter_actually_varies() {
        let base = Duration::from_secs(30);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.insert(jittered(base).as_millis());
        }
        assert!(seen.len() > 1, "jitter must not be constant");
    }

    #[tokio::test]
    async fn a_lone_node_has_nothing_to_sync_with() {
        let dir = tempfile::tempdir().unwrap();
        crate::Node::init(dir.path(), None).unwrap();
        let node = crate::Node::open(NodeConfig::loopback(dir.path()))
            .await
            .unwrap();
        assert!(node.dialable_peers().unwrap().is_empty());
        let report = node.anti_entropy_round().await.unwrap();
        assert!(report.peer.is_none());
        assert_eq!(report.unreachable, 0);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_node_never_dials_itself() {
        let dir = tempfile::tempdir().unwrap();
        crate::Node::init(dir.path(), None).unwrap();
        let node = crate::Node::open(NodeConfig::loopback(dir.path()))
            .await
            .unwrap();
        // The self binding exists, but it must not appear as a dial target.
        assert!(node
            .store()
            .trusted_keys(now_ns())
            .unwrap()
            .contains(&node.node_id()));
        assert!(!node.dialable_peers().unwrap().contains(&node.node_id()));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn maintenance_expires_bindings_and_runs_gc() {
        let dir = tempfile::tempdir().unwrap();
        crate::Node::init(dir.path(), None).unwrap();
        let node = crate::Node::open(NodeConfig::loopback(dir.path()))
            .await
            .unwrap();
        node.store()
            .put_binding(&synch_store::Binding {
                origin: synch_core::OriginId::named("gone", "x.example").unwrap(),
                node_id: iroh_base::SecretKey::generate().public(),
                source: synch_store::BindingSource::Dns,
                domain: Some("x.example".into()),
                note: None,
                added_at: 0,
                expires_at: Some(1),
            })
            .unwrap();
        node.maintenance_pass().unwrap();
        assert_eq!(
            node.store().bindings().unwrap().len(),
            1,
            "only self remains"
        );
        node.shutdown().await.unwrap();
    }

    /// A pending head nobody can serve stops holding an origin hostage.
    ///
    /// `head_floor` is the best of both slots, so a head pushed reactively by a
    /// publisher that then goes offline sits in the pending slot refusing every
    /// older head a peer could actually serve. Past the TTL the maintenance
    /// pass drops it and head selection re-runs.
    #[tokio::test]
    async fn a_pending_head_nobody_serves_is_abandoned_by_maintenance() {
        use synch_core::{file_key, FileEntry, Hash, SignedHead};
        use synch_store::{Binding, BindingSource, Slot};

        let dir = tempfile::tempdir().unwrap();
        crate::Node::init(dir.path(), None).unwrap();
        let mut config = NodeConfig::loopback(dir.path());
        config.pending_head_ttl = Duration::from_secs(60);
        let node = crate::Node::open(config).await.unwrap();

        let key = iroh_base::SecretKey::generate();
        let origin = synch_core::OriginId::named("nas", "x.example").unwrap();
        node.store()
            .put_binding(&Binding {
                origin: origin.clone(),
                node_id: key.public(),
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();

        // A root this node holds nothing of, pushed long enough ago that the
        // TTL has run out.
        let ttl_ns = 60 * 1_000_000_000i64;
        let now = now_ns();
        let stranded = SignedHead::sign(&key, origin.clone(), 5, Hash::new(b"unserved"), 0);
        node.store()
            .put_head(Slot::Pending, &stranded, now - 2 * ttl_ns, 0)
            .unwrap();

        // A fresh pending head for another origin is left where it is.
        let fresh_origin = synch_core::OriginId::named("laptop", "x.example").unwrap();
        node.store()
            .put_binding(&Binding {
                origin: fresh_origin.clone(),
                node_id: key.public(),
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        let fresh = SignedHead::sign(&key, fresh_origin.clone(), 1, Hash::new(b"recent"), 0);
        node.store()
            .put_head(Slot::Pending, &fresh, now, 0)
            .unwrap();

        // And an old pending head whose trie *is* here: one promotion away
        // from complete, not stranded.
        let held_origin = synch_core::OriginId::named("vps", "x.example").unwrap();
        node.store()
            .put_binding(&Binding {
                origin: held_origin.clone(),
                node_id: key.public(),
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        let trie = synch_mpt::Trie::new(node.store().as_ref());
        let root = trie
            .insert(
                Hash::EMPTY,
                &file_key("s", "a.txt").unwrap(),
                &postcard::to_stdvec(&FileEntry::file(1, 0, Hash::new(b"c"), 1)).unwrap(),
            )
            .unwrap();
        let held = SignedHead::sign(&key, held_origin.clone(), 1, root, 0);
        node.store()
            .put_head(Slot::Pending, &held, now - 2 * ttl_ns, 0)
            .unwrap();

        node.maintenance_pass().unwrap();
        assert_eq!(node.store().pending_head(&origin).unwrap(), None);
        assert_eq!(
            node.store().pending_head(&fresh_origin).unwrap(),
            Some(fresh)
        );
        assert_eq!(node.store().pending_head(&held_origin).unwrap(), Some(held));

        // With the floor dropped, the older head a peer can actually serve is
        // adopted rather than refused.
        let servable = SignedHead::sign(&key, origin.clone(), 3, Hash::EMPTY, 0);
        assert!(crate::Syncer::new(node.store().clone())
            .offer_head(&servable, now)
            .unwrap()
            .accepted());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_anti_entropy_loop_stops_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        crate::Node::init(dir.path(), None).unwrap();
        let mut config = NodeConfig::loopback(dir.path());
        config.aae_interval = Duration::from_millis(10);
        let node = crate::Node::open(config).await.unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let runner = node.clone();
        let handle = tokio::spawn(async move {
            runner
                .run_anti_entropy(async {
                    let _ = rx.await;
                })
                .await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the loop must stop promptly")
            .unwrap();
        node.shutdown().await.unwrap();
    }
}
