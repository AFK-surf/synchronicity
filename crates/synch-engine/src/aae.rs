//! Anti-entropy scheduling (§5.3).
//!
//! Reactive: a local publish is pushed to every trusted peer immediately —
//! the whole membership, not just current connections — which gives sub-second
//! propagation on a connected cluster. A head *received* from a peer is not
//! relayed onward; at the §12 sizes the publisher's own fan-out already reaches
//! everyone it can reach, so the pull path below is what covers a member the
//! origin cannot dial. Periodic: every `aae_interval` (±50 % jitter) one random
//! trusted peer gets a full `Hello` push-pull exchange, which repairs anything
//! the reactive path missed and is the mechanism that guarantees convergence.

use std::time::Duration;

use crate::reconcile::SyncReport;
use synch_core::{now_ns, NodeId, SignedHead};

use crate::{
    error::{EngineError, Result},
    node::Node,
};

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
    ///
    /// Bounded as a whole, not only per exchange. `synch-net` puts a deadline on
    /// every request, but how many requests one `sync_with` issues is the
    /// peer's to choose — one `fetch_pending` per head it hands back, each
    /// looping to [`MAX_UNPRODUCTIVE_ROUNDS`], plus a pass over every pending
    /// head — so per-request deadlines compose into no bound at all. A peer
    /// answering just inside each one would hold this loop indefinitely, and
    /// `anti_entropy_round` returns on the first success, so no other peer
    /// would be reached and no pending trie fetched for as long as it kept that
    /// up.
    ///
    /// [`MAX_UNPRODUCTIVE_ROUNDS`]: crate::reconcile::MAX_UNPRODUCTIVE_ROUNDS
    pub async fn sync_with_peer(&self, node_id: &NodeId) -> Result<SyncReport> {
        let addr = self
            .peer_addr(node_id)?
            .unwrap_or_else(|| iroh::EndpointAddr::new(*node_id));
        let started = std::time::Instant::now();
        let client = self.net().connect_mpt(addr).await?;
        let budget = self.config().sync_round_budget;
        let report = tokio::time::timeout(budget, self.syncer().sync_with(&client))
            .await
            .map_err(|_| {
                EngineError::invalid(format!(
                    "the sync round with {} outran its {budget:?} budget",
                    node_id.fmt_short()
                ))
            })??;
        let elapsed = started.elapsed().as_micros().min(i64::MAX as u128) as i64;
        self.store().record_peer_sync(node_id, now_ns(), elapsed)?;
        Ok(report)
    }

    /// The trusted device keys this node may dial, excluding its own.
    pub fn dialable_peers(&self) -> Result<Vec<NodeId>> {
        // Every key this node holds, not just the active one: through a
        // rotation window the retiring key is still bound to our own origin,
        // and filtering only the active key would leave the node dialling
        // itself and reporting itself unreachable — in exactly the window where
        // an operator is watching `sync` and `key ls` the hardest (§3.4).
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
        let start = (jitter_seed() % peers.len() as u64) as usize;
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

    /// Pushes a head to every trusted peer (§5.3, reactive path).
    ///
    /// All of them at once. Each push is bounded by a dial timeout and a request
    /// deadline, so a peer that has gone dark costs seconds — but sequentially
    /// those seconds add up across the membership and a publish waits for all of
    /// them before it returns. Run together, one slow peer costs one deadline
    /// rather than delaying every peer behind it.
    pub async fn push_head(&self, head: &SignedHead) -> Result<usize> {
        let peers = self.dialable_peers()?;
        let mut targets = Vec::with_capacity(peers.len());
        for peer in peers {
            let addr = self
                .peer_addr(&peer)?
                .unwrap_or_else(|| iroh::EndpointAddr::new(peer));
            targets.push((peer, addr));
        }
        let results = crate::join::futures_join(targets.into_iter().map(|(peer, addr)| async move {
            match self.net().connect_mpt(addr).await {
                Ok(client) => match client.push_head(head).await {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::debug!(peer = %peer.fmt_short(), error = %e, "head push failed");
                        false
                    }
                },
                Err(e) => {
                    tracing::debug!(peer = %peer.fmt_short(), error = %e, "peer unreachable");
                    false
                }
            }
        }))
        .await;
        Ok(results.into_iter().filter(|pushed| *pushed).count())
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
            contained(
                "advancing the trust floor",
                self.store().advance_trust_floor(now),
            );
        } else {
            tracing::warn!(
                reading = now,
                "the host clock cannot date a trust decision: no dns binding is honored and \
                 none is expired until it is set (see `synch doctor`)"
            );
        }
        if let Some(expired) = contained("expiring bindings", self.store().expire_bindings(now)) {
            if expired > 0 {
                tracing::info!(expired, "dns bindings lapsed");
            }
        }
        contained("expiring tombstones", self.expire_tombstones());
        self.sweep_pending_heads(now);
        // Ads for objects content GC has since dropped. Staged before the
        // content sweep below rather than after, so a root that goes this pass
        // is retired next pass rather than lingering an interval — and so the
        // ad and the payload never disagree in the direction that has peers
        // dialling us for bytes we no longer have (§6.3).
        contained("retiring ads", self.retire_ads());

        let retention = self
            .config()
            .root_retention
            .as_nanos()
            .min(i64::MAX as u128) as i64;
        let before = now.saturating_sub(retention);
        let mut pruned = 0;
        for origin in self.store().history_origins()? {
            // Per origin, so one origin's history cannot stop another's from
            // being pruned — and so the trie sweep below still runs.
            if let Some(n) = contained(
                "pruning history",
                self.store().prune_history_before(&origin, before),
            ) {
                pruned += n;
            }
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

    /// Decides what becomes of every pending head: promote it, abandon it, or
    /// leave it to the fetch that is still working on it (§5.2).
    ///
    /// One pass over the slots rather than two, and — the part that matters —
    /// **contained per origin**. Every step here can fail on data one origin
    /// published: `try_promote` ends in `materialize_diff`, which raises on a
    /// record that will not decode, and `is_complete` raises on a node graph
    /// the structural guard refuses. Propagating either aborted the whole
    /// maintenance pass, so nothing after it ran — not the abandonment sweep,
    /// not ad retirement, not history pruning, and not `gc()`. A single member
    /// publishing one undecodable `f:` value therefore disabled garbage
    /// collection on every peer that adopted the head, permanently and
    /// silently, with a `warn!` every five minutes as the only trace. That is
    /// the opposite of what §12 promises: "a record this node cannot apply
    /// fails its own origin and no other".
    ///
    /// Three outcomes per head:
    ///
    /// - **Promoted**, when its trie is wholly here. `try_promote` otherwise
    ///   runs only from an accepted offer and from the end of a successful
    ///   fetch, and neither covers a crash between the last committed batch of
    ///   trie nodes and the promotion that would have followed.
    /// - **Abandoned**, when nobody has served it past `pending_head_ttl`, or
    ///   when promoting it *failed*. The second case is new and it is the
    ///   escape a poisoned head needs: `head_floor` is the best of both slots,
    ///   so a pending head holds the floor above every servable head for its
    ///   origin, and a head whose trie is complete but whose promotion cannot
    ///   succeed is stepped over by the TTL rule below for exactly the reason
    ///   that rule exists — it looks like it is one promotion away. It is not,
    ///   and it would hold that origin hostage forever.
    /// - **Left alone**, when a fetch is still working on it.
    fn sweep_pending_heads(&self, now: i64) {
        let ttl = self
            .config()
            .pending_head_ttl
            .as_nanos()
            .min(i64::MAX as u128) as i64;
        let before = now.saturating_sub(ttl);
        let syncer = self.syncer();
        let trie = synch_mpt::Trie::new(self.store().as_ref());

        let Some(pending) = contained(
            "listing pending heads",
            self.store().all_heads(synch_store::Slot::Pending),
        ) else {
            return;
        };

        let (mut promoted, mut abandoned) = (0usize, 0usize);
        for stored in pending {
            let origin = &stored.head.origin;
            let outcome = syncer.try_promote(origin, now);
            let poisoned = match outcome {
                Ok(true) => {
                    promoted += 1;
                    continue;
                }
                Ok(false) => false,
                Err(e) => {
                    tracing::warn!(
                        origin = %origin,
                        seq = stored.head.seq,
                        error = %e,
                        "origin left behind: its pending head cannot be materialized"
                    );
                    true
                }
            };

            // `is_complete` walks a peer's node graph, so it can raise on its
            // own; a head whose completeness cannot even be decided is in the
            // same position as one whose promotion failed.
            let complete = match trie.is_complete(stored.head.root) {
                Ok(complete) => complete,
                Err(e) => {
                    tracing::warn!(
                        origin = %origin,
                        error = %e,
                        "origin left behind: its pending trie cannot be walked"
                    );
                    true
                }
            };

            let stale = stored.received_at <= before && !complete;
            if !poisoned && !stale {
                continue;
            }
            tracing::warn!(
                origin = %origin,
                seq = stored.head.seq,
                poisoned,
                "abandoning a pending head"
            );
            if contained(
                "clearing a pending head",
                self.store().clear_head(origin, synch_store::Slot::Pending),
            )
            .is_some()
            {
                abandoned += 1;
            }
        }
        if promoted > 0 {
            tracing::info!(promoted, "pending heads whose tries were already here");
        }
        if abandoned > 0 {
            tracing::info!(abandoned, "pending heads dropped");
        }
    }
}

/// Runs one maintenance step, reporting a failure rather than propagating it.
///
/// The pass is a sequence of independent sweeps over shared state, and its
/// later steps — ad retirement, history pruning, the trie and content sweeps —
/// are the ones that reclaim disk. Letting an earlier step's failure abort the
/// pass means a fault in *one* origin's data stops garbage collection for the
/// whole node, on every pass, forever. `gc_orphans` already documents that
/// hazard for itself ("`maintenance_pass` would report failure forever and no
/// orphan would be swept again"); this applies the same rule to the steps
/// ahead of it.
fn contained<T, E: std::fmt::Display>(what: &str, result: std::result::Result<T, E>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(step = what, %error, "a maintenance step failed; the pass continues");
            None
        }
    }
}

/// Applies ±50 % jitter to a duration.
///
/// Jitter is what keeps a cluster from synchronizing its rounds into a
/// thundering herd.
pub fn jittered(base: Duration) -> Duration {
    let base_ms = base.as_millis().max(1) as u64;
    let spread = base_ms; // ±50 % is a full base-width window centered on base
    let offset = jitter_seed() % spread.max(1);
    Duration::from_millis(base_ms / 2 + offset)
}

/// A cheap non-cryptographic source of jitter, seeded from the clock.
fn jitter_seed() -> u64 {
    let mut state = (now_ns() as u64) ^ 0x9e37_79b9_7f4a_7c15;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
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

        // And an old pending head whose trie *is* here. The abandonment sweep
        // steps over it — it is one promotion away from complete, not stranded
        // — and the promotion pass ahead of it performs that promotion, which
        // is what keeps "not stranded" from meaning "left in the pending slot
        // forever holding the floor above every servable head".
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
        assert_eq!(
            node.store().pending_head(&held_origin).unwrap(),
            None,
            "a pending head whose trie is here is promoted, not left sitting"
        );
        assert_eq!(
            node.store().complete_head(&held_origin).unwrap(),
            Some(held),
            "and what it is promoted into is the complete slot"
        );

        // With the floor dropped, the older head a peer can actually serve is
        // adopted rather than refused.
        let servable = SignedHead::sign(&key, origin.clone(), 3, Hash::EMPTY, 0);
        assert!(crate::Syncer::new(node.store().clone())
            .offer_head(&servable, now)
            .unwrap()
            .accepted());
        node.shutdown().await.unwrap();
    }

    /// A pending head this node cannot materialize fails its own origin and
    /// nothing else — GC in particular still runs (§12).
    ///
    /// `maintenance_pass` used to `?` out of `promote_ready_pending_heads`, so
    /// one member publishing a structurally perfect trie with a single `f:`
    /// value that is not a `FileEntry` aborted the whole pass on every peer
    /// that adopted the head. Nothing after it ever ran again: no abandonment
    /// sweep, no ad retirement, no history pruning, no trie or content sweep.
    /// Permanent, silent apart from a `warn!`, and ~200 bytes to trigger.
    ///
    /// The head also has to stop holding `head_floor`: its trie *is* complete,
    /// so the TTL rule steps over it as "one promotion away", which it is not.
    #[tokio::test]
    async fn a_head_that_cannot_be_materialized_does_not_stop_the_pass() {
        use synch_core::{file_key, Hash, SignedHead};
        use synch_store::{Binding, BindingSource, Slot};

        let dir = tempfile::tempdir().unwrap();
        crate::Node::init(dir.path(), None).unwrap();
        let node = crate::Node::open(NodeConfig::loopback(dir.path()))
            .await
            .unwrap();

        let key = iroh_base::SecretKey::generate();
        let origin = synch_core::OriginId::named("rogue", "x.example").unwrap();
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

        // A canonical one-leaf trie whose `f:` record will not decode.
        let trie = synch_mpt::Trie::new(node.store().as_ref());
        let root = trie
            .insert(Hash::EMPTY, &file_key("s", "a.txt").unwrap(), &[0xffu8; 8])
            .unwrap();
        assert!(trie.is_complete(root).unwrap(), "the trie is wholly here");
        let head = SignedHead::sign(&key, origin.clone(), 1, root, 0);
        node.store()
            .put_head(Slot::Pending, &head, now_ns(), 0)
            .unwrap();

        // Junk in the trie tables that only a sweep removes.
        let junk = Hash::new(b"junk");
        synch_mpt::NodeStore::put_value(node.store().as_ref(), &junk, b"junk").unwrap();

        node.maintenance_pass()
            .expect("one origin's undecodable record must not fail the pass");

        // The sweep ran.
        assert!(
            synch_mpt::NodeStore::get_value(node.store().as_ref(), &junk)
                .unwrap()
                .is_none(),
            "gc did not run"
        );
        // And the head stopped holding the origin hostage.
        assert_eq!(
            node.store().pending_head(&origin).unwrap(),
            None,
            "a head whose promotion cannot succeed must not hold head_floor"
        );
        assert_eq!(node.store().complete_head(&origin).unwrap(), None);

        // With the floor dropped, an older head a peer can actually serve is
        // adoptable again.
        let servable = SignedHead::sign(&key, origin.clone(), 1, Hash::EMPTY, 0);
        assert!(crate::Syncer::new(node.store().clone())
            .offer_head(&servable, now_ns())
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
