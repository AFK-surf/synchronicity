//! Anti-entropy scheduling (§5.3).
//!
//! Reactive: local publishes and newly accepted heads are pushed to every
//! reachable peer immediately, which gives sub-second propagation and epidemic
//! spread. Periodic: every `aae_interval` (±50 % jitter) one random trusted
//! peer gets a full `Hello` push-pull exchange, which repairs anything the
//! reactive path missed and is the mechanism that guarantees convergence.

use std::time::Duration;

use synch_core::{now_ns, NodeId, SignedHead};
use synch_net::SyncReport;

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
        let own = self.node_id();
        Ok(self
            .store()
            .trusted_keys(now_ns())?
            .into_iter()
            .filter(|k| *k != own)
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

    /// Pushes a head to every reachable peer (§5.3, reactive path).
    pub async fn push_head(&self, head: &SignedHead) -> Result<usize> {
        let mut pushed = 0;
        for peer in self.dialable_peers()? {
            let addr = self
                .peer_addr(&peer)?
                .unwrap_or_else(|| iroh::EndpointAddr::new(peer));
            match self.net().connect_mpt(addr).await {
                Ok(client) => match client.push_head(head).await {
                    Ok(()) => pushed += 1,
                    Err(e) => {
                        tracing::debug!(peer = %peer.fmt_short(), error = %e, "head push failed")
                    }
                },
                Err(e) => {
                    tracing::debug!(peer = %peer.fmt_short(), error = %e, "peer unreachable")
                }
            }
        }
        Ok(pushed)
    }

    /// Scans, publishes, and pushes the resulting head in one step.
    ///
    /// The scan stages into the publisher and then flushes it, so the result is
    /// one batch and one head — including anything a watcher-triggered rescan
    /// had already staged — and the head is out before this returns.
    pub async fn scan_publish_push(&self) -> Result<Option<SignedHead>> {
        self.scan_and_stage()?;
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
                _ = tokio::time::sleep(Duration::from_secs(300)) => {
                    if let Err(e) = self.maintenance_pass() {
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
        let expired = self.store().expire_bindings(now)?;
        if expired > 0 {
            tracing::info!(expired, "dns bindings lapsed");
        }
        self.expire_tombstones()?;

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
        if stats.nodes > 0 || stats.values > 0 || stats.blobs > 0 {
            tracing::info!(
                nodes = stats.nodes,
                values = stats.values,
                blobs = stats.blobs,
                "garbage collected"
            );
        }
        Ok(stats)
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
