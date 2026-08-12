//! Content fetching: provider resolution, ranking, and verified range reads
//! (§6.3, §6.4).

use synch_core::{group_count, groups_for_byte_range, now_ns, ChunkRanges, Hash, OriginId};

use crate::{
    error::{EngineError, Result},
    node::Node,
};

/// A ranked provider candidate.
#[derive(Debug, Clone)]
pub struct Provider {
    /// The advertising origin.
    pub origin: OriginId,
    /// The device keys currently bound to it, in dial order.
    pub keys: Vec<synch_core::NodeId>,
    /// The groups it claims to hold, derived from its advertised spans.
    pub claims: ChunkRanges,
    /// Its latency EWMA in microseconds; `0` means "never measured".
    pub latency_us: i64,
}

/// What one fetch achieved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchReport {
    /// The groups newly verified and committed.
    pub fetched: ChunkRanges,
    /// How many providers were contacted.
    pub providers_tried: usize,
    /// True if the whole wanted range is now present locally.
    pub complete: bool,
}

impl Node {
    /// Resolves and ranks the providers for a byte range of an object (§6.4).
    ///
    /// Ranking is by latency EWMA, then by advertised coverage, then by a
    /// deterministic tiebreak on the origin's canonical name. Span summaries
    /// are hints: a stale one costs one wasted round trip, never correctness.
    pub fn providers_for(&self, root: &Hash, start: u64, end: u64) -> Result<Vec<Provider>> {
        let now = now_ns();
        let peers = self.store().peers_seen()?;
        let mut out = Vec::new();
        for (origin, ad) in self.store().providers_for_range(root, start, end)? {
            if &origin == self.origin() {
                continue;
            }
            let keys = self.store().keys_for_origin(&origin, now)?;
            if keys.is_empty() {
                // No live binding: we could not dial them even if we wanted to.
                continue;
            }
            let claims = match &ad.state {
                synch_core::AdState::Complete => ChunkRanges::single(0, group_count(ad.size)),
                synch_core::AdState::Partial { spans } => ChunkRanges::from_ranges(
                    spans.iter().map(|&(s, e)| groups_for_byte_range(s, e)),
                ),
            };
            let latency_us = keys
                .iter()
                .filter_map(|k| {
                    peers
                        .iter()
                        .find(|p| &p.node_id == k)
                        .map(|p| p.latency_ewma_us)
                })
                .filter(|l| *l > 0)
                .min()
                .unwrap_or(0);
            out.push(Provider {
                origin,
                keys,
                claims,
                latency_us,
            });
        }
        out.sort_by(|a, b| {
            let a_rank = if a.latency_us == 0 {
                i64::MAX / 2
            } else {
                a.latency_us
            };
            let b_rank = if b.latency_us == 0 {
                i64::MAX / 2
            } else {
                b.latency_us
            };
            a_rank
                .cmp(&b_rank)
                .then(b.claims.count().cmp(&a.claims.count()))
                .then(a.origin.canonical().cmp(&b.origin.canonical()))
        });
        Ok(out)
    }

    /// Fetches the chunk groups covering `[start, end)` of an object.
    ///
    /// Wanted ranges are split across up to `fetch_fanout` providers; each
    /// slice is verified against the object root before any byte is committed,
    /// and verified groups survive a restart because they land in the bitmap
    /// immediately.
    pub async fn fetch_range(
        &self,
        root: &Hash,
        size: u64,
        start: u64,
        end: u64,
    ) -> Result<FetchReport> {
        let wanted = ChunkRanges::from_ranges([groups_for_byte_range(start, end)])
            .intersect(&ChunkRanges::single(0, group_count(size)));
        self.fetch_groups(root, size, &wanted).await
    }

    /// Fetches an object in full.
    pub async fn fetch_all(&self, root: &Hash, size: u64) -> Result<FetchReport> {
        let wanted = ChunkRanges::single(0, group_count(size));
        self.fetch_groups(root, size, &wanted).await
    }

    /// Fetches specific chunk groups.
    pub async fn fetch_groups(
        &self,
        root: &Hash,
        size: u64,
        wanted: &ChunkRanges,
    ) -> Result<FetchReport> {
        let mut report = FetchReport::default();
        let mut remaining = wanted.difference(&self.local_groups(root)?);
        if remaining.is_empty() {
            report.complete = true;
            return Ok(report);
        }

        let byte_end = size;
        let providers = self.providers_for(root, 0, byte_end.max(1))?;
        for provider in providers.iter().take(self.config().fetch_fanout.max(1)) {
            if remaining.is_empty() {
                break;
            }
            let ask = remaining.intersect(&provider.claims);
            if ask.is_empty() {
                continue;
            }
            report.providers_tried += 1;
            match self.fetch_from(provider, root, size, &ask).await {
                Ok(got) => {
                    remaining = remaining.difference(&got);
                    report.fetched = report.fetched.union(&got);
                }
                Err(e) => {
                    // Re-plan on provider failure: a peer that cannot help is
                    // simply skipped, and the next candidate is tried.
                    tracing::debug!(origin = %provider.origin, error = %e, "provider failed");
                }
            }
        }

        if !report.fetched.is_empty() {
            self.on_content_progress(root)?;
        }
        report.complete = wanted.difference(&self.local_groups(root)?).is_empty();
        Ok(report)
    }

    async fn fetch_from(
        &self,
        provider: &Provider,
        root: &Hash,
        size: u64,
        ask: &ChunkRanges,
    ) -> Result<ChunkRanges> {
        let mut last_error = None;
        for key in &provider.keys {
            let addr = match self.peer_addr(key)? {
                Some(addr) => addr,
                None => iroh::EndpointAddr::new(*key),
            };
            let started = std::time::Instant::now();
            match self.net().connect_blob(addr).await {
                Ok(client) => {
                    let got = client.fetch_into(self.store(), *root, size, ask).await?;
                    let elapsed = started.elapsed().as_micros().min(i64::MAX as u128) as i64;
                    self.store().record_peer_sync(key, now_ns(), elapsed)?;
                    return Ok(got);
                }
                Err(e) => last_error = Some(e),
            }
        }
        Err(match last_error {
            Some(e) => EngineError::Net(e),
            None => EngineError::not_found(format!("no dialable key for {}", provider.origin)),
        })
    }

    /// The groups of an object we hold and have verified.
    pub fn local_groups(&self, root: &Hash) -> Result<ChunkRanges> {
        Ok(self
            .store()
            .blob(root)?
            .map(|b| b.verified_groups())
            .unwrap_or_else(ChunkRanges::empty))
    }

    /// Publishes an updated `b:` advertisement if a milestone was reached
    /// (§6.3).
    pub fn on_content_progress(&self, root: &Hash) -> Result<Option<synch_core::SignedHead>> {
        if !self.ad_update_due(root)? {
            return Ok(None);
        }
        let Some(change) = self.ad_change(root)? else {
            return Ok(None);
        };
        self.publish(vec![change])
    }

    /// Reads a byte range of a published entry, fetching whatever is missing
    /// first — the engine half of `synch cat --range` (§7.2).
    pub async fn read_entry_range(
        &self,
        origin: &OriginId,
        space: &str,
        path: &str,
        start: u64,
        len: Option<u64>,
    ) -> Result<Vec<u8>> {
        let entry = self
            .store()
            .entry(origin, space, path)?
            .ok_or_else(|| EngineError::not_found(format!("{origin}:{space}/{path}")))?;
        if entry.kind == synch_core::EntryKind::Tombstone {
            return Err(EngineError::not_found(format!(
                "{origin}:{space}/{path} was deleted at seq {}",
                entry.seq
            )));
        }
        let root = entry
            .content
            .ok_or_else(|| EngineError::invalid("entry has no content"))?;
        let end = match len {
            Some(len) => start.saturating_add(len).min(entry.size),
            None => entry.size,
        };
        if start > entry.size {
            return Err(EngineError::invalid(format!(
                "offset {start} is past the end of a {}-byte object",
                entry.size
            )));
        }
        let report = self.fetch_range(&root, entry.size, start, end).await?;
        if !report.complete {
            return Err(EngineError::not_found(format!(
                "no provider could serve bytes {start}..{end} of {root}"
            )));
        }
        Ok(self.store().read_range(&root, start, end - start)?)
    }

    /// Reads a published entry in full.
    pub async fn read_entry(&self, origin: &OriginId, space: &str, path: &str) -> Result<Vec<u8>> {
        self.read_entry_range(origin, space, path, 0, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use synch_core::{BlobAd, AD_SPAN_GRANULARITY};
    use synch_store::{Binding, BindingSource};

    async fn node() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        (dir, node)
    }

    fn trust(node: &Node, name: &str) -> (OriginId, synch_core::NodeId) {
        let key = iroh_base::SecretKey::generate().public();
        let origin = OriginId::named(name, "x.example").unwrap();
        node.store()
            .put_binding(&Binding {
                origin: origin.clone(),
                node_id: key,
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        (origin, key)
    }

    #[tokio::test]
    async fn providers_are_ranked_by_latency() {
        let (_d, node) = node().await;
        let root = Hash::new(b"object");
        let (fast, fast_key) = trust(&node, "fast");
        let (slow, slow_key) = trust(&node, "slow");
        let (unknown, _) = trust(&node, "unknown");
        for origin in [&fast, &slow, &unknown] {
            node.store()
                .put_provider(&root, origin, &BlobAd::complete(1000))
                .unwrap();
        }
        node.store().record_peer_sync(&fast_key, 0, 1_000).unwrap();
        node.store()
            .record_peer_sync(&slow_key, 0, 500_000)
            .unwrap();

        let ranked = node.providers_for(&root, 0, 1000).unwrap();
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].origin, fast);
        assert_eq!(ranked[1].origin, slow);
        // A never-measured peer sorts after measured ones but is still a
        // candidate.
        assert_eq!(ranked[2].origin, unknown);
    }

    #[tokio::test]
    async fn our_own_origin_is_never_a_provider() {
        let (_d, node) = node().await;
        let root = Hash::new(b"object");
        node.store()
            .put_provider(&root, node.origin(), &BlobAd::complete(10))
            .unwrap();
        assert!(node.providers_for(&root, 0, 10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn providers_without_a_live_binding_are_skipped() {
        let (_d, node) = node().await;
        let root = Hash::new(b"object");
        let stranger = OriginId::named("stranger", "x.example").unwrap();
        node.store()
            .put_provider(&root, &stranger, &BlobAd::complete(10))
            .unwrap();
        assert!(node.providers_for(&root, 0, 10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn partial_ads_narrow_what_we_ask_for() {
        let (_d, node) = node().await;
        let g = AD_SPAN_GRANULARITY;
        let root = Hash::new(b"object");
        let (origin, _) = trust(&node, "partial");
        node.store()
            .put_provider(&root, &origin, &BlobAd::partial(4 * g, [(0, g)]))
            .unwrap();

        // The head of the object is claimed...
        let head = node.providers_for(&root, 0, 100).unwrap();
        assert_eq!(head.len(), 1);
        assert!(head[0].claims.contains(0));
        // ...the tail is not, so the provider is not offered for it at all.
        assert!(node.providers_for(&root, 3 * g, 4 * g).unwrap().is_empty());
    }

    #[tokio::test]
    async fn locally_complete_objects_need_no_fetch() {
        let (_d, node) = node().await;
        let payload = vec![3u8; 100_000];
        let root = node.store().ingest_bytes(&payload, now_ns()).unwrap();
        let report = node.fetch_all(&root, payload.len() as u64).await.unwrap();
        assert!(report.complete);
        assert_eq!(report.providers_tried, 0);
        assert!(report.fetched.is_empty());
    }

    #[tokio::test]
    async fn a_fetch_with_no_providers_reports_incomplete() {
        let (_d, node) = node().await;
        let report = node
            .fetch_all(&Hash::new(b"nobody has this"), 100_000)
            .await
            .unwrap();
        assert!(!report.complete);
        assert_eq!(report.providers_tried, 0);
    }

    #[tokio::test]
    async fn reading_a_tombstoned_entry_is_a_clear_error() {
        let (_d, node) = node().await;
        let origin = node.origin().clone();
        node.store()
            .put_entry(
                &origin,
                "s",
                "gone",
                &synch_core::FileEntry::tombstone(0, 4, None),
            )
            .unwrap();
        let err = node.read_entry(&origin, "s", "gone").await.unwrap_err();
        assert!(err.to_string().contains("deleted at seq 4"));
    }

    #[tokio::test]
    async fn reading_a_locally_held_entry_returns_exact_bytes() {
        let (_d, node) = node().await;
        let payload: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        let root = node.store().ingest_bytes(&payload, now_ns()).unwrap();
        let origin = node.origin().clone();
        node.store()
            .put_entry(
                &origin,
                "s",
                "big.bin",
                &synch_core::FileEntry::file(payload.len() as u64, 0, root, 1),
            )
            .unwrap();

        assert_eq!(
            node.read_entry(&origin, "s", "big.bin").await.unwrap(),
            payload
        );
        assert_eq!(
            node.read_entry_range(&origin, "s", "big.bin", 100, Some(50))
                .await
                .unwrap(),
            &payload[100..150]
        );
        // A range that runs past the end is clamped, not an error.
        assert_eq!(
            node.read_entry_range(&origin, "s", "big.bin", 49_990, Some(1000))
                .await
                .unwrap(),
            &payload[49_990..]
        );
    }
}
