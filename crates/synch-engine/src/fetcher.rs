//! Content fetching: provider resolution, ranking, and verified range reads
//! (§6.3, §6.4).

use std::future::Future;

use synch_core::{group_count, groups_for_byte_range, now_ns, ChunkRanges, Hash, OriginId};
use synch_store::VersionPolicy;

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

/// A byte window of an object that is present and verified locally.
///
/// What [`Node::prepare_range`] hands back so a caller can stream the
/// window out of the CAS in pieces of its own choosing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedRange {
    /// The object's blake3 root.
    pub root: Hash,
    /// The object's full size in bytes.
    pub size: u64,
    /// The first byte of the window.
    pub start: u64,
    /// One past the last byte of the window.
    pub end: u64,
}

impl PreparedRange {
    /// How many bytes the window covers.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// True if the window is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
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

/// Splits a set of groups into `parts` contiguous shares of roughly equal size.
///
/// This is what makes `fetch_fanout` mean something: without it, the first
/// provider asked for a whole object claims all of it and the others have
/// nothing left to do. Contiguous shares rather than interleaved ones, because
/// a bao slice over one span is cheaper to encode and verify than one over
/// many.
fn split_ranges(ranges: &ChunkRanges, parts: usize) -> Vec<ChunkRanges> {
    let parts = parts.max(1) as u64;
    let total = ranges.count();
    if total == 0 {
        return vec![ChunkRanges::empty(); parts as usize];
    }
    let mut out = Vec::with_capacity(parts as usize);
    let mut consumed = 0u64;
    let mut cursor = ranges.ranges.iter().copied().peekable();
    let mut carry: Option<synch_core::GroupRange> = None;
    for part in 0..parts {
        // Each share ends at its proportional boundary, so rounding never
        // leaves a group unassigned: the last share takes whatever is left.
        let boundary = if part + 1 == parts {
            total
        } else {
            total * (part + 1) / parts
        };
        let mut share = Vec::new();
        while consumed < boundary {
            let range = match carry.take().or_else(|| cursor.next()) {
                Some(range) => range,
                None => break,
            };
            let len = range.end - range.start;
            let want = boundary - consumed;
            if len <= want {
                share.push(range);
                consumed += len;
            } else {
                let split = range.start + want;
                share.push(synch_core::GroupRange::new(range.start, split));
                carry = Some(synch_core::GroupRange::new(split, range.end));
                consumed = boundary;
            }
        }
        out.push(ChunkRanges::from_ranges(share));
    }
    out
}

/// Runs several futures to completion together, collecting their outputs.
///
/// A hand-rolled join rather than a `futures` dependency: this is the only
/// place in the workspace that needs one, and it needs the simplest possible
/// shape — no cancellation, no early return, every branch polled to the end.
async fn futures_join<F: Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
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

    /// Fetches specific chunk groups (§6.4).
    ///
    /// The wanted ranges are split across up to `fetch_fanout` providers and
    /// those requests run concurrently, which is what the fanout is for: three
    /// peers each serving a third of a large object beats one peer serving all
    /// of it. Failures do not end the fetch — the surviving ranges go back into
    /// the pool and the next batch of candidates is tried, so a fourth provider
    /// that holds what the first three did not is still reached.
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

        let mut providers = self.providers_for(root, 0, size.max(1))?;
        if providers.is_empty() {
            // No local ad covers this root — a cold cache, or an origin just
            // admitted whose ads have not replicated yet. Peers may know who
            // holds it, and a hint costs at most a wasted dial because content
            // is hash-verified regardless (§5.1).
            providers = self.ask_peers_for_providers(root, size).await?;
        }

        let fanout = self.config().fetch_fanout.max(1);
        let mut candidates = providers.into_iter();
        loop {
            if remaining.is_empty() {
                break;
            }
            // One batch: up to `fanout` providers that can help with what is
            // still missing.
            let mut chosen = Vec::new();
            for provider in candidates.by_ref() {
                if remaining.intersect(&provider.claims).is_empty() {
                    continue;
                }
                chosen.push(provider);
                if chosen.len() >= fanout {
                    break;
                }
            }
            if chosen.is_empty() {
                break;
            }

            // Split what is missing into one contiguous share per provider,
            // then narrow each share to what that provider actually claims.
            // Anything a provider does not claim simply stays in `remaining`
            // and is offered to the next batch.
            let shares = split_ranges(&remaining, chosen.len());
            let batch: Vec<(Provider, ChunkRanges)> = chosen
                .into_iter()
                .zip(shares)
                .map(|(provider, share)| {
                    let ask = share.intersect(&provider.claims);
                    (provider, ask)
                })
                .filter(|(_, ask)| !ask.is_empty())
                .collect();
            if batch.is_empty() {
                break;
            }
            report.providers_tried += batch.len();

            let results = futures_join(batch.iter().map(|(provider, ask)| async move {
                (
                    provider.origin.clone(),
                    self.fetch_from(provider, root, size, ask).await,
                )
            }))
            .await;
            for (origin, result) in results {
                match result {
                    Ok(got) => {
                        remaining = remaining.difference(&got);
                        report.fetched = report.fetched.union(&got);
                    }
                    Err(e) => {
                        // A peer that cannot help is skipped and its slice
                        // stays in `remaining`, so the next batch offers it to
                        // whoever comes after.
                        tracing::debug!(origin = %origin, error = %e, "provider failed");
                    }
                }
            }
        }

        if !report.fetched.is_empty() {
            self.on_content_progress(root)?;
        }
        report.complete = wanted.difference(&self.local_groups(root)?).is_empty();
        Ok(report)
    }

    /// Asks trusted peers who holds an object, for roots no local ad covers
    /// (§5.1 `FindProviders`).
    ///
    /// Hints are unverified: they are fed back through the ordinary ranking so
    /// a wrong one costs a dial and nothing else, and every byte is still
    /// checked against the object root.
    async fn ask_peers_for_providers(&self, root: &Hash, size: u64) -> Result<Vec<Provider>> {
        let mut learned = 0;
        for peer in self.dialable_peers()? {
            let addr = self
                .peer_addr(&peer)?
                .unwrap_or_else(|| iroh::EndpointAddr::new(peer));
            let client = match self.net().connect_mpt(addr).await {
                Ok(client) => client,
                Err(e) => {
                    tracing::debug!(peer = %peer.fmt_short(), error = %e, "peer unreachable");
                    continue;
                }
            };
            let ads = match client.find_providers(*root).await {
                Ok(ads) => ads,
                Err(e) => {
                    tracing::debug!(peer = %peer.fmt_short(), error = %e, "provider hint failed");
                    continue;
                }
            };
            for (origin, ad) in ads {
                if &origin == self.origin() {
                    continue;
                }
                self.store().put_provider(root, &origin, &ad)?;
                learned += 1;
            }
        }
        if learned > 0 {
            tracing::debug!(hints = learned, "learned providers from peers");
        }
        self.providers_for(root, 0, size.max(1))
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
        self.publish(&[change])
    }

    /// Reads a byte range of the policy-selected version of a path, fetching
    /// whatever is missing first — the engine half of `synch cat --range`
    /// (§7.2, §8).
    ///
    /// Buffers the whole range: callers streaming a large object want
    /// [`Node::prepare_range`] and then chunked
    /// [`Store::read_range`](synch_store::Store::read_range) reads instead.
    pub async fn read_range(
        &self,
        space: &str,
        path: &str,
        policy: &VersionPolicy,
        start: u64,
        len: Option<u64>,
    ) -> Result<Vec<u8>> {
        let range = self.prepare_range(space, path, policy, start, len).await?;
        Ok(self
            .store()
            .read_range(&range.root, range.start, range.end - range.start)?)
    }

    /// Reads the policy-selected version of a path in full.
    pub async fn read_path(
        &self,
        space: &str,
        path: &str,
        policy: &VersionPolicy,
    ) -> Result<Vec<u8>> {
        self.read_range(space, path, policy, 0, None).await
    }

    /// Selects a version under a policy, fetches whatever of the requested
    /// range is missing, and reports where the bytes now live locally.
    ///
    /// Every byte is verified against the object's bao tree before it is
    /// committed to the CAS, so a subsequent
    /// [`Store::read_range`](synch_store::Store::read_range) over the returned
    /// window reads only verified content.
    pub async fn prepare_range(
        &self,
        space: &str,
        path: &str,
        policy: &VersionPolicy,
        start: u64,
        len: Option<u64>,
    ) -> Result<PreparedRange> {
        let entry = self.resolve(space, path, policy)?;
        if entry.kind == synch_core::EntryKind::Tombstone {
            return Err(EngineError::not_found(format!(
                "{} was deleted at seq {}",
                crate::tree::reference_of(policy, space, path),
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
        Ok(PreparedRange {
            root,
            size: entry.size,
            start,
            end,
        })
    }

    /// Reads one origin's entry in full — the pinned form of
    /// [`Node::read_path`], which is what `synch take` adopts from.
    pub async fn read_entry(&self, origin: &OriginId, space: &str, path: &str) -> Result<Vec<u8>> {
        self.read_path(space, path, &VersionPolicy::Origin(origin.clone()))
            .await
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

    fn pin(origin: &OriginId) -> VersionPolicy {
        VersionPolicy::Origin(origin.clone())
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
            node.read_range("s", "big.bin", &pin(&origin), 100, Some(50))
                .await
                .unwrap(),
            &payload[100..150]
        );
        // A range that runs past the end is clamped, not an error.
        assert_eq!(
            node.read_range("s", "big.bin", &pin(&origin), 49_990, Some(1000))
                .await
                .unwrap(),
            &payload[49_990..]
        );
    }

    #[test]
    fn ranges_split_into_contiguous_shares() {
        let all = ChunkRanges::single(0, 9);
        let shares = split_ranges(&all, 3);
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0], ChunkRanges::single(0, 3));
        assert_eq!(shares[1], ChunkRanges::single(3, 6));
        assert_eq!(shares[2], ChunkRanges::single(6, 9));
        // Nothing is lost and nothing overlaps.
        assert_eq!(shares.iter().map(|s| s.count()).sum::<u64>(), 9);

        // A ragged split gives the remainder to the last share.
        let shares = split_ranges(&ChunkRanges::single(0, 10), 3);
        assert_eq!(shares.iter().map(|s| s.count()).sum::<u64>(), 10);
        assert_eq!(shares[2], ChunkRanges::single(6, 10));

        // Shares cross range boundaries without dropping anything.
        let split = ChunkRanges::from_ranges([
            synch_core::GroupRange::new(0, 2),
            synch_core::GroupRange::new(10, 14),
        ]);
        let shares = split_ranges(&split, 2);
        assert_eq!(shares.iter().map(|s| s.count()).sum::<u64>(), 6);
        assert_eq!(
            shares[0].union(&shares[1]),
            split,
            "the shares reassemble into the original"
        );

        // Degenerate cases stay well-defined.
        assert_eq!(split_ranges(&ChunkRanges::empty(), 3).len(), 3);
        assert_eq!(split_ranges(&all, 1)[0], all);
    }

    #[tokio::test]
    async fn a_fetch_keeps_going_past_the_first_fanout_candidates() {
        // §6.4: giving up after `fetch_fanout` candidates would strand a fetch
        // whose fourth-ranked provider is the one that can actually serve it.
        let (_d, node) = node().await;
        let payload = vec![9u8; 100_000];
        let root = synch_core::Hash::new(&payload);
        let size = payload.len() as u64;

        // Three providers that advertise the object and cannot be dialed, all
        // ranked ahead of the fourth because they have measured latencies.
        for (i, name) in ["ghost-a", "ghost-b", "ghost-c"].iter().enumerate() {
            let (origin, key) = trust(&node, name);
            node.store()
                .put_provider(&root, &origin, &BlobAd::complete(size))
                .unwrap();
            node.store()
                .record_peer_sync(&key, 0, (i as i64 + 1) * 10)
                .unwrap();
        }

        // The fourth is a real node that holds the bytes.
        let holder_dir = tempfile::tempdir().unwrap();
        let holder_origin = OriginId::named("holder", "x.example").unwrap();
        Node::init(holder_dir.path(), Some(holder_origin.clone())).unwrap();
        let holder = Node::open(NodeConfig::loopback(holder_dir.path()))
            .await
            .unwrap();
        assert_eq!(
            holder.store().ingest_bytes(&payload, now_ns()).unwrap(),
            root
        );
        for (here, there, origin) in [
            (&node, &holder, &holder_origin),
            (&holder, &node, node.origin()),
        ] {
            here.store()
                .put_binding(&Binding {
                    origin: origin.clone(),
                    node_id: there.node_id(),
                    source: BindingSource::Static,
                    domain: None,
                    note: None,
                    added_at: 0,
                    expires_at: None,
                })
                .unwrap();
            here.remember_peer(&there.net().direct_addr()).unwrap();
        }
        node.store()
            .put_provider(&root, &holder_origin, &BlobAd::complete(size))
            .unwrap();

        let ranked = node.providers_for(&root, 0, size).unwrap();
        assert_eq!(ranked.len(), 4);
        assert_eq!(
            ranked[3].origin, holder_origin,
            "the one that works is ranked last"
        );

        let report = node.fetch_all(&root, size).await.unwrap();
        assert!(report.complete, "{report:?}");
        assert!(
            report.providers_tried > node.config().fetch_fanout,
            "the fetch must look past its first batch: {report:?}"
        );
        assert_eq!(node.store().read_all(&root).unwrap(), payload);

        holder.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
    }
}
