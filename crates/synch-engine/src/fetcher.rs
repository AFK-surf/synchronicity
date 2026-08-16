//! Content fetching: provider resolution, ranking, and verified range reads
//! (§6.3, §6.4).

use std::future::Future;

use synch_core::{group_count, groups_for_byte_range, now_ns, ChunkRanges, Hash, OriginId};
use synch_store::{Donor, EntryRow, ProvenSubtree, VersionPolicy, VersionSet};

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
    /// The groups that never crossed the network: bytes a local donor already
    /// held, proven against the new root and committed
    /// (`docs/DELTA-SYNC.md` §3.4).
    ///
    /// What lets a caller say "reused 98.9 GB, fetched 1.1 GB" rather than
    /// reporting a suspiciously fast transfer.
    pub promoted: ChunkRanges,
    /// Which donor supplied which groups.
    ///
    /// A mirror needs the breakdown and not just the total: the file already
    /// sitting at its destination is byte-identical to the new version exactly
    /// where *that* donor supplied it, and that is the set it can leave alone
    /// when it patches (§3.5).
    pub reused: Vec<(Donor, ChunkRanges)>,
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

    /// Fetches an object in full, offering donors it might be assembled from
    /// (`docs/DELTA-SYNC.md` §3.2).
    pub async fn fetch_all_from(
        &self,
        root: &Hash,
        size: u64,
        donors: &[Donor],
    ) -> Result<FetchReport> {
        let wanted = ChunkRanges::single(0, group_count(size));
        self.fetch_groups_from(root, size, &wanted, donors).await
    }

    /// Pins an object, fetching it first when it is not held whole (§9.2).
    ///
    /// A pin is a promise that these bytes stay available here, and a promise
    /// about bytes this node does not hold starts by getting them: pinning
    /// metadata-only content used to mark nothing and say so to no one. The
    /// size travels with the entry the pin was resolved from; a bare root
    /// nobody holds even partially has no size to fetch by, and is refused
    /// rather than half-promised.
    pub async fn pin_object(&self, root: &Hash, size_hint: Option<u64>) -> Result<()> {
        let blob = self.store().blob(root)?;
        if !blob.as_ref().is_some_and(|b| b.complete) {
            let Some(size) = blob.as_ref().map(|b| b.size).or(size_hint) else {
                return Err(EngineError::NotFound(format!(
                    "no local object with root {root}; pin it as <space>/<path> so the \
                     fetch knows the object's size"
                )));
            };
            self.fetch_all(root, size).await?;
        }
        if !self.store().set_pinned(root, true)? {
            return Err(EngineError::NotFound(format!(
                "object {root} left the store before it could be pinned"
            )));
        }
        Ok(())
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
        self.fetch_groups_from(root, size, wanted, &[]).await
    }

    /// Fetches specific chunk groups, offering local donors first
    /// (`docs/DELTA-SYNC.md` §3.3).
    ///
    /// Everything [`Node::fetch_groups`] does, with a descent in front of it:
    /// the object's tree is asked for at span granularity, compared against
    /// what the donors hold at the same offsets, and every span that turns out
    /// to be byte-identical is promoted out of local storage instead of being
    /// transferred. What is left descends to the leaf level and is compared
    /// again, and only what survives *that* reaches the network.
    ///
    /// The floor is worth stating plainly: with no donors, no provider that
    /// answers, or no span in common, this is [`Node::fetch_groups`] plus at
    /// most one small exchange — which is why the delta attempt needs no
    /// similarity heuristic in front of it (§3.3).
    pub async fn fetch_groups_from(
        &self,
        root: &Hash,
        size: u64,
        wanted: &ChunkRanges,
        donors: &[Donor],
    ) -> Result<FetchReport> {
        if size == 0 {
            return self.take_empty_object(root);
        }
        let mut report = FetchReport::default();
        let mut remaining = wanted.difference(&self.local_groups(root)?);
        if remaining.is_empty() {
            report.complete = true;
            return Ok(report);
        }

        // Objects below `delta_min_size` skip the descent entirely: the round
        // trips cost more than the bytes they could save (§4).
        if !donors.is_empty() && size >= self.config().delta_min_size {
            report.reused = self.delta_descent(root, size, &remaining, donors).await?;
            for (_, groups) in &report.reused {
                report.promoted = report.promoted.union(groups);
            }
            remaining = remaining.difference(&report.promoted);
            if !report.promoted.is_empty() {
                tracing::debug!(
                    root = %root,
                    promoted = report.promoted.count(),
                    remaining = remaining.count(),
                    "delta descent reused local bytes"
                );
            }
        }

        // A descent that satisfied everything leaves nobody to dial.
        let mut providers = if remaining.is_empty() {
            Vec::new()
        } else {
            self.providers_for(root, 0, size.max(1))?
        };
        if providers.is_empty() && !remaining.is_empty() {
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

        if !report.fetched.is_empty() || !report.promoted.is_empty() {
            // Promoted groups count as progress exactly as fetched ones do:
            // they are verified, they are held, and the point of advertising
            // them is that other mirrors of the same space can then delta from
            // *this* node rather than from the origin (§3.4, §6.3).
            //
            // Publishing an updated ad is a trie write and a signed head, so
            // the milestone check and the publish it may trigger both go off
            // the runtime (§6.3).
            let node = self.clone();
            let root = *root;
            crate::blocking::offload(move || node.on_content_progress(&root).map(|_| ())).await?;
        }
        report.complete = wanted.difference(&self.local_groups(root)?).is_empty();
        Ok(report)
    }

    /// The local objects and files that might already hold bytes of a version
    /// (`docs/DELTA-SYNC.md` §3.2).
    ///
    /// In the order the descent should try them: the entry's `prev` root first,
    /// because 1-step lineage (§4.2, §8) names the version this one replaced
    /// and that is the common case by a wide margin; then every other version
    /// of the same path, which is what a divergent origin or a losing version
    /// under `newest` leaves lying around. A candidate is offered only if the
    /// CAS actually holds something of it — a donor with no bytes is a wasted
    /// pass over the proof list.
    ///
    /// The object being fetched is never its own donor: the groups it already
    /// holds are subtracted from the fetch before the descent starts.
    pub fn donors_for(&self, selected: &EntryRow, versions: &VersionSet) -> Result<Vec<Donor>> {
        let mut roots: Vec<Hash> = Vec::new();
        let mut push = |root: Option<Hash>| {
            if let Some(root) = root {
                if selected.content != Some(root) && !roots.contains(&root) {
                    roots.push(root);
                }
            }
        };
        push(selected.prev);
        for entry in &versions.entries {
            push(entry.content);
            push(entry.prev);
        }
        let mut donors = Vec::new();
        for root in roots {
            let holds = self
                .store()
                .blob(&root)?
                .is_some_and(|blob| !blob.verified_groups().is_empty());
            if holds {
                donors.push(Donor::Object(root));
            }
        }
        Ok(donors)
    }

    /// Discovers how much of an object this node can supply itself, in two
    /// rounds of proof (`docs/DELTA-SYNC.md` §3.3).
    ///
    /// Round one asks for the tree at span granularity — 32 bytes per 16 MiB,
    /// about 200 KB for a 100 GB object — and promotes every span a donor
    /// turns out to agree with, whole. Round two asks for leaf chaining values
    /// inside what is left, which is the changed region and nothing else, and
    /// promotes group by group. What survives both rounds is the delta, and it
    /// is all the caller has to fetch.
    ///
    /// Nothing here can fail the fetch. A provider that will not answer, a
    /// donor that has rotted, a file rewritten end to end — each just leaves
    /// more work for the ordinary fetch path, which is exactly what would have
    /// happened without any of this.
    async fn delta_descent(
        &self,
        root: &Hash,
        size: u64,
        wanted: &ChunkRanges,
        donors: &[Donor],
    ) -> Result<Vec<(Donor, ChunkRanges)>> {
        let groups = group_count(size);
        // The whole tree is only as tall as the object: descending "to the span
        // level" of an object that *is* one span would ask for nothing at all,
        // because the root's own hash is not a chaining value anything can be
        // compared against (§2). One level below the top is the deepest cut
        // that still says something.
        let top = groups.next_power_of_two().trailing_zeros().min(63) as u8;
        let span_level = synch_core::AD_SPAN_LEVEL.min(top.saturating_sub(1));
        let mut levels = vec![span_level];
        if span_level > 0 {
            levels.push(0);
        }

        let mut reused: Vec<(Donor, ChunkRanges)> = Vec::new();
        let mut remaining = wanted.clone();
        for level in levels {
            if remaining.is_empty() {
                break;
            }
            let proven = self.fetch_proofs(root, size, &remaining, level).await?;
            if proven.is_empty() {
                continue;
            }
            for (donor, got) in self.promote_from(root, size, donors, proven).await? {
                remaining = remaining.difference(&got);
                match reused.iter_mut().find(|(existing, _)| existing == &donor) {
                    Some((_, ranges)) => *ranges = ranges.union(&got),
                    None => reused.push((donor, got)),
                }
            }
        }
        Ok(reused)
    }

    /// Collects proofs for `ranges` from whoever will serve them.
    ///
    /// Sequential across providers rather than fanned out like a fetch: a proof
    /// is a few hundred kilobytes at the span level and the round trips, not
    /// the bytes, are what it costs. A provider that answers with nothing —
    /// because it holds none of the object, or has gone away — simply hands the
    /// remainder to the next candidate.
    async fn fetch_proofs(
        &self,
        root: &Hash,
        size: u64,
        ranges: &ChunkRanges,
        level: u8,
    ) -> Result<Vec<ProvenSubtree>> {
        let mut providers = self.providers_for(root, 0, size.max(1))?;
        if providers.is_empty() {
            providers = self.ask_peers_for_providers(root, size).await?;
        }
        let mut remaining = ranges.clone();
        let mut proven = Vec::new();
        for provider in providers {
            if remaining.is_empty() {
                break;
            }
            let ask = remaining.intersect(&provider.claims);
            if ask.is_empty() {
                continue;
            }
            match self.proofs_from(&provider, root, size, &ask, level).await {
                Ok(outcome) => {
                    remaining = remaining.difference(&outcome.served);
                    proven.extend(outcome.proven);
                }
                Err(e) => {
                    tracing::debug!(origin = %provider.origin, error = %e, "proof request failed");
                }
            }
        }
        Ok(proven)
    }

    async fn proofs_from(
        &self,
        provider: &Provider,
        root: &Hash,
        size: u64,
        ask: &ChunkRanges,
        level: u8,
    ) -> Result<synch_net::ProofOutcome> {
        let mut last_error = None;
        for key in &provider.keys {
            let addr = match self.peer_addr(key)? {
                Some(addr) => addr,
                None => iroh::EndpointAddr::new(*key),
            };
            let started = std::time::Instant::now();
            match self.net().connect_blob(addr).await {
                Ok(client) => {
                    let outcome = client
                        .fetch_proof_into(self.store(), *root, size, ask, level)
                        .await?;
                    let elapsed = started.elapsed().as_micros().min(i64::MAX as u128) as i64;
                    self.store().record_peer_sync(key, now_ns(), elapsed)?;
                    return Ok(outcome);
                }
                Err(e) => last_error = Some(e),
            }
        }
        Err(match last_error {
            Some(e) => EngineError::Net(e),
            None => EngineError::not_found(format!("no dialable key for {}", provider.origin)),
        })
    }

    /// Offers every donor the subtrees a proof round established, in order.
    ///
    /// All of it is disk work — outboard lookups, whole spans read and hashed,
    /// payload and bitmap commits — so all of it goes to the blocking pool
    /// (§10).
    async fn promote_from(
        &self,
        root: &Hash,
        size: u64,
        donors: &[Donor],
        proven: Vec<ProvenSubtree>,
    ) -> Result<Vec<(Donor, ChunkRanges)>> {
        let node = self.clone();
        let root = *root;
        let donors = donors.to_vec();
        crate::blocking::offload(move || node.promote_blocking(&root, size, &donors, proven)).await
    }

    /// The body of [`Node::promote_from`], for callers already off the runtime.
    fn promote_blocking(
        &self,
        root: &Hash,
        size: u64,
        donors: &[Donor],
        proven: Vec<ProvenSubtree>,
    ) -> Result<Vec<(Donor, ChunkRanges)>> {
        let mut out = Vec::new();
        let mut left = proven;
        for donor in donors {
            if left.is_empty() {
                break;
            }
            if donor.root() == Some(*root) {
                continue;
            }
            let candidates = self.donor_candidates(donor, &left)?;
            if candidates.is_empty() {
                continue;
            }
            let got = self
                .store()
                .promote(root, size, donor, &candidates, now_ns())?;
            if got.is_empty() {
                continue;
            }
            left.retain(|subtree| !got.overlaps(subtree.start, subtree.end()));
            out.push((donor.clone(), got));
        }
        Ok(out)
    }

    /// Narrows a proof round's subtrees to the ones a donor plausibly matches.
    ///
    /// For a CAS donor this is the cheap half of the descent: a whole subtree's
    /// chaining value is two positional reads out of the donor's outboard, so
    /// asking whether it agrees about a 16 MiB span costs nothing next to
    /// hashing one. Below [`CV_LOOKUP_MIN_GROUPS`] the arithmetic inverts — a
    /// tree descent per 16 KiB group is more work than just hashing the group —
    /// and the subtree goes forward as a candidate to be settled by the
    /// promotion's own re-hash. A file donor has no tree at all, so everything
    /// goes forward and its bytes answer for themselves.
    fn donor_candidates(
        &self,
        donor: &Donor,
        proven: &[ProvenSubtree],
    ) -> Result<Vec<ProvenSubtree>> {
        let Donor::Object(donor_root) = donor else {
            return Ok(proven.to_vec());
        };
        let looked_up: Vec<usize> = proven
            .iter()
            .enumerate()
            .filter(|(_, s)| s.whole && s.groups >= CV_LOOKUP_MIN_GROUPS)
            .map(|(index, _)| index)
            .collect();
        let spans: Vec<(u64, u64)> = looked_up
            .iter()
            .map(|&index| (proven[index].start, proven[index].groups))
            .collect();
        let cvs = self.store().subtree_cvs(donor_root, &spans)?;
        let mut rejected = std::collections::HashSet::new();
        for (position, &index) in looked_up.iter().enumerate() {
            if cvs.get(position).copied().flatten() != Some(proven[index].cv) {
                rejected.insert(index);
            }
        }
        Ok(proven
            .iter()
            .enumerate()
            .filter(|(index, _)| !rejected.contains(index))
            .map(|(_, subtree)| *subtree)
            .collect())
    }

    /// Produces an object of no bytes locally, rather than fetching it.
    ///
    /// A zero-length object has nothing to transfer: no bytes, and no group a
    /// provider could serve. Asking for one anyway is what broke empty files —
    /// [`group_count`] counts an empty object as one group so that "complete"
    /// is representable, but bao encodes nothing over an empty tree, so every
    /// window came back served-nothing, the fetch ran out of providers with
    /// that group still missing, and a mirror reported the path as `no
    /// provider could serve the content` (§6.4).
    ///
    /// Nobody has to serve it. An empty object's content is settled by its
    /// size, and its root is what BLAKE3 gives for no input — so this node can
    /// produce the object itself and get, byte for byte and hash for hash, what
    /// a provider would have sent. Ingesting it here is also what leaves the
    /// CAS row every later read goes through: `synch cat`, `get`, and `take` of
    /// an empty file all resolve through the store like any other object.
    fn take_empty_object(&self, root: &Hash) -> Result<FetchReport> {
        let mut report = FetchReport::default();
        if self.store().blob(root)?.is_some_and(|blob| blob.complete) {
            report.complete = true;
            return Ok(report);
        }
        // An entry that declares no bytes while naming some other object is
        // inconsistent: nothing is invented for it, and the caller reports it
        // unservable exactly as it would any root nobody can supply.
        report.complete = self.store().ingest_bytes(&[], now_ns())? == *root;
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
        // The read verifies every group it returns against the object's bao
        // tree, reading payload and outboard off disk to do it: blocking work
        // proportional to the range, so it runs on the blocking pool.
        let store = self.store().clone();
        crate::blocking::offload(move || {
            Ok(store.read_range(&range.root, range.start, range.end - range.start)?)
        })
        .await
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
        // Every read path resolved an entry to get here, which means the
        // lineage that makes delta possible is already in hand: `synch cat`, a
        // `take`, and the gateway's range reads all get the descent for the
        // price of one `VersionSet` lookup (§3.5).
        let donors = match self.store().versions_for(space, path) {
            Ok(versions) => self.donors_for(&entry, &versions)?,
            Err(e) => {
                tracing::debug!(error = %e, "no version set for donors");
                Vec::new()
            }
        };
        let wanted = ChunkRanges::from_ranges([groups_for_byte_range(start, end)])
            .intersect(&ChunkRanges::single(0, group_count(entry.size)));
        let report = self
            .fetch_groups_from(&root, entry.size, &wanted, &donors)
            .await?;
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

    /// Writes an object the CAS already holds into `target`, a bounded piece at
    /// a time.
    ///
    /// The fetch has to have happened first — [`Node::fetch_all`] or
    /// [`Node::prepare_range`] — because this only copies what is verified and
    /// local. Everything that materializes an object onto disk goes through
    /// here: a mirror writing a file (§7.2), `synch take` adopting a peer's
    /// version (§8), and the gateway's fetch-to-file. None of them may hold the
    /// object in memory, which is the whole reason this is not
    /// `write(read_all(root))`.
    ///
    /// The bytes land in a staging file that is renamed into place, so a reader
    /// of `target` sees the old contents or the new ones and never a half-copy.
    ///
    /// Async because the copy is the size of the object: every piece is a
    /// verified CAS read and a file write, so the whole loop runs on the
    /// blocking pool rather than on the worker thread that called it (§10).
    pub async fn write_blob_to(
        &self,
        root: &Hash,
        size: u64,
        target: impl Into<std::path::PathBuf>,
    ) -> Result<()> {
        let node = self.clone();
        let root = *root;
        let target = target.into();
        crate::blocking::offload(move || node.write_blob_to_blocking(&root, size, &target)).await
    }

    /// The body of [`Node::write_blob_to`], for callers already off the
    /// runtime.
    pub fn write_blob_to_blocking(
        &self,
        root: &Hash,
        size: u64,
        target: &std::path::Path,
    ) -> Result<()> {
        let mut out = crate::scanner::Adoption::at(target)?;
        let mut offset = 0u64;
        while offset < size {
            let take = COPY_CHUNK.min(size - offset);
            let bytes = self.store().read_range(root, offset, take)?;
            if bytes.is_empty() {
                // Short of the size the entry declares: the object is not
                // whole locally, and a truncated file must not be left behind
                // wearing the name of a complete one.
                return Err(EngineError::not_found(format!(
                    "{root} has no bytes at offset {offset} of {size}"
                )));
            }
            offset += bytes.len() as u64;
            out.write(&bytes)?;
        }
        out.commit()?;
        Ok(())
    }

    /// Materializes an object over a file that is already most of it
    /// (`docs/DELTA-SYNC.md` §3.5).
    ///
    /// `keep` is the set of groups the file at `target` was *proven* to hold
    /// correctly — the ones a donor promotion took from it and checked against
    /// the new object's tree. Everything else is written out of the CAS.
    ///
    /// The staging file is a clone of the target rather than a fresh empty one,
    /// so the groups in `keep` cost nothing to reproduce: on a filesystem with
    /// reflink they are not even copied, only shared. The old-or-new invariant
    /// is exactly as before — the patched clone is renamed over the target when
    /// it is complete, and a crash before that leaves the target untouched.
    /// Patching the live file in place would be faster still and is refused:
    /// a crash halfway through would leave a franken-file wearing a complete
    /// file's name, which is the one thing the staging rename exists to prevent
    /// (§7.2).
    pub fn patch_blob_to_blocking(
        &self,
        root: &Hash,
        size: u64,
        target: &std::path::Path,
        keep: &ChunkRanges,
        reflink: bool,
    ) -> Result<()> {
        let (mut out, kind) = crate::scanner::Adoption::cloning(target, target, reflink)?;
        // The old file is rarely the same length as the new one — an appended
        // log never is — and the clone starts out as long as it was.
        out.set_len(size)?;
        let rewrite = ChunkRanges::single(0, group_count(size)).difference(keep);
        tracing::debug!(
            target = %target.display(),
            clone = ?kind,
            patched = rewrite.count(),
            kept = keep.count(),
            "patching a mirrored file"
        );
        for range in &rewrite.ranges {
            let end = range
                .end
                .saturating_mul(synch_core::CHUNK_GROUP_SIZE)
                .min(size);
            let mut offset = range.start.saturating_mul(synch_core::CHUNK_GROUP_SIZE);
            while offset < end {
                let take = COPY_CHUNK.min(end - offset);
                let bytes = self.store().read_range(root, offset, take)?;
                if bytes.is_empty() {
                    return Err(EngineError::not_found(format!(
                        "{root} has no bytes at offset {offset} of {size}"
                    )));
                }
                out.write_at(offset, &bytes)?;
                offset += bytes.len() as u64;
            }
        }
        out.commit()?;
        Ok(())
    }
}

/// The smallest subtree worth asking a donor's outboard about.
///
/// Reading a chaining value out of a donor is a walk down its tree — a handful
/// of positional reads — while hashing a subtree is a read of the bytes. For a
/// 16 MiB span the walk wins by four orders of magnitude; for a single 16 KiB
/// group it loses, and the group is settled by the re-hash that promotion does
/// anyway. This is roughly where the two meet.
const CV_LOOKUP_MIN_GROUPS: u64 = 16;

/// How much of an object is held in memory while it is copied out of the CAS.
///
/// The same order as the control socket's chunk: large enough that the
/// per-piece cost disappears, small enough that object size stops mattering.
const COPY_CHUNK: u64 = 256 * 1024;

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

    /// An object of no bytes needs no provider.
    ///
    /// It used to need one and never find it: an empty object counts as one
    /// chunk group, nothing encodes for that group, so every window came back
    /// served-nothing and the fetch gave up — which is how `synch cat` and
    /// mirrors of empty files reported that nobody could serve them.
    #[tokio::test]
    async fn an_empty_object_needs_no_provider() {
        let (_d, node) = node().await;
        let (peer, _) = trust(&node, "nas");
        let empty = Hash::new(b"");
        // Published by a peer, never held here: no CAS row, no provider ad,
        // and — being offline in this test — nobody to ask either.
        node.store()
            .put_entry(
                &peer,
                "s",
                "empty.txt",
                &synch_core::FileEntry::file(0, 0, empty, 1),
            )
            .unwrap();

        let report = node.fetch_all(&empty, 0).await.unwrap();
        assert!(report.complete, "{report:?}");
        assert_eq!(report.providers_tried, 0, "nobody should have been asked");
        // And it reads back through the store like any other object.
        assert!(node
            .read_entry(&peer, "s", "empty.txt")
            .await
            .unwrap()
            .is_empty());

        // An entry claiming no bytes while naming some other object is not
        // completed by inventing content for it.
        let report = node
            .fetch_all(&Hash::new(b"not the empty object"), 0)
            .await
            .unwrap();
        assert!(!report.complete, "{report:?}");
    }

    /// Donors are the versions this node can actually supply bytes from, in
    /// the order §3.2 of `docs/DELTA-SYNC.md` wants them tried.
    #[tokio::test]
    async fn donors_are_the_lineage_this_node_can_still_read() {
        let (_d, node) = node().await;
        let (peer, _) = trust(&node, "nas");
        let (rival, _) = trust(&node, "laptop");
        let payload = |seed: u8| vec![seed; 100_000];

        let previous = node.store().ingest_bytes(&payload(1), now_ns()).unwrap();
        let rival_root = node.store().ingest_bytes(&payload(2), now_ns()).unwrap();
        let new_root = Hash::new(b"the version being fetched");
        // A version nobody here has any bytes of: named in the tree, useless
        // as a donor, and left out rather than tried.
        let unheld = Hash::new(b"a version this node never fetched");

        let mut selected = synch_core::FileEntry::file(100_000, 5, new_root, 2);
        selected.prev = Some(previous);
        node.store()
            .put_entry(&peer, "s", "disk.img", &selected)
            .unwrap();
        let mut theirs = synch_core::FileEntry::file(100_000, 4, rival_root, 1);
        theirs.prev = Some(unheld);
        node.store()
            .put_entry(&rival, "s", "disk.img", &theirs)
            .unwrap();

        let versions = node.store().versions_for("s", "disk.img").unwrap();
        let entry = versions
            .entries
            .iter()
            .find(|e| e.origin == peer)
            .unwrap()
            .clone();
        let donors = node.donors_for(&entry, &versions).unwrap();
        assert_eq!(
            donors,
            vec![Donor::Object(previous), Donor::Object(rival_root)],
            "the replaced version first, then the other version of the path"
        );
        assert!(
            !donors.contains(&Donor::Object(new_root)),
            "the object being fetched is never its own donor"
        );
        node.shutdown().await.unwrap();
    }

    /// An object below `delta_min_size` never pays for a descent: with no
    /// providers to answer one, the fetch reports exactly what it did before.
    #[tokio::test]
    async fn a_small_object_skips_the_descent() {
        let (_d, node) = node().await;
        let donor = node
            .store()
            .ingest_bytes(&vec![4u8; 100_000], now_ns())
            .unwrap();
        let root = Hash::new(b"a small object nobody has");
        let report = node
            .fetch_all_from(&root, 100_000, &[Donor::Object(donor)])
            .await
            .unwrap();
        assert!(report.promoted.is_empty(), "{report:?}");
        assert!(report.reused.is_empty(), "{report:?}");
        assert!(!report.complete, "{report:?}");
        node.shutdown().await.unwrap();
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
