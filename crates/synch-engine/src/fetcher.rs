//! Content fetching: provider resolution, ranking, and verified range reads
//! (§6.3, §6.4).

use synch_core::{group_count, groups_for_byte_range, now_ns, ChunkRanges, Hash, OriginId};
use synch_store::{Donor, EntryRow, Proven, ProvenSubtree, VersionPolicy, VersionSet};

use crate::{
    error::{EngineError, Result},
    join::futures_join,
    node::Node,
    scanner::CloneKind,
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
    /// A per-selection random value, breaking ties between equally ranked
    /// providers so the cluster does not converge on one of them (§6.4).
    pub tiebreak: u64,
}

/// The rank an unmeasured provider sorts at: the median of the measured ones,
/// so "unknown" means unknown rather than "worse than everything measured".
fn median_latency(providers: &[Provider]) -> i64 {
    let mut measured: Vec<i64> = providers
        .iter()
        .map(|p| p.latency_us)
        .filter(|l| *l > 0)
        .collect();
    if measured.is_empty() {
        return 0;
    }
    measured.sort_unstable();
    let mid = measured.len() / 2;
    if measured.len() % 2 == 1 {
        return measured[mid];
    }
    // The midpoint of the two middle values, not one of them: landing *on* a
    // measured peer's rank makes the two tie, and the tiebreak is random, so
    // the unmeasured peer's position would flap between runs.
    measured[mid - 1] + (measured[mid] - measured[mid - 1]) / 2
}

/// What a failed dial contributes to a peer's latency EWMA.
///
/// A fixed penalty, not the elapsed time: a dial that fails *fast* — connection
/// refused, no route — would otherwise feed a small number into the average and
/// promote the peer for being quick about being useless. Worse than any real
/// latency, and smoothed by the EWMA, so one failure demotes sharply and a few
/// successes earn the rank back.
const FAILURE_PENALTY_US: i64 = 30_000_000;

/// A cheap non-cryptographic random state, seeded from the clock.
fn jitter_state() -> u64 {
    (synch_core::now_ns() as u64) ^ 0x9e37_79b9_7f4a_7c15
}

/// xorshift64*, for tiebreaks. Nothing here needs a real generator.
fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
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
    /// The total says a fetch was cheap; the breakdown says which of this
    /// node's objects made it cheap, which is what an operator looking at a
    /// mirror that suddenly stopped reusing anything needs to see.
    pub reused: Vec<(Donor, ChunkRanges)>,
    /// How many providers were contacted, for proofs and for slices alike.
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

impl Node {
    /// Resolves and ranks the providers for a byte range of an object (§6.4).
    ///
    /// Ranking is by latency EWMA, then by advertised coverage, then randomly
    /// (§6.4). Span summaries are hints: a stale one costs one wasted round
    /// trip, never correctness.
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
            let claims = ChunkRanges::from_ranges(
                ad.state
                    .spans
                    .iter()
                    .map(|&(s, e)| groups_for_byte_range(s, e)),
            );
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
                tiebreak: 0,
            });
        }
        // Rank by latency, then coverage, then *randomly* — which is what §6.4
        // specifies and what a deterministic tiebreak quietly undid. Ordering
        // the tail by canonical origin makes every node in the cluster choose
        // the same provider first for any object whose holders are unmeasured,
        // which is precisely the load concentration the random tiebreak exists
        // to prevent.
        //
        // An unmeasured peer sorts into the middle rather than behind every
        // measured one. `i64::MAX / 2` put a fast new local mirror behind a peer
        // measured at 400 ms, and nothing would measure it until something else
        // happened to pick it — a peer with no measurement is unknown, not slow.
        let mut rng = jitter_state();
        for provider in out.iter_mut() {
            provider.tiebreak = next_random(&mut rng);
        }
        let unmeasured = median_latency(&out);
        out.sort_by(|a, b| {
            let rank = |p: &Provider| {
                if p.latency_us == 0 {
                    unmeasured
                } else {
                    p.latency_us
                }
            };
            rank(a)
                .cmp(&rank(b))
                .then(b.claims.count().cmp(&a.claims.count()))
                .then(a.tiebreak.cmp(&b.tiebreak))
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
    /// about bytes this node does not hold starts by getting them, or pinning
    /// metadata-only content marks nothing and says so to no one. The
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
            self.delta_descent(root, size, &remaining, donors, &mut report)
                .await?;
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
        // A pool, not a one-shot iterator. Advancing a single iterator across
        // batches meant each provider was selected at most once for the whole
        // fetch, so a provider that served its share and stayed healthy was
        // never asked again: with one good provider and two ghosts in the first
        // batch, the good one served a third, the ghosts failed, the iterator
        // was exhausted, and the fetch reported failure with the holder still
        // online. §6.4 promises the opposite — a provider that cannot help is
        // dropped and its groups are re-split across *the remainder*.
        let mut pool: Vec<Provider> = providers;
        // Providers are retired only by failing, so a round that makes no
        // progress at all must end the loop or it would spin forever.
        loop {
            if remaining.is_empty() || pool.is_empty() {
                break;
            }
            let mut chosen: Vec<Provider> = Vec::new();
            for provider in pool.iter() {
                if remaining.intersect(&provider.claims).is_empty() {
                    continue;
                }
                chosen.push(provider.clone());
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
            let mut progressed = false;
            for (origin, result) in results {
                match result {
                    Ok(got) => {
                        if !got.is_empty() {
                            progressed = true;
                        } else {
                            // Served nothing despite claiming the range: its
                            // ads overstate what it has, so stop asking.
                            pool.retain(|p| p.origin != origin);
                        }
                        remaining = remaining.difference(&got);
                        report.fetched = report.fetched.union(&got);
                    }
                    Err(e) => {
                        // A peer that cannot help is retired from the pool and
                        // its slice stays in `remaining`, so the next batch
                        // offers it to whoever is left.
                        tracing::debug!(origin = %origin, error = %e, "provider failed");
                        pool.retain(|p| p.origin != origin);
                    }
                }
            }
            if !progressed && pool.is_empty() {
                break;
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

    /// The lineage of a version: every other root that might hold bytes of it
    /// (`docs/DELTA-SYNC.md` §3.2).
    ///
    /// In the order the descent should try them: the entry's `prev` root first,
    /// because 1-step lineage (§4.2, §8) names the version this one replaced
    /// and that is the common case by a wide margin; then every other version
    /// of the same path, which is what a divergent origin or a losing version
    /// under `newest` leaves lying around.
    ///
    /// Candidates, not donors: whether this node holds any of them is
    /// [`Node::donors_for`]'s question. A mirror asks this one because it needs
    /// the names of the versions it *fails* to hold — a root missing from the
    /// CAS that the file on its disk turns out to be is a donor one `ingest`
    /// away (§3.2).
    ///
    /// The object being fetched is never its own donor: the groups it already
    /// holds are subtracted from the fetch before the descent starts.
    pub fn donor_roots(&self, selected: &EntryRow, versions: &VersionSet) -> Vec<Hash> {
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
        roots
    }

    /// The lineage this node can actually supply bytes from.
    ///
    /// [`Node::donor_roots`] narrowed to the roots the CAS holds something of:
    /// a donor with no bytes is a wasted pass over the proof list.
    pub fn donors_for(&self, selected: &EntryRow, versions: &VersionSet) -> Result<Vec<Donor>> {
        let mut donors = Vec::new();
        for root in self.donor_roots(selected, versions) {
            if self.holds_any_of(&root)? {
                donors.push(Donor(root));
            }
        }
        Ok(donors)
    }

    /// True if the CAS holds any verified group of an object.
    pub fn holds_any_of(&self, root: &Hash) -> Result<bool> {
        Ok(self
            .store()
            .blob(root)?
            .is_some_and(|blob| !blob.verified_groups().is_empty()))
    }

    /// Discovers how much of an object this node can supply itself, in two
    /// rounds of proof (`docs/DELTA-SYNC.md` §3.3).
    ///
    /// Round one asks for the tree at span granularity — a 64-byte node pair per
    /// interior node above the spans, so about 381 KB for a 100 GB object — and
    /// promotes every span a donor turns out to agree with, whole. Round two
    /// asks for leaf chaining values inside the spans a donor could speak to and
    /// *disagreed* with, and promotes group by group. What survives both rounds
    /// is the delta, and it is all the caller has to fetch.
    ///
    /// Nothing here can fail the fetch. A provider that will not answer, a
    /// donor the collector took, a file rewritten end to end — each just leaves
    /// more work for the ordinary fetch path, which is exactly what would have
    /// happened without any of this.
    async fn delta_descent(
        &self,
        root: &Hash,
        size: u64,
        wanted: &ChunkRanges,
        donors: &[Donor],
        report: &mut FetchReport,
    ) -> Result<()> {
        // The whole tree is only as tall as the object: descending "to the span
        // level" of an object that *is* one span would ask for nothing at all,
        // because the root's own hash is not a chaining value anything can be
        // compared against (§2). One level below the top is the deepest cut that
        // still says something, so the level is clamped to `top - 1` — an object
        // of one span is compared at half-span granularity, one of two spans at
        // span granularity, and only an object of two groups or fewer has round
        // one land on the leaf level itself.
        let top = group_count(size)
            .next_power_of_two()
            .trailing_zeros()
            .min(63) as u8;
        let span_level = synch_core::AD_SPAN_LEVEL.min(top.saturating_sub(1));

        // Round one, at span granularity.
        let round = self
            .fetch_proofs(root, size, wanted, span_level, report)
            .await?;
        if round.is_empty() {
            return Ok(());
        }
        let leftover = self.promote_round(root, donors, round, report).await?;
        if span_level == 0 {
            return Ok(());
        }
        // Nothing in common at all, across every donor: stop here rather than
        // buy the leaf round. A same-size donor with unrelated content — a
        // re-keyed container, a rebuilt archive — passes every cheap test the
        // descent has and then matches nothing, and the leaf round over a
        // 100 GB object is ~391 MB of tree and ~750 round trips. What that
        // spend could still find is bytes that agree *inside* spans whose
        // span-level chaining values all differed, which for fixed-offset
        // groups means a run that happens to align on a group boundary within
        // an otherwise-changed span: real, but rare enough that paying 391 MB
        // for the chance is the wrong trade every time it is not found
        // (`docs/DELTA-SYNC.md` §3.3). One span in common is enough to
        // establish the donor is a relative of this object and the round is
        // worth running; zero says it is not.
        if report.promoted.is_empty() {
            tracing::debug!(
                root = %root,
                "no span in common with any donor: skipping the leaf round"
            );
            return Ok(());
        }

        // Round two, at the leaf level, inside the spans round one could not
        // settle — and inside nothing else. A span no donor can speak to has
        // nothing for a leaf comparison to compare against, and asking for its
        // tree group by group would buy a proof the size of the object to learn
        // what round one already said (§3.3).
        let unsettled = {
            let node = self.clone();
            let donors = donors.to_vec();
            let wanted = wanted.clone();
            crate::blocking::offload(move || node.unsettled_spans(&donors, &leftover, &wanted))
                .await?
        };
        let mut left = unsettled;
        while !left.is_empty() {
            // One exchange's worth at a time, because the proven subtrees of a
            // leaf-level round are one per 16 KiB group and a re-keyed 100 GB
            // container makes every span unsettled at once: held whole, that
            // list is hundreds of megabytes of a node's memory to say something
            // about bytes it is about to fetch anyway. The size of an exchange
            // is the provider's window sizer's answer, asked here rather than
            // guessed, so the two cannot disagree about where a round ends.
            let batch = synch_net::proof_window(&left, 0);
            left = left.difference(&batch);
            let round = self.fetch_proofs(root, size, &batch, 0, report).await?;
            if round.is_empty() {
                continue;
            }
            self.promote_round(root, donors, round, report).await?;
        }
        Ok(())
    }

    /// The spans a leaf-level round should look inside.
    ///
    /// A span descends only if some donor had a chaining value at that position:
    /// round one already promoted the ones that agreed, so what is left with a
    /// donor behind it is a span whose bytes moved, and the groups inside it are
    /// worth comparing one at a time. A span no donor can speak to at all — past
    /// the end of every one of them, or held by none — has nothing to be
    /// compared against, and goes to the ordinary fetch.
    ///
    /// The object's right edge is the exception, and it is bounded to one span:
    /// a subtree cut short by the end of the object is not comparable *as a
    /// subtree* in the first place (§3.3), so the absence of a donor value there
    /// says nothing, and the groups under it descend.
    ///
    /// Blocking: one outboard walk per span per donor.
    fn unsettled_spans(
        &self,
        donors: &[Donor],
        leftover: &Proven,
        wanted: &ChunkRanges,
    ) -> Result<ChunkRanges> {
        let mut out = ChunkRanges::empty();
        let mut whole: Vec<ProvenSubtree> = Vec::new();
        for subtree in &leftover.subtrees {
            if subtree.groups <= 1 {
                // Already at the leaf level: round two would ask the same
                // question again.
                continue;
            }
            if subtree.whole {
                whole.push(*subtree);
            } else {
                out = out.union(&ChunkRanges::from_ranges([subtree.range()]));
            }
        }
        if whole.is_empty() {
            return Ok(out);
        }
        let spans: Vec<(u64, u64)> = whole.iter().map(|s| (s.start, s.groups)).collect();
        let mut comparable = vec![false; whole.len()];
        for donor in donors {
            if donor.root() == leftover.root {
                continue;
            }
            // Same rule as promotion: a donor that errors has nothing to say,
            // and saying so must not fail the fetch.
            let cvs = match self.store().subtree_cvs(&donor.root(), &spans) {
                Ok(cvs) => cvs,
                Err(e) => {
                    tracing::debug!(
                        donor = %donor.root(),
                        error = %e,
                        "a donor could not be read for the leaf round"
                    );
                    continue;
                }
            };
            for (index, cv) in cvs.iter().enumerate() {
                comparable[index] |= cv.is_some();
            }
        }
        for (subtree, comparable) in whole.iter().zip(comparable) {
            if comparable {
                out = out.union(&ChunkRanges::from_ranges([subtree.range()]));
            }
        }
        // Spans are whole 16 MiB subtrees, so a span that merely *overlaps*
        // what this fetch wants was being descended in full — buying a leaf
        // proof, and a round trip, for groups already in the bitmap, which
        // `promote` then discards. Clipping costs nothing and is what makes a
        // resumed fetch's second round proportional to what is still missing.
        Ok(out.intersect(wanted))
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
        report: &mut FetchReport,
    ) -> Result<Proven> {
        let mut providers = self.providers_for(root, 0, size.max(1))?;
        if providers.is_empty() {
            providers = self.ask_peers_for_providers(root, size).await?;
        }
        let mut remaining = ranges.clone();
        let mut proven = Proven::none(*root, size);
        for provider in providers {
            if remaining.is_empty() {
                break;
            }
            let ask = remaining.intersect(&provider.claims);
            if ask.is_empty() {
                continue;
            }
            report.providers_tried += 1;
            match self.proofs_from(&provider, root, size, &ask, level).await {
                Ok(outcome) => {
                    remaining = remaining.difference(&outcome.served);
                    proven.absorb(outcome.proven)?;
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
                    // The dial, for the same reason as the slice path above: a
                    // proof descent is also a walk of as many windows as the
                    // range needs.
                    let elapsed = started.elapsed().as_micros().min(i64::MAX as u128) as i64;
                    self.store().record_peer_sync(key, now_ns(), elapsed)?;
                    let outcome = client
                        .fetch_proof_into(self.store(), *root, size, ask, level)
                        .await?;
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

    /// Offers every donor the subtrees a proof round established, in order, and
    /// reports what is left over.
    ///
    /// All of it is disk work — outboard lookups, run clones, payload and
    /// bitmap commits — so all of it goes to the blocking pool (§10). The
    /// subtrees a donor supplied are struck off before the next donor is asked,
    /// and what comes back is what nobody could supply.
    async fn promote_round(
        &self,
        root: &Hash,
        donors: &[Donor],
        proven: Proven,
        report: &mut FetchReport,
    ) -> Result<Proven> {
        let node = self.clone();
        let root = *root;
        let donors = donors.to_vec();
        let (leftover, supplied) = crate::blocking::offload(move || {
            let mut proven = proven;
            let supplied = node.promote_blocking(&root, &donors, &mut proven)?;
            Ok((proven, supplied))
        })
        .await?;
        for (donor, got) in supplied {
            report.promoted = report.promoted.union(&got);
            match report.reused.iter_mut().find(|(had, _)| had == &donor) {
                Some((_, ranges)) => *ranges = ranges.union(&got),
                None => report.reused.push((donor, got)),
            }
        }
        Ok(leftover)
    }

    /// The body of [`Node::promote_round`], for callers already off the runtime.
    fn promote_blocking(
        &self,
        root: &Hash,
        donors: &[Donor],
        proven: &mut Proven,
    ) -> Result<Vec<(Donor, ChunkRanges)>> {
        let mut out = Vec::new();
        for donor in donors {
            if proven.is_empty() {
                break;
            }
            if donor.root() == *root {
                continue;
            }
            // A donor that errors is a donor with nothing to give, exactly like
            // one that matched nothing. Nothing in the descent may fail the
            // fetch — that is the rule the rest of this path already keeps, and
            // the proof rounds keep it per provider — but this call propagated,
            // so a raced size settlement or an ENOSPC while copying a subtree
            // failed a fetch that the ordinary slice path would have completed
            // over the network.
            let got = match self.store().promote(donor, proven, now_ns()) {
                Ok(got) => got,
                Err(e) => {
                    tracing::debug!(
                        root = %root,
                        donor = %donor.root(),
                        error = %e,
                        "a donor could not be promoted from: leaving its groups to the fetch"
                    );
                    continue;
                }
            };
            if got.is_empty() {
                continue;
            }
            proven
                .subtrees
                .retain(|subtree| !got.overlaps(subtree.start, subtree.end()));
            out.push((*donor, got));
        }
        Ok(out)
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
    ///
    /// Two things bound what one unresolvable root can cost. The walk stops at
    /// the first peer that names a provider, rather than asking everybody for
    /// hints it already has; and a root that nobody could name is remembered as
    /// a miss and left alone for a while (§6.3). Without either, a root nobody
    /// holds — an origin publishing `f:` records whose content hashes name
    /// nothing — is re-planned by every mirror pass and re-dials every peer in
    /// the cluster on each one, sequentially, so the victim's mirror can be
    /// made never to finish a pass and never to do the work it exists for.
    /// The miss expires, so a root that is published later is still picked up,
    /// and a root a local ad covers never reaches this at all.
    async fn ask_peers_for_providers(&self, root: &Hash, size: u64) -> Result<Vec<Provider>> {
        if self.provider_discovery_backed_off(root, now_ns()) {
            tracing::debug!(root = %root, "provider discovery backed off; not dialling");
            let known = self.providers_for(root, 0, size.max(1))?;
            if !known.is_empty() {
                // An ad reached this node some other way — head replication, or
                // another fetch's hints — so the miss is stale.
                self.clear_provider_miss(root);
            }
            return Ok(known);
        }
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
            // Storing a hint is a row, and the origin in one is a peer's word:
            // nothing in the answer establishes that the origin exists, and
            // nothing sweeps `blob_providers`. A hint about an origin this node
            // has no live binding for could never be dialled anyway
            // ([`Node::providers_for`] drops it), so it is not worth a row.
            //
            // The writes go to the blocking pool with every other database
            // path: this runs inside a fetch on a runtime worker, and a bounded
            // answer is still a row apiece (§10).
            let node = self.clone();
            let root = *root;
            learned += crate::blocking::offload(move || {
                let now = now_ns();
                let mut stored = 0usize;
                for (origin, ad) in ads {
                    if &origin == node.origin()
                        || node.store().keys_for_origin(&origin, now)?.is_empty()
                    {
                        continue;
                    }
                    node.store().put_provider(&root, &origin, &ad)?;
                    stored += 1;
                }
                Ok(stored)
            })
            .await?;
            // One peer that knows a holder is the answer; the rest of the
            // cluster has nothing to add that this fetch needs.
            if learned > 0 {
                break;
            }
        }
        if learned > 0 {
            tracing::debug!(hints = learned, "learned providers from peers");
        }
        let found = self.providers_for(root, 0, size.max(1))?;
        if found.is_empty() {
            self.note_provider_miss(root, now_ns());
        } else {
            self.clear_provider_miss(root);
        }
        Ok(found)
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
                    // Timed at the dial, not around the transfer. `fetch_into`
                    // walks the provider's whole share one window at a time, so
                    // timing it measured *how much was asked of the peer*, not
                    // how quick the peer is — a provider that successfully
                    // served a gigabyte recorded tens of seconds, worse than
                    // `FAILURE_PENALTY_US`, and so was ranked below a peer whose
                    // dial was refused. The ranking inverted under exactly the
                    // load it exists to spread.
                    let elapsed = started.elapsed().as_micros().min(i64::MAX as u128) as i64;
                    self.store().record_peer_sync(key, now_ns(), elapsed)?;
                    let got = client.fetch_into(self.store(), *root, size, ask).await?;
                    return Ok(got);
                }
                Err(e) => {
                    // A failed dial has to move the EWMA, or ranking is a
                    // one-way ratchet: latency was recorded only on success, so
                    // a peer that was once fast and is now a black hole kept its
                    // low EWMA and was therefore selected first on every
                    // subsequent fetch, forever, with nothing able to demote it.
                    let _ = self
                        .store()
                        .record_peer_failure(key, now_ns(), FAILURE_PENALTY_US);
                    last_error = Some(e);
                }
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
        // `take`, and the gateway's reads all get the descent for the price of
        // one `VersionSet` lookup (§3.5).
        //
        // A *ranged* read has to earn it, though. Promotion works a span at a
        // time and the two proof rounds come before the first byte, so a small
        // cold range would pay for both and then reuse 16 MiB to answer with a
        // few hundred: below one span the descent costs more than the read
        // (§4). Whole-object reads always descend.
        let whole = start == 0 && end == entry.size;
        let donors = match self.store().versions_for(space, path) {
            Ok(versions) if whole || end - start >= DESCENT_MIN_RANGE => {
                self.donors_for(&entry, &versions)?
            }
            Ok(_) => Vec::new(),
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

    /// Materializes an object the CAS already holds onto the filesystem
    /// (`docs/DELTA-SYNC.md` §3.5).
    ///
    /// The one way an object becomes a file. A mirror writing its copy (§7.2),
    /// `synch take` adopting a peer's version (§8), and the gateway's
    /// fetch-to-file all come through here, and all of them get the same
    /// guarantees: the target is old-or-new and never half, no staging residue
    /// is left behind on any path, and the object is never held in memory.
    ///
    /// The fetch has to have happened first — [`Node::fetch_all`] or
    /// [`Node::prepare_range`] — because this materializes what is verified and
    /// local, and refuses an object it does not hold whole rather than leaving
    /// a truncated file wearing a complete file's name.
    ///
    /// The payload is **cloned**, not copied. `FICLONE` on btrfs, XFS or
    /// bcachefs shares the CAS payload's extents with the new file: O(1),
    /// no data moved, and no second copy of the object on the disk until one of
    /// the two is written to. Where the ioctl cannot apply — the mirror is on a
    /// different filesystem from the CAS, ext4, a platform without it — the
    /// fallback is `std::fs::copy`, itself a kernel-side `copy_file_range` on
    /// Linux with no bounce through user space. Small objects live in the index
    /// rather than in a file (§6.2) and are written straight out of it.
    ///
    /// Returns which of those happened, which is what a mirror reports.
    pub async fn materialize_blob(
        &self,
        root: &Hash,
        size: u64,
        target: impl Into<std::path::PathBuf>,
    ) -> Result<CloneKind> {
        let node = self.clone();
        let root = *root;
        let target = target.into();
        crate::blocking::offload(move || node.materialize_blob_blocking(&root, size, &target)).await
    }

    /// The body of [`Node::materialize_blob`], for callers already off the
    /// runtime.
    pub(crate) fn materialize_blob_blocking(
        &self,
        root: &Hash,
        size: u64,
        target: &std::path::Path,
    ) -> Result<CloneKind> {
        let blob = self.store().blob(root)?.filter(|row| row.complete);
        let Some(blob) = blob else {
            return Err(EngineError::not_found(format!(
                "{root} is not held whole here, so there is nothing to write to \
                 {}",
                target.display()
            )));
        };
        if blob.size != size {
            return Err(EngineError::invalid(format!(
                "{root} is {} bytes here, and {size} were asked for",
                blob.size
            )));
        }
        // An inline blob has no payload file to share extents with, and is at
        // most one chunk group: it comes out of the index, verified on the way
        // through like any other read.
        if blob.inline.is_some() {
            let mut out = crate::scanner::Adoption::at(target)?;
            out.write(&self.store().read_all(root)?)?;
            out.commit()?;
            return Ok(CloneKind::Copy);
        }
        let (mut out, kind) =
            crate::scanner::Adoption::cloning(target, &self.store().blob_path(root))?;
        // The payload of a complete object is exactly its size; saying so costs
        // one syscall and means a payload that somehow is not cannot produce a
        // mirrored file that is not either.
        out.set_len(size)?;
        tracing::debug!(
            target = %target.display(),
            clone = ?kind,
            size,
            "materializing an object"
        );
        out.commit()?;
        Ok(kind)
    }
}

/// The smallest range a cold read runs the delta descent for
/// (`docs/DELTA-SYNC.md` §4).
///
/// Delta promotes at span granularity, and the two proof rounds are round trips
/// before the first byte: a one-byte `synch cat --range` of an object nobody
/// here holds would pay both of them and then promote up to 16 MiB to answer
/// with 1 byte. A whole-object fetch always descends — that is the case delta
/// exists for — and a ranged one only when the range is worth a span.
const DESCENT_MIN_RANGE: u64 = synch_core::AD_SPAN_GRANULARITY;

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

    /// A peer that answers `FindProviders` with a canned answer per root, and
    /// counts what it was asked.
    struct CountingPeer {
        origin: OriginId,
        key: synch_core::NodeId,
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        endpoint: iroh::Endpoint,
        task: tokio::task::JoinHandle<()>,
    }

    impl CountingPeer {
        /// Binds one that answers `known` with an ad for `holder` and every
        /// other root with nothing.
        async fn bind(name: &str, known: Hash, holder: OriginId) -> CountingPeer {
            let secret = iroh_base::SecretKey::generate();
            let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                .secret_key(secret.clone())
                .relay_mode(iroh::endpoint::RelayMode::Disabled)
                .clear_address_lookup()
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
                .unwrap()
                .alpns(vec![synch_core::ALPN_MPT.to_vec()])
                .bind()
                .await
                .unwrap();
            let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let serving = endpoint.clone();
            let counter = hits.clone();
            let task = tokio::spawn(async move {
                while let Some(incoming) = serving.accept().await {
                    let Ok(connection) = incoming.await else {
                        continue;
                    };
                    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                        let Ok(request) =
                            synch_net::frame::read_frame::<synch_core::MptMessage>(&mut recv).await
                        else {
                            break;
                        };
                        let synch_core::MptMessage::FindProviders { object_root } = request else {
                            break;
                        };
                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let ads = if object_root == known {
                            vec![(holder.clone(), BlobAd::complete(1000))]
                        } else {
                            Vec::new()
                        };
                        let _ = synch_net::frame::write_frame(
                            &mut send,
                            &synch_core::MptMessage::Providers { ads },
                        )
                        .await;
                        let _ = send.finish();
                    }
                }
            });
            CountingPeer {
                origin: OriginId::named(name, "x.example").unwrap(),
                key: secret.public(),
                hits,
                endpoint,
                task,
            }
        }

        fn asked(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::Relaxed)
        }

        /// Makes the node trust this peer and know where to reach it.
        fn known_to(&self, node: &Node) {
            node.store()
                .put_binding(&Binding {
                    origin: self.origin.clone(),
                    node_id: self.key,
                    source: BindingSource::Static,
                    domain: None,
                    note: None,
                    added_at: 0,
                    expires_at: None,
                })
                .unwrap();
            let addr = iroh::EndpointAddr::from_parts(
                self.endpoint.id(),
                self.endpoint
                    .bound_sockets()
                    .into_iter()
                    .map(iroh::TransportAddr::Ip),
            );
            node.store()
                .record_peer_seen(&self.key, Some(&crate::node::encode_addr(&addr)), now_ns())
                .unwrap();
        }

        async fn shutdown(self) {
            self.task.abort();
            self.endpoint.close().await;
        }
    }

    /// Provider discovery stops at the first answer and backs off after a
    /// fruitless round.
    ///
    /// Discovery is entered whenever no local ad covers a root, and it used to
    /// walk *every* dialable peer with no early exit and remember nothing. A
    /// content root nobody holds — an origin publishing `f:` records whose
    /// content hashes name nothing — was therefore re-planned by every mirror
    /// pass and re-dialled the whole cluster on each one, so the victim's
    /// mirror could be kept from ever completing a pass. `trust rm` does not
    /// help: what has been published is retained for `root_retention` (§6.3).
    #[tokio::test]
    async fn provider_discovery_stops_early_and_then_backs_off() {
        let (_d, node) = node().await;
        let held = Hash::new(b"an object somebody holds");
        let unheld = Hash::new(b"an object nobody holds");
        let (holder, _) = trust(&node, "holder");
        let first = CountingPeer::bind("peer-a", held, holder.clone()).await;
        let second = CountingPeer::bind("peer-b", held, holder.clone()).await;
        first.known_to(&node);
        second.known_to(&node);

        // One peer names a holder, so the rest of the cluster is not asked.
        let found = node.ask_peers_for_providers(&held, 1000).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin, holder);
        assert_eq!(
            first.asked() + second.asked(),
            1,
            "the walk stops at the first peer that answers"
        );
        assert!(!node.provider_discovery_backed_off(&held, now_ns()));

        // A root nobody can name costs one round of the cluster, once.
        let before = first.asked() + second.asked();
        assert!(node
            .ask_peers_for_providers(&unheld, 1000)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            first.asked() + second.asked() - before,
            2,
            "every peer is asked when none of them knows"
        );
        assert!(node.provider_discovery_backed_off(&unheld, now_ns()));

        let after = first.asked() + second.asked();
        for _ in 0..5 {
            assert!(node
                .ask_peers_for_providers(&unheld, 1000)
                .await
                .unwrap()
                .is_empty());
        }
        assert_eq!(
            first.asked() + second.asked(),
            after,
            "and asking again dials nobody while the miss is warm"
        );

        // The miss is a delay, not a verdict: it lets go on its own, and a
        // root that turns out to be held clears it outright.
        let past_it = now_ns() + 2 * crate::node::PROVIDER_MISS_MAX_BACKOFF.as_nanos() as i64;
        assert!(!node.provider_discovery_backed_off(&unheld, past_it));
        node.store()
            .put_provider(&unheld, &holder, &BlobAd::complete(1000))
            .unwrap();
        assert_eq!(
            node.ask_peers_for_providers(&unheld, 1000)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(!node.provider_discovery_backed_off(&unheld, now_ns()));

        first.shutdown().await;
        second.shutdown().await;
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
        // A never-measured peer ranks at the median of the measured ones, not
        // behind all of them: "unknown" is not "slow", and sorting it last is
        // self-fulfilling — nothing would ever measure it. Here that puts it
        // ahead of a peer measured at half a second.
        assert_eq!(ranked[1].origin, unknown);
        assert_eq!(ranked[2].origin, slow);
    }

    #[tokio::test]
    async fn a_failed_dial_demotes_a_peer_that_was_fast() {
        // Ranking has to move in both directions. Latency was recorded only on
        // success, so a peer that went dark kept its low EWMA and was chosen
        // first on every subsequent fetch, forever.
        let (_d, node) = node().await;
        let root = Hash::new(b"object");
        let (gone, gone_key) = trust(&node, "gone");
        let (steady, steady_key) = trust(&node, "steady");
        for origin in [&gone, &steady] {
            node.store()
                .put_provider(&root, origin, &BlobAd::complete(1000))
                .unwrap();
        }
        node.store().record_peer_sync(&gone_key, 0, 1_000).unwrap();
        node.store()
            .record_peer_sync(&steady_key, 0, 50_000)
            .unwrap();
        assert_eq!(
            node.providers_for(&root, 0, 1000).unwrap()[0].origin,
            gone,
            "the fast peer leads while it is working"
        );

        node.store()
            .record_peer_failure(&gone_key, 1, FAILURE_PENALTY_US)
            .unwrap();
        assert_eq!(
            node.providers_for(&root, 0, 1000).unwrap()[0].origin,
            steady,
            "and is demoted once it stops answering"
        );
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
    /// Requiring one means never finding it: an empty object counts as one
    /// chunk group, nothing encodes for that group, so every window comes back
    /// served-nothing and the fetch gives up — which is how `synch cat` and
    /// mirrors of empty files come to report that nobody can serve them.
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
            vec![Donor(previous), Donor(rival_root)],
            "the replaced version first, then the other version of the path"
        );
        assert!(
            !donors.contains(&Donor(new_root)),
            "the object being fetched is never its own donor"
        );
        node.shutdown().await.unwrap();
    }

    /// Round two looks inside the spans a donor can speak to, and nowhere else
    /// (`docs/DELTA-SYNC.md` §3.3).
    ///
    /// This is the F3 restriction, stated as the ranges round two would ask for.
    /// A span past the end of every donor — or held by none of them — has
    /// nothing for a leaf comparison to compare against, so descending into it
    /// would buy a leaf proof of the whole object to learn what round one
    /// already said. Getting this wrong is invisible in the result (the object
    /// still completes) and costs 1/256 of the object on the wire, which is
    /// precisely the thing delta sync exists to not spend.
    #[tokio::test]
    async fn the_leaf_round_descends_only_where_a_donor_can_answer() {
        let (_d, node) = node().await;
        const GROUP: usize = 16 * 1024;
        // A donor of eight groups. The new version is nineteen groups and a bit,
        // so spans 0..4 and 4..8 are inside the donor, spans 8..12 and 12..16
        // are past its end, and the span on the right edge is cut short by the
        // end of the object and is not a whole subtree at all.
        let donor_bytes: Vec<u8> = (0..8 * GROUP).map(|i| (i * 13 % 251) as u8).collect();
        let donor = node.store().ingest_bytes(&donor_bytes, now_ns()).unwrap();
        let new_root = Hash::new(b"the version being fetched");
        let size = (19 * GROUP + 700) as u64;

        let span = |start: u64, groups: u64, whole: bool| ProvenSubtree {
            start,
            groups,
            cv: synch_core::Cv([0u8; 32]),
            whole,
        };
        let round_one = Proven {
            root: new_root,
            size,
            subtrees: vec![
                span(0, 4, true),
                span(4, 4, true),
                span(8, 4, true),
                span(12, 4, true),
                // The right edge: cut short by the end of the object, so the
                // donor's silence there says nothing and the groups descend.
                span(16, 4, false),
            ],
        };

        let all = ChunkRanges::single(0, 20);
        let unsettled = node
            .unsettled_spans(&[Donor(donor)], &round_one, &all)
            .unwrap();
        assert_eq!(
            unsettled,
            ChunkRanges::from_ranges([
                synch_core::GroupRange::new(0, 8),
                synch_core::GroupRange::new(16, 20),
            ]),
            "only the spans the donor reaches, plus the object's right edge"
        );

        // With no donor at all, round two has nothing to look inside but that
        // right edge — the whole of the rest goes straight to the fetch.
        let unsettled = node.unsettled_spans(&[], &round_one, &all).unwrap();
        assert_eq!(unsettled, ChunkRanges::single(16, 20));

        // Spans are whole subtrees, so one that merely overlaps what this fetch
        // wants would otherwise be descended in full — buying a leaf proof, and
        // a round trip, for groups already held. The result is clipped to what
        // was asked for.
        let wanted = ChunkRanges::single(5, 18);
        let unsettled = node
            .unsettled_spans(&[Donor(donor)], &round_one, &wanted)
            .unwrap();
        assert_eq!(
            unsettled,
            ChunkRanges::from_ranges([
                synch_core::GroupRange::new(5, 8),
                synch_core::GroupRange::new(16, 18),
            ]),
            "round two looks only inside what is still wanted"
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
            .fetch_all_from(&root, 100_000, &[Donor(donor)])
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
        // Measured, and slower than every ghost, so it deterministically ranks
        // last. It used to land there for being *unmeasured*, which no longer
        // sorts to the back — and the tiebreak among equals is random now, by
        // §6.4 — so the ordering this test depends on has to be stated rather
        // than inherited.
        node.store()
            .record_peer_sync(&holder.node_id(), 0, 100_000)
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
