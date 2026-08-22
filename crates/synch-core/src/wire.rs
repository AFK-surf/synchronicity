//! Wire schemas for the two ALPNs (§5.1, §6.4).
//!
//! All messages are length-framed `postcard` on QUIC streams; the framing lives
//! in `synch-net`. This module owns the schemas so they can be round-trip
//! tested without networking.

use serde::{Deserialize, Serialize};

use crate::{
    hash::Hash,
    head::{HeadSummary, SignedHead},
    origin::{NodeId, OriginId},
    record::BlobAd,
    record::MAX_DELEGATION_SPACES,
};

/// ALPN for metadata anti-entropy (§5).
pub const ALPN_MPT: &[u8] = b"sync/mpt/1";
/// ALPN for content transfer (§6.4).
pub const ALPN_BLOB: &[u8] = b"sync/blob/1";

/// Protocol version carried in `Hello`.
///
/// postcard numbers enum variants by position, so the message shapes *are* the
/// protocol: reordering one changes the wire. `Hello`'s check is the whole
/// compatibility story — a peer on another version is refused, not negotiated
/// with.
pub const PROTO_VERSION: u16 = 3;

/// Maximum number of hashes per `GetNodes`/`GetValues` batch (§5.1).
pub const MAX_BATCH: usize = 256;

/// The most nibble-path bytes one `GetNodes`/`GetValues` batch may carry.
///
/// Set to exactly what a legal batch can carry — [`MAX_BATCH`] paths of the
/// deepest key [`MAX_KEY_LEN`][crate::MAX_KEY_LEN] allows — so no honest
/// requester can build a batch its peer refuses. A tighter figure would be a
/// wedge: the walk is deterministic, so an over-cap batch is over it on every
/// retry and two honest nodes would stop syncing for good.
pub const MAX_BATCH_PATH_BYTES: usize = MAX_BATCH * 2 * crate::MAX_KEY_LEN;

/// An upper bound on the tree nodes a proof over `ranges` at `level` emits.
///
/// A proof stopping at `level` names one subtree per `2^level` groups; the
/// interior above `n` subtrees of one run numbers at most `n - 1`, and each
/// disjoint range costs a root-to-range path no deeper than the 64 levels a
/// `u64` group index can address. So `n + ranges * 64` bounds it. The looser
/// `2n + ranges * 64` is wrong in a way that matters, because the provider
/// *refuses* an over-budget request rather than truncating: it puts the
/// span-level round of a 100 GB object (~5 960 subtrees, what `MAX_PROOF_NODES`
/// is sized to carry in one exchange) over the budget, splitting the one round
/// the whole descent depends on being atomic.
///
/// An over-estimate on purpose: the provider walks `requested ∩ what it holds`,
/// which the requester cannot predict, but a subset never emits more nodes than
/// the whole — so a window sized for a full holder fits for every holder.
pub fn proof_nodes_upper_bound(ranges: &ChunkRanges, level: u8) -> u64 {
    /// The deepest a root-to-range path can be for a `u64` group index.
    const MAX_PATH: u64 = 64;
    let per_subtree = 1u64 << level.min(63);
    let subtrees = ranges.count().div_ceil(per_subtree);
    subtrees.saturating_add((ranges.range_count() as u64).saturating_mul(MAX_PATH))
}

/// How many heads or head summaries one message may carry (§5.1).
///
/// The costlier counterpart of [`MAX_BATCH`]: each `SignedHead` in a `Heads`
/// frame buys an Ed25519 verification and a `head_history` insert, and each
/// origin in a `HeadsWant` buys a query — bounded only by the frame, one 16 MiB
/// message is worth six figures of both. §12 sizes a cluster at N ≤ 100 origins
/// and one head per origin per slot, so a legitimate exchange names tens; this
/// leaves two orders of magnitude of headroom and still cuts the amplification.
pub const MAX_HEADS_PER_MESSAGE: usize = 4096;

/// Maximum accepted length of a single framed message, in bytes — the per-stream
/// memory bound against a hostile peer (§12, DoS).
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// The most chunk groups one slice exchange carries — 8 MiB of payload.
///
/// A bao slice is encoded into memory whole on both sides and travels in one
/// frame, so an unbounded `GetSlice` is two problems at once: an object larger
/// than [`MAX_FRAME_LEN`] could never be served, and a peer could make a
/// provider allocate an object-sized buffer just by asking (§6.4, §12).
/// Requests are therefore served a window at a time and the requester loops.
pub const MAX_SLICE_GROUPS: u64 = 512;

/// The most interior tree nodes one proof exchange carries — 512 KiB of hashes.
///
/// A proof is a slice with the payload left out, bounded for the same reason
/// (§12): built in memory and traveling in one frame, its allocation size must
/// not be the requester's to choose. It cannot be bounded by group count alone
/// — the point of the span-level round is that one exchange describes a huge
/// range cheaply, and clamping to [`MAX_SLICE_GROUPS`] would turn the 381 KB
/// descent of a 100 GB object into twelve thousand round trips
/// (`docs/DELTA-SYNC.md` §3.3). Nodes are what a proof costs, so nodes are what
/// it is counted in; `ProofEnd` reports where anything larger stopped.
pub const MAX_PROOF_NODES: u64 = 8192;

/// The wire size of one proof node: a pair of 32-byte chaining values.
pub const PROOF_NODE_LEN: usize = 64;

/// The most ranges one [`ChunkRanges`] may carry across the wire.
///
/// Set operations are quadratic in the number of ranges, so a request built
/// from a million singleton ranges is a CPU exhaustion vector even though it
/// fits in a frame. No honest request needs near this many: a window is
/// [`MAX_SLICE_GROUPS`] groups, so it cannot describe more disjoint runs.
pub const MAX_RANGES: usize = 4096;

/// How many provider hints one [`MptMessage::Providers`] may carry (§5.1).
///
/// A hint is unverified by design — content is hash-verified whatever it said —
/// but taking one still costs a `blob_providers` row, and `OriginId` arrives
/// without anything vouching the origin exists, so an unbounded answer buys the
/// responder's peer a table of fabricated origins for one small request. §12
/// sizes a cluster at N ≤ 100 origins, one ad per origin, so a legitimate
/// answer names tens.
pub const MAX_PROVIDER_ADS: usize = 256;

/// Decodes a `Vec` that refuses to grow past `N` elements, rather than checking
/// its length once it is already in memory.
///
/// Every capped `MptMessage` field uses this, because a check on the
/// materialized `Vec` comes too late — in both senses. The memory: a 16 MiB
/// frame is ~524 000 `NodeId`s or ~117 000 `SignedHead`s, all resident before a
/// length check can look at them. The CPU, which is the half that hurt: a
/// `NodeId` decodes through an Edwards decompression, so that frame cost 2.4 s
/// of runtime-worker time — measured — before `check_heads` could reject it,
/// and the decode runs inline on the connection task, not the blocking pool.
/// §12 promises "sanity bounds that cap the cost of any *single* malformed or
/// extreme message"; a cap that fires after the work is not one. Refused
/// outright rather than truncated: a truncated request is a different request,
/// and a truncated answer silently misreports what a peer served.
fn bounded_vec<'de, D, T, const N: usize>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T, const N: usize>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Visitor<T, N> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {N} elements")
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Vec<T>, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            // Never `with_capacity(size_hint)`: the hint is the peer's.
            let mut out: Vec<T> = Vec::new();
            while let Some(item) = seq.next_element::<T>()? {
                if out.len() >= N {
                    return Err(serde::de::Error::custom(format!(
                        "a sequence past the {N} limit"
                    )));
                }
                out.push(item);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(Visitor::<T, N>(std::marker::PhantomData))
}

/// The longest error text a peer may send.
///
/// Generous for a sentence naming what went wrong, and small enough that a
/// stream of them is not a way to write to this node's log.
pub const MAX_ERROR_REASON_LEN: usize = 1024;

/// Decodes an error reason that refuses to grow past [`MAX_ERROR_REASON_LEN`].
///
/// Truncated rather than refused, unlike a request field: the reason is the only
/// account of the failure the peer will give, and losing it entirely to punish
/// its length would leave the caller with less than a clipped sentence.
fn bounded_reason<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
        type Value = String;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {MAX_ERROR_REASON_LEN} bytes of text")
        }

        // Copies only what it keeps, so an over-long reason never becomes an
        // allocation of its own size.
        fn visit_str<E: serde::de::Error>(self, text: &str) -> std::result::Result<String, E> {
            if text.len() <= MAX_ERROR_REASON_LEN {
                return Ok(text.to_string());
            }
            let cut = (0..=MAX_ERROR_REASON_LEN)
                .rev()
                .find(|i| text.is_char_boundary(*i))
                .unwrap_or(0);
            let mut out = String::with_capacity(cut + '…'.len_utf8());
            out.push_str(&text[..cut]);
            out.push('…');
            Ok(out)
        }
    }

    deserializer.deserialize_str(Visitor)
}

/// What a peer declares it will serve the peer it is talking to (§5.5).
///
/// The declaration is what a delegated node learns its scope from: the
/// peer's view of the caller's key, read from the same `d:` records the
/// caller will materialize out of the trie. Three-valued on purpose — the
/// old encoding collapsed the first two into `None`, and the difference is
/// the whole of the revocation story: a peer that has *no* binding for the
/// key (revoked) must not be mistaken for a peer that has a rooted one
/// (promoted to a full member).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeclaredScope {
    /// No live binding for the peer's key: it is not in this node's view of
    /// the zone at all.
    Untrusted,
    /// A live rooted binding: the peer may read anything.
    Unrestricted,
    /// Live delegations only: confined to these spaces.
    Confined(#[serde(deserialize_with = "bounded_vec::<_, _, MAX_DELEGATION_SPACES>")] Vec<String>),
}

impl Default for DeclaredScope {
    /// No statement: a peer that said nothing is read as holding no binding,
    /// which is the fail-closed reading.
    fn default() -> Self {
        DeclaredScope::Untrusted
    }
}

/// A message on the `sync/mpt/1` ALPN (§5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MptMessage {
    /// Head gossip, push-pull. Sent first on the head-gossip stream.
    Hello {
        /// Protocol version.
        proto: u16,
        /// The sender's head summaries.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_HEADS_PER_MESSAGE>")]
        heads: Vec<HeadSummary>,
        /// What the sender will serve the peer it is talking to (§5.5).
        ///
        /// How a delegated node learns what it may ask for: its scope lives in
        /// the delegating origin's trie, which it cannot read until it knows
        /// its scope, so the peer serving it says, in the exchange that opens
        /// every session. Advisory in the only direction that matters — the
        /// responder enforces the same scope on every request regardless, so a
        /// wrong value can only make a peer ask for less, never more — and it
        /// is adopted only from a peer this node holds a *rooted* binding for,
        /// so a delegate cannot narrow a member that admitted it.
        scope: DeclaredScope,
    },
    /// "Yours is newer, send the full signed heads for these origins."
    HeadsWant {
        /// Origins whose full signed heads are wanted.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_HEADS_PER_MESSAGE>")]
        origins: Vec<OriginId>,
    },
    /// Full signed heads, in response to `HeadsWant` or `Hello`.
    Heads {
        /// The signed heads.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_HEADS_PER_MESSAGE>")]
        heads: Vec<SignedHead>,
    },
    /// Reactive push, sent on any head change (§5.3).
    HeadPush {
        /// The changed head.
        head: SignedHead,
    },
    /// Request trie nodes, each with the position it is claimed to occupy.
    ///
    /// At most [`MAX_BATCH`] per batch, and at most [`MAX_BATCH_PATH_BYTES`]
    /// of paths across the batch. The position is what a responder authorizes
    /// on, and it has to be: a hash carries no position and none can be
    /// recovered from it, since structural sharing lets one node sit under
    /// several prefixes. A responder serving a scoped peer descends `path`
    /// from `root` in its own store and compares it against the peer's scope;
    /// the hash is the integrity assertion checked on arrival (§5.5). Between
    /// unscoped peers the path is carried and ignored.
    GetNodes {
        /// The root the paths are relative to. Any root the responder holds.
        root: Hash,
        /// `(nibble path, wanted node hash)` pairs.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_BATCH>")]
        wants: Vec<(Vec<u8>, Hash)>,
    },
    /// Trie nodes, plus the subset the responder did not have, plus the subset
    /// it holds and may not show.
    Nodes {
        /// `(hash, encoded node)` pairs.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_BATCH>")]
        nodes: Vec<(Hash, Vec<u8>)>,
        /// Hashes the responder did not have.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_BATCH>")]
        missing: Vec<Hash>,
        /// Positions the requester may not see past (§5.5).
        ///
        /// Distinct from `missing`, and the distinction is what keeps a scoped
        /// peer from wedging: `missing` says "ask again", while this says
        /// "there is nothing here for you, ever". A trie compresses, so a node
        /// on the spine can carry key material running out of the peer's scope
        /// — the name of an ungranted space, or a whole leaf record. Withheld
        /// silently, the peer could not tell an absent node from a refused one
        /// and would retry until its head was abandoned.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_BATCH>")]
        redacted: Vec<Hash>,
    },
    /// Request out-of-line trie value payloads, with the position of the node
    /// that holds each one.
    GetValues {
        /// The root the paths are relative to.
        root: Hash,
        /// `(nibble path of the holding node, wanted value hash)` pairs.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_BATCH>")]
        wants: Vec<(Vec<u8>, Hash)>,
    },
    /// Out-of-line trie values, plus the subset the responder did not have.
    Values {
        /// `(hash, value bytes)` pairs.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_BATCH>")]
        values: Vec<(Hash, Vec<u8>)>,
        /// Hashes the responder did not have.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_BATCH>")]
        missing: Vec<Hash>,
    },
    /// Ask a peer which origins advertise an object. Hints are unverified (§5.1).
    FindProviders {
        /// The object root being looked up.
        object_root: Hash,
    },
    /// Unverified provider hints. At most [`MAX_PROVIDER_ADS`] per answer.
    Providers {
        /// `(origin, ad)` pairs.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_PROVIDER_ADS>")]
        ads: Vec<(OriginId, BlobAd)>,
    },
    /// An error response, used instead of dropping a stream silently.
    Error {
        /// A short human-readable reason, bounded while decoding — the one
        /// field a peer could otherwise fill to [`MAX_FRAME_LEN`].
        #[serde(deserialize_with = "bounded_reason")]
        reason: String,
    },
    /// "Which device keys do you currently hold bound for this origin?"
    ///
    /// Purely informational within the trusted cluster: what `synch key ls`
    /// aggregates to tell an operator whether a rotation's new key has
    /// propagated (§3.4, §5.1). Appended after [`MptMessage::Error`] because
    /// postcard numbers variants by position — a new variant only ever goes on
    /// the end.
    GetBindings {
        /// The origin being asked about.
        origin: OriginId,
    },
    /// The device keys the answering peer holds bound for an origin.
    BindingsFor {
        /// The origin asked about.
        origin: OriginId,
        /// The bound device keys, in the peer's own order.
        #[serde(deserialize_with = "bounded_vec::<_, _, MAX_HEADS_PER_MESSAGE>")]
        keys: Vec<NodeId>,
    },
}

/// A half-open range of 16 KiB chunk groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GroupRange {
    /// First group index, inclusive.
    pub start: u64,
    /// Last group index, exclusive.
    pub end: u64,
}

impl GroupRange {
    /// Builds a range, normalizing an inverted range to empty.
    pub fn new(start: u64, end: u64) -> Self {
        GroupRange {
            start,
            end: end.max(start),
        }
    }

    /// True if the range covers no groups.
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// A set of chunk-group ranges, in 16 KiB group units (§6.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChunkRanges {
    /// Sorted, non-overlapping ranges.
    pub ranges: Vec<GroupRange>,
}

/// Decoding stops at [`MAX_RANGES`] rather than checking afterwards, and
/// normalizes.
///
/// Both sides refuse a set past [`MAX_RANGES`], because the set operations
/// under it are quadratic in the number of ranges — and a check on the
/// materialized `Vec` comes too late: a `GroupRange` of two zeroes is two
/// postcard bytes, so a frame at [`MAX_FRAME_LEN`] decodes to ~8.4 million
/// elements, ~134 MB resident — an eightfold heap amplification over the frame
/// already accepted, per stream, on `GetSlice` and `GetProof`. Refused
/// outright rather than truncated: unlike a `BlobAd`'s spans, where a short
/// tail is a weaker claim and costs a re-fetch, a truncated *request* is a
/// different request, and a truncated `served` would silently overstate what a
/// provider withheld.
///
/// The *normalizing* is the other half. "Sorted, non-overlapping" is documented
/// on the field and required by [`ChunkRanges::overlaps`], `covers` and
/// `difference`, all of which walk the ranges assuming order — and the field is
/// `pub` and the decoder is a trust boundary. Every call site happened to
/// normalize first, so the invariant held by convention, across three crates,
/// on data a peer supplies. Establishing it here makes it a property of the
/// type: a set that has been decoded is a set the operations may be run on.
impl<'de> Deserialize<'de> for ChunkRanges {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            ranges: BoundedRanges,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(ChunkRanges::from_ranges(raw.ranges.0))
    }
}

/// A range list that refuses to grow past [`MAX_RANGES`] while decoding.
struct BoundedRanges(Vec<GroupRange>);

impl<'de> Deserialize<'de> for BoundedRanges {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = BoundedRanges;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "at most {MAX_RANGES} chunk-group ranges")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<BoundedRanges, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // Never `with_capacity(size_hint)`: the hint is the peer's.
                let mut ranges: Vec<GroupRange> = Vec::new();
                while let Some(range) = seq.next_element::<GroupRange>()? {
                    if ranges.len() >= MAX_RANGES {
                        return Err(serde::de::Error::custom(format!(
                            "a range set past the {MAX_RANGES} limit"
                        )));
                    }
                    ranges.push(range);
                }
                Ok(BoundedRanges(ranges))
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}

impl ChunkRanges {
    /// An empty set.
    pub fn empty() -> Self {
        ChunkRanges::default()
    }

    /// A set covering a single range.
    pub fn single(start: u64, end: u64) -> Self {
        let r = GroupRange::new(start, end);
        if r.is_empty() {
            ChunkRanges::empty()
        } else {
            ChunkRanges { ranges: vec![r] }
        }
    }

    /// Builds a normalized set from arbitrary ranges: sorted and merged.
    pub fn from_ranges(ranges: impl IntoIterator<Item = GroupRange>) -> Self {
        let mut v: Vec<GroupRange> = ranges.into_iter().filter(|r| !r.is_empty()).collect();
        v.sort_unstable();
        let mut out: Vec<GroupRange> = Vec::with_capacity(v.len());
        for r in v {
            match out.last_mut() {
                Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
                _ => out.push(r),
            }
        }
        ChunkRanges { ranges: out }
    }

    /// True if the set covers no groups.
    pub fn is_empty(&self) -> bool {
        self.ranges.iter().all(GroupRange::is_empty)
    }

    /// Total number of groups covered. Saturating: a `GetSlice` range arrives
    /// from a peer unbounded, so `[0, u64::MAX)` must not panic or wrap here.
    pub fn count(&self) -> u64 {
        self.ranges
            .iter()
            .map(|r| r.end.saturating_sub(r.start))
            .fold(0u64, u64::saturating_add)
    }

    /// True if `group` is covered.
    pub fn contains(&self, group: u64) -> bool {
        self.ranges
            .iter()
            .any(|r| r.start <= group && group < r.end)
    }

    /// True if any part of `[start, end)` is covered.
    ///
    /// The question a tree descent asks at every node, answered by a binary
    /// search over the (sorted, disjoint) ranges rather than by building an
    /// intersection: a proof walk visits thousands of nodes, and the quadratic
    /// version is a denial of service with extra steps (§12).
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return false;
        }
        // The first range that could reach `start` is the first whose end is
        // past it; everything before that lies entirely to the left.
        let index = self.ranges.partition_point(|r| r.end <= start);
        self.ranges.get(index).is_some_and(|r| r.start < end)
    }

    /// True if the whole of `[start, end)` is covered.
    pub fn covers(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return true;
        }
        let index = self.ranges.partition_point(|r| r.end <= start);
        self.ranges
            .get(index)
            .is_some_and(|r| r.start <= start && end <= r.end)
    }

    /// The intersection of two sets.
    ///
    /// A linear merge over both sides, which the sorted-and-disjoint invariant
    /// permits — a nested loop over the same two sets costs `n * m`, and a
    /// range set arrives off the wire: `served` in a `SliceEnd`/`ProofEnd` is
    /// bounded only by the frame, so a provider could answer with a million
    /// singleton ranges and make the requester spend that on a set operation
    /// it runs on a runtime worker.
    ///
    /// Two properties callers rely on, stated because one is load-bearing at a
    /// trust boundary. Every emitted group is in *both* inputs — each output
    /// range is the overlap of an actual pair — so the result is a subset of
    /// `other` **whatever order `self` arrived in**, which is what makes
    /// `check_served` safe against a provider's unsorted `served`: containment
    /// is structural, not a consequence of sortedness. And the result is
    /// normalized (built through [`ChunkRanges::from_ranges`]), so a malformed
    /// input cannot propagate past here: a malformed `self` can make the
    /// answer too *small* — a retry — never too large.
    pub fn intersect(&self, other: &ChunkRanges) -> ChunkRanges {
        let mut out = Vec::new();
        let (mut i, mut j) = (0usize, 0usize);
        while i < self.ranges.len() && j < other.ranges.len() {
            let (a, b) = (&self.ranges[i], &other.ranges[j]);
            let start = a.start.max(b.start);
            let end = a.end.min(b.end);
            if start < end {
                out.push(GroupRange { start, end });
            }
            // Retire whichever ends first; the other may still overlap what
            // comes next on this side.
            if a.end <= b.end {
                i += 1;
            } else {
                j += 1;
            }
        }
        ChunkRanges::from_ranges(out)
    }

    /// The part of `self` not covered by `other`. Linear, like [`ChunkRanges::intersect`].
    pub fn difference(&self, other: &ChunkRanges) -> ChunkRanges {
        let mut out = Vec::new();
        let mut j = 0usize;
        for a in &self.ranges {
            let mut cursor = a.start;
            // Skip anything entirely before this range. `other` is sorted, so
            // the cursor into it only ever moves forward across the whole loop.
            while j < other.ranges.len() && other.ranges[j].end <= cursor {
                j += 1;
            }
            let mut k = j;
            while k < other.ranges.len() && other.ranges[k].start < a.end {
                let b = &other.ranges[k];
                if b.start > cursor {
                    out.push(GroupRange {
                        start: cursor,
                        end: b.start.min(a.end),
                    });
                }
                cursor = cursor.max(b.end);
                if cursor >= a.end {
                    break;
                }
                k += 1;
            }
            if cursor < a.end {
                out.push(GroupRange {
                    start: cursor,
                    end: a.end,
                });
            }
        }
        ChunkRanges::from_ranges(out)
    }

    /// The union of two sets.
    pub fn union(&self, other: &ChunkRanges) -> ChunkRanges {
        ChunkRanges::from_ranges(self.ranges.iter().chain(other.ranges.iter()).copied())
    }

    /// The first `groups` groups of this set, in order — how a fetch walks a
    /// large object: one bounded window per exchange ([`MAX_SLICE_GROUPS`]).
    pub fn take(&self, groups: u64) -> ChunkRanges {
        let mut out = Vec::new();
        let mut budget = groups;
        for range in &self.ranges {
            if budget == 0 {
                break;
            }
            let len = range.end.saturating_sub(range.start);
            if len <= budget {
                out.push(*range);
                budget -= len;
            } else {
                out.push(GroupRange::new(range.start, range.start + budget));
                break;
            }
        }
        ChunkRanges { ranges: out }
    }

    /// How many ranges the set is made of.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }
}

/// A message on the `sync/blob/1` ALPN (§6.4) — nothing but these plus the raw
/// bao slice and proof bytes (§5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobMessage {
    /// Request a verified bao slice.
    GetSlice {
        /// The object root.
        root: Hash,
        /// Wanted ranges, in 16 KiB group units.
        ranges: ChunkRanges,
    },
    /// Terminates a slice response with what the provider actually had.
    SliceEnd {
        /// The ranges actually served.
        served: ChunkRanges,
    },
    /// Request the tree over a range without its bytes
    /// (`docs/DELTA-SYNC.md` §3.1).
    ///
    /// The response is the interior hash pairs on the paths from the root to
    /// `ranges`, in pre-order, descending no deeper than `level` — exactly a
    /// bao slice with the payload left out: 64 bytes per node rather than
    /// 16 KiB per group, so a requester can ask "what does the new version's
    /// tree look like here?" without paying for bytes it may well already have.
    ///
    /// `level` is in chunk-group units: `level = n` stops at subtrees of `2^n`
    /// groups, so `level = 0` yields every leaf group's chaining value and
    /// [`AD_SPAN_LEVEL`](crate::AD_SPAN_LEVEL) one per ad span. Appended after
    /// [`BlobMessage::SliceEnd`] because postcard numbers variants by position.
    GetProof {
        /// The object root.
        root: Hash,
        /// The ranges whose tree is wanted, in 16 KiB group units.
        ranges: ChunkRanges,
        /// How deep to descend, in group units.
        level: u8,
    },
    /// Terminates a proof response with the ranges it actually covers — how the
    /// requester learns where an answer past [`MAX_PROOF_NODES`] stopped and
    /// where its next request starts, the same shape as [`BlobMessage::SliceEnd`] (§6.4).
    ProofEnd {
        /// The ranges the proof covers.
        served: ChunkRanges,
    },
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;
    use crate::record::BlobAd;

    #[test]
    fn mpt_messages_round_trip() {
        let key = SecretKey::generate();
        let origin = OriginId::named("nas", "x.example").unwrap();
        let head = SignedHead::sign(&key, origin.clone(), 3, Hash::new(b"r"), 9);

        let msgs = vec![
            MptMessage::Hello {
                proto: PROTO_VERSION,
                heads: vec![HeadSummary {
                    origin: origin.clone(),
                    seq: 3,
                    root: Hash::new(b"r"),
                    complete: true,
                }],
                scope: DeclaredScope::Confined(vec!["photos".into()]),
            },
            MptMessage::HeadsWant {
                origins: vec![origin.clone()],
            },
            MptMessage::Heads {
                heads: vec![head.clone()],
            },
            MptMessage::HeadPush { head },
            MptMessage::GetNodes {
                root: Hash::new(b"r"),
                wants: vec![
                    (vec![6, 6], Hash::new(b"a")),
                    (vec![6, 6, 3], Hash::new(b"b")),
                ],
            },
            MptMessage::Nodes {
                nodes: vec![(Hash::new(b"a"), vec![1, 2, 3])],
                missing: vec![Hash::new(b"b")],
                redacted: vec![Hash::new(b"c")],
            },
            MptMessage::GetValues {
                root: Hash::new(b"r"),
                wants: vec![(vec![6, 6], Hash::new(b"v"))],
            },
            MptMessage::Values {
                values: vec![(Hash::new(b"v"), vec![4, 5])],
                missing: vec![],
            },
            MptMessage::FindProviders {
                object_root: Hash::new(b"o"),
            },
            MptMessage::Providers {
                ads: vec![(origin.clone(), BlobAd::complete(10))],
            },
            MptMessage::Error {
                reason: "nope".into(),
            },
            MptMessage::GetBindings {
                origin: origin.clone(),
            },
            MptMessage::BindingsFor {
                origin,
                keys: vec![SecretKey::generate().public()],
            },
        ];
        for m in msgs {
            let bytes = postcard::to_stdvec(&m).unwrap();
            assert_eq!(postcard::from_bytes::<MptMessage>(&bytes).unwrap(), m);
        }
    }

    #[test]
    fn blob_messages_round_trip() {
        for m in [
            BlobMessage::GetSlice {
                root: Hash::new(b"o"),
                ranges: ChunkRanges::single(0, 4),
            },
            BlobMessage::SliceEnd {
                served: ChunkRanges::single(0, 2),
            },
            BlobMessage::GetProof {
                root: Hash::new(b"o"),
                ranges: ChunkRanges::single(0, 4096),
                level: 10,
            },
            BlobMessage::ProofEnd {
                served: ChunkRanges::single(0, 1024),
            },
        ] {
            let bytes = postcard::to_stdvec(&m).unwrap();
            assert_eq!(postcard::from_bytes::<BlobMessage>(&bytes).unwrap(), m);
        }
    }

    #[test]
    fn chunk_ranges_take_bounds_a_window() {
        let r = ChunkRanges::from_ranges([GroupRange::new(0, 4), GroupRange::new(10, 20)]);
        assert_eq!(r.take(0), ChunkRanges::empty());
        assert_eq!(r.take(3).ranges, vec![GroupRange::new(0, 3)]);
        // A window that spans a gap keeps both sides and splits the second.
        assert_eq!(
            r.take(6).ranges,
            vec![GroupRange::new(0, 4), GroupRange::new(10, 12)]
        );
        // Asking for more than there is yields everything, not a wider set.
        assert_eq!(r.take(1000), r);
        assert_eq!(r.take(6).count(), 6);
    }

    #[test]
    fn chunk_ranges_normalize_and_set_ops() {
        // Normalization: unsorted and inverted input is sorted and merged.
        let r = ChunkRanges::from_ranges([
            GroupRange::new(5, 8),
            GroupRange::new(0, 3),
            GroupRange::new(3, 4),
            GroupRange::new(9, 9),
        ]);
        assert_eq!(r.ranges, vec![GroupRange::new(0, 4), GroupRange::new(5, 8)]);
        assert_eq!(r.count(), 7);
        assert!(r.contains(0));
        assert!(!r.contains(4));

        let a = ChunkRanges::from_ranges([GroupRange::new(0, 10)]);
        let b = ChunkRanges::from_ranges([GroupRange::new(3, 5), GroupRange::new(8, 20)]);
        assert_eq!(
            a.intersect(&b).ranges,
            vec![GroupRange::new(3, 5), GroupRange::new(8, 10)]
        );
        assert_eq!(
            a.difference(&b).ranges,
            vec![GroupRange::new(0, 3), GroupRange::new(5, 8)]
        );
        assert_eq!(a.union(&b).ranges, vec![GroupRange::new(0, 20)]);
        assert!(a.difference(&a).is_empty());
        assert!(ChunkRanges::empty().is_empty());
    }

    #[test]
    fn overlap_and_coverage_answer_without_building_a_set() {
        let r = ChunkRanges::from_ranges([GroupRange::new(2, 5), GroupRange::new(10, 20)]);
        assert!(r.overlaps(0, 3));
        assert!(
            r.overlaps(4, 12),
            "a window spanning the gap still overlaps"
        );
        assert!(r.overlaps(19, 100));
        assert!(!r.overlaps(5, 10), "the gap itself does not");
        assert!(!r.overlaps(20, 21));
        assert!(!r.overlaps(7, 7), "an empty window overlaps nothing");

        assert!(r.covers(2, 5));
        assert!(r.covers(11, 12));
        assert!(!r.covers(4, 11), "coverage is not satisfied across a gap");
        assert!(!r.covers(0, 3));
        assert!(r.covers(9, 9), "an empty window is covered by anything");
        assert!(!ChunkRanges::empty().overlaps(0, u64::MAX));
    }
}

#[cfg(test)]
mod bounded_decode_tests {
    use super::*;

    /// Every capped field refuses an over-long sequence *while decoding*, not
    /// after: the responder's `check_heads`/`check_batch` calls run after
    /// `read_frame` has already deserialized the message, so a 16 MiB frame of
    /// `SignedHead`s or `NodeId`s bought the sender seconds of the victim's
    /// runtime-worker time — a `NodeId` decodes through an Edwards
    /// decompression — for the price of an upload. The cap fires on element
    /// `N + 1`. postcard collapses a visitor's custom message into its own
    /// opaque `Serde Deserialization Error`, so the assertion is that decoding
    /// fails at all; the at-cap control below says the failure is the cap, not
    /// the encoding.
    fn refuses(msg: &MptMessage) {
        assert!(
            postcard::from_bytes::<MptMessage>(&postcard::to_stdvec(msg).unwrap()).is_err(),
            "a sequence past its cap must not decode"
        );
    }

    #[test]
    fn a_sequence_past_its_cap_is_refused_while_decoding() {
        let wants = |n: usize| -> Vec<(Vec<u8>, Hash)> {
            (0..n)
                .map(|i| (vec![0u8, 1], Hash([i as u8; 32])))
                .collect()
        };
        let origin = || OriginId::Key(iroh_base::SecretKey::generate().public());

        // At-cap control: a batch at exactly MAX_BATCH decodes, so the failures
        // below are the caps, not the encoding.
        let at_cap = MptMessage::GetNodes {
            root: Hash([0u8; 32]),
            wants: wants(MAX_BATCH),
        };
        assert_eq!(
            postcard::from_bytes::<MptMessage>(&postcard::to_stdvec(&at_cap).unwrap()).unwrap(),
            at_cap
        );

        let heads: Vec<HeadSummary> = (0..MAX_HEADS_PER_MESSAGE + 1)
            .map(|i| HeadSummary {
                origin: origin(),
                seq: i as u64,
                root: Hash([0u8; 32]),
                complete: false,
            })
            .collect();
        refuses(&MptMessage::Hello {
            proto: 1,
            heads,
            scope: DeclaredScope::Untrusted,
        });
        refuses(&MptMessage::GetNodes {
            root: Hash([0u8; 32]),
            wants: wants(MAX_BATCH + 1),
        });
        refuses(&MptMessage::GetValues {
            root: Hash([0u8; 32]),
            wants: wants(MAX_BATCH + 1),
        });
        refuses(&MptMessage::BindingsFor {
            origin: origin(),
            keys: vec![iroh_base::SecretKey::generate().public(); MAX_HEADS_PER_MESSAGE + 1],
        });
        let ads: Vec<(OriginId, BlobAd)> = (0..MAX_PROVIDER_ADS + 1)
            .map(|i| (origin(), BlobAd::complete(i as u64)))
            .collect();
        refuses(&MptMessage::Providers { ads });
    }
}
