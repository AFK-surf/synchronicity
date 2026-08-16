//! Wire schemas for the two ALPNs (§5.1, §6.4).
//!
//! All messages are length-framed `postcard` on QUIC streams. The framing
//! itself lives in `synch-net`; this module owns the schemas so that they can be
//! round-trip tested without any networking.

use serde::{Deserialize, Serialize};

use crate::{
    hash::Hash,
    head::{HeadSummary, SignedHead},
    origin::{NodeId, OriginId},
    record::BlobAd,
};

/// ALPN for metadata anti-entropy (§5).
pub const ALPN_MPT: &[u8] = b"sync/mpt/1";
/// ALPN for content transfer (§6.4).
pub const ALPN_BLOB: &[u8] = b"sync/blob/1";

/// Protocol version carried in `Hello`.
pub const PROTO_VERSION: u16 = 1;

/// Maximum number of hashes per `GetNodes`/`GetValues` batch (§5.1).
pub const MAX_BATCH: usize = 256;

/// Maximum accepted length of a single framed message, in bytes.
///
/// This bounds memory use per stream against a hostile peer (§12, DoS).
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// The most chunk groups one slice exchange carries — 8 MiB of payload.
///
/// A bao slice is encoded into memory whole, on both sides, and travels in one
/// frame, so an unbounded `GetSlice` is two problems at once: an object larger
/// than [`MAX_FRAME_LEN`] could never be served at all, and a peer could make a
/// provider allocate an object-sized buffer just by asking for one (§6.4, §12).
/// Requests are therefore served a window at a time and the requester loops.
/// The ceiling leaves room for the hash pairs bao interleaves with the payload,
/// which stay well under the remaining 8 MiB even when a window is asked for
/// one group at a time.
pub const MAX_SLICE_GROUPS: u64 = 512;

/// The most interior tree nodes one proof exchange carries — 512 KiB of hashes.
///
/// A proof is a slice with the payload left out, and it is bounded for the same
/// reason (§12): it is built in memory and travels in one frame, so the size of
/// the provider's allocation must not be the requester's to choose. Unlike a
/// slice, though, a proof cannot be bounded by group count alone — the whole
/// point of the span-level round is that one exchange describes a very large
/// range very cheaply, and clamping it to [`MAX_SLICE_GROUPS`] groups would
/// turn the 381 KB descent of a 100 GB object into twelve thousand round trips
/// (`docs/DELTA-SYNC.md` §3.3). Nodes are what a proof costs, so nodes are what
/// it is counted in: this ceiling covers a 100 GB object's span-level round in
/// a single exchange, and `ProofEnd` reports where anything larger stopped.
pub const MAX_PROOF_NODES: u64 = 8192;

/// The wire size of one proof node: a pair of 32-byte chaining values.
pub const PROOF_NODE_LEN: usize = 64;

/// The most ranges one [`ChunkRanges`] may carry across the wire.
///
/// Set operations are quadratic in the number of ranges, so a request built
/// from a million singleton ranges is a CPU exhaustion vector even though it
/// fits in a frame. No honest request needs anything near this many: a window
/// is [`MAX_SLICE_GROUPS`] groups, so it cannot describe more than that many
/// disjoint runs.
pub const MAX_RANGES: usize = 4096;

/// A message on the `sync/mpt/1` ALPN (§5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MptMessage {
    /// Head gossip, push-pull. Sent first on the head-gossip stream.
    Hello {
        /// Protocol version.
        proto: u16,
        /// The sender's head summaries.
        heads: Vec<HeadSummary>,
    },
    /// "Yours is newer, send the full signed heads for these origins."
    HeadsWant {
        /// Origins whose full signed heads are wanted.
        origins: Vec<OriginId>,
    },
    /// Full signed heads, in response to `HeadsWant` or `Hello`.
    Heads {
        /// The signed heads.
        heads: Vec<SignedHead>,
    },
    /// Reactive push, sent on any head change (§5.3).
    HeadPush {
        /// The changed head.
        head: SignedHead,
    },
    /// Request trie nodes by hash. At most [`MAX_BATCH`] per batch.
    GetNodes {
        /// The wanted node hashes.
        hashes: Vec<Hash>,
    },
    /// Trie nodes, plus the subset the responder did not have.
    Nodes {
        /// `(hash, encoded node)` pairs.
        nodes: Vec<(Hash, Vec<u8>)>,
        /// Hashes the responder did not have.
        missing: Vec<Hash>,
    },
    /// Request out-of-line trie value payloads by hash.
    GetValues {
        /// The wanted value hashes.
        hashes: Vec<Hash>,
    },
    /// Out-of-line trie values, plus the subset the responder did not have.
    Values {
        /// `(hash, value bytes)` pairs.
        values: Vec<(Hash, Vec<u8>)>,
        /// Hashes the responder did not have.
        missing: Vec<Hash>,
    },
    /// Ask a peer which origins advertise an object. Hints are unverified (§5.1).
    FindProviders {
        /// The object root being looked up.
        object_root: Hash,
    },
    /// Unverified provider hints.
    Providers {
        /// `(origin, ad)` pairs.
        ads: Vec<(OriginId, BlobAd)>,
    },
    /// An error response, used instead of dropping a stream silently.
    Error {
        /// A short human-readable reason.
        reason: String,
    },
    /// "Which device keys do you currently hold bound for this origin?"
    ///
    /// Purely informational within the trusted cluster: this is what
    /// `synch key ls` aggregates to tell an operator whether a rotation's new
    /// key has actually propagated (§3.4, §5.1).
    ///
    /// Appended after [`MptMessage::Error`] rather than beside the other
    /// request/response pairs: postcard numbers variants by position, so a new
    /// variant may only ever go on the end.
    GetBindings {
        /// The origin being asked about.
        origin: OriginId,
    },
    /// The device keys the answering peer holds bound for an origin.
    BindingsFor {
        /// The origin asked about.
        origin: OriginId,
        /// The bound device keys, in the peer's own order.
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRanges {
    /// Sorted, non-overlapping ranges.
    pub ranges: Vec<GroupRange>,
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

    /// Total number of groups covered.
    ///
    /// Saturating: `GroupRange`s in a `GetSlice` arrive from peers unbounded, so
    /// a range near `[0, u64::MAX)` must not panic (debug) or silently wrap
    /// (release) here.
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
    /// The question a tree descent asks at every node it considers, which is
    /// why it is answered by a binary search over the (sorted, disjoint) ranges
    /// rather than by building an intersection: a proof walk visits thousands
    /// of nodes and a set that may carry thousands of ranges, and the quadratic
    /// version of that is a denial of service with extra steps (§12).
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
    pub fn intersect(&self, other: &ChunkRanges) -> ChunkRanges {
        let mut out = Vec::new();
        for a in &self.ranges {
            for b in &other.ranges {
                let start = a.start.max(b.start);
                let end = a.end.min(b.end);
                if start < end {
                    out.push(GroupRange { start, end });
                }
            }
        }
        ChunkRanges::from_ranges(out)
    }

    /// The part of `self` not covered by `other`.
    pub fn difference(&self, other: &ChunkRanges) -> ChunkRanges {
        let mut out = Vec::new();
        for a in &self.ranges {
            let mut cursor = a.start;
            for b in &other.ranges {
                if b.end <= cursor || b.start >= a.end {
                    continue;
                }
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

    /// The first `groups` groups of this set, in order.
    ///
    /// How a fetch walks a large object: one bounded window per exchange
    /// ([`MAX_SLICE_GROUPS`]) rather than one request for the whole thing.
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

/// A message on the `sync/blob/1` ALPN (§6.4).
///
/// The blob ALPN carries nothing but these messages plus the raw bao slice and
/// proof bytes (§5.3).
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
    /// `ranges`, in pre-order, descending no deeper than `level` — which is
    /// exactly a bao slice with the payload left out. It is what lets a
    /// requester ask "what does the new version's tree look like here?" without
    /// paying for the bytes it may well already have: the answer is 64 bytes
    /// per node rather than 16 KiB per group.
    ///
    /// `level` is in chunk-group units: `level = n` stops at subtrees of `2^n`
    /// groups, so `level = 0` yields the chaining value of every leaf group and
    /// [`AD_SPAN_LEVEL`](crate::AD_SPAN_LEVEL) yields one per ad span.
    ///
    /// Appended after [`BlobMessage::SliceEnd`] rather than beside `GetSlice`:
    /// postcard numbers variants by position, so a new variant may only ever go
    /// on the end.
    GetProof {
        /// The object root.
        root: Hash,
        /// The ranges whose tree is wanted, in 16 KiB group units.
        ranges: ChunkRanges,
        /// How deep to descend, in group units.
        level: u8,
    },
    /// Terminates a proof response with the ranges it actually covers.
    ///
    /// A proof for a large range can run past [`MAX_PROOF_NODES`]; `served` is
    /// how the requester learns where the answer stopped, and where its next
    /// request starts — the same shape as [`BlobMessage::SliceEnd`] (§6.4).
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
            },
            MptMessage::HeadsWant {
                origins: vec![origin.clone()],
            },
            MptMessage::Heads {
                heads: vec![head.clone()],
            },
            MptMessage::HeadPush { head },
            MptMessage::GetNodes {
                hashes: vec![Hash::new(b"a"), Hash::new(b"b")],
            },
            MptMessage::Nodes {
                nodes: vec![(Hash::new(b"a"), vec![1, 2, 3])],
                missing: vec![Hash::new(b"b")],
            },
            MptMessage::GetValues {
                hashes: vec![Hash::new(b"v")],
            },
            MptMessage::Values {
                values: vec![(Hash::new(b"v"), vec![4, 5])],
                missing: vec![],
            },
            MptMessage::FindProviders {
                object_root: Hash::new(b"o"),
            },
            MptMessage::Providers {
                ads: vec![(origin, BlobAd::complete(10))],
            },
            MptMessage::Error {
                reason: "nope".into(),
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
    fn chunk_ranges_normalize() {
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
    fn chunk_ranges_set_ops() {
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
