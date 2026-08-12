//! Wire schemas for the two ALPNs (§5.1, §6.4).
//!
//! All messages are length-framed `postcard` on QUIC streams. The framing
//! itself lives in `synch-net`; this module owns the schemas so that they can be
//! round-trip tested without any networking.

use serde::{Deserialize, Serialize};

use crate::{
    hash::Hash,
    head::{HeadSummary, SignedHead},
    origin::OriginId,
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
    pub fn count(&self) -> u64 {
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }

    /// True if `group` is covered.
    pub fn contains(&self, group: u64) -> bool {
        self.ranges
            .iter()
            .any(|r| r.start <= group && group < r.end)
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
}

/// A message on the `sync/blob/1` ALPN (§6.4).
///
/// The blob ALPN carries nothing but these two messages plus the raw bao slice
/// bytes (§5.3).
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
}
