//! Core types for synchronicity: origins, hashes, records, signed heads and the
//! wire schemas shared by every other crate in the workspace.
//!
//! Section references in the documentation point at `DESIGN.md` at the
//! repository root.
#![deny(missing_docs)]

pub mod blocking;
pub mod hash;
pub mod head;
pub mod origin;
pub mod path;
pub mod record;
pub mod wire;

pub use blocking::{assert_off_runtime, blocking_is_allowed, offload, BlockingScope, TaskLost};
pub use hash::{group_cv, hash_reader, join_cvs, join_root, Cv, Hash, HashParseError};
pub use head::{head_signing_input, HeadError, HeadSummary, SignedHead, HEAD_SIGNING_DOMAIN};
pub use origin::{NodeId, OriginId, OriginParseError};
pub use path::{normalize_native_path, normalize_path, PathError, MAX_KEY_LEN};
pub use record::{
    blob_key, blob_prefix, dir_prefix, file_key, manifest_key, parse_blob_key, parse_file_key,
    space_prefix, validate_space, AdState, BlobAd, ChunkFormat, ChunkParams, EntryKind, FileEntry,
    KeyError, NodeManifest, SpaceInfo, AD_SPAN_GRANULARITY, MAX_AD_SPANS, RECORD_VERSION,
};
pub use wire::{
    proof_nodes_upper_bound, BlobMessage, ChunkRanges, GroupRange, MptMessage, ALPN_BLOB, ALPN_MPT,
    MAX_BATCH, MAX_FRAME_LEN, MAX_HEADS_PER_MESSAGE, MAX_PROOF_NODES, MAX_PROVIDER_ADS, MAX_RANGES,
    MAX_SLICE_GROUPS, PROOF_NODE_LEN, PROTO_VERSION,
};

/// The software identification string published in [`NodeManifest::software`].
pub const SOFTWARE: &str = concat!("synchronicity/", env!("CARGO_PKG_VERSION"));

/// Size of a bao chunk group, in bytes (§6.1).
pub const CHUNK_GROUP_SIZE: u64 = 16 * 1024;

/// log2 of the chunk group size in BLAKE3 chunks (§6.1).
pub const CHUNK_GROUP_LOG2: u8 = 4;

/// The descent level whose subtrees are exactly one ad span across.
///
/// Delta sync's first proof round asks for the tree at this level and no
/// deeper: one chaining value per 16 MiB. What travels is the *interior* of the
/// tree above those spans — a 64-byte pair per node, one node per span less one
/// — so a 100 GB object costs about 381 KB, not the 32 bytes per span the
/// chaining values alone would suggest (`docs/DELTA-SYNC.md` §3.3, §7). The ad
/// span is the
/// unit deliberately — a span proven equal to a donor's is promoted whole, and
/// the same boundary is what `BlobAd` summarizes possession at (§6.3), so a
/// node that promotes a span can advertise it without any further arithmetic.
pub const AD_SPAN_LEVEL: u8 = (AD_SPAN_GRANULARITY / CHUNK_GROUP_SIZE).trailing_zeros() as u8;

/// Blobs at or below this size are inlined in SQLite rather than written to the
/// filesystem CAS (§6.2).
pub const INLINE_BLOB_MAX: u64 = 16 * 1024;

/// Values at or below this size are inlined in trie nodes (§4.3).
pub const INLINE_VALUE_MAX: usize = 128;

/// The largest a trie value may be, inline or out of line (§4.3, §12).
///
/// The key side of the trie is bounded three ways — [`MAX_KEY_LEN`] on insert,
/// twice that in nibbles at decode, and `MAX_DEPTH_NIBBLES` on every walk. The
/// value side had none: `check_invariants` bounds `ValueRef::Inline` at
/// [`INLINE_VALUE_MAX`] and says nothing about `ValueRef::Hash`, and the fetch
/// that carries the payload only enforced the *lower* edge (a value small enough
/// to be inline must be inline). So a value was bounded by the frame, at 16 MiB
/// each and no limit on how many.
///
/// That is the enabler for two costs a §12 "sanity bound on any single message"
/// is supposed to cap. A `GetValues` answer is `MAX_BATCH` payloads built in
/// memory and serialized whole, so 256 × 16 MiB is gigabytes of allocation for
/// an 8 KB request. And the promotion diff resolves a value per changed
/// position, so a canonical six-node trie whose one leaf carries a 16 MiB
/// payload — legal, cheap to publish, and well inside the walk's position
/// ceiling — resolves to terabytes.
///
/// Generous next to anything the system produces: the largest legitimate value
/// is a `b:` record, whose span list is capped at
/// [`MAX_AD_SPANS`] and comes to ~20 KB; a `FileEntry` is
/// small because the path lives in the *key*. At this ceiling a full
/// `MAX_BATCH` answer is 8 MiB, half a frame.
///
/// `MAX_DEPTH_NIBBLES` is `synch-mpt`'s; it is twice [`MAX_KEY_LEN`].
pub const MAX_TRIE_VALUE_LEN: usize = 32 * 1024;

/// The earliest wall-clock reading a trust decision may be evaluated at
/// (§3.2): 2025-01-01T00:00:00Z, in unix nanoseconds.
///
/// Every expiry check in this system is `now < expires_at`, so the instant the
/// check is made at decides what it means. At the epoch — a dead RTC coming up
/// at 1970, a clock stepped backwards, a container with no time source —
/// *nothing has ever expired*, and a node in that state would honor every
/// binding it has ever stored, revoked members included, forever. So a reading
/// no build of this software could honestly produce is not treated as a small
/// number: it is treated as no reading at all, and a trust decision that
/// cannot be dated is refused.
///
/// The bound is a fixed date rather than the build date because it has to be
/// checkable from a stored constant, and it only has to be far enough forward
/// to exclude a clock that never got set: this repository is younger than it.
pub const MIN_TRUSTED_NS: i64 = 1_735_689_600_000_000_000;

/// Returns the current unix time in nanoseconds.
///
/// A clock reading before the epoch comes back *negative* rather than clamped
/// to zero, because zero is a plausible-looking instant and a broken clock
/// must not be able to disguise itself as one. Nothing derives trust from this
/// value directly: [`clock_is_trusted`] is what decides whether a reading can
/// carry a trust decision, and `Store::trust_instant` is what every expiry
/// check in the store passes through.
pub fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos().min(i64::MAX as u128) as i64,
        Err(e) => -(e.duration().as_nanos().min(i64::MAX as u128) as i64),
    }
}

/// Whether `ns` is a clock reading a trust decision may be dated by (§3.2).
///
/// See [`MIN_TRUSTED_NS`]. A node whose clock fails this keeps its static
/// trust — which no clock is consulted for — and honors no DNS binding at all,
/// which is the fail-closed half of the two available answers: it refuses to
/// extend trust rather than serving on trust it cannot date.
pub fn clock_is_trusted(ns: i64) -> bool {
    ns >= MIN_TRUSTED_NS
}

/// Converts a byte offset to the chunk group index containing it.
pub fn group_of_offset(offset: u64) -> u64 {
    offset / CHUNK_GROUP_SIZE
}

/// Converts a byte range to the half-open group range covering it.
pub fn groups_for_byte_range(start: u64, end: u64) -> GroupRange {
    if start >= end {
        return GroupRange::new(0, 0);
    }
    GroupRange::new(start / CHUNK_GROUP_SIZE, end.div_ceil(CHUNK_GROUP_SIZE))
}

/// The number of chunk groups an object of `size` bytes occupies.
pub fn group_count(size: u64) -> u64 {
    if size == 0 {
        1
    } else {
        size.div_ceil(CHUNK_GROUP_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_math() {
        assert_eq!(group_of_offset(0), 0);
        assert_eq!(group_of_offset(CHUNK_GROUP_SIZE), 1);
        assert_eq!(groups_for_byte_range(0, 1), GroupRange::new(0, 1));
        assert_eq!(
            groups_for_byte_range(CHUNK_GROUP_SIZE - 1, CHUNK_GROUP_SIZE + 1),
            GroupRange::new(0, 2)
        );
        assert!(groups_for_byte_range(5, 5).is_empty());
        assert_eq!(group_count(0), 1);
        assert_eq!(group_count(1), 1);
        assert_eq!(group_count(CHUNK_GROUP_SIZE + 1), 2);
    }

    #[test]
    fn now_is_positive() {
        assert!(now_ns() > 0);
    }

    #[test]
    fn the_epoch_is_not_a_trustworthy_instant() {
        // The failure this guards is `now = 0` passing an expiry check: at zero
        // nothing has ever expired. A clock that reads at or before the epoch
        // has to be refused rather than believed.
        assert!(!clock_is_trusted(0));
        assert!(!clock_is_trusted(-1));
        assert!(!clock_is_trusted(MIN_TRUSTED_NS - 1));
        assert!(clock_is_trusted(MIN_TRUSTED_NS));
        assert!(clock_is_trusted(now_ns()), "a working clock is trusted");
        assert!(clock_is_trusted(i64::MAX));
    }
}
