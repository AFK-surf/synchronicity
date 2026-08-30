//! Core types for synchronicity: origins, hashes, records, signed heads and the
//! wire schemas shared by every other crate. Section references point at
//! `DESIGN.md` at the repository root.
#![deny(missing_docs)]

pub mod blocking;
pub mod civil;
pub mod fs;
pub mod hash;
pub mod head;
pub mod json;
pub mod origin;
pub mod path;
pub mod record;
pub mod sock;
pub mod wire;

pub use blocking::{assert_off_runtime, blocking_is_allowed, offload, BlockingScope, TaskLost};
pub use hash::{group_cv, hash_reader, join_cvs, join_root, Cv, Hash};
pub use head::{head_signing_input, HeadSummary, SignedHead};
pub use origin::{NodeId, OriginId};
pub use path::{normalize_native_path, normalize_path, MAX_KEY_LEN};
pub use record::{
    blob_key, delegation_key, dir_prefix, file_key, manifest_key, parse_blob_key,
    parse_delegation_key, parse_file_key, parse_replica_claim_key, publish_prefixes,
    replica_claim_key, scope_prefixes, space_info_key, space_prefix, validate_space, AdState,
    BlobAd, Delegation, EntryKind, FileEntry, KeyError, NodeManifest, ReplicaClaim, ScopeKeys,
    SpaceInfo, AD_SPAN_GRANULARITY, MAX_AD_SPANS, MAX_DELEGATION_SPACES, RECORD_VERSION,
};
pub use sock::{
    display_text_is_safe, valid_ebpf_stack_frame_size, Declaration, FaultKind,
    FileTransferCapability, ProcessCapability, RefuseCode, SockClosed, SockOpen, SockOpened,
    SockStatus, TreeWriteCapability, ALPN_SOCK, DEFAULT_EBPF_STACK_FRAME_SIZE,
    DEFAULT_TREE_WRITE_MAX_BYTES, MAX_DECLARED_EGRESS, MAX_DECLARED_FILE_TRANSFERS,
    MAX_DECLARED_PROCESSES, MAX_DECLARED_TREE_WRITES, MAX_EBPF_STACK_FRAME_SIZE,
    MAX_OPEN_FRAME_LEN, TREE_WRITE_CREATE, TREE_WRITE_DELETE, TREE_WRITE_REPLACE,
};
pub use wire::{
    proof_nodes_upper_bound, BlobMessage, ChunkRanges, DeclaredScope, GroupRange, MptMessage,
    ALPN_BLOB, ALPN_MPT, MAX_BATCH, MAX_BATCH_PATH_BYTES, MAX_FRAME_LEN, MAX_HEADS_PER_MESSAGE,
    MAX_PROOF_NODES, MAX_PROVIDER_ADS, MAX_RANGES, MAX_SLICE_GROUPS, PROOF_NODE_LEN, PROTO_VERSION,
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
/// deeper: one chaining value per 16 MiB, a 64-byte pair per node, so a 100 GB
/// object costs about 381 KB (`docs/DELTA-SYNC.md` §3.3, §7). The ad span is the
/// unit deliberately — a span proven equal is promoted whole, and the same
/// boundary is what `BlobAd` summarizes possession at (§6.3).
pub const AD_SPAN_LEVEL: u8 = (AD_SPAN_GRANULARITY / CHUNK_GROUP_SIZE).trailing_zeros() as u8;

/// Blobs at or below this size are inlined in SQLite rather than written to the
/// filesystem CAS (§6.2).
pub const INLINE_BLOB_MAX: u64 = 16 * 1024;

/// Values at or below this size are inlined in trie nodes (§4.3).
pub const INLINE_VALUE_MAX: usize = 128;

/// The largest a trie value may be, inline or out of line (§4.3, §12).
///
/// The key side is bounded three ways — [`MAX_KEY_LEN`] on insert, twice that
/// in nibbles at decode, and `MAX_DEPTH_NIBBLES` on every walk — but the value
/// side had none: `check_invariants` bounds `ValueRef::Inline` at
/// [`INLINE_VALUE_MAX`] and says nothing about `ValueRef::Hash`, so a value was
/// bounded only by the frame, at 16 MiB each. That is the enabler for two costs
/// a §12 sanity bound is supposed to cap: a `GetValues` answer is `MAX_BATCH`
/// payloads serialized whole (256 × 16 MiB), and a promotion diff resolves a
/// value per changed position, so one 16 MiB leaf payload resolves to terabytes.
/// Generous next to anything the system produces — the largest legitimate value
/// is a `b:` record at ~20 KB — and at this ceiling a full `MAX_BATCH` answer is
/// 8 MiB, half a frame.
///
/// `MAX_DEPTH_NIBBLES` is `synch-mpt`'s; it is twice [`MAX_KEY_LEN`].
pub const MAX_TRIE_VALUE_LEN: usize = 32 * 1024;

/// The earliest wall-clock reading a trust decision may be evaluated at
/// (§3.2): 2025-01-01T00:00:00Z, in unix nanoseconds.
///
/// Every expiry check is `now < expires_at`, so the instant the check is made
/// decides what it means. At the epoch — a dead RTC, a stepped-back clock —
/// *nothing has ever expired*, and a node would honor every binding it has ever
/// stored, revoked members included, forever. So a reading no build of this
/// software could honestly produce is treated as no reading at all: a trust
/// decision that cannot be dated is refused. The bound is a fixed date rather
/// than the build date because it must be checkable from a stored constant.
pub const MIN_TRUSTED_NS: i64 = 1_735_689_600_000_000_000;

/// Returns the current unix time in nanoseconds.
///
/// A reading before the epoch comes back *negative* rather than clamped to
/// zero, because zero is a plausible-looking instant and a broken clock must
/// not be able to disguise itself as one. Nothing derives trust from this
/// directly: [`clock_is_trusted`] decides whether a reading can carry a trust
/// decision.
pub fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos().min(i64::MAX as u128) as i64,
        Err(e) => -(e.duration().as_nanos().min(i64::MAX as u128) as i64),
    }
}

/// Whether `ns` is a clock reading a trust decision may be dated by (§3.2).
///
/// See [`MIN_TRUSTED_NS`]. A node whose clock fails this keeps its static trust
/// and honors no DNS binding at all: it refuses to extend trust rather than
/// serving on trust it cannot date.
pub fn clock_is_trusted(ns: i64) -> bool {
    ns >= MIN_TRUSTED_NS
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
        assert_eq!(groups_for_byte_range(0, 1), GroupRange::new(0, 1));
        assert_eq!(
            groups_for_byte_range(CHUNK_GROUP_SIZE - 1, CHUNK_GROUP_SIZE + 1),
            GroupRange::new(0, 2)
        );
        assert!(groups_for_byte_range(5, 5).is_empty());
        assert_eq!(group_count(0), 1);
        assert_eq!(group_count(CHUNK_GROUP_SIZE + 1), 2);
    }

    #[test]
    fn the_epoch_is_not_a_trustworthy_instant() {
        // `now = 0` must not pass an expiry check: at zero nothing has ever
        // expired, so a clock at or before the epoch is refused, not believed.
        assert!(!clock_is_trusted(0));
        assert!(!clock_is_trusted(-1));
        assert!(!clock_is_trusted(MIN_TRUSTED_NS - 1));
        assert!(clock_is_trusted(MIN_TRUSTED_NS));
        assert!(clock_is_trusted(now_ns()), "a working clock is trusted");
        assert!(clock_is_trusted(i64::MAX));
    }
}
