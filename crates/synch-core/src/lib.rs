//! Core types for synchronicity: origins, hashes, records, signed heads and the
//! wire schemas shared by every other crate in the workspace.
//!
//! Section references in the documentation point at `DESIGN.md` at the
//! repository root.
#![deny(missing_docs)]

pub mod hash;
pub mod head;
pub mod origin;
pub mod path;
pub mod record;
pub mod wire;

pub use hash::{Hash, HashParseError};
pub use head::{head_signing_input, HeadError, HeadSummary, SignedHead, HEAD_SIGNING_DOMAIN};
pub use origin::{NodeId, OriginId, OriginParseError};
pub use path::{normalize_native_path, normalize_path, PathError, MAX_KEY_LEN};
pub use record::{
    blob_key, blob_prefix, dir_prefix, file_key, manifest_key, parse_blob_key, parse_file_key,
    space_prefix, validate_space, AdState, BlobAd, ChunkFormat, ChunkParams, EntryKind, FileEntry,
    KeyError, NodeManifest, SpaceInfo, AD_SPAN_GRANULARITY, RECORD_VERSION,
};
pub use wire::{
    BlobMessage, ChunkRanges, GroupRange, MptMessage, ALPN_BLOB, ALPN_MPT, MAX_BATCH,
    MAX_FRAME_LEN, PROTO_VERSION,
};

/// The software identification string published in [`NodeManifest::software`].
pub const SOFTWARE: &str = concat!("synchronicity/", env!("CARGO_PKG_VERSION"));

/// Size of a bao chunk group, in bytes (§6.1).
pub const CHUNK_GROUP_SIZE: u64 = 16 * 1024;

/// log2 of the chunk group size in BLAKE3 chunks (§6.1).
pub const CHUNK_GROUP_LOG2: u8 = 4;

/// Blobs at or below this size are inlined in SQLite rather than written to the
/// filesystem CAS (§6.2).
pub const INLINE_BLOB_MAX: u64 = 16 * 1024;

/// Values at or below this size are inlined in trie nodes (§4.3).
pub const INLINE_VALUE_MAX: usize = 128;

/// Returns the current unix time in nanoseconds.
pub fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos().min(i64::MAX as u128) as i64,
        Err(_) => 0,
    }
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
}
