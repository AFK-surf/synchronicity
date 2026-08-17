//! Trie record values (§4.2) and the trie keyspace (§4.1).

use serde::{Deserialize, Serialize};

use crate::{
    hash::Hash,
    path::{normalize_path, PathError, MAX_KEY_LEN},
};

/// Current schema version stamped into every record's `v` field.
pub const RECORD_VERSION: u8 = 1;

/// The `f:` key prefix: this origin's copy of a file.
pub const PREFIX_FILE: u8 = b'f';
/// The `b:` key prefix: "I hold (part of) this object".
pub const PREFIX_BLOB: u8 = b'b';
/// The `m:` key prefix: node manifest.
pub const PREFIX_MANIFEST: u8 = b'm';

/// What a [`FileEntry`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link; the target is in [`FileEntry::symlink_target`].
    Symlink,
    /// A deletion marker retained for interpretation (§4.2).
    Tombstone,
}

/// The hash-tree format an object was chunked with. Fixed per object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkParams {
    /// The chunking format. Only [`ChunkFormat::Bao`] exists in v1.
    pub format: ChunkFormat,
    /// log2 of the chunk group size, in BLAKE3 chunks. 4 == 16 KiB groups.
    pub group_log2: u8,
}

impl ChunkParams {
    /// The v1 default: bao with 16 KiB chunk groups (§6.1).
    pub const DEFAULT: ChunkParams = ChunkParams {
        format: ChunkFormat::Bao,
        group_log2: 4,
    };
}

impl Default for ChunkParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The hash-tree format of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkFormat {
    /// BLAKE3 / bao hash tree with chunk groups.
    Bao,
}

/// This origin's copy of a file, stored under `f:<space>/<path>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Schema version.
    pub v: u8,
    /// What this entry describes.
    pub kind: EntryKind,
    /// Content length in bytes (0 for directories and tombstones).
    pub size: u64,
    /// The origin's observed mtime, in unix nanoseconds.
    pub mtime_ns: i64,
    /// Advisory unix mode; best-effort cross-platform.
    pub unix_mode: Option<u32>,
    /// BLAKE3 hash-tree root of the content (`None` for dirs and tombstones).
    pub content: Option<Hash>,
    /// Chunking parameters of the content.
    pub chunking: ChunkParams,
    /// The origin trie seq at which this version was published.
    pub seq: u64,
    /// Previous content root — one-step lineage (§8).
    pub prev: Option<Hash>,
    /// Link target for [`EntryKind::Symlink`].
    pub symlink_target: Option<String>,
}

impl FileEntry {
    /// Builds a regular-file entry.
    pub fn file(size: u64, mtime_ns: i64, content: Hash, seq: u64) -> Self {
        FileEntry {
            v: RECORD_VERSION,
            kind: EntryKind::File,
            size,
            mtime_ns,
            unix_mode: None,
            content: Some(content),
            chunking: ChunkParams::DEFAULT,
            seq,
            prev: None,
            symlink_target: None,
        }
    }

    /// Builds a tombstone entry for a deleted path.
    pub fn tombstone(mtime_ns: i64, seq: u64, prev: Option<Hash>) -> Self {
        FileEntry {
            v: RECORD_VERSION,
            kind: EntryKind::Tombstone,
            size: 0,
            mtime_ns,
            unix_mode: None,
            content: None,
            chunking: ChunkParams::DEFAULT,
            seq,
            prev,
            symlink_target: None,
        }
    }

    /// True if this entry marks a deletion.
    pub fn is_tombstone(&self) -> bool {
        self.kind == EntryKind::Tombstone
    }
}

/// How much of an object a holder has: the byte spans it holds, coalesced at
/// 16 MiB granularity.
///
/// One representation, not two. There used to be a `Complete` variant beside
/// `Partial`, and it was exactly `Partial { spans: [(0, size)] }` — every
/// consumer had to branch on the distinction to arrive back at the same answer,
/// six sites of it, and the same duplication was carried into the
/// `blob_providers` table as a `complete` column beside the spans. Completeness
/// is a question you ask of the spans and the size, not a second thing to keep
/// in step with them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdState {
    /// Held `[start, end)` byte spans.
    pub spans: Vec<(u64, u64)>,
}

/// Granularity at which partial spans are coalesced before publishing (§4.2).
pub const AD_SPAN_GRANULARITY: u64 = 16 * 1024 * 1024;

/// "I hold (part of) this object", stored under `b:<32-byte object root>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobAd {
    /// Schema version.
    pub v: u8,
    /// Object length in bytes.
    pub size: u64,
    /// Which parts are held.
    pub state: AdState,
}

impl BlobAd {
    /// Builds a complete advertisement.
    pub fn complete(size: u64) -> Self {
        BlobAd {
            v: RECORD_VERSION,
            size,
            state: AdState {
                spans: if size == 0 {
                    Vec::new()
                } else {
                    vec![(0, size)]
                },
            },
        }
    }

    /// Builds a partial advertisement, coalescing spans to 16 MiB granularity.
    pub fn partial(size: u64, spans: impl IntoIterator<Item = (u64, u64)>) -> Self {
        BlobAd {
            v: RECORD_VERSION,
            size,
            state: AdState {
                spans: coalesce_spans(spans, size),
            },
        }
    }

    /// True if the ad covers the whole object.
    ///
    /// Derived, not stored: one span reaching from nothing to the object's end.
    pub fn is_complete(&self) -> bool {
        self.size == 0 || matches!(self.state.spans.as_slice(), [(0, end)] if *end >= self.size)
    }

    /// True if the advertised spans intersect `[start, end)`.
    pub fn intersects(&self, start: u64, end: u64) -> bool {
        self.state.spans.iter().any(|&(s, e)| s < end && start < e)
    }
}

/// Rounds spans out to [`AD_SPAN_GRANULARITY`] boundaries and merges overlaps.
///
/// Rounding *outward* would over-claim; ads are hints, not promises (§6.3), and
/// the fetcher learns exact availability from `SliceEnd`, so we round the start
/// down and the end up only within the object's true size, then merge.
pub fn coalesce_spans(spans: impl IntoIterator<Item = (u64, u64)>, size: u64) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = spans
        .into_iter()
        .filter(|(s, e)| s < e)
        .map(|(s, e)| {
            // Clamp to the object size *before* rounding the end up, so the
            // outward round can never overflow u64 for an `e` within one
            // granularity of u64::MAX.
            let s = (s / AD_SPAN_GRANULARITY) * AD_SPAN_GRANULARITY;
            let e = e.min(size).div_ceil(AD_SPAN_GRANULARITY) * AD_SPAN_GRANULARITY;
            (s.min(size), e.min(size).max(s.min(size)))
        })
        .filter(|(s, e)| s < e)
        .collect();
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// A space advertised in a [`NodeManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceInfo {
    /// The space id.
    pub id: String,
    /// A human description.
    pub description: String,
    /// How many entries the origin published for this space.
    pub entry_count: u64,
}

/// Node info published under `m:self`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeManifest {
    /// Schema version.
    pub v: u8,
    /// Human-friendly node name.
    pub name: String,
    /// Advertised spaces.
    pub spaces: Vec<SpaceInfo>,
    /// Software identification, e.g. `synchronicity/0.1.0`.
    pub software: String,
}

/// Error building or parsing a trie key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// A space id was empty, too long, or contained a `/` or control character.
    #[error("invalid space id {0:?}")]
    Space(String),
    /// The path part was not normalizable.
    #[error("invalid path: {0}")]
    Path(#[from] PathError),
    /// The key did not have the expected shape for its prefix.
    #[error("malformed trie key")]
    Malformed,
    /// The key exceeded the §12 length bound.
    #[error("trie key too long (max {MAX_KEY_LEN} bytes)")]
    TooLong,
}

/// Validates a space id: non-empty, `<= 63` bytes, no `/`, no control characters.
pub fn validate_space(space: &str) -> Result<(), KeyError> {
    let ok = !space.is_empty()
        && space.len() <= 63
        && !space.contains('/')
        && !space.chars().any(|c| c.is_control());
    if ok {
        Ok(())
    } else {
        Err(KeyError::Space(space.to_string()))
    }
}

/// Builds the trie key `f:<space>/<path>`.
pub fn file_key(space: &str, path: &str) -> Result<Vec<u8>, KeyError> {
    validate_space(space)?;
    let path = normalize_path(path)?;
    let mut key = Vec::with_capacity(2 + space.len() + 1 + path.len());
    key.push(PREFIX_FILE);
    key.push(b':');
    key.extend_from_slice(space.as_bytes());
    key.push(b'/');
    key.extend_from_slice(path.as_bytes());
    if key.len() > MAX_KEY_LEN {
        return Err(KeyError::TooLong);
    }
    Ok(key)
}

/// The `f:<space>/` prefix used for range scans over a whole space.
pub fn space_prefix(space: &str) -> Result<Vec<u8>, KeyError> {
    validate_space(space)?;
    let mut key = Vec::with_capacity(3 + space.len());
    key.push(PREFIX_FILE);
    key.push(b':');
    key.extend_from_slice(space.as_bytes());
    key.push(b'/');
    Ok(key)
}

/// The `f:<space>/<dir>` prefix used for directory listings (§4.1).
pub fn dir_prefix(space: &str, dir: &str) -> Result<Vec<u8>, KeyError> {
    let mut key = space_prefix(space)?;
    let dir = dir.trim_start_matches('/');
    if !dir.is_empty() {
        let dir = normalize_path(dir.trim_end_matches('/'))?;
        key.extend_from_slice(dir.as_bytes());
        key.push(b'/');
    }
    Ok(key)
}

/// Parses `f:<space>/<path>` back into its parts.
pub fn parse_file_key(key: &[u8]) -> Result<(String, String), KeyError> {
    if key.len() < 4 || key[0] != PREFIX_FILE || key[1] != b':' {
        return Err(KeyError::Malformed);
    }
    let rest = std::str::from_utf8(&key[2..]).map_err(|_| KeyError::Malformed)?;
    let (space, path) = rest.split_once('/').ok_or(KeyError::Malformed)?;
    validate_space(space)?;
    if path.is_empty() {
        return Err(KeyError::Malformed);
    }
    // The path invariant (no `.`/`..`, no leading/empty segments, NFC — §4.1)
    // must be enforced at the trust boundary, not just when we build our own
    // keys. A peer's origin trie is single-writer and replicated wholesale, so
    // a malicious peer can publish `f:space//etc/x` or `f:space/../../x`; if we
    // accept it, the raw path flows into the entries view and then into
    // `root_dir.join(path)` during mirror materialization, escaping the mirror
    // root. Reject any key whose path is not already canonical.
    let normalized = normalize_path(path).map_err(|_| KeyError::Malformed)?;
    if normalized != path {
        return Err(KeyError::Malformed);
    }
    Ok((space.to_string(), normalized))
}

/// Builds the trie key `b:<32-byte object root>`.
pub fn blob_key(root: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(34);
    key.push(PREFIX_BLOB);
    key.push(b':');
    key.extend_from_slice(root.as_bytes());
    key
}

/// Parses `b:<32-byte object root>`.
pub fn parse_blob_key(key: &[u8]) -> Result<Hash, KeyError> {
    if key.len() != 34 || key[0] != PREFIX_BLOB || key[1] != b':' {
        return Err(KeyError::Malformed);
    }
    Hash::from_slice(&key[2..]).map_err(|_| KeyError::Malformed)
}

/// The `b:` prefix used for range scans over all of an origin's ads.
pub fn blob_prefix() -> Vec<u8> {
    vec![PREFIX_BLOB, b':']
}

/// The trie key `m:self`.
pub fn manifest_key() -> Vec<u8> {
    let mut key = vec![PREFIX_MANIFEST, b':'];
    key.extend_from_slice(b"self");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_keys_round_trip() {
        let key = file_key("photos", "2024/summer/a.jpg").unwrap();
        assert_eq!(&key[..2], b"f:");
        let (space, path) = parse_file_key(&key).unwrap();
        assert_eq!(space, "photos");
        assert_eq!(path, "2024/summer/a.jpg");
    }

    #[test]
    fn file_keys_normalize_paths() {
        let a = file_key("s", "cafe\u{0301}.txt").unwrap();
        let b = file_key("s", "caf\u{00e9}.txt").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn prefixes_are_key_prefixes() {
        let key = file_key("photos", "a/b.jpg").unwrap();
        assert!(key.starts_with(&space_prefix("photos").unwrap()));
        assert!(key.starts_with(&dir_prefix("photos", "a").unwrap()));
        assert!(!key.starts_with(&dir_prefix("photos", "b").unwrap()));
        assert_eq!(dir_prefix("photos", "").unwrap(), b"f:photos/".to_vec());
    }

    #[test]
    fn blob_keys_round_trip() {
        let h = Hash::new(b"object");
        let key = blob_key(&h);
        assert_eq!(key.len(), 34);
        assert_eq!(parse_blob_key(&key).unwrap(), h);
        assert!(key.starts_with(&blob_prefix()));
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(file_key("has/slash", "a").is_err());
        assert!(file_key("", "a").is_err());
        assert!(file_key("s", "/abs").is_err());
        assert!(parse_file_key(b"f:nopath").is_err());
        assert!(parse_blob_key(b"b:short").is_err());
    }

    #[test]
    fn parse_rejects_non_normalized_paths() {
        // A peer's origin trie is attacker-controlled bytes. `parse_file_key`
        // must reject any path that is not already canonical, so a hand-crafted
        // key can never flow into `root_dir.join(path)` and escape a mirror.
        assert!(parse_file_key(b"f:media//etc/passwd").is_err()); // absolute
        assert!(parse_file_key(b"f:media/../../etc/passwd").is_err()); // dot-dot
        assert!(parse_file_key(b"f:media/a/../b").is_err()); // interior dot-dot
        assert!(parse_file_key(b"f:media/a//b").is_err()); // empty component
        assert!(parse_file_key(b"f:media/./a").is_err()); // dot component
                                                          // A canonical path still round-trips.
        let key = file_key("media", "a/b/c.txt").unwrap();
        assert_eq!(parse_file_key(&key).unwrap().1, "a/b/c.txt");
    }

    #[test]
    fn record_round_trips_via_postcard() {
        let e = FileEntry::file(1234, 42, Hash::new(b"x"), 7);
        let bytes = postcard::to_stdvec(&e).unwrap();
        assert_eq!(postcard::from_bytes::<FileEntry>(&bytes).unwrap(), e);

        let ad = BlobAd::partial(100 * 1024 * 1024, [(0, 20 * 1024 * 1024)]);
        let bytes = postcard::to_stdvec(&ad).unwrap();
        assert_eq!(postcard::from_bytes::<BlobAd>(&bytes).unwrap(), ad);

        let m = NodeManifest {
            v: RECORD_VERSION,
            name: "nas".into(),
            spaces: vec![SpaceInfo {
                id: "media".into(),
                description: "movies".into(),
                entry_count: 40_000,
            }],
            software: "synchronicity/0.1.0".into(),
        };
        let bytes = postcard::to_stdvec(&m).unwrap();
        assert_eq!(postcard::from_bytes::<NodeManifest>(&bytes).unwrap(), m);
    }

    #[test]
    fn spans_coalesce_at_16mib() {
        let g = AD_SPAN_GRANULARITY;
        let size = 10 * g;
        let spans = coalesce_spans([(1, 2), (g + 5, g + 6)], size);
        assert_eq!(spans, vec![(0, 2 * g)]);

        let spans = coalesce_spans([(0, 1), (5 * g, 5 * g + 1)], size);
        assert_eq!(spans, vec![(0, g), (5 * g, 6 * g)]);
    }

    #[test]
    fn spans_clamp_to_size() {
        let g = AD_SPAN_GRANULARITY;
        let size = g / 2;
        assert_eq!(coalesce_spans([(0, 10)], size), vec![(0, size)]);
    }

    #[test]
    fn ad_intersection() {
        let g = AD_SPAN_GRANULARITY;
        let ad = BlobAd::partial(10 * g, [(0, g)]);
        assert!(ad.intersects(0, 10));
        assert!(!ad.intersects(2 * g, 3 * g));
        assert!(BlobAd::complete(10).intersects(0, 10));
    }
}
