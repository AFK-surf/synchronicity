//! Trie record values (§4.2) and the trie keyspace (§4.1).

use serde::{Deserialize, Serialize};

use crate::{
    hash::Hash,
    path::{normalize_path, PathError, MAX_KEY_LEN},
};

/// Current schema version stamped into every record's `v` field.
pub const RECORD_VERSION: u8 = 1;

/// True if a record stamped `v` is one this build understands.
///
/// The stamp is only worth carrying if something reads it. postcard decodes
/// structurally and ignores trailing bytes, so a future record with a field
/// appended decodes cleanly *as the current shape* — the new field silently
/// dropped, as though the publisher had never set it. That is the one failure
/// a version stamp is for, and catching it costs one byte. Older versions stay
/// readable; only the future is refused.
pub fn is_supported_version(v: u8) -> bool {
    v <= RECORD_VERSION
}

/// The `f:` key prefix: this origin's copy of a file.
pub const PREFIX_FILE: u8 = b'f';
/// The `b:` key prefix: "I hold (part of) this object".
pub const PREFIX_BLOB: u8 = b'b';
/// The `m:` key prefix: node manifest.
pub(crate) const PREFIX_MANIFEST: u8 = b'm';
/// The `d:` key prefix: a delegation this origin has issued (§3.5).
pub const PREFIX_DELEGATION: u8 = b'd';
/// The `r:` key prefix: what this origin replicates (`docs/REPLICATION.md` §4.1).
pub const PREFIX_REPLICA: u8 = b'r';

/// The most spaces one [`Delegation`] may name. A delegation is a restriction,
/// so a list too long to be unreadable is the wrong shape — and the record is
/// replicated to every member, so the bound keeps one issuer from growing
/// everybody's trie.
pub const MAX_DELEGATION_SPACES: usize = 32;

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
    /// A socket: content is an eBPF ELF object this origin will execute for a
    /// peer that connects to it (`docs/SOCKETS.md` §2).
    ///
    /// Appended, because postcard numbers enum variants by position and the
    /// four above it are already on every wire in every cluster. A build that
    /// predates this variant fails to decode the record, which fails that
    /// origin and no other (§12) — unavoidable for any new kind, and the
    /// reason the rollout order is upgrade, then declare.
    ///
    /// The kind is this origin's assertion about its own copy, like
    /// `unix_mode` and unlike content: it comes from a local declaration and is
    /// never adopted from a peer, so taking someone's socket takes its bytes
    /// and not its socket-ness (`docs/SOCKETS.md` §2.2).
    Socket,
}

impl EntryKind {
    /// True if this kind carries content addressed by a BLAKE3 root.
    ///
    /// [`EntryKind::Socket`] does, which is what makes the ELF an ordinary CAS
    /// object: replicated, fetched, verified per 16 KiB group, and pinnable
    /// like anything else.
    pub fn has_content(self) -> bool {
        matches!(self, EntryKind::File | EntryKind::Socket)
    }
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

    /// Builds a socket entry over an already-hashed ELF object.
    pub fn socket(size: u64, mtime_ns: i64, content: Hash, seq: u64) -> Self {
        FileEntry {
            kind: EntryKind::Socket,
            ..FileEntry::file(size, mtime_ns, content, seq)
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
/// One representation, not two: a `Complete` variant would be exactly
/// `Partial { spans: [(0, size)] }`, so every consumer would branch on the
/// distinction to arrive back at the same answer. Completeness is a question
/// you ask of the spans and the size, not a second thing to keep in step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdState {
    /// Held `[start, end)` byte spans.
    pub spans: Vec<(u64, u64)>,
}

/// The most spans one advertisement may carry, on the wire or in memory.
///
/// A `b:` record is a trie value bounded only by `MAX_FRAME_LEN` (16 MiB) and a
/// span is sixteen bytes, so an origin can publish one record naming a million
/// spans and every peer that materializes it — or answers `FindProviders` over
/// it — decodes the lot; §12's per-message cap cannot apply after the decode,
/// which is after the allocation it is meant to bound. Generous next to
/// anything honest: spans are 16 MiB-granular runs, a fetch walks windows in
/// order, and native advertisement construction merges what touches, so a real partial holder
/// publishes a handful. What is over the cap is dropped rather than merged
/// across gaps, because merging would claim bytes the holder does not have:
/// over-reporting sends a fetcher to a provider that cannot serve it, while
/// under-reporting costs at most a re-fetch (§6.3).
pub const MAX_AD_SPANS: usize = 1024;

/// Granularity at which partial spans are coalesced before publishing (§4.2).
pub const AD_SPAN_GRANULARITY: u64 = 16 * 1024 * 1024;

/// Decodes the span list under the [`MAX_AD_SPANS`] cap.
///
/// The cap is applied *during* the decode, not after it: the point is that the
/// unbounded vector never exists, and a `Vec<(u64, u64)>` that has already been
/// deserialized has already cost what it was supposed to be denied. Spans past
/// the cap are read and dropped, so the rest of the record still decodes.
impl<'de> Deserialize<'de> for AdState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// The struct shape [`AdState`] serializes as, with the field bounded
        /// (rather than hand-decoding a sequence, so a self-describing format
        /// still sees a `spans` field).
        #[derive(Deserialize)]
        struct Wire {
            spans: BoundedSpans,
        }
        Wire::deserialize(deserializer).map(|wire| AdState {
            spans: wire.spans.spans,
        })
    }
}

/// A span list that stops collecting at [`MAX_AD_SPANS`].
struct BoundedSpans {
    spans: Vec<(u64, u64)>,
}

impl<'de> Deserialize<'de> for BoundedSpans {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = BoundedSpans;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a list of byte spans")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<BoundedSpans, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut spans: Vec<(u64, u64)> = Vec::new();
                while let Some(span) = seq.next_element::<(u64, u64)>()? {
                    // Truncating the tail keeps the claim a subset of what was
                    // published — a re-fetch rather than a wasted dial.
                    if spans.len() < MAX_AD_SPANS {
                        spans.push(span);
                    }
                }
                Ok(BoundedSpans { spans })
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}

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

    /// True if the ad covers the whole object. Derived, not stored: one span
    /// reaching from nothing to the object's end.
    pub fn is_complete(&self) -> bool {
        self.size == 0 || matches!(self.state.spans.as_slice(), [(0, end)] if *end >= self.size)
    }

    /// True if the advertised spans intersect `[start, end)`.
    pub fn intersects(&self, start: u64, end: u64) -> bool {
        self.state.spans.iter().any(|&(s, e)| s < end && start < e)
    }
}

/// What an origin advertises about one space, published under
/// `m:space/<space-id>`.
///
/// One record per space rather than a list inside the manifest, because the
/// redaction boundary is a key prefix (§5.5): a delegate is served the spaces
/// it was granted and nothing of the rest, so a single leaf holding every
/// space's name and count could not be shown to it at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceInfo {
    /// Schema version.
    pub v: u8,
    /// A human description.
    pub description: String,
    /// How many entries the origin published for this space.
    pub entry_count: u64,
}

/// Node info published under `m:self`.
///
/// Carries nothing space-specific: space advertisements live under
/// `m:space/<id>`, one record each, so they can be redacted per space (§5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeManifest {
    /// Schema version.
    pub v: u8,
    /// Human-friendly node name.
    pub name: String,
    /// Software identification, e.g. `synchronicity/0.1.0`.
    pub software: String,
}

/// What this origin holds of a space, published under `r:<space>`
/// (`docs/REPLICATION.md` §4.1).
///
/// A claim, in exactly the sense §12 already accepts for `mtime_ns` and for
/// `BlobAd`: a member with a full disk, a bug, or bad intent can say it holds a
/// space it does not. So a reader may let this *order* its work, and may let it
/// keep bytes, and may never let it drop them. Nothing in this design consults
/// another node's claim to decide a release.
///
/// A new key prefix rather than a field on [`SpaceInfo`], for compatibility
/// rather than taste: postcard is not self-describing and every record carries a
/// version stamp checked with `v <= RECORD_VERSION`, so appending a field to
/// `SpaceInfo` would make every older node *refuse* the record. An unknown
/// prefix already falls through the materializer untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaClaim {
    /// Schema version.
    pub v: u8,
    /// When this node started replicating the space, in unix nanoseconds.
    pub since_ns: i64,
    /// The retention policy, as `current` or `forever`.
    pub policy: String,
    /// Seconds a released root is still held. Zero under `forever`, which
    /// releases nothing.
    pub grace_secs: i64,
    /// Objects held for the space.
    pub objects: u64,
    /// Bytes those objects account for.
    pub bytes: u64,
    /// True when nothing is outstanding: everything the tree names is held.
    pub complete: bool,
}

/// A delegation this origin has issued, published under `d:<device key>`
/// (§3.5).
///
/// The delegated key *is* the trie key, settling three things at once:
/// re-issuing is an update, revoking is a deletion of the obvious key, and the
/// accept-time question is a direct lookup. The issuer is implicit — the
/// record sits in the issuer's trie — so there is no issuer field to check,
/// and none to forge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Schema version.
    pub v: u8,
    /// The spaces the subject may read and publish into. Closed list, at most
    /// [`MAX_DELEGATION_SPACES`], never a wildcard.
    pub spaces: Vec<String>,
    /// When the delegation stops being honored, in unix nanoseconds.
    pub not_after: i64,
    /// A note for `trust ls` and `doctor`.
    pub note: Option<String>,
}

impl Delegation {
    /// True if this record is well-formed enough to grant anything.
    ///
    /// Fail-closed, unlike the same question asked of an `f:` or `b:` record:
    /// a file entry this node cannot read loses a row, while a delegation it
    /// cannot read would otherwise grant whatever the caller assumed.
    pub fn is_well_formed(&self) -> bool {
        is_supported_version(self.v)
            && !self.spaces.is_empty()
            && self.spaces.len() <= MAX_DELEGATION_SPACES
            && self.spaces.iter().all(|s| validate_space(s).is_ok())
            && {
                let mut sorted: Vec<&String> = self.spaces.iter().collect();
                sorted.sort();
                let before = sorted.len();
                sorted.dedup();
                sorted.len() == before
            }
    }
}

/// One failed record encode or decode.
///
/// The ~20 sites that serialize or parse a stored record each restated the
/// same `map_err` onto their crate's error; this is the one body, and each
/// crate's `From` impl decides which of its variants a codec failure is —
/// `synch-store` classifies it as a corrupt record (an origin's fault in
/// reconciliation), `synch-engine` as a record error — exactly as the
/// restatements did.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct CodecError(pub String);

/// Encodes a record as postcard bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    postcard::to_stdvec(value).map_err(|e| CodecError(e.to_string()))
}

/// Decodes a record from postcard bytes.
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    postcard::from_bytes(bytes).map_err(|e| CodecError(e.to_string()))
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
    // The path invariant (§4.1) is enforced at the trust boundary, not just
    // when we build our own keys: a peer's origin trie is single-writer and
    // replicated wholesale, so a malicious peer can publish `f:space//etc/x`
    // or `f:space/../../x`; accepted, the raw path flows into the entries view
    // and then `root_dir.join(path)` during checkout materialization, escaping
    // the checkout root. Reject any key whose path is not already canonical.
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

/// The trie key `m:self`.
pub fn manifest_key() -> Vec<u8> {
    let mut key = vec![PREFIX_MANIFEST, b':'];
    key.extend_from_slice(b"self");
    key
}

/// The trie key `m:space/<space-id>`.
pub fn space_info_key(space: &str) -> Result<Vec<u8>, KeyError> {
    validate_space(space)?;
    let mut key = vec![PREFIX_MANIFEST, b':'];
    key.extend_from_slice(b"space/");
    key.extend_from_slice(space.as_bytes());
    Ok(key)
}

/// Builds the trie key `r:<space>`.
pub fn replica_claim_key(space: &str) -> Result<Vec<u8>, KeyError> {
    validate_space(space)?;
    let mut key = Vec::with_capacity(2 + space.len());
    key.push(PREFIX_REPLICA);
    key.push(b':');
    key.extend_from_slice(space.as_bytes());
    Ok(key)
}

/// Parses `r:<space>`.
pub fn parse_replica_claim_key(key: &[u8]) -> Result<String, KeyError> {
    if key.len() < 3 || key[0] != PREFIX_REPLICA || key[1] != b':' {
        return Err(KeyError::Malformed);
    }
    let space = std::str::from_utf8(&key[2..]).map_err(|_| KeyError::Malformed)?;
    validate_space(space)?;
    Ok(space.to_string())
}

/// Builds the trie key `d:<32-byte device key>`.
pub fn delegation_key(subject: &crate::NodeId) -> Vec<u8> {
    let mut key = Vec::with_capacity(34);
    key.push(PREFIX_DELEGATION);
    key.push(b':');
    key.extend_from_slice(subject.as_bytes());
    key
}

/// Parses `d:<32-byte device key>`.
pub fn parse_delegation_key(key: &[u8]) -> Result<crate::NodeId, KeyError> {
    if key.len() != 34 || key[0] != PREFIX_DELEGATION || key[1] != b':' {
        return Err(KeyError::Malformed);
    }
    let bytes: [u8; 32] = key[2..].try_into().map_err(|_| KeyError::Malformed)?;
    crate::NodeId::from_bytes(&bytes).map_err(|_| KeyError::Malformed)
}

/// What part of the keyspace a scope covers, as the two shapes it takes.
///
/// The distinction is load-bearing. `f:<space>/` ends in a separator
/// `validate_space` forbids inside an id, so it bounds itself and everything
/// under it belongs to that space. `m:space/<id>` and `m:self` bound nothing:
/// as prefixes they admit every key that merely *starts* with them, so a
/// delegation of `photos` would carry `m:space/photos-raw` — another space's
/// entry count and its absolute local path — and a delegate could publish
/// under it too.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeKeys {
    /// Every key beneath these belongs to the scope.
    pub prefixes: Vec<Vec<u8>>,
    /// These exact keys belong to the scope, and nothing extending them.
    pub exact: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_and_delegation_keys_round_trip() {
        let key = space_info_key("photos").unwrap();
        assert_eq!(key, b"m:space/photos");
        assert!(space_info_key("bad/id").is_err());

        let subject = iroh_base::SecretKey::generate().public();
        let key = delegation_key(&subject);
        assert_eq!(key.len(), 34);
        assert_eq!(parse_delegation_key(&key).unwrap(), subject);
        assert!(parse_delegation_key(b"d:short").is_err());
        assert!(key.starts_with(b"d:"));
    }

    #[test]
    fn a_delegation_must_name_distinct_valid_spaces() {
        let good = Delegation {
            v: RECORD_VERSION,
            spaces: vec!["photos".into(), "incoming".into()],
            not_after: 1,
            note: None,
        };
        assert!(good.is_well_formed());
        for spaces in [
            vec![],
            vec!["photos".into(), "photos".into()],
            vec!["bad/id".into()],
            vec!["".into()],
            (0..MAX_DELEGATION_SPACES + 1)
                .map(|i| format!("s{i}"))
                .collect(),
        ] {
            let d = Delegation {
                spaces,
                ..good.clone()
            };
            assert!(!d.is_well_formed(), "{:?} passed", d.spaces);
        }
    }

    #[test]
    fn file_and_blob_keys_round_trip_and_reject_bad_input() {
        let key = file_key("photos", "2024/summer/a.jpg").unwrap();
        assert_eq!(&key[..2], b"f:");
        let (space, path) = parse_file_key(&key).unwrap();
        assert_eq!(
            (space.as_str(), path.as_str()),
            ("photos", "2024/summer/a.jpg")
        );
        assert!(key.starts_with(&space_prefix("photos").unwrap()));
        assert_eq!(dir_prefix("photos", "").unwrap(), b"f:photos/".to_vec());

        let key = file_key("photos", "a/b.jpg").unwrap();
        assert!(key.starts_with(&dir_prefix("photos", "a").unwrap()));
        assert!(!key.starts_with(&dir_prefix("photos", "b").unwrap()));

        let h = Hash::new(b"object");
        let key = blob_key(&h);
        assert_eq!(key.len(), 34);
        assert_eq!(parse_blob_key(&key).unwrap(), h);
        assert!(key.starts_with(b"b:"));

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
        // key can never flow into `root_dir.join(path)` and escape a checkout.
        assert!(parse_file_key(b"f:media//etc/passwd").is_err()); // absolute
        assert!(parse_file_key(b"f:media/../../etc/passwd").is_err()); // dot-dot
        assert!(parse_file_key(b"f:media/a/../b").is_err()); // interior dot-dot
        assert!(parse_file_key(b"f:media/a//b").is_err()); // empty component
        assert!(parse_file_key(b"f:media/./a").is_err()); // dot component
                                                          // A canonical path still round-trips.
        let key = file_key("media", "a/b/c.txt").unwrap();
        assert_eq!(parse_file_key(&key).unwrap().1, "a/b/c.txt");
    }

    /// Round-trips a record through postcard unchanged.
    fn round_trips<
        T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
    >(
        v: T,
    ) {
        assert_eq!(
            postcard::from_bytes::<T>(&postcard::to_stdvec(&v).unwrap()).unwrap(),
            v
        );
    }

    #[test]
    fn record_round_trips_via_postcard() {
        round_trips(FileEntry::file(1234, 42, Hash::new(b"x"), 7));
        round_trips(BlobAd {
            v: RECORD_VERSION,
            size: 100 * 1024 * 1024,
            state: AdState {
                spans: vec![(0, AD_SPAN_GRANULARITY)],
            },
        });
        round_trips(NodeManifest {
            v: RECORD_VERSION,
            name: "nas".into(),
            software: "synchronicity/0.1.0".into(),
        });
        round_trips(SpaceInfo {
            v: RECORD_VERSION,
            description: "movies".into(),
            entry_count: 40_000,
        });
        round_trips(Delegation {
            v: RECORD_VERSION,
            spaces: vec!["photos".into(), "incoming".into()],
            not_after: 1_800_000_000_000_000_000,
            note: Some("zeynep's phone".into()),
        });
    }

    /// A record naming a million spans decodes to at most the cap.
    ///
    /// `spans` is a bare `Vec` on the wire: one 16 MiB record names on the order
    /// of a million spans — 128 MB of allocation and decode. The cap must apply
    /// during the decode, since a deserialized vector has already cost what the
    /// cap exists to deny (§12).
    #[test]
    fn an_extreme_span_list_is_capped_as_it_decodes() {
        let g = AD_SPAN_GRANULARITY;
        let spans: Vec<(u64, u64)> = (0..(MAX_AD_SPANS as u64 + 500))
            .map(|i| (i * 2 * g, i * 2 * g + g))
            .collect();
        let claimed = spans.len();
        // Encoded by hand, because the constructors coalesce and cap: this is
        // what a hostile origin puts in the trie.
        let record = BlobAd {
            v: RECORD_VERSION,
            size: u64::MAX,
            state: AdState {
                spans: spans.clone(),
            },
        };
        let bytes = postcard::to_stdvec(&record).unwrap();
        let decoded: BlobAd = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.state.spans.len(), MAX_AD_SPANS);
        assert!(MAX_AD_SPANS < claimed);
        // The kept spans are the published ones, untouched: what is over the
        // cap is dropped, never merged across the gaps, so the ad claims less
        // than was published rather than more.
        assert_eq!(decoded.state.spans, spans[..MAX_AD_SPANS]);
        assert!(!decoded.is_complete());
    }

    #[test]
    fn advertisements_intersect_only_their_stated_ranges() {
        let g = AD_SPAN_GRANULARITY;
        let ad = BlobAd {
            v: RECORD_VERSION,
            size: 10 * g,
            state: AdState {
                spans: vec![(0, g)],
            },
        };
        assert!(ad.intersects(0, 10));
        assert!(!ad.intersects(2 * g, 3 * g));
        assert!(BlobAd::complete(10).intersects(0, 10));
    }
}
