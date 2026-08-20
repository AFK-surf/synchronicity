//! The 32-byte content/node address used everywhere in synchronicity.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// A 32-byte BLAKE3 hash.
///
/// Used for trie node addresses, out-of-line trie values, and object (content)
/// roots. Object roots are plain BLAKE3 digests of the file contents, so they
/// are checkable with any BLAKE3 tool (§6.1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// The all-zero sentinel, used as the root of the empty trie (§4.4).
    pub const EMPTY: Hash = Hash([0u8; 32]);

    /// Hashes a byte slice with plain BLAKE3.
    pub fn new(data: &[u8]) -> Self {
        Hash(*blake3::hash(data).as_bytes())
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the hash as a lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Builds a hash from a byte slice, which must be exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, HashParseError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| HashParseError::Length)?;
        Ok(Hash(arr))
    }

    /// True if this is the [`Hash::EMPTY`] sentinel.
    pub fn is_empty_sentinel(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// A BLAKE3 chaining value: the hash of a subtree, without the root flag.
///
/// Deliberately not [`struct@Hash`], and deliberately not convertible into one.
/// BLAKE3 finalizes the root of a tree with a distinguishing flag, so a
/// subtree's hash can never be passed off as the hash of a whole object — a
/// property `docs/DELTA-SYNC.md` §3.4 leans on when it treats donor-supplied
/// bytes as candidates rather than content.
///
/// What makes chaining values worth carrying around at all is what they do
/// *not* depend on. A chaining value is a function of the subtree's bytes and
/// of the absolute chunk counter it starts at — not of the size of the object
/// it sits in (§6.1). Two objects holding the same bytes at the same offset
/// therefore agree on the chaining value there, however much else differs,
/// which is the whole basis of delta sync.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cv(pub [u8; 32]);

impl Cv {
    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the chaining value as a lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl From<[u8; 32]> for Cv {
    fn from(v: [u8; 32]) -> Self {
        Cv(v)
    }
}

impl fmt::Debug for Cv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cv({}…)", &self.to_hex()[..8])
    }
}

/// The chaining value of one chunk group, hashed at its place in the object.
///
/// `offset` is the group's absolute byte offset, which is what fixes the chunk
/// counter BLAKE3 starts at — hash the same 16 KiB at a different offset and a
/// different value comes out. `bytes` is the group's content: a full
/// [`CHUNK_GROUP_SIZE`](crate::CHUNK_GROUP_SIZE) except for an object's last
/// group, which is short.
///
/// Panics if `offset` is not a multiple of BLAKE3's 1024-byte chunk (every
/// chunk-group offset is, by construction) or if `bytes` is empty: an empty
/// subtree has no chaining value, only an empty *object* has a hash.
pub fn group_cv(offset: u64, bytes: &[u8]) -> Cv {
    use blake3::hazmat::HasherExt;
    let mut hasher = blake3::Hasher::new();
    hasher.set_input_offset(offset);
    hasher.update(bytes);
    Cv(hasher.finalize_non_root())
}

/// Combines two child chaining values into their parent's, off the root.
pub fn join_cvs(left: &Cv, right: &Cv) -> Cv {
    Cv(blake3::hazmat::merge_subtrees_non_root(
        &left.0,
        &right.0,
        blake3::hazmat::Mode::Hash,
    ))
}

/// Combines the two children of an object's root into the object's hash.
///
/// The root-flagged counterpart of [`join_cvs`], and the step that ties a proof
/// to an address a caller already trusts: a proof is believed because
/// recomputing up its path arrives back at the root the entry named.
pub fn join_root(left: &Cv, right: &Cv) -> Hash {
    Hash(
        *blake3::hazmat::merge_subtrees_root(&left.0, &right.0, blake3::hazmat::Mode::Hash)
            .as_bytes(),
    )
}

/// Hashes everything a reader yields, in bounded pieces.
///
/// The whole-slice [`Hash::new`] is fine for a record; this is for content.
/// "Is the file on disk already the version the tree names?" is a question a
/// mirror asks about multi-gigabyte objects (§7.2), and it must never be
/// answered by reading one into memory.
pub fn hash_reader(mut reader: impl std::io::Read) -> std::io::Result<Hash> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(Hash(*hasher.finalize().as_bytes()));
        }
        hasher.update(&buffer[..read]);
    }
}

impl From<blake3::Hash> for Hash {
    fn from(h: blake3::Hash) -> Self {
        Hash(*h.as_bytes())
    }
}

impl From<Hash> for blake3::Hash {
    fn from(h: Hash) -> Self {
        blake3::Hash::from_bytes(h.0)
    }
}

impl From<[u8; 32]> for Hash {
    fn from(v: [u8; 32]) -> Self {
        Hash(v)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short form keeps logs readable; use Display for the full value.
        write!(f, "Hash({}…)", &self.to_hex()[..8])
    }
}

/// Error parsing a [`struct@Hash`].
#[derive(Debug, thiserror::Error)]
pub enum HashParseError {
    /// The input was not 32 bytes / 64 hex characters.
    #[error("hash must be 32 bytes (64 hex characters)")]
    Length,
    /// The input was not valid hex.
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
}

impl FromStr for Hash {
    type Err = HashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        Hash::from_slice(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_hashes_the_same_as_a_slice() {
        // Longer than the internal buffer, so the multi-read path is the one
        // being checked.
        let payload: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            hash_reader(payload.as_slice()).unwrap(),
            Hash::new(&payload)
        );
        assert_eq!(hash_reader(&[][..]).unwrap(), Hash::new(b""));
    }

    /// The claim delta sync rests on, checked against plain BLAKE3: a root is
    /// exactly what you get by hashing each chunk group at its own offset and
    /// merging the results up bao's tree shape.
    #[test]
    fn chaining_values_merge_back_into_the_plain_root() {
        const GROUP: usize = 16 * 1024;
        // Three groups, the last one short: the ragged shape is the one that
        // gets tree math wrong, so it is the one to pin.
        let payload: Vec<u8> = (0..2 * GROUP + 1000).map(|i| (i * 7 + 3) as u8).collect();
        let cvs: Vec<Cv> = payload
            .chunks(GROUP)
            .enumerate()
            .map(|(i, bytes)| group_cv((i * GROUP) as u64, bytes))
            .collect();
        // bao splits at the largest power of two below the group count, so
        // three groups are (0,1) on the left and 2 alone on the right.
        let left = join_cvs(&cvs[0], &cvs[1]);
        assert_eq!(join_root(&left, &cvs[2]), Hash::new(&payload));

        // And position matters: the same bytes elsewhere are a different value.
        assert_ne!(group_cv(0, &payload[..GROUP]), cvs[1]);
    }

    /// A subtree's chaining value is independent of the size of the object it
    /// sits in — which is why an appended-to file keeps every chaining value of
    /// its old prefix (`docs/DELTA-SYNC.md` §2).
    #[test]
    fn a_chaining_value_does_not_depend_on_the_rest_of_the_object() {
        const GROUP: usize = 16 * 1024;
        let prefix: Vec<u8> = (0..2 * GROUP).map(|i| (i % 251) as u8).collect();
        let mut appended = prefix.clone();
        appended.extend(std::iter::repeat_n(9u8, 5 * GROUP));

        let of = |bytes: &[u8], group: usize| {
            group_cv(
                (group * GROUP) as u64,
                &bytes[group * GROUP..(group + 1) * GROUP],
            )
        };
        assert_eq!(of(&prefix, 0), of(&appended, 0));
        assert_eq!(of(&prefix, 1), of(&appended, 1));
        // The two-group subtree they form is the same in both, too.
        assert_eq!(
            join_cvs(&of(&prefix, 0), &of(&prefix, 1)),
            join_cvs(&of(&appended, 0), &of(&appended, 1))
        );
        // The roots, of course, are not.
        assert_ne!(Hash::new(&prefix), Hash::new(&appended));
    }
}
