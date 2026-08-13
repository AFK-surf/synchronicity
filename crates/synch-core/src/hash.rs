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
    fn hex_round_trip() {
        let h = Hash::new(b"hello");
        let s = h.to_hex();
        assert_eq!(s.len(), 64);
        assert_eq!(Hash::from_str(&s).unwrap(), h);
    }

    #[test]
    fn matches_plain_blake3() {
        assert_eq!(Hash::new(b"abc").0, *blake3::hash(b"abc").as_bytes());
    }

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

    #[test]
    fn empty_sentinel() {
        assert!(Hash::EMPTY.is_empty_sentinel());
        assert!(!Hash::new(b"").is_empty_sentinel());
    }
}
