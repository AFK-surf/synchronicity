//! Nibble sequences: the radix-16 alphabet the trie is keyed on (§4.3).

use serde::{Deserialize, Deserializer, Serialize};

/// A sequence of nibbles (4-bit values), high nibble of each byte first.
///
/// Stored one nibble per byte so the postcard encoding is canonical — equal
/// sequences produce identical bytes, which is what makes node hashing
/// deterministic. Every element is in `0..16`, an invariant of the type rather
/// than of its constructors: `Deserialize` is written by hand to enforce it,
/// because a peer's node is decoded, not constructed, and a nibble outside the
/// alphabet indexes a 16-element child array out of bounds (a panic) and
/// breaks [`Nibbles::to_bytes`]'s injectivity.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Nibbles(Vec<u8>);

impl<'de> Deserialize<'de> for Nibbles {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Vec::<u8>::deserialize(deserializer)?;
        if let Some(bad) = raw.iter().find(|n| **n > 0x0f) {
            return Err(serde::de::Error::custom(format!(
                "nibble {bad} is outside the radix-16 alphabet"
            )));
        }
        Ok(Nibbles(raw))
    }
}

impl Nibbles {
    /// An empty sequence.
    pub fn new() -> Self {
        Nibbles(Vec::new())
    }

    /// Expands a byte string into nibbles, high nibble first.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut v = Vec::with_capacity(bytes.len() * 2);
        for b in bytes {
            v.push(b >> 4);
            v.push(b & 0x0f);
        }
        Nibbles(v)
    }

    /// Builds from raw nibble values, masking each to 4 bits.
    pub fn from_nibbles(nibbles: &[u8]) -> Self {
        Nibbles(nibbles.iter().map(|n| n & 0x0f).collect())
    }

    /// Packs an even-length nibble sequence back into bytes; `None` for odd
    /// lengths, which cannot correspond to a byte-string key.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        if !self.0.len().is_multiple_of(2) {
            return None;
        }
        Some(
            self.0
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&[hi, lo]| (hi << 4) | lo)
                .collect(),
        )
    }

    /// The nibbles as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// The number of nibbles.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if there are no nibbles.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A new sequence with `prefix` prepended.
    pub(crate) fn prepend_all(&self, prefix: &[u8]) -> Nibbles {
        let mut v = Vec::with_capacity(self.0.len() + prefix.len());
        v.extend(prefix.iter().map(|n| n & 0x0f));
        v.extend_from_slice(&self.0);
        Nibbles(v)
    }
}

impl From<&[u8]> for Nibbles {
    fn from(nibbles: &[u8]) -> Self {
        Nibbles::from_nibbles(nibbles)
    }
}

/// The length of the longest common prefix of two nibble slices.
pub(crate) fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nibble_codec() {
        // High nibble first, so nibble order agrees with byte order — the
        // ordering canonical hashing and prefix scans rely on.
        let bytes = b"f:photos/a.jpg";
        let n = Nibbles::from_bytes(bytes);
        assert_eq!(n.len(), bytes.len() * 2);
        assert_eq!(n.to_bytes().unwrap(), bytes.to_vec());
        assert_eq!(Nibbles::from_bytes(&[0xab]).as_slice(), &[0x0a, 0x0b]);

        // Odd lengths have no byte form; helpers used by collect.
        assert!(Nibbles::from_nibbles(&[1, 2, 3]).to_bytes().is_none());
        let m = Nibbles::from_nibbles(&[3, 4]);
        assert_eq!(m.prepend_all(&[0, 1]).as_slice(), &[0, 1, 3, 4]);
        assert_eq!(common_prefix_len(&[1, 2, 3], &[1, 2, 9]), 2);
        assert_eq!(common_prefix_len(&[1], &[2]), 0);
        assert_eq!(common_prefix_len(&[], &[1]), 0);

        // Lexicographic nibble order must agree with byte order.
        assert!(Nibbles::from_bytes(b"ab") < Nibbles::from_bytes(b"abc"));
        assert!(Nibbles::from_bytes(b"abc") < Nibbles::from_bytes(b"abd"));
    }
}
