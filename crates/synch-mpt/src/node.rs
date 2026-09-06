//! Trie nodes, their canonical encoding, and their domain-separated hashing (§4.3).

use serde::{Deserialize, Serialize};
use synch_core::{Hash, INLINE_VALUE_MAX};

use crate::{error::MptError, nibbles::Nibbles};

/// Domain-separation tag for [`TrieNode::Leaf`] hashing.
pub(crate) const LEAF_TAG: &[u8] = b"synch-mpt/1/leaf";
/// Domain-separation tag for [`TrieNode::Ext`] hashing.
pub(crate) const EXT_TAG: &[u8] = b"synch-mpt/1/ext";
/// Domain-separation tag for [`TrieNode::Branch`] hashing.
pub(crate) const BRANCH_TAG: &[u8] = b"synch-mpt/1/branch";

/// How a leaf's value is carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueRef {
    /// A value of at most [`INLINE_VALUE_MAX`] bytes, embedded in the node.
    Inline(Vec<u8>),
    /// A larger value, stored out-of-line and addressed by its BLAKE3 hash.
    Hash(Hash),
}

impl ValueRef {
    /// Chooses the representation for `value`, returning the out-of-line
    /// payload that must be stored alongside it, if any.
    pub fn for_value(value: &[u8]) -> (ValueRef, Option<(Hash, Vec<u8>)>) {
        if value.len() <= INLINE_VALUE_MAX {
            (ValueRef::Inline(value.to_vec()), None)
        } else {
            let hash = Hash::new(value);
            (ValueRef::Hash(hash), Some((hash, value.to_vec())))
        }
    }

    /// The out-of-line value hash, if this reference is not inline.
    pub(crate) fn out_of_line(&self) -> Option<Hash> {
        match self {
            ValueRef::Inline(_) => None,
            ValueRef::Hash(h) => Some(*h),
        }
    }
}

/// A node of the radix-16 Merkle-Patricia Trie.
// A branch carries 16 optional hashes and is therefore much larger than a leaf
// or an extension. Boxing it would add an allocation to every node load and
// would not shrink the encoded form, which is what actually goes on the wire.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrieNode {
    /// A terminal node holding the remaining key nibbles and a value.
    Leaf {
        /// Key nibbles below this node's position.
        key_rest: Nibbles,
        /// The value.
        value: ValueRef,
    },
    /// A path-compression node: a shared nibble prefix above a branch.
    ///
    /// Invariant: `prefix` is non-empty and `child` is always a
    /// [`TrieNode::Branch`]; an extension above anything else would have been
    /// merged during canonicalization.
    Ext {
        /// The shared nibble prefix.
        prefix: Nibbles,
        /// The branch below.
        child: Hash,
    },
    /// A 16-way branch, optionally carrying a value for the key that ends here.
    ///
    /// Invariant: a branch always has at least two occupants counting `value`
    /// and the non-`None` children; anything less collapses.
    Branch {
        /// Child hashes by nibble.
        children: [Option<Hash>; 16],
        /// The value of the key ending exactly at this node, if any.
        value: Option<ValueRef>,
    },
}

impl TrieNode {
    /// The canonical postcard encoding, as stored in `trie_nodes` (§10).
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("trie node encoding is infallible")
    }

    /// Decodes a node from its canonical encoding.
    pub fn decode(bytes: &[u8]) -> Result<TrieNode, MptError> {
        postcard::from_bytes(bytes).map_err(|e| MptError::Decode(e.to_string()))
    }

    /// The domain-separation tag for this node kind.
    pub fn tag(&self) -> &'static [u8] {
        match self {
            TrieNode::Leaf { .. } => LEAF_TAG,
            TrieNode::Ext { .. } => EXT_TAG,
            TrieNode::Branch { .. } => BRANCH_TAG,
        }
    }

    /// `BLAKE3(domain_sep || canonical postcard encoding)` (§4.3).
    pub fn hash(&self) -> Hash {
        hash_encoded(self.tag(), &self.encode())
    }

    /// The hash an already-encoded node is stored under, once the canonical
    /// ingress boundary admits it (§5.2, §12).
    ///
    /// The boundary is the Lean operation `Trie.admit`: the bytes must decode,
    /// re-encode to exactly themselves (so a peer cannot smuggle padding past
    /// the hash), keep one node's nibble run within twice
    /// [`MAX_KEY_LEN`](synch_core::MAX_KEY_LEN) (the per-node half of the depth
    /// bound; `MissingWalk::next_batch` bounds the *path*), and satisfy the
    /// structural invariants the node kinds document: a non-empty extension
    /// prefix, inline values within [`INLINE_VALUE_MAX`], at least two
    /// occupants of a branch. Two halves need more than one node and are
    /// checked where the structure is walked and where values arrive: an
    /// extension above a non-branch ([`crate::MissingWalk::next_batch`]), and
    /// an out-of-line value small enough to be inline (the fetch's `put`).
    ///
    /// Rust supplies the BLAKE3 primitive and names the refusal; the decision
    /// is Lean's, and the same-source proofs in `specs/lean` are about it.
    pub fn hash_of_encoded(bytes: &[u8]) -> Result<Hash, MptError> {
        match synch_verified::trie::admit(&mut crate::lean_storage::Blake3, bytes)
            .map_err(crate::lean_storage::operation_error)?
        {
            Ok(hash) => Ok(Hash(hash)),
            Err(refusal) => Err(crate::lean_storage::refusal_error(refusal)),
        }
    }

    /// Whether served bytes are the node they were requested as and, when
    /// they are not, whose fault that is (§12).
    ///
    /// A node hash covers the raw bytes exactly as served, so bytes that hash
    /// to the hash they were requested by under some kind's tag are the
    /// origin's own (a relaying peer cannot have altered them), and a shape
    /// this build then refuses is that origin's fault and nobody else's. Bytes
    /// that hash to nothing wanted are the peer's. The decision is the Lean
    /// operation `Trie.verify`; the `Err` here is a host or transport failure,
    /// never a verdict.
    pub fn verify_served(expected: &Hash, bytes: &[u8]) -> Result<Verdict, MptError> {
        use synch_verified::trie::NodeVerdict;
        match synch_verified::trie::verify(&mut crate::lean_storage::Blake3, &expected.0, bytes)
            .map_err(crate::lean_storage::operation_error)?
        {
            NodeVerdict::Accepted => Ok(Verdict::Accepted),
            NodeVerdict::OriginFault(refusal) => Ok(Verdict::OriginFault(
                crate::lean_storage::refusal_error(refusal),
            )),
            NodeVerdict::PeerFault => Ok(Verdict::PeerFault),
        }
    }

    /// The hashes of this node's child nodes.
    pub(crate) fn child_hashes(&self) -> Vec<Hash> {
        match self {
            TrieNode::Leaf { .. } => Vec::new(),
            TrieNode::Ext { child, .. } => vec![*child],
            TrieNode::Branch { children, .. } => children.iter().flatten().copied().collect(),
        }
    }

    /// The hashes of any out-of-line values this node references.
    pub fn value_hashes(&self) -> Vec<Hash> {
        match self {
            TrieNode::Leaf { value, .. } => value.out_of_line().into_iter().collect(),
            TrieNode::Ext { .. } => Vec::new(),
            TrieNode::Branch { value, .. } => value
                .as_ref()
                .and_then(ValueRef::out_of_line)
                .into_iter()
                .collect(),
        }
    }

    /// Builds a leaf.
    pub fn leaf(key_rest: Nibbles, value: ValueRef) -> TrieNode {
        TrieNode::Leaf { key_rest, value }
    }

    /// Builds an extension node.
    pub fn ext(prefix: Nibbles, child: Hash) -> TrieNode {
        debug_assert!(!prefix.is_empty(), "extension prefixes must be non-empty");
        TrieNode::Ext { prefix, child }
    }
}

/// What [`TrieNode::verify_served`] decided about served bytes.
#[derive(Debug)]
pub enum Verdict {
    /// The bytes are the requested node, canonical and within bounds.
    Accepted,
    /// The requested hash covers the bytes, but this build refuses their
    /// shape: the origin published them, so the fault is contained to it.
    OriginFault(MptError),
    /// The bytes hash to nothing wanted: the serving peer's fault.
    PeerFault,
}

/// Hashes an encoded node under an explicit domain-separation tag.
pub fn hash_encoded(tag: &[u8], encoded: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher.update(encoded);
    Hash(*hasher.finalize().as_bytes())
}

/// An empty child array, for building branches by hand in tests; the write
/// path builds its branches in Lean.
#[cfg(test)]
pub(crate) const NO_CHILDREN: [Option<Hash>; 16] = [None; 16];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_ref_inlines_small_values() {
        // Exactly at the boundary stays inline; one byte past it goes out of
        // line — the split decides node hashing and wire shape.
        let edge = vec![7u8; INLINE_VALUE_MAX];
        let (r, extra) = ValueRef::for_value(&edge);
        assert!(matches!(r, ValueRef::Inline(_)));
        assert!(extra.is_none());

        let big = vec![7u8; INLINE_VALUE_MAX + 1];
        let (r, extra) = ValueRef::for_value(&big);
        let (h, payload) = extra.unwrap();
        assert_eq!(r, ValueRef::Hash(h));
        assert_eq!(h, Hash::new(&big));
        assert_eq!(payload, big);
    }

    #[test]
    fn encoding_round_trips() {
        let nodes = [
            TrieNode::leaf(Nibbles::from_bytes(b"ab"), ValueRef::Inline(vec![1])),
            TrieNode::ext(Nibbles::from_nibbles(&[1, 2]), Hash::new(b"c")),
            TrieNode::Branch {
                children: {
                    let mut c = NO_CHILDREN;
                    c[3] = Some(Hash::new(b"x"));
                    c[9] = Some(Hash::new(b"y"));
                    c
                },
                value: Some(ValueRef::Hash(Hash::new(b"v"))),
            },
        ];
        for n in nodes {
            let bytes = n.encode();
            assert_eq!(TrieNode::decode(&bytes).unwrap(), n);
            assert_eq!(TrieNode::hash_of_encoded(&bytes).unwrap(), n.hash());
        }
        // Domain-separated hashing: the same bytes hash differently under
        // another kind's tag, so no encoding can be reinterpreted as another.
        let leaf = TrieNode::leaf(Nibbles::from_bytes(b"ab"), ValueRef::Inline(vec![1]));
        let bytes = leaf.encode();
        assert_ne!(LEAF_TAG, EXT_TAG);
        assert_ne!(
            hash_encoded(LEAF_TAG, &bytes),
            hash_encoded(EXT_TAG, &bytes)
        );
    }

    #[test]
    fn non_canonical_encodings_are_rejected() {
        let leaf = TrieNode::leaf(Nibbles::from_bytes(b"a"), ValueRef::Inline(vec![1]));
        let mut bytes = leaf.encode();
        bytes.push(0);
        assert!(TrieNode::hash_of_encoded(&bytes).is_err());
    }
}
