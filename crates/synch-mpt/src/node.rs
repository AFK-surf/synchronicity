//! Trie nodes, their canonical encoding, and their domain-separated hashing (§4.3).

use serde::{Deserialize, Serialize};
use synch_core::{Hash, INLINE_VALUE_MAX, MAX_KEY_LEN};

use crate::{error::MptError, nibbles::Nibbles};

/// Domain-separation tag for [`TrieNode::Leaf`] hashing.
pub const LEAF_TAG: &[u8] = b"synch-mpt/1/leaf";
/// Domain-separation tag for [`TrieNode::Ext`] hashing.
pub const EXT_TAG: &[u8] = b"synch-mpt/1/ext";
/// Domain-separation tag for [`TrieNode::Branch`] hashing.
pub const BRANCH_TAG: &[u8] = b"synch-mpt/1/branch";

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
    pub fn out_of_line(&self) -> Option<Hash> {
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

    /// Computes the hash of an already-encoded node, re-deriving its tag.
    ///
    /// This is the function the sync path uses to verify that a received node
    /// really hashes to the hash it was requested by (§5.2).
    pub fn hash_of_encoded(bytes: &[u8]) -> Result<Hash, MptError> {
        let node = TrieNode::decode(bytes)?;
        // Re-encode: a node whose encoding is not canonical must not verify,
        // otherwise a peer could smuggle padding past the hash check.
        let canonical = node.encode();
        if canonical != bytes {
            return Err(MptError::Decode("non-canonical node encoding".into()));
        }
        // Bound the node's key portion at the sync trust boundary. A key is
        // never longer than MAX_KEY_LEN bytes (§12), so a single node's nibble
        // run can never exceed twice that. Without it a peer could serve a
        // hash-valid Leaf whose key_rest is megabytes of nibbles, and every
        // reader would then walk it: `collect` and `diff_walk` use heap stacks
        // and prune at MAX_DEPTH_NIBBLES, so what it costs is work rather than a
        // stack overflow, but it is work proportional to a number the peer
        // chose. This bounds one node; `MissingWalk::next_batch` bounds the
        // *path*, which is the half a per-node cap cannot see.
        let nibble_len = match &node {
            TrieNode::Leaf { key_rest, .. } => key_rest.len(),
            TrieNode::Ext { prefix, .. } => prefix.len(),
            TrieNode::Branch { .. } => 0,
        };
        if nibble_len > MAX_KEY_LEN * 2 {
            return Err(MptError::KeyTooLong(nibble_len / 2));
        }
        node.check_invariants()?;
        Ok(hash_encoded(node.tag(), bytes))
    }

    /// Checks the structural invariants the node kinds document (§4.3).
    ///
    /// The write path maintains all of these by construction — `collapse`,
    /// `merge_down` and `wrap_in_ext` exist precisely to — so this is only ever
    /// about nodes that arrived from a peer. Each one is load-bearing:
    ///
    /// - An **empty extension prefix** is what a canonical trie never contains:
    ///   `collapse` and `merge_down` exist to remove the shape. Accepting one
    ///   would give a single key/value map two roots, which is exactly what
    ///   structural sharing and the reference-pruning walk rest on not
    ///   happening. (`Trie::get` refuses to follow one as well, and
    ///   `ingest_boundary`'s `get_and_the_structural_walks_agree_even_if_one_slips_through`
    ///   pins that the two readers answer alike — so the *reader disagreement*
    ///   this used to describe is closed at both ends, and this check is what
    ///   keeps the shape from being stored at all.)
    /// - An **oversized inline value** is 128 bytes by construction
    ///   ([`INLINE_VALUE_MAX`]); decoded, it is bounded only by the frame, so a
    ///   peer could put 16 MiB in a single node and have every diff clone it.
    /// - An **under-occupied branch** and an **extension above a non-branch**
    ///   are read consistently, so they corrupt nothing — but they give one
    ///   key/value map several distinct roots, which is exactly what structural
    ///   sharing and the reference-pruning walk rely on not happening.
    ///
    /// Two halves of this need more than one node and are therefore checked
    /// where the structure is walked and where values arrive, not here:
    /// **an extension above a non-branch** needs the child node
    /// ([`crate::MissingWalk::next_batch`]), and **an out-of-line value small
    /// enough to be inline** needs the payload, which only the fetch that
    /// carries it has seen.
    pub fn check_invariants(&self) -> Result<(), MptError> {
        let non_canonical = |what: &str| Err(MptError::NonCanonical(what.to_string()));
        let check_value = |value: &ValueRef| match value {
            ValueRef::Inline(bytes) if bytes.len() > INLINE_VALUE_MAX => {
                Err(MptError::NonCanonical(format!(
                    "inline value of {} bytes exceeds the {INLINE_VALUE_MAX}-byte ceiling",
                    bytes.len()
                )))
            }
            _ => Ok(()),
        };
        match self {
            TrieNode::Leaf { value, .. } => check_value(value),
            TrieNode::Ext { prefix, .. } => {
                if prefix.is_empty() {
                    return non_canonical("an extension prefix is empty");
                }
                Ok(())
            }
            TrieNode::Branch { children, value } => {
                if let Some(value) = value {
                    check_value(value)?;
                }
                let occupants = children.iter().flatten().count() + usize::from(value.is_some());
                if occupants < 2 {
                    return non_canonical("a branch has fewer than two occupants");
                }
                Ok(())
            }
        }
    }

    /// The hashes of this node's child nodes.
    pub fn child_hashes(&self) -> Vec<Hash> {
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

/// Hashes an encoded node under an explicit domain-separation tag.
pub fn hash_encoded(tag: &[u8], encoded: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher.update(encoded);
    Hash(*hasher.finalize().as_bytes())
}

/// An empty child array, for building branches.
pub const NO_CHILDREN: [Option<Hash>; 16] = [None; 16];

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
