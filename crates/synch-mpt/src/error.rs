//! Errors produced by trie operations.

use synch_core::Hash;

/// An error from a trie operation.
#[derive(Debug, thiserror::Error)]
pub enum MptError {
    /// A node referenced by the trie was not in the node store.
    ///
    /// During anti-entropy this is the normal signal that more nodes must be
    /// fetched (§5.2); after a complete head flip it indicates corruption.
    #[error("missing trie node {0}")]
    MissingNode(Hash),
    /// An out-of-line value referenced by a leaf was not in the value store.
    #[error("missing out-of-line trie value {0}")]
    MissingValue(Hash),
    /// A stored or received node could not be decoded, or was not canonical.
    #[error("malformed trie node: {0}")]
    Decode(String),
    /// A node did not hash to the hash it was requested by (§5.2).
    #[error("trie node hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The hash the node was requested by.
        expected: Hash,
        /// The hash the received bytes actually have.
        actual: Hash,
    },
    /// A key exceeded the §12 bound.
    #[error("trie key too long: {0} bytes (max {max})", max = synch_core::MAX_KEY_LEN)]
    KeyTooLong(usize),
    /// A node was well-formed and correctly hashed but broke one of the
    /// structural invariants the node kinds document (§4.3).
    ///
    /// The write path maintains these by construction; a node arriving from a
    /// peer is only decoded, so they are checked at the trust boundary
    /// ([`TrieNode::hash_of_encoded`](crate::TrieNode::hash_of_encoded)).
    /// Accepting such a node does not corrupt anything on its own, but it puts
    /// the readers into disagreement — an empty extension prefix is followed by
    /// `get` and skipped by every structural walk — and it gives one key/value
    /// map more than one root, which defeats structural sharing.
    #[error("trie node breaks a structural invariant: {0}")]
    NonCanonical(String),
    /// The trie contained a value at an odd nibble depth, which no byte-string
    /// key can produce.
    #[error("trie contains a value at an odd nibble depth")]
    OddDepthValue,
    /// The backing store failed.
    #[error("trie store error: {0}")]
    Store(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl MptError {
    /// Wraps a store error.
    pub fn store<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        MptError::Store(Box::new(e))
    }
}
