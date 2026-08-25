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
    /// A value exceeded the §12 bound.
    ///
    /// The counterpart of [`MptError::KeyTooLong`], and it did not exist: a
    /// value was bounded only by the frame it arrived in, which is what let one
    /// small trie cost every peer gigabytes to serve and terabytes to
    /// materialize ([`MAX_TRIE_VALUE_LEN`](synch_core::MAX_TRIE_VALUE_LEN)).
    #[error("trie value too long: {0} bytes (max {max})", max = synch_core::MAX_TRIE_VALUE_LEN)]
    ValueTooLong(usize),
    /// A node was well-formed and correctly hashed but broke one of the
    /// structural invariants the node kinds document (§4.3).
    ///
    /// The write path maintains these by construction; a node arriving from a
    /// peer is only decoded, so they are checked at the trust boundary
    /// ([`TrieNode::hash_of_encoded`](crate::TrieNode::hash_of_encoded)).
    /// Accepting such a node corrupts nothing on its own — every reader agrees
    /// about what it means — but it gives one key/value map more than one root,
    /// which defeats structural sharing and makes every peer's incremental sync
    /// cost the whole tree.
    #[error("trie node breaks a structural invariant: {0}")]
    NonCanonical(String),
    /// The trie contained a value at an odd nibble depth, which no byte-string
    /// key can produce.
    #[error("trie contains a value at an odd nibble depth")]
    OddDepthValue,
    /// A caller's own error ended a streaming walk.
    ///
    /// Never returned to that caller — [`Trie::for_each_resolved_change_scoped`] hands
    /// back the error it was carrying. It exists because the walk's own
    /// signature is `Result<_, MptError>` and a caller's error type is not one.
    ///
    /// [`Trie::for_each_resolved_change_scoped`]: crate::Trie::for_each_resolved_change_scoped
    #[error("a walk was stopped by its caller")]
    WalkStopped,
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
