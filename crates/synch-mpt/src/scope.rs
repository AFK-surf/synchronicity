//! Which part of a trie a peer may see (§5.5).
//!
//! Scope is a statement about *where* a node sits, never about which node it
//! is: a hash cannot carry it — the hash of a redacted subtree sits inside the
//! branch node that makes the root verify, and position cannot be recovered
//! from a hash because structural sharing lets one node sit under several
//! prefixes — so both sides of a fetch work in nibble paths, and Lean owns the
//! predicates and complete operations that enforce this scope.
//!
//! Redaction itself is free: a branch node already carries all sixteen child
//! hashes, so withholding a subtree means declining to send its nodes, and the
//! signed root recomputes exactly as from a whole trie. The boundary is the
//! child hash inside the last in-scope node, never the first out-of-scope node
//! — an [`crate::node::TrieNode::Ext`] above an undelegated space spells that
//! space's name in its prefix, so it must not travel.

use synch_core::Hash;

use crate::nibbles::Nibbles;

/// The trie key prefixes a peer may be served.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scope {
    /// Allowed nibble prefixes, or `None` for the whole keyspace.
    prefixes: Option<Vec<Vec<u8>>>,
    /// Allowed exact keys, as nibble paths. Empty when the scope is full.
    ///
    /// Separate from `prefixes` because a key that bounds nothing must not be
    /// read as one that bounds everything under it: `m:space/photos` used as a
    /// prefix would carry `m:space/photos-raw` with it.
    exact: Vec<Vec<u8>>,
}

impl Scope {
    /// The whole keyspace: what a rooted member holds and serves.
    pub fn full() -> Scope {
        Scope {
            prefixes: None,
            exact: Vec::new(),
        }
    }

    /// Only keys under one of `prefixes`, given as byte prefixes.
    ///
    /// An empty list is a scope that admits nothing, which is the right
    /// reading of a delegation that named no space: it grants no view rather
    /// than every view.
    pub fn of(keys: &synch_core::ScopeKeys) -> Scope {
        let nibbles = |set: &[Vec<u8>]| -> Vec<Vec<u8>> {
            set.iter()
                .map(|p| Nibbles::from_bytes(p).as_slice().to_vec())
                .collect()
        };
        Scope {
            prefixes: Some(nibbles(&keys.prefixes)),
            exact: nibbles(&keys.exact),
        }
    }

    /// True if this scope is the whole keyspace.
    pub fn is_full(&self) -> bool {
        self.prefixes.is_none()
    }

    /// The allowed nibble prefixes, or `None` for the whole keyspace: what a
    /// scope is, for the serving side to hand to Lean (`Trie.Serve.Scope`).
    pub fn prefixes(&self) -> Option<&[Vec<u8>]> {
        self.prefixes.as_deref()
    }

    /// The allowed exact keys, as nibble paths.
    pub fn exact(&self) -> &[Vec<u8>] {
        &self.exact
    }

    /// The key a completeness answer for `root` may be memoized under.
    ///
    /// "Do I hold all of this?" is a question about a root *and* a scope: a
    /// memo keyed by the root alone would answer a wider scope with a narrower
    /// one's answer. Folding the scope in makes a widened scope re-derive
    /// rather than inherit. "Do I hold all of this *as this origin's*?" is a
    /// third question, distinct from both: a trie held whole is not held
    /// whole with provenance, and the answers must not be confused.
    ///
    /// The layout is Lean's (`Trie.Memo.keyFor`), shared with the sweep that
    /// decides which certificates survive a collection; this side only hashes.
    pub fn memo_key_for(
        &self,
        owner: Option<&synch_core::OriginId>,
        root: Hash,
    ) -> Result<Hash, crate::MptError> {
        let owner = owner.map(|origin| origin.canonical());
        synch_verified::trie::memo_key(
            &mut crate::lean_storage::Blake3,
            root.as_bytes(),
            self.prefixes(),
            &self.exact,
            owner.as_deref(),
        )
        .map(Hash)
        .map_err(crate::lean_storage::operation_error)
    }

    /// The key a completeness answer for `root` may be memoized under, with
    /// no provenance in the question; see [`Scope::memo_key_for`].
    pub fn memo_key(&self, root: Hash) -> Result<Hash, crate::MptError> {
        self.memo_key_for(None, root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(bytes: &[u8]) -> Vec<u8> {
        Nibbles::from_bytes(bytes).as_slice().to_vec()
    }

    /// The serving side reads a scope back as exactly what it was built from.
    #[test]
    fn a_scope_hands_its_parts_to_the_serving_side() {
        assert_eq!(Scope::full().prefixes(), None);
        assert!(Scope::full().exact().is_empty());
        let scope = Scope::of(&synch_core::scope_prefixes(&["photos".to_string()]));
        let prefixes = scope.prefixes().expect("a delegated scope is bounded");
        assert!(prefixes.contains(&path(b"f:photos/")));
        assert!(scope.exact().contains(&path(b"m:space/photos")));
    }
}
