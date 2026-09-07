//! Which part of a trie a peer may see (§5.5).
//!
//! Scope is a statement about *where* a node sits, never about which node it
//! is: a hash cannot carry it — the hash of a redacted subtree sits inside the
//! branch node that makes the root verify, and position cannot be recovered
//! from a hash because structural sharing lets one node sit under several
//! prefixes — so both sides of a fetch work in nibble paths, and this is the
//! predicate they share.
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

    /// True if a node sitting at nibble `path` may be served.
    ///
    /// A node at `path` commits to every key beginning with `path`, so it is
    /// in scope as an ancestor of an allowed prefix or inside one. Both
    /// directions matter: the ancestors are the spine that makes the signed
    /// root recompute.
    // The executable Lean predicate is `Trie.Serve.Scope.admitsPath`;
    // `TrieServeProofs.admitsPath_of_append` proves its spine property.
    pub fn admits_path(&self, path: &[u8]) -> bool {
        match &self.prefixes {
            None => true,
            Some(prefixes) => {
                prefixes
                    .iter()
                    .any(|p| p.starts_with(path) || path.starts_with(p.as_slice()))
                    // An exact key admits the spine down to it and the key
                    // itself — never a position *below* it, which would be a
                    // longer key the scope does not cover.
                    || self.exact.iter().any(|k| k.starts_with(path))
            }
        }
    }

    /// True if everything below `path` is inside this scope.
    ///
    /// Once a position sits inside a granted prefix, no descent below it can
    /// leave — which lets a scope check stop at the boundary. Exact keys are
    /// deliberately absent: a subtree at an exact key may hold longer keys
    /// extending it, and those are outside.
    // The executable Lean predicate is `Trie.Serve.Scope.containsSubtree`;
    // `TrieServeProofs.containsSubtree_append` is the stop-at-the-
    // boundary property.
    pub fn contains_subtree(&self, path: &[u8]) -> bool {
        match &self.prefixes {
            None => true,
            Some(prefixes) => prefixes.iter().any(|p| path.starts_with(p.as_slice())),
        }
    }

    /// True if a key, given as a full nibble path, lies inside this scope.
    pub(crate) fn admits_key_path(&self, key: &[u8]) -> bool {
        self.contains_subtree(key) || self.exact.iter().any(|k| k == key)
    }

    /// True if a whole byte key lies inside this scope.
    ///
    /// Stricter than [`Scope::admits_path`]: a key is a leaf position, so
    /// being an ancestor of an allowed prefix is not enough — `f:` is on the
    /// spine of every space, and is nobody's key. Production admission works
    /// in nibbles (`admits_key_path`); this byte-key form is what the tests
    /// below state the rules through.
    #[cfg(test)]
    pub(crate) fn admits_key(&self, key: &[u8]) -> bool {
        match self.prefixes {
            None => true,
            Some(_) => self.admits_key_path(Nibbles::from_bytes(key).as_slice()),
        }
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

    #[test]
    fn scope_extremes_admit_or_grant_nothing() {
        let scope = Scope::full();
        assert!(scope.is_full());
        assert!(scope.admits_path(&path(b"anything")));
        assert!(scope.admits_key(b"f:finance/q3.pdf"));

        let scope = Scope::of(&synch_core::ScopeKeys::default());
        assert!(!scope.is_full());
        assert!(!scope.admits_path(&[]));
        assert!(!scope.admits_key(b"f:photos/a.jpg"));
    }

    #[test]
    fn the_spine_is_admitted_and_the_sibling_is_not() {
        let scope = Scope::of(&synch_core::ScopeKeys {
            prefixes: vec![b"f:photos/".to_vec()],
            exact: Vec::new(),
        });
        // The root and everything above the granted subtree: the spine a
        // scoped peer needs to recompute the signed root.
        assert!(scope.admits_path(&[]));
        assert!(scope.admits_path(&path(b"f")));
        assert!(scope.admits_path(&path(b"f:pho")));
        // Inside the grant.
        assert!(scope.admits_path(&path(b"f:photos/2024/")));
        // The sibling subtree, which is the whole point.
        assert!(!scope.admits_path(&path(b"f:finance/")));
        assert!(!scope.admits_key(b"f:finance/q3.pdf"));
        assert!(scope.admits_key(b"f:photos/a.jpg"));
    }

    #[test]
    fn a_spine_position_is_not_a_key() {
        // `f:` is on the path to every space and is nobody's key: admitting it
        // as a *path* is what lets the root verify, admitting it as a *key*
        // would hand over a value the peer was never granted.
        let scope = Scope::of(&synch_core::ScopeKeys {
            prefixes: vec![b"f:photos/".to_vec()],
            exact: Vec::new(),
        });
        assert!(scope.admits_path(&path(b"f:")));
        assert!(!scope.admits_key(b"f:"));
    }

    /// One space id being a prefix of another must not carry it along.
    ///
    /// `f:<space>/` bounds itself with a separator no id may contain, but a
    /// space's own `m:space/<id>` record does not — as a prefix it would hand
    /// a delegate of `photos` the record of `photos-raw`, with its entry count
    /// and absolute local path.
    #[test]
    fn an_exact_key_does_not_carry_its_extensions() {
        let scope = Scope::of(&synch_core::scope_prefixes(&["photos".to_string()]));
        assert!(scope.admits_key(b"m:space/photos"));
        assert!(!scope.admits_key(b"m:space/photos-raw"));
        assert!(!scope.admits_key(b"m:space/photography"));
        // `m:self` the same way: nothing under it comes with it.
        assert!(scope.admits_key(b"m:self"));
        assert!(!scope.admits_key(b"m:selfie"));
        // The spine down to an exact key is still admitted, or the root would
        // not recompute.
        assert!(scope.admits_path(&path(b"m:")));
        // And `f:` keeps working the way it always did.
        assert!(scope.admits_key(b"f:photos/a.jpg"));
        assert!(!scope.admits_key(b"f:photos-raw/a.jpg"));
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
