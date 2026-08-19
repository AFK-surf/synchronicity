//! Which part of a trie a peer may see (§5.5).
//!
//! Scope is a statement about *where* a node sits, never about which node it
//! is. A hash cannot carry it: the hash of a redacted subtree is inside the
//! branch node that makes the root verify, so possession of one proves nothing
//! about entitlement to it — and position cannot be recovered from a hash
//! either, because structural sharing lets one node sit under several prefixes.
//! So both sides of a fetch work in nibble paths, and this is the predicate
//! they share.
//!
//! Redaction itself is free. A branch node already carries the hashes of all
//! sixteen children, so withholding a subtree means declining to send its
//! nodes: the parent that *was* sent already commits to it, and the signed root
//! recomputes exactly as it would from a whole trie. The boundary is therefore
//! the child hash inside the last in-scope node, never the first out-of-scope
//! node — an [`crate::node::TrieNode::Ext`] above an undelegated space spells
//! that space's name in its prefix, so it is the node that must not travel.

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

    /// True if a node sitting at nibble `path` may be served.
    ///
    /// A node at `path` commits to every key beginning with `path`, so it is
    /// in scope when it is an ancestor of an allowed prefix or sits inside
    /// one. Both directions matter: the ancestors are the spine that makes the
    /// root verify, and without them a scoped peer could not check the
    /// signature it was handed.
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
    /// leave the scope — which is what lets a scope check stop at the boundary
    /// instead of walking the subtree it has just admitted. Exact keys are
    /// deliberately absent: a subtree at an exact key may hold longer keys
    /// extending it, and those are outside.
    pub fn contains_subtree(&self, path: &[u8]) -> bool {
        match &self.prefixes {
            None => true,
            Some(prefixes) => prefixes.iter().any(|p| path.starts_with(p.as_slice())),
        }
    }

    /// True if a key, given as a full nibble path, lies inside this scope.
    pub fn admits_key_path(&self, key: &[u8]) -> bool {
        self.contains_subtree(key) || self.exact.iter().any(|k| k == key)
    }

    /// True if a node at `path` may be served whole, given what it reveals.
    ///
    /// Position alone is not enough, and this is the subtle half of the
    /// boundary. A `Branch` reveals only child hashes, so its position is the
    /// whole story — but the trie compresses, and a compressed node carries
    /// key material of its own: an `Ext` spells the nibbles between its
    /// position and its child, and a `Leaf` spells the rest of a key together
    /// with that key's value. Both sit at a position on the spine that the
    /// scope legitimately admits — the spine is what makes the signed root
    /// recompute — while describing a key range that runs out of the scope
    /// entirely. Serving one hands over the name of a space the peer was never
    /// granted, and in a leaf's case its record too.
    ///
    /// So what is tested here is the node's *coverage*, not its position.
    pub fn admits_node(&self, path: &[u8], node: &crate::node::TrieNode) -> bool {
        if self.is_full() {
            return true;
        }
        match node {
            crate::node::TrieNode::Branch { value, .. } => {
                value.is_none() || self.admits_key_path(path)
            }
            crate::node::TrieNode::Ext { prefix, .. } => {
                let mut covered = path.to_vec();
                covered.extend_from_slice(prefix.as_slice());
                self.admits_path(&covered)
            }
            crate::node::TrieNode::Leaf { key_rest, .. } => {
                let mut key = path.to_vec();
                key.extend_from_slice(key_rest.as_slice());
                self.admits_key_path(&key)
            }
        }
    }

    /// True if a whole byte key lies inside this scope.
    ///
    /// Stricter than [`Scope::admits_path`]: a key is a leaf position, so
    /// being an ancestor of an allowed prefix is not enough — `f:` is on the
    /// spine of every space, and is nobody's key.
    pub fn admits_key(&self, key: &[u8]) -> bool {
        match self.prefixes {
            None => true,
            Some(_) => self.admits_key_path(Nibbles::from_bytes(key).as_slice()),
        }
    }

    /// The key a completeness answer for `root` may be memoized under.
    ///
    /// "Do I hold all of this?" is a question about a root *and* a scope: a
    /// trie held whole under one scope is not held whole under a wider one,
    /// and a memo keyed by the root alone would answer the second question
    /// with the first one's answer. Folding the scope into the key makes a
    /// widened scope re-derive rather than inherit, with nothing to
    /// invalidate.
    pub fn memo_key(&self, root: Hash) -> Hash {
        match &self.prefixes {
            None => root,
            Some(prefixes) => {
                let mut bytes = Vec::with_capacity(64);
                bytes.extend_from_slice(b"scoped-root/1");
                bytes.extend_from_slice(root.as_bytes());
                for set in [prefixes, &self.exact] {
                    bytes.extend_from_slice(&(set.len() as u32).to_le_bytes());
                    for key in set {
                        bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
                        bytes.extend_from_slice(key);
                    }
                }
                Hash::new(&bytes)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(bytes: &[u8]) -> Vec<u8> {
        Nibbles::from_bytes(bytes).as_slice().to_vec()
    }

    #[test]
    fn a_full_scope_admits_everything() {
        let scope = Scope::full();
        assert!(scope.is_full());
        assert!(scope.admits_path(&path(b"anything")));
        assert!(scope.admits_key(b"f:finance/q3.pdf"));
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

    #[test]
    fn an_empty_scope_grants_no_view() {
        let scope = Scope::of(&synch_core::ScopeKeys::default());
        assert!(!scope.is_full());
        assert!(!scope.admits_path(&[]));
        assert!(!scope.admits_key(b"f:photos/a.jpg"));
    }

    /// One space id being a prefix of another must not carry it along.
    ///
    /// `f:<space>/` bounds itself with a separator no id may contain, but a
    /// space's own `m:space/<id>` record does not — treated as a prefix it
    /// would hand a delegate of `photos` the record of `photos-raw`, which
    /// carries that space's entry count and the absolute local path its origin
    /// keeps it at.
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

    /// A compressed node is judged by what it reveals, not by where it sits.
    #[test]
    fn a_node_is_judged_by_its_coverage() {
        use crate::node::TrieNode;
        let scope = Scope::of(&synch_core::scope_prefixes(&["photos".to_string()]));
        let spine = path(b"f:");
        // An extension leading into the grant may travel; one leading away
        // spells the other space's name in its own prefix and may not.
        let toward = TrieNode::Ext {
            prefix: Nibbles::from_bytes(b"photos/"),
            child: Hash::new(b"c"),
        };
        let away = TrieNode::Ext {
            prefix: Nibbles::from_bytes(b"finance/"),
            child: Hash::new(b"c"),
        };
        assert!(scope.admits_node(&spine, &toward));
        assert!(!scope.admits_node(&spine, &away));
        // A leaf completes a whole key, and carries that key's value with it.
        let leaf = |rest: &[u8]| TrieNode::Leaf {
            key_rest: Nibbles::from_bytes(rest),
            value: crate::node::ValueRef::Inline(vec![1]),
        };
        assert!(scope.admits_node(&spine, &leaf(b"photos/a.jpg")));
        assert!(!scope.admits_node(&spine, &leaf(b"finance/q3.pdf")));
        // A full scope judges nothing.
        assert!(Scope::full().admits_node(&spine, &away));
    }

    #[test]
    fn a_completeness_memo_is_keyed_by_root_and_scope() {
        let root = Hash::new(b"root");
        let other = Hash::new(b"other");
        let photos = Scope::of(&synch_core::ScopeKeys {
            prefixes: vec![b"f:photos/".to_vec()],
            exact: Vec::new(),
        });
        let finance = Scope::of(&synch_core::ScopeKeys {
            prefixes: vec![b"f:finance/".to_vec()],
            exact: Vec::new(),
        });
        // A trie held whole under one scope is not held whole under another,
        // and never under the full one.
        assert_ne!(photos.memo_key(root), finance.memo_key(root));
        assert_ne!(photos.memo_key(root), Scope::full().memo_key(root));
        assert_ne!(photos.memo_key(root), photos.memo_key(other));
        assert_eq!(Scope::full().memo_key(root), root);
    }
}
