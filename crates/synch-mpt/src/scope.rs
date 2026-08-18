//! Which part of a trie a peer may see (§8).
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
}

impl Scope {
    /// The whole keyspace: what a rooted member holds and serves.
    pub fn full() -> Scope {
        Scope { prefixes: None }
    }

    /// Only keys under one of `prefixes`, given as byte prefixes.
    ///
    /// An empty list is a scope that admits nothing, which is the right
    /// reading of a delegation that named no space: it grants no view rather
    /// than every view.
    pub fn of(prefixes: &[Vec<u8>]) -> Scope {
        Scope {
            prefixes: Some(
                prefixes
                    .iter()
                    .map(|p| Nibbles::from_bytes(p).as_slice().to_vec())
                    .collect(),
            ),
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
            Some(prefixes) => prefixes
                .iter()
                .any(|p| p.starts_with(path) || path.starts_with(p.as_slice())),
        }
    }

    /// True if everything below `path` is inside this scope.
    ///
    /// Once a position sits inside a granted prefix, no descent below it can
    /// leave the scope — which is what lets a scope check stop at the boundary
    /// instead of walking the subtree it has just admitted.
    pub fn contains_subtree(&self, path: &[u8]) -> bool {
        match &self.prefixes {
            None => true,
            Some(prefixes) => prefixes.iter().any(|p| path.starts_with(p.as_slice())),
        }
    }

    /// True if a key, given as a full nibble path, lies inside this scope.
    pub fn admits_key_path(&self, key: &[u8]) -> bool {
        self.contains_subtree(key)
    }

    /// True if a whole byte key lies inside this scope.
    ///
    /// Stricter than [`Scope::admits_path`]: a key is a leaf position, so
    /// being an ancestor of an allowed prefix is not enough — `f:` is on the
    /// spine of every space, and is nobody's key.
    pub fn admits_key(&self, key: &[u8]) -> bool {
        match &self.prefixes {
            None => true,
            Some(prefixes) => {
                let nibbles = Nibbles::from_bytes(key);
                prefixes
                    .iter()
                    .any(|p| nibbles.as_slice().starts_with(p.as_slice()))
            }
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
                for prefix in prefixes {
                    bytes.extend_from_slice(&(prefix.len() as u32).to_le_bytes());
                    bytes.extend_from_slice(prefix);
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
        let scope = Scope::of(&[b"f:photos/".to_vec()]);
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
        let scope = Scope::of(&[b"f:photos/".to_vec()]);
        assert!(scope.admits_path(&path(b"f:")));
        assert!(!scope.admits_key(b"f:"));
    }

    #[test]
    fn an_empty_scope_grants_no_view() {
        let scope = Scope::of(&[]);
        assert!(!scope.is_full());
        assert!(!scope.admits_path(&[]));
        assert!(!scope.admits_key(b"f:photos/a.jpg"));
    }

    #[test]
    fn a_completeness_memo_is_keyed_by_root_and_scope() {
        let root = Hash::new(b"root");
        let other = Hash::new(b"other");
        let photos = Scope::of(&[b"f:photos/".to_vec()]);
        let finance = Scope::of(&[b"f:finance/".to_vec()]);
        // A trie held whole under one scope is not held whole under another,
        // and never under the full one.
        assert_ne!(photos.memo_key(root), finance.memo_key(root));
        assert_ne!(photos.memo_key(root), Scope::full().memo_key(root));
        assert_ne!(photos.memo_key(root), photos.memo_key(other));
        assert_eq!(Scope::full().memo_key(root), root);
    }
}
