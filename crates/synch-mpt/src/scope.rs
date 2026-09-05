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
#[derive(Debug, Clone)]
pub struct Scope {
    /// Allowed nibble prefixes, or `None` for the whole keyspace.
    prefixes: Option<Vec<Vec<u8>>>,
    /// Allowed exact keys, as nibble paths. Empty when the scope is full.
    ///
    /// Separate from `prefixes` because a key that bounds nothing must not be
    /// read as one that bounds everything under it: `m:space/photos` used as a
    /// prefix would carry `m:space/photos-raw` with it.
    exact: Vec<Vec<u8>>,
    native: synch_verified::Scope,
}

impl Default for Scope {
    fn default() -> Self {
        Self::full()
    }
}

impl PartialEq for Scope {
    fn eq(&self, other: &Self) -> bool {
        self.prefixes == other.prefixes && self.exact == other.exact
    }
}
impl Eq for Scope {}

impl Scope {
    /// The whole keyspace: what a rooted member holds and serves.
    pub fn full() -> Scope {
        Scope {
            prefixes: None,
            exact: Vec::new(),
            native: synch_verified::Scope::new(None, &[]),
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
        let prefixes = nibbles(&keys.prefixes);
        let exact = nibbles(&keys.exact);
        Scope {
            native: synch_verified::Scope::new(Some(&prefixes), &exact),
            prefixes: Some(prefixes),
            exact,
        }
    }

    /// True if this scope is the whole keyspace.
    pub fn is_full(&self) -> bool {
        self.prefixes.is_none()
    }

    /// True if a node sitting at nibble `path` may be served.
    ///
    /// A node at `path` commits to every key beginning with `path`, so it is
    /// in scope as an ancestor of an allowed prefix or inside one. Both
    /// directions matter: the ancestors are the spine that makes the signed
    /// root recompute.
    // LEAN-MODEL: mpt-scope-admits-path (Scope.AdmitsPath)
    // `Scope.AdmitsPath`; `admitsPath_of_append` is the spine property.
    pub fn admits_path(&self, path: &[u8]) -> bool {
        // LEAN-MODEL: verified-native-path (VerifiedCoreProofs.exported_path_correct)
        self.native.admits_path(path)
    }

    /// True if everything below `path` is inside this scope.
    ///
    /// Once a position sits inside a granted prefix, no descent below it can
    /// leave — which lets a scope check stop at the boundary. Exact keys are
    /// deliberately absent: a subtree at an exact key may hold longer keys
    /// extending it, and those are outside.
    // LEAN-MODEL: mpt-scope-contains-subtree (Scope.ContainsSubtree)
    // `Scope.ContainsSubtree`; `containsSubtree_append` is the stop-at-the-
    // boundary property.
    pub fn contains_subtree(&self, path: &[u8]) -> bool {
        self.native.contains_subtree(path)
    }

    /// True if a key, given as a full nibble path, lies inside this scope.
    pub(crate) fn admits_key_path(&self, key: &[u8]) -> bool {
        self.native.admits_key(key)
    }

    /// True if a node at `path` may be served whole, given what it reveals.
    ///
    /// Position alone is not enough. A `Branch` reveals only child hashes, so
    /// its position is the whole story — but the trie compresses, and a
    /// compressed node carries key material: an `Ext` spells the nibbles
    /// between its position and its child, a `Leaf` the rest of a key and its
    /// value. Both sit on the spine the scope legitimately admits while
    /// describing a key range running out of it entirely, so serving one hands
    /// over the name of a space never granted — and in a leaf's case its
    /// record too.
    ///
    /// What is tested here is the node's *coverage*, not its position.
    // LEAN-MODEL: mpt-scope-admits-node (ScopedSync.AdmitsNode)
    // `ScopedSync.AdmitsNode`; `no_redaction_inside_grant` is why a position
    // inside a granted prefix is never refused.
    pub fn admits_node(&self, path: &[u8], node: &crate::node::TrieNode) -> bool {
        // A hash-only branch may travel as spine structure. Inline values
        // require key permission; the Lean decision enforces that distinction.
        // LEAN-MODEL: verified-native-node (VerifiedCoreProofs.exported_node_correct)
        self.native.admits_node(path, Self::native_shape(node))
    }

    /// Whether the value carried by a node belongs to a granted key. A branch
    /// may travel on the spine without granting the value at the branch itself.
    pub fn admits_value(&self, path: &[u8], node: &crate::node::TrieNode) -> bool {
        // LEAN-MODEL: verified-native-value (VerifiedCoreProofs.exported_value_correct)
        self.native.admits_value(path, Self::native_shape(node))
    }

    fn native_shape(node: &crate::node::TrieNode) -> synch_verified::Shape<'_> {
        use crate::node::{TrieNode, ValueRef};
        match node {
            TrieNode::Branch { value, .. } => synch_verified::Shape::Branch {
                inline_value: matches!(value, Some(ValueRef::Inline(_))),
            },
            TrieNode::Ext { prefix, .. } => synch_verified::Shape::Extension(prefix.as_slice()),
            TrieNode::Leaf { key_rest, .. } => synch_verified::Shape::Leaf(key_rest.as_slice()),
        }
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
    /// rather than inherit.
    pub fn memo_key_for(&self, owner: Option<&synch_core::OriginId>, root: Hash) -> Hash {
        match owner {
            None => self.memo_key(root),
            Some(origin) => {
                // "Do I hold all of this *as this origin's*?" is a third
                // question, distinct from both the unscoped and the scoped
                // one: a trie held whole is not held whole with provenance,
                // and the answers must not be confused.
                let mut bytes = Vec::with_capacity(96);
                bytes.extend_from_slice(b"owned-root/1");
                bytes.extend_from_slice(self.memo_key(root).as_bytes());
                bytes.extend_from_slice(origin.canonical().as_bytes());
                Hash::new(&bytes)
            }
        }
    }

    /// The key a completeness answer for `root` may be memoized under.
    ///
    /// "Do I hold all of this?" is a question about a root *and* a scope: a
    /// memo keyed by the root alone would answer a wider scope with a narrower
    /// one's answer. Folding the scope in makes a widened scope re-derive
    /// rather than inherit. With provenance in the question as well, see
    /// [`Scope::memo_key_for`].
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
    fn a_branch_keeps_its_children_when_its_value_is_out_of_line() {
        // `photos` is a key in its own right and `photos-raw` is the grant, so
        // the branch at `f:photos` carries a value the peer may not have while
        // sitting on the spine into a subtree it may. Refusing it whole cost
        // all sixteen children; only an inline value forces that now.
        let scope = Scope::of(&synch_core::ScopeKeys {
            prefixes: vec![b"f:photos-raw/".to_vec()],
            exact: Vec::new(),
        });
        let at = path(b"f:photos");
        let children: [Option<Hash>; 16] = std::array::from_fn(|_| None);
        let out_of_line = crate::node::TrieNode::Branch {
            children,
            value: Some(crate::node::ValueRef::Hash(Hash::new(b"record"))),
        };
        assert!(
            scope.admits_node(&at, &out_of_line),
            "a hash reveals no more than the child hashes already in the node"
        );
        let inline = crate::node::TrieNode::Branch {
            children,
            value: Some(crate::node::ValueRef::Inline(b"record".to_vec())),
        };
        assert!(
            !scope.admits_node(&at, &inline),
            "inline bytes are the record itself, so the node cannot travel"
        );
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
}
