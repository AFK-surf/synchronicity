//! Trie *structure* arrives from peers over the network (§5.2), and only the
//! per-node hash is checked on the way in — nothing canonicalizes the shape.
//! These tests build the shapes a well-behaved publisher never would, and pin
//! that walking them fails safely instead of aborting the process.

use synch_core::Hash;
use synch_mpt::{node::hash_encoded, MemStore, Nibbles, NodeStore, Trie, TrieNode, ValueRef};

/// Stores a node under its own hash, the way a fetch commits a served node.
fn put(store: &MemStore, node: &TrieNode) -> Hash {
    let encoded = node.encode();
    let hash = hash_encoded(node.tag(), &encoded);
    store.put_node(&hash, &encoded).unwrap();
    hash
}

/// A leaf under `depth` single-nibble extension nodes: a legal-looking trie of
/// any depth the builder cares to name.
fn extension_chain(store: &MemStore, depth: usize) -> Hash {
    let mut hash = put(
        store,
        &TrieNode::Leaf {
            key_rest: Nibbles::new(),
            value: ValueRef::Inline(vec![7]),
        },
    );
    for _ in 0..depth {
        hash = put(
            store,
            &TrieNode::Ext {
                prefix: Nibbles::from_nibbles(&[1]),
                child: hash,
            },
        );
    }
    hash
}

#[test]
fn a_deep_extension_chain_does_not_overflow_the_diff() {
    // The walk head promotion runs (§5.2). Recursing one frame per nibble here
    // aborted the whole daemon on a chain a peer can serve in a few megabytes.
    let store = MemStore::new();
    let root = extension_chain(&store, 50_000);
    let changes = Trie::new(&store).diff(Hash::EMPTY, root).unwrap();
    // Every value in the chain sits below the depth any valid key can reach, so
    // there is nothing to report — and, above all, the process is still here.
    assert!(changes.is_empty());
}

#[test]
fn a_deep_extension_chain_does_not_overflow_a_scan() {
    let store = MemStore::new();
    let root = extension_chain(&store, 50_000);
    assert!(Trie::new(&store).iter(root).unwrap().is_empty());
}

#[test]
fn a_hand_built_chain_within_the_bound_still_reads() {
    // The depth bound must not cost anything a real trie relies on: the same
    // hand-built shape, shallow enough to hold a valid key, still yields it.
    let store = MemStore::new();
    let root = extension_chain(&store, 100);
    let trie = Trie::new(&store);
    let key = vec![0x11u8; 50];
    assert_eq!(trie.get(root, &key).unwrap(), Some(vec![7]));
    assert_eq!(trie.iter(root).unwrap(), vec![(key, vec![7])]);
    assert_eq!(trie.diff(Hash::EMPTY, root).unwrap().len(), 1);
}
