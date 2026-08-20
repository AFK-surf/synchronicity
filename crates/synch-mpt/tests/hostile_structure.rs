//! Trie *structure* arrives from peers (§5.2) and only the per-node hash is
//! checked — nothing canonicalizes the shape. These build shapes a well-behaved
//! publisher never would, and pin that walking them fails safely.

use synch_core::Hash;
use synch_mpt::{node::hash_encoded, MemStore, Nibbles, NodeStore, Trie, TrieNode, ValueRef};

/// Stores a node under its own hash, the way a fetch commits a served node.
fn put(store: &MemStore, node: &TrieNode) -> Hash {
    let encoded = node.encode();
    let hash = hash_encoded(node.tag(), &encoded);
    store.put_node(&hash, &encoded).unwrap();
    hash
}

/// A leaf under `depth` single-nibble extension nodes: a legal-looking trie of any depth.
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

/// A 50 000-deep extension chain — the walk head promotion runs (§5.2).
/// Recursing one frame per nibble here aborted the whole daemon on a chain a
/// peer can serve in a few megabytes; both position-walking readers must fail
/// safely instead.
#[test]
fn extension_chains_fail_safely_past_the_bound_and_read_within_it() {
    let store = MemStore::new();
    let trie = Trie::new(&store);

    // 50 000 deep: every value sits below the depth any valid key can reach,
    // so there is nothing to report — and, above all, the process is still here.
    let root = extension_chain(&store, 50_000);
    assert!(trie.diff(Hash::EMPTY, root).unwrap().is_empty());
    assert!(trie.iter(root).unwrap().is_empty());

    // The depth bound must not cost anything a real trie relies on: the same
    // shape, shallow enough to hold a valid key, still yields it.
    let root = extension_chain(&store, 100);
    let key = vec![0x11u8; 50];
    assert_eq!(trie.get(root, &key).unwrap(), Some(vec![7]));
    assert_eq!(trie.iter(root).unwrap(), vec![(key, vec![7])]);
    assert_eq!(trie.diff(Hash::EMPTY, root).unwrap().len(), 1);
}
