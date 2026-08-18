//! A trie DAG fans out exponentially in `diff`, but not in the fetch that
//! admits it.
//!
//! Nothing canonicalises a peer's node graph, and a branch may point all
//! sixteen children at the same hash. `MissingWalk` deduplicates on hash, so
//! such a structure is `k + 1` nodes on the wire and `is_complete` answers yes.
//! `diff_walk` walks *positions*, so without a bound it expands into 16^k
//! paths — one SQLite read each, one `Change` per leaf visit — inside the
//! promotion transaction, holding the write lock. Measured: k = 6 is 7 nodes
//! on the wire, 16 777 216 changes, 155 s. `MAX_DEPTH_NIBBLES` bounds depth,
//! not breadth, so it is no defence.
//!
//! Note what such a structure *is*: a valid trie describing 16^k entries in
//! k + 1 nodes. There is no local check that calls it malformed, because it is
//! not — so the fix is not a structural rule but a proportionality one. A walk
//! may visit only so many positions per distinct node it has actually reached
//! (`FanoutGuard`), which honest data never approaches and this exceeds by
//! orders of magnitude.
//!
//! Deduplicating positions by node hash is the obvious fix and is wrong: one
//! leaf legitimately sits at as many positions as there are keys carrying its
//! value, so pruning repeats silently drops keys. `scan_pagination` catches it.

use synch_core::Hash;
use synch_mpt::{node::hash_encoded, MemStore, Nibbles, NodeStore, Trie, TrieNode, ValueRef};

/// Stores a node the way a peer's `Nodes` response would, through the same
/// check the sync path applies.
fn plant(store: &MemStore, node: &TrieNode) -> Hash {
    let encoded = node.encode();
    let hash = TrieNode::hash_of_encoded(&encoded).expect("accepted at the trust boundary");
    assert_eq!(hash, hash_encoded(node.tag(), &encoded));
    store.put_node(&hash, &encoded).unwrap();
    hash
}

/// A `k`-level DAG whose every branch points all sixteen children at one node.
/// `k + 1` distinct nodes; 16^k distinct positions.
///
/// `k` must be even: an odd nibble depth puts the values at a depth no byte key
/// can address, and the walk fails with `OddDepthValue` first.
fn fanout_bomb(store: &MemStore, k: usize) -> Hash {
    assert_eq!(k % 2, 0, "an odd depth trips OddDepthValue instead");
    let mut child = plant(
        store,
        &TrieNode::Leaf {
            key_rest: Nibbles::new(),
            value: ValueRef::Inline(b"x".to_vec()),
        },
    );
    for _ in 0..k {
        child = plant(
            store,
            &TrieNode::Branch {
                children: [Some(child); 16],
                value: None,
            },
        );
    }
    child
}

#[test]
fn a_fanout_bomb_is_refused_rather_than_walked() {
    // Unbounded, k = 6 is 16.7M changes and 155 s. The walk stops inside the
    // bounded floor instead, so this test runs in milliseconds.
    let store = MemStore::new();
    let root = fanout_bomb(&store, 6);
    let trie = Trie::new(&store);

    // The fetch side is unchanged and still cheap: dedup on hash means the
    // whole structure is 7 nodes, and the completeness gate still passes.
    assert_eq!(store.node_count(), 7);
    assert!(trie.is_complete(root).unwrap());

    // The diff — which head promotion runs inside the write transaction — now
    // refuses it instead of expanding it.
    let err = trie
        .diff(Hash::EMPTY, root)
        .expect_err("a 16^6-position walk must be refused");
    assert!(
        err.to_string().contains("no key set can produce"),
        "unexpected error: {err}"
    );

    // Scanning is bounded the same way; `collect` had the identical defect.
    let err = trie.iter(root).expect_err("iteration must be refused too");
    assert!(err.to_string().contains("no key set can produce"), "{err}");
}

#[test]
fn an_honest_trie_is_nowhere_near_the_bound() {
    // The guard must not fire on real data, including the shape that most
    // stresses it: many distinct keys all carrying one value, so a single leaf
    // node is shared across every one of their positions.
    let store = MemStore::new();
    let trie = Trie::new(&store);
    let mut root = Hash::EMPTY;
    for i in 0..2000u16 {
        root = trie
            .insert(root, format!("f:space/dir{i:04}/file").as_bytes(), b"v")
            .unwrap();
    }
    assert_eq!(trie.iter(root).unwrap().len(), 2000);
    assert_eq!(trie.diff(Hash::EMPTY, root).unwrap().len(), 2000);
}
