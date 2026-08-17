//! Audit finding F1 — a trie DAG fans out exponentially in `diff`, but not in
//! the fetch that admits it.
//!
//! Nothing canonicalises a peer's node graph, and a branch may point all
//! sixteen children at the same hash. `MissingWalk` deduplicates on hash, so
//! such a structure is `k + 1` nodes on the wire and `is_complete` answers yes.
//! `diff_walk` walks *positions*, not hashes, so it expands into 16^k paths —
//! one SQLite read each, one `Change` per leaf visit — inside the promotion
//! transaction, holding the write lock. `MAX_DEPTH_NIBBLES` bounds depth, not
//! breadth, so it is no defence.
//!
//! THIS TEST ASSERTS THE DEFECT AS IT STANDS. When `diff_walk`/`collect` learn
//! to memoise visited `(reference, hash)` pairs, the `changes.len()` assertion
//! below is what will fail — invert it rather than deleting it.
//!
//! Depth here stops at k = 4 (65 536 positions, ~0.5 s) to keep the suite fast.
//! Measured on the unfixed tree: k = 6 is 7 nodes on the wire, 16 777 216
//! changes, 155 s.

use std::time::Instant;

use synch_core::Hash;
use synch_mpt::{node::hash_encoded, MemStore, Nibbles, NodeStore, Trie, TrieNode, ValueRef};

/// Stores a node the way a peer's `Nodes` response would, through the same
/// check the sync path applies (`reconcile.rs`, the `hash_of_encoded` call).
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
/// can address, and the walk fails with `OddDepthValue` before it can blow up
/// (which is audit finding F9's fourth bullet, not this one).
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
fn a_fanout_bomb_is_cheap_to_fetch_and_exponential_to_diff() {
    for k in [2usize, 4] {
        let store = MemStore::new();
        let root = fanout_bomb(&store, k);
        let trie = Trie::new(&store);

        // The fetch side is fine: `MissingWalk` dedups on hash, so the whole
        // structure costs k + 1 nodes and the completeness gate passes.
        assert_eq!(store.node_count(), k + 1);
        assert!(trie.is_complete(root).unwrap());

        // The diff side is not. This is what head promotion runs, inside the
        // write transaction.
        let started = Instant::now();
        let changes = trie.diff(Hash::EMPTY, root).unwrap();
        eprintln!(
            "k={k}: {} nodes on the wire -> {} changes in {:?}",
            k + 1,
            changes.len(),
            started.elapsed()
        );
        assert_eq!(
            changes.len(),
            16usize.pow(k as u32),
            "F1 is fixed if this is no longer 16^k — invert the assertion"
        );
    }
}
