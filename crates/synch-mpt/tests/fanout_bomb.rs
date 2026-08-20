//! A trie DAG fans out exponentially in `diff`, but not in the fetch that
//! admits it. Nothing canonicalises a peer's node graph, and a branch may
//! point all sixteen children at the same hash: `MissingWalk` deduplicates on
//! hash, so the structure is `k + 1` nodes on the wire and `is_complete`
//! answers yes, while `diff_walk` walks *positions* and expands into 16^k
//! paths — one SQLite read each, one `Change` per leaf visit, inside the
//! promotion transaction (measured: k = 6 is 7 nodes on the wire, 16.7M
//! changes, 155 s). `MAX_DEPTH_NIBBLES` bounds depth, not breadth.
//!
//! The shape is *not* distinguishable from honest data: sixty thousand keys
//! sharing one value collapse to ~10 distinct nodes, which is why the bound is
//! on work alone (`FanoutGuard`, `WALK_POSITION_CEILING`) — deduplicating
//! positions by node hash instead silently drops keys.

use synch_core::Hash;
use synch_mpt::{node::hash_encoded, MemStore, Nibbles, NodeStore, Trie, TrieNode, ValueRef};

/// Stores a node the way a peer's `Nodes` response would, through the sync path's check.
fn plant(store: &MemStore, node: &TrieNode) -> Hash {
    let encoded = node.encode();
    let hash = TrieNode::hash_of_encoded(&encoded).expect("accepted at the trust boundary");
    assert_eq!(hash, hash_encoded(node.tag(), &encoded));
    store.put_node(&hash, &encoded).unwrap();
    hash
}

/// A `k`-level DAG whose every branch points all sixteen children at one node:
/// `k + 1` distinct nodes, 16^k positions. `k` must be even — an odd nibble
/// depth puts the values at a depth no byte key can address, and the walk
/// fails with `OddDepthValue`.
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

/// Ignored because it is expensive *by construction*, not because it is
/// flaky: refusal happens at `WALK_POSITION_CEILING`, so asserting it end to
/// end means walking that many positions — ~8 s in release, ~90 s in a debug
/// CI run, and the CI job runs the suite twice. `trie.rs`'s
/// `the_walk_guard_stops_at_the_ceiling` covers the guard's arithmetic in
/// microseconds; this covers the wiring, and is worth running by hand
/// (`cargo test -- --ignored`) whenever either changes.
#[test]
#[ignore = "walks to WALK_POSITION_CEILING; see the fast guard test in trie.rs"]
fn a_fanout_bomb_is_refused_rather_than_walked() {
    // Unbounded, k = 6 is 16.7M changes and 155 s; at a 64M-position ceiling it
    // slipped under entirely and wrote every one of those rows. The walk stops
    // at the ceiling instead.
    let store = MemStore::new();
    let root = fanout_bomb(&store, 6);
    let trie = Trie::new(&store);

    // The fetch side is cheap either way: dedup on hash means the whole
    // structure is 7 nodes, and the completeness gate passes.
    assert_eq!(store.node_count(), 7);
    assert!(trie.is_complete(root).unwrap());

    // The diff — which head promotion runs inside the write transaction —
    // refuses it instead of expanding it.
    let err = trie
        .diff(Hash::EMPTY, root)
        .expect_err("a 16^6-position walk must be refused");
    assert!(
        err.to_string().contains("exceeded"),
        "unexpected error: {err}"
    );

    // Scanning is bounded the same way; `collect` walks positions alike.
    let err = trie.iter(root).expect_err("iteration must be refused too");
    assert!(err.to_string().contains("exceeded"), "{err}");
}

/// First adoption of an origin diffs from `Hash::EMPTY`, and that must survive
/// a corpus the size §7.1 names — including the shape that most stresses the
/// guard.
#[test]
fn a_first_adoption_diff_survives_the_documented_corpus_size() {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    let mut root = Hash::EMPTY;
    // Sixty thousand files — where this actually broke (120 000 entries);
    // bigger proves nothing more and costs debug CI time on every run.
    for i in 0..60_000u32 {
        let entry = format!("f:media/photos/2024/07/IMG_{i:07}.jpg");
        root = trie.insert(root, entry.as_bytes(), &[7u8; 55]).unwrap();
        let ad = format!("b:{i:064x}");
        root = trie.insert(root, ad.as_bytes(), &[3u8; 40]).unwrap();
    }
    assert_eq!(trie.diff(Hash::EMPTY, root).unwrap().len(), 120_000);

    // Many distinct keys, one value: content addressing collapses the lower
    // trie to ~10 nodes — a fan-out DAG built by ordinary inserts, which the
    // per-node-arrival ratio refused. The iter count is the shared-leaf
    // regression: deduping positions by hash would silently drop keys.
    let store = MemStore::new();
    let trie = Trie::new(&store);
    let mut root = Hash::EMPTY;
    for i in 0..60_000u32 {
        root = trie
            .insert(
                root,
                format!("f:space/{i:08}/file").as_bytes(),
                b"entry-value",
            )
            .unwrap();
    }
    assert_eq!(trie.iter(root).unwrap().len(), 60_000);
    assert_eq!(trie.diff(Hash::EMPTY, root).unwrap().len(), 60_000);
}
