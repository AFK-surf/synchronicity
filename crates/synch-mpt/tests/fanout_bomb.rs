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
//! k + 1 nodes. Nothing about its *shape* distinguishes it from honest data —
//! give sixty thousand keys under dense structured paths one identical value
//! and content addressing collapses the whole lower trie to about ten distinct
//! nodes carrying sixty thousand positions — which is why the bound is on work
//! alone (`FanoutGuard`, `WALK_POSITION_CEILING`). Deduplicating positions by
//! node hash is the other obvious defence and is also wrong: one leaf
//! legitimately sits at as many positions as there are keys carrying its
//! value, so pruning repeats silently drops keys.

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
///
/// The guard used to be charged once per *nibble slot* of every frame entered —
/// all sixteen, before checking whether either side had anything there — so it
/// measured frames rather than positions and billed sixteen times the real
/// cost. At §14's one-`f:`-and-one-`b:`-per-file shape that refused the
/// first-adoption diff at ~57 k files, inside the 100 k initial index §7.1
/// names, and `doctor --rebuild` was dead for the same origin.
#[test]
fn a_first_adoption_diff_survives_the_documented_corpus_size() {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    let mut root = Hash::EMPTY;
    // Sixty thousand files, which is where this actually broke: two records
    // each, so 120 000 entries. Bigger proves nothing more and costs debug CI
    // time on every run.
    for i in 0..60_000u32 {
        let entry = format!("f:media/photos/2024/07/IMG_{i:07}.jpg");
        root = trie.insert(root, entry.as_bytes(), &[7u8; 55]).unwrap();
        let ad = format!("b:{i:064x}");
        root = trie.insert(root, ad.as_bytes(), &[3u8; 40]).unwrap();
    }
    assert_eq!(trie.diff(Hash::EMPTY, root).unwrap().len(), 120_000);

    // Many distinct keys all carrying one value: content addressing collapses
    // the lower trie to ~10 distinct nodes — structurally a fan-out DAG, built
    // by ordinary inserts — and the previous per-node-arrival ratio refused it
    // at ~65 k positions. The iter count is the shared-leaf regression the cut
    // `scan_pagination` used to catch: deduping positions by hash would
    // silently drop keys here.
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
