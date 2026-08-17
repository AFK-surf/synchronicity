//! Audit finding F4 (fixed) — a missing out-of-line value was reported once,
//! after which the walk declared itself exhausted.
//!
//! `MissingWalk::next_batch` pushes a missing *node* onto both `missing.nodes`
//! and `self.deferred`, so `resume()` re-queues it. A missing *value* went to
//! `missing.values` only: its parent node loaded fine, so it was never
//! deferred, `seen` kept it from being revisited, and `is_exhausted()` consults
//! only `frontier` and `deferred`.
//!
//! The consequence was in `reconcile.rs`: `fetch_pending` broke out of its loop
//! with `unproductive` at 1, so `MAX_UNPRODUCTIVE_ROUNDS` could never fire for
//! a value-only failure — the §5.2 "no wedging on unservable heads" property
//! did not exist for out-of-line values — and `note_complete` then vouched for
//! a root the node could not serve (F5).
//!
//! The fix defers a node whose values have not arrived, so the walk keeps
//! asking and the fetch loop can see it is making no progress.

use synch_core::Hash;
use synch_mpt::{MemStore, MissingWalk, Trie};

#[test]
fn a_missing_out_of_line_value_is_asked_for_until_it_arrives() {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    // A value over INLINE_VALUE_MAX (128) goes out of line.
    let root = trie.insert(Hash::EMPTY, b"k", &vec![9u8; 500]).unwrap();
    assert!(trie.is_complete(root).unwrap());

    // Drop the value row, keeping every node: exactly the state of a peer that
    // relayed the structure but GC'd (or never held) the out-of-line payload.
    store.retain(&store.node_hashes(), &[]);

    let mut walk = MissingWalk::new(root);
    let first = walk.next_batch(&trie, 256).unwrap();
    assert_eq!(first.nodes.len(), 0);
    assert_eq!(first.values.len(), 1, "the value is reported");

    // The fetch failed (the peer answered `missing`). Resume, as fetch_pending
    // does. The walk must NOT consider itself finished.
    walk.resume();
    assert!(
        !walk.is_exhausted(),
        "a walk with an outstanding value is not exhausted"
    );

    // And it asks again, which is what lets fetch_pending count unproductive
    // rounds and eventually abandon the head per §5.2.
    let second = walk.next_batch(&trie, 256).unwrap();
    assert_eq!(
        second.values.len(),
        1,
        "the missing value must be re-reported, got {second:?}"
    );

    // The walk and the completeness predicate agree throughout.
    assert!(!trie.is_complete(root).unwrap());
}

#[test]
fn a_value_that_arrives_lets_the_walk_finish() {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    let payload = vec![9u8; 500];
    let root = trie.insert(Hash::EMPTY, b"k", &payload).unwrap();

    // Snapshot the value, drop it, then let the walk discover it is missing.
    let value_hashes = [Hash::new(&payload)];
    store.retain(&store.node_hashes(), &[]);
    let mut walk = MissingWalk::new(root);
    assert_eq!(walk.next_batch(&trie, 256).unwrap().values.len(), 1);

    // The "peer" now serves it, as fetch_pending would commit it.
    synch_mpt::NodeStore::put_value(&store, &value_hashes[0], &payload).unwrap();
    walk.resume();
    let next = walk.next_batch(&trie, 256).unwrap();
    assert!(next.is_empty(), "nothing should be missing now: {next:?}");
    assert!(walk.is_exhausted(), "the walk drains once the value lands");
    assert!(trie.is_complete(root).unwrap());
}
