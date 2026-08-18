//! A missing out-of-line value must not be reported once and then leave the
//! walk declaring itself exhausted.
//!
//! `MissingWalk::next_batch` pushes a missing *node* onto both `missing.nodes`
//! and `self.deferred`, so `resume()` re-queues it. A missing *value* put on
//! `missing.values` alone would not be re-queued: its parent node loads fine,
//! so it is never deferred, `seen` keeps it from being revisited, and
//! `is_exhausted()` consults only `frontier` and `deferred`.
//!
//! The consequence lands in `reconcile.rs`: `fetch_pending` would break out of
//! its loop with `unproductive` at 1, so `MAX_UNPRODUCTIVE_ROUNDS` could never
//! fire for a value-only failure — the §5.2 "no wedging on unservable heads"
//! property would not hold for out-of-line values — and `note_complete` would
//! then vouch for a root the node cannot serve (F5).
//!
//! A node whose values have not arrived is therefore deferred too, so the walk
//! keeps asking and the fetch loop can see it is making no progress.

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

/// One batch asks for a shared out-of-line value once, not once per node that
/// references it.
///
/// Structural sharing makes a repeat ordinary: two keys carrying the same
/// payload reference one `trie_values` row from two different leaves. The node
/// side of the walk is deduplicated by `seen`; the value side was not, so a
/// single `GetValues` request named the same hash several times. The responder
/// answers per requested hash, and `take_served` refuses a repeated payload as
/// a protocol violation — a `NetError`, which `is_origin_fault` does not
/// contain — so the *whole* exchange ended for every origin, blaming an honest
/// peer for answering exactly what it was asked. Deterministic, so it repeated
/// on every retry.
#[test]
fn one_batch_asks_for_a_shared_value_once() {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    let shared = vec![4u8; 300];
    let mut root = Hash::EMPTY;
    for key in [b"f:s/alpha".as_slice(), b"f:s/beta", b"f:s/gamma"] {
        root = trie.insert(root, key, &shared).unwrap();
    }
    assert!(trie.is_complete(root).unwrap());
    store.retain(&store.node_hashes(), &[]);

    let mut walk = MissingWalk::new(root);
    let mut asked: Vec<Hash> = Vec::new();
    loop {
        let batch = walk.next_batch(&trie, 256).unwrap();
        if batch.is_empty() {
            if walk.is_exhausted() {
                break;
            }
            walk.resume();
            continue;
        }
        let mut seen = std::collections::HashSet::new();
        for (_path, hash) in &batch.values {
            assert!(
                seen.insert(*hash),
                "one batch named {hash} twice: the responder answers per \
                 requested hash and take_served refuses the repeat"
            );
        }
        asked.extend(batch.values.iter().map(|(_, hash)| *hash));
        // The peer has nothing to give, so the walk must keep asking — which is
        // what makes the duplicate reachable in the first place.
        if asked.len() > 8 {
            break;
        }
        walk.resume();
    }
    assert!(!asked.is_empty(), "the shared value is asked for");
}
