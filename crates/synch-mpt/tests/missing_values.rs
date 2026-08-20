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
//! property would not hold — and `note_complete` would then vouch for a root
//! the node cannot serve (F5).

use synch_core::Hash;
use synch_mpt::{MemStore, MissingWalk, Trie};

#[test]
fn a_missing_out_of_line_value_is_asked_for_until_it_arrives() {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    // Three leaves reference one `trie_values` row — structural sharing makes
    // a repeat ordinary. The value side of the walk used not to deduplicate
    // within a batch, so one `GetValues` request named the same hash several
    // times; the responder answers per requested hash, and `take_served`
    // refuses a repeated payload as a protocol violation — a `NetError`,
    // which `is_origin_fault` does not contain — so the *whole* exchange
    // ended for every origin, blaming an honest peer, deterministically.
    let shared = vec![4u8; 300];
    let mut root = Hash::EMPTY;
    for key in [b"f:s/alpha".as_slice(), b"f:s/beta", b"f:s/gamma"] {
        root = trie.insert(root, key, &shared).unwrap();
    }
    assert!(trie.is_complete(root).unwrap());

    // Drop the value row, keeping every node: exactly the state of a peer that
    // relayed the structure but GC'd (or never held) the out-of-line payload.
    store.retain(&store.node_hashes(), &[]);

    let mut walk = MissingWalk::new(root);
    let first = walk.next_batch(&trie, 256).unwrap();
    assert_eq!(first.nodes.len(), 0);
    assert_eq!(first.values.len(), 1, "the shared value is asked for once");

    // Resume, as fetch_pending does; the walk must not consider itself
    // finished, and must ask again — which is what lets fetch_pending count
    // unproductive rounds and abandon the head per §5.2.
    walk.resume();
    assert!(
        !walk.is_exhausted(),
        "a walk with an outstanding value is not exhausted"
    );
    let second = walk.next_batch(&trie, 256).unwrap();
    assert_eq!(
        second.values.len(),
        1,
        "the missing value must be re-reported, got {second:?}"
    );
    assert!(!trie.is_complete(root).unwrap());

    // Serve it, as fetch_pending would commit it: the walk drains and the
    // trie is complete again.
    synch_mpt::NodeStore::put_value(&store, &Hash::new(&shared), &shared).unwrap();
    walk.resume();
    let next = walk.next_batch(&trie, 256).unwrap();
    assert!(next.is_empty(), "nothing should be missing now: {next:?}");
    assert!(walk.is_exhausted(), "the walk drains once the value lands");
    assert!(trie.is_complete(root).unwrap());
}
