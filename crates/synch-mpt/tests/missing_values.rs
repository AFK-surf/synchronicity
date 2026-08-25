//! A missing out-of-line value must not be reported once and then leave the
//! walk exhausted. `next_batch` defers a missing *node* so `resume()` re-queues
//! it, but a missing *value* is not re-queued — its parent node loads fine,
//! `seen` keeps it from being revisited, and `is_exhausted()` consults only
//! `frontier` and `deferred`. In `reconcile.rs` that broke the §5.2 "no wedging
//! on unservable heads" property — `MAX_UNPRODUCTIVE_ROUNDS` could never fire —
//! and `note_complete` vouched for a root the node cannot serve (F5).

use synch_core::Hash;
use synch_mpt::{MemStore, MissingWalk, Trie};

#[test]
fn a_missing_out_of_line_value_is_asked_for_until_it_arrives() {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    // Three leaves share one `trie_values` row. The value side of the walk
    // used not to deduplicate within a batch, and the responder refuses a
    // repeated payload — so the *whole* exchange ended for every origin,
    // blaming an honest peer, deterministically.
    let shared = vec![4u8; 300];
    let mut root = Hash::EMPTY;
    for key in [b"f:s/alpha".as_slice(), b"f:s/beta", b"f:s/gamma"] {
        root = trie.insert(root, key, &shared).unwrap();
    }
    assert!(trie.is_complete(root).unwrap());

    // Drop the value row, keeping every node: a peer that relayed the structure
    // but GC'd (or never held) the out-of-line payload.
    store.clear_values();

    let mut walk = MissingWalk::new(root);
    let first = walk.next_batch(&trie, 256).unwrap();
    assert_eq!(first.nodes.len(), 0);
    assert_eq!(first.values.len(), 1, "the shared value is asked for once");

    // Resume, as fetch_pending does: the walk must ask again, so unproductive
    // rounds can fire and the head is abandoned per §5.2.
    walk.resume();
    assert!(!walk.is_exhausted());
    let second = walk.next_batch(&trie, 256).unwrap();
    assert_eq!(second.values.len(), 1);
    assert!(!trie.is_complete(root).unwrap());

    // Serve it, as fetch_pending would commit it; the walk drains and completes.
    synch_mpt::NodeStore::put_value(&store, &Hash::new(&shared), &shared).unwrap();
    walk.resume();
    let next = walk.next_batch(&trie, 256).unwrap();
    assert!(next.is_empty());
    assert!(walk.is_exhausted());
    assert!(trie.is_complete(root).unwrap());
}
