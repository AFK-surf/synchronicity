//! Audit finding F4 — a missing out-of-line value is reported once, and then
//! the walk declares itself exhausted.
//!
//! `MissingWalk::next_batch` pushes a missing *node* onto both `missing.nodes`
//! and `self.deferred`, so `resume()` re-queues it. A missing *value* goes to
//! `missing.values` only: its parent node loaded fine, so it stays in `seen`
//! and is never revisited, and `is_exhausted()` consults only `frontier` and
//! `deferred`.
//!
//! The consequence is in `reconcile.rs`: `fetch_pending` breaks out of its loop
//! with `unproductive` at 1, so `MAX_UNPRODUCTIVE_ROUNDS` can never fire for a
//! value-only failure — the §5.2 "no wedging on unservable heads" property does
//! not exist for out-of-line values. It then calls `note_complete` on the root
//! regardless (finding F5).
//!
//! THIS TEST ASSERTS THE DEFECT AS IT STANDS. When values are deferred like
//! nodes, `is_exhausted()` will be false here and the second batch will report
//! the value again — invert both assertions rather than deleting them.

use synch_core::Hash;
use synch_mpt::{MemStore, MissingWalk, Trie};

#[test]
fn a_missing_out_of_line_value_is_reported_once_and_then_forgotten() {
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
    assert_eq!(first.values.len(), 1, "the value is reported once");

    // The fetch failed (the peer answered `missing`). Resume, as fetch_pending does.
    walk.resume();
    assert!(
        walk.is_exhausted(),
        "the walk claims to have covered everything while a value is still absent"
    );

    let second = walk.next_batch(&trie, 256).unwrap();
    assert!(
        second.is_empty(),
        "the missing value is never asked for again: {second:?}"
    );

    // And the trie itself still knows it is incomplete — so the walk and the
    // completeness predicate disagree.
    assert!(!trie.is_complete(root).unwrap());
}
