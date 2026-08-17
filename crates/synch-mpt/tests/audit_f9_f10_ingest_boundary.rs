//! Audit findings F9 and F10 — `TrieNode::hash_of_encoded` is the single trust
//! boundary for peer-supplied nodes, and it accepts structures the trie's own
//! documented invariants forbid.
//!
//! F10 (empty `Ext` prefix) is the serious one: `get` and every structural walk
//! disagree about the same root, so a head promotes cleanly while writing zero
//! rows to `entries` — and the engine's direct `trie.get` reads still see the
//! keys. F9's fourth bullet (a value at odd nibble depth) passes the
//! completeness gate and then throws from inside the promotion transaction,
//! wedging that origin's pending slot.
//!
//! THESE TESTS ASSERT THE DEFECTS AS THEY STAND. Adding the four checks the
//! audit recommends to `hash_of_encoded` — every nibble <= 0x0f, non-empty
//! `Ext` prefix, `Inline` length <= `INLINE_VALUE_MAX`, `Branch` occupancy >= 2
//! — makes `plant` panic on its `expect`, which is the correct new outcome.

use synch_core::Hash;
use synch_mpt::{node::hash_encoded, MemStore, Nibbles, NodeStore, Trie, TrieNode, ValueRef};

fn plant(store: &MemStore, node: &TrieNode) -> Hash {
    let encoded = node.encode();
    // The one and only gate on peer-supplied nodes.
    let hash = TrieNode::hash_of_encoded(&encoded).expect("accepted by the sync trust boundary");
    assert_eq!(hash, hash_encoded(node.tag(), &encoded));
    store.put_node(&hash, &encoded).unwrap();
    hash
}

#[test]
fn an_empty_ext_prefix_makes_get_and_iter_disagree() {
    let store = MemStore::new();
    let leaf = plant(
        &store,
        &TrieNode::Leaf {
            key_rest: Nibbles::from_bytes(b"k"),
            value: ValueRef::Inline(vec![1]),
        },
    );
    // `Ext` with an empty prefix. node.rs:60-63 declares this impossible;
    // `hash_of_encoded` never checks it.
    let root = plant(
        &store,
        &TrieNode::Ext {
            prefix: Nibbles::from_nibbles(&[]),
            child: leaf,
        },
    );

    let trie = Trie::new(&store);
    // The promotion gate is happy.
    assert!(trie.is_complete(root).unwrap(), "is_complete");
    // A point lookup finds the key...
    assert_eq!(trie.get(root, b"k").unwrap(), Some(vec![1]), "get");
    // ...and every structural walk says the trie is empty.
    assert_eq!(trie.iter(root).unwrap(), Vec::new(), "iter");
    assert_eq!(trie.diff(Hash::EMPTY, root).unwrap().len(), 0, "diff");
    eprintln!("get=Some([1])  iter=[]  diff=[]  is_complete=true");
}

#[test]
fn an_odd_depth_leaf_root_is_complete_but_cannot_be_materialized() {
    let store = MemStore::new();
    // A value landing at nibble depth 1: no byte key can address it.
    let root = plant(
        &store,
        &TrieNode::Leaf {
            key_rest: Nibbles::from_nibbles(&[6]),
            value: ValueRef::Inline(b"v".to_vec()),
        },
    );
    let trie = Trie::new(&store);
    assert!(trie.is_complete(root).unwrap(), "the promotion gate passes");
    let iter_err = trie.iter(root).unwrap_err();
    let diff_err = trie.diff(Hash::EMPTY, root).unwrap_err();
    eprintln!("is_complete=true  iter={iter_err:?}  diff={diff_err:?}");
}
