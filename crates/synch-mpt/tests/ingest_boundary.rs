//! `TrieNode::hash_of_encoded` is the single trust boundary for peer-supplied
//! nodes, so it must refuse structures the trie's own documented invariants
//! forbid.
//!
//! F10 is the serious one: admitted, an empty `Ext` prefix makes `get` and
//! every structural walk disagree about the same root, so a head promotes
//! cleanly while writing zero rows to `entries` — and the engine's direct
//! `trie.get` reads still see the keys. F9's remaining bullets are an oversized
//! inline value, a nibble outside the radix-16 alphabet (an out-of-bounds panic
//! if it reaches `insert`), and under-occupied branches giving one key/value
//! map several distinct roots.
//!
//! All four are rejected at the boundary, so the structures below never reach
//! a store.

use synch_core::{Hash, INLINE_VALUE_MAX};
use synch_mpt::{MemStore, MptError, Nibbles, NodeStore, Trie, TrieNode, ValueRef};

/// Offers a hand-built node to the boundary the sync path uses.
fn offer(node: &TrieNode) -> Result<Hash, MptError> {
    TrieNode::hash_of_encoded(&node.encode())
}

/// Offers raw bytes, for shapes that cannot be built through the typed API.
fn offer_bytes(bytes: &[u8]) -> Result<Hash, MptError> {
    TrieNode::hash_of_encoded(bytes)
}

#[test]
fn an_empty_ext_prefix_is_refused() {
    let leaf = TrieNode::Leaf {
        key_rest: Nibbles::from_bytes(b"k"),
        value: ValueRef::Inline(vec![1]),
    };
    let leaf_hash = offer(&leaf).expect("an ordinary leaf is fine");
    let err = offer(&TrieNode::Ext {
        prefix: Nibbles::from_nibbles(&[]),
        child: leaf_hash,
    })
    .expect_err("an empty extension prefix must be refused");
    assert!(
        err.to_string().contains("extension prefix is empty"),
        "{err}"
    );
}

#[test]
fn get_and_the_structural_walks_agree_even_if_one_slips_through() {
    // Defence in depth: `get` does not treat an empty prefix as a transparent
    // hop, so even a node planted directly into a store cannot put the two
    // readers into disagreement.
    let store = MemStore::new();
    let leaf = TrieNode::Leaf {
        key_rest: Nibbles::from_bytes(b"k"),
        value: ValueRef::Inline(vec![1]),
    };
    let leaf_bytes = leaf.encode();
    let leaf_hash = offer(&leaf).unwrap();
    store.put_node(&leaf_hash, &leaf_bytes).unwrap();

    let ext = TrieNode::Ext {
        prefix: Nibbles::from_nibbles(&[]),
        child: leaf_hash,
    };
    let ext_bytes = ext.encode();
    let root = synch_mpt::node::hash_encoded(ext.tag(), &ext_bytes);
    store.put_node(&root, &ext_bytes).unwrap();

    let trie = Trie::new(&store);
    assert_eq!(
        trie.get(root, b"k").unwrap(),
        None,
        "get must not follow it"
    );
    assert_eq!(trie.iter(root).unwrap(), Vec::new());
    assert_eq!(trie.diff(Hash::EMPTY, root).unwrap().len(), 0);
}

#[test]
fn an_oversized_inline_value_is_refused() {
    let err = offer(&TrieNode::Leaf {
        key_rest: Nibbles::from_bytes(b"k"),
        value: ValueRef::Inline(vec![9u8; INLINE_VALUE_MAX + 1]),
    })
    .expect_err("an inline value past the ceiling must be refused");
    assert!(err.to_string().contains("exceeds the"), "{err}");
}

#[test]
fn a_nibble_outside_the_alphabet_is_refused() {
    // Built by hand: the typed API masks, so this shape can only arrive from a
    // peer. Reaching `insert`, it indexed a 16-element child array with 32.
    let honest = TrieNode::Leaf {
        key_rest: Nibbles::from_nibbles(&[2, 1]),
        value: ValueRef::Inline(vec![1]),
    };
    let mut bytes = honest.encode();
    let bad = bytes
        .iter()
        .rposition(|b| *b == 2)
        .expect("the nibble is in the encoding");
    bytes[bad] = 0x20;
    let err = offer_bytes(&bytes).expect_err("a nibble above 0x0f must be refused");
    assert!(
        err.to_string().contains("alphabet") || err.to_string().contains("malformed"),
        "{err}"
    );
}

#[test]
fn an_under_occupied_branch_is_refused() {
    let leaf = TrieNode::Leaf {
        key_rest: Nibbles::from_nibbles(&[1]),
        value: ValueRef::Inline(b"v".to_vec()),
    };
    let leaf_hash = offer(&leaf).unwrap();
    let mut children = [None; 16];
    children[6] = Some(leaf_hash);
    let err = offer(&TrieNode::Branch {
        children,
        value: None,
    })
    .expect_err("a one-occupant branch must be refused");
    assert!(err.to_string().contains("fewer than two"), "{err}");

    // Two occupants is the canonical shape and stays accepted.
    children[7] = Some(leaf_hash);
    offer(&TrieNode::Branch {
        children,
        value: None,
    })
    .expect("a two-occupant branch is canonical");
}

#[test]
fn an_odd_depth_value_still_fails_closed() {
    // A value at odd nibble depth is not a per-node property, so the boundary
    // cannot reject it. It must still fail rather than promote: the walk
    // reports OddDepthValue and the completeness gate must not paper over it.
    let store = MemStore::new();
    let leaf = TrieNode::Leaf {
        key_rest: Nibbles::from_nibbles(&[6]),
        value: ValueRef::Inline(b"v".to_vec()),
    };
    let bytes = leaf.encode();
    let root = offer(&leaf).expect("a single leaf is a well-formed node");
    store.put_node(&root, &bytes).unwrap();

    let trie = Trie::new(&store);
    assert!(matches!(trie.iter(root), Err(MptError::OddDepthValue)));
    assert!(matches!(
        trie.diff(Hash::EMPTY, root),
        Err(MptError::OddDepthValue)
    ));
}
