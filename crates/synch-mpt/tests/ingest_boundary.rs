//! `TrieNode::hash_of_encoded` is the single trust boundary for peer-supplied
//! nodes, so it must refuse the structures the trie's own documented invariants
//! forbid. F10 is the serious one: admitted, an empty `Ext` prefix makes `get`
//! and every structural walk disagree about the same root, so a head promotes
//! while writing zero rows to `entries`. F9's rest: an oversized inline value,
//! a nibble outside the radix-16 alphabet (an out-of-bounds panic if it reaches
//! `insert`), and under-occupied branches giving one map several distinct
//! roots. All are rejected at the boundary, before they reach a store.

use synch_core::{Hash, INLINE_VALUE_MAX, MAX_KEY_LEN, MAX_TRIE_VALUE_LEN};
use synch_mpt::{MemStore, MptError, Nibbles, NodeStore, Trie, TrieNode, ValueRef};

/// Offers a hand-built node to the boundary the sync path uses.
fn offer(node: &TrieNode) -> Result<Hash, MptError> {
    TrieNode::hash_of_encoded(&node.encode())
}

/// Offers raw bytes, for shapes that cannot be built through the typed API.
fn offer_bytes(bytes: &[u8]) -> Result<Hash, MptError> {
    TrieNode::hash_of_encoded(bytes)
}

/// Stores a node the way a peer's `Nodes` response would.
fn plant(store: &MemStore, node: &TrieNode) -> Hash {
    let encoded = node.encode();
    let hash = TrieNode::hash_of_encoded(&encoded).expect("accepted at the boundary");
    store.put_node(&hash, &encoded).unwrap();
    hash
}

/// A two-occupant branch, the shape a prefix chain of keys produces.
fn branch(store: &MemStore, a: Hash, b: Hash) -> Hash {
    plant(
        store,
        &TrieNode::Branch {
            children: {
                let mut c = [None; 16];
                c[0] = Some(a);
                c[1] = Some(b);
                c
            },
            value: None,
        },
    )
}

#[test]
fn an_empty_ext_prefix_is_refused_and_never_followed() {
    let store = MemStore::new();
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
    assert!(err.to_string().contains("extension prefix is empty"));

    // Defence in depth: `get` must not follow an empty prefix even when one is
    // planted directly into a store.
    store.put_node(&leaf_hash, &leaf.encode()).unwrap();
    let ext = TrieNode::Ext {
        prefix: Nibbles::from_nibbles(&[]),
        child: leaf_hash,
    };
    let root = synch_mpt::node::hash_encoded(ext.tag(), &ext.encode());
    store.put_node(&root, &ext.encode()).unwrap();

    let trie = Trie::new(&store);
    assert_eq!(trie.get(root, b"k").unwrap(), None);
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
    // The typed API masks this, so it can only arrive from a peer; in `insert`
    // it indexed a 16-element child array with 32.
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
    assert!(err.to_string().contains("alphabet") || err.to_string().contains("malformed"));
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
}

/// An extension above anything but a branch is refused where the structure is
/// walked (`check_invariants`): it reads correctly but gives one key/value map
/// several distinct roots, silently disabling `MissingWalk::since`'s pruning.
#[test]
fn an_extension_above_a_non_branch_is_refused_by_the_walk() {
    use synch_mpt::MissingWalk;

    let store = MemStore::new();
    let child = TrieNode::Leaf {
        key_rest: Nibbles::from_nibbles(&[1, 2]),
        value: ValueRef::Inline(b"v".to_vec()),
    };
    // The node passes single-node checks; the shape is only visible with the child in hand.
    assert!(TrieNode::hash_of_encoded(&child.encode()).is_ok());
    let child_hash = plant(&store, &child);
    let root = plant(
        &store,
        &TrieNode::Ext {
            prefix: Nibbles::from_nibbles(&[0]),
            child: child_hash,
        },
    );

    let trie = Trie::new(&store);
    let mut walk = MissingWalk::new(root);
    let err = walk
        .next_batch(&trie, 256)
        .expect_err("an ext above a leaf must be refused");
    assert!(err.to_string().contains("not a branch"));

    // And so the trie is never declared complete, so no head over it flips.
    assert!(trie.is_complete(root).is_err());
}

/// The key-depth ceiling is one thing to every reader: `get` counted node
/// *loads* against `MAX_DEPTH_NIBBLES` while a key of `n` nibbles needs `n+1`,
/// so `iter`/`diff` yielded the longest legal key while `get` called it
/// structurally invalid — and a node hung below any valid key's depth was
/// pulled and committed, vouched for, and never reflected in `entries`.
#[test]
fn the_key_depth_ceiling_is_one_thing_to_every_reader() {
    let store = MemStore::new();

    // Phase 1 — at the ceiling: the deepest legal key, planted as a branch per
    // nibble (the shape `insert` makes, without the quadratic cost). Two
    // fillers keep a branch's second occupant at an even nibble depth: an odd
    // one is a position no byte key can name, and every walk fails closed on it.
    let flat = plant(
        &store,
        &TrieNode::Leaf {
            key_rest: Nibbles::from_nibbles(&[]),
            value: ValueRef::Inline(b"filler".to_vec()),
        },
    );
    let stepped = plant(
        &store,
        &TrieNode::Leaf {
            key_rest: Nibbles::from_nibbles(&[2]),
            value: ValueRef::Inline(b"filler".to_vec()),
        },
    );
    let mut node = plant(
        &store,
        &TrieNode::Leaf {
            key_rest: Nibbles::from_nibbles(&[]),
            value: ValueRef::Inline(b"deepest".to_vec()),
        },
    );
    for depth in (0..MAX_KEY_LEN * 2).rev() {
        let filler = if depth % 2 == 0 { stepped } else { flat };
        node = branch(&store, node, filler);
    }
    let root = node;
    let longest = vec![0x00u8; MAX_KEY_LEN];

    let trie = Trie::new(&store);
    assert_eq!(
        trie.get(root, &longest).unwrap().as_deref(),
        Some(b"deepest".as_slice())
    );
    let walked = trie.iter(root).unwrap();
    assert!(walked.iter().any(|(k, _)| k == &longest));
    // The fetch that would admit this graph accepts it too: the value sits exactly at the ceiling.
    assert!(trie.is_complete(root).unwrap());

    // One byte past it is refused by every path, rather than refused by some.
    let past = vec![0x00u8; MAX_KEY_LEN + 1];
    assert!(trie.get(root, &past).is_err());
    assert!(trie.insert(root, &past, b"v").is_err());

    // Phase 2 — past the ceiling: a ladder of one-nibble extensions (two
    // nibbles per rung) past the depth a 4 KiB key can address. Every node is
    // canonical on its own; the fetch must refuse the path rather than commit it.
    let leaf = plant(
        &store,
        &TrieNode::Leaf {
            key_rest: Nibbles::from_nibbles(&[]),
            value: ValueRef::Inline(vec![1]),
        },
    );
    let mut child = branch(&store, leaf, leaf);
    for _ in 0..=(MAX_KEY_LEN) {
        let ext = plant(
            &store,
            &TrieNode::Ext {
                prefix: Nibbles::from_nibbles(&[0]),
                child,
            },
        );
        child = branch(&store, ext, ext);
    }

    let mut walk = synch_mpt::MissingWalk::new(child);
    let err = loop {
        match walk.next_batch(&trie, 256) {
            Ok(missing) => {
                assert!(missing.is_empty());
                if walk.is_exhausted() {
                    panic!("the walk accepted a graph past the key-depth ceiling");
                }
                walk.resume();
            }
            Err(e) => break e,
        }
    };
    assert!(err.to_string().contains("nibble depth"), "{err}");
    assert!(!trie.is_complete(child).unwrap_or(false));
}

/// A value past the §12 ceiling is refused where a key past it is.
#[test]
fn an_oversized_value_is_refused_by_the_write_path() {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    let big = vec![7u8; MAX_TRIE_VALUE_LEN + 1];
    let err = trie
        .insert(Hash::EMPTY, b"k", &big)
        .expect_err("a value past the ceiling must not be published");
    assert!(matches!(err, MptError::ValueTooLong(_)), "{err}");

    // At the ceiling it is an ordinary value.
    let edge = vec![7u8; MAX_TRIE_VALUE_LEN];
    let root = trie.insert(Hash::EMPTY, b"k", &edge).unwrap();
    assert_eq!(trie.get(root, b"k").unwrap().as_deref(), Some(&edge[..]));
}
