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

/// An extension above anything but a branch is refused where the structure is
/// walked, which is what `check_invariants` says happens.
///
/// The invariant is documented on `TrieNode::Ext` and the doc on
/// `check_invariants` promised it was "checked where the structure is walked".
/// Nothing checked it. Such a node reads correctly through `get`, `iter` and
/// `diff` — so it corrupts nothing — but it produces a different root for the
/// same one-key map, which falsifies the canonical-root property the crate
/// documents and silently disables both structural sharing across roots and
/// the `reference == Some(hash)` pruning in `MissingWalk::since`.
#[test]
fn an_extension_above_a_non_branch_is_refused_by_the_walk() {
    use synch_mpt::MissingWalk;

    for (name, child) in [
        (
            "leaf",
            TrieNode::Leaf {
                key_rest: Nibbles::from_nibbles(&[1, 2]),
                value: ValueRef::Inline(b"v".to_vec()),
            },
        ),
        (
            "ext",
            TrieNode::Ext {
                prefix: Nibbles::from_nibbles(&[3]),
                child: Hash::new(b"whatever"),
            },
        ),
    ] {
        let store = MemStore::new();
        let child_hash = plant(&store, &child);
        let root = plant(
            &store,
            &TrieNode::Ext {
                prefix: Nibbles::from_nibbles(&[0]),
                child: child_hash,
            },
        );

        // The node itself still passes the single-node checks: the shape is
        // only visible with the child in hand.
        assert!(TrieNode::hash_of_encoded(&child.encode()).is_ok());

        let trie = Trie::new(&store);
        let mut walk = MissingWalk::new(root);
        let err = walk
            .next_batch(&trie, 256)
            .expect_err("an ext above a {name} must be refused");
        assert!(
            err.to_string().contains("not a branch"),
            "ext above {name}: {err}"
        );

        // And so the trie is never declared complete, so no head over it flips.
        assert!(trie.is_complete(root).is_err(), "ext above {name}");
    }
}

/// A key at exactly the §12 ceiling is one thing to every reader.
///
/// `get` counted node *loads* against `MAX_DEPTH_NIBBLES` while a key of `n`
/// nibbles needs `n + 1` of them, so the longest legal key was yielded by
/// `iter` and `diff` — and therefore materialized into `entries` and served
/// through the unified tree — while `get` called it structurally invalid and
/// `synch history` rendered the path as absent.
#[test]
fn the_longest_legal_key_is_visible_to_every_reader() {
    let store = MemStore::new();

    // A branch at every nibble of the deepest legal key, planted directly: the
    // same shape a prefix chain of keys produces through `insert`, without the
    // quadratic cost of building it that way. The key of 8 192 zero nibbles
    // descends 8 192 branches and then loads the leaf holding the value, which
    // is 8 193 node loads for a key `insert` accepts.
    // Two fillers, so a branch's second occupant always puts its value at an
    // even nibble depth: an odd one is a position no byte key can name, and
    // every walk fails closed on it.
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
        node = plant(
            &store,
            &TrieNode::Branch {
                children: {
                    let mut c = [None; 16];
                    c[0] = Some(node);
                    c[1] = Some(filler);
                    c
                },
                value: None,
            },
        );
    }
    let root = node;
    let longest = vec![0x00u8; MAX_KEY_LEN];

    let trie = Trie::new(&store);
    assert_eq!(
        trie.get(root, &longest).unwrap().as_deref(),
        Some(b"deepest".as_slice()),
        "the longest legal key must be readable"
    );
    let walked: Vec<Vec<u8>> = trie
        .iter(root)
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert!(
        walked.contains(&longest),
        "and reachable by the structural walk"
    );
    // The fetch that would have admitted this graph accepts it too: the value
    // sits exactly at the ceiling, not past it.
    assert!(trie.is_complete(root).unwrap());

    // One byte past it is refused by every path, rather than refused by some.
    let past = vec![0x00u8; MAX_KEY_LEN + 1];
    assert!(matches!(
        trie.get(root, &past),
        Err(MptError::KeyTooLong(_))
    ));
    assert!(matches!(
        trie.insert(root, &past, b"v"),
        Err(MptError::KeyTooLong(_))
    ));
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

/// A node hung below the depth any valid key reaches is refused by the fetch.
///
/// The node encoding bounds one node's nibble run, and DESIGN §12 read that as
/// bounding ingest depth. It does not: a path is made of many nodes. Without a
/// bound on the *path*, a member could have every peer pull and commit an
/// arbitrarily large graph that `is_complete` then vouches for, that no
/// `entries` row reflects, and that every GC pass marks from the retained head
/// above it.
#[test]
fn a_node_past_the_key_depth_is_refused_by_the_walk() {
    let store = MemStore::new();

    // A ladder of one-nibble extensions, each above a branch, reaching past the
    // depth a 4 KiB key can address. Every node is canonical on its own.
    let leaf = plant(
        &store,
        &TrieNode::Leaf {
            key_rest: Nibbles::from_nibbles(&[]),
            value: ValueRef::Inline(vec![1]),
        },
    );
    let mut child = plant(
        &store,
        &TrieNode::Branch {
            children: {
                let mut c = [None; 16];
                c[0] = Some(leaf);
                c[1] = Some(leaf);
                c
            },
            value: None,
        },
    );
    // Two nibbles per rung — one for the `Ext` prefix, one for the branch's
    // child index — so this reaches just past the ceiling.
    for _ in 0..=(MAX_KEY_LEN) {
        let ext = plant(
            &store,
            &TrieNode::Ext {
                prefix: Nibbles::from_nibbles(&[0]),
                child,
            },
        );
        child = plant(
            &store,
            &TrieNode::Branch {
                children: {
                    let mut c = [None; 16];
                    c[0] = Some(ext);
                    c[1] = Some(ext);
                    c
                },
                value: None,
            },
        );
    }

    let trie = Trie::new(&store);
    let mut walk = synch_mpt::MissingWalk::new(child);
    let err = loop {
        match walk.next_batch(&trie, 256) {
            Ok(missing) => {
                assert!(
                    missing.is_empty(),
                    "every node of the ladder is already stored"
                );
                if walk.is_exhausted() {
                    panic!("the walk accepted a graph past the key-depth ceiling");
                }
                walk.resume();
            }
            Err(e) => break e,
        }
    };
    assert!(err.to_string().contains("nibble depth"), "{err}");
    assert!(
        !trie.is_complete(child).unwrap_or(false),
        "and the root is not vouched for"
    );
}
