//! Fixtures shared by the integration suites; each binary compiles its own copy.
#![allow(dead_code)]

use synch_core::Hash;
use synch_mpt::{node::hash_encoded, MemStore, MissingWalk, NodeStore, Trie, TrieNode};

/// Stores a node the way a peer's `Nodes` response would, through the boundary check.
pub(crate) fn plant(store: &MemStore, node: &TrieNode) -> Hash {
    let encoded = node.encode();
    let hash = TrieNode::hash_of_encoded(&encoded).expect("accepted at the trust boundary");
    assert_eq!(hash, hash_encoded(node.tag(), &encoded));
    store.put_node(&hash, &encoded).unwrap();
    hash
}

/// Drains `root` from `source` into `destination` the way `fetch_pending`
/// does: batch, copy what was asked for, resume — never restart at the root.
pub(crate) fn fetch_all(source: &MemStore, destination: &MemStore, root: Hash) {
    let held = Trie::new(source).reachable(root).unwrap();
    let total = held.nodes.len() + held.values.len();
    let trie = Trie::new(destination);
    let mut walk = MissingWalk::new(root);
    let mut rounds = 0;
    loop {
        let missing = walk.next_batch(&trie, 64).unwrap();
        if missing.is_empty() {
            if walk.is_exhausted() {
                return;
            }
            walk.resume();
            continue;
        }
        for (_, hash) in &missing.nodes {
            let bytes = source.get_node(hash).unwrap().expect("source has it");
            destination.put_node(hash, &bytes).unwrap();
        }
        for (_, hash) in &missing.values {
            let bytes = source.get_value(hash).unwrap().expect("source has it");
            destination.put_value(hash, &bytes).unwrap();
        }
        walk.resume();
        rounds += 1;
        assert!(rounds <= total, "the fetch is not converging");
    }
}
