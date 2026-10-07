//! Publication normalization runs through the same native Lean command as
//! the engine. Expectations describe entries and retained versions.
use synch_core::{Hash, MAX_KEY_LEN};
use synch_mpt::{MemStore, NodeStore, Trie, TrieNode};

#[test]
fn routing_preserves_entries_and_old_versions_and_is_idempotent() {
    let store = MemStore::default();
    let trie = Trie::new(&store);
    let mut root = Hash::EMPTY;
    for (key, value) in [
        (b"f:photos/a.jpg".as_slice(), b"photo".as_slice()),
        (b"f:finance/q3.pdf", b"private"),
        (b"r:photos", b"private shorter exact key"),
        (b"r:photos-raw", b"shared longer exact key"),
        (b"m:self", b"manifest"),
        (b"m:space/photos", b"space metadata"),
        (b"d:subject", b"delegation"),
    ] {
        root = trie.insert(root, key, value).unwrap();
    }
    let entries = trie.iter(root).unwrap();
    let routed = trie.normalize_publication(root).unwrap();
    assert_ne!(routed, root);
    assert!(matches!(
        TrieNode::decode(&store.get_node(&routed).unwrap().unwrap()).unwrap(),
        TrieNode::Route { .. }
    ));
    assert_eq!(trie.iter(routed).unwrap(), entries);
    assert_eq!(trie.iter(root).unwrap(), entries);
    assert_eq!(trie.normalize_publication(routed).unwrap(), routed);
    assert!(trie.is_complete(routed).unwrap());

    let edited = trie.insert(routed, b"r:photos-raw", b"new").unwrap();
    assert_eq!(
        trie.get(edited, b"r:photos").unwrap(),
        Some(b"private shorter exact key".to_vec())
    );
    assert_eq!(
        trie.get(edited, b"r:photos-raw").unwrap(),
        Some(b"new".to_vec())
    );
    let removed = trie.remove(edited, b"r:photos-raw").unwrap();
    assert_eq!(trie.get(removed, b"r:photos-raw").unwrap(), None);
    assert_eq!(trie.iter(routed).unwrap(), entries);
}

#[test]
fn routing_handles_the_longest_exact_key_without_nested_native_continuations() {
    let store = MemStore::default();
    let trie = Trie::new(&store);
    let key = vec![b'x'; MAX_KEY_LEN];
    let root = trie.insert(Hash::EMPTY, &key, b"payload").unwrap();
    let routed = trie.normalize_publication(root).unwrap();
    assert_eq!(trie.get(routed, &key).unwrap(), Some(b"payload".to_vec()));
    assert!(trie.is_complete(routed).unwrap());
}

#[test]
fn an_empty_publication_stays_empty() {
    let store = MemStore::default();
    assert_eq!(
        Trie::new(&store)
            .normalize_publication(Hash::EMPTY)
            .unwrap(),
        Hash::EMPTY
    );
    assert_eq!(store.node_count(), 0);
}
