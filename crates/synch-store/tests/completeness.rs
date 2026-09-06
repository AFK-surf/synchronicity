use synch_core::{Hash, OriginId, ScopeKeys};
use synch_mpt::{MissingWalk, Nibbles, NodeStore, Scope, Trie, TrieNode, ValueRef};
use synch_store::{Store, StoreError};

fn boundary() -> (Scope, Hash, Vec<u8>) {
    let scope = Scope::of(&ScopeKeys {
        prefixes: vec![b"ab".to_vec()],
        exact: vec![],
    });
    let leaf = TrieNode::Leaf {
        key_rest: Nibbles::from_bytes(b"b"),
        value: ValueRef::Inline(vec![1]),
    };
    let mut children = [None; 16];
    children[6] = Some(TrieNode::hash_of_encoded(&leaf.encode()).unwrap());
    let node = TrieNode::Branch {
        children,
        value: Some(ValueRef::Inline(vec![2])),
    };
    assert!(!scope.admits_node(&[], &node));
    let bytes = node.encode();
    (scope, TrieNode::hash_of_encoded(&bytes).unwrap(), bytes)
}

#[test]
fn ownership_invalidates_an_already_stored_boundary_across_handles() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let other = Store::open(dir.path()).unwrap();
    let owner = OriginId::named("delegate", "cluster.example").unwrap();
    let (scope, root, bytes) = boundary();
    store.put_node(&root, &bytes).unwrap();
    store.note_redacted(&root, &[]).unwrap();
    assert!(Trie::new(&store)
        .is_complete_scoped_for(Some(&owner), root, &scope)
        .unwrap());
    other.note_owned(&owner, &root).unwrap();
    assert!(!Trie::new(&store)
        .is_complete_scoped_for(Some(&owner), root, &scope)
        .unwrap());
}

#[test]
fn an_old_walk_cannot_recertify_a_dissolved_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let other = Store::open(dir.path()).unwrap();
    let (scope, root, bytes) = boundary();
    store.note_redacted(&root, &[]).unwrap();
    let generation = store.completeness_generation().unwrap();
    let mut walk = MissingWalk::scoped(None, root, scope.clone());
    assert!(walk.next_batch(&Trie::new(&store), 256).unwrap().is_empty());
    assert!(walk.is_exhausted());
    other.put_node(&root, &bytes).unwrap();
    assert!(!store
        .note_complete_at(&scope.memo_key(root), generation)
        .unwrap());
    assert!(!Trie::new(&store).is_complete_scoped(root, &scope).unwrap());
}

#[test]
fn a_walk_started_during_an_invalidating_transaction_cannot_certify_after_commit() {
    let dir = tempfile::tempdir().unwrap();
    let writer = Store::open(dir.path()).unwrap();
    let reader = Store::open(dir.path()).unwrap();
    let (scope, root, bytes) = boundary();
    writer.note_redacted(&root, &[]).unwrap();
    let generation = writer
        .transaction(|txn| -> Result<_, StoreError> {
            txn.put_node(&root, &bytes)?;
            // A separate WAL reader sees the old, refused boundary. It must not
            // cache that snapshot while this writer is uncommitted.
            let generation = reader.completeness_generation()?;
            assert!(!reader.note_complete_at(&scope.memo_key(root), generation)?);
            Ok(generation)
        })
        .unwrap();
    assert!(!reader
        .note_complete_at(&scope.memo_key(root), generation)
        .unwrap());
    assert!(!Trie::new(&reader).is_complete_scoped(root, &scope).unwrap());
}

#[test]
fn rollback_releases_invalidation_but_does_not_reuse_its_generation() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (scope, root, bytes) = boundary();
    store.note_redacted(&root, &[]).unwrap();
    let before = store.completeness_generation().unwrap();
    let error = store.transaction(|txn| -> Result<(), StoreError> {
        txn.put_node(&root, &bytes)?;
        Err(StoreError::Invalid("rollback".into()))
    });
    assert!(error.is_err());
    assert!(!store
        .note_complete_at(&scope.memo_key(root), before)
        .unwrap());
    assert!(Trie::new(&store).is_complete_scoped(root, &scope).unwrap());
}
