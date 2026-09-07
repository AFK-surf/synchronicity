//! Observable progress and transfer cost of the actual suspended requesting operation.
use std::collections::HashSet;

use synch_core::{Hash, OriginId};
use synch_mpt::{MemStore, NodeStore, Scope, Trie};
use synch_store::Store;
use synch_verified::suspend::{PeerReply, PeerRequest};

fn populate(source: &MemStore, count: usize) -> Hash {
    let trie = Trie::new(source);
    (0..count).fold(Hash::EMPTY, |root, index| {
        trie.insert(
            root,
            format!("f:media/dir{:02}/file{index:06}", index % 100).as_bytes(),
            &index.to_le_bytes(),
        )
        .unwrap()
    })
}

fn pull(source: &MemStore, destination: &Store, root: Hash, reference: Option<Hash>) -> usize {
    let origin = OriginId::named("fixture", "example.test").unwrap();
    let mut requested = HashSet::new();
    assert!(destination
        .fetch_trie(
            root,
            &origin,
            1,
            &Scope::full(),
            None,
            reference,
            64,
            3,
            |request| Some(match request {
                PeerRequest::Nodes { wants, .. } => PeerReply::Nodes {
                    served: wants
                        .iter()
                        .map(|(_, hash)| {
                            let key = Hash::from_slice(hash).unwrap();
                            assert!(
                                requested.insert(key),
                                "an already delivered node was requested twice"
                            );
                            (hash.clone(), source.get_node(&key).unwrap().unwrap())
                        })
                        .collect(),
                    missing: vec![],
                    redacted: vec![],
                },
                PeerRequest::Values { wants, .. } => PeerReply::Values {
                    served: wants
                        .iter()
                        .map(|(_, hash)| (
                            hash.clone(),
                            source
                                .get_value(&Hash::from_slice(hash).unwrap())
                                .unwrap()
                                .unwrap()
                        ))
                        .collect(),
                    missing: vec![],
                },
            })
        )
        .unwrap()
        .unwrap());
    assert!(Trie::new(destination).is_complete(root).unwrap());
    requested.len()
}

#[test]
fn a_cold_fetch_transfers_each_node_once_and_an_update_only_transfers_changes() {
    let source = MemStore::new();
    let old = populate(&source, 2_000);
    let dir = tempfile::tempdir().unwrap();
    let destination = Store::open(dir.path()).unwrap();
    let total = Trie::new(&source).reachable(old).unwrap().nodes.len();
    assert_eq!(pull(&source, &destination, old, None), total);
    let new = Trie::new(&source)
        .insert(old, b"f:media/dir00/file000000", b"changed")
        .unwrap();
    assert!(pull(&source, &destination, new, Some(old)) < 100);
    assert_eq!(
        Trie::new(&destination)
            .get(new, b"f:media/dir00/file000000")
            .unwrap(),
        Some(b"changed".to_vec())
    );
}

#[test]
fn an_unheld_reference_never_hides_missing_shared_structure() {
    let source = MemStore::new();
    let old = populate(&source, 500);
    let new = Trie::new(&source)
        .insert(old, b"f:media/dir00/file000000", b"changed")
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let destination = Store::open(dir.path()).unwrap();
    let total = Trie::new(&source).reachable(new).unwrap().nodes.len();
    assert_eq!(pull(&source, &destination, new, Some(old)), total);
}

#[test]
fn a_shared_missing_payload_is_requested_once_per_round_until_it_arrives() {
    let source = MemStore::new();
    let payload = vec![4; 300];
    let mut root = Hash::EMPTY;
    for key in [b"f:s/alpha".as_slice(), b"f:s/beta", b"f:s/gamma"] {
        root = Trie::new(&source).insert(root, key, &payload).unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let destination = Store::open(dir.path()).unwrap();
    for hash in Trie::new(&source).reachable(root).unwrap().nodes {
        destination
            .put_node(&hash, &source.get_node(&hash).unwrap().unwrap())
            .unwrap();
    }
    let origin = OriginId::named("fixture", "example.test").unwrap();
    let mut rounds = 0;
    assert!(destination
        .fetch_trie(
            root,
            &origin,
            1,
            &Scope::full(),
            None,
            None,
            256,
            3,
            |request| {
                let PeerRequest::Values { wants, .. } = request else {
                    panic!("all nodes are held")
                };
                assert_eq!(
                    wants.len(),
                    1,
                    "shared payload must be requested only once in one round"
                );
                assert!(!Trie::new(&destination).is_complete(root).unwrap());
                rounds += 1;
                Some(PeerReply::Values {
                    served: if rounds == 2 {
                        vec![(wants[0].1.clone(), payload.clone())]
                    } else {
                        vec![]
                    },
                    missing: if rounds == 1 {
                        vec![wants[0].1.clone()]
                    } else {
                        vec![]
                    },
                })
            }
        )
        .unwrap()
        .unwrap());
    assert_eq!(rounds, 2);
    for key in [b"f:s/alpha".as_slice(), b"f:s/beta", b"f:s/gamma"] {
        assert_eq!(
            Trie::new(&destination).get(root, key).unwrap(),
            Some(payload.clone())
        );
    }
}

#[test]
fn an_extension_child_arriving_as_a_leaf_never_completes() {
    use synch_mpt::{Nibbles, TrieNode, ValueRef};
    let leaf = TrieNode::Leaf {
        key_rest: Nibbles::new(),
        value: ValueRef::Inline(vec![1]),
    };
    let extension = TrieNode::Ext {
        prefix: Nibbles::from_nibbles(&[1]),
        child: leaf.hash(),
    };
    let dir = tempfile::tempdir().unwrap();
    let destination = Store::open(dir.path()).unwrap();
    destination
        .put_node(&extension.hash(), &extension.encode())
        .unwrap();
    let origin = OriginId::named("fixture", "example.test").unwrap();
    let result = destination
        .fetch_trie(
            extension.hash(),
            &origin,
            1,
            &Scope::full(),
            None,
            None,
            64,
            3,
            |request| {
                let PeerRequest::Nodes { wants, .. } = request else {
                    panic!("no payload request")
                };
                assert_eq!(wants, &vec![(vec![1], leaf.hash().as_bytes().to_vec())]);
                Some(PeerReply::Nodes {
                    served: vec![(leaf.hash().as_bytes().to_vec(), leaf.encode())],
                    missing: vec![],
                    redacted: vec![],
                })
            },
        )
        .unwrap();
    assert!(matches!(
        result,
        Err(synch_verified::trie::TrieFetchDomainError::Walk(
            synch_verified::trie::TrieMissingDomainError::ExpectedBranch(_)
        ))
    ));
    assert!(!destination.is_known_complete(&extension.hash()).unwrap());
}

#[test]
fn small_route_values_arrive_through_the_same_fetch_admission_as_large_values() {
    use synch_mpt::TrieNode;
    let source = MemStore::new();
    let payload = b"small";
    let value = Hash::new(payload);
    let node = TrieNode::Route {
        children: [None; 16],
        value: Some(value),
    };
    source.put_node(&node.hash(), &node.encode()).unwrap();
    source.put_value(&value, payload).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let destination = Store::open(dir.path()).unwrap();
    assert_eq!(pull(&source, &destination, node.hash(), None), 1);
    assert_eq!(
        Trie::new(&destination).get(node.hash(), b"").unwrap(),
        Some(payload.to_vec())
    );
}
