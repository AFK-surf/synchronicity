//! Raw store services for the requesting Lean operation. Each continuation
//! interval owns a storage session; no session survives a peer round trip.

use synch_core::{Hash, OriginId};
use synch_mpt::{NodeStore, Scope};
use synch_verified::{
    host,
    suspend::{PeerReply, PeerRequest, Step},
    trie,
};

use crate::{lean_storage::Session, Result, Store, StoreError};

struct Digest;
impl host::Digest for Digest {
    type Error = StoreError;
    fn blake3(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(Hash::new(bytes).as_bytes().to_vec())
    }
}

struct Memo<'a>(&'a Store);
impl host::Memo for Memo<'_> {
    type Error = StoreError;
    fn forget_except(&mut self, _: &[&[u8]]) -> Result<()> {
        Err(StoreError::invalid("fetch requested memo invalidation"))
    }
    fn is_known(&mut self, key: &[u8]) -> Result<bool> {
        let key = Hash::from_slice(key).map_err(|e| StoreError::invalid(e.to_string()))?;
        self.0.is_known_complete(&key)
    }
    fn generation(&mut self) -> Result<u64> {
        self.0.completeness_generation()
    }
    fn certify(&mut self, key: &[u8], generation: u64) -> Result<bool> {
        let key = Hash::from_slice(key).map_err(|e| StoreError::invalid(e.to_string()))?;
        self.0.note_complete_at(&key, generation)
    }
}

impl Store {
    /// Fetch one named version through the Lean requesting operation. Run on
    /// one blocking worker: the callback transports peer requests, and returning
    /// `None` cancels the continuation without leaving a connection or transaction open.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch_trie(
        &self,
        root: Hash,
        origin: &OriginId,
        seq: u64,
        scope: &Scope,
        owner: Option<&OriginId>,
        reference: Option<Hash>,
        maximum: u64,
        retry_limit: u64,
        mut roundtrip: impl FnMut(&PeerRequest) -> Option<PeerReply<StoreError>>,
    ) -> std::result::Result<
        std::result::Result<bool, trie::TrieFetchDomainError>,
        trie::OperationError<StoreError>,
    > {
        let mut digest = Digest;
        let mut memo = Memo(self);
        let mut clock = crate::lean_durable::Clock;
        let mut step = {
            let mut storage = Session::new(self);
            trie::fetch(
                &mut storage,
                trie::FetchResources {
                    digest: &mut digest,
                    memo: &mut memo,
                    clock: &mut clock,
                },
                root.as_bytes(),
                origin.canonical(),
                seq,
                trie::ServeScope {
                    prefixes: scope.prefixes().map(<[Vec<u8>]>::to_vec),
                    exact: scope.exact().to_vec(),
                },
                owner.map(OriginId::canonical),
                reference.map(|h| h.as_bytes().to_vec()),
                maximum,
                retry_limit,
            )?
        };
        loop {
            match step {
                Step::Done(outcome) => return Ok(outcome),
                Step::Suspended(suspended) => {
                    let Some(reply) = roundtrip(suspended.request()) else {
                        return Err(trie::OperationError::Host(StoreError::invalid(
                            "fetch cancelled",
                        )));
                    };
                    let mut storage = Session::new(self);
                    step = trie::resume_fetch(
                        suspended,
                        reply,
                        &mut storage,
                        trie::FetchResources {
                            digest: &mut digest,
                            memo: &mut memo,
                            clock: &mut clock,
                        },
                    )?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{origin, store};
    use synch_mpt::Trie;

    #[test]
    fn requesting_operation_fetches_values_and_provenance_without_holding_a_connection() {
        let (_source_dir, source) = store();
        let (_destination_dir, destination) = store();
        let root = Trie::new(&source)
            .insert(Hash::EMPTY, b"shared", &vec![7; 300])
            .unwrap();
        let owner = origin();
        let mut rounds = 0;
        let result = destination
            .fetch_trie(
                root,
                &owner,
                1,
                &Scope::full(),
                Some(&owner),
                None,
                256,
                3,
                |request| {
                    // Reentry would panic or deadlock if a connection guard survived
                    // the suspension; this also exercises a fresh transaction.
                    destination
                        .transaction(|_| Ok::<(), StoreError>(()))
                        .unwrap();
                    rounds += 1;
                    Some(match request {
                        PeerRequest::Nodes { wants, .. } => PeerReply::Nodes {
                            served: wants
                                .iter()
                                .map(|(_, hash)| {
                                    let key = Hash::from_slice(hash).unwrap();
                                    (hash.clone(), source.get_node(&key).unwrap().unwrap())
                                })
                                .collect(),
                            missing: vec![],
                            redacted: vec![],
                        },
                        PeerRequest::Values { wants, .. } => PeerReply::Values {
                            served: wants
                                .iter()
                                .map(|(_, hash)| {
                                    let key = Hash::from_slice(hash).unwrap();
                                    (hash.clone(), source.get_value(&key).unwrap().unwrap())
                                })
                                .collect(),
                            missing: vec![],
                        },
                    })
                },
            )
            .unwrap()
            .unwrap();
        assert!(result);
        assert_eq!(rounds, 2);
        assert_eq!(
            Trie::new(&destination).get(root, b"shared").unwrap(),
            Some(vec![7; 300])
        );
        assert!(destination.owns_node(&owner, &root).unwrap());
    }

    #[test]
    fn refusing_every_request_is_not_progress_or_completion() {
        let (_dir, destination) = store();
        let root = Hash::new(b"unavailable");
        let mut rounds = 0;
        let result = destination
            .fetch_trie(
                root,
                &origin(),
                1,
                &Scope::full(),
                None,
                None,
                256,
                3,
                |request| {
                    rounds += 1;
                    let PeerRequest::Nodes { wants, .. } = request else {
                        panic!("expected nodes")
                    };
                    Some(PeerReply::Nodes {
                        served: vec![],
                        missing: vec![],
                        redacted: wants.iter().map(|(_, hash)| hash.clone()).collect(),
                    })
                },
            )
            .unwrap()
            .unwrap();
        assert!(!result);
        assert_eq!(rounds, 3);
        assert!(!Trie::new(&destination).is_complete(root).unwrap());
    }

    #[test]
    fn cancellation_preserves_verified_nodes_for_the_next_attempt() {
        let (_source_dir, source) = store();
        let (_destination_dir, destination) = store();
        let root = Trie::new(&source)
            .insert(Hash::EMPTY, b"shared", &vec![8; 300])
            .unwrap();
        let result = destination.fetch_trie(
            root,
            &origin(),
            1,
            &Scope::full(),
            None,
            None,
            256,
            3,
            |request| match request {
                PeerRequest::Nodes { wants, .. } => Some(PeerReply::Nodes {
                    served: wants
                        .iter()
                        .map(|(_, hash)| {
                            (
                                hash.clone(),
                                source
                                    .get_node(&Hash::from_slice(hash).unwrap())
                                    .unwrap()
                                    .unwrap(),
                            )
                        })
                        .collect(),
                    missing: vec![],
                    redacted: vec![],
                }),
                PeerRequest::Values { .. } => None,
            },
        );
        assert!(result.is_err());
        assert!(destination.has_node(&root).unwrap());
        assert!(!Trie::new(&destination).is_complete(root).unwrap());
        destination
            .transaction(|_| Ok::<(), StoreError>(()))
            .unwrap();
    }

    #[test]
    fn a_repeated_answer_rolls_back_bytes_and_provenance_together() {
        let (_source_dir, source) = store();
        let (_destination_dir, destination) = store();
        let root = Trie::new(&source)
            .insert(Hash::EMPTY, b"shared", b"data")
            .unwrap();
        let owner = origin();
        let result = destination
            .fetch_trie(
                root,
                &owner,
                1,
                &Scope::full(),
                Some(&owner),
                None,
                256,
                3,
                |request| {
                    let PeerRequest::Nodes { wants, .. } = request else {
                        panic!("expected nodes")
                    };
                    let served = wants
                        .iter()
                        .flat_map(|(_, hash)| {
                            let pair = (
                                hash.clone(),
                                source
                                    .get_node(&Hash::from_slice(hash).unwrap())
                                    .unwrap()
                                    .unwrap(),
                            );
                            [pair.clone(), pair]
                        })
                        .collect();
                    Some(PeerReply::Nodes {
                        served,
                        missing: vec![],
                        redacted: vec![],
                    })
                },
            )
            .unwrap();
        assert!(matches!(
            result,
            Err(trie::TrieFetchDomainError::Unsolicited { value: false, .. })
        ));
        assert!(!destination.has_node(&root).unwrap());
        assert!(!destination.owns_node(&owner, &root).unwrap());
    }

    #[test]
    fn invalidation_between_replies_discards_the_pruning_reference() {
        let (_source_dir, source) = store();
        let (_destination_dir, destination) = store();
        let trie = Trie::new(&source);
        let old = trie.insert(Hash::EMPTY, b"a", b"first").unwrap();
        let old = trie.insert(old, b"b", b"second").unwrap();
        let removed = synch_mpt::TrieNode::Leaf {
            key_rest: synch_mpt::Nibbles::new(),
            value: synch_mpt::ValueRef::Inline(b"first".to_vec()),
        }
        .hash();
        assert!(source.has_node(&removed).unwrap());
        let copy = Trie::new(&destination);
        let copied = copy.insert(Hash::EMPTY, b"a", b"first").unwrap();
        let copied = copy.insert(copied, b"b", b"second").unwrap();
        assert_eq!(copied, old);
        assert!(Trie::new(&destination).is_complete(old).unwrap());
        let new = trie.insert(old, b"c", b"third").unwrap();
        let mut invalidated = false;
        let mut asked_for_removed = false;
        let result = destination
            .fetch_trie(
                new,
                &origin(),
                2,
                &Scope::full(),
                None,
                Some(old),
                256,
                3,
                |request| {
                    if !invalidated {
                        destination
                            .transaction(|txn| -> Result<()> {
                                txn.invalidate_completeness();
                                txn.conn().execute(
                                    "DELETE FROM trie_nodes WHERE hash = ?1",
                                    [removed.as_bytes().as_slice()],
                                )?;
                                Ok(())
                            })
                            .unwrap();
                        invalidated = true;
                    }
                    let PeerRequest::Nodes { wants, .. } = request else {
                        panic!("inline values")
                    };
                    asked_for_removed |= wants
                        .iter()
                        .any(|(_, hash)| hash.as_slice() == removed.as_bytes());
                    Some(PeerReply::Nodes {
                        served: wants
                            .iter()
                            .map(|(_, hash)| {
                                (
                                    hash.clone(),
                                    source
                                        .get_node(&Hash::from_slice(hash).unwrap())
                                        .unwrap()
                                        .unwrap(),
                                )
                            })
                            .collect(),
                        missing: vec![],
                        redacted: vec![],
                    })
                },
            )
            .unwrap()
            .unwrap();
        assert!(result);
        assert!(
            asked_for_removed,
            "a stale reference skipped the deleted shared leaf"
        );
        assert!(Trie::new(&destination).is_complete(new).unwrap());
        assert_eq!(
            Trie::new(&destination).get(new, b"a").unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            Trie::new(&destination).get(new, b"b").unwrap(),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn actual_fetch_reads_scale_with_the_initial_tree_and_then_the_change() {
        let source = synch_mpt::MemStore::new();
        let mut root = Hash::EMPTY;
        for index in 0..2_000usize {
            root = Trie::new(&source)
                .insert(
                    root,
                    format!("f:media/dir{:02}/file{index:06}", index % 100).as_bytes(),
                    &index.to_le_bytes(),
                )
                .unwrap();
        }
        let (_dir, destination) = store();
        let pull = |root, reference| {
            crate::lean_storage::take_byte_read_calls();
            let mut requests = 0;
            assert!(destination
                .fetch_trie(
                    root,
                    &origin(),
                    1,
                    &Scope::full(),
                    None,
                    reference,
                    64,
                    3,
                    |request| Some(match request {
                        PeerRequest::Nodes { wants, .. } => {
                            requests += wants.len();
                            PeerReply::Nodes {
                                served: wants
                                    .iter()
                                    .map(|(_, hash)| {
                                        (
                                            hash.clone(),
                                            source
                                                .get_node(&Hash::from_slice(hash).unwrap())
                                                .unwrap()
                                                .unwrap(),
                                        )
                                    })
                                    .collect(),
                                missing: vec![],
                                redacted: vec![],
                            }
                        }
                        PeerRequest::Values { .. } => panic!("fixture values are inline"),
                    })
                )
                .unwrap()
                .unwrap());
            (requests, crate::lean_storage::take_byte_read_calls())
        };
        let (requests, reads) = pull(root, None);
        assert!(
            reads < requests * 4,
            "{requests} transferred nodes caused {reads} reads"
        );
        let changed = Trie::new(&source)
            .insert(root, b"f:media/dir00/file000000", b"changed")
            .unwrap();
        let (requests, reads) = pull(changed, Some(root));
        assert!(
            requests < 100 && reads < 100,
            "one changed key caused {requests} transfers and {reads} local reads"
        );
        assert_eq!(
            Trie::new(&destination)
                .get(changed, b"f:media/dir00/file000000")
                .unwrap(),
            Some(b"changed".to_vec())
        );
    }
}
