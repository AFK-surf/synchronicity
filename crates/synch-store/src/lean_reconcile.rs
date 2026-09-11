//! Raw services for the Lean reconciliation and materialized-view commands.
use crate::{
    lean_authorization::origin, lean_history, lean_storage::SqliteStorage, Result, Store,
    StoreError, Txn,
};
use synch_core::{Hash, OriginId, SignedHead};
use synch_mpt::NodeStore;
use synch_verified::{host, reconcile as native, trie, CommandError};

struct Unicode;
impl host::Unicode for Unicode {
    type Error = StoreError;
    fn is_nfc(&mut self, text: &str) -> Result<bool> {
        Ok(unicode_normalization::is_nfc(text))
    }
}
struct Digest;
impl host::Digest for Digest {
    type Error = StoreError;
    fn blake3(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(Hash::new(bytes).as_bytes().to_vec())
    }
}
struct Memo<'a, S>(&'a S);
impl<S: NodeStore<Error = StoreError>> host::Memo for Memo<'_, S> {
    type Error = StoreError;
    fn forget_except(&mut self, _: &[&[u8]]) -> Result<()> {
        Err(StoreError::invalid(
            "reconciliation requested memo invalidation",
        ))
    }
    fn is_known(&mut self, key: &[u8]) -> Result<bool> {
        self.0.is_known_complete(&hash(key)?)
    }
    fn generation(&mut self) -> Result<u64> {
        self.0.completeness_generation()
    }
    fn certify(&mut self, key: &[u8], generation: u64) -> Result<bool> {
        // Whole reconciliation certifies only committed trie bytes: admission
        // commits before inspection, and promotion never writes trie nodes.
        // Borrowed publication views use Txn's non-caching implementation.
        self.0.note_complete_at(&hash(key)?, generation)
    }
}
struct Redaction<'a, S>(&'a S);
impl<S: NodeStore<Error = StoreError>> host::Redaction for Redaction<'_, S> {
    type Error = StoreError;
    fn is_redacted(&mut self, key: &[u8], path: Option<&[u8]>) -> Result<bool> {
        self.0.is_redacted(&hash(key)?, path)
    }
}
fn hash(bytes: &[u8]) -> Result<Hash> {
    Hash::from_slice(bytes).map_err(|e| StoreError::invalid(e.to_string()))
}
fn services<'a, S: NodeStore<Error = StoreError>>(
    crypto: &'a mut lean_history::Crypto,
    unicode: &'a mut Unicode,
    digest: &'a mut Digest,
    clock: &'a mut crate::lean_durable::Clock,
    memo: &'a mut Memo<'_, S>,
    redaction: &'a mut Redaction<'_, S>,
) -> native::Resources<'a, StoreError> {
    native::Resources {
        crypto,
        unicode,
        digest,
        clock,
        memo,
        redaction,
    }
}
fn walk_error(error: trie::WalkError<StoreError>) -> StoreError {
    use trie::TrieWalkDomainError as D;
    let domain = match error {
        CommandError::Operation(trie::OperationError::Host(e)) => return e,
        CommandError::Operation(e) => return StoreError::invalid(e.to_string()),
        CommandError::Domain(d) => d,
    };
    let error = match domain {
        D::MissingNode(h) => synch_mpt::MptError::MissingNode(hash(&h).unwrap_or(Hash::EMPTY)),
        D::MissingValue(h) => synch_mpt::MptError::MissingValue(hash(&h).unwrap_or(Hash::EMPTY)),
        D::Decode(s) => return StoreError::Decode(s),
        D::OddDepthValue => synch_mpt::MptError::OddDepthValue,
        D::Ceiling => {
            synch_mpt::MptError::NonCanonical("trie walk position ceiling exceeded".into())
        }
    };
    StoreError::Mpt(error)
}
fn domain_error(error: native::ReconcileDomainError) -> StoreError {
    match error {
        native::ReconcileDomainError::History(e) => lean_history::error(CommandError::Domain(e)),
        native::ReconcileDomainError::Walk(e) => walk_error(CommandError::Domain(e)),
        native::ReconcileDomainError::Missing(e) => {
            StoreError::Mpt(synch_mpt::MptError::NonCanonical(format!("{e:?}")))
        }
        native::ReconcileDomainError::Fetch(e) => {
            StoreError::Mpt(synch_mpt::MptError::NonCanonical(format!("{e:?}")))
        }
    }
}
impl From<native::ReconcileDomainError> for StoreError {
    fn from(value: native::ReconcileDomainError) -> Self {
        domain_error(value)
    }
}
fn error(error: CommandError<StoreError, native::ReconcileDomainError>) -> StoreError {
    match error {
        CommandError::Operation(trie::OperationError::Host(e)) => e,
        CommandError::Operation(e) => StoreError::invalid(e.to_string()),
        CommandError::Domain(e) => domain_error(e),
    }
}

impl Store {
    /// Reconcile the selected pending version through one suspended Lean
    /// command. Returning no peer reply cancels and releases its continuation.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch_pending(
        &self,
        id: &OriginId,
        expected: Option<(u64, Hash)>,
        refused: Vec<(u64, Hash, Hash)>,
        maximum: u64,
        retry_limit: u64,
        mut roundtrip: impl FnMut(
            &synch_verified::suspend::PeerRequest,
        ) -> Option<synch_verified::suspend::PeerReply<StoreError>>,
    ) -> std::result::Result<
        native::FetchReport,
        CommandError<StoreError, native::ReconcileDomainError>,
    > {
        use synch_verified::suspend::Step;
        let mut crypto = lean_history::Crypto;
        let mut unicode = Unicode;
        let mut digest = Digest;
        let mut clock = crate::lean_durable::Clock;
        let mut memo = Memo(self);
        let mut redaction = Redaction(self);
        let mut step = {
            let mut storage = crate::lean_storage::Session::new(self);
            native::fetch(
                &mut storage,
                services(
                    &mut crypto,
                    &mut unicode,
                    &mut digest,
                    &mut clock,
                    &mut memo,
                    &mut redaction,
                ),
                origin(id),
                expected.map(|(seq, root)| (seq, root.as_bytes().to_vec())),
                refused
                    .into_iter()
                    .map(|(seq, root, old)| {
                        (seq, (root.as_bytes().to_vec(), old.as_bytes().to_vec()))
                    })
                    .collect(),
                maximum,
                retry_limit,
            )
            .map_err(CommandError::Operation)?
        };
        loop {
            match step {
                Step::Done(report) => return report.map_err(CommandError::Domain),
                Step::Suspended(suspended) => {
                    let Some(reply) = roundtrip(suspended.request()) else {
                        return Err(CommandError::Operation(trie::OperationError::Host(
                            StoreError::invalid("fetch cancelled"),
                        )));
                    };
                    let mut storage = crate::lean_storage::Session::new(self);
                    step = native::resume(
                        suspended,
                        reply,
                        &mut storage,
                        services(
                            &mut crypto,
                            &mut unicode,
                            &mut digest,
                            &mut clock,
                            &mut memo,
                            &mut redaction,
                        ),
                    )
                    .map_err(CommandError::Operation)?;
                }
            }
        }
    }
    /// Lean verifies the head and commits its history and pending transition.
    pub fn accept_head(
        &self,
        head: &SignedHead,
        now: i64,
        keep: usize,
    ) -> Result<native::Acceptance> {
        self.with_connection_scope(|conn| {
            native::accept(
                &mut SqliteStorage::new(conn),
                &mut lean_history::Crypto,
                native::Head {
                    origin: origin(&head.origin),
                    seq: head.seq,
                    root: head.root.as_bytes().to_vec(),
                    created_at: head.created_at,
                    signed_by: head.signed_by.as_bytes().to_vec(),
                    signature: head.sig.to_bytes().to_vec(),
                },
                now,
                keep as u64,
            )
            .map_err(lean_history::error)
        })
    }
    /// Lean owns promotion, rollback and exact-version retirement. The callback
    /// stores only the diagnostic memo entry explicitly returned by Lean.
    pub fn promote_head(
        &self,
        id: &OriginId,
        now: i64,
        refused: Vec<(u64, Hash, Hash)>,
        mut note_refused: impl FnMut(u64, Hash, Hash),
    ) -> Result<native::Promotion> {
        let report = self.with_connection_scope(|conn| {
            let mut storage = SqliteStorage::new(conn);
            native::promote(
                &mut storage,
                services(
                    &mut lean_history::Crypto,
                    &mut Unicode,
                    &mut Digest,
                    &mut crate::lean_durable::Clock,
                    &mut Memo(self),
                    &mut Redaction(self),
                ),
                origin(id),
                now,
                refused
                    .into_iter()
                    .map(|(seq, root, old)| {
                        (seq, (root.as_bytes().to_vec(), old.as_bytes().to_vec()))
                    })
                    .collect(),
            )
            .map_err(error)
        })?;
        if let Some((seq, (root, old))) = report.refused {
            note_refused(seq, hash(&root)?, hash(&old)?);
        }
        if let Some(e) = report.failure {
            return Err(domain_error(e));
        }
        Ok(report.promotion)
    }
}

pub(crate) fn materialize(txn: &Txn<'_>, id: &OriginId, old: Hash, new: Hash) -> Result<usize> {
    let (mut storage, tx) = SqliteStorage::borrow_transaction(txn.conn())?;
    let count = native::materialize(
        &mut storage,
        services(
            &mut lean_history::Crypto,
            &mut Unicode,
            &mut Digest,
            &mut crate::lean_durable::Clock,
            &mut Memo(txn),
            &mut Redaction(txn),
        ),
        tx,
        origin(id),
        old.as_bytes().to_vec(),
        new.as_bytes().to_vec(),
    )
    .map_err(error)?;
    usize::try_from(count).map_err(|_| StoreError::invalid("view change count overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Binding, BindingSource, Slot};
    use synch_core::{file_key, FileEntry};
    use synch_mpt::Trie;
    use synch_verified::suspend::{PeerReply, PeerRequest};

    fn trust(store: &Store, key: &iroh_base::SecretKey, id: &OriginId) {
        store
            .put_binding(&Binding {
                origin: id.clone(),
                node_id: key.public(),
                source: BindingSource::Static,
                domain: None,
                issuer: None,
                spaces: vec![],
                read_only: Vec::new(),
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
    }

    #[test]
    fn local_metadata_failure_keeps_pending_work_retryable() {
        let (_dir, store) = crate::testutil::store();
        let id = crate::testutil::origin();
        let key = iroh_base::SecretKey::generate();
        trust(&store, &key, &id);
        let entry = FileEntry::file(7, 0, Hash::new(b"payload"), 1);
        let root = Trie::new(&store)
            .insert(
                Hash::EMPTY,
                &file_key("s", "file").unwrap(),
                &postcard::to_stdvec(&entry).unwrap(),
            )
            .unwrap();
        let head = SignedHead::sign(&key, id.clone(), 1, root, 0);
        store.accept_head(&head, 0, 8).unwrap();
        store.set_config("replica.release_floor", "0").unwrap();
        store
            .conn()
            .execute(
                "UPDATE config SET value = x'ff' WHERE key = 'replica.release_floor'",
                [],
            )
            .unwrap();
        let error = store
            .promote_head(&id, 0, vec![], |_, _, _| {
                panic!("local failure memoized as origin fault")
            })
            .unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::Sqlite(rusqlite::Error::InvalidColumnType(..))
            ),
            "{error}"
        );
        assert_eq!(store.pending_head(&id).unwrap(), Some(head.clone()));
        assert!(store.complete_head(&id).unwrap().is_none());
        assert!(store.entry(&id, "s", "file").unwrap().is_none());
        assert!(store.conn().is_autocommit());
        store.set_config("replica.release_floor", "0").unwrap();
        assert_eq!(
            store
                .promote_head(&id, 0, vec![], |_, _, _| panic!("valid head refused"))
                .unwrap(),
            native::Promotion::Flipped
        );
        assert_eq!(store.complete_head(&id).unwrap(), Some(head));
        assert_eq!(
            store.entry(&id, "s", "file").unwrap().unwrap().content,
            entry.content
        );
    }

    #[test]
    fn obsolete_fetch_cannot_retire_the_newer_pending_version() {
        let (_dir, store) = crate::testutil::store();
        let id = crate::testutil::origin();
        let key = iroh_base::SecretKey::generate();
        trust(&store, &key, &id);
        let old = SignedHead::sign(&key, id.clone(), 1, Hash::new(b"old"), 0);
        let newer = SignedHead::sign(&key, id.clone(), 2, Hash::new(b"new"), 0);
        store.accept_head(&old, 0, 8).unwrap();
        let mut rounds = 0;
        let result = store
            .fetch_pending(&id, Some((old.seq, old.root)), vec![], 256, 3, |request| {
                rounds += 1;
                if rounds == 1 {
                    store.accept_head(&newer, 0, 8).unwrap();
                }
                let PeerRequest::Nodes { wants, .. } = request else {
                    panic!("missing trie has no values to fetch")
                };
                Some(PeerReply::Nodes {
                    served: vec![],
                    missing: wants.iter().map(|(_, h)| h.clone()).collect(),
                    redacted: vec![],
                })
            })
            .unwrap();
        assert_eq!(rounds, 3);
        assert!(result.abandoned);
        assert_eq!(store.pending_head(&id).unwrap(), Some(newer.clone()));
        let stale = store
            .fetch_pending(&id, Some((old.seq, old.root)), vec![], 256, 3, |_| {
                panic!("stale expected version contacted a peer")
            })
            .unwrap();
        assert_eq!(stale.report.promotion, native::Promotion::Idle);
        assert_eq!(store.pending_head(&id).unwrap(), Some(newer));
        assert!(store.complete_head(&id).unwrap().is_none());
    }

    #[test]
    fn pending_reconciliation_cancels_without_losing_verified_progress_or_holding_storage() {
        let (_source_dir, source) = crate::testutil::store();
        let (_dir, store) = crate::testutil::store();
        let id = crate::testutil::origin();
        let key = iroh_base::SecretKey::generate();
        trust(&store, &key, &id);
        let mut entry = FileEntry::file(7, 0, Hash::new(b"payload"), 1);
        entry.symlink_target = Some("large value".repeat(100));
        let root = Trie::new(&source)
            .insert(
                Hash::EMPTY,
                &file_key("s", "file").unwrap(),
                &postcard::to_stdvec(&entry).unwrap(),
            )
            .unwrap();
        let head = SignedHead::sign(&key, id.clone(), 1, root, 0);
        store.accept_head(&head, 0, 8).unwrap();
        let answer = |request: &PeerRequest| match request {
            PeerRequest::Nodes { wants, .. } => PeerReply::Nodes {
                served: wants
                    .iter()
                    .map(|(_, h)| {
                        (
                            h.clone(),
                            source.get_node(&hash(h).unwrap()).unwrap().unwrap(),
                        )
                    })
                    .collect(),
                missing: vec![],
                redacted: vec![],
            },
            PeerRequest::Values { wants, .. } => PeerReply::Values {
                served: wants
                    .iter()
                    .map(|(_, h)| {
                        (
                            h.clone(),
                            source.get_value(&hash(h).unwrap()).unwrap().unwrap(),
                        )
                    })
                    .collect(),
                missing: vec![],
            },
        };
        let mut asked_for_values = false;
        let result = store.fetch_pending(&id, Some((1, root)), vec![], 256, 3, |request| {
            store.transaction(|_| Ok::<(), StoreError>(())).unwrap();
            if matches!(request, PeerRequest::Values { .. }) {
                asked_for_values = true;
                None
            } else {
                Some(answer(request))
            }
        });
        assert!(asked_for_values && result.is_err());
        assert!(store.get_node(&root).unwrap().is_some());
        assert_eq!(store.pending_head(&id).unwrap(), Some(head.clone()));
        assert!(store.complete_head(&id).unwrap().is_none());
        let result = store
            .fetch_pending(&id, Some((1, root)), vec![], 256, 3, |request| {
                store.transaction(|_| Ok::<(), StoreError>(())).unwrap();
                Some(answer(request))
            })
            .unwrap();
        assert_eq!(result.report.promotion, native::Promotion::Flipped);
        assert!(result.report.failure.is_none());
        assert_eq!(store.head(&id, Slot::Complete).unwrap().unwrap().head, head);
        assert_eq!(
            store
                .entry(&id, "s", "file")
                .unwrap()
                .unwrap()
                .symlink_target,
            entry.symlink_target
        );
    }
}
