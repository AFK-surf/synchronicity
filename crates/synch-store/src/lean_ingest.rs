//! Mandatory whole native Lean ingestion integration. Rust binds raw services
//! and maps terminal diagnostics only; the operation's ordering, resource
//! lifecycle and metadata commit live in Lean, and the byte streaming,
//! hashing and outboard layout in the resource pool's construction service.

use synch_core::Hash;
use synch_verified::cas;

use crate::{
    lean_diagnostics,
    lean_resources::{Files, Input, Leases},
    Result, Store, StoreError,
};

fn error(error: cas::IngestError<StoreError>) -> StoreError {
    use cas::{IngestDomainError as Domain, IngestError, OperationError};
    match error {
        IngestError::Operation(OperationError::Host(error)) => error,
        IngestError::Operation(_) => StoreError::invalid("invalid native ingestion protocol"),
        IngestError::Domain(Domain::Malformed) => StoreError::Decode("invalid blob claim".into()),
        IngestError::Domain(Domain::ColumnType {
            index,
            column,
            actual,
        }) => lean_diagnostics::column_type(index, column, actual),
        IngestError::Domain(Domain::SizeMismatch {
            root,
            recorded,
            offered,
        }) => StoreError::Verification {
            root: Hash::from_slice(&root).expect("typed digest width"),
            reason: format!("size mismatch: have {recorded}, offered {offered}"),
        },
        IngestError::Domain(Domain::DirectorySyncUnsupported) => std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "directory synchronization is unsupported",
        )
        .into(),
    }
}

fn tier(store: &Store) -> cas::IngestTier {
    if store.complete_is_durable() {
        cas::IngestTier::Local
    } else {
        cas::IngestTier::Cache
    }
}

fn directory_policy() -> cas::DirectoryPolicy {
    if cfg!(windows) {
        cas::DirectoryPolicy::AllowUnsupported
    } else {
        cas::DirectoryPolicy::RequireSync
    }
}

/// Records verified groups through the Lean metadata commit.
pub(crate) fn commit_groups(
    store: &Store,
    root: &Hash,
    size: u64,
    groups: &synch_core::ChunkRanges,
    inline: Option<Vec<u8>>,
    now: i64,
) -> Result<crate::cas::Commit> {
    let spans: Vec<(u64, u64)> = groups.ranges.iter().map(|r| (r.start, r.end)).collect();
    let mut storage = crate::lean_storage::Session::new(store);
    let committed = cas::commit_groups(
        &mut storage,
        root.as_bytes(),
        size,
        &spans,
        inline.as_deref(),
        now,
        tier(store),
    )
    .map_err(error)?;
    Ok(crate::cas::Commit {
        size: committed.size,
        complete: committed.complete,
    })
}

/// Refuses a size the row's claim cannot yield to, before any bytes are
/// decoded against it.
pub(crate) fn admit_size(store: &Store, root: &Hash, size: u64) -> Result<()> {
    let mut storage = crate::lean_storage::Session::new(store);
    cas::admit_size(&mut storage, root.as_bytes(), size).map_err(error)
}

pub(crate) fn ingest(store: &Store, input: Input<'_>, now: i64) -> Result<(Hash, u64)> {
    let kind = match input {
        Input::Bytes(bytes) => cas::IngestInput::Bytes(
            u64::try_from(bytes.len())
                .map_err(|_| StoreError::invalid("input exceeds unsigned size domain"))?,
        ),
        Input::File(_) => cas::IngestInput::File,
    };
    let mut storage = crate::lean_storage::Session::new(store);
    let mut files = Files::new(store, input);
    let mut construct = files.clone();
    let mut temporary = files.clone();
    let mut source = files.clone();
    let mut leases = Leases::new(store);
    let result = cas::ingest(
        &mut storage,
        cas::IngestResources {
            files: &mut files,
            construct: &mut construct,
            temporary: &mut temporary,
            leases: &mut leases,
            source: &mut source,
        },
        kind,
        now,
        tier(store),
        directory_policy(),
    )
    .map_err(error)?;
    Ok((
        Hash::from_slice(&result.root).expect("typed digest width"),
        result.size,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_verified::host;

    #[derive(Default)]
    struct FaultState {
        target: &'static str,
        occurrence: usize,
        seen: usize,
        fired: bool,
        trace: Vec<&'static str>,
        opened: std::collections::BTreeSet<u64>,
    }
    type Fault = std::rc::Rc<std::cell::RefCell<FaultState>>;
    struct Faulty<T> {
        inner: T,
        fault: Fault,
    }
    impl<T> Faulty<T> {
        fn step(&self, label: &'static str) -> Result<()> {
            let mut state = self.fault.borrow_mut();
            state.trace.push(label);
            if state.target == label {
                state.seen += 1;
                if state.seen == state.occurrence {
                    state.fired = true;
                    return Err(StoreError::invalid(format!("injected {label}")));
                }
            }
            Ok(())
        }
    }
    fn file_error(error: StoreError) -> host::FileFailure<StoreError> {
        host::FileFailure {
            error,
            kind: host::FileFailureKind::Other,
        }
    }
    impl<T: host::FileIO<Error = StoreError>> host::FileIO for Faulty<T> {
        type Error = StoreError;
        fn open(
            &mut self,
            space: &str,
            key: &[u8],
        ) -> std::result::Result<u64, host::FileFailure<StoreError>> {
            self.step("open").map_err(file_error)?;
            let handle = self.inner.open(space, key)?;
            self.fault.borrow_mut().opened.insert(handle);
            Ok(handle)
        }
        fn read_at(
            &mut self,
            handle: u64,
            offset: u64,
            count: u64,
        ) -> std::result::Result<Vec<u8>, host::FileFailure<StoreError>> {
            self.step("read").map_err(file_error)?;
            self.inner.read_at(handle, offset, count)
        }
        fn read_into(
            &mut self,
            handle: u64,
            offset: u64,
            buffer: &mut [u8],
        ) -> std::result::Result<(), host::FileFailure<StoreError>> {
            self.inner.read_into(handle, offset, buffer)
        }
        fn close(&mut self, handle: u64) -> Result<()> {
            self.inner.close(handle)?;
            self.fault.borrow_mut().opened.remove(&handle);
            self.step("close")
        }
    }
    impl<T: host::Construct<Error = StoreError>> host::Construct for Faulty<T> {
        type Error = StoreError;
        fn build(
            &mut self,
            source: u64,
            payload: u64,
            outboard: u64,
            size: u64,
        ) -> Result<Vec<u8>> {
            self.step("build")?;
            self.inner.build(source, payload, outboard, size)
        }
        fn hash(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
            self.step("hash")?;
            self.inner.hash(bytes)
        }
    }
    impl<T: host::TemporaryFiles<Error = StoreError>> host::TemporaryFiles for Faulty<T> {
        type Error = StoreError;
        fn create_temporary(&mut self, space: &str) -> Result<u64> {
            self.step("create")?;
            self.inner.create_temporary(space)
        }
        fn flush(&mut self, handle: u64) -> Result<()> {
            self.step("flush")?;
            self.inner.flush(handle)
        }
        fn replace(&mut self, handle: u64, space: &str, key: &[u8]) -> Result<()> {
            self.step("replace")?;
            self.inner.replace(handle, space, key)
        }
        fn discard(&mut self, handle: u64) -> Result<()> {
            self.inner.discard(handle)?;
            self.step("discard")
        }
        fn sync_parent(&mut self, space: &str, key: &[u8]) -> Result<host::SyncStatus> {
            self.step("sync")?;
            self.inner.sync_parent(space, key)
        }
    }
    impl<T: host::Lease<Error = StoreError>> host::Lease for Faulty<T> {
        type Error = StoreError;
        fn acquire(&mut self, space: &str, key: &[u8]) -> Result<u64> {
            self.step("acquire")?;
            self.inner.acquire(space, key)
        }
        fn order(&mut self, space: &str) -> Result<u64> {
            self.step("order")?;
            self.inner.order(space)
        }
        fn release(&mut self, token: u64) -> Result<()> {
            self.inner.release(token)?;
            self.step("release")
        }
    }
    impl<T: host::SourceIO<Error = StoreError>> host::SourceIO for Faulty<T> {
        type Error = StoreError;
        fn stat(&mut self, space: &str, key: &[u8]) -> Result<u64> {
            self.step("stat")?;
            self.inner.stat(space, key)
        }
        fn read_some(&mut self, handle: u64, offset: u64, count: u64) -> Result<Vec<u8>> {
            self.step("read_some")?;
            self.inner.read_some(handle, offset, count)
        }
        fn freeze(&mut self, bytes: &[u8]) -> Result<u64> {
            self.step("freeze")?;
            let handle = self.inner.freeze(bytes)?;
            self.fault.borrow_mut().opened.insert(handle);
            Ok(handle)
        }
    }

    #[test]
    fn native_ingestion_effect_failures_cleanup_without_false_metadata_publication() {
        for (target, occurrence) in [
            ("stat", 1),
            ("open", 1),
            ("create", 1),
            ("create", 2),
            ("build", 1),
            ("close", 1),
            ("flush", 1),
            ("flush", 2),
            ("acquire", 1),
            ("replace", 1),
            ("replace", 2),
            ("sync", 1),
            ("sync", 2),
            ("release", 1),
        ] {
            let (dir, store) = crate::testutil::store();
            let bytes = data(32769);
            let root = Hash::from_slice(blake3::hash(&bytes).as_bytes()).unwrap();
            let path = dir.path().join("input");
            std::fs::write(&path, &bytes).unwrap();
            let fault = std::rc::Rc::new(std::cell::RefCell::new(FaultState {
                target,
                occurrence,
                ..FaultState::default()
            }));
            let pool = Files::new(&store, Input::File(&path));
            let mut files = Faulty {
                inner: pool.clone(),
                fault: fault.clone(),
            };
            let mut construct = Faulty {
                inner: pool.clone(),
                fault: fault.clone(),
            };
            let mut temporary = Faulty {
                inner: pool.clone(),
                fault: fault.clone(),
            };
            let mut source = Faulty {
                inner: pool,
                fault: fault.clone(),
            };
            let mut leases = Faulty {
                inner: Leases::new(&store),
                fault: fault.clone(),
            };
            let mut storage = crate::lean_storage::Session::new(&store);
            let result = cas::ingest(
                &mut storage,
                cas::IngestResources {
                    files: &mut files,
                    construct: &mut construct,
                    temporary: &mut temporary,
                    leases: &mut leases,
                    source: &mut source,
                },
                cas::IngestInput::File,
                17,
                cas::IngestTier::Local,
                if cfg!(windows) {
                    cas::DirectoryPolicy::AllowUnsupported
                } else {
                    cas::DirectoryPolicy::RequireSync
                },
            )
            .map_err(error);
            let message = result.unwrap_err().to_string();
            assert!(
                message.contains(&format!("injected {target}")),
                "{target}/{occurrence}: {message}"
            );
            let state = fault.borrow();
            assert!(state.fired, "{target}/{occurrence}: {:?}", state.trace);
            // Check before adapters drop: the Lean continuation has already
            // released resources, rather than relying only on host abandonment.
            assert!(
                state.opened.is_empty(),
                "{target}/{occurrence}: {:?}",
                state.trace
            );
            assert!(
                store.active_temporaries().is_empty(),
                "{target}/{occurrence}"
            );
            assert!(!store.is_being_written(&root), "{target}/{occurrence}");
            assert_eq!(
                std::fs::read_dir(store.staging_dir())
                    .map(|entries| entries.count())
                    .unwrap_or(0),
                0
            );
            assert!(store.conn().is_autocommit());
            if target == "release" {
                // Lease release is after commit; an error there cannot undo
                // already-durable metadata or erase the published files.
                assert!(store.blob(&root).unwrap().unwrap().complete);
            } else {
                assert!(
                    store.blob(&root).unwrap().is_none(),
                    "{target}/{occurrence}"
                );
            }
            if store.blob_path(&root).exists() {
                assert_eq!(std::fs::read(store.blob_path(&root)).unwrap(), bytes);
            }
            if target == "release" || (target == "replace" && occurrence == 2) || target == "sync" {
                assert!(
                    store.blob_path(&root).exists(),
                    "published payload lost: {target}/{occurrence}"
                );
            }
        }
    }

    struct ChangingSource<'a> {
        inner: Files<'a>,
        path: &'a std::path::Path,
        after_stat: &'a [u8],
        before_freeze: Option<&'a [u8]>,
        stats: usize,
        freezes: usize,
    }

    impl host::SourceIO for ChangingSource<'_> {
        type Error = StoreError;
        fn stat(&mut self, space: &str, key: &[u8]) -> Result<u64> {
            let size = host::SourceIO::stat(&mut self.inner, space, key)?;
            self.stats += 1;
            std::fs::write(self.path, self.after_stat)?;
            Ok(size)
        }
        fn read_some(&mut self, handle: u64, offset: u64, count: u64) -> Result<Vec<u8>> {
            host::SourceIO::read_some(&mut self.inner, handle, offset, count)
        }
        fn freeze(&mut self, bytes: &[u8]) -> Result<u64> {
            self.freezes += 1;
            if let Some(replacement) = self.before_freeze {
                std::fs::write(self.path, replacement)?;
            }
            host::SourceIO::freeze(&mut self.inner, bytes)
        }
    }

    fn ingest_changing_file(
        store: &Store,
        path: &std::path::Path,
        after_stat: &[u8],
        before_freeze: Option<&[u8]>,
    ) -> (Result<cas::Ingested>, usize) {
        let mut storage = crate::lean_storage::Session::new(store);
        let mut files = Files::new(store, Input::File(path));
        let mut construct = files.clone();
        let mut temporary = files.clone();
        let mut source = ChangingSource {
            inner: files.clone(),
            path,
            after_stat,
            before_freeze,
            stats: 0,
            freezes: 0,
        };
        let mut leases = Leases::new(store);
        let result = cas::ingest(
            &mut storage,
            cas::IngestResources {
                files: &mut files,
                construct: &mut construct,
                temporary: &mut temporary,
                leases: &mut leases,
                source: &mut source,
            },
            cas::IngestInput::File,
            17,
            cas::IngestTier::Local,
            if cfg!(windows) {
                cas::DirectoryPolicy::AllowUnsupported
            } else {
                cas::DirectoryPolicy::RequireSync
            },
        )
        .map_err(error);
        assert_eq!(source.stats, 1);
        (result, source.freezes)
    }

    fn assert_captured(store: &Store, result: cas::Ingested, expected: &[u8]) {
        assert_eq!(result.size, expected.len() as u64);
        assert_eq!(result.root.as_slice(), blake3::hash(expected).as_bytes());
        let root = Hash::from_slice(&result.root).unwrap();
        assert_eq!(store.read_all(&root).unwrap(), expected);
        assert!(store.blob(&root).unwrap().unwrap().complete);
        assert!(!store.is_being_written(&root));
        assert_eq!(
            std::fs::read_dir(store.staging_dir())
                .map(|entries| entries.count())
                .unwrap_or(0),
            0
        );
        assert!(store.conn().is_autocommit());
    }

    #[test]
    fn native_small_file_growth_freezes_captured_bytes_without_reopening_changed_path() {
        // Include multiple 64-KiB reads and a partial final chunk. The Lean
        // collector must preserve order when flattening reversed chunks.
        for size in [32769, 131075, 2097155] {
            let (dir, store) = crate::testutil::store();
            let path = dir.path().join("growing");
            std::fs::write(&path, b"initial").unwrap();
            let captured = data(size);
            let replaced = b"different stream after capture";
            let (result, freezes) = ingest_changing_file(&store, &path, &captured, Some(replaced));
            assert_eq!(freezes, 1);
            assert_eq!(std::fs::read(&path).unwrap(), replaced);
            assert_captured(&store, result.unwrap(), &captured);
        }
    }

    #[test]
    fn native_large_file_growth_consumes_only_initial_stat_length() {
        let (dir, store) = crate::testutil::store();
        let path = dir.path().join("appending");
        let original = data(32769);
        std::fs::write(&path, &original).unwrap();
        let mut grown = original.clone();
        grown.extend_from_slice(&[255; 4096]);
        let (result, freezes) = ingest_changing_file(&store, &path, &grown, None);
        assert_eq!(freezes, 0);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), grown.len() as u64);
        assert_captured(&store, result.unwrap(), &original);
    }

    #[test]
    fn native_large_file_truncation_fails_and_cleans_owned_staging() {
        let (dir, store) = crate::testutil::store();
        let path = dir.path().join("truncated");
        std::fs::write(&path, data(32769)).unwrap();
        let (result, freezes) = ingest_changing_file(&store, &path, &data(16385), None);
        assert_eq!(freezes, 0);
        assert!(
            matches!(result, Err(StoreError::Io(ref error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(std::fs::read_dir(store.staging_dir()).unwrap().count(), 0);
        assert_eq!(
            store
                .conn()
                .query_row("SELECT count(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(store.conn().is_autocommit());
    }

    #[test]
    fn native_small_file_shrink_records_actual_eof_length() {
        let (dir, store) = crate::testutil::store();
        let path = dir.path().join("shrinking");
        std::fs::write(&path, data(1024)).unwrap();
        let captured = b"short";
        let (result, freezes) = ingest_changing_file(&store, &path, captured, None);
        assert_eq!(freezes, 0);
        assert_captured(&store, result.unwrap(), captured);
    }

    fn data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn native_ingestion_produces_content_peers_can_verify() {
        let (dir, store) = crate::testutil::store();
        for size in [0, 1, 63, 1024, 1025, 16384, 16385, 32768, 49152, 100_003] {
            let bytes = data(size);
            for from_file in [false, true] {
                let path = dir.path().join("source");
                std::fs::write(&path, &bytes).unwrap();
                let input = if from_file {
                    Input::File(&path)
                } else {
                    Input::Bytes(&bytes)
                };
                let (root, length) = ingest(&store, input, 17).unwrap();
                assert_eq!(root.as_bytes(), blake3::hash(&bytes).as_bytes());
                assert_eq!(length, size as u64);
                assert_eq!(store.read_all(&root).unwrap(), bytes);
                let row = store.blob(&root).unwrap().unwrap();
                assert!(row.complete);
                assert_eq!(
                    row.inline.is_some(),
                    size <= synch_core::INLINE_BLOB_MAX as usize
                );
                if size > synch_core::INLINE_BLOB_MAX as usize {
                    let (_peer_dir, peer) = crate::testutil::store();
                    let wanted =
                        synch_core::ChunkRanges::single(0, synch_core::group_count(size as u64));
                    let (encoded, served) = store.encode_slice(&root, &wanted).unwrap();
                    assert_eq!(served, wanted);
                    peer.write_slice(&root, length, &served, &encoded, 17)
                        .unwrap();
                    assert_eq!(peer.read_all(&root).unwrap(), bytes);
                }
                assert!(!store.is_being_written(&root));
                assert_eq!(
                    std::fs::read_dir(store.staging_dir())
                        .map(|entries| entries.count())
                        .unwrap_or(0),
                    0
                );
            }
        }
    }

    #[test]
    fn native_failed_metadata_commit_releases_resources_without_claiming_complete() {
        let (_dir, store) = crate::testutil::store();
        store.conn().execute_batch("CREATE TRIGGER reject_ingest BEFORE INSERT ON blobs BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        let bytes = data(32769);
        let root = Hash::from_slice(blake3::hash(&bytes).as_bytes()).unwrap();
        assert!(ingest(&store, Input::Bytes(&bytes), 0).is_err());
        assert!(store.blob(&root).unwrap().is_none());
        assert!(!store.is_being_written(&root));
        assert_eq!(std::fs::read_dir(store.staging_dir()).unwrap().count(), 0);
        assert!(store.conn().is_autocommit());
        // Already-published names remain, never unlinked by temporary cleanup.
        assert_eq!(std::fs::read(store.blob_path(&root)).unwrap(), bytes);
    }

    #[test]
    fn native_deferred_commit_failure_rolls_back_metadata_without_unlinking_published_targets() {
        let (_dir, store) = crate::testutil::store();
        store
            .conn()
            .execute_batch(
                "PRAGMA foreign_keys = ON;
             CREATE TABLE ingest_parent(id INTEGER PRIMARY KEY);
             CREATE TABLE ingest_deferred(parent INTEGER REFERENCES ingest_parent(id)
                DEFERRABLE INITIALLY DEFERRED);
             CREATE TRIGGER defer_ingest_failure AFTER INSERT ON blobs
                BEGIN INSERT INTO ingest_deferred VALUES (1); END;",
            )
            .unwrap();
        let bytes = data(32769);
        let root = Hash::from_slice(blake3::hash(&bytes).as_bytes()).unwrap();
        let failure = ingest(&store, Input::Bytes(&bytes), 0).unwrap_err();
        assert!(failure.to_string().contains("FOREIGN KEY"), "{failure}");
        assert!(store.conn().is_autocommit());
        assert!(store.blob(&root).unwrap().is_none());
        assert_eq!(
            store
                .conn()
                .query_row("SELECT count(*) FROM ingest_deferred", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(!store.is_being_written(&root));
        assert!(store.active_temporaries().is_empty());
        assert_eq!(std::fs::read_dir(store.staging_dir()).unwrap().count(), 0);
        assert_eq!(std::fs::read(store.blob_path(&root)).unwrap(), bytes);
        assert!(store.outboard_path(&root).exists());
    }
}
