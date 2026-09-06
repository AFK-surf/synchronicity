//! Whole native Lean ingestion integration, staged until production cutover
//! gates finish. Rust binds raw services and maps terminal diagnostics only.
#![cfg_attr(not(test), allow(dead_code))]

use synch_core::Hash;
use synch_verified::{cas, host};

use crate::{
    lean_resources::{Files, Input, Leases},
    Result, Store, StoreError,
};

struct Hashes;
impl host::Blake3 for Hashes {
    type Error = StoreError;
    fn chunk(&mut self, counter: u64, root: bool, bytes: &[u8]) -> Result<Vec<u8>> {
        crate::lean_hash::chunk(counter, root, bytes).map(|digest| digest.to_vec())
    }
    fn parent(&mut self, root: bool, left: &[u8], right: &[u8]) -> Result<Vec<u8>> {
        crate::lean_hash::parent(root, left, right).map(|digest| digest.to_vec())
    }
}

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
        }) => {
            let kind = match actual {
                cas::CellType::Null => rusqlite::types::Type::Null,
                cas::CellType::Integer => rusqlite::types::Type::Integer,
                cas::CellType::Real => rusqlite::types::Type::Real,
                cas::CellType::Text => rusqlite::types::Type::Text,
                cas::CellType::Blob => rusqlite::types::Type::Blob,
            };
            match usize::try_from(index) {
                Ok(index) => rusqlite::Error::InvalidColumnType(index, column, kind).into(),
                Err(_) => StoreError::invalid("native column index exceeds address space"),
            }
        }
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

pub(crate) fn ingest(store: &Store, input: Input<'_>, now: i64) -> Result<(Hash, u64)> {
    let kind = match input {
        Input::Bytes(bytes) => cas::IngestInput::Bytes {
            size: u64::try_from(bytes.len())
                .map_err(|_| StoreError::invalid("input exceeds unsigned size domain"))?,
        },
        Input::File(_) => cas::IngestInput::File,
    };
    let mut storage = crate::lean_storage::Session::new(store);
    let mut files = Files::new(store, input);
    let mut writer = files.clone();
    let mut temporary = files.clone();
    let mut source = files.clone();
    let mut hashes = Hashes;
    let mut leases = Leases::new(store);
    let result = cas::ingest(
        &mut storage,
        cas::IngestResources {
            files: &mut files,
            writer: &mut writer,
            hash: &mut hashes,
            temporary: &mut temporary,
            leases: &mut leases,
            source: &mut source,
        },
        kind,
        now,
        if store.complete_is_durable() {
            cas::IngestTier::Local
        } else {
            cas::IngestTier::Cache
        },
        if cfg!(windows) {
            cas::DirectoryPolicy::AllowUnsupported
        } else {
            cas::DirectoryPolicy::RequireSync
        },
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
        let mut writer = files.clone();
        let mut temporary = files.clone();
        let mut source = ChangingSource {
            inner: files.clone(),
            path,
            after_stat,
            before_freeze,
            stats: 0,
            freezes: 0,
        };
        let mut hashes = Hashes;
        let mut leases = Leases::new(store);
        let result = cas::ingest(
            &mut storage,
            cas::IngestResources {
                files: &mut files,
                writer: &mut writer,
                hash: &mut hashes,
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
        assert_eq!(&result.root, blake3::hash(expected).as_bytes());
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
        let (dir, store) = crate::testutil::store();
        let path = dir.path().join("growing");
        std::fs::write(&path, b"initial").unwrap();
        let captured = data(32769);
        let replaced = b"different stream after capture";
        let (result, freezes) = ingest_changing_file(&store, &path, &captured, Some(replaced));
        assert_eq!(freezes, 1);
        assert_eq!(std::fs::read(&path).unwrap(), replaced);
        assert_captured(&store, result.unwrap(), &captured);
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
    fn native_ingestion_matches_standard_roots_payloads_and_bao_layouts() {
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
                    let tree = Store::tree(size as u64);
                    let mut expected = vec![0; tree.outboard_size() as usize];
                    crate::cas::compute_outboard(&bytes[..], tree, &mut expected).unwrap();
                    assert_eq!(std::fs::read(store.outboard_path(&root)).unwrap(), expected);
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
}
