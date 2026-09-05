//! Raw file resources and completed local-read diagnostics. All read/repair
//! decisions are executed by the Lean domain program.

use std::{collections::BTreeMap, fs::File};

use bao_tree::io::sync::ReadAt;
use synch_core::Hash;
use synch_verified::{cas, host};

use crate::{Result, Store, StoreError};

struct Files<'a> {
    store: &'a Store,
    opened: BTreeMap<u64, File>,
    next: u64,
}

impl<'a> Files<'a> {
    fn new(store: &'a Store) -> Self {
        Self {
            store,
            opened: BTreeMap::new(),
            next: 1,
        }
    }
}

fn io_failure(error: std::io::Error) -> host::FileFailure<StoreError> {
    let kind = match error.kind() {
        std::io::ErrorKind::NotFound => host::FileFailureKind::Missing,
        std::io::ErrorKind::UnexpectedEof => host::FileFailureKind::ShortRead,
        _ => host::FileFailureKind::Other,
    };
    host::FileFailure {
        error: error.into(),
        kind,
    }
}

fn file_protocol(message: &str) -> host::FileFailure<StoreError> {
    host::FileFailure {
        error: StoreError::invalid(message),
        kind: host::FileFailureKind::Other,
    }
}

impl host::FileIO for Files<'_> {
    type Error = StoreError;

    fn open(
        &mut self,
        space: &str,
        key: &[u8],
    ) -> std::result::Result<u64, host::FileFailure<Self::Error>> {
        if space != "cas_payload" {
            return Err(file_protocol("unsupported file namespace"));
        }
        let root = Hash::from_slice(key).map_err(|_| file_protocol("invalid file key"))?;
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| file_protocol("file handle exhaustion"))?;
        let file = File::open(self.store.blob_path(&root)).map_err(io_failure)?;
        let handle = self.next;
        self.next = next;
        self.opened.insert(handle, file);
        Ok(handle)
    }

    fn read_at(
        &mut self,
        handle: u64,
        offset: u64,
        count: u64,
    ) -> std::result::Result<Vec<u8>, host::FileFailure<Self::Error>> {
        let file = self
            .opened
            .get(&handle)
            .ok_or_else(|| file_protocol("unknown file handle"))?;
        let count =
            usize::try_from(count).map_err(|_| file_protocol("file read exceeds address space"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(count)
            .map_err(|_| file_protocol("file read allocation failed"))?;
        bytes.resize(count, 0);
        file.read_exact_at(offset, &mut bytes).map_err(io_failure)?;
        Ok(bytes)
    }

    fn close(&mut self, handle: u64) -> Result<()> {
        self.opened
            .remove(&handle)
            .ok_or_else(|| StoreError::invalid("unknown file handle"))?;
        // File drop has the same non-flushing close semantics as the previous
        // read path. Dropping this registry also releases abandoned handles.
        Ok(())
    }
}

struct Clock;
impl host::Clock for Clock {
    type Error = StoreError;
    fn now_ns(&mut self) -> Result<i64> {
        Ok(synch_core::now_ns())
    }
}

fn error(root: &Hash, error: cas::ReadError<StoreError>) -> StoreError {
    use cas::{OperationError, ReadDomainError as Domain, ReadError};
    match error {
        ReadError::Operation(OperationError::Host(error)) => error,
        ReadError::Operation(_) => StoreError::invalid("invalid native read-operation protocol"),
        ReadError::Domain(Domain::MissingBlob) => StoreError::MissingBlob(*root),
        ReadError::Domain(Domain::Range { start, stop, size }) => StoreError::RangeOutOfBounds {
            start,
            end: stop,
            size,
        },
        ReadError::Domain(Domain::Unavailable) => StoreError::Verification {
            root: *root,
            reason: "requested range is not fully present locally".into(),
        },
        ReadError::Domain(Domain::ShortInline) => {
            StoreError::column("blobs.inline", "payload shorter than the requested range")
        }
        ReadError::Domain(Domain::Malformed) => {
            StoreError::Decode("invalid local blob metadata".into())
        }
        ReadError::Domain(Domain::ColumnType {
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
        ReadError::Domain(Domain::Column { column, reason }) => match column.as_str() {
            "blobs.root" => StoreError::column("blobs.root", reason),
            _ => StoreError::invalid("unknown native read error column"),
        },
    }
}

pub(crate) fn read(store: &Store, root: &Hash, request: cas::ReadRequest) -> Result<Vec<u8>> {
    let mut storage = crate::lean_storage::Session::new(store);
    let mut files = Files::new(store);
    // LEAN-MODEL: cas-local-read-operation (CasReadProgramProofs.read_observes_metadata)
    cas::read(
        &mut storage,
        &mut files,
        &mut Clock,
        root.as_bytes(),
        request,
    )
    .map_err(|failure| error(root, failure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        testutil::{data, store},
        PinHolder,
    };
    use host::FileIO;
    use rusqlite::params;

    struct ObservedFiles<'a> {
        inner: Files<'a>,
        root: Hash,
        reads: Vec<(u64, u64)>,
        opens: usize,
        closes: usize,
    }
    impl host::FileIO for ObservedFiles<'_> {
        type Error = StoreError;
        fn open(
            &mut self,
            space: &str,
            key: &[u8],
        ) -> std::result::Result<u64, host::FileFailure<Self::Error>> {
            // This would trip the reentry guard (or deadlock) if the snapshot
            // connection had escaped its statement into filesystem work.
            assert!(self.inner.store.blob(&self.root).unwrap().is_some());
            self.opens += 1;
            self.inner.open(space, key)
        }
        fn read_at(
            &mut self,
            handle: u64,
            offset: u64,
            count: u64,
        ) -> std::result::Result<Vec<u8>, host::FileFailure<Self::Error>> {
            assert!(self.inner.store.blob(&self.root).unwrap().is_some());
            self.reads.push((offset, count));
            self.inner.read_at(handle, offset, count)
        }
        fn close(&mut self, handle: u64) -> Result<()> {
            self.closes += 1;
            self.inner.close(handle)
        }
    }

    #[test]
    fn large_read_uses_one_file_bounded_chunks_and_no_connection_during_io() {
        let (_dir, store) = store();
        let payload = data(1024 * 1024 + 17);
        let root = store.ingest_bytes(&payload, 0).unwrap();
        let mut files = ObservedFiles {
            inner: Files::new(&store),
            root,
            reads: vec![],
            opens: 0,
            closes: 0,
        };
        let mut storage = crate::lean_storage::Session::new(&store);
        assert_eq!(
            cas::read(
                &mut storage,
                &mut files,
                &mut Clock,
                root.as_bytes(),
                cas::ReadRequest::All
            )
            .unwrap(),
            payload
        );
        assert_eq!((files.opens, files.closes), (1, 1));
        assert_eq!(files.reads.len(), 17);
        assert!(files.reads.iter().all(|(_, count)| *count <= 65536));
        assert_eq!(files.reads.last(), Some(&(1024 * 1024, 17)));
        assert!(files.inner.opened.is_empty());
    }

    #[test]
    fn positioned_reads_retain_open_file_identity() {
        let (dir, store) = store();
        let payload = data(100_000);
        let root = store.ingest_bytes(&payload, 0).unwrap();
        let mut files = Files::new(&store);
        let handle = files.open("cas_payload", root.as_bytes()).unwrap();
        std::fs::rename(store.blob_path(&root), dir.path().join("original-payload")).unwrap();
        std::fs::write(store.blob_path(&root), vec![0; payload.len()]).unwrap();
        assert_eq!(files.read_at(handle, 100, 50).unwrap(), payload[100..150]);
        files.close(handle).unwrap();
        assert!(files.read_at(handle, 0, 1).is_err());
        assert!(files.close(handle).is_err());
    }

    #[test]
    fn truncated_payload_repairs_raw_roles_preserves_existing_wants_and_operator() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(&data(100_000), 0).unwrap();
        let source = PinHolder::Source("media".into());
        let mixed = PinHolder::Other("RePlIcA:".into());
        for holder in [&source, &mixed, &PinHolder::Operator] {
            assert!(store.pin(&root, holder, 1).unwrap());
        }
        store.conn().execute(
            "INSERT INTO content_want (root, holder, size, prev, first_wanted) VALUES (?1, ?2, 999, NULL, -7)",
            params![root.as_bytes().as_slice(), source.render()],
        ).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(store.blob_path(&root))
            .unwrap()
            .set_len(1)
            .unwrap();
        let failure = store.read_range(&root, 2, 10).unwrap_err();
        assert!(
            matches!(failure, StoreError::Io(ref error) if error.kind() == std::io::ErrorKind::UnexpectedEof)
        );
        let row = store.blob(&root).unwrap().unwrap();
        assert!(!row.complete && !row.durable && row.bitmap.is_none() && row.inline.is_none());
        let pins = store.pins_for(&root).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].holder, PinHolder::Operator);
        let old: (i64, i64) = store
            .conn()
            .query_row(
                "SELECT size, first_wanted FROM content_want WHERE root = ?1 AND holder = ?2",
                params![root.as_bytes().as_slice(), source.render()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(old, (999, -7));
        let repaired: i64 = store
            .conn()
            .query_row(
                "SELECT size FROM content_want WHERE root = ?1 AND holder = ?2",
                params![root.as_bytes().as_slice(), mixed.render()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(repaired, 100_000);
    }

    #[test]
    fn repair_failure_overrides_io_error_and_rolls_back_invalidation() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(&data(100_000), 0).unwrap();
        assert!(store
            .pin(&root, &PinHolder::Source("media".into()), 0)
            .unwrap());
        std::fs::remove_file(store.blob_path(&root)).unwrap();
        store
            .conn()
            .execute_batch(
                "CREATE TEMP TRIGGER deny_repair BEFORE INSERT ON content_want
             BEGIN SELECT RAISE(ABORT, 'repair denied'); END;",
            )
            .unwrap();
        let failure = store.read_all(&root).unwrap_err();
        assert!(failure.to_string().contains("repair denied"));
        let row = store.blob(&root).unwrap().unwrap();
        assert!(row.complete && row.durable);
        assert_eq!(store.pins_for(&root).unwrap().len(), 1);
        assert!(store.conn().is_autocommit());
    }

    #[test]
    fn short_inline_is_an_error_and_partial_bitmap_uses_lean_coverage() {
        let (_dir, store) = store();
        let root = store.ingest_bytes(&data(100_000), 0).unwrap();
        store
            .conn()
            .execute(
                "UPDATE blobs SET inline = x'01' WHERE root = ?1",
                [root.as_bytes().as_slice()],
            )
            .unwrap();
        assert!(matches!(
            store.read_range(&root, 0, 2),
            Err(StoreError::Column {
                column: "blobs.inline",
                ..
            })
        ));
        store
            .conn()
            .execute(
                "UPDATE blobs SET inline = NULL, complete = 0, bitmap = ?2 WHERE root = ?1",
                params![
                    root.as_bytes().as_slice(),
                    vec![129u8, 0, 128, 0, 129, 0, 255]
                ],
            )
            .unwrap();
        assert_eq!(
            store.read_range(&root, 10, 20).unwrap(),
            data(100_000)[10..30]
        );
        assert!(matches!(
            store.read_range(&root, 16384, 1),
            Err(StoreError::Verification { .. })
        ));
        store
            .conn()
            .execute(
                "UPDATE blobs SET bitmap = x'ff' WHERE root = ?1",
                [root.as_bytes().as_slice()],
            )
            .unwrap();
        assert!(matches!(
            store.read_range(&root, 0, 1),
            Err(StoreError::Verification { .. })
        ));
        assert_eq!(store.read_range(&root, 0, 0).unwrap(), Vec::<u8>::new());
    }

    // Run each case in a fresh process under a memory cap for comparable peak
    // RSS. Seed a trusted-local-read fixture without retaining a second full
    // payload or including ingestion/Bao allocations in the measurement.
    fn large_read_fixture() -> (tempfile::TempDir, Store, Hash) {
        use std::io::Write;
        let (dir, store) = store();
        let root = store.ingest_bytes(&data(100_000), 0).unwrap();
        let mut file = File::create(store.blob_path(&root)).unwrap();
        for _ in 0..1024 {
            file.write_all(&[37; 65536]).unwrap();
        }
        store
            .conn()
            .execute(
                "UPDATE blobs SET size = ?2 WHERE root = ?1",
                params![root.as_bytes().as_slice(), 64 * 1024 * 1024],
            )
            .unwrap();
        (dir, store, root)
    }

    #[test]
    #[ignore = "manual isolated peak-memory and throughput measurement"]
    fn large_native_read_memory_probe() {
        let (_dir, store, root) = large_read_fixture();
        let started = std::time::Instant::now();
        let bytes = store.read_all(&root).unwrap();
        eprintln!("native read: {:?}", started.elapsed());
        assert_eq!(bytes.len(), 64 * 1024 * 1024);
        assert!(bytes.iter().all(|byte| *byte == 37));
    }

    #[test]
    #[ignore = "manual isolated raw-file allocation baseline, not a domain implementation"]
    fn large_raw_file_memory_probe() {
        let (_dir, store, root) = large_read_fixture();
        let started = std::time::Instant::now();
        let mut bytes = vec![0; 64 * 1024 * 1024];
        File::open(store.blob_path(&root))
            .unwrap()
            .read_exact_at(0, &mut bytes)
            .unwrap();
        eprintln!("raw file read: {:?}", started.elapsed());
        assert!(bytes.iter().all(|byte| *byte == 37));
    }
}
