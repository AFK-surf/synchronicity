//! Deterministic native-ingestion publication/GC ordering across Store opens.
use std::sync::mpsc::{self, Receiver, SyncSender};

use synch_verified::{
    cas,
    host::{self, TemporaryFiles},
};

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

struct PublicationGate<'a> {
    files: Files<'a>,
    published: SyncSender<()>,
    resume: Receiver<()>,
    replacements: usize,
}
impl TemporaryFiles for PublicationGate<'_> {
    type Error = StoreError;
    fn create_temporary(&mut self, space: &str) -> Result<u64> {
        self.files.create_temporary(space)
    }
    fn flush(&mut self, handle: u64) -> Result<()> {
        self.files.flush(handle)
    }
    fn replace(&mut self, handle: u64, space: &str, key: &[u8]) -> Result<()> {
        self.files.replace(handle, space, key)?;
        self.replacements += 1;
        if self.replacements == 1 {
            assert_eq!(space, "cas_payload");
            self.published
                .send(())
                .map_err(|_| StoreError::invalid("publication observer dropped"))?;
            self.resume
                .recv()
                .map_err(|_| StoreError::invalid("publication gate dropped"))?;
        } else {
            assert_eq!(self.replacements, 2);
            assert_eq!(space, "cas_outboard");
        }
        Ok(())
    }
    fn discard(&mut self, handle: u64) -> Result<()> {
        self.files.discard(handle)
    }
    fn sync_parent(&mut self, space: &str, key: &[u8]) -> Result<host::DirectorySync> {
        self.files.sync_parent(space, key)
    }
}

#[test]
fn whole_native_ingestion_holds_gc_lease_across_both_file_publications() {
    let directory = tempfile::tempdir().unwrap();
    let writer = Store::open(directory.path()).unwrap();
    let collector = Store::open(directory.path()).unwrap();
    let bytes: Vec<u8> = (0..100_003).map(|index| (index % 251) as u8).collect();
    let root = writer.ingest_bytes(&bytes, 0).unwrap();
    let old = collector.blob(&root).unwrap().unwrap();
    assert!(!old.pinned);
    assert_eq!(old.last_access, 0);

    let (published_tx, published_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    let expected = bytes.clone();
    let worker = std::thread::spawn(move || {
        // Rc-backed capability clones are made and retained exclusively on
        // this worker. Only channel messages cross the resource boundary.
        let mut files = Files::new(&writer, Input::Bytes(&bytes));
        let mut output = files.clone();
        let mut source = files.clone();
        let mut temporary = PublicationGate {
            files: files.clone(),
            published: published_tx,
            resume: resume_rx,
            replacements: 0,
        };
        let mut leases = Leases::new(&writer);
        let mut hashes = Hashes;
        let mut storage = crate::lean_storage::Session::new(&writer);
        let result = cas::ingest(
            &mut storage,
            cas::IngestResources {
                files: &mut files,
                writer: &mut output,
                hash: &mut hashes,
                temporary: &mut temporary,
                leases: &mut leases,
                source: &mut source,
            },
            cas::IngestInput::Bytes {
                size: bytes.len() as u64,
            },
            123,
            cas::IngestTier::Local,
            if cfg!(windows) {
                cas::DirectoryPolicy::AllowUnsupported
            } else {
                cas::DirectoryPolicy::RequireSync
            },
        )
        .unwrap();
        assert_eq!(temporary.replacements, 2);
        // Check before dropping the host adapters: explicit Lean cleanup,
        // rather than final adapter destruction, must have released these.
        assert!(!writer.is_being_written(&root));
        assert!(writer.active_temporaries().is_empty());
        assert_eq!(writer.read_all(&root).unwrap(), bytes);
        result
    });

    published_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap();
    // Observe the exact interval after first replacement but before the
    // second replacement/metadata transaction. Do not assert until the gate
    // is released, so a failed observation cannot strand the worker.
    let leased = collector.is_being_written(&root);
    let during = collector.blob(&root);
    let collected = collector.delete_blob_if_collectable(&root, i64::MAX);
    let orphans = collector.gc_orphans(i64::MAX);
    let staging = collector.gc_staging(i64::MAX);
    let payload_survived = collector.blob_path(&root).exists();
    let outboard_survived = collector.outboard_path(&root).exists();
    let active_temporary_count = collector.active_temporaries().len();
    resume_tx.send(()).unwrap();
    let result = worker.join().unwrap();

    assert!(leased);
    assert_eq!(during.unwrap().unwrap(), old);
    assert!(
        !collected.unwrap(),
        "an old candidate must not erase in-flight publication"
    );
    assert_eq!(orphans.unwrap(), 0);
    assert_eq!(staging.unwrap(), 0);
    assert!(payload_survived && outboard_survived);
    assert_eq!(
        active_temporary_count, 1,
        "the unpublished outboard remains protected"
    );
    assert_eq!(result.root.as_slice(), root.as_bytes());
    assert_eq!(result.size, expected.len() as u64);
    let committed = collector.blob(&root).unwrap().unwrap();
    assert!(committed.complete && committed.durable);
    assert_eq!(committed.size, expected.len() as u64);
    assert_eq!(collector.read_all(&root).unwrap(), expected);
    assert!(!collector.is_being_written(&root));
    assert!(collector.active_temporaries().is_empty());
    assert!(
        collector
            .delete_blob_if_collectable(&root, i64::MAX)
            .unwrap(),
        "the lease must be gone after whole-operation success"
    );
    assert!(!collector.blob_path(&root).exists());
    assert!(!collector.outboard_path(&root).exists());
}
