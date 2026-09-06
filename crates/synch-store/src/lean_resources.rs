//! Raw invocation-owned resources for mandatory Lean ingestion. No hash-tree,
//! commit or publication policy lives here.

use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    rc::Rc,
};

use bao_tree::io::sync::{ReadAt, WriteAt};
use synch_core::Hash;
use synch_verified::host::{self, ByteWriter, FileIO, Lease, SourceIO, TemporaryFiles};

use crate::{db::WriteLease, Result, Store, StoreError};

#[derive(Debug, Clone, Copy)]
pub(crate) enum Input<'a> {
    Bytes(&'a [u8]),
    File(&'a Path),
}

#[derive(Debug)]
struct Temporary {
    path: PathBuf,
    file: Option<File>,
}

#[derive(Debug)]
enum Handle<'a> {
    Temporary(Temporary),
    File(SourceFile),
    Borrowed(&'a [u8]),
    Frozen(Vec<u8>),
}

#[derive(Debug)]
struct SourceFile {
    file: File,
    /// Position advanced only by sequential SourceIO reads. Positioned FileIO
    /// reads do not change the OS cursor or this accounting.
    cursor: u64,
}

#[derive(Debug)]
struct Pool<'a> {
    store: &'a Store,
    input: Input<'a>,
    next: u64,
    handles: BTreeMap<u64, Handle<'a>>,
}

impl<'a> Pool<'a> {
    fn insert(&mut self, value: Handle<'a>) -> Result<u64> {
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| StoreError::invalid("file handle identifiers exhausted"))?;
        let handle = self.next;
        self.next = next;
        self.handles.insert(handle, value);
        Ok(handle)
    }

    fn temporary(&mut self, handle: u64) -> Result<&mut Temporary> {
        match self.handles.get_mut(&handle) {
            Some(Handle::Temporary(temporary)) => Ok(temporary),
            _ => Err(StoreError::invalid("unknown temporary file handle")),
        }
    }

    fn create_using(&mut self, mut name: impl FnMut() -> String) -> Result<u64> {
        // Reserve a handle before any filesystem side effects.
        self.next
            .checked_add(1)
            .ok_or_else(|| StoreError::invalid("file handle identifiers exhausted"))?;
        std::fs::create_dir_all(self.store.staging_dir())?;
        let directory = self.store.staging_dir().canonicalize()?;
        let mut active = self.store.active_temporaries();
        for _ in 0..128 {
            let path = directory.join(name());
            if active.contains(&path) {
                continue;
            }
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    active.insert(path.clone());
                    // Handle exhaustion was checked while holding exclusive
                    // access to this invocation's allocator; insertion cannot fail.
                    let handle = self.next;
                    self.next += 1;
                    self.handles.insert(
                        handle,
                        Handle::Temporary(Temporary {
                            path,
                            file: Some(file),
                        }),
                    );
                    return Ok(handle);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary name collisions exhausted",
        )
        .into())
    }

    fn discard(&mut self, handle: u64) -> Result<()> {
        let Some(Handle::Temporary(temporary)) = self.handles.get_mut(&handle) else {
            if self.handles.contains_key(&handle) {
                return Err(StoreError::invalid(
                    "discard requires a temporary file handle",
                ));
            }
            // Consumed handles, including successful replacements, are already
            // discarded. In particular, this never targets a published name.
            return Ok(());
        };
        drop(temporary.file.take());
        let mut active = self.store.active_temporaries();
        match std::fs::remove_file(&temporary.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        active.remove(&temporary.path);
        self.handles.remove(&handle);
        Ok(())
    }

    fn read_some(&self, handle: u64, offset: u64, count: u64) -> Result<Vec<u8>> {
        if count > 65536 {
            return Err(StoreError::invalid(
                "raw read exceeds bounded transfer size",
            ));
        }
        let source = self
            .handles
            .get(&handle)
            .ok_or_else(|| StoreError::invalid("unknown file handle"))?;
        match source {
            Handle::Borrowed(bytes) => slice_read(bytes, offset, count),
            Handle::Frozen(bytes) => slice_read(bytes, offset, count),
            Handle::File(source) => file_read(&source.file, offset, count),
            Handle::Temporary(temporary) => file_read(
                temporary
                    .file
                    .as_ref()
                    .ok_or_else(|| StoreError::invalid("temporary file is closed"))?,
                offset,
                count,
            ),
        }
    }

    fn source_read_some(&mut self, handle: u64, offset: u64, count: u64) -> Result<Vec<u8>> {
        if count > 65536 {
            return Err(StoreError::invalid(
                "raw read exceeds bounded transfer size",
            ));
        }
        if let Some(Handle::File(source)) = self.handles.get_mut(&handle) {
            if offset == source.cursor {
                // A sequential read preserves pipes and other non-seekable
                // sources accepted by read-to-EOF. Non-sequential requests
                // retain ordinary positioned-read semantics below.
                let mut bytes = vec![0; count as usize];
                let read = loop {
                    match source.file.read(&mut bytes) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        result => break result?,
                    }
                };
                source.cursor = source
                    .cursor
                    .checked_add(read as u64)
                    .ok_or_else(|| StoreError::invalid("source cursor overflow"))?;
                bytes.truncate(read);
                return Ok(bytes);
            }
        }
        self.read_some(handle, offset, count)
    }
}

impl Drop for Pool<'_> {
    fn drop(&mut self) {
        // Retry cleanup after a failed explicit discard. If the filesystem
        // still refuses unlink, unregister the abandoned name so a later GC
        // can retry; never leave an immortal live-registration tombstone.
        let mut active = self.store.active_temporaries();
        for resource in self.handles.values_mut() {
            if let Handle::Temporary(temporary) = resource {
                drop(temporary.file.take());
                let _ = std::fs::remove_file(&temporary.path);
                active.remove(&temporary.path);
            }
        }
    }
}

/// Clones share one invocation's allocator and ownership registry. Separate
/// trait-object borrows can use clones without aliasing mutable references or
/// extending lifetimes; the final clone's Drop releases all resources.
#[derive(Debug, Clone)]
pub(crate) struct Files<'a>(Rc<RefCell<Pool<'a>>>);

impl<'a> Files<'a> {
    pub(crate) fn new(store: &'a Store, input: Input<'a>) -> Self {
        Self(Rc::new(RefCell::new(Pool {
            store,
            input,
            next: 1,
            handles: BTreeMap::new(),
        })))
    }
}

fn target(store: &Store, space: &str, key: &[u8]) -> Result<PathBuf> {
    let root = Hash::from_slice(key).map_err(|error| StoreError::invalid(error.to_string()))?;
    match space {
        "cas_payload" => Ok(store.blob_path(&root)),
        "cas_outboard" => Ok(store.outboard_path(&root)),
        _ => Err(StoreError::invalid("unsupported file namespace")),
    }
}

impl TemporaryFiles for Files<'_> {
    type Error = StoreError;

    fn create_temporary(&mut self, space: &str) -> Result<u64> {
        if !matches!(space, "cas_payload" | "cas_outboard") {
            return Err(StoreError::invalid("unsupported temporary namespace"));
        }
        self.0
            .borrow_mut()
            .create_using(|| format!("{}.tmp", synch_core::fs::unique_suffix()))
    }

    fn flush(&mut self, handle: u64) -> Result<()> {
        self.0
            .borrow_mut()
            .temporary(handle)?
            .file
            .as_ref()
            .ok_or_else(|| StoreError::invalid("temporary file is closed"))?
            .sync_all()?;
        Ok(())
    }

    fn replace(&mut self, handle: u64, space: &str, key: &[u8]) -> Result<()> {
        let mut pool = self.0.borrow_mut();
        let destination = target(pool.store, space, key)?;
        let original = pool.temporary(handle)?.path.clone();
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Failure retains temporary ownership for explicit cleanup or Drop.
        synch_core::fs::replace_file(&original, &destination)?;
        pool.store.active_temporaries().remove(&original);
        pool.handles.remove(&handle);
        Ok(())
    }

    fn discard(&mut self, handle: u64) -> Result<()> {
        self.0.borrow_mut().discard(handle)
    }

    fn sync_parent(&mut self, space: &str, key: &[u8]) -> Result<host::DirectorySync> {
        let pool = self.0.borrow();
        let path = target(pool.store, space, key)?;
        #[cfg(windows)]
        {
            let _ = path;
            Ok(host::DirectorySync::Unsupported)
        }
        #[cfg(not(windows))]
        {
            let directory = path
                .parent()
                .ok_or_else(|| StoreError::invalid("file has no parent"))?;
            // The shard may have been created by replace. Flushing only its
            // contents does not persist the new shard entry in the CAS root.
            // Include the namespace ancestors down to the pre-existing store
            // directory; durability of that configured directory is a setup
            // precondition, not an ingestion decision.
            let cas_directory = pool.store.cas_dir();
            let mut status = host::DirectorySync::Synced;
            for directory in [directory, cas_directory.as_path(), pool.store.data_dir()] {
                match File::open(directory)?.sync_all() {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                        status = host::DirectorySync::Unsupported;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(status)
        }
    }
}

impl ByteWriter for Files<'_> {
    type Error = StoreError;
    fn write_at(&mut self, handle: u64, offset: u64, bytes: &[u8]) -> Result<()> {
        self.0
            .borrow_mut()
            .temporary(handle)?
            .file
            .as_mut()
            .ok_or_else(|| StoreError::invalid("temporary file is closed"))?
            .write_all_at(offset, bytes)?;
        Ok(())
    }
}

fn input_key(space: &str, key: &[u8]) -> Result<()> {
    if space == "input" && key.is_empty() {
        Ok(())
    } else {
        Err(StoreError::invalid("unsupported invocation input"))
    }
}

fn io_failure(error: StoreError) -> host::FileFailure<StoreError> {
    let kind = match &error {
        StoreError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            host::FileFailureKind::Missing
        }
        StoreError::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            host::FileFailureKind::ShortRead
        }
        _ => host::FileFailureKind::Other,
    };
    host::FileFailure { error, kind }
}

impl FileIO for Files<'_> {
    type Error = StoreError;

    fn open(
        &mut self,
        space: &str,
        key: &[u8],
    ) -> std::result::Result<u64, host::FileFailure<StoreError>> {
        let open = || -> Result<u64> {
            input_key(space, key)?;
            let mut pool = self.0.borrow_mut();
            let value = match pool.input {
                Input::Bytes(bytes) => Handle::Borrowed(bytes),
                Input::File(path) => Handle::File(SourceFile {
                    file: File::open(path)?,
                    cursor: 0,
                }),
            };
            pool.insert(value)
        };
        open().map_err(io_failure)
    }

    fn read_at(
        &mut self,
        handle: u64,
        offset: u64,
        count: u64,
    ) -> std::result::Result<Vec<u8>, host::FileFailure<StoreError>> {
        let read = || -> Result<Vec<u8>> {
            let mut bytes = self.0.borrow().read_some(handle, offset, count)?;
            // read_some is allowed a short OS read before EOF. Complete it
            // mechanically; the Lean program still chooses ranges and recovery.
            while bytes.len() as u64 != count {
                let position = offset
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| StoreError::invalid("file read offset overflow"))?;
                let more =
                    self.0
                        .borrow()
                        .read_some(handle, position, count - bytes.len() as u64)?;
                if more.is_empty() {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                }
                bytes.extend_from_slice(&more);
            }
            Ok(bytes)
        };
        read().map_err(io_failure)
    }

    fn close(&mut self, handle: u64) -> Result<()> {
        let mut pool = self.0.borrow_mut();
        if let Some(Handle::Temporary(temporary)) = pool.handles.get_mut(&handle) {
            // Close consumes file access, not ownership of the unpublished
            // pathname. Discard/Drop must still reclaim that name afterward.
            drop(
                temporary
                    .file
                    .take()
                    .ok_or_else(|| StoreError::invalid("temporary file is closed"))?,
            );
            return Ok(());
        }
        pool.handles
            .remove(&handle)
            .ok_or_else(|| StoreError::invalid("unknown file handle"))?;
        Ok(())
    }
}

fn slice_read(bytes: &[u8], offset: u64, count: u64) -> Result<Vec<u8>> {
    let offset = usize::try_from(offset)
        .map_err(|_| StoreError::invalid("input offset exceeds address space"))?;
    let start = offset.min(bytes.len());
    let count = usize::try_from(count)
        .map_err(|_| StoreError::invalid("input count exceeds address space"))?;
    let end = start.saturating_add(count).min(bytes.len());
    Ok(bytes[start..end].to_vec())
}

fn file_read(file: &File, offset: u64, count: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![0; count as usize];
    let read = loop {
        match file.read_at(offset, &mut bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => break result?,
        }
    };
    bytes.truncate(read);
    Ok(bytes)
}

impl SourceIO for Files<'_> {
    type Error = StoreError;
    fn stat(&mut self, space: &str, key: &[u8]) -> Result<u64> {
        input_key(space, key)?;
        match self.0.borrow().input {
            Input::Bytes(bytes) => Ok(bytes.len() as u64),
            Input::File(path) => Ok(std::fs::metadata(path)?.len()),
        }
    }
    fn read_some(&mut self, handle: u64, offset: u64, count: u64) -> Result<Vec<u8>> {
        self.0.borrow_mut().source_read_some(handle, offset, count)
    }
    fn freeze(&mut self, bytes: &[u8]) -> Result<u64> {
        let mut owned = Vec::new();
        owned
            .try_reserve(bytes.len())
            .map_err(|_| StoreError::invalid("frozen input allocation failed"))?;
        owned.extend_from_slice(bytes);
        self.0.borrow_mut().insert(Handle::Frozen(owned))
    }
}

#[derive(Debug)]
pub(crate) struct Leases<'a> {
    store: &'a Store,
    next: u64,
    active: BTreeMap<u64, WriteLease<'a>>,
}

impl<'a> Leases<'a> {
    pub(crate) fn new(store: &'a Store) -> Self {
        Self {
            store,
            next: 1,
            active: BTreeMap::new(),
        }
    }
}

impl Lease for Leases<'_> {
    type Error = StoreError;
    fn acquire(&mut self, space: &str, key: &[u8]) -> Result<u64> {
        if space != "cas_writers" {
            return Err(StoreError::invalid("unsupported lease namespace"));
        }
        let root = Hash::from_slice(key).map_err(|error| StoreError::invalid(error.to_string()))?;
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| StoreError::invalid("lease identifiers exhausted"))?;
        let token = self.next;
        let lease = self.store.lease_write(&root);
        self.next = next;
        self.active.insert(token, lease);
        Ok(token)
    }
    fn release(&mut self, token: u64) -> Result<()> {
        self.active
            .remove(&token)
            .ok_or_else(|| StoreError::invalid("unknown lease token"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::store;

    fn temporary_path(files: &Files<'_>, handle: u64) -> PathBuf {
        let pool = files.0.borrow();
        match pool.handles.get(&handle).unwrap() {
            Handle::Temporary(temporary) => temporary.path.clone(),
            _ => panic!("expected temporary resource"),
        }
    }

    #[test]
    fn exclusive_creation_never_truncates_a_colliding_name() {
        let (_dir, store) = store();
        std::fs::create_dir_all(store.staging_dir()).unwrap();
        let occupied = store.staging_dir().join("collision.tmp");
        std::fs::write(&occupied, b"existing bytes").unwrap();
        let files = Files::new(&store, Input::Bytes(&[]));
        let mut attempts = 0;
        let handle = files
            .0
            .borrow_mut()
            .create_using(|| {
                attempts += 1;
                if attempts == 1 {
                    "collision.tmp".into()
                } else {
                    "fresh.tmp".into()
                }
            })
            .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(std::fs::read(&occupied).unwrap(), b"existing bytes");
        assert!(temporary_path(&files, handle).ends_with("fresh.tmp"));
        assert!(files
            .0
            .borrow_mut()
            .create_using(|| "collision.tmp".into())
            .is_err());
        assert_eq!(std::fs::read(&occupied).unwrap(), b"existing bytes");
    }

    #[test]
    fn live_temporary_survives_gc_through_an_independent_store_alias() {
        let (dir, store) = store();
        let other = Store::open(dir.path().join(".")).unwrap();
        let mut files = Files::new(&store, Input::Bytes(&[]));
        let handle = files.create_temporary("cas_payload").unwrap();
        let path = temporary_path(&files, handle);
        files.write_at(handle, 0, b"live").unwrap();
        let stale = store.staging_dir().join("abandoned.tmp");
        std::fs::write(&stale, b"stale").unwrap();
        assert_eq!(other.gc_staging(i64::MAX).unwrap(), 1);
        assert!(path.exists());
        assert!(!stale.exists());
        files.discard(handle).unwrap();
        assert!(!path.exists());
        assert!(store.active_temporaries().is_empty());
    }

    #[test]
    fn final_pool_clone_cleans_abandoned_temporaries() {
        let (_dir, store) = store();
        let mut files = Files::new(&store, Input::Bytes(&[]));
        let handle = files.create_temporary("cas_outboard").unwrap();
        let path = temporary_path(&files, handle);
        let mut writer = files.clone();
        writer.write_at(handle, 0, b"bytes").unwrap();
        drop(files);
        assert!(path.exists());
        drop(writer);
        assert!(!path.exists());
        assert!(store.active_temporaries().is_empty());
    }

    #[test]
    fn replacement_failure_retains_cleanup_ownership() {
        let (_dir, store) = store();
        let root = Hash::new(b"cannot replace directory");
        std::fs::create_dir_all(store.blob_path(&root)).unwrap();
        let mut files = Files::new(&store, Input::Bytes(&[]));
        let handle = files.create_temporary("cas_payload").unwrap();
        let path = temporary_path(&files, handle);
        files.write_at(handle, 0, b"staged").unwrap();
        files.flush(handle).unwrap();
        assert!(files
            .replace(handle, "cas_payload", root.as_bytes())
            .is_err());
        assert!(path.exists());
        assert!(store.active_temporaries().contains(&path));
        files.discard(handle).unwrap();
        assert!(!path.exists());
        assert!(store.blob_path(&root).is_dir());
    }

    #[test]
    fn discard_after_replacement_cannot_remove_published_bytes() {
        let (_dir, store) = store();
        let root = Hash::new(b"published");
        let mut files = Files::new(&store, Input::Bytes(&[]));
        let handle = files.create_temporary("cas_payload").unwrap();
        let path = temporary_path(&files, handle);
        files.write_at(handle, 0, b"published").unwrap();
        files.flush(handle).unwrap();
        files
            .replace(handle, "cas_payload", root.as_bytes())
            .unwrap();
        assert!(!path.exists());
        assert!(store.active_temporaries().is_empty());
        files.discard(handle).unwrap();
        files.discard(handle).unwrap();
        assert!(files.flush(handle).is_err());
        drop(files);
        assert_eq!(std::fs::read(store.blob_path(&root)).unwrap(), b"published");
    }

    #[test]
    fn failed_discard_keeps_drop_cleanup_fallback() {
        let (_dir, store) = store();
        let mut files = Files::new(&store, Input::Bytes(&[]));
        let handle = files.create_temporary("cas_payload").unwrap();
        let path = temporary_path(&files, handle);
        // Force a portable unlink error without relying on permissions (the
        // suite may run as root). Restore a removable file before abandonment.
        drop(files.0.borrow_mut().temporary(handle).unwrap().file.take());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(files.discard(handle).is_err());
        assert!(store.active_temporaries().contains(&path));
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, b"retry cleanup").unwrap();
        drop(files);
        assert!(!path.exists());
        assert!(store.active_temporaries().is_empty());
    }

    #[test]
    fn raw_sync_status_does_not_swallow_real_errors() {
        let (_dir, store) = store();
        let mut files = Files::new(&store, Input::Bytes(&[]));
        let root = Hash::new(b"missing shard");
        assert!(files.flush(99).is_err());
        assert!(files.sync_parent("unknown", root.as_bytes()).is_err());
        #[cfg(not(windows))]
        assert!(files.sync_parent("cas_payload", root.as_bytes()).is_err());
        #[cfg(windows)]
        assert_eq!(
            files.sync_parent("cas_payload", root.as_bytes()).unwrap(),
            host::DirectorySync::Unsupported
        );
    }

    #[test]
    fn input_and_frozen_handles_share_allocator_but_not_mutability() {
        let (_dir, store) = store();
        let mut files = Files::new(&store, Input::Bytes(b"source"));
        let source = files.open("input", &[]).unwrap();
        let temporary = files.create_temporary("cas_payload").unwrap();
        let mut original = b"frozen".to_vec();
        let frozen = files.freeze(&original).unwrap();
        original.fill(0);
        assert_ne!(source, temporary);
        assert_ne!(temporary, frozen);
        assert_eq!(files.read_at(source, 1, 3).unwrap(), b"our");
        assert_eq!(files.read_at(frozen, 0, 6).unwrap(), b"frozen");
        assert!(files.read_at(frozen, 0, 7).is_err());
        assert!(files.read_some(source, 0, 65537).is_err());
        files.write_at(temporary, 0, b"staged").unwrap();
        assert_eq!(files.read_at(temporary, 0, 6).unwrap(), b"staged");
        assert!(files.write_at(frozen, 0, b"bad").is_err());
        files.close(temporary).unwrap();
        assert!(files.read_at(temporary, 0, 1).is_err());
        assert!(files.write_at(temporary, 0, b"bad").is_err());
        assert!(files.flush(temporary).is_err());
        assert!(files.close(temporary).is_err());
        assert_eq!(store.active_temporaries().len(), 1);
        files.discard(temporary).unwrap();
        assert!(store.active_temporaries().is_empty());
        files.close(source).unwrap();
        assert!(files.read_at(source, 0, 1).is_err());
        assert!(files.close(source).is_err());
    }

    #[test]
    fn raw_file_source_stat_and_read_some_observe_current_bytes() {
        let (dir, store) = store();
        let path = dir.path().join("input-file");
        std::fs::write(&path, b"a").unwrap();
        let mut files = Files::new(&store, Input::File(&path));
        assert_eq!(files.stat("input", &[]).unwrap(), 1);
        std::fs::write(&path, b"abc").unwrap();
        let source = files.open("input", &[]).unwrap();
        assert_eq!(files.read_some(source, 0, 8).unwrap(), b"abc");
        assert!(files.read_some(source, 3, 8).unwrap().is_empty());
        assert!(files.read_at(source, 0, 4).is_err());
        files.close(source).unwrap();
    }

    #[test]
    fn leases_are_counted_and_abandonment_releases_remaining_tokens() {
        let (_dir, store) = store();
        let root = Hash::new(b"leased");
        let mut leases = Leases::new(&store);
        let first = leases.acquire("cas_writers", root.as_bytes()).unwrap();
        let second = leases.acquire("cas_writers", root.as_bytes()).unwrap();
        assert_eq!(store.writer_count(&root), 2);
        leases.release(first).unwrap();
        assert_eq!(store.writer_count(&root), 1);
        assert!(leases.release(first).is_err());
        assert_ne!(first, second);
        drop(leases);
        assert_eq!(store.writer_count(&root), 0);
    }
}
