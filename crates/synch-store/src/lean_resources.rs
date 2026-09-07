//! Raw invocation-owned resources for mandatory Lean ingestion, and the bulk
//! construction service that streams, hashes and lays out an object into
//! them. No commit or publication policy lives here: Lean decides what is
//! built, into which owned temporaries, and everything before and after.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    fs::{File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    rc::Rc,
};

use bao_tree::io::sync::{ReadAt, WriteAt};
use synch_core::Hash;
use synch_verified::host::{self, Construct, FileIO, Lease, SourceIO, TemporaryFiles};

use crate::{db::WriteLease, lean_diagnostics::io_failure, Result, Store, StoreError};

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
    // Failed discard consumes the public token, but abandonment must still
    // retry unlink while the path remains protected from staging GC.
    retired_temporaries: Vec<PathBuf>,
    // Shard directories `replace` had to create. Only a new shard leaves a
    // new entry in the CAS root that a directory flush has to reach.
    created_directories: HashSet<PathBuf>,
    // Directories flushed since the last `replace`. Lean asks for a sync per
    // published file; the two files of one ingest share a shard, so the
    // second request finds nothing left to flush.
    synced_directories: HashSet<PathBuf>,
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
        let path = temporary.path.clone();
        self.handles.remove(&handle);
        let mut active = self.store.active_temporaries();
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                self.retired_temporaries.push(path);
                return Err(error.into());
            }
        }
        active.remove(&path);
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
        for path in &self.retired_temporaries {
            let _ = std::fs::remove_file(path);
            active.remove(path);
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
            retired_temporaries: Vec::new(),
            created_directories: HashSet::new(),
            synced_directories: HashSet::new(),
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
            if !parent.is_dir() {
                std::fs::create_dir_all(parent)?;
                pool.created_directories.insert(parent.to_path_buf());
            }
        }
        // Failure retains temporary ownership for explicit cleanup or Drop.
        synch_core::fs::replace_file(&original, &destination)?;
        // A new entry in the shard: whatever was flushed before is stale.
        pool.synced_directories.clear();
        pool.store.active_temporaries().remove(&original);
        pool.handles.remove(&handle);
        Ok(())
    }

    fn discard(&mut self, handle: u64) -> Result<()> {
        self.0.borrow_mut().discard(handle)
    }

    fn sync_parent(&mut self, space: &str, key: &[u8]) -> Result<host::SyncStatus> {
        let mut pool = self.0.borrow_mut();
        let path = target(pool.store, space, key)?;
        #[cfg(windows)]
        {
            let _ = (path, &mut pool);
            Ok(host::SyncStatus::Unsupported)
        }
        #[cfg(not(windows))]
        {
            let directory = path
                .parent()
                .ok_or_else(|| StoreError::invalid("file has no parent"))?
                .to_path_buf();
            // A shard `replace` created is a new entry in the CAS root, so the
            // root is flushed too. The CAS root itself exists from `Store::open`
            // on; durability of that configured directory is a setup
            // precondition, not an ingestion decision. Each directory is
            // flushed once per publication round: Lean requests a sync per
            // published file, and both files of one ingest share a shard.
            let mut pending = vec![];
            if !pool.synced_directories.contains(&directory) {
                pending.push(directory.clone());
                if pool.created_directories.contains(&directory) {
                    let cas_directory = pool.store.cas_dir();
                    if !pool.synced_directories.contains(&cas_directory) {
                        pending.push(cas_directory);
                    }
                }
            }
            let mut status = host::SyncStatus::Synced;
            for directory in pending {
                match File::open(&directory)?.sync_all() {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                        status = host::SyncStatus::Unsupported;
                    }
                    Err(error) => return Err(error.into()),
                }
                pool.synced_directories.insert(directory);
            }
            // The root now carries this shard's entry durably; later
            // publications into the shard flush the shard alone.
            pool.created_directories.remove(&directory);
            Ok(status)
        }
    }
}

/// The bytes of a source handle, read positioned from its start so that the
/// sequential SourceIO cursor and the OS file position are left alone. Every
/// byte handed out is also written to the payload temporary at the same
/// offset, so hashing the object and staging it take one pass.
struct Tee<'a> {
    source: &'a Handle<'a>,
    payload: &'a mut File,
    position: u64,
}

impl Read for Tee<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = match self.source {
            Handle::Borrowed(bytes) => copy_from(bytes, self.position, buf),
            Handle::Frozen(bytes) => copy_from(bytes, self.position, buf),
            Handle::File(source) => loop {
                match source.file.read_at(self.position, buf) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => break result?,
                }
            },
            Handle::Temporary(_) => {
                return Err(io::Error::other("a temporary is not a construction source"))
            }
        };
        self.payload.write_all_at(self.position, &buf[..count])?;
        self.position += count as u64;
        Ok(count)
    }
}

fn copy_from(bytes: &[u8], position: u64, buf: &mut [u8]) -> usize {
    let start = usize::try_from(position)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let count = buf.len().min(bytes.len() - start);
    buf[..count].copy_from_slice(&bytes[start..start + count]);
    count
}

impl Construct for Files<'_> {
    type Error = StoreError;

    /// One streaming pass: the source is read in tree groups, each group is
    /// written to the payload temporary and hashed, and the outboard is
    /// accumulated in memory (64 bytes per group pair) and written whole.
    /// A source shorter than `size` fails with `UnexpectedEof` after the
    /// bytes read so far were staged; the caller discards the temporaries.
    fn build(&mut self, source: u64, payload: u64, outboard: u64, size: u64) -> Result<Vec<u8>> {
        if source == payload || source == outboard || payload == outboard {
            return Err(StoreError::invalid(
                "construction needs distinct source, payload and outboard handles",
            ));
        }
        let mut pool = self.0.borrow_mut();
        // Both destinations are taken out of the registry for the duration
        // and put back whatever happens, so the temporaries stay owned and
        // discardable after a failed construction.
        let mut payload_file = pool
            .temporary(payload)?
            .file
            .take()
            .ok_or_else(|| StoreError::invalid("temporary file is closed"))?;
        let mut outboard_file = match pool.temporary(outboard).and_then(|temporary| {
            temporary
                .file
                .take()
                .ok_or_else(|| StoreError::invalid("temporary file is closed"))
        }) {
            Ok(file) => file,
            Err(error) => {
                pool.temporary(payload)?.file = Some(payload_file);
                return Err(error);
            }
        };
        let built = (|| -> Result<Vec<u8>> {
            let handle = pool
                .handles
                .get(&source)
                .ok_or_else(|| StoreError::invalid("unknown file handle"))?;
            let tree = Store::tree(size);
            let mut outboard_bytes = Vec::new();
            outboard_bytes
                .try_reserve_exact(
                    usize::try_from(tree.outboard_size())
                        .map_err(|_| StoreError::invalid("outboard exceeds address space"))?,
                )
                .map_err(|_| StoreError::invalid("outboard allocation failed"))?;
            outboard_bytes.resize(tree.outboard_size() as usize, 0);
            let root = crate::cas::compute_outboard(
                Tee {
                    source: handle,
                    payload: &mut payload_file,
                    position: 0,
                },
                tree,
                &mut outboard_bytes,
            )?;
            outboard_file.write_all_at(0, &outboard_bytes)?;
            Ok(root.as_bytes().to_vec())
        })();
        pool.temporary(payload)?.file = Some(payload_file);
        pool.temporary(outboard)?.file = Some(outboard_file);
        built
    }

    fn hash(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(blake3::hash(bytes).as_bytes().to_vec())
    }
}

#[cfg(test)]
fn write_at(files: &mut Files<'_>, handle: u64, offset: u64, bytes: &[u8]) -> Result<()> {
    files
        .0
        .borrow_mut()
        .temporary(handle)?
        .file
        .as_mut()
        .ok_or_else(|| StoreError::invalid("temporary file is closed"))?
        .write_all_at(offset, bytes)?;
    Ok(())
}

fn input_key(space: &str, key: &[u8]) -> Result<()> {
    if space == "input" && key.is_empty() {
        Ok(())
    } else {
        Err(StoreError::invalid("unsupported invocation input"))
    }
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

    fn read_into(
        &mut self,
        handle: u64,
        offset: u64,
        buffer: &mut [u8],
    ) -> std::result::Result<(), host::FileFailure<StoreError>> {
        // Ingestion inputs are read as replies; the output sink belongs to
        // the local-read operation.
        let _ = (handle, offset, buffer);
        Err(io_failure(StoreError::invalid(
            "ingestion has no output sink to transfer into",
        )))
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

/// One held token: a writer's mark, or the remover's critical section. The
/// section's guards drop in the order they are declared: the CAS ordering
/// guard first, then the connection it was taken after.
#[derive(Debug)]
enum Token<'a> {
    Write {
        _mark: WriteLease<'a>,
    },
    Order {
        _order: std::sync::MutexGuard<'a, ()>,
        _conn: std::rc::Rc<crate::db::ConnectionLease<'a>>,
    },
}

#[derive(Debug)]
pub(crate) struct Leases<'a> {
    store: &'a Store,
    next: u64,
    active: BTreeMap<u64, Token<'a>>,
    /// The connection state shared with the invocation's storage session,
    /// when the operation may open the remover's critical section.
    section: Option<crate::lean_storage::Section<'a>>,
}

impl<'a> Leases<'a> {
    pub(crate) fn new(store: &'a Store) -> Self {
        Self {
            store,
            next: 1,
            active: BTreeMap::new(),
            section: None,
        }
    }

    /// A lease service that can also open the remover's critical section,
    /// sharing the connection it holds with the storage session `section`
    /// came from.
    pub(crate) fn ordered(store: &'a Store, section: crate::lean_storage::Section<'a>) -> Self {
        Self {
            store,
            next: 1,
            active: BTreeMap::new(),
            section: Some(section),
        }
    }

    fn in_section(&self) -> bool {
        self.section
            .as_ref()
            .is_some_and(|section| section.borrow().held.is_some())
    }

    fn insert(&mut self, token: Token<'a>) -> Result<u64> {
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| StoreError::invalid("lease identifiers exhausted"))?;
        let handle = self.next;
        self.next = next;
        self.active.insert(handle, token);
        Ok(handle)
    }
}

impl Lease for Leases<'_> {
    type Error = StoreError;
    fn acquire(&mut self, space: &str, key: &[u8]) -> Result<u64> {
        if space != "cas_writers" {
            return Err(StoreError::invalid("unsupported lease namespace"));
        }
        // A writer's mark is taken through the guards the section holds;
        // taking it inside the section would wait on the invocation itself.
        if self.in_section() {
            return Err(StoreError::invalid(
                "a write lease cannot be taken inside the removal section",
            ));
        }
        let root = Hash::from_slice(key).map_err(|error| StoreError::invalid(error.to_string()))?;
        self.next
            .checked_add(1)
            .ok_or_else(|| StoreError::invalid("lease identifiers exhausted"))?;
        let lease = self.store.lease_write(&root);
        self.insert(Token::Write { _mark: lease })
    }
    fn order(&mut self, space: &str) -> Result<u64> {
        if space != "cas" {
            return Err(StoreError::invalid("unsupported ordering namespace"));
        }
        let Some(section) = self.section.clone() else {
            return Err(StoreError::invalid(
                "this operation has no removal section to enter",
            ));
        };
        {
            let shared = section.borrow();
            if shared.held.is_some() {
                return Err(StoreError::invalid("the removal section is already held"));
            }
            if shared.transaction {
                return Err(StoreError::invalid(
                    "the removal section cannot begin inside a transaction",
                ));
            }
        }
        self.next
            .checked_add(1)
            .ok_or_else(|| StoreError::invalid("lease identifiers exhausted"))?;
        // The same order every writer's lease takes: the connection, then the
        // CAS ordering guard shared by every Store on this data directory.
        let conn = std::rc::Rc::new(self.store.connection_lease());
        let order = self.store.cas_order();
        section.borrow_mut().held = Some(conn.clone());
        self.insert(Token::Order {
            _order: order,
            _conn: conn,
        })
    }
    fn release(&mut self, token: u64) -> Result<()> {
        let held = self
            .active
            .remove(&token)
            .ok_or_else(|| StoreError::invalid("unknown lease token"))?;
        if let Token::Order { .. } = &held {
            if let Some(section) = &self.section {
                section.borrow_mut().held = None;
            }
        }
        // The session's own reference to the connection is gone with the
        // section; dropping the token releases both guards.
        drop(held);
        Ok(())
    }
}

impl Drop for Leases<'_> {
    fn drop(&mut self) {
        // Abandonment: the section's connection must not outlive the token
        // that holds the ordering guard, so the shared reference goes first.
        if let Some(section) = &self.section {
            section.borrow_mut().held = None;
        }
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
        write_at(&mut files, handle, 0, b"live").unwrap();
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
        write_at(&mut writer, handle, 0, b"bytes").unwrap();
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
        write_at(&mut files, handle, 0, b"staged").unwrap();
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
        write_at(&mut files, handle, 0, b"published").unwrap();
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
    fn failed_discard_consumes_token_and_keeps_private_drop_cleanup() {
        let (_dir, store) = store();
        let mut files = Files::new(&store, Input::Bytes(&[]));
        let handle = files.create_temporary("cas_payload").unwrap();
        let path = temporary_path(&files, handle);
        // Force a portable unlink error without relying on permissions (the
        // suite may run as root). Restore a removable file before abandonment.
        drop(files.0.borrow_mut().temporary(handle).unwrap().file.take());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let expected_error = std::fs::remove_file(&path).unwrap_err();
        let StoreError::Io(error) = files.discard(handle).unwrap_err() else {
            panic!("discard must preserve the original filesystem error");
        };
        assert_eq!(error.kind(), expected_error.kind());
        assert_eq!(error.raw_os_error(), expected_error.raw_os_error());
        assert!(!files.0.borrow().handles.contains_key(&handle));
        assert_eq!(files.0.borrow().retired_temporaries, vec![path.clone()]);
        assert!(store.active_temporaries().contains(&path));
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, b"retry cleanup").unwrap();
        let root = Hash::new(b"retry cleanup");
        assert!(files.flush(handle).is_err());
        assert!(write_at(&mut files, handle, 0, b"overwrite").is_err());
        assert!(files.read_at(handle, 0, 1).is_err());
        assert!(files.read_some(handle, 0, 1).is_err());
        assert!(files
            .replace(handle, "cas_payload", root.as_bytes())
            .is_err());
        assert!(!store.blob_path(&root).exists());
        files.discard(handle).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"retry cleanup");
        assert!(store.active_temporaries().contains(&path));
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
            host::SyncStatus::Unsupported
        );
    }

    /// Lean asks for a directory sync per published file. Both files of one
    /// ingest land in the same shard, so the second request has nothing left
    /// to flush; the CAS root is flushed only when the shard is new; and a
    /// later publication into a flushed shard makes it flushable again.
    #[cfg(not(windows))]
    #[test]
    fn directory_syncs_are_shared_by_one_publication_round() {
        let synced = |files: &Files<'_>| {
            let mut synced: Vec<PathBuf> = files
                .0
                .borrow()
                .synced_directories
                .iter()
                .cloned()
                .collect();
            synced.sort();
            synced
        };
        let publish = |files: &mut Files<'_>, root: &Hash| {
            for space in ["cas_payload", "cas_outboard"] {
                let handle = files.create_temporary(space).unwrap();
                write_at(files, handle, 0, b"bytes").unwrap();
                files.replace(handle, space, root.as_bytes()).unwrap();
            }
        };
        let (_dir, store) = store();
        let mut files = Files::new(&store, Input::Bytes(&[]));
        let root = Hash::new(b"first publication");
        let shard = store.blob_path(&root).parent().unwrap().to_path_buf();
        assert!(!shard.exists());
        publish(&mut files, &root);
        assert!(files.0.borrow().created_directories.contains(&shard));
        assert!(synced(&files).is_empty());

        assert_eq!(
            files.sync_parent("cas_payload", root.as_bytes()).unwrap(),
            host::SyncStatus::Synced
        );
        let mut expected = vec![shard.clone(), store.cas_dir()];
        expected.sort();
        assert_eq!(synced(&files), expected);
        assert_eq!(
            files.sync_parent("cas_outboard", root.as_bytes()).unwrap(),
            host::SyncStatus::Synced
        );
        assert_eq!(
            synced(&files),
            expected,
            "the second request flushed nothing new"
        );

        // A new file in a flushed shard: the shard is due again, the root is
        // not, because the shard entry it holds is already durable.
        let sibling = {
            let mut candidate = 0u64;
            loop {
                let hash = Hash::new(&candidate.to_le_bytes());
                if store.blob_path(&hash).parent().unwrap() == shard && hash != root {
                    break hash;
                }
                candidate += 1;
            }
        };
        publish(&mut files, &sibling);
        assert!(synced(&files).is_empty());
        files
            .sync_parent("cas_payload", sibling.as_bytes())
            .unwrap();
        assert_eq!(synced(&files), vec![shard.clone()]);

        // A pre-existing shard never puts the root on the list.
        let mut other = Files::new(&store, Input::Bytes(&[]));
        let stranger = Hash::new(b"published into an existing shard");
        let stranger_shard = store.blob_path(&stranger).parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&stranger_shard).unwrap();
        publish(&mut other, &stranger);
        assert!(other.0.borrow().created_directories.is_empty());
        other
            .sync_parent("cas_outboard", stranger.as_bytes())
            .unwrap();
        assert_eq!(synced(&other), vec![stranger_shard]);
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
        write_at(&mut files, temporary, 0, b"staged").unwrap();
        assert_eq!(files.read_at(temporary, 0, 6).unwrap(), b"staged");
        assert!(write_at(&mut files, frozen, 0, b"bad").is_err());
        files.close(temporary).unwrap();
        assert!(files.read_at(temporary, 0, 1).is_err());
        assert!(write_at(&mut files, temporary, 0, b"bad").is_err());
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
    #[test]
    fn construction_streams_source_into_owned_temporaries() {
        let (dir, store) = store();
        let bytes: Vec<u8> = (0..100_003).map(|n| (n % 251) as u8).collect();
        let path = dir.path().join("source");
        std::fs::write(&path, &bytes).unwrap();
        for input in [Input::Bytes(&bytes), Input::File(&path)] {
            let mut files = Files::new(&store, input);
            let source = files.open("input", &[]).unwrap();
            let payload = files.create_temporary("cas_payload").unwrap();
            let outboard = files.create_temporary("cas_outboard").unwrap();
            let root = files
                .build(source, payload, outboard, bytes.len() as u64)
                .unwrap();
            assert_eq!(root, blake3::hash(&bytes).as_bytes());
            assert_eq!(
                std::fs::read(temporary_path(&files, payload)).unwrap(),
                bytes
            );
            // The temporaries stay owned, flushable and discardable.
            files.flush(payload).unwrap();
            files.flush(outboard).unwrap();
            assert_eq!(files.read_at(payload, 100, 3).unwrap(), bytes[100..103]);
            // The source cursor was not moved by the positioned pass.
            assert_eq!(files.read_some(source, 0, 4).unwrap(), bytes[..4]);
            files.close(source).unwrap();
            files.discard(payload).unwrap();
            files.discard(outboard).unwrap();
            assert!(store.active_temporaries().is_empty());
        }
    }

    #[test]
    fn construction_refuses_short_sources_and_confused_handles() {
        let (_dir, store) = store();
        let bytes = vec![7u8; 20_000];
        let mut files = Files::new(&store, Input::Bytes(&bytes));
        let source = files.open("input", &[]).unwrap();
        let payload = files.create_temporary("cas_payload").unwrap();
        let outboard = files.create_temporary("cas_outboard").unwrap();
        let short = files.build(source, payload, outboard, 20_001).unwrap_err();
        assert!(
            matches!(short, StoreError::Io(ref error) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
        for (from, into, aside) in [
            (source, payload, payload),
            (payload, payload, outboard),
            (source, source, outboard),
            (99, payload, outboard),
            (source, 99, outboard),
            (source, payload, 99),
        ] {
            assert!(files.build(from, into, aside, 20_000).is_err());
        }
        // A failed pass leaves the temporaries owned and discardable.
        assert_eq!(
            files.build(source, payload, outboard, 20_000).unwrap(),
            blake3::hash(&bytes).as_bytes()
        );
        files.discard(payload).unwrap();
        files.discard(outboard).unwrap();
        assert!(store.active_temporaries().is_empty());
        assert_eq!(files.hash(b"abc").unwrap(), blake3::hash(b"abc").as_bytes());
    }
}
