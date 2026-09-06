//! The object store as a directory, for Lean's sweeps: what an object's
//! files cost on disk, when they were written, and which objects have files
//! at all. The layout (shard directories, file names, the staging directory
//! that is not a shard) is this side's; what is evicted, collected or
//! unlinked, and in what order, is the program's.

use std::{collections::BTreeSet, path::PathBuf};

use synch_core::Hash;
use synch_verified::host;

use crate::{
    gc::{cas_root_of, mtime_nanos},
    Result, Store, StoreError,
};

pub(crate) struct Sweeper<'a> {
    store: &'a Store,
    /// The shard directories, listed once at the first page request so the
    /// pages of one sweep partition one snapshot of the store.
    shards: Option<Vec<PathBuf>>,
}

impl<'a> Sweeper<'a> {
    pub(crate) fn new(store: &'a Store) -> Self {
        Self {
            store,
            shards: None,
        }
    }

    fn path(&self, space: &str, key: &[u8]) -> Result<PathBuf> {
        let root = Hash::from_slice(key).map_err(|error| StoreError::invalid(error.to_string()))?;
        match space {
            "cas_payload" => Ok(self.store.blob_path(&root)),
            "cas_outboard" => Ok(self.store.outboard_path(&root)),
            _ => Err(StoreError::invalid("unsupported file namespace")),
        }
    }

    /// Nothing in the CAS root but a directory is descended into: `read_dir`
    /// on a stray regular file fails with `NotADirectory`, not `NotFound`,
    /// and one leaked file would otherwise fail every sweep from then on.
    /// The staging directory holds temporaries, not objects.
    fn shards(&mut self) -> Result<&[PathBuf]> {
        if self.shards.is_none() {
            let mut shards = Vec::new();
            match std::fs::read_dir(self.store.cas_dir()) {
                Ok(entries) => {
                    let staging = self.store.staging_dir();
                    for entry in entries {
                        let path = entry?.path();
                        if path.is_dir() && path != staging {
                            shards.push(path);
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            shards.sort();
            self.shards = Some(shards);
        }
        Ok(self.shards.as_deref().unwrap_or_default())
    }
}

/// The bytes a file occupies on disk: its allocated blocks where the
/// platform reports them, so a sparse or trimmed file is charged for what it
/// actually holds; its length elsewhere.
pub(crate) fn file_bytes(path: &std::path::Path) -> u64 {
    let Ok(metadata) = std::fs::metadata(path) else {
        return 0;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks().saturating_mul(512)
    }
    #[cfg(not(unix))]
    {
        metadata.len()
    }
}

impl host::Sweep for Sweeper<'_> {
    type Error = StoreError;

    fn file_bytes(&mut self, space: &str, key: &[u8]) -> Result<u64> {
        Ok(file_bytes(&self.path(space, key)?))
    }

    fn file_modified(&mut self, space: &str, key: &[u8]) -> Result<Option<i64>> {
        let path = self.path(space, key)?;
        let Ok(metadata) = std::fs::metadata(&path) else {
            return Ok(None);
        };
        if !metadata.is_file() {
            return Ok(None);
        }
        Ok(mtime_nanos(&metadata))
    }

    fn list_objects(&mut self, page: u64) -> Result<Option<Vec<u8>>> {
        let shards = self.shards()?;
        let Some(shard) = usize::try_from(page)
            .ok()
            .and_then(|index| shards.get(index).cloned())
        else {
            return Ok(None);
        };
        let entries = match std::fs::read_dir(&shard) {
            Ok(entries) => entries,
            // A shard removed since the listing has no objects left in it.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Some(Vec::new()))
            }
            Err(error) => return Err(error.into()),
        };
        // A payload and its outboard name the same object once; anything not
        // named for an object is left alone by never being listed.
        let mut roots = BTreeSet::new();
        for entry in entries {
            if let Some(root) = cas_root_of(&entry?.path()) {
                roots.insert(root);
            }
        }
        let mut listed = Vec::with_capacity(roots.len() * 32);
        for root in roots {
            listed.extend_from_slice(root.as_bytes());
        }
        Ok(Some(listed))
    }
}
