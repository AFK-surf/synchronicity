//! Object-safe async CAS backend contract (`docs/SERVERLESS.md` §3).
//!
//! This module is the migration boundary around the legacy synchronous
//! `Store` CAS. `LocalFs` centralizes its blocking handoff; `Cloud` adds the
//! remote durability promise while retaining the same verified cache codec.

use std::{
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use synch_core::{group_count, groups_for_byte_range, ChunkRanges, Hash, INLINE_BLOB_MAX};

use crate::{
    cloud::{CloudStore, CloudUploadPolicy},
    Donor, Proven, Result, Store, StoreError,
};

/// Whether bytes are stable enough for a durable SQLite reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// Bytes exist only in reconstructible or unacknowledged scratch.
    Staged,
    /// Bytes reached the backend's stable tier.
    Durable,
}

/// Result of ingesting one complete object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ingested {
    /// Content root.
    pub root: Hash,
    /// Content length.
    pub size: u64,
    /// Always durable for a successful whole-object ingest.
    pub durability: Durability,
}

/// Result of committing a verified slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupsWritten {
    /// Groups newly committed to cache.
    pub groups: ChunkRanges,
    /// Whether the object is now remotely durable or merely staged.
    pub durability: Durability,
}

/// How a complete object was materialized into a local target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Materialization {
    /// Source and target share copy-on-write extents.
    Reflink,
    /// Bytes were copied (or written from an inline value).
    Copy,
}

/// Work completed by one backend maintenance pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    /// Stale local staging/cache files removed.
    pub local_orphans: usize,
    /// Remote CAS objects inspected by an eligible provider sweep.
    pub remote_inspected: usize,
    /// Remote CAS objects deleted as old orphans.
    pub remote_deleted: usize,
    /// Row-first delete intents completed against the remote backend.
    pub remote_deletes_completed: usize,
    /// Durable local cache entries evicted by capacity policy.
    pub cache_entries_evicted: usize,
    /// Payload/outboard bytes released by cache eviction.
    pub cache_bytes_evicted: u64,
}

/// Semantic content-addressed storage operations used by the network and engine.
#[async_trait]
pub trait CasBackend: std::fmt::Debug + Send + Sync + 'static {
    /// Ingests owned bytes and returns only after their durable tier is safe.
    async fn ingest_bytes(&self, data: Vec<u8>, now: i64) -> Result<Ingested>;
    /// Ingests a file and returns only after its durable tier is safe.
    async fn ingest_file(&self, path: PathBuf, now: i64) -> Result<Ingested>;
    /// Makes a durable cold object readable from verified local cache.
    async fn ensure_cached(&self, root: Hash, size: u64) -> Result<()>;
    /// Makes selected durable groups readable from verified local cache.
    async fn ensure_ranges(&self, root: Hash, size: u64, ranges: ChunkRanges) -> Result<()>;
    /// Encodes a verified bao slice and the ranges actually served.
    async fn encode_slice(
        &self,
        root: Hash,
        requested: ChunkRanges,
    ) -> Result<(Vec<u8>, ChunkRanges)>;
    /// Commits a received bao slice after verification.
    async fn write_slice(
        &self,
        root: Hash,
        size: u64,
        served: ChunkRanges,
        encoded: Vec<u8>,
        now: i64,
    ) -> Result<GroupsWritten>;
    /// Reads and verifies one byte range.
    async fn read_range(&self, root: Hash, offset: u64, len: u64) -> Result<Vec<u8>>;
    /// Encodes a delta proof.
    async fn encode_proof(
        &self,
        root: Hash,
        requested: ChunkRanges,
        level: u8,
        budget: u64,
    ) -> Result<(Vec<u8>, ChunkRanges)>;
    /// Verifies and commits a delta proof.
    async fn write_proof(
        &self,
        root: Hash,
        size: u64,
        served: ChunkRanges,
        level: u8,
        encoded: Vec<u8>,
        now: i64,
    ) -> Result<Proven>;
    /// Promotes verified donor ranges into a partially assembled object.
    async fn promote(&self, donor: Donor, proven: Proven, now: i64) -> Result<ChunkRanges>;
    /// Promotes a complete staged object to the durable tier.
    async fn finalize(&self, root: Hash, size: u64) -> Result<()>;
    /// Writes a complete verified object to a local target atomically.
    async fn materialize(&self, root: Hash, size: u64, target: PathBuf) -> Result<Materialization>;
    /// Deletes metadata first and backend bytes second; idempotent.
    async fn delete(&self, root: Hash) -> Result<()>;
    /// Whether multipart parts must be persisted through backend object APIs.
    fn remote_upload_parts(&self) -> bool {
        false
    }
    /// Persists one backend-private multipart part.
    async fn put_upload_part(&self, _key: String, _source: PathBuf) -> Result<()> {
        Err(StoreError::invalid(
            "the local backend stores multipart parts as files",
        ))
    }
    /// Reads one range of a backend-private multipart part.
    async fn read_upload_part(
        &self,
        _key: String,
        _range: std::ops::Range<u64>,
    ) -> Result<Vec<u8>> {
        Err(StoreError::invalid(
            "the local backend stores multipart parts as files",
        ))
    }
    /// Deletes one backend-private multipart part.
    async fn delete_upload_part(&self, _key: String) -> Result<()> {
        Err(StoreError::invalid(
            "the local backend stores multipart parts as files",
        ))
    }
    /// Deletes every backend-private multipart object below a prefix.
    async fn delete_upload_prefix(&self, _prefix: String) -> Result<usize> {
        Err(StoreError::invalid(
            "the local backend stores multipart parts as files",
        ))
    }
    /// Sweeps backend-private orphans and enforces cache capacity.
    async fn maintain(&self, now: i64) -> Result<MaintenanceReport>;
}

/// Local filesystem CAS behind the async backend contract.
#[derive(Debug, Clone)]
pub struct LocalFs {
    store: Arc<Store>,
}

impl LocalFs {
    /// Wraps one SQLite/local-CAS store.
    pub fn new(store: Arc<Store>) -> Self {
        store.set_remote_cas(false);
        Self { store }
    }
}

/// OpenDAL durable CAS plus the shared verified local cache codec.
#[derive(Debug, Clone)]
pub struct Cloud {
    store: Arc<Store>,
    objects: CloudStore,
    upload_policy: CloudUploadPolicy,
    cache_bytes: Option<u64>,
    accessed: Arc<std::sync::Mutex<std::collections::HashMap<Hash, i64>>>,
}

impl Cloud {
    /// Builds a production cloud backend and reconciles the private ephemeral
    /// scratch generation before any cache claim can be served.
    pub async fn open(
        store: Arc<Store>,
        objects: CloudStore,
        upload_policy: CloudUploadPolicy,
        cache_bytes: Option<u64>,
    ) -> Result<Self> {
        let scratch = objects.scratch_dir().to_path_buf();
        let marker = blocking(move || scratch_generation(&scratch)).await?;
        let reconciled = store.clone();
        blocking(move || reconciled.reconcile_scratch_generation(&marker).map(|_| ())).await?;
        Ok(Self::new(store, objects, upload_policy, cache_bytes))
    }

    /// Builds a cloud backend over one metadata store and OpenDAL operator.
    pub fn new(
        store: Arc<Store>,
        objects: CloudStore,
        upload_policy: CloudUploadPolicy,
        cache_bytes: Option<u64>,
    ) -> Self {
        store.set_remote_cas(true);
        Self {
            store,
            objects,
            upload_policy,
            cache_bytes,
            accessed: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    async fn durability(&self, root: Hash) -> Result<Durability> {
        let store = self.store.clone();
        blocking(move || {
            Ok(match store.blob(&root)? {
                Some(row) if row.durable || row.inline.is_some() => Durability::Durable,
                _ => Durability::Staged,
            })
        })
        .await
    }

    async fn touch(&self, root: Hash) -> Result<()> {
        const TOUCH_INTERVAL_NS: i64 = 60 * 1_000_000_000;
        let now = synch_core::now_ns();
        let due = {
            let mut accessed = self
                .accessed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if accessed
                .get(&root)
                .is_some_and(|last| now.saturating_sub(*last) < TOUCH_INTERVAL_NS)
            {
                false
            } else {
                accessed.insert(root, now);
                true
            }
        };
        if due {
            let store = self.store.clone();
            blocking(move || store.touch_blob(&root, now)).await?;
        }
        Ok(())
    }

    async fn hydrate_ranges(&self, root: Hash, size: u64, ranges: ChunkRanges) -> Result<()> {
        if ranges.is_empty() {
            return Ok(());
        }
        let outboard = self.outboard_bytes(root, size).await?;
        let encoded = match self
            .objects
            .read_verified_slice(&root, size, &ranges, &outboard)
            .await
        {
            Ok(encoded) => encoded,
            Err(error @ StoreError::CloudNotFound { .. }) => {
                let store = self.store.clone();
                blocking(move || store.heal_missing_durable_blob(&root).map(|_| ())).await?;
                return Err(error);
            }
            Err(error @ StoreError::Verification { .. }) => {
                let store = self.store.clone();
                blocking(move || store.quarantine_blob(&root).map(|_| ())).await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let store = self.store.clone();
        blocking(move || {
            store.write_slice(&root, size, &ranges, &encoded, synch_core::now_ns())?;
            Ok(())
        })
        .await
    }

    async fn outboard_bytes(&self, root: Hash, size: u64) -> Result<Vec<u8>> {
        let store = self.store.clone();
        if let Some(cached) = blocking(move || Ok(store.cached_outboard(&root, size))).await? {
            return Ok(cached);
        }
        let outboard = match self.objects.read_outboard(&root).await {
            Ok(outboard) => outboard.to_vec(),
            Err(error @ StoreError::CloudNotFound { .. }) => {
                let store = self.store.clone();
                blocking(move || store.heal_missing_durable_blob(&root).map(|_| ())).await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let store = self.store.clone();
        let cached = outboard.clone();
        match blocking(move || store.cache_outboard(&root, size, &cached)).await {
            Ok(()) => {}
            Err(error @ StoreError::Verification { .. }) => {
                let store = self.store.clone();
                blocking(move || store.quarantine_blob(&root).map(|_| ())).await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        Ok(outboard)
    }

    /// Replaces a faulty reconstructible cache copy from the durable tier.
    /// Returns false when the error is not cache-shaped or no remote promise
    /// exists, in which case the original error belongs to the caller.
    async fn recover_cache_fault(&self, root: Hash, size: u64, error: &StoreError) -> Result<bool> {
        let cache_shaped = match error {
            StoreError::Verification { .. } => true,
            StoreError::Io(error) => matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::UnexpectedEof
            ),
            _ => false,
        };
        if !cache_shaped {
            return Ok(false);
        }
        let store = self.store.clone();
        let durable = blocking(move || {
            Ok(store
                .blob(&root)?
                .is_some_and(|row| row.durable && !row.quarantined))
        })
        .await?;
        if !durable {
            return Ok(false);
        }
        let store = self.store.clone();
        blocking(move || store.clear_blob_cache(&root)).await?;
        self.ensure_cached(root, size).await?;
        Ok(true)
    }
}

fn scratch_generation(scratch: &std::path::Path) -> Result<String> {
    let marker_path = scratch.join("generation");
    if let Ok(marker) = std::fs::read_to_string(&marker_path) {
        let marker = marker.trim();
        if !marker.is_empty() {
            return Ok(marker.to_string());
        }
    }
    if scratch.exists() {
        std::fs::remove_dir_all(scratch)?;
    }
    std::fs::create_dir_all(scratch)?;
    let marker = hex::encode(iroh_base::SecretKey::generate().to_bytes());
    let mut file = std::fs::File::create(&marker_path)?;
    file.write_all(marker.as_bytes())?;
    file.sync_all()?;
    if let Some(parent) = marker_path.parent() {
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(marker)
}

#[async_trait]
impl CasBackend for LocalFs {
    async fn ingest_bytes(&self, data: Vec<u8>, now: i64) -> Result<Ingested> {
        let store = self.store.clone();
        blocking(move || {
            let size = data.len() as u64;
            let root = store.ingest_bytes(&data, now)?;
            Ok(Ingested {
                root,
                size,
                durability: Durability::Durable,
            })
        })
        .await
    }

    async fn ingest_file(&self, path: PathBuf, now: i64) -> Result<Ingested> {
        let store = self.store.clone();
        blocking(move || {
            let (root, size) = store.ingest_file(&path, now)?;
            Ok(Ingested {
                root,
                size,
                durability: Durability::Durable,
            })
        })
        .await
    }

    async fn ensure_cached(&self, _root: Hash, _size: u64) -> Result<()> {
        Ok(())
    }

    async fn ensure_ranges(&self, _root: Hash, _size: u64, _ranges: ChunkRanges) -> Result<()> {
        Ok(())
    }

    async fn encode_slice(
        &self,
        root: Hash,
        requested: ChunkRanges,
    ) -> Result<(Vec<u8>, ChunkRanges)> {
        let store = self.store.clone();
        blocking(move || store.encode_slice(&root, &requested)).await
    }

    async fn write_slice(
        &self,
        root: Hash,
        size: u64,
        served: ChunkRanges,
        encoded: Vec<u8>,
        now: i64,
    ) -> Result<GroupsWritten> {
        let store = self.store.clone();
        blocking(move || {
            Ok(GroupsWritten {
                groups: store.write_slice(&root, size, &served, &encoded, now)?,
                durability: Durability::Durable,
            })
        })
        .await
    }

    async fn read_range(&self, root: Hash, offset: u64, len: u64) -> Result<Vec<u8>> {
        let store = self.store.clone();
        blocking(move || store.read_range(&root, offset, len)).await
    }

    async fn encode_proof(
        &self,
        root: Hash,
        requested: ChunkRanges,
        level: u8,
        budget: u64,
    ) -> Result<(Vec<u8>, ChunkRanges)> {
        let store = self.store.clone();
        blocking(move || store.encode_proof(&root, &requested, level, budget)).await
    }

    async fn write_proof(
        &self,
        root: Hash,
        size: u64,
        served: ChunkRanges,
        level: u8,
        encoded: Vec<u8>,
        now: i64,
    ) -> Result<Proven> {
        let store = self.store.clone();
        blocking(move || store.write_proof(&root, size, &served, level, &encoded, now)).await
    }

    async fn promote(&self, donor: Donor, proven: Proven, now: i64) -> Result<ChunkRanges> {
        let store = self.store.clone();
        blocking(move || store.promote(&donor, &proven, now)).await
    }

    async fn finalize(&self, _root: Hash, _size: u64) -> Result<()> {
        Ok(())
    }

    async fn materialize(&self, root: Hash, size: u64, target: PathBuf) -> Result<Materialization> {
        let store = self.store.clone();
        blocking(move || materialize_cached(&store, root, size, &target)).await
    }

    async fn delete(&self, root: Hash) -> Result<()> {
        let store = self.store.clone();
        blocking(move || store.delete_blob(&root)).await
    }

    async fn maintain(&self, now: i64) -> Result<MaintenanceReport> {
        const HORIZON_NS: i64 = 7 * 24 * 60 * 60 * 1_000_000_000;
        let store = self.store.clone();
        let local_orphans =
            blocking(move || store.gc_orphans(now.saturating_sub(HORIZON_NS))).await?;
        Ok(MaintenanceReport {
            local_orphans,
            ..MaintenanceReport::default()
        })
    }
}

#[async_trait]
impl CasBackend for Cloud {
    async fn ingest_bytes(&self, data: Vec<u8>, now: i64) -> Result<Ingested> {
        let size = data.len() as u64;
        let store = self.store.clone();
        let root = blocking(move || store.ingest_bytes(&data, now)).await?;
        if size > INLINE_BLOB_MAX {
            self.finalize(root, size).await?;
        }
        Ok(Ingested {
            root,
            size,
            durability: Durability::Durable,
        })
    }

    async fn ingest_file(&self, path: PathBuf, now: i64) -> Result<Ingested> {
        let size = tokio::fs::metadata(&path).await?.len();
        if size <= INLINE_BLOB_MAX {
            let store = self.store.clone();
            return blocking(move || {
                let (root, size) = store.ingest_file(&path, now)?;
                Ok(Ingested {
                    root,
                    size,
                    durability: Durability::Durable,
                })
            })
            .await;
        }
        let remote = self.objects.ingest_file(&path).await?;
        let store = self.store.clone();
        let path_for_cache = path;
        blocking(move || {
            let (root, size) = store.ingest_file(&path_for_cache, now)?;
            if (root, size) != (remote.root, remote.size) {
                return Err(StoreError::invalid(
                    "ingest source changed during cloud upload",
                ));
            }
            store.mark_blob_durable(&root)?;
            Ok(Ingested {
                root,
                size,
                durability: Durability::Durable,
            })
        })
        .await
    }

    async fn ensure_cached(&self, root: Hash, size: u64) -> Result<()> {
        let store = self.store.clone();
        let row = blocking(move || store.blob(&root))
            .await?
            .ok_or(StoreError::MissingBlob(root))?;
        if row.quarantined {
            return Err(StoreError::MissingBlob(root));
        }
        if row.inline.is_some() {
            return Ok(());
        }
        if row.complete {
            let store = self.store.clone();
            let present =
                blocking(move || Ok(store.cached_blob_files_present(&root, size))).await?;
            if present {
                return Ok(());
            }
            let store = self.store.clone();
            blocking(move || store.clear_blob_cache(&root)).await?;
            if !row.durable {
                return Err(StoreError::MissingBlob(root));
            }
        }
        if !row.durable {
            return Ok(());
        }
        self.hydrate_ranges(root, size, ChunkRanges::single(0, group_count(size)))
            .await
    }

    async fn ensure_ranges(&self, root: Hash, size: u64, ranges: ChunkRanges) -> Result<()> {
        let row = {
            let store = self.store.clone();
            blocking(move || store.blob(&root)).await?
        };
        let Some(row) = row else {
            return Ok(());
        };
        if row.quarantined {
            return Err(StoreError::MissingBlob(root));
        }
        if row.inline.is_some() || !row.durable {
            return Ok(());
        }
        let wanted = ranges.intersect(&ChunkRanges::single(0, group_count(size)));
        self.hydrate_ranges(root, size, wanted.difference(&row.verified_groups()))
            .await
    }

    async fn encode_slice(
        &self,
        root: Hash,
        requested: ChunkRanges,
    ) -> Result<(Vec<u8>, ChunkRanges)> {
        let size = {
            let store = self.store.clone();
            blocking(move || store.blob(&root).map(|row| row.map(|row| row.size))).await?
        }
        .ok_or(StoreError::MissingBlob(root))?;
        let wanted = requested
            .intersect(&ChunkRanges::single(0, group_count(size)))
            .take(synch_core::MAX_SLICE_GROUPS);
        let (held, durable) = {
            let store = self.store.clone();
            blocking(move || {
                Ok(match store.blob(&root)? {
                    Some(row) => (row.verified_groups(), row.durable),
                    None => (ChunkRanges::empty(), false),
                })
            })
            .await?
        };
        if durable {
            self.hydrate_ranges(root, size, wanted.difference(&held))
                .await?;
        }
        let store = self.store.clone();
        let first_requested = requested.clone();
        let first = blocking(move || store.encode_slice(&root, &first_requested)).await;
        let result = match first {
            Ok(value) => Ok(value),
            Err(error) if self.recover_cache_fault(root, size, &error).await? => {
                let store = self.store.clone();
                blocking(move || store.encode_slice(&root, &requested)).await
            }
            Err(error) => Err(error),
        };
        if result.is_ok() {
            self.touch(root).await?;
        }
        result
    }

    async fn write_slice(
        &self,
        root: Hash,
        size: u64,
        served: ChunkRanges,
        encoded: Vec<u8>,
        now: i64,
    ) -> Result<GroupsWritten> {
        let store = self.store.clone();
        let groups =
            blocking(move || store.write_slice(&root, size, &served, &encoded, now)).await?;
        if self.upload_policy == CloudUploadPolicy::All {
            self.finalize(root, size).await?;
        }
        Ok(GroupsWritten {
            groups,
            durability: self.durability(root).await?,
        })
    }

    async fn read_range(&self, root: Hash, offset: u64, len: u64) -> Result<Vec<u8>> {
        let size = {
            let store = self.store.clone();
            blocking(move || store.blob(&root).map(|row| row.map(|row| row.size))).await?
        }
        .ok_or(StoreError::MissingBlob(root))?;
        if offset > size {
            return Err(StoreError::RangeOutOfBounds {
                start: offset,
                end: offset.saturating_add(len).min(size),
                size,
            });
        }
        let end = offset.saturating_add(len).min(size);
        if offset < end {
            let wanted = ChunkRanges::from_ranges([groups_for_byte_range(offset, end)]);
            let (held, durable) = {
                let store = self.store.clone();
                blocking(move || {
                    Ok(match store.blob(&root)? {
                        Some(row) => (row.verified_groups(), row.durable),
                        None => (ChunkRanges::empty(), false),
                    })
                })
                .await?
            };
            if durable {
                self.hydrate_ranges(root, size, wanted.difference(&held))
                    .await?;
            }
        }
        let store = self.store.clone();
        let first = blocking(move || store.read_range(&root, offset, len)).await;
        let result = match first {
            Ok(value) => Ok(value),
            Err(error) if self.recover_cache_fault(root, size, &error).await? => {
                let store = self.store.clone();
                blocking(move || store.read_range(&root, offset, len)).await
            }
            Err(error) => Err(error),
        };
        if result.is_ok() {
            self.touch(root).await?;
        }
        result
    }

    async fn encode_proof(
        &self,
        root: Hash,
        requested: ChunkRanges,
        level: u8,
        budget: u64,
    ) -> Result<(Vec<u8>, ChunkRanges)> {
        let size = {
            let store = self.store.clone();
            blocking(move || store.blob(&root).map(|row| row.map(|row| row.size))).await?
        }
        .ok_or(StoreError::MissingBlob(root))?;
        let store = self.store.clone();
        let first_requested = requested.clone();
        let first =
            blocking(move || store.encode_proof(&root, &first_requested, level, budget)).await;
        let wanted = requested.intersect(&ChunkRanges::single(0, group_count(size)));
        if let Ok((encoded, served)) = &first {
            if *served == wanted {
                self.touch(root).await?;
                return Ok((encoded.clone(), served.clone()));
            }
        }
        let row = {
            let store = self.store.clone();
            blocking(move || store.blob(&root)).await?
        }
        .ok_or(StoreError::MissingBlob(root))?;
        if !row.durable || row.inline.is_some() {
            if first.is_ok() {
                self.touch(root).await?;
            }
            return first;
        }
        let outboard = self.outboard_bytes(root, size).await?;
        let encoded = {
            let requested = requested.clone();
            blocking(move || {
                Store::encode_complete_proof(root, size, &requested, level, budget, outboard)
            })
            .await
        };
        let result = match encoded {
            Err(error @ StoreError::Verification { .. }) => {
                let store = self.store.clone();
                blocking(move || store.quarantine_blob(&root).map(|_| ())).await?;
                Err(error)
            }
            other => other,
        };
        if result.is_ok() {
            self.touch(root).await?;
        }
        result
    }

    async fn write_proof(
        &self,
        root: Hash,
        size: u64,
        served: ChunkRanges,
        level: u8,
        encoded: Vec<u8>,
        now: i64,
    ) -> Result<Proven> {
        let store = self.store.clone();
        blocking(move || store.write_proof(&root, size, &served, level, &encoded, now)).await
    }

    async fn promote(&self, donor: Donor, proven: Proven, now: i64) -> Result<ChunkRanges> {
        let donor_state = {
            let store = self.store.clone();
            let donor_root = donor.root();
            blocking(move || store.blob(&donor_root)).await?
        };
        if let Some(row) = donor_state {
            if row.durable {
                let wanted =
                    ChunkRanges::from_ranges(proven.subtrees.iter().map(|subtree| subtree.range()));
                self.hydrate_ranges(
                    donor.root(),
                    row.size,
                    wanted.difference(&row.verified_groups()),
                )
                .await?;
            }
        }
        let store = self.store.clone();
        let root = proven.root;
        let size = proven.size;
        let promoted = blocking(move || store.promote(&donor, &proven, now)).await?;
        if self.upload_policy == CloudUploadPolicy::All {
            self.finalize(root, size).await?;
        }
        Ok(promoted)
    }

    async fn finalize(&self, root: Hash, size: u64) -> Result<()> {
        let store = self.store.clone();
        let row = blocking(move || store.blob(&root))
            .await?
            .ok_or(StoreError::MissingBlob(root))?;
        if row.durable || row.inline.is_some() {
            return Ok(());
        }
        if !row.complete {
            return Ok(());
        }
        let uploaded = self
            .objects
            .ingest_file(&self.store.blob_path(&root))
            .await?;
        if (uploaded.root, uploaded.size) != (root, size) {
            return Err(StoreError::Verification {
                root,
                reason: format!(
                    "cloud finalize produced {} ({} bytes)",
                    uploaded.root, uploaded.size
                ),
            });
        }
        let store = self.store.clone();
        blocking(move || {
            if store.mark_blob_durable(&root)? {
                Ok(())
            } else {
                Err(StoreError::MissingBlob(root))
            }
        })
        .await
    }

    async fn materialize(&self, root: Hash, size: u64, target: PathBuf) -> Result<Materialization> {
        self.ensure_cached(root, size).await?;
        let store = self.store.clone();
        let first_target = target.clone();
        let first = blocking(move || materialize_cached(&store, root, size, &first_target)).await;
        let result = match first {
            Ok(value) => Ok(value),
            Err(error) if self.recover_cache_fault(root, size, &error).await? => {
                let store = self.store.clone();
                blocking(move || materialize_cached(&store, root, size, &target)).await
            }
            Err(error) => Err(error),
        };
        if result.is_ok() {
            self.touch(root).await?;
        }
        result
    }

    async fn delete(&self, root: Hash) -> Result<()> {
        let store = self.store.clone();
        blocking(move || store.delete_blob(&root)).await?;
        self.objects.delete(&root).await?;
        let store = self.store.clone();
        blocking(move || store.finish_backend_delete(&root)).await
    }

    fn remote_upload_parts(&self) -> bool {
        true
    }

    async fn put_upload_part(&self, key: String, source: PathBuf) -> Result<()> {
        self.objects.write_object_file(&key, &source).await
    }

    async fn read_upload_part(&self, key: String, range: std::ops::Range<u64>) -> Result<Vec<u8>> {
        Ok(self.objects.read_object_range(&key, range).await?.to_vec())
    }

    async fn delete_upload_part(&self, key: String) -> Result<()> {
        self.objects.delete_object(&key).await
    }

    async fn delete_upload_prefix(&self, prefix: String) -> Result<usize> {
        self.objects.delete_prefix(&prefix).await
    }

    async fn maintain(&self, now: i64) -> Result<MaintenanceReport> {
        const DAY_NS: i64 = 24 * 60 * 60 * 1_000_000_000;
        const HORIZON_SECONDS: i64 = 7 * 24 * 60 * 60;
        const LAST_SWEEP_KEY: &str = "cas.cloud.last_sweep_ns";

        let store = self.store.clone();
        let cache_bytes = self.cache_bytes;
        let (local_orphans, cache_entries_evicted, cache_bytes_evicted) = blocking(move || {
            let local_orphans = store.gc_orphans(now.saturating_sub(7 * DAY_NS))?;
            let (cache_entries_evicted, cache_bytes_evicted) =
                enforce_cache_limit(&store, cache_bytes)?;
            Ok((local_orphans, cache_entries_evicted, cache_bytes_evicted))
        })
        .await?;

        let store = self.store.clone();
        let due = blocking(move || {
            let last = match store.config(LAST_SWEEP_KEY)? {
                Some(value) => value.parse::<i64>().map_err(|_| {
                    StoreError::invalid(format!(
                        "invalid {LAST_SWEEP_KEY} timestamp in config: {value}"
                    ))
                })?,
                None => i64::MIN,
            };
            Ok(now.saturating_sub(last) >= DAY_NS)
        })
        .await?;

        let mut report = MaintenanceReport {
            local_orphans,
            cache_entries_evicted,
            cache_bytes_evicted,
            ..MaintenanceReport::default()
        };
        let store = self.store.clone();
        let pending = blocking(move || store.pending_backend_deletes()).await?;
        for root in pending {
            self.objects.delete(&root).await?;
            let store = self.store.clone();
            blocking(move || store.finish_backend_delete(&root)).await?;
            report.remote_deletes_completed += 1;
        }
        if due {
            let store = self.store.clone();
            let live = blocking(move || {
                Ok(store
                    .blob_candidates()?
                    .into_iter()
                    .filter(|blob| blob.durable)
                    .map(|blob| blob.root)
                    .collect())
            })
            .await?;
            let swept = self
                .objects
                .sweep_orphans(
                    &live,
                    now.saturating_div(1_000_000_000)
                        .saturating_sub(HORIZON_SECONDS),
                )
                .await?;
            report.remote_inspected = swept.inspected;
            report.remote_deleted = swept.deleted;
            let store = self.store.clone();
            blocking(move || store.set_config(LAST_SWEEP_KEY, &now.to_string())).await?;
        }
        Ok(report)
    }
}

fn enforce_cache_limit(store: &Store, configured: Option<u64>) -> Result<(usize, u64)> {
    let usage = store.durable_cache_bytes()?;
    let mut target = configured.unwrap_or(u64::MAX);
    #[cfg(unix)]
    {
        let filesystem = rustix::fs::statvfs(store.cas_dir())
            .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
        let fragment = filesystem.f_frsize.max(filesystem.f_bsize);
        let total = filesystem.f_blocks.saturating_mul(fragment);
        let available = filesystem.f_bavail.saturating_mul(fragment);
        let free_floor = total / 5;
        let shortfall = free_floor.saturating_sub(available);
        target = target.min(usage.saturating_sub(shortfall));
    }
    if target == u64::MAX || usage <= target {
        return Ok((0, 0));
    }
    store.evict_durable_cache_to(target)
}

fn materialize_cached(
    store: &Store,
    root: Hash,
    size: u64,
    target: &std::path::Path,
) -> Result<Materialization> {
    let row = store.blob(&root)?.ok_or(StoreError::MissingBlob(root))?;
    if !row.complete || row.size != size {
        return Err(StoreError::MissingBlob(root));
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    static MATERIALIZE_SEQ: AtomicU64 = AtomicU64::new(0);
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "object".to_string());
    let temporary = target.with_file_name(format!(
        ".{name}.{}.{}.synch-materialize",
        std::process::id(),
        MATERIALIZE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let kind = if let Some(inline) = row.inline {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&inline)?;
            file.sync_all()?;
            Materialization::Copy
        } else {
            clone_or_copy(&store.blob_path(&root), &temporary)?
        };
        let materialized_root =
            synch_core::hash_reader(std::io::BufReader::new(std::fs::File::open(&temporary)?))?;
        if materialized_root != root {
            return Err(StoreError::Verification {
                root,
                reason: format!("materialized cache bytes hashed to {materialized_root}"),
            });
        }
        std::fs::rename(&temporary, target)?;
        if let Some(parent) = target.parent() {
            if let Ok(directory) = std::fs::File::open(parent) {
                let _ = directory.sync_all();
            }
        }
        Ok(kind)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn clone_or_copy(source: &std::path::Path, target: &std::path::Path) -> Result<Materialization> {
    let source_file = std::fs::File::open(source)?;
    let target_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(target)?;
    if reflink_file(&source_file, &target_file).is_ok() {
        target_file.sync_all()?;
        return Ok(Materialization::Reflink);
    }
    drop(target_file);
    std::fs::remove_file(target)?;
    let copied = std::fs::copy(source, target)?;
    if copied != source_file.metadata()?.len() {
        return Err(StoreError::invalid(
            "short copy while materializing CAS object",
        ));
    }
    std::fs::File::open(target)?.sync_all()?;
    Ok(Materialization::Copy)
}

fn reflink_file(source: &std::fs::File, dest: &std::fs::File) -> std::io::Result<()> {
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "sparc", target_arch = "sparc64"))
    ))]
    {
        rustix::fs::ioctl_ficlone(dest, source).map_err(std::io::Error::from)
    }
    #[cfg(not(all(
        target_os = "linux",
        not(any(target_arch = "sparc", target_arch = "sparc64"))
    )))]
    {
        let _ = (source, dest);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "reflink is not available on this platform",
        ))
    }
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        operation()
    })
    .await
    .map_err(|error| StoreError::invalid(format!("CAS blocking task failed: {error}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use opendal::{services::Memory, Operator};
    use synch_core::group_count;

    async fn contract(
        backend: Arc<dyn CasBackend>,
        store: Arc<Store>,
        partial_durability: Durability,
    ) {
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("source");
        let payload: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
        std::fs::write(&source, &payload).unwrap();

        let ingested = backend.ingest_file(source, 1).await.unwrap();
        assert_eq!(ingested.root, Hash::new(&payload));
        assert_eq!(ingested.size, payload.len() as u64);
        assert_eq!(ingested.durability, Durability::Durable);
        assert_eq!(
            backend.read_range(ingested.root, 71, 90_000).await.unwrap(),
            payload[71..90_071]
        );
        let requested = ChunkRanges::single(0, group_count(ingested.size));
        let (encoded, served) = backend
            .encode_slice(ingested.root, requested.clone())
            .await
            .unwrap();
        assert_eq!(served, requested);
        assert!(!encoded.is_empty());
        let target = source_dir.path().join("materialized");
        backend
            .materialize(ingested.root, ingested.size, target.clone())
            .await
            .unwrap();
        assert_eq!(std::fs::read(target).unwrap(), payload);
        backend.delete(ingested.root).await.unwrap();
        backend.delete(ingested.root).await.unwrap();
        assert!(store.blob(&ingested.root).unwrap().is_none());

        // Partial commit and finalize use a fresh root after deletion.
        let (_provider_dir, provider_store) = crate::testutil::store();
        let provider_root = provider_store.ingest_bytes(&payload, 2).unwrap();
        let (encoded, served) = provider_store
            .encode_slice(&provider_root, &requested)
            .unwrap();
        let written = backend
            .write_slice(provider_root, payload.len() as u64, served, encoded, 3)
            .await
            .unwrap();
        assert_eq!(written.durability, partial_durability);
        backend
            .finalize(provider_root, payload.len() as u64)
            .await
            .unwrap();
        assert!(store.blob(&provider_root).unwrap().unwrap().durable);

        // Delta proof commitment and donor promotion are backend semantics as
        // well: the engine must never fall through to LocalFs for this path.
        let old: Vec<u8> = (0..200_000)
            .map(|index| ((index * 17 + 3) % 251) as u8)
            .collect();
        let mut new = old.clone();
        new[64 * 1024..80 * 1024].fill(0xa5);
        let donor = backend.ingest_bytes(old, 4).await.unwrap();
        let target_root = provider_store.ingest_bytes(&new, 5).unwrap();
        let target_all = ChunkRanges::single(0, group_count(new.len() as u64));
        let (proof, proof_served) = provider_store
            .encode_proof(&target_root, &target_all, 0, synch_core::MAX_PROOF_NODES)
            .unwrap();
        let proven = backend
            .write_proof(target_root, new.len() as u64, proof_served, 0, proof, 6)
            .await
            .unwrap();
        let promoted = backend.promote(Donor(donor.root), proven, 7).await.unwrap();
        assert!(!promoted.is_empty());
        let missing = target_all.difference(&promoted);
        let (encoded, served) = provider_store.encode_slice(&target_root, &missing).unwrap();
        backend
            .write_slice(target_root, new.len() as u64, served, encoded, 8)
            .await
            .unwrap();
        backend
            .finalize(target_root, new.len() as u64)
            .await
            .unwrap();
        assert_eq!(
            backend
                .read_range(target_root, 0, new.len() as u64)
                .await
                .unwrap(),
            new
        );
    }

    #[tokio::test]
    async fn localfs_passes_the_backend_contract() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let backend: Arc<dyn CasBackend> = Arc::new(LocalFs::new(store.clone()));
        contract(backend, store, Durability::Durable).await;
    }

    #[tokio::test]
    async fn opendal_memory_passes_the_backend_contract() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let objects = CloudStore::from_operator(
            Operator::new(Memory::default()).unwrap(),
            scratch.path().to_path_buf(),
        )
        .unwrap();
        let backend: Arc<dyn CasBackend> = Arc::new(Cloud::new(
            store.clone(),
            objects,
            CloudUploadPolicy::OwnPinned,
            None,
        ));
        contract(backend, store, Durability::Staged).await;
    }

    #[tokio::test]
    async fn cloud_cache_eviction_refill_not_found_and_quarantine_follow_the_contract() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let objects = CloudStore::from_operator(
            Operator::new(Memory::default()).unwrap(),
            scratch.path().to_path_buf(),
        )
        .unwrap();
        let backend = Arc::new(Cloud::new(
            store.clone(),
            objects.clone(),
            CloudUploadPolicy::OwnPinned,
            Some(0),
        ));

        let payload: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
        let ingested = backend.ingest_bytes(payload.clone(), 1).await.unwrap();
        let deleted_payload = vec![0x31; 100_000];
        let deleted = backend.ingest_bytes(deleted_payload, 1).await.unwrap();
        store.delete_blob(&deleted.root).unwrap();
        assert!(objects.read_range(&deleted.root, 0..1).await.is_ok());
        let report = backend
            .maintain(10 * 24 * 60 * 60 * 1_000_000_000)
            .await
            .unwrap();
        assert_eq!(report.cache_entries_evicted, 1);
        assert_eq!(report.remote_deletes_completed, 1);
        assert!(matches!(
            objects.read_range(&deleted.root, 0..1).await,
            Err(StoreError::CloudNotFound { .. })
        ));
        let cold = store.blob(&ingested.root).unwrap().unwrap();
        assert!(cold.durable);
        assert!(!cold.complete);
        let all = ChunkRanges::single(0, group_count(ingested.size));
        let (proof, proved) = backend
            .encode_proof(ingested.root, all.clone(), 0, synch_core::MAX_PROOF_NODES)
            .await
            .unwrap();
        assert_eq!(proved, all);
        assert!(!proof.is_empty());
        assert!(
            store
                .blob(&ingested.root)
                .unwrap()
                .unwrap()
                .verified_groups()
                .is_empty(),
            "serving a cloud proof must not download payload groups"
        );
        assert_eq!(
            backend.read_range(ingested.root, 37, 91_000).await.unwrap(),
            payload[37..91_037]
        );
        let warmed = store.blob(&ingested.root).unwrap().unwrap();
        assert!(
            !warmed.complete,
            "a range read must not hydrate the whole object"
        );
        assert!(warmed.verified_groups().count() < group_count(ingested.size));

        // Scratch corruption is not durable corruption: discard it, refill
        // from the remote object, and serve the verified answer.
        let mut cached = std::fs::read(store.blob_path(&ingested.root)).unwrap();
        cached[40] ^= 0xff;
        std::fs::write(store.blob_path(&ingested.root), cached).unwrap();
        assert_eq!(
            backend.read_range(ingested.root, 37, 91_000).await.unwrap(),
            payload[37..91_037]
        );
        assert!(!store.blob(&ingested.root).unwrap().unwrap().quarantined);

        // A strongly consistent NotFound withdraws the remote durability
        // claim after local cache is removed.
        backend
            .maintain(10 * 24 * 60 * 60 * 1_000_000_000 + 1)
            .await
            .unwrap();
        objects.delete(&ingested.root).await.unwrap();
        assert!(matches!(
            backend.read_range(ingested.root, 0, 1).await,
            Err(StoreError::CloudNotFound { .. })
        ));
        assert!(store.blob(&ingested.root).unwrap().is_none());

        // A present object whose bytes no longer hash to its key is retained
        // remotely for diagnosis but retired from advertisements.
        let second = backend.ingest_bytes(payload.clone(), 2).await.unwrap();
        backend
            .maintain(10 * 24 * 60 * 60 * 1_000_000_000 + 2)
            .await
            .unwrap();
        let corrupt = scratch.path().join("corrupt");
        std::fs::write(&corrupt, vec![0x55; payload.len()]).unwrap();
        objects
            .write_object_file(&CloudStore::payload_key(&second.root), &corrupt)
            .await
            .unwrap();
        assert!(matches!(
            backend.read_range(second.root, 0, 1).await,
            Err(StoreError::Verification { .. })
        ));
        let row = store.blob(&second.root).unwrap().unwrap();
        assert!(row.durable && row.quarantined);
        assert!(store.local_ad(&second.root).unwrap().is_none());

        let third_payload: Vec<u8> = payload.iter().map(|byte| byte ^ 0x3c).collect();
        let third = backend.ingest_bytes(third_payload, 3).await.unwrap();
        backend
            .maintain(10 * 24 * 60 * 60 * 1_000_000_000 + 3)
            .await
            .unwrap();
        let mut bad_outboard = objects.read_outboard(&third.root).await.unwrap().to_vec();
        bad_outboard[0] ^= 0xff;
        let corrupt_outboard = scratch.path().join("corrupt-outboard");
        std::fs::write(&corrupt_outboard, bad_outboard).unwrap();
        objects
            .write_object_file(&CloudStore::outboard_key(&third.root), &corrupt_outboard)
            .await
            .unwrap();
        let third_all = ChunkRanges::single(0, group_count(third.size));
        assert!(matches!(
            backend
                .encode_proof(third.root, third_all, 0, synch_core::MAX_PROOF_NODES,)
                .await,
            Err(StoreError::Verification { .. })
        ));
        assert!(store.blob(&third.root).unwrap().unwrap().quarantined);
    }
}
