//! Object-safe async CAS backend contract (`docs/SERVERLESS.md` §3).
//!
//! This module is the migration boundary around the legacy synchronous
//! `Store` CAS. `LocalFs` centralizes its blocking handoff; `Cloud` adds the
//! remote durability promise while retaining the same cache codec.

use std::{
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use synch_core::{group_count, groups_for_byte_range, ChunkRanges, Hash, CHUNK_GROUP_SIZE};

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
    /// Makes a durable cold object readable from local cache.
    async fn ensure_cached(&self, root: Hash, size: u64) -> Result<()>;
    /// Makes selected durable groups readable from local cache.
    async fn ensure_ranges(&self, root: Hash, size: u64, ranges: ChunkRanges) -> Result<()>;
    /// Encodes a bao slice and the ranges actually served.
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
    /// Reads one byte range.
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
    /// Writes a complete object to a local target atomically.
    async fn materialize(&self, root: Hash, size: u64, target: PathBuf) -> Result<Materialization>;
    /// Deletes the local claim/cache; LocalFs also removes its private bytes,
    /// while Cloud keeps globally addressed final objects append-only.
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

/// OpenDAL durable CAS plus the shared local cache codec.
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
        #[cfg(not(unix))]
        if cache_bytes.is_none() {
            return Err(StoreError::invalid(
                "cloud CAS requires an explicit cache_bytes target on non-Unix platforms",
            ));
        }
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
                Some(row) if row.durable => Durability::Durable,
                _ => Durability::Staged,
            })
        })
        .await
    }

    async fn adopt_remote_if_present(&self, root: Hash, size: u64) -> Result<bool> {
        let store = self.store.clone();
        let mut replace_claim = false;
        if let Some(row) = blocking(move || store.blob(&root)).await? {
            if row.size != size {
                let attested = row.durable
                    || row.complete
                    || row
                        .verified_groups()
                        .contains(group_count(row.size).saturating_sub(1));
                if attested {
                    return Err(StoreError::invalid(format!(
                        "size mismatch for {root}: have {}, offered {size}",
                        row.size
                    )));
                }
                replace_claim = true;
            }
            if row.durable {
                return Ok(true);
            }
        }
        match self.objects.require_pair(&root).await {
            Ok(stored_size) => {
                if stored_size != size {
                    return Err(StoreError::invalid(format!(
                        "size mismatch for {root}: storage has {stored_size}, offered {size}"
                    )));
                }
                if replace_claim {
                    let store = self.store.clone();
                    if !blocking(move || store.clear_blob_cache(&root)).await? {
                        return Err(StoreError::invalid(
                            "stale size claim changed while the object was being written",
                        ));
                    }
                }
                let store = self.store.clone();
                blocking(move || store.adopt_durable_blob(&root, size, synch_core::now_ns()))
                    .await?;
                Ok(true)
            }
            Err(StoreError::CloudNotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Finds an object's size from SQLite, or reconstructs a cold row directly
    /// from its content-addressed final keys. Peer-serving requests carry no
    /// size hint, so this is the restored-database path for encode/read calls.
    async fn durable_size_or_adopt(&self, root: Hash) -> Result<u64> {
        let store = self.store.clone();
        if let Some(size) =
            blocking(move || store.blob(&root).map(|row| row.map(|row| row.size))).await?
        {
            return Ok(size);
        }
        let store = self.store.clone();
        if let Some(size) =
            blocking(move || store.blob(&root).map(|row| row.map(|row| row.size))).await?
        {
            return Ok(size);
        }
        let store = self.store.clone();
        let size = blocking(move || {
            let Some(ours) = store.self_origin()? else {
                return Ok(None);
            };
            Ok(store
                .providers(&root)?
                .into_iter()
                .find(|(origin, ad)| origin == &ours && ad.is_complete())
                .map(|(_, ad)| ad.size))
        })
        .await?
        .ok_or(StoreError::MissingBlob(root))?;
        let stored_size = self.objects.require_pair(&root).await?;
        if stored_size != size {
            return Err(StoreError::invalid(format!(
                "size mismatch for {root}: storage has {stored_size}, advertised {size}"
            )));
        }
        let store = self.store.clone();
        blocking(move || store.adopt_durable_blob(&root, size, synch_core::now_ns())).await?;
        Ok(size)
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
        // Keep maintenance from evicting an earlier window or the cached
        // outboard while this hydration is still assembling the requested
        // ranges. The lease holds no SQLite connection across these awaits.
        let _hydrating = self.store.lease_write(&root);
        self.outboard_bytes(root).await?;
        if size == 0 {
            let store = self.store.clone();
            blocking(move || {
                store.cache_trusted_range(&root, size, 0, &[], synch_core::now_ns())?;
                Ok(())
            })
            .await?;
            return Ok(());
        }
        const WINDOW: u64 = 8 * 1024 * 1024;
        for range in &ranges.ranges {
            let mut offset = range.start.saturating_mul(CHUNK_GROUP_SIZE);
            let end = range.end.saturating_mul(CHUNK_GROUP_SIZE).min(size);
            while offset < end {
                let window_end = offset.saturating_add(WINDOW).min(end);
                let bytes = match self.objects.read_range(&root, offset..window_end).await {
                    Ok(bytes) => bytes,
                    Err(error @ StoreError::CloudNotFound { .. }) => {
                        let store = self.store.clone();
                        blocking(move || store.heal_missing_durable_blob(&root).map(|_| ()))
                            .await?;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
                let store = self.store.clone();
                let bytes = bytes.to_vec();
                blocking(move || {
                    store.cache_trusted_range(&root, size, offset, &bytes, synch_core::now_ns())?;
                    Ok(())
                })
                .await?;
                offset = window_end;
            }
        }
        Ok(())
    }

    async fn outboard_bytes(&self, root: Hash) -> Result<Vec<u8>> {
        let store = self.store.clone();
        if let Some(cached) = blocking(move || Ok(store.cached_outboard(&root))).await? {
            return Ok(cached);
        }
        self.remote_outboard_bytes(root).await
    }

    async fn remote_outboard_bytes(&self, root: Hash) -> Result<Vec<u8>> {
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
        blocking(move || store.cache_outboard(&root, &cached)).await?;
        Ok(outboard)
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
        self.finalize(root, size).await?;
        Ok(Ingested {
            root,
            size,
            durability: Durability::Durable,
        })
    }

    async fn ingest_file(&self, path: PathBuf, now: i64) -> Result<Ingested> {
        let store = self.store.clone();
        let (root, size) = blocking(move || store.ingest_file(&path, now)).await?;
        self.finalize(root, size).await?;
        Ok(Ingested {
            root,
            size,
            durability: Durability::Durable,
        })
    }

    async fn ensure_cached(&self, root: Hash, size: u64) -> Result<()> {
        let store = self.store.clone();
        let row = blocking(move || store.blob(&root)).await?;
        let row = match row {
            Some(row) => row,
            None if self.adopt_remote_if_present(root, size).await? => {
                let store = self.store.clone();
                blocking(move || store.blob(&root))
                    .await?
                    .ok_or(StoreError::MissingBlob(root))?
            }
            None => return Err(StoreError::MissingBlob(root)),
        };
        if row.durable && row.size != size {
            return Err(StoreError::invalid(format!(
                "size mismatch for {root}: have {}, offered {size}",
                row.size
            )));
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
            if !blocking(move || store.clear_blob_cache(&root)).await? {
                return Err(StoreError::invalid(
                    "the cloud cache is currently being filled by another operation",
                ));
            }
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
        let row = match row {
            Some(row) => row,
            None if self.adopt_remote_if_present(root, size).await? => {
                let store = self.store.clone();
                blocking(move || store.blob(&root))
                    .await?
                    .ok_or(StoreError::MissingBlob(root))?
            }
            None => return Ok(()),
        };
        if row.durable && row.size != size {
            return Err(StoreError::invalid(format!(
                "size mismatch for {root}: have {}, offered {size}",
                row.size
            )));
        }
        if !row.durable && !self.adopt_remote_if_present(root, size).await? {
            return Ok(());
        }
        if row.inline.is_some() {
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
        let size = self.durable_size_or_adopt(root).await?;
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
        let result = blocking(move || store.encode_slice(&root, &requested)).await;
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
        let size = self.durable_size_or_adopt(root).await?;
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
        let result = blocking(move || store.read_range(&root, offset, len)).await;
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
        let size = self.durable_size_or_adopt(root).await?;
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
        let outboard = self.outboard_bytes(root).await?;
        let result = {
            let requested = requested.clone();
            blocking(move || {
                Store::encode_complete_proof(root, size, &requested, level, budget, outboard)
            })
            .await
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
        let mut row = blocking(move || store.blob(&root))
            .await?
            .ok_or(StoreError::MissingBlob(root))?;
        if row.size != size {
            return Err(StoreError::invalid(format!(
                "size mismatch for {root}: have {}, offered {size}",
                row.size
            )));
        }
        if row.durable {
            match self.objects.require_pair(&root).await {
                Ok(stored_size) if stored_size == size => return Ok(()),
                Ok(stored_size) => {
                    return Err(StoreError::invalid(format!(
                        "size mismatch for {root}: storage has {stored_size}, row has {size}"
                    )))
                }
                Err(error @ StoreError::CloudNotFound { .. }) => {
                    let store = self.store.clone();
                    blocking(move || store.heal_missing_durable_blob(&root).map(|_| ())).await?;
                    if !row.complete && row.inline.is_none() {
                        return Err(error);
                    }
                    row.durable = false;
                }
                Err(error) => return Err(error),
            }
        }
        if !row.complete && row.inline.is_none() {
            return if row.durable {
                Err(StoreError::MissingBlob(root))
            } else {
                Ok(())
            };
        }
        match row.inline.as_deref() {
            Some(bytes) => self.objects.put_pair_bytes(&root, bytes, &[]).await?,
            None => {
                self.objects
                    .put_pair_files(
                        &root,
                        &self.store.blob_path(&root),
                        &self.store.outboard_path(&root),
                    )
                    .await?
            }
        };
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
        let result = blocking(move || materialize_cached(&store, root, size, &target)).await;
        if result.is_ok() {
            self.touch(root).await?;
        }
        result
    }

    async fn delete(&self, root: Hash) -> Result<()> {
        let store = self.store.clone();
        blocking(move || store.delete_blob(&root)).await
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

        let store = self.store.clone();
        let cache_bytes = self.cache_bytes;
        let (mut local_orphans, cache_entries_evicted, cache_bytes_evicted) = blocking(move || {
            let local_orphans = store.gc_orphans(now.saturating_sub(7 * DAY_NS))?;
            let (cache_entries_evicted, cache_bytes_evicted) =
                enforce_cache_limit(&store, cache_bytes)?;
            Ok((local_orphans, cache_entries_evicted, cache_bytes_evicted))
        })
        .await?;
        let scratch_cutoff = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(HORIZON_SECONDS as u64))
            .unwrap_or(std::time::UNIX_EPOCH);
        local_orphans += self.objects.sweep_scratch(scratch_cutoff).await?;
        Ok(MaintenanceReport {
            local_orphans,
            cache_entries_evicted,
            cache_bytes_evicted,
        })
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
        crate::cas::replace_file(&temporary, target)?;
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
    std::fs::copy(source, target)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(target)?
        .sync_all()?;
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
        std::fs::write(&target, b"replace me").unwrap();
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
        let origin = crate::testutil::origin();
        store.set_self_origin(&origin).unwrap();
        let objects = CloudStore::from_operator(
            Operator::new(Memory::default()).unwrap(),
            scratch.path().to_path_buf(),
        )
        .unwrap();
        let backend: Arc<dyn CasBackend> = Arc::new(Cloud::new(
            store.clone(),
            objects.clone(),
            CloudUploadPolicy::OwnPinned,
            None,
        ));
        contract(backend.clone(), store.clone(), Durability::Staged).await;

        let inline = backend
            .ingest_bytes(b"inline must reach OpenDAL".to_vec(), 9)
            .await
            .unwrap();
        assert!(store.blob(&inline.root).unwrap().unwrap().durable);
        store
            .put_provider(
                &inline.root,
                &origin,
                &synch_core::BlobAd::complete(inline.size),
            )
            .unwrap();
        assert_eq!(
            objects
                .read_range(&inline.root, 0..inline.size)
                .await
                .unwrap(),
            b"inline must reach OpenDAL".as_slice()
        );
        store.delete_blob(&inline.root).unwrap();
        assert_eq!(
            backend
                .read_range(inline.root, 0, inline.size)
                .await
                .unwrap(),
            b"inline must reach OpenDAL"
        );

        let restored_payload = vec![0x2a; 100_000];
        let restored = backend
            .ingest_bytes(restored_payload.clone(), 10)
            .await
            .unwrap();
        store
            .put_provider(
                &restored.root,
                &origin,
                &synch_core::BlobAd::complete(restored.size),
            )
            .unwrap();
        // Shape an older SQLite restore: final cloud keys survived, but the
        // row naming their durability did not.
        store.delete_blob(&restored.root).unwrap();
        assert!(store.blob(&restored.root).unwrap().is_none());
        let (encoded, served) = backend
            .encode_slice(restored.root, ChunkRanges::single(0, 1))
            .await
            .unwrap();
        assert_eq!(served, ChunkRanges::single(0, 1));
        assert!(!encoded.is_empty());
        let readopted = store.blob(&restored.root).unwrap().unwrap();
        assert!(readopted.durable);
        assert_eq!(readopted.size, restored.size);
        assert_eq!(
            backend
                .read_range(restored.root, 0, restored.size)
                .await
                .unwrap(),
            restored_payload
        );
        store.delete_blob(&restored.root).unwrap();
        let all = ChunkRanges::single(0, group_count(restored.size));
        let (proof, proved) = backend
            .encode_proof(restored.root, all.clone(), 0, synch_core::MAX_PROOF_NODES)
            .await
            .unwrap();
        assert_eq!(proved, all);
        assert!(!proof.is_empty());

        let claimed_payload = vec![0x61; 120_000];
        let claimed = objects.ingest_bytes(&claimed_payload).await.unwrap();
        store
            .commit_groups(
                &claimed.root,
                claimed.size + 1,
                &ChunkRanges::empty(),
                None,
                11,
            )
            .unwrap();
        backend
            .ensure_ranges(claimed.root, claimed.size, ChunkRanges::empty())
            .await
            .unwrap();
        let corrected = store.blob(&claimed.root).unwrap().unwrap();
        assert_eq!(corrected.size, claimed.size);
        assert!(corrected.durable);

        // Storage metadata, not a peer's entry, is authoritative when a cold
        // final pair has no SQLite row after restore.
        let rowless = objects.ingest_bytes(&vec![0x72; 100_000]).await.unwrap();
        assert!(matches!(
            backend
                .ensure_ranges(rowless.root, rowless.size + 1, ChunkRanges::empty())
                .await,
            Err(StoreError::Invalid(_))
        ));
        assert!(store.blob(&rowless.root).unwrap().is_none());
        backend
            .ensure_ranges(rowless.root, rowless.size, ChunkRanges::empty())
            .await
            .unwrap();
        let adopted = store.blob(&rowless.root).unwrap().unwrap();
        assert_eq!(adopted.size, rowless.size);
        assert!(adopted.durable);
    }

    #[tokio::test]
    async fn cloud_final_objects_are_append_only_across_shared_nodes() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a_scratch = tempfile::tempdir().unwrap();
        let b_scratch = tempfile::tempdir().unwrap();
        let a_store = Arc::new(Store::open(a_dir.path()).unwrap());
        let b_store = Arc::new(Store::open(b_dir.path()).unwrap());
        let operator = Operator::new(Memory::default()).unwrap();
        let a_objects =
            CloudStore::from_operator(operator.clone(), a_scratch.path().to_path_buf()).unwrap();
        let b_objects =
            CloudStore::from_operator(operator, b_scratch.path().to_path_buf()).unwrap();
        let a = Cloud::new(
            a_store.clone(),
            a_objects,
            CloudUploadPolicy::OwnPinned,
            Some(0),
        );
        let b = Cloud::new(
            b_store.clone(),
            b_objects,
            CloudUploadPolicy::OwnPinned,
            Some(0),
        );
        let payload = vec![0x41; 100_000];
        let a_object = a.ingest_bytes(payload.clone(), 1).await.unwrap();
        let b_object = b.ingest_bytes(payload.clone(), 1).await.unwrap();
        assert_eq!(a_object, b_object);

        b.maintain(10 * 24 * 60 * 60 * 1_000_000_000).await.unwrap();
        assert!(!b_store.blob(&b_object.root).unwrap().unwrap().complete);
        a.delete(a_object.root).await.unwrap();
        a.maintain(10 * 24 * 60 * 60 * 1_000_000_000).await.unwrap();
        assert!(a_store.blob(&a_object.root).unwrap().is_none());
        assert_eq!(
            b.read_range(b_object.root, 0, b_object.size).await.unwrap(),
            payload
        );
        assert!(b_store.blob(&b_object.root).unwrap().unwrap().durable);
    }

    #[tokio::test]
    async fn cloud_cache_eviction_refill_and_not_found_follow_the_contract() {
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
        assert!(objects.read_range(&deleted.root, 0..1).await.is_ok());
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

        let wrong_size = ingested.size + 1;
        assert!(matches!(
            backend
                .ensure_ranges(ingested.root, wrong_size, ChunkRanges::single(0, 1))
                .await,
            Err(StoreError::Invalid(_))
        ));
        let unchanged = store.blob(&ingested.root).unwrap().unwrap();
        assert_eq!(unchanged.size, ingested.size);
        assert!(unchanged.durable);

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
        backend
            .encode_proof(ingested.root, all.clone(), 0, synch_core::MAX_PROOF_NODES)
            .await
            .unwrap();
        assert_eq!(
            backend.read_range(ingested.root, 37, 91_000).await.unwrap(),
            payload[37..91_037]
        );

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
    }
}
