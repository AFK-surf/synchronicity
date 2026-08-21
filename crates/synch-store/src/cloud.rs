//! OpenDAL-backed durable object storage (`docs/SERVERLESS.md` §6).
//!
//! Provider APIs stop at this module. The rest of the CAS sees immutable
//! payload/outboard keys, normalized NotFound, and completed writes.

use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use bao_tree::BaoTree;
use bytes::Bytes;
use opendal::{
    layers::{RetryLayer, TimeoutLayer},
    services::{AzblobConfig, GcsConfig, MemoryConfig, S3Config},
    Configurator, ErrorKind, Operator,
};
use tokio::io::AsyncReadExt;

use synch_core::{Hash, CHUNK_GROUP_LOG2};

use crate::{
    cas::{compute_outboard, fsync_file, TeeReader},
    error::{Result, StoreError},
};

const UPLOAD_CHUNK: usize = 8 * 1024 * 1024;
static INGEST_SEQ: AtomicU64 = AtomicU64::new(0);

/// One cloud service admitted by the serverless CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudService {
    /// Amazon S3 or an S3-compatible endpoint.
    S3,
    /// Google Cloud Storage.
    Gcs,
    /// Azure Blob Storage.
    Azblob,
    /// OpenDAL's in-memory service, for the shared contract suite only.
    Memory,
}

/// Which fetched objects a cloud node promotes to remote durability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudUploadPolicy {
    /// Only content ingested locally through detached writes.
    Own,
    /// Locally ingested content plus every object pinned here.
    OwnPinned,
    /// Every object that becomes complete in cache.
    All,
}

impl CloudUploadPolicy {
    /// Stable configuration spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            CloudUploadPolicy::Own => "own",
            CloudUploadPolicy::OwnPinned => "own+pinned",
            CloudUploadPolicy::All => "all",
        }
    }
}

impl CloudService {
    /// The stable configuration name.
    pub fn as_str(self) -> &'static str {
        match self {
            CloudService::S3 => "s3",
            CloudService::Gcs => "gcs",
            CloudService::Azblob => "azblob",
            CloudService::Memory => "memory",
        }
    }
}

/// Provider-neutral OpenDAL construction settings.
///
/// `options` uses the selected OpenDAL service config's field names. It may
/// contain credentials, so `Debug` deliberately prints keys but not values.
#[derive(Clone)]
pub struct CloudConfig {
    /// The OpenDAL service builder to use.
    pub service: CloudService,
    /// Service configuration (bucket/container, root, endpoint, credentials).
    pub options: HashMap<String, String>,
    /// Ephemeral local scratch/cache root.
    pub scratch_dir: PathBuf,
    /// Per-operation I/O timeout.
    pub io_timeout: std::time::Duration,
    /// Promotion policy for peer-fetched content.
    pub upload_policy: CloudUploadPolicy,
    /// Maintenance target for verified local cache bytes. `None` keeps only
    /// the automatic 20%-free filesystem target on Unix.
    pub cache_bytes: Option<u64>,
}

impl std::fmt::Debug for CloudConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys: Vec<&str> = self.options.keys().map(String::as_str).collect();
        keys.sort_unstable();
        f.debug_struct("CloudConfig")
            .field("service", &self.service)
            .field("option_keys", &keys)
            .field("scratch_dir", &self.scratch_dir)
            .field("io_timeout", &self.io_timeout)
            .field("upload_policy", &self.upload_policy)
            .field("cache_bytes", &self.cache_bytes)
            .finish()
    }
}

/// Provider-independent cloud object primitives used by the cloud CAS.
#[derive(Clone)]
pub struct CloudStore {
    operator: Operator,
    scratch_dir: PathBuf,
}

impl std::fmt::Debug for CloudStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let info = self.operator.info();
        f.debug_struct("CloudStore")
            .field("scheme", &info.scheme())
            .field("name", &info.name())
            .field("root", &info.root())
            .field("scratch_dir", &self.scratch_dir)
            .finish()
    }
}

/// Result of a whole-object cloud ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudIngested {
    /// BLAKE3/bao root of the payload.
    pub root: Hash,
    /// Payload length.
    pub size: u64,
}

impl CloudStore {
    /// Builds and capability-checks the configured OpenDAL operator.
    pub fn open(config: &CloudConfig) -> Result<Self> {
        // Default features are deliberately disabled so OpenDAL cannot choose
        // a rustls crypto provider for the process. That also disables its
        // pre-main registry constructor, so install the enabled reqwest
        // transport explicitly. Shipped binaries install the workspace's
        // aws-lc provider before reaching this constructor.
        opendal::install_default();
        let operator = match config.service {
            CloudService::S3 => Operator::from_config(config_from::<S3Config>(&config.options)?),
            CloudService::Gcs => Operator::from_config(config_from::<GcsConfig>(&config.options)?),
            CloudService::Azblob => {
                Operator::from_config(config_from::<AzblobConfig>(&config.options)?)
            }
            CloudService::Memory => {
                Operator::from_config(config_from::<MemoryConfig>(&config.options)?)
            }
        }
        .map_err(|source| cloud("open", "", source))?
        .layer(RetryLayer::default())
        .layer(TimeoutLayer::default().with_io_timeout(config.io_timeout));
        Self::from_operator(operator, config.scratch_dir.clone())
    }

    /// Wraps an operator supplied by a contract test.
    pub(crate) fn from_operator(operator: Operator, scratch_dir: PathBuf) -> Result<Self> {
        let capability = operator.info().capability();
        let mut missing = Vec::new();
        for (name, supported) in [
            ("stat", capability.stat),
            ("read", capability.read),
            ("write", capability.write),
            ("delete", capability.delete),
            ("list", capability.list),
            ("recursive list", capability.list_with_recursive),
        ] {
            if !supported {
                missing.push(name);
            }
        }
        if !missing.is_empty() {
            return Err(StoreError::invalid(format!(
                "OpenDAL service {} lacks required cloud CAS capabilities: {}",
                operator.info().scheme(),
                missing.join(", ")
            )));
        }
        Ok(CloudStore {
            operator,
            scratch_dir,
        })
    }

    /// Returns the immutable payload key for `root`.
    pub fn payload_key(root: &Hash) -> String {
        let hex = root.to_hex();
        format!("cas/{}/{hex}", &hex[..2])
    }

    /// Returns the immutable bao outboard key for `root`.
    pub fn outboard_key(root: &Hash) -> String {
        format!("{}.obao", Self::payload_key(root))
    }

    pub(crate) fn scratch_dir(&self) -> &Path {
        &self.scratch_dir
    }

    /// Stages, hashes, and durably uploads one whole file.
    pub async fn ingest_file(&self, source: &Path) -> Result<CloudIngested> {
        let source = source.to_path_buf();
        let scratch_dir = self.scratch_dir.clone();
        let staged = tokio::task::spawn_blocking(move || stage_and_hash(&source, &scratch_dir))
            .await
            .map_err(|error| {
                StoreError::invalid(format!("cloud ingest worker failed: {error}"))
            })??;

        let payload_key = Self::payload_key(&staged.root);
        let outboard_key = Self::outboard_key(&staged.root);
        let result = async {
            self.write_object_file(&payload_key, &staged.payload)
                .await?;
            self.operator
                .write(&outboard_key, Bytes::from(staged.outboard))
                .await
                .map_err(|source| cloud("write", &outboard_key, source))?;
            Ok(CloudIngested {
                root: staged.root,
                size: staged.size,
            })
        }
        .await;
        let _ = tokio::fs::remove_file(&staged.payload).await;
        result
    }

    /// Durably uploads a small in-memory object and its deterministic outboard.
    pub async fn ingest_bytes(&self, data: &[u8]) -> Result<CloudIngested> {
        let size = data.len() as u64;
        let tree = BaoTree::new(size, bao_tree::BlockSize::from_chunk_log(CHUNK_GROUP_LOG2));
        let mut outboard = vec![0u8; tree.outboard_size() as usize];
        let root = compute_outboard(data, tree, &mut outboard)?;
        let payload_key = Self::payload_key(&root);
        let outboard_key = Self::outboard_key(&root);
        self.operator
            .write(&payload_key, Bytes::copy_from_slice(data))
            .await
            .map_err(|source| cloud("write", &payload_key, source))?;
        self.operator
            .write(&outboard_key, Bytes::from(outboard))
            .await
            .map_err(|source| cloud("write", &outboard_key, source))?;
        Ok(CloudIngested { root, size })
    }

    /// Stores a payload/outboard pair under an already assigned content
    /// address. The caller produced the address when it accepted the object;
    /// storage is trusted after that boundary and is not re-hashed here.
    pub async fn put_pair_files(&self, root: &Hash, payload: &Path, outboard: &Path) -> Result<()> {
        self.write_object_file(&Self::payload_key(root), payload)
            .await?;
        self.write_object_file(&Self::outboard_key(root), outboard)
            .await
    }

    /// Stores an in-memory payload/outboard pair under an assigned address.
    pub async fn put_pair_bytes(&self, root: &Hash, payload: &[u8], outboard: &[u8]) -> Result<()> {
        let payload_key = Self::payload_key(root);
        self.operator
            .write(&payload_key, Bytes::copy_from_slice(payload))
            .await
            .map_err(|source| cloud("write", &payload_key, source))?;
        let outboard_key = Self::outboard_key(root);
        self.operator
            .write(&outboard_key, Bytes::copy_from_slice(outboard))
            .await
            .map_err(|source| cloud("write", &outboard_key, source))?;
        Ok(())
    }

    /// Confirms both durable objects exist and returns the payload length from
    /// authoritative storage metadata. Contents are trusted once acknowledged;
    /// the length binds an untrusted peer's size claim without re-hashing data.
    pub async fn require_pair(&self, root: &Hash) -> Result<u64> {
        let payload = Self::payload_key(root);
        let size = self
            .operator
            .stat(&payload)
            .await
            .map_err(|source| cloud("stat", &payload, source))?
            .content_length();
        let outboard = Self::outboard_key(root);
        self.operator
            .stat(&outboard)
            .await
            .map_err(|source| cloud("stat", &outboard, source))?;
        Ok(size)
    }

    /// Reads one byte range from an immutable payload.
    pub async fn read_range(&self, root: &Hash, range: std::ops::Range<u64>) -> Result<Bytes> {
        let key = Self::payload_key(root);
        self.read_object_range(&key, range).await
    }

    /// Reads the complete outboard object.
    pub async fn read_outboard(&self, root: &Hash) -> Result<Bytes> {
        let key = Self::outboard_key(root);
        let buffer = self
            .operator
            .read(&key)
            .await
            .map_err(|source| cloud("read", &key, source))?;
        Ok(buffer.to_bytes())
    }

    /// Deletes a final pair idempotently for NotFound-path tests. Production
    /// final CAS keys are append-only.
    #[cfg(test)]
    pub(crate) async fn delete(&self, root: &Hash) -> Result<()> {
        for key in [Self::payload_key(root), Self::outboard_key(root)] {
            match self.operator.delete(&key).await {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(source) => return Err(cloud("delete", &key, source)),
            }
        }
        Ok(())
    }

    /// Streams a local file into an arbitrary backend-private object key.
    pub async fn write_object_file(&self, key: &str, source: &Path) -> Result<()> {
        let mut input = tokio::fs::File::open(source).await?;
        let mut writer = self
            .operator
            .writer(key)
            .await
            .map_err(|source| cloud("write", key, source))?;
        let mut buffer = vec![0u8; UPLOAD_CHUNK];
        loop {
            let read = input.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            writer
                .write(Bytes::copy_from_slice(&buffer[..read]))
                .await
                .map_err(|source| cloud("write", key, source))?;
        }
        writer
            .close()
            .await
            .map_err(|source| cloud("write", key, source))?;
        Ok(())
    }

    /// Reads a byte range from an arbitrary backend-private object key.
    pub async fn read_object_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Bytes> {
        let buffer = self
            .operator
            .read_with(key)
            .range(range)
            .await
            .map_err(|source| cloud("read", key, source))?;
        Ok(buffer.to_bytes())
    }

    /// Deletes one arbitrary backend-private key idempotently.
    pub async fn delete_object(&self, key: &str) -> Result<()> {
        match self.operator.delete(key).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(source) => Err(cloud("delete", key, source)),
        }
    }

    /// Recursively deletes every object under a backend-private prefix.
    pub async fn delete_prefix(&self, prefix: &str) -> Result<usize> {
        let entries = self
            .operator
            .list_with(prefix)
            .recursive(true)
            .await
            .map_err(|source| cloud("list", prefix, source))?;
        let mut deleted = 0;
        for entry in entries {
            if !entry.metadata().is_file() {
                continue;
            }
            self.delete_object(entry.path()).await?;
            deleted += 1;
        }
        Ok(deleted)
    }

    /// Removes abandoned local cloud-operation temporaries older than `cutoff`.
    pub(crate) async fn sweep_scratch(&self, cutoff: std::time::SystemTime) -> Result<usize> {
        let scratch = self.scratch_dir.clone();
        tokio::task::spawn_blocking(move || {
            let mut removed = 0;
            let Ok(entries) = std::fs::read_dir(&scratch) else {
                return Ok(0);
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !(name.starts_with("ingest-") || name.starts_with("slice-")) {
                    continue;
                }
                let old = entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .is_ok_and(|modified| modified < cutoff);
                if old && std::fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
            }
            Ok(removed)
        })
        .await
        .map_err(|error| StoreError::invalid(format!("cloud scratch sweep failed: {error}")))?
    }
}

struct Staged {
    root: Hash,
    size: u64,
    payload: PathBuf,
    outboard: Vec<u8>,
}

fn stage_and_hash(source: &Path, scratch_dir: &Path) -> Result<Staged> {
    std::fs::create_dir_all(scratch_dir)?;
    let size = std::fs::metadata(source)?.len();
    let payload = scratch_dir.join(format!(
        "ingest-{}-{}.tmp",
        std::process::id(),
        INGEST_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let staged = (|| {
        let tree = BaoTree::new(size, bao_tree::BlockSize::from_chunk_log(CHUNK_GROUP_LOG2));
        let mut outboard = vec![0u8; tree.outboard_size() as usize];
        let source = File::open(source)?;
        let sink = File::create(&payload)?;
        let root = compute_outboard(
            TeeReader {
                inner: source,
                sink,
            },
            tree,
            &mut outboard,
        )?;
        fsync_file(&std::fs::OpenOptions::new().write(true).open(&payload)?)?;
        Ok(Staged {
            root,
            size,
            payload: payload.clone(),
            outboard,
        })
    })();
    if staged.is_err() {
        let _ = std::fs::remove_file(&payload);
    }
    staged
}

fn config_from<C: Configurator>(options: &HashMap<String, String>) -> Result<C> {
    C::from_iter(options.clone()).map_err(|source| cloud("open", "", source))
}

fn cloud(operation: &'static str, path: &str, source: opendal::Error) -> StoreError {
    if source.kind() == ErrorKind::NotFound {
        StoreError::CloudNotFound {
            path: path.to_string(),
            source: Box::new(source),
        }
    } else {
        StoreError::Cloud {
            operation,
            path: path.to_string(),
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opendal::services::Memory;

    #[tokio::test]
    async fn memory_operator_round_trips_and_deletes_immutable_objects() {
        let scratch = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("payload");
        let payload: Vec<u8> = (0..200_000).map(|n| (n % 251) as u8).collect();
        std::fs::write(&source, &payload).unwrap();
        let cloud = CloudStore::from_operator(
            Operator::new(Memory::default()).unwrap(),
            scratch.path().to_path_buf(),
        )
        .unwrap();

        let ingested = cloud.ingest_file(&source).await.unwrap();
        assert_eq!(ingested.root, Hash::new(&payload));
        assert_eq!(ingested.size, payload.len() as u64);
        assert_eq!(
            cloud.read_range(&ingested.root, 17..91_337).await.unwrap(),
            payload[17..91_337]
        );
        assert!(!cloud
            .read_outboard(&ingested.root)
            .await
            .unwrap()
            .is_empty());
        cloud.delete(&ingested.root).await.unwrap();
        cloud.delete(&ingested.root).await.unwrap();
        assert!(matches!(
            cloud.read_range(&ingested.root, 0..1).await,
            Err(StoreError::CloudNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn scratch_sweep_removes_only_abandoned_cloud_temporaries() {
        let scratch = tempfile::tempdir().unwrap();
        let cloud = CloudStore::from_operator(
            Operator::new(Memory::default()).unwrap(),
            scratch.path().to_path_buf(),
        )
        .unwrap();
        for name in ["ingest-dead.tmp", "slice-dead", "keep-me"] {
            std::fs::write(scratch.path().join(name), b"temporary").unwrap();
        }
        let removed = cloud
            .sweep_scratch(std::time::SystemTime::now() + std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(removed, 2);
        assert!(scratch.path().join("keep-me").exists());
    }
}
