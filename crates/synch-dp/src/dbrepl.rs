//! The in-process database replicator (`docs/CLOUD-DATAPLANE.md` §5.3).
//!
//! Every tenant's SQLite database lives on an ephemeral volume, so the copy
//! that survives is the one in object storage. This module is what puts it
//! there: a WAL-shipping replicator, one per tenant, over the same OpenDAL
//! operator the CAS uses.
//!
//! # The generation model
//!
//! ```text
//! db/<org>/<network>/
//!   <generation>/snapshot                  a whole database file
//!   <generation>/wal/<index>.<off>.<len>   WAL bytes appended since it
//! ```
//!
//! A *generation* is one database file plus the write-ahead log that grew on
//! top of it. Restoring is therefore: take the snapshot, lay the log back
//! beside it, and let SQLite recover — no bespoke replay, and no format of our
//! own that could disagree with SQLite about what a committed transaction is.
//!
//! The reason a generation ever ends is that a WAL only makes sense on top of
//! the database file it grew from. Checkpointing moves frames *into* that file
//! and restarts the log, so the old log no longer describes anything: the
//! moment we checkpoint, the old generation is closed and a new snapshot opens
//! the next one. This is why the replicator owns checkpointing outright
//! ([`synch_store::Checkpointing::Embedder`]) — a checkpoint it did not
//! schedule would recycle frames it has not shipped, and the stream would have
//! a hole in it that nothing could detect.
//!
//! Generation ids sort chronologically (nanoseconds, zero-padded, then random
//! bytes to break ties), so "the newest generation" is a lexicographic maximum
//! over a listing — no index to keep consistent, and no metadata object whose
//! absence would strand a perfectly good stream.
//!
//! # What a torn stream costs
//!
//! Nothing that is not already survivable. Segments are named with the offset
//! they start at, so restore assembles a *contiguous prefix* and stops at the
//! first gap. A prefix of a WAL is a valid WAL: SQLite checksums every frame
//! and replays up to the last commit frame it can verify, which means a
//! half-uploaded segment costs the transactions inside it and nothing before
//! them. That is the same bound as an unclean shutdown, which the node already
//! survives (`docs/SERVERLESS.md` §8.3).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::error::{DpError, Result};
use crate::store::ObjectStore;

/// The WAL header, which every generation's first segment must start with.
const WAL_HEADER_LEN: u64 = 32;

/// Bytes of frame header in front of each page in the log.
const WAL_FRAME_HEADER_LEN: u64 = 24;

/// How large the log may grow before the replicator rolls a generation.
///
/// The tradeoff is restore time against snapshot cost: a bigger log means
/// fewer whole-database uploads and a longer replay. 64 MiB of WAL replays in
/// well under the time it takes to download the snapshot it sits on, so this
/// is comfortably on the cheap side of the curve.
const DEFAULT_WAL_ROLL_BYTES: u64 = 64 * 1024 * 1024;

/// How often the replicator looks for new frames.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);

/// Settings for one tenant's replica stream.
#[derive(Debug, Clone)]
pub struct ReplicatorConfig {
    /// Key prefix for this tenant's stream, e.g. `db/acme/prod`.
    pub prefix: String,
    /// How often to ship.
    pub interval: Duration,
    /// WAL size at which to roll a generation.
    pub wal_roll_bytes: u64,
}

impl ReplicatorConfig {
    /// The defaults, for a stream under `prefix`.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            interval: DEFAULT_INTERVAL,
            wal_roll_bytes: DEFAULT_WAL_ROLL_BYTES,
        }
    }
}

/// One tenant's replica stream.
#[derive(Debug)]
pub struct Replicator {
    objects: ObjectStore,
    config: ReplicatorConfig,
    store: Arc<synch_store::Store>,
    /// The generation being written, and how far into its log we have shipped.
    generation: String,
    shipped: u64,
    /// The next segment index within the generation.
    next_index: u64,
    /// The log's salt when the generation opened. A change means SQLite reset
    /// the log under us, which — since we own checkpointing — should not
    /// happen; if it does, the generation is closed rather than corrupted.
    salt: Option<[u8; 8]>,
    /// Page size, read from the log header, needed to find frame boundaries.
    page_size: Option<u64>,
}

impl Replicator {
    /// Opens a stream for a database that is already open in `store`.
    ///
    /// Takes the first snapshot before returning, so a caller that starts a
    /// replicator has a complete copy in the bucket by the time it does — the
    /// window where a tenant exists and is unreplicated closes here rather
    /// than at the first tick.
    pub async fn start(
        objects: ObjectStore,
        config: ReplicatorConfig,
        store: Arc<synch_store::Store>,
    ) -> Result<Self> {
        let mut replicator = Self {
            objects,
            config,
            store,
            generation: String::new(),
            shipped: 0,
            next_index: 0,
            salt: None,
            page_size: None,
        };
        replicator.roll_generation().await?;
        Ok(replicator)
    }

    /// The generation currently being written.
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// Bytes of log shipped in this generation.
    pub fn shipped_bytes(&self) -> u64 {
        self.shipped
    }

    /// Closes the current generation and opens a new one on a fresh snapshot.
    ///
    /// The checkpoint comes first and must reach [`CheckpointMode::Truncate`]:
    /// it moves every frame into the database file, which is what makes the
    /// file about to be uploaded a complete database, and it empties the log
    /// so the next generation's frames start at offset zero of a log whose
    /// header the first segment carries.
    async fn roll_generation(&mut self) -> Result<()> {
        let store = self.store.clone();
        // A reader can hold the log open; the checkpoint then reports busy
        // rather than failing, and the retry is the whole recovery.
        for attempt in 0..CHECKPOINT_ATTEMPTS {
            let report = synch_core::offload({
                let store = store.clone();
                move || store.checkpoint(CheckpointMode::Truncate)
            })
            .await?;
            if !report.busy {
                break;
            }
            if attempt + 1 == CHECKPOINT_ATTEMPTS {
                // Not fatal: the snapshot is still consistent (the database
                // file is only ever mutated by a checkpoint, and we are the
                // only checkpointer), it just carries fewer transactions and
                // the log it starts from is not empty. Recorded because a
                // permanently busy database is a bug worth seeing.
                tracing::warn!(
                    prefix = %self.config.prefix,
                    "checkpoint stayed busy; snapshotting over a non-empty log"
                );
            }
            tokio::time::sleep(CHECKPOINT_RETRY).await;
        }

        let generation = new_generation_id();
        let db_path = self.store.db_path();
        let snapshot = tokio::fs::read(&db_path)
            .await
            .map_err(|error| DpError::io("reading the database for a snapshot", error))?;
        let key = format!("{}/{generation}/snapshot", self.config.prefix);
        self.objects.put(&key, snapshot).await?;

        tracing::info!(
            prefix = %self.config.prefix,
            generation = %generation,
            "opened a database replica generation"
        );
        self.generation = generation;
        self.shipped = 0;
        self.next_index = 0;
        self.salt = None;
        self.page_size = None;
        Ok(())
    }

    /// Ships every complete frame appended since the last call.
    ///
    /// Returns how many bytes went up. Rolls a generation when the log has
    /// grown past the configured ceiling.
    pub async fn tick(&mut self) -> Result<u64> {
        let wal_path = self.store.wal_path();
        let Some(len) = file_len(&wal_path).await? else {
            // No log at all: nothing has been written since the generation
            // opened. Not an error, and not a state to correct.
            return Ok(0);
        };
        if len < WAL_HEADER_LEN {
            return Ok(0);
        }
        let header = read_at(&wal_path, 0, WAL_HEADER_LEN as usize).await?;
        let salt: [u8; 8] = header[16..24]
            .try_into()
            .expect("the WAL header is 32 bytes and 16..24 is inside it");
        let page_size = u32::from_be_bytes(
            header[8..12]
                .try_into()
                .expect("the WAL header is 32 bytes and 8..12 is inside it"),
        ) as u64;
        if page_size == 0 {
            return Ok(0);
        }

        match self.salt {
            None => {
                self.salt = Some(salt);
                self.page_size = Some(page_size);
            }
            Some(known) if known != salt => {
                // Somebody else checkpointed, or SQLite reset the log. Every
                // frame after this point belongs to a log our segments do not
                // describe, so the honest move is a new generation rather than
                // shipping bytes that will not replay.
                tracing::warn!(
                    prefix = %self.config.prefix,
                    "the write-ahead log was reset underneath the replicator; rolling"
                );
                return self.roll_generation().await.map(|()| 0);
            }
            Some(_) => {}
        }

        let frame = WAL_FRAME_HEADER_LEN + page_size;
        // Only whole frames: a partially written one is a frame SQLite has not
        // committed to, and shipping it would put bytes in the stream that the
        // next segment would then overlap.
        let complete = WAL_HEADER_LEN + ((len - WAL_HEADER_LEN) / frame) * frame;
        // `shipped` is zero for a fresh generation, so the first segment
        // starts at zero and carries the log header — which is what makes the
        // assembled file a WAL rather than a pile of frames.
        let start = self.shipped;
        if complete <= start {
            return Ok(0);
        }
        let payload = read_at(&wal_path, start, (complete - start) as usize).await?;
        let shipped = payload.len() as u64;
        let key = format!(
            "{}/{}/wal/{:08}.{}.{}",
            self.config.prefix, self.generation, self.next_index, start, shipped
        );
        self.objects.put(&key, payload).await?;
        self.next_index += 1;
        self.shipped = complete;

        if complete >= self.config.wal_roll_bytes {
            self.roll_generation().await?;
        }
        Ok(shipped)
    }

    /// Ships everything outstanding. The last thing a draining tenant does.
    pub async fn flush(&mut self) -> Result<()> {
        self.tick().await.map(|_| ())
    }
}

/// How many times a generation roll retries a busy checkpoint.
const CHECKPOINT_ATTEMPTS: usize = 5;

/// How long it waits between those attempts.
const CHECKPOINT_RETRY: Duration = Duration::from_millis(200);

use synch_store::CheckpointMode;

/// Mints a generation id that sorts chronologically.
///
/// Nanoseconds zero-padded to twenty digits (which covers every timestamp a
/// 64-bit nanosecond clock can produce), then random bytes so two generations
/// opened in the same nanosecond — a restore racing the process that is being
/// replaced — cannot collide.
fn new_generation_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut random = [0u8; 8];
    // Failure here would mean the system RNG is gone, which is not a condition
    // this process can improve on; the timestamp alone still orders correctly.
    let _ = aws_lc_rs::rand::fill(&mut random);
    format!("{nanos:020}-{}", hex::encode(random))
}

/// A restored database, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// The generation it was assembled from.
    pub generation: String,
    /// Bytes of log laid back beside the snapshot.
    pub wal_bytes: u64,
    /// Segments that were on the far side of a gap, and so left out.
    pub segments_skipped: usize,
}

/// Restores the newest usable generation into `data_dir`.
///
/// Returns `None` when the stream holds nothing restorable — a network never
/// hosted before, or one whose stream has been deleted. That is the signal to
/// initialize a fresh node, and it is deliberately distinguishable from an
/// error: "there is nothing here" and "I could not tell" must not lead to the
/// same action, because one of them silently replaces an identity.
pub async fn restore(
    objects: &ObjectStore,
    prefix: &str,
    data_dir: &Path,
) -> Result<Option<RestoreReport>> {
    let generations = objects.list_dirs(&format!("{prefix}/")).await?;
    // Newest first: ids sort chronologically by construction.
    let mut candidates: Vec<String> = generations;
    candidates.sort();
    candidates.reverse();

    for generation in candidates {
        let snapshot_key = format!("{prefix}/{generation}/snapshot");
        let Some(snapshot) = objects.get_if_present(&snapshot_key).await? else {
            // A generation whose snapshot never landed (the process died
            // between opening it and uploading) describes nothing. Skip to the
            // one before it, which is complete.
            tracing::warn!(%generation, "replica generation has no snapshot; skipping it");
            continue;
        };

        let (wal, segments_skipped) = assemble_wal(objects, prefix, &generation).await?;
        std::fs::create_dir_all(data_dir)
            .map_err(|error| DpError::io("creating the tenant data directory", error))?;
        let db_path = data_dir.join(synch_store::DB_FILE);
        let wal_bytes = wal.len() as u64;
        tokio::fs::write(&db_path, &snapshot)
            .await
            .map_err(|error| DpError::io("writing the restored database", error))?;
        let wal_path = wal_path_for(&db_path);
        if wal.is_empty() {
            // Leave no stale log beside a fresh snapshot.
            let _ = tokio::fs::remove_file(&wal_path).await;
        } else {
            tokio::fs::write(&wal_path, &wal)
                .await
                .map_err(|error| DpError::io("writing the restored write-ahead log", error))?;
        }
        // The -shm file is derived state SQLite rebuilds; a stale one from a
        // previous life of this directory would describe the wrong log.
        let _ = tokio::fs::remove_file(shm_path_for(&db_path)).await;

        tracing::info!(
            %generation,
            wal_bytes,
            segments_skipped,
            "restored a tenant database from its replica stream"
        );
        return Ok(Some(RestoreReport {
            generation,
            wal_bytes,
            segments_skipped,
        }));
    }
    Ok(None)
}

/// Concatenates a generation's log segments into a contiguous prefix.
///
/// Segments are named `<index>.<offset>.<len>`, so the offset each one claims
/// is checked against the length assembled so far. The first that does not
/// continue the run ends the assembly: everything after it is unreachable,
/// because a WAL with a hole in it is not a WAL.
async fn assemble_wal(
    objects: &ObjectStore,
    prefix: &str,
    generation: &str,
) -> Result<(Vec<u8>, usize)> {
    let mut segments: Vec<(u64, u64, u64, String)> = Vec::new();
    for key in objects.list(&format!("{prefix}/{generation}/wal/")).await? {
        let name = key.rsplit('/').next().unwrap_or_default();
        let mut parts = name.split('.');
        let (Some(index), Some(offset), Some(len)) = (parts.next(), parts.next(), parts.next())
        else {
            tracing::warn!(%key, "ignoring an unparseable replica segment name");
            continue;
        };
        let (Ok(index), Ok(offset), Ok(len)) = (
            index.parse::<u64>(),
            offset.parse::<u64>(),
            len.parse::<u64>(),
        ) else {
            tracing::warn!(%key, "ignoring an unparseable replica segment name");
            continue;
        };
        segments.push((index, offset, len, key));
    }
    segments.sort_by_key(|(index, _, _, _)| *index);

    let mut wal: Vec<u8> = Vec::new();
    let mut skipped = 0usize;
    let mut ended = false;
    for (_, offset, len, key) in segments {
        if ended {
            skipped += 1;
            continue;
        }
        if offset != wal.len() as u64 {
            // The gap. Everything from here on is unusable, but what came
            // before is a valid shorter log.
            tracing::warn!(
                %key,
                expected = wal.len(),
                found = offset,
                "replica segment does not continue the log; truncating here"
            );
            ended = true;
            skipped += 1;
            continue;
        }
        let Some(bytes) = objects.get_if_present(&key).await? else {
            tracing::warn!(%key, "replica segment vanished between listing and read");
            ended = true;
            skipped += 1;
            continue;
        };
        if bytes.len() as u64 != len {
            // A short object is a torn upload. SQLite would stop at the first
            // frame that fails its checksum anyway; stopping here is the same
            // outcome, reached deliberately.
            tracing::warn!(%key, expected = len, found = bytes.len(), "replica segment is short");
            ended = true;
            skipped += 1;
            continue;
        }
        wal.extend_from_slice(&bytes);
    }
    Ok((wal, skipped))
}

/// The log beside a database file.
fn wal_path_for(db_path: &Path) -> PathBuf {
    sidecar(db_path, "-wal")
}

/// The shared-memory index beside a database file.
fn shm_path_for(db_path: &Path) -> PathBuf {
    sidecar(db_path, "-shm")
}

fn sidecar(db_path: &Path, suffix: &str) -> PathBuf {
    let mut name = db_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push_str(suffix);
    db_path.with_file_name(name)
}

/// The length of a file, or `None` when it does not exist.
async fn file_len(path: &Path) -> Result<Option<u64>> {
    match tokio::fs::metadata(path).await {
        Ok(meta) => Ok(Some(meta.len())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(DpError::io("reading the write-ahead log's size", error)),
    }
}

/// Reads exactly `len` bytes at `offset`.
async fn read_at(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| DpError::io("opening the write-ahead log", error))?;
    file.seek(io::SeekFrom::Start(offset))
        .await
        .map_err(|error| DpError::io("seeking the write-ahead log", error))?;
    let mut buffer = vec![0u8; len];
    file.read_exact(&mut buffer)
        .await
        .map_err(|error| DpError::io("reading the write-ahead log", error))?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_store(dir: &Path) -> Arc<synch_store::Store> {
        Arc::new(
            synch_store::Store::open_with(
                dir,
                synch_store::StoreOptions {
                    checkpointing: synch_store::Checkpointing::Embedder,
                },
            )
            .unwrap(),
        )
    }

    /// The property the whole module exists for: what the stream holds
    /// restores to a database carrying the writes that were shipped.
    #[tokio::test]
    async fn a_shipped_stream_restores_the_writes_it_carried() {
        let source = tempfile::tempdir().unwrap();
        let objects = ObjectStore::memory().unwrap();
        let store = open_store(source.path());
        let mut replicator = Replicator::start(
            objects.clone(),
            ReplicatorConfig::new("db/acme/prod"),
            store.clone(),
        )
        .await
        .unwrap();

        // A write the snapshot cannot contain, since it happened after it.
        {
            let store = store.clone();
            synch_core::offload(move || store.set_config("dbrepl.probe", "shipped"))
                .await
                .unwrap();
        }
        let shipped = replicator.tick().await.unwrap();
        assert!(shipped > 0, "the write should have produced log frames");

        let restored = tempfile::tempdir().unwrap();
        let report = restore(&objects, "db/acme/prod", restored.path())
            .await
            .unwrap()
            .expect("the stream holds a generation");
        assert_eq!(report.generation, replicator.generation());
        assert_eq!(report.segments_skipped, 0);

        let reopened = open_store(restored.path());
        let value = {
            let reopened = reopened.clone();
            synch_core::offload(move || reopened.config("dbrepl.probe"))
                .await
                .unwrap()
        };
        assert_eq!(value.as_deref(), Some("shipped"));
    }

    /// A stream nothing has been written to is not an error — it is the signal
    /// to initialize a new node, and must be distinguishable from a failure.
    #[tokio::test]
    async fn an_empty_stream_restores_nothing() {
        let objects = ObjectStore::memory().unwrap();
        let restored = tempfile::tempdir().unwrap();
        let report = restore(&objects, "db/acme/prod", restored.path())
            .await
            .unwrap();
        assert!(report.is_none());
    }

    /// A generation roll must not lose the writes that preceded it: the new
    /// snapshot has to carry everything the old generation's log did.
    #[tokio::test]
    async fn rolling_a_generation_carries_earlier_writes_into_the_snapshot() {
        let source = tempfile::tempdir().unwrap();
        let objects = ObjectStore::memory().unwrap();
        let store = open_store(source.path());
        let mut replicator = Replicator::start(
            objects.clone(),
            ReplicatorConfig::new("db/acme/prod"),
            store.clone(),
        )
        .await
        .unwrap();
        let first = replicator.generation().to_string();

        {
            let store = store.clone();
            synch_core::offload(move || store.set_config("dbrepl.probe", "before-roll"))
                .await
                .unwrap();
        }
        replicator.tick().await.unwrap();
        replicator.roll_generation().await.unwrap();
        assert_ne!(
            replicator.generation(),
            first,
            "the generation should change"
        );

        // Restore picks the newest generation, whose snapshot must already
        // contain the write that was only in the previous generation's log.
        let restored = tempfile::tempdir().unwrap();
        let report = restore(&objects, "db/acme/prod", restored.path())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(report.generation, replicator.generation());
        let reopened = open_store(restored.path());
        let value = {
            let reopened = reopened.clone();
            synch_core::offload(move || reopened.config("dbrepl.probe"))
                .await
                .unwrap()
        };
        assert_eq!(value.as_deref(), Some("before-roll"));
    }

    /// A segment that never landed truncates the log rather than poisoning it.
    #[tokio::test]
    async fn a_gap_truncates_the_log_at_the_gap() {
        let objects = ObjectStore::memory().unwrap();
        // Segment 0 covers [0, 4); segment 2 claims to start at 8, which
        // nothing reaches — so only the first survives assembly.
        objects
            .put("db/x/y/g1/wal/00000000.0.4", vec![1, 2, 3, 4])
            .await
            .unwrap();
        objects
            .put("db/x/y/g1/wal/00000002.8.4", vec![9, 9, 9, 9])
            .await
            .unwrap();
        let (wal, skipped) = assemble_wal(&objects, "db/x/y", "g1").await.unwrap();
        assert_eq!(wal, vec![1, 2, 3, 4]);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn generation_ids_sort_chronologically() {
        let first = new_generation_id();
        std::thread::sleep(Duration::from_millis(2));
        let second = new_generation_id();
        assert!(second > first, "{second} should sort after {first}");
    }
}
