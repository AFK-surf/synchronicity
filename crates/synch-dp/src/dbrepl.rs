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
//!
//! # Why the shipper verifies rather than counts
//!
//! The obvious implementation — ship every whole frame the file has grown by
//! — is wrong twice, and both ways are silent. SQLite spills a big
//! transaction's pages into the log *before* it commits, and rolls back by
//! rewinding its own high-water mark while leaving those bytes behind for the
//! next transaction to overwrite. So a length-driven shipper both ships
//! frames that never committed and then misses the frames that replace them,
//! and the stream ends up describing a log that never existed.
//!
//! So the shipper walks frames instead: it stops at the last frame that
//! *committed* a transaction, and it verifies every frame's checksum against
//! the running chain SQLite maintains. A frame that does not continue the
//! chain is proof the log was rewritten behind us, and the only sound
//! response is to end the generation and take a fresh snapshot — the database
//! file is authoritative whatever the log did.

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
    /// The running frame checksum at `shipped`, and the log's byte order.
    ///
    /// SQLite chains every frame's checksum onto its predecessor's, so this
    /// is what lets the next tick prove the frames it is about to ship
    /// continue the ones already shipped — and notice when they do not,
    /// which is how a rewritten log is caught (see the module docs).
    chain: Option<Chain>,
}

/// The running checksum a WAL's frames chain through.
#[derive(Debug, Clone, Copy)]
struct Chain {
    /// The two 32-bit halves of the running checksum.
    state: (u32, u32),
    /// Whether the log's checksums are computed over big-endian words. Taken
    /// from the header magic, which is the only thing that says.
    big_endian: bool,
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
            chain: None,
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
        // Ship what the old generation still owes before the checkpoint
        // destroys the only local record of it. A checkpoint folds unshipped
        // frames into the database file and empties the log; if the snapshot
        // upload then fails and the pod is replaced, those writes exist
        // nowhere. Shipping first bounds the loss to what the stream already
        // bounds it to.
        //
        // Only when there is a generation to owe it to: the first roll opens
        // one, and `ship_pending` on an empty stream has nothing to say.
        if !self.generation.is_empty() {
            if let Err(error) = self.ship_once().await {
                // Not fatal: the snapshot about to be taken supersedes the
                // log either way. Recorded because it is the one moment the
                // window widens.
                tracing::warn!(
                    prefix = %self.config.prefix, %error,
                    "could not ship the outstanding log before rolling"
                );
            }
        }
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

    /// Ships every *committed* frame appended since the last call.
    ///
    /// Returns how many bytes went up. Rolls a generation when the log has
    /// grown past the configured ceiling, or when the log turns out to have
    /// been rewritten under us.
    ///
    /// Two rules make this safe, and neither is optional:
    ///
    /// **Only through the last commit frame.** SQLite spills a large
    /// transaction's pages into the log *before* it commits, and rolls back
    /// by rewinding its own high-water mark while leaving those bytes in the
    /// file — the next transaction then writes over them. Shipping by file
    /// length would therefore ship frames that are about to be replaced, and
    /// the stream would carry a version of the log that never existed.
    ///
    /// **Every frame is checked against the chain.** Each frame's checksum
    /// covers its predecessor's, so a frame that does not continue the run
    /// we shipped proves the log was rewritten behind us. There is no way to
    /// patch that up, so it ends the generation: the next snapshot is taken
    /// from the database file, which is authoritative either way.
    pub async fn tick(&mut self) -> Result<u64> {
        let outcome = self.ship_once().await?;
        if outcome.needs_roll {
            self.roll_generation().await?;
        }
        Ok(outcome.bytes)
    }

    /// The frame walk, without ever rolling a generation.
    ///
    /// Split out because a roll ships the outstanding tail first, and a
    /// shipper that could roll would recurse into the roll that called it.
    async fn ship_once(&mut self) -> Result<Shipped> {
        let wal_path = self.store().wal_path();
        let Some(len) = file_len(&wal_path).await? else {
            // No log at all: nothing has been written since the generation
            // opened. Not an error, and not a state to correct.
            return Ok(Shipped::none());
        };
        if len < WAL_HEADER_LEN {
            return Ok(Shipped::none());
        }
        let header = read_at(&wal_path, 0, WAL_HEADER_LEN as usize).await?;
        let Some(header) = WalHeader::parse(&header) else {
            tracing::warn!(prefix = %self.config.prefix, "unrecognized write-ahead log header");
            return Ok(Shipped::none());
        };

        match self.salt {
            None => {
                self.salt = Some(header.salt);
                self.page_size = Some(header.page_size);
                self.chain = Some(Chain {
                    state: header.checksum,
                    big_endian: header.big_endian,
                });
            }
            Some(known) if known != header.salt => {
                // The log was reset. Since this process owns checkpointing
                // that should not happen, and the honest response is a new
                // generation rather than bytes that will not replay.
                tracing::warn!(
                    prefix = %self.config.prefix,
                    "the write-ahead log was reset underneath the replicator; rolling"
                );
                return Ok(Shipped::roll());
            }
            Some(_) => {}
        }

        let frame = WAL_FRAME_HEADER_LEN + header.page_size;
        let Some(mut chain) = self.chain else {
            return Ok(Shipped::none());
        };
        // Walk from where we stopped, verifying as we go, and remember the
        // end of the last frame that *committed* a transaction.
        let mut offset = self.shipped.max(WAL_HEADER_LEN);
        let mut committed = self.shipped;
        let mut committed_chain = chain;
        while offset + frame <= len {
            let bytes = read_at(&wal_path, offset, frame as usize).await?;
            let Some(next) = verify_frame(&bytes, header.salt, chain) else {
                if offset < self.shipped {
                    // A frame we already shipped no longer chains: the log
                    // was rewritten behind us.
                    tracing::warn!(
                        prefix = %self.config.prefix,
                        offset,
                        "the write-ahead log was rewritten behind the replicator; rolling"
                    );
                    return Ok(Shipped::roll());
                }
                // An incomplete or uncommitted tail. Stop; it is not ours to
                // ship yet, and the next tick will find it finished.
                break;
            };
            chain = next.chain;
            offset += frame;
            if next.commit {
                committed = offset;
                committed_chain = next.chain;
            }
        }

        if committed <= self.shipped {
            return Ok(Shipped::none());
        }
        // `shipped` is zero for a fresh generation, so the first segment
        // starts at zero and carries the log header — which is what makes the
        // assembled file a WAL rather than a pile of frames.
        let start = self.shipped;
        let payload = read_at(&wal_path, start, (committed - start) as usize).await?;
        let shipped = payload.len() as u64;
        let key = format!(
            "{}/{}/wal/{:08}.{}.{}",
            self.config.prefix, self.generation, self.next_index, start, shipped
        );
        self.objects.put(&key, payload).await?;
        self.next_index += 1;
        self.shipped = committed;
        self.chain = Some(committed_chain);

        Ok(Shipped {
            bytes: shipped,
            needs_roll: committed >= self.config.wal_roll_bytes,
        })
    }

    /// The store this replicator streams.
    fn store(&self) -> &Arc<synch_store::Store> {
        &self.store
    }

    /// Ships everything outstanding. The last thing a draining tenant does.
    pub async fn flush(&mut self) -> Result<()> {
        self.tick().await.map(|_| ())
    }
}

/// What one pass of the frame walk did.
#[derive(Debug, Clone, Copy)]
struct Shipped {
    /// Bytes uploaded.
    bytes: u64,
    /// Whether the caller should now close this generation.
    needs_roll: bool,
}

impl Shipped {
    /// Nothing to do.
    fn none() -> Self {
        Self {
            bytes: 0,
            needs_roll: false,
        }
    }

    /// Nothing shipped, and the generation must end.
    fn roll() -> Self {
        Self {
            bytes: 0,
            needs_roll: true,
        }
    }
}

/// The parts of a WAL header this module reads.
///
/// Layout (SQLite's file format, section 4.1): magic, format version, page
/// size, checkpoint sequence, two salts, then the header's own checksum.
#[derive(Debug, Clone, Copy)]
struct WalHeader {
    /// Bytes per page, which fixes the frame size.
    page_size: u64,
    /// The salt every frame in this log must carry.
    salt: [u8; 8],
    /// The checksum the first frame chains from.
    checksum: (u32, u32),
    /// Whether checksums are computed over big-endian words.
    big_endian: bool,
}

impl WalHeader {
    /// Parses a 32-byte header, or `None` if it is not a WAL this build
    /// understands.
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < WAL_HEADER_LEN as usize {
            return None;
        }
        // The magic's low bit is the one thing that says which byte order the
        // checksums are computed in; everything else in the file is big-endian.
        let magic = u32::from_be_bytes(bytes[0..4].try_into().ok()?);
        let big_endian = match magic {
            0x377f_0682 => false,
            0x377f_0683 => true,
            _ => return None,
        };
        let page_size = u32::from_be_bytes(bytes[8..12].try_into().ok()?) as u64;
        // A page size of 65536 is stored as 1, and anything else must be a
        // power of two: a bogus one would make every frame boundary wrong.
        let page_size = if page_size == 1 { 65_536 } else { page_size };
        if page_size < 512 || !page_size.is_power_of_two() {
            return None;
        }
        Some(Self {
            page_size,
            salt: bytes[16..24].try_into().ok()?,
            checksum: (
                u32::from_be_bytes(bytes[24..28].try_into().ok()?),
                u32::from_be_bytes(bytes[28..32].try_into().ok()?),
            ),
            big_endian,
        })
    }
}

/// What verifying one frame established.
#[derive(Debug, Clone, Copy)]
struct Frame {
    /// The running checksum after it.
    chain: Chain,
    /// Whether it is a commit frame — the last frame of a transaction, and
    /// the only kind it is safe to stop shipping on.
    commit: bool,
}

/// Checks one frame against the salt and the running checksum.
///
/// Returns `None` when the frame is not part of this log or does not continue
/// the chain, which are the two ways a frame can be "not ours to ship".
fn verify_frame(bytes: &[u8], salt: [u8; 8], chain: Chain) -> Option<Frame> {
    if bytes.len() < WAL_FRAME_HEADER_LEN as usize {
        return None;
    }
    // A frame written under a different salt belongs to an older log that
    // happened to occupy this offset.
    if bytes[8..16] != salt[..] {
        return None;
    }
    let claimed = (
        u32::from_be_bytes(bytes[16..20].try_into().ok()?),
        u32::from_be_bytes(bytes[20..24].try_into().ok()?),
    );
    // The checksum covers the frame header's first eight bytes (page number
    // and post-commit database size) and then the whole page.
    let mut state = checksum(chain.state, &bytes[0..8], chain.big_endian);
    state = checksum(
        state,
        &bytes[WAL_FRAME_HEADER_LEN as usize..],
        chain.big_endian,
    );
    if state != claimed {
        return None;
    }
    // A non-zero database size marks the frame that commits the transaction.
    let commit = u32::from_be_bytes(bytes[4..8].try_into().ok()?) != 0;
    Some(Frame {
        chain: Chain {
            state,
            big_endian: chain.big_endian,
        },
        commit,
    })
}

/// SQLite's WAL checksum, continued from `state` over `bytes`.
///
/// Two interleaved running sums over 32-bit words, which is the algorithm the
/// file format defines; it is not a general-purpose checksum and is not
/// interchangeable with one.
fn checksum(state: (u32, u32), bytes: &[u8], big_endian: bool) -> (u32, u32) {
    let (mut s0, mut s1) = state;
    // Whole 8-byte pairs only; a trailing partial word cannot be part of a
    // checksummed region, since both the frame header slice and a page are
    // multiples of eight.
    for pair in bytes.as_chunks::<8>().0 {
        let (a, b) = if big_endian {
            (
                u32::from_be_bytes([pair[0], pair[1], pair[2], pair[3]]),
                u32::from_be_bytes([pair[4], pair[5], pair[6], pair[7]]),
            )
        } else {
            (
                u32::from_le_bytes([pair[0], pair[1], pair[2], pair[3]]),
                u32::from_le_bytes([pair[4], pair[5], pair[6], pair[7]]),
            )
        };
        s0 = s0.wrapping_add(a).wrapping_add(s1);
        s1 = s1.wrapping_add(b).wrapping_add(s0);
    }
    (s0, s1)
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

    /// The rule that keeps an uncommitted spill out of the stream: shipping
    /// stops at the last commit frame, so a partially written transaction is
    /// never uploaded and the bytes it will be replaced by are still ours to
    /// read next tick.
    #[tokio::test]
    async fn shipping_stops_at_the_last_commit() {
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

        {
            let store = store.clone();
            synch_core::offload(move || store.set_config("probe", "committed"))
                .await
                .unwrap();
        }
        let shipped = replicator.tick().await.unwrap();
        assert!(shipped > 0);
        // Every byte shipped ends on a frame boundary at a commit, so the
        // WAL file's length is greater than or equal to what went up — never
        // the other way round.
        let wal_len = std::fs::metadata(store.wal_path()).unwrap().len();
        assert!(
            replicator.shipped_bytes() <= wal_len,
            "shipped {} beyond a log of {wal_len}",
            replicator.shipped_bytes()
        );
    }

    /// The checksum chain is what catches a log rewritten behind us. Feeding
    /// a frame that does not continue the chain must not verify.
    #[test]
    fn a_frame_that_does_not_continue_the_chain_is_refused() {
        let salt = [1u8; 8];
        let chain = Chain {
            state: (0, 0),
            big_endian: false,
        };
        // A frame carrying the right salt but a checksum that chains from
        // nothing: the shape of a frame written over an older one.
        let mut frame = vec![0u8; (WAL_FRAME_HEADER_LEN + 512) as usize];
        frame[8..16].copy_from_slice(&salt);
        frame[16..20].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        assert!(verify_frame(&frame, salt, chain).is_none());

        // And a frame from another log entirely is refused on the salt
        // before its checksum is even considered.
        assert!(verify_frame(&frame, [2u8; 8], chain).is_none());
    }

    /// The checksum is SQLite's, not a general-purpose one — two interleaved
    /// running sums, order-dependent, and it must chain rather than restart.
    #[test]
    fn the_checksum_chains() {
        let first = checksum((0, 0), &[1u8; 16], false);
        let chained = checksum(first, &[1u8; 16], false);
        let restarted = checksum((0, 0), &[1u8; 16], false);
        assert_ne!(
            chained, restarted,
            "the second block must depend on the first"
        );
        // Byte order is a property of the log, and changes the answer — on
        // bytes that are not the same read either way.
        let asymmetric = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_ne!(
            checksum((0, 0), &asymmetric, true),
            checksum((0, 0), &asymmetric, false)
        );
    }

    /// A header that is not a WAL is refused rather than guessed at: a wrong
    /// page size makes every frame boundary wrong.
    #[test]
    fn an_unrecognized_header_is_refused() {
        assert!(WalHeader::parse(&[0u8; 32]).is_none());
        let mut header = [0u8; 32];
        header[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        header[8..12].copy_from_slice(&777u32.to_be_bytes());
        assert!(
            WalHeader::parse(&header).is_none(),
            "a page size that is not a power of two is not a WAL"
        );
        header[8..12].copy_from_slice(&4096u32.to_be_bytes());
        let parsed = WalHeader::parse(&header).expect("a valid header");
        assert_eq!(parsed.page_size, 4096);
        assert!(!parsed.big_endian);
    }

    #[test]
    fn generation_ids_sort_chronologically() {
        let first = new_generation_id();
        std::thread::sleep(Duration::from_millis(2));
        let second = new_generation_id();
        assert!(second > first, "{second} should sort after {first}");
    }
}
