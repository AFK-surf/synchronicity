//! The content-addressed blob store (§6.1, §6.2).
//!
//! Every object is hashed with BLAKE3 over 16 KiB chunk groups and kept
//! alongside its bao outboard, so any byte range can be served as a bao slice
//! without touching the rest of the object. Partial objects are first class: a
//! verified-group bitmap records exactly which peer-supplied groups are
//! present, which is what lets a node holding the first half of a video
//! usefully advertise and serve it.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use bao_tree::{
    io::{
        outboard::PreOrderOutboard,
        sync::{decode_ranges, WriteAt},
    },
    BaoTree, BlockSize, ChunkNum,
};
use rusqlite::{params, OptionalExtension};
use synch_core::{
    group_count, groups_for_byte_range, BlobAd, ChunkRanges, GroupRange, Hash, CHUNK_GROUP_LOG2,
    CHUNK_GROUP_SIZE, INLINE_BLOB_MAX,
};

use crate::{
    db::{hash_column, Store, Txn},
    error::{Result, StoreError},
};

impl Txn<'_> {
    /// Reads the local CAS row from this transaction's snapshot.
    pub fn blob(&self, root: &Hash) -> Result<Option<BlobRow>> {
        let row = self
            .conn()
            .query_row(
                &format!("SELECT {BLOB_COLUMNS} FROM blobs WHERE root = ?1"),
                params![root.as_bytes().to_vec()],
                raw_blob_row,
            )
            .optional()?;
        row.map(blob_row_from).transpose()
    }

    /// Verifies durable possession and installs the source hold used by the
    /// publication transaction.
    pub fn hold_source_blob(&self, space: &str, root: &Hash, size: u64, now: i64) -> Result<()> {
        let configured: bool = self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM sources WHERE space = ?1)",
            params![space],
            |row| row.get(0),
        )?;
        if !configured {
            return Err(StoreError::Invalid(format!(
                "cannot publish into {space}: this node has no source role"
            )));
        }
        let row = self
            .conn()
            .query_row(
                "SELECT size, durable FROM blobs WHERE root = ?1",
                params![root.as_bytes().to_vec()],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        match row {
            Some((recorded, true)) if recorded == size => {}
            Some((recorded, true)) => {
                return Err(StoreError::Invalid(format!(
                    "source {space} tried to publish {root} as {size} bytes, but durable storage records {recorded}"
                )))
            }
            _ => {
                return Err(StoreError::Invalid(format!(
                    "source {space} cannot publish {root}: complete durable content is not present"
                )))
            }
        }
        let holder = PinHolder::Source(space.to_string()).render();
        self.conn().execute(
            "INSERT INTO pins (root, holder, created_at, release_after)
             VALUES (?1, ?2, ?3, NULL)
             ON CONFLICT(root, holder) DO UPDATE SET release_after = NULL",
            params![root.as_bytes().to_vec(), holder, now],
        )?;
        // Held is not wanted. A source want exists only as a repair intent
        // left by a heal, and the durable row just verified is that repair;
        // `Cas.SourcePublish` retires the want in the same step.
        self.conn().execute(
            "DELETE FROM content_want WHERE root = ?1 AND holder = ?2",
            params![root.as_bytes().to_vec(), holder],
        )?;
        Ok(())
    }

    /// Releases source holds no live own-origin entry in `space` names after
    /// the new head has been materialized.
    pub fn reconcile_source_holds(&self, origin: &synch_core::OriginId, space: &str) -> Result<()> {
        self.conn().execute(
            "DELETE FROM pins
              WHERE holder = ?1
                AND NOT EXISTS (
                  SELECT 1 FROM entries
                   WHERE origin_id = ?2 AND space = ?3 AND content = pins.root
                )",
            params![
                PinHolder::Source(space.to_string()).render(),
                origin.canonical(),
                space,
            ],
        )?;
        Ok(())
    }

    /// Returns the durable size of `root` when this node's materialized view
    /// still has a configured source entry naming it. Publication reads this
    /// after applying a proposed trie diff and derives the publisher-owned
    /// `b:` value from that final view.
    pub fn live_source_blob_size(
        &self,
        origin: &synch_core::OriginId,
        root: &Hash,
    ) -> Result<Option<u64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT b.size
                   FROM entries e
                   JOIN sources s ON s.space = e.space
                   JOIN blobs b ON b.root = e.content
                  WHERE e.origin_id = ?1
                    AND e.content = ?2
                    AND e.size = b.size
                    AND b.durable != 0
                  LIMIT 1",
                params![origin.canonical(), root.as_bytes().to_vec()],
                |row| Ok(row.get::<_, i64>(0)? as u64),
            )
            .optional()?)
    }
}

/// The bao block size synchronicity uses everywhere: 16 KiB chunk groups.
pub(crate) const BLOCK_SIZE: BlockSize = BlockSize::from_chunk_log(CHUNK_GROUP_LOG2);

/// Flushes a file's contents to stable storage. A blob row is only ever written
/// after this returns, so a crash cannot leave a `complete=1` index row whose
/// bytes never reached the disk (§6.2 durability).
pub(crate) fn fsync_file(file: &File) -> Result<()> {
    file.sync_all()?;
    Ok(())
}

pub(crate) use synch_core::fs::fsync_parent;

pub(crate) use synch_core::fs::replace_file;

/// Writes a file whole and flushes it (contents and directory entry) to stable
/// storage before returning.
///
/// Staged and renamed, never written in place. `File::create` truncates first,
/// and the object this replaces may already be held complete: re-ingesting
/// content the CAS already has is routine, not exotic — a duplicate file
/// anywhere in a scanned tree, the scanner's racily-clean re-ingest, an
/// explicit re-`put` — and for a large object the window between the truncate
/// and the last byte is the length of the whole write. A power loss inside it
/// left the object with its `complete = 1` row intact and a truncated outboard
/// behind it: still advertised by `local_ad`, still `has_complete_blob`, but no
/// longer satisfying the stable-storage promise represented by that row. The
/// payload beside it already staged and renamed ([`Store::ingest_file`]); this
/// is the same rule applied to the file that describes it.
///
/// The staging file lives in the staging directory, which [`Store::gc_staging`]
/// sweeps by age, so a crash between the write and the rename leaks nothing
/// permanently.
fn write_and_sync(
    staging_dir: &std::path::Path,
    path: &std::path::Path,
    data: &[u8],
) -> Result<()> {
    std::fs::create_dir_all(staging_dir)?;
    let staging = staging_dir.join(format!("{}.tmp", synch_core::fs::unique_suffix()));
    let write = || -> Result<()> {
        let mut file = File::create(&staging)?;
        file.write_all(data)?;
        fsync_file(&file)?;
        Ok(())
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&staging);
        return Err(e);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // `rename` is atomic within a filesystem: a reader sees either the whole
    // old file or the whole new one, never a truncated prefix of either.
    if let Err(e) = replace_file(&staging, path) {
        let _ = std::fs::remove_file(&staging);
        return Err(e.into());
    }
    fsync_parent(path);
    Ok(())
}

/// Who holds a pin (`docs/REPLICATION.md` §3.1).
///
/// The holder is what makes a release decidable. Two things can hold one
/// object — content is deduplicated by hash, so one root is reachable from any
/// number of spaces and from an operator's own `pin add` — and "may these bytes
/// go now?" is a question about the whole set of claims, not about any one of
/// them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PinHolder {
    /// `synch pin add`: an operator asked for this by hand.
    Operator,
    /// A source's current published tree promises these bytes.
    Source(String),
    /// A replica holds this for as long as its policy says.
    Replica(String),
    /// A spelling this build does not know, kept verbatim.
    ///
    /// A claim it cannot read is still a claim. Dropping it — or refusing to
    /// list it — is how a downgrade turns another version's pins into
    /// collectable garbage.
    Other(String),
}

impl PinHolder {
    /// The stored spelling.
    pub fn render(&self) -> String {
        match self {
            PinHolder::Operator => "operator".to_string(),
            PinHolder::Source(space) => format!("source:{space}"),
            PinHolder::Replica(space) => format!("replica:{space}"),
            PinHolder::Other(text) => text.clone(),
        }
    }

    /// Reads a stored spelling. Never fails; see [`PinHolder::Other`].
    pub fn parse(text: &str) -> PinHolder {
        match text.split_once(':') {
            Some(("replica", space)) if !space.is_empty() => PinHolder::Replica(space.to_string()),
            Some(("source", space)) if !space.is_empty() => PinHolder::Source(space.to_string()),
            _ if text == "operator" => PinHolder::Operator,
            _ => PinHolder::Other(text.to_string()),
        }
    }

    /// The space this claim is on behalf of, if it belongs to a standing role.
    pub fn space(&self) -> Option<&str> {
        match self {
            PinHolder::Source(space) | PinHolder::Replica(space) => Some(space),
            _ => None,
        }
    }
}

impl std::fmt::Display for PinHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

/// One claim on one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRow {
    /// The object held.
    pub root: Hash,
    /// Who holds it.
    pub holder: PinHolder,
    /// When the claim was made, in unix nanoseconds.
    pub created_at: i64,
    /// When the claim is due to end, if it has been scheduled to.
    pub release_after: Option<i64>,
}

/// A blob index row without its payload: what a sweep or a report needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobSummary {
    /// The object root.
    pub root: Hash,
    /// The object size in bytes.
    pub size: u64,
    /// True if every group is present and verified.
    pub complete: bool,
    /// True when the backend has committed the complete object to its durable tier.
    pub durable: bool,
    /// True if the blob is pinned against GC.
    pub pinned: bool,
    /// When the blob was last written to, in unix nanoseconds.
    pub last_access: i64,
}

/// The column list `blob` and `blobs` share, in the order [`raw_blob_row`]
/// destructures. One spelling, because hand-aligned tuple destructurings of
/// the same columns is how a reordered schema change compiles cleanly and
/// decodes the wrong column. (`blob_candidates` still hand-decodes its own
/// narrower row below.)
const BLOB_COLUMNS: &str = "root, size, complete, bitmap, inline,
        EXISTS(SELECT 1 FROM pins WHERE pins.root = blobs.root),
        last_access, durable";

/// A [`BLOB_COLUMNS`] row as SQLite hands it over, before hash decoding —
/// which reports through [`StoreError`], so it happens outside the closure.
type RawBlobRow = (
    Vec<u8>,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    i64,
    i64,
);

fn raw_blob_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawBlobRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn blob_row_from(raw: RawBlobRow) -> Result<BlobRow> {
    let (root, size, complete, bitmap, inline, pinned, last_access, durable) = raw;
    Ok(BlobRow {
        root: hash_column(root, "blobs.root")?,
        size: size as u64,
        complete: complete != 0,
        durable: durable != 0,
        bitmap,
        inline,
        pinned: pinned != 0,
        last_access,
    })
}

/// A row of the local blob index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRow {
    /// The object root.
    pub root: Hash,
    /// The object size in bytes.
    pub size: u64,
    /// True if every group is present and verified.
    pub complete: bool,
    /// True when the backend has committed the complete object to stable storage.
    pub durable: bool,
    /// The verified-group bitmap, when partial.
    pub bitmap: Option<Vec<u8>>,
    /// The payload, for blobs small enough to inline (§6.2).
    pub inline: Option<Vec<u8>>,
    /// True if the blob is pinned against GC.
    pub pinned: bool,
    /// When the blob was last read, in unix nanoseconds.
    pub last_access: i64,
}

impl BlobRow {
    /// The groups this holder has verified.
    pub fn verified_groups(&self) -> ChunkRanges {
        // This is cache availability, not the durable-tier promise. A cold
        // cloud row advertises complete through `to_ad`, while the fetch/read
        // planner still sees which groups are actually local.
        if self.complete {
            return ChunkRanges::single(0, group_count(self.size));
        }
        match &self.bitmap {
            None => ChunkRanges::empty(),
            Some(bytes) => blob_to_ranges(bytes, group_count(self.size)),
        }
    }

    /// The advertisement this holder should publish for the object (§6.3).
    pub fn to_ad(&self) -> BlobAd {
        if self.complete || self.durable {
            return BlobAd::complete(self.size);
        }
        let spans: Vec<(u64, u64)> = self
            .verified_groups()
            .ranges
            .iter()
            .map(|r| {
                (
                    r.start * CHUNK_GROUP_SIZE,
                    (r.end * CHUNK_GROUP_SIZE).min(self.size),
                )
            })
            .collect();
        BlobAd::partial(self.size, spans)
    }
}

/// What a bitmap commit settled.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Commit {
    /// The size the row records now the claim has met what was there.
    pub(crate) size: u64,
    /// True if every group of the object is present.
    pub(crate) complete: bool,
}

/// Extends a file to at least `len`, and never shortens it.
///
/// A `set_len` down is destructive, and until a decode has run the size a
/// writer arrived with is a peer's claim rather than a fact: an understated one
/// would truncate away groups this node had already verified, whose bitmap bits
/// would survive to advertise bytes that are gone (`docs/DELTA-SYNC.md` §6).
/// Shortening waits for [`Store::trim_to_size`], after the commit that settled
/// the size.
pub(crate) fn grow_to(file: &File, len: u64) -> Result<()> {
    if file.metadata()?.len() < len {
        file.set_len(len)?;
    }
    Ok(())
}

/// Encodes an object's verified groups for the `blobs.bitmap` column.
///
/// Ranges, not a bit per group, despite the column's name. A bitmap costs
/// `O(group_count)` to read *and* to write, and both happen on every commit:
/// `write_slice` reads the row, `commit_groups` reads it again inside its
/// transaction and rewrites the whole blob — per 8 MiB window. For a 100 GB
/// object that is 6.1M loop iterations and a 763 KB blob rewritten ~12 200
/// times, so moving 100 GB of payload cost tens of GB of index traffic and
/// ~10^11 iterations. It is worse remotely: `encode_slice` reads the row before
/// anything else, so a `GetSlice` for one group of a 1 TB partial object cost
/// the provider a 7.6 MB read and 61M iterations for a ~50-byte request.
///
/// Verified groups are contiguous runs in practice — fetches walk windows in
/// order — so the range form is a handful of integers where the bitmap was
/// hundreds of kilobytes, and both directions are `O(runs)`.
pub(crate) fn ranges_to_blob(ranges: &ChunkRanges) -> Vec<u8> {
    let pairs: Vec<(u64, u64)> = ranges.ranges.iter().map(|r| (r.start, r.end)).collect();
    postcard::to_stdvec(&pairs).expect("range encoding is infallible")
}

/// Decodes the `blobs.bitmap` column, clamped to the object's group count.
pub(crate) fn blob_to_ranges(bytes: &[u8], groups: u64) -> ChunkRanges {
    let pairs: Vec<(u64, u64)> = match postcard::from_bytes(bytes) {
        Ok(pairs) => pairs,
        // A row this build cannot read is treated as holding nothing, which
        // costs a re-fetch and never a wrong claim of availability.
        Err(_) => return ChunkRanges::empty(),
    };
    ChunkRanges::from_ranges(
        pairs
            .into_iter()
            .map(|(start, end)| GroupRange::new(start, end.min(groups))),
    )
}

/// Decodes the pre-v10 bit-per-group encoding.
///
/// Live only inside the v10 migration, which rewrites every partial row into
/// the range form. Nothing on a running node reads a bitmap any more.
pub(crate) fn bitmap_to_ranges(bits: &[u8], groups: u64) -> ChunkRanges {
    // A bitmap describes no more groups than it has bits for, and the group
    // count comes from the row's stored size. Bounding the walk by both keeps
    // the migration's cost proportional to the bytes it is reading — this runs
    // inside the migration transaction, where a long loop is a daemon that will
    // not start.
    let groups = groups.min((bits.len() as u64).saturating_mul(8));
    let mut ranges = Vec::new();
    let mut start: Option<u64> = None;
    for group in 0..groups {
        let byte = (group / 8) as usize;
        let set = bits.get(byte).is_some_and(|b| b & (1 << (group % 8)) != 0);
        match (set, start) {
            (true, None) => start = Some(group),
            (false, Some(s)) => {
                ranges.push(GroupRange::new(s, group));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        ranges.push(GroupRange::new(s, groups));
    }
    ChunkRanges::from_ranges(ranges)
}

/// Converts our group ranges into bao chunk ranges.
pub(crate) fn to_bao_ranges(ranges: &ChunkRanges) -> bao_tree::ChunkRanges {
    let per_group = 1u64 << CHUNK_GROUP_LOG2;
    let mut out = bao_tree::ChunkRanges::empty();
    for r in &ranges.ranges {
        out |=
            bao_tree::ChunkRanges::from(ChunkNum(r.start * per_group)..ChunkNum(r.end * per_group));
    }
    out
}

impl Store {
    /// The filesystem path of a blob payload: `store/<hex[0..2]>/<hex>` (§6.2).
    pub(crate) fn blob_path(&self, root: &Hash) -> PathBuf {
        let hex = root.to_hex();
        self.cas_dir().join(&hex[..2]).join(&hex)
    }

    /// The filesystem path of a blob's outboard.
    pub(crate) fn outboard_path(&self, root: &Hash) -> PathBuf {
        let mut path = self.blob_path(root);
        path.set_extension("obao");
        path
    }

    pub(crate) fn tree(size: u64) -> BaoTree {
        BaoTree::new(size, BLOCK_SIZE)
    }

    // ---- ingest -----------------------------------------------------------

    /// Ingests an in-memory object, returning its root.
    ///
    /// The mandatory Lean operation owns hashing, inline selection, file
    /// publication, write-lease lifetime and the atomic metadata commit.
    pub fn ingest_bytes(&self, data: &[u8], now: i64) -> Result<Hash> {
        crate::lean_ingest::ingest(self, crate::lean_resources::Input::Bytes(data), now)
            .map(|(root, _)| root)
    }

    /// Ingests a local file and returns its root and captured byte count.
    ///
    /// Lean observes the source and owns read-to-EOF versus bounded capture;
    /// Rust supplies the path capability without preparing an ingestion plan.
    pub fn ingest_file(&self, path: &std::path::Path, now: i64) -> Result<(Hash, u64)> {
        crate::lean_ingest::ingest(self, crate::lean_resources::Input::File(path), now)
    }

    /// Records a complete object whose bytes were durably committed by a
    /// remote backend before this call.
    ///
    /// No local groups are claimed: a cold cloud cache is still a complete
    /// holder because `durable=1`, and the backend refills it on demand.
    #[cfg(test)]
    pub(crate) fn record_remote_durable_blob(
        &self,
        root: &Hash,
        size: u64,
        now: i64,
    ) -> Result<()> {
        self.with_immediate_tx(|tx| {
            tx.execute(
                "INSERT INTO blobs
               (root, size, complete, bitmap, inline, last_access, durable)
             VALUES (?1, ?2, 0, NULL, NULL, ?3, 1)
             ON CONFLICT(root) DO UPDATE SET
               size = excluded.size,
               durable = 1,
               last_access = excluded.last_access",
                params![root.as_bytes().to_vec(), size as i64, now],
            )?;
            Ok(())
        })
    }

    /// Folds newly verified groups into an object's row, atomically (§10).
    ///
    /// Two writers of one root is the ordinary case rather than an exotic one:
    /// checkout reconciliation, a `synch cat` and the gateway's range read all resolve to
    /// the same content, and a promotion commits a whole span in a single step.
    /// So the read, the settlement, the union and the write happen inside one
    /// transaction, and the expensive part (decoding, hashing, copying,
    /// fsyncing) stays outside it. The Lean commit owns that decision: the
    /// offered size is settled against the row's claim, a claim only a
    /// complete, durable or final-group-holding row can refuse; a changed
    /// tree shape resets an unattested bitmap; and the merged groups are
    /// written as ranges, `NULL` when there are none or all.
    pub(crate) fn commit_groups(
        &self,
        root: &Hash,
        size: u64,
        groups: &ChunkRanges,
        inline: Option<Vec<u8>>,
        now: i64,
    ) -> Result<Commit> {
        crate::lean_ingest::commit_groups(self, root, size, groups, inline, now)
    }

    /// The cheap refusal of a size the row's claim cannot yield to, decided
    /// by the same Lean settlement outside a transaction, so a writer never
    /// decodes bytes (and writes an outboard of the wrong shape) against a
    /// claim the commit would refuse anyway.
    pub(crate) fn admit_size(&self, root: &Hash, size: u64) -> Result<()> {
        crate::lean_ingest::admit_size(self, root, size)
    }

    /// Shortens an object's payload and outboard to the size a commit settled.
    ///
    /// The one place a file in the CAS is ever made smaller, and it runs only
    /// after a commit that *completed* the object — at which point the final
    /// group is held and the size is a fact rather than a claim
    /// (the attestation predicate). What it cleans up is the overstatement
    /// case: an entry claimed a few bytes more than the object has, the sparse
    /// payload was grown to fit the claim, and the honest writer that finished
    /// the object replaced it. Best effort — a payload left long costs disk,
    /// not correctness, because every read is bounded by the tree.
    pub(crate) fn trim_to_size(&self, root: &Hash, commit: Commit) {
        if !commit.complete {
            return;
        }
        for (path, len) in [
            (self.blob_path(root), commit.size),
            (
                self.outboard_path(root),
                Self::tree(commit.size).outboard_size(),
            ),
        ] {
            if let Ok(file) = OpenOptions::new().write(true).open(&path) {
                if file.metadata().is_ok_and(|m| m.len() > len) {
                    let _ = file.set_len(len);
                }
            }
        }
    }

    // ---- index reads ------------------------------------------------------

    /// Reads the local index row for an object.
    pub fn blob(&self, root: &Hash) -> Result<Option<BlobRow>> {
        let conn = self.conn();
        let row = conn
            .query_row(
                &format!("SELECT {BLOB_COLUMNS} FROM blobs WHERE root = ?1"),
                params![root.as_bytes().to_vec()],
                raw_blob_row,
            )
            .optional()?;
        row.map(blob_row_from).transpose()
    }

    /// Every locally held object, as the columns a sweep or a report reads.
    ///
    /// [`Store::blobs`] returns whole rows, which means `inline` — up to
    /// [`INLINE_BLOB_MAX`] per row — and `bitmap`. Neither GC nor `synch
    /// doctor` looks at either: they read the root, the completeness flag, the
    /// pin state and `last_access`. Pulling the payloads anyway made a pass
    /// over a store of many small objects allocate the inlined half of the CAS,
    /// every five minutes and again on every doctor run, and drop all of it.
    pub fn blob_candidates(&self) -> Result<Vec<BlobSummary>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT root, size, complete, durable,
                    EXISTS(SELECT 1 FROM pins WHERE pins.root = blobs.root),
                    last_access
             FROM blobs ORDER BY last_access DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (root, size, complete, durable, pinned, last_access) = row?;
            out.push(BlobSummary {
                root: hash_column(root, "blobs.root")?,
                size: size as u64,
                complete: complete != 0,
                durable: durable != 0,
                pinned: pinned != 0,
                last_access,
            });
        }
        Ok(out)
    }

    /// Every locally held object.
    pub fn blobs(&self) -> Result<Vec<BlobRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {BLOB_COLUMNS} FROM blobs ORDER BY last_access DESC"
        ))?;
        let rows = stmt.query_map([], raw_blob_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(blob_row_from(row?)?);
        }
        Ok(out)
    }

    /// True if the whole object is present and verified locally.
    #[cfg(test)]
    pub(crate) fn has_complete_blob(&self, root: &Hash) -> Result<bool> {
        Ok(self.blob(root)?.is_some_and(|b| b.complete || b.durable))
    }

    /// The advertisement this node should publish for an object (§6.3).
    pub fn local_ad(&self, root: &Hash) -> Result<Option<BlobAd>> {
        Ok(self.blob(root)?.map(|blob| blob.to_ad()))
    }

    /// Records that the configured backend has promoted a complete object to
    /// stable storage. Call only after the backend's durability promise.
    ///
    /// The transition is the Lean command `Cas.Durable.markDurable`; it never
    /// creates a row.
    pub(crate) fn mark_blob_durable(&self, root: &Hash) -> Result<bool> {
        crate::lean_durable::mark_durable(self, root)
    }

    /// Reconstructs a cold durable row after metadata restore, once the remote
    /// backend has confirmed that the final payload/outboard pair exists.
    ///
    /// `Cas.AdoptRemote` is this row creation from a remote pair the backend
    /// has just confirmed; it only ever adds availability. The row decision
    /// (agreeing size marked, missing row created, disagreeing size refused)
    /// is the Lean command `Cas.Durable.adoptDurable`.
    pub(crate) fn adopt_durable_blob(&self, root: &Hash, size: u64, now: i64) -> Result<()> {
        crate::lean_durable::adopt_durable(self, root, size, now)
    }

    /// Applies the authoritative S3 `NoSuchKey` heal rule.
    ///
    /// The durable claim is withdrawn. A row with no verified cache bytes is
    /// removed altogether; otherwise it remains a partial peer-fetched cache.
    ///
    /// `FaultTolerant.HealRemote` is this transaction, the Lean command
    /// `Cas.Durable.healMissing`: the durable claim is withdrawn, role pins
    /// become wants, the operator's pin is left alone. The backend losing the
    /// object is the environment step before it. A replica's claim must not
    /// outlive the bytes it was a promise about (`docs/REPLICATION.md` §8):
    /// this is the one place where absence of bytes *is* evidence, because the
    /// backend answered `NotFound` about a content address. The repair is
    /// gated on the *withdrawal*, not on the row disappearing: a cloud
    /// replica reaches `durable=1, complete=0, bitmap NOT NULL` in the
    /// ordinary course of things, and for such a row nothing is deleted.
    /// `CasDurableProofs.lean` proves the gating and what moves.
    pub(crate) fn heal_missing_durable_blob(&self, root: &Hash) -> Result<bool> {
        crate::lean_durable::heal_missing(self, root)
    }

    /// Reconciles database cache claims with an ephemeral scratch generation.
    ///
    /// A changed marker drops staged-only rows and clears cached groups on
    /// durable rows in one transaction. A matching marker is an O(1) no-op.
    /// The transaction is the Lean command `Cas.Durable.reconcileScratch`.
    pub fn reconcile_scratch_generation(&self, marker: &str) -> Result<bool> {
        crate::lean_durable::reconcile_scratch(self, marker)
    }

    /// Whether both files behind a complete out-of-line cache claim exist.
    pub fn cached_blob_files_present(&self, root: &Hash, _size: u64) -> bool {
        self.blob_path(root).is_file() && self.outboard_path(root).is_file()
    }

    /// Reads the whole cached outboard when present.
    pub(crate) fn cached_outboard(&self, root: &Hash) -> Option<Vec<u8>> {
        std::fs::read(self.outboard_path(root)).ok()
    }

    /// Caches a complete remote outboard without claiming any payload groups.
    pub(crate) fn cache_outboard(&self, root: &Hash, bytes: &[u8]) -> Result<()> {
        let _lease = self.lease_write(root);
        write_and_sync(&self.staging_dir(), &self.outboard_path(root), bytes)
    }

    /// Drops only reconstructible local bytes while retaining a remote durable
    /// claim. The row changes first, so a crash can leave only harmless orphan
    /// files, never a warm-cache claim with missing bytes.
    pub(crate) fn clear_blob_cache(&self, root: &Hash) -> Result<bool> {
        // `Cas.CacheEvict` retains remote durability when local cache
        // bytes disappear; callers select durable cache rows.
        //
        // `Cas.DropStaged` is the row removal of a non-durable cache claim
        // inside it, and the same transition behind
        // `reconcile_scratch_generation` and the `commit_cas_migration`
        // discard. None of the three consults `pins`:
        // `SystemSafety.staged_row_drop_is_unpinned` is why they need not
        // (`Cas.NoLoss`: a pin is only ever granted over available content),
        // and `Store::pin`'s `durable` predicate is what makes that theorem
        // true of the store. The Lean command `Cas.Durable.clearCache` reads
        // the writer count first, changes the rows, and removes the files
        // after the commit; Rust holds the ordering guard that makes the
        // count it reads meaningful.
        let conn = self.conn();
        let _ordered_against_writers = self.cas_order();
        crate::lean_durable::clear_cache(self, &conn, root)
    }

    /// Atomically commits a verified backend migration and drops leftover
    /// cloud-only staged filesystem rows. The caller holds the lifecycle lock.
    pub fn commit_cas_migration(
        &self,
        target: &str,
        settings: &[(String, Option<String>)],
        migrated: &[Hash],
        discard_nondurable: bool,
    ) -> Result<usize> {
        let discarded = self.with_immediate_tx(|tx| {
            for root in migrated {
                tx.execute(
                    "UPDATE blobs SET durable = 1 WHERE root = ?1",
                    params![root.as_bytes().to_vec()],
                )?;
            }
            let discarded = if discard_nondurable {
                let mut stmt =
                    tx.prepare("SELECT root FROM blobs WHERE durable = 0 AND inline IS NULL")?;
                let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
                let mut roots = Vec::new();
                for row in rows {
                    roots.push(hash_column(row?, "blobs.root")?);
                }
                roots
            } else {
                Vec::new()
            };
            if discard_nondurable {
                tx.execute("DELETE FROM blobs WHERE durable = 0 AND inline IS NULL", [])?;
            }
            crate::db::set_config_in(tx, "cas.backend", target)?;
            for (key, value) in settings {
                match value {
                    Some(value) => crate::db::set_config_in(tx, key, value)?,
                    None => crate::db::clear_config_in(tx, key)?,
                }
            }
            Ok(discarded)
        })?;
        for root in &discarded {
            let _ = std::fs::remove_file(self.blob_path(root));
            let _ = std::fs::remove_file(self.outboard_path(root));
        }
        Ok(discarded.len())
    }

    /// Evicts least-recently-used durable cache entries until the cache is
    /// within `limit` bytes and `shortfall` bytes more are free. Pinned rows
    /// are eligible because their promise lives remotely; staged-only rows
    /// are never eligible because scratch is their only copy. Which rows, in
    /// what order, the measure of each and the refusal of one a writer holds
    /// are the Lean program's; returns the entries evicted and the bytes freed.
    pub(crate) fn evict_durable_cache(
        &self,
        limit: Option<u64>,
        shortfall: u64,
    ) -> Result<(usize, u64)> {
        crate::lean_collect::evict(self, limit, shortfall)
    }

    /// Advances a cache entry's LRU clock after a backend-served read. The
    /// Lean program coalesces touches to once a minute against the row's own
    /// stamp and never moves it backwards; answers whether it moved.
    pub(crate) fn touch_blob(&self, root: &Hash) -> Result<bool> {
        crate::lean_collect::touch(self, root)
    }

    /// Records one holder's claim on an object against GC (§9.2,
    /// `docs/REPLICATION.md` §3.1).
    ///
    /// Returns whether an object with this root was there to hold. A pin that
    /// matched nothing guards nothing, and the caller is the one that can say
    /// so — silently succeeding here is how a pin of never-fetched content once
    /// vanished without a trace. The check and the insert share one immediate
    /// transaction, or a GC pass landing between them collects the object this
    /// call is about to report as pinned.
    ///
    /// Re-pinning what this holder already holds clears any scheduled release:
    /// content that comes back is content that stays, and the root reappearing
    /// under a live entry is exactly the evidence that the release was decided
    /// against a tree that has since changed its mind.
    pub fn pin(&self, root: &Hash, holder: &PinHolder, now: i64) -> Result<bool> {
        self.acquire_pin(root, holder, now, false)
    }

    /// Execute the complete Lean pin/possession operation over raw storage.
    /// A pin promises a durable claim, never merely a partial or staged cache
    /// row. Possession also needs the holder's uncancelled want, so a late fetch
    /// cannot resurrect an orphan role claim after role removal.
    /// This durable-only contract is why staged-row eviction need not consult
    /// pins: scratch copies cannot acquire promises about durable availability.
    pub(crate) fn acquire_pin(
        &self,
        root: &Hash,
        holder: &PinHolder,
        now: i64,
        possession: bool,
    ) -> Result<bool> {
        use synch_verified::cas::acquire;
        let conn = self.conn();
        let _ordered_against_writers = self.cas_order();
        let mut storage = crate::lean_storage::SqliteStorage::new(&conn);
        // Lean requests begin before reading metadata and owns every normal
        // completion/failure path. Rust holds host resources, not policy facts.
        acquire(
            &mut storage,
            root.as_bytes(),
            &holder.render(),
            now,
            possession,
        )
        .map_err(|error| {
            crate::lean_diagnostics::lifecycle_error(error, "invalid CAS acquisition metadata")
        })
    }

    /// Drops one holder's claim. Returns whether one was dropped.
    ///
    /// A role holder's claim is refused while an entry in its space still
    /// names the root: a source's or replica's pin is what the live leaf
    /// stands on, and removing it from underneath is exactly the state the
    /// model forbids. The operator's claim has no leaf behind it and goes
    /// unconditionally.
    pub fn unpin(&self, root: &Hash, holder: &PinHolder) -> Result<bool> {
        use synch_verified::cas::{unpin, OperationError, PinHolder as Holder};
        let holder = match holder {
            PinHolder::Operator => Holder::Operator,
            PinHolder::Source(space) => Holder::Source(space.clone()),
            PinHolder::Replica(space) => Holder::Replica(space.clone()),
            PinHolder::Other(text) => Holder::Other(text.clone()),
        };
        self.with_connection_scope(|conn| {
            let mut storage = crate::lean_storage::SqliteStorage::new(conn);
            unpin(&mut storage, root.as_bytes(), holder).map_err(|error| match error {
                OperationError::Host(error) => error,
                OperationError::MalformedMetadata(_) | OperationError::Protocol => {
                    StoreError::invalid("invalid native release-operation protocol")
                }
            })
        })
    }

    /// Schedules one holder's claim to end, without ending it yet
    /// (`docs/REPLICATION.md` §3.4).
    ///
    /// Idempotent in the direction that matters: a release already scheduled
    /// keeps its original instant rather than being pushed further out by a
    /// second observation of the same departure, so a path that churns cannot
    /// hold a superseded root forever.
    #[cfg(test)]
    pub(crate) fn schedule_release(
        &self,
        root: &Hash,
        holder: &PinHolder,
        at: i64,
    ) -> Result<bool> {
        let touched = self.conn().execute(
            "UPDATE pins SET release_after = ?3
               WHERE root = ?1 AND holder = ?2 AND release_after IS NULL",
            params![root.as_bytes().to_vec(), holder.render(), at],
        )?;
        Ok(touched > 0)
    }

    /// Drops one holder's claims whose scheduled release has arrived.
    ///
    /// Per holder so that a sweep can report what *this* space let go of. The
    /// node-wide [`Store::expire_pins`] stays as the catch-all for holders no
    /// sweep visits any more: a space removed with its pins kept still has
    /// claims that were scheduled before it went.
    pub fn expire_pins_of(&self, holder: &PinHolder, now: i64) -> Result<usize> {
        self.expire_claims(Some(holder), now)
    }

    /// Drops claims whose scheduled release has arrived, so that every other
    /// predicate over `pins` can stay free of the clock. Returns how many went.
    pub fn expire_pins(&self, now: i64) -> Result<usize> {
        self.expire_claims(None, now)
    }

    fn expire_claims(&self, holder: Option<&PinHolder>, now: i64) -> Result<usize> {
        use synch_verified::cas::{expire, OperationError, PinHolder as Holder};
        let holder = holder.map(|holder| match holder {
            PinHolder::Operator => Holder::Operator,
            PinHolder::Source(space) => Holder::Source(space.clone()),
            PinHolder::Replica(space) => Holder::Replica(space.clone()),
            PinHolder::Other(text) => Holder::Other(text.clone()),
        });
        self.with_connection_scope(|conn| {
            let mut storage = crate::lean_storage::SqliteStorage::new(conn);
            let count = expire(&mut storage, holder, now).map_err(|error| match error {
                OperationError::Host(error) => error,
                OperationError::MalformedMetadata(_) | OperationError::Protocol => {
                    StoreError::invalid("invalid native expiry-operation protocol")
                }
            })?;
            usize::try_from(count)
                .map_err(|_| StoreError::invalid("native expiry count exceeds address space"))
        })
    }

    /// Every claim on one object, oldest first.
    pub fn pins_for(&self, root: &Hash) -> Result<Vec<PinRow>> {
        self.query_pins("WHERE root = ?1", params![root.as_bytes().to_vec()])
    }

    /// Every claim this node holds, by object and then by holder.
    pub fn pins(&self) -> Result<Vec<PinRow>> {
        self.query_pins("", params![])
    }

    fn query_pins(&self, filter: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<PinRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT root, holder, created_at, release_after FROM pins {filter}
             ORDER BY root, holder"
        ))?;
        let rows = stmt.query_map(args, |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (root, holder, created_at, release_after) = row?;
            out.push(PinRow {
                root: hash_column(root, "pins.root")?,
                // A holder spelling this build does not know is kept as a
                // holder rather than dropped: an unreadable claim is still a
                // claim, and forgetting it is how bytes go missing after a
                // downgrade.
                holder: PinHolder::parse(&holder),
                created_at,
                release_after,
            });
        }
        Ok(out)
    }

    /// Every pinned object.
    pub fn pinned_blobs(&self) -> Result<Vec<Hash>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT DISTINCT root FROM pins ORDER BY root")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(hash_column(row?, "pins.root")?);
        }
        Ok(out)
    }

    /// Deletes an object, but only if it is still a GC candidate.
    ///
    /// The predicate is re-read inside an immediate transaction rather than
    /// trusted from the caller's snapshot, and the unlinks happen only if the
    /// commit says the row was still deletable. `gc_content` reads the
    /// referenced set, the pinned set and the candidate rows as three separate
    /// statements and then deletes in a fourth, which is exactly the split
    /// [`Store::gc_trie`] documents as a data-loss bug: a `synch pin`, or a
    /// resumed fetch's first commit, landing in the gap would otherwise be
    /// decided against by a snapshot taken before it existed. The pin case is
    /// the plain one — the command reports success and the object is unlinked
    /// moments later — and
    /// the fetch case is worse, because `commit_groups` then re-inserts a row
    /// whose bitmap claims groups whose bytes went to an unlinked inode, which
    /// the node would then advertise without any reachable payload.
    ///
    /// The unlinks cannot join the transaction — SQLite rolls back, `unlink`
    /// does not — so they stay after the commit, in the order
    /// [`Store::delete_blob`] explains.
    ///
    /// Returns whether the object was deleted.
    #[cfg(test)]
    pub(crate) fn delete_blob_if_collectable(&self, root: &Hash, before: i64) -> Result<bool> {
        // The connection and shared CAS order guards are held across the
        // unlinks, not just across the transaction, so no row writer or writer
        // from an independently opened Store can slip between the decision and
        // the files going.
        //
        // Every writer of a blob row goes through this mutex; no writer of a
        // blob's *bytes* does.
        // `write_slice` creates, grows, decodes and fsyncs the payload and the
        // outboard with nothing held, and only then takes the connection to
        // commit. Holding the guard across the unlinks therefore forces that
        // commit to land *after* them — which is precisely the bad order, since
        // the writer's bytes went into the inode this just unlinked. What that
        // leaves is the state `delete_blob` calls the dangerous orphan:
        // `complete`/bitmap set with no payload, advertised by `local_ad`,
        // failing every read, and self-healing never, because the new row is
        // warm so `gc_content` skips it and `gc_orphans` only removes files that
        // have *no* row.
        //
        // So the writer's own mark is consulted, under the same guard. A write
        // in flight is not a collectable object, whatever the row says.
        Ok(
            self.execute_blob_deletion(root, Some(before))?
                == synch_verified::cas::Outcome::Applied,
        )
    }

    /// Deletes an unprotected object's payload, outboard, and index row.
    ///
    /// Unlike GC this has no age horizon, but it still re-checks every safety
    /// predicate in the transaction that removes the row. An API called
    /// "delete" must not be a back door around a live entry or pin: callers
    /// remove those claims first, then delete the now-unprotected cache object.
    pub fn delete_blob(&self, root: &Hash) -> Result<()> {
        use synch_verified::cas::Outcome;
        match self.execute_blob_deletion(root, None)? {
            Outcome::Writing => Err(StoreError::invalid(format!(
                "blob {root} is being written and cannot be deleted"
            ))),
            Outcome::ProtectedClaim => Err(StoreError::invalid(format!(
                "blob {root} is referenced or pinned and cannot be deleted"
            ))),
            Outcome::Applied => Ok(()),
            _ => unreachable!("explicit Lean deletion returned a nonterminal outcome"),
        }
    }

    /// Execute Lean's ordered deletion effects while holding both ordering
    /// guards. The SQL only reads facts or performs unconditional keyed writes;
    /// policy and the commit-before-unlink protocol live in the native core.
    fn execute_blob_deletion(
        &self,
        root: &Hash,
        before: Option<i64>,
    ) -> Result<synch_verified::cas::Outcome> {
        use synch_verified::cas::delete;
        let conn = self.conn();
        let _ordered_against_writers = self.cas_order();
        let mut storage = crate::lean_storage::SqliteStorage::new(&conn);
        let mut resources = crate::lean_storage::Resources(self);
        delete(&mut storage, &mut resources, root.as_bytes(), before).map_err(|error| {
            crate::lean_diagnostics::lifecycle_error(error, "invalid CAS deletion metadata")
        })
    }

    /// Simulates storage loss for recovery and race tests.
    ///
    /// Production code has no unconditional deletion path: bypassing the
    /// protection predicate would invalidate the CAS safety invariant.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn force_delete_blob_for_test(&self, root: &Hash) -> Result<()> {
        // Row first, bytes second. The reverse order leaves the dangerous
        // orphan: a crash between the unlink and the delete leaves a row saying
        // `complete=1` with no bytes behind it, so `has_complete_blob` keeps
        // answering yes, `local_ad` keeps advertising the object to peers, and
        // reads fail with a raw io error rather than `MissingBlob`. This way a
        // crash usually leaves the opposite — files with no row — which costs
        // disk until the next sweep and never lies to anyone.
        //
        // Usually, not always: the ordering is comparative, not a guarantee.
        // Under `journal_mode=WAL` with `synchronous=NORMAL` the row delete is
        // not fsynced at commit, so a power loss can roll it back while the
        // unlink survives, producing the bad state anyway. What makes that
        // tolerable rather than a durability bug is that it self-heals: a blob
        // only reaches here because it was unreferenced, unpinned and cold, and
        // a restored row still is, so the next `gc_content` pass deletes it
        // again. The window is one GC interval, on an object nothing in the
        // tree references.
        // The guard spans the unlinks for the same reason
        // `delete_blob_if_collectable` holds it: a writer committing a row for
        // this root between the delete and the unlinks would be left with a row
        // whose bytes are gone.
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM blobs WHERE root = ?1",
            params![root.as_bytes().to_vec()],
        )?;
        tx.commit()?;
        let _ = std::fs::remove_file(self.blob_path(root));
        let _ = std::fs::remove_file(self.outboard_path(root));
        drop(conn);
        Ok(())
    }

    // ---- reads ------------------------------------------------------------

    /// Reads a byte range from the trusted storage backend.
    pub fn read_range(&self, root: &Hash, offset: u64, len: u64) -> Result<Vec<u8>> {
        crate::lean_read::read(
            self,
            root,
            synch_verified::cas::ReadRequest::Range {
                offset,
                length: len,
            },
        )
    }

    /// Reads a whole object from the trusted storage backend.
    pub fn read_all(&self, root: &Hash) -> Result<Vec<u8>> {
        crate::lean_read::read(self, root, synch_verified::cas::ReadRequest::All)
    }

    // ---- slice serving and receiving --------------------------------------

    /// Encodes a bao slice for the requested ranges, returning the encoded
    /// bytes and the ranges actually served (§6.4).
    ///
    /// The provider serves the intersection of what was asked for and what it
    /// verifiably holds; the requester learns exact availability from the
    /// returned ranges, which is what `SliceEnd` carries.
    ///
    /// At most [`synch_core::MAX_SLICE_GROUPS`] groups are served per call, whatever was
    /// asked for. The encoding is built in memory and travels in one frame, so
    /// an unclamped request would let a peer name an object-sized allocation —
    /// and no honest requester needs one, because `SliceEnd` tells it exactly
    /// how far it got and its next window starts there (§6.4, §12).
    ///
    /// The window (what was asked for, that the row holds, within the object,
    /// clamped) is the Lean command `Cas.Serve.encodeSlice`; this store is
    /// the Bao service that encodes exactly the groups it names.
    pub fn encode_slice(
        &self,
        root: &Hash,
        requested: &ChunkRanges,
    ) -> Result<(Vec<u8>, ChunkRanges)> {
        crate::lean_serve::encode_slice(self, root, requested)
    }

    /// Caches one group-aligned range returned by the trusted remote backend.
    ///
    /// This deliberately does not run the bytes back through bao. OpenDAL's
    /// successful write/read contract is the storage-integrity boundary; bao
    /// verification remains for slices received from peers in [`Store::write_slice`].
    pub(crate) fn cache_trusted_range(
        &self,
        root: &Hash,
        size: u64,
        offset: u64,
        bytes: &[u8],
        now: i64,
    ) -> Result<ChunkRanges> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| StoreError::invalid("trusted cache range overflowed"))?;
        if offset > size || end > size {
            return Err(StoreError::RangeOutOfBounds {
                start: offset,
                end,
                size,
            });
        }
        if !offset.is_multiple_of(CHUNK_GROUP_SIZE)
            || (end != size && !end.is_multiple_of(CHUNK_GROUP_SIZE))
        {
            return Err(StoreError::invalid(
                "trusted cache writes must cover whole chunk groups",
            ));
        }
        let served = if size == 0 {
            ChunkRanges::single(0, 1)
        } else {
            ChunkRanges::from_ranges([groups_for_byte_range(offset, end)])
                .intersect(&ChunkRanges::single(0, group_count(size)))
        };
        if served.is_empty() {
            return Ok(served);
        }

        let _lease = self.lease_write(root);
        self.admit_size(root, size)?;
        if self.blob(root)?.is_some_and(|row| row.complete) {
            return Ok(ChunkRanges::empty());
        }

        if size <= INLINE_BLOB_MAX {
            if offset != 0 || end != size {
                return Err(StoreError::invalid(
                    "an inline cache fill must contain the whole object",
                ));
            }
            self.commit_groups(root, size, &served, Some(bytes.to_vec()), now)?;
            return Ok(served);
        }

        let payload_path = self.blob_path(root);
        if let Some(parent) = payload_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut payload = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&payload_path)?;
        payload.write_all_at(offset, bytes)?;
        fsync_file(&payload)?;
        fsync_parent(&payload_path);
        let commit = self.commit_groups(root, size, &served, None, now)?;
        self.trim_to_size(root, commit);
        Ok(served)
    }

    /// Decodes a received bao slice into the CAS, verifying every group against
    /// the object root before committing it (§6.4).
    ///
    /// Returns the groups newly verified. Progress survives restarts: verified
    /// groups are committed to the bitmap immediately.
    pub fn write_slice(
        &self,
        root: &Hash,
        size: u64,
        served: &ChunkRanges,
        encoded: &[u8],
        now: i64,
    ) -> Result<ChunkRanges> {
        crate::lean_receive::write_slice(self, root, size, served, encoded, now)
    }

    /// The inline half of the Bao slice service: decode `encoded`, a slice of
    /// exactly `served`, against the root into the object's inline buffer,
    /// starting from the bytes the row already holds and zero-filled to `size`.
    pub(crate) fn decode_inline(
        &self,
        root: &Hash,
        size: u64,
        inline: Option<&[u8]>,
        served: &ChunkRanges,
        encoded: &[u8],
    ) -> Result<Vec<u8>> {
        let mut buffer = inline
            .map(<[u8]>::to_vec)
            .unwrap_or_else(|| vec![0u8; size as usize]);
        buffer.resize(size as usize, 0);
        let outboard = PreOrderOutboard {
            root: blake3::Hash::from_bytes(root.0),
            tree: Self::tree(size),
            data: Vec::<u8>::new(),
        };
        decode_ranges(
            std::io::Cursor::new(encoded),
            &to_bao_ranges(served),
            buffer.as_mut_slice(),
            MemOutboard(outboard),
        )
        .map_err(|e| StoreError::Verification {
            root: *root,
            reason: e.to_string(),
        })?;
        Ok(buffer)
    }

    /// The file half of the Bao slice service: decode `encoded`, a slice of
    /// exactly `served`, against the root into the object's sparse payload and
    /// outboard, created as needed and left unflushed.
    ///
    /// Not pre-grown at all, and never shrunk. Never shrunk, because sizing a
    /// file down on the strength of a claim is how an understated entry
    /// destroys verified groups: bytes gone, bitmap bits intact, the node
    /// advertising a group it can no longer serve ([`grow_to`],
    /// `docs/DELTA-SYNC.md` §6). Not pre-grown, because `size` is a peer's
    /// assertion off an entry and this runs *before* `decode_ranges` turns any
    /// of it into fact: an entry claiming 32 TiB for any root would otherwise
    /// have every node that attempts a fetch create a 32 TiB payload and a
    /// 128 GiB outboard, fail verification, and leave both behind. The decode
    /// extends the file as each verified group lands, so the payload never
    /// gets longer than the bytes proven against the root.
    pub(crate) fn decode_slice_into_files(
        &self,
        root: &Hash,
        size: u64,
        served: &ChunkRanges,
        encoded: &[u8],
    ) -> Result<()> {
        let payload_path = self.blob_path(root);
        if let Some(parent) = payload_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let payload = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&payload_path)?;
        let outboard_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.outboard_path(root))?;
        let outboard = PreOrderOutboard {
            root: blake3::Hash::from_bytes(root.0),
            tree: Self::tree(size),
            data: outboard_file,
        };
        decode_ranges(
            std::io::Cursor::new(encoded),
            &to_bao_ranges(served),
            DataFile(payload),
            outboard,
        )
        .map_err(|e| StoreError::Verification {
            root: *root,
            reason: e.to_string(),
        })
    }

    /// Flush the object's payload and outboard, contents and directory
    /// entries, to stable storage; a file that does not exist has nothing to
    /// flush. Both flushes are checked: swallowing them would let an EIO or
    /// ENOSPC on flush advance the bitmap over data that never reached stable
    /// storage. The directory entries too, not only the contents: the first
    /// window of a fetch creates the files, and `fsync` promises the bytes,
    /// not that the name they hang from survives; unlike an orphaned file, a
    /// lost name under an advanced bitmap never self-heals. Reopened for
    /// *write* to flush, which is what Windows requires of a flush.
    pub(crate) fn flush_object(&self, root: &Hash) -> Result<()> {
        for path in [self.blob_path(root), self.outboard_path(root)] {
            if !path.is_file() {
                continue;
            }
            fsync_file(&OpenOptions::new().write(true).open(&path)?)?;
            fsync_parent(&path);
        }
        Ok(())
    }
}

/// `positioned-io` gives `File` the random-access reads and writes bao needs;
/// this newtype exists only so the trait bounds resolve on both platforms
/// without importing `positioned-io` directly.
pub(crate) struct DataFile(pub(crate) File);

impl bao_tree::io::sync::ReadAt for DataFile {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        <File as bao_tree::io::sync::ReadAt>::read_at(&self.0, pos, buf)
    }
}

impl bao_tree::io::sync::WriteAt for DataFile {
    fn write_at(&mut self, pos: u64, buf: &[u8]) -> std::io::Result<usize> {
        <File as bao_tree::io::sync::WriteAt>::write_at(&mut self.0, pos, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        <File as bao_tree::io::sync::WriteAt>::flush(&mut self.0)
    }
}

impl bao_tree::io::sync::Size for DataFile {
    fn size(&self) -> std::io::Result<Option<u64>> {
        <File as bao_tree::io::sync::Size>::size(&self.0)
    }
}

/// An outboard that discards writes, for single-group objects whose outboard is
/// empty by construction.
struct MemOutboard(PreOrderOutboard<Vec<u8>>);

impl bao_tree::io::sync::Outboard for MemOutboard {
    fn root(&self) -> blake3::Hash {
        self.0.root
    }
    fn tree(&self) -> BaoTree {
        self.0.tree
    }
    fn load(
        &self,
        node: bao_tree::TreeNode,
    ) -> std::io::Result<Option<(blake3::Hash, blake3::Hash)>> {
        bao_tree::io::sync::Outboard::load(&self.0, node)
    }
}

impl bao_tree::io::sync::OutboardMut for MemOutboard {
    fn save(
        &mut self,
        node: bao_tree::TreeNode,
        pair: &(blake3::Hash, blake3::Hash),
    ) -> std::io::Result<()> {
        bao_tree::io::sync::OutboardMut::save(&mut self.0, node, pair)
    }

    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A reader that copies everything it yields into a sink, so hashing a file and
/// writing it into the CAS take one pass over the bytes.
/// Retained for cloud ingestion, whose separate outer operation still awaits
/// migration. Mandatory local ingestion does not use this Rust orchestration.
pub(crate) struct TeeReader {
    pub(crate) inner: std::fs::File,
    pub(crate) sink: std::fs::File,
}

impl Read for TeeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.sink.write_all(&buf[..n])?;
        Ok(n)
    }
}

/// Legacy cloud-ingestion builder and independent test oracle. Local
/// ingestion constructs its hash tree and outboard entirely in Lean.
pub(crate) fn compute_outboard(
    data: impl Read,
    tree: BaoTree,
    outboard: &mut [u8],
) -> Result<Hash> {
    let mut ob = bao_tree::io::outboard::PreOrderMemOutboard {
        root: blake3::Hash::from_bytes([0u8; 32]),
        tree,
        data: outboard,
    };
    let root = bao_tree::io::sync::outboard(data, tree, &mut ob)?;
    Ok(Hash(*root.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_metadata_reports_text_type_before_invalid_utf8() {
        let (_dir, store) = crate::testutil::store();
        let root = Hash::new(b"raw text integer metadata");
        {
            let conn = store.conn();
            conn.execute_batch(
                "CREATE TEMP TABLE blobs (root BLOB PRIMARY KEY, durable, last_access)",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO blobs VALUES (?1, CAST(X'FF' AS TEXT), CAST(X'FE' AS TEXT))",
                params![root.as_bytes().to_vec()],
            )
            .unwrap();
        }
        for (column, result) in [
            (
                "durable",
                store
                    .acquire_pin(&root, &PinHolder::Operator, 1, false)
                    .map(|_| ()),
            ),
            ("last_access", store.delete_blob(&root)),
        ] {
            match result.unwrap_err() {
                StoreError::Sqlite(rusqlite::Error::InvalidColumnType(
                    0,
                    name,
                    rusqlite::types::Type::Text,
                )) => assert_eq!(name, column),
                other => panic!("raw text preempted the integer field error: {other:?}"),
            }
            assert!(store.conn().is_autocommit());
        }
    }

    #[test]
    fn acquisition_preserves_sqlite_column_errors_for_corrupt_durability() {
        use rusqlite::types::Value;

        for value in [
            Value::Null,
            Value::Text("1".into()),
            Value::Text("not an integer".into()),
            Value::Blob(vec![]),
            Value::Blob(vec![1]),
            Value::Real(1.5),
        ] {
            let (_dir, store) = crate::testutil::store();
            let root = Hash::new(b"corrupt durability fixture");
            let expected_type = {
                let conn = store.conn();
                // A temporary raw table models damaged column types without
                // changing the persisted schema or bypassing NOT NULL checks.
                conn.execute_batch("CREATE TEMP TABLE blobs (root BLOB PRIMARY KEY, durable)")
                    .unwrap();
                conn.execute(
                    "INSERT INTO blobs (root, durable) VALUES (?1, ?2)",
                    params![root.as_bytes().to_vec(), value],
                )
                .unwrap();
                let old_error = conn
                    .query_row("SELECT durable FROM blobs", [], |row| row.get::<_, i64>(0))
                    .unwrap_err();
                match old_error {
                    rusqlite::Error::InvalidColumnType(0, column, kind) => {
                        assert_eq!(column, "durable");
                        kind
                    }
                    other => panic!("unexpected reference decoder error: {other:?}"),
                }
            };
            for possession in [false, true] {
                let error = store
                    .acquire_pin(&root, &PinHolder::Operator, 1, possession)
                    .unwrap_err();
                match error {
                    StoreError::Sqlite(rusqlite::Error::InvalidColumnType(0, column, kind)) => {
                        assert_eq!(column, "durable");
                        assert_eq!(kind, expected_type);
                    }
                    other => panic!("native acquisition changed the error: {other:?}"),
                }
                assert!(store.conn().is_autocommit());
                assert!(store.pins_for(&root).unwrap().is_empty());
            }
        }
    }

    #[test]
    fn durable_rows_survive_cold_scratch_and_heal_missing_objects() {
        let (_dir, store) = crate::testutil::store();
        let root = store.ingest_bytes(&vec![7u8; 100_000], 1).unwrap();

        assert!(store.reconcile_scratch_generation("first").unwrap());
        let cold = store.blob(&root).unwrap().unwrap();
        assert!(!cold.complete);
        assert!(cold.durable);
        assert!(store.has_complete_blob(&root).unwrap());
        assert!(store.local_ad(&root).unwrap().unwrap().is_complete());
        assert!(!store.reconcile_scratch_generation("first").unwrap());

        assert!(store.heal_missing_durable_blob(&root).unwrap());
        assert!(store.blob(&root).unwrap().is_none());
    }

    /// An empty verified set has one database spelling: `bitmap IS NULL`.
    /// `HealRemote` reads that spelling as a cold row and removes it after the
    /// backend withdraws durability, matching the Lean `held = ∅` branch.
    #[test]
    fn an_empty_group_commit_is_removed_by_the_remote_heal() {
        let (_dir, store) = crate::testutil::store();
        let root = Hash::new(b"proof-only row");
        let size = 4 * CHUNK_GROUP_SIZE;

        store
            .commit_groups(&root, size, &ChunkRanges::empty(), None, 0)
            .unwrap();
        let cold = store.blob(&root).unwrap().unwrap();
        assert!(cold.bitmap.is_none());
        assert!(cold.verified_groups().is_empty());

        store.adopt_durable_blob(&root, size, 1).unwrap();
        assert!(store.heal_missing_durable_blob(&root).unwrap());
        assert!(store.blob(&root).unwrap().is_none());
    }

    #[test]
    fn a_missing_source_blob_becomes_a_repair_want() {
        let (_dir, store) = crate::testutil::store();
        store
            .put_source("media", crate::SourceKind::Api, None)
            .unwrap();
        let bytes = vec![7u8; 100_000];
        let root = store.ingest_bytes(&bytes, 1).unwrap();
        let holder = crate::PinHolder::Source("media".into());
        store.pin(&root, &holder, 1).unwrap();

        std::fs::remove_file(store.blob_path(&root)).unwrap();
        assert!(store.read_all(&root).is_err());

        let blob = store.blob(&root).unwrap().unwrap();
        assert!(!blob.complete);
        assert!(!blob.durable);
        let wants = store.wants_of(&holder).unwrap();
        assert_eq!(wants.len(), 1);
        assert_eq!(wants[0].root, root);
        assert_eq!(wants[0].size, bytes.len() as u64);
    }

    #[test]
    fn remote_complete_cache_is_not_a_durability_claim() {
        let (_provider_dir, provider) = crate::testutil::store();
        let (_cache_dir, cache) = crate::testutil::store();
        cache.set_remote_cas(true);
        let payload = crate::testutil::data(100_000);
        let root = provider.ingest_bytes(&payload, 0).unwrap();
        let all = ChunkRanges::single(0, group_count(payload.len() as u64));
        let (encoded, served) = provider.encode_slice(&root, &all).unwrap();
        cache
            .write_slice(&root, payload.len() as u64, &served, &encoded, 1)
            .unwrap();
        let row = cache.blob(&root).unwrap().unwrap();
        assert!(row.complete);
        assert!(!row.durable);
        assert!(cache.local_ad(&root).unwrap().unwrap().is_complete());

        // A fresh scratch volume drops the cache-only row entirely.
        cache.reconcile_scratch_generation("new").unwrap();
        assert!(cache.blob(&root).unwrap().is_none());

        let inline = cache.ingest_bytes(b"inline", 2).unwrap();
        assert!(!cache.blob(&inline).unwrap().unwrap().durable);
    }

    /// A pin is a promise about the durable tier. A complete scratch copy on a
    /// cloud backend is not one, and the store says so at both entry points —
    /// which is what lets the staged-row drops skip the pin check
    /// (`SystemSafety.staged_row_drop_is_unpinned`).
    #[test]
    fn a_staged_cloud_row_cannot_be_pinned_or_possessed() {
        let (_d, store) = store();
        store.set_remote_cas(true);
        let root = store.ingest_bytes(&data(100_000), 0).unwrap();
        let row = store.blob(&root).unwrap().unwrap();
        assert!(row.complete && !row.durable);

        assert!(!store.pin(&root, &PinHolder::Operator, 1).unwrap());
        let replica = PinHolder::Replica("media".into());
        assert!(store.stage_want(&root, &replica, 100_000, None, 1).unwrap());
        assert!(!store.take_possession(&root, &replica, 2).unwrap());
        assert_eq!(
            store.wants_of(&replica).unwrap().len(),
            1,
            "a refused possession keeps the want"
        );
        assert!(store.pinned_blobs().unwrap().is_empty());
        // So the scratch reset may drop the row without asking anyone.
        assert!(store.reconcile_scratch_generation("fresh").unwrap());
        assert!(store.blob(&root).unwrap().is_none());

        // Once the backend has the bytes, both claims stand.
        let root = store.ingest_bytes(&data(100_000), 3).unwrap();
        store.mark_blob_durable(&root).unwrap();
        assert!(store.pin(&root, &PinHolder::Operator, 4).unwrap());
        assert!(store.take_possession(&root, &replica, 5).unwrap());
        assert!(store.wants_of(&replica).unwrap().is_empty());
    }

    /// A role's pin is what its live leaf stands on, so the role cannot let
    /// go while an entry in its space still names the root
    /// (`Cas.Unpin`). The operator's claim has no leaf behind it.
    #[test]
    fn a_role_holder_cannot_unpin_content_its_space_still_names() {
        let (_d, store) = store();
        let root = store.ingest_bytes(&data(100_000), 0).unwrap();
        let replica = PinHolder::Replica("media".into());
        assert!(store.pin(&root, &replica, 1).unwrap());
        store
            .put_entry(
                &crate::testutil::origin(),
                "media",
                "a",
                &synch_core::FileEntry::file(100_000, 0, root, 1),
            )
            .unwrap();
        assert!(
            !store.unpin(&root, &replica).unwrap(),
            "the leaf still stands on this pin"
        );
        assert_eq!(store.pinned_blobs().unwrap(), vec![root]);

        assert!(store.pin(&root, &PinHolder::Operator, 2).unwrap());
        assert!(store.unpin(&root, &PinHolder::Operator).unwrap());

        // An entry in some other space is not this role's leaf.
        let other = PinHolder::Replica("docs".into());
        assert!(store.pin(&root, &other, 3).unwrap());
        assert!(store.unpin(&root, &other).unwrap());

        store
            .delete_entry(&crate::testutil::origin(), "media", "a")
            .unwrap();
        assert!(store.unpin(&root, &replica).unwrap());
        assert!(store.pinned_blobs().unwrap().is_empty());
    }

    #[test]
    fn unpin_preserves_typed_holder_identity_and_empty_role_space() {
        let (_d, store) = store();
        let root = store.ingest_bytes(&data(100), 0).unwrap();
        for space in ["media", "", "odd:space'雪"] {
            let role = PinHolder::Source(space.into());
            assert!(store.pin(&root, &role, 1).unwrap());
            store
                .put_entry(
                    &crate::testutil::origin(),
                    space,
                    "a",
                    &synch_core::FileEntry::file(100, 0, root, 1),
                )
                .unwrap();
            assert!(!store.unpin(&root, &role).unwrap());
            // Public Other values intentionally remain opaque: reparsing the
            // identical stored spelling would invent a role guard.
            let opaque = PinHolder::Other(role.render());
            assert!(store.unpin(&root, &opaque).unwrap());
            assert!(!store.unpin(&root, &opaque).unwrap());
        }
    }

    #[test]
    fn failed_unpin_rolls_back_and_preserves_the_claim() {
        let (_d, store) = store();
        let root = store.ingest_bytes(&data(100), 0).unwrap();
        assert!(store.pin(&root, &PinHolder::Operator, 1).unwrap());
        store
            .conn()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_pin_release BEFORE DELETE ON pins
                 BEGIN SELECT RAISE(ABORT, 'release denied'); END;",
            )
            .unwrap();
        let error = store.unpin(&root, &PinHolder::Operator).unwrap_err();
        assert!(error.to_string().contains("release denied"));
        assert!(store.conn().is_autocommit());
        assert_eq!(store.pins_for(&root).unwrap().len(), 1);
    }

    #[test]
    fn expiry_preserves_sqlite_time_ordering_and_cross_space_protection() {
        let (_d, store) = store();
        let root = store.ingest_bytes(&data(100), 0).unwrap();
        for (holder, time) in [
            ("minimum", rusqlite::types::Value::Integer(i64::MIN)),
            ("due", rusqlite::types::Value::Integer(0)),
            ("future", rusqlite::types::Value::Integer(i64::MAX)),
            ("real_due", rusqlite::types::Value::Real(-0.5)),
            ("real_future", rusqlite::types::Value::Real(0.5)),
            ("text", rusqlite::types::Value::Text("corrupt".into())),
            ("blob", rusqlite::types::Value::Blob(vec![0])),
            ("unscheduled", rusqlite::types::Value::Null),
        ] {
            store.conn().execute(
                "INSERT INTO pins (root, holder, created_at, release_after) VALUES (?1, ?2, 0, ?3)",
                params![root.as_bytes().as_slice(), holder, time],
            ).unwrap();
        }
        let origin = crate::testutil::origin();
        store
            .put_entry(
                &origin,
                "other",
                "live",
                &synch_core::FileEntry::file(100, 0, root, 1),
            )
            .unwrap();
        assert_eq!(store.expire_pins(0).unwrap(), 0);
        store.delete_entry(&origin, "other", "live").unwrap();
        assert_eq!(
            store
                .expire_pins_of(&PinHolder::Other("due".into()), 0)
                .unwrap(),
            1
        );
        assert_eq!(store.expire_pins(0).unwrap(), 2);
        assert_eq!(store.expire_pins(0).unwrap(), 0);
        let count: i64 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM pins", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 5);
        assert!(store.conn().is_autocommit());
    }

    #[test]
    fn failed_expiry_rolls_back_earlier_deletes_in_the_same_statement() {
        let (_d, store) = store();
        let root = store.ingest_bytes(&data(100), 0).unwrap();
        for name in ["first", "second"] {
            let holder = PinHolder::Other(name.into());
            assert!(store.pin(&root, &holder, 0).unwrap());
            assert!(store.schedule_release(&root, &holder, 1).unwrap());
        }
        store
            .conn()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_second_expiry BEFORE DELETE ON pins
             WHEN (SELECT COUNT(*) FROM pins) = 1
             BEGIN SELECT RAISE(ABORT, 'expiry denied'); END;",
            )
            .unwrap();
        let error = store.expire_pins(1).unwrap_err();
        assert!(error.to_string().contains("expiry denied"));
        assert!(store.conn().is_autocommit());
        assert_eq!(store.pins_for(&root).unwrap().len(), 2);
    }

    use crate::testutil::{data, store};

    #[test]
    fn root_matches_plain_blake3() {
        let (_d, store) = store();
        for size in [0usize, 1, 1000, 16 * 1024, 100_000] {
            let bytes = data(size);
            let root = store.ingest_bytes(&bytes, 0).unwrap();
            assert_eq!(
                root.as_bytes(),
                blake3::hash(&bytes).as_bytes(),
                "size {size}"
            );
        }
    }

    #[test]
    fn small_blobs_are_inlined_and_large_ones_go_to_the_filesystem() {
        let (_d, store) = store();
        for (size, inline) in [(0usize, true), (100, true), (200_000, false)] {
            let bytes = data(size);
            let root = store.ingest_bytes(&bytes, 0).unwrap();
            let row = store.blob(&root).unwrap().unwrap();
            assert_eq!(row.inline.is_some(), inline, "size {size}");
            assert!(row.complete);
            assert_eq!(store.blob_path(&root).exists(), !inline, "size {size}");
            assert_eq!(store.outboard_path(&root).exists(), !inline, "size {size}");
            assert_eq!(store.read_all(&root).unwrap(), bytes);
        }
        // An empty object advertises a complete ad like any other.
        let root = store.ingest_bytes(b"", 0).unwrap();
        assert!(store.local_ad(&root).unwrap().unwrap().is_complete());
    }

    #[test]
    fn range_reads() {
        let (_d, store) = store();
        let bytes = data(200_000);
        let root = store.ingest_bytes(&bytes, 0).unwrap();
        for (offset, len) in [(0u64, 10u64), (100, 5000), (150_000, 50_000), (199_999, 1)] {
            let got = store.read_range(&root, offset, len).unwrap();
            let end = (offset + len).min(bytes.len() as u64);
            assert_eq!(got, &bytes[offset as usize..end as usize], "{offset}+{len}");
        }
        assert!(store.read_range(&root, 0, 0).unwrap().is_empty());
    }

    #[test]
    fn ingest_file_round_trip() {
        let (dir, store) = store();
        let bytes = data(150_000);
        let path = dir.path().join("input.bin");
        std::fs::write(&path, &bytes).unwrap();
        let (root, size) = store.ingest_file(&path, 0).unwrap();
        assert_eq!(size, bytes.len() as u64);
        assert_eq!(root.as_bytes(), blake3::hash(&bytes).as_bytes());
        assert_eq!(store.read_all(&root).unwrap(), bytes);
        // No staging files left behind, and none in the CAS root: a regular
        // file there breaks the orphan sweep.
        let staged: Vec<_> = std::fs::read_dir(store.staging_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(staged.is_empty());
        let in_root: Vec<_> = std::fs::read_dir(store.cas_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .collect();
        assert!(in_root.is_empty(), "the CAS root holds only directories");
    }

    #[test]
    fn slice_round_trip_between_two_stores() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let bytes = data(300_000);
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let size = bytes.len() as u64;

        // Fetch the middle third first, then the rest — order must not matter.
        let first = ChunkRanges::single(6, 12);
        let (encoded, served) = provider.encode_slice(&root, &first).unwrap();
        assert_eq!(served, first);
        let written = fetcher
            .write_slice(&root, size, &served, &encoded, 0)
            .unwrap();
        assert_eq!(written, first);

        let row = fetcher.blob(&root).unwrap().unwrap();
        assert!(!row.complete);
        assert_eq!(row.verified_groups(), first);
        // A partial holder can serve what it has, and refuses what it does not.
        assert_eq!(
            fetcher.read_range(&root, 6 * 16384, 100).unwrap(),
            &bytes[6 * 16384..6 * 16384 + 100]
        );
        assert!(fetcher.read_range(&root, 0, 100).is_err());
        let all = ChunkRanges::single(0, group_count(size));
        let (_, served) = fetcher.encode_slice(&root, &all).unwrap();
        assert_eq!(served, first, "a partial holder reports only what it had");

        let rest = all.difference(&first);
        let (encoded, served) = provider.encode_slice(&root, &rest).unwrap();
        fetcher
            .write_slice(&root, size, &served, &encoded, 0)
            .unwrap();
        let row = fetcher.blob(&root).unwrap().unwrap();
        assert!(row.complete);
        assert_eq!(fetcher.read_all(&root).unwrap(), bytes);
    }

    #[test]
    fn tampered_slices_are_rejected() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let bytes = data(300_000);
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let size = bytes.len() as u64;
        let ranges = ChunkRanges::single(0, 4);
        let (mut encoded, served) = provider.encode_slice(&root, &ranges).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 0xff;

        assert!(matches!(
            fetcher.write_slice(&root, size, &served, &encoded, 0),
            Err(StoreError::Verification { .. })
        ));
        // Nothing was committed: a bad peer can withhold, never corrupt.
        assert!(fetcher
            .blob(&root)
            .unwrap()
            .is_none_or(|r| r.verified_groups().is_empty()));

        // A slice built for another root is refused the same way, and commits
        // nothing under the wrong name either.
        let (encoded, served) = provider.encode_slice(&root, &ranges).unwrap();
        let wrong = Hash::new(b"not the object");
        assert!(matches!(
            fetcher.write_slice(&wrong, size, &served, &encoded, 0),
            Err(StoreError::Verification { .. })
        ));
        assert!(fetcher.blob(&wrong).unwrap().is_none());
    }

    #[test]
    fn a_slice_is_clamped_to_one_window() {
        // The encoding is built in memory and travels in one frame, so a
        // request for everything is answered with the first window and a
        // `served` saying where the requester's next window starts (§12).
        let (_d, provider) = store();
        let bytes = data((synch_core::MAX_SLICE_GROUPS as usize + 200) * 16384);
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let groups = group_count(bytes.len() as u64);
        assert!(groups > synch_core::MAX_SLICE_GROUPS);

        let (encoded, served) = provider
            .encode_slice(&root, &ChunkRanges::single(0, groups))
            .unwrap();
        assert_eq!(served.count(), synch_core::MAX_SLICE_GROUPS);
        assert_eq!(served, ChunkRanges::single(0, synch_core::MAX_SLICE_GROUPS));
        assert!(encoded.len() < synch_core::MAX_FRAME_LEN);

        // And the window after it picks up exactly where that one stopped.
        let rest = ChunkRanges::single(0, groups).difference(&served);
        let (_, served_next) = provider.encode_slice(&root, &rest).unwrap();
        assert_eq!(served_next.ranges[0].start, synch_core::MAX_SLICE_GROUPS);
    }

    #[test]
    fn ads_summarize_held_spans() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let g = synch_core::AD_SPAN_GRANULARITY;
        let bytes = data(3 * g as usize);
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        assert!(provider.local_ad(&root).unwrap().unwrap().is_complete());

        // An ad span is 16 MiB and a slice window 8, so the first window
        // advertises nothing: spans round inward rather than claiming a
        // granule the holder is halfway through (`coalesce_spans`).
        let groups_per_span = g / CHUNK_GROUP_SIZE;
        let mut want = ChunkRanges::single(0, groups_per_span);
        let mut windows = 0;
        while !want.is_empty() {
            let (encoded, served) = provider.encode_slice(&root, &want).unwrap();
            fetcher
                .write_slice(&root, bytes.len() as u64, &served, &encoded, 0)
                .unwrap();
            want = want.difference(&served);
            windows += 1;
            if windows == 1 {
                let partial = fetcher.local_ad(&root).unwrap().unwrap();
                assert!(!partial.is_complete());
                assert_eq!(
                    partial.state.spans,
                    vec![],
                    "half a span is not a span this node can serve"
                );
            }
        }
        assert!(windows > 1, "a span takes more than one window");

        let ad = fetcher.local_ad(&root).unwrap().unwrap();
        assert!(!ad.is_complete());
        assert_eq!(ad.state.spans, vec![(0, g)]);
        assert!(ad.intersects(0, 10));
        assert!(!ad.intersects(2 * g, 3 * g));
    }

    /// Re-ingesting content already held complete never leaves the outboard
    /// truncated: it is staged and renamed rather than written in place, so a
    /// power loss inside the write cannot shorten a file that describes a
    /// complete object.
    #[test]
    fn re_ingesting_held_content_never_truncates_the_outboard() {
        let (dir, store) = store();
        let data = data(200_000);
        let root = store.ingest_bytes(&data, 1).unwrap();
        let outboard = store.outboard_path(&root);
        let full = std::fs::metadata(&outboard).unwrap().len();
        assert!(full > 0, "a multi-group object has an outboard");

        // Ingest the same bytes again, as a duplicate file in a scan does.
        assert_eq!(store.ingest_bytes(&data, 2).unwrap(), root);
        assert_eq!(std::fs::metadata(&outboard).unwrap().len(), full);
        assert_eq!(store.read_all(&root).unwrap(), data);

        // No staging file is left behind by a successful write.
        let staged: Vec<_> = std::fs::read_dir(store.staging_dir())
            .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default();
        assert!(staged.is_empty(), "staging left behind: {staged:?}");
        drop(dir);
    }

    #[test]
    fn pinning_and_deletion() {
        let (_d, store) = store();
        let root = store.ingest_bytes(&data(100_000), 0).unwrap();
        assert!(store.pinned_blobs().unwrap().is_empty());
        store.pin(&root, &PinHolder::Operator, 1).unwrap();
        assert_eq!(store.pinned_blobs().unwrap(), vec![root]);
        // A second holder keeps the object pinned when the first lets go: the
        // whole reason the flag became a set of claims.
        let replica = PinHolder::Replica("media".into());
        store.pin(&root, &replica, 2).unwrap();
        store.unpin(&root, &PinHolder::Operator).unwrap();
        assert_eq!(store.pinned_blobs().unwrap(), vec![root]);
        assert!(store.blob(&root).unwrap().unwrap().pinned);
        let refused = store.delete_blob(&root);
        assert!(matches!(refused, Err(StoreError::Invalid(_))));
        assert!(store.blob(&root).unwrap().is_some());
        assert!(store.blob_path(&root).exists());
        store.unpin(&root, &replica).unwrap();
        assert!(store.pinned_blobs().unwrap().is_empty());
        assert!(!store.blob(&root).unwrap().unwrap().pinned);
        // A pin of content this node does not hold guards nothing and says so.
        assert!(!store
            .pin(&Hash::new(b"absent"), &PinHolder::Operator, 3)
            .unwrap());

        assert_eq!(store.blobs().unwrap().len(), 1);
        store.delete_blob(&root).unwrap();
        assert!(store.blob(&root).unwrap().is_none());
        assert!(!store.blob_path(&root).exists());
        assert!(matches!(
            store.read_all(&root),
            Err(StoreError::MissingBlob(_))
        ));
    }

    #[test]
    fn deletion_sql_failures_never_advance_to_unlink() {
        for fail_at_commit in [false, true] {
            for collect in [false, true] {
                let (_dir, store) = store();
                let bytes = data(100_000);
                let root = store.ingest_bytes(&bytes, 0).unwrap();
                if fail_at_commit {
                    // The DELETE succeeds, but its deferred constraint fails
                    // COMMIT. No filesystem effect may have been requested yet.
                    store
                        .conn()
                        .execute_batch(
                            "CREATE TABLE deletion_parent (id INTEGER PRIMARY KEY);
                         CREATE TABLE deletion_child (parent INTEGER REFERENCES deletion_parent(id)
                           DEFERRABLE INITIALLY DEFERRED);
                         CREATE TRIGGER fail_deletion_commit AFTER DELETE ON blobs
                           BEGIN INSERT INTO deletion_child VALUES (1); END;",
                        )
                        .unwrap();
                } else {
                    store
                        .conn()
                        .execute_batch(
                            "CREATE TRIGGER fail_deletion_row BEFORE DELETE ON blobs
                           BEGIN SELECT RAISE(ABORT, 'injected deletion failure'); END;",
                        )
                        .unwrap();
                }
                let result = if collect {
                    store
                        .delete_blob_if_collectable(&root, i64::MAX)
                        .map(|_| ())
                } else {
                    store.delete_blob(&root)
                };
                assert!(result.is_err());
                assert!(
                    store.blob(&root).unwrap().is_some(),
                    "row deletion must roll back"
                );
                assert!(store.blob_path(&root).exists());
                assert!(store.outboard_path(&root).exists());
                assert_eq!(store.read_all(&root).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn deletion_preserves_corrupt_access_errors_and_never_unlinks() {
        use rusqlite::types::Value;
        for value in [
            Value::Null,
            Value::Text("not a timestamp".into()),
            Value::Blob(vec![]),
            Value::Real(1.5),
        ] {
            let (_dir, store) = store();
            let root = store.ingest_bytes(&data(100_000), 0).unwrap();
            let expected_type = {
                let conn = store.conn();
                conn.execute_batch("CREATE TEMP TABLE blobs (root BLOB PRIMARY KEY, last_access)")
                    .unwrap();
                conn.execute(
                    "INSERT INTO blobs VALUES (?1, ?2)",
                    params![root.as_bytes().to_vec(), value],
                )
                .unwrap();
                match conn
                    .query_row("SELECT last_access FROM blobs", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap_err()
                {
                    rusqlite::Error::InvalidColumnType(0, _, kind) => kind,
                    other => panic!("unexpected decoder error: {other:?}"),
                }
            };
            for collect in [false, true] {
                let error = if collect {
                    store
                        .delete_blob_if_collectable(&root, i64::MAX)
                        .map(|_| ())
                } else {
                    store.delete_blob(&root)
                }
                .unwrap_err();
                match error {
                    StoreError::Sqlite(rusqlite::Error::InvalidColumnType(0, column, kind)) => {
                        assert_eq!(column, "last_access");
                        assert_eq!(kind, expected_type);
                    }
                    other => panic!("deletion changed the original column error: {other:?}"),
                }
                assert!(store.conn().is_autocommit());
                assert!(store.blob_path(&root).exists());
                assert!(store.outboard_path(&root).exists());
            }
        }
    }

    /// Two writers filling one object keep both halves of what they wrote: a
    /// read-union-write of the verified bitmap drops the earlier writer's bits
    /// — harmless bytes-wise, but the dropped groups are fetched all over
    /// again, and a promotion's share of that loss is a whole span.
    #[test]
    fn concurrent_commits_of_disjoint_groups_keep_both() {
        let (_d, store) = store();
        let size = 64 * CHUNK_GROUP_SIZE;
        let all = ChunkRanges::single(0, 64);

        // Two halves, committed by two threads over the one connection, a few
        // objects over so an interleaving is actually met.
        for round in 0..16u8 {
            let root = Hash::new(&[round]);
            std::thread::scope(|scope| {
                for half in [ChunkRanges::single(0, 32), ChunkRanges::single(32, 64)] {
                    let (store, root) = (&store, &root);
                    scope.spawn(move || store.commit_groups(root, size, &half, None, 0).unwrap());
                }
            });
            assert_eq!(
                store.blob(&root).unwrap().unwrap().verified_groups(),
                all,
                "round {round}: one writer's groups were lost"
            );
        }
    }

    #[test]
    fn partial_commit_normalizes_ranges_at_unsigned_size_boundaries() {
        let (_d, store) = store();
        for size in [i64::MAX as u64, 1u64 << 63, u64::MAX] {
            let root = Hash::new(&size.to_le_bytes());
            let total = group_count(size);
            let malformed = ChunkRanges {
                ranges: vec![
                    GroupRange::new(total, u64::MAX),
                    GroupRange::new(2, 4),
                    GroupRange::new(4, 2),
                    GroupRange::new(0, 3),
                ],
            };
            let partial = store
                .commit_groups(&root, size, &malformed, None, 0)
                .unwrap();
            assert_eq!(partial.size, size);
            assert!(!partial.complete);
            assert_eq!(
                store.blob(&root).unwrap().unwrap().verified_groups(),
                ChunkRanges::single(0, 4)
            );
            let complete = store
                .commit_groups(&root, size, &ChunkRanges::single(4, u64::MAX), None, 0)
                .unwrap();
            assert!(complete.complete);
            // A complete row denotes all groups even though its bitmap is NULL.
            assert!(
                store
                    .commit_groups(&root, size, &ChunkRanges::empty(), None, 0)
                    .unwrap()
                    .complete
            );
            assert!(matches!(
                store.commit_groups(&root, size - 1, &ChunkRanges::empty(), None, 0),
                Err(StoreError::Verification { .. })
            ));
            assert_eq!(store.blob(&root).unwrap().unwrap().size, size);
        }
    }

    /// Seeds a row the way a writer left it, bypassing the commit path.
    fn seed_claim(
        store: &Store,
        root: &Hash,
        size: u64,
        complete: bool,
        durable: bool,
        held: &[(u64, u64)],
    ) {
        store
            .conn()
            .execute(
                "INSERT OR REPLACE INTO blobs (root, size, complete, durable, bitmap, last_access)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![
                    root.as_bytes().to_vec(),
                    size as i64,
                    complete,
                    durable,
                    postcard::to_stdvec(held).unwrap()
                ],
            )
            .unwrap();
    }

    #[test]
    fn partial_size_settlement_only_replaces_unattested_claims() {
        let (_d, store) = store();
        let root = Hash::new(b"settlement cases");
        let recorded = 4 * CHUNK_GROUP_SIZE;
        let prefix = [(0, 1)];
        let final_group = [(3, 4)];
        assert!(
            store.admit_size(&root, recorded).is_ok(),
            "no row admits any size"
        );
        for (complete, durable, held) in [
            (true, false, &prefix[..]),
            (false, true, &prefix[..]),
            (false, false, &final_group[..]),
        ] {
            seed_claim(&store, &root, recorded, complete, durable, held);
            assert!(store.admit_size(&root, recorded).is_ok());
            assert!(matches!(
                store.admit_size(&root, recorded - 1),
                Err(StoreError::Verification { .. })
            ));
        }
        // An unattested claim yields: the same tree shape keeps its bits and a
        // changed one starts over.
        seed_claim(&store, &root, recorded, false, false, &prefix);
        store.admit_size(&root, recorded - 1).unwrap();
        let same_shape = store
            .commit_groups(&root, recorded - 1, &ChunkRanges::empty(), None, 0)
            .unwrap();
        assert_eq!(same_shape.size, recorded - 1);
        assert_eq!(
            store.blob(&root).unwrap().unwrap().verified_groups(),
            ChunkRanges::single(0, 1)
        );
        store.admit_size(&root, recorded + 1).unwrap();
        let changed_shape = store
            .commit_groups(&root, recorded + 1, &ChunkRanges::empty(), None, 0)
            .unwrap();
        assert_eq!(changed_shape.size, recorded + 1);
        assert!(store
            .blob(&root)
            .unwrap()
            .unwrap()
            .verified_groups()
            .is_empty());
    }

    #[test]
    fn partial_commit_resets_unattested_tree_shape_and_handles_empty_objects() {
        let (_d, store) = store();
        let empty = Hash::new(b"empty commit");
        assert!(
            store
                .commit_groups(&empty, 0, &ChunkRanges::single(0, u64::MAX), None, 0)
                .unwrap()
                .complete
        );
        let root = Hash::new(b"changed shape");
        store
            .commit_groups(
                &root,
                4 * CHUNK_GROUP_SIZE,
                &ChunkRanges::single(0, 2),
                None,
                0,
            )
            .unwrap();
        let result = store
            .commit_groups(
                &root,
                8 * CHUNK_GROUP_SIZE,
                &ChunkRanges::single(7, u64::MAX),
                None,
                0,
            )
            .unwrap();
        assert!(!result.complete);
        assert_eq!(
            store.blob(&root).unwrap().unwrap().verified_groups(),
            ChunkRanges::single(7, 8)
        );
    }

    proptest::proptest! {
        #[test]
        fn partial_settlement_matches_the_integer_contract(
            row in proptest::prelude::any::<bool>(), durable in proptest::prelude::any::<bool>(), complete in proptest::prelude::any::<bool>(),
            final_held in proptest::prelude::any::<bool>(), recorded in 0u64..(128 * CHUNK_GROUP_SIZE), claimed in 0u64..(128 * CHUNK_GROUP_SIZE),
        ) {
            let count = |size: u64| u128::from(size).div_ceil(u128::from(CHUNK_GROUP_SIZE)).max(1) as u64;
            proptest::prop_assert_eq!(group_count(recorded), count(recorded));
            let (_d, store) = store();
            let root = Hash::new(b"property");
            if row {
                let held: &[(u64, u64)] = if final_held { &[(count(recorded) - 1, count(recorded))] } else { &[] };
                seed_claim(&store, &root, recorded, complete, durable, held);
            }
            let admitted = store.admit_size(&root, claimed);
            let actual = store.commit_groups(&root, claimed, &ChunkRanges::empty(), None, 0);
            if row && recorded != claimed && (durable || complete || final_held) {
                proptest::prop_assert!(admitted.is_err());
                proptest::prop_assert!(actual.is_err());
            } else {
                proptest::prop_assert!(admitted.is_ok());
                let actual = actual.unwrap();
                proptest::prop_assert_eq!(actual.size, claimed);
                let reset = row && count(recorded) != count(claimed);
                let kept = store.blob(&root).unwrap().unwrap().verified_groups();
                proptest::prop_assert_eq!(kept.is_empty(), reset || !(row && (final_held || complete)));
            }
        }

        #[test]
        fn partial_commits_match_pointwise_group_membership(
            row in proptest::prelude::any::<bool>(), durable in proptest::prelude::any::<bool>(), complete in proptest::prelude::any::<bool>(),
            recorded in 0u64..(128 * CHUNK_GROUP_SIZE), claimed in 0u64..(128 * CHUNK_GROUP_SIZE),
            old in proptest::collection::vec((0u64..150, 0u64..150), 0..32),
            incoming in proptest::collection::vec((0u64..150, 0u64..150), 0..32),
        ) {
            let (_d, store) = store();
            let root = Hash::new(b"bitmap property");
            if row {
                store.conn().execute(
                    "INSERT INTO blobs (root, size, complete, durable, bitmap, last_access) VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                    params![root.as_bytes().to_vec(), recorded as i64, complete, durable, postcard::to_stdvec(&old).unwrap()],
                ).unwrap();
            }
            let contains = |ranges: &[(u64, u64)], g| ranges.iter().any(|&(a, b)| a <= g && g < b);
            let prior = |g| row && (if complete { g < group_count(recorded) } else { contains(&old, g) });
            let refused = row && recorded != claimed && (durable || complete || prior(group_count(recorded) - 1));
            let incoming_ranges = ChunkRanges { ranges: incoming.iter().map(|&(a, b)| GroupRange::new(a, b)).collect() };
            let actual = store.commit_groups(&root, claimed, &incoming_ranges, None, 0);
            if refused {
                proptest::prop_assert!(actual.is_err());
            } else {
                let actual = actual.unwrap();
                let total = group_count(claimed);
                let reset = row && group_count(recorded) != total;
                let expected = |g| g < total && (contains(&incoming, g) || (!reset && prior(g)));
                let ranges = store.blob(&root).unwrap().unwrap().verified_groups();
                for g in 0..151 {
                    proptest::prop_assert_eq!(ranges.contains(g), expected(g));
                }
                proptest::prop_assert_eq!(actual.complete, (0..total).all(expected));
                proptest::prop_assert!(ranges.ranges.iter().all(|r| r.start < r.end && r.end <= total));
                proptest::prop_assert!(ranges.ranges.windows(2).all(|rs| rs[0].end < rs[1].start));
            }
        }
    }

    /// A peer that understates an object's size cannot destroy bytes already
    /// verified: nothing is resized on the strength of a size nobody has
    /// proved — the file only ever grows until a commit settles the length
    /// (§6.2, `docs/DELTA-SYNC.md` §6).
    #[test]
    fn an_understated_size_cannot_truncate_groups_already_held() {
        let (_d1, provider) = store();
        let (_d2, victim) = store();
        let bytes = data(9 * CHUNK_GROUP_SIZE as usize);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();

        // The victim holds one group in the middle and nothing else.
        let held = ChunkRanges::single(5, 6);
        let (encoded, served) = provider.encode_slice(&root, &held).unwrap();
        assert_eq!(
            victim
                .write_slice(&root, size, &served, &encoded, 0)
                .unwrap(),
            held
        );
        let payload_len = std::fs::metadata(victim.blob_path(&root)).unwrap().len();

        // A peer offers a slice of the same root under a three-group size; it
        // must be refused before anything is resized, not after.
        let lie = 3 * CHUNK_GROUP_SIZE;
        let attack = ChunkRanges::single(0, 1);
        assert!(matches!(
            victim.write_slice(&root, lie, &attack, &encoded, 0),
            Err(StoreError::Verification { .. })
        ));

        // Payload, outboard, row and bitmap exactly as they were.
        assert_eq!(
            std::fs::metadata(victim.blob_path(&root)).unwrap().len(),
            payload_len
        );
        let row = victim.blob(&root).unwrap().unwrap();
        assert_eq!(row.size, size);
        assert_eq!(row.verified_groups(), held);
        // The honest writer that follows is not refused either: the object
        // completes from where it was left, the read below proves the held
        // group's bytes survived the refused lie.
        let rest = ChunkRanges::single(0, 9).difference(&held);
        let (encoded, served) = provider.encode_slice(&root, &rest).unwrap();
        victim
            .write_slice(&root, size, &served, &encoded, 0)
            .unwrap();
        assert_eq!(victim.read_all(&root).unwrap(), bytes);
    }
    /// A size claim racing a commit that completes the object never wins: the
    /// decision is made inside the transaction that records it, so a claim
    /// decided on an earlier snapshot can never leave its size on a completed
    /// row.
    #[test]
    fn a_size_claim_racing_a_completing_commit_never_wins() {
        let (_d, store) = store();
        let size = 4 * CHUNK_GROUP_SIZE + 500;
        // A hundred bytes on, inside the same chunk group: the same tree, so
        // this is exactly the lie a verifying proof can carry (§6.2).
        let lie = size + 100;
        assert_eq!(group_count(lie), group_count(size));
        let all = ChunkRanges::single(0, group_count(size));

        for round in 0..64u16 {
            let root = Hash::new(&round.to_le_bytes());
            std::thread::scope(|scope| {
                let (store, root, all) = (&store, &root, &all);
                scope.spawn(move || {
                    store
                        .commit_groups(root, size, all, None, 0)
                        .expect("the honest writer is never refused")
                });
                scope.spawn(move || {
                    // Refused or absorbed, either is fine — what it must not do
                    // is leave its size on a completed row.
                    let _ = store.commit_groups(root, lie, &ChunkRanges::empty(), None, 0);
                });
            });
            let row = store.blob(&root).unwrap().unwrap();
            assert_eq!(row.size, size, "round {round}: the claim won");
            assert!(row.complete, "round {round}");
            // And an honest writer arriving afterwards is still let in.
            store.commit_groups(&root, size, &all, None, 0).unwrap();
        }
    }

    /// An ingest is a writer like any other and meets the size settlement: a claim
    /// a partial fetch left behind under a size nothing attests to yields to
    /// the ingest, bitmap and all, and the object is complete at the length
    /// its bytes have. A size the disk attests to is never rewritten, not
    /// even by the writer that hashed the bytes — the only way the two can
    /// disagree is a root two objects share (`CasPlanProofs.settlement_accepts_iff`).
    #[test]
    fn an_ingest_settles_size_like_any_other_writer() {
        let (_d1, provider) = store();
        let bytes = data(4 * CHUNK_GROUP_SIZE as usize + 500);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();

        // A claim a whole bracket over, with a group verified under it.
        let (_d2, claimed) = store();
        let lie = 9 * CHUNK_GROUP_SIZE;
        claimed
            .commit_groups(&root, lie, &ChunkRanges::single(0, 1), None, 0)
            .unwrap();
        let row = claimed.blob(&root).unwrap().unwrap();
        assert_eq!(row.size, lie);
        assert!(!row.complete);

        assert_eq!(claimed.ingest_bytes(&bytes, 1).unwrap(), root);
        let row = claimed.blob(&root).unwrap().unwrap();
        assert_eq!(row.size, size, "the ingest's size settles the row");
        assert!(row.complete);
        assert!(row.durable);
        assert_eq!(claimed.read_all(&root).unwrap(), bytes);

        // A settled size stands against everyone, the ingest included.
        let (_d3, attested) = store();
        let settled = size + 100;
        let all = ChunkRanges::single(0, group_count(settled));
        attested
            .commit_groups(&root, settled, &all, None, 0)
            .unwrap();
        assert!(matches!(
            attested.ingest_bytes(&bytes, 1),
            Err(StoreError::Verification { .. })
        ));
        let row = attested.blob(&root).unwrap().unwrap();
        assert_eq!(row.size, settled, "a settled size is never rewritten");
        assert!(row.complete);
    }

    /// The pre-v10 bitmap describes no more groups than it has bits for: the
    /// group count the migration passes comes from a size nobody proved, and
    /// the walk is inside the migration transaction, where a long loop is a
    /// daemon that will not start.
    #[test]
    fn a_bitmap_is_read_only_as_far_as_its_bits_reach() {
        // Groups 0..3 and 7..20 held, in the three bytes that describe 24.
        let mut bits = vec![0u8; 3];
        for group in (0..3usize).chain(7..20) {
            bits[group / 8] |= 1 << (group % 8);
        }
        let held = ChunkRanges::from_ranges([GroupRange::new(0, 3), GroupRange::new(7, 20)]);
        assert_eq!(bitmap_to_ranges(&bits, 20), held);
        assert!(bitmap_to_ranges(&[0u8; 3], 20).is_empty());

        // The same three bytes under a size claiming every group there could
        // ever be: the same answer, and it arrives.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(bitmap_to_ranges(&bits, u64::MAX));
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(30))
                .expect("the walk is bounded by the bitmap, not by the claim"),
            held
        );
    }

    /// A collector cannot unlink the bytes of an object a fetch is writing:
    /// the sweep holds its guard across the unlinks, so a writer's commit
    /// would land after them — a row claiming verified groups whose payload is
    /// gone. Driven by hand rather than racing, because the interleaving is
    /// the point and a race would only find it sometimes.
    #[test]
    fn a_sweep_leaves_an_object_a_write_is_in_flight_for() {
        let (_d, store) = store();
        let size = 4 * CHUNK_GROUP_SIZE;
        let payload = data(size as usize);
        let root = store.ingest_bytes(&payload, 0).unwrap();
        // Cold and unreferenced: an ordinary collection candidate.
        assert!(store.blob(&root).unwrap().is_some());

        {
            let _lease = store.lease_write(&root);
            assert!(
                !store.delete_blob_if_collectable(&root, i64::MAX).unwrap(),
                "a write in flight is not a collectable object"
            );
            assert!(store.blob_path(&root).exists());
            // And the orphan sweep leaves its files alone too, even with the row
            // gone — which is the shape a resumed fetch into a stale payload has.
            store.force_delete_blob_for_test(&root).unwrap();
            std::fs::write(store.blob_path(&root), &payload).unwrap();
            assert_eq!(store.gc_orphans(i64::MAX).unwrap(), 0);
            assert!(store.blob_path(&root).exists());
        }

        // Once the lease is gone both sweeps do their job.
        assert!(store.gc_orphans(i64::MAX).unwrap() > 0);
        assert!(!store.blob_path(&root).exists());
    }

    #[test]
    fn independently_opened_stores_share_write_gc_ordering() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Store::open(dir.path()).unwrap();
        let collector = Store::open(dir.path()).unwrap();
        let root = writer.ingest_bytes(&data(100_000), 0).unwrap();

        let lease = writer.lease_write(&root);
        assert!(writer.is_being_written(&root));
        assert!(collector.is_being_written(&root));
        assert!(!collector
            .delete_blob_if_collectable(&root, i64::MAX)
            .unwrap());
        assert!(writer.blob_path(&root).exists());
        drop(lease);

        assert!(collector
            .delete_blob_if_collectable(&root, i64::MAX)
            .unwrap());
        assert!(!writer.blob_path(&root).exists());
    }

    #[test]
    fn cache_eviction_leaves_an_object_a_write_is_in_flight_for() {
        let (_d, store) = store();
        store.set_remote_cas(true);
        let payload = data(100_000);
        let root = store.ingest_bytes(&payload, 0).unwrap();
        store.mark_blob_durable(&root).unwrap();

        {
            let _lease = store.lease_write(&root);
            assert!(!store.clear_blob_cache(&root).unwrap());
            assert!(store.blob(&root).unwrap().unwrap().complete);
            assert!(store.blob_path(&root).exists());
        }
        assert!(store.clear_blob_cache(&root).unwrap());
        let row = store.blob(&root).unwrap().unwrap();
        assert!(row.durable && !row.complete);
        assert!(!store.blob_path(&root).exists());
    }

    /// A lease cannot be taken while a sweep is between its check and its
    /// unlink: if it could, a writer would slip in and commit a row claiming a
    /// complete object whose payload the sweep just unlinked. Asserted as the
    /// ordering itself, because the interleaving that exposes it is a
    /// microsecond wide and a racing test would find it only sometimes.
    #[test]
    fn a_lease_waits_for_a_sweep_that_is_mid_unlink() {
        let (_d, store) = store();
        let store = std::sync::Arc::new(store);
        let root = store.ingest_bytes(&data(64), 0).unwrap();

        let held = store.conn();
        let leasing = {
            let store = store.clone();
            std::thread::spawn(move || {
                let _blocking = synch_core::BlockingScope::enter();
                let _lease = store.lease_write(&root);
                true
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !leasing.is_finished(),
            "a lease was taken while a sweep held the connection"
        );
        drop(held);
        assert!(leasing.join().unwrap());
    }

    /// A write that resumes into a stale payload keeps it: `write_slice` opens
    /// with `truncate(false)` and reuses whatever is there, so an mtime reading
    /// sampled before the writer touched the file proves nothing about the
    /// present.
    #[test]
    fn a_resumed_write_is_not_mistaken_for_a_leftover() {
        let (_d, store) = store();
        let size = 4 * CHUNK_GROUP_SIZE;
        let payload = data(size as usize);
        let root = store.ingest_bytes(&payload, 0).unwrap();
        let (encoded, served) = store
            .encode_slice(&root, &ChunkRanges::single(0, group_count(size)))
            .unwrap();

        // A stale orphan: the files are there, no row accounts for them.
        store.force_delete_blob_for_test(&root).unwrap();
        std::fs::write(store.blob_path(&root), vec![0u8; size as usize]).unwrap();

        // A fetch resumes into it while the sweep runs.
        let lease = store.lease_write(&root);
        assert_eq!(store.gc_orphans(i64::MAX).unwrap(), 0);
        drop(lease);
        let written = store
            .write_slice(&root, size, &served, &encoded, 0)
            .unwrap();
        assert_eq!(written.count(), group_count(size));
        assert_eq!(store.read_all(&root).unwrap(), payload);
    }
}
