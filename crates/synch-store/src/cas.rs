//! The content-addressed blob store (§6.1, §6.2).
//!
//! Every object is hashed with BLAKE3 over 16 KiB chunk groups and kept
//! alongside its bao outboard, so any byte range can be served — and read — as
//! a verified slice without touching the rest of the object. Partial objects
//! are first class: a verified-group bitmap records exactly which groups are
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
        sync::{decode_ranges, encode_ranges_validated, DecodeResponseIter},
        BaoContentItem,
    },
    BaoTree, BlockSize, ChunkNum,
};
use rusqlite::{params, OptionalExtension};
use synch_core::{
    group_count, groups_for_byte_range, BlobAd, ChunkRanges, GroupRange, Hash, CHUNK_GROUP_LOG2,
    CHUNK_GROUP_SIZE, INLINE_BLOB_MAX,
};

use crate::{
    db::{hash_column, Store},
    error::{Result, StoreError},
};

/// The bao block size synchronicity uses everywhere: 16 KiB chunk groups.
pub const BLOCK_SIZE: BlockSize = BlockSize::from_chunk_log(CHUNK_GROUP_LOG2);

/// Distinguishes concurrent staging files within one process. The name also
/// carries the pid, so two daemons over one CAS never collide either.
static STAGING_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Flushes a file's contents to stable storage. A blob row is only ever written
/// after this returns, so a crash cannot leave a `complete=1` index row whose
/// bytes never reached the disk (§6.2 durability).
pub(crate) fn fsync_file(file: &File) -> Result<()> {
    file.sync_all()?;
    Ok(())
}

/// Flushes a directory entry (a rename or create) to stable storage so the file
/// is findable after a crash, not just its contents. A no-op on platforms that
/// cannot open a directory as a file.
fn fsync_parent(path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// Writes a file and flushes it (contents and directory entry) to stable
/// storage before returning.
fn write_and_sync(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    fsync_file(&file)?;
    fsync_parent(path);
    Ok(())
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
        if self.complete {
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

/// True if the groups on this disk actually attest to a recorded size.
///
/// Only the last group can. Every other group's chaining value is the same
/// whatever the object's total length, so holding the first half of an object
/// says a great deal about its content and nothing at all about where it ends;
/// the final group is short by exactly the amount the size determines, and is
/// the one place a wrong size cannot survive.
///
/// This is what keeps a peer from bricking a root. An object's tree has the same
/// shape for every size inside its last 16 KiB **group** — the group is this
/// store's leaf, and nothing above it moves while the group count stays put — so
/// an entry that overstates an honest root by a few bytes yields a proof that
/// verifies, and the row it creates would then refuse every honest writer of
/// that root forever with "size mismatch", on every node that ever touched the
/// poisoned path, with nothing to collect the row because the honest entry still
/// references it. A size no group attests to is a claim, not a fact, and the
/// next writer's claim replaces it (§5.1, §6.2).
///
/// Taken as three loose values rather than off a [`BlobRow`] so that the commit
/// path can ask the question of a row it read *inside* its own transaction.
fn size_is_attested(size: u64, complete: bool, held: &ChunkRanges) -> bool {
    complete || held.contains(group_count(size) - 1)
}

/// What a size claim settled to, and what that costs the bits already held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Settlement {
    /// The size the row should record.
    pub(crate) size: u64,
    /// True when the recorded size changed the object's *group count*, so the
    /// verified-group bitmap describes a tree that is no longer the one being
    /// written and must be started again.
    pub(crate) reset_held: bool,
}

/// Decides the size an object's row should record when a writer arrives
/// claiming `claimed`, or refuses the writer.
///
/// Three answers, and the order matters:
///
/// 1. A size the disk attests to ([`size_is_attested`]) is a fact, and a writer
///    offering a different one is offering bytes for some other object: refused.
/// 2. A size no group attests to is a peer's claim off an entry, and yields to
///    this writer's — that is what keeps an overstated entry from bricking an
///    honest root forever (§5.1, §6.2).
/// 3. It yields *completely*, including the bits already held.
///
/// Rule 3 used to refuse a claim that changed the object's group count while
/// any group was held, on the reasoning that a changed count changes the shape
/// of the tree and so no slice for it could have verified. That reasoning is
/// wrong, and it inverted the rule it was protecting. bao splits at the largest
/// power of two below the chunk count, so every size in one bracket shares a
/// left subtree: 20 groups and 24 groups both split at 16, and a slice covering
/// groups 0..16 verifies identically under either — the right sibling's
/// chaining value is opaque bytes from the encoder that join to the same root.
/// An entry overstating the size within its bracket therefore produced a row
/// that verified, held real bits, and refused every honest writer of that root
/// for good: exactly the brick rule 2 exists to prevent, reached through rule 3.
///
/// So bits set under a size nothing attests to are themselves only a claim. A
/// writer offering a different size takes the row, and if the group count moves
/// the bitmap starts again — a re-fetch, which is cheap next to an object no
/// one can ever complete. Rule 1 is what stops this churning: the first writer
/// to hold the final group settles the size permanently, because that is the
/// one group whose chaining value a wrong size cannot survive.
///
/// The decision belongs inside the transaction that writes the row. Read
/// outside it, rule 1 is a check against a snapshot: an honest writer finishing
/// an object could see "not attested yet", and a claim of a different size
/// could land between the look and the commit, leaving the row complete under a
/// size no byte on the disk supports — attested from then on, unreadable, and
/// refusing every honest writer for good (`docs/DELTA-SYNC.md` §6).
pub(crate) fn settle_size(
    root: &Hash,
    existing: Option<(u64, bool, &ChunkRanges)>,
    claimed: u64,
) -> Result<Settlement> {
    let settled = |size| {
        Ok(Settlement {
            size,
            reset_held: false,
        })
    };
    let Some((recorded, complete, held)) = existing else {
        return settled(claimed);
    };
    if recorded == claimed {
        return settled(recorded);
    }
    if size_is_attested(recorded, complete, held) {
        return Err(StoreError::Verification {
            root: *root,
            reason: format!("size mismatch: have {recorded}, offered {claimed}"),
        });
    }
    Ok(Settlement {
        size: claimed,
        reset_held: group_count(claimed) != group_count(recorded),
    })
}

/// What a bitmap commit settled.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Commit {
    /// The size the row records now the claim has met what was there.
    pub(crate) size: u64,
    /// True if every group of the object is present.
    pub(crate) complete: bool,
}

/// What an object's row already claims, as the commit path needs it.
struct RowClaim {
    size: u64,
    complete: bool,
    held: ChunkRanges,
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

/// The first byte past the last group of `served`, clamped to `size`.
///
/// What a window's writes can actually reach, which is the only length a file
/// may be grown to on the strength of an unverified claim.
fn window_end_bytes(served: &ChunkRanges, size: u64) -> u64 {
    served
        .ranges
        .last()
        .map(|r| r.end.saturating_mul(CHUNK_GROUP_SIZE).min(size))
        .unwrap_or(0)
}

#[cfg(test)]
fn bitmap_len(groups: u64) -> usize {
    groups.div_ceil(8) as usize
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

/// Writes an object's index row, creating it or replacing what it claimed.
fn upsert_blob_row(
    conn: &rusqlite::Connection,
    root: &Hash,
    size: u64,
    complete: bool,
    bitmap: Option<Vec<u8>>,
    inline: Option<Vec<u8>>,
    now: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO blobs (root, size, complete, bitmap, inline, pinned, last_access)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)
         ON CONFLICT(root) DO UPDATE SET
           size = excluded.size,
           complete = excluded.complete,
           bitmap = excluded.bitmap,
           inline = COALESCE(excluded.inline, blobs.inline),
           last_access = excluded.last_access",
        params![
            root.as_bytes().to_vec(),
            size as i64,
            complete as i64,
            bitmap,
            inline,
            now
        ],
    )?;
    Ok(())
}

/// What an object's row currently claims, read on a given connection.
///
/// The bitmap is read against the row's *own* size, not the caller's: the two
/// can differ, and that difference is the whole subject of [`settle_size`].
fn read_claim(conn: &rusqlite::Connection, root: &Hash) -> Result<Option<RowClaim>> {
    let row: Option<(i64, i64, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT size, complete, bitmap FROM blobs WHERE root = ?1",
            params![root.as_bytes().to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(row.map(|(size, complete, bitmap)| {
        let size = size as u64;
        let total = group_count(size);
        let complete = complete != 0;
        let held = match (complete, &bitmap) {
            (true, _) => ChunkRanges::single(0, total),
            (false, Some(bytes)) => blob_to_ranges(bytes, total),
            (false, None) => ChunkRanges::empty(),
        };
        RowClaim {
            size,
            complete,
            held,
        }
    }))
}

#[cfg(test)]
pub(crate) fn ranges_to_bitmap(ranges: &ChunkRanges, groups: u64) -> Vec<u8> {
    let mut bits = vec![0u8; bitmap_len(groups)];
    for r in &ranges.ranges {
        for group in r.start..r.end.min(groups) {
            bits[(group / 8) as usize] |= 1 << (group % 8);
        }
    }
    bits
}

/// Converts our group ranges into bao chunk ranges.
fn to_bao_ranges(ranges: &ChunkRanges) -> bao_tree::ChunkRanges {
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
    pub fn blob_path(&self, root: &Hash) -> PathBuf {
        let hex = root.to_hex();
        self.cas_dir().join(&hex[..2]).join(&hex)
    }

    /// The filesystem path of a blob's outboard.
    pub fn outboard_path(&self, root: &Hash) -> PathBuf {
        let mut path = self.blob_path(root);
        path.set_extension("obao");
        path
    }

    pub(crate) fn tree(size: u64) -> BaoTree {
        BaoTree::new(size, BLOCK_SIZE)
    }

    // ---- ingest -----------------------------------------------------------

    /// Ingests an in-memory object, returning its root.
    pub fn ingest_bytes(&self, data: &[u8], now: i64) -> Result<Hash> {
        let size = data.len() as u64;
        let tree = Self::tree(size);
        let mut outboard = vec![0u8; tree.outboard_size() as usize];
        let root = compute_outboard(data, tree, &mut outboard)?;

        if size <= INLINE_BLOB_MAX {
            self.write_blob_row(&root, size, true, None, Some(data.to_vec()), now)?;
        } else {
            self.write_payload(&root, data, &outboard)?;
            self.write_blob_row(&root, size, true, None, None, now)?;
        }
        Ok(root)
    }

    /// Ingests a file from the local filesystem in a single streaming pass,
    /// emitting the outboard as a by-product (§7.1).
    pub fn ingest_file(&self, path: &std::path::Path, now: i64) -> Result<(Hash, u64)> {
        let metadata = std::fs::metadata(path)?;
        let size = metadata.len();
        if size <= INLINE_BLOB_MAX {
            let data = std::fs::read(path)?;
            let root = self.ingest_bytes(&data, now)?;
            return Ok((root, size));
        }

        let tree = Self::tree(size);
        let mut outboard = vec![0u8; tree.outboard_size() as usize];
        // Stream the file once, teeing into a staging file in the CAS so the
        // payload lands without a second read.
        std::fs::create_dir_all(self.cas_dir())?;
        // Unique per ingest, not just per process: two concurrent ingests
        // (a scan and a control-socket `put`, or parallel space scans) must not
        // share one staging file, or each would truncate the other's stream and
        // rename a corrupt payload into place under a correct-looking root.
        let staging = self.cas_dir().join(format!(
            "incoming-{}-{}.tmp",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let root = {
            let source = File::open(path)?;
            let sink = File::create(&staging)?;
            let tee = TeeReader {
                inner: source,
                sink,
            };
            match compute_outboard(tee, tree, &mut outboard) {
                Ok(root) => root,
                Err(e) => {
                    let _ = std::fs::remove_file(&staging);
                    return Err(e);
                }
            }
        };

        let target = self.blob_path(&root);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&staging, &target)?;
        // Flush the payload contents, the outboard, and the directory entries
        // before the index row claims this blob is complete.
        if let Ok(payload) = File::open(&target) {
            let _ = fsync_file(&payload);
        }
        fsync_parent(&target);
        write_and_sync(&self.outboard_path(&root), &outboard)?;
        self.write_blob_row(&root, size, true, None, None, now)?;
        Ok((root, size))
    }

    fn write_payload(&self, root: &Hash, data: &[u8], outboard: &[u8]) -> Result<()> {
        let path = self.blob_path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_and_sync(&path, data)?;
        write_and_sync(&self.outboard_path(root), outboard)?;
        Ok(())
    }

    pub(crate) fn write_blob_row(
        &self,
        root: &Hash,
        size: u64,
        complete: bool,
        bitmap: Option<Vec<u8>>,
        inline: Option<Vec<u8>>,
        now: i64,
    ) -> Result<()> {
        upsert_blob_row(&self.conn(), root, size, complete, bitmap, inline, now)
    }

    /// Folds newly verified groups into an object's row, atomically (§10).
    ///
    /// Two writers of one root is the ordinary case rather than an exotic one:
    /// a mirror pass, a `synch cat` and the gateway's range read all resolve to
    /// the same content, and a promotion commits a whole span in a single step.
    /// Reading the bitmap, unioning, and writing it back as three separate
    /// statements loses one of two interleaved writers' progress every time —
    /// harmlessly, because bits only ever grow and the bytes are already on the
    /// disk, but the groups it dropped are then fetched all over again, and a
    /// promotion's share of that loss is a whole span rather than a slice.
    ///
    /// So the read, the union and the write happen inside one transaction on
    /// the store's single connection. The expensive part — decoding, hashing,
    /// copying, fsyncing — stays outside it, as it must: this is a row update,
    /// not a lock over the file IO that earned it.
    ///
    /// The **size** decision is made in here too, and for the same reason
    /// ([`settle_size`]). Deciding whether a writer's claimed length may stand
    /// is a read of the row followed by a write of it, and every committer used
    /// to make that decision on its own snapshot before doing the work: two
    /// writers of one root — the honest one finishing the object, the other
    /// carrying a size a hundred bytes long off a peer's entry — could each see
    /// an unattested row and each go ahead, and whichever committed second left
    /// the row complete under a size no byte on the disk supports. Attested from
    /// then on, unreadable, refusing every honest writer, and pinned against the
    /// collector by the entry that named it. One decision, one transaction.
    pub(crate) fn commit_groups(
        &self,
        root: &Hash,
        size: u64,
        groups: &ChunkRanges,
        inline: Option<Vec<u8>>,
        now: i64,
    ) -> Result<Commit> {
        self.with_immediate_tx(|tx| {
            let claim = read_claim(tx, root)?;
            let settlement = settle_size(
                root,
                claim.as_ref().map(|c| (c.size, c.complete, &c.held)),
                size,
            )?;
            let size = settlement.size;
            let total = group_count(size);
            // A settlement that moved the group count invalidates the bitmap:
            // those bits were verified against a tree of a different shape, and
            // the size that gave them that shape was only ever a claim. Start
            // the bitmap again rather than carry bits describing a tree nobody
            // is writing any more.
            let held = match (settlement.reset_held, claim) {
                (false, Some(claim)) => claim.held,
                _ => ChunkRanges::empty(),
            };
            let verified = held.union(groups).intersect(&ChunkRanges::single(0, total));
            let complete = verified.count() >= total;
            upsert_blob_row(
                tx,
                root,
                size,
                complete,
                (!complete).then(|| ranges_to_blob(&verified)),
                inline,
                now,
            )?;
            Ok(Commit { size, complete })
        })
    }

    /// Shortens an object's payload and outboard to the size a commit settled.
    ///
    /// The one place a file in the CAS is ever made smaller, and it runs only
    /// after a commit that *completed* the object — at which point the final
    /// group is held and the size is a fact rather than a claim
    /// ([`size_is_attested`]). What it cleans up is the overstatement
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
                "SELECT root, size, complete, bitmap, inline, pinned, last_access
                 FROM blobs WHERE root = ?1",
                params![root.as_bytes().to_vec()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((root, size, complete, bitmap, inline, pinned, last_access)) = row else {
            return Ok(None);
        };
        Ok(Some(BlobRow {
            root: hash_column(root, "blobs.root")?,
            size: size as u64,
            complete: complete != 0,
            bitmap,
            inline,
            pinned: pinned != 0,
            last_access,
        }))
    }

    /// Every locally held object.
    pub fn blobs(&self) -> Result<Vec<BlobRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT root, size, complete, bitmap, inline, pinned, last_access FROM blobs
             ORDER BY last_access DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (root, size, complete, bitmap, inline, pinned, last_access) = row?;
            out.push(BlobRow {
                root: hash_column(root, "blobs.root")?,
                size: size as u64,
                complete: complete != 0,
                bitmap,
                inline,
                pinned: pinned != 0,
                last_access,
            });
        }
        Ok(out)
    }

    /// True if the whole object is present and verified locally.
    pub fn has_complete_blob(&self, root: &Hash) -> Result<bool> {
        Ok(self.blob(root)?.is_some_and(|b| b.complete))
    }

    /// The advertisement this node should publish for an object (§6.3).
    pub fn local_ad(&self, root: &Hash) -> Result<Option<BlobAd>> {
        Ok(self.blob(root)?.map(|b| b.to_ad()))
    }

    /// Pins or unpins an object against GC (§9.2).
    ///
    /// Returns whether an object with this root was there to mark. A pin
    /// that matched nothing guards nothing, and the caller is the one that
    /// can say so — silently succeeding here is how a pin of never-fetched
    /// content once vanished without a trace.
    pub fn set_pinned(&self, root: &Hash, pinned: bool) -> Result<bool> {
        let matched = self.conn().execute(
            "UPDATE blobs SET pinned = ?2 WHERE root = ?1",
            params![root.as_bytes().to_vec(), pinned as i64],
        )?;
        Ok(matched > 0)
    }

    /// Every pinned object.
    pub fn pinned_blobs(&self) -> Result<Vec<Hash>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT root FROM blobs WHERE pinned != 0")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(hash_column(row?, "blobs.root")?);
        }
        Ok(out)
    }

    /// Deletes an object's payload, outboard, and index row.
    pub fn delete_blob(&self, root: &Hash) -> Result<()> {
        // Row first, bytes second. The reverse order leaves the dangerous
        // orphan: a crash between the unlink and the delete leaves a row saying
        // `complete=1` with no bytes behind it, so `has_complete_blob` keeps
        // answering yes, `local_ad` keeps advertising the object to peers, and
        // reads fail with a raw io error rather than `MissingBlob`. This way a
        // crash leaves the opposite — files with no row — which costs disk
        // until the next sweep and never lies to anyone.
        self.conn().execute(
            "DELETE FROM blobs WHERE root = ?1",
            params![root.as_bytes().to_vec()],
        )?;
        let _ = std::fs::remove_file(self.blob_path(root));
        let _ = std::fs::remove_file(self.outboard_path(root));
        Ok(())
    }

    // ---- verified reads ---------------------------------------------------

    /// Reads a byte range, verified against the object root (§6.1).
    ///
    /// Cost is `O(range + log(size))`: only the chunk groups covering the range
    /// and the sibling hashes on their paths to the root are touched. A flipped
    /// bit anywhere fails at the exact 16 KiB group it occurs in.
    pub fn read_range(&self, root: &Hash, offset: u64, len: u64) -> Result<Vec<u8>> {
        let blob = self.blob(root)?.ok_or(StoreError::MissingBlob(*root))?;
        let end = offset.saturating_add(len).min(blob.size);
        if offset > blob.size {
            return Err(StoreError::RangeOutOfBounds {
                start: offset,
                end,
                size: blob.size,
            });
        }
        if offset == end {
            return Ok(Vec::new());
        }
        let wanted = ChunkRanges::from_ranges([groups_for_byte_range(offset, end)]);
        let available = blob.verified_groups();
        if !wanted.difference(&available).is_empty() {
            return Err(StoreError::Verification {
                root: *root,
                reason: "requested range is not fully present locally".into(),
            });
        }

        let encoded = self.encode_slice_inner(&blob, &wanted)?;
        let tree = Self::tree(blob.size);
        let bao_ranges = to_bao_ranges(&wanted);
        let iter = DecodeResponseIter::new(
            blake3::Hash::from_bytes(root.0),
            tree,
            std::io::Cursor::new(&encoded),
            &bao_ranges,
        );
        let mut out = vec![0u8; (end - offset) as usize];
        for item in iter {
            let item = item.map_err(|e| StoreError::Verification {
                root: *root,
                reason: e.to_string(),
            })?;
            if let BaoContentItem::Leaf(leaf) = item {
                let leaf_start = leaf.offset;
                let leaf_end = leaf_start + leaf.data.len() as u64;
                let copy_start = leaf_start.max(offset);
                let copy_end = leaf_end.min(end);
                if copy_start < copy_end {
                    let src = (copy_start - leaf_start) as usize;
                    let dst = (copy_start - offset) as usize;
                    let n = (copy_end - copy_start) as usize;
                    out[dst..dst + n].copy_from_slice(&leaf.data[src..src + n]);
                }
            }
        }
        Ok(out)
    }

    /// Reads a whole object, verified.
    pub fn read_all(&self, root: &Hash) -> Result<Vec<u8>> {
        let blob = self.blob(root)?.ok_or(StoreError::MissingBlob(*root))?;
        self.read_range(root, 0, blob.size)
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
    pub fn encode_slice(
        &self,
        root: &Hash,
        requested: &ChunkRanges,
    ) -> Result<(Vec<u8>, ChunkRanges)> {
        let blob = self.blob(root)?.ok_or(StoreError::MissingBlob(*root))?;
        let served = requested
            .intersect(&blob.verified_groups())
            .intersect(&ChunkRanges::single(0, group_count(blob.size)))
            .take(synch_core::MAX_SLICE_GROUPS);
        if served.is_empty() {
            return Ok((Vec::new(), served));
        }
        let encoded = self.encode_slice_inner(&blob, &served)?;
        Ok((encoded, served))
    }

    fn encode_slice_inner(&self, blob: &BlobRow, ranges: &ChunkRanges) -> Result<Vec<u8>> {
        let tree = Self::tree(blob.size);
        let bao_ranges = to_bao_ranges(ranges);
        let mut encoded = Vec::new();
        let root_hash = blake3::Hash::from_bytes(blob.root.0);

        match &blob.inline {
            Some(data) => {
                let outboard = PreOrderOutboard {
                    root: root_hash,
                    tree,
                    data: Vec::<u8>::new(),
                };
                encode_ranges_validated(data.as_slice(), outboard, &bao_ranges, &mut encoded)
            }
            None => {
                // Both files are read positionally, never slurped. An outboard
                // is 1/256 of its object, so reading it whole costs 40 MB on a
                // 10 GB object — and this runs once per served window (§6.4)
                // and once per chunk of a streaming read, which turns a large
                // object's transfer into a repeated scan of its own hash tree.
                // What each call actually touches is the sibling hashes on the
                // path to the requested groups.
                let data = File::open(self.blob_path(&blob.root))?;
                let outboard = PreOrderOutboard {
                    root: root_hash,
                    tree,
                    data: DataFile(File::open(self.outboard_path(&blob.root))?),
                };
                encode_ranges_validated(DataFile(data), outboard, &bao_ranges, &mut encoded)
            }
        }
        .map_err(|e| StoreError::Verification {
            root: blob.root,
            reason: e.to_string(),
        })?;
        Ok(encoded)
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
        let groups = group_count(size);
        let served = served.intersect(&ChunkRanges::single(0, groups));
        if served.is_empty() {
            return Ok(ChunkRanges::empty());
        }
        let tree = Self::tree(size);
        let bao_ranges = to_bao_ranges(&served);
        let root_hash = blake3::Hash::from_bytes(root.0);

        let existing = self.blob(root)?;
        if let Some(row) = &existing {
            // The cheap refusal. [`settle_size`] decides again, transactionally,
            // at the commit — this one is here so a claim that cannot possibly
            // stand never reaches the disk at all.
            let held = row.verified_groups();
            settle_size(root, Some((row.size, row.complete, &held)), size)?;
            if row.complete {
                return Ok(ChunkRanges::empty());
            }
        }

        // Small objects are decoded in memory and inlined; larger ones stream
        // into the sparse payload and outboard files.
        if size <= INLINE_BLOB_MAX {
            let mut buffer = existing
                .as_ref()
                .and_then(|r| r.inline.clone())
                .unwrap_or_else(|| vec![0u8; size as usize]);
            buffer.resize(size as usize, 0);
            let outboard = PreOrderOutboard {
                root: root_hash,
                tree,
                data: Vec::<u8>::new(),
            };
            decode_ranges(
                std::io::Cursor::new(encoded),
                &bao_ranges,
                buffer.as_mut_slice(),
                MemOutboard(outboard),
            )
            .map_err(|e| StoreError::Verification {
                root: *root,
                reason: e.to_string(),
            })?;
            self.commit_groups(root, size, &served, Some(buffer), now)?;
            return Ok(served);
        }

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
        // Grown to fit the *window*, never to the claimed size, and never
        // shrunk.
        //
        // Never shrunk, because sizing a file down on the strength of a claim is
        // how an understated entry used to destroy verified groups — bytes gone,
        // bitmap bits intact, the node advertising a group it could no longer
        // serve ([`grow_to`], `docs/DELTA-SYNC.md` §6).
        //
        // Never to the claimed size, because `size` is a peer's assertion off an
        // entry and this runs *before* `decode_ranges` turns any of it into
        // fact. An entry claiming 32 TiB for any root made every node that
        // attempted a fetch create a 32 TiB sparse payload and a 128 GiB sparse
        // outboard, fail verification, and leave both behind — `trim_to_size`
        // only runs on a commit that completed the object, so nothing reclaimed
        // them. Growing to the end of the window bounds the file by what is
        // about to be verified; `write_at` extends past it as later windows
        // land, so a real object still fills out normally.
        grow_to(&payload, window_end_bytes(&served, size))?;
        let outboard_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.outboard_path(root))?;
        let outboard = PreOrderOutboard {
            root: root_hash,
            tree,
            data: outboard_file,
        };
        let payload_for_sync = payload.try_clone().ok();
        decode_ranges(
            std::io::Cursor::new(encoded),
            &bao_ranges,
            DataFile(payload),
            outboard,
        )
        .map_err(|e| StoreError::Verification {
            root: *root,
            reason: e.to_string(),
        })?;

        // Persist the verified groups (payload and outboard) before the bitmap
        // in the index advances to cover them — otherwise a crash could leave
        // the index claiming groups the disk never received.
        // Both flushes are checked. Swallowing them meant an EIO or ENOSPC on
        // flush let the bitmap advance over data that never reached stable
        // storage — the exact inversion of the ordering this block exists to
        // enforce. `try_clone` is likewise no longer allowed to fail silently:
        // it fails under fd exhaustion, which is precisely when the machine is
        // least able to afford an unflushed commit.
        let payload = payload_for_sync.ok_or_else(|| StoreError::Verification {
            root: *root,
            reason: "could not duplicate the payload handle to flush it".into(),
        })?;
        fsync_file(&payload)?;
        fsync_file(&File::open(self.outboard_path(root))?)?;

        let commit = self.commit_groups(root, size, &served, None, now)?;
        self.trim_to_size(root, commit);
        Ok(served)
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
struct TeeReader<R, W> {
    inner: R,
    sink: W,
}

impl<R: Read, W: Write> Read for TeeReader<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.sink.write_all(&buf[..n])?;
        Ok(n)
    }
}

fn compute_outboard(data: impl Read, tree: BaoTree, outboard: &mut [u8]) -> Result<Hash> {
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

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).unwrap();
        (dir, s)
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 + 7) as u8).collect()
    }

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
    fn small_blobs_are_inlined() {
        let (_d, store) = store();
        let bytes = data(100);
        let root = store.ingest_bytes(&bytes, 0).unwrap();
        let row = store.blob(&root).unwrap().unwrap();
        assert!(row.inline.is_some());
        assert!(row.complete);
        assert!(!store.blob_path(&root).exists());
        assert_eq!(store.read_all(&root).unwrap(), bytes);
    }

    #[test]
    fn large_blobs_go_to_the_filesystem() {
        let (_d, store) = store();
        let bytes = data(200_000);
        let root = store.ingest_bytes(&bytes, 0).unwrap();
        let row = store.blob(&root).unwrap().unwrap();
        assert!(row.inline.is_none());
        assert!(store.blob_path(&root).exists());
        assert!(store.outboard_path(&root).exists());
        assert_eq!(store.read_all(&root).unwrap(), bytes);
    }

    #[test]
    fn verified_range_reads() {
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
    fn corrupted_payload_fails_verification() {
        let (_d, store) = store();
        let bytes = data(200_000);
        let root = store.ingest_bytes(&bytes, 0).unwrap();
        // Flip a bit in the middle of the payload behind the store's back.
        let mut raw = std::fs::read(store.blob_path(&root)).unwrap();
        raw[100_000] ^= 0xff;
        std::fs::write(store.blob_path(&root), &raw).unwrap();

        assert!(matches!(
            store.read_range(&root, 100_000, 16),
            Err(StoreError::Verification { .. })
        ));
        // A read of an untouched group still succeeds: verification is
        // per-16 KiB-group, not whole-file.
        assert_eq!(store.read_range(&root, 0, 16).unwrap(), &bytes[..16]);
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
        // No staging files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(store.cas_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("incoming-"))
            .collect();
        assert!(leftovers.is_empty());
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

        let rest = ChunkRanges::single(0, group_count(size)).difference(&first);
        let (encoded, served) = provider.encode_slice(&root, &rest).unwrap();
        fetcher
            .write_slice(&root, size, &served, &encoded, 0)
            .unwrap();
        let row = fetcher.blob(&root).unwrap().unwrap();
        assert!(row.complete);
        assert_eq!(fetcher.read_all(&root).unwrap(), bytes);
    }

    #[test]
    fn slice_from_a_partial_holder_reports_what_it_had() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let bytes = data(300_000);
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let size = bytes.len() as u64;

        let half = ChunkRanges::single(0, 8);
        let (encoded, served) = provider.encode_slice(&root, &half).unwrap();
        fetcher
            .write_slice(&root, size, &served, &encoded, 0)
            .unwrap();

        // Asking the partial holder for everything yields only what it has.
        let all = ChunkRanges::single(0, group_count(size));
        let (_, served) = fetcher.encode_slice(&root, &all).unwrap();
        assert_eq!(served, half);
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
    }

    #[test]
    fn a_slice_for_the_wrong_root_is_rejected() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let bytes = data(300_000);
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let ranges = ChunkRanges::single(0, 4);
        let (encoded, served) = provider.encode_slice(&root, &ranges).unwrap();

        let wrong = Hash::new(b"not the object");
        assert!(matches!(
            fetcher.write_slice(&wrong, bytes.len() as u64, &served, &encoded, 0),
            Err(StoreError::Verification { .. })
        ));
    }

    #[test]
    fn a_slice_is_clamped_to_one_window() {
        // The encoding is built in memory and travels in one frame, so what a
        // peer asks for cannot decide how much a provider allocates: a request
        // for everything is answered with the first window and a `served` that
        // says so, which is where the requester's next window starts.
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

        let groups_per_span = g / CHUNK_GROUP_SIZE;
        let first_span = ChunkRanges::single(0, groups_per_span);
        let (encoded, served) = provider.encode_slice(&root, &first_span).unwrap();
        fetcher
            .write_slice(&root, bytes.len() as u64, &served, &encoded, 0)
            .unwrap();
        let ad = fetcher.local_ad(&root).unwrap().unwrap();
        assert!(!ad.is_complete());
        match ad.state {
            synch_core::AdState::Partial { ref spans } => assert_eq!(spans, &vec![(0, g)]),
            synch_core::AdState::Complete => panic!("expected a partial ad"),
        }
        assert!(ad.intersects(0, 10));
        assert!(!ad.intersects(2 * g, 3 * g));
    }

    #[test]
    fn empty_object() {
        let (_d, store) = store();
        let root = store.ingest_bytes(b"", 0).unwrap();
        assert_eq!(root.as_bytes(), blake3::hash(b"").as_bytes());
        assert_eq!(store.read_all(&root).unwrap(), Vec::<u8>::new());
        assert!(store.local_ad(&root).unwrap().unwrap().is_complete());
    }

    #[test]
    fn pinning_and_deletion() {
        let (_d, store) = store();
        let root = store.ingest_bytes(&data(100_000), 0).unwrap();
        assert!(store.pinned_blobs().unwrap().is_empty());
        store.set_pinned(&root, true).unwrap();
        assert_eq!(store.pinned_blobs().unwrap(), vec![root]);
        store.set_pinned(&root, false).unwrap();
        assert!(store.pinned_blobs().unwrap().is_empty());

        assert_eq!(store.blobs().unwrap().len(), 1);
        store.delete_blob(&root).unwrap();
        assert!(store.blob(&root).unwrap().is_none());
        assert!(!store.blob_path(&root).exists());
        assert!(matches!(
            store.read_all(&root),
            Err(StoreError::MissingBlob(_))
        ));
    }

    /// Two writers filling one object keep both halves of what they wrote.
    ///
    /// The same content root is reached by more than one path at once as a
    /// matter of course — a mirror pass, a `synch cat`, the gateway's range
    /// read — and each commits the groups it verified. Read the bitmap, union,
    /// write it back as three separate statements and the later write erases
    /// the earlier one's bits: harmless, since the bytes are on the disk either
    /// way and bits only ever grow, but the groups it dropped are fetched all
    /// over again, and a promotion's share of that loss is a whole span.
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

    /// A size claim racing a commit that completes the object never wins.
    ///
    /// Whether a claimed length may stand is a read of the row followed by a
    /// write of it, and every committer used to make that decision on a snapshot
    /// taken before it did its work. Two writers of one root — the honest one
    /// finishing the object, the other carrying an entry's overstatement of it —
    /// could each look, each see a row no group attested to yet, and each go
    /// ahead; whichever committed second wrote its size over the other's. When
    /// that was the claim, the row ended `complete` under a length no byte on
    /// the disk supports: attested from then on, so `read_all` failed, every
    /// honest writer was refused "size mismatch" for good, and the entry that
    /// named the root kept the collector off it. Now the decision is made inside
    /// the transaction that records it, so the loser is always the claim.
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

    /// A peer that understates an object's size cannot destroy bytes this node
    /// has already verified.
    ///
    /// The claim arrives before the decode that would disprove it, and the
    /// payload used to be `set_len` to it on the way past: a node holding group
    /// 5 of a nine-group object, met by an entry claiming three groups, had
    /// group 5's bytes truncated away while its bitmap bit survived. The row
    /// then advertised a group the node could not serve, every read of it failed
    /// with an unexpected end of file, every later fetch skipped it as already
    /// held, and nothing short of deleting the object recovered. Nothing is
    /// resized on the strength of a size nobody has proved — the file only ever
    /// grows until a commit settles the length (§6.2, `docs/DELTA-SYNC.md` §6).
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

        // A peer offers a slice of the same root under a three-group size. It
        // could never verify; what matters is that it is refused before
        // anything is resized, not after.
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
        // And the group is still readable, and still servable to somebody else.
        let offset = 5 * CHUNK_GROUP_SIZE;
        assert_eq!(
            victim.read_range(&root, offset, 64).unwrap(),
            &bytes[offset as usize..offset as usize + 64]
        );
        let (onward, served) = victim.encode_slice(&root, &held).unwrap();
        assert_eq!(served, held);
        assert!(!onward.is_empty());

        // The honest writer that follows is not refused either: the object
        // completes from where it was left.
        let rest = ChunkRanges::single(0, 9).difference(&held);
        let (encoded, served) = provider.encode_slice(&root, &rest).unwrap();
        victim
            .write_slice(&root, size, &served, &encoded, 0)
            .unwrap();
        assert_eq!(victim.read_all(&root).unwrap(), bytes);
    }

    #[test]
    fn bitmap_round_trip() {
        let ranges = ChunkRanges::from_ranges([GroupRange::new(0, 3), GroupRange::new(7, 20)]);
        let bits = ranges_to_bitmap(&ranges, 20);
        assert_eq!(bitmap_to_ranges(&bits, 20), ranges);
        assert!(bitmap_to_ranges(&[0u8; 3], 20).is_empty());
    }
}
