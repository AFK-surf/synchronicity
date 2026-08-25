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
        sync::{decode_ranges, encode_ranges, ReadAt, WriteAt},
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
    /// A replicated space holds this for as long as its policy says.
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
            PinHolder::Replica(space) => format!("replica:{space}"),
            PinHolder::Other(text) => text.clone(),
        }
    }

    /// Reads a stored spelling. Never fails; see [`PinHolder::Other`].
    pub fn parse(text: &str) -> PinHolder {
        match text.split_once(':') {
            Some(("replica", space)) if !space.is_empty() => PinHolder::Replica(space.to_string()),
            _ if text == "operator" => PinHolder::Operator,
            _ => PinHolder::Other(text.to_string()),
        }
    }

    /// The space this claim is on behalf of, if it is a replica's.
    pub fn space(&self) -> Option<&str> {
        match self {
            PinHolder::Replica(space) => Some(space),
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
    pub(crate) fn to_ad(&self) -> BlobAd {
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
/// Rule 3 does *not* refuse a claim that changes the object's group count
/// while a group is held. The tempting reasoning — a changed count changes the
/// shape of the tree, so no slice for it could have verified — is wrong, and
/// inverts the rule it would be protecting. bao splits at the largest
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
    existing: Option<(u64, bool, bool, &ChunkRanges)>,
    claimed: u64,
) -> Result<Settlement> {
    let settled = |size| {
        Ok(Settlement {
            size,
            reset_held: false,
        })
    };
    let Some((recorded, complete, durable, held)) = existing else {
        return settled(claimed);
    };
    if recorded == claimed {
        return settled(recorded);
    }
    if durable || size_is_attested(recorded, complete, held) {
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
    durable: bool,
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

/// Writes an object's index row, creating it or replacing what it claimed.
struct BlobRowWrite<'a> {
    root: &'a Hash,
    size: u64,
    complete: bool,
    bitmap: Option<Vec<u8>>,
    inline: Option<Vec<u8>>,
    now: i64,
    durable: bool,
}

fn upsert_blob_row(conn: &rusqlite::Connection, row: BlobRowWrite<'_>) -> Result<()> {
    let BlobRowWrite {
        root,
        size,
        complete,
        bitmap,
        inline,
        now,
        durable,
    } = row;
    conn.execute(
        "INSERT INTO blobs
           (root, size, complete, bitmap, inline, last_access, durable)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(root) DO UPDATE SET
           size = excluded.size,
           complete = excluded.complete,
           bitmap = excluded.bitmap,
           inline = COALESCE(excluded.inline, blobs.inline),
           last_access = excluded.last_access,
           durable = max(blobs.durable, excluded.durable)",
        params![
            root.as_bytes().to_vec(),
            size as i64,
            complete as i64,
            bitmap,
            inline,
            now,
            (complete && durable) as i64
        ],
    )?;
    Ok(())
}

/// What an object's row currently claims, read on a given connection.
///
/// The bitmap is read against the row's *own* size, not the caller's: the two
/// can differ, and that difference is the whole subject of [`settle_size`].
fn read_claim(conn: &rusqlite::Connection, root: &Hash) -> Result<Option<RowClaim>> {
    let row: Option<(i64, i64, i64, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT size, complete, durable, bitmap FROM blobs WHERE root = ?1",
            params![root.as_bytes().to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    Ok(row.map(|(size, complete, durable, bitmap)| {
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
            durable: durable != 0,
            held,
        }
    }))
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

fn cache_file_bytes(path: &std::path::Path) -> u64 {
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
    pub fn ingest_bytes(&self, data: &[u8], now: i64) -> Result<Hash> {
        let size = data.len() as u64;
        let tree = Self::tree(size);
        let mut outboard = vec![0u8; tree.outboard_size() as usize];
        let root = compute_outboard(data, tree, &mut outboard)?;

        if size <= INLINE_BLOB_MAX {
            self.write_blob_row(&root, size, true, None, Some(data.to_vec()), now)?;
        } else {
            // Held from the first byte on disk through the row that describes
            // it, exactly as `write_slice` does. An ingest re-creating content
            // whose *old* row is a collection candidate is the one writer that
            // races `gc_content` rather than `gc_orphans`, so the mtime window
            // does not cover it ([`Store::lease_write`]).
            let _lease = self.lease_write(&root);
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
            // The length of what was read, not what the stat said. A file
            // appended to between the two is ordinary — a log, a download in
            // progress — and returning the stale length publishes an entry
            // whose size does not describe its own root: no peer can fetch
            // that version, because their tree is built over the wrong length.
            let size = data.len() as u64;
            let root = self.ingest_bytes(&data, now)?;
            return Ok((root, size));
        }

        let tree = Self::tree(size);
        let mut outboard = vec![0u8; tree.outboard_size() as usize];
        // Stream the file once, teeing into a staging file in the CAS so the
        // payload lands without a second read.
        //
        // Into the staging directory, never the CAS root: the root holds shard
        // directories, and a regular file among them stopped
        // [`Store::gc_orphans`] dead — `read_dir` on a file is `NotADirectory`,
        // which the sweep took as a hard error, so one leaked staging file
        // disabled orphan collection on that node forever. The sweep is also
        // what reclaims these, which is why they have a place of their own.
        std::fs::create_dir_all(self.staging_dir())?;
        // Unique per ingest, not just per process: two concurrent ingests
        // (a scan and a control-socket `put`, or parallel space scans) must not
        // share one staging file, or each would truncate the other's stream and
        // rename a corrupt payload into place under a correct-looking root.
        let staging = self
            .staging_dir()
            .join(format!("{}.tmp", synch_core::fs::unique_suffix()));
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

        // Taken as soon as the root is known — which is the first moment it
        // *can* be — and held past the row. Everything from here to
        // `write_blob_row` is file IO with no lock held, and for a large object
        // that is a full payload fsync plus an outboard write: seconds, during
        // which `gc_content` acting on this root's older row would delete that
        // row and unlink the bytes this is about to claim are complete
        // ([`Store::lease_write`]).
        let _lease = self.lease_write(&root);
        let target = self.blob_path(&root);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        replace_file(&staging, &target)?;
        // Flush the payload contents, the outboard, and the directory entries
        // before the index row claims this blob is complete. Checked, like the
        // flushes below it: a swallowed ENOSPC or EIO here is a row claiming
        // bytes the disk never took. Opened for *writing* to flush it, because
        // Windows refuses `FlushFileBuffers` on a read-only handle.
        fsync_file(&OpenOptions::new().write(true).open(&target)?)?;
        fsync_parent(&target);
        write_and_sync(&self.staging_dir(), &self.outboard_path(&root), &outboard)?;
        self.write_blob_row(&root, size, true, None, None, now)?;
        Ok((root, size))
    }

    fn write_payload(&self, root: &Hash, data: &[u8], outboard: &[u8]) -> Result<()> {
        let staging = self.staging_dir();
        write_and_sync(&staging, &self.blob_path(root), data)?;
        write_and_sync(&staging, &self.outboard_path(root), outboard)?;
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
        let durable = self.complete_is_durable();
        upsert_blob_row(
            &self.conn(),
            BlobRowWrite {
                root,
                size,
                complete,
                bitmap,
                inline,
                now,
                durable,
            },
        )
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
                claim
                    .as_ref()
                    .map(|c| (c.size, c.complete, c.durable, &c.held)),
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
            let durable = self.complete_is_durable();
            upsert_blob_row(
                tx,
                BlobRowWrite {
                    root,
                    size,
                    complete,
                    bitmap: (!complete).then(|| ranges_to_blob(&verified)),
                    inline,
                    now,
                    durable,
                },
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
    pub(crate) fn mark_blob_durable(&self, root: &Hash) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE blobs SET durable = 1 WHERE root = ?1",
            params![root.as_bytes().to_vec()],
        )?;
        Ok(changed > 0)
    }

    /// Reconstructs a cold durable row after metadata restore, once the remote
    /// backend has confirmed that the final payload/outboard pair exists.
    pub(crate) fn adopt_durable_blob(&self, root: &Hash, size: u64, now: i64) -> Result<()> {
        self.with_immediate_tx(|tx| {
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT size FROM blobs WHERE root = ?1",
                    params![root.as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing as u64 != size {
                    return Err(StoreError::invalid(format!(
                        "size mismatch for {root}: have {existing}, offered {size}"
                    )));
                }
                tx.execute(
                    "UPDATE blobs SET durable = 1 WHERE root = ?1",
                    params![root.as_bytes().to_vec()],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO blobs
                       (root, size, complete, bitmap, inline, last_access, durable)
                     VALUES (?1, ?2, 0, NULL, NULL, ?3, 1)",
                    params![root.as_bytes().to_vec(), size as i64, now],
                )?;
            }
            Ok(())
        })
    }

    /// Applies the authoritative S3 `NoSuchKey` heal rule.
    ///
    /// The durable claim is withdrawn. A row with no verified cache bytes is
    /// removed altogether; otherwise it remains a partial peer-fetched cache.
    pub(crate) fn heal_missing_durable_blob(&self, root: &Hash) -> Result<bool> {
        self.with_immediate_tx(|tx| {
            let key = root.as_bytes().to_vec();
            // Read before anything is written: this row is the most
            // authoritative record of the object's size, and it is about to be
            // withdrawn or deleted.
            let size: Option<i64> = tx
                .query_row(
                    "SELECT size FROM blobs WHERE root = ?1",
                    params![key.clone()],
                    |row| row.get(0),
                )
                .optional()?;
            let changed = tx.execute(
                "UPDATE blobs SET durable = 0 WHERE root = ?1 AND durable != 0",
                params![key.clone()],
            )?;
            tx.execute(
                "DELETE FROM blobs
                   WHERE root = ?1 AND complete = 0 AND bitmap IS NULL AND inline IS NULL",
                params![key.clone()],
            )?;
            // A replica's claim must not outlive the bytes it was a promise
            // about (`docs/REPLICATION.md` §8). This is the one place where
            // absence of bytes *is* evidence: the backend answered `NotFound`
            // about a content address, which is a statement — unlike `entries`
            // merely not naming a root.
            //
            // Gated on the *withdrawal*, not on the row disappearing. A cloud
            // replica reaches `durable=1, complete=0, bitmap NOT NULL` in the
            // ordinary course of things — the cache LRU clears a durable row
            // and any later ranged read writes a partial bitmap back — and for
            // such a row the delete above matches nothing. Gating on it left
            // the pin standing over bytes that are neither complete nor
            // durable, which is the same permanent hole this exists to close:
            // both staging paths skip a root the holder already pins, so no
            // sweep could ever re-want it.
            if changed > 0 {
                // `blobs.size` is `NOT NULL` and `changed > 0` means the row
                // was there to withdraw, so the size is always in hand — which
                // is the point: a root no entry names is still re-fetchable
                // from any provider that has it, and `blob_providers` survives
                // independently of `entries`. Dropping such a claim silently
                // would lose exactly the objects an `archive` replica is bought
                // to keep, since nothing else names a superseded version.
                tx.execute(
                    "INSERT INTO replica_want (root, holder, size, prev, first_wanted)
                     SELECT p.root, p.holder, ?2, NULL, ?3
                       FROM pins p
                      WHERE p.root = ?1 AND p.holder LIKE 'replica:%'
                     ON CONFLICT(root, holder) DO NOTHING",
                    params![key.clone(), size.unwrap_or(0), synch_core::now_ns()],
                )?;
                // The claim goes either way: it was a promise about bytes this
                // node no longer holds. The operator's own pins are left alone
                // — those are a person's promise, not this node's bookkeeping,
                // and a vanished object is something they should be told about
                // rather than have quietly rewritten.
                tx.execute(
                    "DELETE FROM pins WHERE root = ?1 AND holder LIKE 'replica:%'",
                    params![key],
                )?;
            }
            Ok(changed > 0)
        })
    }

    /// Reconciles database cache claims with an ephemeral scratch generation.
    ///
    /// A changed marker drops staged-only rows and clears cached groups on
    /// durable rows in one transaction. A matching marker is an O(1) no-op.
    pub fn reconcile_scratch_generation(&self, marker: &str) -> Result<bool> {
        const KEY: &str = "cas.cloud.scratch_generation";
        self.with_immediate_tx(|tx| {
            let previous: Option<String> = tx
                .query_row(
                    "SELECT value FROM config WHERE key = ?1",
                    params![KEY],
                    |row| row.get(0),
                )
                .optional()?;
            if previous.as_deref() == Some(marker) {
                return Ok(false);
            }
            tx.execute(
                "DELETE FROM blobs
                   WHERE durable = 0 AND inline IS NULL",
                [],
            )?;
            tx.execute(
                "UPDATE blobs
                    SET complete = 0, bitmap = NULL
                  WHERE durable != 0 AND inline IS NULL",
                [],
            )?;
            crate::db::set_config_in(tx, KEY, marker)?;
            Ok(true)
        })
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
        let conn = self.conn();
        if self.is_being_written(root) {
            return Ok(false);
        }
        conn.execute(
            "DELETE FROM blobs WHERE root = ?1 AND durable = 0 AND inline IS NULL",
            params![root.as_bytes().to_vec()],
        )?;
        conn.execute(
            "UPDATE blobs SET complete = 0, bitmap = NULL
               WHERE root = ?1 AND durable != 0 AND inline IS NULL",
            params![root.as_bytes().to_vec()],
        )?;
        let _ = std::fs::remove_file(self.blob_path(root));
        let _ = std::fs::remove_file(self.outboard_path(root));
        drop(conn);
        Ok(true)
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

    /// Current out-of-line bytes occupied by reconstructible durable cache
    /// entries (payload plus outboard).
    pub(crate) fn durable_cache_bytes(&self) -> Result<u64> {
        Ok(self
            .durable_cache_entries()?
            .into_iter()
            .map(|(_, _, bytes)| bytes)
            .sum())
    }

    /// Evicts least-recently-used durable cache entries until `target_bytes`
    /// is met. Pinned rows are eligible because their promise lives remotely;
    /// staged-only rows are never eligible because scratch is their only copy.
    pub(crate) fn evict_durable_cache_to(&self, target_bytes: u64) -> Result<(usize, u64)> {
        let mut entries = self.durable_cache_entries()?;
        entries.sort_unstable_by_key(|(_, last_access, _)| *last_access);
        let mut usage: u64 = entries.iter().map(|(_, _, bytes)| *bytes).sum();
        let mut evicted = 0usize;
        let mut freed = 0u64;
        for (root, _, bytes) in entries {
            if usage <= target_bytes {
                break;
            }
            if !self.clear_blob_cache(&root)? {
                continue;
            }
            usage = usage.saturating_sub(bytes);
            freed = freed.saturating_add(bytes);
            evicted += 1;
        }
        Ok((evicted, freed))
    }

    /// Advances a cache entry's LRU clock after a backend-served read.
    pub(crate) fn touch_blob(&self, root: &Hash, now: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE blobs SET last_access = max(last_access, ?2) WHERE root = ?1",
            params![root.as_bytes().to_vec(), now],
        )?;
        Ok(())
    }

    fn durable_cache_entries(&self) -> Result<Vec<(Hash, i64, u64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT root, last_access FROM blobs
              WHERE durable != 0 AND inline IS NULL",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (encoded, last_access) = row?;
            let root = hash_column(encoded, "blobs.root")?;
            let payload = cache_file_bytes(&self.blob_path(&root));
            let outboard = cache_file_bytes(&self.outboard_path(&root));
            let bytes = payload.saturating_add(outboard);
            if bytes > 0 {
                out.push((root, last_access, bytes));
            }
        }
        Ok(out)
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
        self.with_immediate_tx(|tx| {
            // Held, not merely known: a `blobs` row exists for a partial fetch
            // too. `take_possession` enforces the same thing on the other entry
            // point, and a promise about bytes belongs in the store rather than
            // in the discipline of every caller.
            let held: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs
                                WHERE root = ?1 AND (complete != 0 OR durable != 0))",
                params![root.as_bytes().to_vec()],
                |row| row.get(0),
            )?;
            if !held {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO pins (root, holder, created_at, release_after)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT(root, holder) DO UPDATE SET release_after = NULL",
                params![root.as_bytes().to_vec(), holder.render(), now],
            )?;
            Ok(true)
        })
    }

    /// Drops one holder's claim. Returns whether there was one to drop.
    pub fn unpin(&self, root: &Hash, holder: &PinHolder) -> Result<bool> {
        let dropped = self.conn().execute(
            "DELETE FROM pins WHERE root = ?1 AND holder = ?2",
            params![root.as_bytes().to_vec(), holder.render()],
        )?;
        Ok(dropped > 0)
    }

    /// Drops every claim one holder has, for `space rm --release` and
    /// `--no-replicate --release`. Returns how many went.
    pub fn unpin_all(&self, holder: &PinHolder) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM pins WHERE holder = ?1",
            params![holder.render()],
        )?)
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
        Ok(self.conn().execute(
            "DELETE FROM pins
              WHERE holder = ?1 AND release_after IS NOT NULL AND release_after <= ?2",
            params![holder.render(), now],
        )?)
    }

    /// Drops claims whose scheduled release has arrived, so that every other
    /// predicate over `pins` can stay free of the clock. Returns how many went.
    pub fn expire_pins(&self, now: i64) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM pins WHERE release_after IS NOT NULL AND release_after <= ?1",
            params![now],
        )?)
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
    pub(crate) fn delete_blob_if_collectable(&self, root: &Hash, before: i64) -> Result<bool> {
        // The connection guard is held across the unlinks, not just across the
        // transaction, so no *row* writer can slip between the delete and the
        // files going.
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
        let mut conn = self.conn();
        if self.is_being_written(root) {
            return Ok(false);
        }
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let rows = tx.execute(
            "DELETE FROM blobs
               WHERE root = ?1
                 AND NOT EXISTS (SELECT 1 FROM pins WHERE pins.root = blobs.root)
                 AND last_access < ?2
                 AND NOT EXISTS (
                   SELECT 1 FROM entries WHERE entries.content = blobs.root
                 )",
            params![root.as_bytes().to_vec(), before],
        )?;
        tx.commit()?;
        let deleted = rows > 0;
        if deleted {
            let _ = std::fs::remove_file(self.blob_path(root));
            let _ = std::fs::remove_file(self.outboard_path(root));
        }
        drop(conn);
        Ok(deleted)
    }

    /// Deletes an object's payload, outboard, and index row.
    ///
    /// Unconditional: for callers that have already decided, such as an
    /// explicit `synch rm`. GC goes through `delete_blob_if_collectable`
    /// instead, which re-checks the predicate against the same transaction that
    /// does the delete.
    pub fn delete_blob(&self, root: &Hash) -> Result<()> {
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

        let mut out = vec![0u8; (end - offset) as usize];
        match &blob.inline {
            Some(data) => out.copy_from_slice(&data[offset as usize..end as usize]),
            None => File::open(self.blob_path(root))?.read_exact_at(offset, &mut out)?,
        }
        Ok(out)
    }

    /// Reads a whole object from the trusted storage backend.
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
                encode_ranges(data.as_slice(), outboard, &bao_ranges, &mut encoded)
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
                encode_ranges(DataFile(data), outboard, &bao_ranges, &mut encoded)
            }
        }
        .map_err(|error| StoreError::invalid(format!("encode slice: {error}")))?;
        Ok(encoded)
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
        if let Some(row) = self.blob(root)? {
            let held = row.verified_groups();
            settle_size(
                root,
                Some((row.size, row.complete, row.durable, &held)),
                size,
            )?;
            if row.complete {
                return Ok(ChunkRanges::empty());
            }
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
        let groups = group_count(size);
        let served = served.intersect(&ChunkRanges::single(0, groups));
        if served.is_empty() {
            return Ok(ChunkRanges::empty());
        }
        // Taken before the row is read and held past the commit: everything
        // between is file IO with no lock held, and a sweep deciding this object
        // is collectable in that window would unlink the bytes out from under
        // the row this is about to write ([`Store::lease_write`]).
        let _lease = self.lease_write(root);
        let tree = Self::tree(size);
        let bao_ranges = to_bao_ranges(&served);
        let root_hash = blake3::Hash::from_bytes(root.0);

        let existing = self.blob(root)?;
        if let Some(row) = &existing {
            // The cheap refusal. [`settle_size`] decides again, transactionally,
            // at the commit — this one is here so a claim that cannot possibly
            // stand never reaches the disk at all.
            let held = row.verified_groups();
            settle_size(
                root,
                Some((row.size, row.complete, row.durable, &held)),
                size,
            )?;
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
        // Not pre-grown at all, and never shrunk.
        //
        // Never shrunk, because sizing a file down on the strength of a claim
        // is how an understated entry destroys verified groups — bytes gone,
        // bitmap bits intact, the node advertising a group it can no longer
        // serve ([`grow_to`], `docs/DELTA-SYNC.md` §6).
        //
        // Not pre-grown, because `size` is a peer's assertion off an entry and
        // this runs *before* `decode_ranges` turns any of it into fact. An
        // entry claiming 32 TiB for any root would otherwise have every node
        // that attempts a fetch create a 32 TiB payload and a 128 GiB outboard,
        // fail verification, and leave both behind — `trim_to_size` only runs
        // on a commit that completed the object, so nothing reclaims them.
        //
        // Let the decode extend the file: `write_at` grows it as each verified
        // group lands, so the
        // payload never gets longer than the bytes that have been proven
        // against the root, whatever the window's position.
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
        // Both flushes are checked. Swallowing them would let an EIO or ENOSPC
        // on flush advance the bitmap over data that never reached stable
        // storage — the exact inversion of the ordering this block exists to
        // enforce. `try_clone` may likewise not fail silently: it fails under
        // fd exhaustion, which is precisely when the machine is least able to
        // afford an unflushed commit.
        let payload = payload_for_sync.ok_or_else(|| StoreError::Verification {
            root: *root,
            reason: "could not duplicate the payload handle to flush it".into(),
        })?;
        fsync_file(&payload)?;
        // The directory entries too, not only the contents. Both files are
        // opened `create(true)`, so the first window of a fetch creates them —
        // and `fsync` promises the bytes, not that the name they hang from
        // survives. The mainstream Linux filesystems do persist a new file's
        // dirent on its own `fsync`, so this is defence in depth rather than a
        // live hole, but the two other creation sites here (`ingest_file` and
        // `write_and_sync`) both do it, and unlike the orphan case a lost name
        // under an advanced bitmap never self-heals: the row goes on claiming
        // groups whose bytes are unreachable.
        fsync_parent(&payload_path);
        // Reopened for *write* to flush it. `File::open` hands back a read-only
        // handle, and Windows refuses `FlushFileBuffers` on one with
        // ERROR_ACCESS_DENIED — a hard failure here, since these flushes are
        // checked rather than discarded. Unix does not care either way.
        fsync_file(
            &OpenOptions::new()
                .write(true)
                .open(self.outboard_path(root))?,
        )?;
        fsync_parent(&self.outboard_path(root));

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
            store.delete_blob(&root).unwrap();
            std::fs::write(store.blob_path(&root), &payload).unwrap();
            assert_eq!(store.gc_orphans(i64::MAX).unwrap(), 0);
            assert!(store.blob_path(&root).exists());
        }

        // Once the lease is gone both sweeps do their job.
        assert!(store.gc_orphans(i64::MAX).unwrap() > 0);
        assert!(!store.blob_path(&root).exists());
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

    /// An ingest re-creating content whose old row is collectable keeps its
    /// bytes: between the rename and the row write there is a window a
    /// `gc_content` pass could unlink the payload in. Threaded with a
    /// handshake, because the window only exists inside `ingest_file` and the
    /// collector must be spinning before the ingest begins.
    #[test]
    fn an_ingest_that_recreates_a_collectable_object_keeps_its_bytes() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let (dir, store) = store();
        let store = std::sync::Arc::new(store);
        // Past `INLINE_BLOB_MAX`, so the payload is a file rather than a column
        // and the rename → fsync → outboard → row window is a real one.
        let payload = data(32 * 1024 * 1024);
        let source = dir.path().join("restored.bin");
        std::fs::write(&source, &payload).unwrap();

        // The state that makes this reachable: a row for this exact content
        // that is cold, unreferenced and unpinned — an ordinary `gc_content`
        // candidate — while the same content is ingested again.
        let root = store.ingest_bytes(&payload, 0).unwrap();

        let ready = std::sync::Arc::new(AtomicBool::new(false));
        let observed = std::sync::Arc::new(AtomicBool::new(false));
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let collector = {
            let store = store.clone();
            let (ready, observed, done) = (ready.clone(), observed.clone(), done.clone());
            std::thread::spawn(move || {
                ready.store(true, Ordering::SeqCst);
                while !done.load(Ordering::SeqCst) {
                    if store.is_being_written(&root) {
                        observed.store(true, Ordering::SeqCst);
                        // Refused — or this returns true and unlinks the bytes
                        // the ingest is midway through writing, leaving the row
                        // it is about to commit describing nothing.
                        assert!(
                            !store.delete_blob_if_collectable(&root, i64::MAX).unwrap(),
                            "an ingest in flight is not a collectable object"
                        );
                        return;
                    }
                    std::thread::yield_now();
                }
            })
        };
        while !ready.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }

        let (ingested, size) = store.ingest_file(&source, 1).unwrap();
        done.store(true, Ordering::SeqCst);
        collector.join().unwrap();

        assert_eq!(ingested, root);
        assert_eq!(size, payload.len() as u64);
        assert!(
            observed.load(Ordering::SeqCst),
            "the ingest held no write lease, so a sweep in its window would have \
             unlinked the bytes of the row it then committed"
        );
        // The invariant: a row calling the object complete, and the bytes it
        // describes.
        assert!(store.blob(&root).unwrap().unwrap().complete);
        assert_eq!(store.read_all(&root).unwrap(), payload);
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
        store.delete_blob(&root).unwrap();
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
