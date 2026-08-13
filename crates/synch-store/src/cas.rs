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
            Some(bits) => bitmap_to_ranges(bits, group_count(self.size)),
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

fn bitmap_len(groups: u64) -> usize {
    groups.div_ceil(8) as usize
}

fn bitmap_to_ranges(bits: &[u8], groups: u64) -> ChunkRanges {
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

fn ranges_to_bitmap(ranges: &ChunkRanges, groups: u64) -> Vec<u8> {
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

    fn tree(size: u64) -> BaoTree {
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
        let staging = self
            .cas_dir()
            .join(format!("incoming-{}.tmp", std::process::id()));
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
        std::fs::write(self.outboard_path(&root), &outboard)?;
        self.write_blob_row(&root, size, true, None, None, now)?;
        Ok((root, size))
    }

    fn write_payload(&self, root: &Hash, data: &[u8], outboard: &[u8]) -> Result<()> {
        let path = self.blob_path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, data)?;
        std::fs::write(self.outboard_path(root), outboard)?;
        Ok(())
    }

    fn write_blob_row(
        &self,
        root: &Hash,
        size: u64,
        complete: bool,
        bitmap: Option<Vec<u8>>,
        inline: Option<Vec<u8>>,
        now: i64,
    ) -> Result<()> {
        self.conn().execute(
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
        let _ = std::fs::remove_file(self.blob_path(root));
        let _ = std::fs::remove_file(self.outboard_path(root));
        self.conn().execute(
            "DELETE FROM blobs WHERE root = ?1",
            params![root.as_bytes().to_vec()],
        )?;
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
        self.touch(root)?;
        Ok(out)
    }

    /// Reads a whole object, verified.
    pub fn read_all(&self, root: &Hash) -> Result<Vec<u8>> {
        let blob = self.blob(root)?.ok_or(StoreError::MissingBlob(*root))?;
        self.read_range(root, 0, blob.size)
    }

    fn touch(&self, root: &Hash) -> Result<()> {
        self.conn().execute(
            "UPDATE blobs SET last_access = ?2 WHERE root = ?1",
            params![root.as_bytes().to_vec(), synch_core::now_ns()],
        )?;
        Ok(())
    }

    // ---- slice serving and receiving --------------------------------------

    /// Encodes a bao slice for the requested ranges, returning the encoded
    /// bytes and the ranges actually served (§6.4).
    ///
    /// The provider serves the intersection of what was asked for and what it
    /// verifiably holds; the requester learns exact availability from the
    /// returned ranges, which is what `SliceEnd` carries.
    pub fn encode_slice(
        &self,
        root: &Hash,
        requested: &ChunkRanges,
    ) -> Result<(Vec<u8>, ChunkRanges)> {
        let blob = self.blob(root)?.ok_or(StoreError::MissingBlob(*root))?;
        let served = requested
            .intersect(&blob.verified_groups())
            .intersect(&ChunkRanges::single(0, group_count(blob.size)));
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
                let data = File::open(self.blob_path(&blob.root))?;
                let outboard_data = std::fs::read(self.outboard_path(&blob.root))?;
                let outboard = PreOrderOutboard {
                    root: root_hash,
                    tree,
                    data: outboard_data,
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
            if row.size != size {
                return Err(StoreError::Verification {
                    root: *root,
                    reason: format!("size mismatch: have {}, offered {}", row.size, size),
                });
            }
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
            let verified = existing
                .map(|r| r.verified_groups())
                .unwrap_or_else(ChunkRanges::empty)
                .union(&served);
            let complete = verified.count() >= groups;
            self.write_blob_row(
                root,
                size,
                complete,
                (!complete).then(|| ranges_to_bitmap(&verified, groups)),
                Some(buffer),
                now,
            )?;
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
        payload.set_len(size)?;
        let outboard_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.outboard_path(root))?;
        outboard_file.set_len(tree.outboard_size())?;
        let outboard = PreOrderOutboard {
            root: root_hash,
            tree,
            data: outboard_file,
        };
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

        let verified = existing
            .map(|r| r.verified_groups())
            .unwrap_or_else(ChunkRanges::empty)
            .union(&served);
        let complete = verified.count() >= groups;
        self.write_blob_row(
            root,
            size,
            complete,
            (!complete).then(|| ranges_to_bitmap(&verified, groups)),
            None,
            now,
        )?;
        Ok(served)
    }
}

/// `positioned-io` gives `File` the random-access reads and writes bao needs;
/// this newtype exists only so the trait bounds resolve on both platforms
/// without importing `positioned-io` directly.
struct DataFile(File);

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

    #[test]
    fn bitmap_round_trip() {
        let ranges = ChunkRanges::from_ranges([GroupRange::new(0, 3), GroupRange::new(7, 20)]);
        let bits = ranges_to_bitmap(&ranges, 20);
        assert_eq!(bitmap_to_ranges(&bits, 20), ranges);
        assert!(bitmap_to_ranges(&[0u8; 3], 20).is_empty());
    }
}
