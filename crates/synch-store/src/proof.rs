//! Tree proofs and donor promotion: the store half of delta sync
//! (`docs/DELTA-SYNC.md` §3.1, §3.3, §3.4).
//!
//! A *proof* is a bao slice with the payload left out: the interior hash pairs
//! on the paths from an object's root to a set of chunk groups, descending no
//! deeper than a requested level. It answers "what does this object's tree look
//! like here?" for 64 bytes a node instead of 16 KiB a group, which is what
//! makes it worth asking before fetching anything — a node that already holds
//! the previous version of a file can compare the answer against bytes it has
//! and discover that almost none of the new version needs to cross the network.
//!
//! Nothing here trusts anyone. A proof is verified by recomputation from the
//! root the caller already trusts (§5.1's rule that no byte is believed because
//! of who supplied it, applied to hashes), and a *donor* — a local object or
//! file whose bytes look like they belong in the new object — is verified the
//! same way, by hashing what is actually on the disk right now and checking it
//! against a chaining value the proof established. A stale or hostile donor
//! costs CPU; it cannot cost correctness.

use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
};

use bao_tree::{
    io::{
        outboard::PreOrderOutboard,
        sync::{Outboard, OutboardMut, ReadAt, WriteAt},
    },
    BaoTree, TreeNode,
};
use synch_core::{
    group_count, group_cv, join_cvs, join_root, ChunkRanges, Cv, GroupRange, Hash,
    CHUNK_GROUP_SIZE, INLINE_BLOB_MAX, MAX_PROOF_NODES, PROOF_NODE_LEN,
};

use crate::{
    cas::{fsync_file, ranges_to_bitmap, DataFile},
    db::Store,
    error::{Result, StoreError},
};

/// A subtree of an object whose chaining value is proven against its root.
///
/// "Proven" means recomputed: the pairs on the path from the root down to this
/// subtree were combined back up and arrived at the root the caller named. It
/// says nothing yet about whether anyone holds the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenSubtree {
    /// The first chunk group the subtree covers.
    pub start: u64,
    /// How many groups it covers.
    pub groups: u64,
    /// Its chaining value.
    pub cv: Cv,
    /// True if the subtree is whole: aligned, a full power of two of groups,
    /// and entirely inside the object.
    ///
    /// Only whole subtrees are comparable across objects. A subtree cut short
    /// by the end of one object covers different bytes from the one at the same
    /// position in a longer object, so their chaining values say nothing about
    /// each other — which is why the tail of a file always descends to the leaf
    /// level rather than being promoted wholesale (§3.3).
    pub whole: bool,
}

impl ProvenSubtree {
    /// One past the last group the subtree covers.
    pub fn end(&self) -> u64 {
        self.start + self.groups
    }

    /// The subtree as a group range.
    pub fn range(&self) -> GroupRange {
        GroupRange::new(self.start, self.end())
    }
}

/// A local source of candidate bytes for an object (§3.2).
///
/// Donors are hints about where bytes might be found, never authority about
/// what they are: every group a donor supplies is hashed and checked against a
/// proven chaining value before it is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Donor {
    /// Another object in this node's CAS, read from its payload at the same
    /// byte offsets — typically the entry's `prev` root, or another version of
    /// the same path (§4.2, §8).
    Object(Hash),
    /// An ordinary file on disk, read at the same byte offsets.
    ///
    /// A mirror's materialized copy of the previous version is the case this
    /// exists for: the bytes are right there even when the CAS has long since
    /// collected the object they came from (§3.2.4).
    File(PathBuf),
}

impl Donor {
    /// The object root a donor supplies bytes for, when it has one.
    pub fn root(&self) -> Option<Hash> {
        match self {
            Donor::Object(root) => Some(*root),
            Donor::File(_) => None,
        }
    }
}

/// One node of an object's bao tree, in chunk-group units.
///
/// `span` is the node's untruncated width — always a power of two — and
/// `groups` is how much of it the object actually reaches. The two differ only
/// along the tree's right edge, and only there does the distinction matter:
/// `span` decides the shape (where the subtree splits, which node of the
/// outboard holds its pair) while `groups` decides the bytes.
#[derive(Debug, Clone, Copy)]
struct Subtree {
    /// bao's name for the node, which is what indexes the outboard.
    node: TreeNode,
    /// The first group the subtree covers.
    start: u64,
    /// How many groups it actually covers.
    groups: u64,
    /// The untruncated width, a power of two.
    span: u64,
}

impl Subtree {
    /// The root of an object's tree, covering every group it has.
    fn root_of(tree: &BaoTree, groups: u64) -> Subtree {
        Subtree {
            node: tree.root(),
            start: 0,
            groups,
            span: groups.next_power_of_two(),
        }
    }

    /// One past the last group the subtree covers.
    fn end(&self) -> u64 {
        self.start + self.groups
    }

    /// The two halves of a subtree of more than one group.
    ///
    /// bao splits at the largest power of two below the group count, which for
    /// a node of span `2^k` is always `2^(k-1)`: the left half is full and the
    /// right half is whatever is left, one group at the least.
    ///
    /// The right half then *collapses*. A tree of 20 groups splits 16 and 4, and
    /// those 4 groups are not a quarter-full node of span 16 — bao has no such
    /// node, and the outboard stores nothing for it. They are a full node of
    /// span 4, reached by walking down the left edge of where the wider node
    /// would have been. Getting this wrong is the classic bao off-by-a-subtree:
    /// every hash on the right edge of every object whose size is not a power
    /// of two lands at the wrong place.
    fn children(&self) -> Option<(Subtree, Subtree)> {
        if self.groups <= 1 {
            return None;
        }
        let half = self.span / 2;
        let left = Subtree {
            node: self.node.left_child()?,
            start: self.start,
            groups: half,
            span: half,
        };
        let mut right = Subtree {
            node: self.node.right_child()?,
            start: self.start + half,
            groups: self.groups - half,
            span: half,
        };
        while right.groups <= right.span / 2 {
            right.span /= 2;
            right.node = right.node.left_child()?;
        }
        Some((left, right))
    }

    /// Finds the node of a tree that covers exactly this run of groups.
    ///
    /// A [`ProvenSubtree`] names itself by position and width, which is all a
    /// caller comparing objects needs; writing its interior back into *this*
    /// object's outboard needs bao's name for it, and that is a walk down from
    /// the root. `None` for a run that is not a subtree of this tree at all.
    fn locate(tree: &BaoTree, total: u64, start: u64, groups: u64) -> Option<Subtree> {
        let mut node = Subtree::root_of(tree, total);
        loop {
            if node.start == start && node.groups == groups {
                return Some(node);
            }
            let (left, right) = node.children()?;
            node = if start < right.start { left } else { right };
            if start < node.start || start >= node.end() {
                return None;
            }
        }
    }

    /// True if the subtree is whole within an object of `size` bytes.
    fn is_whole(&self, size: u64) -> bool {
        self.groups == self.span
            && self
                .end()
                .checked_mul(CHUNK_GROUP_SIZE)
                .is_some_and(|end| end <= size)
    }

    /// The byte range the subtree covers in an object of `size` bytes.
    fn byte_range(&self, size: u64) -> (u64, u64) {
        let start = self.start.saturating_mul(CHUNK_GROUP_SIZE);
        let end = self
            .end()
            .saturating_mul(CHUNK_GROUP_SIZE)
            .min(size)
            .max(start);
        (start, end)
    }
}

/// What one walk of an object's tree established.
#[derive(Debug, Default)]
struct Proof {
    /// The interior nodes the walk visited, in pre-order.
    nodes: Vec<(TreeNode, [u8; PROOF_NODE_LEN])>,
    /// The subtrees whose chaining values the walk established.
    proven: Vec<ProvenSubtree>,
}

/// A pre-order descent over the nodes a proof consists of.
///
/// Both sides of the exchange run this same walk, which is the point: the
/// provider emits exactly the nodes the requester will ask for, in exactly the
/// order it will consume them, so a proof needs no self-describing framing and
/// a requester that runs out of bytes early knows the answer was wrong rather
/// than merely differently shaped. `load` supplies each node's pair — off the
/// `.obao` file on the serving side, out of the received bytes on the receiving
/// one — and every pair is checked against the chaining value its parent
/// already committed to before either side goes any further.
struct Walk<'a, L> {
    root: Hash,
    size: u64,
    ranges: &'a ChunkRanges,
    level: u8,
    budget: u64,
    load: L,
    out: Proof,
    /// The first group whose proof did not fit in the budget, if any.
    truncated_at: Option<u64>,
}

impl<L> Walk<'_, L>
where
    L: FnMut(&TreeNode) -> Result<[u8; PROOF_NODE_LEN]>,
{
    fn verification(&self, reason: impl Into<String>) -> StoreError {
        StoreError::Verification {
            root: self.root,
            reason: reason.into(),
        }
    }

    /// Walks one node, with the chaining value its parent proved for it —
    /// `None` at the root, whose hash the caller already trusts.
    fn descend(&mut self, node: Subtree, expected: Option<Cv>) -> Result<()> {
        if self.truncated_at.is_some() {
            // The budget ran out to the left of here. Emitting anything now
            // would make the two sides disagree about what a proof for these
            // ranges contains, so the walk stops dead and `ProofEnd` reports
            // where.
            return Ok(());
        }
        if !self.ranges.overlaps(node.start, node.end()) {
            return Ok(());
        }
        // A single group has no interior, and a subtree no wider than the level
        // the caller asked to stop at is as deep as this proof goes: either way
        // its chaining value came from its parent and the descent ends here.
        if node.groups == 1 || node.span <= (1u64 << self.level.min(63)) {
            if let Some(cv) = expected {
                self.out.proven.push(ProvenSubtree {
                    start: node.start,
                    groups: node.groups,
                    cv,
                    whole: node.is_whole(self.size),
                });
            }
            return Ok(());
        }
        if self.out.nodes.len() as u64 >= self.budget {
            self.truncated_at = Some(node.start);
            return Ok(());
        }

        let pair = (self.load)(&node.node)?;
        let left = Cv(pair[..32].try_into().expect("32 of 64 bytes"));
        let right = Cv(pair[32..].try_into().expect("32 of 64 bytes"));
        // The one check the whole exchange rests on. A pair is believed because
        // recomputing its parent from it lands on a value that was itself
        // believed, all the way up to the root the entry named — so a flipped
        // bit fails at the node it occurs in, exactly as it does in a slice.
        match expected {
            Some(cv) => {
                if join_cvs(&left, &right) != cv {
                    return Err(self.verification(format!(
                        "proof node at group {} does not hash to the value its parent proved",
                        node.start
                    )));
                }
            }
            None => {
                if join_root(&left, &right) != self.root {
                    return Err(self.verification("the top proof node does not hash to the root"));
                }
            }
        }
        self.out.nodes.push((node.node, pair));

        let (left_child, right_child) = node
            .children()
            .ok_or_else(|| self.verification("a multi-group subtree has no children"))?;
        self.descend(left_child, Some(left))?;
        self.descend(right_child, Some(right))
    }
}

/// Runs one proof walk over an object's tree.
///
/// Returns what the walk established and, when the node budget ran out, the
/// first group it could not cover.
fn walk_proof<L>(
    root: &Hash,
    size: u64,
    ranges: &ChunkRanges,
    level: u8,
    budget: u64,
    load: L,
) -> Result<(Proof, Option<u64>)>
where
    L: FnMut(&TreeNode) -> Result<[u8; PROOF_NODE_LEN]>,
{
    let groups = group_count(size);
    let mut walk = Walk {
        root: *root,
        size,
        ranges,
        level,
        budget,
        load,
        out: Proof::default(),
        truncated_at: None,
    };
    if size > 0 && !ranges.is_empty() {
        let tree = Store::tree(size);
        walk.descend(Subtree::root_of(&tree, groups), None)?;
    }
    Ok((walk.out, walk.truncated_at))
}

/// Reads a node's pair out of a pre-order outboard.
fn load_from_outboard<R: ReadAt>(
    outboard: &PreOrderOutboard<R>,
    root: &Hash,
    node: &TreeNode,
) -> Result<[u8; PROOF_NODE_LEN]> {
    let pair = outboard.load(*node)?.ok_or(StoreError::Verification {
        root: *root,
        reason: format!("no outboard entry for node {node}"),
    })?;
    let mut bytes = [0u8; PROOF_NODE_LEN];
    bytes[..32].copy_from_slice(pair.0.as_bytes());
    bytes[32..].copy_from_slice(pair.1.as_bytes());
    Ok(bytes)
}

/// Walks down to one aligned subtree and reads its chaining value out of the
/// pair its parent holds.
///
/// Chaining values are only ever half of somebody's pair, which is exactly why
/// the object's own root is not one: it carries BLAKE3's root flag, and a
/// subtree of another object could never equal it (`docs/DELTA-SYNC.md` §2).
/// Asking for the whole object therefore answers `None` rather than the root.
fn cv_at<R: ReadAt>(
    root: &Hash,
    outboard: &PreOrderOutboard<R>,
    groups: u64,
    start: u64,
    span: u64,
) -> Result<Option<Cv>> {
    let mut node = Subtree::root_of(&outboard.tree, groups);
    loop {
        if node.start == start && node.span == span {
            return Ok(None);
        }
        let Some((left, right)) = node.children() else {
            return Ok(None);
        };
        let pair = load_from_outboard(outboard, root, &node.node)?;
        let (child, cv) = if start < right.start {
            (left, Cv(pair[..32].try_into().expect("32 of 64 bytes")))
        } else {
            (right, Cv(pair[32..].try_into().expect("32 of 64 bytes")))
        };
        if child.span < span {
            // This object's tree is finer here than the span asked about — the
            // span straddles a boundary that only exists in the other object.
            return Ok(None);
        }
        if child.start == start && child.span == span {
            return Ok(Some(cv));
        }
        node = child;
    }
}

/// A donor's bytes, however they are stored.
enum DonorBytes {
    /// A blob small enough to live in the index (§6.2).
    Inline(Vec<u8>),
    /// A payload or an ordinary file, read positionally.
    OnDisk(File),
}

impl DonorBytes {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            DonorBytes::Inline(data) => {
                let start = offset.min(data.len() as u64) as usize;
                let end = start + buf.len();
                if end > data.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "donor is shorter than the range asked of it",
                    ));
                }
                buf.copy_from_slice(&data[start..end]);
                Ok(())
            }
            DonorBytes::OnDisk(file) => file.read_exact_at(offset, buf),
        }
    }
}

/// A donor opened for reading, with the groups it can actually supply.
struct OpenDonor {
    bytes: DonorBytes,
    /// The groups the donor is known to hold, in the object's own grid — the
    /// bitmap for a CAS object, everything up to the end for a plain file.
    held: ChunkRanges,
    /// How long the donor is, which bounds what can be read out of it.
    size: u64,
}

impl Store {
    // ---- proof serving ----------------------------------------------------

    /// Encodes the tree over `requested` down to `level`, without the payload
    /// (`docs/DELTA-SYNC.md` §3.1).
    ///
    /// Returns the pre-order node pairs and the ranges they actually cover.
    /// Like a slice, a proof is served for the intersection of what was asked
    /// for and what the provider verifiably holds — a partial holder's outboard
    /// carries every node on the path to its own groups, and nothing else — and
    /// like a slice it is clamped to one window, here counted in nodes rather
    /// than groups ([`MAX_PROOF_NODES`]). `ProofEnd` carries the second return
    /// value, and the requester's next window starts where it stopped.
    ///
    /// The outboard is read positionally, one node at a time, never slurped:
    /// the span-level round over a 100 GB object touches a few thousand of its
    /// 390 MB of tree.
    pub fn encode_proof(
        &self,
        root: &Hash,
        requested: &ChunkRanges,
        level: u8,
    ) -> Result<(Vec<u8>, ChunkRanges)> {
        self.encode_proof_bounded(root, requested, level, MAX_PROOF_NODES)
    }

    /// [`Store::encode_proof`] with the window bound spelled out, so that the
    /// clamping can be exercised without a 128 GB object.
    fn encode_proof_bounded(
        &self,
        root: &Hash,
        requested: &ChunkRanges,
        level: u8,
        budget: u64,
    ) -> Result<(Vec<u8>, ChunkRanges)> {
        let blob = self.blob(root)?.ok_or(StoreError::MissingBlob(*root))?;
        let groups = group_count(blob.size);
        let wanted = requested
            .intersect(&blob.verified_groups())
            .intersect(&ChunkRanges::single(0, groups));
        if wanted.is_empty() || groups <= 1 {
            // A single-group object has no interior nodes at all: its root is
            // the group, and there is nothing to prove about it that the root
            // does not already say.
            return Ok((Vec::new(), wanted));
        }

        let tree = Self::tree(blob.size);
        let outboard = PreOrderOutboard {
            root: blake3::Hash::from_bytes(root.0),
            tree,
            data: DataFile(File::open(self.outboard_path(root))?),
        };
        let (proof, truncated) = walk_proof(root, blob.size, &wanted, level, budget, |node| {
            load_from_outboard(&outboard, root, node)
        })?;
        let (proof, served) = match truncated {
            None => (proof, wanted),
            Some(at) => {
                // The walk stopped partway. Rather than ship the prefix it
                // managed and leave the requester to guess which nodes it got,
                // the walk is repeated over exactly the ranges that fit: both
                // sides then agree on the answer node for node.
                let served = wanted.intersect(&ChunkRanges::single(0, at));
                if served.is_empty() {
                    return Ok((Vec::new(), served));
                }
                let (proof, _) = walk_proof(root, blob.size, &served, level, budget, |node| {
                    load_from_outboard(&outboard, root, node)
                })?;
                (proof, served)
            }
        };

        let mut encoded = Vec::with_capacity(proof.nodes.len() * PROOF_NODE_LEN);
        for (_, pair) in &proof.nodes {
            encoded.extend_from_slice(pair);
        }
        Ok((encoded, served))
    }

    // ---- proof receiving --------------------------------------------------

    /// Verifies a received proof and commits its nodes to the object's tree.
    ///
    /// Every pair is checked by recomputation up to `root` before anything is
    /// written, so a tampered proof is rejected whole. What survives is written
    /// into the object's sparse `.obao` at the positions bao would have put it:
    /// the tree of the new version accumulates ahead of its bytes, which is
    /// what lets promoted groups be *served* rather than merely held (§3.4).
    ///
    /// Returns the subtrees whose chaining values the proof established — one
    /// per group at `level = 0`, one per span higher up.
    pub fn write_proof(
        &self,
        root: &Hash,
        size: u64,
        served: &ChunkRanges,
        level: u8,
        encoded: &[u8],
        now: i64,
    ) -> Result<Vec<ProvenSubtree>> {
        let groups = group_count(size);
        let served = served.intersect(&ChunkRanges::single(0, groups));
        if let Some(row) = self.blob(root)? {
            if row.size != size {
                return Err(StoreError::Verification {
                    root: *root,
                    reason: format!("size mismatch: have {}, offered {}", row.size, size),
                });
            }
        }
        if !encoded.len().is_multiple_of(PROOF_NODE_LEN) {
            return Err(StoreError::Verification {
                root: *root,
                reason: format!("a proof of {} bytes is not whole nodes", encoded.len()),
            });
        }

        let mut cursor = 0usize;
        let (proof, truncated) = walk_proof(root, size, &served, level, MAX_PROOF_NODES, |_| {
            let end = cursor + PROOF_NODE_LEN;
            if end > encoded.len() {
                return Err(StoreError::Verification {
                    root: *root,
                    reason: "the proof ended before the ranges it claimed".into(),
                });
            }
            let mut bytes = [0u8; PROOF_NODE_LEN];
            bytes.copy_from_slice(&encoded[cursor..end]);
            cursor = end;
            Ok(bytes)
        })?;
        if truncated.is_some() {
            // No honest provider emits more than one window's worth, so a proof
            // that needs more than that is not a proof of what it claims.
            return Err(StoreError::Verification {
                root: *root,
                reason: "the proof claims more ranges than one window can cover".into(),
            });
        }
        if cursor != encoded.len() {
            // Trailing nodes are not merely wasteful: they mean the provider
            // walked a different tree from the one this root describes.
            return Err(StoreError::Verification {
                root: *root,
                reason: format!(
                    "the proof carries {} bytes the ranges it claimed do not account for",
                    encoded.len() - cursor
                ),
            });
        }

        if !proof.nodes.is_empty() {
            let tree = Self::tree(size);
            let (_, outboard_file) = self.open_sparse(root, size, tree)?;
            let mut outboard = PreOrderOutboard {
                root: blake3::Hash::from_bytes(root.0),
                tree,
                data: DataFile(outboard_file),
            };
            for (node, pair) in &proof.nodes {
                let left = blake3::Hash::from_bytes(pair[..32].try_into().expect("32 of 64"));
                let right = blake3::Hash::from_bytes(pair[32..].try_into().expect("32 of 64"));
                outboard.save(*node, &(left, right))?;
            }
            outboard.sync()?;
            let _ = fsync_file(&outboard.data.0);
            // The row is what later passes read the object's size and bitmap
            // out of. A proof commits no bytes, so an object first met this way
            // is recorded as held-nothing rather than not held at all.
            if self.blob(root)?.is_none() {
                let empty = ranges_to_bitmap(&ChunkRanges::empty(), groups);
                self.write_blob_row(root, size, false, Some(empty), None, now)?;
            }
        }
        Ok(proof.proven)
    }

    /// The chaining values this object's tree holds at the given spans.
    ///
    /// The cheap half of the descent (§3.3): a donor that is in the CAS carries
    /// an outboard, so asking whether it agrees with the new version about a
    /// 16 MiB span is two positional reads and a comparison rather than 16 MiB
    /// of hashing. Each span is `(first group, width in groups)`, and a `None`
    /// answer means the donor cannot speak to it — the span is not whole in
    /// this object, is not aligned to its tree, or is not held here.
    pub fn subtree_cvs(&self, root: &Hash, spans: &[(u64, u64)]) -> Result<Vec<Option<Cv>>> {
        let mut out = vec![None; spans.len()];
        let Some(blob) = self.blob(root)? else {
            return Ok(out);
        };
        let groups = group_count(blob.size);
        if groups <= 1 {
            return Ok(out);
        }
        let held = blob.verified_groups();
        let tree = Self::tree(blob.size);
        let outboard = PreOrderOutboard {
            root: blake3::Hash::from_bytes(root.0),
            tree,
            data: DataFile(File::open(self.outboard_path(root))?),
        };
        for (index, &(start, span)) in spans.iter().enumerate() {
            if span == 0 || !span.is_power_of_two() || start % span != 0 {
                continue;
            }
            let whole = start
                .checked_add(span)
                .and_then(|end| end.checked_mul(CHUNK_GROUP_SIZE))
                .is_some_and(|end| end <= blob.size);
            if !whole || !held.covers(start, start + span) {
                continue;
            }
            out[index] = cv_at(root, &outboard, groups, start, span)?;
        }
        Ok(out)
    }

    // ---- promotion --------------------------------------------------------

    /// Commits the donor's bytes for every proven subtree they turn out to
    /// match (§3.4).
    ///
    /// For each subtree, the donor's bytes at the same offsets are read, hashed
    /// at their place in the *new* object's tree, and compared with the
    /// chaining value a proof established. Only on a match are the bytes
    /// committed: payload, interior tree nodes, and the bitmap bit, in that
    /// order and fsynced before the bitmap advances — the same discipline as
    /// [`Store::write_slice`](crate::Store::write_slice), so a torn pass
    /// resumes instead of restarting.
    ///
    /// The re-hash is not ceremony. It closes the gap between "the donor's
    /// outboard said these bytes were right" and "the bytes on the disk still
    /// are": a donor whose payload rotted under a correct outboard fails here,
    /// and its groups fall through to the network fetch.
    ///
    /// Returns the groups newly committed.
    pub fn promote(
        &self,
        root: &Hash,
        size: u64,
        donor: &Donor,
        proven: &[ProvenSubtree],
        now: i64,
    ) -> Result<ChunkRanges> {
        let groups = group_count(size);
        // Inline blobs never delta (§4): one group is smaller than the round
        // trip that would discover it could be reused.
        if size <= INLINE_BLOB_MAX || proven.is_empty() {
            return Ok(ChunkRanges::empty());
        }
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
        let held = existing
            .as_ref()
            .map(|row| row.verified_groups())
            .unwrap_or_else(ChunkRanges::empty);
        let Some(donor) = self.open_donor(donor)? else {
            return Ok(ChunkRanges::empty());
        };

        let tree = Self::tree(size);
        let (payload, outboard_file) = self.open_sparse(root, size, tree)?;
        let mut payload = DataFile(payload);
        let mut outboard = PreOrderOutboard {
            root: blake3::Hash::from_bytes(root.0),
            tree,
            data: DataFile(outboard_file),
        };

        let mut promoted = ChunkRanges::empty();
        for subtree in proven {
            let Some(node) = Subtree::locate(&tree, groups, subtree.start, subtree.groups) else {
                // Not a subtree of this object: a caller mixing up two objects'
                // proofs, which is a bug rather than an attack, but either way
                // there is nothing here to promote into.
                continue;
            };
            // A subtree that overlaps groups this node has already verified is
            // left alone entirely. Writing donor bytes over a verified group to
            // find out whether they were right would risk the one thing the
            // bitmap promises, and the groups around it come back around at the
            // leaf level anyway.
            if held.overlaps(subtree.start, subtree.end()) {
                continue;
            }
            let (_, end_byte) = node.byte_range(size);
            if end_byte > donor.size || !donor.held.covers(subtree.start, subtree.end()) {
                continue;
            }

            let mut nodes = Vec::new();
            let cv = match self.absorb_subtree(&donor, &mut payload, size, node, &mut nodes) {
                Ok(cv) => cv,
                // A donor that cannot be read where it said it could is not an
                // error in the fetch, just a donor with nothing to give here.
                Err(StoreError::Io(_)) => continue,
                Err(e) => return Err(e),
            };
            if cv != subtree.cv {
                continue;
            }
            for (node, pair) in nodes {
                let left = blake3::Hash::from_bytes(pair[..32].try_into().expect("32 of 64"));
                let right = blake3::Hash::from_bytes(pair[32..].try_into().expect("32 of 64"));
                outboard.save(node, &(left, right))?;
            }
            promoted = promoted.union(&ChunkRanges::from_ranges([subtree.range()]));
        }

        if promoted.is_empty() {
            return Ok(promoted);
        }
        // Bytes and tree to stable storage first, the claim that they are there
        // second: a crash between the two costs a re-promotion, the other order
        // would cost an index that lies (§6.2).
        payload.flush()?;
        outboard.sync()?;
        let _ = fsync_file(&payload.0);
        let _ = fsync_file(&outboard.data.0);
        let verified = held.union(&promoted);
        let complete = verified.count() >= groups;
        self.write_blob_row(
            root,
            size,
            complete,
            (!complete).then(|| ranges_to_bitmap(&verified, groups)),
            None,
            now,
        )?;
        Ok(promoted)
    }

    /// Reads one subtree out of a donor, writing it into the object's payload
    /// and computing its chaining value and interior nodes on the way.
    ///
    /// Group by group, so a 16 MiB span costs 16 KiB of memory; depth-first, so
    /// the interior nodes come out in the order the outboard wants them. The
    /// nodes are handed back rather than saved because none of this is trusted
    /// until the chaining value at the top of it matches.
    fn absorb_subtree(
        &self,
        donor: &OpenDonor,
        payload: &mut DataFile,
        size: u64,
        node: Subtree,
        nodes: &mut Vec<(TreeNode, [u8; PROOF_NODE_LEN])>,
    ) -> Result<Cv> {
        if node.groups == 1 {
            let (start, end) = node.byte_range(size);
            let mut buffer = vec![0u8; (end - start) as usize];
            donor.bytes.read_exact_at(start, &mut buffer)?;
            payload.write_all_at(start, &buffer)?;
            return Ok(group_cv(start, &buffer));
        }
        let (left, right) = node
            .children()
            .ok_or_else(|| StoreError::invalid("a multi-group subtree has no children"))?;
        let left_cv = self.absorb_subtree(donor, payload, size, left, nodes)?;
        let right_cv = self.absorb_subtree(donor, payload, size, right, nodes)?;
        let mut pair = [0u8; PROOF_NODE_LEN];
        pair[..32].copy_from_slice(left_cv.as_bytes());
        pair[32..].copy_from_slice(right_cv.as_bytes());
        nodes.push((node.node, pair));
        Ok(join_cvs(&left_cv, &right_cv))
    }

    /// Opens a donor for reading, or reports that it has nothing to offer.
    fn open_donor(&self, donor: &Donor) -> Result<Option<OpenDonor>> {
        match donor {
            Donor::Object(root) => {
                let Some(row) = self.blob(root)? else {
                    return Ok(None);
                };
                let held = row.verified_groups();
                if held.is_empty() {
                    return Ok(None);
                }
                let bytes = match &row.inline {
                    Some(data) => DonorBytes::Inline(data.clone()),
                    None => match File::open(self.blob_path(root)) {
                        Ok(file) => DonorBytes::OnDisk(file),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                        Err(e) => return Err(e.into()),
                    },
                };
                Ok(Some(OpenDonor {
                    bytes,
                    held,
                    size: row.size,
                }))
            }
            Donor::File(path) => {
                let file = match File::open(path) {
                    Ok(file) => file,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(e.into()),
                };
                let size = file.metadata()?.len();
                Ok(Some(OpenDonor {
                    bytes: DonorBytes::OnDisk(file),
                    held: ChunkRanges::single(0, group_count(size)),
                    size,
                }))
            }
        }
    }

    /// Opens (creating if need be) the sparse payload and outboard of an object
    /// this node is accumulating.
    fn open_sparse(&self, root: &Hash, size: u64, tree: BaoTree) -> Result<(File, File)> {
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
        let outboard = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.outboard_path(root))?;
        outboard.set_len(tree.outboard_size())?;
        Ok((payload, outboard))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One chunk group, the unit everything here is counted in.
    const GROUP: usize = CHUNK_GROUP_SIZE as usize;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).unwrap();
        (dir, s)
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 + 7) as u8).collect()
    }

    /// Recomputes a subtree's chaining value and every interior pair under it
    /// straight from the bytes — the receiving side's arithmetic, with none of
    /// the store's plumbing in the way.
    fn recompute(
        bytes: &[u8],
        node: Subtree,
        out: &mut Vec<(TreeNode, [u8; PROOF_NODE_LEN])>,
    ) -> Cv {
        let size = bytes.len() as u64;
        if node.groups == 1 {
            let (start, end) = node.byte_range(size);
            return group_cv(start, &bytes[start as usize..end as usize]);
        }
        let (left, right) = node.children().unwrap();
        let left_cv = recompute(bytes, left, out);
        let right_cv = recompute(bytes, right, out);
        let mut pair = [0u8; PROOF_NODE_LEN];
        pair[..32].copy_from_slice(left_cv.as_bytes());
        pair[32..].copy_from_slice(right_cv.as_bytes());
        out.push((node.node, pair));
        join_cvs(&left_cv, &right_cv)
    }

    fn outboard_of(store: &Store, root: &Hash, size: u64) -> PreOrderOutboard<DataFile> {
        PreOrderOutboard {
            root: blake3::Hash::from_bytes(root.0),
            tree: Store::tree(size),
            data: DataFile(File::open(store.outboard_path(root)).unwrap()),
        }
    }

    /// The foundation everything else here stands on: our idea of the tree —
    /// which groups pair with which, which node of the outboard holds the
    /// result, where the right edge collapses — is bao's idea of it, node for
    /// node, for objects whose sizes land on every awkward boundary.
    #[test]
    fn our_tree_math_agrees_with_the_outboard_bao_wrote() {
        let (_d, store) = store();
        for groups_and_change in [
            2 * GROUP,
            3 * GROUP,
            4 * GROUP,
            5 * GROUP + 1,
            8 * GROUP,
            9 * GROUP - 5,
            20 * GROUP,
            33 * GROUP + 100,
        ] {
            let bytes = data(groups_and_change);
            let size = bytes.len() as u64;
            let root = store.ingest_bytes(&bytes, 0).unwrap();
            let tree = Store::tree(size);
            let outboard = outboard_of(&store, &root, size);

            let mut nodes = Vec::new();
            let top = Subtree::root_of(&tree, group_count(size));
            recompute(&bytes, top, &mut nodes);
            assert_eq!(
                nodes.len(),
                group_count(size) as usize - 1,
                "a tree of n groups has n-1 interior nodes ({size} bytes)"
            );
            for (node, pair) in &nodes {
                let theirs = load_from_outboard(&outboard, &root, node).unwrap();
                assert_eq!(
                    &theirs, pair,
                    "node {node} of a {size}-byte object disagrees"
                );
            }
            // And the top pair, root-finalized, is the address itself.
            let (_, top_pair) = nodes.last().unwrap();
            let left = Cv(top_pair[..32].try_into().unwrap());
            let right = Cv(top_pair[32..].try_into().unwrap());
            assert_eq!(join_root(&left, &right), root, "{size} bytes");
        }
    }

    /// A leaf-level proof of a whole object is that object's whole tree: what
    /// lands on the receiving side is byte for byte the outboard bao wrote.
    #[test]
    fn a_leaf_proof_round_trips_into_the_same_outboard() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let bytes = data(9 * GROUP + 7);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let all = ChunkRanges::single(0, group_count(size));

        let (encoded, served) = provider.encode_proof(&root, &all, 0).unwrap();
        assert_eq!(served, all);
        let proven = fetcher
            .write_proof(&root, size, &served, 0, &encoded, 0)
            .unwrap();

        assert_eq!(proven.len(), group_count(size) as usize);
        for subtree in &proven {
            assert_eq!(subtree.groups, 1);
            let start = subtree.start as usize * GROUP;
            let end = (start + GROUP).min(bytes.len());
            assert_eq!(subtree.cv, group_cv(start as u64, &bytes[start..end]));
            // The last group is short, so it is not a whole subtree.
            assert_eq!(subtree.whole, end - start == GROUP);
        }
        assert_eq!(
            std::fs::read(fetcher.outboard_path(&root)).unwrap(),
            std::fs::read(provider.outboard_path(&root)).unwrap(),
            "the proof carried the entire tree, so the two outboards are equal"
        );
        // A proof commits no bytes: the object is known, and held not at all.
        let row = fetcher.blob(&root).unwrap().unwrap();
        assert!(!row.complete);
        assert!(row.verified_groups().is_empty());
    }

    /// A span-level proof costs a fraction of a leaf-level one and still ties
    /// every span it names to the root.
    #[test]
    fn a_span_level_proof_names_one_subtree_per_span() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let bytes = data(20 * GROUP);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let all = ChunkRanges::single(0, group_count(size));

        // Spans of four groups: five of them, and the tree above them.
        let (encoded, served) = provider.encode_proof(&root, &all, 2).unwrap();
        assert_eq!(served, all);
        let (leaf_encoded, _) = provider.encode_proof(&root, &all, 0).unwrap();
        assert!(
            encoded.len() * 3 < leaf_encoded.len(),
            "a span proof is much cheaper than a leaf proof: {} vs {}",
            encoded.len(),
            leaf_encoded.len()
        );

        let proven = fetcher
            .write_proof(&root, size, &served, 2, &encoded, 0)
            .unwrap();
        assert_eq!(proven.len(), 5);
        for (index, subtree) in proven.iter().enumerate() {
            assert_eq!(subtree.start, index as u64 * 4);
            assert_eq!(subtree.groups, 4);
            assert!(subtree.whole);
        }
    }

    /// The property the whole design rests on, end to end: two objects of
    /// different sizes agree, span for span, wherever their bytes agree — and a
    /// span whose bytes changed is the only one that disagrees.
    #[test]
    fn equal_spans_are_proven_equal_across_unequal_sizes() {
        let (_d, store) = store();
        let old = data(16 * GROUP);
        // The new version appends four groups and rewrites one in the middle.
        let mut new = old.clone();
        new.extend(data(4 * GROUP));
        new[9 * GROUP + 100] ^= 0xff;

        let old_root = store.ingest_bytes(&old, 0).unwrap();
        let (_d2, holder) = self::store();
        let new_root = holder.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;

        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = holder.encode_proof(&new_root, &all, 2).unwrap();
        let proven = store
            .write_proof(&new_root, size, &served, 2, &encoded, 0)
            .unwrap();

        let spans: Vec<(u64, u64)> = proven.iter().map(|s| (s.start, s.groups)).collect();
        let donor_cvs = store.subtree_cvs(&old_root, &spans).unwrap();
        let equal: Vec<u64> = proven
            .iter()
            .zip(&donor_cvs)
            .filter(|(subtree, cv)| **cv == Some(subtree.cv))
            .map(|(subtree, _)| subtree.start)
            .collect();
        assert_eq!(
            equal,
            vec![0, 4, 12],
            "every span but the edited one and the appended tail is reused"
        );
        // The appended spans lie past the donor's end, so it cannot speak to
        // them at all rather than answering wrongly.
        assert_eq!(donor_cvs[4], None);
    }

    /// The whole flow at store level: prove, compare, promote, and fetch only
    /// what is left.
    #[test]
    fn a_donor_supplies_every_group_that_did_not_change() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let old = data(12 * GROUP + 500);
        let mut new = old.clone();
        new[5 * GROUP + 3] ^= 0xff;
        let old_root = fetcher.ingest_bytes(&old, 0).unwrap();
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;
        let groups = group_count(size);

        let all = ChunkRanges::single(0, groups);
        let (encoded, served) = provider.encode_proof(&new_root, &all, 0).unwrap();
        let proven = fetcher
            .write_proof(&new_root, size, &served, 0, &encoded, 0)
            .unwrap();
        let promoted = fetcher
            .promote(&new_root, size, &Donor::Object(old_root), &proven, 0)
            .unwrap();

        assert_eq!(promoted, all.difference(&ChunkRanges::single(5, 6)));
        assert_eq!(promoted.count(), groups - 1);
        // Promoted groups are held like any others: readable, and servable,
        // because the tree came with them.
        assert_eq!(
            fetcher.read_range(&new_root, 0, 100).unwrap(),
            &new[..100],
            "a promoted group reads back verified"
        );
        let (slice, slice_served) = fetcher
            .encode_slice(&new_root, &ChunkRanges::single(0, 4))
            .unwrap();
        assert_eq!(slice_served, ChunkRanges::single(0, 4));
        assert!(!slice.is_empty());

        // What is left is exactly one group, and an ordinary slice finishes it.
        let missing = all.difference(&promoted);
        assert_eq!(missing, ChunkRanges::single(5, 6));
        let (encoded, served) = provider.encode_slice(&new_root, &missing).unwrap();
        fetcher
            .write_slice(&new_root, size, &served, &encoded, 0)
            .unwrap();
        assert!(fetcher.blob(&new_root).unwrap().unwrap().complete);
        assert_eq!(fetcher.read_all(&new_root).unwrap(), new);
    }

    /// A span promoted whole can be *served* whole, not merely held.
    ///
    /// The interior nodes under a promoted span have to land in the new
    /// object's outboard at bao's positions for that to be true, and getting
    /// those positions wrong is invisible until something asks this node for a
    /// slice — which is the moment it has advertised itself as a source and
    /// then cannot deliver (§3.4, §6.3).
    #[test]
    fn a_promoted_span_can_be_served_onward() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let (_d3, third) = store();
        let old = data(64 * GROUP);
        let mut new = old.clone();
        new[40 * GROUP + 7] ^= 0xff;
        let old_root = fetcher.ingest_bytes(&old, 0).unwrap();
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;
        let all = ChunkRanges::single(0, group_count(size));

        // Spans of sixteen groups, three of which are untouched.
        let (encoded, served) = provider.encode_proof(&new_root, &all, 4).unwrap();
        let spans = fetcher
            .write_proof(&new_root, size, &served, 4, &encoded, 0)
            .unwrap();
        assert_eq!(spans.len(), 4);
        let promoted = fetcher
            .promote(&new_root, size, &Donor::Object(old_root), &spans, 0)
            .unwrap();
        assert_eq!(promoted.count(), 48, "three whole spans: {promoted:?}");

        // A third node fetches one of those spans from the promoter and gets
        // bytes that verify against the root.
        let span = ChunkRanges::single(16, 32);
        let (encoded, served) = fetcher.encode_slice(&new_root, &span).unwrap();
        assert_eq!(served, span);
        third
            .write_slice(&new_root, size, &served, &encoded, 0)
            .unwrap();
        assert_eq!(
            third.read_range(&new_root, 16 * GROUP as u64, 100).unwrap(),
            &new[16 * GROUP..16 * GROUP + 100]
        );
        // And the promoter's own outboard is byte for byte the one bao wrote,
        // wherever the promotion filled it in.
        assert_eq!(fetcher.read_range(&new_root, 0, 100).unwrap(), &new[..100]);
    }

    /// The tail group is the one fixed-offset chunking is least kind to: it is
    /// short, it is not a whole subtree, and it still has to be reusable when
    /// it did not change.
    #[test]
    fn a_short_tail_group_is_promoted_when_it_did_not_change() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let old = data(6 * GROUP + 13);
        let mut new = old.clone();
        new[0] ^= 0xff;
        let old_root = fetcher.ingest_bytes(&old, 0).unwrap();
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;

        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider.encode_proof(&new_root, &all, 0).unwrap();
        let proven = fetcher
            .write_proof(&new_root, size, &served, 0, &encoded, 0)
            .unwrap();
        assert!(!proven.last().unwrap().whole, "the tail group is short");

        let promoted = fetcher
            .promote(&new_root, size, &Donor::Object(old_root), &proven, 0)
            .unwrap();
        assert!(
            promoted.contains(6),
            "the short tail is reusable: {promoted:?}"
        );
        assert!(!promoted.contains(0), "the changed group is not");
    }

    /// A file on disk is a donor too, with no CAS row and no outboard behind
    /// it — the case a mirror meets when the object it materialized has since
    /// been collected (§3.2.4).
    #[test]
    fn a_plain_file_can_be_the_donor() {
        let (dir, provider) = store();
        let (_d2, fetcher) = store();
        let old = data(10 * GROUP);
        let mut new = old.clone();
        new[3 * GROUP..4 * GROUP].fill(0x5a);
        let path = dir.path().join("previous.bin");
        std::fs::write(&path, &old).unwrap();
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;

        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider.encode_proof(&new_root, &all, 0).unwrap();
        let proven = fetcher
            .write_proof(&new_root, size, &served, 0, &encoded, 0)
            .unwrap();
        let promoted = fetcher
            .promote(&new_root, size, &Donor::File(path), &proven, 0)
            .unwrap();
        assert_eq!(promoted, all.difference(&ChunkRanges::single(3, 4)));
    }

    /// A donor whose payload rotted under a correct outboard is caught by the
    /// re-hash at promotion time, and only the rotted groups are lost.
    ///
    /// This is the difference between believing a donor's tree and believing
    /// its bytes. The donor's outboard is perfectly consistent — it was written
    /// by an honest ingest — and the group it describes is no longer what is on
    /// the disk. Nothing but hashing the bytes again would notice.
    #[test]
    fn rotted_donor_bytes_are_refused_and_left_to_the_fetch() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let old = data(8 * GROUP);
        let mut new = old.clone();
        new[7 * GROUP..].fill(0x11);
        let old_root = fetcher.ingest_bytes(&old, 0).unwrap();
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;

        // A bit flips in the donor's payload, behind the store's back.
        let mut raw = std::fs::read(fetcher.blob_path(&old_root)).unwrap();
        raw[2 * GROUP + 9] ^= 0xff;
        std::fs::write(fetcher.blob_path(&old_root), &raw).unwrap();

        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider.encode_proof(&new_root, &all, 0).unwrap();
        let proven = fetcher
            .write_proof(&new_root, size, &served, 0, &encoded, 0)
            .unwrap();
        let promoted = fetcher
            .promote(&new_root, size, &Donor::Object(old_root), &proven, 0)
            .unwrap();

        assert!(!promoted.contains(2), "the rotted group is refused");
        assert!(
            !promoted.contains(7),
            "the changed group has nothing to give"
        );
        assert_eq!(
            promoted.count(),
            6,
            "the other six are promoted: {promoted:?}"
        );
        // Rot is per-extent: the donor keeps supplying the groups it still has
        // right, and what it lost goes back to the network.
        assert_eq!(fetcher.read_range(&new_root, 0, 10).unwrap(), &new[..10]);
        let missing = all.difference(&promoted);
        let (encoded, served) = provider.encode_slice(&new_root, &missing).unwrap();
        fetcher
            .write_slice(&new_root, size, &served, &encoded, 0)
            .unwrap();
        assert_eq!(fetcher.read_all(&new_root).unwrap(), new);
    }

    /// A tampered proof is rejected whole, and commits nothing.
    #[test]
    fn a_tampered_proof_is_rejected() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let bytes = data(9 * GROUP);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let all = ChunkRanges::single(0, group_count(size));

        let (encoded, served) = provider.encode_proof(&root, &all, 0).unwrap();
        for flip in [0usize, 63, 64, encoded.len() - 1] {
            let mut tampered = encoded.clone();
            tampered[flip] ^= 0xff;
            assert!(
                matches!(
                    fetcher.write_proof(&root, size, &served, 0, &tampered, 0),
                    Err(StoreError::Verification { .. })
                ),
                "a flip at byte {flip} was accepted"
            );
        }
        // Truncated and padded proofs are refused too: the walk and the bytes
        // have to account for each other exactly.
        assert!(fetcher
            .write_proof(&root, size, &served, 0, &encoded[..encoded.len() - 64], 0)
            .is_err());
        let mut padded = encoded.clone();
        padded.extend_from_slice(&[0u8; 64]);
        assert!(fetcher
            .write_proof(&root, size, &served, 0, &padded, 0)
            .is_err());
        // A proof for the wrong root fails at the very first node.
        assert!(fetcher
            .write_proof(&Hash::new(b"elsewhere"), size, &served, 0, &encoded, 0)
            .is_err());
        assert!(
            fetcher.blob(&root).unwrap().is_none(),
            "nothing was written"
        );
    }

    /// A proof is clamped to one window like a slice, and `served` is where the
    /// next request starts.
    #[test]
    fn a_proof_is_clamped_to_one_window() {
        let (_d, provider) = store();
        let bytes = data(40 * GROUP);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let all = ChunkRanges::single(0, group_count(size));

        // A budget far below what a leaf-level proof of the whole object needs.
        let (encoded, served) = provider.encode_proof_bounded(&root, &all, 0, 12).unwrap();
        assert!(!served.is_empty());
        assert!(served != all, "the window is short of the request");
        assert!(encoded.len() as u64 <= 12 * PROOF_NODE_LEN as u64);

        // And what it did serve verifies on its own.
        let (_d2, fetcher) = store();
        let proven = fetcher
            .write_proof(&root, size, &served, 0, &encoded, 0)
            .unwrap();
        assert!(!proven.is_empty());

        // The next window picks up exactly where this one stopped.
        let rest = all.difference(&served);
        let (_, next) = provider.encode_proof_bounded(&root, &rest, 0, 12).unwrap();
        assert_eq!(next.ranges[0].start, served.ranges[0].end);
    }

    /// A partial holder can serve proofs for what it has, and says so.
    #[test]
    fn a_partial_holder_proves_only_the_groups_it_holds() {
        let (_d1, provider) = store();
        let (_d2, partial) = store();
        let bytes = data(16 * GROUP);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();

        let half = ChunkRanges::single(0, 8);
        let (encoded, served) = provider.encode_slice(&root, &half).unwrap();
        partial
            .write_slice(&root, size, &served, &encoded, 0)
            .unwrap();

        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = partial.encode_proof(&root, &all, 0).unwrap();
        assert_eq!(served, half);
        // What it served is a proof against the same root, from a node that
        // holds half the object.
        let (_d3, fetcher) = store();
        let proven = fetcher
            .write_proof(&root, size, &served, 0, &encoded, 0)
            .unwrap();
        assert_eq!(proven.len(), 8);
    }

    /// Objects too small to have a tree have nothing to prove, and say so
    /// without failing.
    #[test]
    fn tiny_objects_have_nothing_to_prove() {
        let (_d, store) = store();
        for size in [0usize, 1, 100, GROUP] {
            let bytes = data(size);
            let root = store.ingest_bytes(&bytes, 0).unwrap();
            let all = ChunkRanges::single(0, group_count(bytes.len() as u64));
            let (encoded, served) = store.encode_proof(&root, &all, 0).unwrap();
            assert!(encoded.is_empty(), "{size} bytes");
            assert_eq!(served, all, "{size} bytes");
            // And promoting into one is a no-op rather than an error: inline
            // blobs never delta (§4).
            let promoted = store
                .promote(&root, bytes.len() as u64, &Donor::Object(root), &[], 0)
                .unwrap();
            assert!(promoted.is_empty());
        }
    }
}
