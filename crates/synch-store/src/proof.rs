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
//! Nothing here trusts anyone *else*. A proof is verified by recomputation from
//! the root the caller already trusts (§5.1's rule that no byte is believed
//! because of who supplied it, applied to hashes), and a *donor* — another
//! object in this node's CAS whose bytes may belong in the new one — supplies a
//! run only where its own tree agrees, chaining value for chaining value, with
//! what the proof established. Equal chaining values are equal bytes; a stale
//! donor simply matches nothing.
//!
//! What this deliberately does not do is read a donor's payload back to check
//! it again. Verification happens at the trust boundary — a slice off the
//! network, a proof, a file being ingested — and bytes already committed under
//! a verified bitmap are trusted at rest, which is the posture the rest of the
//! design takes towards the filesystem it sits on (§6.2, §10). Re-hashing
//! 100 GB of local payload to reconfirm what was confirmed when it was written
//! would make every delta update cost the size of the object rather than the
//! size of the change, which is the whole of what delta sync exists to avoid —
//! and it would duplicate, badly, what a checksumming filesystem already does.

use std::fs::{File, OpenOptions};

use bao_tree::{
    io::{
        outboard::PreOrderOutboard,
        sync::{Outboard, OutboardMut, ReadAt, WriteAt},
    },
    BaoTree, TreeNode,
};
use synch_core::{
    group_count, join_cvs, join_root, ChunkRanges, Cv, GroupRange, Hash, CHUNK_GROUP_SIZE,
    INLINE_BLOB_MAX, MAX_PROOF_NODES, PROOF_NODE_LEN,
};

use crate::{
    cas::{fsync_file, DataFile},
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

/// What proof rounds established about one object.
///
/// The root and the size travel with the subtrees, and that is the whole reason
/// this type exists. A chaining value means nothing except against the tree it
/// was proved in, and a bare list of subtrees carries nothing that would stop it
/// being spent on the wrong tree:
///
/// - **The root.** Two objects of the same size have the same tree *shape*, so
///   every positional check a promotion makes would pass for another object's
///   proof just as readily as for the right one's — and what would come out is
///   an object filled with a stranger's bytes and marked complete.
/// - **The size.** One object has the same tree shape at every size inside its
///   last chunk group, and a *shorter* size makes a subtree that is really cut
///   short by the end of the object look whole. A legitimate proof of a 20-span
///   object, taken under a size four spans short of it, names sixteen spans this
///   object does not end after — promote them and the row is complete at 80% of
///   its length: unreadable, and refusing every honest writer of the rest.
///
/// [`Store::promote`] checks both against what it was asked to fill; without
/// them in the type there is nothing there to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proven {
    /// The object root every subtree here was chained back to.
    pub root: Hash,
    /// The object size the tree was walked under. Two different sizes give two
    /// different answers to "is this subtree whole?", so a proof is only
    /// spendable on an object of the length it was proved for.
    pub size: u64,
    /// The subtrees, in tree order — one per group at level 0, one per span
    /// higher up.
    pub subtrees: Vec<ProvenSubtree>,
}

impl Proven {
    /// An empty result for an object.
    pub fn none(root: Hash, size: u64) -> Proven {
        Proven {
            root,
            size,
            subtrees: Vec::new(),
        }
    }

    /// True if no subtree was proven.
    pub fn is_empty(&self) -> bool {
        self.subtrees.is_empty()
    }

    /// Folds another round's subtrees over the same object into this one.
    ///
    /// Refuses to mix roots or sizes: the two would be indistinguishable
    /// afterwards, which is exactly what carrying them is meant to prevent.
    pub fn absorb(&mut self, other: Proven) -> Result<()> {
        if other.root != self.root || other.size != self.size {
            return Err(StoreError::Verification {
                root: self.root,
                reason: format!(
                    "a proof of {} at {} bytes cannot join a proof of this object at {} bytes",
                    other.root, other.size, self.size
                ),
            });
        }
        self.subtrees.extend(other.subtrees);
        Ok(())
    }
}

/// A local source of candidate bytes for an object (§3.2).
///
/// Always another object in this node's CAS, read from its payload at the same
/// byte offsets — typically the entry's `prev` root, or another version of the
/// same path (§4.2, §8). Donors are hints about where bytes might be found,
/// never authority about what they are: a run is promoted only where the
/// donor's own tree gives it the chaining value a proof chained to the new
/// object's root.
///
/// One shape of donor, deliberately. A mirror whose file on disk *is* a version
/// the CAS has since collected re-ingests that file rather than being offered
/// here as a second kind of donor: the capability is preserved, the rare path
/// pays for it, and nothing inside this module has to know that a donor might
/// have no tree (`docs/DELTA-SYNC.md` §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Donor(pub Hash);

impl Donor {
    /// The object root the donor supplies bytes for.
    pub fn root(&self) -> Hash {
        self.0
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
    /// Finds the subtree covering `[start, start + groups)` by descending.
    ///
    /// `promote` calls this once per proven span because [`ProvenSubtree`]
    /// carries only `(start, groups)` and not the `TreeNode` the walk that
    /// produced it already held — so the descent recomputes a value that was in
    /// hand a moment earlier.
    ///
    /// It stays a descent deliberately. A whole subtree is aligned and a power
    /// of two wide, so its node index is `start | ((1 << level) - 1)` and could
    /// be built in constant time — but `bao_tree::TreeNode` wraps a private
    /// field with no public constructor (0.16 keeps `from_start_chunk_and_level`
    /// behind `cfg(test)`), so that identity cannot be expressed from here.
    /// Carrying the node in `ProvenSubtree` instead would leak `TreeNode`
    /// through `synch-store`'s public API into `synch-engine`, and keeping it
    /// in a private side-table parallel to the public `Vec` buys a desync
    /// hazard. The descent is `O(log groups)` of integer arithmetic — tens of
    /// operations per span — so all three of those cost more than they save.
    /// The real fix is the seam: were the proof walk to live behind a narrower
    /// interface, the node would simply travel with its subtree.
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

/// A donor opened for reading: its payload, its tree, and what it holds.
struct OpenDonor {
    /// The donor object's root, for the errors its tree can raise.
    root: Hash,
    /// Its payload, read positionally and cloned range by range.
    payload: File,
    /// Its tree, which is what makes a donor cheap to ask about: a 16 MiB span
    /// costs two positional reads to compare rather than 16 MiB of hashing.
    outboard: PreOrderOutboard<DataFile>,
    /// The groups the donor is known to hold, out of its bitmap.
    held: ChunkRanges,
    /// How long the donor is, which bounds what can be read out of it.
    size: u64,
    /// Its group count, which fixes the shape of its tree.
    groups: u64,
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
    ) -> Result<Proven> {
        let groups = group_count(size);
        let served = served.intersect(&ChunkRanges::single(0, groups));
        if let Some(row) = self.blob(root)? {
            // The cheap refusal; `commit_groups` makes the same decision again
            // inside the transaction that records it (`settle_size`).
            let held = row.verified_groups();
            crate::cas::settle_size(root, Some((row.size, row.complete, &held)), size)?;
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
            // The outboard only. A proof commits no bytes, so it has no
            // business creating a payload file the size of an object this node
            // holds nothing of — that file is the business of whatever first
            // puts a byte in it.
            let mut outboard = PreOrderOutboard {
                root: blake3::Hash::from_bytes(root.0),
                tree,
                data: DataFile(self.open_sparse_outboard(root, tree)?),
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
            // is recorded as held-nothing rather than not held at all — and the
            // recording is a union of nothing, so a fetch that raced this proof
            // into the same root does not have its groups erased by it.
            //
            // The size in that row is a claim off an entry, not something this
            // proof established: an object's tree is the same shape for every
            // size inside its last 16 KiB chunk group, so a peer can overstate a
            // root by a few bytes and have the proof verify anyway. Nothing
            // durable may rest on it, which is what `settle_size` is for — until
            // the final group is held, the next writer's size wins, and the
            // decision is made inside the transaction that records it so that
            // two writers cannot each decide it on a stale snapshot.
            self.commit_groups(root, size, &ChunkRanges::empty(), None, now)?;
        }
        Ok(Proven {
            root: *root,
            size,
            subtrees: proof.proven,
        })
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

    /// Commits the donor's bytes for every proven subtree its tree turns out to
    /// agree with (§3.4).
    ///
    /// For each subtree, the chaining value the donor's own outboard holds at
    /// the same position is compared with the chaining value a proof chained to
    /// the new object's root. Equal chaining values are equal bytes, so on a
    /// match the run is copied straight across — payload, interior tree nodes,
    /// and the bitmap bit, in that order and fsynced before the bitmap advances,
    /// the same discipline as [`Store::write_slice`](crate::Store::write_slice)
    /// so a torn pass resumes instead of restarting.
    ///
    /// Two positional reads per span, and a copy the kernel may not even have to
    /// perform: this is what makes an update cost the size of its change rather
    /// than the size of the object. The donor's bytes are not read back and
    /// re-hashed — they were verified when they entered the CAS, and the module
    /// header says why that is where the checking belongs.
    ///
    /// Two shapes of subtree are promotable, and between them they cover
    /// everything the descent produces: a whole subtree, whose chaining value is
    /// comparable across objects at all (§3.3), and a single group, which is
    /// comparable whenever both objects run the same distance past its start.
    /// A multi-group subtree cut short by the end of the object is neither, and
    /// is left to the leaf-level round that follows it.
    ///
    /// Returns the groups newly committed.
    pub fn promote(&self, donor: &Donor, proven: &Proven, now: i64) -> Result<ChunkRanges> {
        // The object and its length come off the proof itself.
        //
        // They used to be passed alongside it and checked for agreement, and
        // `DELTA-SYNC.md` §3.1 presented that as a security property. It was
        // not one: tracing every construction site, `write_proof` builds
        // `Proven` from its own arguments and `Proven::none` from the caller's
        // locals, and `promote` was then handed those same locals again — no
        // peer-supplied value ever reached `proven.root` or `proven.size`
        // independently of what the caller already had. The check could only
        // ever catch a caller mixing up two objects, which is what taking the
        // values from one place makes unrepresentable instead.
        //
        // The real protection is elsewhere and unaffected: `walk_proof`
        // recomputes every chaining value to the root, so a proof of another
        // object cannot verify in the first place.
        let root = &proven.root;
        let size = proven.size;
        let groups = group_count(size);
        // Inline blobs never delta (§4): one group is smaller than the round
        // trip that would discover it could be reused.
        if size <= INLINE_BLOB_MAX || proven.is_empty() {
            return Ok(ChunkRanges::empty());
        }
        let existing = self.blob(root)?;
        let mut held = ChunkRanges::empty();
        if let Some(row) = &existing {
            held = row.verified_groups();
            // The cheap refusal; `commit_groups` decides again inside the
            // transaction that records the result (`settle_size`).
            crate::cas::settle_size(root, Some((row.size, row.complete, &held)), size)?;
            if row.complete {
                return Ok(ChunkRanges::empty());
            }
        }
        let Some(donor) = self.open_donor(donor)? else {
            return Ok(ChunkRanges::empty());
        };

        let tree = Self::tree(size);
        // The payload and the outboard are opened on the first run that matches,
        // and not before. A donor with nothing to give is the common case — the
        // descent offers every version of the path in turn and most of them
        // agree about nothing — and opening up front left each of them a
        // full-size sparse payload behind: no data, but an inode and a length,
        // for an object this node may never fetch a byte of.
        let mut sink: Option<Sink> = None;

        let mut promoted = ChunkRanges::empty();
        for subtree in &proven.subtrees {
            let Some(node) = Subtree::locate(&tree, groups, subtree.start, subtree.groups) else {
                // Not a subtree of this object: a caller mixing up two objects'
                // proofs, which is a bug rather than an attack, but either way
                // there is nothing here to promote into.
                continue;
            };
            // A subtree that overlaps groups this node has already verified is
            // left alone entirely. Copying donor bytes over a verified group
            // would risk the one thing the bitmap promises, and the groups
            // around it come back around at the leaf level anyway.
            if held.overlaps(subtree.start, subtree.end()) {
                continue;
            }
            if node.groups > 1 && !node.is_whole(size) {
                continue;
            }
            let (start_byte, end_byte) = node.byte_range(size);
            if end_byte > donor.size || !donor.held.covers(subtree.start, subtree.end()) {
                continue;
            }
            // The donor's own word for this run, out of the tree it was given
            // when its bytes were verified into the CAS. `None` means it cannot
            // speak to the position at all — its tree is shaped differently
            // there, or the run is the whole of it and so has no chaining value
            // (§2); a value that differs means the bytes differ.
            let donor_cv = match cv_at(
                &donor.root,
                &donor.outboard,
                donor.groups,
                node.start,
                node.span,
            ) {
                Ok(Some(cv)) => cv,
                Ok(None) => continue,
                // A donor whose tree cannot be read where it said it could is
                // not an error in the fetch, just a donor with nothing to give.
                Err(e) => {
                    tracing::debug!(donor = %donor.root, error = %e, "donor tree unreadable");
                    continue;
                }
            };
            if donor_cv != subtree.cv {
                continue;
            }

            // Everything from here on writes, and everything that decides
            // *whether* to write is above: the comparison happens strictly
            // before a byte of this run lands in the payload. Judging after
            // writing — as an earlier shape of this did — means a run that
            // turns out not to match has already overwritten whatever was at
            // those offsets, and a group another writer had just verified into
            // the bitmap becomes a bit that lies (§6.2).

            // The nodes *under* the run come across as well, or the groups this
            // pass gains could be held and not served (§3.4, §6.3).
            let mut nodes = Vec::new();
            if let Err(e) = copy_subtree_nodes(&donor, node, subtree.cv, &mut nodes) {
                tracing::debug!(donor = %donor.root, error = %e, "donor tree not copied");
                continue;
            }
            let sink = match &mut sink {
                Some(sink) => sink,
                slot => slot.insert(self.open_sink(root, size, tree)?),
            };
            if let Err(e) = copy_run(&donor.payload, &mut sink.payload, start_byte, end_byte) {
                tracing::debug!(donor = %donor.root, error = %e, "donor payload not copied");
                continue;
            }
            for (node, pair) in nodes {
                let left = blake3::Hash::from_bytes(pair[..32].try_into().expect("32 of 64"));
                let right = blake3::Hash::from_bytes(pair[32..].try_into().expect("32 of 64"));
                sink.outboard.save(node, &(left, right))?;
            }
            promoted = promoted.union(&ChunkRanges::from_ranges([subtree.range()]));
        }

        let Some(mut sink) = sink.filter(|_| !promoted.is_empty()) else {
            return Ok(ChunkRanges::empty());
        };
        // Bytes and tree to stable storage first, the claim that they are there
        // second: a crash between the two costs a re-promotion, the other order
        // would cost an index that lies (§6.2).
        sink.payload.flush()?;
        sink.outboard.sync()?;
        let _ = fsync_file(&sink.payload.0);
        let _ = fsync_file(&sink.outboard.data.0);
        let commit = self.commit_groups(root, size, &promoted, None, now)?;
        drop(sink);
        self.trim_to_size(root, commit);
        Ok(promoted)
    }

    /// Opens a donor for reading, or reports that it has nothing to offer.
    ///
    /// An inline blob is turned away here rather than special-cased later: a
    /// blob that fits in the index is a single chunk group, and a single group's
    /// only hash is its object's root, which carries BLAKE3's root flag and can
    /// therefore equal no chaining value of anything (§2). It could never match,
    /// so it is never opened.
    fn open_donor(&self, donor: &Donor) -> Result<Option<OpenDonor>> {
        let root = donor.root();
        let Some(row) = self.blob(&root)? else {
            return Ok(None);
        };
        let held = row.verified_groups();
        let groups = group_count(row.size);
        if held.is_empty() || row.inline.is_some() || groups <= 1 {
            return Ok(None);
        }
        let (payload, outboard) = match (
            File::open(self.blob_path(&root)),
            File::open(self.outboard_path(&root)),
        ) {
            (Ok(payload), Ok(outboard)) => (payload, outboard),
            // A donor the GC took between the plan and the promotion is a donor
            // with nothing to give, not a failure of the fetch.
            _ => return Ok(None),
        };
        Ok(Some(OpenDonor {
            root,
            payload,
            outboard: PreOrderOutboard {
                root: blake3::Hash::from_bytes(root.0),
                tree: Self::tree(row.size),
                data: DataFile(outboard),
            },
            held,
            size: row.size,
            groups,
        }))
    }

    /// Opens (creating if need be) the sparse payload and outboard of an object
    /// this node is accumulating.
    ///
    /// `size` is still a claim here, so the files are only ever grown to fit it
    /// ([`Store::trim_to_size`] is the one place either is made smaller, after a
    /// commit that settled the length).
    fn open_sink(&self, root: &Hash, size: u64, tree: BaoTree) -> Result<Sink> {
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
        crate::cas::grow_to(&payload, size)?;
        Ok(Sink {
            payload: DataFile(payload),
            outboard: PreOrderOutboard {
                root: blake3::Hash::from_bytes(root.0),
                tree,
                data: DataFile(self.open_sparse_outboard(root, tree)?),
            },
        })
    }

    /// Opens (creating if need be) just the sparse outboard, for a proof that
    /// has a tree to record and no bytes to put under it.
    fn open_sparse_outboard(&self, root: &Hash, tree: BaoTree) -> Result<File> {
        let path = self.outboard_path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let outboard = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        crate::cas::grow_to(&outboard, tree.outboard_size())?;
        Ok(outboard)
    }
}

/// The files a promotion writes into: the object's sparse payload and its
/// sparse outboard, opened together on the first run that matched.
struct Sink {
    payload: DataFile,
    outboard: PreOrderOutboard<DataFile>,
}

/// Copies a whole subtree's interior nodes out of a donor's tree, checking on
/// the way up that they are the tree the proof proved.
///
/// The new object needs them: a span promoted without the nodes beneath it is a
/// span this node holds and cannot serve, which is the worse half of advertising
/// it (§3.4, §6.3). They are copied rather than recomputed from the payload
/// because a pair is 64 bytes per 16 KiB group — 1/256 of the bytes it describes
/// — so reading the tree is cheap where reading the object is not.
///
/// The recombination on the way back up is what keeps the copy honest: each pair
/// has to hash to the value its parent already committed to, up to the chaining
/// value the proof chained to the new object's root. A donor whose *outboard*
/// rotted therefore cannot poison a tree this node will go on to serve, and the
/// check costs one 64-byte hash per group rather than a pass over the bytes.
///
/// Only ever called for a whole subtree, whose shape — a full binary tree of
/// `span` groups at a fixed position — is the same in every object that contains
/// it, which is why the donor's nodes land at the same [`TreeNode`] here.
fn copy_subtree_nodes(
    donor: &OpenDonor,
    node: Subtree,
    expected: Cv,
    out: &mut Vec<(TreeNode, [u8; PROOF_NODE_LEN])>,
) -> Result<()> {
    if node.groups <= 1 {
        // A single group has no interior, and its chaining value came from the
        // pair its parent already contributed.
        return Ok(());
    }
    let pair = load_from_outboard(&donor.outboard, &donor.root, &node.node)?;
    let left = Cv(pair[..32].try_into().expect("32 of 64 bytes"));
    let right = Cv(pair[32..].try_into().expect("32 of 64 bytes"));
    if join_cvs(&left, &right) != expected {
        return Err(StoreError::Verification {
            root: donor.root,
            reason: format!(
                "the donor's tree at group {} does not hash to the value above it",
                node.start
            ),
        });
    }
    out.push((node.node, pair));
    let (left_child, right_child) = node
        .children()
        .ok_or_else(|| StoreError::invalid("a multi-group subtree has no children"))?;
    copy_subtree_nodes(donor, left_child, left, out)?;
    copy_subtree_nodes(donor, right_child, right, out)
}

/// How much of a run is held in memory when the kernel will not move it.
const COPY_RUN_CHUNK: u64 = 256 * 1024;

/// Copies a byte run from a donor's payload into an object's sparse payload.
///
/// `copy_file_range` first. Both files are in the CAS directory and therefore on
/// one filesystem, which is the condition under which Linux routes the call
/// through the filesystem's own remap: on btrfs, XFS and bcachefs an aligned run
/// becomes a **reflink**, so the bytes are shared rather than moved and the new
/// object costs no space wherever it agrees with the old one. A run of whole
/// 16 KiB groups at 16 KiB offsets satisfies any block size a filesystem is
/// likely to have; the short tail group of an object does not, and the kernel
/// quietly copies that instead of sharing it. Everywhere else — ext4, an old
/// kernel, a platform without the syscall — the call copies without a bounce
/// through user space, or refuses, and the loop below finishes the job by hand.
///
/// Either way the caller has already established that these bytes belong here:
/// the run's chaining value, in the donor's tree, is one a proof chained to the
/// new object's root.
fn copy_run(donor: &File, payload: &mut DataFile, start: u64, end: u64) -> std::io::Result<()> {
    let mut offset = start;
    #[cfg(target_os = "linux")]
    while offset < end {
        let mut from = offset;
        let mut to = offset;
        let len = usize::try_from(end - offset).unwrap_or(usize::MAX);
        match rustix::fs::copy_file_range(donor, Some(&mut from), &payload.0, Some(&mut to), len) {
            // A copy of nothing means the donor ended early: the fallback will
            // read it and report the real error.
            Ok(0) => break,
            Ok(moved) => offset += moved as u64,
            Err(_) => break,
        }
    }
    if offset < end {
        let mut buffer = vec![0u8; COPY_RUN_CHUNK.min(end - offset) as usize];
        while offset < end {
            let take = COPY_RUN_CHUNK.min(end - offset) as usize;
            let piece = &mut buffer[..take];
            donor.read_exact_at(offset, piece)?;
            payload.write_all_at(offset, piece)?;
            offset += take as u64;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_core::group_cv;

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

        assert_eq!(proven.subtrees.len(), group_count(size) as usize);
        for subtree in &proven.subtrees {
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
        assert_eq!(proven.subtrees.len(), 5);
        for (index, subtree) in proven.subtrees.iter().enumerate() {
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

        let spans: Vec<(u64, u64)> = proven
            .subtrees
            .iter()
            .map(|s| (s.start, s.groups))
            .collect();
        let donor_cvs = store.subtree_cvs(&old_root, &spans).unwrap();
        let equal: Vec<u64> = proven
            .subtrees
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
        let promoted = fetcher.promote(&Donor(old_root), &proven, 0).unwrap();

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
        assert_eq!(spans.subtrees.len(), 4);
        let promoted = fetcher.promote(&Donor(old_root), &spans, 0).unwrap();
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
        assert!(
            !proven.subtrees.last().unwrap().whole,
            "the tail group is short"
        );

        let promoted = fetcher.promote(&Donor(old_root), &proven, 0).unwrap();
        assert!(
            promoted.contains(6),
            "the short tail is reusable: {promoted:?}"
        );
        assert!(!promoted.contains(0), "the changed group is not");
    }

    /// A matched run is copied across whole — the aligned middle of an object
    /// and the short group on the end of it alike — and what comes out reads
    /// back as the new version, byte for byte.
    ///
    /// The copy is `copy_file_range` where the kernel will take it, which on a
    /// filesystem that shares extents moves no data at all. Nothing here asserts
    /// which of those happened: the point of the fallback chain is that the
    /// object is the same either way, so what is asserted is the object.
    #[test]
    fn a_matched_run_is_copied_across_whole_including_the_tail_group() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        // A size with a short last group, and more than one span's worth of
        // whole ones in front of it.
        let old = data(20 * GROUP + 777);
        let mut new = old.clone();
        new[9 * GROUP..10 * GROUP].fill(0x5a);
        let old_root = fetcher.ingest_bytes(&old, 0).unwrap();
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;
        let all = ChunkRanges::single(0, group_count(size));

        // The descent as the fetcher runs it: spans first, then leaves in what
        // the spans did not settle.
        let mut promoted = ChunkRanges::empty();
        for level in [2u8, 0] {
            let want = all.difference(&promoted);
            let (encoded, served) = provider.encode_proof(&new_root, &want, level).unwrap();
            let proven = fetcher
                .write_proof(&new_root, size, &served, level, &encoded, 0)
                .unwrap();
            let got = fetcher.promote(&Donor(old_root), &proven, 0).unwrap();
            promoted = promoted.union(&got);
        }
        assert_eq!(
            promoted,
            all.difference(&ChunkRanges::single(9, 10)),
            "every group but the edited one, the short tail included"
        );
        assert!(promoted.contains(20), "the short tail group came across");

        // The bytes that came across are the new version's bytes, and they
        // verify: a read is a bao decode against the root.
        assert_eq!(
            fetcher.read_range(&new_root, 0, 8 * GROUP as u64).unwrap(),
            &new[..8 * GROUP]
        );
        assert_eq!(
            fetcher
                .read_range(&new_root, 20 * GROUP as u64, 777)
                .unwrap(),
            &new[20 * GROUP..]
        );
        // And the one group that changed finishes it off.
        let missing = all.difference(&promoted);
        let (encoded, served) = provider.encode_slice(&new_root, &missing).unwrap();
        fetcher
            .write_slice(&new_root, size, &served, &encoded, 0)
            .unwrap();
        assert!(fetcher.blob(&new_root).unwrap().unwrap().complete);
        assert_eq!(fetcher.read_all(&new_root).unwrap(), new);
    }

    /// A donor whose *tree* rotted cannot poison the tree being built.
    ///
    /// Promotion believes a donor's bytes on the strength of its outboard, so
    /// the outboard is the thing that has to be self-consistent: the nodes
    /// copied out from under a matched span are recombined on the way up and
    /// have to arrive at the chaining value the proof proved. A flipped bit
    /// below the span survives the span's own comparison — that value is read
    /// from the pair *above* it — and is caught here. The span is left to the
    /// network, and the spans either side of it are unaffected.
    #[test]
    fn a_rotted_donor_tree_is_refused_and_left_to_the_fetch() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let old = data(16 * GROUP);
        let mut new = old.clone();
        new[15 * GROUP..].fill(0x11);
        let old_root = fetcher.ingest_bytes(&old, 0).unwrap();
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;
        let all = ChunkRanges::single(0, group_count(size));

        // Spans of four groups. A bit flips inside the donor's outboard, under
        // the span covering groups 4..8, behind the store's back.
        let (encoded, served) = provider.encode_proof(&new_root, &all, 2).unwrap();
        let proven = fetcher
            .write_proof(&new_root, size, &served, 2, &encoded, 0)
            .unwrap();
        let span = proven.subtrees.iter().find(|s| s.start == 4).unwrap();
        // The node one level under that span, which its own comparison cannot
        // see: the span's value comes out of the pair above it.
        let inner = Subtree::locate(&Store::tree(size), 16, 4, 2).unwrap().node;
        let outboard = outboard_of(&fetcher, &old_root, size);
        let offset = outboard.tree.pre_order_offset(inner).unwrap() * PROOF_NODE_LEN as u64;
        let mut raw = std::fs::read(fetcher.outboard_path(&old_root)).unwrap();
        raw[offset as usize + 8 + 3] ^= 0xff;
        std::fs::write(fetcher.outboard_path(&old_root), &raw).unwrap();

        let promoted = fetcher.promote(&Donor(old_root), &proven, 0).unwrap();
        assert!(
            !promoted.overlaps(span.start, span.end()),
            "the span over the rotted tree is refused: {promoted:?}"
        );
        assert!(
            promoted.contains(0) && promoted.contains(8),
            "the spans either side of it are not: {promoted:?}"
        );
        // What was refused goes back to the network, and the object completes.
        let missing = all.difference(&promoted);
        let (encoded, served) = provider.encode_slice(&new_root, &missing).unwrap();
        fetcher
            .write_slice(&new_root, size, &served, &encoded, 0)
            .unwrap();
        assert_eq!(fetcher.read_all(&new_root).unwrap(), new);
    }

    /// A proof of one object cannot be spent on another.
    ///
    /// Two objects of a size have the same tree, so every positional check
    /// promotion makes — does this subtree exist here, is it whole, does the
    /// donor reach that far — passes for the wrong proof just as readily as for
    /// the right one. What would come out is an object filled with a stranger's
    /// bytes and marked complete: advertised, and unreadable by anyone who
    /// asked for it. The root travelling with the subtrees is what makes the
    /// refusal possible.
    #[test]
    fn a_proof_is_spent_on_the_object_it_was_taken_for() {
        // `promote` reads the object and its length off the proof rather than
        // taking them alongside it, so "spending a proof on the wrong object"
        // is no longer a thing a caller can express — which is what the pair of
        // checks that used to guard it could only ever catch. The guarantee
        // that matters is unchanged and lives in `walk_proof`: a proof only
        // verifies against the root it was taken for, so it can never be turned
        // into bytes for a different object.
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let mine = data(8 * GROUP);
        let mut theirs = mine.clone();
        theirs[0] ^= 0xff;
        let size = mine.len() as u64;
        let my_root = provider.ingest_bytes(&mine, 0).unwrap();
        let their_root = provider.ingest_bytes(&theirs, 0).unwrap();
        let donor = fetcher.ingest_bytes(&mine, 0).unwrap();

        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider.encode_proof(&my_root, &all, 0).unwrap();

        // The forgery attempt: my object's proof bytes, offered as theirs.
        assert!(
            matches!(
                fetcher.write_proof(&their_root, size, &served, 0, &encoded, 0),
                Err(StoreError::Verification { .. })
            ),
            "a proof must not verify against another object's root"
        );
        assert!(
            fetcher.blob(&their_root).unwrap().is_none(),
            "nothing was written for the object the proof was not about"
        );

        // And spent honestly, it names the object it was taken for — which is
        // now the only object it can be spent on. (A promote that actually
        // moves groups is covered by `a_proof_carries_the_length_it_was_taken_at`;
        // here the donor *is* the object, so there is nothing left to fill.)
        let proven = fetcher
            .write_proof(&my_root, size, &served, 0, &encoded, 0)
            .unwrap();
        assert_eq!(proven.root, my_root);
        assert_eq!(proven.size, size);
        fetcher.promote(&Donor(donor), &proven, 0).unwrap();
    }

    /// A proof of the right object at the wrong length is refused.
    ///
    /// The root travelling with a proof settles *which* object it describes;
    /// this settles how long that object is, and the two holes are the same
    /// shape. "Whole" — the property that makes a subtree comparable across
    /// objects at all — is a fact about where the object ends, so a proof spent
    /// under a size shorter than the one it was taken at hands out whole-looking
    /// subtrees that the object does not end after. A group-aligned
    /// understatement of a twenty-group object by four groups would promote
    /// sixteen of them and leave the row complete at eighty percent of its
    /// length: unreadable, and refusing every honest writer of the rest for
    /// good, exactly as an unattested size claim once did.
    #[test]
    fn a_proof_carries_the_length_it_was_taken_at() {
        // The length is part of the proof rather than a parameter beside it, so
        // a proof cannot be spent at a length it was not taken at. "Whole" —
        // the property that makes a subtree comparable across objects — is a
        // fact about where the object ends, and a proof taken under a short
        // size would hand out whole-looking subtrees this object does not end
        // after.
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let bytes = data(20 * GROUP);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        // A donor sharing every group but the last: a real reuse.
        let mut donor_bytes = bytes.clone();
        donor_bytes[19 * GROUP] ^= 0xff;
        let donor = fetcher.ingest_bytes(&donor_bytes, 0).unwrap();

        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider.encode_proof(&root, &all, 0).unwrap();

        // A proof cannot be *taken* at a length the object does not have.
        let short = 16 * GROUP as u64;
        assert!(
            fetcher
                .write_proof(&root, short, &served, 0, &encoded, 0)
                .is_err(),
            "a proof must not verify under a length the tree does not have"
        );

        let proven = fetcher
            .write_proof(&root, size, &served, 0, &encoded, 0)
            .unwrap();
        assert_eq!(
            proven.size, size,
            "a proof carries the size it was taken at"
        );

        let promoted = fetcher.promote(&Donor(donor), &proven, 0).unwrap();
        assert_eq!(promoted.count(), 19, "every group but the changed one");
    }

    /// A size claim racing a write that completes the object cannot brick it.
    ///
    /// Both committers used to decide whether a claimed size could stand by
    /// reading the row *before* doing their work: an honest `write_slice`
    /// finishing an object and a `write_proof` carrying an entry's overstatement
    /// of it could each look, each see a row no group attested to yet, and each
    /// go ahead. Whichever committed second wrote its size over the other's, and
    /// when that was the liar the row ended `complete` under a length no byte on
    /// the disk supports — attested from then on, so every honest writer was
    /// refused "size mismatch" for good, `read_all` failed, and the entry that
    /// named the root kept the collector off it. The decision now happens inside
    /// the same transaction as the bitmap union, so one of the two loses and it
    /// is always the claim.
    ///
    /// A bounded loop rather than a stress test: the interleaving is rare enough
    /// that the original took dozens of rounds to hit, and what is asserted is
    /// the invariant, which has to hold on every one of them.
    #[test]
    fn a_size_claim_racing_a_completing_write_never_wins() {
        let (_d1, provider) = store();
        let (_d2, victim) = store();
        for round in 0..64usize {
            // A fresh object per round, so each race starts from no row at all.
            let bytes = data(4 * GROUP + 500 + round);
            let size = bytes.len() as u64;
            let root = provider.ingest_bytes(&bytes, 0).unwrap();
            // A hundred bytes further on, inside the same chunk group: the same
            // tree, so the proof under the lie verifies against the same root.
            let lie = size + 100;
            assert_eq!(group_count(lie), group_count(size));

            let all = ChunkRanges::single(0, group_count(size));
            let (slice, slice_served) = provider.encode_slice(&root, &all).unwrap();
            let (proof, proof_served) = provider.encode_proof(&root, &all, 0).unwrap();

            std::thread::scope(|scope| {
                let (victim, root) = (&victim, &root);
                let (slice, slice_served) = (&slice, &slice_served);
                let (proof, proof_served) = (&proof, &proof_served);
                scope.spawn(move || {
                    victim
                        .write_slice(root, size, slice_served, slice, 0)
                        .expect("the honest writer is never refused")
                });
                scope.spawn(move || {
                    // Refused or absorbed, either is fine — what it must not do
                    // is leave its size on a completed row.
                    let _ = victim.write_proof(root, lie, proof_served, 0, proof, 0);
                });
            });

            let row = victim.blob(&root).unwrap().unwrap();
            assert_eq!(row.size, size, "round {round}: the claim won");
            assert!(row.complete, "round {round}");
            assert_eq!(victim.read_all(&root).unwrap(), bytes, "round {round}");
        }
    }

    /// A size a peer merely claimed does not brick a root.
    ///
    /// An object's tree is the same shape for every size inside its last 16 KiB
    /// chunk group, so an entry that overstates an honest root by a hundred bytes
    /// yields a proof that verifies against that root perfectly well. The row
    /// it leaves behind used to record the lie, and every honest writer of the
    /// same root afterwards — from any origin, on any node that touched the
    /// path — was refused with "size mismatch" for good, with nothing to
    /// collect the row because the honest entry still named it.
    #[test]
    fn an_overstated_size_does_not_brick_a_root() {
        let (_d1, provider) = store();
        let (_d2, victim) = store();
        let bytes = data(8 * GROUP + 500);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        // A hundred bytes further on, inside the same chunk: the same tree.
        let lie = size + 100;
        assert_eq!(group_count(lie), group_count(size));

        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider.encode_proof(&root, &all, 0).unwrap();
        victim
            .write_proof(&root, lie, &served, 0, &encoded, 0)
            .expect("the proof verifies: the lie is invisible in the tree");
        assert_eq!(victim.blob(&root).unwrap().unwrap().size, lie);

        // The honest fetch that follows replaces the claim rather than being
        // refused by it, and the object completes.
        let (encoded, served) = provider.encode_slice(&root, &all).unwrap();
        victim
            .write_slice(&root, size, &served, &encoded, 0)
            .unwrap();
        let row = victim.blob(&root).unwrap().unwrap();
        assert!(row.complete);
        assert_eq!(row.size, size);
        assert_eq!(victim.read_all(&root).unwrap(), bytes);

        // And once the last group is held, the size *is* attested: a later
        // claim of a different one is refused, as it always was.
        assert!(matches!(
            victim.write_slice(&root, lie, &served, &encoded, 0),
            Err(StoreError::Verification { .. })
        ));
    }

    /// An inline donor has nothing to say and is not consulted.
    ///
    /// A blob that fits in the index is one chunk group, and a single group's
    /// only hash is its object's root — root-flagged, and so equal to no
    /// chaining value anywhere (§2). Offering one is not an error; it simply
    /// promotes nothing.
    #[test]
    fn an_inline_donor_promotes_nothing() {
        let (_d1, provider) = store();
        let (_d2, fetcher) = store();
        let new = data(8 * GROUP);
        let tiny = fetcher.ingest_bytes(&data(100), 0).unwrap();
        assert!(fetcher.blob(&tiny).unwrap().unwrap().inline.is_some());
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let size = new.len() as u64;

        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider.encode_proof(&new_root, &all, 0).unwrap();
        let proven = fetcher
            .write_proof(&new_root, size, &served, 0, &encoded, 0)
            .unwrap();
        let promoted = fetcher.promote(&Donor(tiny), &proven, 0).unwrap();
        assert!(promoted.is_empty(), "{promoted:?}");
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
        assert_eq!(proven.subtrees.len(), 8);
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
                .promote(&Donor(root), &Proven::none(root, bytes.len() as u64), 0)
                .unwrap();
            assert!(promoted.is_empty());
        }
    }
}
