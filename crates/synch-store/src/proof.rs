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
/// Carrying them here is what makes the hazard unrepresentable rather than
/// checked: [`Store::promote`] reads the object and its length off the proof, so
/// a caller has no way to spend one on a different object, and `walk_proof`
/// binds both to the tree it verified. A check against a root and size the
/// caller passed separately would only ever catch a caller disagreeing with
/// itself.
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
        // Deduplicated by position. `Walk::descend` emits a subtree for every
        // level-L node that *overlaps* the request, not only those wholly inside
        // it, so two providers whose asks split one span both prove that whole
        // span — and `promote` reads `held` once before its loop, so the second
        // copy misses the "already held" guard and the whole run is copied
        // again. Wasted IO inside the path whose entire purpose is avoiding IO,
        // and it grows with the fanout rather than being a constant.
        //
        // Through a set rather than a scan of what is already held. A window
        // carries up to `MAX_PROOF_NODES`-worth of subtrees — about 8 000 at
        // the span level — and one window covers a 100 GB object, so below that
        // the scan never ran at all. Past it the accumulator is folded once per
        // window, and a linear scan makes the fold quadratic in the object's
        // size: a 1 TB object is eight windows and ~1.9e9 comparisons, seconds
        // of a runtime worker. This runs beside the offloaded `write_proof`
        // rather than inside it, and it touches no store connection, so §10's
        // checker cannot see it (`Store::conn` is where that check lives).
        let mut held: std::collections::HashSet<(u64, u64)> =
            self.subtrees.iter().map(|s| (s.start, s.groups)).collect();
        for subtree in other.subtrees {
            if held.insert((subtree.start, subtree.groups)) {
                self.subtrees.push(subtree);
            }
        }
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

    /// Finds the subtree covering `[start, start + groups)` by descending from
    /// the root, or `None` for a run that is not a subtree of this tree at all.
    ///
    /// A [`ProvenSubtree`] names itself by position and width, which is all a
    /// caller comparing objects needs; writing its interior back into *this*
    /// object's outboard needs bao's name for it, and that is a walk down from
    /// the root. `promote` calls this once per proven span, because
    /// [`ProvenSubtree`] carries only `(start, groups)` and not the `TreeNode`
    /// the walk that produced it already held — so the descent recomputes a
    /// value that was in hand a moment earlier.
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
/// the object's own *address* is not one: it carries BLAKE3's root flag, and a
/// subtree of another object could never equal it (`docs/DELTA-SYNC.md` §2).
/// The donor's whole tree still *has* a chaining value, though — the ordinary,
/// unflagged join of its root pair — and that is what those same bytes carry
/// when they sit as a subtree of a larger object.
///
/// Returning `None` there instead would cost a donor its most valuable answer.
/// A donor whose group count is exactly the span the round asks about is whole
/// for exactly one span — its own — and is not whole for any other, so every
/// span would fail: `promoted` comes back empty, the zero-match exit skips the
/// leaf round, and an object grown from a donor of exactly the span size
/// re-fetches all of itself. `promote` still pins the extent, since it checks
/// the proven subtree's byte range against the donor's.
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
            // The whole of this object, as a subtree of some larger one.
            let Some(_) = node.children() else {
                // A single-group object has no pair to join: its group *is* the
                // tree, and the only hash the outboard holds for it is the
                // root-flagged address.
                return Ok(None);
            };
            let pair = load_from_outboard(outboard, root, &node.node)?;
            let left = Cv(pair[..32].try_into().expect("32 of 64 bytes"));
            let right = Cv(pair[32..].try_into().expect("32 of 64 bytes"));
            return Ok(Some(join_cvs(&left, &right)));
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

    /// Encodes the interior tree over `requested` at `level`, up to `budget`
    /// nodes, without the payload (`docs/DELTA-SYNC.md` §3.1).
    ///
    /// Returns the pre-order node pairs and the ranges they actually cover.
    /// Like a slice, a proof is served for the intersection of what was asked
    /// for and what the provider verifiably holds — a partial holder's outboard
    /// carries every node on the path to its own groups, and nothing else — and
    /// like a slice it is clamped to one window, here counted in nodes rather
    /// than groups. `ProofEnd` carries the second return value, and the
    /// requester's next window starts where it stopped.
    ///
    /// The outboard is read positionally, one node at a time, never slurped:
    /// the span-level round over a 100 GB object touches a few thousand of its
    /// nodes, where the outboard as a whole is hundreds of megabytes.
    ///
    /// The budget is a parameter rather than a constant read from
    /// `synch_core`. It is a *frame* bound — how much of an answer fits one
    /// exchange — and the frame belongs to the layer that writes it, so
    /// `synch-net` supplies `MAX_PROOF_NODES` at the call site — which also
    /// means the clamping can be exercised without a 128 GB object.
    ///
    /// An over-budget request is refused rather than truncated; see the walk
    /// below for why that is safe once the requester sizes its own windows.
    pub fn encode_proof(
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
        // A truncated walk is a refused request, not a partial answer.
        //
        // The requester sizes its window from `proof_nodes_upper_bound` so that
        // a provider holding *everything* it asked for still fits the budget,
        // and this walk covers `requested ∩ what we hold`, which is a subset of
        // that and so cannot cost more. Overrunning therefore means the request
        // was not sized by a conforming requester, and the answer is to say so
        // rather than to serve a prefix.
        //
        // Refusing *after* walking is not the amplification it reads as: the
        // budget is checked before each node is loaded, so an over-budget
        // request costs at most `budget` loads — strictly less than a
        // conforming maximal request, which does the same loads and then
        // serialises and sends the result. The §12 sanity bound on this message
        // is enforced, and it is enforced by `budget`, not by this check.
        //
        // Refusing is also what keeps this to a single walk. Serving a
        // truncated answer would mean making the two sides agree about where it
        // stopped — done by discarding the work and walking the whole thing
        // again over the ranges that fit, at up to `MAX_PROOF_NODES` random
        // 64-byte outboard reads for a ~50-byte request.
        if let Some(at) = truncated {
            return Err(StoreError::Verification {
                root: *root,
                reason: format!(
                    "a proof over these ranges at level {level} exceeds the \
                     {budget}-node budget (stopped at group {at}); the requester \
                     must split the request"
                ),
            });
        }
        let served = wanted;

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
        // Held past the commit below, for the reason `write_slice` takes one: the
        // outboard is written with no lock held ([`Store::lease_write`]).
        let _lease = self.lease_write(root);
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
            //
            // And only as far as this proof's own nodes reach, not as far as
            // the claimed length's tree would: `size` came off a trie entry and
            // nothing has verified it, so growing to `tree.outboard_size()`
            // turned a 32 TiB claim into a 128 GiB file that nothing reclaims.
            // The nodes below are the whole of what is about to be written.
            let reach = proof
                .nodes
                .iter()
                .filter_map(|(node, _)| tree.pre_order_offset(*node))
                .map(|offset| (offset + 1) * PROOF_NODE_LEN as u64)
                .max()
                .unwrap_or(0);
            let mut outboard = PreOrderOutboard {
                root: blake3::Hash::from_bytes(root.0),
                tree,
                data: DataFile(self.open_sparse_outboard(root, reach)?),
            };
            for (node, pair) in &proof.nodes {
                let left = blake3::Hash::from_bytes(pair[..32].try_into().expect("32 of 64"));
                let right = blake3::Hash::from_bytes(pair[32..].try_into().expect("32 of 64"));
                outboard.save(*node, &(left, right))?;
            }
            outboard.sync()?;
            // Checked, like the flushes `write_slice` runs: a swallowed ENOSPC
            // or EIO here lets the row below record a tree that never reached
            // stable storage. The handle is open for writing, which is what
            // Windows requires of a flush.
            fsync_file(&outboard.data.0)?;
            crate::cas::fsync_parent(&self.outboard_path(root));
            // The row is what later passes read the object's size and bitmap
            // out of. A proof commits no bytes, so an object first met this way
            // is recorded as held-nothing rather than not held at all.
            //
            // This may affect an in-flight fetch: `commit_groups` also settles
            // the size, and a claim that moves the object's *group count* resets the bitmap
            // (`settle_size`, rule 3), so a proof carrying a wrong size erases
            // whatever a concurrent fetch had verified. Sixty-four bytes on the
            // wire, repeatable, and reachable from any origin that publishes a
            // false `f:` size for a root a peer is fetching.
            //
            // That is a documented, accepted cost rather than a defect — the
            // same erasure is reachable through the ordinary slice path, and
            // `docs/DELTA-SYNC.md` §6 states the trade: an unattested size
            // yields to the next writer so that an overstated entry cannot
            // brick a root forever, and the price is a re-fetch of what was
            // held. It is written down here because a comment claiming the
            // opposite is what would keep the next reader from finding it.
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
    ///
    /// A donor whose files are gone answers `None` to everything rather than
    /// failing: nothing in the descent may fail a fetch, and a donor the
    /// collector took between the plan and the question is a donor with
    /// nothing to say.
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
        let Ok(file) = File::open(self.outboard_path(root)) else {
            return Ok(out);
        };
        let outboard = PreOrderOutboard {
            root: blake3::Hash::from_bytes(root.0),
            tree,
            data: DataFile(file),
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
        // Passing them alongside it and checking for agreement is not the
        // security property it looks like: `write_proof` builds `Proven` from
        // its own arguments and `Proven::none` from the caller's locals, so no
        // peer-supplied value reaches `proven.root` or `proven.size`
        // independently of what the caller already had. Such a check could
        // only catch a caller mixing up two objects — which taking the values
        // from one place makes unrepresentable instead.
        //
        // The real protection is elsewhere: `walk_proof` recomputes every
        // chaining value to the root, so a proof of another object cannot
        // verify in the first place.
        let root = &proven.root;
        let size = proven.size;
        // Promotion copies donor bytes into this object's payload and its tree
        // into the outboard, both with no lock held, and commits after — the same
        // shape as `write_slice`, and the same reason for a lease
        // ([`Store::lease_write`]).
        let _lease = self.lease_write(root);
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
            // The extent a chaining value attests has to be the extent that is
            // copied. `size` is the caller's claim, and a claim a few bytes
            // short of the object leaves the final group's run shorter here than
            // in the donor while both sides' chaining values still cover the
            // whole of it — so the run would be copied truncated and the row
            // committed complete at a length no byte on the disk supports.
            // Requiring the two extents to agree costs nothing honest: a whole
            // subtree ends at `node.end() * CHUNK_GROUP_SIZE` in both objects,
            // an honest short tail is the same length in both, and a donor that
            // runs further at the final group fails the comparison below anyway.
            let donor_end = node.end().saturating_mul(CHUNK_GROUP_SIZE).min(donor.size);
            if end_byte != donor_end {
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
            // writing would mean a run that turns out not to match has already
            // overwritten whatever was at those offsets, and a group another
            // writer had just verified into the bitmap becomes a bit that lies
            // (§6.2).

            // The nodes *under* the run come across as well, or the groups this
            // pass gains could be held and not served (§3.4, §6.3).
            let mut nodes = Vec::new();
            if let Err(e) = copy_subtree_nodes(&donor, node, subtree.cv, &mut nodes) {
                tracing::debug!(donor = %donor.root, error = %e, "donor tree not copied");
                continue;
            }
            let sink = match &mut sink {
                Some(sink) => sink,
                slot => slot.insert(self.open_sink(root, tree)?),
            };
            // Grown to the end of the run about to land in it, exactly as
            // `write_slice` grows to the end of the window it is about to
            // verify — never to the claimed size, which no proof has
            // established.
            crate::cas::grow_to(&sink.payload.0, end_byte)?;
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
        fsync_file(&sink.payload.0)?;
        fsync_file(&sink.outboard.data.0)?;
        // The directory entries too. `open_sink` creates both files with
        // `create(true)`, so a promotion into a root this node held nothing of
        // is what puts their names in the shard directory, and `fsync` promises
        // the bytes rather than the name. `write_slice` states the reason it
        // does the same: unlike an orphaned file, a lost *name* under an
        // advanced bitmap never self-heals — the row goes on claiming groups
        // whose bytes are unreachable.
        crate::cas::fsync_parent(&self.blob_path(root));
        crate::cas::fsync_parent(&self.outboard_path(root));
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
    /// Neither file is sized to the object here, because at this point the
    /// object's length is a peer's claim off a trie entry and nothing has
    /// verified it: `walk_proof` verifies the tree's *shape*, never its length,
    /// and `settle_size` has no row to argue with the first time a root is met.
    /// Sizing them here would let a `size` of 32 TiB buy a 32 TiB sparse
    /// payload and a 128 GiB sparse outboard from every node that attempted
    /// the fetch, with nothing to reclaim them: `trim_to_size` runs only on a
    /// commit that completes an object, `gc_orphans` skips roots that have a
    /// row, and `gc_content` skips referenced roots — the attacker's own entry
    /// being the reference. `write_slice` refuses this for the same reason
    /// (`crate::cas`, `docs/DELTA-SYNC.md` §6).
    ///
    /// Each run grows the payload to its own end before it is copied, and
    /// `PreOrderOutboard::save` extends the outboard as it writes — which is
    /// why `write_slice` does not grow the outboard at all. So a real object
    /// still fills out normally, one verified run at a time.
    /// ([`Store::trim_to_size`] is the one place either is made smaller, after
    /// a commit that settled the length.)
    fn open_sink(&self, root: &Hash, tree: BaoTree) -> Result<Sink> {
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
        Ok(Sink {
            payload: DataFile(payload),
            outboard: PreOrderOutboard {
                root: blake3::Hash::from_bytes(root.0),
                tree,
                data: DataFile(self.open_sparse_outboard(root, 0)?),
            },
        })
    }

    /// Opens (creating if need be) just the sparse outboard, for a proof that
    /// has a tree to record and no bytes to put under it.
    ///
    /// `reach` is the first byte past the last node this operation will write,
    /// which is the only length the file may be grown to on the strength of an
    /// unverified size. The tree's full `outboard_size()` is a function of the
    /// claimed length, so growing to it hands a peer's assertion straight to
    /// `set_len`.
    ///
    /// Computed from the nodes in hand, not from where the window ends. A tail
    /// window ends at the claimed size, which is not itself verified.
    fn open_sparse_outboard(&self, root: &Hash, reach: u64) -> Result<File> {
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
        crate::cas::grow_to(&outboard, reach)?;
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
    use crate::testutil;
    use synch_core::group_cv;

    /// One chunk group, the unit everything here is counted in.
    const GROUP: usize = CHUNK_GROUP_SIZE as usize;

    /// A provider holding `new` and a fetcher holding `old` as a donor:
    /// (tempdirs, provider, fetcher, new_root, old_root, size). The tempdirs
    /// must live as long as the stores, or the CAS files vanish.
    fn pair_of_stores(
        old: &[u8],
        new: &[u8],
    ) -> (
        tempfile::TempDir,
        tempfile::TempDir,
        Store,
        Store,
        Hash,
        Hash,
        u64,
    ) {
        let (_d1, provider) = testutil::store();
        let (_d2, fetcher) = testutil::store();
        let old_root = fetcher.ingest_bytes(old, 0).unwrap();
        let new_root = provider.ingest_bytes(new, 0).unwrap();
        (
            _d1,
            _d2,
            provider,
            fetcher,
            new_root,
            old_root,
            new.len() as u64,
        )
    }

    /// The fetcher's proof round over the whole object at `level`.
    fn prove(
        provider: &Store,
        fetcher: &Store,
        root: &Hash,
        size: u64,
        level: u8,
    ) -> (Proven, ChunkRanges) {
        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider
            .encode_proof(root, &all, level, MAX_PROOF_NODES)
            .unwrap();
        let proven = fetcher
            .write_proof(root, size, &served, level, &encoded, 0)
            .unwrap();
        (proven, all)
    }

    /// Slices `missing` from the provider and asserts the object reads back as `expected` — the epilogue of every fetch path here.
    fn finish_via_slice(
        provider: &Store,
        fetcher: &Store,
        root: &Hash,
        size: u64,
        missing: &ChunkRanges,
        expected: &[u8],
    ) {
        let (encoded, served) = provider.encode_slice(root, missing).unwrap();
        fetcher
            .write_slice(root, size, &served, &encoded, 0)
            .unwrap();
        assert!(fetcher.blob(root).unwrap().unwrap().complete);
        assert_eq!(fetcher.read_all(root).unwrap(), expected);
    }

    /// A donor as wide as the span vouches for its whole tree as a subtree; single groups have no pair, so None (§3.3).
    #[test]
    fn a_donor_the_width_of_the_span_vouches_for_its_whole_tree() {
        let (_d, store) = testutil::store();
        let bytes = testutil::data(16 * GROUP);
        let donor = store.ingest_bytes(&bytes, 0).unwrap();
        let mut nodes = Vec::new();
        let expected = recompute(
            &bytes,
            Subtree::root_of(&Store::tree(bytes.len() as u64), 16),
            &mut nodes,
        );
        assert_eq!(
            store.subtree_cvs(&donor, &[(0, 16)]).unwrap(),
            vec![Some(expected)]
        );
        assert_ne!(expected.0, donor.0, "it is not the root-flagged address");
        assert!(
            store.subtree_cvs(&donor, &[(0, 8)]).unwrap()[0].is_some(),
            "narrower spans still answer"
        );
        let tiny = store.ingest_bytes(&testutil::data(GROUP), 0).unwrap();
        assert_eq!(store.subtree_cvs(&tiny, &[(0, 1)]).unwrap(), vec![None]);
        // A donor whose outboard the collector took answers None, not Err.
        std::fs::remove_file(store.outboard_path(&donor)).unwrap();
        assert_eq!(store.subtree_cvs(&donor, &[(0, 16)]).unwrap(), vec![None]);
    }

    /// Our idea of the tree — which groups pair, which outboard node holds the result, where the right edge collapses — is bao's, node for node.
    #[test]
    fn our_tree_math_agrees_with_the_outboard_bao_wrote() {
        let (_d, store) = testutil::store();
        for n in [2 * GROUP, 5 * GROUP + 1, 8 * GROUP, 33 * GROUP + 100] {
            let bytes = testutil::data(n);
            let size = bytes.len() as u64;
            let root = store.ingest_bytes(&bytes, 0).unwrap();
            let outboard = outboard_of(&store, &root, size);
            let mut nodes = Vec::new();
            recompute(
                &bytes,
                Subtree::root_of(&Store::tree(size), group_count(size)),
                &mut nodes,
            );
            assert_eq!(
                nodes.len(),
                group_count(size) as usize - 1,
                "n groups, n-1 interior nodes ({size} bytes)"
            );
            for (node, pair) in &nodes {
                assert_eq!(
                    &load_from_outboard(&outboard, &root, node).unwrap(),
                    pair,
                    "node {node} of a {size}-byte object disagrees"
                );
            }
        }
    }

    /// A leaf proof of a whole object is that object's whole tree: byte for byte the outboard bao wrote, held-nothing on the row.
    #[test]
    fn a_leaf_proof_round_trips_into_the_same_outboard() {
        let (_d1, provider) = testutil::store();
        let (_d2, fetcher) = testutil::store();
        let bytes = testutil::data(9 * GROUP + 7);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let (proven, _) = prove(&provider, &fetcher, &root, size, 0);
        assert_eq!(proven.subtrees.len(), group_count(size) as usize);
        let last = proven.subtrees.last().unwrap();
        let tail_start = (group_count(size) - 1) * GROUP as u64;
        assert_eq!(last.cv, group_cv(tail_start, &bytes[tail_start as usize..]));
        assert!(!last.whole, "the short tail is not whole");
        assert_eq!(
            std::fs::read(fetcher.outboard_path(&root)).unwrap(),
            std::fs::read(provider.outboard_path(&root)).unwrap()
        );
        let row = fetcher.blob(&root).unwrap().unwrap();
        assert!(!row.complete);
        assert!(row.verified_groups().is_empty(), "a proof commits no bytes");
    }

    /// Objects of different sizes agree span for span wherever their bytes agree; a changed span is the only one that disagrees.
    #[test]
    fn equal_spans_are_proven_equal_across_unequal_sizes() {
        let old = testutil::data(16 * GROUP);
        let mut new = old.clone();
        new.extend(testutil::data(4 * GROUP));
        new[9 * GROUP + 100] ^= 0xff;
        let (_d, store) = testutil::store();
        let old_root = store.ingest_bytes(&old, 0).unwrap();
        let (_d2, holder) = testutil::store();
        let new_root = holder.ingest_bytes(&new, 0).unwrap();
        let (proven, _) = prove(&holder, &store, &new_root, new.len() as u64, 2);
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
            .filter(|(s, cv)| **cv == Some(s.cv))
            .map(|(s, _)| s.start)
            .collect();
        assert_eq!(
            equal,
            vec![0, 4, 12],
            "every span but the edited one and the appended tail"
        );
        assert_eq!(
            donor_cvs[4], None,
            "the appended spans lie past the donor's end"
        );
    }

    /// Neither delta-sync file is grown to a length no proof established: a 32 TiB claim must not buy sparse files nothing reclaims (§6).
    #[test]
    fn a_size_claim_cannot_grow_the_delta_sync_files_past_what_is_written() {
        let (_d1, provider) = testutil::store();
        let (_d2, victim) = testutil::store();
        // A proof of one group writes a handful of pairs, not the whole tree.
        let bytes = testutil::data(1024 * GROUP);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let (encoded, served) = provider
            .encode_proof(&root, &ChunkRanges::single(0, 1), 0, MAX_PROOF_NODES)
            .unwrap();
        victim
            .write_proof(&root, size, &served, 0, &encoded, 0)
            .unwrap();
        let written = std::fs::metadata(victim.outboard_path(&root))
            .unwrap()
            .len();
        assert!(
            written < Store::tree(size).outboard_size() / 4,
            "nothing like the tree of the claimed length"
        );

        // A promotion writes the runs it matched and no more.
        let old = testutil::data(16 * GROUP);
        let mut new = old.clone();
        new[15 * GROUP + 7] ^= 0xff;
        let (_d3, _d4, provider, victim, new_root, old_root, new_size) = pair_of_stores(&old, &new);
        let (proven, _) = prove(&provider, &victim, &new_root, new_size, 0);
        let promoted = victim.promote(&Donor(old_root), &proven, 0).unwrap();
        assert_eq!(promoted, ChunkRanges::single(0, 15));
        let reach = promoted.ranges.last().unwrap().end * CHUNK_GROUP_SIZE;
        assert_eq!(
            std::fs::metadata(victim.blob_path(&new_root))
                .unwrap()
                .len(),
            reach,
            "the payload reaches the last promoted byte, not the claimed size"
        );
        assert!(reach < new_size);
    }

    /// A promoted span is servable to a third node, not merely held: the interior nodes land in the new outboard at bao's positions (§6.3).
    #[test]
    fn a_promoted_span_can_be_served_onward() {
        let old = testutil::data(64 * GROUP);
        let mut new = old.clone();
        new[40 * GROUP + 7] ^= 0xff;
        let (_d1, _d2, provider, fetcher, new_root, old_root, size) = pair_of_stores(&old, &new);
        let (_d3, third) = testutil::store();
        let (proven, _) = prove(&provider, &fetcher, &new_root, size, 4);
        assert_eq!(proven.subtrees.len(), 4);
        let promoted = fetcher.promote(&Donor(old_root), &proven, 0).unwrap();
        assert_eq!(promoted.count(), 48, "three whole spans: {promoted:?}");
        // A third node fetches one promoted span and gets bytes that verify.
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
        assert_eq!(fetcher.read_range(&new_root, 0, 100).unwrap(), &new[..100]);
    }

    /// A matched run is copied across whole — aligned middle and short tail alike — and promoted groups are servable, not merely held.
    #[test]
    fn a_matched_run_is_copied_across_whole_including_the_tail_group() {
        let old = testutil::data(20 * GROUP + 777);
        let mut new = old.clone();
        new[9 * GROUP..10 * GROUP].fill(0x5a);
        let (_d1, _d2, provider, fetcher, new_root, old_root, size) = pair_of_stores(&old, &new);
        let all = ChunkRanges::single(0, group_count(size));
        // The descent as the fetcher runs it: spans first, then leaves.
        let mut promoted = ChunkRanges::empty();
        for level in [2u8, 0] {
            let want = all.difference(&promoted);
            let (encoded, served) = provider
                .encode_proof(&new_root, &want, level, MAX_PROOF_NODES)
                .unwrap();
            let proven = fetcher
                .write_proof(&new_root, size, &served, level, &encoded, 0)
                .unwrap();
            promoted = promoted.union(&fetcher.promote(&Donor(old_root), &proven, 0).unwrap());
        }
        assert_eq!(
            promoted,
            all.difference(&ChunkRanges::single(9, 10)),
            "every group but the edited one, the short tail included"
        );
        assert!(promoted.contains(20), "the short tail came across");
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
        // Promoted groups are servable because the tree came with them.
        let (slice, slice_served) = fetcher
            .encode_slice(&new_root, &ChunkRanges::single(0, 4))
            .unwrap();
        assert_eq!(slice_served, ChunkRanges::single(0, 4));
        assert!(!slice.is_empty());
        finish_via_slice(
            &provider,
            &fetcher,
            &new_root,
            size,
            &all.difference(&promoted),
            &new,
        );
    }

    /// A donor whose outboard rotted cannot poison the tree: copied nodes must recombine to the proven value, or the span falls back to the network.
    #[test]
    fn a_rotted_donor_tree_is_refused_and_left_to_the_fetch() {
        let old = testutil::data(16 * GROUP);
        let mut new = old.clone();
        new[15 * GROUP..].fill(0x11);
        let (_d1, _d2, provider, fetcher, new_root, old_root, size) = pair_of_stores(&old, &new);
        let all = ChunkRanges::single(0, group_count(size));
        let (proven, _) = prove(&provider, &fetcher, &new_root, size, 2);
        let span = proven.subtrees.iter().find(|s| s.start == 4).unwrap();
        // A bit flips in the donor's outboard under span 4..8, behind the
        // store's back — a value the span's own comparison cannot see.
        let inner = Subtree::locate(&Store::tree(size), 16, 4, 2).unwrap().node;
        let offset = outboard_of(&fetcher, &old_root, size)
            .tree
            .pre_order_offset(inner)
            .unwrap()
            * PROOF_NODE_LEN as u64;
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
            "the spans either side are not: {promoted:?}"
        );
        finish_via_slice(
            &provider,
            &fetcher,
            &new_root,
            size,
            &all.difference(&promoted),
            &new,
        );
    }

    /// A size claim short of the truth cannot promote a short tail: the run would be copied truncated, completing a row nothing supports (§6).
    #[test]
    fn an_understated_size_does_not_promote_a_short_tail() {
        let bytes = testutil::data(8 * GROUP + 500);
        let size = bytes.len() as u64;
        let mut donor_bytes = bytes.clone();
        donor_bytes[3 * GROUP + 9] ^= 0xff;
        let (_d1, _d2, provider, victim, root, donor, _) = pair_of_stores(&donor_bytes, &bytes);
        let all = ChunkRanges::single(0, group_count(size));
        // One byte short of the truth: the same tree, so the proof verifies.
        let short = size - 1;
        assert_eq!(group_count(short), group_count(size));
        let (encoded, served) = provider
            .encode_proof(&root, &all, 0, MAX_PROOF_NODES)
            .unwrap();
        let proven = victim
            .write_proof(&root, short, &served, 0, &encoded, 0)
            .expect("the proof verifies under the short size");
        let promoted = victim.promote(&Donor(donor), &proven, 0).unwrap();
        assert!(
            !promoted.contains(8),
            "the tail group's bytes reach further than the claim: {promoted:?}"
        );
        assert!(
            promoted.contains(0) && !promoted.contains(3),
            "the whole groups either side still promote: {promoted:?}"
        );
        assert!(
            !victim.blob(&root).unwrap().unwrap().complete,
            "nothing completed the object under the claim"
        );
        // The honest writer of the real length is not refused by the residue.
        finish_via_slice(&provider, &victim, &root, size, &all, &bytes);
    }
    /// A proof of the right object at the wrong length is refused: a group-aligned
    /// understatement would promote subtrees the object does not end after, completing
    /// a row at 80% of its length (§6).
    #[test]
    fn a_proof_carries_the_length_it_was_taken_at() {
        let bytes = testutil::data(20 * GROUP);
        let size = bytes.len() as u64;
        let mut donor_bytes = bytes.clone();
        donor_bytes[19 * GROUP] ^= 0xff;
        let (_d1, _d2, provider, fetcher, root, donor, _) = pair_of_stores(&donor_bytes, &bytes);
        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider
            .encode_proof(&root, &all, 0, MAX_PROOF_NODES)
            .unwrap();
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
        assert_eq!(
            fetcher.promote(&Donor(donor), &proven, 0).unwrap().count(),
            19,
            "every group but the changed one"
        );
    }

    /// A size a peer merely claimed does not brick a root: it yields to the next
    /// honest writer, and a completed row refuses a later lie.
    #[test]
    fn an_overstated_size_does_not_brick_a_root() {
        let (_d1, provider) = testutil::store();
        let (_d2, victim) = testutil::store();
        let bytes = testutil::data(8 * GROUP + 500);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let all = ChunkRanges::single(0, group_count(size));
        let lie = size + 100;
        assert_eq!(group_count(lie), group_count(size));
        let (encoded, served) = provider
            .encode_proof(&root, &all, 0, MAX_PROOF_NODES)
            .unwrap();
        victim
            .write_proof(&root, lie, &served, 0, &encoded, 0)
            .expect("the proof verifies: the lie is invisible in the tree");
        assert_eq!(victim.blob(&root).unwrap().unwrap().size, lie);
        // The honest fetch replaces the claim, and the object completes.
        finish_via_slice(&provider, &victim, &root, size, &all, &bytes);
        assert!(
            matches!(
                victim.write_slice(&root, lie, &served, &encoded, 0),
                Err(StoreError::Verification { .. })
            ),
            "once the last group is held, the size is attested"
        );
    }

    /// A tampered proof — flips, truncation, padding, a wrong root — is rejected whole with nothing committed; spent honestly it names its object and length.
    #[test]
    fn a_tampered_proof_is_rejected() {
        let bytes = testutil::data(9 * GROUP);
        let size = bytes.len() as u64;
        let (_d1, provider) = testutil::store();
        let (_d2, fetcher) = testutil::store();
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let all = ChunkRanges::single(0, group_count(size));
        let (encoded, served) = provider
            .encode_proof(&root, &all, 0, MAX_PROOF_NODES)
            .unwrap();
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
        assert!(
            fetcher
                .write_proof(&root, size, &served, 0, &encoded[..encoded.len() - 64], 0)
                .is_err(),
            "truncated"
        );
        let mut padded = encoded.clone();
        padded.extend_from_slice(&[0u8; 64]);
        assert!(
            fetcher
                .write_proof(&root, size, &served, 0, &padded, 0)
                .is_err(),
            "padded"
        );
        assert!(
            fetcher
                .write_proof(&Hash::new(b"elsewhere"), size, &served, 0, &encoded, 0)
                .is_err(),
            "a wrong root fails at the first node"
        );
        assert!(
            fetcher.blob(&root).unwrap().is_none(),
            "nothing was written"
        );
        let proven = fetcher
            .write_proof(&root, size, &served, 0, &encoded, 0)
            .unwrap();
        assert_eq!(proven.root, root);
        assert_eq!(proven.size, size);
    }

    /// An over-budget proof request is refused rather than truncated; sized to the budget, the same request is served whole and verifies.
    #[test]
    fn an_over_budget_proof_is_refused_rather_than_truncated() {
        let (_d, provider) = testutil::store();
        let bytes = testutil::data(40 * GROUP);
        let size = bytes.len() as u64;
        let root = provider.ingest_bytes(&bytes, 0).unwrap();
        let all = ChunkRanges::single(0, group_count(size));
        let err = provider
            .encode_proof(&root, &all, 0, 12)
            .expect_err("an over-budget request must be refused");
        assert!(err.to_string().contains("budget"), "{err}");
        let window = ChunkRanges::single(0, 8);
        let (encoded, served) = provider.encode_proof(&root, &window, 0, 128).unwrap();
        assert_eq!(served, window, "a sized window is never short");
        let (_d2, fetcher) = testutil::store();
        let proven = fetcher
            .write_proof(&root, size, &served, 0, &encoded, 0)
            .unwrap();
        assert!(!proven.is_empty());
    }

    /// Objects too small to have a tree have nothing to prove, and an inline donor promotes nothing: a single group has no chaining value (§2).
    #[test]
    fn tiny_objects_have_nothing_to_prove() {
        let (_d, store) = testutil::store();
        for size in [0usize, GROUP] {
            let bytes = testutil::data(size);
            let root = store.ingest_bytes(&bytes, 0).unwrap();
            let all = ChunkRanges::single(0, group_count(bytes.len() as u64));
            let (encoded, served) = store.encode_proof(&root, &all, 0, MAX_PROOF_NODES).unwrap();
            assert!(encoded.is_empty(), "{size} bytes");
            assert_eq!(served, all, "{size} bytes");
            let promoted = store
                .promote(&Donor(root), &Proven::none(root, bytes.len() as u64), 0)
                .unwrap();
            assert!(promoted.is_empty());
        }
        // An inline donor against a real proof promotes nothing.
        let (_d1, provider) = testutil::store();
        let (_d2, fetcher) = testutil::store();
        let tiny = fetcher.ingest_bytes(&testutil::data(100), 0).unwrap();
        let new = testutil::data(8 * GROUP);
        let new_root = provider.ingest_bytes(&new, 0).unwrap();
        let (proven, _) = prove(&provider, &fetcher, &new_root, new.len() as u64, 0);
        assert!(fetcher
            .promote(&Donor(tiny), &proven, 0)
            .unwrap()
            .is_empty());
    }

    /// Recomputes a subtree's chaining value and every interior pair under it straight from the bytes — the receiving side's arithmetic, with none of the store's plumbing in the way.
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
}
