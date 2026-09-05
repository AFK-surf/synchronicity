//! Trie operations: get, insert, remove, iterate, and completeness walks (§4.3).

use std::collections::HashSet;

use synch_core::{Hash, OriginId, MAX_KEY_LEN};

use crate::{
    error::MptError,
    nibbles::{common_prefix_len, Nibbles},
    node::{TrieNode, ValueRef, NO_CHILDREN},
    scope::Scope,
    store::NodeStore,
};

/// A position in the trie, which may sit *inside* a compressed node.
///
/// Extension and leaf nodes compress several nibble levels into one stored
/// node; a cursor can therefore be "half way through" such a node, in which
/// case it has no hash of its own. Diffing and scanning both walk cursors, so
/// they share one uniform view of the structure regardless of compression.
// A branch node is much larger than the other variants; boxing it would cost an
// allocation on the hottest walk in the crate for no benefit, since cursors are
// short-lived stack values.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub(crate) enum Cursor {
    /// Nothing is stored at this position.
    Empty,
    /// A node. A cursor may sit part-way through a compressed node, in which
    /// case this is the virtual remainder rather than a whole stored one.
    At {
        /// The node itself.
        node: TrieNode,
    },
}

impl Cursor {
    pub(crate) fn is_empty(&self) -> bool {
        matches!(self, Cursor::Empty)
    }

    pub(crate) fn value_ref(&self) -> Option<&ValueRef> {
        match self {
            Cursor::Empty => None,
            Cursor::At { node, .. } => match node {
                TrieNode::Leaf { key_rest, value } if key_rest.is_empty() => Some(value),
                TrieNode::Leaf { .. } | TrieNode::Ext { .. } => None,
                TrieNode::Branch { value, .. } => value.as_ref(),
            },
        }
    }

    pub(crate) fn node_ref(&self) -> Option<&TrieNode> {
        match self {
            Cursor::Empty => None,
            Cursor::At { node, .. } => Some(node),
        }
    }
}

/// How deep, in nibbles, any walk over trie structure descends.
///
/// A key is at most [`MAX_KEY_LEN`] bytes (§12), so a value below this depth
/// belongs to a key that could never have been inserted and can only come from
/// a peer that built the structure by hand. Walks prune there rather than
/// following it down.
pub const MAX_DEPTH_NIBBLES: usize = MAX_KEY_LEN * 2;

/// An absolute ceiling on the positions any one structural walk may visit.
///
/// The bound is on *work*, not a guess at which shapes are honest; both numbers
/// that set it are measured: honest data costs ~5.2 positions per entry (§14's
/// shape) to ~11 (identical placeholder files, the densest legitimate shape), so
/// this ceiling carries ~1.5 M entries, past §7.1's 100 k index and §12's
/// sizes. A refused walk is the worst case: a fan-out DAG expands until stopped
/// — ~8 s inside the promotion transaction, once, failing the head's own origin
/// (§12). Raising it is not free: at 64 M a nine-node bomb cost 63 s to refuse,
/// and a seven-node one slipped under and wrote 16.7 M rows.
///
/// This caps how large a trie any origin can have materialized here — a
/// deliberate limit — but nothing observes it on the way there: diffs prune at
/// the first equal hash and `MissingWalk` dedups, so an origin grows past it
/// with no node ever running the walk that would say so, and the limit shows up
/// only on *first cold materialization* (join, restore, `repair rebuild-views`).
/// Existing followers keep syncing it happily; the refusal at least names the
/// situation rather than reading as one more unparseable record.
const WALK_POSITION_CEILING: usize = 8_000_000;

/// Keeps a structural walk proportional to the work it is allowed to do.
///
/// A peer's node graph is a DAG: nothing stops a branch pointing all sixteen
/// children at one hash, and sixteen such branches stacked are seventeen
/// distinct nodes — which `MissingWalk` fetches happily and `is_complete`
/// passes — yet 16^16 positions to walk. Depth bounds do not help; the
/// explosion is in breadth.
///
/// Deduping positions by node hash is *not* the fix: structural sharing means
/// one leaf node legitimately sits at as many positions as there are keys with
/// that value, so pruning repeats silently drops keys from source scans and changes
/// from `diff`. Neither is classifying the shape — a former rule capping
/// arrivals at a multiple of the *distinct* node count collapsed on an ordinary
/// corpus: sixty thousand keys with one identical value make every leaf the
/// same node, ~ten distinct nodes carrying sixty thousand positions, blowing
/// the ratio exactly as a fan-out bomb does. The two cases are not separable by
/// this measurement, so the walk is bounded by work and nothing else.
#[derive(Debug, Default)]
pub(crate) struct FanoutGuard {
    /// Positions of every kind, against the absolute ceiling.
    positions: usize,
}

impl FanoutGuard {
    /// Records one visited position, failing if the walk has outrun its budget.
    pub(crate) fn visit(&mut self) -> Result<(), MptError> {
        self.positions += 1;
        if self.positions > WALK_POSITION_CEILING {
            return Err(MptError::NonCanonical(format!(
                "structural walk exceeded {WALK_POSITION_CEILING} positions. If this is a cold \
                 materialization of an origin that has been publishing for a long time, this \
                 node cannot adopt it at all — its trie has grown past what any *first* \
                 adoption here can walk, while incremental followers are unaffected"
            )));
        }
        Ok(())
    }
}

/// One level of an insert's descent: how the level above was entered, so the
/// path can be rebuilt once the changed subtree below it is known.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum InsertFrame {
    /// An extension whose prefix the key matched whole.
    Ext { prefix: Nibbles },
    /// A branch entered through `idx`.
    Branch {
        children: [Option<Hash>; 16],
        value: Option<ValueRef>,
        idx: usize,
    },
}

/// One level of a removal's descent. Carries the level's own hash as well, so
/// an unchanged child can be answered with the node that is already stored
/// rather than an identical rebuild.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum RemoveFrame {
    Ext {
        hash: Hash,
        prefix: Nibbles,
        child: Hash,
    },
    Branch {
        hash: Hash,
        children: [Option<Hash>; 16],
        value: Option<ValueRef>,
        idx: usize,
        child: Hash,
    },
}

/// One step of a [`Trie::descend`] walk: the parent's state, the child
/// nibble, and the child's path (already pushed), deciding a [`Step`].
pub(crate) type StepFn<'s, T> = dyn FnMut(&T, u8, &[u8]) -> Result<Step<T>, MptError> + 's;

/// What one step of a [`Trie::descend`] walk decided about a child position.
pub(crate) enum Step<T> {
    /// A real position worth descending: charged against the walk ceiling,
    /// its state pushed as the next level.
    Descend(T),
    /// A real position not worth descending — a diff whose subtrees are
    /// structurally shared, say. Charged, not pushed.
    Visited,
    /// Nothing there, or pruned before it was read. Uncharged.
    Skip,
    /// The walk has what it came for; unwind everything.
    Stop,
}

/// Maps the empty-trie sentinel onto `None`.
pub(crate) fn root_opt(root: Hash) -> Option<Hash> {
    if root.is_empty_sentinel() {
        None
    } else {
        Some(root)
    }
}

/// The set of hashes referenced by a root but absent from the store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Missing {
    /// Trie nodes that must be fetched, each with the nibble path it occupies.
    ///
    /// The path travels with the request because that is what a responder
    /// authorizes on (§5.5): a hash carries no position, and none can be
    /// recovered from it.
    pub nodes: Vec<(Vec<u8>, Hash)>,
    /// Out-of-line values that must be fetched, each with the nibble path of
    /// the node that holds it.
    pub values: Vec<(Vec<u8>, Hash)>,
}

impl Missing {
    /// True if nothing is missing.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.values.is_empty()
    }

    /// Total number of missing hashes.
    pub fn len(&self) -> usize {
        self.nodes.len() + self.values.len()
    }
}

/// A key/value pair as yielded by iteration and range scans.
pub type Entry = (Vec<u8>, Vec<u8>);

/// The §5.2 frontier, as a walk that keeps its place.
///
/// **It resumes.** Restarting at the root for every batch makes a cold fetch
/// quadratic — roughly `n²/batch` node reads — so the walk holds its frontier
/// across batches and only revisits a node once the caller has stored it.
///
/// **It prunes against what is already held.** A node is committed the moment
/// it arrives, so a present node's children may well be absent and a walk
/// cannot simply stop at a node it has — but a hash appearing in a root held
/// *whole* is a subtree it has all of. Handed the origin's last complete root,
/// the walk skips everything the new root shares with it and descends only the
/// paths that changed, making an incremental sync cost the change rather than
/// the tree (§5.2).
#[derive(Debug)]
pub struct MissingWalk {
    /// Lean owns the frontier, positional seen set, deferred retries and
    /// extension-child obligations. Hash-only deduplication is used only
    /// inside a complete prefix grant; spine visits retain their positions.
    state: synch_verified::MissingWalk,
    /// The origin whose trie this is, when presence must carry provenance.
    ///
    /// `Some` for a confined origin's root: a node counts as present only if
    /// this store was served it as that origin's ([`NodeStore::owns_node`]),
    /// so a node merely held from another origin's trie is asked for again —
    /// and an origin that never held it cannot supply it. `None` reads
    /// presence off the shared store, which is right for a rooted origin and
    /// for this node's own trie.
    owner: Option<OriginId>,
}

impl MissingWalk {
    /// A walk over everything reachable from `root`, pruning nothing.
    pub fn new(root: Hash) -> MissingWalk {
        MissingWalk::scoped(None, root, Scope::full())
    }

    /// A walk confined to `scope` that skips every subtree `root` shares with
    /// `known_complete`.
    ///
    /// The reference root must be one this store holds in full; pass `None`
    /// when there is no such root, or when it has not been established. A
    /// wrong reference would have the walk skip subtrees it does not hold, and
    /// report a trie complete that it cannot serve.
    ///
    /// Pruning against the reference root survives the confinement: a hash
    /// matching one in a trie held whole *within this scope* is a subtree held
    /// whole within this scope, since every boundary the walk stops at is a
    /// scope edge.
    // LEAN-MODEL: mpt-walk-scoped (ScopedSync.Reach)
    // `ScopedSync.Reach`: the root is on the frontier when its position is
    // admitted, and (in `next_batch`) a child is pushed when its position is.
    pub fn scoped(known_complete: Option<Hash>, root: Hash, scope: Scope) -> MissingWalk {
        MissingWalk::for_origin(None, known_complete, root, scope)
    }

    /// A scoped walk whose presence carries provenance for `owner`.
    ///
    /// The reference root, when given, must be complete *with the same
    /// provenance*: pruning a shared subtree stands in for having fetched it
    /// as `owner`'s, which a reference merely held whole cannot vouch for.
    // LEAN-MODEL: mpt-walk-owned (Provenance.view)
    // `Provenance.view`: the store a walk with an owner sees is the shared
    // store cut down to what was served as that origin's.
    pub fn for_origin(
        owner: Option<OriginId>,
        known_complete: Option<Hash>,
        root: Hash,
        scope: Scope,
    ) -> MissingWalk {
        let root = root_opt(root);
        let reference = known_complete.and_then(root_opt);
        let state = synch_verified::MissingWalk::new(
            scope.native(),
            reference.as_ref().map(Hash::as_bytes),
            root.as_ref().map(Hash::as_bytes),
            MAX_DEPTH_NIBBLES as u64,
        );
        MissingWalk { state, owner }
    }

    /// True once the walk has covered everything and nothing is outstanding.
    pub fn is_exhausted(&self) -> bool {
        self.state.is_exhausted()
    }

    /// Re-queues everything reported absent, for after the caller has stored
    /// it. Nodes that arrived expand into their children; ones that did not
    /// are reported again, which is what lets a caller notice it is making no
    /// progress.
    pub fn resume(&mut self) {
        self.state.resume();
    }

    /// Walks until `max` absent hashes are found or the frontier drains.
    pub fn next_batch<S: NodeStore + ?Sized>(
        &mut self,
        trie: &Trie<'_, S>,
        max: usize,
    ) -> Result<Missing, MptError> {
        let mut missing = Missing::default();
        // One request may ask for a hash once. Structural sharing makes repeats
        // ordinary — two keys with one out-of-line payload — and `seen` dedups
        // nodes but not values, so a single batch asked for one hash several
        // times; the responder answers per hash, and `take_served` treats a
        // second copy as a protocol violation that ends the *whole* exchange,
        // blaming an honest peer for answering exactly what it was asked.
        // Local to the batch: an absent value must be reported again next round,
        // or the unproductive counter behind §5.2's abandonment never fires.
        self.state.start_batch();
        while missing.len() < max {
            // The depth bound every walk carries, applied to the *fetch*, which
            // carried none: `hash_of_encoded` bounds one node's run at
            // `MAX_KEY_LEN * 2` and §12 read that as bounding ingest depth, but
            // the bound is per node and a path is made of many. Without this, a
            // chain past the depth any valid key reaches was pulled in full,
            // vouched for, and served on to every peer — marked by no GC pass,
            // reflected in no `entries` row.
            //
            // It refuses a *position* no valid key reaches (a canonicality rule
            // costing nothing honest) and is **not** a bound on how much a
            // member can make a peer store: `seen` expands a node at whichever
            // depth it is popped first, so one extra branch per rung makes the
            // whole chain reachable at depth 1. Storage is bounded by the walk
            // being deduplicated — one node per *distinct* node served, no
            // leverage beyond what the member uploads (§12: `synch trust rm`).
            // An `MptError`, so it fails that origin and not the relaying peer.
            // LEAN-MODEL: verified-walk-poll (VerifiedCoreProofs.walk_poll_selected)
            let position = self.state.poll().map_err(walk_error)?;
            let Some(position) = position else { break };
            let reference = position.reference.map(Hash);
            let hash = Hash(position.hash);
            let path = position.path;
            // Lean already skipped reference-equal positions. Connecting this
            // executable pruning to completeness still requires proving the
            // full walk's reference-validity invariant.
            let Some(data) = trie.load_owned_raw(self.owner.as_ref(), &hash)? else {
                // A position a peer has refused holds nothing this node may
                // see, so it is satisfied rather than missing (§5.5). Only
                // above the grant: inside it nothing could rightly be refused,
                // and calling such a trie complete would vouch for what is not
                // held. It cannot be tightened to `admits_path`: the child
                // filter below drops every unadmitted position, so the memo
                // would never fire. The refusal is looked up for *this*
                // position: an honest one (`Ext`/`Leaf` running out of scope)
                // is about where the node sits, and the same node at another
                // spine position may lead back into the grant. The distinction
                // lives where the node is: `Scope::admits_node`, which no
                // longer refuses a branch it can serve.
                //
                // And only for an *absent* node. A node this store holds —
                // served at another position it shares by structure, whatever
                // a peer refused here — is expanded wherever the walk meets it.
                // A held boundary would stop the walk above an in-grant
                // subtree it never fetched, and Lean's edge pairing, which
                // follows held reference nodes, would prune against that
                // subtree under the next root.
                let redacted = trie.is_redacted_raw(&hash, Some(&path))?;
                // LEAN-MODEL: verified-walk-absence (VerifiedCoreProofs.absent_inside_grant)
                if self.state.observe_absent(redacted).map_err(walk_error)? {
                    missing.nodes.push((path, hash));
                }
                continue;
            };
            let node = TrieNode::decode(&data)?;
            // The half of the extension invariant `check_invariants` cannot
            // reach: an `Ext` must sit above a `Branch`, which needs the child
            // node. An `Ext` above a `Leaf` or another `Ext` reads fine through
            // `get`/`iter`/`diff` but gives one key/value map several distinct
            // roots — exactly what structural sharing and reference pruning
            // rely on not happening — making every peer's incremental sync cost
            // the whole tree. An `MptError`, so it fails its own origin and no
            // other (§12): the relaying peer served exactly what it was asked.
            let child_shape = if let TrieNode::Ext { child, .. } = &node {
                // Checked now if the child is already here: a DAG means it may
                // have been visited under another parent, and `seen` would keep
                // it from being revisited.
                match trie.load_raw(child)? {
                    Some(bytes) => match TrieNode::decode(&bytes)? {
                        TrieNode::Branch { .. } => synch_verified::ChildShape::Branch,
                        _ => synch_verified::ChildShape::Other,
                    },
                    None => synch_verified::ChildShape::Absent,
                }
            } else {
                synch_verified::ChildShape::Absent
            };
            let reference_node = match reference {
                Some(reference) => trie
                    .load_raw(&reference)?
                    .map(|bytes| TrieNode::decode(&bytes))
                    .transpose()?,
                None => None,
            };
            let reference_fields = WalkFields::from(reference_node.as_ref());
            let node_fields = WalkFields::from(Some(&node));
            // A node whose out-of-line values have not arrived is not done
            // with, so it is deferred like a node that never loaded. Reporting
            // the value once and moving on would have the walk claim exhaustion
            // over a trie it cannot serve — the node loads, so it is never
            // deferred and `seen` never revisits it — and the §5.2 abandonment
            // counter would sit at one while `note_complete` vouched for the
            // root.
            let payload = match &node {
                TrieNode::Branch { value, .. } => value.as_ref().and_then(ValueRef::out_of_line),
                TrieNode::Leaf { value, .. } => value.out_of_line(),
                TrieNode::Ext { .. } => None,
            };
            let present = match payload {
                Some(hash) => trie.has_value_raw(&hash)?,
                None => false,
            };
            // LEAN-MODEL: verified-walk-pairing (VerifiedCoreProofs.paired_reference_same_step)
            if let Some(value) = self
                .state
                .observe_present(
                    reference_fields.native(),
                    node_fields.native(),
                    child_shape,
                    payload.as_ref().map(Hash::as_bytes),
                    present,
                )
                .map_err(walk_error)?
            {
                missing.values.push((path, Hash(value)));
            }
        }
        Ok(missing)
    }
}

/// Structural ABI fields only: no child enumeration, pairing or authorization.
// Short-lived stack marshalling buffer, never stored in a collection. Boxing
// the fixed 16-slot array would allocate for every branch visited by a fetch.
#[allow(clippy::large_enum_variant)]
enum WalkFields<'a> {
    Branch([Option<[u8; 32]>; 16]),
    Extension(&'a [u8], &'a [u8; 32]),
    Leaf(&'a [u8]),
}

impl<'a> From<Option<&'a TrieNode>> for WalkFields<'a> {
    fn from(node: Option<&'a TrieNode>) -> Self {
        match node {
            Some(TrieNode::Branch { children, .. }) => {
                Self::Branch(children.map(|h| h.map(|h| h.0)))
            }
            Some(TrieNode::Ext { prefix, child }) => {
                Self::Extension(prefix.as_slice(), child.as_bytes())
            }
            Some(TrieNode::Leaf { key_rest, .. }) => Self::Leaf(key_rest.as_slice()),
            None => Self::Leaf(&[]),
        }
    }
}

impl WalkFields<'_> {
    fn native(&self) -> synch_verified::WalkNode<'_> {
        match self {
            Self::Branch(children) => synch_verified::WalkNode::Branch(children),
            Self::Extension(prefix, child) => synch_verified::WalkNode::Extension { prefix, child },
            Self::Leaf(suffix) => synch_verified::WalkNode::Leaf(suffix),
        }
    }
}

/// Render Lean's diagnostic without reimplementing the decision that produced it.
fn walk_error(error: synch_verified::WalkError) -> MptError {
    MptError::NonCanonical(match error {
        synch_verified::WalkError::NodeDepth(depth) => format!(
            "a trie node sits at nibble depth {depth}, past the {MAX_DEPTH_NIBBLES} any valid key reaches"),
        synch_verified::WalkError::ValueDepth(depth) => format!(
            "a trie value sits at nibble depth {depth}, past the {MAX_DEPTH_NIBBLES} any valid key reaches"),
        synch_verified::WalkError::NotBranch(hash) => format!(
            "node {} sits under an extension but is not a branch", Hash(hash)),
    })
}

/// Everything reachable from a root, for mark-and-sweep GC (§5.4).
#[derive(Debug, Clone, Default)]
pub struct Reachable {
    /// Reachable trie node hashes.
    pub nodes: HashSet<Hash>,
    /// Reachable out-of-line value hashes.
    pub values: HashSet<Hash>,
}

/// A trie rooted in a content-addressed [`NodeStore`].
///
/// The trie itself is stateless: every operation takes an explicit root hash and
/// returns the new one, so successive roots share structure automatically.
#[derive(Debug)]
pub struct Trie<'a, S: NodeStore + ?Sized> {
    store: &'a S,
}

impl<'a, S: NodeStore + ?Sized> Trie<'a, S> {
    /// Binds a trie to a node store.
    pub fn new(store: &'a S) -> Self {
        Trie { store }
    }

    /// The underlying store.
    pub fn store(&self) -> &'a S {
        self.store
    }

    fn wrap<T>(r: Result<T, S::Error>) -> Result<T, MptError> {
        r.map_err(MptError::store)
    }

    fn load(&self, hash: &Hash) -> Result<TrieNode, MptError> {
        let data = Self::wrap(self.store.get_node(hash))?.ok_or(MptError::MissingNode(*hash))?;
        TrieNode::decode(&data)
    }

    /// Reads a node's bytes without requiring it to be present, for the walks
    /// whose whole purpose is finding out whether it is.
    pub(crate) fn load_raw(&self, hash: &Hash) -> Result<Option<Vec<u8>>, MptError> {
        Self::wrap(self.store.get_node(hash))
    }

    /// Whether a peer has refused to show this node at `path`, or at any
    /// position for `None` (§5.5).
    /// [`Trie::load_raw`], with provenance when the walk carries an owner: a
    /// node this store holds but was never served as `owner`'s reads as
    /// absent, so the walk asks for it ([`MissingWalk::for_origin`]).
    pub(crate) fn load_owned_raw(
        &self,
        owner: Option<&OriginId>,
        hash: &Hash,
    ) -> Result<Option<Vec<u8>>, MptError> {
        if let Some(origin) = owner {
            if !Self::wrap(self.store.owns_node(origin, hash))? {
                return Ok(None);
            }
        }
        self.load_raw(hash)
    }

    pub(crate) fn is_redacted_raw(
        &self,
        hash: &Hash,
        path: Option<&[u8]>,
    ) -> Result<bool, MptError> {
        Self::wrap(self.store.is_redacted(hash, path))
    }

    pub(crate) fn has_value_raw(&self, hash: &Hash) -> Result<bool, MptError> {
        Self::wrap(self.store.has_value(hash))
    }

    fn put(&self, node: &TrieNode) -> Result<Hash, MptError> {
        let encoded = node.encode();
        let hash = crate::node::hash_encoded(node.tag(), &encoded);
        Self::wrap(self.store.put_node(&hash, &encoded))?;
        Ok(hash)
    }

    /// Resolves a value reference into bytes, fetching out-of-line payloads.
    pub fn resolve(&self, value: &ValueRef) -> Result<Vec<u8>, MptError> {
        match value {
            ValueRef::Inline(bytes) => Ok(bytes.clone()),
            ValueRef::Hash(h) => {
                Self::wrap(self.store.get_value(h))?.ok_or(MptError::MissingValue(*h))
            }
        }
    }

    // ---- reads ------------------------------------------------------------

    /// Looks up a key.
    ///
    /// Refuses a key the write path would refuse: `insert`/`remove` bound the
    /// key at [`MAX_KEY_LEN`] and this did not, so a peer could put a value
    /// past that depth with compressed nodes and `get` would answer for a key
    /// `iter`, `diff` and therefore `entries` can never see. The two readers
    /// must agree about which keys exist — the whole of what
    /// [`TrieNode::check_invariants`](crate::TrieNode::check_invariants) and
    /// the ingest bound are for.
    // LEAN-MODEL: mpt-trie-get (Convergence.HasValue)
    // `Convergence.HasValue`; `view_deterministic` is why a key has one value
    // under a root, given `check_invariants`' non-empty extension prefix.
    pub fn get(&self, root: Hash, key: &[u8]) -> Result<Option<Vec<u8>>, MptError> {
        if key.len() > MAX_KEY_LEN {
            return Err(MptError::KeyTooLong(key.len()));
        }
        let nibbles = Nibbles::from_bytes(key);
        let mut rest = nibbles.as_slice();
        let mut current = root_opt(root);
        // Every iteration consumes at least one nibble except the last, so this
        // is bounded by the key length — once an empty extension prefix is
        // impossible. `hash_of_encoded` rejects those now; the guard stays
        // because `get` is the one descent with no stack to bound it. A key of
        // `n` nibbles needs up to `n + 1` loads, not `n` (the last is the leaf
        // or branch holding the value), so the budget is `MAX_DEPTH_NIBBLES + 1`:
        // counted without it, this refused a key of exactly `MAX_KEY_LEN` bytes
        // that `iter` and `diff` yield.
        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > MAX_DEPTH_NIBBLES + 1 {
                return Err(MptError::NonCanonical(
                    "lookup descended further than any valid key is long".into(),
                ));
            }
            let Some(hash) = current else { return Ok(None) };
            match self.load(&hash)? {
                TrieNode::Leaf { key_rest, value } => {
                    return if key_rest.as_slice() == rest {
                        Ok(Some(self.resolve(&value)?))
                    } else {
                        Ok(None)
                    };
                }
                TrieNode::Ext { prefix, child } => {
                    let p = prefix.as_slice();
                    // An empty prefix would make this a dead end for every
                    // structural walk (`cursor_child` can never match one) and
                    // a transparent hop here — the two readers must agree.
                    if p.is_empty() || !rest.starts_with(p) {
                        return Ok(None);
                    }
                    rest = &rest[p.len()..];
                    current = Some(child);
                }
                TrieNode::Branch { children, value } => {
                    if rest.is_empty() {
                        return match value {
                            Some(v) => Ok(Some(self.resolve(&v)?)),
                            None => Ok(None),
                        };
                    }
                    current = children[rest[0] as usize];
                    rest = &rest[1..];
                }
            }
        }
    }

    /// True if the key is present.
    pub fn contains(&self, root: Hash, key: &[u8]) -> Result<bool, MptError> {
        Ok(self.get(root, key)?.is_some())
    }

    // ---- writes -----------------------------------------------------------

    /// Inserts or replaces a key, returning the new root.
    pub fn insert(&self, root: Hash, key: &[u8], value: &[u8]) -> Result<Hash, MptError> {
        if key.len() > MAX_KEY_LEN {
            return Err(MptError::KeyTooLong(key.len()));
        }
        // The value side is bounded here for the same reason the key side is,
        // and it was not: this node must not publish a record every peer's
        // `GetValues` answer and promotion diff will then have to carry
        // ([`MAX_TRIE_VALUE_LEN`]).
        if value.len() > synch_core::MAX_TRIE_VALUE_LEN {
            return Err(MptError::ValueTooLong(value.len()));
        }
        let (vref, out_of_line) = ValueRef::for_value(value);
        if let Some((hash, payload)) = out_of_line {
            Self::wrap(self.store.put_value(&hash, &payload))?;
        }
        let nibbles = Nibbles::from_bytes(key);
        self.insert_at(root_opt(root), nibbles.as_slice(), &vref)
    }

    /// Applies a batch of insertions and removals in one pass, returning the
    /// new root. `None` values remove the key.
    ///
    /// This is what the publisher uses (§7.1): one staged batch becomes one new
    /// root, allocating only the paths that actually changed.
    pub fn apply<'k, I>(&self, root: Hash, changes: I) -> Result<Hash, MptError>
    where
        I: IntoIterator<Item = (&'k [u8], Option<&'k [u8]>)>,
    {
        let mut root = root;
        for (key, value) in changes {
            root = match value {
                Some(v) => self.insert(root, key, v)?,
                None => self.remove(root, key)?,
            };
        }
        Ok(root)
    }

    /// Descends to the one position an insert changes, then rebuilds the path
    /// above it — with the path on the heap.
    fn insert_at(
        &self,
        node: Option<Hash>,
        key: &[u8],
        value: &ValueRef,
    ) -> Result<Hash, MptError> {
        let mut stack: Vec<InsertFrame> = Vec::new();
        let mut cursor = node;
        let mut rest = key;

        // Descend to the position that actually changes, remembering how each
        // level was entered so it can be rebuilt on the way back up.
        let mut built = loop {
            let Some(hash) = cursor else {
                break self.put(&TrieNode::leaf(Nibbles::from_nibbles(rest), value.clone()))?;
            };
            match self.load(&hash)? {
                TrieNode::Ext { prefix, child } => {
                    let p = prefix.as_slice();
                    let cp = common_prefix_len(p, rest);
                    if cp == p.len() {
                        stack.push(InsertFrame::Ext {
                            prefix: prefix.clone(),
                        });
                        cursor = Some(child);
                        rest = &rest[cp..];
                        continue;
                    }
                    break self.split_ext(&prefix, child, rest, value)?;
                }
                TrieNode::Branch {
                    children,
                    value: branch_value,
                } => {
                    if rest.is_empty() {
                        break self.put(&TrieNode::Branch {
                            children,
                            value: Some(value.clone()),
                        })?;
                    }
                    let idx = rest[0] as usize;
                    let next = children[idx];
                    stack.push(InsertFrame::Branch {
                        children,
                        value: branch_value,
                        idx,
                    });
                    cursor = next;
                    rest = &rest[1..];
                }
                node @ TrieNode::Leaf { .. } => break self.split_leaf(node, rest, value)?,
            }
        };

        while let Some(frame) = stack.pop() {
            built = match frame {
                InsertFrame::Ext { prefix } => self.put(&TrieNode::ext(prefix, built))?,
                InsertFrame::Branch {
                    mut children,
                    value,
                    idx,
                } => {
                    children[idx] = Some(built);
                    self.put(&TrieNode::Branch { children, value })?
                }
            };
        }
        Ok(built)
    }

    /// Splits a leaf that shares only part of its key with the one being
    /// inserted, returning the hash of the replacement subtree.
    fn split_leaf(&self, leaf: TrieNode, key: &[u8], value: &ValueRef) -> Result<Hash, MptError> {
        let TrieNode::Leaf {
            key_rest,
            value: old,
        } = leaf
        else {
            unreachable!("split_leaf is only called with a leaf")
        };
        let k = key_rest.as_slice();
        if k == key {
            return self.put(&TrieNode::leaf(key_rest.clone(), value.clone()));
        }
        let cp = common_prefix_len(k, key);
        let mut children = NO_CHILDREN;
        let mut branch_value = None;

        let existing = &k[cp..];
        if existing.is_empty() {
            branch_value = Some(old);
        } else {
            let child = self.put(&TrieNode::leaf(Nibbles::from_nibbles(&existing[1..]), old))?;
            children[existing[0] as usize] = Some(child);
        }

        let inserted = &key[cp..];
        if inserted.is_empty() {
            branch_value = Some(value.clone());
        } else {
            let child = self.put(&TrieNode::leaf(
                Nibbles::from_nibbles(&inserted[1..]),
                value.clone(),
            ))?;
            children[inserted[0] as usize] = Some(child);
        }

        let branch = self.put(&TrieNode::Branch {
            children,
            value: branch_value,
        })?;
        self.wrap_in_ext(&key[..cp], branch)
    }

    /// Splits an extension whose prefix diverges from the key being inserted,
    /// returning the hash of the replacement subtree.
    fn split_ext(
        &self,
        prefix: &Nibbles,
        child: Hash,
        key: &[u8],
        value: &ValueRef,
    ) -> Result<Hash, MptError> {
        let p = prefix.as_slice();
        let cp = common_prefix_len(p, key);
        let mut children = NO_CHILDREN;
        let mut branch_value = None;

        let existing = &p[cp..];
        let down = if existing.len() > 1 {
            self.put(&TrieNode::ext(Nibbles::from_nibbles(&existing[1..]), child))?
        } else {
            child
        };
        children[existing[0] as usize] = Some(down);

        let inserted = &key[cp..];
        if inserted.is_empty() {
            branch_value = Some(value.clone());
        } else {
            let leaf = self.put(&TrieNode::leaf(
                Nibbles::from_nibbles(&inserted[1..]),
                value.clone(),
            ))?;
            children[inserted[0] as usize] = Some(leaf);
        }

        let branch = self.put(&TrieNode::Branch {
            children,
            value: branch_value,
        })?;
        self.wrap_in_ext(&key[..cp], branch)
    }

    fn wrap_in_ext(&self, prefix: &[u8], child: Hash) -> Result<Hash, MptError> {
        if prefix.is_empty() {
            Ok(child)
        } else {
            self.put(&TrieNode::ext(Nibbles::from_nibbles(prefix), child))
        }
    }

    /// Removes a key, returning the new root.
    ///
    /// Removing an absent key returns the root unchanged, so the trie stays in
    /// canonical form: any two tries holding the same key/value map have the
    /// same root regardless of the operation history that produced them.
    pub fn remove(&self, root: Hash, key: &[u8]) -> Result<Hash, MptError> {
        // The same §12 bound `insert` applies. A key this long cannot be
        // present, so the walk is merely wasted — but the asymmetry is the kind
        // that stops being harmless the moment `remove_at` grows an allocation
        // keyed on the input.
        if key.len() > MAX_KEY_LEN {
            return Err(MptError::KeyTooLong(key.len()));
        }
        let nibbles = Nibbles::from_bytes(key);
        match root_opt(root) {
            None => Ok(Hash::EMPTY),
            Some(hash) => Ok(self
                .remove_at(hash, nibbles.as_slice())?
                .unwrap_or(Hash::EMPTY)),
        }
    }

    /// The removal counterpart of [`Trie::insert_at`], on the same heap stack
    /// and for the same reason: one recursion frame per trie level aborted the
    /// process on a deep tree rather than returning an error.
    fn remove_at(&self, hash: Hash, key: &[u8]) -> Result<Option<Hash>, MptError> {
        let mut stack: Vec<RemoveFrame> = Vec::new();
        let mut cursor = hash;
        let mut rest = key;

        let mut result: Option<Hash> = loop {
            match self.load(&cursor)? {
                TrieNode::Leaf { ref key_rest, .. } => {
                    break if key_rest.as_slice() == rest {
                        None
                    } else {
                        Some(cursor)
                    };
                }
                TrieNode::Ext { prefix, child } => {
                    let p = prefix.as_slice();
                    if !rest.starts_with(p) {
                        break Some(cursor);
                    }
                    rest = &rest[p.len()..];
                    stack.push(RemoveFrame::Ext {
                        hash: cursor,
                        prefix: prefix.clone(),
                        child,
                    });
                    cursor = child;
                }
                TrieNode::Branch { children, value } => {
                    if rest.is_empty() {
                        if value.is_none() {
                            break Some(cursor);
                        }
                        break self.collapse(children, None)?;
                    }
                    let idx = rest[0] as usize;
                    let Some(child) = children[idx] else {
                        break Some(cursor);
                    };
                    rest = &rest[1..];
                    stack.push(RemoveFrame::Branch {
                        hash: cursor,
                        children,
                        value,
                        idx,
                        child,
                    });
                    cursor = child;
                }
            }
        };

        // Unwind. A level whose child came back unchanged is itself unchanged,
        // which is what keeps removing an absent key from rewriting the path
        // and so from producing a second root for one key/value map.
        while let Some(frame) = stack.pop() {
            result = match frame {
                RemoveFrame::Ext {
                    hash,
                    prefix,
                    child,
                } => match result {
                    None => None,
                    Some(new_child) if new_child == child => Some(hash),
                    Some(new_child) => Some(self.merge_down(prefix.as_slice(), new_child)?),
                },
                RemoveFrame::Branch {
                    hash,
                    mut children,
                    value,
                    idx,
                    child,
                } => {
                    if result == Some(child) {
                        Some(hash)
                    } else {
                        children[idx] = result;
                        self.collapse(children, value)?
                    }
                }
            };
        }
        Ok(result)
    }

    /// Pushes `prefix` down into `child`, preserving canonical form: an
    /// extension node always sits above a branch, never above a leaf or another
    /// extension.
    fn merge_down(&self, prefix: &[u8], child: Hash) -> Result<Hash, MptError> {
        match self.load(&child)? {
            TrieNode::Leaf { key_rest, value } => {
                self.put(&TrieNode::leaf(key_rest.prepend_all(prefix), value))
            }
            TrieNode::Ext {
                prefix: below,
                child: grandchild,
            } => self.put(&TrieNode::ext(below.prepend_all(prefix), grandchild)),
            TrieNode::Branch { .. } => {
                self.put(&TrieNode::ext(Nibbles::from_nibbles(prefix), child))
            }
        }
    }

    fn collapse(
        &self,
        children: [Option<Hash>; 16],
        value: Option<ValueRef>,
    ) -> Result<Option<Hash>, MptError> {
        let occupied: Vec<usize> = (0..16).filter(|&i| children[i].is_some()).collect();
        match (occupied.len(), value) {
            (0, None) => Ok(None),
            (0, Some(v)) => Ok(Some(self.put(&TrieNode::leaf(Nibbles::new(), v))?)),
            (1, None) => {
                let idx = occupied[0];
                let child = children[idx].expect("occupied slot");
                Ok(Some(self.merge_down(&[idx as u8], child)?))
            }
            (_, value) => Ok(Some(self.put(&TrieNode::Branch { children, value })?)),
        }
    }

    // ---- cursors, iteration, range scans ----------------------------------

    pub(crate) fn cursor_at(&self, hash: Option<Hash>) -> Result<Cursor, MptError> {
        match hash {
            None => Ok(Cursor::Empty),
            Some(h) => match self.load(&h) {
                Ok(node) => Ok(Cursor::At { node }),
                // A refused position holds nothing this node may see, so to a
                // walk over what it *does* hold it is empty rather than absent
                // (§5.5). Both roots of a diff redact the same positions, so no
                // spurious change is emitted; otherwise promotion's
                // materialization would fail on a subtree withheld on purpose.
                // Asked of the hash at any position: a node that is missing
                // here and was refused somewhere was refused at every spine
                // position the scoped fetch walked, and the diff skips the
                // unadmitted positions before it cursors them.
                Err(MptError::MissingNode(_)) if self.is_redacted_raw(&h, None)? => {
                    Ok(Cursor::Empty)
                }
                Err(e) => Err(e),
            },
        }
    }

    pub(crate) fn cursor_child(&self, cursor: &Cursor, nibble: u8) -> Result<Cursor, MptError> {
        let Cursor::At { node, .. } = cursor else {
            return Ok(Cursor::Empty);
        };
        match node {
            TrieNode::Leaf { key_rest, value } => {
                let k = key_rest.as_slice();
                if k.first() != Some(&nibble) {
                    return Ok(Cursor::Empty);
                }
                // Part-way through a compressed node: no stored hash of its own.
                Ok(Cursor::At {
                    node: TrieNode::leaf(Nibbles::from_nibbles(&k[1..]), value.clone()),
                })
            }
            TrieNode::Ext { prefix, child } => {
                let p = prefix.as_slice();
                if p.first() != Some(&nibble) {
                    return Ok(Cursor::Empty);
                }
                if p.len() == 1 {
                    self.cursor_at(Some(*child))
                } else {
                    Ok(Cursor::At {
                        node: TrieNode::ext(Nibbles::from_nibbles(&p[1..]), *child),
                    })
                }
            }
            TrieNode::Branch { children, .. } => self.cursor_at(children[nibble as usize]),
        }
    }

    /// Every key/value pair under `root`, in lexicographic key order.
    pub fn iter(&self, root: Hash) -> Result<Vec<Entry>, MptError> {
        self.scan(root, &[], None, None)
    }

    /// A range scan: every pair whose key starts with `prefix`, in
    /// lexicographic order, optionally resuming strictly after `start_after`
    /// and capped at `limit` results.
    ///
    /// This is the directory-listing primitive (§4.1) and the S3
    /// `ListObjectsV2` cursor (§9.4).
    pub fn scan(
        &self,
        root: Hash,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        limit: Option<usize>,
    ) -> Result<Vec<Entry>, MptError> {
        let prefix_nibbles = Nibbles::from_bytes(prefix);
        let mut cursor = self.cursor_at(root_opt(root))?;
        for &n in prefix_nibbles.as_slice() {
            cursor = self.cursor_child(&cursor, n)?;
            if cursor.is_empty() {
                return Ok(Vec::new());
            }
        }
        let after = start_after.map(Nibbles::from_bytes);
        let mut path = prefix_nibbles.as_slice().to_vec();
        let mut out = Vec::new();
        self.collect(&cursor, &mut path, after.as_ref(), limit, &mut out)?;
        Ok(out)
    }

    /// Drives one structural walk with an explicit heap stack: the hostile-trie
    /// defences, held once for every descent (source-scan collection, `diff`'s
    /// lockstep walk).
    ///
    /// Depth is attacker-controlled — a peer's trie is fetched by hash and
    /// nothing about its shape is canonicalized, so it may chain extensions to
    /// any depth — and a recursive walk would meet that with a stack overflow:
    /// an abort rather than an error, in `diff`'s case inside head promotion
    /// (§5.2, §12). So the frames live on the heap, the walk stops past
    /// [`MAX_DEPTH_NIBBLES`] (below which no valid key can begin), and every
    /// real position is charged against [`FanoutGuard`]'s ceiling, which keeps
    /// the walk proportional to the trie — a fan-out DAG cannot turn a handful
    /// of nodes into an unbounded walk.
    ///
    /// `step` is handed the parent's state, the child nibble, and the child's
    /// path (already pushed); what it answers is a [`Step`]. `path` keeps
    /// whatever prefix it arrives with. The ceiling is charged on the step's
    /// *answer*, so the position that trips it has already done its own work
    /// (emitted its change, taken its value) before the walk refuses — one
    /// position's worth of slack against an 8 M bound, accepted so the driver
    /// need not know in advance which children are real.
    pub(crate) fn descend<T>(
        &self,
        start: T,
        path: &mut Vec<u8>,
        step: &mut StepFn<'_, T>,
    ) -> Result<(), MptError> {
        let base = path.len();
        let mut guard = FanoutGuard::default();
        let mut stack: Vec<(T, u8)> = vec![(start, 0)];
        while let Some(top) = stack.len().checked_sub(1) {
            let nibble = stack[top].1;
            if nibble >= 16 || path.len() >= MAX_DEPTH_NIBBLES {
                stack.pop();
                if path.len() > base {
                    path.pop();
                }
                continue;
            }
            stack[top].1 += 1;
            path.push(nibble);
            match step(&stack[top].0, nibble, path)? {
                Step::Descend(child) => {
                    guard.visit()?;
                    stack.push((child, 0));
                }
                Step::Visited => {
                    guard.visit()?;
                    path.pop();
                }
                Step::Skip => {
                    path.pop();
                }
                // The prefix contract holds on every exit, the early one
                // included: a caller that reuses the buffer after a stopped
                // walk must find it as it was handed over.
                Step::Stop => {
                    path.truncate(base);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Walks a subtree, collecting values ([`Trie::descend`]).
    fn collect(
        &self,
        cursor: &Cursor,
        path: &mut Vec<u8>,
        after: Option<&Nibbles>,
        limit: Option<usize>,
        out: &mut Vec<Entry>,
    ) -> Result<(), MptError> {
        let after_bytes = after.map(|a| a.to_bytes().unwrap_or_default());
        self.take_value(cursor, path, after_bytes.as_deref(), limit, out)?;
        self.descend(cursor.clone(), path, &mut |parent, nibble, path| {
            if limit.is_some_and(|l| out.len() >= l) {
                return Ok(Step::Stop);
            }
            if after.is_some_and(|a| subtree_is_below(path, a.as_slice())) {
                return Ok(Step::Skip);
            }
            let child = self.cursor_child(parent, nibble)?;
            if child.is_empty() {
                return Ok(Step::Skip);
            }
            self.take_value(&child, path, after_bytes.as_deref(), limit, out)?;
            Ok(Step::Descend(child))
        })
    }

    /// Emits the value sitting exactly at `path`, if there is one and the scan
    /// cursor has passed it.
    fn take_value(
        &self,
        cursor: &Cursor,
        path: &[u8],
        after: Option<&[u8]>,
        limit: Option<usize>,
        out: &mut Vec<Entry>,
    ) -> Result<(), MptError> {
        if limit.is_some_and(|l| out.len() >= l) {
            return Ok(());
        }
        let Some(value) = cursor.value_ref() else {
            return Ok(());
        };
        let key = Nibbles::from_nibbles(path)
            .to_bytes()
            .ok_or(MptError::OddDepthValue)?;
        let include = match after {
            Some(a) => key.as_slice() > a,
            None => true,
        };
        if include {
            out.push((key, self.resolve(value)?));
        }
        Ok(())
    }

    // ---- completeness and reachability ------------------------------------

    /// True if the whole trie under `root` is present locally and servable.
    ///
    /// Computed from the trie, never assumed from a head naming the root — but
    /// computed *once* per root: a full walk is not a per-`Hello` cost a
    /// converged cluster should pay (§5.1), and a content-addressed root that
    /// was complete cannot become incomplete — no node is ever rewritten under
    /// an existing hash, and GC marks from every head a root reaches through.
    pub fn is_complete(&self, root: Hash) -> Result<bool, MptError> {
        self.is_complete_scoped(root, &Scope::full())
    }

    /// True if everything under `root` *that `scope` admits* is present.
    ///
    /// Completeness is a property of a root *and* a scope: a trie held whole
    /// within one grant is not held whole within a wider one. The memo is keyed
    /// by both, so widening a scope re-derives rather than inheriting.
    // LEAN-MODEL: mpt-complete-scoped (ScopedSync.CompleteWithin)
    // `ScopedSync.CompleteWithin`: every position the scoped walk reaches is
    // held or a boundary, and every expanded node has its value.
    pub fn is_complete_scoped(&self, root: Hash, scope: &Scope) -> Result<bool, MptError> {
        self.is_complete_scoped_for(None, root, scope)
    }

    /// [`Trie::is_complete_scoped`] with provenance: for `Some(owner)`, every
    /// admitted node under `root` must have been served as `owner`'s
    /// ([`NodeStore::owns_node`]), not merely be present.
    ///
    /// This is the question a member asks of a confined origin's head before
    /// it vouches for it (§5.5): a trie assembled out of nodes the origin was
    /// never shown is not complete however many of them this store holds.
    /// Memoized under a key of its own, since it is a stricter question than
    /// either of the other two.
    // LEAN-MODEL: mpt-complete-owned (Provenance.step_sound)
    // `Provenance.withheld_root_incomplete`: a confined origin's root that
    // reaches a node the origin could not legitimately hold never completes.
    pub fn is_complete_scoped_for(
        &self,
        owner: Option<&OriginId>,
        root: Hash,
        scope: &Scope,
    ) -> Result<bool, MptError> {
        let memo = scope.memo_key_for(owner, root);
        if Self::wrap(self.store.is_known_complete(&memo))? {
            return Ok(true);
        }
        let generation = Self::wrap(self.store.completeness_generation())?;
        let complete = MissingWalk::for_origin(owner.cloned(), None, root, scope.clone())
            .next_batch(self, 1)?
            .is_empty();
        if complete {
            // A concurrent write may have dissolved a boundary while this walk
            // ran. In that case the caller must retry on a fresh snapshot.
            return Self::wrap(self.store.note_complete_at(&memo, generation));
        }
        Ok(complete)
    }

    /// Resolves claimed positions against `root`, returning what actually
    /// stands at each one.
    ///
    /// The responder's half of a scoped fetch (§5.5): the caller says where it
    /// believes a node sits; this descends from a root the responder itself
    /// holds and reports what is really there, so a position cannot be claimed
    /// into existence — a fabricated root fails at the first step, because the
    /// descent reads this store and nothing else.
    ///
    /// One merged descent over the sorted paths shares every prefix two wants
    /// have in common: a batch is the frontier of a single walk, so the cost is
    /// close to trie depth plus batch size, not their product.
    // LEAN-MODEL: mpt-resolve-position (ScopedSync.At)
    // `ScopedSync.At`; `At.unique` is why a position names one hash, given
    // `check_invariants`' non-empty extension prefix.
    pub fn resolve_paths(
        &self,
        root: Hash,
        paths: &[Vec<u8>],
    ) -> Result<Vec<Option<Hash>>, MptError> {
        let mut order: Vec<usize> = (0..paths.len()).collect();
        order.sort_by(|&a, &b| paths[a].cmp(&paths[b]));

        let mut out = vec![None; paths.len()];
        // The previous descent, as `(nibbles consumed, hash standing there)`,
        // together with the path it was walked along. Retained between wants
        // so a shared prefix is walked once.
        let mut trail: Vec<(usize, Hash)> = Vec::new();
        let mut walked: Vec<u8> = Vec::new();
        for &index in &order {
            let path = &paths[index];
            // Rewind to the deepest point of the previous descent that this
            // path still agrees with.
            while let Some(&(depth, _)) = trail.last() {
                if depth <= path.len() && walked[..depth] == path[..depth] {
                    break;
                }
                trail.pop();
            }
            let (mut consumed, mut current) = match trail.last() {
                Some(&(depth, hash)) => (depth, Some(hash)),
                None => (0, root_opt(root)),
            };
            let resolved = loop {
                let Some(hash) = current else { break None };
                if consumed == path.len() {
                    break Some(hash);
                }
                let Some(data) = self.load_raw(&hash)? else {
                    break None;
                };
                match TrieNode::decode(&data)? {
                    TrieNode::Branch { children, .. } => {
                        let slot = path[consumed] as usize;
                        if slot >= 16 {
                            break None;
                        }
                        current = children[slot];
                        consumed += 1;
                    }
                    TrieNode::Ext { prefix, child } => {
                        let prefix = prefix.as_slice();
                        if path.len() - consumed < prefix.len()
                            || &path[consumed..consumed + prefix.len()] != prefix
                        {
                            break None;
                        }
                        current = Some(child);
                        consumed += prefix.len();
                    }
                    // A leaf holds no positions below itself, so a path that
                    // continues past one names nothing.
                    TrieNode::Leaf { .. } => break None,
                }
                if let Some(hash) = current {
                    trail.push((consumed, hash));
                }
            };
            out[index] = resolved;
            walked.clear();
            walked.extend_from_slice(path);
        }
        Ok(out)
    }

    /// The first key under `root` that `scope` does not admit, if there is one.
    ///
    /// The publish-scope question (§3.5): a delegated origin's trie must hold
    /// nothing outside its granted spaces, and a head whose trie does is
    /// refused whole rather than materialized in part.
    ///
    /// Cheap despite sounding like a full scan: the walk descends only where
    /// the boundary is unresolved — a position already *inside* a granted
    /// prefix cannot lead out of it, so its subtree is skipped — and visits on
    /// the order of trie depth times the number of granted prefixes.
    ///
    /// An absent node stops that branch rather than raising: this is asked of
    /// a trie about to be promoted, where absence was already settled by fetch.
    // LEAN-MODEL: mpt-first-key-outside (ScopedSync.keys_below_grant_admitted)
    // `ScopedSync.keys_below_grant_admitted`: skipping a position inside a
    // granted prefix loses no key outside the grant.
    pub fn first_key_outside(
        &self,
        root: Hash,
        scope: &Scope,
    ) -> Result<Option<Vec<u8>>, MptError> {
        if scope.is_full() {
            return Ok(None);
        }
        let mut stack = match root_opt(root) {
            None => return Ok(None),
            Some(hash) => vec![(hash, Vec::<u8>::new())],
        };
        while let Some((hash, path)) = stack.pop() {
            if scope.contains_subtree(&path) {
                continue;
            }
            let Some(data) = self.load_raw(&hash)? else {
                continue;
            };
            match TrieNode::decode(&data)? {
                TrieNode::Leaf { key_rest, .. } => {
                    let mut key = path;
                    key.extend_from_slice(key_rest.as_slice());
                    if !scope.admits_key_path(&key) {
                        return Ok(Some(key));
                    }
                }
                TrieNode::Ext { prefix, child } => {
                    let mut child_path = path;
                    child_path.extend_from_slice(prefix.as_slice());
                    if !scope.admits_path(&child_path) {
                        return Ok(Some(child_path));
                    }
                    stack.push((child, child_path));
                }
                TrieNode::Branch { children, value } => {
                    // A branch may itself carry a value, and that value's key
                    // is the branch's own position.
                    if value.is_some() && !scope.admits_key_path(&path) {
                        return Ok(Some(path.clone()));
                    }
                    for (slot, child) in children.iter().enumerate() {
                        let Some(child) = child else { continue };
                        let mut child_path = path.clone();
                        child_path.push(slot as u8);
                        if !scope.admits_path(&child_path) {
                            return Ok(Some(child_path));
                        }
                        stack.push((*child, child_path));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Everything reachable from `root`, for mark-and-sweep GC (§5.4).
    ///
    /// Missing nodes are skipped rather than raising: GC must be able to mark
    /// from a partially fetched pending head without failing.
    pub fn reachable(&self, root: Hash) -> Result<Reachable, MptError> {
        let mut out = Reachable::default();
        self.reach_into(root, &mut out)?;
        Ok(out)
    }

    /// The same walk, accumulating into a mark set that already holds what
    /// earlier roots reached.
    ///
    /// Successive roots of one origin share all but the path that changed
    /// (§4.3), so walking each retained root into a fresh set would re-read the
    /// entire trie once per root: `head_history` keeps a row per publish for
    /// `root_retention` (7 days), thousands of roots, all inside the single
    /// `BEGIN IMMEDIATE` that holds the one write connection, every five
    /// minutes. Sharing the visited set collapses that to one walk of the live
    /// node set plus each root's own delta — what §5.4's "runs incrementally"
    /// means.
    ///
    /// A hash already in `out.nodes` has had its subtree walked by definition,
    /// so skipping it is exactly the dedup the single-root walk does.
    pub fn reach_into(&self, root: Hash, out: &mut Reachable) -> Result<(), MptError> {
        let mut frontier = match root_opt(root) {
            None => return Ok(()),
            Some(h) => vec![h],
        };
        while let Some(hash) = frontier.pop() {
            if !out.nodes.insert(hash) {
                continue;
            }
            let Some(data) = Self::wrap(self.store.get_node(&hash))? else {
                continue;
            };
            let node = TrieNode::decode(&data)?;
            frontier.extend(node.child_hashes());
            out.values.extend(node.value_hashes());
        }
        Ok(())
    }
}

/// True if every key under nibble path `path` sorts at or before `after`.
///
/// Used to prune whole subtrees when resuming a scan from a continuation token.
fn subtree_is_below(path: &[u8], after: &[u8]) -> bool {
    let shared = path.len().min(after.len());
    match path[..shared].cmp(&after[..shared]) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        // A prefix of `after`: the subtree may straddle the cursor, so descend.
        std::cmp::Ordering::Equal => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemStore;

    /// Fetches everything a walk asks for from `source` into `into`, and
    /// returns the requested positions, in order.
    fn drain<S: NodeStore>(
        walk: &mut MissingWalk,
        source: &MemStore,
        into: &S,
    ) -> Vec<(Vec<u8>, Hash)> {
        let mut wanted = Vec::new();
        loop {
            let batch = MissingWalk::next_batch(walk, &Trie::new(into), 64).unwrap();
            if batch.is_empty() {
                break;
            }
            for (path, hash) in &batch.nodes {
                wanted.push((path.clone(), *hash));
                let bytes = source.get_node(hash).unwrap().unwrap();
                into.put_node(hash, &bytes).unwrap();
            }
            for (_, hash) in &batch.values {
                let bytes = source.get_value(hash).unwrap().unwrap();
                into.put_value(hash, &bytes).unwrap();
            }
            walk.resume();
        }
        wanted
    }

    /// A walk confined to one space must ask for the spine — which is what
    /// makes the signed root recomputable — and never for a sibling subtree,
    /// whose hash it nonetheless holds (§5.5).
    #[test]
    fn a_scoped_walk_asks_for_the_spine_and_never_the_sibling() {
        let source = MemStore::new();
        let trie = Trie::new(&source);
        let mut root = Hash::EMPTY;
        for key in [
            b"f:photos/a.jpg".as_slice(),
            b"f:photos/b.jpg".as_slice(),
            b"f:finance/q3.pdf".as_slice(),
            b"f:finance/q4.pdf".as_slice(),
        ] {
            root = trie.insert(root, key, key).unwrap();
        }

        // Everything the scoped walk would ever fetch, from an empty store.
        let empty = MemStore::new();
        let scope = Scope::of(&synch_core::ScopeKeys {
            prefixes: vec![b"f:photos/".to_vec()],
            exact: Vec::new(),
        });
        let mut walk = MissingWalk::scoped(None, root, scope.clone());
        let wanted = drain(&mut walk, &source, &empty);

        assert!(!wanted.is_empty(), "the walk fetched nothing at all");
        // Every position asked for is one the scope admits — an honest walk
        // never generates a request its peer would refuse.
        for (path, _) in &wanted {
            assert!(
                scope.admits_path(path),
                "the walk asked for a position outside its scope"
            );
        }
        // The granted space is wholly present; the withheld one is not.
        let scoped = Trie::new(&empty);
        assert_eq!(
            scoped.get(root, b"f:photos/a.jpg").unwrap().as_deref(),
            Some(b"f:photos/a.jpg".as_slice())
        );
        assert!(scoped.get(root, b"f:finance/q3.pdf").is_err());
        // And the walk considers itself done: complete *within its scope*,
        // while plainly not holding the trie whole.
        assert!(scoped.is_complete_scoped(root, &scope).unwrap());
        assert!(!scoped.is_complete(root).unwrap());
    }

    /// A scoped walk deduplicates spine visits by position, not by hash. The
    /// same node can stand at two positions the scope admits — here an
    /// extension spelling `photos/`, under `f:` where it leads into the grant
    /// and under `m:space/` where it leads out of it (§5.5). Whichever is
    /// walked first must not stand in for the other, or the children admitted
    /// under only the second are never asked for and the walk calls a trie
    /// complete that is missing part of the grant.
    #[test]
    fn a_node_at_two_spine_positions_is_visited_at_both() {
        let source = MemStore::new();
        let trie = Trie::new(&source);
        let mut root = Hash::EMPTY;
        // The subtree under `photos/` is byte-identical in both places, so
        // the extension above it is one node with two positions; `finance`
        // beside each makes both parents branches, so both positions exist.
        for key in [
            b"f:photos/a".as_slice(),
            b"f:photos/b".as_slice(),
            b"f:finance/x".as_slice(),
            b"m:space/photos/a".as_slice(),
            b"m:space/photos/b".as_slice(),
            b"m:space/finance".as_slice(),
        ] {
            let value = key.rsplit(|b| *b == b'/').next().unwrap();
            root = trie.insert(root, key, value).unwrap();
        }
        let scope = Scope::of(&synch_core::scope_prefixes(&["photos".to_string()]));
        let f_side = Nibbles::from_bytes(b"f:p").as_slice()[..5].to_vec();
        let m_side = Nibbles::from_bytes(b"m:space/p").as_slice()[..17].to_vec();
        let positions = trie
            .resolve_paths(root, &[f_side.clone(), m_side.clone()])
            .unwrap();
        assert_eq!(positions[0], positions[1], "the shape is not self-similar");
        assert!(scope.admits_path(&f_side) && scope.admits_path(&m_side));
        // Walked first, because the frontier is a stack and `m:` sorts after
        // `f:` in the root branch.
        let empty = MemStore::new();
        let mut walk = MissingWalk::scoped(None, root, scope.clone());
        let asked = drain(&mut walk, &source, &empty);
        assert!(asked.iter().any(|(path, _)| path == &f_side));
        assert!(asked.iter().any(|(path, _)| path == &m_side));

        let scoped = Trie::new(&empty);
        assert_eq!(
            scoped.get(root, b"f:photos/a").unwrap().as_deref(),
            Some(b"a".as_slice()),
            "the grant was not fetched: the spine visit under `m:` stood in for the one under `f:`"
        );
        assert!(scoped.is_complete_scoped(root, &scope).unwrap());
        // The subtree the `m:` position leads to was never asked for at that
        // position — every request was admitted — though being the same
        // nodes, it is of course readable there too.
        assert!(asked.iter().all(|(path, _)| scope.admits_path(path)));
        assert!(scoped.get(root, b"m:space/finance").is_err());
    }

    /// With an owner, presence is provenance: a node this store holds from
    /// another origin's trie is asked for again under a confined origin's
    /// root, and only a node served as that origin's counts (§5.5). This is
    /// the walk's half of closing the graft: a delegate that places a withheld
    /// subtree's hash in its own trie cannot serve the subtree, so the head
    /// never completes on any member.
    #[test]
    fn presence_with_an_owner_is_provenance() {
        let store = MemStore::new();
        let trie = Trie::new(&store);
        let mut root = Hash::EMPTY;
        for key in [b"f:photos/a.jpg".as_slice(), b"f:finance/q3.pdf".as_slice()] {
            root = trie.insert(root, key, key).unwrap();
        }
        let owner = synch_core::OriginId::Named {
            domain: "cluster.example".to_string(),
            id: "grafter".to_string(),
        };

        // Held whole, but as nobody's: judged by presence the trie is complete,
        // judged as `owner`'s nothing of it is.
        assert!(trie.is_complete(root).unwrap());
        assert!(!trie
            .is_complete_scoped_for(Some(&owner), root, &Scope::full())
            .unwrap());
        let mut walk = MissingWalk::for_origin(Some(owner.clone()), None, root, Scope::full());
        let missing = walk.next_batch(&trie, 64).unwrap();
        assert_eq!(
            missing.nodes,
            vec![(Vec::new(), root)],
            "the root is asked for again"
        );

        // Served as the owner's, node by node, the walk drains; what it asked
        // for is exactly what it now owns.
        let mut owned = vec![root];
        store.note_owned(&owner, &root).unwrap();
        walk.resume();
        loop {
            let batch = walk.next_batch(&trie, 64).unwrap();
            if batch.is_empty() {
                break;
            }
            for (_, hash) in &batch.nodes {
                store.note_owned(&owner, hash).unwrap();
                owned.push(*hash);
            }
            walk.resume();
        }
        assert!(walk.is_exhausted());
        assert!(trie
            .is_complete_scoped_for(Some(&owner), root, &Scope::full())
            .unwrap());
        for (_, hash) in walk_positions(&store, root) {
            assert!(owned.contains(&hash), "a node completed without provenance");
        }
        // The two memos are distinct questions.
        assert_ne!(
            Scope::full().memo_key_for(Some(&owner), root),
            Scope::full().memo_key(root)
        );
    }

    /// Every node of `root`'s trie by position, over a store holding it whole.
    fn walk_positions(store: &MemStore, root: Hash) -> Vec<(Vec<u8>, Hash)> {
        let empty = MemStore::new();
        let mut walk = MissingWalk::new(root);
        let mut all = Vec::new();
        loop {
            let batch = walk.next_batch(&Trie::new(&empty), 64).unwrap();
            if batch.is_empty() {
                break;
            }
            for (path, hash) in &batch.nodes {
                all.push((path.clone(), *hash));
                empty
                    .put_node(hash, &store.get_node(hash).unwrap().unwrap())
                    .unwrap();
            }
            walk.resume();
        }
        all
    }

    /// A node this store holds is expanded wherever the walk meets it, even if
    /// a peer once refused the same hash at this position. Treating a *held*
    /// node as a boundary would let the walk stop above an absent in-grant
    /// subtree and call the trie complete — and would let Lean's edge pairing
    /// follow, as a reference, a node whose subtree the reference root's own
    /// walk never fetched (`ScopedSync.paired_reaches`).
    #[test]
    fn a_held_node_is_never_a_boundary() {
        let source = MemStore::new();
        let trie = Trie::new(&source);
        let mut root = Hash::EMPTY;
        for key in [
            b"f:photos/a.jpg".as_slice(),
            b"f:photos/b.jpg".as_slice(),
            b"f:finance/q3.pdf".as_slice(),
        ] {
            root = trie.insert(root, key, key).unwrap();
        }
        let scope = Scope::of(&synch_core::ScopeKeys {
            prefixes: vec![b"f:photos/".to_vec()],
            exact: Vec::new(),
        });
        let local = RedactingStore::default();
        drain(
            &mut MissingWalk::scoped(None, root, scope.clone()),
            &source,
            &local,
        );
        let scoped = Trie::new(&local);
        assert!(scoped.is_complete_scoped(root, &scope).unwrap());

        // The spine branch at `f:` — above the grant — and the photos subtree
        // hanging off its `p` slot.
        let spine = Nibbles::from_bytes(b"f:").as_slice().to_vec();
        let mut photos_at = spine.clone();
        photos_at.push(0x7);
        let resolved = trie
            .resolve_paths(root, &[spine.clone(), photos_at.clone()])
            .unwrap();
        let (branch, photos) = (resolved[0].unwrap(), resolved[1].unwrap());

        // A refusal of the spine branch at its own position arrives, and the
        // photos subtree goes missing.
        local.note_redacted(&branch, &spine).unwrap();
        local.remove_node(&photos);
        assert!(
            !scoped.is_complete_scoped(root, &scope).unwrap(),
            "a held node was treated as a boundary and hid an absent in-grant subtree"
        );
        let missing = MissingWalk::scoped(None, root, scope)
            .next_batch(&scoped, 64)
            .unwrap();
        assert_eq!(missing.nodes, vec![(photos_at, photos)]);
    }

    /// A store that remembers refusals and can forget a node — what the
    /// boundary test needs and `MemStore` does not do.
    #[derive(Default)]
    struct RedactingStore {
        inner: MemStore,
        redacted: std::sync::Mutex<HashSet<(Hash, Vec<u8>)>>,
    }

    impl RedactingStore {
        fn remove_node(&self, hash: &Hash) {
            self.inner.remove_node(hash);
        }
    }

    impl NodeStore for RedactingStore {
        type Error = std::convert::Infallible;

        fn get_node(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner.get_node(hash)
        }

        fn put_node(&self, hash: &Hash, data: &[u8]) -> Result<(), Self::Error> {
            self.inner.put_node(hash, data)
        }

        fn get_value(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Self::Error> {
            self.inner.get_value(hash)
        }

        fn put_value(&self, hash: &Hash, data: &[u8]) -> Result<(), Self::Error> {
            self.inner.put_value(hash, data)
        }

        fn is_redacted(&self, hash: &Hash, path: Option<&[u8]>) -> Result<bool, Self::Error> {
            let redacted = self.redacted.lock().unwrap();
            Ok(match path {
                Some(path) => redacted.contains(&(*hash, path.to_vec())),
                None => redacted.iter().any(|(h, _)| h == hash),
            })
        }

        fn note_redacted(&self, hash: &Hash, path: &[u8]) -> Result<(), Self::Error> {
            self.redacted.lock().unwrap().insert((*hash, path.to_vec()));
            Ok(())
        }
    }

    /// Position, not hash, is what a scoped fetch may be authorized on: a path
    /// that stops partway through an extension names nothing, so a fabricated
    /// position is unresolvable rather than merely wrong (§5.5).
    #[test]
    fn a_claimed_position_resolves_to_what_is_really_there() {
        let source = MemStore::new();
        let trie = Trie::new(&source);
        let mut root = Hash::EMPTY;
        for key in [
            b"f:photos/a.jpg".as_slice(),
            b"f:photos/b.jpg".as_slice(),
            b"f:finance/q3.pdf".as_slice(),
        ] {
            root = trie.insert(root, key, key).unwrap();
        }

        // The positions a real walk emits, paired with the hashes it claims
        // for them. This is exactly what a request carries.
        let empty = MemStore::new();
        let mut walk = MissingWalk::new(root);
        let wants = drain(&mut walk, &source, &empty);
        assert!(wants.len() > 1, "the trie is too small to be a test");

        // Every position the walk claimed resolves, on the server's own copy,
        // to exactly the hash it claimed.
        let paths: Vec<Vec<u8>> = wants.iter().map(|(p, _)| p.clone()).collect();
        let resolved = trie.resolve_paths(root, &paths).unwrap();
        for (i, (_, claimed)) in wants.iter().enumerate() {
            assert_eq!(
                resolved[i],
                Some(*claimed),
                "a real position did not resolve"
            );
        }

        // A position that names nothing resolves to nothing, so a hash cannot
        // be reached by claiming a place for it.
        let nowhere = Nibbles::from_bytes(b"zzzz").as_slice().to_vec();
        assert_eq!(trie.resolve_paths(root, &[nowhere]).unwrap()[0], None);

        // The merged descent must agree with resolving each path alone:
        // sharing prefixes between wants is an optimization and must never
        // become an answer.
        for (i, path) in paths.iter().enumerate() {
            let alone = trie
                .resolve_paths(root, std::slice::from_ref(path))
                .unwrap();
            assert_eq!(resolved[i], alone[0], "batching changed an answer");
        }
    }

    /// A delegated origin publishing outside its spaces is caught, by walking
    /// the spine rather than the trie (§3.5).
    #[test]
    fn a_key_outside_the_scope_is_found() {
        let store = MemStore::new();
        let trie = Trie::new(&store);
        let mut root = Hash::EMPTY;
        for key in [b"f:photos/a.jpg".as_slice(), b"f:photos/b.jpg".as_slice()] {
            root = trie.insert(root, key, key).unwrap();
        }
        let scope = Scope::of(&synch_core::ScopeKeys {
            prefixes: vec![b"f:photos/".to_vec()],
            exact: Vec::new(),
        });
        assert_eq!(trie.first_key_outside(root, &scope).unwrap(), None);

        // One record outside the grant, and the whole head is refusable.
        let root = trie.insert(root, b"f:finance/q3.pdf", b"x").unwrap();
        let offending = trie.first_key_outside(root, &scope).unwrap();
        assert!(offending.is_some(), "an out-of-scope key went unnoticed");
        assert!(!scope.admits_path(&offending.unwrap()));

        // A full scope has nothing to find, however the trie is shaped.
        assert_eq!(trie.first_key_outside(root, &Scope::full()).unwrap(), None);
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    /// The guard stops a walk at exactly the ceiling, driven directly in
    /// microseconds; the end-to-end wiring twin lives `#[ignore]`d in
    /// fanout_bomb.rs because it must walk all 8 000 000 positions.
    #[test]
    fn the_walk_guard_stops_at_the_ceiling() {
        let mut guard = FanoutGuard::default();
        for i in 0..WALK_POSITION_CEILING {
            guard
                .visit()
                .unwrap_or_else(|e| panic!("refused at position {i}, under the ceiling: {e}"));
        }
        let err = guard.visit().expect_err("the ceiling must be enforced");
        assert!(err.to_string().contains("exceeded"), "{err}");
    }
}
