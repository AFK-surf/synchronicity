//! Trie operations: get, insert, remove, iterate, and completeness walks (§4.3).

use std::collections::HashSet;

use synch_core::{Hash, MAX_KEY_LEN};

use crate::{
    error::MptError,
    nibbles::{common_prefix_len, Nibbles},
    node::{TrieNode, ValueRef, NO_CHILDREN},
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
    /// A node, with the hash it was loaded from when the position is a whole
    /// stored node rather than the virtual remainder of a compressed one.
    At {
        /// The stored node's hash, or `None` part-way through a compressed node.
        ///
        /// This is a walk's identity for the position. Two positions carrying
        /// the same hash have the same subtree beneath them, which is what lets
        /// a walk over a peer's node *graph* — a DAG, not a tree — avoid
        /// re-descending a subtree it has already covered.
        hash: Option<Hash>,
        /// The node itself.
        node: TrieNode,
    },
}

impl Cursor {
    fn is_empty(&self) -> bool {
        matches!(self, Cursor::Empty)
    }

    /// The identity of this position, for walk memoization, or `None` when the
    /// position has none.
    ///
    /// A cursor part-way through a compressed node is *not* identified: the
    /// synthetic remainder it carries depends on the path taken into it, so two
    /// unrelated positions would otherwise collide under one key and a walk
    /// would prune a subtree it had never visited. Those positions need no
    /// memo — they are bounded by the node's own nibble run, which
    /// [`TrieNode::hash_of_encoded`] caps at `MAX_KEY_LEN * 2`.
    pub(crate) fn identity(&self) -> Option<PositionId> {
        match self {
            Cursor::Empty => Some(PositionId::Empty),
            Cursor::At { hash, .. } => hash.map(PositionId::Node),
        }
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

/// What identifies a walk position, when anything does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PositionId {
    /// Nothing is stored here.
    Empty,
    /// A stored node.
    Node(Hash),
}

/// How many times one distinct stored node may be arrived at.
///
/// Structural sharing makes this greater than one for honest data — two keys
/// whose suffixes and values coincide share a leaf — but only by a small
/// factor, because sharing requires the subtries to be *identical*. The case
/// this exists to catch misses by orders of magnitude.
const WALK_REVISIT_RATIO: usize = 16;

/// A floor below which the ratio is not applied, so small tries are never
/// refused for being lopsided. Also the bounded worst case: a walk that is
/// going to be refused does at most this much work first.
const WALK_REVISIT_FLOOR: usize = 65_536;

/// An absolute ceiling on positions of every kind, as a backstop for the
/// compressed-node traversal the ratio deliberately does not count.
const WALK_POSITION_CEILING: usize = 64_000_000;

/// Keeps a structural walk proportional to the trie it is walking.
///
/// A walk over trie *structure* descends positions, and a peer's node graph is
/// a DAG rather than a tree: nothing stops a branch pointing all sixteen
/// children at one hash. Sixteen such branches stacked are seventeen distinct
/// nodes — which `MissingWalk` fetches happily, because it dedups on hash, and
/// which `is_complete` then passes — and 16^16 positions to walk. Depth bounds
/// do not help; the explosion is in breadth.
///
/// Deduping positions by node hash is *not* the fix, and looks like it is:
/// structural sharing means one leaf node legitimately sits at as many
/// positions as there are keys with that value, so pruning repeats silently
/// drops keys from `scan` and changes from `diff`.
///
/// What separates the two cases is how often a *stored node* is arrived at. A
/// walk over an honest trie reaches each stored node about once — sharing makes
/// it a few times, never many, because sharing requires whole subtries to
/// coincide. A fan-out DAG holds its node count still while arrivals multiply,
/// so it blows the ratio immediately.
///
/// Only positions that *are* a stored node are counted against it. A cursor
/// part-way through a compressed node has no hash, and there are legitimately
/// many of those — one per nibble of the run — so counting them measured depth
/// rather than fan-out and refused ordinary tries. They are bounded instead by
/// the per-node nibble cap and by [`WALK_POSITION_CEILING`].
#[derive(Debug, Default)]
pub(crate) struct FanoutGuard {
    /// Positions of every kind, against the absolute ceiling.
    positions: usize,
    /// Positions that are a whole stored node, against the ratio.
    arrivals: usize,
    nodes: HashSet<Hash>,
}

impl FanoutGuard {
    /// Records one visited position, failing if the walk has outrun the trie.
    pub(crate) fn visit(
        &mut self,
        ids: impl IntoIterator<Item = PositionId>,
    ) -> Result<(), MptError> {
        self.positions += 1;
        if self.positions > WALK_POSITION_CEILING {
            return Err(MptError::NonCanonical(format!(
                "structural walk exceeded {WALK_POSITION_CEILING} positions"
            )));
        }
        for id in ids {
            if let PositionId::Node(hash) = id {
                self.arrivals += 1;
                self.nodes.insert(hash);
            }
        }
        let allowed = WALK_REVISIT_FLOOR.max(self.nodes.len().saturating_mul(WALK_REVISIT_RATIO));
        if self.arrivals > allowed {
            return Err(MptError::NonCanonical(format!(
                "structural walk arrived at {} node positions over {} distinct nodes, \
                 which no key set can produce",
                self.arrivals,
                self.nodes.len()
            )));
        }
        Ok(())
    }
}

/// One level of an explicit walk stack: the cursor at that level, and which
/// child nibble to visit next.
#[derive(Debug)]
pub(crate) struct Frame {
    pub(crate) cursor: Cursor,
    pub(crate) next: u8,
}

/// Maps the empty-trie sentinel onto `None`.
pub fn root_opt(root: Hash) -> Option<Hash> {
    if root.is_empty_sentinel() {
        None
    } else {
        Some(root)
    }
}

/// The set of hashes referenced by a root but absent from the store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Missing {
    /// Trie nodes that must be fetched.
    pub nodes: Vec<Hash>,
    /// Out-of-line values that must be fetched.
    pub values: Vec<Hash>,
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
/// A fetch asks "what does this root need?" repeatedly, a batch at a time, and
/// two things about how it asks decide what the whole exchange costs.
///
/// **It resumes.** Restarting the walk at the root for every batch makes a cold
/// fetch quadratic: each round re-descends everything already fetched to reach
/// the next batch of absent nodes, so a trie of `n` nodes costs roughly
/// `n²/batch` node reads. The walk therefore holds its frontier across batches
/// and only revisits a node once the caller has stored it.
///
/// **It prunes against what is already held.** Content addressing makes
/// subtree *equality* free — matching hashes are the same subtree — but says
/// nothing about whether a subtree is *held*, and a node is committed the
/// moment it arrives, so a present node's children may well be absent. That is
/// why a walk cannot simply stop at a node it has. Given a root it holds
/// *whole*, though, it can: a hash appearing in that trie is a subtree it has
/// all of. Handed the origin's last complete root, the walk skips everything
/// the new root shares with it and descends only the paths that actually
/// changed — which is what makes an incremental sync cost the change rather
/// than the tree (§5.2).
#[derive(Debug)]
pub struct MissingWalk {
    /// `(the hash at this position in the reference trie, the hash wanted)`.
    frontier: Vec<(Option<Hash>, Hash)>,
    seen: HashSet<Hash>,
    /// Reported absent and awaiting the caller's fetch, so they can be
    /// revisited — and their children discovered — once they land.
    deferred: Vec<(Option<Hash>, Hash)>,
}

impl MissingWalk {
    /// A walk over everything reachable from `root`, pruning nothing.
    pub fn new(root: Hash) -> MissingWalk {
        MissingWalk::since(None, root)
    }

    /// A walk that skips every subtree `root` shares with `known_complete`.
    ///
    /// The reference root must be one this store holds in full; pass `None`
    /// when there is no such root, or when it has not been established. A
    /// wrong reference would have the walk skip subtrees it does not hold, and
    /// report a trie complete that it cannot serve.
    pub fn since(known_complete: Option<Hash>, root: Hash) -> MissingWalk {
        let frontier = match root_opt(root) {
            None => Vec::new(),
            Some(root) => vec![(known_complete.and_then(root_opt), root)],
        };
        MissingWalk {
            frontier,
            seen: HashSet::new(),
            deferred: Vec::new(),
        }
    }

    /// True once the walk has covered everything and nothing is outstanding.
    pub fn is_exhausted(&self) -> bool {
        self.frontier.is_empty() && self.deferred.is_empty()
    }

    /// Re-queues everything reported absent, for after the caller has stored
    /// it. Nodes that arrived expand into their children; ones that did not
    /// are reported again, which is what lets a caller notice it is making no
    /// progress.
    pub fn resume(&mut self) {
        for (reference, hash) in self.deferred.drain(..) {
            self.seen.remove(&hash);
            self.frontier.push((reference, hash));
        }
    }

    /// Walks until `max` absent hashes are found or the frontier drains.
    pub fn next_batch<S: NodeStore + ?Sized>(
        &mut self,
        trie: &Trie<'_, S>,
        max: usize,
    ) -> Result<Missing, MptError> {
        let mut missing = Missing::default();
        // Two nodes in one batch may reference the same out-of-line value —
        // structural sharing is exactly that — and the hash is reported once:
        // a duplicate asks the peer for the same bytes twice in one request.
        let mut values_seen: HashSet<Hash> = HashSet::new();
        while let Some((reference, hash)) = self.frontier.pop() {
            if missing.len() >= max {
                self.frontier.push((reference, hash));
                break;
            }
            // The same hash in a trie held whole: this subtree is already here,
            // values and all.
            if reference == Some(hash) {
                continue;
            }
            if !self.seen.insert(hash) {
                continue;
            }
            let Some(data) = trie.load_raw(&hash)? else {
                missing.nodes.push(hash);
                self.deferred.push((reference, hash));
                continue;
            };
            let node = TrieNode::decode(&data)?;
            let reference_node = match reference {
                Some(reference) => trie
                    .load_raw(&reference)?
                    .map(|bytes| TrieNode::decode(&bytes))
                    .transpose()?,
                None => None,
            };
            self.frontier
                .extend(paired_children(reference_node.as_ref(), &node));
            // A node whose out-of-line values have not arrived is not done
            // with. Reporting the value once and moving on made the walk claim
            // exhaustion over a trie it could not serve: the node loaded, so it
            // was never deferred, and `seen` kept it from ever being revisited.
            // The fetch loop then broke out with its unproductive counter at
            // one, so the §5.2 abandonment clause could never fire for a
            // value-only failure, and `note_complete` vouched for the root.
            let mut awaiting_values = false;
            for value_hash in node.value_hashes() {
                if !values_seen.insert(value_hash) {
                    continue;
                }
                if !trie.has_value_raw(&value_hash)? {
                    missing.values.push(value_hash);
                    awaiting_values = true;
                }
            }
            if awaiting_values {
                self.deferred.push((reference, hash));
            }
        }
        Ok(missing)
    }
}

/// Pairs a node's children with the ones at the same positions in the
/// reference trie, so the walk can prune where the two agree.
///
/// Pairing is only attempted where the two nodes have the same shape. Anywhere
/// else the children are walked with no reference, which costs traversal and
/// never correctness — pruning is an optimization, and declining to prune is
/// always safe.
fn paired_children(reference: Option<&TrieNode>, node: &TrieNode) -> Vec<(Option<Hash>, Hash)> {
    match (reference, node) {
        (
            Some(TrieNode::Branch {
                children: theirs, ..
            }),
            TrieNode::Branch { children, .. },
        ) => children
            .iter()
            .enumerate()
            .filter_map(|(i, child)| child.map(|child| (theirs[i], child)))
            .collect(),
        (
            Some(TrieNode::Ext {
                prefix: their_prefix,
                child: their_child,
            }),
            TrieNode::Ext { prefix, child },
        ) if their_prefix == prefix => vec![(Some(*their_child), *child)],
        (_, node) => node
            .child_hashes()
            .into_iter()
            .map(|child| (None, child))
            .collect(),
    }
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
    pub fn get(&self, root: Hash, key: &[u8]) -> Result<Option<Vec<u8>>, MptError> {
        let nibbles = Nibbles::from_bytes(key);
        let mut rest = nibbles.as_slice();
        let mut current = root_opt(root);
        // Every hop consumes at least one nibble (an empty extension prefix is
        // rejected both here and at the ingest boundary), so a valid key of
        // `MAX_KEY_LEN` bytes resolves in at most `MAX_DEPTH_NIBBLES` hops —
        // plus one step that loads the root. The structural walks agree:
        // `collect`/`diff` still examine a position *at* `MAX_DEPTH_NIBBLES`
        // and prune only below it, so a value at exactly that depth is
        // readable here too. The guard exists because `get` is the one descent
        // with no explicit stack to bound it: a chain of zero-progress nodes
        // would otherwise turn one lookup into one store read per node.
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

    fn insert_at(
        &self,
        node: Option<Hash>,
        key: &[u8],
        value: &ValueRef,
    ) -> Result<Hash, MptError> {
        match node {
            None => self.put(&TrieNode::leaf(Nibbles::from_nibbles(key), value.clone())),
            Some(hash) => {
                let node = self.load(&hash)?;
                self.insert_into(node, key, value)
            }
        }
    }

    fn insert_into(&self, node: TrieNode, key: &[u8], value: &ValueRef) -> Result<Hash, MptError> {
        match node {
            TrieNode::Leaf {
                key_rest,
                value: old,
            } => {
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
                    let child =
                        self.put(&TrieNode::leaf(Nibbles::from_nibbles(&existing[1..]), old))?;
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
            TrieNode::Ext { prefix, child } => {
                let p = prefix.as_slice();
                let cp = common_prefix_len(p, key);
                if cp == p.len() {
                    let new_child = self.insert_at(Some(child), &key[cp..], value)?;
                    return self.put(&TrieNode::ext(prefix.clone(), new_child));
                }
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
            TrieNode::Branch {
                mut children,
                value: mut branch_value,
            } => {
                if key.is_empty() {
                    branch_value = Some(value.clone());
                } else {
                    let idx = key[0] as usize;
                    let new_child = self.insert_at(children[idx], &key[1..], value)?;
                    children[idx] = Some(new_child);
                }
                self.put(&TrieNode::Branch {
                    children,
                    value: branch_value,
                })
            }
        }
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

    fn remove_at(&self, hash: Hash, key: &[u8]) -> Result<Option<Hash>, MptError> {
        let node = self.load(&hash)?;
        match node {
            TrieNode::Leaf { ref key_rest, .. } => {
                if key_rest.as_slice() == key {
                    Ok(None)
                } else {
                    Ok(Some(hash))
                }
            }
            TrieNode::Ext { ref prefix, child } => {
                let p = prefix.as_slice();
                if !key.starts_with(p) {
                    return Ok(Some(hash));
                }
                match self.remove_at(child, &key[p.len()..])? {
                    None => Ok(None),
                    Some(new_child) if new_child == child => Ok(Some(hash)),
                    Some(new_child) => Ok(Some(self.merge_down(p, new_child)?)),
                }
            }
            TrieNode::Branch {
                mut children,
                value,
            } => {
                if key.is_empty() {
                    if value.is_none() {
                        return Ok(Some(hash));
                    }
                    return self.collapse(children, None);
                }
                let idx = key[0] as usize;
                let Some(child) = children[idx] else {
                    return Ok(Some(hash));
                };
                let new_child = self.remove_at(child, &key[1..])?;
                if new_child == Some(child) {
                    return Ok(Some(hash));
                }
                children[idx] = new_child;
                self.collapse(children, value)
            }
        }
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
            Some(h) => Ok(Cursor::At {
                hash: Some(h),
                node: self.load(&h)?,
            }),
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
                    hash: None,
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
                        hash: None,
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

    /// Walks a subtree, collecting values, with an explicit heap stack.
    ///
    /// Depth is attacker-controlled — a peer's trie is fetched by hash and
    /// nothing about the *shape* it describes is canonicalized, so it may chain
    /// extension nodes to any depth — and a recursive walk would abort the
    /// process on a stack overflow rather than return an error (§12). The
    /// frames therefore live on the heap, and the walk stops descending past
    /// [`MAX_DEPTH_NIBBLES`], below which no key short enough to be valid can
    /// begin.
    fn collect(
        &self,
        cursor: &Cursor,
        path: &mut Vec<u8>,
        after: Option<&Nibbles>,
        limit: Option<usize>,
        out: &mut Vec<Entry>,
    ) -> Result<(), MptError> {
        let after_bytes = after.map(|a| a.to_bytes().unwrap_or_default());
        let base = path.len();
        let mut stack: Vec<Frame> = Vec::new();
        // Keeps the scan proportional to the trie, so a fan-out DAG cannot turn
        // a handful of nodes into an unbounded walk.
        let mut guard = FanoutGuard::default();

        self.take_value(cursor, path, after_bytes.as_deref(), limit, out)?;
        stack.push(Frame {
            cursor: cursor.clone(),
            next: 0,
        });

        while let Some(top) = stack.len().checked_sub(1) {
            if limit.is_some_and(|l| out.len() >= l) {
                return Ok(());
            }
            let nibble = stack[top].next;
            if nibble >= 16 || path.len() >= MAX_DEPTH_NIBBLES {
                stack.pop();
                if path.len() > base {
                    path.pop();
                }
                continue;
            }
            stack[top].next += 1;
            path.push(nibble);
            let skip = after.is_some_and(|a| subtree_is_below(path, a.as_slice()));
            if skip {
                path.pop();
                continue;
            }
            let child = self.cursor_child(&stack[top].cursor, nibble)?;
            if child.is_empty() {
                path.pop();
                continue;
            }
            guard.visit(child.identity())?;
            self.take_value(&child, path, after_bytes.as_deref(), limit, out)?;
            stack.push(Frame {
                cursor: child,
                next: 0,
            });
        }
        Ok(())
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

    /// Which hashes reachable from `root` are absent from the store.
    ///
    /// A one-shot walk from scratch. A fetch wants [`MissingWalk`] instead: it
    /// keeps its place between batches, and can prune against a trie it
    /// already holds whole.
    pub fn missing(&self, root: Hash, max: usize) -> Result<Missing, MptError> {
        MissingWalk::new(root).next_batch(self, max)
    }

    /// True if the whole trie under `root` is present locally and servable.
    ///
    /// The answer is computed from the trie, never assumed from the fact that
    /// a head names the root — but it is computed *once* per root. A walk of
    /// everything reachable is not a per-`Hello` cost a converged cluster
    /// should pay (§5.1), and a content-addressed root that was complete
    /// cannot become incomplete: no node is ever rewritten under an existing
    /// hash, and GC marks from every head a root can be reached through.
    pub fn is_complete(&self, root: Hash) -> Result<bool, MptError> {
        if Self::wrap(self.store.is_known_complete(&root))? {
            return Ok(true);
        }
        let complete = self.missing(root, 1)?.is_empty();
        if complete {
            Self::wrap(self.store.note_complete(&root))?;
        }
        Ok(complete)
    }

    /// Everything reachable from `root`, for mark-and-sweep GC (§5.4).
    ///
    /// Missing nodes are skipped rather than raising: GC must be able to mark
    /// from a partially fetched pending head without failing.
    pub fn reachable(&self, root: Hash) -> Result<Reachable, MptError> {
        let mut out = Reachable::default();
        let mut frontier = match root_opt(root) {
            None => return Ok(out),
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
        Ok(out)
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

    fn trie(store: &MemStore) -> Trie<'_, MemStore> {
        Trie::new(store)
    }

    #[test]
    fn empty_trie_reads_nothing() {
        let s = MemStore::new();
        let t = trie(&s);
        assert_eq!(t.get(Hash::EMPTY, b"a").unwrap(), None);
        assert!(t.iter(Hash::EMPTY).unwrap().is_empty());
        assert!(t.is_complete(Hash::EMPTY).unwrap());
    }

    #[test]
    fn insert_and_get() {
        let s = MemStore::new();
        let t = trie(&s);
        let mut root = Hash::EMPTY;
        for (k, v) in [("apple", "1"), ("apply", "2"), ("ape", "3"), ("b", "4")] {
            root = t.insert(root, k.as_bytes(), v.as_bytes()).unwrap();
        }
        assert_eq!(t.get(root, b"apple").unwrap().unwrap(), b"1");
        assert_eq!(t.get(root, b"apply").unwrap().unwrap(), b"2");
        assert_eq!(t.get(root, b"ape").unwrap().unwrap(), b"3");
        assert_eq!(t.get(root, b"b").unwrap().unwrap(), b"4");
        assert_eq!(t.get(root, b"app").unwrap(), None);
        assert_eq!(t.get(root, b"c").unwrap(), None);
        assert!(t.contains(root, b"b").unwrap());
    }

    #[test]
    fn key_that_is_a_prefix_of_another() {
        let s = MemStore::new();
        let t = trie(&s);
        let mut root = Hash::EMPTY;
        root = t.insert(root, b"abc", b"long").unwrap();
        root = t.insert(root, b"ab", b"short").unwrap();
        assert_eq!(t.get(root, b"ab").unwrap().unwrap(), b"short");
        assert_eq!(t.get(root, b"abc").unwrap().unwrap(), b"long");
        assert_eq!(
            t.iter(root).unwrap(),
            vec![
                (b"ab".to_vec(), b"short".to_vec()),
                (b"abc".to_vec(), b"long".to_vec())
            ]
        );
    }

    #[test]
    fn overwrite_replaces_value() {
        let s = MemStore::new();
        let t = trie(&s);
        let root = t.insert(Hash::EMPTY, b"k", b"v1").unwrap();
        let root2 = t.insert(root, b"k", b"v2").unwrap();
        assert_ne!(root, root2);
        assert_eq!(t.get(root2, b"k").unwrap().unwrap(), b"v2");
        // The old root remains readable: structural sharing keeps history alive.
        assert_eq!(t.get(root, b"k").unwrap().unwrap(), b"v1");
    }

    #[test]
    fn remove_returns_to_empty() {
        let s = MemStore::new();
        let t = trie(&s);
        let root = t.insert(Hash::EMPTY, b"only", b"v").unwrap();
        let root = t.remove(root, b"only").unwrap();
        assert_eq!(root, Hash::EMPTY);
    }

    #[test]
    fn remove_absent_key_is_a_no_op() {
        let s = MemStore::new();
        let t = trie(&s);
        let root = t.insert(Hash::EMPTY, b"a", b"1").unwrap();
        assert_eq!(t.remove(root, b"zzz").unwrap(), root);
        assert_eq!(t.remove(Hash::EMPTY, b"zzz").unwrap(), Hash::EMPTY);
    }

    #[test]
    fn large_values_go_out_of_line() {
        let s = MemStore::new();
        let t = trie(&s);
        let big = vec![9u8; 500];
        let root = t.insert(Hash::EMPTY, b"k", &big).unwrap();
        assert_eq!(s.value_count(), 1);
        assert_eq!(t.get(root, b"k").unwrap().unwrap(), big);
        assert!(t.is_complete(root).unwrap());
    }

    #[test]
    fn missing_values_are_reported() {
        let s = MemStore::new();
        let t = trie(&s);
        let big = vec![9u8; 500];
        let root = t.insert(Hash::EMPTY, b"k", &big).unwrap();
        s.retain(&s.node_hashes(), &[]);
        let missing = t.missing(root, 10).unwrap();
        assert_eq!(missing.nodes.len(), 0);
        assert_eq!(missing.values.len(), 1);
        assert!(!t.is_complete(root).unwrap());
        assert!(matches!(t.get(root, b"k"), Err(MptError::MissingValue(_))));
    }

    #[test]
    fn a_shared_value_is_reported_missing_once() {
        // Two keys holding the same out-of-line value is one value hash
        // referenced from two leaves; the missing walk names it once.
        let s = MemStore::new();
        let t = trie(&s);
        let big = vec![9u8; 500];
        let mut root = Hash::EMPTY;
        for key in [b"a".as_slice(), b"b".as_slice()] {
            root = t.insert(root, key, &big).unwrap();
        }
        assert_eq!(s.value_count(), 1);
        s.retain(&s.node_hashes(), &[]);
        let missing = t.missing(root, 100).unwrap();
        assert_eq!(missing.nodes.len(), 0);
        assert_eq!(
            missing.values.len(),
            1,
            "the shared value is missing once, not once per referencing leaf: {:?}",
            missing.values
        );
    }

    /// A branch-per-nibble chain of `depth` levels with a value at the bottom:
    /// the shape a maximally uncompressible key produces, built node by node
    /// because inserting the keys to force it costs quadratic time.
    fn branch_chain(store: &MemStore, depth: usize) -> Hash {
        let mut hash = {
            let node = TrieNode::leaf(Nibbles::new(), crate::ValueRef::Inline(vec![1]));
            let encoded = node.encode();
            let hash = crate::node::hash_encoded(node.tag(), &encoded);
            store.put_node(&hash, &encoded).unwrap();
            hash
        };
        for _ in 0..depth {
            let mut children = NO_CHILDREN;
            children[0] = Some(hash);
            let node = TrieNode::Branch {
                children,
                // A second occupant, or the branch would not be canonical.
                value: Some(crate::ValueRef::Inline(vec![2])),
            };
            let encoded = node.encode();
            let hash_next = crate::node::hash_encoded(node.tag(), &encoded);
            store.put_node(&hash_next, &encoded).unwrap();
            hash = hash_next;
        }
        hash
    }

    #[test]
    fn get_reads_a_value_at_exactly_the_depth_bound() {
        // A legal key is `MAX_KEY_LEN` bytes — `MAX_DEPTH_NIBBLES` nibbles —
        // and a value can sit at exactly that depth. The readers agree there:
        // the structural walks examine a position at the bound and prune only
        // below it, so `get` must reach it too.
        let s = MemStore::new();
        let t = trie(&s);
        let root = branch_chain(&s, MAX_DEPTH_NIBBLES);
        let key = vec![0u8; MAX_KEY_LEN];
        assert_eq!(t.get(root, &key).unwrap(), Some(vec![1]));

        // A key past the length bound descends past the step bound, and that
        // still errors rather than walking on.
        let root = branch_chain(&s, MAX_DEPTH_NIBBLES + 2);
        let key = vec![0u8; MAX_KEY_LEN + 1];
        assert!(matches!(t.get(root, &key), Err(MptError::NonCanonical(_))));
    }

    #[test]
    fn missing_nodes_are_reported() {
        let s = MemStore::new();
        let t = trie(&s);
        let mut root = Hash::EMPTY;
        for i in 0..20u8 {
            root = t.insert(root, &[i, i], b"v").unwrap();
        }
        assert!(t.is_complete(root).unwrap());
        s.retain(&[root], &[]);
        let missing = t.missing(root, 100).unwrap();
        assert!(!missing.is_empty());
        assert!(!t.is_complete(root).unwrap());
    }

    #[test]
    fn scan_by_prefix() {
        let s = MemStore::new();
        let t = trie(&s);
        let mut root = Hash::EMPTY;
        for k in ["f:a/1", "f:a/2", "f:a/sub/3", "f:b/1", "b:x"] {
            root = t.insert(root, k.as_bytes(), k.as_bytes()).unwrap();
        }
        let keys: Vec<String> = t
            .scan(root, b"f:a/", None, None)
            .unwrap()
            .into_iter()
            .map(|(k, _)| String::from_utf8(k).unwrap())
            .collect();
        assert_eq!(keys, vec!["f:a/1", "f:a/2", "f:a/sub/3"]);

        let keys: Vec<String> = t
            .scan(root, b"f:", None, None)
            .unwrap()
            .into_iter()
            .map(|(k, _)| String::from_utf8(k).unwrap())
            .collect();
        assert_eq!(keys, vec!["f:a/1", "f:a/2", "f:a/sub/3", "f:b/1"]);

        assert!(t.scan(root, b"zzz", None, None).unwrap().is_empty());
    }

    #[test]
    fn scan_pagination() {
        let s = MemStore::new();
        let t = trie(&s);
        let mut root = Hash::EMPTY;
        for i in 0..10u8 {
            root = t.insert(root, format!("k{i:02}").as_bytes(), b"v").unwrap();
        }
        let page1 = t.scan(root, b"k", None, Some(4)).unwrap();
        assert_eq!(page1.len(), 4);
        assert_eq!(page1[0].0, b"k00".to_vec());
        let page2 = t.scan(root, b"k", Some(&page1[3].0), Some(4)).unwrap();
        assert_eq!(page2.len(), 4);
        assert_eq!(page2[0].0, b"k04".to_vec());
        let page3 = t.scan(root, b"k", Some(&page2[3].0), Some(4)).unwrap();
        assert_eq!(page3.len(), 2);
        assert_eq!(page3[1].0, b"k09".to_vec());
        let page4 = t.scan(root, b"k", Some(&page3[1].0), Some(4)).unwrap();
        assert!(page4.is_empty());
    }

    #[test]
    fn structural_sharing_bounds_allocation() {
        let s = MemStore::new();
        let t = trie(&s);
        let mut root = Hash::EMPTY;
        for i in 0..200u16 {
            root = t
                .insert(root, format!("f:space/{i:04}").as_bytes(), b"entry")
                .unwrap();
        }
        let before = s.node_count();
        let root2 = t.insert(root, b"f:space/0000", b"changed").unwrap();
        let added = s.node_count() - before;
        // Only the path from the touched leaf to the root is allocated.
        assert!(added <= 12, "allocated {added} nodes for a one-key change");
        assert_ne!(root, root2);
    }

    #[test]
    fn apply_batch() {
        let s = MemStore::new();
        let t = trie(&s);
        let root = t
            .apply(
                Hash::EMPTY,
                vec![
                    (b"a".as_slice(), Some(b"1".as_slice())),
                    (b"b".as_slice(), Some(b"2".as_slice())),
                ],
            )
            .unwrap();
        let root = t
            .apply(
                root,
                vec![
                    (b"a".as_slice(), None),
                    (b"c".as_slice(), Some(b"3".as_slice())),
                ],
            )
            .unwrap();
        assert_eq!(
            t.iter(root).unwrap(),
            vec![
                (b"b".to_vec(), b"2".to_vec()),
                (b"c".to_vec(), b"3".to_vec())
            ]
        );
    }

    #[test]
    fn reachable_covers_nodes_and_values() {
        let s = MemStore::new();
        let t = trie(&s);
        let mut root = Hash::EMPTY;
        root = t.insert(root, b"a", &vec![1u8; 300]).unwrap();
        root = t.insert(root, b"b", b"small").unwrap();
        let r = t.reachable(root).unwrap();
        assert!(r.nodes.contains(&root));
        assert_eq!(r.values.len(), 1);
    }

    #[test]
    fn key_length_is_bounded() {
        let s = MemStore::new();
        let t = trie(&s);
        let key = vec![b'x'; MAX_KEY_LEN + 1];
        assert!(matches!(
            t.insert(Hash::EMPTY, &key, b"v"),
            Err(MptError::KeyTooLong(_))
        ));
    }
}
