//! Trie operations: get, insert, remove, iterate, and completeness walks (§4.3).

use std::collections::HashSet;

use synch_core::{Hash, OriginId, MAX_KEY_LEN};

use crate::{
    error::MptError,
    node::{TrieNode, ValueRef},
    scope::Scope,
    store::NodeStore,
};

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
/// the first equal hash and the Lean requesting walk deduplicates, so an origin grows past it
/// with no node ever running the walk that would say so, and the limit shows up
/// only on *first cold materialization* (join, restore, `repair rebuild-views`).
/// Existing followers keep syncing it happily; the refusal at least names the
/// situation rather than reading as one more unparseable record.
///
/// The walk itself, and the charge against this ceiling, is Lean's
/// `Trie.Walk.descend` (`walkPositionCeiling`); this is the figure the
/// refusal names.
pub(crate) const WALK_POSITION_CEILING: usize = 8_000_000;

/// Maps the empty-trie sentinel onto `None`.
pub(crate) fn root_opt(root: Hash) -> Option<Hash> {
    if root.is_empty_sentinel() {
        None
    } else {
        Some(root)
    }
}

/// A key/value pair as yielded by iteration and range scans.
pub type Entry = (Vec<u8>, Vec<u8>);

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

    /// Reads a node's bytes without requiring it to be present, for the walks
    /// whose whole purpose is finding out whether it is.
    pub(crate) fn load_raw(&self, hash: &Hash) -> Result<Option<Vec<u8>>, MptError> {
        Self::wrap(self.store.get_node(hash))
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
    /// must agree about which keys exist — the whole of what the ingress
    /// boundary ([`TrieNode::hash_of_encoded`](crate::TrieNode::hash_of_encoded))
    /// and the ingest bound are for.
    // Lean owns input bounds, decoding, the depth budget and value resolution.
    // Empty extensions remain dead ends; exact-boundary keys retain their
    // final leaf/branch read. Rust supplies encoded storage bytes only.
    pub fn get(&self, root: Hash, key: &[u8]) -> Result<Option<Vec<u8>>, MptError> {
        synch_verified::trie::get(
            &mut crate::lean_storage::Bytes(self.store),
            root.as_bytes(),
            key,
        )
        .map_err(crate::lean_storage::lookup_error)
    }

    /// True if the key is present.
    pub fn contains(&self, root: Hash, key: &[u8]) -> Result<bool, MptError> {
        Ok(self.get(root, key)?.is_some())
    }

    // ---- writes -----------------------------------------------------------

    /// Inserts or replaces a key, returning the new root.
    ///
    /// The whole write is the Lean operation `Trie.insert`: the §12 key and
    /// value bounds, the inline-or-out-of-line choice, the descent to the one
    /// position that changes, the rebuild of the path above it in canonical
    /// form, and the order of writes (a value before the node that names it).
    /// Rust supplies raw node reads, content-addressed writes and BLAKE3.
    pub fn insert(&self, root: Hash, key: &[u8], value: &[u8]) -> Result<Hash, MptError> {
        let mut bytes = crate::lean_storage::Bytes(self.store);
        let mut writes = crate::lean_storage::Bytes(self.store);
        match synch_verified::trie::insert(
            &mut bytes,
            &mut writes,
            &mut crate::lean_storage::Blake3,
            root.as_bytes(),
            key,
            value,
        )
        .map_err(crate::lean_storage::operation_error)?
        {
            Ok(root) => Ok(Hash(root)),
            Err(error) => Err(crate::lean_storage::mutation_error(error)),
        }
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

    /// Removes a key, returning the new root.
    ///
    /// Removing an absent key returns the root unchanged, so the trie stays in
    /// canonical form: any two tries holding the same key/value map have the
    /// same root regardless of the operation history that produced them. The
    /// whole removal is the Lean operation `Trie.remove`, including the §12
    /// key bound `insert` applies and the collapse and merge rules that keep
    /// an extension above a branch only.
    pub fn remove(&self, root: Hash, key: &[u8]) -> Result<Hash, MptError> {
        let mut bytes = crate::lean_storage::Bytes(self.store);
        let mut writes = crate::lean_storage::Bytes(self.store);
        match synch_verified::trie::remove(
            &mut bytes,
            &mut writes,
            &mut crate::lean_storage::Blake3,
            root.as_bytes(),
            key,
        )
        .map_err(crate::lean_storage::operation_error)?
        {
            Ok(root) => Ok(Hash(root)),
            Err(error) => Err(crate::lean_storage::mutation_error(error)),
        }
    }

    // ---- iteration, range scans -------------------------------------------

    /// Every key/value pair under `root`, in lexicographic key order.
    pub fn iter(&self, root: Hash) -> Result<Vec<Entry>, MptError> {
        self.scan(root, &[], None, None)
    }

    /// A range scan: every pair whose key starts with `prefix`, in
    /// lexicographic order, optionally resuming strictly after `start_after`
    /// and capped at `limit` results.
    ///
    /// This is the directory-listing primitive (§4.1) and the S3
    /// `ListObjectsV2` cursor (§9.4). The whole walk is the Lean operation
    /// `Trie.Walk.scan`: the cursor through stored and compressed nodes, the
    /// hostile-shape defences (a depth past which no valid key can begin, the
    /// absolute ceiling on positions visited), the resume cursor's pruning
    /// and the key order. A missing referenced node makes the scan fail;
    /// a peer refusal cannot turn it into an empty subtree.
    pub fn scan(
        &self,
        root: Hash,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        limit: Option<usize>,
    ) -> Result<Vec<Entry>, MptError> {
        synch_verified::trie::scan(
            &mut crate::lean_storage::Bytes(self.store),
            &mut crate::lean_storage::Redactions(self.store),
            root.as_bytes(),
            prefix,
            start_after,
            limit.map(|limit| limit as u64),
        )
        .map_err(crate::lean_storage::walk_error)
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

    /// Whether the scoped requesting walk and its generation check accept
    /// `root`. Refused nodes remain missing. Authenticated scoped omission
    /// and the full exact-view proof remain open obligations in
    /// `docs/RUST-LEAN-PROOFS.md`.
    ///
    /// Completeness is a property of a root *and* a scope: a trie held whole
    /// within one grant is not held whole within a wider one. The memo is keyed
    /// by both, so widening a scope re-derives rather than inheriting.
    pub fn is_complete_scoped(&self, root: Hash, scope: &Scope) -> Result<bool, MptError> {
        self.is_complete_scoped_for(None, root, scope)
    }

    /// [`Trie::is_complete_scoped`] with provenance: for `Some(owner)`,
    /// node presence is checked as `owner`'s ([`NodeStore::owns_node`]),
    /// while retaining the same requirement for every admitted path.
    ///
    /// This is the question a member asks of a confined origin's head before
    /// it vouches for it (§5.5): a trie assembled out of nodes the origin was
    /// never shown is not complete however many of them this store holds.
    /// Memoized under a key of its own, since it is a stricter question than
    /// either of the other two.
    pub fn is_complete_scoped_for(
        &self,
        owner: Option<&OriginId>,
        root: Hash,
        scope: &Scope,
    ) -> Result<bool, MptError> {
        crate::lean_storage::complete(self.store, owner, root, scope)
    }

    /// Resolves claimed positions against `root`, returning what actually
    /// stands at each one.
    ///
    /// The responder's half of a scoped fetch (§5.5): the caller says where it
    /// believes a node sits; this descends from a root the responder itself
    /// holds and reports what is really there. Establishing that the root
    /// belongs to an authorized signed version is the serving admission's
    /// responsibility, not this traversal's.
    ///
    /// One merged descent over the sorted paths shares every prefix two wants
    /// have in common: a batch is the frontier of a single walk, so the cost is
    /// close to trie depth plus batch size, not their product.
    // Production resolution is Lean's `Trie.Serve.resolvePaths`
    // (`Store::resolve_trie_paths`); this is the walk tests' oracle over an
    // in-memory store.
    #[cfg(test)]
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
    /// An absent node stops that branch rather than raising. The caller
    /// relies on its completeness check; this is not an independent check
    /// that every shared entry is present.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::missing_oracle::{paired_children, MissingWalk};
    use crate::nibbles::Nibbles;
    use crate::{node::NO_CHILDREN, store::MemStore};

    #[test]
    fn walk_depth_fault_precedes_reference_pruning_and_survives_resume() {
        let store = MemStore::new();
        let hash = Hash([1; 32]);
        let mut walk = MissingWalk::new(hash);
        walk.frontier = vec![(Some(hash), hash, vec![0; MAX_DEPTH_NIBBLES + 1])];
        let error = walk
            .next_batch(&Trie::new(&store), 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("nibble depth"));
        walk.resume();
        assert_eq!(
            walk.next_batch(&Trie::new(&store), 1)
                .unwrap_err()
                .to_string(),
            error
        );
        assert!(!walk.is_exhausted());
    }

    #[test]
    fn walk_retries_deferred_positions_lifo_after_thread_migration() {
        let store = MemStore::new();
        let mut children = NO_CHILDREN;
        children[0] = Some(Hash([2; 32]));
        children[1] = Some(Hash([3; 32]));
        let root = TrieNode::Branch {
            children,
            value: None,
        };
        store.put_node(&root.hash(), &root.encode()).unwrap();
        let mut walk = MissingWalk::new(root.hash());
        let first = walk.next_batch(&Trie::new(&store), 10).unwrap();
        assert_eq!(
            first.nodes,
            vec![(vec![1], Hash([3; 32])), (vec![0], Hash([2; 32]))]
        );
        assert!(!walk.is_exhausted());
        walk.resume();
        std::thread::spawn(move || {
            let retry = walk.next_batch(&Trie::new(&MemStore::new()), 10).unwrap();
            assert_eq!(
                retry.nodes,
                vec![(vec![0], Hash([2; 32])), (vec![1], Hash([3; 32]))]
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn walk_rejects_a_deferred_extension_child_that_arrives_as_a_leaf() {
        let store = MemStore::new();
        let leaf = TrieNode::Leaf {
            key_rest: Nibbles::new(),
            value: ValueRef::Inline(vec![1]),
        };
        let root = TrieNode::Ext {
            prefix: Nibbles::from_bytes(&[0]),
            child: leaf.hash(),
        };
        store.put_node(&root.hash(), &root.encode()).unwrap();
        let mut walk = MissingWalk::new(root.hash());
        assert_eq!(
            walk.next_batch(&Trie::new(&store), 10).unwrap().nodes,
            vec![(vec![0, 0], leaf.hash())]
        );
        store.put_node(&leaf.hash(), &leaf.encode()).unwrap();
        walk.resume();
        let error = walk
            .next_batch(&Trie::new(&store), 10)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a branch"));
        walk.resume();
        assert_eq!(
            walk.next_batch(&Trie::new(&store), 10)
                .unwrap_err()
                .to_string(),
            error
        );
        assert!(!walk.is_exhausted());
    }

    #[test]
    fn walk_defers_every_shared_payload_waiter_but_requests_it_once() {
        let store = MemStore::new();
        let payload = Hash([9; 32]);
        let mut children = NO_CHILDREN;
        for slot in [0, 1] {
            let leaf = TrieNode::Leaf {
                key_rest: Nibbles::from_bytes(&[slot as u8]),
                value: ValueRef::Hash(payload),
            };
            store.put_node(&leaf.hash(), &leaf.encode()).unwrap();
            children[slot] = Some(leaf.hash());
        }
        let root = TrieNode::Branch {
            children,
            value: None,
        };
        store.put_node(&root.hash(), &root.encode()).unwrap();
        let mut walk = MissingWalk::new(root.hash());
        assert_eq!(
            walk.next_batch(&Trie::new(&store), 10)
                .unwrap()
                .values
                .len(),
            1
        );
        assert_eq!(walk.deferred.len(), 2);
        assert!(!walk.is_exhausted());
        store.put_value(&payload, &[42]).unwrap();
        walk.resume();
        assert!(walk.next_batch(&Trie::new(&store), 10).unwrap().is_empty());
        assert!(walk.is_exhausted());
    }

    #[test]
    fn walk_pairs_only_same_slot_or_identical_extension_runs() {
        let mut children = NO_CHILDREN;
        children[0] = Some(Hash([2; 32]));
        children[7] = Some(Hash([3; 32]));
        children[15] = Some(Hash([4; 32]));
        let mut reference = NO_CHILDREN;
        reference[0] = children[0];
        reference[7] = Some(Hash([8; 32]));
        reference[8] = children[15];
        assert_eq!(
            paired_children(
                Some(&TrieNode::Branch {
                    children: reference,
                    value: None
                }),
                &TrieNode::Branch {
                    children,
                    value: None
                }
            ),
            vec![
                (Some(Hash([2; 32])), Hash([2; 32]), vec![0]),
                (Some(Hash([8; 32])), Hash([3; 32]), vec![7]),
                (None, Hash([4; 32]), vec![15]),
            ]
        );
        let node = TrieNode::Ext {
            prefix: Nibbles::from_bytes(&[0x12]),
            child: Hash([2; 32]),
        };
        for (run, expected) in [(0x12, Some(Hash([9; 32]))), (0x13, None)] {
            let reference = TrieNode::Ext {
                prefix: Nibbles::from_bytes(&[run]),
                child: Hash([9; 32]),
            };
            assert_eq!(
                paired_children(Some(&reference), &node),
                vec![(expected, Hash([2; 32]), vec![1, 2])]
            );
        }
    }

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
            Scope::full().memo_key_for(Some(&owner), root).unwrap(),
            Scope::full().memo_key(root).unwrap()
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
    /// walk never fetched.
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
