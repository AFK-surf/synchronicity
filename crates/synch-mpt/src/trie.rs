//! Trie operations: get, insert, remove, iterate, and completeness walks (§4.3).

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

    /// Normalize routing spines before signing a publication. This preserves
    /// the logical entries while allowing authenticated private omissions.
    /// Call inside the same transaction that retains and publishes the root.
    pub fn normalize_publication(&self, root: Hash) -> Result<Hash, MptError> {
        match synch_verified::trie::normalize_publication(
            &mut crate::lean_storage::Bytes(self.store),
            &mut crate::lean_storage::Bytes(self.store),
            &mut crate::lean_storage::Blake3,
            root.as_bytes(),
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
    /// Removing an absent key returns the root unchanged. The whole removal
    /// is the Lean operation `Trie.remove`, including the §12 key bound and
    /// the collapse and merge rules that preserve valid compressed or routing
    /// nodes. Different supported representations can have different roots
    /// for the same entries.
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
                TrieNode::Route { children, value } => {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemStore;

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
