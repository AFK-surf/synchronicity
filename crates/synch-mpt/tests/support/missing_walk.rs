//! The former Rust requesting walk, retained only as an independent regression
//! oracle. Production requesting operations execute VerifiedCore.Trie.Fetch.
#![allow(dead_code)]

use std::collections::HashSet;
use synch_core::{Hash, OriginId};
use synch_mpt::trie::MAX_DEPTH_NIBBLES;
use synch_mpt::{MptError, NodeStore, Scope, Trie, TrieNode};

fn root_opt(root: Hash) -> Option<Hash> {
    if root.is_empty_sentinel() {
        None
    } else {
        Some(root)
    }
}

fn load_owned_raw<S: NodeStore + ?Sized>(
    trie: &Trie<'_, S>,
    owner: Option<&OriginId>,
    hash: &Hash,
) -> Result<Option<Vec<u8>>, MptError> {
    if let Some(owner) = owner {
        if !trie
            .store()
            .owns_node(owner, hash)
            .map_err(MptError::store)?
        {
            return Ok(None);
        }
    }
    trie.store().get_node(hash).map_err(MptError::store)
}

/// The set of hashes referenced by a root but absent from the store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Missing {
    /// Trie nodes that must be fetched, each with the nibble path it occupies.
    ///
    /// The path travels with the request because that is what a responder
    /// authorizes on (§5.5): a hash carries no position, and none can be
    /// recovered from it.
    pub(crate) nodes: Vec<(Vec<u8>, Hash)>,
    /// Out-of-line values that must be fetched, each with the nibble path of
    /// the node that holds it.
    pub(crate) values: Vec<(Vec<u8>, Hash)>,
}

impl Missing {
    /// True if nothing is missing.
    pub(crate) fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.values.is_empty()
    }

    /// Total number of missing hashes.
    pub(crate) fn len(&self) -> usize {
        self.nodes.len() + self.values.len()
    }
}

/// A node position paired with what stands there in a known-complete reference.
type Position = (Option<Hash>, Hash, Vec<u8>);

/// What identifies a visit for deduplication: the node, and — only where the
/// scope admits a position partially — the position too.
///
/// Under a full scope, or inside a granted prefix, hash and depth determine
/// validation: a deeper reuse may exceed the canonical key-depth ceiling.
/// On a scope spine, the full position also matters: a
/// node standing at two spine positions has children admitted under one and
/// refused under the other, so a visit at the first cannot stand in for the
/// second (§5.5).
type Visit = (usize, Hash, Option<Vec<u8>>);

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
pub(crate) struct MissingWalk {
    /// `(the hash at this position in the reference trie, the hash wanted,
    /// the nibble path of the position)`.
    pub(crate) frontier: Vec<Position>,
    /// Canonicality failures remain terminal, including across resume.
    fault: Option<String>,
    seen: HashSet<Visit>,
    /// Reported absent and awaiting the caller's fetch, so they can be
    /// revisited — and their children discovered — once they land.
    pub(crate) deferred: Vec<Position>,
    /// Children of extension nodes that were not yet present when their parent
    /// was walked, and so must be checked for being branches when they arrive.
    must_be_branch: HashSet<Hash>,
    /// The part of the keyspace this walk may descend into (§5.5).
    ///
    /// A scoped walk stops at the boundary rather than asking for what it
    /// would be refused — the serving peer applies the same predicate, so an
    /// out-of-scope request is a probe, never a race.
    scope: Scope,
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
    pub(crate) fn new(root: Hash) -> MissingWalk {
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
    /// The reference must describe this same scope. Sound pruning also
    /// requires every admitted path to have been checked. A recorded refusal
    /// does not establish that a subtree contains no authorized entries.
    // The root and each child are queued only at admitted positions.
    pub(crate) fn scoped(known_complete: Option<Hash>, root: Hash, scope: Scope) -> MissingWalk {
        MissingWalk::for_origin(None, known_complete, root, scope)
    }

    /// A scoped walk whose presence carries provenance for `owner`.
    ///
    /// The reference root, when given, must be complete *with the same
    /// provenance*: pruning a shared subtree stands in for having fetched it
    /// as `owner`'s, which a reference merely held whole cannot vouch for.
    // The owner restricts presence to nodes served as that origin's.
    pub(crate) fn for_origin(
        owner: Option<OriginId>,
        known_complete: Option<Hash>,
        root: Hash,
        scope: Scope,
    ) -> MissingWalk {
        let frontier = match root_opt(root) {
            None => Vec::new(),
            Some(root) if scope.admits_path(&[]) => {
                vec![(known_complete.and_then(root_opt), root, Vec::new())]
            }
            Some(_) => Vec::new(),
        };
        MissingWalk {
            frontier,
            fault: None,
            seen: HashSet::new(),
            deferred: Vec::new(),
            must_be_branch: HashSet::new(),
            scope,
            owner,
        }
    }

    /// True once the walk has covered everything and nothing is outstanding.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.frontier.is_empty() && self.deferred.is_empty() && self.fault.is_none()
    }

    /// Re-queues everything reported absent, for after the caller has stored
    /// it. Nodes that arrived expand into their children; ones that did not
    /// are reported again, which is what lets a caller notice it is making no
    /// progress.
    pub(crate) fn resume(&mut self) {
        let deferred = std::mem::take(&mut self.deferred);
        for (reference, hash, path) in deferred {
            let visit = visit(&self.scope, hash, &path);
            self.seen.remove(&visit);
            self.frontier.push((reference, hash, path));
        }
    }

    /// Walks until `max` absent hashes are found or the frontier drains.
    pub(crate) fn next_batch<S: NodeStore + ?Sized>(
        &mut self,
        trie: &Trie<'_, S>,
        max: usize,
    ) -> Result<Missing, MptError> {
        if let Some(fault) = &self.fault {
            return Err(MptError::NonCanonical(fault.clone()));
        }
        let mut missing = Missing::default();
        // One request may ask for a hash once. Structural sharing makes repeats
        // ordinary — two keys with one out-of-line payload — and `seen` dedups
        // nodes but not values, so a single batch asked for one hash several
        // times; the responder answers per hash, and `take_served` treats a
        // second copy as a protocol violation that ends the *whole* exchange,
        // blaming an honest peer for answering exactly what it was asked.
        // Local to the batch: an absent value must be reported again next round,
        // or the unproductive counter behind §5.2's abandonment never fires.
        let mut asked: HashSet<Hash> = HashSet::new();
        while let Some((reference, hash, path)) = self.frontier.last().cloned() {
            if missing.len() >= max {
                break;
            }
            // The depth bound every walk carries, applied to the *fetch*, which
            // carried none: `hash_of_encoded` bounds one node's run at
            // `MAX_KEY_LEN * 2` and §12 read that as bounding ingest depth, but
            // the bound is per node and a path is made of many. Without this, a
            // chain past the depth any valid key reaches was pulled in full,
            // vouched for, and served on to every peer — marked by no GC pass,
            // reflected in no `entries` row.
            //
            // Depth remains part of every deduplication key: deeper reuse can
            // invalidate a leaf previously checked at a shallower position.
            // An `MptError`, so it fails that origin and not the relaying peer.
            if path.len() > MAX_DEPTH_NIBBLES {
                return Err(self.fail(format!(
                    "a trie node sits at nibble depth {}, past the \
                     {MAX_DEPTH_NIBBLES} any valid key reaches",
                    path.len()
                )));
            }
            // The same hash in a trie held whole: this subtree is already here,
            // values and all.
            // This relies on the caller's reference-completeness contract;
            // it is not an independent check of the shared subtree.
            if reference == Some(hash) {
                self.frontier.pop();
                continue;
            }
            if self.seen.contains(&visit(&self.scope, hash, &path)) {
                self.frontier.pop();
                continue;
            }
            let Some(data) = load_owned_raw(trie, self.owner.as_ref(), &hash)? else {
                // A peer refusal does not authenticate absence beneath an
                // admitted spine. Keep the node outstanding: otherwise a
                // partial view could replace a complete published file list.
                self.frontier.pop();
                self.seen.insert(visit(&self.scope, hash, &path));
                missing.nodes.push((path.clone(), hash));
                self.deferred.push((reference, hash, path));
                continue;
            };
            let node = TrieNode::decode(&data)?;
            // The half of the extension invariant the ingress boundary cannot
            // reach: an `Ext` must sit above a `Branch`, which needs the child
            // node. An `Ext` above a `Leaf` or another `Ext` reads fine through
            // `get`/`iter`/`diff` but gives one key/value map several distinct
            // roots — exactly what structural sharing and reference pruning
            // rely on not happening — making every peer's incremental sync cost
            // the whole tree. An `MptError`, so it fails its own origin and no
            // other (§12): the relaying peer served exactly what it was asked.
            if self.must_be_branch.contains(&hash) && !matches!(node, TrieNode::Branch { .. }) {
                return Err(self.fail(format!(
                    "node {hash} sits under an extension but is not a branch"
                )));
            }
            let mut missing_branch = None;
            if let TrieNode::Ext { child, .. } = &node {
                // Checked now if the child is already here: a DAG means it may
                // have been visited under another parent, and `seen` would keep
                // it from being revisited.
                match trie.store().get_node(child).map_err(MptError::store)? {
                    Some(bytes)
                        if !matches!(TrieNode::decode(&bytes)?, TrieNode::Branch { .. }) =>
                    {
                        return Err(self.fail(format!(
                            "node {child} sits under an extension but is not a branch"
                        )));
                    }
                    Some(_) => {}
                    None => {
                        missing_branch = Some(*child);
                    }
                }
            }
            let reference_node = match reference {
                Some(reference) => trie
                    .store()
                    .get_node(&reference)
                    .map_err(MptError::store)?
                    .map(|bytes| TrieNode::decode(&bytes))
                    .transpose()?,
                None => None,
            };
            // A leaf's value sits at the end of its own run, which is the
            // position a key would have to be that long to name, and nothing
            // below charges this depth. Checked here or not at all.
            if let TrieNode::Leaf { key_rest, .. } = &node {
                let depth = path.len().saturating_add(key_rest.len());
                if depth > MAX_DEPTH_NIBBLES {
                    return Err(self.fail(format!(
                        "a trie value sits at nibble depth {depth}, past the \
                         {MAX_DEPTH_NIBBLES} any valid key reaches"
                    )));
                }
            }
            // A node whose out-of-line values have not arrived is not done
            // with, so it is deferred like a node that never loaded. Reporting
            // the value once and moving on would have the walk claim exhaustion
            // over a trie it cannot serve — the node loads, so it is never
            // deferred and `seen` never revisits it — and the §5.2 abandonment
            // counter would sit at one while `note_complete` vouched for the
            // root.
            let mut awaiting_values = false;
            for value_hash in node.value_hashes() {
                if self.scope.admits_value(&path, &node)
                    && !trie
                        .store()
                        .has_value(&value_hash)
                        .map_err(MptError::store)?
                {
                    // Deferred whether or not already asked this batch: another
                    // node reporting the same payload says nothing about *this*
                    // node being done with.
                    awaiting_values = true;
                    if asked.insert(value_hash) {
                        missing.values.push((path.clone(), value_hash));
                    }
                }
            }
            // Commit this visit only after every storage read and decode has
            // succeeded. An interrupted call leaves the position on the stack,
            // so retry (with or without resume) cannot skip unfinished work.
            self.frontier.pop();
            self.seen.insert(visit(&self.scope, hash, &path));
            self.must_be_branch.remove(&hash);
            if let Some(child) = missing_branch {
                self.must_be_branch.insert(child);
            }
            for (child_reference, child, step) in paired_children(reference_node.as_ref(), &node) {
                let mut child_path = path.clone();
                child_path.extend_from_slice(&step);
                // A child leading out of scope is not descended or asked for;
                // its hash stays committed by the node just walked, keeping the
                // root verifiable without it.
                if !self.scope.admits_path(&child_path) {
                    continue;
                }
                self.frontier.push((child_reference, child, child_path));
            }
            if awaiting_values {
                self.deferred.push((reference, hash, path));
            }
        }
        Ok(missing)
    }

    fn fail(&mut self, message: String) -> MptError {
        self.fault = Some(message.clone());
        MptError::NonCanonical(message)
    }
}

/// The deduplication key for a node at a position ([`Visit`]).
// Inside a grant expansion is position-independent. Depth is still
// retained for canonicality validation.
fn visit(scope: &Scope, hash: Hash, path: &[u8]) -> Visit {
    match scope.contains_subtree(path) {
        true => (path.len(), hash, None),
        false => (path.len(), hash, Some(path.to_vec())),
    }
}

/// Pairs a node's children with the ones at the same positions in the
/// reference trie, so the walk can prune where the two agree.
///
/// Pairing is only attempted where the two nodes have the same shape; elsewhere
/// children are walked with no reference — pruning is an optimization, and
/// declining to prune is always safe. Each child carries the nibbles that lead
/// to it (one for a branch slot, the whole prefix for an extension), the
/// position a scoped fetch is authorized on (§5.5), which costs the walk
/// nothing to keep.
// Pairing follows the same steps through held reference nodes. A held
// node must be expanded even when a refusal was recorded at its position.
pub(crate) fn paired_children(
    reference: Option<&TrieNode>,
    node: &TrieNode,
) -> Vec<(Option<Hash>, Hash, Vec<u8>)> {
    match (reference, node) {
        (
            Some(TrieNode::Branch {
                children: theirs, ..
            }),
            TrieNode::Branch { children, .. },
        ) => children
            .iter()
            .enumerate()
            .filter_map(|(i, child)| child.map(|child| (theirs[i], child, vec![i as u8])))
            .collect(),
        (
            Some(TrieNode::Ext {
                prefix: their_prefix,
                child: their_child,
            }),
            TrieNode::Ext { prefix, child },
        ) if their_prefix == prefix => {
            vec![(Some(*their_child), *child, prefix.as_slice().to_vec())]
        }
        (_, TrieNode::Branch { children, .. }) => children
            .iter()
            .enumerate()
            .filter_map(|(i, child)| child.map(|child| (None, child, vec![i as u8])))
            .collect(),
        (_, TrieNode::Ext { prefix, child }) => {
            vec![(None, *child, prefix.as_slice().to_vec())]
        }
        (_, TrieNode::Leaf { .. }) => Vec::new(),
    }
}
