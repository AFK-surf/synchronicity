//! The content-addressed node store the trie reads and writes through (§4.3).

use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Mutex, PoisonError},
};

use synch_core::{Hash, OriginId};

/// A content-addressed store for trie nodes and out-of-line values.
///
/// Writes take `&self` so that a single store handle can be shared: real
/// implementations (SQLite) funnel writes through their own single-writer
/// discipline (§10).
pub trait NodeStore {
    /// The error type the backing store can produce.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Fetches an encoded trie node by hash.
    fn get_node(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Stores an encoded trie node under its hash.
    fn put_node(&self, hash: &Hash, data: &[u8]) -> Result<(), Self::Error>;

    /// Fetches an out-of-line value payload by hash.
    fn get_value(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Stores an out-of-line value payload under its hash.
    fn put_value(&self, hash: &Hash, data: &[u8]) -> Result<(), Self::Error>;

    /// True if the node is present. Overridable when the store can answer this
    /// more cheaply than a full read (the §5.2 frontier check does this a lot).
    fn has_node(&self, hash: &Hash) -> Result<bool, Self::Error> {
        Ok(self.get_node(hash)?.is_some())
    }

    /// True if the out-of-line value is present.
    fn has_value(&self, hash: &Hash) -> Result<bool, Self::Error> {
        Ok(self.get_value(hash)?.is_some())
    }

    /// True if this store has already established that every node and value
    /// under `root` is present.
    ///
    /// "Do I hold this whole trie?" has no cheap answer — it is a walk of
    /// everything reachable — and it is asked on every `Hello` (§5.1), which
    /// makes a converged cluster pay for the size of its metadata on every
    /// anti-entropy round rather than for what changed. A root is immutable
    /// and content-addressed, so the answer, once *computed*, cannot stop
    /// being true: nothing rewrites a node under an existing hash, and GC
    /// marks from every head it could be reached through. A store that can
    /// remember the answer says so here; the default remembers nothing.
    fn is_known_complete(&self, _root: &Hash) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Records that every node and value under `root` was found present.
    ///
    /// Only ever called after a full walk has established it.
    fn note_complete(&self, _root: &Hash) -> Result<(), Self::Error> {
        Ok(())
    }

    /// True if a peer has told this store it may not see the node `hash` at
    /// nibble position `path` — or, for `None`, at any position.
    ///
    /// A scoped node needs to tell "absent" from "refused" (§5.5), and needs
    /// to keep telling them apart across restarts: a completeness walk that
    /// re-read a refused position as merely missing would never settle, and a
    /// fetch would retry until its head was abandoned. The default remembers
    /// nothing, which is right for a store that never asks for a scoped view.
    ///
    /// Keyed by position as well as by hash, because a refusal is about
    /// *where* a node sits: the same node can stand at two positions the
    /// scope admits and reveal an out-of-scope range at only one of them.
    /// A refusal recorded against the hash alone would have the walk skip the
    /// position it was entitled to as well.
    fn is_redacted(&self, _hash: &Hash, _path: Option<&[u8]>) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Records that a peer refused to show the node `hash` at `path`.
    fn note_redacted(&self, _hash: &Hash, _path: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    /// True if this store was served node `hash` as part of `origin`'s own
    /// trie — under one of that origin's roots, by a peer vouching for it —
    /// rather than merely holding it because some other origin's trie carries
    /// the same node.
    ///
    /// Provenance is what keeps structural sharing from crossing the
    /// delegation boundary (§5.5). A confined origin holds the hash of every
    /// subtree withheld from it, since the hash sits in the branch that makes
    /// the signed root recompute, and can place that hash in its own trie; a
    /// member fetching that trie already holds the nodes from the issuer's
    /// trie, so presence alone would call the head complete and then serve the
    /// withheld subtree back to every delegate at an in-scope position. For a
    /// confined origin's root, "present" therefore means present *as that
    /// origin's*: served under its root by a peer that owned it, which bottoms
    /// out in the origin itself — and the origin cannot serve what it never
    /// held. The default owns nothing, which is the conservative answer for a
    /// store that never records provenance.
    // LEAN-MODEL: mpt-owned-node
    // `Provenance.Store.owned`; `Provenance.view` is the presence a walk with
    // an owner reads, and `owned_is_legit` is what provenance buys.
    fn owns_node(&self, _origin: &OriginId, _hash: &Hash) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Records that `hash` was served to this store as part of `origin`'s trie.
    fn note_owned(&self, _origin: &OriginId, _hash: &Hash) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// An in-memory node store, for tests and for verifying a proof against a
/// root without touching any durable store.
#[derive(Debug, Default)]
pub struct MemStore {
    nodes: Mutex<HashMap<Hash, Vec<u8>>>,
    values: Mutex<HashMap<Hash, Vec<u8>>>,
    owned: Mutex<std::collections::HashSet<(OriginId, Hash)>>,
}

impl MemStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        MemStore::default()
    }

    /// The number of stored nodes.
    pub fn node_count(&self) -> usize {
        self.nodes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Forgets one node, for tests that need a held trie to go partial.
    #[cfg(test)]
    pub(crate) fn remove_node(&self, hash: &Hash) {
        self.nodes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(hash);
    }

    /// Drops every out-of-line value, keeping the nodes: a store that relayed
    /// the structure but GC'd (or never held) the payloads.
    pub fn clear_values(&self) {
        self.values
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

impl NodeStore for MemStore {
    type Error = Infallible;

    fn get_node(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Infallible> {
        Ok(self
            .nodes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(hash)
            .cloned())
    }

    fn put_node(&self, hash: &Hash, data: &[u8]) -> Result<(), Infallible> {
        self.nodes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*hash, data.to_vec());
        Ok(())
    }

    fn get_value(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Infallible> {
        Ok(self
            .values
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(hash)
            .cloned())
    }

    fn put_value(&self, hash: &Hash, data: &[u8]) -> Result<(), Infallible> {
        self.values
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*hash, data.to_vec());
        Ok(())
    }

    fn has_node(&self, hash: &Hash) -> Result<bool, Infallible> {
        Ok(self
            .nodes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(hash))
    }

    fn has_value(&self, hash: &Hash) -> Result<bool, Infallible> {
        Ok(self
            .values
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(hash))
    }

    fn owns_node(&self, origin: &OriginId, hash: &Hash) -> Result<bool, Infallible> {
        Ok(self
            .owned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(origin.clone(), *hash)))
    }

    fn note_owned(&self, origin: &OriginId, hash: &Hash) -> Result<(), Infallible> {
        self.owned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((origin.clone(), *hash));
        Ok(())
    }
}
