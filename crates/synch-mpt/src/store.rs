//! The content-addressed node store the trie reads and writes through (§4.3).

use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Mutex, PoisonError},
};

use synch_core::Hash;

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

    /// True if a peer has told this store it may not see the node `hash`.
    ///
    /// A scoped node needs to tell "absent" from "refused" (§5.5), and needs
    /// to keep telling them apart across restarts: a completeness walk that
    /// re-read a refused position as merely missing would never settle, and a
    /// fetch would retry until its head was abandoned. The default remembers
    /// nothing, which is right for a store that never asks for a scoped view.
    fn is_redacted(&self, _hash: &Hash) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Records that a peer refused to show the node `hash`.
    fn note_redacted(&self, _hash: &Hash) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// An in-memory node store, for tests and for verifying a proof against a
/// root without touching any durable store.
#[derive(Debug, Default)]
pub struct MemStore {
    nodes: Mutex<HashMap<Hash, Vec<u8>>>,
    values: Mutex<HashMap<Hash, Vec<u8>>>,
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
}
