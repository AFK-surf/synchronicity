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
}

impl<S: NodeStore + ?Sized> NodeStore for &S {
    type Error = S::Error;

    fn get_node(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Self::Error> {
        (**self).get_node(hash)
    }
    fn put_node(&self, hash: &Hash, data: &[u8]) -> Result<(), Self::Error> {
        (**self).put_node(hash, data)
    }
    fn get_value(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Self::Error> {
        (**self).get_value(hash)
    }
    fn put_value(&self, hash: &Hash, data: &[u8]) -> Result<(), Self::Error> {
        (**self).put_value(hash, data)
    }
    fn has_node(&self, hash: &Hash) -> Result<bool, Self::Error> {
        (**self).has_node(hash)
    }
    fn has_value(&self, hash: &Hash) -> Result<bool, Self::Error> {
        (**self).has_value(hash)
    }
    fn is_known_complete(&self, root: &Hash) -> Result<bool, Self::Error> {
        (**self).is_known_complete(root)
    }
    fn note_complete(&self, root: &Hash) -> Result<(), Self::Error> {
        (**self).note_complete(root)
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

    /// The number of stored out-of-line values.
    pub fn value_count(&self) -> usize {
        self.values
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Every stored node hash.
    pub fn node_hashes(&self) -> Vec<Hash> {
        self.nodes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }

    /// Removes every node and value not in `keep`, returning how many were swept.
    pub fn retain(&self, keep_nodes: &[Hash], keep_values: &[Hash]) -> usize {
        let mut swept = 0;
        let mut nodes = self.nodes.lock().unwrap_or_else(PoisonError::into_inner);
        let before = nodes.len();
        nodes.retain(|h, _| keep_nodes.contains(h));
        swept += before - nodes.len();
        let mut values = self.values.lock().unwrap_or_else(PoisonError::into_inner);
        let before = values.len();
        values.retain(|h, _| keep_values.contains(h));
        swept += before - values.len();
        swept
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_store_round_trip() {
        let s = MemStore::new();
        let h = Hash::new(b"n");
        assert!(!s.has_node(&h).unwrap());
        s.put_node(&h, b"data").unwrap();
        assert!(s.has_node(&h).unwrap());
        assert_eq!(s.get_node(&h).unwrap().unwrap(), b"data".to_vec());
        assert_eq!(s.node_count(), 1);

        let v = Hash::new(b"v");
        s.put_value(&v, b"payload").unwrap();
        assert_eq!(s.get_value(&v).unwrap().unwrap(), b"payload".to_vec());
        assert_eq!(s.value_count(), 1);

        assert_eq!(s.retain(&[], &[v]), 1);
        assert_eq!(s.node_count(), 0);
        assert_eq!(s.value_count(), 1);
    }
}
