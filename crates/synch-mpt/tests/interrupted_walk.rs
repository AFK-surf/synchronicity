//! Failed native completeness reads cannot establish a certificate.

use std::{cell::Cell, io};

use synch_core::Hash;
use synch_mpt::{MemStore, Nibbles, NodeStore, Trie, TrieNode, ValueRef};

struct InterruptingStore {
    inner: MemStore,
    failure: Cell<u8>,
    reads: Cell<usize>,
}

impl NodeStore for InterruptingStore {
    type Error = io::Error;

    fn get_node(&self, hash: &Hash) -> io::Result<Option<Vec<u8>>> {
        self.reads.set(self.reads.get() + 1);
        match self.failure.get() {
            1 => {
                self.failure.set(0);
                Err(io::Error::other("injected node read failure"))
            }
            2 => {
                self.failure.set(0);
                Ok(Some(vec![255])) // Inject a malformed read, not malformed stored data.
            }
            _ => Ok(self.inner.get_node(hash).unwrap()),
        }
    }

    fn put_node(&self, hash: &Hash, data: &[u8]) -> io::Result<()> {
        self.inner.put_node(hash, data).unwrap();
        Ok(())
    }

    fn get_value(&self, hash: &Hash) -> io::Result<Option<Vec<u8>>> {
        if self.failure.get() == 3 {
            self.failure.set(0);
            return Err(io::Error::other("injected payload read failure"));
        }
        Ok(self.inner.get_value(hash).unwrap())
    }

    fn put_value(&self, hash: &Hash, data: &[u8]) -> io::Result<()> {
        self.inner.put_value(hash, data).unwrap();
        Ok(())
    }
}

#[test]
fn failed_reads_and_decodes_cannot_skip_an_unfinished_node() {
    for failure in [1, 2, 3] {
        let store = InterruptingStore {
            inner: MemStore::new(),
            failure: Cell::new(failure),
            reads: Cell::new(0),
        };
        let payload = Hash([7; 32]);
        let node = TrieNode::Leaf {
            key_rest: Nibbles::new(),
            value: ValueRef::Hash(payload),
        };
        let root = node.hash();
        store.put_node(&root, &node.encode()).unwrap();
        let trie = Trie::new(&store);
        assert!(trie.is_complete(root).is_err());
        assert!(!trie.is_complete(root).unwrap());
        assert_eq!(store.reads.get(), 2);
        store.put_value(&payload, &[7; 129]).unwrap();
        assert!(trie.is_complete(root).unwrap());
    }
}
