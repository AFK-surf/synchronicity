//! Static-link smoke check exercising a complete Lean lookup operation.
use std::convert::Infallible;
use synch_verified::{host::ByteStorage, trie};

struct EmptyStorage {
    reads: usize,
}

impl ByteStorage for EmptyStorage {
    type Error = Infallible;
    fn read_bytes(&mut self, space: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        assert_eq!(space, "trie_nodes");
        assert_eq!(key, [1; 32]);
        self.reads += 1;
        Ok(None)
    }
}

fn main() {
    let mut storage = EmptyStorage { reads: 0 };
    assert!(matches!(
        trie::get(&mut storage, &[1; 32], b"key"),
        Err(trie::LookupError::MissingNode(root)) if root == [1; 32]
    ));
    assert_eq!(storage.reads, 1);
    println!("statically linked whole Lean lookup: missing-node result verified");
}
