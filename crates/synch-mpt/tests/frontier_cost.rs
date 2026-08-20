//! What the §5.2 frontier *costs*, by counting node reads rather than timing:
//! a fetch reads each node about once, and one against a held root touches
//! only what changed.

use std::{cell::Cell, convert::Infallible};

use synch_core::Hash;
use synch_mpt::{MemStore, MissingWalk, NodeStore, Trie};

/// A store that counts the node reads made through it.
#[derive(Debug)]
struct Counting<'a> {
    inner: &'a MemStore,
    reads: Cell<usize>,
}

impl<'a> Counting<'a> {
    fn new(inner: &'a MemStore) -> Self {
        Counting {
            inner,
            reads: Cell::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.get()
    }
}

impl NodeStore for Counting<'_> {
    type Error = Infallible;

    fn get_node(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Infallible> {
        self.reads.set(self.reads.get() + 1);
        self.inner.get_node(hash)
    }
    fn put_node(&self, hash: &Hash, data: &[u8]) -> Result<(), Infallible> {
        self.inner.put_node(hash, data)
    }
    fn get_value(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Infallible> {
        self.inner.get_value(hash)
    }
    fn put_value(&self, hash: &Hash, data: &[u8]) -> Result<(), Infallible> {
        self.inner.put_value(hash, data)
    }
}

/// Fills a store with `count` file-shaped keys and returns the root.
fn populate(store: &MemStore, count: usize, marker: &str) -> Hash {
    let trie = Trie::new(store);
    let mut root = Hash::EMPTY;
    for i in 0..count {
        root = trie
            .insert(
                root,
                format!("f:media/dir{:02}/file{i:06}", i % 100).as_bytes(),
                format!("{marker} {i}").as_bytes(),
            )
            .unwrap();
    }
    root
}

#[test]
fn a_fetch_reads_each_node_about_once() {
    // The walk is resumed between batches, not restarted at the root — a restart
    // makes a cold fetch quadratic: invisible in a small test, fatal at scale.
    let source = MemStore::new();
    let root = populate(&source, 2_000, "v1");
    // Reachable from the final root, not everything the store holds: building
    // the trie key by key leaves every intermediate root's nodes behind too.
    let total = Trie::new(&source).reachable(root).unwrap().nodes.len();

    let destination = MemStore::new();
    let counting = Counting::new(&destination);
    let trie = Trie::new(&counting);
    let mut walk = MissingWalk::new(root);
    let batch = 64;

    let mut rounds = 0;
    loop {
        let missing = walk.next_batch(&trie, batch).unwrap();
        if missing.is_empty() {
            if walk.is_exhausted() {
                break;
            }
            walk.resume();
            continue;
        }
        for (_path, hash) in &missing.nodes {
            let bytes = source.get_node(hash).unwrap().expect("source has it");
            destination.put_node(hash, &bytes).unwrap();
        }
        for (_path, hash) in &missing.values {
            let bytes = source.get_value(hash).unwrap().expect("source has it");
            destination.put_value(hash, &bytes).unwrap();
        }
        walk.resume();
        rounds += 1;
        assert!(rounds < total, "the fetch is not converging");
    }

    assert_eq!(destination.node_count(), total, "every node arrived");
    // Each node is read once absent and once landed; a restart per batch read `total²/batch` times.
    assert!(
        counting.reads() < total * 4,
        "a cold fetch of {total} nodes read {} times; it is re-walking what it \
         has already pulled",
        counting.reads()
    );
}

#[test]
fn a_fetch_against_a_held_root_touches_only_what_changed() {
    // A matching hash in a trie held whole proves the subtree is here, which
    // is what makes an incremental sync cost the change (§5.2).
    let store = MemStore::new();
    let old_root = populate(&store, 2_000, "v1");
    let full = Trie::new(&store).reachable(old_root).unwrap().nodes.len();

    // One key changes; both roots' nodes live here, so anything the walk reads
    // it reads because it chose to descend there.
    let trie = Trie::new(&store);
    let new_root = trie
        .insert(old_root, b"f:media/dir00/file000000", b"changed")
        .unwrap();

    let counting = Counting::new(&store);
    let counted = Trie::new(&counting);
    let mut walk = MissingWalk::since(Some(old_root), new_root);
    let missing = walk.next_batch(&counted, 256).unwrap();

    assert!(missing.is_empty(), "everything is present locally");
    assert!(walk.is_exhausted());
    // The changed path is a handful of nodes deep; the tree is thousands wide.
    assert!(
        counting.reads() < 100,
        "a one-key change over a {full}-node trie read {} nodes; the walk is \
         not pruning against the root it already holds",
        counting.reads()
    );

    // Without the reference it costs the whole tree — the contrast the pruning exists to make.
    let counting = Counting::new(&store);
    let counted = Trie::new(&counting);
    let mut blind = MissingWalk::new(new_root);
    blind.next_batch(&counted, 256).unwrap();
    assert!(
        counting.reads() > full / 2,
        "expected the unpruned walk to visit the tree, it read {}",
        counting.reads()
    );
}

#[test]
fn pruning_never_reports_a_partial_trie_complete() {
    // The pruning rule leans on the reference being held *whole*: shared structure
    // that is genuinely absent must still be reported missing.
    let source = MemStore::new();
    let old_root = populate(&source, 500, "v1");
    let trie = Trie::new(&source);
    let new_root = trie
        .insert(old_root, b"f:media/dir00/file000000", b"changed")
        .unwrap();

    // A destination holding nothing, handed the old root as a reference it does not have.
    let destination = MemStore::new();
    let trie = Trie::new(&destination);
    let mut walk = MissingWalk::since(Some(old_root), new_root);
    let missing = walk.next_batch(&trie, 256).unwrap();
    assert!(!missing.is_empty());
    assert!(!walk.is_exhausted());
}
