//! The whole native completeness operation, including its memo and raw host
//! boundary. The independent Rust requesting walk remains an oracle until
//! its own fetch cutover.
use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
    io,
};

use synch_core::{Hash, OriginId, ScopeKeys, INLINE_VALUE_MAX};
use synch_mpt::{MemStore, MissingWalk, NodeStore, Scope, Trie};

#[derive(Default)]
struct Observed {
    bytes: MemStore,
    calls: RefCell<Vec<&'static str>>,
    known: RefCell<HashSet<Hash>>,
    epoch: Cell<u64>,
    fail_at: Cell<Option<usize>>,
    invalidate_on_read: Cell<bool>,
    validate_only: Cell<bool>,
    refuse: Cell<bool>,
}

impl Observed {
    fn step(&self, name: &'static str) -> io::Result<()> {
        let index = self.calls.borrow().len();
        self.calls.borrow_mut().push(name);
        if self.fail_at.get() == Some(index) {
            return Err(io::Error::other(format!("injected {name}")));
        }
        Ok(())
    }

    fn fixture() -> (Self, Hash) {
        let store = Self::default();
        let root = Trie::new(&store.bytes)
            .insert(Hash::EMPTY, b"key", &[7; INLINE_VALUE_MAX + 1])
            .unwrap();
        (store, root)
    }
}

impl NodeStore for Observed {
    type Error = io::Error;

    fn get_node(&self, hash: &Hash) -> io::Result<Option<Vec<u8>>> {
        self.step("node")?;
        if self.invalidate_on_read.replace(false) {
            self.epoch.set(self.epoch.get() + 2);
            self.known.borrow_mut().clear();
        }
        Ok(self.bytes.get_node(hash).unwrap())
    }

    fn put_node(&self, hash: &Hash, bytes: &[u8]) -> io::Result<()> {
        self.bytes.put_node(hash, bytes).unwrap();
        Ok(())
    }

    fn get_value(&self, hash: &Hash) -> io::Result<Option<Vec<u8>>> {
        self.step("value_payload")?;
        Ok(self.bytes.get_value(hash).unwrap())
    }

    fn put_value(&self, hash: &Hash, bytes: &[u8]) -> io::Result<()> {
        self.bytes.put_value(hash, bytes).unwrap();
        Ok(())
    }

    fn has_value(&self, hash: &Hash) -> io::Result<bool> {
        self.step("value_presence")?;
        Ok(self.bytes.has_value(hash).unwrap())
    }

    fn is_known_complete(&self, key: &Hash) -> io::Result<bool> {
        self.step("known")?;
        Ok(self.known.borrow().contains(key))
    }

    fn completeness_generation(&self) -> io::Result<u64> {
        self.step("generation")?;
        Ok(self.epoch.get())
    }

    fn note_complete_at(&self, key: &Hash, generation: u64) -> io::Result<bool> {
        self.step("certify")?;
        if generation != self.epoch.get() || generation == u64::MAX {
            return Ok(false);
        }
        if !self.validate_only.get() {
            self.known.borrow_mut().insert(*key);
        }
        Ok(true)
    }

    fn owns_node(&self, owner: &OriginId, hash: &Hash) -> io::Result<bool> {
        self.step("provenance")?;
        Ok(self.bytes.owns_node(owner, hash).unwrap())
    }

    fn is_redacted(&self, _: &Hash, _: Option<&[u8]>) -> io::Result<bool> {
        self.step("redaction")?;
        Ok(self.refuse.get())
    }
}

#[test]
fn a_refusal_cannot_turn_missing_shared_entries_into_a_complete_empty_view() {
    let publisher = MemStore::default();
    let root = Trie::new(&publisher)
        .insert(Hash::EMPTY, b"shared/file", b"published value")
        .unwrap();
    let destination = Observed::default();
    destination.refuse.set(true);
    let scope = Scope::of(&ScopeKeys {
        prefixes: vec![b"shared/".to_vec()],
        exact: vec![],
    });
    let trie = Trie::new(&destination);
    assert!(!trie.is_complete_scoped(root, &scope).unwrap());
    assert!(destination.known.borrow().is_empty());
    assert!(trie.scan(root, b"shared/", None, None).is_err());
    let mut walk = MissingWalk::scoped(None, root, scope);
    assert!(!walk.next_batch(&trie, 64).unwrap().is_empty());
    assert!(!walk.is_exhausted());
}

#[test]
fn a_new_certificate_follows_reads_and_a_known_one_skips_them() {
    let (store, root) = Observed::fixture();
    let trie = Trie::new(&store);
    assert!(trie.is_complete(root).unwrap());
    assert_eq!(
        *store.calls.borrow(),
        ["known", "generation", "node", "value_presence", "certify"]
    );
    store.calls.borrow_mut().clear();
    assert!(trie.is_complete(root).unwrap());
    assert_eq!(*store.calls.borrow(), ["known"]);
}

#[test]
fn an_invalidation_during_the_walk_cannot_certify_a_fresh_ticket() {
    let (store, root) = Observed::fixture();
    store.invalidate_on_read.set(true);
    assert!(!Trie::new(&store).is_complete(root).unwrap());
    assert!(store.known.borrow().is_empty());
    assert_eq!(store.epoch.get(), 2);
    assert!(Trie::new(&store).is_complete(root).unwrap());
    assert!(store.known.borrow().contains(&root));
}

#[test]
fn host_failures_are_preserved_and_never_leave_a_certificate() {
    for (index, effect) in ["known", "generation", "node", "value_presence", "certify"]
        .iter()
        .enumerate()
    {
        let (store, root) = Observed::fixture();
        store.fail_at.set(Some(index));
        let error = Trie::new(&store).is_complete(root).unwrap_err();
        assert!(
            error.to_string().contains(&format!("injected {effect}")),
            "{error}"
        );
        assert!(store.known.borrow().is_empty());
        store.fail_at.set(None);
        assert!(Trie::new(&store).is_complete(root).unwrap());
    }
}

#[test]
fn a_missing_value_is_not_certified_and_a_transaction_can_answer_without_caching() {
    let (store, root) = Observed::fixture();
    store.validate_only.set(true);
    assert!(Trie::new(&store).is_complete(root).unwrap());
    assert!(store.known.borrow().is_empty());
    store.bytes.clear_values();
    store.calls.borrow_mut().clear();
    assert!(!Trie::new(&store).is_complete(root).unwrap());
    assert!(!store.calls.borrow().contains(&"certify"));
    assert!(!store.calls.borrow().contains(&"value_payload"));
}

#[test]
fn narrower_scope_and_unowned_answers_cannot_certify_other_views() {
    let (store, root) = Observed::fixture();
    let trie = Trie::new(&store);
    let empty = Scope::of(&ScopeKeys::default());
    store.bytes.clear_values();
    assert!(trie.is_complete_scoped(root, &empty).unwrap());
    assert!(!trie.is_complete(root).unwrap());
    let full_key = Scope::full().memo_key(root).unwrap();
    assert!(!store.known.borrow().contains(&full_key));
    store
        .bytes
        .put_value(
            &Hash::new(&[7; INLINE_VALUE_MAX + 1]),
            &[7; INLINE_VALUE_MAX + 1],
        )
        .unwrap();
    assert!(trie.is_complete(root).unwrap());
    let owner: OriginId = "nas@cluster.example".parse().unwrap();
    assert!(!trie
        .is_complete_scoped_for(Some(&owner), root, &Scope::full())
        .unwrap());
    store.bytes.note_owned(&owner, &root).unwrap();
    assert!(trie
        .is_complete_scoped_for(Some(&owner), root, &Scope::full())
        .unwrap());
}

#[test]
fn native_completeness_matches_the_requesting_walk_on_a_shared_partial_trie() {
    let store = MemStore::new();
    let trie = Trie::new(&store);
    let mut root = Hash::EMPTY;
    for key in [b"alpha".as_slice(), b"alpine", b"beta", b"betamax"] {
        root = trie.insert(root, key, &[4; INLINE_VALUE_MAX + 1]).unwrap();
    }
    let scope = Scope::of(&ScopeKeys {
        prefixes: vec![b"al".to_vec()],
        exact: vec![b"beta".to_vec()],
    });
    for candidate in [&scope, &Scope::full()] {
        let mut oracle = MissingWalk::scoped(None, root, candidate.clone());
        let expected = oracle.next_batch(&trie, 1).unwrap().is_empty();
        assert_eq!(trie.is_complete_scoped(root, candidate).unwrap(), expected);
    }
    store.clear_values();
    for candidate in [&scope, &Scope::full()] {
        let mut oracle = MissingWalk::scoped(None, root, candidate.clone());
        let expected = oracle.next_batch(&trie, 1).unwrap().is_empty();
        assert_eq!(trie.is_complete_scoped(root, candidate).unwrap(), expected);
    }
}

#[test]
#[ignore = "120k-entry completeness cost comparison at the documented corpus size"]
fn completeness_at_the_documented_corpus_size() {
    let store = Observed::default();
    let source = Trie::new(&store.bytes);
    let mut root = Hash::EMPTY;
    for index in 0..120_000u32 {
        root = source
            .insert(
                root,
                format!("f:media/dir{:02}/file{index:06}", index % 100).as_bytes(),
                &index.to_le_bytes(),
            )
            .unwrap();
    }
    let trie = Trie::new(&store);
    let started = std::time::Instant::now();
    let mut oracle = MissingWalk::new(root);
    assert!(oracle.next_batch(&trie, 1).unwrap().is_empty());
    assert!(oracle.is_exhausted());
    let rust_elapsed = started.elapsed();
    let rust_reads = store
        .calls
        .borrow()
        .iter()
        .filter(|call| **call == "node")
        .count();
    store.calls.borrow_mut().clear();

    let started = std::time::Instant::now();
    assert!(trie.is_complete(root).unwrap());
    let lean_elapsed = started.elapsed();
    let lean_reads = store
        .calls
        .borrow()
        .iter()
        .filter(|call| **call == "node")
        .count();
    assert_eq!(
        lean_reads, rust_reads,
        "the cutover must retain the walk's read cost"
    );
    eprintln!("120k-entry completeness: Rust {rust_elapsed:?}, Lean {lean_elapsed:?}; {lean_reads} node reads each");
}
