//! Model-based property tests for the trie (§11, testing strategy).
//!
//! The model is a `BTreeMap`: the trie must agree with it on every read, its
//! root must depend only on the map contents and never on insertion order,
//! diffs must be complete, and deletion must leave the canonical trie.

use std::collections::BTreeMap;

use proptest::prelude::*;
use synch_core::Hash;
use synch_mpt::{ChangeKind, MemStore, NodeStore, Trie};

/// Keys drawn from a small alphabet so shared prefixes, prefix-of-another
/// keys, and branch splits all occur frequently.
fn key_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop::sample::select(vec![0u8, 1, 15, 16, 255, b'a', b'b']),
        1..8,
    )
}

fn value_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..300)
}

fn map_strategy() -> impl Strategy<Value = Vec<(Vec<u8>, Vec<u8>)>> {
    prop::collection::vec((key_strategy(), value_strategy()), 0..40)
}

fn build(store: &MemStore, items: &[(Vec<u8>, Vec<u8>)]) -> (Hash, BTreeMap<Vec<u8>, Vec<u8>>) {
    let trie = Trie::new(store);
    let mut root = Hash::EMPTY;
    let mut model = BTreeMap::new();
    for (k, v) in items {
        root = trie.insert(root, k, v).unwrap();
        model.insert(k.clone(), v.clone());
    }
    (root, model)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Every key the model holds reads back identically from the trie, and
    /// iteration yields exactly the model in lexicographic order.
    #[test]
    fn matches_btreemap_model(items in map_strategy(), probes in prop::collection::vec(key_strategy(), 0..10)) {
        let store = MemStore::new();
        let trie = Trie::new(&store);
        let (root, model) = build(&store, &items);

        for (k, v) in &model {
            let got = trie.get(root, k).unwrap();
            prop_assert_eq!(got.as_ref(), Some(v));
        }
        for probe in &probes {
            prop_assert_eq!(trie.get(root, probe).unwrap(), model.get(probe).cloned());
        }
        let iterated: Vec<(Vec<u8>, Vec<u8>)> = trie.iter(root).unwrap();
        let expected: Vec<(Vec<u8>, Vec<u8>)> = model.into_iter().collect();
        prop_assert_eq!(iterated, expected);
    }

    /// The root hash is a function of the key/value map alone: inserting the
    /// same pairs in any order yields the same root.
    #[test]
    fn root_is_order_independent(items in map_strategy(), seed in any::<u64>()) {
        let map: BTreeMap<Vec<u8>, Vec<u8>> = items.into_iter().collect();
        let forward: Vec<(Vec<u8>, Vec<u8>)> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        let mut shuffled = forward.clone();
        // A deterministic xorshift shuffle driven by the proptest-supplied seed.
        let mut state = seed | 1;
        for i in (1..shuffled.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            shuffled.swap(i, (state % (i as u64 + 1)) as usize);
        }

        let store_a = MemStore::new();
        let (root_a, _) = build(&store_a, &forward);
        let store_b = MemStore::new();
        let (root_b, _) = build(&store_b, &shuffled);
        prop_assert_eq!(root_a, root_b);
    }

    /// Deleting keys leaves exactly the canonical trie of the remaining map:
    /// the root after deletion equals the root of a trie built fresh from the
    /// survivors, so no non-canonical residue survives a delete.
    #[test]
    fn canonical_after_delete(items in map_strategy(), to_delete in prop::collection::vec(key_strategy(), 0..12)) {
        let map: BTreeMap<Vec<u8>, Vec<u8>> = items.into_iter().collect();
        let all: Vec<(Vec<u8>, Vec<u8>)> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        let store = MemStore::new();
        let trie = Trie::new(&store);
        let (mut root, mut model) = build(&store, &all);
        for key in &to_delete {
            root = trie.remove(root, key).unwrap();
            model.remove(key);
        }

        let fresh_store = MemStore::new();
        let survivors: Vec<(Vec<u8>, Vec<u8>)> = model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let (fresh_root, _) = build(&fresh_store, &survivors);

        prop_assert_eq!(root, fresh_root);
        prop_assert_eq!(trie.iter(root).unwrap(), survivors);
        if model.is_empty() {
            prop_assert_eq!(root, Hash::EMPTY);
        }
    }

    /// `diff(a, b)` is complete: applying it to `a` reproduces `b` exactly.
    #[test]
    fn diff_completeness(base in map_strategy(), edits in map_strategy(), removals in prop::collection::vec(key_strategy(), 0..8)) {
        let store = MemStore::new();
        let trie = Trie::new(&store);
        let (root_a, _) = build(&store, &base);

        let mut root_b = root_a;
        for (k, v) in &edits {
            root_b = trie.insert(root_b, k, v).unwrap();
        }
        for k in &removals {
            root_b = trie.remove(root_b, k).unwrap();
        }

        let changes = trie.diff_resolved(root_a, root_b).unwrap();

        // Applying the diff to `a` must yield exactly `b`.
        let mut replayed = root_a;
        for change in &changes {
            replayed = match &change.new {
                Some(v) => trie.insert(replayed, &change.key, v).unwrap(),
                None => trie.remove(replayed, &change.key).unwrap(),
            };
        }
        prop_assert_eq!(replayed, root_b);

        // And the diff must be minimal: every reported key really differs.
        for change in &changes {
            let before = trie.get(root_a, &change.key).unwrap();
            let after = trie.get(root_b, &change.key).unwrap();
            prop_assert_ne!(&before, &after);
            prop_assert_eq!(&before, &change.old);
            prop_assert_eq!(&after, &change.new);
            match change.kind() {
                ChangeKind::Added => prop_assert!(before.is_none() && after.is_some()),
                ChangeKind::Deleted => prop_assert!(before.is_some() && after.is_none()),
                ChangeKind::Changed => prop_assert!(before.is_some() && after.is_some()),
            }
        }

        // Nothing outside the diff may have changed.
        let keys_in_diff: std::collections::BTreeSet<&Vec<u8>> = changes.iter().map(|c| &c.key).collect();
        for (k, v) in trie.iter(root_a).unwrap() {
            if !keys_in_diff.contains(&k) {
                prop_assert_eq!(trie.get(root_b, &k).unwrap(), Some(v));
            }
        }
    }

    /// Prefix scans agree with filtering the model, including pagination.
    #[test]
    fn scan_matches_model(items in map_strategy(), prefix in prop::collection::vec(prop::sample::select(vec![0u8, 1, 15, b'a']), 0..3)) {
        let store = MemStore::new();
        let trie = Trie::new(&store);
        let (root, model) = build(&store, &items);

        let expected: Vec<(Vec<u8>, Vec<u8>)> = model
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        prop_assert_eq!(trie.scan(root, &prefix, None, None).unwrap(), expected.clone());

        // Paging in twos must reconstruct the same sequence.
        let mut paged = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let page = trie.scan(root, &prefix, cursor.as_deref(), Some(2)).unwrap();
            if page.is_empty() {
                break;
            }
            cursor = Some(page.last().unwrap().0.clone());
            paged.extend(page);
        }
        prop_assert_eq!(paged, expected);
    }

    /// Every key in a complete trie has a proof that verifies, and every absent
    /// key has a verifying proof of absence. Behind the `proofs` feature with
    /// the module it exercises (§13, DESIGN.md §4.3).
    #[cfg(feature = "proofs")]
    #[test]
    fn proofs_verify(items in map_strategy(), probes in prop::collection::vec(key_strategy(), 0..8)) {
        let store = MemStore::new();
        let trie = Trie::new(&store);
        let (root, model) = build(&store, &items);

        for (k, v) in &model {
            let proof = trie.prove(root, k).unwrap();
            let got = proof.verify(root, k).unwrap();
            prop_assert_eq!(got.as_ref(), Some(v));
        }
        for probe in &probes {
            let proof = trie.prove(root, probe).unwrap();
            prop_assert_eq!(proof.verify(root, probe).unwrap(), model.get(probe).cloned());
        }
    }

    /// A complete trie reports nothing missing, and every reachable node is
    /// present — the invariant the §5.2 head flip depends on.
    #[test]
    fn complete_tries_report_no_missing(items in map_strategy()) {
        let store = MemStore::new();
        let trie = Trie::new(&store);
        let (root, _) = build(&store, &items);
        prop_assert!(trie.is_complete(root).unwrap());
        prop_assert!(trie.missing(root, 100).unwrap().is_empty());

        let reachable = trie.reachable(root).unwrap();
        for node in &reachable.nodes {
            prop_assert!(store.get_node(node).unwrap().is_some());
        }
    }
}
