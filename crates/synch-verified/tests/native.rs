use proptest::prelude::*;
use synch_verified::{group_count, settle_size, Scope, Settlement, Shape};

#[test]
fn scalar_exports_cover_zero_group_edges_and_maximum_size() {
    for size in [0, 1, 16383, 16384, 16385, u64::MAX] {
        assert_eq!(
            group_count(size),
            u128::from(size).div_ceil(16384).max(1) as u64
        );
        assert_eq!(
            settle_size(true, true, true, true, size, size),
            Settlement::Keep
        );
    }
    assert_eq!(
        settle_size(true, false, false, false, 0, 16384),
        Settlement::Keep
    );
    assert_eq!(
        settle_size(true, false, false, false, 16384, 16385),
        Settlement::Reset
    );
    assert_eq!(
        settle_size(true, false, false, true, 16384, 16385),
        Settlement::Refuse
    );
    assert_eq!(
        settle_size(false, true, true, true, 0, u64::MAX),
        Settlement::Keep
    );
}

#[test]
fn native_exports_deny_the_spine_payload_and_handle_empty_scopes() {
    let scope = Scope::new(Some(&[vec![6, 1, 6, 2]]), &[]);
    assert!(scope.admits_path(&[6, 1]));
    assert!(scope.admits_node(
        &[6, 1],
        Shape::Branch {
            inline_value: false
        }
    ));
    assert!(!scope.admits_value(
        &[6, 1],
        Shape::Branch {
            inline_value: false
        }
    ));
    assert!(!scope.admits_node(&[6, 1], Shape::Branch { inline_value: true }));
    assert!(!Scope::new(Some(&[]), &[]).admits_path(&[]));
    let full = Scope::new(None, &[]);
    assert!(full.admits_key(&[]));
    assert!(!full.admits_value(&[], Shape::Extension(&[])));
}

#[test]
fn immutable_scopes_can_be_shared_called_and_dropped_on_foreign_threads() {
    let scope = Scope::new(Some(&[vec![1, 2]]), &[vec![4, 5]]);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let scope = scope.clone();
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    assert!(scope.admits_key(&[1, 2, 3]));
                    assert!(scope.admits_path(&[4]));
                    assert!(!scope.contains_subtree(&[4, 5]));
                }
                scope
            })
        })
        .collect();
    drop(scope);
    for thread in threads {
        drop(thread.join().unwrap());
    }
    // Also exercise first-use and last-drop on fresh threads.
    for _ in 0..16 {
        std::thread::spawn(|| assert!(Scope::new(None, &[]).admits_path(&[0])))
            .join()
            .unwrap();
    }
}

#[test]
fn scopes_in_older_rust_tls_outlive_the_lean_thread_guard_safely() {
    thread_local! {
        static SLOT: std::cell::RefCell<Option<Scope>> = const { std::cell::RefCell::new(None) };
    }
    for _ in 0..16 {
        std::thread::spawn(|| {
            SLOT.with(|slot| {
                // SLOT's destructor is registered before Lean's THREAD guard.
                let mut slot = slot.borrow_mut();
                *slot = Some(Scope::new(Some(&[vec![1, 2]]), &[]));
            });
        })
        .join()
        .unwrap();
    }
}

proptest! {
    #[test]
    fn group_count_and_settlement_match_the_integer_contract(
        recorded in any::<u64>(), claimed in any::<u64>(),
        row in any::<bool>(), durable in any::<bool>(), complete in any::<bool>(), final_held in any::<bool>(),
    ) {
        let count = |size: u64| u128::from(size).div_ceil(16384).max(1) as u64;
        prop_assert_eq!(group_count(recorded), count(recorded));
        let expected = if !row || recorded == claimed { Settlement::Keep }
            else if durable || complete || final_held { Settlement::Refuse }
            else if count(recorded) == count(claimed) { Settlement::Keep }
            else { Settlement::Reset };
        prop_assert_eq!(settle_size(row, durable, complete, final_held, recorded, claimed), expected);
    }

    #[test]
    fn native_scope_matches_the_finite_set_contract(
        prefixes in prop::collection::vec(prop::collection::vec(0u8..16, 0..12), 0..8),
        exact in prop::collection::vec(prop::collection::vec(0u8..16, 0..12), 0..8),
        path in prop::collection::vec(0u8..16, 0..16),
        suffix in prop::collection::vec(0u8..16, 0..8),
        full in any::<bool>(),
    ) {
        let scope = Scope::new(if full { None } else { Some(&prefixes) }, &exact);
        let subtree = |p: &[u8]| full || prefixes.iter().any(|grant| p.starts_with(grant));
        let key = |p: &[u8]| subtree(p) || exact.iter().any(|k| k == p);
        let admitted = |p: &[u8]| full || prefixes.iter().any(|g| p.starts_with(g) || g.starts_with(p)) || exact.iter().any(|k| k.starts_with(p));
        prop_assert_eq!(scope.contains_subtree(&path), subtree(&path));
        prop_assert_eq!(scope.admits_key(&path), key(&path));
        prop_assert_eq!(scope.admits_path(&path), admitted(&path));
        let covered = [path.as_slice(), suffix.as_slice()].concat();
        prop_assert_eq!(scope.admits_node(&path, Shape::Leaf(&suffix)), key(&covered));
        prop_assert_eq!(scope.admits_node(&path, Shape::Extension(&suffix)), admitted(&covered));
        prop_assert_eq!(scope.admits_value(&path, Shape::Leaf(&suffix)), key(&covered));
        prop_assert!(!scope.admits_value(&path, Shape::Extension(&suffix)));
        prop_assert_eq!(scope.admits_node(&path, Shape::Branch { inline_value: true }), key(&path));
        prop_assert!(scope.admits_node(&path, Shape::Branch { inline_value: false }), "hash-only branch is traversable");
        prop_assert_eq!(scope.admits_value(&path, Shape::Branch { inline_value: false }), key(&path));
    }
}
