use proptest::prelude::*;
use synch_verified::{group_count, settle_size, CertificateCache, Scope, Settlement, Shape};

#[test]
fn pin_acquisition_requires_durability_and_orders_possession_effects() {
    use synch_verified::{PinAcquisition, PinAcquisitionStep::*};
    for row in [false, true] {
        for durable in [false, true] {
            for wanted in [false, true] {
                for possession in [false, true] {
                    let mut plan = PinAcquisition::new(row, durable, wanted, possession);
                    if row && durable && (!possession || wanted) {
                        if possession {
                            assert_eq!(plan.step(), DeleteWant);
                            assert_eq!(plan.step(), DeleteWant, "polling must not advance");
                            plan.acknowledge();
                        }
                        assert_eq!(plan.step(), UpsertPin);
                        plan.acknowledge();
                        assert_eq!(plan.step(), Finished);
                        plan.acknowledge();
                        assert_eq!(plan.step(), Finished);
                    } else {
                        for _ in 0..5 {
                            assert_eq!(plan.step(), Refused);
                            plan.acknowledge();
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn deletion_protocol_checks_every_protection_and_orders_effects() {
    use synch_verified::{Deletion, DeletionStep::*};
    for row in [false, true] {
        for writing in [false, true] {
            for pinned in [false, true] {
                for referenced in [false, true] {
                    for last in [i64::MIN, -1, 0, 1, i64::MAX] {
                        for before in [None, Some(i64::MIN), Some(-1), Some(0), Some(i64::MAX)] {
                            let mut plan =
                                Deletion::new(row, writing, pinned, referenced, last, before);
                            let initial = if writing {
                                Writing
                            } else if pinned || referenced {
                                Protected
                            } else if before.is_some_and(|cutoff| !row || last >= cutoff) {
                                Skip
                            } else {
                                DeleteRow
                            };
                            assert_eq!(plan.step(), initial);
                            assert_eq!(plan.step(), initial, "polling is not acknowledgment");
                            if initial == DeleteRow {
                                for expected in
                                    [Commit, UnlinkPayload, UnlinkOutboard, Finished, Finished]
                                {
                                    plan.acknowledge();
                                    assert_eq!(plan.step(), expected);
                                }
                            } else {
                                for _ in 0..5 {
                                    plan.acknowledge();
                                    assert_eq!(plan.step(), initial);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn cas_plan_handles_empty_objects_resets_and_unbounded_input_endpoints() {
    let plan =
        synch_verified::plan_cas_commit(false, false, false, 0, 0, &[], &[(0, u64::MAX)]).unwrap();
    assert!(plan.complete);
    assert_eq!(plan.ranges, vec![(0, 1)]);
    assert!(synch_verified::plan_cas_commit(true, true, false, 1, 2, &[], &[(0, 1)]).is_none());
    let plan = synch_verified::plan_cas_commit(
        true,
        false,
        false,
        16384 * 4,
        16384 * 8,
        &[(0, 2)],
        &[(7, u64::MAX)],
    )
    .unwrap();
    assert_eq!(plan.ranges, vec![(7, 8)]);
    assert!(!plan.complete);
    let plan =
        synch_verified::plan_cas_commit(true, false, true, u64::MAX, u64::MAX, &[], &[]).unwrap();
    assert!(plan.complete);
    assert_eq!(plan.ranges, vec![(0, group_count(u64::MAX))]);
}

proptest! {
    #[test]
    fn cas_plan_matches_pointwise_group_membership(
        row in any::<bool>(), durable in any::<bool>(), complete in any::<bool>(),
        recorded in 0u64..(128 * 16384), claimed in 0u64..(128 * 16384),
        old in prop::collection::vec((0u64..150, 0u64..150), 0..32),
        incoming in prop::collection::vec((0u64..150, 0u64..150), 0..32),
    ) {
        let contains = |rs: &[(u64,u64)], g| rs.iter().any(|&(a,b)| a <= g && g < b);
        let prior = |g| row && (if complete { g < group_count(recorded) } else { contains(&old, g) });
        let decision = settle_size(row, durable, complete, prior(group_count(recorded)-1), recorded, claimed);
        let plan = synch_verified::plan_cas_commit(row, durable, complete, recorded, claimed, &old, &incoming);
        if decision == Settlement::Refuse {
            prop_assert!(plan.is_none());
        } else {
            let plan = plan.unwrap();
            let total = group_count(claimed);
            let expected = |g| g < total && (contains(&incoming, g) || (decision != Settlement::Reset && prior(g)));
            for g in 0..151 {
                prop_assert_eq!(contains(&plan.ranges, g), expected(g));
            }
            prop_assert_eq!(plan.complete, (0..total).all(expected));
            prop_assert!(plan.ranges.iter().all(|&(a,b)| a < b && b <= total));
            prop_assert!(plan.ranges.windows(2).all(|rs| rs[0].1 < rs[1].0));
        }
    }
}

fn observe(
    walk: &mut synch_verified::MissingWalk,
    reference: synch_verified::WalkNode<'_>,
    node: synch_verified::WalkNode<'_>,
) {
    walk.observe_present(
        reference,
        node,
        synch_verified::ChildShape::Branch,
        None,
        true,
    )
    .unwrap();
}

fn complete(walk: &mut synch_verified::MissingWalk) {
    observe(
        walk,
        synch_verified::WalkNode::Leaf(&[]),
        synch_verified::WalkNode::Leaf(&[]),
    );
}

#[test]
fn shared_leaf_must_be_validated_again_when_reached_deeper() {
    use synch_verified::{ChildShape, WalkError, WalkNode};
    let mut root_children = [None; 16];
    root_children[1] = Some([2; 32]); // LIFO visits the shared leaf at depth 1 first.
    root_children[0] = Some([3; 32]);
    let mut nested_children = [None; 16];
    nested_children[0] = Some([2; 32]);
    let mut walk =
        synch_verified::MissingWalk::new(&Scope::new(None, &[]), None, Some(&[1; 32]), 2);
    walk.poll().unwrap().unwrap();
    observe(
        &mut walk,
        WalkNode::Leaf(&[]),
        WalkNode::Branch(&root_children),
    );
    assert_eq!(walk.poll().unwrap().unwrap().hash, [2; 32]);
    observe(&mut walk, WalkNode::Leaf(&[]), WalkNode::Leaf(&[5])); // key depth 2 is legal.
    assert_eq!(walk.poll().unwrap().unwrap().hash, [3; 32]);
    observe(
        &mut walk,
        WalkNode::Leaf(&[]),
        WalkNode::Branch(&nested_children),
    );
    let deeper = walk
        .poll()
        .unwrap()
        .expect("different-depth visit cannot be deduplicated");
    assert_eq!((deeper.hash, deeper.path), ([2; 32], vec![0, 0]));
    assert_eq!(
        walk.observe_present(
            WalkNode::Leaf(&[]),
            WalkNode::Leaf(&[5]),
            ChildShape::Absent,
            None,
            true
        ),
        Err(WalkError::ValueDepth(3))
    );
    assert!(!walk.is_exhausted());
}

#[test]
fn interrupted_read_remains_pending_across_poll_resume_and_batch_reset() {
    let mut walk =
        synch_verified::MissingWalk::new(&Scope::new(None, &[]), None, Some(&[1; 32]), 8);
    let first = walk.poll().unwrap().unwrap();
    assert!(!walk.is_exhausted());
    walk.resume();
    walk.start_batch();
    let retry = walk.poll().unwrap().unwrap();
    assert_eq!((retry.hash, retry.path), (first.hash, first.path));
    assert!(!walk.is_exhausted());
    complete(&mut walk);
    assert!(walk.is_exhausted());
    assert!(walk.poll().unwrap().is_none());
    assert_eq!(
        walk.observe_absent(false),
        Err(synch_verified::WalkError::UnexpectedObservation)
    );
    assert!(!walk.is_exhausted());
}

#[test]
fn observations_refuse_only_absent_spines_not_granted_subtrees() {
    for (scope, request) in [
        (Scope::new(None, &[]), true),
        (Scope::new(Some(&[vec![1, 2]]), &[]), false),
    ] {
        let mut walk = synch_verified::MissingWalk::new(&scope, None, Some(&[1; 32]), 8);
        walk.poll().unwrap().unwrap();
        assert_eq!(walk.observe_absent(true).unwrap(), request);
        assert_eq!(walk.is_exhausted(), !request);
        if request {
            walk.resume();
            walk.poll().unwrap().unwrap();
            assert!(walk.observe_absent(false).unwrap());
        }
    }
}

#[test]
fn observations_defer_every_node_waiting_for_a_shared_payload() {
    use synch_verified::{ChildShape, WalkNode};
    let mut children = [None; 16];
    children[0] = Some([2; 32]);
    children[1] = Some([3; 32]);
    let mut walk =
        synch_verified::MissingWalk::new(&Scope::new(None, &[]), None, Some(&[1; 32]), 8);
    walk.poll().unwrap().unwrap();
    assert!(walk
        .observe_present(
            WalkNode::Leaf(&[]),
            WalkNode::Branch(&children),
            ChildShape::Absent,
            None,
            false
        )
        .unwrap()
        .is_none());
    for expected in [Some([9; 32]), None] {
        walk.poll().unwrap().unwrap();
        assert_eq!(
            walk.observe_present(
                WalkNode::Leaf(&[]),
                WalkNode::Leaf(&[]),
                ChildShape::Absent,
                Some(&[9; 32]),
                false
            )
            .unwrap(),
            expected
        );
    }
    assert!(walk.poll().unwrap().is_none());
    assert!(!walk.is_exhausted());
    walk.start_batch();
    walk.resume();
    for _ in 0..2 {
        walk.poll().unwrap().unwrap();
        assert!(walk
            .observe_present(
                WalkNode::Leaf(&[]),
                WalkNode::Leaf(&[]),
                ChildShape::Absent,
                Some(&[9; 32]),
                true
            )
            .unwrap()
            .is_none());
    }
    assert!(walk.poll().unwrap().is_none());
    assert!(walk.is_exhausted());
}

#[test]
fn observations_validate_leaf_depth_and_deferred_extension_children() {
    use synch_verified::{ChildShape, WalkError, WalkNode};
    let mut deep =
        synch_verified::MissingWalk::new(&Scope::new(None, &[]), None, Some(&[1; 32]), 1);
    deep.poll().unwrap().unwrap();
    assert_eq!(
        deep.observe_present(
            WalkNode::Leaf(&[]),
            WalkNode::Leaf(&[1, 2]),
            ChildShape::Absent,
            None,
            true
        ),
        Err(WalkError::ValueDepth(2))
    );
    deep.resume();
    assert_eq!(deep.poll().unwrap_err(), WalkError::ValueDepth(2));
    assert!(!deep.is_exhausted());

    let mut walk =
        synch_verified::MissingWalk::new(&Scope::new(None, &[]), None, Some(&[1; 32]), 8);
    walk.poll().unwrap().unwrap();
    walk.observe_present(
        WalkNode::Leaf(&[]),
        WalkNode::Extension {
            prefix: &[0],
            child: &[2; 32],
        },
        ChildShape::Absent,
        None,
        false,
    )
    .unwrap();
    walk.poll().unwrap().unwrap();
    assert!(walk.observe_absent(false).unwrap());
    walk.resume();
    walk.poll().unwrap().unwrap();
    assert_eq!(
        walk.observe_present(
            WalkNode::Leaf(&[]),
            WalkNode::Leaf(&[]),
            ChildShape::Absent,
            None,
            true
        ),
        Err(WalkError::NotBranch([2; 32]))
    );
    walk.resume();
    assert_eq!(walk.poll().unwrap_err(), WalkError::NotBranch([2; 32]));
    assert_eq!(
        walk.observe_absent(true),
        Err(WalkError::NotBranch([2; 32]))
    );
    assert!(!walk.is_exhausted());
}

#[test]
fn walk_pairs_branch_slots_without_dropping_unmatched_children() {
    use synch_verified::WalkNode;
    let mut children = [None; 16];
    let mut reference = [None; 16];
    children[0] = Some([2; 32]);
    children[7] = Some([3; 32]);
    children[15] = Some([4; 32]);
    reference[0] = children[0]; // Only this target edge can be pruned.
    reference[7] = Some([8; 32]);
    reference[8] = Some([4; 32]); // Equal hash, wrong position: must not prune slot 15.
    let mut walk =
        synch_verified::MissingWalk::new(&Scope::new(None, &[]), None, Some(&[1; 32]), 8);
    walk.poll().unwrap().unwrap();
    observe(
        &mut walk,
        WalkNode::Branch(&reference),
        WalkNode::Branch(&children),
    );
    let p = walk.poll().unwrap().unwrap();
    assert_eq!((p.path, p.hash, p.reference), (vec![15], [4; 32], None));
    complete(&mut walk);
    let p = walk.poll().unwrap().unwrap();
    assert_eq!(
        (p.path, p.hash, p.reference),
        (vec![7], [3; 32], Some([8; 32]))
    );
    complete(&mut walk);
    assert!(walk.poll().unwrap().is_none());
    assert!(walk.is_exhausted());
}

#[test]
fn walk_pairs_extensions_only_with_identical_runs_and_filters_scope() {
    use synch_verified::WalkNode;
    for (run, expected) in [(&[1, 2][..], Some([9; 32])), (&[1, 3][..], None)] {
        let mut walk =
            synch_verified::MissingWalk::new(&Scope::new(None, &[]), None, Some(&[1; 32]), 8);
        walk.poll().unwrap().unwrap();
        observe(
            &mut walk,
            WalkNode::Extension {
                prefix: run,
                child: &[9; 32],
            },
            WalkNode::Extension {
                prefix: &[1, 2],
                child: &[2; 32],
            },
        );
        let p = walk.poll().unwrap().unwrap();
        assert_eq!((p.path, p.reference), (vec![1, 2], expected));
    }
    let mut children = [None; 16];
    children[0] = Some([2; 32]);
    children[1] = Some([3; 32]);
    let scope = Scope::new(Some(&[vec![0]]), &[]);
    let mut walk = synch_verified::MissingWalk::new(&scope, None, Some(&[1; 32]), 8);
    walk.poll().unwrap().unwrap();
    observe(
        &mut walk,
        WalkNode::Extension {
            prefix: &[0],
            child: &[2; 32],
        },
        WalkNode::Branch(&children),
    );
    let p = walk.poll().unwrap().unwrap();
    assert_eq!((p.path, p.reference), (vec![0], None));
    complete(&mut walk);
    assert!(walk.poll().unwrap().is_none());
}

#[test]
fn walk_retries_lifo_across_thread_migration() {
    let mut walk =
        synch_verified::MissingWalk::new(&Scope::new(None, &[]), None, Some(&[1; 32]), 8);
    assert_eq!(walk.poll().unwrap().unwrap().hash, [1; 32]);
    let mut children = [None; 16];
    children[0] = Some([2; 32]);
    children[1] = Some([3; 32]);
    observe(
        &mut walk,
        synch_verified::WalkNode::Leaf(&[]),
        synch_verified::WalkNode::Branch(&children),
    );
    assert_eq!(walk.poll().unwrap().unwrap().hash, [3; 32]);
    assert!(walk.observe_absent(false).unwrap());
    assert_eq!(walk.poll().unwrap().unwrap().hash, [2; 32]);
    assert!(walk.observe_absent(false).unwrap());
    assert!(walk.poll().unwrap().is_none());
    assert!(!walk.is_exhausted());
    walk.start_batch();
    walk.resume();
    // Move an already populated Lean state to a fresh Rust thread.
    std::thread::spawn(move || {
        assert_eq!(walk.poll().unwrap().unwrap().hash, [2; 32]);
        complete(&mut walk);
        assert_eq!(walk.poll().unwrap().unwrap().hash, [3; 32]);
        complete(&mut walk);
        assert!(walk.poll().unwrap().is_none());
        assert!(walk.is_exhausted());
    })
    .join()
    .unwrap();
}

#[test]
fn walk_checks_depth_before_reference_pruning_and_faults_stick() {
    let mut walk =
        synch_verified::MissingWalk::new(&Scope::new(None, &[]), None, Some(&[1; 32]), 1);
    walk.poll().unwrap().unwrap();
    observe(
        &mut walk,
        synch_verified::WalkNode::Extension {
            prefix: &[0, 1],
            child: &[2; 32],
        },
        synch_verified::WalkNode::Extension {
            prefix: &[0, 1],
            child: &[2; 32],
        },
    );
    assert_eq!(
        walk.poll().unwrap_err(),
        synch_verified::WalkError::NodeDepth(2)
    );
    walk.resume();
    walk.start_batch();
    assert_eq!(
        walk.poll().unwrap_err(),
        synch_verified::WalkError::NodeDepth(2)
    );
    assert!(!walk.is_exhausted());
}

#[test]
fn walk_dedup_is_positional_on_scope_spines_and_hash_only_inside_grants() {
    for (scope, expected) in [
        (Scope::new(None, &[]), 1),
        (Scope::new(Some(&[vec![0, 5], vec![1, 5]]), &[]), 2),
    ] {
        let mut walk = synch_verified::MissingWalk::new(&scope, None, Some(&[1; 32]), 8);
        walk.poll().unwrap().unwrap();
        let mut children = [None; 16];
        children[0] = Some([2; 32]);
        children[1] = Some([2; 32]);
        observe(
            &mut walk,
            synch_verified::WalkNode::Leaf(&[]),
            synch_verified::WalkNode::Branch(&children),
        );
        let mut count = 0;
        while walk.poll().unwrap().is_some() {
            count += 1;
            complete(&mut walk);
        }
        assert_eq!(count, expected);
        assert!(walk.is_exhausted());
    }
    let denied = Scope::new(Some(&[]), &[]);
    let walk = synch_verified::MissingWalk::new(&denied, None, Some(&[1; 32]), 8);
    assert!(walk.is_exhausted());
}

#[test]
fn certificate_cache_owns_nested_invalidation_and_bounded_retention() {
    let mut cache = CertificateCache::new(2);
    assert!(cache.certify(0, b"a"));
    assert!(cache.certify(0, b"b"));
    cache.begin(&[b"a"]);
    assert_eq!(cache.epoch(), 1);
    assert!(!cache.contains(b"a"));
    assert!(!cache.certify(1, b"c"));
    cache.begin(&[b"a"]);
    cache.finish();
    assert!(!cache.contains(b"a"));
    cache.finish();
    assert_eq!(cache.epoch(), 4);
    assert!(cache.contains(b"a"));
    assert!(!cache.contains(b"b"));
    assert!(!cache.certify(0, b"stale"));
    assert!(!cache.certify(u64::MAX, b"terminal"));
    assert!(cache.certify(4, b"b"));
    assert!(cache.certify(4, b"c"));
    assert!(!cache.contains(b"a"));
    assert!(!cache.contains(b"b"));
    assert!(cache.contains(b"c"));
}

#[test]
fn certificate_updates_can_move_between_foreign_threads() {
    let cache = std::sync::Arc::new(std::sync::Mutex::new(CertificateCache::new(32)));
    let threads: Vec<_> = (0u8..8)
        .map(|key| {
            let cache = cache.clone();
            std::thread::spawn(move || {
                for _ in 0..100 {
                    let mut cache = cache.lock().unwrap();
                    cache.begin(&[]);
                    cache.finish();
                    let epoch = cache.epoch();
                    assert!(cache.certify(epoch, &[key]));
                    assert!(cache.contains(&[key]));
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(cache.lock().unwrap().epoch(), 1600);
}

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
