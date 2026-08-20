//! An entry body is evidence only once bound to the **signed checkpoint** —
//! the attack is a forged body plus the one level-0 hash tile covering it,
//! leaving every higher tile and the root intact. The stronger check must
//! cost what the weaker one did.

use synch_monitor::{
    testsupport::{reference_root, MemoryLog},
    tiles::Tree,
    MonitorError,
};

const SIZE: u64 = 65_536;
const TARGET: u64 = 300; // well away from the frontier

/// A body the signed root does not commit to is refused, even when the
/// level-0 hash tile beneath it agrees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_body_and_its_level_zero_tile_are_refused_against_the_signed_root() {
    let honest = MemoryLog::new(SIZE);
    let tree = Tree::new(&honest, SIZE, 8);
    let root = tree.root().await.expect("the honest root recomputes");
    assert_eq!(root, reference_root(&honest.leaves, 0, SIZE));

    // The forgery: body and its level-0 tile changed together, every higher tile honest.
    let mut hostile = MemoryLog::new(SIZE);
    hostile.forge_at = Some(TARGET);
    hostile.forged_body = b"not a hashedrekord at all".to_vec();
    let tree = Tree::new(&hostile, SIZE, 8);
    assert_eq!(
        tree.root().await.expect("root still recomputes"),
        root,
        "the forgery leaves the checkpoint root intact — that is the attack"
    );
    assert_eq!(
        tree.subtree_hash(0, 32_768).await.expect("a prefix"),
        reference_root(&honest.leaves, 0, 32_768),
        "and the consistency prefix with it"
    );

    // The bundle really does serve the substitute...
    let served = tree
        .entry_bundle(TARGET)
        .await
        .expect("the bundle decodes")
        .into_iter()
        .find(|(index, _)| *index == TARGET)
        .expect("the target is in its bundle")
        .1;
    assert_eq!(served, hostile.forged_body);

    // ...and this is the check that refuses it: the level-0 tile folded into
    // the node its parent tile stores, which the forged hash cannot reproduce.
    let refused = tree
        .verify_leaf(TARGET, &served, root)
        .await
        .expect_err("a body the signed root does not commit to must be refused");
    assert!(matches!(refused, MonitorError::Tile(_)), "{refused}");
    // The honest body at the same index still verifies — not refusing everything.
    Tree::new(&honest, SIZE, 8)
        .verify_leaf(TARGET, &honest.leaves[TARGET as usize], root)
        .await
        .expect("the real body verifies against the real root");
}

/// What the binding costs, in fetches: one level-0 hash tile per 256 entries,
/// plus one per 65,536 at level 1, memoized — the weaker check's budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binding_a_whole_bundle_to_the_root_costs_a_handful_of_tiles() {
    let log = MemoryLog::new(SIZE);
    let tree = Tree::new(&log, SIZE, 1);
    let root = tree.root().await.expect("a root");
    let after_root = log.paths().len();

    // Cache tiles the way `HttpTiles` does — this fixture has no cache, so
    // count *distinct* paths rather than calls.
    for index in 256..512 {
        tree.verify_leaf(index, &log.leaves[index as usize], root)
            .await
            .expect("every honest leaf verifies");
    }
    let distinct: std::collections::BTreeSet<String> = log
        .paths()
        .into_iter()
        .skip(after_root)
        .filter(|p| p.starts_with("api/v2/tile/"))
        .collect();

    // 256 entries bound to the signed root: the level-0 tile holding them,
    // the level-1 tile pinning it, the level-2 tile the root already read —
    // not one fetch per entry, and not one fold per entry either.
    assert!(distinct.len() <= 4);
    assert!(distinct.contains("api/v2/tile/0/001"));
}
