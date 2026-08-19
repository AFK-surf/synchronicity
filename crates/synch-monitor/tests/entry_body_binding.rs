//! An entry body is evidence only once it is bound to the **signed
//! checkpoint** — and the monitor must never decide to skip a leaf on bytes
//! that are not.
//!
//! This is the property, stated as an attack. A log serves entry bundles and
//! hash tiles as separate static resources, and rewriting one costs exactly
//! what rewriting the other costs. So the adversary here is the whole log: it
//! forges an entry body *and* the level-0 hash tile entry covering it, leaving
//! every higher hash tile honest. That pair survives the checkpoint-root
//! recomputation and the consistency prefix untouched — over a tree of 65,536
//! leaves the root is folded from a single level-2 tile and no level-0 tile is
//! read at all — so a check that compares a body against `stored_hash(0,
//! index)` accepts it.
//!
//! The consequence of accepting it is the case the tiering exists to prevent.
//! The forged body fails to parse, or names a zone nobody watches, so the walk
//! skips it and never classifies anything; meanwhile the victim's client
//! receives the *real* proof, with a real audit path to the real leaf, and
//! accepts it. Accepted by every client, reported by no monitor.
//!
//! What refuses the pair is folding the level-0 tile into the single node it
//! is and checking that against the entry its parent tile holds — climbing
//! until a tile the root recomputation itself consumed — before any skip
//! decision. Asserted here over a tree big enough for the level-0 tile to be
//! genuinely uncovered, together with the fetch counts that say what it costs.

use std::sync::Mutex;

use synch_monitor::{
    tiles::{TileSource, Tree},
    MonitorError,
};
use synch_net::rekor::{leaf_hash, node_hash};

fn reference_root(leaves: &[Vec<u8>], lo: u64, hi: u64) -> [u8; 32] {
    if lo + 1 == hi {
        return leaf_hash(&leaves[lo as usize]);
    }
    let mut span = 1u64;
    while span * 2 < hi - lo {
        span *= 2;
    }
    let split = lo + span;
    node_hash(
        &reference_root(leaves, lo, split),
        &reference_root(leaves, split, hi),
    )
}

/// A log that serves honest tiles, records every path fetched, and can be
/// told to forge one entry body together with the level-0 hash tile entry
/// that covers it — leaving every higher-level hash tile untouched.
struct Log {
    leaves: Vec<Vec<u8>>,
    forge_at: Option<u64>,
    forged_body: Vec<u8>,
    fetched: Mutex<Vec<String>>,
}

impl Log {
    fn new(size: u64) -> Log {
        Log {
            leaves: (0..size)
                .map(|i| format!("entry {i}").into_bytes())
                .collect(),
            forge_at: None,
            forged_body: Vec::new(),
            fetched: Mutex::new(Vec::new()),
        }
    }

    fn paths(&self) -> Vec<String> {
        self.fetched.lock().unwrap().clone()
    }
}

impl TileSource for Log {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
        self.fetched.lock().unwrap().push(path.to_string());
        let rest = path.strip_prefix("api/v2/tile/").expect("tile path");
        let (level, rest) = rest.split_once('/').expect("level");
        let (digits, width) = match rest.split_once(".p/") {
            Some((digits, width)) => (digits, width.parse::<u64>().unwrap()),
            None => (rest, 256),
        };
        let index: u64 = digits.split('/').fold(0u64, |acc, group| {
            acc * 1000 + group.trim_start_matches('x').parse::<u64>().unwrap()
        });
        let tile_level: u32 = match level {
            "entries" => 0,
            level => level.parse().unwrap(),
        };
        let current = ((self.leaves.len() as u64) >> (8 * tile_level))
            .saturating_sub(index * 256)
            .min(256);
        if width != current {
            return Ok(None);
        }
        if level == "entries" {
            let mut out = Vec::new();
            for i in 0..width {
                let at = index * 256 + i;
                let body = match self.forge_at == Some(at) {
                    true => &self.forged_body,
                    false => &self.leaves[at as usize],
                };
                out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                out.extend_from_slice(body);
            }
            return Ok(Some(out));
        }
        let span = 1u64 << (8 * tile_level);
        let mut out = Vec::new();
        for i in 0..width {
            let start = (index * 256 + i) * span;
            // The forgery: only the *level-0* hash tile entry covering the
            // forged body is changed. Every higher level stays honest, so the
            // tree the root check walks is the real one.
            let hash = match (tile_level == 0, self.forge_at) {
                (true, Some(at)) if at == start => leaf_hash(&self.forged_body),
                _ => reference_root(&self.leaves, start, start + span),
            };
            out.extend_from_slice(&hash);
        }
        Ok(Some(out))
    }

    async fn checkpoint_size(&self) -> Result<Option<u64>, MonitorError> {
        Ok(Some(self.leaves.len() as u64))
    }
}

const SIZE: u64 = 65_536;
const TARGET: u64 = 300; // well away from the frontier

/// A body the signed root does not commit to is refused, even when the
/// level-0 hash tile beneath it agrees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_body_and_its_level_zero_tile_are_refused_against_the_signed_root() {
    let honest = Log::new(SIZE);
    let tree = Tree::new(&honest, SIZE, 8);
    let root = tree.root().await.expect("the honest root recomputes");
    assert_eq!(root, reference_root(&honest.leaves, 0, SIZE));

    // The premise of the attack, measured rather than asserted from memory:
    // the root recomputation reads no level-0 tile, so nothing about a
    // level-0 hash has been checked against the checkpoint.
    let level_zero = honest
        .paths()
        .into_iter()
        .filter(|p| p.starts_with("api/v2/tile/0/"))
        .count();
    assert_eq!(
        level_zero, 0,
        "the root check reads no level-0 tile over {SIZE} leaves, which is why a \
         body compared against one is not bound to the checkpoint"
    );

    // The forgery: body and its level-0 hash-tile entry changed together,
    // every higher hash tile honest.
    let mut hostile = Log::new(SIZE);
    hostile.forge_at = Some(TARGET);
    hostile.forged_body = b"not a hashedrekord at all".to_vec();
    let tree = Tree::new(&hostile, SIZE, 8);

    // Every hash-based check the log's own history is judged by still passes.
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

    // The bundle really does serve the substitute.
    let served = tree
        .entry_bundle(TARGET)
        .await
        .expect("the bundle decodes")
        .into_iter()
        .find(|(index, _)| *index == TARGET)
        .expect("the target is in its bundle")
        .1;
    assert_eq!(served, hostile.forged_body);

    // And this is the check that refuses it: the level-0 tile folded into the
    // node its parent tile stores, which the forged hash cannot reproduce.
    let refused = tree
        .verify_leaf(TARGET, &served, root)
        .await
        .expect_err("a body the signed root does not commit to must be refused");
    assert!(matches!(refused, MonitorError::Tile(_)), "{refused}");

    // The honest body at the same index still verifies, so the check is not
    // simply refusing everything.
    Tree::new(&honest, SIZE, 8)
        .verify_leaf(TARGET, &honest.leaves[TARGET as usize], root)
        .await
        .expect("the real body verifies against the real root");
}

/// What the binding costs, in fetches: the budget the weaker check was chosen
/// for, and it is the same budget.
///
/// One level-0 hash tile per 256 entries — the same tile a body-against-tile
/// comparison fetched — plus one tile per 65,536 entries at level 1 and one
/// per 16.7 M at level 2, every one of them cached for the rest of the run,
/// and the fold over each is memoized so the 256 entries in a tile share it.
/// Measured over a whole bundle so the amortized cost is what is asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binding_a_whole_bundle_to_the_root_costs_a_handful_of_tiles() {
    let log = Log::new(SIZE);
    let tree = Tree::new(&log, SIZE, 1);
    let root = tree.root().await.expect("a root");
    let after_root = log.paths().len();

    // Cache the tiles the way `HttpTiles` does — this fixture has no cache of
    // its own, so count *distinct* paths rather than calls.
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
    // the level-1 tile that pins it, and the level-2 tile the root already
    // read — not one fetch per entry, and not one fold per entry either.
    assert!(
        distinct.len() <= 4,
        "256 entries should cost a handful of tiles, not one each: {distinct:?}"
    );
    assert!(
        distinct.contains("api/v2/tile/0/001"),
        "the level-0 tile holding the bundle: {distinct:?}"
    );
}
