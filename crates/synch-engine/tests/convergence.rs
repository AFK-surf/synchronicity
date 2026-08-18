//! Randomized convergence over the §5.2 head-reconciliation rule.
//!
//! DESIGN §11 asks for an `mptsync` harness: an in-memory duplex-transport
//! simulation of N nodes with random partitions, message loss and interleaved
//! publishes, asserting that all heads and tries converge. This is the part of
//! it that carries the weight of the rule itself — many randomized deliveries
//! of one head set to N nodes, each in its own order and each seeing only some
//! of it, then gossip until it settles — built directly on [`Syncer`] and
//! [`Store`] so a case costs milliseconds and hundreds of them can run per test
//! rather than a handful of scripted scenarios.
//!
//! What it pins is the join: `(seq, root)` under lexicographic order is a
//! join-semilattice, so the head a node settles on is the *maximum* of what it
//! has seen and cannot depend on the order it saw things in. Anything that
//! refuses a head for a reason other than the ordering rule breaks that, and
//! the failure is not local — two honest peers end up on different heads and
//! then refuse each other's forever. The wide forks below are exactly that
//! case: applying the fork cap as an acceptance rule would leave a node that
//! met the greatest root of a storm late never taking it.
//!
//! Note what the propagation step here deliberately is *not*. It gossips a
//! node's `head_floor` — the maximum over both slots — because that is the
//! right stimulus for the property above: the join is about a node's current
//! maximum. The wire does something narrower (`heads_for` serves the *complete*
//! slot only, and `sync_with` pushes off `complete_head`), and every root here
//! is fabricated, so everything sits in the pending slot and no promotion runs.
//! That is a scope boundary, not an oversight, but it does mean the acceptance
//! rule is what this covers and the push/pull *decision* is not. That half is
//! covered over real endpoints with real tries in `cluster.rs` — see
//! `convergence_survives_a_partition`, where a node that knows nothing pulls an
//! origin through one `anti_entropy_round`.
//!
//! Still outstanding from §11: the live duplex transport, partitions and
//! message loss as first-class events, interleaved *publishes* (these heads are
//! signed up front), and convergence of the tries under the heads rather than
//! of the heads alone. This asserts head convergence.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use iroh_base::SecretKey;
use synch_core::{Hash, OriginId, SignedHead};
use synch_engine::reconcile::{Syncer, MAX_RETAINED_FORKS};
use synch_store::{Binding, BindingSource, Store};

/// xorshift64*, so a case is reproducible from its seed. Nothing here needs a
/// real generator, and a seeded one is what makes a failure debuggable.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

/// One node: a store with the signing key bound, and a syncer over it.
struct Node {
    store: Arc<Store>,
    syncer: Syncer,
    /// Every head this node was handed directly, for the evidence invariant.
    delivered: Vec<SignedHead>,
    _dir: tempfile::TempDir,
}

fn node(key: &SecretKey, origins: &[OriginId]) -> Node {
    let dir = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(Store::open(dir.path()).expect("a store"));
    for origin in origins {
        store
            .put_binding(&Binding {
                origin: origin.clone(),
                node_id: key.public(),
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .expect("the binding");
    }
    Node {
        syncer: Syncer::new(store.clone()),
        store,
        delivered: Vec::new(),
        _dir: dir,
    }
}

/// The greatest `(seq, root)` in a set — what every node must settle on.
fn maximum(heads: &[SignedHead]) -> (u64, Hash) {
    heads
        .iter()
        .map(|h| (h.seq, h.root))
        .max_by_key(|(seq, root)| (*seq, root.0))
        .expect("a non-empty head set")
}

/// Builds the head set for one case: a few origins, a few seqs each, forks of
/// random width, and one storm well past [`MAX_RETAINED_FORKS`].
fn head_set(rng: &mut Rng, key: &SecretKey, origins: &[OriginId], seed: u64) -> Vec<SignedHead> {
    let mut heads = Vec::new();
    let mint = |origin: &OriginId, seq: u64, fork: usize| {
        let label = format!("{origin}/{seq}/{fork}/{seed}");
        SignedHead::sign(key, origin.clone(), seq, Hash::new(label.as_bytes()), 0)
    };
    for origin in origins {
        for seq in 1..=(2 + rng.below(4) as u64) {
            for fork in 0..1 + rng.below(3) {
                heads.push(mint(origin, seq, fork));
            }
        }
        // A storm at one seq: more roots than may be retained, so the eviction
        // rule runs and the acceptance rule must not.
        let storm = 1 + rng.below(3) as u64;
        for fork in 0..MAX_RETAINED_FORKS + 4 {
            heads.push(mint(origin, storm, 100 + fork));
        }
    }
    heads
}

/// Runs one randomized case: deliver, gossip, and check what everyone settled
/// on.
fn one_case(seed: u64) {
    let mut rng = Rng::new(seed);
    let key = SecretKey::generate();
    let origins: Vec<OriginId> = ["nas", "laptop"]
        .iter()
        .map(|name| OriginId::named(name, "x.example").expect("an origin"))
        .collect();
    let heads = head_set(&mut rng, &key, &origins, seed);
    let by_key: HashMap<(u64, [u8; 32]), SignedHead> = heads
        .iter()
        .map(|h| ((h.seq, h.root.0), h.clone()))
        .collect();

    let count = 3 + rng.below(3);
    let mut nodes: Vec<Node> = (0..count).map(|_| node(&key, &origins)).collect();

    // Every head reaches at least one node, and each node sees a random part of
    // the rest — message loss, without a transport to lose it on.
    let mut plan: Vec<Vec<SignedHead>> = vec![Vec::new(); count];
    for head in &heads {
        plan[rng.below(count)].push(head.clone());
        for node in plan.iter_mut() {
            if rng.below(3) == 0 {
                node.push(head.clone());
            }
        }
    }
    for (node, mut for_node) in nodes.iter_mut().zip(plan) {
        rng.shuffle(&mut for_node);
        for head in for_node {
            node.syncer
                .offer_head(&head, 0)
                .expect("an offer never errors on a well-formed head");
            node.delivered.push(head);
        }
    }

    // Gossip: each round, every node offers what it currently holds to one
    // peer, which is the one thing a `Hello` exchange does with heads. Random
    // rounds first — the interesting part, since a node's own best head changes
    // under it — then one all-pairs sweep, so what has to reach everybody
    // provably does rather than probably does.
    let exchange = |from: usize, to: usize, nodes: &mut Vec<Node>| {
        for origin in &origins {
            let Some(floor) = nodes[from].store.head_floor(origin).expect("a floor") else {
                continue;
            };
            let head = by_key
                .get(&(floor.0, floor.1 .0))
                .expect("a held head is one of the set")
                .clone();
            nodes[to].syncer.offer_head(&head, 0).expect("an offer");
        }
    };
    for _round in 0..count {
        for i in 0..count {
            let mut j = rng.below(count);
            if j == i {
                j = (j + 1) % count;
            }
            exchange(i, j, &mut nodes);
        }
    }
    for i in 0..count {
        for j in 0..count {
            if i != j {
                exchange(i, j, &mut nodes);
            }
        }
    }

    for origin in &origins {
        let mine: Vec<SignedHead> = heads
            .iter()
            .filter(|h| &h.origin == origin)
            .cloned()
            .collect();
        let expected = maximum(&mine);
        for (i, node) in nodes.iter().enumerate() {
            assert_eq!(
                node.store.head_floor(origin).expect("a floor"),
                Some(expected),
                "seed {seed}: node {i} settled elsewhere for {origin}"
            );
        }
    }

    // Evidence survives the eviction that bounds it: wherever a node was handed
    // two different roots at one seq, it can still say so (§4.4).
    for node in &nodes {
        let mut seen: HashMap<(String, u64), HashSet<[u8; 32]>> = HashMap::new();
        for head in &node.delivered {
            seen.entry((head.origin.canonical(), head.seq))
                .or_default()
                .insert(head.root.0);
        }
        let reported: HashSet<(String, u64)> = node
            .store
            .equivocations()
            .expect("the equivocations")
            .into_iter()
            .map(|e| (e.origin.canonical(), e.seq))
            .collect();
        for (at, roots) in seen {
            if roots.len() > 1 {
                assert!(
                    reported.contains(&at),
                    "seed {seed}: a fork at {at:?} was delivered and is not reported"
                );
            }
        }
    }
}

/// Every node settles on the same head, from every arrival order.
///
/// The property the whole of §5.2 rests on, and the one an acceptance rule that
/// looks at anything but `(seq, root)` destroys.
#[test]
fn heads_converge_whatever_order_they_arrive_in() {
    for seed in 0..10 {
        one_case(seed);
    }
}
