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
//! Two harnesses, because the rule and the decision are two things.
//!
//! `heads_converge_whatever_order_they_arrive_in` gossips a node's `head_floor`
//! — the maximum over both slots — because that is the right stimulus for the
//! property above: the join is about a node's current maximum. Every root there
//! is fabricated, so everything sits in the pending slot and no promotion runs.
//! That covers the *acceptance rule* and nothing else.
//!
//! `the_push_pull_decision_converges_over_real_slots` covers the part the wire
//! actually runs, which is narrower in two ways: `heads_for` serves the
//! **complete** slot only, and `sync_with` pushes off `complete_head` rather
//! than off whichever summary was advertised. Every root there is a real trie,
//! so promotion runs, the complete slot moves, and "converged" is checked as
//! *servable* — the trie is here and the derived `entries` agree with the head —
//! rather than merely known. That half used to be covered by nothing, and the
//! decision is what a later audit found reading the store once per advertised
//! origin on a runtime worker.
//!
//! Still outstanding from §11: the live duplex transport, partitions and
//! message loss as first-class events, and interleaved *publishes* (the heads
//! here are minted up front).

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
                issuer: None,
                spaces: Vec::new(),
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

/// The same convergence property, gossiped the way the *protocol* gossips.
///
/// `one_case` above offers each node's `head_floor` — the maximum over both
/// slots — which is the right stimulus for the acceptance rule and is not what
/// the wire does. The wire is narrower in two ways that matter: `heads_for`
/// serves the **complete** slot only, and `sync_with` pushes off `complete_head`
/// rather than off whichever summary was advertised. So the push/pull *decision*
/// — which origins each side asks for, and which heads it offers — was covered
/// by nothing here, and the harness noted that as a scope boundary.
///
/// It is covered now, because the decision is the part that was quietly reading
/// the store per advertised origin and had to be rewritten. Every root below is
/// a real trie this node can serve, so promotion runs, the complete slot moves,
/// and both narrowings are exercised: a node that has adopted a head but cannot
/// serve it does not offer it, and a node that can serve an older root still
/// advertises that.
///
/// What this still is not is a live duplex transport with partitions as
/// first-class events (DESIGN §11). It is the decision over real slots and real
/// tries, which is the half that was missing.
#[test]
fn the_push_pull_decision_converges_over_real_slots() {
    for seed in 0..8 {
        wire_case(seed);
    }
}

/// One randomized case over the real push/pull decision.
fn wire_case(seed: u64) {
    use synch_core::{file_key, FileEntry, HeadSummary};
    use synch_mpt::Trie;

    let mut rng = Rng::new(seed);
    let key = SecretKey::generate();
    let origins: Vec<OriginId> = ["nas", "laptop", "vps"]
        .iter()
        .map(|name| OriginId::named(name, "x.example").expect("an origin"))
        .collect();

    let count = 3 + rng.below(3);
    let nodes: Vec<Node> = (0..count).map(|_| node(&key, &origins)).collect();

    // A published head is a head whose trie exists, so each one is built in the
    // store of the node that "published" it and nowhere else. Peers have to pull
    // the nodes to be able to serve it on, exactly as they do over the wire.
    let entry = |n: u64| {
        postcard::to_stdvec(&FileEntry::file(n, 0, Hash::new(&n.to_le_bytes()), 1)).expect("encode")
    };
    /// A published head and how many leaves its trie holds.
    struct Published {
        head: SignedHead,
        leaves: usize,
    }
    let mut published: Vec<Published> = Vec::new();
    for (i, origin) in origins.iter().enumerate() {
        // One origin per publisher, and a couple of successive heads each, so
        // the pull side has to choose the greater and the push side has to stop
        // offering the lesser.
        let at = i % count;
        let mut root = Hash::EMPTY;
        let mut leaves: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for seq in 1..=(1 + rng.below(3) as u64) {
            let key_bytes = file_key("media", &format!("{origin}-{seq}.bin")).expect("a key");
            let value = entry(seq);
            leaves.push((key_bytes.clone(), value.clone()));
            root = Trie::new(nodes[at].store.as_ref())
                .insert(root, &key_bytes, &value)
                .expect("the insert");
            let head = SignedHead::sign(&key, origin.clone(), seq, root, 0);
            nodes[at]
                .store
                .put_head(synch_store::Slot::Complete, &head, 0, 0)
                .expect("the slot");
            nodes[at]
                .store
                .transaction(|txn| txn.materialize_diff(origin, Hash::EMPTY, root))
                .expect("the views");
            published.push(Published {
                head,
                leaves: leaves.len(),
            });
        }
    }

    // One exchange, in the shape `sync_with` runs it: both sides advertise what
    // `local_summaries` says, each decides what to push and what to want, the
    // pushed heads go through `offer_head`, and the wanted origins are answered
    // out of `heads_for` — the complete slot only.
    let exchange = |from: usize, to: usize, nodes: &[Node]| {
        let ours = nodes[from].syncer.local_summaries().expect("summaries");
        let theirs = nodes[to].syncer.local_summaries().expect("summaries");
        let best = |set: &[HeadSummary], origin: &OriginId| {
            set.iter()
                .filter(|s| &s.origin == origin)
                .map(|s| s.order_key())
                .max()
        };

        // Push: every complete head that beats what the peer advertised.
        for stored in nodes[from]
            .store
            .all_heads(synch_store::Slot::Complete)
            .expect("the slots")
        {
            let head = stored.head;
            if best(&theirs, &head.origin).is_none_or(|peer| (head.seq, head.root.0) > peer) {
                // Applying it needs the trie, so the receiver first pulls
                // whatever the sender can serve: content-addressed nodes, from
                // any peer that holds them (§5.2).
                copy_trie(&nodes[from], &nodes[to], head.root);
                let _ = nodes[to].syncer.offer_head(&head, 0);
            }
        }
        // Pull: every origin the peer is ahead on, answered from its complete
        // slot alone.
        let want: Vec<OriginId> = theirs
            .iter()
            .filter(|s| best(&ours, &s.origin).is_none_or(|mine| s.order_key() > mine))
            .map(|s| s.origin.clone())
            .collect();
        for head in nodes[to].syncer.heads_for(&want).expect("heads_for") {
            copy_trie(&nodes[to], &nodes[from], head.root);
            let _ = nodes[from].syncer.offer_head(&head, 0);
        }
    };

    // Random rounds, then an all-pairs sweep so what has to reach everybody
    // provably does.
    for _ in 0..count {
        for i in 0..count {
            let mut j = rng.below(count);
            if j == i {
                j = (j + 1) % count;
            }
            exchange(i, j, &nodes);
        }
    }
    for i in 0..count {
        for j in 0..count {
            if i != j {
                exchange(i, j, &nodes);
            }
        }
    }

    for origin in &origins {
        let expected = published
            .iter()
            .filter(|p| &p.head.origin == origin)
            .map(|p| (p.head.seq, p.head.root))
            .max_by_key(|(seq, root)| (*seq, root.0))
            .expect("every origin published");
        for (i, holder) in nodes.iter().enumerate() {
            let complete = holder
                .store
                .complete_head(origin)
                .expect("the slot")
                .unwrap_or_else(|| panic!("seed {seed}: node {i} holds no head for {origin}"));
            assert_eq!(
                (complete.seq, complete.root),
                expected,
                "seed {seed}: node {i} settled elsewhere for {origin}"
            );
            // Converged means servable, not merely known: the trie under the
            // head is here, so this node can hand it to the next one.
            assert!(
                synch_mpt::Trie::new(holder.store.as_ref())
                    .is_complete(complete.root)
                    .expect("completeness"),
                "seed {seed}: node {i} holds a head for {origin} it cannot serve"
            );
            // And the derived view agrees with the head, which is what the
            // unified tree, mirrors and the gateway read.
            let leaves = published
                .iter()
                .filter(|p| p.head.root == complete.root)
                .map(|p| p.leaves)
                .max()
                .expect("the published head");
            assert_eq!(
                holder
                    .store
                    .list_entries(Some(origin), "media", "", None, None)
                    .expect("the entries")
                    .len(),
                leaves,
                "seed {seed}: node {i}'s entries do not match the head it holds"
            );
        }
    }
}

/// Copies every trie node and value under `root` from one store to another.
///
/// Stands in for `GetNodes`/`GetValues` without a transport: the fetch's job is
/// to make the receiver able to *serve* the root, and this is that outcome. The
/// walk itself is covered over real endpoints in `two_nodes.rs`.
fn copy_trie(from: &Node, to: &Node, root: Hash) {
    use synch_mpt::NodeStore;
    let reachable = synch_mpt::Trie::new(from.store.as_ref())
        .reachable(root)
        .expect("the reachable set");
    for hash in reachable.nodes {
        if let Some(bytes) = NodeStore::get_node(from.store.as_ref(), &hash).expect("a node") {
            NodeStore::put_node(to.store.as_ref(), &hash, &bytes).expect("the put");
        }
    }
    for hash in reachable.values {
        if let Some(bytes) = NodeStore::get_value(from.store.as_ref(), &hash).expect("a value") {
            NodeStore::put_value(to.store.as_ref(), &hash, &bytes).expect("the put");
        }
    }
}
