//! Key-loss recovery across real loopback endpoints (§3.4).
//!
//! The scenario throughout: an origin named `nas@cluster.example` publishes for
//! a while, its device key and database are lost, and the operator brings it
//! back under a fresh key with the same `id=` name. Its peers still hold the
//! history it no longer has, signed by a key that is no longer bound — so those
//! heads can never be accepted (§4.4), and their existence in the `Hello`
//! summary is the only thing recovery has to work with.

use std::time::Duration;

use synch_core::{now_ns, OriginId};
use synch_engine::{Node, NodeConfig, RecoveryOptions};
use synch_store::{Binding, BindingSource};

struct Peer {
    _data: tempfile::TempDir,
    space: tempfile::TempDir,
    node: Node,
}

async fn spawn(name: &str) -> Peer {
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let node = open(data.path(), Some(origin(name))).await;
    Peer {
        _data: data,
        space,
        node,
    }
}

async fn open(data_dir: &std::path::Path, id: Option<OriginId>) -> Node {
    if let Some(id) = id {
        Node::init(data_dir, Some(id)).unwrap();
    }
    Node::open(NodeConfig::loopback(data_dir)).await.unwrap()
}

fn origin(name: &str) -> OriginId {
    OriginId::named(name, "cluster.example").unwrap()
}

/// Trust is unilateral, so admitting a peer is one direction at a time (§3.2).
fn trust(node: &Node, peer: &Node) {
    node.store()
        .put_binding(&Binding {
            origin: peer.origin().clone(),
            node_id: peer.node_id(),
            source: BindingSource::Static,
            domain: None,
            note: None,
            added_at: 0,
            expires_at: None,
        })
        .unwrap();
    node.remember_peer(&peer.net().direct_addr()).unwrap();
}

/// What the operator's replacement TXT record does to a peer: the origin now
/// resolves to the new device key, and the lost one speaks for nothing.
fn rebind(node: &Node, origin: &OriginId, lost: &synch_core::NodeId, recovered: &Node) {
    node.store()
        .remove_binding(origin, lost, BindingSource::Static)
        .unwrap();
    trust(node, recovered);
}

fn write(peer: &Peer, name: &str, body: &str) {
    std::fs::write(peer.space.path().join(name), body.as_bytes()).unwrap();
}

fn quick(wait: Duration, gap: u64) -> RecoveryOptions {
    RecoveryOptions {
        wait,
        gap,
        poll: Duration::from_millis(20),
    }
}

/// The whole arc: a wiped node refuses to publish, learns how far its origin
/// had got from an ordinary `Hello` exchange, resumes above it, and is accepted
/// by the peer that holds the old history.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wiped_node_refuses_to_publish_then_resumes_above_its_peers() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    trust(&nas.node, &laptop.node);
    trust(&laptop.node, &nas.node);
    let lost_key = nas.node.node_id();

    // The NAS publishes three roots; the laptop replicates them.
    nas.node.add_space("media", nas.space.path()).unwrap();
    for round in 1..=3 {
        write(&nas, &format!("round{round}.txt"), "content");
        nas.node.scan_and_publish().unwrap();
    }
    laptop
        .node
        .sync_with_peer(&nas.node.node_id())
        .await
        .unwrap();
    assert_eq!(
        laptop
            .node
            .store()
            .complete_head(nas.node.origin())
            .unwrap()
            .unwrap()
            .seq,
        3
    );
    nas.node.shutdown().await.unwrap();

    // Key and database are gone. The operator brings the origin back under a
    // fresh key, with the same name, on an empty database.
    let data = tempfile::tempdir().unwrap();
    let recovered = open(data.path(), Some(origin("nas"))).await;
    assert_ne!(recovered.node_id(), lost_key);
    trust(&recovered, &laptop.node);
    rebind(&laptop.node, &origin("nas"), &lost_key, &recovered);

    // One ordinary exchange. The laptop's head for `nas` is signed by the lost
    // key, which is no longer bound: it is rejected, exactly as §4.4 requires.
    // What survives the exchange is the summary that mentioned it.
    let report = recovered
        .sync_with_peer(&laptop.node.node_id())
        .await
        .unwrap();
    assert_eq!(report.heads_rejected, 1, "{report:?}");
    assert!(recovered
        .store()
        .complete_head(recovered.origin())
        .unwrap()
        .is_none());

    let state = recovered.recovery_state().unwrap();
    assert!(state.in_recovery, "{state:?}");
    assert_eq!(state.observed_seq, Some(3));
    assert_eq!(state.own_seq, None);

    // Publishing is refused, and the error says what to run. The refusal comes
    // before the scan, so nothing is recorded as published that was not.
    recovered.add_space("media", nas.space.path()).unwrap();
    let err = recovered.scan_and_publish().unwrap_err();
    let message = err.to_string();
    assert!(message.contains("synch recover"), "{message}");
    assert!(message.contains("seq 3"), "{message}");
    assert!(recovered.store().local_files("media").unwrap().is_empty());
    assert!(recovered.remove_space("media").is_err());

    // `--wait 0` collects one round and returns promptly.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let started = std::time::Instant::now();
    let recovery = tokio::time::timeout(
        Duration::from_secs(30),
        recovered.recover(quick(Duration::ZERO, 1_000), tx),
    )
    .await
    .expect("a zero wait must not linger")
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(recovery.rounds, 1);
    assert_eq!(recovery.reached, 1, "{recovery:?}");
    assert_eq!(recovery.observed_seq, Some(3));
    assert_eq!(recovery.floor, Some(1_003));
    assert_eq!(rx.try_recv().unwrap().observed_seq, Some(3));
    assert!(!recovered.recovery_state().unwrap().in_recovery);

    // The floor is durable: it is still there after a restart, before anything
    // has been published under it.
    recovered.shutdown().await.unwrap();
    let recovered = open(data.path(), None).await;
    assert_eq!(recovered.next_seq().unwrap(), 1_003);

    // Publishing resumes strictly above everything the peer advertised, by the
    // gap, and the peer accepts it under the ordinary acceptance rule.
    let head = recovered.scan_publish_push().await.unwrap().unwrap();
    assert_eq!(head.seq, 1_003);
    head.verify_signature().unwrap();
    assert_eq!(head.signed_by, recovered.node_id());
    // The push carries the head; the pull that follows completes its trie and
    // flips the peer's complete slot (§5.2).
    laptop
        .node
        .sync_with_peer(&recovered.node_id())
        .await
        .unwrap();
    let theirs = laptop
        .node
        .store()
        .complete_head(recovered.origin())
        .unwrap()
        .unwrap();
    assert_eq!(theirs.seq, 1_003);
    assert_eq!(theirs.root, head.root);

    // And the next publish carries on from there, not from the floor.
    write(&nas, "after-recovery.txt", "more");
    let head = recovered.scan_and_publish().unwrap().1.unwrap();
    assert_eq!(head.seq, 1_004);

    recovered.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

/// A genuinely new node joining a cluster that has never heard of it is *not*
/// in recovery, and publishes at seq 1. Misdetecting this would brick every new
/// node.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_node_joining_a_busy_cluster_publishes_at_seq_one() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let newcomer = spawn("laptop").await;
    trust(&nas.node, &newcomer.node);
    trust(&newcomer.node, &nas.node);

    // The cluster is busy: the NAS has plenty of history, at seqs far above 1.
    nas.node.add_space("media", nas.space.path()).unwrap();
    for round in 1..=5 {
        write(&nas, &format!("round{round}.txt"), "content");
        nas.node.scan_and_publish().unwrap();
    }

    // The newcomer syncs everything the cluster has — and none of it is about
    // its own origin.
    let report = newcomer
        .node
        .sync_with_peer(&nas.node.node_id())
        .await
        .unwrap();
    assert_eq!(report.heads_accepted, 1, "{report:?}");
    let state = newcomer.node.recovery_state().unwrap();
    assert!(!state.in_recovery, "{state:?}");
    assert_eq!(state.observed_seq, None);
    assert_eq!(state.next_seq, 1);

    newcomer
        .node
        .add_space("media", newcomer.space.path())
        .unwrap();
    write(&newcomer, "mine.txt", "first");
    let head = newcomer.node.scan_and_publish().unwrap().1.unwrap();
    assert_eq!(head.seq, 1);

    // Running recovery on such a node changes nothing either.
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let report = newcomer
        .node
        .recover(quick(Duration::ZERO, 1_000), tx)
        .await
        .unwrap();
    assert_eq!(report.observed_seq, None);
    assert_eq!(report.floor, None);
    assert_eq!(newcomer.node.next_seq().unwrap(), 2);

    nas.node.shutdown().await.unwrap();
    newcomer.node.shutdown().await.unwrap();
}

/// Both sides of the report: the recovering node says it is in recovery and how
/// far peers say it had got; the peer holding the pre-recovery history names
/// the origin and the seq (§3.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_reports_recovery_on_one_side_and_the_fork_on_the_other() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    trust(&nas.node, &laptop.node);
    trust(&laptop.node, &nas.node);
    let lost_key = nas.node.node_id();

    nas.node.add_space("media", nas.space.path()).unwrap();
    write(&nas, "notes.txt", "before the loss");
    nas.node.scan_and_publish().unwrap();
    laptop
        .node
        .sync_with_peer(&nas.node.node_id())
        .await
        .unwrap();
    nas.node.shutdown().await.unwrap();

    let data = tempfile::tempdir().unwrap();
    let recovered = open(data.path(), Some(origin("nas"))).await;
    trust(&recovered, &laptop.node);
    rebind(&laptop.node, &origin("nas"), &lost_key, &recovered);
    recovered.observe_peers().await.unwrap();

    // The recovering node's own report.
    let report = recovered.doctor().unwrap();
    assert!(report.recovery.in_recovery);
    assert_eq!(report.recovery.observed_seq, Some(1));
    assert_eq!(report.recovery.origin, origin("nas"));
    assert!(report.unreconciled.is_empty(), "{:?}", report.unreconciled);

    // The peer's. It holds a head for `nas` signed by a key that no longer
    // speaks for it, and nothing has superseded that head.
    let report = laptop.node.doctor().unwrap();
    assert!(!report.recovery.in_recovery);
    assert_eq!(report.unreconciled.len(), 1, "{:?}", report.unreconciled);
    let fork = &report.unreconciled[0];
    assert_eq!(fork.origin, origin("nas"));
    assert_eq!(fork.seq, 1);
    assert_eq!(fork.signed_by, lost_key);
    assert_eq!(fork.current_seq, Some(1));
    // The evidence is a real head, kept with its signature (§4.4).
    assert!(laptop
        .node
        .store()
        .head_history(&origin("nas"))
        .unwrap()
        .iter()
        .any(|h| h.seq == 1 && h.verify_signature().is_ok()));

    // Once the recovered origin publishes above it, the peer's history is
    // superseded and the report goes quiet.
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    recovered
        .recover(quick(Duration::ZERO, 1_000), tx)
        .await
        .unwrap();
    recovered.add_space("media", nas.space.path()).unwrap();
    write(&nas, "after.txt", "after the loss");
    recovered.scan_publish_push().await.unwrap().unwrap();
    // The push delivers the head; the pull that follows is what completes its
    // trie and flips the laptop's complete slot (§5.2).
    laptop
        .node
        .sync_with_peer(&recovered.node_id())
        .await
        .unwrap();
    assert_eq!(
        laptop
            .node
            .store()
            .complete_head(&origin("nas"))
            .unwrap()
            .unwrap()
            .seq,
        1_001
    );
    let report = laptop.node.doctor().unwrap();
    assert!(report.unreconciled.is_empty(), "{:?}", report.unreconciled);

    recovered.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

/// Why the gap is not an optimization to remove. With it turned down to 1, a
/// peer that was unreachable throughout the quiesce comes back holding history
/// *above* the floor: the recovered node's publishes are refused as not newer,
/// and the pre-recovery history stays as provable fork evidence for the
/// operator to resolve (§3.4, §4.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_only_an_unreachable_peer_held_survives_as_fork_evidence() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    let vps = spawn("vps").await;
    for (a, b) in [(&nas, &laptop), (&laptop, &nas), (&nas, &vps), (&vps, &nas)] {
        trust(&a.node, &b.node);
    }
    let lost_key = nas.node.node_id();

    nas.node.add_space("media", nas.space.path()).unwrap();
    write(&nas, "a.txt", "one");
    nas.node.scan_and_publish().unwrap();
    // The laptop replicates seq 1 and then falls behind.
    laptop
        .node
        .sync_with_peer(&nas.node.node_id())
        .await
        .unwrap();
    for round in 2..=4 {
        write(&nas, &format!("round{round}.txt"), "more");
        nas.node.scan_and_publish().unwrap();
    }
    // The VPS has the newest history, and is then partitioned away entirely.
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();
    assert_eq!(
        vps.node
            .store()
            .complete_head(nas.node.origin())
            .unwrap()
            .unwrap()
            .seq,
        4
    );
    nas.node.shutdown().await.unwrap();
    vps.node.shutdown().await.unwrap();

    // Recovery sees only the laptop, which knows about seq 1, and the operator
    // asks for a gap of 1 — the smallest the protocol allows.
    let data = tempfile::tempdir().unwrap();
    let recovered = open(data.path(), Some(origin("nas"))).await;
    trust(&recovered, &laptop.node);
    rebind(&laptop.node, &origin("nas"), &lost_key, &recovered);
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let report = recovered
        .recover(quick(Duration::ZERO, 1), tx)
        .await
        .unwrap();
    assert_eq!(report.observed_seq, Some(1));
    assert_eq!(report.floor, Some(2));

    recovered.add_space("media", nas.space.path()).unwrap();
    let head = recovered.scan_publish_push().await.unwrap().unwrap();
    assert_eq!(head.seq, 2);

    // The VPS returns. Its own head is newer than anything the recovered node
    // has published, so seq monotonicity refuses the new head — a fork, not a
    // silent overwrite.
    let vps = open(vps._data.path(), None).await;
    rebind(&vps, &origin("nas"), &lost_key, &recovered);
    trust(&recovered, &vps);
    let sync = vps.sync_with_peer(&recovered.node_id()).await.unwrap();
    assert_eq!(sync.heads_accepted, 0, "{sync:?}");
    assert_eq!(
        vps.store()
            .complete_head(&origin("nas"))
            .unwrap()
            .unwrap()
            .seq,
        4
    );

    // And it is reported as exactly that, on the side that holds the evidence.
    let report = vps.doctor().unwrap();
    let fork = report
        .unreconciled
        .iter()
        .find(|entry| entry.origin == origin("nas"))
        .unwrap_or_else(|| panic!("{:?}", report.unreconciled));
    assert_eq!(fork.seq, 4);
    assert_eq!(fork.signed_by, lost_key);
    // The content behind it is still there for manual salvage (§3.4).
    assert_eq!(
        vps.read_entry(&origin("nas"), "media", "a.txt")
            .await
            .unwrap(),
        b"one"
    );

    let _ = now_ns();
    recovered.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
    vps.shutdown().await.unwrap();
}
