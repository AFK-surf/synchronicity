//! Cluster locks over real loopback endpoints (`docs/LOCKS.md`): exclusion
//! while nodes can reach each other, split brain across a partition and its
//! heal, takeover from a crashed holder, restart, handoff, and fencing.

use std::time::Duration;

use synch_core::{ClaimState, EndReason, LockMessage, LockName};
use synch_engine::{locks::Lost, Acquired, EngineError, HoldMode, LockFailure, LockRequest, Node};
use synch_net::LockService;
use synch_store::BindingSource;

use crate::common;
use common::{off_runtime, shutdown, spawn_node, trust, Peer};

fn lock() -> LockName {
    LockName::parse("media/deploy").unwrap()
}

fn request(mode: HoldMode, wait: Duration) -> LockRequest {
    LockRequest {
        lock: lock(),
        ttl: Duration::from_secs(5),
        wait,
        owner: "test".into(),
        payload: Vec::new(),
        mode,
        allow_behind: false,
    }
}

async fn acquire(node: &Node, wait: Duration) -> Result<Acquired, EngineError> {
    node.locks()
        .acquire(node, request(HoldMode::Session, wait))
        .await
}

fn failure(result: &Result<Acquired, EngineError>) -> Option<LockFailure> {
    match result {
        Err(EngineError::Lock { failure, .. }) => Some(*failure),
        _ => None,
    }
}

/// Cuts both directions of trust, which is what a partition looks like to the
/// protocol: neither side can reach the other.
async fn partition(a: &Node, b: &Node) {
    for (node, peer) in [(a, b), (b, a)] {
        let store = node.store().clone();
        let (origin, key) = (peer.origin().clone(), peer.node_id());
        off_runtime(move || {
            store
                .remove_binding(&origin, &key, BindingSource::Static)
                .unwrap()
        })
        .await;
    }
}

async fn heal(a: &Node, b: &Node) {
    let (a2, b2) = (a.clone(), b.clone());
    off_runtime(move || {
        trust(&a2, &b2);
        trust(&b2, &a2);
    })
    .await;
}

async fn cluster(names: &[&str]) -> Vec<Peer> {
    let mut peers = Vec::new();
    for name in names {
        peers.push(spawn_node(name).await);
    }
    let nodes: Vec<Node> = peers.iter().map(|p| p.node.clone()).collect();
    off_runtime(move || {
        for a in &nodes {
            for b in &nodes {
                if a.origin() != b.origin() {
                    trust(a, b);
                }
            }
        }
    })
    .await;
    peers
}

/// Simultaneous claims by connected nodes grant exactly one, and the others
/// learn who holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_claims_grant_exactly_one() {
    let peers = cluster(&["a", "b", "c"]).await;
    let nodes: Vec<Node> = peers.iter().map(|p| p.node.clone()).collect();
    let attempts = nodes.iter().map(|node| {
        let node = node.clone();
        tokio::spawn(async move { acquire(&node, Duration::ZERO).await })
    });
    let mut results = Vec::new();
    for attempt in attempts {
        results.push(attempt.await.unwrap());
    }
    let held: Vec<&Acquired> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(held.len(), 1, "{results:?}");
    for result in &results {
        if result.is_err() {
            assert!(
                matches!(
                    failure(result),
                    Some(LockFailure::Held | LockFailure::Contended)
                ),
                "{result:?}"
            );
        }
    }
    // A later claim, from any node, is refused while the hold lasts.
    for node in &nodes {
        if node
            .locks()
            .current(&lock())
            .is_some_and(|v| v.mode.is_some())
        {
            continue;
        }
        let late = acquire(node, Duration::ZERO).await;
        assert_eq!(failure(&late), Some(LockFailure::Held), "{late:?}");
    }
    shutdown(&nodes.iter().collect::<Vec<_>>()).await;
}

/// A release hands the lock to a waiter, and the waiter holds the releaser's
/// writes before it is told it acquired (§8).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_hands_over_the_lock_with_the_releasers_writes() {
    let peers = cluster(&["writer", "reader"]).await;
    let (writer, reader) = (&peers[0], &peers[1]);
    {
        let (node, path) = (writer.node.clone(), writer.space.path().to_path_buf());
        off_runtime(move || node.add_filesystem_source("media", &path).unwrap()).await;
    }
    let held = acquire(&writer.node, Duration::ZERO).await.unwrap();

    let waiter = {
        let node = reader.node.clone();
        tokio::spawn(async move { acquire(&node, Duration::from_secs(20)).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::write(writer.space.path().join("state.txt"), b"serial 2").unwrap();
    writer.node.scan_publish_push().await.unwrap();
    writer
        .node
        .locks()
        .release(&writer.node, &lock(), Some(&held.id))
        .await
        .unwrap();
    let published = {
        let store = writer.node.store().clone();
        let origin = writer.node.origin().clone();
        off_runtime(move || store.complete_head(&origin).unwrap().unwrap().seq).await
    };

    let handed = waiter.await.unwrap().unwrap();
    assert!(handed.id > held.id, "tokens are monotone across a handoff");
    assert!(handed
        .handoff
        .iter()
        .any(|m| &m.origin == writer.node.origin() && m.seq == published));
    let seen = {
        let store = reader.node.store().clone();
        let origin = writer.node.origin().clone();
        off_runtime(move || store.complete_head(&origin).unwrap().map(|h| h.seq)).await
    };
    assert!(seen >= Some(published), "{seen:?} < {published}");
    shutdown(&[&writer.node, &reader.node]).await;
}

/// Across a partition both sides grant — the split brain the design accepts
/// (§2) — and once they reach each other again exactly one keeps it (§6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partition_grants_both_sides_and_the_heal_keeps_one() {
    let peers = cluster(&["east", "west"]).await;
    let (east, west) = (&peers[0].node, &peers[1].node);
    partition(east, west).await;
    let mut a = acquire(east, Duration::ZERO).await.unwrap();
    let mut b = acquire(west, Duration::ZERO).await.unwrap();

    heal(east, west).await;
    let lost = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::select! {
            _ = a.lost.wait_for(Option::is_some) => "east",
            _ = b.lost.wait_for(Option::is_some) => "west",
        }
    })
    .await
    .expect("the heal names a loser within a few renewals");
    // The survivor is the lesser ticket, and both sides agree on it.
    let keeper = if a.id < b.id { "east" } else { "west" };
    assert_ne!(lost, keeper);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (survivor, loser) = if keeper == "east" {
        (east, west)
    } else {
        (west, east)
    };
    assert!(survivor
        .locks()
        .current(&lock())
        .is_some_and(|v| v.mode.is_some()));
    let view = loser
        .locks()
        .current(&lock())
        .expect("the loser sees the survivor");
    assert!(view.mode.is_none());
    shutdown(&[east, west]).await;
}

/// A holder that crashes is taken over once its lease runs out, and the new
/// claim names the one it superseded (§6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crashed_holder_is_superseded_after_its_lease() {
    let peers = cluster(&["crashes", "survives"]).await;
    let (crashes, survives) = (&peers[0].node, &peers[1].node);
    let first = acquire(crashes, Duration::ZERO).await.unwrap();
    // Hold long enough that the survivor has seen a renewal.
    tokio::time::sleep(Duration::from_secs(2)).await;
    crashes.shutdown().await.unwrap();

    let started = std::time::Instant::now();
    let second = acquire(survives, Duration::from_secs(20)).await.unwrap();
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "not before the lease ran out"
    );
    let current = survives.locks().current(&lock()).unwrap();
    assert_eq!(current.claim.id, second.id);
    assert!(current.claim.supersedes.contains(&first.id));
    shutdown(&[survives]).await;
}

/// A sticky hold survives a daemon restart within its lease (§5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sticky_hold_survives_a_restart() {
    let peers = cluster(&["holder", "other"]).await;
    let other = peers[1].node.clone();
    let holder = peers[0].node.clone();
    let held = holder
        .locks()
        .acquire(&holder, request(HoldMode::Sticky, Duration::ZERO))
        .await
        .unwrap();
    holder.shutdown().await.unwrap();
    drop(holder);
    let reopened = Node::open(synch_engine::NodeConfig::loopback(peers[0]._data.path()))
        .await
        .unwrap();
    {
        let (a, b) = (reopened.clone(), other.clone());
        off_runtime(move || {
            trust(&a, &b);
            trust(&b, &a);
        })
        .await;
    }
    let view = reopened.locks().current(&lock()).expect("restored");
    assert_eq!(view.claim.id, held.id);
    // Well past the lease the restart would have lost it in.
    tokio::time::sleep(Duration::from_secs(7)).await;
    let refused = acquire(&other, Duration::ZERO).await;
    assert_eq!(failure(&refused), Some(LockFailure::Held), "{refused:?}");
    shutdown(&[&reopened, &other]).await;
}

/// A claim that arrives after its end is not revived: ended is terminal (§4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_claim_after_its_end_is_not_revived() {
    let peers = cluster(&["claimant", "observer"]).await;
    let (claimant, observer) = (peers[0].node.clone(), peers[1].node.clone());
    let held = acquire(&claimant, Duration::ZERO).await.unwrap();
    claimant
        .locks()
        .release(&claimant, &lock(), None)
        .await
        .unwrap();
    let current = observer.locks().current(&lock());
    assert!(current.is_none(), "{current:?}");

    // The original claim, replayed late, is answered with its end.
    let replay = LockMessage::Renew {
        lock: lock(),
        claim: synch_core::Claim {
            id: held.id.clone(),
            ttl_ms: 5_000,
            owner: String::new(),
            payload: Vec::new(),
            supersedes: Vec::new(),
        },
    };
    let key = claimant.node_id();
    let locks = observer.locks().clone();
    let answer = off_runtime(move || locks.serve(key, replay)).await;
    let LockMessage::Answer { reports, ended, .. } = answer else {
        panic!("{answer:?}")
    };
    assert!(reports.iter().all(|r| r.claim.id != held.id));
    assert!(ended.contains(&(held.id.clone(), EndReason::Released)));
    assert!(observer.locks().current(&lock()).is_none());
    shutdown(&[&claimant, &observer]).await;
}

/// A fenced commit is refused once the hold it names is broken (§7), and a
/// broken holder is told so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broken_hold_refuses_its_fence() {
    let peers = cluster(&["holder", "operator"]).await;
    let (holder, operator) = (&peers[0].node, &peers[1].node);
    let mut held = acquire(holder, Duration::ZERO).await.unwrap();
    drop(holder.locks().fence(&lock(), &held.id).await.unwrap());

    let broken = operator
        .locks()
        .break_lock(operator, &lock(), None)
        .await
        .unwrap();
    assert_eq!(broken, vec![held.id.clone()]);
    tokio::time::timeout(Duration::from_secs(5), held.lost.wait_for(Option::is_some))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*held.lost.borrow(), Some(Lost::Ended(EndReason::Broken)));
    let fenced = holder.locks().fence(&lock(), &held.id).await;
    assert!(
        matches!(
            fenced,
            Err(EngineError::Lock {
                failure: LockFailure::Lost,
                ..
            })
        ),
        "{fenced:?}"
    );
    // And the lock is free again.
    acquire(operator, Duration::ZERO).await.unwrap();
    shutdown(&[holder, operator]).await;
}

/// A node outside every trust relation still locks: AP, not CP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_alone_can_lock() {
    let alone = spawn_node("alone").await;
    let held = acquire(&alone.node, Duration::ZERO).await.unwrap();
    assert!(held.waited_on.is_empty());
    let view = alone.node.locks().current(&lock()).unwrap();
    assert_eq!(view.state, ClaimState::Held);
    shutdown(&[&alone.node]).await;
}
