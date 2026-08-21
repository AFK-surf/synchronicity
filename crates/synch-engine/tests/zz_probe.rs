//! TEMPORARY review probe — delete after use.

use std::time::Duration;

use synch_engine::Node;
use synch_store::ReplicaPolicy;

mod common;
use common::{off_runtime, spawn_node as spawn};

async fn published(node: &Node) -> Option<synch_core::ReplicaClaim> {
    let n = node.clone();
    tokio::task::spawn_blocking(move || {
        let _s = synch_core::BlockingScope::enter();
        n.replica_claim_of(n.origin(), "media").unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_no_loop() {
    let peer = spawn("peer").await;
    let node = peer.node.clone();
    let path = peer.space.path().to_path_buf();
    off_runtime(move || {
        node.add_space("media", &path).unwrap();
        node.set_space_replication("media", Some(ReplicaPolicy::Tree), None, None, false)
            .unwrap();
    })
    .await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    eprintln!("no loop: published={:?}", published(&peer.node).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_with_loop() {
    let peer = spawn("peer").await;
    let node = peer.node.clone();
    let path = peer.space.path().to_path_buf();
    off_runtime(move || {
        node.add_space("media", &path).unwrap();
        node.set_space_replication("media", Some(ReplicaPolicy::Tree), None, None, false)
            .unwrap();
    })
    .await;
    let (stop, mut rx) = tokio::sync::broadcast::channel::<()>(1);
    let running: Node = peer.node.clone();
    let handle = tokio::spawn(async move {
        running
            .run_replicas(async move {
                let _ = rx.recv().await;
            })
            .await
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    let _ = stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    eprintln!("with loop: published={:?}", published(&peer.node).await);
}
