//! A replicated space, end to end over two real nodes (`docs/REPLICATION.md`).
//!
//! The publisher indexes a directory; the replica indexes nothing and holds
//! everything. What is being tested is the lifecycle a version goes through
//! there — wanted, held, superseded, scheduled, released — and the discipline
//! that decides the last two.

use std::time::Duration;

use synch_engine::{replica::ViewState, Node};
use synch_store::{PinHolder, ReplicaPolicy};

mod common;
use common::{off_runtime, shutdown, spawn_node as spawn, trust_all as introduce};

fn holder() -> PinHolder {
    PinHolder::Replica("media".into())
}

/// Syncs the replica from the publisher and runs one full replication pass.
async fn converge(replica: &Node, publisher: &Node) {
    replica.sync_with_peer(&publisher.node_id()).await.unwrap();
    let sweeping = replica.clone();
    off_runtime(move || sweeping.sweep_replicas(None).unwrap()).await;
    replica.fetch_replica_wants().await.unwrap();
}

/// What the replica holds and wants for `media`.
async fn coverage(replica: &Node) -> synch_store::ReplicaCoverage {
    let store = replica.store().clone();
    off_runtime(move || {
        store
            .replica_coverage(&holder(), synch_engine::replica::UNREACHABLE_ATTEMPTS)
            .unwrap()
    })
    .await
}

/// The whole point: a node that publishes nothing ends up holding every
/// version of every path, and goes on holding a version after the publisher
/// has replaced it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replica_holds_what_the_publisher_publishes_and_keeps_what_it_supersedes() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let replica = spawn("replica").await;
    introduce(&[&publisher, &replica]);

    publisher
        .node
        .add_space("media", publisher.space.path())
        .unwrap();
    std::fs::write(publisher.space.path().join("keynote.mp4"), b"first cut").unwrap();
    publisher.node.scan_publish_push().await.unwrap();

    // The replica holds no checkout of `media` at all: replication is not a
    // mirror, and the space it replicates is one it never indexes.
    let replicating = replica.node.clone();
    off_runtime(move || {
        replicating.add_detached_space("media").unwrap();
        replicating
            .set_space_replication("media", Some(ReplicaPolicy::Tree), Some(3600), None, false)
            .unwrap();
    })
    .await;

    converge(&replica.node, &publisher.node).await;
    let first = coverage(&replica.node).await;
    assert_eq!(first.held, 1, "the published version should be held");
    assert_eq!(first.wanted, 0, "and nothing should still be wanted");
    assert_eq!(first.held_bytes, b"first cut".len() as u64);

    // The publisher replaces the file. The replica takes the new version and
    // schedules — but does not yet drop — the old one.
    std::fs::write(
        publisher.space.path().join("keynote.mp4"),
        b"the second cut",
    )
    .unwrap();
    publisher.node.scan_publish_push().await.unwrap();
    converge(&replica.node, &publisher.node).await;

    let second = coverage(&replica.node).await;
    assert_eq!(
        second.held, 2,
        "both versions are held while the first is inside its grace window"
    );
    assert_eq!(
        second.releasing, 1,
        "and exactly one of them is on its way out"
    );

    // Inside the window the superseded bytes are still readable, which is the
    // whole reason to have one.
    let store = replica.node.store().clone();
    let held: Vec<synch_store::PinRow> =
        off_runtime(move || store.pins().unwrap().into_iter().collect()).await;
    let leaving = held
        .iter()
        .find(|pin| pin.release_after.is_some())
        .expect("a scheduled release");
    let store = replica.node.store().clone();
    let root = leaving.root;
    let bytes = off_runtime(move || store.read_all(&root).unwrap()).await;
    assert_eq!(bytes, b"first cut");

    shutdown(&[&publisher.node, &replica.node]).await;
}

/// The live path does the work, not the sweep (§3.4).
///
/// Staging and release-scheduling happen inside the transaction that flips the
/// head, so one anti-entropy round — with no sweep behind it — is enough to
/// want the new version and to schedule the one it replaced. The sweep exists
/// to catch what this misses, not to do this.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_promotion_stages_and_schedules_without_any_sweep() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let replica = spawn("replica").await;
    introduce(&[&publisher, &replica]);

    publisher
        .node
        .add_space("media", publisher.space.path())
        .unwrap();
    std::fs::write(publisher.space.path().join("keynote.mp4"), b"first cut").unwrap();
    publisher.node.scan_publish_push().await.unwrap();

    let replicating = replica.node.clone();
    off_runtime(move || {
        replicating.add_detached_space("media").unwrap();
        replicating
            .set_space_replication("media", Some(ReplicaPolicy::Tree), Some(3600), None, false)
            .unwrap();
    })
    .await;

    // One round, no sweep: the promotion alone must want the content.
    replica
        .node
        .sync_with_peer(&publisher.node.node_id())
        .await
        .unwrap();
    let staged = coverage(&replica.node).await;
    assert_eq!(
        staged.wanted, 1,
        "the promotion transaction should have staged the want itself"
    );
    assert_eq!(staged.held, 0, "and nothing is held until the fetch runs");

    // Fetch it, then supersede it — again with no sweep anywhere.
    replica.node.fetch_replica_wants().await.unwrap();
    assert_eq!(coverage(&replica.node).await.held, 1);

    std::fs::write(
        publisher.space.path().join("keynote.mp4"),
        b"the second cut",
    )
    .unwrap();
    publisher.node.scan_publish_push().await.unwrap();
    replica
        .node
        .sync_with_peer(&publisher.node.node_id())
        .await
        .unwrap();

    let after = coverage(&replica.node).await;
    assert_eq!(
        after.releasing, 1,
        "the promotion that replaced the root should have scheduled its release"
    );
    assert_eq!(
        after.wanted, 1,
        "and wanted the version that replaced it, before any sweep ran"
    );

    shutdown(&[&publisher.node, &replica.node]).await;
}

/// The grace window is what makes a deletion recoverable, and expiry is what
/// finally ends a claim — so that every other predicate over `pins` can stay
/// free of the clock (§3.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_version_survives_its_grace_window_and_not_a_moment_longer() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let replica = spawn("replica").await;
    introduce(&[&publisher, &replica]);

    publisher
        .node
        .add_space("media", publisher.space.path())
        .unwrap();
    std::fs::write(publisher.space.path().join("notes.txt"), b"keep me").unwrap();
    publisher.node.scan_publish_push().await.unwrap();

    let replicating = replica.node.clone();
    off_runtime(move || {
        replicating.add_detached_space("media").unwrap();
        replicating
            .set_space_replication("media", Some(ReplicaPolicy::Tree), Some(3600), None, false)
            .unwrap();
    })
    .await;
    converge(&replica.node, &publisher.node).await;
    assert_eq!(coverage(&replica.node).await.held, 1);

    // The publisher deletes it. A tombstone is a version like any other, and
    // the content it supersedes is scheduled rather than dropped.
    std::fs::remove_file(publisher.space.path().join("notes.txt")).unwrap();
    publisher.node.scan_publish_push().await.unwrap();
    converge(&replica.node, &publisher.node).await;

    let after = coverage(&replica.node).await;
    assert_eq!(after.held, 1, "still held: the grace window has not passed");
    assert_eq!(after.releasing, 1);

    // Expiry is what removes the claim. Nothing before its instant does.
    let store = replica.node.store().clone();
    let (before, after_expiry) = off_runtime(move || {
        let scheduled = store.pins().unwrap()[0].release_after.unwrap();
        let before = store.expire_pins(scheduled - 1).unwrap();
        let after = store.expire_pins(scheduled).unwrap();
        (before, after)
    })
    .await;
    assert_eq!(before, 0, "a scheduled release is a plan, not a departure");
    assert_eq!(after_expiry, 1);
    assert_eq!(coverage(&replica.node).await.held, 0);

    shutdown(&[&publisher.node, &replica.node]).await;
}

/// §2.1: under `archive` nothing is ever released, whatever the tree does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_archive_policy_releases_nothing() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let replica = spawn("replica").await;
    introduce(&[&publisher, &replica]);

    publisher
        .node
        .add_space("media", publisher.space.path())
        .unwrap();
    std::fs::write(publisher.space.path().join("draft.txt"), b"v1").unwrap();
    publisher.node.scan_publish_push().await.unwrap();

    let replicating = replica.node.clone();
    off_runtime(move || {
        replicating.add_detached_space("media").unwrap();
        replicating
            .set_space_replication("media", Some(ReplicaPolicy::Archive), None, None, false)
            .unwrap();
    })
    .await;
    converge(&replica.node, &publisher.node).await;

    std::fs::remove_file(publisher.space.path().join("draft.txt")).unwrap();
    publisher.node.scan_publish_push().await.unwrap();
    converge(&replica.node, &publisher.node).await;

    let after = coverage(&replica.node).await;
    assert_eq!(after.held, 1);
    assert_eq!(
        after.releasing, 0,
        "an archive schedules nothing, deletion included"
    );

    shutdown(&[&publisher.node, &replica.node]).await;
}

/// §3.6: absence of a reference is not evidence that a reference was removed.
///
/// The hazard is not hypothetical. `set_read_scope` throws away every foreign
/// origin's `entries` rows by design, so for a moment the tree looks empty —
/// and a sweep that scheduled releases from a listing would let go of the whole
/// store at exactly that moment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sweep_releases_nothing_while_the_view_is_incomplete() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let replica = spawn("replica").await;
    introduce(&[&publisher, &replica]);

    publisher
        .node
        .add_space("media", publisher.space.path())
        .unwrap();
    std::fs::write(publisher.space.path().join("a.bin"), b"content").unwrap();
    publisher.node.scan_publish_push().await.unwrap();

    let replicating = replica.node.clone();
    off_runtime(move || {
        replicating.add_detached_space("media").unwrap();
        replicating
            .set_space_replication("media", Some(ReplicaPolicy::Tree), Some(0), None, false)
            .unwrap();
    })
    .await;
    converge(&replica.node, &publisher.node).await;
    assert_eq!(coverage(&replica.node).await.held, 1);

    // A scope change discards every foreign origin's entries and drops their
    // complete heads back to pending. Nothing was deleted; this node's
    // knowledge is what changed.
    let scoped = replica.node.clone();
    let state = off_runtime(move || {
        scoped
            .store()
            .set_read_scope(Some(&["media".to_string()]))
            .unwrap();
        let state = scoped.view_state().unwrap();
        scoped.sweep_replicas(None).unwrap();
        state
    })
    .await;

    assert!(
        matches!(state, ViewState::Incomplete(_)),
        "a demoted head must make the view incomplete, got {state:?}"
    );
    let after = coverage(&replica.node).await;
    assert_eq!(
        after.releasing, 0,
        "a sweep with an incomplete view must schedule nothing, even at zero grace"
    );
    assert_eq!(after.held, 1, "and must certainly not drop anything");

    shutdown(&[&publisher.node, &replica.node]).await;
}

/// A want survives a restart, which is what makes the guarantee about observed
/// versions rather than about uptime (§3.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unfetchable_want_persists_and_backs_off() {
    let _blocking = synch_core::BlockingScope::enter();
    let replica = spawn("replica").await;

    let node = replica.node.clone();
    let (wanted, first_attempt) = off_runtime(move || {
        node.add_detached_space("media").unwrap();
        node.set_space_replication("media", Some(ReplicaPolicy::Tree), None, None, false)
            .unwrap();
        // An entry naming content nobody here holds and nobody advertises: the
        // shape of a version whose last provider left before this node
        // reached it.
        let absent = synch_core::Hash::new(b"gone from the cluster");
        node.store()
            .put_entry(
                &synch_core::OriginId::named("nas", "cluster.example").unwrap(),
                "media",
                "lost.bin",
                &synch_core::FileEntry::file(64, 1, absent, 1),
            )
            .unwrap();
        node.sweep_replicas(None).unwrap();
        let wanted = node.store().wants_of(&holder()).unwrap();
        // Ready immediately, before any attempt has been made.
        let ready = node
            .store()
            .wants_to_attempt(0, 60_000_000_000, 3_600_000_000_000, 8)
            .unwrap();
        (wanted, ready.len())
    })
    .await;
    assert_eq!(wanted.len(), 1, "the sweep should want the missing object");
    assert_eq!(wanted[0].size, 64, "carrying the size the entry knew");
    assert_eq!(first_attempt, 1);

    // The fetch cannot succeed, and the failure is recorded rather than lost.
    let report = replica.node.fetch_replica_wants().await.unwrap();
    assert_eq!(report.held, 0);
    assert_eq!(report.failed, 1);

    let store = replica.node.store().clone();
    let (attempts, ready_now) = off_runtime(move || {
        let wants = store.wants_of(&holder()).unwrap();
        let now = synch_core::now_ns();
        let ready = store
            .wants_to_attempt(now, 60_000_000_000, 3_600_000_000_000, 8)
            .unwrap();
        (wants[0].attempts, ready.len())
    })
    .await;
    assert_eq!(attempts, 1, "the want records its failure and stays");
    assert_eq!(
        ready_now, 0,
        "and waits out its backoff rather than spinning"
    );

    shutdown(&[&replica.node]).await;
}

/// A space this node only replicates publishes no tombstones when it is
/// removed: `space rm` is an unpublish, and there is nothing here to unpublish
/// (§3.2, §8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_replicated_space_publishes_nothing() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let replica = spawn("replica").await;
    introduce(&[&publisher, &replica]);

    publisher
        .node
        .add_space("media", publisher.space.path())
        .unwrap();
    std::fs::write(publisher.space.path().join("a.bin"), b"content").unwrap();
    publisher.node.scan_publish_push().await.unwrap();

    let replicating = replica.node.clone();
    off_runtime(move || {
        replicating.add_detached_space("media").unwrap();
        replicating
            .set_space_replication("media", Some(ReplicaPolicy::Tree), None, None, false)
            .unwrap();
    })
    .await;
    converge(&replica.node, &publisher.node).await;

    let node = replica.node.clone();
    let (staged, held_after, released_after) = off_runtime(move || {
        let staged = node.remove_space("media", false).unwrap();
        let held = node.store().pins().unwrap().len();
        // And again with `--release`, which is the only thing that drops it.
        node.add_detached_space("media").unwrap();
        node.set_space_replication("media", Some(ReplicaPolicy::Tree), None, None, false)
            .unwrap();
        node.remove_space("media", true).unwrap();
        (staged, held, node.store().pins().unwrap().len())
    })
    .await;

    assert!(
        staged.is_empty(),
        "a space this node never published into has nothing to unpublish, got {staged:?}"
    );
    assert_eq!(held_after, 1, "and its content stays unless asked");
    assert_eq!(released_after, 0, "`--release` is what drops it");

    shutdown(&[&publisher.node, &replica.node]).await;
}

/// A replica of a space it also indexes is two independent halves of one row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_space_can_be_indexed_and_replicated_at_once() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let both = spawn("both").await;
    introduce(&[&publisher, &both]);

    publisher
        .node
        .add_space("media", publisher.space.path())
        .unwrap();
    std::fs::write(publisher.space.path().join("theirs.bin"), b"theirs").unwrap();
    publisher.node.scan_publish_push().await.unwrap();

    // This node publishes its own copy of `media` *and* holds everyone else's.
    both.node.add_space("media", both.space.path()).unwrap();
    let replicating = both.node.clone();
    off_runtime(move || {
        replicating
            .set_space_replication("media", Some(ReplicaPolicy::Tree), None, None, false)
            .unwrap();
    })
    .await;
    std::fs::write(both.space.path().join("mine.bin"), b"mine").unwrap();
    both.node.scan_publish_push().await.unwrap();
    converge(&both.node, &publisher.node).await;

    let after = coverage(&both.node).await;
    assert_eq!(
        after.held, 2,
        "both its own version and the publisher's are held"
    );

    // The checkout is untouched by any of it.
    assert!(both.space.path().join("mine.bin").exists());
    assert!(
        !both.space.path().join("theirs.bin").exists(),
        "replication materializes nothing; that is what a mirror is for"
    );

    let node = both.node.clone();
    let path = off_runtime(move || node.store().space("media").unwrap().unwrap().local_path).await;
    assert!(path.is_some(), "and the space is still indexed");

    shutdown(&[&publisher.node, &both.node]).await;
}

/// Turning replication off leaves the checkout alone, and the reverse.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_two_halves_of_a_space_are_set_independently() {
    let _blocking = synch_core::BlockingScope::enter();
    let peer = spawn("peer").await;
    let node = peer.node.clone();
    let path = peer.space.path().to_path_buf();

    off_runtime(move || {
        node.add_space("media", &path).unwrap();
        node.set_space_replication(
            "media",
            Some(ReplicaPolicy::Archive),
            Some(60),
            Some(99),
            false,
        )
        .unwrap();
        let row = node.store().space("media").unwrap().unwrap();
        assert_eq!(row.replicate, Some(ReplicaPolicy::Archive));
        assert_eq!(row.grace_secs(), 60);
        assert_eq!(row.budget, Some(99));
        assert!(row.local_path.is_some());

        node.set_space_replication("media", None, None, None, false)
            .unwrap();
        let row = node.store().space("media").unwrap().unwrap();
        assert!(row.replicate.is_none(), "replication is off");
        assert!(row.local_path.is_some(), "and the checkout is untouched");
    })
    .await;

    tokio::time::timeout(Duration::from_secs(5), shutdown(&[&peer.node]))
        .await
        .unwrap();
}
