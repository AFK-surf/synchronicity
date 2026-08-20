//! Three in-process nodes on localhost iroh endpoints with static trust,
//! converging over the real protocols with no relay and no discovery.

use std::time::Duration;

use synch_core::{now_ns, OriginId};
use synch_engine::{Node, NodeConfig, VersionPolicy};
use synch_store::{Binding, BindingSource};

/// Runs a closure that touches the store on the blocking pool, as
/// `Store::conn` requires on a multi-thread runtime worker (§10).
async fn off_runtime<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        f()
    })
    .await
    .unwrap()
}

/// A spawned node plus the tempdirs keeping its database and space alive.
struct Peer {
    _data: tempfile::TempDir,
    space: tempfile::TempDir,
    node: Node,
}

/// A node named `name@cluster.example`, opened over loopback.
async fn spawn(name: &str) -> Peer {
    spawn_with(name, |_| {}).await
}

/// A node whose configuration is tuned before it opens; the store opens off
/// the runtime worker so even the §10 audit test below may spawn safely.
async fn spawn_with(name: &str, tune: impl FnOnce(&mut NodeConfig)) -> Peer {
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let origin = OriginId::named(name, "cluster.example").unwrap();
    let dir = data.path().to_path_buf();
    off_runtime(move || Node::init_named_by_zone(&dir, origin))
        .await
        .unwrap();
    let mut config = NodeConfig::loopback(data.path());
    tune(&mut config);
    let node = Node::open(config).await.unwrap();
    Peer {
        _data: data,
        space,
        node,
    }
}

/// Trust is unilateral (§3.2): `a` admits `b` and learns how to dial it.
fn trust(a: &Node, b: &Node) {
    a.store()
        .put_binding(&Binding {
            origin: b.origin().clone(),
            node_id: b.node_id(),
            source: BindingSource::Static,
            domain: None,
            issuer: None,
            spaces: Vec::new(),
            note: None,
            added_at: 0,
            expires_at: None,
        })
        .unwrap();
    // Direct addresses only: these tests never touch the network.
    a.remember_peer(&b.net().direct_addr()).unwrap();
}

/// Every node in `peers` trusts and can dial every other.
fn introduce(peers: &[&Peer]) {
    for a in peers {
        for b in peers {
            if a.node.origin() != b.node.origin() {
                trust(&a.node, &b.node);
            }
        }
    }
}

/// The same over bare nodes, so a multi-thread test can run it inside a
/// blocking scope.
fn introduce_nodes(nodes: &[&Node]) {
    for a in nodes {
        for b in nodes {
            if a.origin() != b.origin() {
                trust(a, b);
            }
        }
    }
}

fn big_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 37 + 11) as u8).collect()
}

/// The §14 walkthrough: scan-publish-push, pull, a verified partial range
/// read, and a milestone ad (§6.3) turning a fetcher into a provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_nodes_converge_and_fetch_verified_content() {
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    let vps = spawn("vps").await;
    introduce(&[&nas, &laptop, &vps]);

    // The NAS indexes a space with a mix of small and large files.
    let keynote = big_payload(200_000);
    nas.node.add_space("media", nas.space.path()).unwrap();
    std::fs::create_dir_all(nas.space.path().join("talks")).unwrap();
    std::fs::write(nas.space.path().join("notes.txt"), b"read me").unwrap();
    std::fs::write(nas.space.path().join("talks/keynote.mp4"), &keynote).unwrap();
    for i in 0..3 {
        std::fs::write(
            nas.space.path().join(format!("talks/slide{i:02}.txt")),
            format!("slide {i}").as_bytes(),
        )
        .unwrap();
    }
    let head = nas.node.scan_publish_push().await.unwrap().unwrap();
    assert_eq!(head.seq, 1);

    // Both peers pull from the NAS. The push above already delivered the head;
    // the pull is what completes the trie under it.
    for peer in [&laptop, &vps] {
        let report = peer.node.sync_with_peer(&nas.node.node_id()).await.unwrap();
        assert_eq!(report.tries_completed, 1, "{report:?}");
    }
    for peer in [&laptop, &vps] {
        assert_eq!(
            peer.node.store().complete_head(nas.node.origin()).unwrap(),
            Some(head.clone()),
            "head mismatch on {}",
            peer.node.origin()
        );
    }

    // Entries match everywhere, and nobody holds content yet.
    let expected = nas
        .node
        .store()
        .list_entries(Some(nas.node.origin()), "media", "", None, None)
        .unwrap();
    assert_eq!(expected.len(), 5);
    for peer in [&laptop, &vps] {
        assert_eq!(
            peer.node
                .store()
                .list_entries(Some(nas.node.origin()), "media", "", None, None)
                .unwrap(),
            expected
        );
    }
    let keynote_root = expected
        .iter()
        .find(|e| e.path == "talks/keynote.mp4")
        .unwrap()
        .content
        .unwrap();
    assert!(laptop.node.store().blob(&keynote_root).unwrap().is_none());

    // A range read in the middle of the large object fetches only the groups
    // covering it, each verified.
    let slice = laptop
        .node
        .read_range(
            "media",
            "talks/keynote.mp4",
            &VersionPolicy::Origin(nas.node.origin().clone()),
            100_000,
            Some(4096),
        )
        .await
        .unwrap();
    assert_eq!(slice, &keynote[100_000..104_096]);
    let held = laptop.node.local_groups(&keynote_root).unwrap();
    assert!(
        held.count() < synch_core::group_count(keynote.len() as u64),
        "a range read must not drag the whole object across"
    );

    // A full read completes the object, byte for byte.
    assert_eq!(
        laptop
            .node
            .read_entry(nas.node.origin(), "media", "talks/keynote.mp4")
            .await
            .unwrap(),
        keynote
    );

    // The completed fetch published a milestone ad (§6.3): once the head
    // carrying it propagates, the object has a second provider.
    assert!(laptop
        .node
        .published_ad(&keynote_root)
        .unwrap()
        .expect("a completed object must be advertised")
        .is_complete());
    let ad_head = laptop.node.own_head().unwrap().unwrap();
    laptop.node.push_head(&ad_head).await.unwrap();
    vps.node
        .sync_with_peer(&laptop.node.node_id())
        .await
        .unwrap();
    let providers = vps.node.store().providers(&keynote_root).unwrap();
    assert!(
        providers.iter().any(|(o, _)| o == laptop.node.origin()),
        "the laptop's partial-then-complete copy must be discoverable"
    );

    for peer in [&nas, &laptop, &vps] {
        peer.node.shutdown().await.unwrap();
    }
}

/// §8 executed across real nodes: two origins publish different content for
/// the same `(space, path)`, a third sees one tree with one divergent path,
/// selects deterministically, and adoption ends the divergence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_unified_tree_carries_every_version_of_a_divergent_path() {
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    let vps = spawn("vps").await;
    introduce(&[&nas, &laptop, &vps]);

    nas.node.add_space("media", nas.space.path()).unwrap();
    laptop.node.add_space("media", laptop.space.path()).unwrap();
    std::fs::write(nas.space.path().join("shared.txt"), b"from the nas").unwrap();
    nas.node.scan_publish_push().await.unwrap().unwrap();
    // Distinct mtimes: the filesystem supplies them, and `newest` reads them
    // as published.
    tokio::time::sleep(Duration::from_millis(20)).await;
    std::fs::write(laptop.space.path().join("shared.txt"), b"from the laptop").unwrap();
    laptop.node.scan_publish_push().await.unwrap().unwrap();

    for peer in [&nas, &laptop, &vps] {
        for other in [&nas, &laptop] {
            if peer.node.origin() != other.node.origin() {
                peer.node
                    .sync_with_peer(&other.node.node_id())
                    .await
                    .unwrap();
            }
        }
    }

    // The observer's unified view: one tree, one path, two versions.
    let listing = vps.node.unified_listing("media", "", None, None).unwrap();
    assert_eq!(listing.len(), 1, "one path, not one per origin");
    assert_eq!(listing[0].path, "shared.txt");
    assert_eq!(listing[0].version_count(), 2);
    assert!(listing[0].is_divergent());
    assert!(listing[0].exists());

    // `newest` is a deterministic total order, so every node computes the same
    // answer from the same data.
    let mut selected = Vec::new();
    for peer in [&nas, &laptop, &vps] {
        let entry = peer
            .node
            .resolve("media", "shared.txt", &VersionPolicy::Newest)
            .unwrap();
        selected.push((entry.origin.clone(), entry.content));
    }
    assert_eq!(selected[0], selected[1]);
    assert_eq!(selected[1], selected[2]);
    assert_eq!(selected[0].0, *laptop.node.origin(), "the newer mtime wins");
    assert_eq!(
        vps.node
            .read_path("media", "shared.txt", &VersionPolicy::Newest)
            .await
            .unwrap(),
        b"from the laptop"
    );

    // An origin pin — what `--from` builds — reads the other version.
    assert_eq!(
        vps.node
            .read_path(
                "media",
                "shared.txt",
                &VersionPolicy::Origin(nas.node.origin().clone())
            )
            .await
            .unwrap(),
        b"from the nas"
    );

    // `strict` refuses, and names both versions in the refusal.
    let err = vps
        .node
        .resolve("media", "shared.txt", &VersionPolicy::Strict)
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("nas@cluster.example"), "{text}");
    assert!(text.contains("laptop@cluster.example"), "{text}");
    assert!(vps
        .node
        .read_path("media", "shared.txt", &VersionPolicy::Strict)
        .await
        .is_err());

    // Adoption is how divergence ends: the nas takes the laptop's version as
    // its own, republishing with `prev` pointing at what it replaced.
    let theirs = nas
        .node
        .read_entry(laptop.node.origin(), "media", "shared.txt")
        .await
        .unwrap();
    nas.node.adopt("media", "shared.txt", &theirs).unwrap();
    nas.node.scan_publish_push().await.unwrap().unwrap();
    let mine = nas
        .node
        .store()
        .entry(nas.node.origin(), "media", "shared.txt")
        .unwrap()
        .unwrap();
    assert_eq!(mine.prev, Some(synch_core::Hash::new(b"from the nas")));
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();

    let set = vps.node.versions("media", "shared.txt").unwrap();
    assert_eq!(set.version_count(), 1, "one version, two attestors");
    assert!(!set.is_divergent());
    assert_eq!(set.versions[0].attestors.len(), 2);
    // And `strict` now reads it without complaint.
    assert_eq!(
        vps.node
            .read_path("media", "shared.txt", &VersionPolicy::Strict)
            .await
            .unwrap(),
        b"from the laptop"
    );

    for peer in [&nas, &laptop, &vps] {
        peer.node.shutdown().await.unwrap();
    }
}

/// §5.3: the periodic pull is what guarantees convergence after a partition
/// heals — one anti-entropy round jumps straight to the newest head without
/// replaying the intermediates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn convergence_survives_a_partition() {
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;

    nas.node.add_space("media", nas.space.path()).unwrap();
    for round in 1..=3 {
        std::fs::write(
            nas.space.path().join(format!("round{round}.txt")),
            format!("content {round}").as_bytes(),
        )
        .unwrap();
        // Publish without pushing: the laptop is "partitioned" — it does not
        // even know the NAS exists yet.
        nas.node.scan_and_publish().unwrap();
    }
    let final_head = nas
        .node
        .store()
        .complete_head(nas.node.origin())
        .unwrap()
        .unwrap();
    assert_eq!(final_head.seq, 3);

    // The partition heals: trust is established and one pull round runs.
    introduce(&[&nas, &laptop]);
    let report = tokio::time::timeout(Duration::from_secs(30), laptop.node.anti_entropy_round())
        .await
        .unwrap()
        .unwrap();
    assert!(report.peer.is_some(), "{report:?}");

    // One round is enough: the laptop jumps straight to the newest head and
    // pulls only the trie under it, not each intermediate root.
    assert_eq!(
        laptop
            .node
            .store()
            .complete_head(nas.node.origin())
            .unwrap(),
        Some(final_head)
    );
    assert_eq!(
        laptop
            .node
            .store()
            .list_entries(Some(nas.node.origin()), "media", "", None, None)
            .unwrap()
            .len(),
        3
    );

    nas.node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

/// §9.2: a pin starts by fetching what it guards — pinning content this node
/// has never read must not mark zero rows and report success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinning_fetches_what_it_promises_to_keep() {
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    introduce(&[&nas, &laptop]);

    nas.node.add_space("media", nas.space.path()).unwrap();
    std::fs::write(nas.space.path().join("report.md"), b"keep these bytes").unwrap();
    nas.node.scan_and_publish().unwrap();
    laptop.node.anti_entropy_round().await.unwrap();

    let entry = laptop
        .node
        .store()
        .entry(nas.node.origin(), "media", "report.md")
        .unwrap()
        .unwrap();
    let root = entry.content.unwrap();
    // Metadata only so far: the pin is what brings the bytes here.
    assert!(laptop.node.store().blob(&root).unwrap().is_none());

    laptop
        .node
        .pin_object(&root, Some(entry.size))
        .await
        .unwrap();
    assert_eq!(laptop.node.store().pinned_blobs().unwrap(), vec![root]);
    assert!(laptop.node.store().blob(&root).unwrap().unwrap().complete);
    assert_eq!(
        laptop.node.store().read_all(&root).unwrap(),
        b"keep these bytes"
    );

    // A bare root nobody holds even partially has no size to fetch by, and is
    // refused rather than recorded as a pin that guards nothing.
    let absent = synch_core::Hash::new(b"never published");
    assert!(laptop.node.pin_object(&absent, None).await.is_err());
    assert_eq!(laptop.node.store().pinned_blobs().unwrap(), vec![root]);

    nas.node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

/// §5.4 end to end: publish, overwrite, then one maintenance pass with a
/// retention window of nothing. The old root leaves `head_history`, its
/// private trie nodes are swept, and the old content's bytes leave the CAS.
/// A pinned object survives all of it, and a fresh peer can still pull the
/// current root and read the content (the former gc test's property).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_prunes_history_sweeps_the_trie_and_reclaims_bytes() {
    let _blocking = synch_core::BlockingScope::enter();
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    Node::init_named_by_zone(
        data.path(),
        OriginId::named("nas", "cluster.example").unwrap(),
    )
    .unwrap();
    let mut config = NodeConfig::loopback(data.path());
    // Everything published before "now" is out of retention.
    config.root_retention = Duration::from_nanos(1);
    let node = Node::open(config).await.unwrap();
    node.add_space("media", space.path()).unwrap();

    std::fs::write(space.path().join("notes.txt"), b"first revision").unwrap();
    node.scan_and_publish().unwrap();
    let old_root = node.current_root().unwrap();
    let old_content = node
        .store()
        .entry(node.origin(), "media", "notes.txt")
        .unwrap()
        .unwrap()
        .content
        .unwrap();
    assert!(node.store().blob(&old_content).unwrap().is_some());

    // A pinned object with no entry pointing at it: retention must not touch it.
    let pinned = node.store().ingest_bytes(b"pinned bytes", 0).unwrap();
    node.store().set_pinned(&pinned, true).unwrap();

    std::fs::write(space.path().join("notes.txt"), b"second revision").unwrap();
    // A distinct mtime, so the scanner cannot mistake the rewrite for no change.
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(space.path().join("notes.txt"), b"second revision").unwrap();
    node.scan_and_publish().unwrap();
    assert_ne!(node.current_root().unwrap(), old_root);
    // Before maintenance: the old root is retained history.
    assert!(node
        .store()
        .head_history(node.origin())
        .unwrap()
        .iter()
        .any(|h| h.root == old_root));

    let stats = node.maintenance_pass().unwrap();

    assert!(
        !node
            .store()
            .head_history(node.origin())
            .unwrap()
            .iter()
            .any(|h| h.root == old_root),
        "the displaced root must leave retention"
    );
    assert!(
        stats.nodes > 0,
        "the old root's private nodes must be swept"
    );
    assert!(
        !synch_mpt::NodeStore::has_node(node.store().as_ref(), &old_root).unwrap(),
        "the old root node itself is gone"
    );
    assert!(
        node.store().blob(&old_content).unwrap().is_none(),
        "the superseded content must leave the index"
    );
    assert!(
        !node.store().blob_path(&old_content).exists(),
        "and its bytes must leave the CAS directory"
    );
    assert!(
        node.store().blob(&pinned).unwrap().is_some(),
        "a pin outlives retention"
    );
    assert_eq!(
        node.read_entry(node.origin(), "media", "notes.txt")
            .await
            .unwrap(),
        b"second revision"
    );

    // The current root is still fully servable to a peer that has never synced.
    let laptop = spawn("laptop").await;
    trust(&laptop.node, &node);
    trust(&node, &laptop.node);
    let report = laptop.node.anti_entropy_round().await.unwrap();
    assert!(report.peer.is_some(), "{report:?}");
    assert_eq!(
        laptop
            .node
            .store()
            .complete_head(node.origin())
            .unwrap()
            .map(|h| h.seq),
        Some(2)
    );
    assert_eq!(
        laptop
            .node
            .read_entry(node.origin(), "media", "notes.txt")
            .await
            .unwrap(),
        b"second revision"
    );

    node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

/// §8: deletions are adoptable exactly as content is. A tombstone on one side
/// and a live file on the other is deletion divergence, and it ends the way
/// every other divergence ends — by someone taking the other's assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deletion_is_adopted_and_the_path_leaves_the_tree() {
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    introduce(&[&nas, &laptop]);

    nas.node.add_space("shared", nas.space.path()).unwrap();
    laptop
        .node
        .add_space("shared", laptop.space.path())
        .unwrap();

    // Both publish the same file, so the path starts out unanimous.
    for peer in [&nas, &laptop] {
        std::fs::write(peer.space.path().join("notes.txt"), b"hello").unwrap();
        peer.node.scan_and_publish().unwrap();
    }
    nas.node
        .sync_with_peer(&laptop.node.node_id())
        .await
        .unwrap();
    laptop
        .node
        .sync_with_peer(&nas.node.node_id())
        .await
        .unwrap();
    let set = laptop.node.versions("shared", "notes.txt").unwrap();
    assert_eq!(set.version_count(), 1, "{:?}", set.versions);

    // The NAS deletes it. Now the tree carries a live version and a tombstone.
    std::fs::remove_file(nas.space.path().join("notes.txt")).unwrap();
    nas.node.scan_and_publish().unwrap();
    laptop
        .node
        .sync_with_peer(&nas.node.node_id())
        .await
        .unwrap();

    let set = laptop.node.versions("shared", "notes.txt").unwrap();
    assert_eq!(set.version_count(), 2, "deletion divergence");
    assert!(set.is_divergent());
    assert!(set.exists(), "a live version keeps the path visible");

    // The laptop takes the NAS's deletion.
    let removed = laptop
        .node
        .adopt_deletion("shared", "notes.txt")
        .unwrap()
        .expect("our copy was here");
    // The engine reports the path under the *stored* space root, which was
    // canonicalized at `space add` time — on macOS the tempdir's `/var/…` is a
    // symlink to `/private/var/…`, so the raw tempdir path would not compare
    // equal even though it names the same file.
    let canonical_space = laptop.space.path().canonicalize().unwrap();
    assert_eq!(removed, canonical_space.join("notes.txt"));
    assert!(!laptop.space.path().join("notes.txt").exists());

    let head = laptop.node.scan_publish_push().await.unwrap().unwrap();
    assert!(head.seq > 1);

    // The laptop now publishes its own tombstone, both sides agree, and the
    // path has left the unified tree.
    let set = laptop.node.versions("shared", "notes.txt").unwrap();
    assert_eq!(set.version_count(), 1, "{:?}", set.versions);
    assert!(set.versions[0].is_tombstone());
    assert!(!set.exists(), "every publisher tombstoned it");
    assert!(laptop
        .node
        .unified_listing("shared", "", None, None)
        .unwrap()
        .iter()
        .all(|s| !s.exists()));

    // And the NAS sees the same once it syncs.
    nas.node
        .sync_with_peer(&laptop.node.node_id())
        .await
        .unwrap();
    let set = nas.node.versions("shared", "notes.txt").unwrap();
    assert_eq!(set.version_count(), 1);
    assert!(!set.exists());

    nas.node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

/// The same guard content adoption takes: outside a configured space nothing
/// would publish the adoption, so the write would be a silent no-op with a
/// filesystem side effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adopting_a_deletion_refuses_a_path_outside_a_space() {
    let _blocking = synch_core::BlockingScope::enter();
    let node = spawn("solo").await;
    let err = node
        .node
        .adopt_deletion("nowhere", "notes.txt")
        .unwrap_err()
        .to_string();
    assert!(err.contains("space nowhere"), "{err}");

    // A path that is simply not here is not an error: the assertion being
    // adopted is "this is gone", and it already is.
    node.node.add_space("shared", node.space.path()).unwrap();
    assert!(node
        .node
        .adopt_deletion("shared", "never-existed.txt")
        .unwrap()
        .is_none());
    node.node.shutdown().await.unwrap();
}

/// One chunk group, so the delta tests can talk in the units the tree does.
const GROUP: usize = 16 * 1024;

/// DELTA-SYNC end to end over a real mirror (`docs/DELTA-SYNC.md` §1, §3.2,
/// §7): an edit moves one group, an append moves only the appended groups, and
/// a re-ingest restores a donor the CAS has dropped. The mirror holds the
/// previous version in its CAS, because that is what the last pass fetched
/// into, so the new version is *built* there out of the old one plus the group
/// that changed — and what crosses the network is the new version's tree over
/// the region that changed, and that group. `delta_min_size` is turned down so
/// the test works in megabytes rather than the 16 MiB an unconfigured node
/// would insist on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mirror_reuses_local_bytes_when_a_file_it_holds_changes() {
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let vps = spawn_with("vps", |config| config.delta_min_size = 32 * 1024).await;
    introduce(&[&nas, &vps]);

    nas.node.add_space("media", nas.space.path()).unwrap();
    let v1 = big_payload(64 * GROUP);
    let source = nas.space.path().join("disk.img");
    std::fs::write(&source, &v1).unwrap();
    nas.node.scan_publish_push().await.unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();

    let target = tempfile::tempdir().unwrap();
    let mirrored = target.path().join("disk.img");
    vps.node
        .add_mirror("media", target.path(), &VersionPolicy::Newest)
        .unwrap();
    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.written, 1, "{report:?}");
    assert_eq!(
        report.reused_bytes, 0,
        "nothing was here to reuse: {report:?}"
    );
    assert_eq!(report.fetched_bytes, v1.len() as u64, "{report:?}");
    assert_eq!(std::fs::read(&mirrored).unwrap(), v1);

    // One 16 KiB group of a megabyte changes.
    let mut v2 = v1.clone();
    v2[40 * GROUP + 5] ^= 0xff;
    std::fs::write(&source, &v2).unwrap();
    nas.node.scan_publish_push().await.unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();

    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.written, 1, "{report:?}");
    assert_eq!(
        report.fetched_bytes, GROUP as u64,
        "only the edited group crossed the network: {report:?}"
    );
    assert_eq!(
        report.reused_bytes,
        (v2.len() - GROUP) as u64,
        "everything else came out of local storage: {report:?}"
    );
    assert_eq!(std::fs::read(&mirrored).unwrap(), v2);

    // The file grows by four groups. Every complete subtree of the old prefix
    // keeps its chaining value, so the descent proves them equal and only the
    // appended groups are fetched.
    let mut v3 = v2.clone();
    v3.extend(big_payload(4 * GROUP));
    std::fs::write(&source, &v3).unwrap();
    nas.node.scan_publish_push().await.unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();

    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.written, 1, "{report:?}");
    assert_eq!(
        report.fetched_bytes,
        4 * GROUP as u64,
        "only the appended groups were fetched: {report:?}"
    );
    assert_eq!(report.reused_bytes, v2.len() as u64, "{report:?}");
    assert_eq!(std::fs::read(&mirrored).unwrap(), v3);

    // The collector takes the version the mirror is sitting on: the only copy
    // of those bytes left on this node is the mirrored file itself, which the
    // pass re-ingests as the donor (§3.2).
    let held_root = synch_core::Hash::new(&v3);
    vps.node.store().delete_blob(&held_root).unwrap();
    assert!(vps.node.store().blob(&held_root).unwrap().is_none());
    let mut v4 = v3.clone();
    v4[40 * GROUP + 5] ^= 0xff;
    std::fs::write(&source, &v4).unwrap();
    nas.node.scan_publish_push().await.unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();

    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.written, 1, "{report:?}");
    assert_eq!(
        report.fetched_bytes, GROUP as u64,
        "the re-ingested copy carried everything but the edit: {report:?}"
    );
    assert_eq!(report.reused_bytes, (v4.len() - GROUP) as u64, "{report:?}");
    assert_eq!(std::fs::read(&mirrored).unwrap(), v4);
    assert!(
        vps.node.store().blob(&held_root).unwrap().is_some(),
        "the old version is back in the CAS under its own root"
    );

    // The staging file is gone (§9.4), and the pass after it has nothing to do.
    let left: Vec<String> = std::fs::read_dir(target.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["disk.img".to_string()]);
    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.current, 1, "{report:?}");
    assert_eq!(report.written, 0, "{report:?}");

    nas.node.shutdown().await.unwrap();
    vps.node.shutdown().await.unwrap();
}

/// A provider hint is only worth a row for an origin this node could dial.
///
/// Hints are unverified by design — content is hash-verified whatever the hint
/// said — but taking one costs a `blob_providers` row, and the origin in it is
/// a peer's word. The fetch below has no local ad covering the root, so it
/// falls back to asking peers (§5.1): completion plus the storage decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_hint_for_an_unbound_origin_is_not_stored() {
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    introduce(&[&nas, &laptop]);

    // An object the NAS holds whole, advertised by itself and by an origin the
    // laptop has never heard of.
    let payload = big_payload(50_000);
    let root = nas.node.store().ingest_bytes(&payload, now_ns()).unwrap();
    let ad = nas.node.store().local_ad(&root).unwrap().unwrap();
    nas.node
        .store()
        .put_provider(&root, nas.node.origin(), &ad)
        .unwrap();
    let stranger = OriginId::named("stranger", "elsewhere.example").unwrap();
    nas.node
        .store()
        .put_provider(&root, &stranger, &ad)
        .unwrap();

    // The laptop holds no ad for this root, so the fetch asks its peers and
    // completes with hash-verified bytes.
    let report = laptop
        .node
        .fetch_all(&root, payload.len() as u64)
        .await
        .unwrap();
    assert!(report.complete, "{report:?}");
    assert_eq!(laptop.node.store().read_all(&root).unwrap(), payload);

    let learned: Vec<OriginId> = laptop
        .node
        .store()
        .providers(&root)
        .unwrap()
        .into_iter()
        .map(|(origin, _)| origin)
        .collect();
    assert!(
        learned.contains(nas.node.origin()),
        "the peer we are bound to is worth a row: {learned:?}"
    );
    assert!(
        !learned.contains(&stranger),
        "the origin we could not dial is not: {learned:?}"
    );
}

/// The whole sync-and-fetch path completes without a runtime worker touching
/// the store (§10) — an audit regression that panics inside the offending
/// task, so "the work completed at all" is the assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sync_path_never_touches_the_store_on_a_runtime_worker() {
    // Deliberately *without* the `BlockingScope` the other tests take: this is
    // the one whose own body also holds to the rule (§10).
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    {
        let (a, b) = (nas.node.clone(), laptop.node.clone());
        off_runtime(move || introduce_nodes(&[&a, &b])).await;
    }

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(nas.space.path().join("big.bin"), &payload).unwrap();
    std::fs::write(nas.space.path().join("small.txt"), b"hello").unwrap();
    off_runtime({
        let node = nas.node.clone();
        let path = nas.space.path().to_path_buf();
        move || node.add_space("media", &path).unwrap()
    })
    .await;

    // Publish and push: the scan, the head, and the fan-out to the membership.
    let head = tokio::time::timeout(Duration::from_secs(30), nas.node.scan_publish_push())
        .await
        .unwrap()
        .unwrap()
        .expect("a head");
    assert_eq!(head.seq, 1);

    // Pull: the `Hello` exchange, its decision, and the trie fetch under it.
    let report = tokio::time::timeout(Duration::from_secs(30), laptop.node.anti_entropy_round())
        .await
        .unwrap()
        .unwrap();
    assert!(report.peer.is_some(), "{report:?}");

    // Fetch: provider ranking, the dial, and the windowed slice transfer.
    let bytes = tokio::time::timeout(
        Duration::from_secs(60),
        laptop.node.read_path(
            "media",
            "big.bin",
            &VersionPolicy::Origin(nas.node.origin().clone()),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(bytes, payload);

    // And the maintenance pass, which is the other standing loop.
    let node = laptop.node.clone();
    off_runtime(move || node.maintenance_pass()).await.unwrap();

    nas.node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

/// §5.3's reactive path delivers a head, and a head is a pointer: the trie
/// under it must follow without waiting for the receiver's own anti-entropy
/// interval, or "sub-second propagation" is true of the pointer and false of
/// the data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_head_is_followed_by_its_trie_without_waiting_for_the_interval() {
    let _blocking = synch_core::BlockingScope::enter();
    // Intervals long enough that a round driven by the clock cannot be what
    // completes this: the whole test has to finish inside a fraction of one.
    let nas = spawn_with("nas", |c| c.aae_interval = Duration::from_secs(600)).await;
    let laptop = spawn_with("laptop", |c| c.aae_interval = Duration::from_secs(600)).await;
    {
        let (a, b) = (nas.node.clone(), laptop.node.clone());
        off_runtime(move || introduce_nodes(&[&a, &b])).await;
    }
    off_runtime({
        let node = nas.node.clone();
        let path = nas.space.path().to_path_buf();
        move || node.add_space("media", &path).unwrap()
    })
    .await;
    std::fs::write(nas.space.path().join("a.txt"), b"hello").unwrap();

    // The follower's standing loop, which is what the bell has to reach.
    let (stop, _) = tokio::sync::broadcast::channel::<()>(1);
    let running = {
        let node = laptop.node.clone();
        let mut rx = stop.subscribe();
        tokio::spawn(async move {
            node.run_anti_entropy(async move {
                let _ = rx.recv().await;
            })
            .await
        })
    };

    // Publish and push. The push lands the head in the follower's pending slot;
    // the bell is what turns that into a fetch.
    let head = tokio::time::timeout(Duration::from_secs(30), nas.node.scan_publish_push())
        .await
        .unwrap()
        .unwrap()
        .expect("a head");

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let complete = loop {
        let got = {
            let (node, origin) = (laptop.node.clone(), nas.node.origin().clone());
            off_runtime(move || node.store().complete_head(&origin).unwrap()).await
        };
        if got.is_some() || std::time::Instant::now() > deadline {
            break got;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(
        complete.map(|h| h.root),
        Some(head.root),
        "the trie must follow the pushed head without a full interval passing"
    );

    let _ = stop.send(());
    let _ = running.await;
    nas.node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}
