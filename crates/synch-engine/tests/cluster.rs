//! Three in-process nodes on localhost iroh endpoints with static trust,
//! converging over the real protocols with no relay and no discovery.

use std::time::Duration;

use synch_engine::{Node, VersionPolicy};
use synch_store::Slot;

mod common;
use common::{
    big_payload, off_runtime, shutdown, spawn_node as spawn, spawn_node_with as spawn_with, trust,
    trust_all as introduce,
};

/// Trust between bare nodes, so a multi-thread test can run it inside a
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

/// A restored database may trail an acknowledged own-origin publish. The peer
/// copy is a full signed head, so startup adopts it before minting another.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_readopts_a_newer_own_head_retained_by_a_peer() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = spawn("publisher").await;
    let witness = spawn("witness").await;
    introduce(&[&publisher, &witness]);

    publisher
        .node
        .add_space("media", publisher.space.path())
        .unwrap();
    std::fs::write(publisher.space.path().join("version.txt"), b"one").unwrap();
    let first = publisher.node.scan_publish_push().await.unwrap().unwrap();
    witness
        .node
        .sync_with_peer(&publisher.node.node_id())
        .await
        .unwrap();

    std::fs::write(publisher.space.path().join("version.txt"), b"two").unwrap();
    let second = publisher.node.scan_publish_push().await.unwrap().unwrap();
    witness
        .node
        .sync_with_peer(&publisher.node.node_id())
        .await
        .unwrap();
    assert_eq!(
        witness
            .node
            .store()
            .complete_head(publisher.node.origin())
            .unwrap(),
        Some(second.clone())
    );

    // Shape a Litestream rollback: the signer and all trie objects survive,
    // but the complete slot and its derived views trail by one publish.
    let store = publisher.node.store().clone();
    let first_for_restore = first.clone();
    off_runtime(move || {
        store
            .transaction(|txn| {
                txn.put_head(
                    Slot::Complete,
                    &first_for_restore,
                    synch_core::now_ns(),
                    synch_core::now_ns(),
                )?;
                txn.materialize_diff(
                    &first_for_restore.origin,
                    second.root,
                    first_for_restore.root,
                )?;
                Ok::<_, synch_store::StoreError>(())
            })
            .unwrap();
    })
    .await;
    assert_eq!(publisher.node.own_head().unwrap(), Some(first));

    assert!(publisher.node.readopt_self_on_startup().await.unwrap());
    assert_eq!(publisher.node.own_head().unwrap(), Some(second));
    let entry = publisher
        .node
        .store()
        .entry(publisher.node.origin(), "media", "version.txt")
        .unwrap()
        .unwrap();
    assert_eq!(
        publisher
            .node
            .cas_backend()
            .read_range(entry.content.unwrap(), 0, entry.size)
            .await
            .unwrap(),
        b"two"
    );

    shutdown(&[&publisher.node, &witness.node]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_take_promotes_to_cloud_before_publishing_its_own_reference() {
    let _blocking = synch_core::BlockingScope::enter();
    let source = spawn("source").await;
    let adopter = spawn_with("adopter", |config| {
        config.cloud = Some(synch_store::cloud::CloudConfig {
            service: synch_store::cloud::CloudService::Memory,
            options: Default::default(),
            scratch_dir: config.data_dir.join("cloud-scratch"),
            io_timeout: Duration::from_secs(5),
            upload_policy: synch_store::cloud::CloudUploadPolicy::Own,
            cache_bytes: None,
        });
    })
    .await;
    introduce(&[&source, &adopter]);

    source.node.add_space("media", source.space.path()).unwrap();
    let payload = big_payload(200_000);
    std::fs::write(source.space.path().join("adopt.bin"), &payload).unwrap();
    source.node.scan_publish_push().await.unwrap().unwrap();
    adopter
        .node
        .sync_with_peer(&source.node.node_id())
        .await
        .unwrap();
    adopter.node.add_detached_space("media").unwrap();

    adopter
        .node
        .adopt_from(source.node.origin(), "media", "adopt.bin")
        .await
        .unwrap();
    let adopted = adopter
        .node
        .store()
        .entry(adopter.node.origin(), "media", "adopt.bin")
        .unwrap();
    assert!(adopted.is_none(), "the reference is staged until publish");
    adopter.node.flush_staged().await.unwrap().unwrap();
    let adopted = adopter
        .node
        .store()
        .entry(adopter.node.origin(), "media", "adopt.bin")
        .unwrap()
        .unwrap();
    let root = adopted.content.unwrap();
    assert!(
        adopter.node.store().blob(&root).unwrap().unwrap().durable,
        "take must override cache-only upload policy before publishing"
    );

    adopter
        .node
        .store()
        .reconcile_scratch_generation("replacement-container")
        .unwrap();
    assert_eq!(
        adopter
            .node
            .cas_backend()
            .read_range(root, 0, payload.len() as u64)
            .await
            .unwrap(),
        payload
    );

    shutdown(&[&source.node, &adopter.node]).await;
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
    std::fs::write(nas.space.path().join("talks/slide00.txt"), b"slide 0").unwrap();
    std::fs::write(nas.space.path().join("talks/slide01.txt"), b"slide 1").unwrap();
    let head = nas.node.scan_publish_push().await.unwrap().unwrap();
    assert_eq!(head.seq, 1);

    // Both peers pull from the NAS; the push delivered the head, the pull completes its trie.
    for peer in [&laptop, &vps] {
        let report = peer.node.sync_with_peer(&nas.node.node_id()).await.unwrap();
        assert_eq!(report.tries_completed, 1, "{report:?}");
        assert_eq!(
            peer.node.store().complete_head(nas.node.origin()).unwrap(),
            Some(head.clone()),
            "head mismatch on {}",
            peer.node.origin()
        );
    }

    // The published tree's listing, and nobody holds content yet.
    let expected = nas
        .node
        .store()
        .list_entries(Some(nas.node.origin()), "media", "", None, None)
        .unwrap();
    assert_eq!(expected.len(), 4);
    let keynote_root = expected
        .iter()
        .find(|e| e.path == "talks/keynote.mp4")
        .unwrap()
        .content
        .unwrap();
    assert!(laptop.node.store().blob(&keynote_root).unwrap().is_none());

    // A range read in the middle of the large object fetches only the groups covering it.
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

    // The completed fetch published a milestone ad (§6.3); once the head
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

    shutdown(&[&nas.node, &laptop.node, &vps.node]).await;
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
    // Distinct mtimes, which `newest` reads as published.
    tokio::time::sleep(Duration::from_millis(20)).await;
    std::fs::write(laptop.space.path().join("shared.txt"), b"from the laptop").unwrap();
    laptop.node.scan_publish_push().await.unwrap().unwrap();

    // The observer pulls both versions; the NAS pulls the laptop's too, so the adoption below can read what it replaces.
    nas.node
        .sync_with_peer(&laptop.node.node_id())
        .await
        .unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();
    vps.node
        .sync_with_peer(&laptop.node.node_id())
        .await
        .unwrap();

    // The observer's unified view: one tree, one path, two versions.
    let listing = vps.node.unified_listing("media", "", None, None).unwrap();
    assert_eq!(listing.len(), 1, "one path, not one per origin");
    assert_eq!(listing[0].path, "shared.txt");
    assert_eq!(listing[0].version_count(), 2);
    assert!(listing[0].exists());

    // `newest` is a deterministic total order over the same tree.
    let selected = vps
        .node
        .resolve("media", "shared.txt", &VersionPolicy::Newest)
        .unwrap();
    assert_eq!(
        selected.origin,
        *laptop.node.origin(),
        "the newer mtime wins"
    );
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

    // Adoption ends divergence: the nas takes the laptop's version as its own,
    // republishing with `prev` pointing at what it replaced.
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

    shutdown(&[&nas.node, &laptop.node, &vps.node]).await;
}

/// §5.3: the periodic pull is what guarantees convergence after a partition
/// heals — one anti-entropy round jumps straight to the newest head.
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
        // Publish without pushing: the laptop is "partitioned" — it does not know the NAS exists yet.
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

    // One round is enough: the laptop jumps straight to the newest head, not each intermediate root.
    assert_eq!(
        laptop
            .node
            .store()
            .complete_head(nas.node.origin())
            .unwrap(),
        Some(final_head)
    );

    shutdown(&[&nas.node, &laptop.node]).await;
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

    // A bare root nobody holds has no size to fetch by, and is refused rather
    // than recorded as a pin that guards nothing.
    let absent = synch_core::Hash::new(b"never published");
    assert!(laptop.node.pin_object(&absent, None).await.is_err());
    assert_eq!(laptop.node.store().pinned_blobs().unwrap(), vec![root]);

    shutdown(&[&nas.node, &laptop.node]).await;
}

/// §5.4 end to end: publish, overwrite, then one maintenance pass with
/// nothing in retention — the old root leaves `head_history`, its private trie
/// nodes are swept, its bytes leave the CAS; a pin survives, and a fresh peer
/// still pulls the current root (the former gc test's property).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_prunes_history_sweeps_the_trie_and_reclaims_bytes() {
    let _blocking = synch_core::BlockingScope::enter();
    // Retention of nothing: everything published before "now" is swept.
    let peer = spawn_with("nas", |config| {
        config.root_retention = Duration::from_nanos(1)
    })
    .await;
    let node = &peer.node;
    node.add_space("media", peer.space.path()).unwrap();

    std::fs::write(peer.space.path().join("notes.txt"), b"first revision").unwrap();
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

    std::fs::write(peer.space.path().join("notes.txt"), b"second revision").unwrap();
    // A distinct mtime, so the scanner cannot mistake the rewrite for no change.
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(peer.space.path().join("notes.txt"), b"second revision").unwrap();
    node.scan_and_publish().unwrap();
    assert_ne!(node.current_root().unwrap(), old_root);
    // Before maintenance: the old root is retained history.
    assert!(node
        .store()
        .head_history(node.origin())
        .unwrap()
        .iter()
        .any(|h| h.root == old_root));

    node.maintenance_pass().unwrap();

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
        !synch_mpt::NodeStore::has_node(node.store().as_ref(), &old_root).unwrap(),
        "the old root node itself is gone"
    );
    assert!(
        node.store().blob(&old_content).unwrap().is_none(),
        "the superseded content must leave the index"
    );
    assert!(node.store().read_all(&old_content).is_err());
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
    trust(&laptop.node, node);
    trust(node, &laptop.node);
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

    shutdown(&[node, &laptop.node]).await;
}

/// §8: deletions are adoptable exactly as content is — a tombstone on one side
/// and a live file on the other is deletion divergence, ended by someone
/// taking the other's assertion.
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
    assert!(set.exists(), "a live version keeps the path visible");

    // The laptop takes the NAS's deletion.
    let removed = laptop
        .node
        .adopt_deletion("shared", "notes.txt")
        .unwrap()
        .expect("our copy was here");
    // The path is reported under the *stored* space root, canonicalized at
    // `space add` time — on macOS `/var/…` is a symlink to `/private/var/…`,
    // so the raw tempdir path would not compare equal.
    let canonical_space = laptop.space.path().canonicalize().unwrap();
    assert_eq!(removed, canonical_space.join("notes.txt"));
    assert!(!laptop.space.path().join("notes.txt").exists());

    let head = laptop.node.scan_publish_push().await.unwrap().unwrap();
    assert!(head.seq > 1);

    // The laptop now publishes its own tombstone, both sides agree, and the path has left the unified tree.
    let set = laptop.node.versions("shared", "notes.txt").unwrap();
    assert_eq!(set.version_count(), 1, "{:?}", set.versions);
    assert!(set.versions[0].is_tombstone());

    // The same guard content adoption takes: outside a configured space
    // nothing would publish the adoption, so the write would be a silent no-op
    // with a filesystem side effect — refused instead. A path that is simply
    // not here is not an error: the assertion being adopted is "this is gone",
    // and it already is.
    let err = laptop
        .node
        .adopt_deletion("nowhere", "notes.txt")
        .unwrap_err()
        .to_string();
    assert!(err.contains("space nowhere"), "{err}");
    assert!(laptop
        .node
        .adopt_deletion("shared", "never-existed.txt")
        .unwrap()
        .is_none());

    shutdown(&[&nas.node, &laptop.node]).await;
}

/// One chunk group, so the delta tests can talk in the units the tree does.
const GROUP: usize = 16 * 1024;

/// DELTA-SYNC end to end over a real mirror (`docs/DELTA-SYNC.md` §1, §3.2,
/// §7): an edit moves one group, an append only the appended groups, and a
/// re-ingest restores a donor the CAS dropped. The mirror holds the previous
/// version, so the new one is *built* locally out of it plus the changed
/// group — and what crosses the network is the tree over the changed region,
/// and that group. `delta_min_size` is turned down so the test works in
/// megabytes rather than the 16 MiB an unconfigured node would insist on.
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

    // The file grows by four groups: every complete subtree of the old prefix
    // keeps its chaining value, so only the appended groups are fetched.
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
    // left is the mirrored file itself, which the pass re-ingests as the donor (§3.2).
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

    shutdown(&[&nas.node, &vps.node]).await;
}

/// The whole sync-and-fetch path completes without a runtime worker touching
/// the store (§10).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sync_path_never_touches_the_store_on_a_runtime_worker() {
    // Deliberately without the `BlockingScope` the other tests take: this body holds to the rule too (§10).
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    {
        let (a, b) = (nas.node.clone(), laptop.node.clone());
        off_runtime(move || introduce_nodes(&[&a, &b])).await;
    }

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(nas.space.path().join("big.bin"), &payload).unwrap();
    off_runtime({
        let node = nas.node.clone();
        let path = nas.space.path().to_path_buf();
        move || node.add_space("media", &path).unwrap()
    })
    .await;

    // Publish and push: the scan, the head, and the fan-out to the membership.
    tokio::time::timeout(Duration::from_secs(30), nas.node.scan_publish_push())
        .await
        .unwrap()
        .unwrap()
        .expect("a head");

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

    shutdown(&[&nas.node, &laptop.node]).await;
}

/// §5.3's reactive path delivers a head, and a head is a pointer: the trie
/// under it must follow without waiting for the receiver's own anti-entropy
/// interval, or "sub-second propagation" is true of the pointer and false of
/// the data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_head_is_followed_by_its_trie_without_waiting_for_the_interval() {
    let _blocking = synch_core::BlockingScope::enter();
    // Intervals of ten minutes: nothing clock-driven can complete this.
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

    // Publish and push: the head lands in the follower's pending slot; the bell turns that into a fetch.
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
    shutdown(&[&nas.node, &laptop.node]).await;
}
