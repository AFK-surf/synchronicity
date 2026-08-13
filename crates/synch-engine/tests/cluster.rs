//! Three in-process nodes on localhost iroh endpoints with static trust,
//! converging over the real protocols with no relay and no discovery.
//!
//! This is the §14 walkthrough, executed: one node indexes a space, the others
//! learn every path and object root without holding a byte of content, then
//! fetch content on demand with per-16 KiB-group verification, including a
//! range read in the middle of a large object.

use std::time::Duration;

use synch_core::{now_ns, OriginId};
use synch_engine::{Node, NodeConfig, VersionPolicy};
use synch_store::{Binding, BindingSource};

struct Peer {
    _data: tempfile::TempDir,
    space: tempfile::TempDir,
    node: Node,
}

async fn spawn(name: &str) -> Peer {
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let origin = OriginId::named(name, "cluster.example").unwrap();
    Node::init(data.path(), Some(origin)).unwrap();
    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    Peer {
        _data: data,
        space,
        node,
    }
}

/// Static trust is unilateral, so every node must be told about every other.
fn introduce(peers: &[&Peer]) {
    for a in peers {
        for b in peers {
            if a.node.origin() == b.node.origin() {
                continue;
            }
            a.node
                .store()
                .put_binding(&Binding {
                    origin: b.node.origin().clone(),
                    node_id: b.node.node_id(),
                    source: BindingSource::Static,
                    domain: None,
                    note: None,
                    added_at: 0,
                    expires_at: None,
                })
                .unwrap();
            // Direct addresses only: these tests never touch the network.
            a.node.remember_peer(&b.node.net().direct_addr()).unwrap();
        }
    }
}

fn big_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 37 + 11) as u8).collect()
}

#[tokio::test]
async fn three_nodes_converge_and_fetch_verified_content() {
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    let vps = spawn("vps").await;
    introduce(&[&nas, &laptop, &vps]);

    // The NAS indexes a space with a mix of small and large files.
    nas.node.add_space("media", nas.space.path()).unwrap();
    std::fs::create_dir_all(nas.space.path().join("talks")).unwrap();
    let keynote = big_payload(300_000);
    std::fs::write(nas.space.path().join("notes.txt"), b"read me").unwrap();
    std::fs::write(nas.space.path().join("talks/keynote.mp4"), &keynote).unwrap();
    for i in 0..20 {
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

    // Heads match everywhere.
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
    assert_eq!(expected.len(), 22);
    for peer in [&laptop, &vps] {
        let got = peer
            .node
            .store()
            .list_entries(Some(nas.node.origin()), "media", "", None, None)
            .unwrap();
        assert_eq!(got, expected);
    }
    let keynote_root = expected
        .iter()
        .find(|e| e.path == "talks/keynote.mp4")
        .unwrap()
        .content
        .unwrap();
    assert!(laptop.node.store().blob(&keynote_root).unwrap().is_none());

    // The laptop reads a range in the middle of the large object. Only the
    // groups covering that range are fetched, and they are verified.
    let slice = laptop
        .node
        .read_range(
            "media",
            "talks/keynote.mp4",
            &VersionPolicy::Origin(nas.node.origin().clone()),
            150_000,
            Some(4096),
        )
        .await
        .unwrap();
    assert_eq!(slice, &keynote[150_000..154_096]);
    let held = laptop.node.local_groups(&keynote_root).unwrap();
    assert!(!held.is_empty());
    assert!(
        held.count() < synch_core::group_count(keynote.len() as u64),
        "a range read must not drag the whole object across"
    );

    // A full read completes the object, byte for byte.
    let whole = laptop
        .node
        .read_entry(nas.node.origin(), "media", "talks/keynote.mp4")
        .await
        .unwrap();
    assert_eq!(whole, keynote);
    assert!(
        laptop
            .node
            .store()
            .blob(&keynote_root)
            .unwrap()
            .unwrap()
            .complete
    );

    // Fetching published a milestone advertisement along the way (§6.3): the
    // laptop now advertises its copy, so the object has two providers
    // cluster-wide once the laptop's head propagates.
    assert!(laptop
        .node
        .published_ad(&keynote_root)
        .unwrap()
        .expect("a completed object must be advertised")
        .is_complete());
    // Re-running the milestone check is idempotent: the ad has not changed, so
    // no new head is minted.
    assert!(laptop
        .node
        .on_content_progress(&keynote_root)
        .unwrap()
        .is_none());
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

    // Small files transfer too, verified.
    assert_eq!(
        vps.node
            .read_entry(nas.node.origin(), "media", "notes.txt")
            .await
            .unwrap(),
        b"read me"
    );

    for peer in [&nas, &laptop, &vps] {
        peer.node.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn an_edit_propagates_and_divergence_is_observable() {
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    introduce(&[&nas, &laptop]);

    nas.node.add_space("media", nas.space.path()).unwrap();
    laptop.node.add_space("media", laptop.space.path()).unwrap();
    std::fs::write(nas.space.path().join("shared.txt"), b"version one").unwrap();
    nas.node.scan_publish_push().await.unwrap().unwrap();
    laptop
        .node
        .sync_with_peer(&nas.node.node_id())
        .await
        .unwrap();

    // The laptop indexes its own copy of the same space id with different
    // content: both assertions coexist, and divergence is data, not an error.
    std::fs::write(laptop.space.path().join("shared.txt"), b"version two").unwrap();
    laptop.node.scan_publish_push().await.unwrap().unwrap();
    nas.node
        .sync_with_peer(&laptop.node.node_id())
        .await
        .unwrap();

    let views = nas
        .node
        .store()
        .entries_for_path("media", "shared.txt")
        .unwrap();
    assert_eq!(views.len(), 2);
    let roots: std::collections::HashSet<_> = views.iter().map(|v| v.content).collect();
    assert_eq!(roots.len(), 2, "the two origins disagree, visibly");

    // Adoption is explicit, and republishes the adopted bytes as the adopter's
    // own entry with `prev` pointing at what it replaced.
    let theirs = nas
        .node
        .read_entry(laptop.node.origin(), "media", "shared.txt")
        .await
        .unwrap();
    assert_eq!(theirs, b"version two");
    nas.node.adopt("media", "shared.txt", &theirs).unwrap();
    nas.node.scan_publish_push().await.unwrap().unwrap();

    let mine = nas
        .node
        .store()
        .entry(nas.node.origin(), "media", "shared.txt")
        .unwrap()
        .unwrap();
    assert_eq!(mine.content, Some(synch_core::Hash::new(b"version two")));
    assert_eq!(mine.prev, Some(synch_core::Hash::new(b"version one")));

    // Now both origins agree: same content root, purely observationally.
    laptop
        .node
        .sync_with_peer(&nas.node.node_id())
        .await
        .unwrap();
    let views = laptop
        .node
        .store()
        .entries_for_path("media", "shared.txt")
        .unwrap();
    assert_eq!(views.len(), 2);
    assert_eq!(views[0].content, views[1].content);

    nas.node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

/// §8 executed across real nodes: two origins publish different content for the
/// same `(space, path)`, and a third — which published nothing — sees one tree
/// with one divergent path, selects deterministically, and watches the
/// divergence end when one side adopts the other.
#[tokio::test]
async fn the_unified_tree_carries_every_version_of_a_divergent_path() {
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    let vps = spawn("vps").await;
    introduce(&[&nas, &laptop, &vps]);

    // Both publishers index their own copy of the same space id, with
    // different content for the same path. The laptop's copy is the newer one.
    nas.node.add_space("media", nas.space.path()).unwrap();
    laptop.node.add_space("media", laptop.space.path()).unwrap();
    std::fs::write(nas.space.path().join("shared.txt"), b"from the nas").unwrap();
    nas.node.scan_publish_push().await.unwrap().unwrap();
    // Distinct mtimes: the filesystem is what supplies them, and `newest`
    // reads them as published.
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

    // `newest` is a deterministic total order over the assertions, so every
    // node computes the same answer from the same data.
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
    // its own, and the two assertions collapse into one unanimous version.
    let theirs = nas
        .node
        .read_entry(laptop.node.origin(), "media", "shared.txt")
        .await
        .unwrap();
    nas.node.adopt("media", "shared.txt", &theirs).unwrap();
    nas.node.scan_publish_push().await.unwrap().unwrap();
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

#[tokio::test]
async fn a_mirror_materializes_the_unified_tree() {
    let nas = spawn("nas").await;
    let vps = spawn("vps").await;
    introduce(&[&nas, &vps]);

    nas.node.add_space("media", nas.space.path()).unwrap();
    std::fs::create_dir_all(nas.space.path().join("sub")).unwrap();
    std::fs::write(nas.space.path().join("a.txt"), b"alpha").unwrap();
    std::fs::write(nas.space.path().join("sub/b.bin"), big_payload(80_000)).unwrap();
    nas.node.scan_publish_push().await.unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();

    let target = tempfile::tempdir().unwrap();
    vps.node
        .add_mirror("media", target.path(), &VersionPolicy::Newest)
        .unwrap();
    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.written, 2, "{report:?}");
    assert!(report.skipped.is_empty(), "{report:?}");
    assert_eq!(
        std::fs::read(target.path().join("a.txt")).unwrap(),
        b"alpha"
    );
    assert_eq!(
        std::fs::read(target.path().join("sub/b.bin")).unwrap(),
        big_payload(80_000)
    );

    // A deletion on the origin removes the mirrored file.
    std::fs::remove_file(nas.space.path().join("a.txt")).unwrap();
    nas.node.scan_publish_push().await.unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();
    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.removed, 1);
    assert!(!target.path().join("a.txt").exists());

    nas.node.shutdown().await.unwrap();
    vps.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn convergence_survives_a_partition() {
    // §5.3: the periodic pull is what guarantees convergence after a partition
    // heals, independently of whether any reactive push was delivered.
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

#[tokio::test]
async fn an_untrusted_node_learns_nothing() {
    let nas = spawn("nas").await;
    let intruder = spawn("intruder").await;

    nas.node.add_space("media", nas.space.path()).unwrap();
    std::fs::write(nas.space.path().join("secret.txt"), b"private").unwrap();
    nas.node.scan_and_publish().unwrap();

    // The intruder trusts the NAS and knows its address, but the NAS does not
    // trust the intruder: trust is unilateral and both sides must hold it.
    intruder
        .node
        .store()
        .put_binding(&Binding {
            origin: nas.node.origin().clone(),
            node_id: nas.node.node_id(),
            source: BindingSource::Static,
            domain: None,
            note: None,
            added_at: 0,
            expires_at: None,
        })
        .unwrap();
    intruder
        .node
        .remember_peer(&nas.node.net().direct_addr())
        .unwrap();

    let report = intruder.node.anti_entropy_round().await.unwrap();
    assert!(report.peer.is_none(), "{report:?}");
    assert_eq!(report.unreachable, 1);
    assert!(intruder
        .node
        .store()
        .complete_head(nas.node.origin())
        .unwrap()
        .is_none());
    assert!(intruder
        .node
        .store()
        .list_entries(Some(nas.node.origin()), "media", "", None, None)
        .unwrap()
        .is_empty());

    nas.node.shutdown().await.unwrap();
    intruder.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn gc_keeps_the_current_root_servable() {
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    introduce(&[&nas, &laptop]);

    nas.node.add_space("media", nas.space.path()).unwrap();
    for round in 1..=4 {
        std::fs::write(
            nas.space.path().join("rolling.txt"),
            format!("revision {round}").as_bytes(),
        )
        .unwrap();
        nas.node.scan_and_publish().unwrap();
    }
    // Drop the retention window entirely, then sweep.
    nas.node
        .store()
        .prune_history(nas.node.origin(), u64::MAX)
        .unwrap();
    let stats = nas.node.maintenance_pass().unwrap();
    assert!(stats.nodes > 0, "old roots must actually be swept");

    // The current root is still fully servable to a peer that has never synced.
    let report = laptop.node.anti_entropy_round().await.unwrap();
    assert!(report.peer.is_some(), "{report:?}");
    assert_eq!(
        laptop
            .node
            .store()
            .complete_head(nas.node.origin())
            .unwrap()
            .map(|h| h.seq),
        Some(4)
    );
    assert_eq!(
        laptop
            .node
            .read_entry(nas.node.origin(), "media", "rolling.txt")
            .await
            .unwrap(),
        b"revision 4"
    );

    nas.node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_node_recovers_its_state_across_a_restart() {
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let origin = OriginId::named("nas", "cluster.example").unwrap();
    Node::init(data.path(), Some(origin.clone())).unwrap();

    let head = {
        let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
        node.add_space("media", space.path()).unwrap();
        std::fs::write(space.path().join("a.txt"), b"durable").unwrap();
        let head = node.scan_and_publish().unwrap().1.unwrap();
        node.shutdown().await.unwrap();
        head
    };

    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
    assert_eq!(node.origin(), &origin);
    assert_eq!(node.store().complete_head(&origin).unwrap(), Some(head));
    assert_eq!(node.next_seq().unwrap(), 2);
    // The scanner's change detection survives too: nothing is re-hashed.
    let report = node.scan_all().unwrap();
    assert_eq!(report.hashed, 0);
    assert_eq!(report.unchanged, 1);
    assert_eq!(
        node.read_entry(&origin, "media", "a.txt").await.unwrap(),
        b"durable"
    );
    let _ = now_ns();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn maintenance_prunes_history_sweeps_the_trie_and_reclaims_bytes() {
    // §5.4 end to end: publish, overwrite, then run the maintenance pass with
    // a retention window of nothing. The old root leaves `head_history`, its
    // private trie nodes are swept, and the old content's *bytes* are gone
    // from the CAS. A pinned object survives all of it.
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    Node::init(
        data.path(),
        Some(OriginId::named("nas", "cluster.example").unwrap()),
    )
    .unwrap();
    let mut config = NodeConfig::loopback(data.path());
    // Everything published before "now" is out of retention.
    config.root_retention = Duration::from_nanos(1);
    let node = Node::open(config).await.unwrap();
    node.add_space("media", space.path()).unwrap();

    std::fs::write(space.path().join("notes.txt"), b"first revision").unwrap();
    node.scan_and_publish().unwrap();
    let old_root = node.current_root();
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
    let old_root = old_root.unwrap();
    assert_ne!(node.current_root().unwrap(), old_root);

    // Before maintenance: the old root is retained history and its bytes are
    // still on disk.
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

    // The current root is still complete and readable.
    assert_eq!(
        node.read_entry(node.origin(), "media", "notes.txt")
            .await
            .unwrap(),
        b"second revision"
    );
    node.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn a_file_and_a_symlink_at_one_path_diverge_on_stable_mtimes() {
    // §8: a symlink is never the same version as a file, and §7.1 makes the
    // link's own lstat mtime what selection compares — a symlink restated at
    // `now_ns()` on every scan would win `newest` forever, and would churn a
    // head every scan while doing it.
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    introduce(&[&nas, &laptop]);

    nas.node.add_space("media", nas.space.path()).unwrap();
    laptop.node.add_space("media", laptop.space.path()).unwrap();

    // The laptop publishes a real file; the NAS publishes a link at the same
    // path. The file is written second, so its mtime is the later one.
    std::os::unix::fs::symlink("../elsewhere", nas.space.path().join("shared")).unwrap();
    nas.node.scan_and_publish().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(laptop.space.path().join("shared"), b"real bytes").unwrap();
    laptop.node.scan_and_publish().unwrap();

    laptop.node.anti_entropy_round().await.unwrap();
    nas.node.anti_entropy_round().await.unwrap();

    for peer in [&nas, &laptop] {
        let set = peer.node.versions("media", "shared").unwrap();
        assert_eq!(set.version_count(), 2, "{:?}", set.versions);
        assert!(set.is_divergent());
        // Both nodes select the same side, from the same assertions.
        let selected = peer
            .node
            .resolve("media", "shared", &VersionPolicy::Newest)
            .unwrap();
        assert_eq!(selected.kind, synch_core::EntryKind::File);
        assert_eq!(selected.origin, *laptop.node.origin());
    }

    // Rescanning the NAS changes nothing: the link is unchanged, so no head.
    let (report, head) = nas.node.scan_and_publish().unwrap();
    assert_eq!(report.hashed, 0);
    assert!(head.is_none(), "an unchanged symlink must not churn a head");

    nas.node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}
