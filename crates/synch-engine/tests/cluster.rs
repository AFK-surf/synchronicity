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

/// Runs a closure that touches the store on the blocking pool.
///
/// The scope is what marks the thread as one blocking work belongs on, which is
/// what `Store::conn`'s assertion reads (§10). `spawn_blocking` alone does not:
/// tokio propagates the runtime handle into a blocking task, so the guard
/// cannot tell one from a worker by itself.
async fn off_runtime<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(move || {
        let _scope = synch_core::BlockingScope::enter();
        f()
    })
    .await
    .unwrap()
}

struct Peer {
    _data: tempfile::TempDir,
    space: tempfile::TempDir,
    node: Node,
}

async fn spawn(name: &str) -> Peer {
    spawn_with(name, |_| {}).await
}

/// A node with its configuration adjusted before it opens.
async fn spawn_with(name: &str, tune: impl FnOnce(&mut NodeConfig)) -> Peer {
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let origin = OriginId::named(name, "cluster.example").unwrap();
    // On the blocking pool: creating a store runs the migration chain, and
    // `Store::conn` refuses to be acquired on a multi-thread runtime worker
    // (§10). Most tests here run current-thread, where that is silent; the
    // multi-thread one below is why this helper does it properly.
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

/// Static trust is unilateral, so every node must be told about every other.
fn introduce(peers: &[&Peer]) {
    let nodes: Vec<&Node> = peers.iter().map(|p| &p.node).collect();
    introduce_nodes(&nodes);
}

/// The same, over the nodes alone, so a multi-thread test can run it inside a
/// blocking scope.
fn introduce_nodes(peers: &[&Node]) {
    for a in peers {
        for b in peers {
            if a.origin() == b.origin() {
                continue;
            }
            a.store()
                .put_binding(&Binding {
                    origin: b.origin().clone(),
                    node_id: b.node_id(),
                    source: BindingSource::Static,
                    domain: None,
                    note: None,
                    added_at: 0,
                    expires_at: None,
                })
                .unwrap();
            // Direct addresses only: these tests never touch the network.
            a.remember_peer(&b.net().direct_addr()).unwrap();
        }
    }
}

fn big_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 37 + 11) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_nodes_converge_and_fetch_verified_content() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_propagates_and_divergence_is_observable() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_unified_tree_carries_every_version_of_a_divergent_path() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mirror_materializes_the_unified_tree() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let vps = spawn("vps").await;
    introduce(&[&nas, &vps]);

    nas.node.add_space("media", nas.space.path()).unwrap();
    std::fs::create_dir_all(nas.space.path().join("sub")).unwrap();
    std::fs::write(nas.space.path().join("a.txt"), b"alpha").unwrap();
    std::fs::write(nas.space.path().join("sub/b.bin"), big_payload(80_000)).unwrap();

    // Metadata the mirror has to reproduce (§7.2), set before the scan so it
    // travels the whole path: scanner, trie, anti-entropy, materialization.
    // A stamp years in the past, so "the mirror kept it" cannot be confused
    // with "the copy happened to land now".
    let source = nas.space.path().join("a.txt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o750)).unwrap();
    }
    let observed = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    std::fs::File::options()
        .write(true)
        .open(&source)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(observed))
        .unwrap();

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

    // The mirrored file is the published file, metadata included: it carries
    // the mtime the NAS observed rather than the moment the copy landed, and
    // the permission bits the NAS published.
    let mirrored = target.path().join("a.txt");
    assert_eq!(
        std::fs::metadata(&mirrored).unwrap().modified().unwrap(),
        std::fs::metadata(&source).unwrap().modified().unwrap(),
        "the mirror must carry the origin's mtime"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&mirrored).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }
    // Nothing about that makes the next pass think there is work to do.
    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.current, 2, "{report:?}");
    assert_eq!(report.written + report.retouched, 0, "{report:?}");

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn convergence_survives_a_partition() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_untrusted_node_learns_nothing() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinning_fetches_what_it_promises_to_keep() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    // §9.2: a pin is a promise the bytes stay available here, so it starts by
    // fetching what it guards: pinning content this node has never read must
    // not mark zero rows and report success.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gc_keeps_the_current_root_servable() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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
        .prune_history_before(nas.node.origin(), i64::MAX)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_recovers_its_state_across_a_restart() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let data = tempfile::tempdir().unwrap();
    let space = tempfile::tempdir().unwrap();
    let origin = OriginId::named("nas", "cluster.example").unwrap();
    Node::init_named_by_zone(data.path(), origin.clone()).unwrap();

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
    // The scanner's change detection survives too: nothing is re-hashed. The
    // record is aged past the racy window first — a hash taken moments after
    // the file's mtime is re-verified on the next scan by design.
    for mut row in node.store().local_file_rows("media").unwrap() {
        row.scanned_at += 2_000_000_000;
        node.store().put_local_file(&row).unwrap();
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_prunes_history_sweeps_the_trie_and_reclaims_bytes() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    // §5.4 end to end: publish, overwrite, then run the maintenance pass with
    // a retention window of nothing. The old root leaves `head_history`, its
    // private trie nodes are swept, and the old content's *bytes* are gone
    // from the CAS. A pinned object survives all of it.
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_and_a_symlink_at_one_path_diverge_on_stable_mtimes() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fetch_falls_back_to_provider_hints_when_no_local_ad_covers_a_root() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    // §5.1: a node holding a root whose ads it has not replicated yet — a cold
    // cache, or an origin just admitted — asks peers who holds it. Hints are
    // unverified, and content is hash-verified regardless.
    let nas = spawn("nas").await;
    let laptop = spawn("laptop").await;
    introduce(&[&nas, &laptop]);

    let payload = big_payload(300_000);
    nas.node.add_space("media", nas.space.path()).unwrap();
    std::fs::write(nas.space.path().join("big.bin"), &payload).unwrap();
    nas.node.scan_and_publish().unwrap();

    // The laptop learns the NAS's head, and with it the `b:` ad, the ordinary
    // way.
    laptop
        .node
        .sync_with_peer(&nas.node.node_id())
        .await
        .unwrap();
    let root = laptop
        .node
        .store()
        .entry(nas.node.origin(), "media", "big.bin")
        .unwrap()
        .unwrap()
        .content
        .unwrap();

    // Now drop every provider row the laptop holds for that object: it knows
    // the head and the root, but no ad says who can serve it.
    laptop
        .node
        .store()
        .delete_provider(&root, nas.node.origin())
        .unwrap();
    assert!(laptop.node.providers_for(&root, 0, 1).unwrap().is_empty());

    // The fetch asks peers, learns the hint, and completes.
    let report = laptop
        .node
        .fetch_all(&root, payload.len() as u64)
        .await
        .unwrap();
    assert!(report.complete, "{report:?}");
    assert_eq!(laptop.node.store().read_all(&root).unwrap(), payload);

    nas.node.shutdown().await.unwrap();
    laptop.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deletion_is_adopted_and_the_path_leaves_the_tree() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    // §8: deletions are adoptable exactly as content is. A tombstone on one
    // side and a live file on the other is deletion divergence, and it ends
    // the way every other divergence ends — by someone taking the other's
    // assertion as their own.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adopting_a_deletion_refuses_a_path_outside_a_space() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    // The same guard content adoption takes: outside a configured space
    // nothing would publish the adoption, so the write would be a silent no-op
    // with a filesystem side effect.
    let node = spawn("solo").await;
    let err = node
        .node
        .adopt_deletion("nowhere", "notes.txt")
        .unwrap_err()
        .to_string();
    assert!(err.contains("space nowhere"), "{err}");

    // And a path that is simply not here is not an error: the assertion being
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

/// An edit to a mirrored file moves the edit, and nothing else
/// (`docs/DELTA-SYNC.md` §1, §3.4).
///
/// The mirror holds the previous version in its CAS, because that is what the
/// last pass fetched into, so the new version is *built* there out of the old
/// one plus the group that changed — and what crosses the network is the new
/// version's tree over the region that changed, and that group. The file then
/// comes off the CAS object it was built in.
///
/// The node is configured with a small `delta_min_size` so the test can work in
/// megabytes rather than the 16 MiB an unconfigured node would insist on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mirror_reuses_local_bytes_when_a_file_it_holds_changes() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
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

    // The staging file is gone (§9.4).
    let left: Vec<String> = std::fs::read_dir(target.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["disk.img".to_string()]);

    // And the pass after it has nothing to do at all.
    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.current, 1, "{report:?}");
    assert_eq!(report.written, 0, "{report:?}");

    nas.node.shutdown().await.unwrap();
    vps.node.shutdown().await.unwrap();
}

/// An appended file keeps everything it had: the tail is fetched, the prefix is
/// not (`docs/DELTA-SYNC.md` §7's append case).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_appended_file_transfers_only_what_was_appended() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let vps = spawn_with("vps", |config| config.delta_min_size = 32 * 1024).await;
    introduce(&[&nas, &vps]);

    nas.node.add_space("media", nas.space.path()).unwrap();
    let v1 = big_payload(48 * GROUP);
    let source = nas.space.path().join("app.log");
    std::fs::write(&source, &v1).unwrap();
    nas.node.scan_publish_push().await.unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();

    let target = tempfile::tempdir().unwrap();
    vps.node
        .add_mirror("media", target.path(), &VersionPolicy::Newest)
        .unwrap();
    vps.node.sync_mirror(target.path()).await.unwrap();

    // The log grows by four groups. Every complete subtree of the old prefix
    // keeps its chaining value, so the descent proves them equal and only the
    // appended groups — plus the tail group the append reshaped — are fetched.
    let mut v2 = v1.clone();
    v2.extend(big_payload(4 * GROUP));
    std::fs::write(&source, &v2).unwrap();
    nas.node.scan_publish_push().await.unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();

    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.written, 1, "{report:?}");
    assert_eq!(
        report.fetched_bytes,
        4 * GROUP as u64,
        "only the appended groups were fetched: {report:?}"
    );
    assert_eq!(report.reused_bytes, v1.len() as u64, "{report:?}");
    assert_eq!(std::fs::read(target.path().join("app.log")).unwrap(), v2);

    nas.node.shutdown().await.unwrap();
    vps.node.shutdown().await.unwrap();
}

/// The mirror's own copy stands in for a donor the CAS has thrown away
/// (`docs/DELTA-SYNC.md` §3.2).
///
/// Donors are CAS objects, so a collector that took the previous version would
/// ordinarily end delta for that path — even though the bytes of that version
/// are sitting at the mirror's own destination, which is where the last pass
/// put them. The pass notices that the file on the disk *is* the version the
/// lineage named, ingests it back, and the update is CAS-to-CAS delta again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mirror_re_ingests_its_own_copy_when_the_cas_has_dropped_it() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
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
    vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(std::fs::read(&mirrored).unwrap(), v1);

    // The collector takes the version the mirror is sitting on. Nothing of it
    // is left in the CAS, and the only copy of those bytes on this node is the
    // mirrored file itself.
    let old_root = synch_core::Hash::new(&v1);
    vps.node.store().delete_blob(&old_root).unwrap();
    assert!(vps.node.store().blob(&old_root).unwrap().is_none());

    // One group changes.
    let mut v2 = v1.clone();
    v2[40 * GROUP + 5] ^= 0xff;
    std::fs::write(&source, &v2).unwrap();
    nas.node.scan_publish_push().await.unwrap();
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();

    let report = vps.node.sync_mirror(target.path()).await.unwrap();
    assert_eq!(report.written, 1, "{report:?}");
    assert_eq!(
        report.fetched_bytes, GROUP as u64,
        "the re-ingested copy carried everything but the edit: {report:?}"
    );
    assert_eq!(report.reused_bytes, (v2.len() - GROUP) as u64, "{report:?}");
    assert_eq!(std::fs::read(&mirrored).unwrap(), v2);
    // The old version is back in the CAS under its own root, which is what
    // made it a donor.
    assert!(vps.node.store().blob(&old_root).unwrap().is_some());

    nas.node.shutdown().await.unwrap();
    vps.node.shutdown().await.unwrap();
}

/// §7.2 end to end: a mirror on a node that is never asked to sync follows
/// the tree as the node learns it. The exchange flips the head to complete,
/// which rings the mirror bell, and the standing loop's pass does the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mirror_follows_the_tree_as_the_node_learns_it() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let nas = spawn("nas").await;
    let vps = spawn("vps").await;
    introduce(&[&nas, &vps]);

    // The standing loop, as the daemon would run it.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let runner = vps.node.clone();
    let mirror_loop = tokio::spawn(async move {
        runner
            .run_mirrors(async {
                let _ = rx.await;
            })
            .await;
    });

    let target = tempfile::tempdir().unwrap();
    vps.node
        .add_mirror("media", target.path(), &VersionPolicy::Newest)
        .unwrap();

    nas.node.add_space("media", nas.space.path()).unwrap();
    std::fs::write(nas.space.path().join("clip.txt"), b"on air").unwrap();
    nas.node.scan_publish_push().await.unwrap();

    // The exchange completes the head's trie; no `sync_mirror` call follows.
    vps.node.sync_with_peer(&nas.node.node_id()).await.unwrap();
    let mirrored = target.path().join("clip.txt");
    for _ in 0..500 {
        if mirrored.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(std::fs::read(&mirrored).unwrap(), b"on air");

    tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), mirror_loop)
        .await
        .expect("the mirror loop must stop promptly")
        .unwrap();
    nas.node.shutdown().await.unwrap();
    vps.node.shutdown().await.unwrap();
}

/// A provider hint is only worth a row for an origin this node could dial.
///
/// Hints are unverified by design — content is hash-verified whatever the hint
/// said — but taking one costs a `blob_providers` row, and the origin in it is
/// a peer's word. An origin with no live binding here is one `providers_for`
/// would skip anyway, so the row buys nothing and is not written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_hint_for_an_unbound_origin_is_not_stored() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
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

    // The laptop holds no ad for this root, so the fetch asks its peers.
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

/// The whole sync-and-fetch path runs without blocking a runtime worker on the
/// store (§10).
///
/// This is the test the guard needs to have teeth. `Store::conn` asserts that
/// it is not being acquired on a **multi-thread** runtime worker outside a
/// blocking scope, and the rest of the suite runs on `#[tokio::test]`'s
/// current-thread runtime, where the assertion is deliberately silent: one
/// worker the test itself is driving is not the hazard. The daemon runs
/// multi-thread, so this test runs multi-thread, and it drives the paths four
/// prior audit passes kept leaving call sites behind on — the accept path, the
/// `Hello` exchange and its push/pull decision, the trie fetch, provider
/// discovery, the blob fetch, publishing, and the maintenance pass.
///
/// A violation is a panic inside the offending task, so the assertion below is
/// really "the work completed at all": a parked-worker regression fails here
/// with a message naming the rule instead of showing up as a daemon that goes
/// quiet under load.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sync_path_never_touches_the_store_on_a_runtime_worker() {
    // Deliberately *without* the `BlockingScope` the other tests take: this is
    // the one whose own body also holds to the rule, so nothing it does can
    // mask a violation (§10).
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

/// A pushed head fetches its trie without waiting for the next interval.
///
/// §5.3's reactive path delivers a head, and a head is a pointer: `entries`,
/// mirrors and the S3 gateway all sit behind promotion, so until the trie under
/// it is fetched nothing a reader looks at has moved. The fetch used to wait
/// for the receiver's own anti-entropy round — 30 s ± 50 % — which made the
/// "sub-second propagation" the design claims true of the pointer and false of
/// the data. The loop listens for a pending head now.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_head_is_followed_by_its_trie_without_waiting_for_the_interval() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    // Long enough that a round driven by the clock cannot be what completes
    // this: the whole test has to finish inside a fraction of one interval.
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
