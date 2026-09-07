//! Two real iroh endpoints on localhost, with relays and discovery disabled,
//! exercising the §5 metadata protocol and the §6.4 blob protocol end to end.

use synch_core::{file_key, now_ns, ChunkRanges, Hash, SignedHead};
use synch_engine::{FetchOutcome, Syncer};
use synch_mpt::Trie;
use synch_store::{Slot, Store};

mod common;
use common::wire::{connect, connect_blob, shutdown_all, trust, trust_all, WireNode};

/// Publishes `files` under the fixed `media` space this suite writes into.
fn publish(node: &WireNode, seq: u64, files: &[(&str, &[u8])]) -> SignedHead {
    let files: Vec<(&str, &str, &[u8])> = files.iter().map(|(p, c)| ("media", *p, *c)).collect();
    node.publish(seq, &files, &[])
}

/// A one-file update stores only its changed paths, independently of the
/// corpus size. Actual requesting-operation traffic is counted in fetch_progress.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incremental_updates_transfer_only_the_change() {
    use std::collections::HashSet;
    use synch_mpt::{NodeStore, TrieNode};
    let _blocking = synch_core::BlockingScope::enter();
    for corpus in [60, 600] {
        let publisher = WireNode::spawn(Some("nas")).await;
        let follower = WireNode::spawn(Some("laptop")).await;
        trust_all(&[&publisher, &follower]);
        let files: Vec<(String, Vec<u8>)> = (0..corpus)
            .map(|i| (format!("f{i:03}.bin"), vec![i as u8; 32]))
            .collect();
        let borrowed: Vec<_> = files
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_slice()))
            .collect();
        let head1 = publish(&publisher, 1, &borrowed);
        let client = connect(&follower, &publisher).await;
        let syncer = Syncer::new(follower.store.clone());
        syncer.sync_with(&client).await.unwrap();
        let unchanged_key = file_key("media", "f059.bin").unwrap();
        let unchanged = Trie::new(follower.store.as_ref())
            .get(head1.root, &unchanged_key)
            .unwrap();
        assert!(unchanged.is_some());
        let nodes_before = count_nodes(&follower.store);

        // Publishing changes the file record and adds its new blob advertisement.
        let head2 = publish(&publisher, 2, &[("f000.bin", b"changed")]);
        let changed_keys = [
            file_key("media", "f000.bin").unwrap(),
            synch_core::blob_key(&Hash::new(b"changed")),
        ];
        let source = Trie::new(publisher.store.as_ref());
        let changes = source.diff(head1.root, head2.root).unwrap();
        assert_eq!(changes.len(), 2);
        assert!(changes
            .iter()
            .all(|change| changed_keys.contains(&change.key)));
        let mut expected_new = HashSet::new();
        for key in &changed_keys {
            let proof = source.prove(head2.root, key).unwrap();
            // Every branch/routing step consumes one nibble; one terminal
            // holder may follow. This bound depends on keys, never entry count.
            assert!(proof.nodes.len() <= 2 * key.len() + 1);
            for bytes in proof.nodes {
                let hash = TrieNode::hash_of_encoded(&bytes).unwrap();
                if !follower.store.has_node(&hash).unwrap() {
                    expected_new.insert(hash);
                }
            }
        }
        let report = syncer.sync_with(&client).await.unwrap();
        assert_eq!(report.tries_completed, 1, "{report:?}");
        assert_eq!(
            follower.store.complete_head(&publisher.origin).unwrap(),
            Some(head2.clone())
        );
        let stored = count_nodes(&follower.store) - nodes_before;
        // Adding the new advertisement may split one existing compressed
        // segment, creating one neighboring node outside the new key's path.
        assert!(
            (expected_new.len()..=expected_new.len() + 1).contains(&stored),
            "{corpus} files: {stored} new nodes exceed {} changed-path nodes plus one split neighbor",
            expected_new.len(),
        );
        assert!(expected_new
            .iter()
            .all(|hash| follower.store.has_node(hash).unwrap()));
        let view = Trie::new(follower.store.as_ref());
        assert_eq!(
            view.get(head2.root, &changed_keys[0]).unwrap(),
            source.get(head2.root, &changed_keys[0]).unwrap()
        );
        assert_eq!(view.get(head2.root, &unchanged_key).unwrap(), unchanged);
        shutdown_all(&[&publisher, &follower]).await;
    }
}

/// §3.2: connections from device keys with no live binding are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_peers_are_refused() {
    let _blocking = synch_core::BlockingScope::enter();
    let server = WireNode::spawn(Some("nas")).await;
    let stranger = WireNode::spawn(Some("intruder")).await;
    // The stranger trusts the server (so it will dial), but not vice versa.
    trust(&stranger.store, &server.origin, &server.key());

    let client = connect(&stranger, &server).await;
    // The handshake may complete, but the server refuses to serve anything.
    let result = client
        .get_nodes(Hash::EMPTY, &[(Vec::new(), Hash::new(b"anything"))])
        .await;
    assert!(result.is_err(), "an untrusted peer must not be served");

    shutdown_all(&[&server, &stranger]).await;
}

/// A request costs a stream, not a session: a fetch that dialed for itself
/// would open one QUIC session per file, a handshake here and an idle
/// connection out there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_to_a_peer_share_one_session() {
    let _blocking = synch_core::BlockingScope::enter();
    let client = WireNode::spawn(Some("laptop")).await;
    let server = WireNode::spawn(Some("nas")).await;
    trust_all(&[&client, &server]);

    let first = connect(&client, &server).await;
    let second = connect(&client, &server).await;
    assert_eq!(
        first.connection().stable_id(),
        second.connection().stable_id(),
        "a second request must not open a second session"
    );
    // Both really are usable, not just equal.
    second
        .get_nodes(Hash::EMPTY, &[(Vec::new(), Hash::new(b"nothing"))])
        .await
        .unwrap();

    // A session that has gone is not handed out again: the next request dials.
    first.connection().close(0u32.into(), b"done");
    let third = connect(&client, &server).await;
    assert_ne!(
        third.connection().stable_id(),
        first.connection().stable_id(),
        "a closed session must be replaced, not reused"
    );
    third
        .get_nodes(Hash::EMPTY, &[(Vec::new(), Hash::new(b"nothing"))])
        .await
        .unwrap();

    // The two ALPNs are separate sessions, untouched by each other's dials.
    connect_blob(&client, &server).await;
    let again = connect(&client, &server).await;
    assert_eq!(
        again.connection().stable_id(),
        third.connection().stable_id()
    );

    // A binding that lapses drops the session it was dialed under (§3.2).
    client
        .store
        .remove_binding(
            &server.origin,
            &server.key(),
            synch_store::BindingSource::Static,
        )
        .unwrap();
    let refused = client.net.connect_mpt(server.net.direct_addr()).await;
    assert!(
        matches!(refused, Err(synch_net::NetError::Untrusted(_))),
        "a peer we no longer trust must not be dialed: {refused:?}"
    );
    assert!(
        third.connection().close_reason().is_some(),
        "and the session it was dialed under must not stay open"
    );

    shutdown_all(&[&client, &server]).await;
}

/// The §5.3 reactive path over the wire: push_head lands in the pending slot
/// (complete untouched), fetch_pending from the publisher flips it — and a
/// head every provider returns `missing` for is abandoned (§5.2), not left
/// wedging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reactive_head_push_propagates_and_unservable_heads_are_abandoned() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = WireNode::spawn(Some("nas")).await;
    let follower = WireNode::spawn(Some("laptop")).await;
    trust_all(&[&publisher, &follower]);

    let head = publish(&publisher, 1, &[("a.txt", b"hello")]);
    let client = connect(&publisher, &follower).await;
    client.push_head(&head).await.unwrap();

    // The follower has the head, not the trie, so it sits in the pending slot.
    assert_eq!(
        follower.store.pending_head(&publisher.origin).unwrap(),
        Some(head.clone())
    );
    assert_eq!(
        follower.store.complete_head(&publisher.origin).unwrap(),
        None
    );

    // Pulling the trie from the publisher completes the flip.
    let back = connect(&follower, &publisher).await;
    let syncer = Syncer::new(follower.store.clone());
    let outcome = syncer
        .fetch_pending(&back, &publisher.origin)
        .await
        .unwrap();
    assert_eq!(outcome, FetchOutcome::Completed);
    assert_eq!(
        follower.store.complete_head(&publisher.origin).unwrap(),
        Some(head)
    );

    // A head whose trie nobody has — signed, valid, but unservable — is
    // abandoned after every provider returns `missing`, not left to wedge.
    let phantom = SignedHead::sign(
        &publisher.secret,
        publisher.origin.clone(),
        9,
        Hash::new(b"a root that was never published"),
        now_ns(),
    );
    assert!(syncer.offer_head(&phantom, now_ns()).unwrap().accepted());
    let outcome = syncer
        .fetch_pending(&back, &publisher.origin)
        .await
        .unwrap();
    assert_eq!(outcome, FetchOutcome::Abandoned);
    assert_eq!(
        follower.store.pending_head(&publisher.origin).unwrap(),
        None
    );

    // And a real head published afterwards is still adopted normally.
    let real = publish(&publisher, 10, &[("a.txt", b"hello")]);
    let report = syncer.sync_with(&back).await.unwrap();
    assert_eq!(report.tries_completed, 1, "{report:?}");
    assert_eq!(
        follower.store.complete_head(&publisher.origin).unwrap(),
        Some(real)
    );

    shutdown_all(&[&publisher, &follower]).await;
}

/// A value small enough to be inline must *be* inline: the alternative gives
/// one key/value map two roots, which is what structural sharing rests on not
/// happening. Such a head is retired by the §5.2 abandonment rule, not the TTL
/// sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_value_in_the_wrong_representation_retires_its_head() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = WireNode::spawn(Some("nas")).await;
    let follower = WireNode::spawn(Some("laptop")).await;
    trust_all(&[&publisher, &follower]);

    // A one-leaf trie whose leaf points at an out-of-line payload small
    // enough that it should have been inline.
    let small = b"short enough to be inline".to_vec();
    assert!(small.len() <= synch_core::INLINE_VALUE_MAX);
    let value_hash = Hash::new(&small);
    synch_mpt::NodeStore::put_value(publisher.store.as_ref(), &value_hash, &small).unwrap();
    let leaf = synch_mpt::TrieNode::Leaf {
        key_rest: synch_mpt::Nibbles::from_bytes(&file_key("media", "a.txt").unwrap()),
        value: synch_mpt::ValueRef::Hash(value_hash),
    };
    let encoded = leaf.encode();
    let root = synch_mpt::TrieNode::hash_of_encoded(&encoded).unwrap();
    synch_mpt::NodeStore::put_node(publisher.store.as_ref(), &root, &encoded).unwrap();

    let head = SignedHead::sign(
        &publisher.secret,
        publisher.origin.clone(),
        7,
        root,
        now_ns(),
    );
    let syncer = Syncer::new(follower.store.clone());
    assert!(syncer.offer_head(&head, now_ns()).unwrap().accepted());

    let client = connect(&follower, &publisher).await;
    // The node arrives; the value is refused each round — no progress — so the
    // head is retired by the counter rather than by the clock.
    let outcome = syncer
        .fetch_pending(&client, &publisher.origin)
        .await
        .unwrap();
    assert_eq!(outcome, FetchOutcome::Abandoned);
    assert_eq!(
        follower.store.pending_head(&publisher.origin).unwrap(),
        None,
        "and the head stops holding the floor"
    );

    shutdown_all(&[&publisher, &follower]).await;
}

fn count_nodes(store: &Store) -> usize {
    store.trie_stats().unwrap().nodes
}

/// An object larger than one frame transfers, a window at a time (§6.4): a
/// bao slice is encoded into memory whole and travels in one framed message,
/// so anything above `MAX_FRAME_LEN` would truncate without the windowed walk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_object_larger_than_one_frame_transfers() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = WireNode::spawn(Some("nas")).await;
    let follower = WireNode::spawn(Some("laptop")).await;
    trust_all(&[&publisher, &follower]);

    let payload: Vec<u8> = (0..20u32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    publish(&publisher, 1, &[("big.bin", payload.as_slice())]);
    let root = publisher
        .store
        .list_entries(Some(&publisher.origin), "media", "", None, None)
        .unwrap()[0]
        .content
        .unwrap();

    let blob = connect_blob(&follower, &publisher).await;
    let all = ChunkRanges::single(0, synch_core::group_count(payload.len() as u64));
    let mut got = ChunkRanges::empty();
    blob.fetch_into(&follower.cas, root, payload.len() as u64, &all, &mut got)
        .await
        .unwrap();
    assert_eq!(got.count(), synch_core::group_count(payload.len() as u64));
    assert_eq!(follower.store.read_all(&root).unwrap().len(), payload.len());

    shutdown_all(&[&publisher, &follower]).await;
}

/// One origin publishing a record this node cannot decode does not stop it
/// converging with the others (§5.2): materialization is atomic, but the
/// failure must not end the whole exchange — the poisoned head is durable, so
/// one bad record would stop *every* origin's metadata from then on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_poisoned_origin_does_not_hold_up_the_others() {
    let _blocking = synch_core::BlockingScope::enter();
    let poisoned = WireNode::spawn(Some("nas")).await;
    let healthy = WireNode::spawn(Some("vps")).await;
    let follower = WireNode::spawn(Some("laptop")).await;
    trust_all(&[&poisoned, &healthy, &follower]);

    // A well-formed `f:` key whose value is not a FileEntry: signed, complete,
    // impossible to materialize.
    let trie = Trie::new(poisoned.store.as_ref());
    let root = trie
        .insert(
            Hash::EMPTY,
            &file_key("media", "bad").unwrap(),
            &[0xffu8; 8],
        )
        .unwrap();
    let head = SignedHead::sign(&poisoned.secret, poisoned.origin.clone(), 1, root, now_ns());
    poisoned
        .store
        .put_head(Slot::Complete, &head, now_ns(), now_ns())
        .unwrap();

    publish(&healthy, 1, &[("good.txt", b"readable")]);

    // One exchange carries both origins — `nas@…` sorts first, so the bad one
    // is handled before the good one is read.
    let to_healthy = connect(&poisoned, &healthy).await;
    Syncer::new(poisoned.store.clone())
        .sync_with(&to_healthy)
        .await
        .unwrap();

    let client = connect(&follower, &poisoned).await;
    let report = Syncer::new(follower.store.clone())
        .sync_with(&client)
        .await
        .unwrap();

    // The poisoned origin is reported and left behind; the healthy one lands.
    assert!(report.heads_failed >= 1, "{report:?}");
    assert_eq!(
        follower
            .store
            .list_entries(Some(&healthy.origin), "media", "", None, None)
            .unwrap()
            .len(),
        1,
        "{report:?}"
    );
    assert!(follower
        .store
        .list_entries(Some(&poisoned.origin), "media", "", None, None)
        .unwrap()
        .is_empty());

    shutdown_all(&[&poisoned, &healthy, &follower]).await;
}
