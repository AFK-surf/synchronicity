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

/// Peer-agnostic fetch (§5.2): trie nodes are content-addressed, so a node
/// converges byte-identical pulling solely from a relayer that is neither the
/// origin nor the head's source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_third_node_learns_the_trie_from_a_relayer() {
    let _blocking = synch_core::BlockingScope::enter();
    let origin_node = WireNode::spawn(Some("nas")).await;
    let relay = WireNode::spawn(Some("vps")).await;
    let laptop = WireNode::spawn(Some("laptop")).await;
    trust_all(&[&origin_node, &relay, &laptop]);

    let files: Vec<(String, Vec<u8>)> = (0..40)
        .map(|i| (format!("dir{}/file{i:03}.bin", i % 5), vec![i as u8; 64]))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_slice()))
        .collect();
    let head = publish(&origin_node, 1, &borrowed);

    // The relay syncs from the origin.
    let to_origin = connect(&relay, &origin_node).await;
    Syncer::new(relay.store.clone())
        .sync_with(&to_origin)
        .await
        .unwrap();
    assert_eq!(
        relay.store.complete_head(&origin_node.origin).unwrap(),
        Some(head.clone())
    );

    // The laptop syncs only from the relay, and still ends up byte-identical.
    let to_relay = connect(&laptop, &relay).await;
    let report = Syncer::new(laptop.store.clone())
        .sync_with(&to_relay)
        .await
        .unwrap();
    assert_eq!(report.tries_completed, 1, "{report:?}");
    assert_eq!(
        laptop.store.complete_head(&origin_node.origin).unwrap(),
        Some(head)
    );
    assert_eq!(
        laptop
            .store
            .list_entries(Some(&origin_node.origin), "media", "", None, None)
            .unwrap(),
        origin_node
            .store
            .list_entries(Some(&origin_node.origin), "media", "", None, None)
            .unwrap()
    );

    shutdown_all(&[&origin_node, &relay, &laptop]).await;
}

/// A one-file update to a 60-file trie pulls only the touched path: a diff
/// regression would silently sync whole tries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incremental_updates_transfer_only_the_change() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = WireNode::spawn(Some("nas")).await;
    let follower = WireNode::spawn(Some("laptop")).await;
    trust_all(&[&publisher, &follower]);

    let files: Vec<(String, Vec<u8>)> = (0..60)
        .map(|i| (format!("f{i:03}.bin"), vec![i as u8; 32]))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_slice()))
        .collect();
    publish(&publisher, 1, &borrowed);

    let client = connect(&follower, &publisher).await;
    let syncer = Syncer::new(follower.store.clone());
    syncer.sync_with(&client).await.unwrap();

    let nodes_before = count_nodes(&follower.store);

    // One file changes; the second exchange must pull only the touched path.
    let head2 = publish(&publisher, 2, &[("f000.bin", b"changed")]);
    let report = syncer.sync_with(&client).await.unwrap();
    assert_eq!(report.tries_completed, 1, "{report:?}");
    assert_eq!(
        follower.store.complete_head(&publisher.origin).unwrap(),
        Some(head2)
    );

    let pulled = count_nodes(&follower.store) - nodes_before;
    assert!(
        pulled < 20,
        "structural sharing should bound a one-file update to a handful of nodes, pulled {pulled}"
    );

    shutdown_all(&[&publisher, &follower]).await;
}

/// §3.2: connections from device keys with no live binding are closed
/// immediately after the QUIC handshake.
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

/// A request costs a stream, not a session: a fetch that dials for itself
/// would open one QUIC session per file, each one a handshake here and a
/// connection left idling out over there.
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

    // The two ALPNs are separate sessions, so the metadata one is untouched by
    // a content dial.
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
/// (complete untouched), and fetch_pending from the publisher flips it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reactive_head_push_propagates() {
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

    shutdown_all(&[&publisher, &follower]).await;
}

/// §5.2: if every candidate provider persistently returns `missing`, the
/// pending head is abandoned and head selection re-runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unservable_head_is_abandoned_rather_than_wedging() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = WireNode::spawn(Some("nas")).await;
    let follower = WireNode::spawn(Some("laptop")).await;
    trust_all(&[&publisher, &follower]);

    // A head whose trie nobody has: signed, valid, but unservable.
    let phantom = SignedHead::sign(
        &publisher.secret,
        publisher.origin.clone(),
        9,
        Hash::new(b"a root that was never published"),
        now_ns(),
    );
    let syncer = Syncer::new(follower.store.clone());
    assert!(syncer.offer_head(&phantom, now_ns()).unwrap().accepted());

    let client = connect(&follower, &publisher).await;
    let outcome = syncer
        .fetch_pending(&client, &publisher.origin)
        .await
        .unwrap();
    assert_eq!(outcome, FetchOutcome::Abandoned);
    assert_eq!(
        follower.store.pending_head(&publisher.origin).unwrap(),
        None
    );

    // And a real head published afterwards is still adopted normally.
    let real = publish(&publisher, 10, &[("a.txt", b"hello")]);
    let report = syncer.sync_with(&client).await.unwrap();
    assert_eq!(report.tries_completed, 1, "{report:?}");
    assert_eq!(
        follower.store.complete_head(&publisher.origin).unwrap(),
        Some(real)
    );

    shutdown_all(&[&publisher, &follower]).await;
}

/// A value small enough to be inline must *be* inline: the alternative gives
/// one key/value map two roots, which is what structural sharing rests on not
/// happening. Such a head is retired by the §5.2 abandonment rule, not left
/// for the TTL sweep — a prior audit found it holding `head_floor` instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_value_in_the_wrong_representation_retires_its_head() {
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = WireNode::spawn(Some("nas")).await;
    let follower = WireNode::spawn(Some("laptop")).await;
    trust_all(&[&publisher, &follower]);

    // A trie the publisher can serve whole, whose one leaf points at an
    // out-of-line payload small enough that it should have been inline.
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
    // The node arrives; the value is refused each round, which is no progress,
    // so the head is retired by the counter rather than by the clock.
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

/// An object larger than one frame transfers, a window at a time (§6.4).
///
/// A bao slice is encoded into memory whole and travels in a single framed
/// message, so everything above `MAX_FRAME_LEN` would fail with a truncated
/// stream: the requester walks the object in `MAX_SLICE_GROUPS` windows, and
/// the provider clamps to the same bound.
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
    blob.fetch_into(&follower.store, root, payload.len() as u64, &all, &mut got)
        .await
        .unwrap();
    assert_eq!(got.count(), synch_core::group_count(payload.len() as u64));
    assert_eq!(follower.store.read_all(&root).unwrap().len(), payload.len());

    shutdown_all(&[&publisher, &follower]).await;
}

/// One origin publishing a record this node cannot decode does not stop it
/// converging with the others (§5.2): materialization is atomic, but the
/// failure must not end the whole exchange — the poisoned head is durable, so
/// a single bad record from any trusted origin would stop *every* origin's
/// metadata from reaching this node, on every sync from then on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_poisoned_origin_does_not_hold_up_the_others() {
    let _blocking = synch_core::BlockingScope::enter();
    let poisoned = WireNode::spawn(Some("nas")).await;
    let healthy = WireNode::spawn(Some("vps")).await;
    let follower = WireNode::spawn(Some("laptop")).await;
    trust_all(&[&poisoned, &healthy, &follower]);

    // A well-formed `f:` key whose value is not a FileEntry: signed, complete,
    // and impossible to materialize.
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

    // The poisoned node picks up the healthy origin's head, so one exchange
    // carries both — `nas@…` sorts before `vps@…`, so the bad one is handled
    // first, before the good one is read.
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
