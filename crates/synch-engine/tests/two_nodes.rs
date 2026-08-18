//! Two real iroh endpoints on localhost, with relays and discovery disabled,
//! exercising the §5 metadata protocol and the §6.4 blob protocol end to end.

use std::sync::Arc;

use iroh_base::SecretKey;
use synch_core::{file_key, now_ns, ChunkRanges, FileEntry, Hash, OriginId, SignedHead};
use synch_engine::{FetchOutcome, Syncer};
use synch_mpt::Trie;
use synch_net::{Net, NetOptions};
use synch_store::{Binding, BindingSource, Slot, Store};

struct Node {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    net: Net,
    secret: SecretKey,
    origin: OriginId,
}

impl Node {
    async fn spawn(name: &str) -> Node {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let secret = SecretKey::generate();
        let origin = OriginId::named(name, "cluster.example").unwrap();
        store.set_self_origin(&origin).unwrap();
        // A node always trusts itself, so its own key is bound before anything
        // else happens.
        trust(&store, &origin, &secret.public());
        // The endpoint reconciles through a head sink, which is what carries
        // the §5.2 acceptance rule; without one it speaks the protocol but
        // adopts nothing. The node dials with the same object it serves
        // through, so a head arriving in either direction lands in one place.
        let mut options = NetOptions::loopback();
        options.heads = Some(Arc::new(Syncer::new(store.clone())) as Arc<dyn synch_net::HeadSink>);
        let net = Net::bind(store.clone(), secret.clone(), options)
            .await
            .unwrap();
        Node {
            _dir: dir,
            store,
            net,
            secret,
            origin,
        }
    }

    /// Publishes a new signed head containing `files`, as the local origin would.
    fn publish(&self, seq: u64, files: &[(&str, &[u8])]) -> SignedHead {
        let trie = Trie::new(self.store.as_ref());
        let mut root = self
            .store
            .complete_head(&self.origin)
            .unwrap()
            .map(|h| h.root)
            .unwrap_or(Hash::EMPTY);
        for (path, content) in files {
            let object = self.store.ingest_bytes(content, now_ns()).unwrap();
            let entry = FileEntry::file(content.len() as u64, 0, object, seq);
            root = trie
                .insert(
                    root,
                    &file_key("media", path).unwrap(),
                    &postcard::to_stdvec(&entry).unwrap(),
                )
                .unwrap();
            let ad = self.store.local_ad(&object).unwrap().unwrap();
            root = trie
                .insert(
                    root,
                    &synch_core::blob_key(&object),
                    &postcard::to_stdvec(&ad).unwrap(),
                )
                .unwrap();
        }
        let head = SignedHead::sign(&self.secret, self.origin.clone(), seq, root, now_ns());
        let old = self
            .store
            .complete_head(&self.origin)
            .unwrap()
            .map(|h| h.root)
            .unwrap_or(Hash::EMPTY);
        // One transaction, as every production writer of the complete slot
        // does it: the head and the views it derives commit together (§5.2).
        self.store
            .transaction(|txn| -> Result<(), synch_store::StoreError> {
                txn.put_head(Slot::Complete, &head, now_ns(), now_ns())?;
                txn.materialize_diff(&self.origin, old, root)?;
                Ok(())
            })
            .unwrap();
        head
    }
}

fn trust(store: &Store, origin: &OriginId, key: &synch_core::NodeId) {
    store
        .put_binding(&Binding {
            origin: origin.clone(),
            node_id: *key,
            source: BindingSource::Static,
            domain: None,
            issuer: None,
            spaces: Vec::new(),
            note: None,
            added_at: 0,
            expires_at: None,
        })
        .unwrap();
}

/// Makes every node in `nodes` trust every other node's origin and key.
fn trust_each_other(nodes: &[&Node]) {
    for a in nodes {
        for b in nodes {
            trust(&a.store, &b.origin, &b.secret.public());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_converge_and_content_transfers() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = Node::spawn("nas").await;
    let follower = Node::spawn("laptop").await;
    trust_each_other(&[&publisher, &follower]);

    let payload_small = b"a short file".to_vec();
    let payload_large: Vec<u8> = (0..300_000).map(|i| (i * 7 + 13) as u8).collect();
    let head = publisher.publish(
        1,
        &[
            ("notes.txt", payload_small.as_slice()),
            ("talks/keynote.mp4", payload_large.as_slice()),
        ],
    );

    // The follower dials the publisher by direct address and runs one exchange.
    let client = follower
        .net
        .connect_mpt(publisher.net.direct_addr())
        .await
        .unwrap();
    let syncer = Syncer::new(follower.store.clone());
    let report = syncer.sync_with(&client).await.unwrap();
    assert_eq!(report.heads_accepted, 1, "{report:?}");
    assert_eq!(report.tries_completed, 1, "{report:?}");

    // Heads match.
    assert_eq!(
        follower.store.complete_head(&publisher.origin).unwrap(),
        Some(head.clone())
    );

    // Entries match.
    let theirs = publisher
        .store
        .list_entries(Some(&publisher.origin), "media", "", None, None)
        .unwrap();
    let ours = follower
        .store
        .list_entries(Some(&publisher.origin), "media", "", None, None)
        .unwrap();
    assert_eq!(theirs, ours);
    assert_eq!(ours.len(), 2);

    // Provider views match: the publisher advertises both objects.
    let big_root = ours
        .iter()
        .find(|e| e.path == "talks/keynote.mp4")
        .unwrap()
        .content
        .unwrap();
    let providers = follower.store.providers(&big_root).unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].0, publisher.origin);

    // A `cat`-equivalent verified fetch returns the exact bytes.
    let blob = follower
        .net
        .connect_blob(publisher.net.direct_addr())
        .await
        .unwrap();
    let all = ChunkRanges::single(0, synch_core::group_count(payload_large.len() as u64));
    let mut got = ChunkRanges::empty();
    blob.fetch_into(
        &follower.store,
        big_root,
        payload_large.len() as u64,
        &all,
        &mut got,
    )
    .await
    .unwrap();
    assert_eq!(follower.store.read_all(&big_root).unwrap(), payload_large);

    // And a range read of an object the follower only partially holds.
    let small_root = ours
        .iter()
        .find(|e| e.path == "notes.txt")
        .unwrap()
        .content
        .unwrap();
    let one_group = ChunkRanges::single(0, 1);
    let mut got_small = ChunkRanges::empty();
    blob.fetch_into(
        &follower.store,
        small_root,
        payload_small.len() as u64,
        &one_group,
        &mut got_small,
    )
    .await
    .unwrap();
    assert_eq!(
        follower.store.read_range(&small_root, 2, 5).unwrap(),
        &payload_small[2..7]
    );

    publisher.net.shutdown().await.unwrap();
    follower.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_third_node_learns_the_trie_from_a_relayer() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    // Peer-agnostic fetch (§5.2): trie nodes are content-addressed, so a node
    // may pull them from a peer that is neither the origin nor the peer that
    // told it about the head.
    let origin_node = Node::spawn("nas").await;
    let relay = Node::spawn("vps").await;
    let laptop = Node::spawn("laptop").await;
    trust_each_other(&[&origin_node, &relay, &laptop]);

    let files: Vec<(String, Vec<u8>)> = (0..40)
        .map(|i| (format!("dir{}/file{i:03}.bin", i % 5), vec![i as u8; 64]))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_slice()))
        .collect();
    let head = origin_node.publish(1, &borrowed);

    // The relay syncs from the origin.
    let to_origin = relay
        .net
        .connect_mpt(origin_node.net.direct_addr())
        .await
        .unwrap();
    Syncer::new(relay.store.clone())
        .sync_with(&to_origin)
        .await
        .unwrap();
    assert_eq!(
        relay.store.complete_head(&origin_node.origin).unwrap(),
        Some(head.clone())
    );

    // The laptop syncs only from the relay, and still ends up byte-identical.
    let to_relay = laptop
        .net
        .connect_mpt(relay.net.direct_addr())
        .await
        .unwrap();
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

    for node in [&origin_node, &relay, &laptop] {
        node.net.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incremental_updates_transfer_only_the_change() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = Node::spawn("nas").await;
    let follower = Node::spawn("laptop").await;
    trust_each_other(&[&publisher, &follower]);

    let files: Vec<(String, Vec<u8>)> = (0..60)
        .map(|i| (format!("f{i:03}.bin"), vec![i as u8; 32]))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_slice()))
        .collect();
    publisher.publish(1, &borrowed);

    let client = follower
        .net
        .connect_mpt(publisher.net.direct_addr())
        .await
        .unwrap();
    let syncer = Syncer::new(follower.store.clone());
    syncer.sync_with(&client).await.unwrap();

    let nodes_before = count_nodes(&follower.store);

    // One file changes; the second exchange must pull only the touched path.
    let head2 = publisher.publish(2, &[("f000.bin", b"changed")]);
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

    let entry = follower
        .store
        .entry(&publisher.origin, "media", "f000.bin")
        .unwrap()
        .unwrap();
    assert_eq!(entry.size, 7);

    publisher.net.shutdown().await.unwrap();
    follower.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_peers_are_refused() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    // §3.2: connections from device keys with no live binding are closed
    // immediately after the QUIC handshake.
    let server = Node::spawn("nas").await;
    let stranger = Node::spawn("intruder").await;
    // The stranger trusts the server (so it will dial), but not vice versa.
    trust(&stranger.store, &server.origin, &server.secret.public());

    let client = stranger
        .net
        .connect_mpt(server.net.direct_addr())
        .await
        .unwrap();
    // The handshake may complete, but the server refuses to serve anything.
    let result = client
        .get_nodes(Hash::EMPTY, &[(Vec::new(), Hash::new(b"anything"))])
        .await;
    assert!(result.is_err(), "an untrusted peer must not be served");

    server.net.shutdown().await.unwrap();
    stranger.net.shutdown().await.unwrap();
}

/// A request costs a stream, not a session.
///
/// A fetch that dials for itself costs a session: a mirror pass or a large
/// `get` would open one QUIC session per file, each one a handshake here and a
/// connection left idling out over there. Requests to the same peer and ALPN
/// share one session, and only a session that is actually gone is replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_to_a_peer_share_one_session() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let client = Node::spawn("laptop").await;
    let server = Node::spawn("nas").await;
    trust_each_other(&[&client, &server]);

    let first = client
        .net
        .connect_mpt(server.net.direct_addr())
        .await
        .unwrap();
    let second = client
        .net
        .connect_mpt(server.net.direct_addr())
        .await
        .unwrap();
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
    let third = client
        .net
        .connect_mpt(server.net.direct_addr())
        .await
        .unwrap();
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
    client
        .net
        .connect_blob(server.net.direct_addr())
        .await
        .unwrap();
    let again = client
        .net
        .connect_mpt(server.net.direct_addr())
        .await
        .unwrap();
    assert_eq!(
        again.connection().stable_id(),
        third.connection().stable_id()
    );

    client.net.shutdown().await.unwrap();
    server.net.shutdown().await.unwrap();
}

/// A binding that lapses does not leave a session open behind it (§3.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lapsed_binding_drops_the_session_it_was_dialed_under() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let client = Node::spawn("laptop").await;
    let server = Node::spawn("nas").await;
    trust_each_other(&[&client, &server]);

    let held = client
        .net
        .connect_mpt(server.net.direct_addr())
        .await
        .unwrap();
    client
        .store
        .remove_binding(
            &server.origin,
            &server.secret.public(),
            synch_store::BindingSource::Static,
        )
        .unwrap();

    let refused = client.net.connect_mpt(server.net.direct_addr()).await;
    assert!(
        matches!(refused, Err(synch_net::NetError::Untrusted(_))),
        "a peer we no longer trust must not be dialed: {refused:?}"
    );
    assert!(
        held.connection().close_reason().is_some(),
        "and the session it was dialed under must not stay open"
    );

    client.net.shutdown().await.unwrap();
    server.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reactive_head_push_propagates() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = Node::spawn("nas").await;
    let follower = Node::spawn("laptop").await;
    trust_each_other(&[&publisher, &follower]);

    let head = publisher.publish(1, &[("a.txt", b"hello")]);
    // Push from the publisher to the follower, the §5.3 reactive path.
    let client = publisher
        .net
        .connect_mpt(follower.net.direct_addr())
        .await
        .unwrap();
    client.push_head(&head).await.unwrap();

    // The follower now knows about the head, but cannot serve it yet: it has
    // the head, not the trie, so the head sits in the pending slot.
    assert_eq!(
        follower.store.pending_head(&publisher.origin).unwrap(),
        Some(head.clone())
    );
    assert_eq!(
        follower.store.complete_head(&publisher.origin).unwrap(),
        None
    );

    // Pulling the trie from the publisher completes the flip.
    let back = follower
        .net
        .connect_mpt(publisher.net.direct_addr())
        .await
        .unwrap();
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

    publisher.net.shutdown().await.unwrap();
    follower.net.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unservable_head_is_abandoned_rather_than_wedging() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    // §5.2: if every candidate provider persistently returns `missing`, the
    // pending head is abandoned and head selection re-runs.
    let publisher = Node::spawn("nas").await;
    let follower = Node::spawn("laptop").await;
    trust_each_other(&[&publisher, &follower]);

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

    let client = follower
        .net
        .connect_mpt(publisher.net.direct_addr())
        .await
        .unwrap();
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
    let real = publisher.publish(10, &[("a.txt", b"hello")]);
    let report = syncer.sync_with(&client).await.unwrap();
    assert_eq!(report.tries_completed, 1, "{report:?}");
    assert_eq!(
        follower.store.complete_head(&publisher.origin).unwrap(),
        Some(real)
    );

    publisher.net.shutdown().await.unwrap();
    follower.net.shutdown().await.unwrap();
}

/// An origin that publishes a value in the wrong representation is retired by the
/// §5.2 abandonment rule, not left for the TTL sweep.
///
/// The rule is that a value small enough to be inline must *be* inline: the
/// alternative gives one key/value map two roots, which is what structural
/// sharing rests on not happening. The rule was right and its stated consequence
/// was not — it returned an error from inside the batch transaction, which rolled
/// back the legitimate values with it and propagated out of `fetch_pending`, so
/// `learned == 0` was never reached and `MAX_UNPRODUCTIVE_ROUNDS` could not fire
/// for this fault at all. The only escape was `pending_head_ttl`, thirty
/// anti-entropy intervals later, and the head held `head_floor` for all of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_value_in_the_wrong_representation_retires_its_head() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = Node::spawn("nas").await;
    let follower = Node::spawn("laptop").await;
    trust_each_other(&[&publisher, &follower]);

    // A trie the publisher can serve whole, whose one leaf points at an
    // out-of-line payload small enough that it should have been inline. Planted
    // rather than inserted: `ValueRef::for_value` makes this unrepresentable
    // through the write path, which is why the check lives at ingest.
    let small = b"short enough to be inline".to_vec();
    assert!(small.len() <= synch_core::INLINE_VALUE_MAX);
    let value_hash = Hash::new(&small);
    synch_mpt::NodeStore::put_value(publisher.store.as_ref(), &value_hash, &small).unwrap();
    let leaf = synch_mpt::TrieNode::Leaf {
        key_rest: synch_mpt::Nibbles::from_bytes(&synch_core::file_key("media", "a.txt").unwrap()),
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

    let client = follower
        .net
        .connect_mpt(publisher.net.direct_addr())
        .await
        .unwrap();
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
    assert!(
        synch_mpt::NodeStore::get_value(follower.store.as_ref(), &value_hash)
            .unwrap()
            .is_none(),
        "the value itself was never stored"
    );

    publisher.net.shutdown().await.unwrap();
    follower.net.shutdown().await.unwrap();
}

fn count_nodes(store: &Store) -> usize {
    store.trie_stats().unwrap().nodes
}

/// An object larger than one frame transfers, a window at a time (§6.4).
///
/// A bao slice is encoded into memory whole and travels in a single framed
/// message, so a fetch that asks for a whole large object would ask the
/// provider for something it can neither hold nor send: everything above
/// `MAX_FRAME_LEN` fails with a truncated stream, which is to say a store that
/// cannot replicate a video file. The requester walks the object in
/// `MAX_SLICE_GROUPS` windows, and the provider clamps to the same bound
/// whatever it is asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_object_larger_than_one_frame_transfers() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = Node::spawn("nas").await;
    let follower = Node::spawn("laptop").await;
    trust_each_other(&[&publisher, &follower]);

    let payload: Vec<u8> = (0..20u32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    publisher.publish(1, &[("big.bin", payload.as_slice())]);
    let root = publisher
        .store
        .list_entries(Some(&publisher.origin), "media", "", None, None)
        .unwrap()[0]
        .content
        .unwrap();

    let blob = follower
        .net
        .connect_blob(publisher.net.direct_addr())
        .await
        .unwrap();
    let all = ChunkRanges::single(0, synch_core::group_count(payload.len() as u64));
    let mut got = ChunkRanges::empty();
    blob.fetch_into(&follower.store, root, payload.len() as u64, &all, &mut got)
        .await
        .unwrap();
    assert_eq!(got.count(), synch_core::group_count(payload.len() as u64));
    assert_eq!(follower.store.read_all(&root).unwrap().len(), payload.len());

    publisher.net.shutdown().await.unwrap();
    follower.net.shutdown().await.unwrap();
}

/// One origin publishing a record this node cannot decode does not stop it
/// converging with the others (§5.2).
///
/// Materialization is deliberately atomic — a head whose delta will not apply
/// does not flip — but that failure must not end the whole exchange: the
/// poisoned head is durable, so a single bad record from any trusted origin
/// would stop *every* origin's metadata from reaching this node, on every sync
/// from then on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_poisoned_origin_does_not_hold_up_the_others() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let poisoned = Node::spawn("nas").await;
    let healthy = Node::spawn("vps").await;
    let follower = Node::spawn("laptop").await;
    trust_each_other(&[&poisoned, &healthy, &follower]);

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

    healthy.publish(1, &[("good.txt", b"readable")]);

    // The poisoned node picks up the healthy origin's head, so one exchange
    // carries both — `nas@…` sorts before `vps@…`, so the bad one is handled
    // first, before the good one is read.
    let to_healthy = poisoned
        .net
        .connect_mpt(healthy.net.direct_addr())
        .await
        .unwrap();
    Syncer::new(poisoned.store.clone())
        .sync_with(&to_healthy)
        .await
        .unwrap();

    let client = follower
        .net
        .connect_mpt(poisoned.net.direct_addr())
        .await
        .unwrap();
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

    for node in [&poisoned, &healthy, &follower] {
        node.net.shutdown().await.unwrap();
    }
}

/// A small edit to a large object moves the edit, not the object
/// (`docs/DELTA-SYNC.md` §1, §3.3).
///
/// The follower already holds the previous version, so the new root's tree is
/// the only thing it is missing. It asks for that tree — hashes, no payload —
/// compares it against the object it has, promotes every span that turns out to
/// be byte-identical, and fetches the one group that changed. What crosses the
/// wire is the proof plus one 16 KiB group, for an object of a megabyte; before
/// this, the same edit cost a megabyte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_small_edit_to_a_large_object_transfers_the_edit() {
    // This test's own body drives the world the way an operator would,
    // synchronously; the runtime workers the node uses stay checked (§10).
    let _blocking = synch_core::BlockingScope::enter();
    let publisher = Node::spawn("nas").await;
    let follower = Node::spawn("laptop").await;
    trust_each_other(&[&publisher, &follower]);

    const GROUP: usize = 16 * 1024;
    let old: Vec<u8> = (0..64 * GROUP).map(|i| (i * 17 + 3) as u8).collect();
    let mut new = old.clone();
    new[40 * GROUP + 77] ^= 0xff;
    let old_root = follower.store.ingest_bytes(&old, now_ns()).unwrap();
    publisher.publish(1, &[("disk.img", new.as_slice())]);
    let new_root = publisher
        .store
        .list_entries(Some(&publisher.origin), "media", "", None, None)
        .unwrap()[0]
        .content
        .unwrap();
    let size = new.len() as u64;
    let groups = synch_core::group_count(size);
    let all = ChunkRanges::single(0, groups);

    let blob = follower
        .net
        .connect_blob(publisher.net.direct_addr())
        .await
        .unwrap();

    // Round one: the tree at span granularity — here spans of 16 groups, the
    // scaled-down stand-in for the 16 MiB ad span a real object would use.
    let round_one = blob.get_proof(new_root, &all, 4).await.unwrap();
    assert_eq!(round_one.served, all);
    assert!(
        round_one.encoded.len() < GROUP,
        "a span proof of a 1 MiB object is a few hundred bytes, not {}",
        round_one.encoded.len()
    );
    let spans = follower
        .store
        .write_proof(&new_root, size, &round_one.served, 4, &round_one.encoded, 0)
        .unwrap();
    assert_eq!(spans.subtrees.len(), 4, "four spans of sixteen groups");

    // The donor agrees about every span but the one holding the edit.
    let asked: Vec<(u64, u64)> = spans.subtrees.iter().map(|s| (s.start, s.groups)).collect();
    let donor_cvs = follower.store.subtree_cvs(&old_root, &asked).unwrap();
    let equal = spans
        .subtrees
        .iter()
        .zip(&donor_cvs)
        .filter(|(span, cv)| **cv == Some(span.cv))
        .count();
    assert_eq!(equal, 3, "only the edited span differs");
    let mut promoted = follower
        .store
        .promote(&synch_store::Donor(old_root), &spans, 0)
        .unwrap();
    assert_eq!(promoted.count(), 48);

    // Round two: leaf chaining values, inside the one span that differs.
    let differing = all.difference(&promoted);
    let round_two = blob.get_proof(new_root, &differing, 0).await.unwrap();
    let leaves = follower
        .store
        .write_proof(&new_root, size, &round_two.served, 0, &round_two.encoded, 0)
        .unwrap();
    promoted = promoted.union(
        &follower
            .store
            .promote(&synch_store::Donor(old_root), &leaves, 0)
            .unwrap(),
    );
    assert_eq!(promoted.count(), groups - 1, "everything but the edit");

    // And the delta itself: one group, fetched the ordinary way.
    let missing = all.difference(&promoted);
    assert_eq!(missing, ChunkRanges::single(40, 41));
    let slice = blob.get_slice(new_root, &missing).await.unwrap();
    let payload_bytes = round_one.encoded.len() + round_two.encoded.len() + slice.encoded.len();
    assert!(
        payload_bytes < 4 * GROUP,
        "a one-group edit to a 64-group object cost {payload_bytes} bytes"
    );
    follower
        .store
        .write_slice(&new_root, size, &slice.served, &slice.encoded, 0)
        .unwrap();

    // The object is whole, verified against the root the publisher signed, and
    // servable onward: the tree came with the proofs.
    assert!(follower.store.blob(&new_root).unwrap().unwrap().complete);
    assert_eq!(follower.store.read_all(&new_root).unwrap(), new);
    let (encoded, served) = follower.store.encode_slice(&new_root, &all).unwrap();
    assert!(!encoded.is_empty() && !served.is_empty());

    publisher.net.shutdown().await.unwrap();
    follower.net.shutdown().await.unwrap();
}
