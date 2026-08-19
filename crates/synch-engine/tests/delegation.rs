//! Delegated space-restricted trust, end to end over two real endpoints
//! (§3.5, §5.5).
//!
//! The properties worth a network for: a delegate is admitted by replicated
//! state and nothing else, it sees the spaces it was delegated and no trace of
//! the others, it cannot reach content it was not delegated, and it cannot
//! publish outside its list.

use std::sync::Arc;

use iroh_base::SecretKey;
use synch_core::{
    delegation_key, file_key, now_ns, ChunkRanges, Delegation, FileEntry, Hash, NodeId, OriginId,
    SignedHead,
};
use synch_engine::Syncer;
use synch_mpt::{Scope, Trie};
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
    /// `named` spawns a rooted member; `None` spawns a key-identified node,
    /// which is the only shape a delegation may bind (§2).
    async fn spawn(named: Option<&str>) -> Node {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let secret = SecretKey::generate();
        let origin = match named {
            Some(name) => OriginId::named(name, "cluster.example").unwrap(),
            None => OriginId::Key(secret.public()),
        };
        store.set_self_origin(&origin).unwrap();
        trust_static(&store, &origin, &secret.public());
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

    fn key(&self) -> NodeId {
        self.secret.public()
    }

    fn root(&self) -> Hash {
        self.store
            .complete_head(&self.origin)
            .unwrap()
            .map(|h| h.root)
            .unwrap_or(Hash::EMPTY)
    }

    /// Publishes `files` as `(space, path, content)`, plus any extra raw
    /// records, as a new signed head.
    fn publish(
        &self,
        seq: u64,
        files: &[(&str, &str, &[u8])],
        extra: &[(Vec<u8>, Vec<u8>)],
    ) -> SignedHead {
        let trie = Trie::new(self.store.as_ref());
        let old = self.root();
        let mut root = old;
        for (space, path, content) in files {
            let object = self.store.ingest_bytes(content, now_ns()).unwrap();
            let entry = FileEntry::file(content.len() as u64, 0, object, seq);
            root = trie
                .insert(
                    root,
                    &file_key(space, path).unwrap(),
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
        for (key, value) in extra {
            root = trie.insert(root, key, value).unwrap();
        }
        let head = SignedHead::sign(&self.secret, self.origin.clone(), seq, root, now_ns());
        self.store
            .put_head(Slot::Complete, &head, now_ns(), now_ns())
            .unwrap();
        self.store
            .transaction(|txn| txn.materialize_diff(&self.origin, old, root))
            .unwrap();
        synch_mpt::NodeStore::note_complete(self.store.as_ref(), &root).unwrap();
        head
    }
}

fn trust_static(store: &Store, origin: &OriginId, key: &NodeId) {
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

/// The `d:` record an issuer publishes to delegate `subject` (§3.5).
fn delegation(subject: &NodeId, spaces: &[&str]) -> (Vec<u8>, Vec<u8>) {
    let record = Delegation {
        v: synch_core::RECORD_VERSION,
        spaces: spaces.iter().map(|s| s.to_string()).collect(),
        not_after: now_ns() + 86_400_000_000_000,
        note: Some("test delegate".into()),
    };
    (
        delegation_key(subject),
        postcard::to_stdvec(&record).unwrap(),
    )
}

/// A delegate is admitted by replicated state, and sees exactly its spaces.
///
/// Nothing is handed to the delegate and nothing is presented by it: the
/// issuer publishes a record, the record reaches the member, and the member
/// admits the key. What the delegate then reads is the projection of the
/// issuer's trie its grant covers — and of the rest, not a filename.
#[tokio::test]
async fn a_delegate_is_admitted_by_replicated_state_and_sees_only_its_spaces() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;

    // The delegate trusts the cluster by the ordinary route; the cluster comes
    // to trust the delegate through the record below. Trust is unilateral, so
    // the two directions are solved separately.
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    // Before the record exists the delegate's key is unknown, and the issuer
    // refuses it — which is the correct answer, not a bug.
    assert!(!issuer
        .store
        .is_trusted_key(&delegate.key(), now_ns())
        .unwrap());

    issuer.publish(
        1,
        &[
            ("photos", "a.jpg", b"the granted bytes"),
            ("finance", "q3.pdf", b"the withheld bytes"),
        ],
        &[delegation(&delegate.key(), &["photos"])],
    );

    // Materializing the issuer's own head admitted the delegate, with the
    // scope the record named.
    assert!(issuer
        .store
        .is_trusted_key(&delegate.key(), now_ns())
        .unwrap());
    assert_eq!(
        issuer
            .store
            .publish_scope_of_key(&delegate.key(), now_ns())
            .unwrap(),
        Some(vec!["photos".to_string()])
    );

    // The delegate syncs. It learns its scope from the exchange, walks under
    // it, and promotes.
    let syncer = Syncer::new(delegate.store.clone());
    let client = delegate
        .net
        .connect_mpt(issuer.net.direct_addr())
        .await
        .unwrap();
    syncer.sync_with(&client).await.unwrap();
    assert_eq!(
        delegate.store.local_scope().unwrap(),
        Some(vec!["photos".to_string()]),
        "the delegate did not learn its scope from the exchange"
    );

    let head = delegate
        .store
        .complete_head(&issuer.origin)
        .unwrap()
        .expect("the delegate promoted the issuer's head");
    assert_eq!(head.root, issuer.root(), "same signed root, partial trie");

    // The granted space is fully readable, verified against that same root.
    let trie = Trie::new(delegate.store.as_ref());
    assert!(trie
        .get(head.root, &file_key("photos", "a.jpg").unwrap())
        .unwrap()
        .is_some());

    // And of the undelegated space: nothing. Not the entry, not the path, not
    // the node that would name it — reading it fails for want of the subtree
    // rather than returning an absence.
    assert!(trie
        .get(head.root, &file_key("finance", "q3.pdf").unwrap())
        .is_err());
    assert!(delegate
        .store
        .list_entries(Some(&issuer.origin), "finance", "", None, None)
        .unwrap()
        .is_empty());
    // The scope check agrees with what actually landed.
    let scope = Scope::of(&synch_core::scope_prefixes(&["photos".to_string()]));
    assert!(trie.is_complete_scoped(head.root, &scope).unwrap());
    assert!(!trie.is_complete(head.root).unwrap());
}

/// A delegate may not reach content outside its spaces, even holding the root.
///
/// `GetSlice` is keyed by object root and carries no space, so this is the one
/// place entitlement has to be looked up rather than read off the request.
#[tokio::test]
async fn content_outside_the_delegated_spaces_is_refused() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    let granted = b"the granted bytes".to_vec();
    let withheld = b"the withheld bytes".to_vec();
    issuer.publish(
        1,
        &[
            ("photos", "a.jpg", granted.as_slice()),
            ("finance", "q3.pdf", withheld.as_slice()),
        ],
        &[delegation(&delegate.key(), &["photos"])],
    );

    let granted_root = Hash::new(&granted);
    let withheld_root = Hash::new(&withheld);
    let blob = delegate
        .net
        .connect_blob(issuer.net.direct_addr())
        .await
        .unwrap();

    // The granted object transfers.
    let slice = blob
        .get_slice(granted_root, &ChunkRanges::single(0, 1))
        .await
        .unwrap();
    assert!(
        !slice.encoded.is_empty(),
        "the granted object did not serve"
    );

    // The withheld one is refused outright — the delegate knows the hash here
    // only because the test handed it over, which is the strongest form of the
    // question: even a peer that has the root by some other means is refused.
    let refused = blob
        .get_slice(withheld_root, &ChunkRanges::single(0, 1))
        .await;
    assert!(
        refused.is_err(),
        "a delegate was served content outside its spaces"
    );
}

/// A delegated origin publishing outside its spaces has its head refused whole
/// (§3.5).
#[tokio::test]
async fn a_delegate_publishing_outside_its_spaces_is_refused() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    // The delegation is the only thing admitting the delegate: statically
    // trusting it here would make it rooted, and a rooted origin publishes
    // whatever it likes.
    issuer.publish(1, &[], &[delegation(&delegate.key(), &["photos"])]);
    assert_eq!(
        issuer
            .store
            .publish_scope(&delegate.origin, now_ns())
            .unwrap(),
        synch_store::PublishScope::Confined(vec!["photos".to_string()])
    );

    // In scope: the issuer accepts it.
    delegate.publish(1, &[("photos", "mine.jpg", b"in scope")], &[]);
    let syncer = Syncer::new(issuer.store.clone());
    let client = issuer
        .net
        .connect_mpt(delegate.net.direct_addr())
        .await
        .unwrap();
    syncer.sync_with(&client).await.unwrap();
    assert_eq!(
        issuer
            .store
            .complete_head(&delegate.origin)
            .unwrap()
            .map(|h| h.seq),
        Some(1)
    );

    // Out of scope: the head is refused whole rather than materialized in
    // part, so the delegate's origin stalls at the head that was legitimate
    // and no other origin is touched.
    delegate.publish(2, &[("finance", "sneaky.pdf", b"out of scope")], &[]);
    syncer.sync_with(&client).await.unwrap();
    assert_eq!(
        issuer
            .store
            .complete_head(&delegate.origin)
            .unwrap()
            .map(|h| h.seq),
        Some(1),
        "a delegate published outside its spaces and the head was promoted"
    );
    assert!(issuer
        .store
        .list_entries(Some(&delegate.origin), "finance", "", None, None)
        .unwrap()
        .is_empty());
}

/// A scoped peer cannot reach a redacted node by claiming a position for it.
///
/// The sharpest form of the question. A delegate necessarily *holds* the hash
/// of every subtree withheld from it — the hash is inside the branch node that
/// makes the signed root recompute — so the only thing between it and the
/// bytes is that the position it must name is out of scope. This asks for a
/// withheld hash under an in-scope position that resolves to nothing, and
/// against a root of the caller's own choosing: the two shapes that get past a
/// naive position check.
#[tokio::test]
async fn a_withheld_node_cannot_be_reached_by_claiming_a_position_for_it() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    issuer.publish(
        1,
        &[
            ("photos", "a.jpg", b"granted"),
            ("finance", "q3.pdf", b"withheld"),
            ("finance", "q4.pdf", b"withheld too"),
        ],
        &[delegation(&delegate.key(), &["photos"])],
    );
    let root = issuer.root();

    // Every node of the issuer's trie by position, from an unscoped walk of
    // its own store — what a full member legitimately sees.
    let empty = synch_mpt::MemStore::new();
    let mut walk = synch_mpt::MissingWalk::new(root);
    let mut all: Vec<(Vec<u8>, Hash)> = Vec::new();
    loop {
        let batch = walk.next_batch(&Trie::new(&empty), 512).unwrap();
        if batch.is_empty() {
            break;
        }
        for (path, hash) in &batch.nodes {
            all.push((path.clone(), *hash));
            let bytes = synch_mpt::NodeStore::get_node(issuer.store.as_ref(), hash)
                .unwrap()
                .unwrap();
            synch_mpt::NodeStore::put_node(&empty, hash, &bytes).unwrap();
        }
        walk.resume();
    }

    let scope = Scope::of(&synch_core::scope_prefixes(&["photos".to_string()]));
    let withheld: Vec<Hash> = all
        .iter()
        .filter(|(path, _)| !scope.admits_path(path))
        .map(|(_, hash)| *hash)
        .collect();
    assert!(
        !withheld.is_empty(),
        "nothing was withheld; test is vacuous"
    );

    // An in-scope position that resolves to nothing.
    let mut bogus = synch_mpt::Nibbles::from_bytes(b"f:photos/")
        .as_slice()
        .to_vec();
    bogus.extend_from_slice(&[0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf]);
    assert!(
        scope.admits_path(&bogus),
        "the position must pass the scope test"
    );

    let client = delegate
        .net
        .connect_mpt(issuer.net.direct_addr())
        .await
        .unwrap();
    for hash in &withheld {
        let answer = client
            .get_nodes(root, &[(bogus.clone(), *hash)])
            .await
            .expect("the request itself is well formed");
        assert!(
            answer.nodes.is_empty(),
            "a withheld node was served for a position that does not hold it"
        );
        assert_eq!(answer.missing, vec![*hash]);

        // And the same hash named against a root of the caller's choosing:
        // the empty path resolves to whatever root it was handed, so a root
        // this node holds no head for has to be refused outright.
        let refused = client.get_nodes(*hash, &[(Vec::new(), *hash)]).await;
        assert!(
            refused.is_err(),
            "a fabricated root let a withheld node be named"
        );
    }
}

/// A delegate cannot lay out the trie its own positions are judged against.
///
/// The position check is only worth anything relative to a trie this node
/// vouches for — but a delegate publishes a trie, and its root lands in
/// `head_history` as soon as the signature and the delegated binding verify.
/// Given one of its own roots, it can put any node hash it has heard of under
/// an in-scope position and be handed the node back, which walks every
/// withheld subtree one level per published head.
#[tokio::test]
async fn a_delegate_cannot_authorize_a_position_with_its_own_root() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    // Only the delegate trusts the issuer statically. The issuer learns the
    // delegate from its own published `d:` record — a static binding here
    // would make it a rooted member and skip the scope checks entirely.
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    issuer.publish(
        1,
        &[
            ("photos", "a.jpg", b"granted"),
            ("finance", "q3.pdf", b"withheld"),
        ],
        &[delegation(&delegate.key(), &["photos"])],
    );

    // A node of the issuer's trie the delegate is not entitled to. It knows
    // this hash honestly: it sits inside a branch the delegate must hold for
    // the signed root to recompute.
    let scope = Scope::of(&synch_core::scope_prefixes(&["photos".to_string()]));
    let withheld = {
        let empty = synch_mpt::MemStore::new();
        let mut walk = synch_mpt::MissingWalk::new(issuer.root());
        let mut found = None;
        loop {
            let batch = walk.next_batch(&Trie::new(&empty), 512).unwrap();
            if batch.is_empty() {
                break;
            }
            for (path, hash) in &batch.nodes {
                if !scope.admits_path(path) && found.is_none() {
                    found = Some(*hash);
                }
                let bytes = synch_mpt::NodeStore::get_node(issuer.store.as_ref(), hash)
                    .unwrap()
                    .unwrap();
                synch_mpt::NodeStore::put_node(&empty, hash, &bytes).unwrap();
            }
            walk.resume();
        }
        found.expect("the issuer withholds something; test is vacuous")
    };

    // The delegate signs a root of its own — an entirely in-scope key, so the
    // publish itself is legitimate — and the issuer records it.
    let mine = delegate.publish(1, &[("photos", "mine.jpg", b"my own bytes")], &[]);
    issuer
        .store
        .put_head(Slot::Complete, &mine, now_ns(), now_ns())
        .unwrap();
    assert!(
        issuer.store.is_head_root(&mine.root, &[]).unwrap(),
        "the issuer really did record the delegate's root"
    );

    // Asked against that root, an in-scope position must not authorize
    // anything: the trie it names is the asker's own.
    let client = delegate
        .net
        .connect_mpt(issuer.net.direct_addr())
        .await
        .unwrap();
    let refused = client
        .get_nodes(
            mine.root,
            &[(
                synch_mpt::Nibbles::from_bytes(b"f:photos/")
                    .as_slice()
                    .to_vec(),
                withheld,
            )],
        )
        .await;
    assert!(
        refused.is_err(),
        "a delegate's own root authorized a position in someone else's trie"
    );
}

/// A delegate cannot grant itself title to content by naming it.
///
/// `GetSlice` carries no space, so entitlement is looked up by asking which
/// spaces name the object — and nothing checks that a published entry's
/// content root is one its publisher holds or could hold. A delegate that has
/// heard a withheld object's hash could otherwise publish an entirely in-scope
/// entry naming it and read that row back as its own authorization.
#[tokio::test]
async fn a_delegate_cannot_name_withheld_content_into_its_own_scope() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    // Only the delegate trusts the issuer statically. The issuer learns the
    // delegate from its own published `d:` record — a static binding here
    // would make it a rooted member and skip the scope checks entirely.
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    let withheld = b"the withheld bytes".to_vec();
    issuer.publish(
        1,
        &[
            ("photos", "a.jpg", b"granted"),
            ("finance", "q3.pdf", withheld.as_slice()),
        ],
        &[delegation(&delegate.key(), &["photos"])],
    );
    let withheld_root = Hash::new(&withheld);

    // The delegate publishes an in-scope path naming the withheld object.
    // This is what the issuer's store holds once it materializes that head.
    issuer
        .store
        .put_entry(
            &delegate.origin,
            "photos",
            "decoy.bin",
            &FileEntry::file(withheld.len() as u64, 0, withheld_root, 1),
        )
        .unwrap();

    let blob = delegate
        .net
        .connect_blob(issuer.net.direct_addr())
        .await
        .unwrap();
    let refused = blob
        .get_slice(withheld_root, &ChunkRanges::single(0, 1))
        .await;
    assert!(
        refused.is_err(),
        "a delegate's own entry granted it content outside its spaces"
    );

    // And the issuer's own grant still works, so the refusal above is about
    // who published the row and not about the lookup being broken.
    let granted = blob
        .get_slice(Hash::new(b"granted"), &ChunkRanges::single(0, 1))
        .await
        .unwrap();
    assert!(
        !granted.encoded.is_empty(),
        "the granted object stopped serving"
    );
}

/// A delegate is never shown a node whose key material runs out of its scope.
///
/// The trie compresses, so a node at a position the spine legitimately admits
/// can still spell an undelegated space's name in its extension prefix, or
/// complete a whole out-of-scope key in its leaf. Both are refused as a
/// boundary — not as an absence, or the walk would retry until its head was
/// abandoned.
#[tokio::test]
async fn a_compressed_node_spanning_out_of_scope_is_a_boundary_not_an_absence() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    // The issuer holds no `photos` at all, so every spine node below `f:`
    // compresses toward a space the delegate was never granted.
    issuer.publish(
        1,
        &[("finance", "q3.pdf", b"withheld")],
        &[delegation(&delegate.key(), &["photos"])],
    );

    let syncer = Syncer::new(delegate.store.clone());
    let client = delegate
        .net
        .connect_mpt(issuer.net.direct_addr())
        .await
        .unwrap();
    syncer.sync_with(&client).await.unwrap();

    // The delegate converged rather than wedging, and holds nothing of the
    // space it was not granted — not even the name.
    let head = delegate
        .store
        .complete_head(&issuer.origin)
        .unwrap()
        .expect("the delegate promoted the issuer's head");
    assert_eq!(head.root, issuer.root());
    assert!(delegate
        .store
        .list_entries(Some(&issuer.origin), "finance", "", None, None)
        .unwrap()
        .is_empty());
    // A second pass is a no-op: the boundary was remembered, not re-asked.
    syncer.sync_with(&client).await.unwrap();
    assert!(delegate
        .store
        .pending_head(&issuer.origin)
        .unwrap()
        .is_none());
}

/// A delegate's own delegation records are read by nobody (§3.5).
///
/// The one-level rule, seen from the reader's side, which is the side that
/// matters: the delegate is free to publish whatever it likes, and no node
/// materializes it, because the origin that published it holds no rooted
/// binding there.
#[tokio::test]
async fn a_delegates_own_delegations_are_honored_by_nobody() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    let third = SecretKey::generate().public();
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    issuer.publish(1, &[], &[delegation(&delegate.key(), &["photos"])]);
    assert!(issuer
        .store
        .is_trusted_key(&delegate.key(), now_ns())
        .unwrap());

    // The delegate publishes a delegation of its own, naming a third key.
    delegate.publish(1, &[], &[delegation(&third, &["photos"])]);
    let syncer = Syncer::new(issuer.store.clone());
    let client = issuer
        .net
        .connect_mpt(delegate.net.direct_addr())
        .await
        .unwrap();
    syncer.sync_with(&client).await.unwrap();

    // Two independent reasons it comes to nothing, and the head never lands:
    // `d:` is outside a delegate's publish scope, so the head is refused (§3.5).
    assert_eq!(
        issuer
            .store
            .complete_head(&delegate.origin)
            .unwrap()
            .map(|h| h.seq),
        None,
        "a delegate's head carrying a d: record was promoted"
    );
    // And the third key is admitted by nobody.
    assert!(!issuer.store.is_trusted_key(&third, now_ns()).unwrap());
}

/// Withdrawing a delegation is deleting a trie key, and it propagates as any
/// deletion does (§6).
#[tokio::test]
async fn revocation_is_deletion_and_cuts_the_delegate_off() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    issuer.publish(
        1,
        &[("photos", "a.jpg", b"bytes")],
        &[delegation(&delegate.key(), &["photos"])],
    );
    assert!(issuer
        .store
        .is_trusted_key(&delegate.key(), now_ns())
        .unwrap());

    // Remove the key from the trie and publish. No revocation state, no
    // tombstone: the key is simply gone from the new root.
    let trie = Trie::new(issuer.store.as_ref());
    let old = issuer.root();
    let root = trie.remove(old, &delegation_key(&delegate.key())).unwrap();
    let head = SignedHead::sign(&issuer.secret, issuer.origin.clone(), 2, root, now_ns());
    issuer
        .store
        .put_head(Slot::Complete, &head, now_ns(), now_ns())
        .unwrap();
    issuer
        .store
        .transaction(|txn| txn.materialize_diff(&issuer.origin, old, root))
        .unwrap();

    assert!(
        !issuer
            .store
            .is_trusted_key(&delegate.key(), now_ns())
            .unwrap(),
        "the delegation outlived its record"
    );
    assert!(issuer.store.delegations(now_ns()).unwrap().is_empty());
}
