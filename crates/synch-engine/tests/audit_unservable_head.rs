//! `heads_for` answers a `HeadsWant` out of the complete *slot*, which is not
//! the same question as "can I serve the trie under it".
//!
//! `Syncer::heads_for` documents itself as handing over "only heads this node
//! can back with a servable trie: what a peer does with one is fetch the trie
//! under it from us." A delegate's complete slot holds every foreign origin's
//! head over a *partial* trie, and `local_summaries` says so in the same
//! exchange (`complete: false`). The two disagree, and the puller believes the
//! head rather than the summary: `sync_with`'s adoption loop calls
//! `fetch_pending` against whichever peer handed the head over, without the
//! `summary.complete` guard its own pending-slot pass applies a few lines
//! later.
//!
//! Fails on purpose; `#[ignore]`d so the suite stays green. Run with:
//!
//! ```text
//! cargo test -p synch-engine --test audit_unservable_head -- --ignored --nocapture
//! ```

use std::sync::Arc;

use iroh_base::SecretKey;
use synch_core::{delegation_key, file_key, now_ns, Delegation, FileEntry, Hash, NodeId, OriginId};
use synch_engine::Syncer;
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

    fn publish(&self, seq: u64, files: &[(&str, &str, &[u8])], extra: &[(Vec<u8>, Vec<u8>)]) {
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
        let head =
            synch_core::SignedHead::sign(&self.secret, self.origin.clone(), seq, root, now_ns());
        self.store
            .put_head(Slot::Complete, &head, now_ns(), now_ns())
            .unwrap();
        self.store
            .transaction(|txn| txn.materialize_diff(&self.origin, old, root))
            .unwrap();
        synch_mpt::NodeStore::note_complete(self.store.as_ref(), &root).unwrap();
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

fn delegation(subject: &NodeId, spaces: &[&str]) -> (Vec<u8>, Vec<u8>) {
    let record = Delegation {
        v: synch_core::RECORD_VERSION,
        spaces: spaces.iter().map(|s| s.to_string()).collect(),
        not_after: now_ns() + 86_400_000_000_000,
        note: Some("audit delegate".into()),
    };
    (
        delegation_key(subject),
        postcard::to_stdvec(&record).unwrap(),
    )
}

/// A delegate holds a foreign origin's head in its complete slot over a trie
/// it holds only the granted part of, and advertises `complete: false` to say
/// so. It hands the head over on `HeadsWant` anyway, so a member pulling from
/// it adopts a head nobody in the exchange can serve, spends
/// `MAX_UNPRODUCTIVE_ROUNDS` of `GetNodes` discovering that, and abandons it —
/// every round it happens to pick the delegate, for every foreign origin the
/// delegate carries.
#[tokio::test]
#[ignore = "reproduces AUDIT F2: a peer hands over a head it advertised as unservable"]
async fn a_member_pulling_from_a_delegate_is_handed_a_head_the_delegate_cannot_serve() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    let member = Node::spawn(Some("laptop")).await;

    trust_static(&delegate.store, &issuer.origin, &issuer.key());
    // The member trusts both the issuer and the delegate, and the delegate
    // trusts the member: an ordinary rooted pair.
    trust_static(&member.store, &issuer.origin, &issuer.key());
    trust_static(&member.store, &delegate.origin, &delegate.key());
    trust_static(&delegate.store, &member.origin, &member.key());

    issuer.publish(
        1,
        &[
            ("photos", "a.jpg", b"granted"),
            ("finance", "q3.pdf", b"withheld"),
        ],
        &[delegation(&delegate.key(), &["photos"])],
    );

    // The delegate syncs and promotes the issuer's head over a partial trie.
    let delegate_syncer = Syncer::new(delegate.store.clone());
    let to_issuer = delegate
        .net
        .connect_mpt(issuer.net.direct_addr())
        .await
        .unwrap();
    delegate_syncer.sync_with(&to_issuer).await.unwrap();
    assert_eq!(
        delegate
            .store
            .complete_head(&issuer.origin)
            .unwrap()
            .expect("the delegate promoted the head")
            .root,
        issuer.root()
    );

    // What the delegate says about that head, and what it hands over, disagree.
    let summaries = delegate_syncer.local_summaries().unwrap();
    let advertised = summaries
        .iter()
        .find(|s| s.origin == issuer.origin)
        .expect("the delegate advertises the origin");
    let served = delegate_syncer
        .heads_for(std::slice::from_ref(&issuer.origin))
        .unwrap();
    println!(
        "delegate advertises complete = {}, hands over {} head(s)",
        advertised.complete,
        served.len()
    );

    // And the member pulling from it pays for the disagreement.
    let member_syncer = Syncer::new(member.store.clone());
    let to_delegate = member
        .net
        .connect_mpt(delegate.net.direct_addr())
        .await
        .unwrap();
    let report = member_syncer.sync_with(&to_delegate).await.unwrap();
    println!("member pulling from the delegate: {report:?}");

    assert!(
        !advertised.complete && served.is_empty(),
        "what a node advertises and what it serves must agree"
    );
    assert_eq!(
        report.heads_abandoned, 0,
        "a peer that cannot serve a trie must not hand out its head"
    );
}
