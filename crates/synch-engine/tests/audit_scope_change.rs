//! A change to this node's read scope (§5.5) is applied to every *future*
//! walk and to nothing that has already been promoted.
//!
//! `local_scope` is one node-wide value, adopted from whichever peer spoke
//! last (`Syncer::adopt_scope`), and it decides three things at once: what
//! `MissingWalk` asks for, what `is_complete_scoped` counts as whole, and what
//! `materialize_diff` walks. Nothing re-derives the first two for a head that
//! is already in the complete slot, so a scope that moves leaves the trie
//! under that head permanently short of the new scope — and the next
//! promotion's diff either prunes over the gap (silently) or falls into it
//! (permanently).
//!
//! Every test here **fails on purpose**; they are `#[ignore]`d so the suite
//! stays green, and are meant to be read as the specification the fix has to
//! satisfy. Run them with:
//!
//! ```text
//! cargo test -p synch-engine --test audit_scope_change -- --ignored --nocapture
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
    /// `named` spawns a rooted member; `None` spawns a key-identified node,
    /// which is the only shape a delegation may bind (§3.5).
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

    /// Publishes `files` as `(space, path, content)` plus any raw records, as
    /// one signed head — the same shape `tests/delegation.rs` publishes in.
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

    fn entries(&self, origin: &OriginId, space: &str) -> usize {
        self.store
            .list_entries(Some(origin), space, "", None, None)
            .unwrap()
            .len()
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
        note: Some("audit delegate".into()),
    };
    (
        delegation_key(subject),
        postcard::to_stdvec(&record).unwrap(),
    )
}

/// Runs `rounds` exchanges, printing each report, so a failure shows whether
/// the origin is stuck or merely slow.
async fn rounds(syncer: &Syncer, client: &synch_net::MptClient, label: &str, rounds: usize) {
    for round in 0..rounds {
        match syncer.sync_with(client).await {
            Ok(report) => println!("{label} round {round}: {report:?}"),
            Err(e) => println!("{label} round {round}: ERROR {e}"),
        }
    }
}

/// **F1a — a widened grant leaves the space it just gained unmaterialized.**
///
/// The newly granted space is untouched by the head that carries the wider
/// grant, which is the ordinary case: an operator widens a delegation and the
/// space that was just opened up has not changed. The delegate fetches the new
/// root under the wider scope, so the record *is* in its trie — but the
/// promotion diff prunes at the shared node hash, and `entries` never learns
/// about it. Nothing reports a problem. `doctor --rebuild` is the only repair.
#[tokio::test]
#[ignore = "reproduces AUDIT F1a: a widened read scope never re-materializes what it gained"]
async fn a_widened_delegation_materializes_the_space_it_just_gained() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    issuer.publish(
        1,
        &[
            ("photos", "a.jpg", b"the granted bytes"),
            ("finance", "q3.pdf", b"the withheld bytes"),
        ],
        &[delegation(&delegate.key(), &["photos"])],
    );

    let syncer = Syncer::new(delegate.store.clone());
    let client = delegate
        .net
        .connect_mpt(issuer.net.direct_addr())
        .await
        .unwrap();
    syncer.sync_with(&client).await.unwrap();
    assert_eq!(
        delegate.store.local_scope().unwrap(),
        Some(vec!["photos".to_string()])
    );

    // The grant widens. `finance` is untouched by this head.
    issuer.publish(
        2,
        &[("photos", "b.jpg", b"another granted file")],
        &[delegation(&delegate.key(), &["photos", "finance"])],
    );
    rounds(&syncer, &client, "widen", 3).await;

    assert_eq!(
        delegate.store.local_scope().unwrap(),
        Some(vec!["finance".to_string(), "photos".to_string()]),
        "the delegate learned the wider grant"
    );
    let head = delegate
        .store
        .complete_head(&issuer.origin)
        .unwrap()
        .unwrap();
    assert_eq!(head.seq, 2, "and promoted the head that carried it");

    // The trie really does hold the newly granted record...
    let in_trie = Trie::new(delegate.store.as_ref())
        .get(head.root, &file_key("finance", "q3.pdf").unwrap())
        .unwrap();
    assert!(in_trie.is_some(), "the record reached the trie");

    // ...but the derived view — what the unified tree, mirrors and the S3
    // gateway read — is short, and nothing says so. Read before the repair
    // below, which is what makes this a materialization bug and not a fetch
    // one: `doctor --rebuild` puts the record in `entries`, and nothing in the
    // protocol ever runs it.
    let (photos, finance) = (
        delegate.entries(&issuer.origin, "photos"),
        delegate.entries(&issuer.origin, "finance"),
    );
    let rebuilt = delegate
        .store
        .rematerialize(&issuer.origin, head.root)
        .expect("a cold rebuild succeeds");
    println!(
        "before rebuild: photos {photos}, finance {finance}; \
         rebuild applied {rebuilt} changes, leaving finance {}",
        delegate.entries(&issuer.origin, "finance")
    );

    assert_eq!(photos, 2, "both granted photos are materialized");
    assert_eq!(
        finance, 1,
        "the newly granted space must be materialized without an operator"
    );
}

/// **F1b — a widened grant whose new space *changed* wedges the origin.**
///
/// Here the promotion diff descends into the newly granted subtree instead of
/// pruning over it, and the *old* root has no node there — it was never
/// fetched under the narrow scope. `MptError::MissingNode` is classified as an
/// origin fault, so the head is retired and put in the refusal memo, and the
/// origin is left behind on every round from then on. `doctor --rebuild`
/// cannot repair it either: the trie under the stuck complete head is itself
/// short of the new scope.
#[tokio::test]
#[ignore = "reproduces AUDIT F1b: a widened read scope wedges the origin permanently"]
async fn a_widened_delegation_with_a_changed_space_still_promotes() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    issuer.publish(
        1,
        &[
            ("photos", "a.jpg", b"the granted bytes"),
            ("finance", "q3.pdf", b"the withheld bytes"),
        ],
        &[delegation(&delegate.key(), &["photos"])],
    );

    let syncer = Syncer::new(delegate.store.clone());
    let client = delegate
        .net
        .connect_mpt(issuer.net.direct_addr())
        .await
        .unwrap();
    syncer.sync_with(&client).await.unwrap();

    issuer.publish(
        2,
        &[("finance", "q4.pdf", b"a new finance file")],
        &[delegation(&delegate.key(), &["photos", "finance"])],
    );
    rounds(&syncer, &client, "widen", 3).await;

    let head = delegate.store.complete_head(&issuer.origin).unwrap();
    if let Some(h) = &head {
        let repair = delegate
            .store
            .rematerialize(&issuer.origin, h.root)
            .map(|n| n.to_string())
            .unwrap_or_else(|e| format!("ERROR {e}"));
        println!("doctor --rebuild at the stuck head: {repair}");
    }
    assert_eq!(head.map(|h| h.seq), Some(2), "the head must promote");
    assert_eq!(
        delegate.entries(&issuer.origin, "finance"),
        2,
        "both finance records must materialize"
    );
}

/// **F1c — promoting a delegate to a full member wedges the origin.**
///
/// The same mechanism as F1b, reached by the most ordinary operation there is:
/// the issuer adds a rooted binding for the delegate's key, so its `Hello`
/// declares no scope at all and the delegate widens to the whole keyspace.
#[tokio::test]
#[ignore = "reproduces AUDIT F1c: promoting a delegate to a member wedges the origin"]
async fn a_delegate_promoted_to_a_full_member_replicates_everything() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    issuer.publish(
        1,
        &[
            ("photos", "a.jpg", b"the granted bytes"),
            ("finance", "q3.pdf", b"the withheld bytes"),
        ],
        &[delegation(&delegate.key(), &["photos"])],
    );

    let syncer = Syncer::new(delegate.store.clone());
    let client = delegate
        .net
        .connect_mpt(issuer.net.direct_addr())
        .await
        .unwrap();
    syncer.sync_with(&client).await.unwrap();
    assert_eq!(
        delegate.store.local_scope().unwrap(),
        Some(vec!["photos".to_string()])
    );

    // The operator promotes the delegate: a rooted binding for its key.
    trust_static(&issuer.store, &delegate.origin, &delegate.key());
    assert_eq!(
        issuer
            .store
            .publish_scope_of_key(&delegate.key(), now_ns())
            .unwrap(),
        synch_store::PublishScope::Unrestricted
    );
    issuer.publish(2, &[("photos", "b.jpg", b"another file")], &[]);
    rounds(&syncer, &client, "promote", 3).await;

    assert_eq!(
        delegate.store.local_scope().unwrap(),
        None,
        "the delegate is a full member now"
    );
    assert_eq!(
        delegate.entries(&issuer.origin, "finance"),
        1,
        "a full member replicates every space"
    );
}

/// **F1d — a narrowed grant leaves the revoked space in the derived views.**
///
/// The mirror image of F1a: nothing re-derives `entries` for a scope that
/// shrank, so the delegate goes on listing and serving the space it lost.
#[tokio::test]
#[ignore = "reproduces AUDIT F1d: a narrowed read scope leaves stale rows behind"]
async fn a_narrowed_delegation_drops_what_it_no_longer_covers() {
    let issuer = Node::spawn(Some("nas")).await;
    let delegate = Node::spawn(None).await;
    trust_static(&delegate.store, &issuer.origin, &issuer.key());

    issuer.publish(
        1,
        &[("photos", "a.jpg", b"one"), ("finance", "q3.pdf", b"two")],
        &[delegation(&delegate.key(), &["photos", "finance"])],
    );

    let syncer = Syncer::new(delegate.store.clone());
    let client = delegate
        .net
        .connect_mpt(issuer.net.direct_addr())
        .await
        .unwrap();
    syncer.sync_with(&client).await.unwrap();
    assert_eq!(delegate.entries(&issuer.origin, "finance"), 1);

    issuer.publish(
        2,
        &[("photos", "b.jpg", b"three")],
        &[delegation(&delegate.key(), &["photos"])],
    );
    rounds(&syncer, &client, "narrow", 3).await;

    assert_eq!(
        delegate.store.local_scope().unwrap(),
        Some(vec!["photos".to_string()])
    );
    assert_eq!(
        delegate.entries(&issuer.origin, "finance"),
        0,
        "the revoked space must leave the derived views"
    );
}

/// **F1e — the scope oscillates with no operator action at all.**
///
/// A node that is a full member of one origin and a delegate of another
/// adopts a *node-wide* read scope from whichever peer it spoke to last, so
/// ordinary anti-entropy alternates it between the grant and the whole
/// keyspace, once per round.
#[tokio::test]
#[ignore = "reproduces AUDIT F1e: the read scope depends on which peer spoke last"]
async fn a_node_that_is_both_a_member_and_a_delegate_flaps_its_scope() {
    let work = Node::spawn(Some("work")).await;
    let home = Node::spawn(Some("home")).await;
    let laptop = Node::spawn(None).await;

    trust_static(&laptop.store, &work.origin, &work.key());
    trust_static(&laptop.store, &home.origin, &home.key());
    trust_static(&home.store, &laptop.origin, &laptop.key());

    work.publish(
        1,
        &[
            ("reports", "q3.pdf", b"delegated"),
            ("secrets", "keys.txt", b"withheld"),
        ],
        &[delegation(&laptop.key(), &["reports"])],
    );
    home.publish(1, &[("family", "a.jpg", b"pictures")], &[]);

    let syncer = Syncer::new(laptop.store.clone());
    let to_work = laptop
        .net
        .connect_mpt(work.net.direct_addr())
        .await
        .unwrap();
    let to_home = laptop
        .net
        .connect_mpt(home.net.direct_addr())
        .await
        .unwrap();

    let mut seen = Vec::new();
    for round in 0..4 {
        let (peer, label) = match round % 2 {
            0 => (&to_work, "work"),
            _ => (&to_home, "home"),
        };
        rounds(&syncer, peer, label, 1).await;
        let scope = laptop.store.local_scope().unwrap();
        println!("  scope now {scope:?}");
        seen.push(scope);
    }
    let distinct: std::collections::HashSet<_> = seen.iter().collect();
    assert_eq!(
        distinct.len(),
        1,
        "the read scope must not depend on which peer spoke last: {seen:?}"
    );
}

/// **F1f — the flap of F1e turns into the wedge of F1b, unattended.**
///
/// The laptop is a delegate of `work` and a full member of `home`, and `home`
/// also replicates `work` — an ordinary mixed cluster. One anti-entropy round
/// that happens to pick `home` promotes `work`'s head under the wider scope,
/// and the origin is left behind from then on. Returning to `work` does not
/// repair it: the refusal memo holds the verdict even once the scope is back.
#[tokio::test]
#[ignore = "reproduces AUDIT F1f: an unattended round wedges the delegating origin"]
async fn a_flapped_scope_wedges_the_delegating_origin() {
    let work = Node::spawn(Some("work")).await;
    let home = Node::spawn(Some("home")).await;
    let laptop = Node::spawn(None).await;

    trust_static(&laptop.store, &work.origin, &work.key());
    trust_static(&laptop.store, &home.origin, &home.key());
    trust_static(&home.store, &laptop.origin, &laptop.key());
    trust_static(&home.store, &work.origin, &work.key());
    trust_static(&work.store, &home.origin, &home.key());

    work.publish(
        1,
        &[
            ("reports", "q3.pdf", b"delegated"),
            ("secrets", "keys.txt", b"withheld"),
        ],
        &[delegation(&laptop.key(), &["reports"])],
    );

    // Home replicates work in full.
    let home_syncer = Syncer::new(home.store.clone());
    let home_to_work = home.net.connect_mpt(work.net.direct_addr()).await.unwrap();
    home_syncer.sync_with(&home_to_work).await.unwrap();
    assert_eq!(
        home.store
            .complete_head(&work.origin)
            .unwrap()
            .unwrap()
            .root,
        work.root()
    );

    // The laptop replicates work under its grant.
    let syncer = Syncer::new(laptop.store.clone());
    let to_work = laptop
        .net
        .connect_mpt(work.net.direct_addr())
        .await
        .unwrap();
    syncer.sync_with(&to_work).await.unwrap();
    assert_eq!(
        laptop.store.local_scope().unwrap(),
        Some(vec!["reports".to_string()])
    );

    // Work publishes again; home picks it up.
    work.publish(2, &[("reports", "q4.pdf", b"more")], &[]);
    home_syncer.sync_with(&home_to_work).await.unwrap();

    // The laptop's next rounds happen to pick `home`, which declares no scope.
    let to_home = laptop
        .net
        .connect_mpt(home.net.direct_addr())
        .await
        .unwrap();
    rounds(&syncer, &to_home, "home", 4).await;
    // And going back to the delegating origin does not repair it.
    rounds(&syncer, &to_work, "work", 3).await;

    let head = laptop.store.complete_head(&work.origin).unwrap();
    assert_eq!(
        head.map(|h| h.seq),
        Some(2),
        "the delegating origin must keep replicating"
    );
    assert_eq!(
        laptop.entries(&work.origin, "reports"),
        2,
        "and its new record must materialize"
    );
}
