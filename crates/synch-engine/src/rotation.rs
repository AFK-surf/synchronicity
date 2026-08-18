//! Operator-driven device-key rotation (§3.4).
//!
//! Rotation is three explicit steps, each an operator command, and nothing in
//! between happens on its own:
//!
//! 1. [`Node::rotate_key`] generates `K_new`, keeps `K_old` active, and reports
//!    the TXT record to publish.
//! 2. The operator publishes the record and waits for it to propagate.
//! 3. [`Node::activate_key`] re-signs the current root as a new head at
//!    `seq + 1` under `K_new` and brings up an endpoint for it, keeping the
//!    `K_old` endpoint live so both keys serve through the overlap window.
//! 4. [`Node::retire_key`] drops the old endpoint and deletes its secret.
//!
//! **A node never polls its own domain and never switches signing keys by
//! itself.** The judgement the switch-over needs — "have my peers picked up the
//! new binding yet?" — depends on resolvers this node cannot observe, so
//! auto-switching on its own view of DNS would strand exactly the peers whose
//! refresh lags furthest.

use iroh_base::SecretKey;
use synch_core::{now_ns, Hash, NodeId, OriginId, SignedHead};
use synch_net::Net;
use synch_store::{Binding, BindingSource, DeviceKey, KeyState, Slot};

use crate::{
    error::{EngineError, Result},
    node::Node,
};

/// What `synch key rotate` generated (§3.4 step 1).
#[derive(Debug, Clone)]
pub struct RotationPlan {
    /// The freshly generated device key, held but not yet signing.
    pub new_key: NodeId,
    /// The membership domain the record belongs in, when the origin is a named
    /// one. A key-identified origin cannot rotate and this is `None`.
    pub domain: Option<String>,
    /// The `id=` label the record must carry.
    pub name: Option<String>,
}

impl RotationPlan {
    /// The TXT record the operator publishes alongside the existing one.
    ///
    /// `None` for a key-identified origin, which has no name to rebind.
    pub fn txt_record(&self) -> Option<String> {
        let (domain, name) = (self.domain.as_ref()?, self.name.as_ref()?);
        Some(format!(
            "_synchronicity.{domain}. 300 IN TXT \"v=sync1 id={name} nk={}\"",
            self.new_key.to_z32()
        ))
    }
}

/// What `synch key activate` did (§3.4 step 3).
#[derive(Debug, Clone)]
pub struct Activation {
    /// The key now signing this origin's heads.
    pub new_key: NodeId,
    /// The key that was signing until now, still serving on its own endpoint.
    pub previous_key: NodeId,
    /// The head re-signed under the new key, at `seq + 1` over the same root.
    pub head: SignedHead,
}

/// What one peer answered about the bindings it holds for an origin (§5.1).
#[derive(Debug, Clone)]
pub struct PeerBindings {
    /// The peer's device key — how it was dialed, and how it is named back.
    pub peer: NodeId,
    /// The keys it holds bound, or why it could not be asked.
    pub keys: std::result::Result<Vec<NodeId>, String>,
}

impl PeerBindings {
    /// True if the peer answered at all.
    pub fn reachable(&self) -> bool {
        self.keys.is_ok()
    }

    /// True if the peer answered and holds this key bound.
    pub fn holds(&self, key: &NodeId) -> bool {
        self.keys.as_ref().map(|k| k.contains(key)).unwrap_or(false)
    }
}

impl Node {
    /// This node's own device keys and their states.
    pub fn device_keys(&self) -> Result<Vec<DeviceKey>> {
        Ok(self.store().device_keys()?)
    }

    /// Asks every trusted peer which of our device keys it currently holds
    /// bound (§3.4 step 3, §5.1).
    ///
    /// This is the judgement a rotation's switch-over needs and that a node
    /// cannot make from its own view of DNS: whether the *peers* have picked
    /// up the new record yet. Unreachable peers are reported as unreachable
    /// rather than counted either way — "three of four peers hold K_new, one
    /// is asleep" is a different fact from "three of four hold it and one does
    /// not".
    pub async fn peer_bindings(&self, origin: &OriginId) -> Result<Vec<PeerBindings>> {
        let mut out = Vec::new();
        for peer in self.dialable_peers()? {
            let addr = self
                .peer_addr(&peer)?
                .unwrap_or_else(|| iroh::EndpointAddr::new(peer));
            let keys = match self.net().connect_mpt(addr).await {
                Ok(client) => client.get_bindings(origin).await.map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            out.push(PeerBindings { peer, keys });
        }
        Ok(out)
    }

    /// Generates the next device key without changing which one signs (§3.4
    /// step 1).
    ///
    /// The key is stored in the `staged` state: it is held, it is not the
    /// signing key, and [`Node::activate_key`] is what promotes it.
    pub fn rotate_key(&self) -> Result<RotationPlan> {
        // Refuse before generating anything. A key-identified origin *is* its
        // device key (§3.1), so there is no name to rebind and no record to
        // publish — storing a `staged` key for it would leave an orphan the
        // node can never activate and nothing ever cleans up.
        let (domain, name) = match self.origin() {
            OriginId::Named { domain, id } => (domain.clone(), id.clone()),
            OriginId::Key(key) => {
                return Err(EngineError::invalid(format!(
                    "origin key:{} is key-identified, so its device key is its identity and \
                     cannot rotate: re-init with --id <name>@<domain>, or have peers run \
                     `synch trust add --as <name>`",
                    key.to_z32()
                )))
            }
        };
        let secret = SecretKey::generate();
        let new_key = secret.public();
        self.store()
            .add_device_key(&secret, KeyState::Staged, now_ns())?;
        Ok(RotationPlan {
            new_key,
            domain: Some(domain),
            name: Some(name),
        })
    }

    /// Switches signing to a previously generated key and brings up its
    /// endpoint (§3.4 step 3).
    ///
    /// The endpoint the node was already running stays live and keeps serving
    /// under the old key until [`Node::retire_key`] drops it, so peers whose
    /// DNS refresh lags are never locked out mid-window. New dials go out under
    /// the new key, which is the identity peers are being moved to.
    pub async fn activate_key(
        &self,
        new_key: &NodeId,
        bind: Option<std::net::SocketAddr>,
    ) -> Result<Activation> {
        if self.origin().as_key().is_some() {
            return Err(EngineError::invalid(
                "key-identified origins cannot rotate: the device key is the identity",
            ));
        }
        // Activation re-signs a head of its own, so it is a publish and the
        // recovery gate applies to it too (§3.4).
        self.ensure_publishable()?;
        let previous_key = self.node_id();
        if new_key == &previous_key {
            return Err(EngineError::invalid(format!(
                "{} is already the active key",
                new_key.to_z32()
            )));
        }
        let held = self
            .device_keys()?
            .into_iter()
            .find(|key| &key.node_id == new_key)
            .ok_or_else(|| {
                EngineError::not_found(format!(
                    "{}: this node holds no such device key; run `synch key rotate` first",
                    new_key.to_z32()
                ))
            })?;

        // A second endpoint on a fixed bind port would collide with the one
        // already running, so without an explicit address the incoming key
        // takes an ephemeral port on the same interface. Static-address
        // deployments pass `bind`: the operator is renumbering the node's
        // known address, and that is their call to make, not a side effect —
        // an ephemeral port silently strands whatever address peers were told.
        let mut options = self.config().net.clone();
        match bind {
            Some(addr) => options.bind_addr = Some(addr),
            None => {
                if let Some(addr) = &mut options.bind_addr {
                    addr.set_port(0);
                }
            }
        }
        let net = Net::bind(self.store().clone(), held.secret.clone(), options).await?;

        // Everything a rotation changes lands in one transaction, for the same
        // reason a publish does (§10): the binding, the two key states, and the
        // re-signed head are one atomic move of this node's identity.
        //
        // As separate autocommit statements this would have two failure modes.
        // The two key-state updates could be interrupted between them, leaving
        // no active key at all — `Node::open` then refuses to start, and the
        // command that would repair it needs a running daemon. And a head built
        // from `current_root()` and `next_seq()` read outside any transaction,
        // while the publisher runs as an independent task that takes no lock
        // this path holds, lets a publish commit between those two reads: the
        // activation signs `(publish_seq + 1, OLD_ROOT)` into the complete
        // slot, so `entries` holds the new root's state while the head names
        // the old one — and `push_head` hands that head to the whole
        // membership, where every peer materializes a rollback of the batch
        // just published.
        let origin = self.origin().clone();
        let secret = held.secret.clone();
        let now = now_ns();
        let binding = Binding {
            origin: origin.clone(),
            node_id: *new_key,
            source: BindingSource::Static,
            domain: origin.domain().map(str::to_string),
            note: Some("self".into()),
            added_at: now,
            expires_at: None,
        };
        let floor = self.store().publish_floor()?.unwrap_or(0);
        let head = self.store().transaction(|txn| -> Result<SignedHead> {
            // The node must be able to verify its own heads after a restart,
            // which means holding a binding for the key that signs them. This
            // is its own locally generated key, not a claim from the network.
            txn.put_binding(&binding)?;
            txn.set_device_key_state(&previous_key, KeyState::Retiring)?;
            txn.set_device_key_state(new_key, KeyState::Active)?;

            // Re-sign the current root as a new head under the new key. The
            // data is untouched: only the signer changes, and seq still moves
            // forward so peers accept it under the ordinary (seq, root) rule.
            // Both come from the snapshot the flip is written against, exactly
            // as `publish` reads them.
            let previous = txn.complete_head(&origin)?;
            let root = previous.as_ref().map(|h| h.root).unwrap_or(Hash::EMPTY);
            let seq = previous.as_ref().map(|h| h.seq + 1).unwrap_or(1).max(floor);
            let head = SignedHead::sign(&secret, origin.clone(), seq, root, now);
            // `put_head` retains the signature; the displaced head retained its
            // own when it took the slot (§10, v11).
            txn.put_head(Slot::Complete, &head, now, now)?;
            // The root does not move, so the diff is empty — but running it is
            // what keeps every complete-slot writer to the same rule, rather
            // than leaving this one relying on a root it did not read here.
            txn.materialize_diff(&origin, root, head.root)?;
            Ok(head)
        })?;
        self.swap_active_endpoint(held.secret.clone(), net);
        tracing::info!(
            seq = head.seq,
            key = %new_key.to_z32(),
            "activated a new device key and re-signed the head"
        );

        Ok(Activation {
            new_key: *new_key,
            previous_key,
            head,
        })
    }

    /// Drops a retiring key's endpoint and deletes its secret (§3.4 step 4).
    ///
    /// The active key cannot be retired: a node with no signing key could not
    /// publish again.
    pub async fn retire_key(&self, key: &NodeId) -> Result<()> {
        if key == &self.node_id() {
            return Err(EngineError::invalid(format!(
                "{} is the active key: run `synch key activate <new-key>` first",
                key.to_z32()
            )));
        }
        if !self.device_keys()?.iter().any(|held| &held.node_id == key) {
            return Err(EngineError::not_found(format!(
                "{}: this node holds no such device key",
                key.to_z32()
            )));
        }
        if let Some(net) = self.take_retiring_endpoint(key) {
            net.shutdown().await?;
        }
        self.store().remove_device_key(key)?;
        // The old key no longer speaks for this origin locally either; peers
        // stop accepting it when the record the operator removed expires.
        let _ = self
            .store()
            .remove_binding(self.origin(), key, BindingSource::Static)?;
        tracing::info!(key = %key.to_z32(), "retired a device key");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use std::path::Path;

    async fn node(dir: &Path, id: Option<OriginId>) -> Node {
        Node::init(dir, id).unwrap();
        Node::open(NodeConfig::loopback(dir)).await.unwrap()
    }

    fn named() -> OriginId {
        OriginId::named("nas", "cluster.example").unwrap()
    }

    #[tokio::test]
    async fn rotate_generates_a_key_without_switching() {
        let dir = tempfile::tempdir().unwrap();
        let node = node(dir.path(), Some(named())).await;
        let before = node.node_id();

        let plan = node.rotate_key().unwrap();
        assert_ne!(plan.new_key, before);
        assert_eq!(node.node_id(), before, "the signing key must not change");
        let record = plan.txt_record().unwrap();
        assert!(
            record.contains("_synchronicity.cluster.example."),
            "{record}"
        );
        assert!(record.contains("v=sync1 id=nas nk="), "{record}");

        let keys = node.device_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys.iter().filter(|k| k.state == KeyState::Active).count(),
            1,
            "exactly one key signs at any moment"
        );
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_key_identified_origin_cannot_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let node = node(dir.path(), None).await;
        // Refused upfront, before a key is generated: refusing later would
        // leave a `staged` key that could never be activated and that nothing
        // ever cleans up.
        let err = node.rotate_key().unwrap_err();
        assert!(err.to_string().contains("key-identified"), "{err}");
        assert!(err.to_string().contains("--id"), "{err}");
        assert_eq!(
            node.device_keys().unwrap().len(),
            1,
            "no orphan key was stored"
        );
        // And activation still refuses, for anyone who gets that far.
        let stranger = SecretKey::generate().public();
        let err = node.activate_key(&stranger, None).await.unwrap_err();
        assert!(err.to_string().contains("cannot rotate"), "{err}");
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn activate_re_signs_the_head_and_serves_both_keys() {
        let dir = tempfile::tempdir().unwrap();
        let node = node(dir.path(), Some(named())).await;
        let old_key = node.node_id();
        let old_addr = node.net().direct_addr();

        // Publish something, so the re-signed head carries a real root.
        let entry = synch_core::FileEntry::file(3, 0, synch_core::Hash::new(b"c"), 1);
        let first = node
            .publish(&[(
                node.key_for("s", "a.txt").unwrap(),
                Some(postcard::to_stdvec(&entry).unwrap()),
            )])
            .unwrap()
            .unwrap();
        assert_eq!(first.signed_by, old_key);

        let new_key = node.rotate_key().unwrap().new_key;
        let activation = node.activate_key(&new_key, None).await.unwrap();

        assert_eq!(activation.previous_key, old_key);
        assert_eq!(node.node_id(), new_key);
        assert_eq!(activation.head.seq, first.seq + 1);
        assert_eq!(activation.head.root, first.root, "the data is untouched");
        assert_eq!(activation.head.signed_by, new_key);
        activation.head.verify_signature().unwrap();

        // The stored head is the re-signed one, and the node can verify it.
        let stored = node.store().complete_head(node.origin()).unwrap().unwrap();
        assert_eq!(stored.signed_by, new_key);
        assert!(node
            .store()
            .is_bound(node.origin(), &new_key, now_ns())
            .unwrap());

        // The retiring key stays bound to our own origin through the window,
        // but it is still *us*: a node that dialed it reported itself
        // unreachable in `sync` and `key ls` for the whole window.
        assert!(
            !node.dialable_peers().unwrap().contains(&old_key),
            "the node must not dial its own retiring key"
        );

        // Both endpoints are live: the new one dials, the old one still serves.
        assert_eq!(node.net().id(), new_key);
        assert_ne!(node.net().direct_addr(), old_addr);
        let retiring = node.retiring_nets();
        assert_eq!(retiring.len(), 1);
        assert_eq!(retiring[0].id(), old_key);

        // Publishing now signs under the new key.
        let next = node
            .publish(&[(node.key_for("s", "a.txt").unwrap(), None)])
            .unwrap()
            .unwrap();
        assert_eq!(next.signed_by, new_key);
        assert_eq!(next.seq, activation.head.seq + 1);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn activate_refuses_unknown_and_already_active_keys() {
        let dir = tempfile::tempdir().unwrap();
        let node = node(dir.path(), Some(named())).await;
        let stranger = SecretKey::generate().public();
        let err = node.activate_key(&stranger, None).await.unwrap_err();
        assert!(err.to_string().contains("no such device key"), "{err}");
        let err = node.activate_key(&node.node_id(), None).await.unwrap_err();
        assert!(err.to_string().contains("already the active key"), "{err}");
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn retire_drops_the_endpoint_and_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let node = node(dir.path(), Some(named())).await;
        let old_key = node.node_id();
        let new_key = node.rotate_key().unwrap().new_key;

        // The active key is not retirable.
        let err = node.retire_key(&old_key).await.unwrap_err();
        assert!(err.to_string().contains("is the active key"), "{err}");

        node.activate_key(&new_key, None).await.unwrap();
        node.retire_key(&old_key).await.unwrap();

        assert!(node.retiring_nets().is_empty());
        let keys = node.device_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].node_id, new_key);
        assert!(!node
            .store()
            .is_bound(node.origin(), &old_key, now_ns())
            .unwrap());

        let err = node.retire_key(&old_key).await.unwrap_err();
        assert!(err.to_string().contains("no such device key"), "{err}");
        node.shutdown().await.unwrap();
    }

    /// A rotated node reopens under the key it activated, not the one it
    /// started with — the state that carries a rotation across a restart is the
    /// `device_keys` table, nothing in memory.
    #[tokio::test]
    async fn a_rotation_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let node = node(dir.path(), Some(named())).await;
        let new_key = node.rotate_key().unwrap().new_key;
        node.activate_key(&new_key, None).await.unwrap();
        node.shutdown().await.unwrap();

        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        assert_eq!(node.node_id(), new_key);
        assert_eq!(node.net().id(), new_key);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn key_ls_learns_which_peers_hold_our_keys() {
        // §3.4 step 3 / §5.1: `GetBindings` is what tells an operator that a
        // rotation's new key has actually propagated. Two loopback nodes, and
        // B's view of A's bindings is what A reads back.
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a_origin = OriginId::named("a", "cluster.example").unwrap();
        let b_origin = OriginId::named("b", "cluster.example").unwrap();
        Node::init(a_dir.path(), Some(a_origin.clone())).unwrap();
        Node::init(b_dir.path(), Some(b_origin.clone())).unwrap();
        let a = Node::open(crate::config::NodeConfig::loopback(a_dir.path()))
            .await
            .unwrap();
        let b = Node::open(crate::config::NodeConfig::loopback(b_dir.path()))
            .await
            .unwrap();

        // Mutual trust, direct addresses only.
        for (here, there, origin) in [(&a, &b, &b_origin), (&b, &a, &a_origin)] {
            here.store()
                .put_binding(&Binding {
                    origin: origin.clone(),
                    node_id: there.node_id(),
                    source: BindingSource::Static,
                    domain: None,
                    note: None,
                    added_at: 0,
                    expires_at: None,
                })
                .unwrap();
            here.remember_peer(&there.net().direct_addr()).unwrap();
        }

        // Before the rotation: B holds exactly A's current key for A.
        let answers = a.peer_bindings(&a_origin).await.unwrap();
        assert_eq!(answers.len(), 1);
        assert!(answers[0].reachable(), "{:?}", answers[0].keys);
        assert_eq!(answers[0].peer, b.node_id());
        assert!(answers[0].holds(&a.node_id()));

        // A generates K_new. B has not heard of it yet.
        let plan = a.rotate_key().unwrap();
        let answers = a.peer_bindings(&a_origin).await.unwrap();
        assert!(!answers[0].holds(&plan.new_key), "not published yet");

        // B refreshes bindings from a record set carrying both of A's keys,
        // which is what the rotation window looks like on the wire (§3.2).
        let records = vec![
            format!("v=sync1 id=a nk={}", a.node_id().to_z32()),
            format!("v=sync1 id=a nk={}", plan.new_key.to_z32()),
        ];
        let set = synch_net::MemberSet::from_records("cluster.example", &records).unwrap();
        b.apply_member_set(
            &set,
            std::time::Duration::from_secs(300),
            synch_core::now_ns(),
        )
        .unwrap();

        let answers = a.peer_bindings(&a_origin).await.unwrap();
        assert!(answers[0].reachable());
        assert!(
            answers[0].holds(&plan.new_key),
            "the new key has propagated: {:?}",
            answers[0].keys
        );
        assert!(
            answers[0].holds(&a.node_id()),
            "and the old one is still bound"
        );

        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_unreachable_peer_is_reported_rather_than_counted() {
        let dir = tempfile::tempdir().unwrap();
        let origin = OriginId::named("a", "cluster.example").unwrap();
        Node::init(dir.path(), Some(origin.clone())).unwrap();
        let node = Node::open(crate::config::NodeConfig::loopback(dir.path()))
            .await
            .unwrap();
        // A trusted peer that is not listening anywhere.
        let absent = iroh_base::SecretKey::generate().public();
        node.store()
            .put_binding(&Binding {
                origin: OriginId::named("ghost", "cluster.example").unwrap(),
                node_id: absent,
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();

        let answers = node.peer_bindings(&origin).await.unwrap();
        assert_eq!(answers.len(), 1);
        assert!(!answers[0].reachable());
        assert!(!answers[0].holds(&node.node_id()), "silence is not a no");
        node.shutdown().await.unwrap();
    }
}
