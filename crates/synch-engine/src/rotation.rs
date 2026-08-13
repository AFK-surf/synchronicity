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
use synch_core::{now_ns, NodeId, OriginId, SignedHead};
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

impl Node {
    /// This node's own device keys and their states.
    pub fn device_keys(&self) -> Result<Vec<DeviceKey>> {
        Ok(self.store().device_keys()?)
    }

    /// Generates the next device key without changing which one signs (§3.4
    /// step 1).
    ///
    /// The key is stored in the `retiring` state: it is held, it is not the
    /// signing key, and [`Node::activate_key`] is what promotes it.
    pub fn rotate_key(&self) -> Result<RotationPlan> {
        let secret = SecretKey::generate();
        let new_key = secret.public();
        self.store()
            .add_device_key(&secret, KeyState::Retiring, now_ns())?;
        let (domain, name) = match self.origin() {
            OriginId::Named { domain, id } => (Some(domain.clone()), Some(id.clone())),
            OriginId::Key(_) => (None, None),
        };
        Ok(RotationPlan {
            new_key,
            domain,
            name,
        })
    }

    /// Switches signing to a previously generated key and brings up its
    /// endpoint (§3.4 step 3).
    ///
    /// The endpoint the node was already running stays live and keeps serving
    /// under the old key until [`Node::retire_key`] drops it, so peers whose
    /// DNS refresh lags are never locked out mid-window. New dials go out under
    /// the new key, which is the identity peers are being moved to.
    pub async fn activate_key(&self, new_key: &NodeId) -> Result<Activation> {
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
        // already running, so the incoming key always takes an ephemeral port
        // on the same interface. Peers reach it by discovery or by the address
        // hints in the record that carries the new key.
        let mut options = self.config().net.clone();
        if let Some(addr) = &mut options.bind_addr {
            addr.set_port(0);
        }
        let net = Net::bind(self.store().clone(), held.secret.clone(), options).await?;

        // The node must be able to verify its own heads after a restart, which
        // means holding a binding for the key that signs them. This is its own
        // locally generated key, not a claim from the network.
        self.store().put_binding(&Binding {
            origin: self.origin().clone(),
            node_id: *new_key,
            source: BindingSource::Static,
            domain: self.origin().domain().map(str::to_string),
            note: Some("self".into()),
            added_at: now_ns(),
            expires_at: None,
        })?;
        self.store()
            .set_device_key_state(&previous_key, KeyState::Retiring)?;
        self.store()
            .set_device_key_state(new_key, KeyState::Active)?;
        self.swap_active_endpoint(held.secret.clone(), net);

        // Re-sign the current root as a new head under the new key. The data is
        // untouched: only the signer changes, and seq still moves forward so
        // peers accept it under the ordinary (seq, root) rule.
        let root = self.current_root()?;
        let seq = self.next_seq()?;
        let head = SignedHead::sign(&held.secret, self.origin().clone(), seq, root, now_ns());
        if let Some(previous) = self.store().complete_head(self.origin())? {
            self.store().record_history(&previous)?;
        }
        self.store()
            .put_head(Slot::Complete, &head, now_ns(), now_ns())?;
        self.store().record_history(&head)?;
        tracing::info!(
            seq,
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
        assert!(node.rotate_key().unwrap().txt_record().is_none());
        let key = node.rotate_key().unwrap().new_key;
        let err = node.activate_key(&key).await.unwrap_err();
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
            .publish(vec![(
                node.key_for("s", "a.txt").unwrap(),
                Some(postcard::to_stdvec(&entry).unwrap()),
            )])
            .unwrap()
            .unwrap();
        assert_eq!(first.signed_by, old_key);

        let new_key = node.rotate_key().unwrap().new_key;
        let activation = node.activate_key(&new_key).await.unwrap();

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

        // Both endpoints are live: the new one dials, the old one still serves.
        assert_eq!(node.net().id(), new_key);
        assert_ne!(node.net().direct_addr(), old_addr);
        let retiring = node.retiring_nets();
        assert_eq!(retiring.len(), 1);
        assert_eq!(retiring[0].id(), old_key);

        // Publishing now signs under the new key.
        let next = node
            .publish(vec![(node.key_for("s", "a.txt").unwrap(), None)])
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
        let err = node.activate_key(&stranger).await.unwrap_err();
        assert!(err.to_string().contains("no such device key"), "{err}");
        let err = node.activate_key(&node.node_id()).await.unwrap_err();
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

        node.activate_key(&new_key).await.unwrap();
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
        node.activate_key(&new_key).await.unwrap();
        node.shutdown().await.unwrap();

        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        assert_eq!(node.node_id(), new_key);
        assert_eq!(node.net().id(), new_key);
        node.shutdown().await.unwrap();
    }
}
