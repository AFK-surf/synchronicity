//! The embeddable node: identity, spaces, publishing, and peering.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use iroh::EndpointAddr;
use iroh_base::SecretKey;
use synch_core::{
    blob_key, file_key, manifest_key, now_ns, validate_space, BlobAd, Hash, NodeId, NodeManifest,
    OriginId, SignedHead, SpaceInfo, SOFTWARE,
};
use synch_mpt::Trie;
use synch_net::{Net, Syncer};
use synch_store::{Binding, BindingSource, KeyState, Slot, Store};

use crate::{
    config::NodeConfig,
    error::{EngineError, Result},
    publisher::Publisher,
};

/// A staged trie change: a key, and its new value or `None` to remove it.
pub type StagedChange = (Vec<u8>, Option<Vec<u8>>);

/// A running node.
///
/// This is the whole embeddable API: any Rust application can hold one of these
/// and get a full participant in the cluster.
#[derive(Debug, Clone)]
pub struct Node {
    inner: Arc<NodeInner>,
}

#[derive(Debug)]
struct NodeInner {
    store: Arc<Store>,
    /// The endpoint under the currently active device key: what this node
    /// dials from and what peers reach first.
    net: std::sync::RwLock<Net>,
    /// Endpoints kept live for keys that are on their way out, so both keys
    /// serve concurrently through a rotation's overlap window (§3.4).
    retiring: std::sync::Mutex<Vec<Net>>,
    syncer: Syncer,
    origin: OriginId,
    /// The signing key. Swapped only by `synch key activate` (§3.4); a node
    /// never switches keys on its own.
    secret: std::sync::RwLock<SecretKey>,
    config: NodeConfig,
    /// The batch between staging and one signed root (§7.1).
    publisher: Publisher,
    ad_clock: std::sync::Mutex<std::collections::HashMap<Hash, i64>>,
    /// What the last mirror pass wrote at each target path, so a pass can tell
    /// "this file is not current" from "this file is not current *and I am the
    /// one who just wrote it*" (`docs/DELTA-SYNC.md` §3.5, §6).
    mirror_writes: std::sync::Mutex<std::collections::HashMap<PathBuf, MirrorWrite>>,
    /// When each configured membership domain is next due for re-resolution,
    /// and when it was last attempted (§3.2, §3.4).
    dns: std::sync::Mutex<std::collections::HashMap<String, crate::membership::DomainSchedule>>,
    /// Rung when an inbound connection is refused for an unknown device key,
    /// which §3.4 makes a trigger for an immediate DNS re-resolution.
    dns_wake: Arc<tokio::sync::Notify>,
    /// Rung when a space is added or removed, so the watcher re-registers
    /// without waiting for the next filesystem hint (§7.1).
    spaces_changed: Arc<tokio::sync::Notify>,
}

/// What one mirror pass materialized at one target, and out of what.
///
/// See [`Node::note_mirror_write`] for why a pass remembers this at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MirrorWrite {
    /// The content root that was written.
    pub(crate) content: Hash,
    /// The CAS payload's length and modification time when it was written — a
    /// cheap identity for "the same bytes as last time", never a hash of them.
    /// `None` for an object small enough to live in the index (§6.2), which has
    /// no payload file to stat.
    pub(crate) payload: Option<(u64, i64)>,
}

/// What `init` created.
#[derive(Debug, Clone)]
pub struct InitReport {
    /// The node's stable identity.
    pub origin: OriginId,
    /// The generated device key.
    pub node_id: NodeId,
    /// The data directory.
    pub data_dir: PathBuf,
}

/// What `adopt_named_origin` did.
#[derive(Debug, Clone)]
pub struct AdoptOriginReport {
    /// The origin this node was publishing as.
    pub previous: OriginId,
    /// The named origin it will publish as after the next scan.
    pub origin: OriginId,
    /// The active device key, unchanged.
    pub node_id: NodeId,
}

impl Node {
    /// Creates an identity and database in `data_dir`.
    ///
    /// With no `--id`, the device key is the identity (§3.1) — self-certifying
    /// but not rotatable. With one, the origin is the named form and the key
    /// can rotate under it.
    pub fn init(data_dir: impl AsRef<Path>, id: Option<OriginId>) -> Result<InitReport> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let store = Store::open(&data_dir)?;
        if store.self_origin()?.is_some() {
            return Err(EngineError::invalid(format!(
                "{} already has an identity",
                data_dir.display()
            )));
        }
        let secret = SecretKey::generate();
        let node_id = secret.public();
        let origin = id.unwrap_or(OriginId::Key(node_id));
        store.add_device_key(&secret, KeyState::Active, now_ns())?;
        store.set_self_origin(&origin)?;
        // A node always holds its own origin: without this binding it could not
        // verify its own heads after a restart.
        store.put_binding(&Binding {
            origin: origin.clone(),
            node_id,
            source: BindingSource::Static,
            domain: None,
            note: Some("self".into()),
            added_at: now_ns(),
            expires_at: None,
        })?;
        Ok(InitReport {
            origin,
            node_id,
            data_dir,
        })
    }

    /// Names a key-identified node without generating a new device key.
    ///
    /// OriginId is otherwise permanent (§3.1). This is the missing half of
    /// §3.2 auto-detection: a node that came up as `key:<nk>` can take the
    /// `<id>@<domain>` that key is already published under. The next
    /// `synch scan` publishes a head under the new name; the daemon must be
    /// restarted first so it signs as that name.
    pub fn adopt_named_origin(
        data_dir: impl AsRef<Path>,
        origin: OriginId,
    ) -> Result<AdoptOriginReport> {
        if origin.as_key().is_some() {
            return Err(EngineError::invalid(
                "id set wants <name>@<domain>, not a key identity",
            ));
        }
        let data_dir = data_dir.as_ref().to_path_buf();
        let store = Store::open(&data_dir)?;
        let previous = store.self_origin()?.ok_or(EngineError::NotInitialized)?;
        let node_id = store
            .active_device_key()?
            .ok_or(EngineError::NoActiveKey)?
            .node_id;
        match &previous {
            OriginId::Named { .. } => {
                return Err(EngineError::invalid(format!(
                    "origin is already {previous}; a named identity cannot be renamed"
                )));
            }
            OriginId::Key(key) if key != &node_id => {
                return Err(EngineError::invalid(
                    "this node's key identity is not its active device key",
                ));
            }
            OriginId::Key(_) => {}
        }
        store.set_self_origin(&origin)?;
        store.remove_binding(&previous, &node_id, BindingSource::Static)?;
        store.put_binding(&Binding {
            origin: origin.clone(),
            node_id,
            source: BindingSource::Static,
            domain: None,
            note: Some("self".into()),
            added_at: now_ns(),
            expires_at: None,
        })?;
        // Drop the key-origin view so the unified tree does not keep a second
        // copy of every path under the old name. Blobs stay; the next scan
        // republishes them under the new origin.
        store.clear_head(&previous, Slot::Complete)?;
        store.clear_head(&previous, Slot::Pending)?;
        store.delete_origin_entries(&previous)?;
        store.delete_origin_providers(&previous)?;
        Ok(AdoptOriginReport {
            previous,
            origin,
            node_id,
        })
    }

    /// Opens an initialized data directory and binds the endpoint.
    pub async fn open(mut config: NodeConfig) -> Result<Node> {
        // Opening runs migrations and hardens file permissions, both of which
        // are filesystem work, so it goes to the blocking pool like everything
        // else that touches the disk.
        let data_dir = config.data_dir.clone();
        let store = Arc::new(crate::blocking::offload(move || Ok(Store::open(&data_dir)?)).await?);
        let origin = store.self_origin()?.ok_or(EngineError::NotInitialized)?;
        let secret = store
            .active_device_key()?
            .ok_or(EngineError::NoActiveKey)?
            .secret;
        // Every endpoint this node ever binds — this one, and the second one a
        // key activation brings up — rings the same bell, because the refusal
        // that matters can arrive at either (§3.4).
        let dns_wake = Arc::new(tokio::sync::Notify::new());
        config.net.on_unknown_key = Some(dns_wake.clone());
        let net = Net::bind(store.clone(), secret.clone(), config.net.clone()).await?;
        let syncer = Syncer::new(store.clone());
        let publisher = Publisher::new(config.publish_quiesce, config.publish_batch_max);
        let node = Node {
            inner: Arc::new(NodeInner {
                store,
                net: std::sync::RwLock::new(net),
                retiring: std::sync::Mutex::new(Vec::new()),
                syncer,
                origin,
                secret: std::sync::RwLock::new(secret),
                config,
                publisher,
                ad_clock: std::sync::Mutex::new(Default::default()),
                mirror_writes: std::sync::Mutex::new(Default::default()),
                dns: std::sync::Mutex::new(Default::default()),
                dns_wake,
                spaces_changed: Arc::new(tokio::sync::Notify::new()),
            }),
        };
        // A batch that was still buffered when the process died was never
        // published, and the scanner would skip those files forever (§7.1).
        // Opening is where that is noticed and undone — one trie lookup per
        // indexed file, so it goes off the runtime with the rest.
        let reindexed = {
            let node = node.clone();
            crate::blocking::offload(move || node.reconcile_local_files()).await?
        };
        if reindexed > 0 {
            tracing::info!(
                paths = reindexed,
                "re-indexing paths whose staged changes never reached a root"
            );
        }
        Ok(node)
    }

    /// The metadata and content store.
    pub fn store(&self) -> &Arc<Store> {
        &self.inner.store
    }

    /// The batch between staging and one signed root (§7.1).
    pub fn publisher(&self) -> &Publisher {
        &self.inner.publisher
    }

    /// The endpoint under the active device key.
    ///
    /// Returned by value because a rotation can replace it (§3.4): holding a
    /// borrow across an `activate` would pin the old endpoint.
    pub fn net(&self) -> Net {
        self.inner
            .net
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The addresses of the endpoints still serving for keys that are being
    /// retired (§3.4).
    pub fn retiring_endpoints(&self) -> Vec<EndpointAddr> {
        self.retiring_nets().iter().map(Net::addr).collect()
    }

    /// The endpoints still serving for keys that are being retired (§3.4).
    pub(crate) fn retiring_nets(&self) -> Vec<Net> {
        self.inner
            .retiring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The active signing key.
    pub(crate) fn secret(&self) -> SecretKey {
        self.inner
            .secret
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Replaces the active key and its endpoint, demoting the previous
    /// endpoint to a serving-only one for the overlap window (§3.4).
    pub(crate) fn swap_active_endpoint(&self, secret: SecretKey, net: Net) {
        let previous = {
            let mut slot = self
                .inner
                .net
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *slot, net)
        };
        *self
            .inner
            .secret
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = secret;
        self.inner
            .retiring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(previous);
    }

    /// Removes a retiring endpoint, returning it so the caller can shut it
    /// down outside the lock.
    pub(crate) fn take_retiring_endpoint(&self, node_id: &NodeId) -> Option<Net> {
        let mut retiring = self
            .inner
            .retiring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = retiring.iter().position(|net| &net.id() == node_id)?;
        Some(retiring.remove(index))
    }

    /// The reconciler.
    pub fn syncer(&self) -> &Syncer {
        &self.inner.syncer
    }

    /// This node's stable identity.
    pub fn origin(&self) -> &OriginId {
        &self.inner.origin
    }

    /// This node's active device key.
    pub fn node_id(&self) -> NodeId {
        self.secret().public()
    }

    /// The configuration this node was opened with.
    pub fn config(&self) -> &NodeConfig {
        &self.inner.config
    }

    /// Shuts every endpoint this node holds down cleanly.
    pub async fn shutdown(&self) -> Result<()> {
        for net in self.retiring_nets() {
            if let Err(e) = net.shutdown().await {
                tracing::warn!(error = %e, "a retiring endpoint did not shut down cleanly");
            }
        }
        self.net().shutdown().await?;
        Ok(())
    }

    // ---- membership -------------------------------------------------------

    /// Statically trusts a device key, optionally under a name (§3.2).
    ///
    /// Trust is unilateral: for two nodes to sync, each must trust the other.
    pub fn trust_add(
        &self,
        node_id: NodeId,
        name: Option<&str>,
        domain: Option<&str>,
        note: Option<&str>,
    ) -> Result<OriginId> {
        let origin =
            match (name, domain) {
                (Some(name), Some(domain)) => OriginId::named(name, domain)
                    .map_err(|e| EngineError::invalid(e.to_string()))?,
                (Some(name), None) => OriginId::named(name, "local")
                    .map_err(|e| EngineError::invalid(e.to_string()))?,
                (None, _) => OriginId::Key(node_id),
            };
        self.store().put_binding(&Binding {
            origin: origin.clone(),
            node_id,
            source: BindingSource::Static,
            domain: domain.map(str::to_string),
            note: note.map(str::to_string),
            added_at: now_ns(),
            expires_at: None,
        })?;
        Ok(origin)
    }

    /// Rebinds a named origin to a new device key, the static-trust equivalent
    /// of a DNS rotation (§3.4).
    pub fn trust_rebind(&self, origin: &OriginId, node_id: NodeId) -> Result<()> {
        if origin.as_key().is_some() {
            return Err(EngineError::invalid(
                "key-identified origins cannot rotate; re-add under a name instead",
            ));
        }
        self.store().put_binding(&Binding {
            origin: origin.clone(),
            node_id,
            source: BindingSource::Static,
            domain: origin.domain().map(str::to_string),
            note: None,
            added_at: now_ns(),
            expires_at: None,
        })?;
        Ok(())
    }

    /// Records a peer's address so it can be dialed later.
    pub fn remember_peer(&self, addr: &EndpointAddr) -> Result<()> {
        let encoded = encode_addr(addr);
        self.store()
            .record_peer_seen(&addr.id, Some(&encoded), now_ns())?;
        Ok(())
    }

    /// The address recorded for a peer, if any.
    pub fn peer_addr(&self, node_id: &NodeId) -> Result<Option<EndpointAddr>> {
        Ok(self
            .store()
            .peers_seen()?
            .into_iter()
            .find(|p| &p.node_id == node_id)
            .and_then(|p| p.last_addr)
            .and_then(|bytes| decode_addr(*node_id, &bytes)))
    }

    // ---- spaces -----------------------------------------------------------

    /// Registers a local directory as a space (§4.1).
    ///
    /// Space roots may not overlap a mirror target, which is what makes the
    /// "no echo" guarantee structural rather than conventional (§7.2).
    pub fn add_space(&self, id: &str, path: impl AsRef<Path>) -> Result<()> {
        validate_space(id)?;
        let path = canonical_dir(path.as_ref())?;
        for mirror in self.store().mirrors()? {
            if paths_overlap(&path, &stored_root(&mirror.local_path)) {
                return Err(EngineError::invalid(format!(
                    "space root {} overlaps mirror {}",
                    path.display(),
                    mirror.local_path
                )));
            }
        }
        for space in self.store().spaces()? {
            if space.id != id && paths_overlap(&path, &stored_root(&space.local_path)) {
                return Err(EngineError::invalid(format!(
                    "space root {} overlaps space {}",
                    path.display(),
                    space.id
                )));
            }
        }
        self.store().put_space(id, &path.to_string_lossy())?;
        self.spaces_changed();
        Ok(())
    }

    /// Removes a space and its published entries.
    ///
    /// Staging the removal is half of a publish, so it takes the same recovery
    /// gate (§3.4): a node that cannot publish must not drop the space either,
    /// or the unpublish would be lost with it.
    pub fn remove_space(&self, id: &str) -> Result<Vec<StagedChange>> {
        // "removed ghost and unpublished 0 record(s)" for a space that never
        // existed is a lie with a friendly face.
        if !self.store().spaces()?.iter().any(|space| space.id == id) {
            return Err(EngineError::NotFound(format!("no space {id}")));
        }
        self.ensure_publishable()?;
        let mut staged = Vec::new();
        let root = self.current_root()?;
        let trie = Trie::new(self.store().as_ref());
        let prefix = synch_core::space_prefix(id)?;
        for (key, _) in trie.scan(root, &prefix, None, None)? {
            staged.push((key, None));
        }
        self.store().remove_space(id)?;
        for path in self.store().local_files(id)? {
            self.store().remove_local_file(id, &path)?;
        }
        self.spaces_changed();
        Ok(staged)
    }

    /// Tells the watcher that the set of spaces changed (§7.1).
    pub(crate) fn spaces_changed(&self) {
        self.inner.spaces_changed.notify_waiters();
    }

    /// The bell the watcher waits on for space additions and removals.
    pub(crate) fn spaces_changed_signal(&self) -> Arc<tokio::sync::Notify> {
        self.inner.spaces_changed.clone()
    }

    /// The bell an unknown-key refusal rings, which the DNS refresh loop waits
    /// on (§3.4).
    pub(crate) fn dns_wake(&self) -> Arc<tokio::sync::Notify> {
        self.inner.dns_wake.clone()
    }

    /// Rings the unknown-key bell as an inbound refusal would.
    ///
    /// The endpoint rings it on its own; this is how a caller that already
    /// knows a binding is stale asks for the same re-resolution.
    pub fn trigger_dns_refresh(&self) {
        self.inner.dns_wake.notify_waiters();
    }

    /// The per-domain re-resolution schedule (§3.2).
    pub(crate) fn dns_schedule(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        std::collections::HashMap<String, crate::membership::DomainSchedule>,
    > {
        self.inner
            .dns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // ---- publishing -------------------------------------------------------

    /// The root of this node's own current head.
    pub fn current_root(&self) -> Result<Hash> {
        Ok(self
            .store()
            .complete_head(self.origin())?
            .map(|h| h.root)
            .unwrap_or(Hash::EMPTY))
    }

    /// This node's own current signed head, if it has published anything.
    pub fn own_head(&self) -> Result<Option<SignedHead>> {
        Ok(self.store().complete_head(self.origin())?)
    }

    /// The seq this node's next publish will carry.
    ///
    /// Normally one past the current head, or 1 for a node that has never
    /// published. A node that came back from key loss also carries a durable
    /// publishing floor (§3.4), and the floor only ever raises the seq: it is
    /// what keeps a recovered node above the history its peers still hold,
    /// across restarts.
    pub fn next_seq(&self) -> Result<u64> {
        let next = self
            .store()
            .complete_head(self.origin())?
            .map(|h| h.seq + 1)
            .unwrap_or(1);
        Ok(next.max(self.store().publish_floor()?.unwrap_or(0)))
    }

    /// Applies staged changes as one new signed root (§7.1).
    ///
    /// One save in an editor costs one head; a 100k-file initial index costs a
    /// handful, because the batch becomes a single root.
    ///
    /// Refuses while this node is in key-loss recovery (§3.4): the head it
    /// would mint carries a seq every peer rejects.
    /// One SQLite transaction, as §10 requires: "trie writes, head, history,
    /// and materialization commit together or not at all". A crash between any
    /// two of those steps used to be able to leave a head whose trie was
    /// half-written, or a head slot the derived views did not agree with.
    pub fn publish(&self, staged: &[StagedChange]) -> Result<Option<SignedHead>> {
        if staged.is_empty() {
            return Ok(None);
        }
        self.ensure_publishable()?;
        let secret = self.secret();
        let origin = self.origin().clone();
        let floor = self.store().publish_floor()?.unwrap_or(0);
        let now = now_ns();

        let head = self
            .store()
            .transaction(|txn| -> Result<Option<SignedHead>> {
                // Read the head we are about to displace inside the transaction:
                // the root we build on and the seq we build past have to come from
                // the same snapshot the flip is written against.
                let previous = txn.complete_head(&origin)?;
                let old_root = previous.as_ref().map(|h| h.root).unwrap_or(Hash::EMPTY);

                let trie = Trie::new(txn);
                let mut root = old_root;
                for (key, value) in staged {
                    root = match value {
                        Some(v) => trie.insert(root, key, v)?,
                        None => trie.remove(root, key)?,
                    };
                }
                if root == old_root {
                    return Ok(None);
                }

                let seq = previous.as_ref().map(|h| h.seq + 1).unwrap_or(1).max(floor);
                let head = SignedHead::sign(&secret, origin.clone(), seq, root, now);
                if let Some(previous) = &previous {
                    txn.record_history(previous)?;
                }
                txn.put_head(Slot::Complete, &head, now, now)?;
                txn.record_history(&head)?;
                txn.materialize_diff(&origin, old_root, root)?;
                Ok(Some(head))
            })?;

        if let Some(head) = &head {
            // This node just built the whole trie under that root, so it holds
            // it whole by construction. Recording that here is what keeps the
            // first `Hello` after every publish from proving it again by
            // walking the entire trie (§5.1).
            synch_mpt::NodeStore::note_complete(self.store().as_ref(), &head.root)?;
            tracing::info!(
                seq = head.seq,
                changes = staged.len(),
                "published a new root"
            );
        }
        Ok(head)
    }

    /// Builds the `m:self` manifest record for this node (§4.2).
    pub fn manifest_change(&self) -> Result<StagedChange> {
        let mut spaces = Vec::new();
        for space in self.store().spaces()? {
            let count = self.store().count_entries(self.origin(), &space.id)?;
            spaces.push(SpaceInfo {
                id: space.id,
                description: space.local_path,
                entry_count: count,
            });
        }
        let manifest = NodeManifest {
            v: synch_core::RECORD_VERSION,
            name: self.inner.config.name.clone(),
            spaces,
            software: SOFTWARE.to_string(),
        };
        let bytes =
            postcard::to_stdvec(&manifest).map_err(|e| EngineError::Record(e.to_string()))?;
        Ok((manifest_key(), Some(bytes)))
    }

    /// Reads an origin's published manifest.
    pub fn manifest_of(&self, origin: &OriginId) -> Result<Option<NodeManifest>> {
        let Some(head) = self.store().complete_head(origin)? else {
            return Ok(None);
        };
        let trie = Trie::new(self.store().as_ref());
        let Some(bytes) = trie.get(head.root, &manifest_key())? else {
            return Ok(None);
        };
        postcard::from_bytes(&bytes)
            .map(Some)
            .map_err(|e| EngineError::Record(e.to_string()))
    }

    // ---- blob advertisements ---------------------------------------------

    /// The `b:` record for a locally held object, if we hold any of it.
    pub fn ad_change(&self, root: &Hash) -> Result<Option<StagedChange>> {
        let Some(ad) = self.store().local_ad(root)? else {
            return Ok(None);
        };
        let bytes = postcard::to_stdvec(&ad).map_err(|e| EngineError::Record(e.to_string()))?;
        Ok(Some((blob_key(root), Some(bytes))))
    }

    /// Records what a mirror pass materialized at `target`
    /// (`docs/DELTA-SYNC.md` §3.5).
    ///
    /// The mirror's currency check hashes the file it finds and rewrites it when
    /// the hash is wrong, which converges on every ordinary cause of a wrong
    /// hash — a truncated write, a user's edit, a version this pass replaced.
    /// It does not converge on one: a CAS payload that rotted at rest. The
    /// object is complete and verified as far as the index is concerned, so
    /// nothing refetches it; materialization clones it without re-reading it,
    /// which is the settled trust posture (§2.1); and the pass after this one
    /// hashes the file, finds the same wrong answer, and writes the same wrong
    /// bytes again, reporting `written` forever.
    ///
    /// So a pass remembers what it wrote where, and which payload it wrote it
    /// from. When the next one is about to write the *same* content root, from
    /// the *same* payload, over a file that still does not hash to it, the
    /// payload — not the file — is the thing at fault, and the path is reported
    /// instead of rewritten ([`Node::mirror_write_was`]).
    ///
    /// Two limits, both deliberate:
    ///
    /// - **In memory, per process.** This is a hint about the immediately
    ///   preceding pass, not a durable quarantine. A restart forgets it and the
    ///   next pass writes once more before noticing again, which costs one
    ///   rewrite and keeps the store free of a "suspect object" record that
    ///   nothing would ever be able to clear.
    /// - **The payload is identified by length and mtime, not by hash.** Reading
    ///   the object back to identify it is exactly the scrubbing §2.1 refuses.
    ///   A stat is enough for the job it has: noticing that the payload has been
    ///   *replaced* — by `synch blob rm` and a refetch, a restore, a filesystem
    ///   repair — so that the suspicion clears and the mirror converges on the
    ///   very next pass. A payload rewritten with the same length and the same
    ///   mtime is indistinguishable from the old one here, and stays suspect
    ///   until the daemon restarts.
    pub(crate) fn note_mirror_write(&self, target: &Path, write: MirrorWrite) {
        self.mirror_writes().insert(target.to_path_buf(), write);
    }

    /// What the previous pass wrote at `target`, if this process wrote anything.
    pub(crate) fn mirror_write_was(&self, target: &Path) -> Option<MirrorWrite> {
        self.mirror_writes().get(target).copied()
    }

    /// Forgets what was written at `target` — called when the file turns out to
    /// be current, which is the evidence that whatever was written landed.
    pub(crate) fn forget_mirror_write(&self, target: &Path) {
        self.mirror_writes().remove(target);
    }

    fn mirror_writes(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<PathBuf, MirrorWrite>> {
        self.inner
            .mirror_writes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether an object's advertisement is due for a milestone update (§6.3).
    ///
    /// Ads are published on first ingest and on completion, and otherwise at
    /// most once per `ad_update_interval` per object while a download is in
    /// flight — never per chunk.
    pub fn ad_update_due(&self, root: &Hash) -> Result<bool> {
        let Some(blob) = self.store().blob(root)? else {
            return Ok(false);
        };
        let interval = self.inner.config.ad_update_interval.as_nanos() as i64;
        let mut clock = self
            .inner
            .ad_clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = now_ns();
        match clock.get(root) {
            // First sighting, or the object just completed: always a milestone.
            None => {
                clock.insert(*root, now);
                Ok(true)
            }
            Some(_) if blob.complete => {
                clock.insert(*root, now);
                Ok(true)
            }
            Some(last) if now - last >= interval => {
                clock.insert(*root, now);
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    /// The published `b:` ad we currently advertise for an object.
    pub fn published_ad(&self, root: &Hash) -> Result<Option<BlobAd>> {
        let head_root = self.current_root()?;
        let trie = Trie::new(self.store().as_ref());
        let Some(bytes) = trie.get(head_root, &blob_key(root))? else {
            return Ok(None);
        };
        postcard::from_bytes(&bytes)
            .map(Some)
            .map_err(|e| EngineError::Record(e.to_string()))
    }

    // ---- entry helpers ----------------------------------------------------

    /// The trie key for a path in one of this node's spaces.
    pub fn key_for(&self, space: &str, path: &str) -> Result<Vec<u8>> {
        Ok(file_key(space, path)?)
    }
}

fn canonical_dir(path: &Path) -> Result<PathBuf> {
    // A bare os error with no path reads as a daemon fault; naming the path
    // and the operation makes "Permission denied" point at the right thing.
    std::fs::create_dir_all(path)
        .map_err(|e| EngineError::invalid(format!("could not create {}: {e}", path.display())))?;
    std::fs::canonicalize(path)
        .map_err(|e| EngineError::invalid(format!("could not resolve {}: {e}", path.display())))
}

/// True if either path contains the other.
pub fn paths_overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Resolves a stored space or mirror root for comparison against a freshly
/// canonicalized path.
///
/// Both registration paths canonicalize before storing, but a stored root can
/// still be non-canonical: it may predate that, or a symlink may have appeared
/// along it since. Comparing a canonical path against a raw one silently
/// misses overlaps — on macOS every temp path under `/var` resolves to
/// `/private/var`, so the guard passed a directory it should have refused.
/// Falls back to the raw value when the directory no longer exists.
pub fn stored_root(path: &str) -> PathBuf {
    let raw = PathBuf::from(path);
    std::fs::canonicalize(&raw).unwrap_or(raw)
}

/// Encodes an endpoint address for the `peers_seen.last_addr` column.
pub fn encode_addr(addr: &EndpointAddr) -> Vec<u8> {
    let parts: Vec<String> = addr
        .ip_addrs()
        .map(|a| format!("ip:{a}"))
        .chain(addr.relay_urls().map(|u| format!("relay:{u}")))
        .collect();
    parts.join("\n").into_bytes()
}

/// Decodes an endpoint address from the `peers_seen.last_addr` column.
pub fn decode_addr(id: NodeId, bytes: &[u8]) -> Option<EndpointAddr> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut addr = EndpointAddr::new(id);
    for part in text.split('\n').filter(|p| !p.is_empty()) {
        if let Some(ip) = part.strip_prefix("ip:") {
            if let Ok(socket) = ip.parse() {
                addr = addr.with_ip_addr(socket);
            }
        } else if let Some(url) = part.strip_prefix("relay:") {
            if let Ok(url) = url.parse() {
                addr = addr.with_relay_url(url);
            }
        }
    }
    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    async fn spawn(dir: &Path, id: Option<OriginId>) -> Node {
        Node::init(dir, id).unwrap();
        Node::open(NodeConfig::loopback(dir)).await.unwrap()
    }

    #[tokio::test]
    async fn init_creates_an_identity_and_binds_it() {
        let dir = node_dir();
        let report = Node::init(dir.path(), None).unwrap();
        assert_eq!(report.origin, OriginId::Key(report.node_id));

        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        assert_eq!(node.origin(), &report.origin);
        assert_eq!(node.node_id(), report.node_id);
        // The node can verify its own heads, which requires a live self binding.
        assert!(node
            .store()
            .is_bound(node.origin(), &node.node_id(), now_ns())
            .unwrap());
        node.shutdown().await.unwrap();
    }

    #[test]
    fn a_key_identity_can_adopt_a_name() {
        let dir = node_dir();
        let report = Node::init(dir.path(), None).unwrap();
        let named = OriginId::named("orb", "cluster.example").unwrap();
        let adopted = Node::adopt_named_origin(dir.path(), named.clone()).unwrap();
        assert_eq!(adopted.previous, OriginId::Key(report.node_id));
        assert_eq!(adopted.origin, named);
        assert_eq!(adopted.node_id, report.node_id);

        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.self_origin().unwrap(), Some(named.clone()));
        assert!(store.is_bound(&named, &report.node_id, now_ns()).unwrap());
        assert!(!store
            .is_bound(&adopted.previous, &report.node_id, now_ns())
            .unwrap());
        assert!(store.complete_head(&adopted.previous).unwrap().is_none());
    }

    #[test]
    fn a_named_identity_cannot_be_renamed() {
        let dir = node_dir();
        let origin = OriginId::named("nas", "cluster.example").unwrap();
        Node::init(dir.path(), Some(origin)).unwrap();
        let other = OriginId::named("orb", "cluster.example").unwrap();
        let err = Node::adopt_named_origin(dir.path(), other).unwrap_err();
        assert!(matches!(err, EngineError::Invalid(_)), "{err:?}");
    }

    #[test]
    fn adopt_named_origin_refuses_a_key_identity() {
        let dir = node_dir();
        let report = Node::init(dir.path(), None).unwrap();
        let err = Node::adopt_named_origin(dir.path(), OriginId::Key(report.node_id)).unwrap_err();
        assert!(matches!(err, EngineError::Invalid(_)), "{err:?}");
    }

    #[tokio::test]
    async fn init_refuses_to_overwrite_an_identity() {
        let dir = node_dir();
        Node::init(dir.path(), None).unwrap();
        assert!(Node::init(dir.path(), None).is_err());
    }

    #[tokio::test]
    async fn opening_an_uninitialized_directory_fails_clearly() {
        let dir = node_dir();
        let err = Node::open(NodeConfig::loopback(dir.path()))
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::NotInitialized));
    }

    #[tokio::test]
    async fn a_named_identity_survives_a_reopen() {
        let dir = node_dir();
        let origin = OriginId::named("nas", "cluster.example").unwrap();
        let node = spawn(dir.path(), Some(origin.clone())).await;
        assert_eq!(node.origin(), &origin);
        node.shutdown().await.unwrap();

        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        assert_eq!(node.origin(), &origin);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn publishing_bumps_seq_and_retains_history() {
        let dir = node_dir();
        let node = spawn(dir.path(), None).await;
        assert_eq!(node.next_seq().unwrap(), 1);

        let entry = synch_core::FileEntry::file(3, 0, Hash::new(b"c"), 1);
        let head = node
            .publish(&[(
                node.key_for("s", "a.txt").unwrap(),
                Some(postcard::to_stdvec(&entry).unwrap()),
            )])
            .unwrap()
            .unwrap();
        assert_eq!(head.seq, 1);
        head.verify_signature().unwrap();
        assert_eq!(node.next_seq().unwrap(), 2);
        assert!(node
            .store()
            .entry(node.origin(), "s", "a.txt")
            .unwrap()
            .is_some());

        let head2 = node
            .publish(&[(node.key_for("s", "a.txt").unwrap(), None)])
            .unwrap()
            .unwrap();
        assert_eq!(head2.seq, 2);
        assert!(node
            .store()
            .entry(node.origin(), "s", "a.txt")
            .unwrap()
            .is_none());
        // Both roots are retained as history.
        assert_eq!(node.store().head_history(node.origin()).unwrap().len(), 2);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn publishing_nothing_is_a_no_op() {
        let dir = node_dir();
        let node = spawn(dir.path(), None).await;
        assert!(node.publish(&[]).unwrap().is_none());
        // A change that does not alter the root does not mint a head either.
        assert!(node
            .publish(&[(node.key_for("s", "absent").unwrap(), None)])
            .unwrap()
            .is_none());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn manifests_round_trip_through_the_trie() {
        let dir = node_dir();
        let node = spawn(dir.path(), None).await;
        let space = tempfile::tempdir().unwrap();
        node.add_space("media", space.path()).unwrap();
        let change = node.manifest_change().unwrap();
        node.publish(&[change]).unwrap().unwrap();

        let manifest = node.manifest_of(node.origin()).unwrap().unwrap();
        assert_eq!(manifest.software, SOFTWARE);
        assert_eq!(manifest.spaces.len(), 1);
        assert_eq!(manifest.spaces[0].id, "media");
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn spaces_may_not_overlap_mirrors() {
        let dir = node_dir();
        let node = spawn(dir.path(), None).await;
        let shared = tempfile::tempdir().unwrap();
        node.store()
            .put_mirror(
                &shared.path().to_string_lossy(),
                "media",
                &synch_store::VersionPolicy::Newest,
            )
            .unwrap();
        let err = node.add_space("media", shared.path()).unwrap_err();
        assert!(err.to_string().contains("overlaps mirror"));

        // And a nested subdirectory is caught too, so "no echo" is structural.
        let nested = shared.path().join("sub");
        assert!(node.add_space("nested", &nested).is_err());
        node.shutdown().await.unwrap();
    }

    /// A mirror root stored through a symlink still has to be caught: the
    /// incoming path is canonicalized, so the stored one must be too. This is
    /// what fails on macOS, where every temp path under `/var` resolves to
    /// `/private/var`.
    #[cfg(unix)]
    #[tokio::test]
    async fn overlap_is_detected_through_symlinked_roots() {
        let dir = node_dir();
        let node = spawn(dir.path(), None).await;
        let real = tempfile::tempdir().unwrap();
        let link_parent = tempfile::tempdir().unwrap();
        let link = link_parent.path().join("via-symlink");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();

        node.store()
            .put_mirror(
                &link.to_string_lossy(),
                "media",
                &synch_store::VersionPolicy::Newest,
            )
            .unwrap();

        let err = node.add_space("media", real.path()).unwrap_err();
        assert!(err.to_string().contains("overlaps mirror"));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn spaces_may_not_overlap_each_other() {
        let dir = node_dir();
        let node = spawn(dir.path(), None).await;
        let a = tempfile::tempdir().unwrap();
        node.add_space("a", a.path()).unwrap();
        assert!(node.add_space("b", a.path().join("sub")).is_err());
        // Re-adding the same space id at the same path is a legal update.
        node.add_space("a", a.path()).unwrap();
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn trust_add_and_rebind() {
        let dir = node_dir();
        let node = spawn(dir.path(), None).await;
        let peer = SecretKey::generate().public();

        let origin = node.trust_add(peer, None, None, Some("laptop")).unwrap();
        assert_eq!(origin, OriginId::Key(peer));
        assert!(node.store().is_trusted_key(&peer, now_ns()).unwrap());
        // A key-identified origin cannot rotate.
        assert!(node
            .trust_rebind(&origin, SecretKey::generate().public())
            .is_err());

        let named = node
            .trust_add(peer, Some("nas"), Some("cluster.example"), None)
            .unwrap();
        let rotated = SecretKey::generate().public();
        node.trust_rebind(&named, rotated).unwrap();
        let keys = node.store().keys_for_origin(&named, now_ns()).unwrap();
        assert_eq!(keys.len(), 2, "the rotation window binds both keys");
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ad_updates_are_milestone_driven() {
        let dir = node_dir();
        let mut config = NodeConfig::loopback(dir.path());
        config.ad_update_interval = std::time::Duration::from_secs(3600);
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(config).await.unwrap();

        let root = node.store().ingest_bytes(b"payload", now_ns()).unwrap();
        // First sighting is always a milestone.
        assert!(node.ad_update_due(&root).unwrap());
        // A complete object re-advertises: completion is itself a milestone.
        assert!(node.ad_update_due(&root).unwrap());

        assert!(!node.ad_update_due(&Hash::new(b"never seen")).unwrap());
        let change = node.ad_change(&root).unwrap().unwrap();
        node.publish(&[change]).unwrap();
        assert!(node.published_ad(&root).unwrap().unwrap().is_complete());
        node.shutdown().await.unwrap();
    }

    #[test]
    fn addresses_round_trip_through_the_peers_table() {
        let id = SecretKey::generate().public();
        let addr = EndpointAddr::new(id).with_ip_addr("127.0.0.1:4433".parse().unwrap());
        let encoded = encode_addr(&addr);
        let back = decode_addr(id, &encoded).unwrap();
        assert_eq!(back.id, id);
        assert_eq!(
            back.ip_addrs().copied().collect::<Vec<_>>(),
            vec!["127.0.0.1:4433".parse().unwrap()]
        );
    }

    #[test]
    fn overlap_detection() {
        assert!(paths_overlap(Path::new("/a/b"), Path::new("/a")));
        assert!(paths_overlap(Path::new("/a"), Path::new("/a/b")));
        assert!(!paths_overlap(Path::new("/a"), Path::new("/b")));
    }

    #[tokio::test]
    async fn a_publish_that_fails_halfway_leaves_nothing_behind() {
        // §10: trie writes, head, history and materialization commit together
        // or not at all. A record the materializer cannot decode fails the
        // last of those steps, after the trie has been written, the head
        // signed, and both history rows inserted — exactly the window a crash
        // used to be able to land in.
        let dir = node_dir();
        let space = tempfile::tempdir().unwrap();
        let node = spawn(dir.path(), None).await;
        node.add_space("media", space.path()).unwrap();
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
        let (_, head) = node.scan_and_publish().unwrap();
        let before = head.unwrap();
        let entries_before = node
            .store()
            .list_entries(Some(node.origin()), "media", "", None, None)
            .unwrap();

        // A well-formed `f:` key whose value is not a `FileEntry`.
        let poison = vec![(
            file_key("media", "poisoned").unwrap(),
            Some(vec![0xffu8; 8]),
        )];
        let err = node.publish(&poison).unwrap_err().to_string();
        assert!(err.contains("corrupt record"), "{err}");

        // Nothing moved: not the head, not the history, not the views, not the
        // trie.
        assert_eq!(node.own_head().unwrap().unwrap(), before);
        assert_eq!(node.current_root().unwrap(), before.root);
        assert_eq!(node.store().head_history(node.origin()).unwrap().len(), 1);
        assert_eq!(
            node.store()
                .list_entries(Some(node.origin()), "media", "", None, None)
                .unwrap(),
            entries_before
        );
        assert!(node
            .store()
            .entry(node.origin(), "media", "poisoned")
            .unwrap()
            .is_none());

        // And a publish after it still works, from the head that survived.
        let after = node
            .publish(&[node.manifest_change().unwrap()])
            .unwrap()
            .unwrap();
        assert_eq!(after.seq, before.seq + 1);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_publish_shows_its_head_history_and_views_together() {
        let dir = node_dir();
        let node = spawn(dir.path(), None).await;
        let root = node
            .publish(&[node.manifest_change().unwrap()])
            .unwrap()
            .unwrap();
        // The head, its history row, and the materialized view of its leaves
        // all exist as of the same commit.
        assert_eq!(node.own_head().unwrap().unwrap().root, root.root);
        assert!(node
            .store()
            .head_history(node.origin())
            .unwrap()
            .iter()
            .any(|h| h.root == root.root));
        assert!(synch_mpt::NodeStore::has_node(node.store().as_ref(), &root.root).unwrap());
        assert!(node.manifest_of(node.origin()).unwrap().is_some());
        node.shutdown().await.unwrap();
    }
}
