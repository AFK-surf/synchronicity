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
use synch_net::Net;

use crate::reconcile::Syncer;
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
    /// Content roots that provider discovery has failed to resolve, and when
    /// each may be asked about again (§6.3).
    ///
    /// Discovery walks every dialable peer, and it is entered whenever no local
    /// ad covers a root — so a root nobody holds is re-planned by every mirror
    /// pass and re-dials the whole cluster, forever. An origin publishing `f:`
    /// records whose content hashes name nothing therefore starves the victim's
    /// mirror of the passes that would have done real work, and `trust rm` does
    /// not clear it because what has already been published is retained for
    /// `root_retention`. The entries expire, so a root that later becomes
    /// available is picked up.
    provider_misses: std::sync::Mutex<std::collections::HashMap<Hash, ProviderMiss>>,
    /// What the running mirror passes believe about the file at each target
    /// path, and the stat that belief is anchored to — so a quiet pass can
    /// skip re-hashing every file it has already written or read
    /// (`docs/DELTA-SYNC.md` §3.5).
    mirror_writes: std::sync::Mutex<std::collections::HashMap<PathBuf, MirrorWrite>>,
    /// When each configured membership domain is next due for re-resolution,
    /// and when it was last attempted (§3.2, §3.4).
    dns: std::sync::Mutex<std::collections::HashMap<String, crate::membership::DomainSchedule>>,
    /// Rung when an inbound connection is refused for an unknown device key,
    /// which §3.4 makes a trigger for an immediate DNS re-resolution.
    dns_wake: Arc<tokio::sync::Notify>,
    /// The one resolver every membership refresh in this process goes through —
    /// the scheduled loop and every control request alike — or why there is
    /// none.
    ///
    /// One, not one per request: the resolver holds when it last walked the TUF
    /// repository, and that bound is what keeps a Sigstore outage costing one
    /// attempt a day instead of one per command (§10.2). And a process that
    /// could not build one refreshes nothing at all, which is a state `doctor`
    /// and `daemon status` have to be able to name.
    dns_resolver: std::sync::Mutex<crate::membership::ResolverSlot>,
    /// Rung when the unified tree may have changed — an accepted head flipped
    /// complete, a local publish landed, a mirror was added — so the standing
    /// mirror loop materializes it without waiting out its interval (§7.2).
    mirror_wake: Arc<tokio::sync::Notify>,
    /// Serializes mirror passes, whether the standing loop or `synch mirror
    /// sync` asked: two passes over one root would plan against each other's
    /// half-written state.
    mirror_lock: tokio::sync::Mutex<()>,
    /// Rung when a space is added or removed, so the watcher re-registers
    /// without waiting for the next filesystem hint (§7.1).
    spaces_changed: Arc<tokio::sync::Notify>,
    /// What the cloud-attach task has achieved per membership domain.
    ///
    /// In memory and nowhere else: a stored table of live connections is a
    /// lie the moment the process dies, and `synch cloud status` is asking
    /// what this daemon is doing now.
    cloud: std::sync::Mutex<std::collections::HashMap<String, crate::cloud::CloudDomainStatus>>,
}

/// What mirror passes believe about the file at one target, and the stat
/// that belief is anchored to.
///
/// See [`Node::note_mirror_write`] for why a pass remembers anything at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MirrorWrite {
    /// The content root the file is believed to be.
    pub(crate) content: Hash,
    /// The file's length when recorded.
    pub(crate) size: u64,
    /// The file's stored mtime when recorded.
    pub(crate) mtime_ns: i64,
    /// The file's platform identity when recorded (dev+inode on unix).
    pub(crate) file_id: Option<Vec<u8>>,
    /// When the record was taken: the racy-window anchor.
    pub(crate) recorded_at: i64,
}

impl MirrorWrite {
    /// A record for the file now at `target`, believed to be `content`: the
    /// stat the belief is anchored to, taken just after the write or hash
    /// that established it. `None` if the file is already gone, in which case
    /// there is nothing to anchor.
    pub(crate) fn of(target: &Path, content: Hash) -> Option<MirrorWrite> {
        let stat = std::fs::metadata(target).ok().filter(|m| m.is_file())?;
        Some(MirrorWrite {
            content,
            size: stat.len(),
            mtime_ns: crate::scanner::mtime_nanos(&stat),
            file_id: crate::scanner::file_identity(&stat),
            recorded_at: synch_core::now_ns(),
        })
    }
}

/// A content root discovery could not resolve, and how long to leave it alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderMiss {
    /// When this root may be asked about again, in unix nanoseconds.
    pub(crate) until: i64,
    /// How many discovery rounds have come back with nothing, which is what
    /// the backoff doubles on.
    pub(crate) misses: u32,
}

/// How long a root nobody could name a provider for is left alone before the
/// next attempt, doubling per failure up to [`PROVIDER_MISS_MAX_BACKOFF`].
pub(crate) const PROVIDER_MISS_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);

/// The ceiling on that backoff. Bounded rather than permanent: a root nobody
/// holds today may be published tomorrow, and a negative cache that never
/// lets go is a worse fault than the polling it replaced.
pub(crate) const PROVIDER_MISS_MAX_BACKOFF: std::time::Duration =
    std::time::Duration::from_secs(3600);

/// How many roots the negative cache remembers.
///
/// It is fed by what other origins publish, so it needs a bound of its own; the
/// entry nearest to expiring is the one dropped, since it is the one whose
/// suppression is worth least.
pub(crate) const MAX_PROVIDER_MISSES: usize = 4096;

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
        // One transaction, as §10 requires of every multi-step state change.
        // As seven autocommit writes, a crash after the head slots are cleared
        // but before the views are would leave `entries` rows for an origin
        // with no head in either slot — and nothing removes those:
        // `rebuild_views` iterates the complete slots, so an origin with
        // neither is never visited, and the command refuses to run twice. The
        // unified tree reads `entries` regardless of heads, so every path would
        // stay duplicated under both identities, in every mirror, permanently.
        let adopted = origin.clone();
        let now = now_ns();
        store.transaction(|txn| -> Result<()> {
            txn.set_self_origin(&adopted)?;
            txn.remove_binding(&previous, &node_id, BindingSource::Static)?;
            txn.put_binding(&Binding {
                origin: adopted.clone(),
                node_id,
                source: BindingSource::Static,
                domain: None,
                note: Some("self".into()),
                added_at: now,
                expires_at: None,
            })?;
            // Drop the key-origin view so the unified tree does not keep a
            // second copy of every path under the old name. Blobs stay; the
            // next scan republishes them under the new origin.
            txn.clear_head(&previous, Slot::Complete)?;
            txn.clear_head(&previous, Slot::Pending)?;
            txn.delete_origin_entries(&previous)?;
            txn.delete_origin_providers(&previous)?;
            Ok(())
        })?;
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
        // Every head that flips to complete — dialed out or pushed in — rings
        // the mirror bell. One syncer does both: it is handed to the endpoint
        // as the head sink the serve side reconciles through, and it is the
        // same object this node's own rounds dial with.
        let mirror_wake = Arc::new(tokio::sync::Notify::new());
        let syncer = Syncer::new(store.clone()).on_change(Some(mirror_wake.clone()));
        config.net.heads = Some(Arc::new(syncer.clone()) as Arc<dyn synch_net::HeadSink>);
        let net = Net::bind(store.clone(), secret.clone(), config.net.clone()).await?;
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
                provider_misses: std::sync::Mutex::new(Default::default()),
                mirror_writes: std::sync::Mutex::new(Default::default()),
                dns: std::sync::Mutex::new(Default::default()),
                dns_resolver: std::sync::Mutex::new(Default::default()),
                dns_wake,
                mirror_wake,
                mirror_lock: tokio::sync::Mutex::new(()),
                spaces_changed: Arc::new(tokio::sync::Notify::new()),
                cloud: std::sync::Mutex::new(Default::default()),
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

    /// The bell that wakes the standing mirror loop (§7.2).
    pub(crate) fn mirror_wake(&self) -> Arc<tokio::sync::Notify> {
        self.inner.mirror_wake.clone()
    }

    /// Serializes a mirror pass against every other pass on this node.
    pub(crate) async fn lock_mirrors(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.mirror_lock.lock().await
    }

    /// Rings the unknown-key bell as an inbound refusal would.
    ///
    /// The endpoint rings it on its own; this is how a caller that already
    /// knows a binding is stale asks for the same re-resolution.
    pub fn trigger_dns_refresh(&self) {
        self.inner.dns_wake.notify_waiters();
    }

    /// The resolver slot every membership refresh in this process reads from.
    pub(crate) fn dns_resolver_slot(
        &self,
    ) -> std::sync::MutexGuard<'_, crate::membership::ResolverSlot> {
        self.inner
            .dns_resolver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What the cloud-attach task has achieved per membership domain.
    pub(crate) fn cloud_slot(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, crate::cloud::CloudDomainStatus>>
    {
        self.inner
            .cloud
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    /// and materialization commit together or not at all". Without that, a
    /// crash between any two of those steps leaves a head whose trie is
    /// half-written, or a head slot the derived views do not agree with.
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
                // No explicit history writes: `put_head` records the signature
                // it is pointing at, and the head being displaced recorded its
                // own when it took the slot (§10, v11).
                txn.put_head(Slot::Complete, &head, now, now)?;
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

    /// Records what a mirror pass believes about the file at `target`, and
    /// the stat that belief is anchored to (`docs/DELTA-SYNC.md` §3.5).
    ///
    /// The belief comes from one of two moments: the pass wrote the file
    /// itself (a successful write is trusted, the same at-rest posture the
    /// CAS takes toward its own payloads, §2.1), or the pass found the file
    /// on disk and hashed it to the selected root. Either way the record lets
    /// later passes answer "is this already the selected version?" with a
    /// stat instead of a hash, so a quiet pass costs the tree's syscalls, not
    /// its bytes. The stat is the evidence the scanner trusts for the node's
    /// own files — length, stored mtime, platform identity, past the racy
    /// window — with a stronger anchor than the scanner's: not a
    /// peer-published mtime that happens to match, but a write or hash this
    /// process performed itself.
    ///
    /// Two limits, both deliberate:
    ///
    /// - **In memory, per process.** Nothing durable ever calls a file good,
    ///   so there is no stale verdict to clear. The price is paid on restart:
    ///   every mirror's first pass hashes the whole tree once, and that pass
    ///   doubles as the mirror's only scrub.
    /// - **A stat that never moved hides what lies beneath it.** A same-size
    ///   rewrite that restores length, mtime, and identity — and bytes that
    ///   rot at rest behind an unmoved stat, including a CAS payload already
    ///   rotted before a pass wrote from it — are invisible until the next
    ///   restart's hash. That is the filesystem-integrity domain, and §2.1
    ///   delegates it there.
    pub(crate) fn note_mirror_write(&self, target: &Path, write: MirrorWrite) {
        self.mirror_writes().insert(target.to_path_buf(), write);
    }

    /// What passes believe about `target`, if this process believes anything.
    pub(crate) fn mirror_write_was(&self, target: &Path) -> Option<MirrorWrite> {
        self.mirror_writes().get(target).cloned()
    }

    /// Forgets what was believed about `target` — called when the file leaves
    /// the mirror, when the file is gone or the wrong length, and when a
    /// fresh write or hash re-anchors the belief.
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

    /// True if provider discovery for this root is still backed off (§6.3).
    ///
    /// Asked before dialling anybody. Callers reach discovery only when no
    /// local ad covers the root, so a root that becomes available through
    /// ordinary head replication is fetched without ever consulting this.
    pub(crate) fn provider_discovery_backed_off(&self, root: &Hash, now: i64) -> bool {
        self.provider_misses()
            .get(root)
            .is_some_and(|miss| now < miss.until)
    }

    /// Records that discovery found nobody for this root, doubling the wait.
    pub(crate) fn note_provider_miss(&self, root: &Hash, now: i64) {
        let mut misses = self.provider_misses();
        let previous = misses.get(root).map(|m| m.misses).unwrap_or(0);
        let backoff = PROVIDER_MISS_BACKOFF
            .saturating_mul(1u32 << previous.min(16))
            .min(PROVIDER_MISS_MAX_BACKOFF);
        let entry = ProviderMiss {
            until: now.saturating_add(backoff.as_nanos() as i64),
            misses: previous.saturating_add(1),
        };
        if misses.len() >= MAX_PROVIDER_MISSES && !misses.contains_key(root) {
            misses.retain(|_, miss| now < miss.until);
            if misses.len() >= MAX_PROVIDER_MISSES {
                if let Some(soonest) = misses
                    .iter()
                    .min_by_key(|(_, miss)| miss.until)
                    .map(|(root, _)| *root)
                {
                    misses.remove(&soonest);
                }
            }
        }
        misses.insert(*root, entry);
    }

    /// Forgets a miss, because somebody turned out to hold the root after all.
    pub(crate) fn clear_provider_miss(&self, root: &Hash) {
        self.provider_misses().remove(root);
    }

    fn provider_misses(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<Hash, ProviderMiss>> {
        self.inner
            .provider_misses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        // signed, and both history rows inserted — exactly the window an
        // untransacted publish would let a crash land in.
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
