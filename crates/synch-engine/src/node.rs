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
    net: Net,
    syncer: Syncer,
    origin: OriginId,
    secret: SecretKey,
    config: NodeConfig,
    ad_clock: std::sync::Mutex<std::collections::HashMap<Hash, i64>>,
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

    /// Opens an initialized data directory and binds the endpoint.
    pub async fn open(config: NodeConfig) -> Result<Node> {
        let store = Arc::new(Store::open(&config.data_dir)?);
        let origin = store.self_origin()?.ok_or(EngineError::NotInitialized)?;
        let secret = store
            .active_device_key()?
            .ok_or(EngineError::NoActiveKey)?
            .secret;
        let net = Net::bind(store.clone(), secret.clone(), config.net.clone()).await?;
        let syncer = Syncer::new(store.clone());
        Ok(Node {
            inner: Arc::new(NodeInner {
                store,
                net,
                syncer,
                origin,
                secret,
                config,
                ad_clock: std::sync::Mutex::new(Default::default()),
            }),
        })
    }

    /// The metadata and content store.
    pub fn store(&self) -> &Arc<Store> {
        &self.inner.store
    }

    /// The endpoint.
    pub fn net(&self) -> &Net {
        &self.inner.net
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
        self.inner.secret.public()
    }

    /// The configuration this node was opened with.
    pub fn config(&self) -> &NodeConfig {
        &self.inner.config
    }

    /// Shuts the endpoint down cleanly.
    pub async fn shutdown(&self) -> Result<()> {
        self.inner.net.shutdown().await?;
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
            if paths_overlap(&path, Path::new(&mirror.local_path)) {
                return Err(EngineError::invalid(format!(
                    "space root {} overlaps mirror {}",
                    path.display(),
                    mirror.local_path
                )));
            }
        }
        for space in self.store().spaces()? {
            if space.id != id && paths_overlap(&path, Path::new(&space.local_path)) {
                return Err(EngineError::invalid(format!(
                    "space root {} overlaps space {}",
                    path.display(),
                    space.id
                )));
            }
        }
        self.store().put_space(id, &path.to_string_lossy())?;
        Ok(())
    }

    /// Removes a space and its published entries.
    pub fn remove_space(&self, id: &str) -> Result<Vec<StagedChange>> {
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
        Ok(staged)
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
    pub fn next_seq(&self) -> Result<u64> {
        Ok(self
            .store()
            .complete_head(self.origin())?
            .map(|h| h.seq + 1)
            .unwrap_or(1))
    }

    /// Applies staged changes as one new signed root (§7.1).
    ///
    /// One save in an editor costs one head; a 100k-file initial index costs a
    /// handful, because the batch becomes a single root.
    pub fn publish(&self, staged: Vec<StagedChange>) -> Result<Option<SignedHead>> {
        if staged.is_empty() {
            return Ok(None);
        }
        let old_root = self.current_root()?;
        let trie = Trie::new(self.store().as_ref());
        let mut root = old_root;
        for (key, value) in &staged {
            root = match value {
                Some(v) => trie.insert(root, key, v)?,
                None => trie.remove(root, key)?,
            };
        }
        if root == old_root {
            return Ok(None);
        }
        let seq = self.next_seq()?;
        let head = SignedHead::sign(
            &self.inner.secret,
            self.origin().clone(),
            seq,
            root,
            now_ns(),
        );
        if let Some(previous) = self.store().complete_head(self.origin())? {
            self.store().record_history(&previous)?;
        }
        self.store()
            .put_head(Slot::Complete, &head, now_ns(), now_ns())?;
        self.store().record_history(&head)?;
        self.store()
            .materialize_diff(self.origin(), old_root, root)?;
        tracing::info!(seq, changes = staged.len(), "published a new root");
        Ok(Some(head))
    }

    /// Builds the `m:self` manifest record for this node (§4.2).
    pub fn manifest_change(&self) -> Result<StagedChange> {
        let mut spaces = Vec::new();
        for space in self.store().spaces()? {
            let count = self
                .store()
                .list_entries(Some(self.origin()), &space.id, "", None, None)?
                .len() as u64;
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
    std::fs::create_dir_all(path)?;
    Ok(std::fs::canonicalize(path)?)
}

/// True if either path contains the other.
pub fn paths_overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
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
            .publish(vec![(
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
            .publish(vec![(node.key_for("s", "a.txt").unwrap(), None)])
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
        assert!(node.publish(Vec::new()).unwrap().is_none());
        // A change that does not alter the root does not mint a head either.
        assert!(node
            .publish(vec![(node.key_for("s", "absent").unwrap(), None)])
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
        node.publish(vec![change]).unwrap().unwrap();

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
                &OriginId::named("nas", "x.example").unwrap(),
                "media",
                &shared.path().to_string_lossy(),
            )
            .unwrap();
        let err = node.add_space("media", shared.path()).unwrap_err();
        assert!(err.to_string().contains("overlaps mirror"));

        // And a nested subdirectory is caught too, so "no echo" is structural.
        let nested = shared.path().join("sub");
        assert!(node.add_space("nested", &nested).is_err());
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
        node.publish(vec![change]).unwrap();
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
}
