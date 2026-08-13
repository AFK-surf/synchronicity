//! DNSSEC membership domains and the `synch doctor` report (§3.2, §9.2, §12).

use std::time::Duration;

use synch_core::{now_ns, NodeId, OriginId};
use synch_net::dns::{DnssecResolver, MemberSet, DEFAULT_TRUST_GRACE};
use synch_store::{Binding, BindingSource, Equivocation};

use crate::{
    error::{EngineError, Result},
    node::Node,
    recovery::{RecoveryState, UnreconciledHistory},
};

/// The config key holding the configured membership domains.
const DOMAINS_KEY: &str = "membership_domains";

/// What one domain refresh did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRefresh {
    /// The domain refreshed.
    pub domain: String,
    /// Bindings written or extended.
    pub bindings: usize,
    /// Device keys that appear under more than one identity (§3.2).
    pub ambiguous: Vec<NodeId>,
    /// TXT records that could not be parsed.
    pub rejected: usize,
    /// How long the answer is good for.
    pub ttl: Duration,
}

/// A `synch doctor` report.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    /// This node's origin.
    pub origin: OriginId,
    /// This node's device keys and their states.
    pub device_keys: Vec<(NodeId, String)>,
    /// Every binding, live or lapsed.
    pub bindings: Vec<Binding>,
    /// Bindings whose expiry has passed.
    pub lapsed: Vec<Binding>,
    /// The complete head of every known origin, with whether we can serve it.
    pub heads: Vec<HeadStatus>,
    /// Detected same-seq forks, with both signed heads as proof (§4.4).
    pub equivocations: Vec<Equivocation>,
    /// Origins whose heads we hold but which have no live binding — their data
    /// is unavailable until the origin republishes under a bound key (§3.4).
    pub unbound_origins: Vec<OriginId>,
    /// Whether this node is itself in key-loss recovery, and how far peers say
    /// its origin had got (§3.4).
    pub recovery: RecoveryState,
    /// Pre-recovery history we hold that the origin's current head does not
    /// supersede: the fork side of someone else's recovery (§3.4, §4.4).
    pub unreconciled: Vec<UnreconciledHistory>,
    /// Configured membership domains.
    pub domains: Vec<String>,
    /// Trie and content storage counts.
    pub trie: synch_store::TrieStats,
    /// How many objects are held locally, and how many are complete.
    pub blobs: (usize, usize),
}

/// One origin's head state.
#[derive(Debug, Clone)]
pub struct HeadStatus {
    /// The origin.
    pub origin: OriginId,
    /// The complete head's seq, if any.
    pub complete_seq: Option<u64>,
    /// A pending head's seq, if a fetch is in progress.
    pub pending_seq: Option<u64>,
    /// True if we hold the full trie under the complete head and can serve it.
    pub servable: bool,
    /// True if at least one device key is currently bound to the origin.
    pub bound: bool,
    /// How many entries the origin publishes, across all spaces.
    pub entries: usize,
}

impl Node {
    /// The configured DNSSEC membership domains.
    pub fn domains(&self) -> Result<Vec<String>> {
        Ok(self
            .store()
            .config(DOMAINS_KEY)?
            .map(|text| {
                text.split('\n')
                    .filter(|d| !d.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Adds a membership domain.
    pub fn add_domain(&self, domain: &str) -> Result<()> {
        let domain = synch_core::origin::normalize_domain(domain)
            .map_err(|e| EngineError::invalid(e.to_string()))?;
        let mut domains = self.domains()?;
        if !domains.contains(&domain) {
            domains.push(domain);
            domains.sort();
        }
        self.store().set_config(DOMAINS_KEY, &domains.join("\n"))?;
        Ok(())
    }

    /// Removes a membership domain and every binding it produced.
    pub fn remove_domain(&self, domain: &str) -> Result<bool> {
        let domain = synch_core::origin::normalize_domain(domain)
            .map_err(|e| EngineError::invalid(e.to_string()))?;
        let mut domains = self.domains()?;
        let before = domains.len();
        domains.retain(|d| d != &domain);
        self.store().set_config(DOMAINS_KEY, &domains.join("\n"))?;
        for binding in self.store().bindings()? {
            if binding.source == BindingSource::Dns && binding.domain.as_deref() == Some(&domain) {
                self.store().remove_binding(
                    &binding.origin,
                    &binding.node_id,
                    BindingSource::Dns,
                )?;
            }
        }
        Ok(domains.len() != before)
    }

    /// Re-resolves one domain and refreshes its bindings.
    ///
    /// The whole answer is discarded unless it validates end to end; bindings
    /// that merely vanished from DNS keep their existing expiry so a
    /// propagation glitch cannot shrink the member set (§3.2).
    pub async fn refresh_domain(
        &self,
        resolver: &DnssecResolver,
        domain: &str,
    ) -> Result<DomainRefresh> {
        let (set, ttl) = resolver.member_set(domain).await?;
        self.apply_member_set(&set, ttl)
    }

    /// Applies an already-validated member set to the bindings table.
    ///
    /// Exposed separately so the §3.2 rules can be exercised without live DNS.
    pub fn apply_member_set(&self, set: &MemberSet, ttl: Duration) -> Result<DomainRefresh> {
        let expires_at =
            now_ns() + (ttl + DEFAULT_TRUST_GRACE).as_nanos().min(i64::MAX as u128) as i64;
        let bindings: Vec<Binding> = set
            .bindings
            .iter()
            .map(|(origin, key)| Binding {
                origin: origin.clone(),
                node_id: *key,
                source: BindingSource::Dns,
                domain: Some(set.domain.clone()),
                note: None,
                added_at: now_ns(),
                expires_at: Some(expires_at),
            })
            .collect();
        self.store().refresh_dns_bindings(&set.domain, &bindings)?;

        // Dialing hints from the record set (§3.3) are recorded as peer
        // addresses so the very first dial can succeed without discovery.
        for (key_bytes, hints) in &set.hints {
            let Ok(key) = NodeId::from_bytes(key_bytes) else {
                continue;
            };
            let mut addr = iroh::EndpointAddr::new(key);
            for hint in hints {
                if let Ok(socket) = hint.parse() {
                    addr = addr.with_ip_addr(socket);
                } else if let Ok(url) = hint.parse() {
                    addr = addr.with_relay_url(url);
                }
            }
            if !addr.is_empty() {
                self.remember_peer(&addr)?;
            }
        }

        Ok(DomainRefresh {
            domain: set.domain.clone(),
            bindings: bindings.len(),
            ambiguous: set.ambiguous_keys.clone(),
            rejected: set.rejected.len(),
            ttl,
        })
    }

    /// Refreshes every configured domain.
    pub async fn refresh_domains(&self, resolver: &DnssecResolver) -> Result<Vec<DomainRefresh>> {
        let mut out = Vec::new();
        for domain in self.domains()? {
            match self.refresh_domain(resolver, &domain).await {
                Ok(refresh) => out.push(refresh),
                Err(e) => {
                    // Fail closed: keep the cached member set until it expires
                    // on its own rather than shrinking on a resolver hiccup.
                    tracing::warn!(domain, error = %e, "membership refresh failed; keeping cached bindings");
                }
            }
        }
        Ok(out)
    }

    /// Builds the `synch doctor` report.
    pub fn doctor(&self) -> Result<DoctorReport> {
        let now = now_ns();
        let bindings = self.store().bindings()?;
        let lapsed: Vec<Binding> = bindings
            .iter()
            .filter(|b| !b.is_live(now))
            .cloned()
            .collect();

        let mut heads = Vec::new();
        let mut unbound_origins = Vec::new();
        let mut origins: Vec<OriginId> = self
            .store()
            .all_heads(synch_store::Slot::Complete)?
            .into_iter()
            .map(|s| s.head.origin)
            .collect();
        for stored in self.store().all_heads(synch_store::Slot::Pending)? {
            if !origins.contains(&stored.head.origin) {
                origins.push(stored.head.origin);
            }
        }
        for origin in self.store().trusted_origins(now)? {
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        origins.sort();

        let trie = synch_mpt::Trie::new(self.store().as_ref());
        let mut unreconciled = Vec::new();
        for origin in origins {
            unreconciled.extend(self.unreconciled_history(&origin)?);
            let complete = self.store().complete_head(&origin)?;
            let pending = self.store().pending_head(&origin)?;
            let servable = match &complete {
                Some(head) => trie.is_complete(head.root)?,
                None => false,
            };
            let bound = !self.store().keys_for_origin(&origin, now)?.is_empty();
            if !bound && complete.is_some() {
                unbound_origins.push(origin.clone());
            }
            let mut entries = 0;
            for space in self.store().known_spaces()? {
                entries += self
                    .store()
                    .list_entries(Some(&origin), &space, "", None, None)?
                    .len();
            }
            heads.push(HeadStatus {
                origin,
                complete_seq: complete.map(|h| h.seq),
                pending_seq: pending.map(|h| h.seq),
                servable,
                bound,
                entries,
            });
        }

        let blobs = self.store().blobs()?;
        let complete_blobs = blobs.iter().filter(|b| b.complete).count();

        Ok(DoctorReport {
            origin: self.origin().clone(),
            device_keys: self
                .store()
                .device_keys()?
                .into_iter()
                .map(|k| (k.node_id, k.state.as_str().to_string()))
                .collect(),
            bindings,
            lapsed,
            heads,
            equivocations: self.store().equivocations()?,
            unbound_origins,
            recovery: self.recovery_state()?,
            unreconciled,
            domains: self.domains()?,
            trie: self.store().trie_stats()?,
            blobs: (blobs.len(), complete_blobs),
        })
    }

    /// Rebuilds `entries` and `blob_providers` from the authoritative trie
    /// (`synch doctor --rebuild`, §10).
    pub fn rebuild_views(&self) -> Result<usize> {
        let mut total = 0;
        for stored in self.store().all_heads(synch_store::Slot::Complete)? {
            total += self
                .store()
                .rematerialize(&stored.head.origin, stored.head.root)?;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use iroh_base::SecretKey;

    async fn node() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        (dir, node)
    }

    #[tokio::test]
    async fn domains_round_trip() {
        let (_d, node) = node().await;
        assert!(node.domains().unwrap().is_empty());
        node.add_domain("Cluster.Example.COM.").unwrap();
        node.add_domain("cluster.example.com").unwrap();
        assert_eq!(node.domains().unwrap(), vec!["cluster.example.com"]);
        assert!(node.remove_domain("cluster.example.com").unwrap());
        assert!(node.domains().unwrap().is_empty());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn applying_a_member_set_writes_dns_bindings() {
        let (_d, node) = node().await;
        let nas = SecretKey::generate().public();
        let laptop = SecretKey::generate().public();
        let records = vec![
            format!("v=sync1 id=nas nk={} addr=127.0.0.1:5555", nas.to_z32()),
            format!("v=sync1 id=laptop nk={}", laptop.to_z32()),
        ];
        let set = MemberSet::from_records("cluster.example", &records).unwrap();
        let refresh = node
            .apply_member_set(&set, Duration::from_secs(300))
            .unwrap();
        assert_eq!(refresh.bindings, 2);
        assert!(refresh.ambiguous.is_empty());

        let origin = OriginId::named("nas", "cluster.example").unwrap();
        assert!(node.store().is_bound(&origin, &nas, now_ns()).unwrap());
        // The addr hint became a dialable address.
        let addr = node.peer_addr(&nas).unwrap().unwrap();
        assert_eq!(addr.ip_addrs().count(), 1);

        // Removing the domain drops exactly its bindings, leaving self intact.
        node.add_domain("cluster.example").unwrap();
        node.remove_domain("cluster.example").unwrap();
        assert!(!node.store().is_bound(&origin, &nas, now_ns()).unwrap());
        assert!(node
            .store()
            .is_bound(node.origin(), &node.node_id(), now_ns())
            .unwrap());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn dns_bindings_expire_after_ttl_plus_grace() {
        let (_d, node) = node().await;
        let nas = SecretKey::generate().public();
        let set = MemberSet::from_records(
            "cluster.example",
            &[format!("v=sync1 id=nas nk={}", nas.to_z32())],
        )
        .unwrap();
        node.apply_member_set(&set, Duration::from_secs(60))
            .unwrap();
        let origin = OriginId::named("nas", "cluster.example").unwrap();
        assert!(node.store().is_bound(&origin, &nas, now_ns()).unwrap());
        let far_future = now_ns() + Duration::from_secs(3600).as_nanos() as i64;
        assert!(!node.store().is_bound(&origin, &nas, far_future).unwrap());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ambiguous_keys_bind_nothing_and_are_reported() {
        let (_d, node) = node().await;
        let key = SecretKey::generate().public();
        let set = MemberSet::from_records(
            "cluster.example",
            &[
                format!("v=sync1 id=nas nk={}", key.to_z32()),
                format!("v=sync1 id=laptop nk={}", key.to_z32()),
            ],
        )
        .unwrap();
        let refresh = node
            .apply_member_set(&set, Duration::from_secs(300))
            .unwrap();
        assert_eq!(refresh.bindings, 0);
        assert_eq!(refresh.ambiguous, vec![key]);
        assert!(!node.store().is_trusted_key(&key, now_ns()).unwrap());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn doctor_reports_the_basics() {
        let (_d, node) = node().await;
        let space = tempfile::tempdir().unwrap();
        node.add_space("media", space.path()).unwrap();
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
        node.scan_and_publish().unwrap();

        let report = node.doctor().unwrap();
        assert_eq!(report.origin, *node.origin());
        assert_eq!(report.device_keys.len(), 1);
        assert_eq!(report.device_keys[0].1, "active");
        assert_eq!(report.heads.len(), 1);
        assert_eq!(report.heads[0].complete_seq, Some(1));
        assert!(report.heads[0].servable);
        assert!(report.heads[0].bound);
        assert_eq!(report.heads[0].entries, 1);
        assert!(report.equivocations.is_empty());
        assert!(report.unbound_origins.is_empty());
        assert!(report.trie.nodes > 0);
        assert_eq!(report.blobs, (1, 1));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn doctor_surfaces_equivocation_and_unbound_origins() {
        let (_d, node) = node().await;
        let peer = SecretKey::generate();
        let origin = OriginId::named("nas", "x.example").unwrap();
        node.store()
            .put_binding(&Binding {
                origin: origin.clone(),
                node_id: peer.public(),
                source: BindingSource::Static,
                domain: None,
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();

        let syncer = node.syncer();
        for root in [synch_core::Hash([1u8; 32]), synch_core::Hash([2u8; 32])] {
            let head = synch_core::SignedHead::sign(&peer, origin.clone(), 5, root, 0);
            syncer.offer_head(&head, now_ns()).unwrap();
        }
        let report = node.doctor().unwrap();
        assert_eq!(report.equivocations.len(), 1);
        assert_eq!(report.equivocations[0].seq, 5);

        // Withdrawing trust leaves the head we already verified in place, but
        // flags the origin: its data is unavailable until it republishes under
        // a bound key (§3.4).
        node.store()
            .put_head(
                synch_store::Slot::Complete,
                &synch_core::SignedHead::sign(
                    &peer,
                    origin.clone(),
                    5,
                    synch_core::Hash([2u8; 32]),
                    0,
                ),
                0,
                0,
            )
            .unwrap();
        node.store().remove_origin_bindings(&origin).unwrap();
        let report = node.doctor().unwrap();
        assert!(report.unbound_origins.contains(&origin));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rebuild_restores_the_derived_views() {
        let (_d, node) = node().await;
        let space = tempfile::tempdir().unwrap();
        node.add_space("media", space.path()).unwrap();
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
        node.scan_and_publish().unwrap();

        node.store().delete_origin_entries(node.origin()).unwrap();
        assert!(node
            .store()
            .list_entries(Some(node.origin()), "media", "", None, None)
            .unwrap()
            .is_empty());

        node.rebuild_views().unwrap();
        assert_eq!(
            node.store()
                .list_entries(Some(node.origin()), "media", "", None, None)
                .unwrap()
                .len(),
            1
        );
        node.shutdown().await.unwrap();
    }
}
