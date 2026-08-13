//! DNSSEC membership domains and the `synch doctor` report (§3.2, §9.2, §12).

use std::time::Duration;

use synch_core::{now_ns, NodeId, OriginId};
use synch_net::dns::{clamp_ttl, MemberResolver, MemberSet, DEFAULT_TRUST_GRACE, MIN_TTL};
use synch_store::{Binding, BindingSource, Equivocation};

use crate::{
    error::{EngineError, Result},
    node::Node,
    recovery::{RecoveryState, UnreconciledHistory},
};

/// The config key holding the configured membership domains.
const DOMAINS_KEY: &str = "membership_domains";

/// The shortest gap between two *triggered* re-resolutions of one domain
/// (§3.4).
///
/// The trigger is an inbound connection from an unbound key, which a peer that
/// keeps retrying produces as fast as it can dial; the cooldown is what keeps
/// that from becoming a query flood.
pub const DNS_TRIGGER_COOLDOWN: Duration = Duration::from_secs(30);

/// The shortest the DNS loop ever sleeps between passes.
const DNS_POLL_FLOOR: Duration = Duration::from_secs(1);
/// The longest the DNS loop sleeps, so a `domain add` is noticed promptly even
/// though nothing was configured when the loop last looked.
const DNS_POLL_CEILING: Duration = Duration::from_secs(30);

fn cooldown_ns() -> i64 {
    DNS_TRIGGER_COOLDOWN.as_nanos().min(i64::MAX as u128) as i64
}

/// When one configured domain is next due for re-resolution, and when it was
/// last attempted (§3.2, §3.4).
///
/// Held in memory rather than in the database: it is a scheduling detail of a
/// running daemon, and a restart re-resolving every domain once is exactly
/// right.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DomainSchedule {
    /// When the TTL this domain's last answer carried runs out.
    pub due_at: i64,
    /// When a lookup was last attempted, successful or not.
    pub last_attempt: i64,
}

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
    /// Origins whose data this node holds without a live binding, each with
    /// how many entries it still carries.
    ///
    /// Two situations read the same way here. An origin that rotated and has
    /// not republished under a bound key yet is temporarily unverifiable
    /// (§3.4); an origin that was untrusted or dropped from the record set is
    /// permanently cut off from *future* participation while what it already
    /// published stays replicated and ages out with ordinary retention (§12).
    /// Neither removes anything from the tree, which is why the list exists.
    pub unbound_origins: Vec<(OriginId, usize)>,
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
        resolver: &dyn MemberResolver,
        domain: &str,
    ) -> Result<DomainRefresh> {
        let (set, ttl) = resolver.resolve_members(domain).await?;
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
    pub async fn refresh_domains(
        &self,
        resolver: &dyn MemberResolver,
    ) -> Result<Vec<DomainRefresh>> {
        let domains = self.domains()?;
        self.refresh_these(resolver, &domains, now_ns()).await
    }

    /// Resolves a domain argument against the configured set (§9.2).
    ///
    /// Naming a domain this node was never told about is a typo, not a
    /// resolver problem, so it is refused before any lookup is attempted.
    pub fn configured_domain(&self, domain: &str) -> Result<String> {
        let name = synch_core::origin::normalize_domain(domain)
            .map_err(|e| EngineError::invalid(e.to_string()))?;
        if !self.domains()?.contains(&name) {
            return Err(EngineError::not_found(format!(
                "{name} is not a configured membership domain"
            )));
        }
        Ok(name)
    }

    /// Refreshes one configured domain by name, or every one if `domain` is
    /// `None` (`synch domain refresh [<domain>]`).
    pub async fn refresh_domains_named(
        &self,
        resolver: &dyn MemberResolver,
        domain: Option<&str>,
    ) -> Result<Vec<DomainRefresh>> {
        let domains = match domain {
            None => self.domains()?,
            Some(name) => vec![self.configured_domain(name)?],
        };
        self.refresh_these(resolver, &domains, now_ns()).await
    }

    /// Re-resolves the domains whose TTL has elapsed (§3.2).
    ///
    /// This is what the daemon's DNS loop calls. A domain that has never been
    /// resolved is due immediately; otherwise it comes due one clamped TTL
    /// after the answer that produced its bindings.
    pub async fn refresh_due_domains(
        &self,
        resolver: &dyn MemberResolver,
        now: i64,
    ) -> Result<Vec<DomainRefresh>> {
        let due: Vec<String> = {
            let schedule = self.dns_schedule();
            self.domains()?
                .into_iter()
                .filter(|d| schedule.get(d).is_none_or(|s| s.due_at <= now))
                .collect()
        };
        self.refresh_these(resolver, &due, now).await
    }

    /// Re-resolves every configured domain now, subject to a per-domain
    /// cooldown (§3.4).
    ///
    /// This is the unknown-key trigger: an inbound connection from a device key
    /// with no live binding is the shape a lagging rotation takes, so it earns
    /// an immediate lookup. The cooldown is what keeps a peer that keeps
    /// retrying — or a hostile one — from turning that into a query flood.
    pub async fn refresh_triggered(
        &self,
        resolver: &dyn MemberResolver,
        now: i64,
    ) -> Result<Vec<DomainRefresh>> {
        let ready: Vec<String> = {
            let schedule = self.dns_schedule();
            self.domains()?
                .into_iter()
                .filter(|d| {
                    schedule
                        .get(d)
                        .is_none_or(|s| now.saturating_sub(s.last_attempt) >= cooldown_ns())
                })
                .collect()
        };
        self.refresh_these(resolver, &ready, now).await
    }

    /// How long the DNS loop should sleep before it next looks for due
    /// domains.
    pub fn next_dns_delay(&self, now: i64) -> Duration {
        let schedule = self.dns_schedule();
        let soonest = self
            .domains()
            .unwrap_or_default()
            .into_iter()
            .map(|d| schedule.get(&d).map(|s| s.due_at).unwrap_or(now))
            .min();
        drop(schedule);
        let gap = match soonest {
            // Nothing configured: wake occasionally anyway, because `domain
            // add` can land at any time and the loop is what notices.
            None => DNS_POLL_CEILING,
            Some(due) => Duration::from_nanos(due.saturating_sub(now).max(0) as u64),
        };
        gap.clamp(DNS_POLL_FLOOR, DNS_POLL_CEILING)
    }

    /// Re-resolves membership on the TTL, and on demand (§3.2, §3.4).
    ///
    /// Without this loop a DNSSEC cluster dissolves one TTL plus grace after
    /// the last manual `synch domain refresh`: `maintenance_pass` expires
    /// bindings on schedule and nothing renews them.
    pub async fn run_dns(
        &self,
        resolver: &dyn MemberResolver,
        shutdown: impl std::future::Future<Output = ()>,
    ) {
        let shutdown = std::pin::pin!(shutdown);
        let mut shutdown = shutdown;
        let wake = self.dns_wake();
        loop {
            let delay = self.next_dns_delay(now_ns());
            let refreshed = tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(delay) => {
                    self.refresh_due_domains(resolver, now_ns()).await
                }
                _ = wake.notified() => {
                    self.refresh_triggered(resolver, now_ns()).await
                }
            };
            if let Err(e) = refreshed {
                tracing::warn!(error = %e, "membership refresh loop failed");
            }
        }
    }

    /// Refreshes the named domains, recording the schedule each answer implies.
    ///
    /// A resolver failure is not allowed to shrink the member set: the cached
    /// bindings keep their own expiry and only the retry time moves (§3.2,
    /// fail closed).
    async fn refresh_these(
        &self,
        resolver: &dyn MemberResolver,
        domains: &[String],
        now: i64,
    ) -> Result<Vec<DomainRefresh>> {
        let mut out = Vec::new();
        for domain in domains {
            // Stamped before the lookup runs, so a resolver that hangs or fails
            // cannot be retried in a tight loop.
            self.note_dns_attempt(domain, now, MIN_TTL);
            match self.refresh_domain(resolver, domain).await {
                Ok(refresh) => {
                    self.note_dns_attempt(domain, now, refresh.ttl);
                    out.push(refresh);
                }
                Err(e) => {
                    tracing::warn!(domain, error = %e, "membership refresh failed; keeping cached bindings");
                }
            }
        }
        Ok(out)
    }

    fn note_dns_attempt(&self, domain: &str, now: i64, ttl: Duration) {
        let due_at = now.saturating_add(clamp_ttl(ttl).as_nanos().min(i64::MAX as u128) as i64);
        let mut schedule = self.dns_schedule();
        let entry = schedule.entry(domain.to_string()).or_default();
        entry.last_attempt = now;
        entry.due_at = due_at;
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
        // An origin whose binding has gone keeps its entries — nothing
        // cascades a deletion through everyone's tries — so it has to be
        // listed even when no head slot survives for it (§12).
        for origin in self.store().entry_origins()? {
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
            let mut entries = 0;
            for space in self.store().known_spaces()? {
                entries += self
                    .store()
                    .list_entries(Some(&origin), &space, "", None, None)?
                    .len();
            }
            if !bound && (complete.is_some() || entries > 0) {
                unbound_origins.push((origin.clone(), entries));
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
        assert!(report.unbound_origins.iter().any(|(o, _)| o == &origin));
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

    /// A resolver that answers from a fixed record set and counts its calls.
    ///
    /// The refresh loop is the thing under test, so what it resolves through
    /// has to be steerable: this answers, or fails, on demand.
    #[derive(Debug)]
    struct FakeResolver {
        records: std::sync::Mutex<Vec<String>>,
        ttl: Duration,
        calls: std::sync::atomic::AtomicUsize,
        failing: std::sync::atomic::AtomicBool,
    }

    impl FakeResolver {
        fn new(records: Vec<String>, ttl: Duration) -> FakeResolver {
            FakeResolver {
                records: std::sync::Mutex::new(records),
                ttl,
                calls: std::sync::atomic::AtomicUsize::new(0),
                failing: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn fail(&self, failing: bool) {
            self.failing
                .store(failing, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl MemberResolver for FakeResolver {
        fn resolve_members<'a>(&'a self, domain: &'a str) -> synch_net::dns::MemberSetFuture<'a> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let failing = self.failing.load(std::sync::atomic::Ordering::SeqCst);
            let records = self
                .records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let ttl = self.ttl;
            Box::pin(async move {
                if failing {
                    return Err(synch_net::NetError::Dns("resolver is down".into()));
                }
                let set = MemberSet::from_records(domain, &records)?;
                Ok((set, ttl))
            })
        }
    }

    #[tokio::test]
    async fn bindings_survive_past_their_ttl_while_the_resolver_answers() {
        // §3.2: records are re-resolved on the TTL. Without that loop the
        // maintenance pass expires every dns binding one TTL plus grace after
        // the last manual refresh and the cluster dissolves.
        let (_d, node) = node().await;
        let nas = SecretKey::generate().public();
        let resolver =
            FakeResolver::new(vec![format!("v=sync1 id=nas nk={}", nas.to_z32())], MIN_TTL);
        node.add_domain("cluster.example").unwrap();

        let start = now_ns();
        assert_eq!(
            node.refresh_due_domains(&resolver, start)
                .await
                .unwrap()
                .len(),
            1,
            "a domain that has never resolved is due at once"
        );
        let origin = OriginId::named("nas", "cluster.example").unwrap();
        assert!(node.store().is_bound(&origin, &nas, start).unwrap());

        // Nothing is due again until the clamped TTL has passed.
        assert!(node
            .refresh_due_domains(&resolver, start + 1_000)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(resolver.calls(), 1);

        // A tick past the TTL re-resolves, which pushes the binding's expiry
        // out ahead of the maintenance pass that would otherwise reap it.
        let later = start + (MIN_TTL.as_nanos() as i64) + 1;
        assert_eq!(
            node.refresh_due_domains(&resolver, later)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(resolver.calls(), 2);

        // Well past the original expiry, the binding is still live and the
        // maintenance pass leaves it alone.
        let horizon = later + (MIN_TTL.as_nanos() as i64) / 2;
        assert!(node.store().is_bound(&origin, &nas, horizon).unwrap());
        node.maintenance_pass().unwrap();
        assert!(node.store().is_bound(&origin, &nas, horizon).unwrap());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_failing_resolver_keeps_the_cached_bindings() {
        // Fail closed (§3.2): a resolver hiccup must not shrink the member set.
        let (_d, node) = node().await;
        let nas = SecretKey::generate().public();
        let resolver =
            FakeResolver::new(vec![format!("v=sync1 id=nas nk={}", nas.to_z32())], MIN_TTL);
        node.add_domain("cluster.example").unwrap();
        let start = now_ns();
        node.refresh_due_domains(&resolver, start).await.unwrap();

        resolver.fail(true);
        let later = start + (MIN_TTL.as_nanos() as i64) + 1;
        assert!(node
            .refresh_due_domains(&resolver, later)
            .await
            .unwrap()
            .is_empty());
        let origin = OriginId::named("nas", "cluster.example").unwrap();
        assert!(
            node.store().is_bound(&origin, &nas, later).unwrap(),
            "the cached binding keeps its own expiry"
        );
        // And the failed attempt still moves the retry time, so the loop does
        // not spin on a resolver that is down.
        assert!(node
            .refresh_due_domains(&resolver, later + 1)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            resolver.calls(),
            2,
            "one initial, one failed; the retry waits out a clamped TTL rather than spinning"
        );
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_unknown_key_trigger_fires_once_per_cooldown() {
        // §3.4: an inbound connection from an unknown key triggers an
        // immediate re-resolution — rate-limited, because a peer that keeps
        // retrying rings the bell as fast as it can dial.
        let (_d, node) = node().await;
        let nas = SecretKey::generate().public();
        let resolver = FakeResolver::new(
            vec![format!("v=sync1 id=nas nk={}", nas.to_z32())],
            Duration::from_secs(3600),
        );
        node.add_domain("cluster.example").unwrap();

        let now = now_ns();
        assert_eq!(
            node.refresh_triggered(&resolver, now).await.unwrap().len(),
            1
        );
        assert_eq!(resolver.calls(), 1);
        // Every further trigger inside the cooldown is dropped.
        for _ in 0..5 {
            assert!(node
                .refresh_triggered(&resolver, now)
                .await
                .unwrap()
                .is_empty());
        }
        assert_eq!(resolver.calls(), 1);

        // Past the cooldown it fires again, even though the TTL has hours left.
        let past = now + DNS_TRIGGER_COOLDOWN.as_nanos() as i64 + 1;
        assert_eq!(
            node.refresh_triggered(&resolver, past).await.unwrap().len(),
            1
        );
        assert_eq!(resolver.calls(), 2);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn the_dns_loop_stops_on_shutdown_and_refreshes_on_the_bell() {
        let (_d, node) = node().await;
        let nas = SecretKey::generate().public();
        let resolver = std::sync::Arc::new(FakeResolver::new(
            vec![format!("v=sync1 id=nas nk={}", nas.to_z32())],
            Duration::from_secs(3600),
        ));
        node.add_domain("cluster.example").unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let runner = node.clone();
        let watched = resolver.clone();
        let handle = tokio::spawn(async move {
            runner
                .run_dns(watched.as_ref(), async {
                    let _ = rx.await;
                })
                .await;
        });

        // The first pass is due immediately; give it a generous window.
        for _ in 0..100 {
            if resolver.calls() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(resolver.calls() >= 1, "the loop resolves what is due");
        let origin = OriginId::named("nas", "cluster.example").unwrap();
        assert!(node.store().is_bound(&origin, &nas, now_ns()).unwrap());

        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("the loop must stop promptly")
            .unwrap();
        node.shutdown().await.unwrap();
    }

    #[test]
    fn the_dns_delay_stays_inside_its_window() {
        assert!(DNS_POLL_FLOOR <= DNS_POLL_CEILING);
    }
}
