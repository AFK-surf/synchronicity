//! Who is calling, and what this invocation may do.
//!
//! The effective policy is the **intersection** of two lists: what the program
//! declared in its `synchronicity.init` hook, and what the operator allowed at
//! `synch socket add`. Neither side can widen it alone. Egress that nobody
//! declared is denied, which is the same answer as egress nobody allowed.
//!
//! The intersection is computed once, when the invocation is built, so a helper
//! answers a policy question by looking at a list rather than by re-deriving it
//! — and so a policy change cannot take effect halfway through a stream.

use std::net::IpAddr;

use synch_core::{sock::egress_rule_matches, Declaration, NodeId, OriginId};

/// A syntactically valid device key that identifies nobody.
///
/// The encoding of the ed25519 base point: a real point on the curve, so
/// `NodeId` accepts it, and one no keypair anybody holds will ever produce. It
/// stands in where the protocol needs a key and there is no caller — the
/// declaration run, which happens at arm time with nobody connected.
///
/// Arbitrary bytes will not do: most 32-byte strings are not valid public keys,
/// and `NodeId::from_bytes` rejects them.
pub const NOBODY: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Which socket an invocation is serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketId {
    /// The space it lives in.
    pub space: String,
    /// Its path within that space.
    pub path: String,
}

impl SocketId {
    /// Builds one.
    pub fn new(space: impl Into<String>, path: impl Into<String>) -> Self {
        SocketId {
            space: space.into(),
            path: path.into(),
        }
    }

    /// `<space>/<path>`, as every command and log line names a socket.
    pub fn qualified(&self) -> String {
        format!("{}/{}", self.space, self.path)
    }
}

/// The caller, as the iroh handshake established it.
///
/// Every field here is a fact the transport authenticated, which is the whole
/// reason the identity helpers exist: a socket that wants finer rules than
/// membership writes them over facts the caller cannot forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The caller's origin.
    pub origin: OriginId,
    /// The caller's device key — the identity that survives an origin rename,
    /// and the right key for a per-caller rate limit.
    pub device_key: NodeId,
    /// The spaces the caller may read, or `None` for a rooted member, which may
    /// read every space by construction (§3.5).
    pub spaces: Option<Vec<String>>,
    /// The remote transport address, for `sy_peer_addr`. Informational: it can
    /// be a relay.
    pub addr: String,
    /// Which stream of the caller's connection this is.
    pub stream_index: u64,
}

impl PeerIdentity {
    /// What `sy_peer_kind` returns: a rooted member, or a delegate.
    pub fn kind(&self) -> u64 {
        match self.spaces {
            None => crate::abi::peer_kind::MEMBER,
            Some(_) => crate::abi::peer_kind::DELEGATE,
        }
    }

    /// Whether the caller may read `space`.
    pub fn has_space(&self, space: &str) -> bool {
        match &self.spaces {
            None => true,
            Some(list) => list.iter().any(|s| s == space),
        }
    }
}

/// What one invocation may do: the intersection, already computed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectivePolicy {
    /// Egress rules both sides agreed to, as `host` or `host:port`.
    pub egress: Vec<String>,
    /// Tree-read prefixes both sides agreed to.
    pub tree_reads: Vec<String>,
    /// Config the operator set, readable through `sy_config_get`.
    pub config: Vec<(String, String)>,
    /// The concurrency cap, already the lower of the two.
    pub max_streams: usize,
}

impl EffectivePolicy {
    /// Intersects what the program declared with what the operator allowed.
    ///
    /// A rule survives only if the *other* side's list also admits it. The
    /// asymmetry worth naming: the operator's list is matched against the
    /// program's rules and not the other way round, because the program's rules
    /// are the ones a connection is checked against — the operator's list
    /// bounds them, it does not add to them.
    pub fn intersect(
        declared: &Declaration,
        allow_egress: &[String],
        allow_tree_read: &[String],
        config: Vec<(String, String)>,
        operator_max_streams: Option<u32>,
        default_max_streams: usize,
    ) -> EffectivePolicy {
        let egress = declared
            .egress
            .iter()
            .filter(|rule| {
                let (host, port) = split_rule(rule);
                allow_egress
                    .iter()
                    .any(|allowed| rule_admits(allowed, host, port))
            })
            .cloned()
            .collect();

        let tree_reads = declared
            .tree_reads
            .iter()
            .filter(|prefix| {
                allow_tree_read
                    .iter()
                    .any(|allowed| synch_core::sock::path_prefix_matches(allowed, prefix))
            })
            .cloned()
            .collect();

        let max_streams = [
            declared.max_streams.map(|n| n as usize),
            operator_max_streams.map(|n| n as usize),
            Some(default_max_streams),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(default_max_streams);

        EffectivePolicy {
            egress,
            tree_reads,
            config,
            max_streams,
        }
    }

    /// Whether this invocation may connect to `host` on `port`.
    pub fn egress_allowed(&self, host: &str, port: u16) -> bool {
        self.egress
            .iter()
            .any(|rule| egress_rule_matches(rule, host, port))
    }

    /// Whether this invocation may read `path` from another origin's view.
    pub fn tree_read_allowed(&self, path: &str) -> bool {
        self.tree_reads
            .iter()
            .any(|prefix| synch_core::sock::path_prefix_matches(prefix, path))
    }

    /// The value of a config key.
    pub fn config_get(&self, key: &str) -> Option<&str> {
        self.config
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Splits `host` or `host:port`, leaving an IPv6 literal intact.
fn split_rule(rule: &str) -> (&str, Option<u16>) {
    match rule.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => {
            (h, p.parse().ok())
        }
        _ => (rule, None),
    }
}

/// Whether an operator rule admits a program rule.
///
/// A program rule with no port is admitted only by an operator rule with no
/// port: "any port on this host" is a wider thing to ask for than any single
/// port, so an operator who named one port has not granted it.
fn rule_admits(allowed: &str, host: &str, port: Option<u16>) -> bool {
    match port {
        Some(p) => egress_rule_matches(allowed, host, p),
        None => {
            let (allowed_host, allowed_port) = split_rule(allowed);
            allowed_port.is_none()
                && allowed_host
                    .trim_matches(['[', ']'])
                    .eq_ignore_ascii_case(host.trim_matches(['[', ']']))
        }
    }
}

/// Whether a resolved address may be connected to under a rule naming `host`.
///
/// The check the name-based list cannot make. An operator who allows
/// `metadata.example` has allowed a name, and a name is somebody else's to
/// point wherever they like — at `127.0.0.1`, at a link-local address, at the
/// node's own control socket's interface. So an address in one of those ranges
/// is refused unless the rule *named that address literally*, which is how a
/// deliberate local upstream — `--allow-egress 127.0.0.1:5432` — keeps working.
///
/// This is not a substitute for the policy check; it runs after it, on what DNS
/// actually answered.
pub fn resolved_address_allowed(host: &str, addr: IpAddr) -> bool {
    if !is_restricted(addr) {
        return true;
    }
    // The rule named this exact address, so the operator has already said yes
    // to it in the only way that is unambiguous.
    host.trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok_and(|literal| literal == addr)
}

/// Addresses a name must not be allowed to reach by resolving to them.
fn is_restricted(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // 169.254.169.254 is inside link-local, but the whole of
                // 100.64/10 (carrier NAT) is not, and it is where a good deal
                // of cloud metadata lives.
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 link-local and fc00::/7 unique-local.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // An IPv4-mapped address is an IPv4 address wearing a hat.
                || v6.to_ipv4_mapped().is_some_and(|v4| is_restricted(IpAddr::V4(v4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(egress: &[&str]) -> Declaration {
        Declaration {
            egress: egress.iter().map(|s| s.to_string()).collect(),
            ..Declaration::default()
        }
    }

    fn intersect(program: &[&str], operator: &[&str]) -> EffectivePolicy {
        EffectivePolicy::intersect(
            &declared(program),
            &operator.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &[],
            vec![],
            None,
            64,
        )
    }

    #[test]
    fn neither_side_can_widen_the_egress_list_alone() {
        // Both agree.
        let p = intersect(&["git.internal:9418"], &["git.internal:9418"]);
        assert!(p.egress_allowed("git.internal", 9418));

        // The program asks for more than the operator allowed.
        let p = intersect(
            &["git.internal:9418", "anywhere.example:80"],
            &["git.internal:9418"],
        );
        assert!(p.egress_allowed("git.internal", 9418));
        assert!(!p.egress_allowed("anywhere.example", 80));

        // The operator allows more than the program asked for. The program
        // still cannot reach it: it never declared it, so the operator never
        // approved it, and a list nobody wrote is not permission.
        let p = intersect(&["git.internal:9418"], &["git.internal:9418", "extra:80"]);
        assert!(!p.egress_allowed("extra", 80));

        // Nobody said anything.
        assert!(!intersect(&[], &[]).egress_allowed("anything", 80));
    }

    #[test]
    fn a_named_port_does_not_grant_every_port() {
        // The program wants any port on the host; the operator named one. "Any
        // port" is the wider ask, so it is not granted.
        let p = intersect(&["git.internal"], &["git.internal:9418"]);
        assert!(
            !p.egress_allowed("git.internal", 22),
            "a one-port grant was read as a whole-host grant"
        );
        assert!(!p.egress_allowed("git.internal", 9418));

        // The operator allowed the whole host, so the program's narrower ask
        // survives whole.
        let p = intersect(&["git.internal:9418"], &["git.internal"]);
        assert!(p.egress_allowed("git.internal", 9418));
        assert!(!p.egress_allowed("git.internal", 22));
    }

    #[test]
    fn the_stream_cap_is_the_lowest_of_the_three() {
        let cap = |program, operator| {
            EffectivePolicy::intersect(
                &Declaration {
                    max_streams: program,
                    ..Declaration::default()
                },
                &[],
                &[],
                vec![],
                operator,
                64,
            )
            .max_streams
        };
        assert_eq!(cap(None, None), 64, "the daemon's default stands alone");
        assert_eq!(cap(Some(32), None), 32);
        assert_eq!(cap(None, Some(8)), 8);
        assert_eq!(cap(Some(32), Some(8)), 8);
        assert_eq!(cap(Some(8), Some(32)), 8);
        assert_eq!(cap(Some(1000), Some(1000)), 64, "the default is a ceiling");
    }

    #[test]
    fn a_name_may_not_resolve_into_the_ranges_a_name_must_not_reach() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let metadata: IpAddr = "169.254.169.254".parse().unwrap();
        let public: IpAddr = "93.184.216.34".parse().unwrap();

        assert!(resolved_address_allowed("git.internal", public));
        assert!(
            !resolved_address_allowed("git.internal", loopback),
            "a name resolved onto the node itself"
        );
        assert!(!resolved_address_allowed("git.internal", metadata));

        // A rule that names the address literally has said yes unambiguously,
        // which is how a deliberate local upstream keeps working.
        assert!(resolved_address_allowed("127.0.0.1", loopback));
        assert!(!resolved_address_allowed("127.0.0.1", metadata));
    }

    #[test]
    fn an_ipv4_mapped_v6_address_is_the_v4_address_it_maps() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(!resolved_address_allowed("git.internal", mapped));
        let ula: IpAddr = "fd00::1".parse().unwrap();
        assert!(!resolved_address_allowed("git.internal", ula));
        let global: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        assert!(resolved_address_allowed("git.internal", global));
    }

    #[test]
    fn tree_reads_intersect_the_same_way() {
        let p = EffectivePolicy::intersect(
            &Declaration {
                tree_reads: vec!["code/pub".into(), "secrets".into()],
                ..Declaration::default()
            },
            &[],
            &["code".to_string()],
            vec![],
            None,
            64,
        );
        assert!(p.tree_read_allowed("code/pub/readme"));
        assert!(
            !p.tree_read_allowed("secrets/keys"),
            "a prefix the operator never allowed survived the intersection"
        );
    }

    #[test]
    fn a_member_reads_every_space_and_a_delegate_reads_its_list() {
        let key = NodeId::from_bytes(&NOBODY).unwrap();
        let member = PeerIdentity {
            origin: OriginId::named("nas", "cluster.example").unwrap(),
            device_key: key,
            spaces: None,
            addr: String::new(),
            stream_index: 0,
        };
        assert_eq!(member.kind(), crate::abi::peer_kind::MEMBER);
        assert!(member.has_space("anything"));

        let delegate = PeerIdentity {
            spaces: Some(vec!["code".into()]),
            ..member
        };
        assert_eq!(delegate.kind(), crate::abi::peer_kind::DELEGATE);
        assert!(delegate.has_space("code"));
        assert!(!delegate.has_space("secrets"));
    }
}
