//! Who is calling, and what this invocation may do.
//!
//! What an invocation may do is what its program's `synchronicity.manifest`
//! section declares. Egress the manifest does not declare remains denied.
//!
//! Reading the tree is not among the things a program declares. Every
//! invocation may read every path in every origin this node holds
//! (`docs/SOCKETS.md` §7.6): the bytes are already readable by any member, and
//! a per-program prefix list bought an approval prompt rather than a boundary.
//!
//! The effective policy is computed once when the invocation is built, so a
//! helper answers a policy question by looking at a list rather than by
//! re-deriving it.

use std::net::IpAddr;

use synch_core::{
    sock::{declared_egress_addresses, egress_rule_matches},
    Declaration, NodeId, OriginId,
};

/// A syntactically valid device key that identifies nobody.
///
/// The encoding of the ed25519 base point: a real point on the curve, so
/// `NodeId` accepts it, and one no keypair anybody holds will ever produce. It
/// stands in where the protocol needs a key and there is no caller — the
/// test harness's bare runs, which have nobody connected.
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
    /// What `sy_peer_info` reports as `kind`: a rooted member, or a delegate.
    pub fn kind(&self) -> &'static str {
        match self.spaces {
            None => "member",
            Some(_) => "delegate",
        }
    }

    /// Whether the caller may read `space`.
    pub(crate) fn has_space(&self, space: &str) -> bool {
        match &self.spaces {
            None => true,
            Some(list) => list.iter().any(|s| s == space),
        }
    }
}

/// What one invocation may do, already computed from the program's manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectivePolicy {
    /// Whether the manifest declares egress to any destination at all, rather
    /// than to a list of them.
    ///
    /// Outward only: [`address_gate`](Self::address_gate) still refuses the
    /// ranges a name may never reach, so this is never a route into the
    /// node's own network.
    pub unrestricted_egress: bool,
    /// Egress rules the program's manifest declares, as `host` or `host:port`.
    pub egress: Vec<String>,
    /// Exact process capabilities the manifest declares.
    pub processes: Vec<synch_core::ProcessCapability>,
    /// Exact file-transfer capabilities the manifest declares.
    pub file_transfers: Vec<synch_core::FileTransferCapability>,
    /// Prefix-scoped tree-write capabilities the manifest declares.
    pub tree_writes: Vec<synch_core::TreeWriteCapability>,
    /// Config the operator set, readable through `sy_config_get`.
    pub config: Vec<(String, String)>,
    /// The concurrency cap, already the lower of the two.
    pub max_streams: usize,
    /// Bytes charged to each eBPF local-call frame.
    pub stack_frame_size: Option<usize>,
    /// Whether inaccessible host-page gaps must separate local-call frames.
    pub guarded_stack_frames: Option<bool>,
}

impl EffectivePolicy {
    /// Builds the runtime policy this declaration grants, capped by the
    /// activation's and the daemon's own stream limits.
    pub fn granted(
        declared: &Declaration,
        config: Vec<(String, String)>,
        operator_max_streams: Option<u32>,
        default_max_streams: usize,
    ) -> EffectivePolicy {
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
            unrestricted_egress: declared.unrestricted_egress,
            egress: declared.egress.clone(),
            processes: declared.processes.clone(),
            file_transfers: declared.file_transfers.clone(),
            tree_writes: declared.tree_writes.clone(),
            config,
            max_streams,
            stack_frame_size: declared.stack_frame_size.map(|size| size as usize),
            guarded_stack_frames: declared.guarded_stack_frames,
        }
    }

    /// Whether this invocation may connect to `host` on `port`.
    pub(crate) fn egress_allowed(&self, host: &str, port: u16) -> bool {
        self.unrestricted_egress
            || self
                .egress
                .iter()
                .any(|rule| egress_rule_matches(rule, host, port))
    }

    /// The check to make on the address a destination turns out to have.
    ///
    /// Taken once per outbound connection and moved into the connect task,
    /// which outlives the helper call that started it and has no borrow of the
    /// policy to make this check with.
    pub(crate) fn address_gate(&self) -> AddressGate {
        AddressGate {
            named: declared_egress_addresses(&self.egress),
        }
    }

    /// The value of a config key.
    pub fn config_get(&self, key: &str) -> Option<&str> {
        self.config
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Which addresses this invocation may be connected to, whatever destination
/// it named to get there.
///
/// The check the destination list cannot make. A program that declares
/// `metadata.example` — or declares unrestricted egress and is handed a name by
/// its caller — has named a destination whose address is somebody else's to
/// point wherever they like: at `127.0.0.1`, at a link-local address, at the
/// node's own control socket's interface. So an address in one of those ranges
/// is refused unless the *declaration* named that address literally, which is
/// how a deliberate local upstream declared as `127.0.0.1:5432` keeps working.
///
/// Keying that exception to the declaration rather than to the host the guest
/// typed is what makes unrestricted egress unrestricted *outward* only: with no
/// list, there is no literal, and no name or address a program can supply
/// reaches inward.
///
/// This is not a substitute for the policy check; it runs after it, on what DNS
/// actually answered — or, for a literal destination, before the connect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AddressGate {
    /// The restricted-range exceptions: addresses the declaration named
    /// literally, each with the port its rule pins, if any.
    named: Vec<(IpAddr, Option<u16>)>,
}

impl AddressGate {
    /// Whether `addr` may be connected to on `port`.
    pub(crate) fn allows(&self, addr: IpAddr, port: u16) -> bool {
        !is_restricted(addr)
            || self
                .named
                .iter()
                .any(|(named, pinned)| *named == addr && pinned.is_none_or(|p| p == port))
    }
}

/// Addresses a name must not be allowed to reach by resolving to them.
fn is_restricted(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
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

    fn armed(program: &[&str]) -> EffectivePolicy {
        EffectivePolicy::granted(&declared(program), vec![], None, 64)
    }

    #[test]
    fn arming_approves_exactly_what_the_program_declared() {
        let p = armed(&["git.internal:9418"]);
        assert!(p.egress_allowed("git.internal", 9418));
        assert!(!p.egress_allowed("extra", 80));
        assert!(!armed(&[]).egress_allowed("anything", 80));
    }

    #[test]
    fn a_named_port_does_not_grant_every_port() {
        let p = armed(&["git.internal:9418"]);
        assert!(p.egress_allowed("git.internal", 9418));
        assert!(!p.egress_allowed("git.internal", 22));
    }

    #[test]
    fn the_stream_cap_is_the_lowest_of_the_three() {
        let cap = |program, operator| {
            EffectivePolicy::granted(
                &Declaration {
                    max_streams: program,
                    ..Declaration::default()
                },
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
    fn the_declared_stack_frame_size_reaches_the_runtime_policy() {
        assert_eq!(armed(&[]).stack_frame_size, None);
        let policy = EffectivePolicy::granted(
            &Declaration {
                stack_frame_size: Some(512),
                guarded_stack_frames: Some(false),
                ..Declaration::default()
            },
            vec![],
            None,
            64,
        );
        assert_eq!(policy.stack_frame_size, Some(512));
        assert_eq!(policy.guarded_stack_frames, Some(false));
    }

    #[test]
    fn a_name_may_not_resolve_into_the_ranges_a_name_must_not_reach() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let metadata: IpAddr = "169.254.169.254".parse().unwrap();
        let private = ["10.0.0.1", "172.16.0.1", "192.168.0.1"];
        let public: IpAddr = "93.184.216.34".parse().unwrap();

        let named = armed(&["git.internal"]).address_gate();
        assert!(named.allows(public, 443));
        assert!(
            !named.allows(loopback, 443),
            "a name resolved onto the node itself"
        );
        assert!(!named.allows(metadata, 80));
        for address in private {
            assert!(
                !named.allows(address.parse().unwrap(), 443),
                "a public name resolved into private address {address}"
            );
        }

        // A rule that names the address literally has said yes unambiguously,
        // which is how a deliberate local upstream keeps working — on the port
        // it named, and no other.
        let literal = armed(&["127.0.0.1:5432"]).address_gate();
        assert!(literal.allows(loopback, 5432));
        assert!(!literal.allows(loopback, 22), "a declared port was ignored");
        assert!(!literal.allows(metadata, 5432));
        assert!(armed(&["127.0.0.1"]).address_gate().allows(loopback, 22));
        assert!(
            !armed(&["127.0.0.1:99999"])
                .address_gate()
                .allows(loopback, 80),
            "a port that fits nothing became a literal on every port"
        );
    }

    #[test]
    fn an_ipv4_mapped_v6_address_is_the_v4_address_it_maps() {
        let named = armed(&["git.internal"]).address_gate();
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(!named.allows(mapped, 443));
        let ula: IpAddr = "fd00::1".parse().unwrap();
        assert!(!named.allows(ula, 443));
        let global: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        assert!(named.allows(global, 443));
    }

    #[test]
    fn an_address_is_named_however_its_rule_spells_it() {
        // `[::1]:9418`, `::1` and the long form are one address, and an
        // approval of it must not depend on which the author typed.
        let loopback: IpAddr = "::1".parse().unwrap();
        for rule in ["[::1]:9418", "0:0:0:0:0:0:0:1:9418"] {
            assert!(
                armed(&[rule]).address_gate().allows(loopback, 9418),
                "rule {rule} did not name ::1"
            );
        }
    }

    #[test]
    fn unrestricted_egress_reaches_any_destination_it_was_never_told_about() {
        let p = EffectivePolicy::granted(
            &Declaration {
                unrestricted_egress: true,
                ..Declaration::default()
            },
            vec![],
            None,
            64,
        );
        assert!(p.egress_allowed("anything.example", 443));
        assert!(p.egress_allowed("something.else.example", 9418));
        assert!(p
            .address_gate()
            .allows("93.184.216.34".parse().unwrap(), 80));
    }

    #[test]
    fn unrestricted_egress_is_outward_only() {
        // The property that makes the declaration safe to grant: whatever host
        // or literal address the program is handed, it does not reach the
        // node's own loopback, its LAN, or a cloud metadata service — because
        // the exception is what the *declaration* named, not what the guest
        // typed at connect time.
        let anywhere = EffectivePolicy::granted(
            &Declaration {
                unrestricted_egress: true,
                ..Declaration::default()
            },
            vec![],
            None,
            64,
        );
        let gate = anywhere.address_gate();
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "192.168.1.1",
            "100.100.0.1",
            "::1",
            "fd00::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                anywhere.egress_allowed(address, 80),
                "the destination list, not the address gate, should have admitted {address}"
            );
            assert!(
                !gate.allows(address.parse().unwrap(), 80),
                "unrestricted egress reached inward at {address}"
            );
        }

        // A program that wants both says both: the list keeps its one remaining
        // job, which is naming the restricted addresses that are still allowed.
        let with_upstream = EffectivePolicy::granted(
            &Declaration {
                unrestricted_egress: true,
                egress: vec!["127.0.0.1:5432".into()],
                ..Declaration::default()
            },
            vec![],
            None,
            64,
        );
        let gate = with_upstream.address_gate();
        assert!(gate.allows("127.0.0.1".parse().unwrap(), 5432));
        assert!(!gate.allows("127.0.0.1".parse().unwrap(), 5433));
        assert!(!gate.allows("169.254.169.254".parse().unwrap(), 80));
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
        assert_eq!(member.kind(), "member");
        assert!(member.has_space("anything"));

        let delegate = PeerIdentity {
            spaces: Some(vec!["code".into()]),
            ..member
        };
        assert_eq!(delegate.kind(), "delegate");
        assert!(delegate.has_space("code"));
        assert!(!delegate.has_space("secrets"));
    }
}
