//! Deciding what a leaf is: an authorization for a zone, or noise.
//!
//! Everything here works from the certificate inside the leaf and nothing
//! else. The authorized keys, their tags and the DS a parent would have
//! published are all read out of the leaf's own **chain-proven DNSKEY
//! RRset**, never looked up: the threat model has a compromised upstream DNS
//! provider in it, so a monitor that asked DNS what the zone's keys are
//! would be asking the attacker. The certificate's SubjectPublicKeyInfo is
//! the entry *signer* — attribution — and plays no part in the verdict.
//!
//! Classification is a pure function of the certificate and the trust
//! anchors: it takes no state, and it cannot be steered by what the monitor
//! happens to have seen before. Whether a tier A entry is *news* is a
//! separate question, answered against the monitor's own state file by the
//! caller; see the crate docs for why the two are kept apart.

use hickory_resolver::proto::{dnssec::TrustAnchors, rr::Name};
use synch_net::{
    chain,
    rekor::{sha256, HashedRekordBody},
};

/// What a leaf turned out to be.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Tier {
    /// No valid chain, or a chain covering some other key: an unauthorized
    /// claim naming this apex. Recorded, not reported — and safe to be quiet
    /// about only because no client would have accepted it either (see the
    /// crate docs).
    B,
    /// A chain that verifies to the anchor in force and covers this key. The
    /// entry **authorizes** this key for this apex — whoever published it.
    A,
}

impl Tier {
    /// The one-letter name used in output and exit-code decisions.
    pub fn letter(&self) -> char {
        match self {
            Tier::A => 'A',
            Tier::B => 'B',
        }
    }
}

/// The keys this monitor has already seen authorized, per apex.
///
/// This is the monitor's memory, and it does exactly one job: stop a key from
/// being reported on every pass forever. A tier A entry proving a key not in
/// here is a **new authorization** — the event an operator is running a
/// monitor to hear about — and once reported it is recorded so the next run
/// stays quiet.
///
/// It is emphatically **not** a trust store. An attacker's substituted key
/// gets recorded here the moment it is reported, exactly like the operator's
/// own, because the monitor has no way to tell them apart and does not
/// pretend to. Recording is bookkeeping about what has been *said*, not a
/// judgement about what is *legitimate*; the judgement is the operator's,
/// made against their own record of what they published.
///
/// The apexes are also the watch list: an apex with an empty key list is how
/// an operator says "tell me about this zone, I have seen nothing yet". What
/// is watched is not just that name but its whole **delegation path**, in
/// both directions — see [`KnownKeys::watches`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KnownKeys {
    /// `apex` → the SHA-256 hex of each already-reported key's DNSKEY rdata.
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, Vec<String>>,
}

impl KnownKeys {
    /// Whether this DNSKEY rdata has already been seen for `apex`.
    ///
    /// Names are compared **parsed**, never trimmed: an operator's state file
    /// says `sync.example` and a certificate says `sync.example.`,
    /// and those are one zone — but `sync.example..` is not a name at all
    /// and must match nothing.
    pub fn contains(&self, apex: &Name, dnskey_rdata: &[u8]) -> bool {
        self.contains_digest(apex, &hex::encode(sha256(dnskey_rdata)))
    }

    /// The same test by the digest itself, which is what a [`Finding`]
    /// carries.
    pub fn contains_digest(&self, apex: &Name, digest_hex: &str) -> bool {
        self.keys
            .iter()
            .filter(|(known, _)| chain::parse_name(known).is_ok_and(|known| known == *apex))
            .any(|(_, digests)| digests.iter().any(|d| d.eq_ignore_ascii_case(digest_hex)))
    }

    /// Records a key as seen for `apex`.
    pub fn insert(&mut self, apex: &Name, dnskey_rdata: &[u8]) {
        self.insert_digest(apex, &hex::encode(sha256(dnskey_rdata)));
    }

    /// The same, by the digest itself.
    pub fn insert_digest(&mut self, apex: &Name, digest_hex: &str) {
        let key = apex.to_string();
        let entry = self.keys.entry(key).or_default();
        if !entry.iter().any(|d| d.eq_ignore_ascii_case(digest_hex)) {
            entry.push(digest_hex.to_string());
        }
    }

    /// The apexes this monitor watches, parsed. An entry that is not a DNS
    /// name watches nothing — it cannot match a certificate's SAN, which is
    /// parsed too.
    pub fn apexes(&self) -> impl Iterator<Item = Name> + '_ {
        self.keys
            .keys()
            .filter_map(|apex| chain::parse_name(apex).ok())
    }

    /// Whether an entry naming `apex` is this monitor's business.
    ///
    /// Not just the configured names: **anything on their delegation path**,
    /// above or below. Watching only the exact name would leave the one
    /// attack the design cannot prevent completely invisible. A zone's
    /// ancestors own its namespace outright — a parent can nullify the
    /// delegation, absorb the child, and publish a declaration and a chain
    /// about *itself* that a resolver will validate — so an entry for
    /// `example.com` is exactly how a takeover of `cp.example.com` would
    /// appear in the log. A monitor pointed at the child that ignored the
    /// parent would be watching the one place the attacker has no need to
    /// touch.
    ///
    /// Downward for the mirror case: an entry for `sub.cp.example.com` is
    /// somebody standing up a control plane inside the operator's own zone,
    /// which is either a delegation they made or one they need to hear about.
    ///
    /// The cost is noise, and it is the right trade. A zone's own operators
    /// are the only people who can say whether `example.com` publishing
    /// synchronicity entries is ordinary or an emergency, and they can only
    /// say it if they are told.
    pub fn watches(&self, apex: &Name) -> bool {
        self.apexes()
            .any(|watched| watched.zone_of(apex) || apex.zone_of(&watched))
    }
}

/// One key of a proven set, as an operator needs to see it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizedKey {
    /// The key tag, computed from the proven rdata.
    pub key_tag: u16,
    /// The SHA-256 hex of the DNSKEY rdata.
    pub sha256: String,
    /// The DS record a parent would publish for this key — derived, so an
    /// operator can compare it against what their registrar actually shows
    /// without believing anything this entry says. Only the DS-covered key
    /// of a split-key zone will match the registrar; the rest are the ZSKs
    /// the chain proved under it.
    pub ds: String,
}

/// One classified leaf.
///
/// Everything an operator needs to act without believing anything the entry
/// says: the zone, the proven key set with the DS their registrar should be
/// showing, and where in the log to look.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Where the entry sits in the log.
    pub log_index: u64,
    /// The apex the certificate names.
    pub apex: String,
    /// The chain-proven key set. Empty for a tier B entry, which proves
    /// nothing about any key.
    pub keys: Vec<AuthorizedKey>,
    /// The verdict.
    pub tier: Tier,
    /// Why, in the order the checks ran. Always non-empty.
    pub reasons: Vec<String>,
}

impl Finding {
    /// A one-line rendering for a terminal or a log.
    ///
    /// The DS is in it deliberately, and it is the longest field: the
    /// operator's first move on a new authorization is to compare this line
    /// against what their registrar is publishing, and a line they have to
    /// re-run a tool to complete is a line they will not act on.
    pub fn line(&self) -> String {
        let keys = match self.keys.is_empty() {
            true => "no proven keys".to_string(),
            false => self
                .keys
                .iter()
                .map(|key| format!("keyTag {} DS {} rdata {}", key.key_tag, key.ds, key.sha256))
                .collect::<Vec<_>>()
                .join(" | "),
        };
        format!(
            "[{}] index {} apex {} {} — {}",
            self.tier.letter(),
            self.log_index,
            self.apex,
            keys,
            self.reasons.join("; ")
        )
    }
}

/// Classifies one entry body.
///
/// No clock is consulted, and none is available to consult: `integratedTime`
/// sits outside the Merkle commitment and is therefore attacker-supplied, and
/// nothing else near an entry carries an attested time. So a chain is judged
/// purely on whether it validates, never on when it was signed — which is the
/// same rule the client applies, and has to be: the monitor's chain rule can
/// never be stricter than the client's, or the silent bin becomes an evasion
/// (see the crate docs).
pub fn classify(
    body: &HashedRekordBody,
    log_index: u64,
    anchors: &TrustAnchors,
) -> Option<Finding> {
    // Everything about the zone and the keys comes out of `chain::authorize`,
    // the same call the client makes — the apex parsed once from the SAN, the
    // chain walked against exactly that, the key set read out of the chain
    // itself. The monitor may not compose this itself: doing so is how the
    // two sides once disagreed about whether `victim.example..` was a zone
    // (see `chain::authorize`), which put a client-accepted entry in the
    // silent bin.
    let apex = body.certificate.single_dns_name().ok()?;
    let mut finding = Finding {
        log_index,
        apex: apex.to_string(),
        keys: Vec::new(),
        tier: Tier::B,
        reasons: Vec::new(),
    };

    match chain::authorize(&body.certificate, anchors) {
        Ok(authorized) => {
            // The chain verifies, so a resolver holding this anchor would
            // take the entry for any key in the proven set. That is the
            // whole of the verdict: these keys are authorized for this apex,
            // and the monitor does not — cannot — say by whom.
            finding.tier = Tier::A;
            finding.keys = authorized
                .proven_keys
                .iter()
                .map(|rdata| AuthorizedKey {
                    key_tag: chain::key_tag(rdata),
                    sha256: hex::encode(sha256(rdata)),
                    ds: chain::ds_fields(&apex, rdata),
                })
                .collect();
            finding.reasons.push(format!(
                "DNSSEC chain valid to {} ({} link(s)): {} key(s) authorized for {apex}",
                authorized.chain.anchor_zone,
                authorized.chain.links,
                finding.keys.len()
            ));
        }
        Err(why) => {
            // No client would have accepted this either — the client runs
            // this same composition and refuses what it rejects — so an entry
            // here is an unauthorized claim nobody could have been served.
            finding.reasons.push(format!("unauthorized claim: {why}"));
        }
    }
    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        chain::parse_name(text).expect("a test name")
    }

    #[test]
    fn known_keys_compare_names_the_way_dns_does() {
        let mut known = KnownKeys::default();
        known.insert(&name("Sync.Example."), b"a key");
        assert!(known.contains(&name("sync.example"), b"a key"));
        assert!(known.contains(&name("SYNC.EXAMPLE."), b"a key"));
        assert!(!known.contains(&name("other.example"), b"a key"));
        assert!(!known.contains(&name("sync.example"), b"another key"));
        // Inserting twice does not double the entry — which is what stops a
        // key being re-reported once it has been recorded.
        known.insert(&name("sync.example"), b"a key");
        assert_eq!(known.keys["sync.example."].len(), 1);
    }

    /// The watch follows the delegation path, both ways.
    ///
    /// The upward half is the one that matters: a parent can nullify its
    /// child's delegation and publish a perfectly valid entry about itself,
    /// so an operator watching only `cp.example.` would never see the
    /// takeover of `cp.example.` go by.
    #[test]
    fn watching_a_zone_watches_its_whole_delegation_path() {
        let mut known = KnownKeys::default();
        known.keys.insert("cp.example.".into(), vec![]);

        assert!(known.watches(&name("cp.example.")), "the zone itself");
        assert!(known.watches(&name("example.")), "its parent");
        assert!(known.watches(&name(".")), "the root above it");
        assert!(known.watches(&name("a.cp.example.")), "a zone beneath it");

        // Not everything, though: a sibling shares no delegation path, and
        // a name that merely ends in the same letters is not a suffix in the
        // DNS sense.
        assert!(!known.watches(&name("other.example.")));
        assert!(!known.watches(&name("notcp.example.")));
    }

    /// A watch entry that is not a DNS name watches nothing.
    ///
    /// The state file is hand-edited, so it can contain anything. What it
    /// must never do is match a certificate by some looser rule than the one
    /// the chain walk uses — that mismatch is what put a client-accepted
    /// entry in the silent bin.
    #[test]
    fn an_unparseable_watch_entry_matches_nothing() {
        let mut known = KnownKeys::default();
        known.keys.insert("sync.example..".into(), vec![]);
        assert_eq!(known.apexes().count(), 0);
        assert!(!known.contains(&name("sync.example"), b"a key"));
    }
}
