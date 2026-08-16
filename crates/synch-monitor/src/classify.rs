//! Deciding what a leaf is: an authorization for a zone, or noise.
//!
//! Everything here works from the certificate inside the leaf and nothing
//! else. In particular the DNSKEY, its key tag and the DS a parent would have
//! published are all **derived from the certificate's SubjectPublicKeyInfo**,
//! never looked up: the threat model has a compromised upstream DNS provider
//! in it, so a monitor that asked DNS what the zone's key is would be asking
//! the attacker.
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
/// being reported on every pass forever. A tier A entry whose key is not in
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
/// an operator says "tell me about this zone, I have seen nothing yet".
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KnownKeys {
    /// `apex` → the SHA-256 hex of each already-reported key's DER
    /// SubjectPublicKeyInfo.
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, Vec<String>>,
}

impl KnownKeys {
    /// Whether this SPKI has already been seen for `apex`.
    ///
    /// Names are compared **parsed**, never trimmed: an operator's state file
    /// says `sync.example` and a certificate says `sync.example.`,
    /// and those are one zone — but `sync.example..` is not a name at all
    /// and must match nothing.
    pub fn contains(&self, apex: &Name, spki: &[u8]) -> bool {
        let digest = hex::encode(sha256(spki));
        self.keys
            .iter()
            .filter(|(known, _)| chain::parse_name(known).is_ok_and(|known| known == *apex))
            .any(|(_, digests)| digests.iter().any(|d| d.eq_ignore_ascii_case(&digest)))
    }

    /// Records a key as seen for `apex`.
    pub fn insert(&mut self, apex: &Name, spki: &[u8]) {
        let key = apex.to_string();
        let digest = hex::encode(sha256(spki));
        let entry = self.keys.entry(key).or_default();
        if !entry.iter().any(|d| d.eq_ignore_ascii_case(&digest)) {
            entry.push(digest);
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
}

/// One classified leaf.
///
/// Everything an operator needs to act without believing anything the entry
/// says: the zone, the key tag and DS their registrar should be showing, the
/// exact key bytes by digest, and where in the log to look.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Where the entry sits in the log.
    pub log_index: u64,
    /// The apex the certificate names.
    pub apex: String,
    /// The key tag derived from the certificate's public key.
    pub key_tag: u16,
    /// The SHA-256 hex of the certificate's DER SubjectPublicKeyInfo.
    pub spki_sha256: String,
    /// The DS record the parent zone would have to publish for this key —
    /// derived, so an operator can compare it against what their registrar
    /// actually shows without believing anything this entry says.
    pub ds: String,
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
        format!(
            "[{}] index {} apex {} keyTag {} DS {} spki {} — {}",
            self.tier.letter(),
            self.log_index,
            self.apex,
            self.key_tag,
            self.ds,
            self.spki_sha256,
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
    // Everything about the zone and the key comes out of `chain::authorize`,
    // the same call the client makes — the apex parsed once from the SAN, the
    // key derived from the SPKI, the chain walked against exactly those. The
    // monitor may not compose this itself: doing so is how the two sides once
    // disagreed about whether `victim.example..` was a zone (see
    // `chain::authorize`), which put a client-accepted entry in the silent bin.
    let apex = body.certificate.single_dns_name().ok()?;
    // Only the P-256 keys this design logs are classifiable at all; anything
    // else in the certificate is somebody else's entry that happens to have
    // a SAN, and saying nothing about it is the honest answer.
    let dnskey_rdata = chain::zone_key_rdata(&body.certificate.spki)?;
    let mut finding = Finding {
        log_index,
        apex: apex.to_string(),
        key_tag: chain::key_tag(&dnskey_rdata),
        spki_sha256: hex::encode(sha256(&body.certificate.spki)),
        ds: chain::ds_fields(&apex, &dnskey_rdata),
        tier: Tier::B,
        reasons: Vec::new(),
    };

    match chain::authorize(&body.certificate, anchors) {
        Ok(authorized) => {
            // The chain verifies and covers this key, so a resolver holding
            // this anchor would take the entry. That is the whole of the
            // verdict: this key is authorized for this apex, and the monitor
            // does not — cannot — say by whom.
            finding.tier = Tier::A;
            finding.reasons.push(format!(
                "DNSSEC chain valid to {} ({} link(s)): this key is authorized for {apex}",
                authorized.chain.anchor_zone, authorized.chain.links
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

    #[test]
    fn a_spki_that_is_not_a_p256_key_is_not_classifiable() {
        assert!(chain::zone_key_rdata(&[0u8; 91]).is_none());
        let spki = synch_net::rekor::p256_spki(&[7u8; 64]);
        assert!(chain::zone_key_rdata(&spki).is_some());
        assert!(chain::zone_key_rdata(&spki[..90]).is_none());
    }
}
