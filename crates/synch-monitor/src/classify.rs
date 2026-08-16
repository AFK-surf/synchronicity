//! Deciding what a leaf is: routine rotation, compromise signature, or noise.
//!
//! Everything here works from the certificate inside the leaf and nothing
//! else. In particular the DNSKEY, its key tag and the DS a parent would have
//! published are all **derived from the certificate's SubjectPublicKeyInfo**,
//! never looked up: the threat model has a compromised upstream DNS provider
//! in it, so a monitor that asked DNS what the zone's key is would be asking
//! the attacker.

use hickory_resolver::proto::{dnssec::TrustAnchors, rr::Name};
use ring::signature;
use synch_net::{
    chain,
    rekor::{sha256, HashedRekordBody},
    zonecert::Succession,
};

/// What a leaf turned out to be.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Tier {
    /// No valid chain: an unauthorized claim naming this apex. Recorded, not
    /// alerted on — and safe to be quiet about only because no client would
    /// have accepted it either (see the crate docs).
    C,
    /// A valid chain and no valid countersignature from a known predecessor.
    /// The compromise signature; also where a genesis key and a disaster
    /// recovery legitimately land.
    B,
    /// A valid chain *and* a valid countersignature by a key this monitor
    /// already knew: a rotation the operator performed.
    A,
}

impl Tier {
    /// The one-letter name used in output and exit-code decisions.
    pub fn letter(&self) -> char {
        match self {
            Tier::A => 'A',
            Tier::B => 'B',
            Tier::C => 'C',
        }
    }
}

/// What a monitor already believes about an apex's keys.
///
/// Seeded from the operator's own record of their zone keys, then grown by
/// **tier A findings only**. Growing it from tier B would be a gift to an
/// attacker: their first substituted key would become a trusted predecessor,
/// and every key after it would be classified as a routine rotation.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KnownKeys {
    /// `apex (lowercase, no trailing dot)` → the SHA-256 hex of each known
    /// key's DER SubjectPublicKeyInfo.
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, Vec<String>>,
}

impl KnownKeys {
    /// Whether this SPKI is one the monitor already trusts for `apex`.
    ///
    /// Names are compared **parsed**, never trimmed: an operator's state file
    /// says `sync.example.dev` and a certificate says `sync.example.dev.`,
    /// and those are one zone — but `sync.example.dev..` is not a name at all
    /// and must match nothing.
    pub fn contains(&self, apex: &Name, spki: &[u8]) -> bool {
        let digest = hex::encode(sha256(spki));
        self.keys
            .iter()
            .filter(|(known, _)| chain::parse_name(known).is_ok_and(|known| known == *apex))
            .any(|(_, digests)| digests.iter().any(|d| d.eq_ignore_ascii_case(&digest)))
    }

    /// Records a key as known for `apex`.
    pub fn insert(&mut self, apex: &Name, spki: &[u8]) {
        let key = apex.to_string();
        let digest = hex::encode(sha256(spki));
        let entry = self.keys.entry(key).or_default();
        if !entry.iter().any(|d| d.eq_ignore_ascii_case(&digest)) {
            entry.push(digest);
        }
    }

    /// The apexes this monitor has an opinion about, parsed. An entry that is
    /// not a DNS name watches nothing — it cannot match a certificate's SAN,
    /// which is parsed too.
    pub fn apexes(&self) -> impl Iterator<Item = Name> + '_ {
        self.keys
            .keys()
            .filter_map(|apex| chain::parse_name(apex).ok())
    }
}

/// One classified leaf.
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
    /// The predecessor the countersignature named, when there was one.
    pub predecessor_key_tag: Option<u16>,
}

impl Finding {
    /// A one-line rendering for a terminal or a log.
    pub fn line(&self) -> String {
        format!(
            "[{}] index {} apex {} keyTag {} spki {}… — {}",
            self.tier.letter(),
            self.log_index,
            self.apex,
            self.key_tag,
            &self.spki_sha256[..16],
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
    known: &KnownKeys,
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
        tier: Tier::C,
        reasons: Vec::new(),
        predecessor_key_tag: None,
    };

    let authorized = match chain::authorize(&body.certificate, anchors) {
        Ok(authorized) => authorized,
        Err(why) => {
            // No client would have accepted this either — the client runs
            // this same composition and refuses what it rejects — so an entry
            // here is an unauthorized claim nobody could have been served.
            finding.reasons.push(format!("unauthorized claim: {why}"));
            return Some(finding);
        }
    };
    finding.reasons.push(format!(
        "DNSSEC chain valid to {} ({} link(s))",
        authorized.chain.anchor_zone, authorized.chain.links
    ));

    // The chain holds. The only remaining question is whether the operator's
    // previous key vouched for this one.
    finding.tier = Tier::B;
    match body.succession() {
        None => finding.reasons.push(
            "no succession countersignature: genesis, disaster recovery, or a substitution".into(),
        ),
        Some(Err(why)) => finding
            .reasons
            .push(format!("succession extension does not decode: {why}")),
        Some(Ok(succession)) => {
            finding.predecessor_key_tag = Some(succession.predecessor_key_tag);
            match check_succession(&succession, &apex, &body.certificate.spki, known) {
                Ok(()) => {
                    finding.tier = Tier::A;
                    finding.reasons.push(format!(
                        "countersigned by known predecessor key tag {}",
                        succession.predecessor_key_tag
                    ));
                }
                Err(why) => finding.reasons.push(why),
            }
        }
    }
    Some(finding)
}

/// Whether a succession countersignature is one this monitor believes.
///
/// Three conditions, and all of them matter: the predecessor is a key the
/// monitor *already knew* for this apex (not merely one that appeared in the
/// log), the signature is over this exact successor's SubjectPublicKeyInfo,
/// and the key tag inside the payload matches the one being claimed.
fn check_succession(
    succession: &Succession,
    apex: &Name,
    successor_spki: &[u8],
    known: &KnownKeys,
) -> Result<(), String> {
    if !known.contains(apex, &succession.predecessor_spki) {
        return Err(format!(
            "the countersigning key (tag {}) is not one this monitor knows for {apex}",
            succession.predecessor_key_tag
        ));
    }
    let rdata = chain::zone_key_rdata(&succession.predecessor_spki)
        .ok_or_else(|| "the predecessor key is not a P-256 SubjectPublicKeyInfo".to_string())?;
    if chain::key_tag(&rdata) != succession.predecessor_key_tag {
        return Err(format!(
            "the countersignature claims key tag {} but its key's tag is {}",
            succession.predecessor_key_tag,
            chain::key_tag(&rdata)
        ));
    }
    let point = &rdata[4..];
    let signed = Succession::signed_bytes(
        &apex.to_string(),
        succession.predecessor_key_tag,
        successor_spki,
    );
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(point);
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &uncompressed)
        .verify(&signed, &succession.signature)
        .map_err(|_| "the succession countersignature does not verify".to_string())
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
        known.insert(&name("Sync.Example.Dev."), b"a key");
        assert!(known.contains(&name("sync.example.dev"), b"a key"));
        assert!(known.contains(&name("SYNC.EXAMPLE.DEV."), b"a key"));
        assert!(!known.contains(&name("other.example.dev"), b"a key"));
        assert!(!known.contains(&name("sync.example.dev"), b"another key"));
        // Inserting twice does not double the entry.
        known.insert(&name("sync.example.dev"), b"a key");
        assert_eq!(known.keys["sync.example.dev."].len(), 1);
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
        known.keys.insert("sync.example.dev..".into(), vec![]);
        assert_eq!(known.apexes().count(), 0);
        assert!(!known.contains(&name("sync.example.dev"), b"a key"));
    }

    #[test]
    fn a_spki_that_is_not_a_p256_key_is_not_classifiable() {
        assert!(chain::zone_key_rdata(&[0u8; 91]).is_none());
        let spki = synch_net::rekor::p256_spki(&[7u8; 64]);
        assert!(chain::zone_key_rdata(&spki).is_some());
        assert!(chain::zone_key_rdata(&spki[..90]).is_none());
    }
}
