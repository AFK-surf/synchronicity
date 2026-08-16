//! Deciding what a leaf is: routine rotation, compromise signature, or noise.
//!
//! Everything here works from the certificate inside the leaf and nothing
//! else. In particular the DNSKEY, its key tag and the DS a parent would have
//! published are all **derived from the certificate's SubjectPublicKeyInfo**,
//! never looked up: the threat model has a compromised upstream DNS provider
//! in it, so a monitor that asked DNS what the zone's key is would be asking
//! the attacker.

use hickory_resolver::proto::dnssec::TrustAnchors;
use ring::signature;
use synch_net::{
    chain::{self, SigWindow},
    rekor::{p256_spki, sha256, HashedRekordBody, ZONE_KEY_ALGORITHM, ZONE_KEY_FLAGS},
    x509::same_dns_name,
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
    pub fn contains(&self, apex: &str, spki: &[u8]) -> bool {
        let digest = hex::encode(sha256(spki));
        self.keys
            .iter()
            .filter(|(known, _)| same_dns_name(known, apex))
            .any(|(_, digests)| digests.iter().any(|d| d.eq_ignore_ascii_case(&digest)))
    }

    /// Records a key as known for `apex`.
    pub fn insert(&mut self, apex: &str, spki: &[u8]) {
        let key = apex.trim_end_matches('.').to_ascii_lowercase();
        let digest = hex::encode(sha256(spki));
        let entry = self.keys.entry(key).or_default();
        if !entry.iter().any(|d| d.eq_ignore_ascii_case(&digest)) {
            entry.push(digest);
        }
    }

    /// The apexes this monitor has an opinion about.
    pub fn apexes(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
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
/// `witness_time` is the moment the checkpoint's witnesses attested to, when
/// there is one. It is used for exactly one thing: noting that a chain's
/// signatures were already outside their validity window when the world last
/// saw this tree. That is a **sub-reason on a tier B finding**, never a
/// demotion to tier C — the monitor's chain rule has to stay no stricter than
/// the client's, or the silent bin becomes an evasion (see the crate docs).
pub fn classify(
    body: &HashedRekordBody,
    log_index: u64,
    known: &KnownKeys,
    anchors: &TrustAnchors,
    witness_time: Option<u64>,
) -> Option<Finding> {
    let apex = body.certificate.single_dns_name().ok()?.to_string();
    // Only the P-256 keys this design logs are classifiable at all; anything
    // else in the certificate is somebody else's entry that happens to have
    // a SAN, and saying nothing about it is the honest answer.
    let point = zone_key_point(&body.certificate.spki)?;
    let dnskey_rdata = dnskey_rdata(point);
    let key_tag = chain::key_tag(&dnskey_rdata);
    let ds = chain::ds_fields(&apex, &dnskey_rdata).unwrap_or_else(|_| "?".into());
    let mut finding = Finding {
        log_index,
        apex: apex.clone(),
        key_tag,
        spki_sha256: hex::encode(sha256(&body.certificate.spki)),
        ds,
        tier: Tier::C,
        reasons: Vec::new(),
        predecessor_key_tag: None,
    };

    let valid = match body
        .dnssec_chain()
        .and_then(|chain| chain::validate(&chain, &apex, &dnskey_rdata, anchors))
    {
        Ok(valid) => valid,
        Err(why) => {
            // No client would have accepted this either — the client runs
            // this same validator and refuses what it rejects — so an entry
            // here is an unauthorized claim nobody could have been served.
            finding.reasons.push(format!("unauthorized claim: {why}"));
            return Some(finding);
        }
    };
    finding.reasons.push(format!(
        "DNSSEC chain valid to {} ({} signatures)",
        valid.anchor_zone,
        valid.windows.len()
    ));
    if let Some(note) = stale_at(&valid.windows, witness_time) {
        finding.reasons.push(note);
    }

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
    apex: &str,
    successor_spki: &[u8],
    known: &KnownKeys,
) -> Result<(), String> {
    if !known.contains(apex, &succession.predecessor_spki) {
        return Err(format!(
            "the countersigning key (tag {}) is not one this monitor knows for {apex}",
            succession.predecessor_key_tag
        ));
    }
    let point = zone_key_point(&succession.predecessor_spki)
        .ok_or_else(|| "the predecessor key is not a P-256 SubjectPublicKeyInfo".to_string())?;
    if chain::key_tag(&dnskey_rdata(point)) != succession.predecessor_key_tag {
        return Err(format!(
            "the countersignature claims key tag {} but its key's tag is {}",
            succession.predecessor_key_tag,
            chain::key_tag(&dnskey_rdata(point))
        ));
    }
    let signed = Succession::signed_bytes(apex, succession.predecessor_key_tag, successor_spki);
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(point);
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &uncompressed)
        .verify(&signed, &succession.signature)
        .map_err(|_| "the succession countersignature does not verify".to_string())
}

/// A note when the chain's signatures did not cover the moment the log's
/// witnesses last attested to. Informational, and deliberately so.
fn stale_at(windows: &[SigWindow], witness_time: Option<u64>) -> Option<String> {
    let at = witness_time?;
    let stale = windows.iter().filter(|w| !w.covers(at)).count();
    match stale {
        0 => None,
        n => Some(format!(
            "{n} of {} chain signature(s) were outside their validity window at the \
             witnesses' timestamp — expected for an archival entry, worth a look for a fresh one",
            windows.len()
        )),
    }
}

/// The 64-byte P-256 point inside a DER SubjectPublicKeyInfo, if that is what
/// this is.
fn zone_key_point(spki: &[u8]) -> Option<&[u8]> {
    let rebuilt = |point: &[u8]| p256_spki(point) == spki;
    let point = spki.get(27..)?;
    (point.len() == 64 && rebuilt(point)).then_some(point)
}

/// The DNSKEY rdata a zone key implies: the CSK convention this design logs.
fn dnskey_rdata(point: &[u8]) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(4 + 64);
    rdata.extend_from_slice(&ZONE_KEY_FLAGS.to_be_bytes());
    rdata.push(3);
    rdata.push(ZONE_KEY_ALGORITHM);
    rdata.extend_from_slice(point);
    rdata
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_keys_compare_names_the_way_dns_does() {
        let mut known = KnownKeys::default();
        known.insert("Sync.Example.Dev.", b"a key");
        assert!(known.contains("sync.example.dev", b"a key"));
        assert!(known.contains("SYNC.EXAMPLE.DEV.", b"a key"));
        assert!(!known.contains("other.example.dev", b"a key"));
        assert!(!known.contains("sync.example.dev", b"another key"));
        // Inserting twice does not double the entry.
        known.insert("sync.example.dev", b"a key");
        assert_eq!(known.keys["sync.example.dev"].len(), 1);
    }

    #[test]
    fn a_spki_that_is_not_a_p256_key_is_not_classifiable() {
        assert!(zone_key_point(&[0u8; 91]).is_none());
        assert!(zone_key_point(&p256_spki(&[7u8; 64])).is_some());
        assert!(zone_key_point(&p256_spki(&[7u8; 64])[..90]).is_none());
    }

    #[test]
    fn a_stale_chain_is_a_note_and_never_a_verdict() {
        let window = SigWindow {
            zone_index: 0,
            type_covered: hickory_resolver::proto::rr::RecordType::DS,
            inception: 100,
            expiration: 200,
        };
        assert!(stale_at(&[window], Some(150)).is_none());
        assert!(stale_at(&[window], Some(500)).is_some());
        // With no witness timestamp there is no clock, so there is no note.
        assert!(stale_at(&[window], None).is_none());
    }
}
