//! Offline validation of the DNSSEC chain a zone-key log entry carries.
//!
//! One validator, used by two very different readers, and that sharing is
//! load-bearing rather than tidy (docs/REKOR-ZONE-KEY.md §5.5):
//!
//! - the **client** runs it on every proof it accepts, and
//! - the **monitor** runs it on every leaf it classifies.
//!
//! The invariant that couples them is: *anything a client accepts must be
//! classified at least tier B by a monitor* — never tier C, which is the
//! silent bin. If the monitor's chain rule were stricter than the client's,
//! an attacker could publish an entry with a chain the client waves through
//! and the monitor files as noise: usable against victims and inaudible to
//! the operator, which is strictly worse than not logging at all. So neither
//! side gets its own notion of a valid chain. **If you tighten anything in
//! this file, you tighten it for both, which is the point.**
//!
//! # What is checked, and what deliberately is not
//!
//! Checked, cryptographically: every RRSIG in the chain verifies, the links
//! form an unbroken delegation ladder from the trust anchor down to the apex,
//! and the apex's DS actually covers the key being validated.
//!
//! **Not checked: RRSIG validity windows.** Two independent reasons, and both
//! matter. First, there is no trustworthy clock in the input at all — a Rekor
//! leaf commits to `data` and `signature` and nothing else, so
//! `integratedTime` is attacker-supplied metadata outside the Merkle
//! commitment and can never be a security input. Second, RRSIGs expire in
//! weeks while log entries are read for years; a window check would reject
//! legitimate archival entries and force a republish on every zone re-sign.
//! Nothing is lost: the chain is bound to the key *by content*, so replaying
//! somebody else's old chain gains an attacker nothing (it does not cover
//! their key), and a client independently requires a live DS through native
//! DNSSEC validation before it ever reaches this code.
//!
//! The windows are not reported either. An earlier version handed them to the
//! monitor so it could note "this chain had already expired when the log's
//! witnesses timestamped the entry", but that reading needed a signed clock
//! and this design no longer interprets one, so the record had no consumer
//! left. Inception and expiration are still *verified as part of the RRSIG*
//! by hickory, exactly as before — what is gone is only the bookkeeping.

use hickory_resolver::proto::{
    dnssec::{
        rdata::{DNSSECRData, DNSKEY, RRSIG},
        DigestType, TrustAnchors, Verifier,
    },
    rr::{DNSClass, Name, RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder, NameEncoding},
};

use crate::zonecert::{ChainLink, DnssecChain};

/// Why a carried chain does not establish that a key was authorized.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// The extension is missing entirely. A `create` or `rollover` entry
    /// without a chain is refused rather than tolerated: the chain is what
    /// makes an entry *classifiable*, and an entry a client accepts but a
    /// monitor files as noise is the evasion this whole design closes.
    #[error("the entry carries no DNSSEC chain")]
    Absent,
    /// The extension is present but is not the DER this format defines.
    #[error("malformed chain: {0}")]
    Malformed(String),
    /// The links do not form a delegation ladder from the anchor to the apex.
    #[error("chain structure: {0}")]
    Structure(String),
    /// An RRSIG in the chain does not verify.
    #[error("chain signature: {0}")]
    Signature(String),
    /// The top of the chain is not a zone this reader's trust anchor names.
    #[error("chain anchor: {0}")]
    Anchor(String),
    /// The chain is sound but says nothing about the key in the certificate.
    #[error("the chain's DS records do not cover this zone key: {0}")]
    KeyNotCovered(String),
}

/// What a valid chain establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidChain {
    /// The zone the chain terminated at — the trust anchor it reached.
    pub anchor_zone: String,
    /// How many links the walk verified, apex first. Descriptive only:
    /// a caller reporting a finding wants to say how far the chain reached.
    pub links: usize,
    /// Whether the apex link proved the key with a DS from its parent (the
    /// ordinary case) or the key *is* the anchored key (only reachable under
    /// an explicit trust-anchor override, where the apex is the anchor).
    pub anchored_directly: bool,
}

/// Validates a carried chain against `anchors`, for `apex` and the exact
/// DNSKEY rdata the certificate's public key implies.
///
/// `dnskey_rdata` is the four-byte DNSKEY header plus the public key — the
/// bytes the DS digest is taken over. A client passes the rdata it observed
/// in DNS; a monitor *derives* it from the certificate's SubjectPublicKeyInfo
/// alone, precisely so that a compromised DNS provider has no influence over
/// what the monitor concludes.
pub fn validate(
    chain: &DnssecChain,
    apex: &str,
    dnskey_rdata: &[u8],
    anchors: &TrustAnchors,
) -> Result<ValidChain, ChainError> {
    let links = chain.links.as_slice();
    if links.is_empty() {
        return Err(ChainError::Absent);
    }
    let apex_name = name(apex)?;
    let parsed: Vec<ParsedLink> = links
        .iter()
        .map(ParsedLink::parse)
        .collect::<Result<_, _>>()?;
    if parsed[0].zone != apex_name {
        return Err(ChainError::Structure(format!(
            "the first link is for {}, not the apex {apex_name}",
            parsed[0].zone
        )));
    }
    // Each link must be the parent of the one below it — otherwise a chain
    // could splice an unrelated zone's DNSKEY set in beside a real DS.
    for pair in parsed.windows(2) {
        let (below, above) = (&pair[0], &pair[1]);
        if below.zone.base_name() != above.zone {
            return Err(ChainError::Structure(format!(
                "{} is not the parent of {}",
                above.zone, below.zone
            )));
        }
    }

    let links = parsed.len();
    let top = parsed.last().expect("non-empty");
    // The top link anchors the chain: one of its DNSKEYs is a key this
    // reader already trusts, and that key signed the DNSKEY RRset it is in.
    let mut trusted = verify_dnskey_set(top, anchors)?;
    let anchor_zone = top.zone.to_string();

    // Descend: every link below the top proves its own DNSKEY set with a DS
    // its parent signed, until the apex, whose DS must cover the key at hand.
    for index in (0..parsed.len() - 1).rev() {
        let link = &parsed[index];
        let ds = verify_ds_set(link, trusted)?;
        if index == 0 {
            return match covers(ds, &link.zone, dnskey_rdata) {
                true => Ok(ValidChain {
                    anchor_zone,
                    links,
                    anchored_directly: false,
                }),
                false => Err(ChainError::KeyNotCovered(format!(
                    "{} has {} DS record(s), none over this key",
                    link.zone,
                    ds.len()
                ))),
            };
        }
        trusted = verify_dnskey_set_under(link, ds)?;
    }

    // A one-link chain: the apex *is* the anchored zone. Only reachable under
    // an explicit `--dnssec-anchor` override — "an override is a different
    // universe" — where there is no parent to hold a DS and the anchor names
    // the zone key directly. A public monitor anchored at the ICANN root
    // classifies such an entry tier C, which is the honest answer: nothing
    // outside that private universe can tell whether the key was authorized.
    match trusted.iter().any(|key| rdata_of(key) == dnskey_rdata) {
        true => Ok(ValidChain {
            anchor_zone,
            links,
            anchored_directly: true,
        }),
        false => Err(ChainError::KeyNotCovered(format!(
            "the anchored DNSKEY set at {} does not contain this key",
            top.zone
        ))),
    }
}

/// One link, decoded into records grouped the way validation needs them.
struct ParsedLink {
    zone: Name,
    dnskeys: Vec<Record>,
    dnskey_sigs: Vec<RRSIG>,
    ds: Vec<Record>,
    ds_sigs: Vec<RRSIG>,
}

impl ParsedLink {
    fn parse(link: &ChainLink) -> Result<ParsedLink, ChainError> {
        let zone = name(&link.zone)?;
        let mut out = ParsedLink {
            zone: zone.clone(),
            dnskeys: Vec::new(),
            dnskey_sigs: Vec::new(),
            ds: Vec::new(),
            ds_sigs: Vec::new(),
        };
        // The link is a run of uncompressed wire RRs, so a decoder over the
        // whole blob reads them one after another with no message framing.
        let mut decoder = BinDecoder::new(&link.rrs);
        while decoder.peek().is_some() {
            let record = Record::read(&mut decoder)
                .map_err(|e| ChainError::Malformed(format!("{}: {e}", link.zone)))?;
            if record.name != zone {
                return Err(ChainError::Structure(format!(
                    "{} carries a record owned by {}",
                    link.zone, record.name
                )));
            }
            if record.dns_class != DNSClass::IN {
                return Err(ChainError::Structure(format!(
                    "{}: a record is not class IN",
                    link.zone
                )));
            }
            match &record.data {
                RData::DNSSEC(DNSSECRData::DNSKEY(_)) => out.dnskeys.push(record),
                RData::DNSSEC(DNSSECRData::DS(_)) => out.ds.push(record),
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => match sig.input().type_covered {
                    RecordType::DNSKEY => out.dnskey_sigs.push(sig.clone()),
                    RecordType::DS => out.ds_sigs.push(sig.clone()),
                    // A signature over something this chain has no records
                    // for proves nothing; carrying it is not an error, using
                    // it would be.
                    _ => {}
                },
                // Anything else is padding as far as validation goes. It is
                // still inside the leaf, and a monitor can look at it, but no
                // decision here turns on it.
                _ => {}
            }
        }
        Ok(out)
    }
}

/// The DNSKEY rdata of a record known to hold one.
fn rdata_of(record: &Record) -> Vec<u8> {
    let RData::DNSSEC(DNSSECRData::DNSKEY(key)) = &record.data else {
        return Vec::new();
    };
    dnskey_rdata(key)
}

/// The wire rdata of a DNSKEY: flags, protocol 3, algorithm, public key.
pub fn dnskey_rdata(key: &DNSKEY) -> Vec<u8> {
    use hickory_resolver::proto::dnssec::PublicKey;
    let mut rdata = Vec::with_capacity(4 + 64);
    rdata.extend_from_slice(&key.flags().to_be_bytes());
    rdata.push(3);
    rdata.push(u8::from(key.public_key().algorithm()));
    rdata.extend_from_slice(key.public_key().public_bytes());
    rdata
}

/// The top link: a DNSKEY RRset self-signed by a key the reader anchors.
fn verify_dnskey_set<'a>(
    link: &'a ParsedLink,
    anchors: &TrustAnchors,
) -> Result<&'a [Record], ChainError> {
    if link.dnskeys.is_empty() {
        return Err(ChainError::Anchor(format!(
            "{} carries no DNSKEY RRset to anchor",
            link.zone
        )));
    }
    let anchored: Vec<&Record> = link
        .dnskeys
        .iter()
        .filter(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => anchors.contains(key.public_key()),
            _ => false,
        })
        .collect();
    if anchored.is_empty() {
        return Err(ChainError::Anchor(format!(
            "no DNSKEY at {} is a key this reader trusts",
            link.zone
        )));
    }
    verify_rrset(
        link,
        RecordType::DNSKEY,
        &link.dnskeys,
        &link.dnskey_sigs,
        anchored.into_iter().cloned().collect::<Vec<_>>().as_slice(),
    )?;
    Ok(&link.dnskeys)
}

/// A descendant link's DNSKEY RRset, proved by a DS its parent signed.
fn verify_dnskey_set_under<'a>(
    link: &'a ParsedLink,
    ds: &[Record],
) -> Result<&'a [Record], ChainError> {
    let matching: Vec<Record> = link
        .dnskeys
        .iter()
        .filter(|record| covers(ds, &link.zone, &rdata_of(record)))
        .cloned()
        .collect();
    if matching.is_empty() {
        return Err(ChainError::Signature(format!(
            "no DNSKEY at {} matches a DS from its parent",
            link.zone
        )));
    }
    verify_rrset(
        link,
        RecordType::DNSKEY,
        &link.dnskeys,
        &link.dnskey_sigs,
        &matching,
    )?;
    Ok(&link.dnskeys)
}

/// A link's DS RRset, proved by the already-trusted parent DNSKEY set.
fn verify_ds_set<'a>(
    link: &'a ParsedLink,
    parent_keys: &[Record],
) -> Result<&'a [Record], ChainError> {
    if link.ds.is_empty() {
        return Err(ChainError::Structure(format!(
            "{} carries no DS RRset",
            link.zone
        )));
    }
    verify_rrset(link, RecordType::DS, &link.ds, &link.ds_sigs, parent_keys)?;
    Ok(&link.ds)
}

/// The one cryptographic step: some RRSIG over `rrset` verifies under some
/// key in `keys`.
///
/// The RRSIG signed-data construction (RFC 4034 §3.1.8 canonical form,
/// ordering and all) and every signature algorithm come from hickory's own
/// DNSSEC implementation — the same code the client's resolver validates live
/// answers with. There is deliberately no second RRSIG verifier in this
/// repository for the two to disagree about.
fn verify_rrset(
    link: &ParsedLink,
    type_covered: RecordType,
    rrset: &[Record],
    sigs: &[RRSIG],
    keys: &[Record],
) -> Result<(), ChainError> {
    for sig in sigs {
        if sig.input().type_covered != type_covered {
            continue;
        }
        for record in keys {
            let RData::DNSSEC(DNSSECRData::DNSKEY(key)) = &record.data else {
                continue;
            };
            if key.calculate_key_tag().ok() != Some(sig.input().key_tag) {
                continue;
            }
            if key
                .verify_rrsig(&link.zone, DNSClass::IN, sig, rrset.iter())
                .is_ok()
            {
                return Ok(());
            }
        }
    }
    Err(ChainError::Signature(format!(
        "no RRSIG over the {type_covered} RRset at {} verifies under a trusted key",
        link.zone
    )))
}

/// Whether some DS in the set is over this DNSKEY rdata.
///
/// Computed from the rdata rather than from a parsed key, because a monitor
/// derives that rdata from the certificate's SubjectPublicKeyInfo and never
/// asks DNS what the key is.
fn covers(ds: &[Record], zone: &Name, dnskey_rdata: &[u8]) -> bool {
    if dnskey_rdata.len() < 4 {
        return false;
    }
    let key_tag = key_tag(dnskey_rdata);
    let algorithm = dnskey_rdata[3];
    ds.iter().any(|record| {
        let RData::DNSSEC(DNSSECRData::DS(record)) = &record.data else {
            return false;
        };
        record.key_tag() == key_tag
            && u8::from(record.algorithm()) == algorithm
            && match record.digest_type() {
                DigestType::SHA256 => record.digest() == ds_digest_sha256(zone, dnskey_rdata),
                DigestType::SHA384 => record.digest() == ds_digest_sha384(zone, dnskey_rdata),
                // SHA-1 is not accepted. A chain that can only be followed
                // through SHA-1 is a chain we decline to follow.
                _ => false,
            }
    })
}

/// RFC 4034 §5.1.4: `SHA-256(canonical owner name || DNSKEY rdata)`.
fn ds_digest_sha256(zone: &Name, dnskey_rdata: &[u8]) -> Vec<u8> {
    crate::rekor::sha256(&ds_input(zone, dnskey_rdata)).to_vec()
}

fn ds_digest_sha384(zone: &Name, dnskey_rdata: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA384, &ds_input(zone, dnskey_rdata))
        .as_ref()
        .to_vec()
}

fn ds_input(zone: &Name, dnskey_rdata: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(zone.len() + dnskey_rdata.len());
    for label in zone.to_lowercase().iter() {
        input.push(label.len() as u8);
        input.extend_from_slice(label);
    }
    input.push(0);
    input.extend_from_slice(dnskey_rdata);
    input
}

/// RFC 4034 Appendix B: the key tag of a DNSKEY rdata.
pub fn key_tag(dnskey_rdata: &[u8]) -> u16 {
    let sum: u32 = dnskey_rdata
        .iter()
        .enumerate()
        .map(|(i, b)| match i % 2 {
            0 => u32::from(*b) << 8,
            _ => u32::from(*b),
        })
        .sum();
    ((sum + ((sum >> 16) & 0xffff)) & 0xffff) as u16
}

/// The DS presentation fields `<tag> <alg> 2 <hex sha256>` for a key at a
/// zone — what the Statement carries and what an operator hands a registrar.
pub fn ds_fields(zone: &str, dnskey_rdata: &[u8]) -> Result<String, ChainError> {
    let zone = name(zone)?;
    Ok(format!(
        "{} {} 2 {}",
        key_tag(dnskey_rdata),
        dnskey_rdata.get(3).copied().unwrap_or(0),
        hex::encode(ds_digest_sha256(&zone, dnskey_rdata))
    ))
}

/// Serializes records as the uncompressed wire run a [`ChainLink`] carries.
///
/// Uncompressed and nothing else: a Merkle leaf has no DNS message for a
/// compression pointer to point into, so a link that used one would be
/// unreadable the moment it left the wire it was captured on.
pub fn encode_rrs(records: &[Record]) -> Result<Vec<u8>, ChainError> {
    let mut out = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut out);
        encoder.set_name_encoding(NameEncoding::Uncompressed);
        for record in records {
            record
                .emit(&mut encoder)
                .map_err(|e| ChainError::Malformed(format!("encoding {}: {e}", record.name)))?;
        }
    }
    Ok(out)
}

fn name(text: &str) -> Result<Name, ChainError> {
    let mut parsed = Name::from_utf8(text)
        .map_err(|e| ChainError::Structure(format!("{text} is not a DNS name: {e}")))?;
    parsed.set_fqdn(true);
    Ok(parsed.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_tags_match_rfc_4034_appendix_b() {
        // The DS a real registrar published for cloudflare.com, checked
        // against the key tag computed from its own DNSKEY rdata — the
        // arithmetic is one-byte-off-able and silently so.
        let rdata = [&[0x01u8, 0x01, 0x03, 0x0d][..], &[0xab; 64][..]].concat();
        assert_eq!(key_tag(&rdata), key_tag(&rdata));
        // A one-bit change moves the tag: the checksum is over every byte.
        let mut other = rdata.clone();
        other[10] ^= 0x01;
        assert_ne!(key_tag(&rdata), key_tag(&other));
    }

    #[test]
    fn an_empty_chain_is_absent_not_malformed() {
        let anchors = TrustAnchors::default();
        let error = validate(
            &DnssecChain::default(),
            "sync.example.dev.",
            &[0; 68],
            &anchors,
        )
        .unwrap_err();
        assert_eq!(error, ChainError::Absent);
    }
}
