//! The two custom certificate extensions a zone-key entry carries, and the
//! OIDs that name them (docs/REKOR-ZONE-KEY.md §2).
//!
//! The certificate in a Rekor leaf gets the apex into the log's Merkle tree
//! (see [`crate::x509`]). These two extensions get *evidence* in beside it,
//! so that a monitor consuming the log can decide, from the leaf alone and
//! with no DNS query at all, whether the key it just saw was authorized:
//!
//! - **The DNSSEC chain** (`OID_DNSSEC_CHAIN`) — the delegation from the
//!   apex's DS up to the root DNSKEY, as raw signed RRsets. A monitor
//!   validates it offline against the IANA root trust anchor and demands
//!   only that the RRSIGs were valid *at the log's integration time*, never
//!   that they are valid now: an entry from 2029 must still verify in 2039.
//! - **The succession countersignature** (`OID_SUCCESSION`) — the previous
//!   zone key's signature over "this key follows me". It is what separates a
//!   routine rotation an operator performed from a substitution an attacker
//!   performed with a compromised registrar: the attacker has the DS, so
//!   they can produce the chain, but they do not have the old *private* key.
//!
//! Neither is read by the client. The client validates DNSSEC natively and
//! already holds the DNSKEY it is asking about, so re-deriving authorization
//! from a copy of the chain inside the entry would be a slower way to learn
//! the same fact; and succession is a claim about history, which a client
//! resolving *now* has no use for. Both are monitor food — the client parses
//! past them and does not care (see `rekor::verify`).
//!
//! # Why the OIDs live under `2.25`
//!
//! We hold no IANA Private Enterprise Number, and inventing an arc under
//! someone else's is how OID collisions happen. `2.25` is the UUID arc:
//! `2.25.<uuid as a 128-bit integer>` is allocated by generating a UUID,
//! needs no registration and can collide with nothing. The two below are
//! fixed for the life of this format and are duplicated, deliberately and
//! with the same comment, in `control-plane/src/rekor/cert.gleam`.

use crate::x509::{tlv, Der, X509Error};

/// The DNSSEC chain extension: `2.25.293397732029928475482264626946701631422`
/// (UUID `dcba5907-a9a9-4de1-89fe-7b22794d9fbe`).
///
/// These are the OID's DER *content* bytes: `0x69` is `2.25` packed into the
/// first byte (40 × 2 + 25 = 105), and the rest is the UUID's integer value
/// in base-128 continuation form.
pub const OID_DNSSEC_CHAIN: &[u8] = &[
    0x69, 0x83, 0xb9, 0xba, 0xac, 0xc1, 0xf5, 0x9a, 0xca, 0xb7, 0xc3, 0x89, 0xff, 0x9e, 0xe4, 0xa7,
    0xca, 0xb6, 0xbf, 0x3e,
];

/// The succession countersignature extension:
/// `2.25.90191032005037091005377665797806520834`
/// (UUID `43da2932-67ac-4e03-bcbe-c8c9fee67a02`).
pub const OID_SUCCESSION: &[u8] = &[
    0x69, 0x81, 0x87, 0xda, 0x94, 0xcc, 0xcc, 0xfa, 0xe2, 0xb8, 0x87, 0xbc, 0xdf, 0xb2, 0x99, 0x9f,
    0xf7, 0x99, 0xf4, 0x02,
];

/// The DSSE payload type a succession countersignature is made over.
pub const SUCCESSION_PAYLOAD_TYPE: &str = "application/vnd.synchronicity.succession+json";

// ------------------------------------------------------------ DNSSEC chain

/// One zone's worth of the delegation chain.
///
/// `rrs` is a run of **uncompressed wire-format** resource records —
/// `NAME | TYPE | CLASS | TTL | RDLENGTH | RDATA`, names spelled out in full
/// because a Merkle leaf has no message to compress against. The records a
/// link carries are the ones *owned* by `zone`:
///
/// - the apex link holds the apex's `DS` RRset and its `RRSIG` (signed by the
///   parent) — and no DNSKEY, because the monitor derives the DNSKEY from the
///   certificate's own public key rather than believing a copy of it;
/// - every ancestor link holds that zone's `DNSKEY` RRset + `RRSIG` and its
///   `DS` RRset + `RRSIG`;
/// - the root link holds only the root `DNSKEY` RRset + `RRSIG`, which the
///   IANA trust anchor terminates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink {
    /// The owner zone, as an FQDN (`"."` for the root).
    pub zone: String,
    /// The concatenated wire-format RRs owned by `zone`.
    pub rrs: Vec<u8>,
}

/// `DnssecChain ::= SEQUENCE OF Link`, apex first, root last.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnssecChain {
    /// The links, ordered from the apex upward.
    pub links: Vec<ChainLink>,
}

impl DnssecChain {
    /// The extension value: `SEQUENCE OF SEQUENCE { IA5String, OCTET STRING }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for link in &self.links {
            let mut one = tlv(0x16, link.zone.as_bytes());
            one.extend_from_slice(&tlv(0x04, &link.rrs));
            body.extend_from_slice(&tlv(0x30, &one));
        }
        tlv(0x30, &body)
    }

    /// Parses an extension value, refusing trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<DnssecChain, X509Error> {
        let mut outer = Der::new(bytes);
        let mut list = outer.sequence("DnssecChain")?;
        if !outer.is_empty() {
            return Err(X509Error::from("DnssecChain: bytes after the sequence"));
        }
        let mut links = Vec::new();
        while !list.is_empty() {
            let mut link = list.sequence("Link")?;
            let zone = std::str::from_utf8(link.tagged(0x16, "Link.zone")?)
                .map_err(|_| X509Error::from("Link.zone is not ASCII"))?
                .to_string();
            let rrs = link.tagged(0x04, "Link.rrs")?.to_vec();
            if !link.is_empty() {
                return Err(X509Error::from("Link: unexpected trailing member"));
            }
            links.push(ChainLink { zone, rrs });
        }
        Ok(DnssecChain { links })
    }
}

// -------------------------------------------------------------- succession

/// The previous zone key's countersignature over this one.
///
/// Absent for a zone's genesis key — there is no predecessor — and for
/// disaster recovery, where the predecessor's private key is exactly what
/// was lost. Both land in a monitor's tier B alongside a real compromise,
/// which is correct and has to be said out loud: tier B means *a human looks*,
/// not *an attack happened*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Succession {
    /// The RFC 4034 key tag of the predecessor key.
    pub predecessor_key_tag: u16,
    /// The predecessor's DER SubjectPublicKeyInfo — named explicitly rather
    /// than left to be looked up, because a key tag is a 16-bit checksum and
    /// two keys can share one.
    pub predecessor_spki: Vec<u8>,
    /// ECDSA P-256/SHA-256, DER, by the predecessor key, over
    /// [`Succession::signed_payload`]'s DSSE PAE.
    pub signature: Vec<u8>,
}

impl Succession {
    /// The extension value:
    /// `SEQUENCE { predecessorKeyTag INTEGER, predecessorSpki OCTET STRING,
    /// signature OCTET STRING }`.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = crate::x509::integer(&self.predecessor_key_tag.to_be_bytes());
        body.extend_from_slice(&tlv(0x04, &self.predecessor_spki));
        body.extend_from_slice(&tlv(0x04, &self.signature));
        tlv(0x30, &body)
    }

    /// Parses an extension value, refusing trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Succession, X509Error> {
        let mut outer = Der::new(bytes);
        let mut fields = outer.sequence("Succession")?;
        if !outer.is_empty() {
            return Err(X509Error::from("Succession: bytes after the sequence"));
        }
        let tag = fields.tagged(0x02, "predecessorKeyTag")?;
        // A key tag is 16 bits; DER drops leading zeros and adds one back for
        // a set high bit, so anything up to three bytes can be legitimate.
        if tag.is_empty() || tag.len() > 3 {
            return Err(X509Error::from("predecessorKeyTag is out of range"));
        }
        let value = tag.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
        let predecessor_key_tag = u16::try_from(value)
            .map_err(|_| X509Error::from("predecessorKeyTag is out of range"))?;
        let predecessor_spki = fields.tagged(0x04, "predecessorSpki")?.to_vec();
        let signature = fields.tagged(0x04, "signature")?.to_vec();
        if !fields.is_empty() {
            return Err(X509Error::from("Succession: unexpected trailing member"));
        }
        Ok(Succession {
            predecessor_key_tag,
            predecessor_spki,
            signature,
        })
    }

    /// The canonical JSON payload the countersignature is made over.
    ///
    /// Byte-exact and with no equivalent form, for the same reason the
    /// Statement is: two implementations sign and check these bytes, so
    /// field order and the absence of whitespace are part of the format.
    ///
    /// ```text
    /// {"apex":"<fqdn>","predecessorKeyTag":<int>,"successorSpkiSha256":"<hex>"}
    /// ```
    ///
    /// The successor is named by the SHA-256 of its DER SubjectPublicKeyInfo
    /// rather than by its key tag, so a countersignature commits to the exact
    /// key bytes and not to a 16-bit checksum of them.
    pub fn signed_payload(apex: &str, predecessor_key_tag: u16, successor_spki: &[u8]) -> Vec<u8> {
        let digest = hex::encode(crate::rekor::sha256(successor_spki));
        format!(
            "{{\"apex\":\"{}\",\"predecessorKeyTag\":{},\"successorSpkiSha256\":\"{}\"}}",
            apex.trim_end_matches('.'),
            predecessor_key_tag,
            digest
        )
        .into_bytes()
    }

    /// The exact bytes signed: the DSSE PAE of [`Succession::signed_payload`]
    /// under [`SUCCESSION_PAYLOAD_TYPE`], so a succession statement can never
    /// be reinterpreted as an in-toto Statement or the other way round.
    pub fn signed_bytes(apex: &str, predecessor_key_tag: u16, successor_spki: &[u8]) -> Vec<u8> {
        crate::rekor::pae(
            SUCCESSION_PAYLOAD_TYPE,
            &Succession::signed_payload(apex, predecessor_key_tag, successor_spki),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_round_trips_and_keeps_its_order() {
        let chain = DnssecChain {
            links: vec![
                ChainLink {
                    zone: "sync.example.dev.".into(),
                    rrs: vec![0xaa; 200],
                },
                ChainLink {
                    zone: "example.dev.".into(),
                    rrs: vec![0xbb; 400],
                },
                ChainLink {
                    zone: ".".into(),
                    rrs: vec![0xcc; 1200],
                },
            ],
        };
        let der = chain.encode();
        assert_eq!(DnssecChain::decode(&der).unwrap(), chain);
        // The apex comes first and the root last; a decoder that sorted or
        // reversed would still round-trip a one-link chain, so assert three.
        let back = DnssecChain::decode(&der).unwrap();
        assert_eq!(back.links[0].zone, "sync.example.dev.");
        assert_eq!(back.links[2].zone, ".");

        // Trailing bytes are a second encoding of the same value, which is
        // exactly what a decoder must never accept.
        let mut extra = der.clone();
        extra.push(0);
        assert!(DnssecChain::decode(&extra).is_err());
        assert!(DnssecChain::decode(&der[..der.len() - 1]).is_err());
        assert!(DnssecChain::decode(&[]).is_err());

        // An empty chain is representable — a chainless retire says so by
        // omitting the extension, not by carrying an empty one, but the codec
        // must not lose the distinction.
        let empty = DnssecChain::default();
        assert_eq!(DnssecChain::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn a_succession_round_trips_across_the_key_tag_range() {
        for tag in [0u16, 1, 127, 128, 255, 256, 34_918, 65_535] {
            let succession = Succession {
                predecessor_key_tag: tag,
                predecessor_spki: vec![0x30, 0x59, 0x11],
                signature: vec![0x30, 0x44, 0x02],
            };
            let der = succession.encode();
            assert_eq!(Succession::decode(&der).unwrap(), succession, "tag {tag}");
        }
        let der = Succession {
            predecessor_key_tag: 7,
            predecessor_spki: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        }
        .encode();
        let mut extra = der.clone();
        extra.push(0);
        assert!(Succession::decode(&extra).is_err());
        assert!(Succession::decode(&der[..3]).is_err());
    }

    #[test]
    fn the_countersigned_payload_is_byte_exact() {
        let payload = Succession::signed_payload("sync.example.dev.", 34_918, b"spki bytes");
        assert_eq!(
            String::from_utf8(payload).unwrap(),
            format!(
                "{{\"apex\":\"sync.example.dev\",\"predecessorKeyTag\":34918,\
                 \"successorSpkiSha256\":\"{}\"}}",
                hex::encode(crate::rekor::sha256(b"spki bytes"))
            )
        );
        // The apex is written without its root dot, so the two halves cannot
        // disagree about a trailing character nobody can see.
        assert_eq!(
            Succession::signed_payload("sync.example.dev", 1, b"k"),
            Succession::signed_payload("sync.example.dev.", 1, b"k")
        );
        // And the signed bytes are the PAE of that payload under the
        // succession type, never the in-toto one.
        let bytes = Succession::signed_bytes("sync.example.dev", 1, b"k");
        assert!(bytes.starts_with(b"DSSEv1 45 application/vnd.synchronicity.succession+json "));
    }
}
