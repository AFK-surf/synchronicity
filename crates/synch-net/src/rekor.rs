//! Zone-key transparency: the offline half (docs/REKOR-ZONE-KEY.md).
//!
//! DNSSEC answers *is this key authorized for this zone?* by delegation, and
//! every link in that delegation is an institution that can be compromised or
//! compelled. A substituted DS names an attacker's key, the attacker signs a
//! perfectly valid zone, and nothing in DNSSEC makes the substitution visible
//! to the zone's real operator. Requiring the zone key to appear in a public,
//! append-only log does not prevent the substitution — it makes it *public*.
//! An attacker must either log their key under the operator's apex, where a
//! monitor sees it, or fail validation here.
//!
//! Everything in this module is pure and offline. A proof arrives inside the
//! zone (a TXT record at `_synchronicity-rekor.<apex>`), so the client never
//! talks to Rekor: the proof verifies against the DNSKEY the chain already
//! validated and against a *pinned* log key, never against where it came
//! from. Fail closed — every check below refuses rather than degrades, and
//! the caller keeps its previously cached member set (§4.3).
//!
//! What an entry claims is an authorized **key set**: the apex DNSKEY RRset
//! its embedded chain proves. The entry's own signature is *attribution* —
//! it names whoever built the entry, via the certificate's key — and
//! authorizes nothing. Authorization is the chain, and only the chain: an
//! attacker able to forge a chain for a rogue key necessarily holds that key
//! and could sign anything it liked, so a possession requirement would add
//! no security while making a provider-held zone key (Cloudflare's, Bunny's)
//! impossible to log at all. See docs/EXTERNAL-DNS-PROVIDER.md.
//!
//! # Wire format
//!
//! `RekorProof` v4, big-endian throughout:
//!
//! ```text
//! u8       version            = 4
//! u8[32]   log_id               SHA-256 of the log's DER SubjectPublicKeyInfo
//! u64      log_index
//! u16+[]   statement            the in-toto Statement, byte-exact (PAE preimage)
//! u16+[]   canonicalized_body   the Rekor entry body, verbatim (leaf preimage)
//! u16+[]   checkpoint           signed note: origin, tree size, root hash, sigs
//! u8+[32]* inclusion_path       Merkle audit path, leaf to root
//! ```
//!
//! There is no key-tag selector: a record's subject is a set, so a client
//! tries each record the zone serves and membership decides.
//!
//! # What this format pins — and why the verifier is a *certificate*
//!
//! A proof is only checkable if both halves agree byte for byte on what was
//! hashed, so this record carries the exact two byte strings the public log
//! itself commits to:
//!
//! 1. **The log entry** is a `hashedrekord` v0.0.2 body. Rekor v2 accepts no
//!    other entry type — `internal/server/service.go` rejects everything with
//!    "invalid type, must be hashedrekord", and the deprecated DSSE type only
//!    ever stored a `payloadHash` — so a DSSE-signed Statement is logged as a
//!    `hashedrekord` over the DSSE **PAE**: `data.digest = SHA-256(PAE)`,
//!    `signature.content` = the ECDSA-P256 signature over that digest (DER,
//!    not raw). The log returns these bytes as `canonicalizedBody` and this
//!    record carries them **verbatim** — nothing here re-canonicalizes JSON,
//!    because the log already did and the leaf commits to its output.
//! 2. **The verifier is an `x509Certificate`, never a raw public key.** This
//!    is the whole of v3. A raw-key entry is *apex-anonymous*: its leaf holds
//!    a digest, a signature and 91 bytes of SubjectPublicKeyInfo, and nothing
//!    that names a zone. Nobody could monitor a zone for newly published
//!    keys, which makes the transparency claim hollow — the threat model has
//!    a compromised upstream DNS provider in it, so DNS-served state cannot
//!    be the monitoring channel. Rekor's `Verifier` is a oneof of exactly two
//!    arms, and it performs **no** certificate validation on the second one
//!    (`pkg/verifier/certificate`: parse, take the public key, stop), copying
//!    the certificate DER verbatim into the canonicalized body. So a
//!    self-signed certificate carrying the apex as a `dNSName` SAN puts the
//!    zone name, in the clear, inside the Merkle leaf — where a monitor
//!    walking the log's tiles can index it (docs/REKOR-ZONE-KEY.md §5.5).
//! 3. **The Merkle leaf** is `SHA-256(0x00 || canonicalized_body)`, and an
//!    interior node is `SHA-256(0x01 || left || right)` — RFC 6962 §2.1.
//!
//! The Statement travels alongside the body (not inside it) because the body
//! commits only to the PAE *digest*; the client re-derives that digest from
//! the Statement bytes and refuses the proof if they disagree. None of this
//! is negotiable per deployment: a v4 of the record format is how it changes.

use std::path::Path;

use hickory_resolver::proto::dnssec::TrustAnchors;
use ring::{digest, signature};

use crate::{
    chain::{self, ChainError},
    x509::Certificate,
    zonecert::{self, DnssecChain},
};

/// The only `RekorProof` version this build accepts.
///
/// v4 is the key-set format: the entry authorizes the apex DNSKEY RRset its
/// chain proves, the entry signature is attribution by the certificate's own
/// key, and the wire carries no key-tag selector. No earlier version is
/// readable — v3's possession semantics are not this claim, and accepting a
/// v2 raw-key entry would be accepting the unmonitorable shape v3 abolished.
pub const PROOF_VERSION: u8 = 4;

/// The label the proof records live under, one below the zone apex.
pub const REKOR_TXT_PREFIX: &str = "_synchronicity-rekor";

/// The DSSE payload type of an in-toto Statement.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The only entry kind Rekor v2 accepts, and the only one this design logs.
pub const HASHEDREKORD_KIND: &str = "hashedrekord";

/// The entry API version the body must declare.
pub const HASHEDREKORD_API_VERSION: &str = "0.0.2";

/// The `hashedrekord` v0.0.2 digest algorithm name the body carries.
pub const HASHEDREKORD_DIGEST_ALGORITHM: &str = "SHA2_256";

/// The `hashedrekord` v0.0.2 verifier key-details tag for a P-256 key.
pub const HASHEDREKORD_KEY_DETAILS: &str = "PKIX_ECDSA_P256_SHA_256";

/// The in-toto Statement type the entry must declare.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// The predicate type carrying the zone-key claim.
///
/// v2 is the key-set claim: the subject is the apex DNSKEY RRset the chain
/// proves, and the DSSE signer is whoever published the entry — attribution,
/// not possession.
pub const PREDICATE_TYPE: &str = "https://synchronicity.sh/zone-key/v2";

/// The log verification keys compiled into this build — the **bootstrap**
/// set, not the last word.
///
/// A snapshot of Sigstore's production transparency logs, taken from the
/// TUF repository's `trusted_root.json` (consistent-snapshot target
/// `6494e21e…`, its SHA-256 checked against the signed `targets.json`;
/// fetched 2026-08-15 from `tuf-repo-cdn.sigstore.dev`).
///
/// These are what a client runs on until it learns better. The in-client TUF
/// workflow ships (§10, [`crate::tuf`]): a client that accepts a TUF bundle
/// relayed by a zone runs on the tlogs that bundle's `trusted_root.json`
/// names instead, persisted in `<data-dir>/rekor-pins.json` and **replacing**
/// this set rather than unioning with it. So the resolution order is
/// `--rekor-key` if given, else the last TUF-verified pin set, else this.
/// Rotating a Sigstore log key is therefore not a new build any more; only a
/// TUF-*root*-level incident is.
///
/// Note that this format's `log_id` is always SHA-256 over the DER
/// SubjectPublicKeyInfo, computed here from the key bytes themselves.
///
/// **There are two 32-byte log ids in play and only one of them is ours.**
/// Rekor's `TransparencyLogEntry.logId.keyId` — which sits a few lines away
/// from the checkpoint in the same JSON response, and is exactly as long, and
/// looks exactly as plausible — is the C2SP **note key id**,
/// `SHA-256(origin ‖ 0x0A ‖ 0x01 ‖ raw32)`. Copying that value into a proof
/// produces a record that matches no pin and fails with "unknown log", which
/// reads like a misconfigured pin set rather than the mix-up it is. The
/// trusted root shows the same split: it agrees with us for the P-256 log and
/// disagrees for the Ed25519 one. What a proof's `log_id` must match is this
/// convention. (Found the hard way while driving a live submission; the
/// control plane's `rekor/proof.log_id` was right all along.)
pub const EMBEDDED_LOG_KEYS: &str = "\
# Sigstore production transparency logs, snapshotted from the TUF
# repository's trusted_root.json. See EMBEDDED_LOG_KEYS in rekor.rs.
# rekor.sigstore.dev — ECDSA P-256, valid from 2021-01-12
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
# log2025-1.rekor.sigstore.dev — Ed25519, valid from 2025-09-23
MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=
";

/// Why a zone-key transparency record was refused.
///
/// The variants are the failure *classes* `synch doctor` explains: an absent
/// record on a not-yet-upgraded control plane reads differently from a
/// binding mismatch, which is an alarm.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The record could not be decoded as a v4 `RekorProof`.
    #[error("malformed proof: {0}")]
    Malformed(String),
    /// The entry signature does not verify under the certificate's own key:
    /// the entry misattributes itself, so nothing about it can be believed.
    #[error("attribution: {0}")]
    Attribution(String),
    /// The Statement does not describe the key and zone that were observed.
    #[error("binding: {0}")]
    Binding(String),
    /// The entry is not in the tree the checkpoint commits to.
    #[error("inclusion: {0}")]
    Inclusion(String),
    /// The checkpoint is not signed by the log it claims to come from.
    #[error("checkpoint: {0}")]
    Checkpoint(String),
    /// No pinned key matches the proof's `log_id`: the entry lives in a log
    /// this client was never told to trust.
    #[error("unknown log: {0}")]
    UnknownLog(String),
    /// The entry carries no DNSSEC chain, or one that does not establish
    /// that this key was ever authorized for this zone.
    ///
    /// A client already knows the answer — it validated the delegation
    /// natively. It enforces this **on behalf of monitors**: an entry whose
    /// chain is absent or broken is one a monitor files as noise, so a client
    /// that accepted it would hand an attacker a key that works against
    /// victims *and* raises no alarm (§5.5, the tier-C invariant).
    #[error("chain: {0}")]
    Chain(String),
}

/// One decoded zone-key transparency record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorProof {
    /// SHA-256 of the log's DER SubjectPublicKeyInfo; selects the pinned key.
    pub log_id: [u8; 32],
    /// The entry's index in the log, needed to walk the audit path.
    pub log_index: u64,
    /// The in-toto Statement, byte-exact — the DSSE PAE preimage the entry's
    /// digest commits to.
    pub statement: Vec<u8>,
    /// The Rekor `hashedrekord` entry body, exactly as the log returned it in
    /// `canonicalizedBody` — the Merkle leaf preimage. The entry signature
    /// and the signer's *certificate* live inside these bytes, and the
    /// certificate is what carries the apex and the monitors' evidence.
    pub canonicalized_body: Vec<u8>,
    /// The signed note the log published, verbatim.
    pub checkpoint: Vec<u8>,
    /// The Merkle audit path, leaf to root.
    pub inclusion_path: Vec<[u8; 32]>,
}

impl RekorProof {
    /// Encodes the record in the v3 wire format.
    ///
    /// `None` for a record that does not fit it — a blob past 65535 bytes or
    /// an audit path past 255 hops. Refusing beats emitting *something*: this
    /// format exists so two implementations agree byte for byte, and the two
    /// used to disagree about the failure itself (this side clamped the
    /// length and truncated the blob; the Gleam side wrapped it modulo
    /// 65536). Two different wrong answers in a format whose whole point is
    /// agreement is worse than no answer, so both sides now refuse.
    pub fn encode(&self) -> Option<Vec<u8>> {
        for blob in [&self.statement, &self.canonicalized_body, &self.checkpoint] {
            u16::try_from(blob.len()).ok()?;
        }
        u8::try_from(self.inclusion_path.len()).ok()?;
        Some(self.encode_unchecked())
    }

    /// The encoder proper, for a record already known to fit.
    fn encode_unchecked(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            43 + self.statement.len()
                + self.canonicalized_body.len()
                + self.checkpoint.len()
                + 32 * self.inclusion_path.len(),
        );
        out.push(PROOF_VERSION);
        out.extend_from_slice(&self.log_id);
        out.extend_from_slice(&self.log_index.to_be_bytes());
        for blob in [&self.statement, &self.canonicalized_body, &self.checkpoint] {
            let len = u16::try_from(blob.len()).expect("checked by encode");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(blob);
        }
        out.push(u8::try_from(self.inclusion_path.len()).expect("checked by encode"));
        for hash in &self.inclusion_path {
            out.extend_from_slice(hash);
        }
        out
    }

    /// Decodes a v4 record, refusing anything with bytes left over — a
    /// record that decodes two ways is a record an attacker can steer.
    pub fn decode(bytes: &[u8]) -> Result<RekorProof, ProofError> {
        let mut reader = Reader::new(bytes);
        let version = reader.u8("version")?;
        if version != PROOF_VERSION {
            return Err(ProofError::Malformed(format!(
                "version {version} is not {PROOF_VERSION}"
            )));
        }
        let log_id = reader.array32("log id")?;
        let log_index = reader.u64("log index")?;
        let statement = reader.blob16("statement")?.to_vec();
        let canonicalized_body = reader.blob16("canonicalized body")?.to_vec();
        let checkpoint = reader.blob16("checkpoint")?.to_vec();
        let hops = reader.u8("inclusion path length")?;
        let mut inclusion_path = Vec::with_capacity(usize::from(hops));
        for _ in 0..hops {
            inclusion_path.push(reader.array32("inclusion path hash")?);
        }
        reader.finish()?;
        Ok(RekorProof {
            log_id,
            log_index,
            statement,
            canonicalized_body,
            checkpoint,
            inclusion_path,
        })
    }

    /// Decodes one TXT record: base64url, with or without padding. A TXT
    /// record's character-strings are concatenated before this is called —
    /// the split into ≤255-byte chunks is DNS packaging, not content.
    pub fn from_txt(text: &str) -> Result<RekorProof, ProofError> {
        RekorProof::decode(&base64url_decode(text)?)
    }

    /// Renders the record as one base64url TXT payload, or `None` for a
    /// record too large for the format (see [`RekorProof::encode`]).
    pub fn to_txt(&self) -> Option<String> {
        Some(base64url_encode(&self.encode()?))
    }

    /// The RFC 6962 leaf hash of this entry: over the log's own body bytes.
    ///
    /// This is the whole point of the format — the leaf commits to the exact
    /// `canonicalizedBody` the log returned, so an inclusion walk under this
    /// hash reaches a root the real Sigstore computed over the same bytes.
    pub fn leaf_hash(&self) -> [u8; 32] {
        leaf_hash(&self.canonicalized_body)
    }
}

/// The zone key an answer was actually signed by: what the proof must bind.
///
/// The apex and key tag come from the RRSIG the validator already accepted,
/// and the rdata from the DNSKEY RRset at that apex — so this is an
/// observation of the chain, never something the proof gets to assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneKey<'a> {
    /// The zone apex, as the RRSIG signer field names it.
    pub apex: &'a str,
    /// The key tag the RRSIG selected.
    pub key_tag: u16,
    /// The DNSKEY rdata: flags, protocol, algorithm, public key.
    pub dnskey_rdata: &'a [u8],
}

/// The raw 64-byte uncompressed P-256 point inside a DER
/// SubjectPublicKeyInfo, or `None` for any other key type.
///
/// Used on the entry *signer's* key — the certificate's own — which this
/// design requires to be P-256 (the `hashedrekord` verifier's
/// `PKIX_ECDSA_P256_SHA_256`). The zone keys the entry authorizes are not
/// constrained by algorithm at all: they are matched by rdata membership in
/// the chain-proven RRset.
pub fn p256_point(spki: &[u8]) -> Option<&[u8]> {
    let point = spki.get(27..)?;
    if point.len() != 64 || p256_spki(point) != spki {
        return None;
    }
    Some(point)
}

/// What a verified record establishes, for logs and `synch doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecord {
    /// The entry's index in the log.
    pub log_index: u64,
    /// The tree size the checkpoint commits to.
    pub tree_size: u64,
    /// The checkpoint's origin line — which log, in its own words.
    pub origin: String,
    /// `create`, `rollover` or `retire`.
    pub action: String,
}

/// Verifies a proof completely, offline (§4.2).
///
/// The chain, in the order the validated algorithm runs it: the log vouches
/// for a leaf (checkpoint, inclusion) whose body names this zone in a
/// certificate (apex binding) carrying a DNSSEC chain that proves an
/// authorized key set (authorization), whose own key signed the entry
/// (attribution), whose digest is the DSSE PAE of this Statement, and whose
/// Statement describes exactly that proven set — a set the key that signed
/// this answer is a member of (key binding). Any single failure refuses the
/// whole record — there is no partial credit.
///
/// There is deliberately no possession check. The entry signature names
/// whoever built the entry, and that is all it can honestly do: an attacker
/// able to forge an authorized chain for a rogue key holds that key and
/// could sign possession too, so requiring the *zone* key's signature would
/// add nothing — while making a provider-held key (a zone hosted and signed
/// by Cloudflare or Bunny) impossible to log. Authorization is the chain.
///
/// # The chain extension, and why the client verifies a chain it does not need
///
/// The client learns nothing from it: it validated this zone's delegation
/// natively, all the way to its trust anchor, before reaching this function.
/// But *the client enforces whatever property makes an entry discoverable, or
/// an attacker simply omits it* — and the chain is that property.
///
/// **The DNSSEC chain is required, and verified cryptographically.** Its
/// absence would *silence* a monitor: a chainless or broken-chain entry is
/// tier B, the bin a monitor records and does not report. An attacker who
/// could get such an entry accepted would hold a key that works against
/// victims and rings no bell — strictly worse than no log at all. So the
/// client refuses it, which makes "client-accepted" imply "tier A"
/// (docs/REKOR-ZONE-KEY.md §5.5). RRSIG validity *windows* are deliberately
/// not checked here; see [`crate::chain`] for the two reasons.
///
/// **Unknown extensions are ignored, and that is load-bearing.**
/// [`Certificate::parse`] collects every extension verbatim and looks them up
/// by OID; nothing here refuses a certificate for carrying one this build has
/// no name for. An entry may therefore carry extensions this design says
/// nothing about — the conformance fixture does — and still verify.
///
/// A `retire` entry is refused outright rather than chain-checked: retirement
/// is a monitor breadcrumb (§2), never authorization, and a chainless retire
/// is legal on the publish side — so accepting one here would reopen exactly
/// the hole the chain requirement closes.
pub fn verify(
    proof: &RekorProof,
    key: &ZoneKey<'_>,
    logs: &LogKeys,
    anchors: &TrustAnchors,
) -> Result<VerifiedRecord, ProofError> {
    let log_key = logs.find(&proof.log_id).ok_or_else(|| {
        ProofError::UnknownLog(match logs.is_empty() {
            // Naming the real reason: an empty pin set is a build with no
            // log key in it, not a proof from the wrong log.
            true => "no log key is pinned in this build — name one with \
                     --rekor-key, or run with --rekor off"
                .to_string(),
            false => format!("no pinned key with id {}", hex_lower(&proof.log_id)),
        })
    })?;
    let checkpoint = Checkpoint::parse(&proof.checkpoint)?;

    // Inclusion: the entry's body is a leaf of the tree the checkpoint
    // commits to. The leaf is over the log's own `canonicalizedBody`, so
    // this walk reaches a root the log computed over the same bytes.
    verify_inclusion(
        proof.log_index,
        checkpoint.tree_size,
        proof.leaf_hash(),
        &proof.inclusion_path,
        checkpoint.root_hash,
    )?;

    // The log vouches: the checkpoint carries the pinned key's signature.
    checkpoint.verify_signature(log_key)?;

    // The body the leaf committed to: a hashedrekord over a PAE digest,
    // carrying the entry signature and the certificate that names the signer.
    let body = HashedRekordBody::parse(&proof.canonicalized_body)?;

    // Who the certificate says it is about — the parsed apex. Read through
    // `chain::identify`, the same reader the monitor uses, so no spelling of
    // a name can mean one thing here and another there.
    let claimed_apex = chain::identify(&body.certificate).map_err(chain_error)?;

    // Apex binding: the zone the certificate names is the zone whose RRSIG
    // signed this answer. This is the check that turns a leaf into something
    // a monitor for this apex would have seen — an entry naming another apex
    // is an entry the operator's monitor was never going to look at.
    let observed_apex = chain::parse_name(key.apex).map_err(chain_error)?;
    if claimed_apex != observed_apex {
        return Err(ProofError::Binding(format!(
            "the entry's certificate names {claimed_apex}, the answer was signed by {observed_apex}",
        )));
    }

    // Authorization: the entry carries a chain that proves, to anyone
    // reading the log and nothing else, which keys were delegated for this
    // zone. `chain::authorize` is the *only* way to ask, and it is the same
    // call the monitor makes — neither side gets to choose the apex it feeds
    // the walk. See `chain::authorize` for the break that rule exists to
    // prevent. What comes back is the proven key set, and it decides the key
    // binding below; a chainless entry proves nothing and is refused.
    let authorized = chain::authorize(&body.certificate, anchors).map_err(chain_error)?;

    // Attribution: the entry signature verifies under the certificate's own
    // key — the entry is what its signer made, whoever that is. Rekor signs
    // the hashedrekord's `data.digest` as a prehash — which, because that
    // digest *is* SHA-256(PAE), is the same signature as ECDSA-SHA256 over
    // the PAE itself. Verifying it over the PAE is how ring is asked the
    // question. Rekor entry signatures are ASN.1/DER, not the raw r||s of
    // DNSSEC.
    let pae = pae(DSSE_PAYLOAD_TYPE, &proof.statement);
    let signer = p256_point(&body.certificate.spki).ok_or_else(|| {
        ProofError::Attribution("the certificate's key is not a P-256 SubjectPublicKeyInfo".into())
    })?;
    verify_ecdsa_p256_asn1(signer, &pae, &body.signature).map_err(|_| {
        ProofError::Attribution("the entry signature is not the certificate's key's".into())
    })?;

    // The entry commits to the DSSE PAE of *this* Statement — the body holds
    // only its digest, so the Statement bytes cannot be swapped under it.
    if body.digest != sha256(&pae) {
        return Err(ProofError::Binding(
            "the logged entry's digest is not this statement's DSSE PAE".into(),
        ));
    }

    // Statement and key binding: the Statement describes exactly the proven
    // set, and the key that signed this answer is a member of it.
    let statement = ZoneKeyStatement::parse(&proof.statement)?;
    statement.check_binds(key, &authorized.proven_keys)?;

    Ok(VerifiedRecord {
        log_index: proof.log_index,
        tree_size: checkpoint.tree_size,
        origin: checkpoint.origin,
        action: statement.action,
    })
}

/// Lifts a chain failure into the proof's own error class.
fn chain_error(error: ChainError) -> ProofError {
    ProofError::Chain(error.to_string())
}

/// The fields a `hashedrekord` v0.0.2 body carries that a proof turns on.
///
/// Rekor v2 accepts no other entry type; a DSSE-signed Statement is logged as
/// a `hashedrekord` over the DSSE PAE (docs/REKOR-ZONE-KEY.md §2). The body is
/// the log's own `canonicalizedBody`, verified here by re-deriving nothing —
/// the digest, signature and certificate are read out and checked against what
/// the DNSSEC chain independently observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedRekordBody {
    /// The SHA-256 the entry commits to — must equal `SHA-256(PAE)`.
    pub digest: Vec<u8>,
    /// The entry signature, DER/ASN.1 ECDSA over the PAE.
    pub signature: Vec<u8>,
    /// The signer's certificate: the apex-carrying key envelope, parsed.
    pub certificate: Certificate,
    /// The certificate's DER, verbatim — what a monitor re-reads and what
    /// anyone auditing the log entry sees.
    pub certificate_der: Vec<u8>,
}

impl HashedRekordBody {
    /// Parses the body, refusing anything whose known members are the wrong
    /// shape and asserting every tag this design logs. Unknown members are
    /// tolerated so the entry format can grow.
    ///
    /// The `publicKey` arm of Rekor's verifier oneof is **not** handled, at
    /// all: an entry whose verifier is a bare key names no apex anywhere in
    /// its leaf, which is exactly the unmonitorable shape v3 abolishes. There
    /// is no branch to reach, no legacy path and no fallback.
    pub fn parse(bytes: &[u8]) -> Result<HashedRekordBody, ProofError> {
        let bad = |why: String| ProofError::Malformed(format!("entry body: {why}"));
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| bad(e.to_string()))?;
        let text = |v: &serde_json::Value, what: &str| -> Result<String, ProofError> {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| bad(format!("{what} is not a string")))
        };
        let b64 = |v: &serde_json::Value, what: &str| -> Result<Vec<u8>, ProofError> {
            base64_decode(&text(v, what)?).map_err(|_| bad(format!("{what} is not base64")))
        };

        let kind = text(&value["kind"], "kind")?;
        let api_version = text(&value["apiVersion"], "apiVersion")?;
        if kind != HASHEDREKORD_KIND || api_version != HASHEDREKORD_API_VERSION {
            return Err(ProofError::Binding(format!(
                "the entry is {kind} {api_version}, not \
                 {HASHEDREKORD_KIND} {HASHEDREKORD_API_VERSION}"
            )));
        }
        let spec = &value["spec"]["hashedRekordV002"];
        if spec.is_null() {
            return Err(bad("not a hashedrekord v0.0.2 entry".into()));
        }

        let data = &spec["data"];
        let algorithm = text(&data["algorithm"], "data.algorithm")?;
        if algorithm != HASHEDREKORD_DIGEST_ALGORITHM {
            return Err(ProofError::Binding(format!(
                "entry digest algorithm {algorithm} is not {HASHEDREKORD_DIGEST_ALGORITHM}"
            )));
        }
        let signature = &spec["signature"];
        let verifier = &signature["verifier"];
        let key_details = text(&verifier["keyDetails"], "verifier.keyDetails")?;
        if key_details != HASHEDREKORD_KEY_DETAILS {
            return Err(ProofError::Binding(format!(
                "entry key details {key_details} are not {HASHEDREKORD_KEY_DETAILS}"
            )));
        }
        let certificate_der = match verifier["x509Certificate"]["rawBytes"].is_string() {
            true => b64(
                &verifier["x509Certificate"]["rawBytes"],
                "verifier.x509Certificate.rawBytes",
            )?,
            false => {
                return Err(ProofError::Binding(
                    "the entry's verifier is not an x509Certificate, so its leaf names \
                     no zone and no monitor could ever have seen it"
                        .into(),
                ))
            }
        };
        let certificate = Certificate::parse(&certificate_der).map_err(|e| bad(e.to_string()))?;
        Ok(HashedRekordBody {
            digest: b64(&data["digest"], "data.digest")?,
            signature: b64(&signature["content"], "signature.content")?,
            certificate,
            certificate_der,
        })
    }

    /// The DNSSEC chain the certificate carries, decoded.
    ///
    /// [`ChainError::Absent`] when the extension is not there at all — the
    /// distinction matters, because an absent chain is a hard client refusal
    /// while a *broken* one is the same refusal with a different story.
    pub fn dnssec_chain(&self) -> Result<DnssecChain, ChainError> {
        match self.certificate.extension(zonecert::OID_DNSSEC_CHAIN) {
            None => Err(ChainError::Absent),
            Some(value) => {
                DnssecChain::decode(value).map_err(|e| ChainError::Malformed(e.to_string()))
            }
        }
    }
}

/// One key of a Statement's claimed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementKey {
    /// The DNSKEY key tag (RFC 4034 App. B, over the whole rdata).
    pub key_tag: u16,
    /// The DNSSEC algorithm number.
    pub algorithm: u8,
    /// The DNSKEY flags.
    pub flags: u16,
    /// Lowercase hex SHA-256 of the DNSKEY rdata.
    pub sha256: String,
}

/// The in-toto Statement a zone-key entry carries (§2).
///
/// The subject is a **key set** — the apex DNSKEY RRset the entry's chain
/// proves — rendered as one in-toto subject per key, each named by the apex
/// and identified by the SHA-256 of its DNSKEY rdata. The predicate repeats
/// the set with the tag, algorithm and flags a human or a monitor wants at a
/// glance; the two lists must agree entry for entry, in order.
///
/// Built here as well as parsed: the canonical rendering is the thing both
/// halves of the system have to agree on, so it lives with the parser that
/// depends on it rather than in whichever tool happened to need it first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneKeyStatement {
    /// The zone this key set is claimed for.
    pub apex: String,
    /// The claimed keys, in canonical order: ascending key tag, ties broken
    /// by the hex digest. Both renderers sort the same way, so one set has
    /// exactly one rendering.
    pub keys: Vec<StatementKey>,
    /// `create`, `rollover` or `retire`.
    pub action: String,
}

impl ZoneKeyStatement {
    /// The Statement for a key set, from the DNSKEY rdatas themselves —
    /// tag, algorithm, flags and digest are all derived, and the canonical
    /// order is applied here.
    pub fn for_keys(apex: &str, rdatas: &[Vec<u8>], action: &str) -> ZoneKeyStatement {
        let mut keys: Vec<StatementKey> = rdatas
            .iter()
            .map(|rdata| StatementKey {
                key_tag: chain::key_tag(rdata),
                algorithm: rdata.get(3).copied().unwrap_or(0),
                flags: u16::from_be_bytes([
                    rdata.first().copied().unwrap_or(0),
                    rdata.get(1).copied().unwrap_or(0),
                ]),
                sha256: hex_lower(&sha256(rdata)),
            })
            .collect();
        keys.sort_by(|a, b| (a.key_tag, &a.sha256).cmp(&(b.key_tag, &b.sha256)));
        ZoneKeyStatement {
            apex: apex.to_string(),
            keys,
            action: action.to_string(),
        }
    }

    /// Renders the canonical Statement bytes.
    ///
    /// Field order is fixed and there is no whitespace: the signature and
    /// the leaf hash are over these exact bytes, so "equivalent JSON" is not
    /// equivalent at all.
    pub fn to_json(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("{\"_type\":");
        json_string(&mut out, STATEMENT_TYPE);
        out.push_str(",\"subject\":[");
        for (index, key) in self.keys.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            json_string(&mut out, &self.apex);
            out.push_str(",\"digest\":{\"sha256\":");
            json_string(&mut out, &key.sha256);
            out.push_str("}}");
        }
        out.push_str("],\"predicateType\":");
        json_string(&mut out, PREDICATE_TYPE);
        out.push_str(",\"predicate\":{\"apex\":");
        json_string(&mut out, &self.apex);
        out.push_str(",\"keys\":[");
        for (index, key) in self.keys.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("{\"keyTag\":");
            out.push_str(&key.key_tag.to_string());
            out.push_str(",\"algorithm\":");
            out.push_str(&key.algorithm.to_string());
            out.push_str(",\"flags\":");
            out.push_str(&key.flags.to_string());
            out.push_str(",\"sha256\":");
            json_string(&mut out, &key.sha256);
            out.push_str("}");
        }
        out.push_str("],\"action\":");
        json_string(&mut out, &self.action);
        out.push_str("}}");
        out.into_bytes()
    }

    /// Parses a Statement, accepting unknown members so the predicate can
    /// grow, and refusing anything whose known members are the wrong shape.
    ///
    /// The subject list and the predicate's key list must agree — same
    /// length, same digests, same order — or the statement is describing two
    /// different sets at once and cannot be believed about either.
    pub fn parse(bytes: &[u8]) -> Result<ZoneKeyStatement, ProofError> {
        let bad = |why: String| ProofError::Malformed(format!("statement: {why}"));
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| bad(e.to_string()))?;
        let text = |v: &serde_json::Value, what: &str| -> Result<String, ProofError> {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| bad(format!("{what} is not a string")))
        };
        let number = |v: &serde_json::Value, what: &str| -> Result<u64, ProofError> {
            v.as_u64()
                .ok_or_else(|| bad(format!("{what} is not a whole number")))
        };

        let statement_type = text(&value["_type"], "_type")?;
        if statement_type != STATEMENT_TYPE {
            return Err(ProofError::Binding(format!(
                "statement type {statement_type} is not {STATEMENT_TYPE}"
            )));
        }
        let predicate_type = text(&value["predicateType"], "predicateType")?;
        if predicate_type != PREDICATE_TYPE {
            return Err(ProofError::Binding(format!(
                "predicate type {predicate_type} is not {PREDICATE_TYPE}"
            )));
        }
        let subjects = value["subject"]
            .as_array()
            .ok_or_else(|| bad("subject is not an array".into()))?;
        if subjects.is_empty() {
            return Err(bad("a zone-key entry claims at least one key".into()));
        }
        let predicate = &value["predicate"];
        let apex = text(&predicate["apex"], "apex")?;
        let listed = predicate["keys"]
            .as_array()
            .ok_or_else(|| bad("predicate keys is not an array".into()))?;
        if listed.len() != subjects.len() {
            return Err(bad(format!(
                "{} subject(s) but {} predicate key(s)",
                subjects.len(),
                listed.len()
            )));
        }
        let mut keys = Vec::with_capacity(listed.len());
        for (subject, entry) in subjects.iter().zip(listed) {
            let subject_name = text(&subject["name"], "subject name")?;
            if subject_name != apex {
                return Err(bad(format!(
                    "a subject names {subject_name}, the predicate names {apex}"
                )));
            }
            let subject_sha256 = text(&subject["digest"]["sha256"], "subject sha256 digest")?;
            let sha256 = text(&entry["sha256"], "key sha256")?;
            if !subject_sha256.eq_ignore_ascii_case(&sha256) {
                return Err(bad("a subject digest and its predicate key disagree".into()));
            }
            keys.push(StatementKey {
                key_tag: u16::try_from(number(&entry["keyTag"], "keyTag")?)
                    .map_err(|_| bad("keyTag is out of range".into()))?,
                algorithm: u8::try_from(number(&entry["algorithm"], "algorithm")?)
                    .map_err(|_| bad("algorithm is out of range".into()))?,
                flags: u16::try_from(number(&entry["flags"], "flags")?)
                    .map_err(|_| bad("flags is out of range".into()))?,
                sha256,
            });
        }
        Ok(ZoneKeyStatement {
            apex,
            keys,
            action: text(&predicate["action"], "action")?,
        })
    }

    /// Checks that the Statement describes the proven set and the key
    /// observed (§4.2).
    ///
    /// Three facts, refused independently: the apex is the one whose RRSIG
    /// signed this answer (stops a set logged for one zone being replayed
    /// into another); the claimed set is exactly the chain-proven set, digest
    /// for digest and metadata for metadata (stops a statement describing
    /// keys its own chain never proved); and the key that signed this answer
    /// is a member (the point of the whole exercise).
    fn check_binds(&self, key: &ZoneKey<'_>, proven: &[Vec<u8>]) -> Result<(), ProofError> {
        if !same_name(&self.apex, key.apex) {
            return Err(ProofError::Binding(format!(
                "the entry names apex {}, the answer was signed by {}",
                self.apex, key.apex
            )));
        }

        // The claimed set is the proven set, exactly. Compared as canonical
        // statements: `for_keys` derives every field from the rdatas alone,
        // so equality here pins digest, tag, algorithm, flags and order all
        // at once.
        let derived = ZoneKeyStatement::for_keys(&self.apex, proven, &self.action);
        if derived.keys != self.keys {
            return Err(ProofError::Binding(
                "the statement's key set is not the set its chain proves".into(),
            ));
        }

        // Membership: the key that signed this answer is in the proven set.
        let digest = hex_lower(&sha256(key.dnskey_rdata));
        if !self
            .keys
            .iter()
            .any(|k| k.sha256.eq_ignore_ascii_case(&digest))
        {
            return Err(ProofError::Binding(format!(
                "the answer was signed by key tag {}, which is not in the authorized set",
                key.key_tag
            )));
        }

        // Only a key set being *put into service* is authorization. A
        // `retire` entry is a breadcrumb for monitors and is allowed to be
        // chainless on the publish side (a retired zone may have no DS
        // left), so a client that accepted one would accept an entry
        // carrying no proof of delegation at all — the exact evasion the
        // chain requirement exists to close.
        if !matches!(self.action.as_str(), "create" | "rollover") {
            return Err(ProofError::Binding(format!(
                "the entry's action is {}, and only create or rollover authorizes a key",
                self.action
            )));
        }
        Ok(())
    }
}

/// A parsed checkpoint: the log's signed statement of a tree.
///
/// The signed-note format (Go's `sumdb/note`): text lines, a blank line,
/// then signature lines. The signature covers the text and its final
/// newline, and nothing after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The origin line — the log's name for itself.
    pub origin: String,
    /// The number of entries the tree contains.
    pub tree_size: u64,
    /// The Merkle root over those entries.
    pub root_hash: [u8; 32],
    /// The exact bytes the signatures cover.
    signed: Vec<u8>,
    /// `(name, signature)` per signature line; the four-byte key hint is a
    /// selector, never a credential, so it is dropped here.
    ///
    /// **This is a list, and it must stay one.** A real Sigstore checkpoint
    /// carries the log's own signature *plus* a line per witness that
    /// cosigned the tree — the checked-in fixtures have four. This design
    /// does not interpret those lines in any way, but it has to tolerate
    /// them: narrowing the parser to a single signature would reject every
    /// checkpoint the production log actually serves. Verification scans the
    /// list for one that a pinned key signed and ignores the rest.
    signatures: Vec<(String, Vec<u8>)>,
}

impl Checkpoint {
    /// Parses a signed note.
    pub fn parse(bytes: &[u8]) -> Result<Checkpoint, ProofError> {
        let bad = |why: &str| ProofError::Malformed(format!("checkpoint: {why}"));
        let text = std::str::from_utf8(bytes).map_err(|_| bad("not UTF-8"))?;
        let split = text
            .find("\n\n")
            .ok_or_else(|| bad("no blank line between the note and its signatures"))?;
        let signed = &text[..split + 1];
        let mut lines = signed.lines();
        let origin = lines.next().ok_or_else(|| bad("no origin line"))?;
        let tree_size: u64 = lines
            .next()
            .ok_or_else(|| bad("no tree size line"))?
            .parse()
            .map_err(|_| bad("the tree size is not a number"))?;
        let root = base64_decode(lines.next().ok_or_else(|| bad("no root hash line"))?)
            .map_err(|_| bad("the root hash is not base64"))?;
        let root_hash: [u8; 32] = root
            .as_slice()
            .try_into()
            .map_err(|_| bad("the root hash is not 32 bytes"))?;

        let mut signatures = Vec::new();
        for line in text[split + 2..].lines().filter(|l| !l.is_empty()) {
            // U+2014 EM DASH, then the key name, then base64(keyhint || sig).
            let rest = line
                .strip_prefix("\u{2014} ")
                .ok_or_else(|| bad("a signature line does not start with an em dash"))?;
            let (name, encoded) = rest
                .split_once(' ')
                .ok_or_else(|| bad("a signature line has no signature"))?;
            let blob = base64_decode(encoded).map_err(|_| bad("a signature is not base64"))?;
            if blob.len() <= 4 {
                return Err(bad("a signature is shorter than its key hint"));
            }
            signatures.push((name.to_string(), blob[4..].to_vec()));
        }
        if signatures.is_empty() {
            return Err(bad("no signature lines"));
        }
        Ok(Checkpoint {
            origin: origin.to_string(),
            tree_size,
            root_hash,
            signed: signed.as_bytes().to_vec(),
            signatures,
        })
    }

    /// Verifies that some pinned key signed this checkpoint.
    ///
    /// The public entry point a monitor uses: a client reaches the same check
    /// through [`verify`], but a monitor holds a checkpoint on its own and
    /// must be able to ask the question directly.
    pub fn verify_under(&self, logs: &LogKeys) -> Result<(), ProofError> {
        match logs
            .keys()
            .iter()
            .any(|key| self.verify_signature(key).is_ok())
        {
            true => Ok(()),
            false => Err(ProofError::Checkpoint(format!(
                "no signature on the checkpoint from {} verifies under a pinned log key",
                self.origin
            ))),
        }
    }

    /// Verifies that the pinned log key signed this checkpoint.
    ///
    /// Scans every signature line, because the log's own is one among
    /// several: witnesses cosign the same note and their lines sit beside it.
    /// A line that verifies under no pinned key is simply not ours.
    fn verify_signature(&self, key: &LogKey) -> Result<(), ProofError> {
        let signed = self
            .signatures
            .iter()
            .any(|(_, signature)| key.verify(&self.signed, signature).is_ok());
        match signed {
            true => Ok(()),
            false => Err(ProofError::Checkpoint(format!(
                "no signature on the checkpoint from {} verifies under the pinned log key",
                self.origin
            ))),
        }
    }
}

/// The signature algorithm a pinned log key uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogKeyAlgorithm {
    /// ECDSA P-256 with SHA-256, signatures as raw `r || s`.
    EcdsaP256Sha256,
    /// Ed25519.
    Ed25519,
}

/// One pinned log verification key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogKey {
    /// SHA-256 of the DER SubjectPublicKeyInfo — the `log_id` a proof names.
    pub id: [u8; 32],
    algorithm: LogKeyAlgorithm,
    /// The raw public key: an uncompressed P-256 point, or 32 Ed25519 bytes.
    point: Vec<u8>,
}

impl LogKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), ProofError> {
        let algorithm: &dyn signature::VerificationAlgorithm = match self.algorithm {
            LogKeyAlgorithm::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_FIXED,
            LogKeyAlgorithm::Ed25519 => &signature::ED25519,
        };
        signature::UnparsedPublicKey::new(algorithm, &self.point)
            .verify(message, signature)
            .map_err(|_| ProofError::Checkpoint("signature does not verify".into()))
    }
}

/// The set of logs this client will accept a record from.
///
/// A file of keys *replaces* the embedded set rather than adding to it —
/// the same "an override is a different universe" semantics as
/// `--dnssec-anchor`. An empty set accepts nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogKeys {
    keys: Vec<LogKey>,
}

impl LogKeys {
    /// The keys compiled into this build (see [`EMBEDDED_LOG_KEYS`]).
    pub fn embedded() -> LogKeys {
        LogKeys::parse(EMBEDDED_LOG_KEYS).unwrap_or_default()
    }

    /// Reads a key file: PEM `PUBLIC KEY` blocks, or one base64
    /// SubjectPublicKeyInfo per line. `#` starts a comment.
    pub fn from_file(path: &Path) -> Result<LogKeys, ProofError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ProofError::UnknownLog(format!("log key file {}: {e}", path.display())))?;
        let keys = LogKeys::parse(&text)?;
        if keys.is_empty() {
            // An empty pin set verifies nothing, forever, quietly.
            return Err(ProofError::UnknownLog(format!(
                "log key file {}: no public keys in the file",
                path.display()
            )));
        }
        Ok(keys)
    }

    /// Parses key material from text.
    pub fn parse(text: &str) -> Result<LogKeys, ProofError> {
        let mut keys = Vec::new();
        let mut block: Option<String> = None;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            match line {
                "" => {}
                "-----BEGIN PUBLIC KEY-----" => block = Some(String::new()),
                "-----END PUBLIC KEY-----" => {
                    let body = block.take().ok_or_else(|| {
                        ProofError::UnknownLog("a PEM block ends before it begins".into())
                    })?;
                    keys.push(LogKey::from_spki(&base64_decode(&body).map_err(|_| {
                        ProofError::UnknownLog("a PEM block is not base64".into())
                    })?)?);
                }
                _ => match &mut block {
                    Some(body) => body.push_str(line),
                    None => keys.push(LogKey::from_spki(&base64_decode(line).map_err(|_| {
                        ProofError::UnknownLog("a key line is not base64".into())
                    })?)?),
                },
            }
        }
        if block.is_some() {
            return Err(ProofError::UnknownLog("a PEM block is never closed".into()));
        }
        Ok(LogKeys { keys })
    }

    /// The key a proof's `log_id` names, if this client pins it.
    pub fn find(&self, log_id: &[u8; 32]) -> Option<&LogKey> {
        self.keys.iter().find(|key| &key.id == log_id)
    }

    /// Whether any log is pinned at all.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The pinned keys, for `synch doctor`.
    pub fn keys(&self) -> &[LogKey] {
        &self.keys
    }
}

impl LogKey {
    /// Parses a DER SubjectPublicKeyInfo holding a P-256 or Ed25519 key.
    ///
    /// Deliberately narrow: two shapes are recognized and everything else is
    /// refused, rather than a general ASN.1 reader parsing whatever it is
    /// handed. The `id` is SHA-256 over the DER bytes exactly as given.
    pub fn from_spki(der: &[u8]) -> Result<LogKey, ProofError> {
        const P256_SPKI_PREFIX: &[u8] = &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        const ED25519_SPKI_PREFIX: &[u8] = &[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let id = sha256(der);
        if let Some(point) = der.strip_prefix(P256_SPKI_PREFIX) {
            if point.len() == 64 {
                let mut uncompressed = Vec::with_capacity(65);
                uncompressed.push(0x04);
                uncompressed.extend_from_slice(point);
                return Ok(LogKey {
                    id,
                    algorithm: LogKeyAlgorithm::EcdsaP256Sha256,
                    point: uncompressed,
                });
            }
        }
        if let Some(point) = der.strip_prefix(ED25519_SPKI_PREFIX) {
            if point.len() == 32 {
                return Ok(LogKey {
                    id,
                    algorithm: LogKeyAlgorithm::Ed25519,
                    point: point.to_vec(),
                });
            }
        }
        Err(ProofError::UnknownLog(
            "a log key is neither an ECDSA P-256 nor an Ed25519 SubjectPublicKeyInfo".into(),
        ))
    }
}

/// The DSSE Pre-Authentication Encoding (DSSE §2): the bytes actually
/// signed, so a payload cannot be reinterpreted under another type.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Verifies an ECDSA P-256/SHA-256 signature in ASN.1/DER form against a
/// DNSSEC algorithm 13 public key (64 bytes of coordinates).
///
/// DER, not the raw `r || s` of DNSSEC: a Rekor entry's `signature.content`
/// is what the log indexed, and Rekor indexes DER. ring hashes the message
/// (the DSSE PAE) internally.
fn verify_ecdsa_p256_asn1(
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ProofError> {
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(public);
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &uncompressed)
        .verify(message, signature)
        .map_err(|_| ProofError::Attribution("signature does not verify".into()))
}

/// Wraps a raw 64-byte uncompressed P-256 point in a DER SubjectPublicKeyInfo.
///
/// The prefix is the fixed algorithm identifier for `id-ecPublicKey` over
/// `prime256v1` plus the bit-string header and the `0x04` uncompressed-point
/// tag — the same 27 bytes [`LogKey::from_spki`] strips back off.
pub fn p256_spki(point: &[u8]) -> Vec<u8> {
    const P256_SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    let mut der = Vec::with_capacity(P256_SPKI_PREFIX.len() + point.len());
    der.extend_from_slice(P256_SPKI_PREFIX);
    der.extend_from_slice(point);
    der
}

/// Walks an RFC 6962 §2.1.1 audit path from a leaf to a root.
///
/// The leaf's index and the tree size decide which side each sibling sits
/// on, which is why both travel with the proof: a path alone proves nothing
/// about *where* in the tree an entry is.
pub fn verify_inclusion(
    index: u64,
    tree_size: u64,
    leaf_hash: [u8; 32],
    path: &[[u8; 32]],
    root: [u8; 32],
) -> Result<(), ProofError> {
    if index >= tree_size {
        return Err(ProofError::Inclusion(format!(
            "entry {index} is outside a tree of {tree_size}"
        )));
    }
    let mut node = index;
    let mut last = tree_size - 1;
    let mut hash = leaf_hash;
    for sibling in path {
        if last == 0 {
            return Err(ProofError::Inclusion(
                "the audit path is longer than the tree is deep".into(),
            ));
        }
        if node % 2 == 1 || node == last {
            hash = node_hash(sibling, &hash);
            while node != 0 && node.is_multiple_of(2) {
                node /= 2;
                last /= 2;
            }
        } else {
            hash = node_hash(&hash, sibling);
        }
        node /= 2;
        last /= 2;
    }
    if last != 0 {
        return Err(ProofError::Inclusion(
            "the audit path is shorter than the tree is deep".into(),
        ));
    }
    if hash != root {
        return Err(ProofError::Inclusion(
            "the audit path does not reach the checkpoint's root".into(),
        ));
    }
    Ok(())
}

/// An RFC 6962 interior node hash.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(65);
    input.push(0x01);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    sha256(&input)
}

/// An RFC 6962 leaf hash over already-serialized entry bytes.
pub fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(entry.len() + 1);
    input.push(0x00);
    input.extend_from_slice(entry);
    sha256(&input)
}

/// SHA-256.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Two DNS names, compared as DNS compares them: parsed and normalized, so a
/// spelling that is not a name (`"x.."`) never equals one that is (`"x."`).
///
/// A name that does not parse equals nothing, including itself — which is the
/// right answer for a Statement field that is supposed to be a zone.
fn same_name(a: &str, b: &str) -> bool {
    match (chain::parse_name(a), chain::parse_name(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Lowercase hex, the form the Statement's digests are written in.
fn hex_lower(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Appends a JSON string literal, escaping what JSON requires escaped.
fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Standard base64 with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Standard base64, padding optional.
fn base64_decode(text: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine;
    let trimmed: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&trimmed)
        .map_err(|_| ())
}

/// base64url without padding — how a proof travels in a TXT record.
pub fn base64url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes a base64url TXT payload, padding optional.
fn base64url_decode(text: &str) -> Result<Vec<u8>, ProofError> {
    use base64::Engine;
    let trimmed: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&trimmed)
        .map_err(|e| ProofError::Malformed(format!("not base64url: {e}")))
}

/// A bounds-checked reader over the wire format.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, at: 0 }
    }

    fn take(&mut self, len: usize, what: &str) -> Result<&'a [u8], ProofError> {
        let end = self.at.checked_add(len).ok_or_else(|| {
            ProofError::Malformed(format!("{what}: length {len} overflows the record"))
        })?;
        if end > self.bytes.len() {
            return Err(ProofError::Malformed(format!(
                "{what}: wanted {len} bytes, {} remain",
                self.bytes.len() - self.at
            )));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self, what: &str) -> Result<u8, ProofError> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &str) -> Result<u16, ProofError> {
        let bytes = self.take(2, what)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self, what: &str) -> Result<u64, ProofError> {
        let bytes = self.take(8, what)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(array))
    }

    fn array32(&mut self, what: &str) -> Result<[u8; 32], ProofError> {
        let bytes = self.take(32, what)?;
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn blob16(&mut self, what: &str) -> Result<&'a [u8], ProofError> {
        let len = self.u16(what)?;
        self.take(usize::from(len), what)
    }

    fn finish(&self) -> Result<(), ProofError> {
        match self.bytes.len() - self.at {
            0 => Ok(()),
            extra => Err(ProofError::Malformed(format!(
                "{extra} bytes after the end of the record"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof() -> RekorProof {
        RekorProof {
            log_id: [7u8; 32],
            log_index: 1_234_567,
            statement: b"{\"_type\":\"x\"}".to_vec(),
            canonicalized_body: b"{\"kind\":\"hashedrekord\"}".to_vec(),
            checkpoint: "log.example\n4\nAAAA\n\n\u{2014} log.example AAAAAAAA\n"
                .as_bytes()
                .to_vec(),
            inclusion_path: vec![[1u8; 32], [2u8; 32]],
        }
    }

    #[test]
    fn proofs_round_trip() {
        let original = proof();
        let bytes = original.encode().expect("a small record encodes");
        assert_eq!(RekorProof::decode(&bytes).unwrap(), original);
        assert_eq!(
            RekorProof::from_txt(&original.to_txt().expect("encodes")).unwrap(),
            original
        );
    }

    #[test]
    fn the_wire_layout_is_pinned() {
        // Field offsets are load-bearing across two implementations; assert
        // them rather than trusting the encoder to agree with itself.
        let bytes = proof().encode().expect("a small record encodes");
        assert_eq!(bytes[0], PROOF_VERSION);
        assert_eq!(&bytes[1..33], &[7u8; 32]);
        assert_eq!(&bytes[33..41], &1_234_567u64.to_be_bytes());
        // The statement blob's u16 length prefix, then its bytes.
        assert_eq!(&bytes[41..43], &13u16.to_be_bytes());
    }

    #[test]
    fn a_truncated_or_padded_record_is_malformed() {
        let bytes = proof().encode().expect("a small record encodes");
        for cut in [0, 1, 10, 42, bytes.len() - 1] {
            assert!(matches!(
                RekorProof::decode(&bytes[..cut]),
                Err(ProofError::Malformed(_))
            ));
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(matches!(
            RekorProof::decode(&extra),
            Err(ProofError::Malformed(_))
        ));
        let mut wrong_version = bytes;
        wrong_version[0] = 1;
        assert!(matches!(
            RekorProof::decode(&wrong_version),
            Err(ProofError::Malformed(_))
        ));
    }

    #[test]
    fn the_dsse_pae_is_the_dsse_pae() {
        // DSSE §2's own example shape: "DSSEv1 SP len SP type SP len SP body".
        assert_eq!(
            pae("application/example", b"hello"),
            b"DSSEv1 19 application/example 5 hello".to_vec()
        );
    }

    #[test]
    fn statements_round_trip_through_their_canonical_form() {
        // Two keys, deliberately supplied out of canonical order: a KSK
        // (flags 257) and a ZSK (flags 256), the split-key shape a
        // provider-hosted zone has. `for_keys` sorts and derives every field
        // from the rdatas alone.
        let ksk = [&[0x01u8, 0x01, 0x03, 0x0d][..], &[0xab; 64][..]].concat();
        let zsk = [&[0x01u8, 0x00, 0x03, 0x0d][..], &[0xcd; 64][..]].concat();
        let statement =
            ZoneKeyStatement::for_keys("sync.example.", &[ksk.clone(), zsk.clone()], "rollover");
        assert_eq!(statement.keys.len(), 2);
        let sorted: Vec<u16> = statement.keys.iter().map(|k| k.key_tag).collect();
        let mut expected = vec![chain::key_tag(&ksk), chain::key_tag(&zsk)];
        expected.sort_unstable();
        assert_eq!(sorted, expected, "keys are in canonical tag order");
        assert_eq!(
            statement
                .keys
                .iter()
                .map(|k| k.flags)
                .collect::<Vec<_>>()
                .len(),
            2
        );

        let json = statement.to_json();
        assert_eq!(ZoneKeyStatement::parse(&json).unwrap(), statement);
        let text = String::from_utf8(json).unwrap();
        assert!(text.starts_with("{\"_type\":\"https://in-toto.io/Statement/v1\","));
        assert!(!text.contains(' '), "the canonical form has no whitespace");
        assert!(text.ends_with("\"action\":\"rollover\"}}"), "{text}");
        assert!(text.contains("\"predicateType\":\"https://synchronicity.sh/zone-key/v2\""));

        // One rendering: the same set supplied in the other order is the
        // same bytes.
        let swapped = ZoneKeyStatement::for_keys("sync.example.", &[zsk, ksk], "rollover");
        assert_eq!(swapped.to_json(), statement.to_json());
    }

    #[test]
    fn a_statement_of_the_wrong_type_is_refused() {
        let bogus = br#"{"_type":"https://in-toto.io/Statement/v0.1","subject":[]}"#;
        assert!(matches!(
            ZoneKeyStatement::parse(bogus),
            Err(ProofError::Binding(_))
        ));
        assert!(matches!(
            ZoneKeyStatement::parse(b"not json"),
            Err(ProofError::Malformed(_))
        ));
    }

    #[test]
    fn merkle_paths_verify_against_a_known_tree() {
        // Four leaves: root = H(H(a,b), H(c,d)); the audit path for leaf 2
        // is [d, H(a,b)] and no other ordering reaches the root.
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| leaf_hash(&[i])).collect();
        let ab = node_hash(&leaves[0], &leaves[1]);
        let cd = node_hash(&leaves[2], &leaves[3]);
        let root = node_hash(&ab, &cd);
        verify_inclusion(2, 4, leaves[2], &[leaves[3], ab], root).unwrap();
        verify_inclusion(0, 4, leaves[0], &[leaves[1], cd], root).unwrap();
        // Wrong sibling order, short path, wrong root, out-of-range index.
        assert!(verify_inclusion(2, 4, leaves[2], &[ab, leaves[3]], root).is_err());
        assert!(verify_inclusion(2, 4, leaves[2], &[leaves[3]], root).is_err());
        assert!(verify_inclusion(2, 4, leaves[2], &[leaves[3], ab], [0u8; 32]).is_err());
        assert!(verify_inclusion(4, 4, leaves[0], &[], root).is_err());
        // A one-leaf tree: the leaf is the root, with an empty path.
        verify_inclusion(0, 1, leaves[0], &[], leaves[0]).unwrap();
    }

    #[test]
    fn checkpoints_parse_or_are_refused() {
        let note = "rekor.example\n17\n8N7C7fXJnu41Y7f/eR2Rqjr3FzLQqZ5jGVLPZaAJcXA=\n\n\u{2014} rekor.example AAAAAAECAw==\n";
        let checkpoint = Checkpoint::parse(note.as_bytes()).unwrap();
        assert_eq!(checkpoint.origin, "rekor.example");
        assert_eq!(checkpoint.tree_size, 17);
        assert_eq!(checkpoint.signatures.len(), 1);
        // The signed bytes stop at the blank line.
        assert!(checkpoint.signed.ends_with(b"cXA=\n"));
        assert!(!String::from_utf8(checkpoint.signed.clone())
            .unwrap()
            .contains('\u{2014}'));

        for broken in [
            "no blank line\n1\nAAAA\n",
            "origin\nnotanumber\nAAAA\n\n\u{2014} n AAAAAAECAw==\n",
            "origin\n1\nAAAA\n\n\u{2014} n AAAAAAECAw==\n",
            "origin\n1\n8N7C7fXJnu41Y7f/eR2Rqjr3FzLQqZ5jGVLPZaAJcXA=\n\n",
            "origin\n1\n8N7C7fXJnu41Y7f/eR2Rqjr3FzLQqZ5jGVLPZaAJcXA=\n\n- n AAAAAAECAw==\n",
        ] {
            assert!(
                matches!(
                    Checkpoint::parse(broken.as_bytes()),
                    Err(ProofError::Malformed(_))
                ),
                "{broken:?} must not parse"
            );
        }
    }

    #[test]
    fn a_real_sigstore_checkpoint_verifies_under_the_embedded_pin_set() {
        // The one external reality anchor for the checkpoint half of the
        // proof path: a genuine signed checkpoint fetched from
        // log2025-1.rekor.sigstore.dev, verified here against the log key
        // this build embeds — nothing in this file authored it. It proves
        // our signed-note parsing and our pinned-key selection accept what
        // real Sigstore emits: the note framing (origin, tree size, base64
        // root, blank line, `— name base64(keyhint||sig)`), the em-dash
        // signature line, the four-byte key-hint prefix, and the Ed25519
        // signature over the note body up to and including its final
        // newline.
        //
        // It is also the regression test for the *shape* of that parse: a
        // real checkpoint carries four signature lines, the log's own plus
        // three witness cosignatures. This design interprets cosignatures not
        // at all (§8.2), but narrowing the parser to a single signature would
        // reject every checkpoint the production log serves. `verify_signature`
        // scans the list and needs exactly one line to match a pinned key.
        //
        // This anchors the checkpoint and log-key machinery to reality; the
        // Merkle *leaf* convention is anchored separately by the
        // `real_rekor_v3` suite, over a genuine published `hashedrekord`
        // entry whose verifier is a certificate (tests/fixtures/rekor_v3).
        let note = include_bytes!("../tests/fixtures/sigstore_checkpoint.txt");
        let checkpoint = Checkpoint::parse(note).expect("a real checkpoint must parse");
        assert_eq!(checkpoint.origin, "log2025-1.rekor.sigstore.dev");
        assert!(checkpoint.tree_size > 0);
        assert_eq!(
            checkpoint.signatures.len(),
            4,
            "a real checkpoint carries the log's signature and three witness \
             cosignatures; a parser that tolerates only one would reject it"
        );

        let embedded = LogKeys::embedded();
        let verified = embedded
            .keys()
            .iter()
            .any(|key| checkpoint.verify_signature(key).is_ok());
        assert!(
            verified,
            "the real checkpoint must verify under an embedded Sigstore key"
        );

        // And the anchor has teeth: flip one byte of the signed body and no
        // embedded key vouches for it any more.
        let mut tampered = checkpoint.clone();
        tampered.signed[0] ^= 0x01;
        assert!(
            !embedded
                .keys()
                .iter()
                .any(|key| tampered.verify_signature(key).is_ok()),
            "a tampered checkpoint must not verify"
        );
    }

    #[test]
    fn pinned_keys_parse_from_pem_and_bare_base64() {
        // A well-formed P-256 SubjectPublicKeyInfo over an arbitrary point:
        // parsing is structural, and a point that is not on the curve fails
        // later, at verification, where ring checks it.
        let mut der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        der.extend_from_slice(&[0x11; 64]);
        let base64 = base64_encode(&der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{base64}\n-----END PUBLIC KEY-----\n");

        for text in [base64.clone(), pem, format!("# a comment\n{base64}\n")] {
            let keys = LogKeys::parse(&text).unwrap();
            assert_eq!(keys.keys().len(), 1);
            assert!(keys.find(&sha256(&der)).is_some());
            assert!(keys.find(&[0u8; 32]).is_none());
        }

        assert!(LogKeys::parse("").unwrap().is_empty());
        assert!(LogKeys::parse("not base64!!").is_err());
        assert!(LogKeys::parse(&base64_encode(b"short")).is_err());
        assert!(LogKeys::parse("-----BEGIN PUBLIC KEY-----\n").is_err());
    }

    #[test]
    fn the_embedded_pin_set_is_the_sigstore_snapshot() {
        // The exact production keys, pinned by id — which is SHA-256 over
        // the DER SubjectPublicKeyInfo, *this format's* convention. (The
        // trusted root's own logId agrees for the P-256 log and not for the
        // Ed25519 one; a proof's log_id must match ours.) A changed id here
        // is a changed key, which is a rollover ceremony, not an edit.
        let keys = LogKeys::embedded();
        assert_eq!(keys.keys().len(), 2);
        let rekor_v1: [u8; 32] =
            hex::decode("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d")
                .unwrap()
                .try_into()
                .unwrap();
        let log2025_1: [u8; 32] =
            hex::decode("b54813cb63d8859870a5e78500cc6adcfdf59723edae93ee8d25faf2475a0690")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(keys.find(&rekor_v1).is_some(), "rekor.sigstore.dev");
        assert!(
            keys.find(&log2025_1).is_some(),
            "log2025-1.rekor.sigstore.dev"
        );
    }

    #[test]
    fn names_compare_the_way_dns_does() {
        assert!(same_name("Sync.Example.", "sync.example"));
        assert!(!same_name("sync.example", "other.example"));
    }
}
