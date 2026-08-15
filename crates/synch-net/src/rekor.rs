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
//! # Wire format
//!
//! `RekorProof` v1, big-endian throughout:
//!
//! ```text
//! u8       version        = 1
//! u16      key_tag          selects the record during a rollover window
//! u8[32]   log_id           SHA-256 of the log's DER SubjectPublicKeyInfo
//! u64      log_index
//! u16+[]   dsse_payload     the in-toto Statement, byte-exact
//! u16+[]   dsse_signature   ECDSA P-256 over DSSE PAE(payload)
//! u16+[]   checkpoint       signed note: origin, tree size, root hash, sigs
//! u8+[32]* inclusion_path   Merkle audit path, leaf to root
//! ```
//!
//! # The two conventions this format pins
//!
//! A proof is only checkable if both halves agree byte for byte on what was
//! hashed. Two conventions are therefore part of the format, not of the
//! implementation, and the control plane mirrors them exactly:
//!
//! 1. **The log entry** is the DSSE envelope rendered as canonical JSON —
//!    field order `payloadType`, `payload`, `signatures`, one signature
//!    object with a single `sig` member, standard padded base64 for both
//!    blobs, no whitespace anywhere. See [`RekorProof::entry_bytes`].
//! 2. **The Merkle leaf** is `SHA-256(0x00 || entry_bytes)`, and an interior
//!    node is `SHA-256(0x01 || left || right)` — RFC 6962 §2.1.
//!
//! Neither is negotiable per deployment: a v2 of the record format is how
//! either changes.

use std::path::Path;

use ring::{digest, signature};

/// The only `RekorProof` version this build accepts.
pub const PROOF_VERSION: u8 = 1;

/// The label the proof records live under, one below the zone apex.
pub const REKOR_TXT_PREFIX: &str = "_synchronicity-rekor";

/// The DSSE payload type of an in-toto Statement.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The in-toto Statement type the entry must declare.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// The predicate type carrying the zone-key claim.
pub const PREDICATE_TYPE: &str = "https://synchronicity.dev/zone-key/v1";

/// DNSSEC algorithm 13, ECDSA P-256/SHA-256 — the only zone-key algorithm
/// this design logs, and the DSSE signing algorithm (§2: no second signing
/// identity).
pub const ZONE_KEY_ALGORITHM: u8 = 13;

/// ZONE + SEP: the single-key (CSK) convention the control plane publishes.
pub const ZONE_KEY_FLAGS: u16 = 257;

/// The log verification keys compiled into this build.
///
/// A snapshot of Sigstore's production transparency logs, taken from the
/// TUF repository's `trusted_root.json` (consistent-snapshot target
/// `6494e21e…`, its SHA-256 checked against the signed `targets.json`;
/// fetched 2026-08-15 from `tuf-repo-cdn.sigstore.dev`). A full in-client
/// TUF workflow is out of v1 (§8) — rotating these keys is a new build, the
/// same way rotating the ICANN trust anchor is.
///
/// Note that this format's `log_id` is always SHA-256 over the DER
/// SubjectPublicKeyInfo, computed here from the key bytes themselves. The
/// trusted root agrees for the P-256 log and *disagrees* for the Ed25519
/// one (its `logId.keyId` is derived differently there); what a proof's
/// `log_id` field must match is this convention, not Sigstore's.
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
    /// The record could not be decoded as a v1 `RekorProof`.
    #[error("malformed proof: {0}")]
    Malformed(String),
    /// The DSSE signature is not the zone key's: whoever built the entry did
    /// not hold the key it claims to log.
    #[error("possession: {0}")]
    Possession(String),
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
}

/// One decoded zone-key transparency record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorProof {
    /// The DNSKEY key tag this record is about, so a rollover window can
    /// publish two records under one owner name.
    pub key_tag: u16,
    /// SHA-256 of the log's DER SubjectPublicKeyInfo; selects the pinned key.
    pub log_id: [u8; 32],
    /// The entry's index in the log, needed to walk the audit path.
    pub log_index: u64,
    /// The in-toto Statement, byte-exact — hashing requires the exact bytes.
    pub dsse_payload: Vec<u8>,
    /// ECDSA P-256 signature over DSSE PAE(payload), raw `r || s`.
    pub dsse_signature: Vec<u8>,
    /// The signed note the log published, verbatim.
    pub checkpoint: Vec<u8>,
    /// The Merkle audit path, leaf to root.
    pub inclusion_path: Vec<[u8; 32]>,
}

impl RekorProof {
    /// Encodes the record in the v1 wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            45 + self.dsse_payload.len()
                + self.dsse_signature.len()
                + self.checkpoint.len()
                + 32 * self.inclusion_path.len(),
        );
        out.push(PROOF_VERSION);
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        out.extend_from_slice(&self.log_id);
        out.extend_from_slice(&self.log_index.to_be_bytes());
        for blob in [&self.dsse_payload, &self.dsse_signature, &self.checkpoint] {
            // A field that cannot be length-prefixed cannot be encoded; the
            // control plane never produces one, and truncating silently
            // would produce a record that fails verification much later.
            let len = u16::try_from(blob.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&blob[..usize::from(len)]);
        }
        let hops = u8::try_from(self.inclusion_path.len()).unwrap_or(u8::MAX);
        out.push(hops);
        for hash in self.inclusion_path.iter().take(usize::from(hops)) {
            out.extend_from_slice(hash);
        }
        out
    }

    /// Decodes a v1 record, refusing anything with bytes left over — a
    /// record that decodes two ways is a record an attacker can steer.
    pub fn decode(bytes: &[u8]) -> Result<RekorProof, ProofError> {
        let mut reader = Reader::new(bytes);
        let version = reader.u8("version")?;
        if version != PROOF_VERSION {
            return Err(ProofError::Malformed(format!(
                "version {version} is not {PROOF_VERSION}"
            )));
        }
        let key_tag = reader.u16("key tag")?;
        let log_id = reader.array32("log id")?;
        let log_index = reader.u64("log index")?;
        let dsse_payload = reader.blob16("dsse payload")?.to_vec();
        let dsse_signature = reader.blob16("dsse signature")?.to_vec();
        let checkpoint = reader.blob16("checkpoint")?.to_vec();
        let hops = reader.u8("inclusion path length")?;
        let mut inclusion_path = Vec::with_capacity(usize::from(hops));
        for _ in 0..hops {
            inclusion_path.push(reader.array32("inclusion path hash")?);
        }
        reader.finish()?;
        Ok(RekorProof {
            key_tag,
            log_id,
            log_index,
            dsse_payload,
            dsse_signature,
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

    /// Renders the record as one base64url TXT payload.
    pub fn to_txt(&self) -> String {
        base64url_encode(&self.encode())
    }

    /// The log entry bytes: the DSSE envelope as canonical JSON.
    ///
    /// This exact rendering — field order, single signature object, padded
    /// standard base64, no whitespace — is what the leaf hash commits to, so
    /// it is part of the format (see the module docs), not a detail.
    pub fn entry_bytes(&self) -> Vec<u8> {
        let mut out = String::with_capacity(64 + 2 * (self.dsse_payload.len() + 96));
        out.push_str("{\"payloadType\":\"");
        out.push_str(DSSE_PAYLOAD_TYPE);
        out.push_str("\",\"payload\":\"");
        out.push_str(&base64_encode(&self.dsse_payload));
        out.push_str("\",\"signatures\":[{\"sig\":\"");
        out.push_str(&base64_encode(&self.dsse_signature));
        out.push_str("\"}]}");
        out.into_bytes()
    }

    /// The RFC 6962 leaf hash of this entry.
    pub fn leaf_hash(&self) -> [u8; 32] {
        leaf_hash(&self.entry_bytes())
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

impl ZoneKey<'_> {
    /// The raw public key: 64 bytes of uncompressed P-256 coordinates, as
    /// DNSSEC algorithm 13 stores them (RFC 6605 §4).
    fn public_key(&self) -> Result<&[u8], ProofError> {
        let rdata = self.dnskey_rdata;
        if rdata.len() != 4 + 64 {
            return Err(ProofError::Binding(format!(
                "DNSKEY rdata is {} bytes, not the 68 of algorithm 13",
                rdata.len()
            )));
        }
        let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
        if flags != ZONE_KEY_FLAGS {
            return Err(ProofError::Binding(format!(
                "DNSKEY flags {flags} are not {ZONE_KEY_FLAGS}"
            )));
        }
        if rdata[3] != ZONE_KEY_ALGORITHM {
            return Err(ProofError::Binding(format!(
                "DNSKEY algorithm {} is not {ZONE_KEY_ALGORITHM}",
                rdata[3]
            )));
        }
        Ok(&rdata[4..])
    }
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
/// The order is the order of the argument: the log vouches for an entry
/// (checkpoint, inclusion) that the zone key itself signed (possession) and
/// that names this exact key and zone (binding). Any single failure refuses
/// the whole record — there is no partial credit.
pub fn verify(
    proof: &RekorProof,
    key: &ZoneKey<'_>,
    logs: &LogKeys,
) -> Result<VerifiedRecord, ProofError> {
    if proof.key_tag != key.key_tag {
        return Err(ProofError::Binding(format!(
            "proof is for key tag {}, the answer was signed by {}",
            proof.key_tag, key.key_tag
        )));
    }
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

    // Possession: the DSSE signature is the zone key's own.
    let public = key.public_key()?;
    verify_ecdsa_p256(
        public,
        &pae(DSSE_PAYLOAD_TYPE, &proof.dsse_payload),
        &proof.dsse_signature,
    )
    .map_err(|_| ProofError::Possession("the DSSE signature is not this zone key's".into()))?;

    // Binding: the Statement describes the key and zone actually observed.
    let statement = ZoneKeyStatement::parse(&proof.dsse_payload)?;
    statement.check_binds(key)?;

    // Inclusion: the entry is in the tree the checkpoint commits to.
    verify_inclusion(
        proof.log_index,
        checkpoint.tree_size,
        proof.leaf_hash(),
        &proof.inclusion_path,
        checkpoint.root_hash,
    )?;

    // The log vouches: the checkpoint carries the pinned key's signature.
    checkpoint.verify_signature(log_key)?;

    Ok(VerifiedRecord {
        log_index: proof.log_index,
        tree_size: checkpoint.tree_size,
        origin: checkpoint.origin,
        action: statement.action,
    })
}

/// The in-toto Statement a zone-key entry carries (§2).
///
/// Built here as well as parsed: the canonical rendering is the thing both
/// halves of the system have to agree on, so it lives with the parser that
/// depends on it rather than in whichever tool happened to need it first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneKeyStatement {
    /// The subject name — the apex, as an FQDN.
    pub subject_name: String,
    /// Lowercase hex SHA-256 of the DNSKEY rdata.
    pub subject_sha256: String,
    /// The zone this key is claimed for.
    pub apex: String,
    /// The DNSKEY key tag.
    pub key_tag: u16,
    /// The DNSSEC algorithm number.
    pub algorithm: u8,
    /// The DNSKEY flags.
    pub flags: u16,
    /// The DS record line for the parent, `<tag> <alg> 2 <hex digest>`.
    pub ds: String,
    /// `create`, `rollover` or `retire`.
    pub action: String,
    /// The key tag this one replaces, for `rollover`.
    pub replaces_key_tag: Option<u16>,
}

impl ZoneKeyStatement {
    /// Renders the canonical Statement bytes.
    ///
    /// Field order is fixed and there is no whitespace: the signature and
    /// the leaf hash are over these exact bytes, so "equivalent JSON" is not
    /// equivalent at all.
    pub fn to_json(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("{\"_type\":");
        json_string(&mut out, STATEMENT_TYPE);
        out.push_str(",\"subject\":[{\"name\":");
        json_string(&mut out, &self.subject_name);
        out.push_str(",\"digest\":{\"sha256\":");
        json_string(&mut out, &self.subject_sha256);
        out.push_str("}}],\"predicateType\":");
        json_string(&mut out, PREDICATE_TYPE);
        out.push_str(",\"predicate\":{\"apex\":");
        json_string(&mut out, &self.apex);
        out.push_str(",\"keyTag\":");
        out.push_str(&self.key_tag.to_string());
        out.push_str(",\"algorithm\":");
        out.push_str(&self.algorithm.to_string());
        out.push_str(",\"flags\":");
        out.push_str(&self.flags.to_string());
        out.push_str(",\"ds\":");
        json_string(&mut out, &self.ds);
        out.push_str(",\"action\":");
        json_string(&mut out, &self.action);
        out.push_str(",\"replacesKeyTag\":");
        match self.replaces_key_tag {
            Some(tag) => out.push_str(&tag.to_string()),
            None => out.push_str("null"),
        }
        out.push_str("}}");
        out.into_bytes()
    }

    /// Parses a Statement, accepting unknown members so the predicate can
    /// grow, and refusing anything whose known members are the wrong shape.
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
        let [subject] = subjects.as_slice() else {
            return Err(bad(format!(
                "a zone-key entry has exactly one subject, not {}",
                subjects.len()
            )));
        };
        let predicate = &value["predicate"];
        let key_tag = number(&predicate["keyTag"], "keyTag")?;
        let algorithm = number(&predicate["algorithm"], "algorithm")?;
        let flags = number(&predicate["flags"], "flags")?;
        let replaces_key_tag = match &predicate["replacesKeyTag"] {
            serde_json::Value::Null => None,
            other => Some(
                u16::try_from(number(other, "replacesKeyTag")?)
                    .map_err(|_| bad("replacesKeyTag is out of range".into()))?,
            ),
        };
        Ok(ZoneKeyStatement {
            subject_name: text(&subject["name"], "subject name")?,
            subject_sha256: text(&subject["digest"]["sha256"], "subject sha256 digest")?,
            apex: text(&predicate["apex"], "apex")?,
            key_tag: u16::try_from(key_tag).map_err(|_| bad("keyTag is out of range".into()))?,
            algorithm: u8::try_from(algorithm)
                .map_err(|_| bad("algorithm is out of range".into()))?,
            flags: u16::try_from(flags).map_err(|_| bad("flags is out of range".into()))?,
            ds: text(&predicate["ds"], "ds")?,
            action: text(&predicate["action"], "action")?,
            replaces_key_tag,
        })
    }

    /// Checks that the Statement describes the key and zone observed (§4.2).
    ///
    /// The apex check is what stops a key logged for one zone being replayed
    /// into another; the digest check is what stops a Statement being reused
    /// for a different key under the same name.
    fn check_binds(&self, key: &ZoneKey<'_>) -> Result<(), ProofError> {
        let digest = hex_lower(&sha256(key.dnskey_rdata));
        if !self.subject_sha256.eq_ignore_ascii_case(&digest) {
            return Err(ProofError::Binding(
                "the subject digest is not this DNSKEY's rdata".into(),
            ));
        }
        if !same_name(&self.apex, key.apex) {
            return Err(ProofError::Binding(format!(
                "the entry names apex {}, the answer was signed by {}",
                self.apex, key.apex
            )));
        }
        if !same_name(&self.subject_name, key.apex) {
            return Err(ProofError::Binding(format!(
                "the subject names {}, the answer was signed by {}",
                self.subject_name, key.apex
            )));
        }
        if self.key_tag != key.key_tag {
            return Err(ProofError::Binding(format!(
                "the entry names key tag {}, the answer was signed by {}",
                self.key_tag, key.key_tag
            )));
        }
        if self.algorithm != ZONE_KEY_ALGORITHM || self.flags != ZONE_KEY_FLAGS {
            return Err(ProofError::Binding(format!(
                "the entry names algorithm {} flags {}, not the CSK convention {ZONE_KEY_ALGORITHM}/{ZONE_KEY_FLAGS}",
                self.algorithm, self.flags
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

    /// Verifies that the pinned log key signed this checkpoint.
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

/// Verifies an ECDSA P-256/SHA-256 signature in raw `r || s` form against a
/// DNSSEC algorithm 13 public key (64 bytes of coordinates).
fn verify_ecdsa_p256(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ProofError> {
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(public);
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &uncompressed)
        .verify(message, signature)
        .map_err(|_| ProofError::Possession("signature does not verify".into()))
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

/// Two DNS names, compared the way DNS compares them: case-insensitively,
/// with the root dot optional.
fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
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
            key_tag: 34_918,
            log_id: [7u8; 32],
            log_index: 1_234_567,
            dsse_payload: b"{\"_type\":\"x\"}".to_vec(),
            dsse_signature: vec![9u8; 64],
            checkpoint: "log.example\n4\nAAAA\n\n\u{2014} log.example AAAAAAAA\n"
                .as_bytes()
                .to_vec(),
            inclusion_path: vec![[1u8; 32], [2u8; 32]],
        }
    }

    #[test]
    fn proofs_round_trip() {
        let original = proof();
        let bytes = original.encode();
        assert_eq!(RekorProof::decode(&bytes).unwrap(), original);
        assert_eq!(RekorProof::from_txt(&original.to_txt()).unwrap(), original);
    }

    #[test]
    fn the_wire_layout_is_pinned() {
        // Field offsets are load-bearing across two implementations; assert
        // them rather than trusting the encoder to agree with itself.
        let bytes = proof().encode();
        assert_eq!(bytes[0], PROOF_VERSION);
        assert_eq!(&bytes[1..3], &34_918u16.to_be_bytes());
        assert_eq!(&bytes[3..35], &[7u8; 32]);
        assert_eq!(&bytes[35..43], &1_234_567u64.to_be_bytes());
        assert_eq!(&bytes[43..45], &13u16.to_be_bytes());
    }

    #[test]
    fn a_truncated_or_padded_record_is_malformed() {
        let bytes = proof().encode();
        for cut in [0, 1, 10, 44, bytes.len() - 1] {
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
        wrong_version[0] = 2;
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
        let statement = ZoneKeyStatement {
            subject_name: "sync.example.dev.".into(),
            subject_sha256: "ab".repeat(32),
            apex: "sync.example.dev.".into(),
            key_tag: 34_918,
            algorithm: 13,
            flags: 257,
            ds: "34918 13 2 deadbeef".into(),
            action: "rollover".into(),
            replaces_key_tag: Some(1234),
        };
        let json = statement.to_json();
        assert_eq!(ZoneKeyStatement::parse(&json).unwrap(), statement);
        let text = String::from_utf8(json).unwrap();
        assert!(text.starts_with("{\"_type\":\"https://in-toto.io/Statement/v1\","));
        assert!(!text.contains(' ') || text.contains("34918 13 2"));
        assert!(text.ends_with("\"replacesKeyTag\":1234}}"));

        let created = ZoneKeyStatement {
            replaces_key_tag: None,
            action: "create".into(),
            ..statement
        };
        let text = String::from_utf8(created.to_json()).unwrap();
        assert!(text.ends_with("\"replacesKeyTag\":null}}"), "{text}");
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
        let rekor_v2: [u8; 32] =
            hex::decode("b54813cb63d8859870a5e78500cc6adcfdf59723edae93ee8d25faf2475a0690")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(keys.find(&rekor_v1).is_some(), "rekor.sigstore.dev");
        assert!(
            keys.find(&rekor_v2).is_some(),
            "log2025-1.rekor.sigstore.dev"
        );
    }

    #[test]
    fn names_compare_the_way_dns_does() {
        assert!(same_name("Sync.Example.Dev.", "sync.example.dev"));
        assert!(!same_name("sync.example.dev", "other.example.dev"));
    }
}
