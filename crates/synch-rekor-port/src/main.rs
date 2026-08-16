//! synch-rekor — the rekor wire formats behind a stdio port.
//!
//! The control plane publishes zone-key transparency entries; the clients and
//! the monitor read them. Both halves are the same handful of byte-exact
//! formats — the in-toto Statement, the DSSE PAE, the `hashedrekord` body,
//! the certificate and its two extensions, the `RekorProof` v3 record — and
//! they used to be implemented twice, once in `crates/synch-net` and once in
//! Gleam. Three shipped bugs came out of the two copies drifting, including a
//! DNS-name comparison rule that was wrong on one side and let an entry every
//! client accepted land in a monitor's silent bin. So there is one
//! implementation now, in `synch-net`, and this program is how the BEAM
//! reaches it: no NIFs, one OS process, a fault here kills that process and
//! nothing else.
//!
//! It is deliberately the same shape as `control-plane/csqlite`: a length-
//! framed request/response loop over stdin/stdout, one request at a time,
//! because the caller serializes access anyway. Framing is a 4-byte
//! big-endian length followed by that many payload bytes ({packet,4} on the
//! BEAM side), both directions.
//!
//! Unlike csqlite this program holds **no state at all** between frames: every
//! request carries everything it needs, so there is no open/close handshake
//! and a crashed process costs the caller a reopen and nothing more.
//!
//! Requests (first payload byte is the opcode):
//!   0x01 LOGKEY  blob path                      — resolve the pinned log key
//!   0x02 MINT    see [`handle_mint`]            — build one submission
//!   0x03 VERIFY  see [`handle_verify`]          — verify one returned entry
//!
//! Responses:
//!   0x81 LOGKEY-OK  blob spki, u8[32] log_id
//!   0x82 MINT-OK    blob statement, blob digest, blob signature,
//!                   blob certificate, u8 reused
//!   0x83 VERIFY-OK  blob proof_txt, u8[32] log_id, u8 chainless,
//!                   u8 countersigned, u16 countersigner_key_tag,
//!                   u64 tree_size, blob origin, blob action
//!   0x84 ERR        i32 class (see [`Class`]), blob message
//!
//! `blob` is a u32 big-endian length followed by that many bytes; every
//! integer is big-endian. An optional file path is spelled as an empty blob,
//! which is a path no filesystem has.
//!
//! **Private keys arrive as paths, never as bytes and never in argv.** The
//! zone CSK is the whole secret of the service; argv is world-readable
//! through `ps`, and a key streamed through a pipe is a key in two processes'
//! memory instead of one. This program opens the file itself, exactly as
//! csqlite opens the database.

use std::io::{Read, Write};

use hickory_resolver::proto::dnssec::TrustAnchors;
use synch_net::{
    chain,
    rekor::{self, Demand, LogKey, LogKeys, RekorProof, ZoneKey, ZoneKeyStatement},
    x509::{self, SelfSigned},
    zonecert::{ChainLink, DnssecChain, Succession, OID_DNSSEC_CHAIN, OID_SUCCESSION},
};

/// A frame larger than this is a protocol violation, not a workload. The same
/// bound csqlite draws, for the same reason.
const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// How long a zone-key certificate claims to be valid: a century.
///
/// The window is **semantically meaningless** — nothing in Rekor, in the
/// client or in the monitor reads it, because the certificate is a key
/// envelope and not a trust assertion — but X.509 has a mandatory field
/// there, so it is filled in with something honest rather than with something
/// that looks like a policy.
const CERTIFICATE_LIFETIME_SECONDS: i64 = 3_155_760_000;

/// The subject and issuer common name. Stable and descriptive: a self-signed
/// certificate's issuer is its subject, and this string is the only
/// human-readable hint an auditor reading the raw log entry gets.
const COMMON_NAME: &str = "synchronicity zone key";

/// The log this service submits to when `CP_REKOR_KEY` is unset:
/// log2025-1.rekor.sigstore.dev's Ed25519 key.
///
/// One key, not the client's whole pin set — the control plane writes to one
/// log and must verify what *that* log returns. It is one of the keys in
/// [`rekor::EMBEDDED_LOG_KEYS`] and the test below holds the two together:
/// a default this service trusts to write to but no client would accept a
/// proof from is a publish that succeeds into a zone nobody can resolve.
const DEFAULT_LOG_KEY: &str = "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=";

// ------------------------------------------------------------------ failure

/// The failure classes a caller can act on.
///
/// The verification classes are `rekor::ProofError`'s own, because the whole
/// point of running the client's verifier here is that the control plane
/// refuses exactly what a client would refuse — and says so in the same
/// words. The numbers are wire values; do not renumber them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
enum Class {
    /// The request itself is malformed: truncated frame, unknown opcode. A
    /// bug in the caller, never an operational state.
    Protocol = 1,
    /// A key file could not be read or is not the material it claims to be.
    Key = 2,
    /// A trust anchor or log key file could not be read.
    Config = 3,
    /// The proof does not decode as the format defines it.
    Malformed = 4,
    /// The entry signature is not the zone key's.
    Possession = 5,
    /// The entry does not describe the key and zone in hand.
    Binding = 6,
    /// The entry is not in the tree the checkpoint commits to.
    Inclusion = 7,
    /// The checkpoint is not signed by the log it claims to come from.
    Checkpoint = 8,
    /// The proof names a log this service does not hold the key for.
    UnknownLog = 9,
    /// The DNSSEC chain does not establish that this key was delegated.
    Chain = 10,
    /// The record does not fit the wire format — an oversized field.
    Format = 11,
}

/// One refusal, as it goes back over the wire.
#[derive(Debug)]
struct Fail {
    class: Class,
    message: String,
}

impl Fail {
    fn new(class: Class, message: impl std::fmt::Display) -> Fail {
        Fail {
            class,
            message: message.to_string(),
        }
    }
}

/// Maps a verification failure onto its class, so the caller's error reads
/// the same as the client's would.
fn proof_fail(error: rekor::ProofError) -> Fail {
    let class = match error {
        rekor::ProofError::Malformed(_) => Class::Malformed,
        rekor::ProofError::Possession(_) => Class::Possession,
        rekor::ProofError::Binding(_) => Class::Binding,
        rekor::ProofError::Inclusion(_) => Class::Inclusion,
        rekor::ProofError::Checkpoint(_) => Class::Checkpoint,
        rekor::ProofError::UnknownLog(_) => Class::UnknownLog,
        rekor::ProofError::Chain(_) => Class::Chain,
    };
    Fail::new(class, error)
}

// ------------------------------------------------------------- request side

/// A bounds-checked reader over one request frame.
///
/// Every accessor returns a `Result`, so a truncated frame is a refusal
/// rather than a panic: these bytes come from another process, and the one
/// thing this program must never do is die on a malformed one.
struct Cur<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cur<'a> {
    fn new(bytes: &'a [u8]) -> Cur<'a> {
        Cur { bytes, at: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Fail> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| Fail::new(Class::Protocol, "a length overflows the frame"))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| Fail::new(Class::Protocol, "the frame is truncated"))?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, Fail> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Fail> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Result<u64, Fail> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("eight bytes");
        Ok(u64::from_be_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, Fail> {
        Ok(self.u64()? as i64)
    }

    fn array32(&mut self) -> Result<[u8; 32], Fail> {
        Ok(self.take(32)?.try_into().expect("thirty-two bytes"))
    }

    /// A u32-length-prefixed byte string.
    fn blob(&mut self) -> Result<&'a [u8], Fail> {
        let bytes = self.take(4)?;
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        self.take(len as usize)
    }

    fn text(&mut self) -> Result<&'a str, Fail> {
        std::str::from_utf8(self.blob()?)
            .map_err(|_| Fail::new(Class::Protocol, "a text field is not UTF-8"))
    }

    /// A text field that is allowed to be absent, spelled as an empty blob.
    fn optional_text(&mut self) -> Result<Option<&'a str>, Fail> {
        Ok(match self.text()? {
            "" => None,
            text => Some(text),
        })
    }

    /// Refuses trailing bytes: they mean the encoder and this parser disagree,
    /// which is a divergence to fail on rather than to tolerate.
    fn finish(&self) -> Result<(), Fail> {
        match self.at == self.bytes.len() {
            true => Ok(()),
            false => Err(Fail::new(
                Class::Protocol,
                "trailing bytes after the request",
            )),
        }
    }
}

// ------------------------------------------------------------ response side

/// A response frame under construction.
#[derive(Default)]
struct Buf {
    data: Vec<u8>,
}

impl Buf {
    fn tagged(tag: u8) -> Buf {
        Buf { data: vec![tag] }
    }

    fn u8(&mut self, value: u8) -> &mut Buf {
        self.data.push(value);
        self
    }

    fn u16(&mut self, value: u16) -> &mut Buf {
        self.data.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn u64(&mut self, value: u64) -> &mut Buf {
        self.data.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn i32(&mut self, value: i32) -> &mut Buf {
        self.data.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn raw(&mut self, bytes: &[u8]) -> &mut Buf {
        self.data.extend_from_slice(bytes);
        self
    }

    fn blob(&mut self, bytes: &[u8]) -> &mut Buf {
        // Unreachable for anything this program produces — a certificate and
        // a proof are kilobytes — but a truncated length prefix would desync
        // the framing forever, so it dies loudly instead.
        let len = u32::try_from(bytes.len()).expect("a response field fits a u32 length");
        self.data.extend_from_slice(&len.to_be_bytes());
        self.data.extend_from_slice(bytes);
        self
    }
}

// -------------------------------------------------------------- exact stdio

fn read_exact(input: &mut impl Read, buf: &mut [u8]) -> bool {
    match input.read_exact(buf) {
        Ok(()) => true,
        // A clean EOF is the owner going away: the only shutdown this
        // program has, exactly as for csqlite.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => false,
        Err(e) => {
            eprintln!("synch-rekor: read: {e}");
            std::process::exit(1);
        }
    }
}

fn write_frame(output: &mut impl Write, buf: &Buf) {
    let len = u32::try_from(buf.data.len()).expect("a response fits a u32 length");
    let mut write = || -> std::io::Result<()> {
        output.write_all(&len.to_be_bytes())?;
        output.write_all(&buf.data)?;
        output.flush()
    };
    if let Err(e) = write() {
        // The owner closing the port is a shutdown, not a crash.
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("synch-rekor: write: {e}");
        std::process::exit(1);
    }
}

// ------------------------------------------------------------------ helpers

/// Standard base64, padding optional — the encoding every key file in this
/// system is written in.
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

/// A zone CSK read from the control plane's key file.
struct Csk {
    private: Vec<u8>,
    public: Vec<u8>,
}

impl Csk {
    /// Reads `private:` / `public:` base64 lines — the format
    /// `control-plane/src/dnssec/keys.gleam` writes.
    ///
    /// The path arrives over the framed protocol and is opened here, so the
    /// private scalar exists in this process and nowhere else.
    fn read(path: &str) -> Result<Csk, Fail> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Fail::new(Class::Key, format!("reading {path}: {e}")))?;
        let field = |prefix: &str| -> Result<Vec<u8>, Fail> {
            let line = text
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .ok_or_else(|| Fail::new(Class::Key, format!("no '{prefix}' line in {path}")))?;
            base64_decode(line.trim())
                .map_err(|()| Fail::new(Class::Key, format!("'{prefix}' in {path} is not base64")))
        };
        let private = field("private: ")?;
        let public = field("public: ")?;
        if private.len() != 32 || public.len() != 64 {
            return Err(Fail::new(
                Class::Key,
                format!("malformed key material in {path}"),
            ));
        }
        Ok(Csk { private, public })
    }

    fn spki(&self) -> Vec<u8> {
        rekor::p256_spki(&self.public)
    }

    /// The DNSKEY rdata this key publishes as: the CSK convention.
    fn dnskey_rdata(&self) -> Vec<u8> {
        let mut rdata = Vec::with_capacity(4 + 64);
        rdata.extend_from_slice(&rekor::ZONE_KEY_FLAGS.to_be_bytes());
        rdata.push(3);
        rdata.push(rekor::ZONE_KEY_ALGORITHM);
        rdata.extend_from_slice(&self.public);
        rdata
    }

    /// Signs with ECDSA P-256/SHA-256, ASN.1/DER — the encoding a Rekor
    /// entry's `signature.content` carries and the client's possession check
    /// verifies, not the raw `r||s` of a DNSSEC signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Fail> {
        let rng = ring::rand::SystemRandom::new();
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&self.public);
        let key = ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &self.private,
            &point,
            &rng,
        )
        .map_err(|e| {
            Fail::new(
                Class::Key,
                format!("the key file's material is not a P-256 key pair: {e}"),
            )
        })?;
        key.sign(&rng, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| Fail::new(Class::Key, "signing failed"))
    }
}

/// The trust anchors a chain is walked against.
///
/// `None` is the IANA root, which is what a public zone is delegated under
/// and therefore what a monitor will use. An override is a different
/// universe — the same semantics as the client's `--dnssec-anchor` — and is
/// how a private-root deployment, or a test, anchors its own chain.
fn anchors(path: Option<&str>) -> Result<TrustAnchors, Fail> {
    match path {
        None => Ok(TrustAnchors::default()),
        Some(path) => TrustAnchors::from_file(std::path::Path::new(path))
            .map_err(|e| Fail::new(Class::Config, format!("trust anchor file {path}: {e}"))),
    }
}

/// The pinned log key: the file's, or the default public log's.
fn log_keys(path: Option<&str>) -> Result<LogKeys, Fail> {
    let keys = match path {
        None => LogKeys::parse(DEFAULT_LOG_KEY).map_err(proof_fail)?,
        Some(path) => LogKeys::from_file(std::path::Path::new(path)).map_err(proof_fail)?,
    };
    // One log, one key. A file with several keys in it would leave the
    // service unable to say which log it just wrote to.
    match keys.keys() {
        [_] => Ok(keys),
        others => Err(Fail::new(
            Class::Config,
            format!(
                "the pinned log key file holds {} keys; this service submits to one log \
                 and must verify what that log returns",
                others.len()
            ),
        )),
    }
}

fn parse_apex(text: &str) -> Result<hickory_resolver::proto::rr::Name, Fail> {
    chain::parse_name(text).map_err(|e| Fail::new(Class::Binding, e))
}

// -------------------------------------------------------------------- LOGKEY

/// `LOGKEY blob path` → the DER SubjectPublicKeyInfo and the log id it
/// implies.
///
/// Resolved up front by a publish run so that a key file this service cannot
/// read is an error *before* anything is submitted, and so that the log id
/// stored beside a proof is the one derived from the pinned key rather than
/// anything a server said. Rekor's `TransparencyLogEntry.logId.keyId` is the
/// C2SP note key id — a different 32-byte value that arrives in the same JSON
/// response and looks every bit as much like the answer.
fn handle_logkey(cur: &mut Cur<'_>) -> Result<Buf, Fail> {
    let path = cur.optional_text()?;
    cur.finish()?;
    let keys = log_keys(path)?;
    let [key] = keys.keys() else {
        unreachable!("log_keys returns exactly one key")
    };
    let mut out = Buf::tagged(0x81);
    out.blob(key.spki()).raw(&key.id);
    Ok(out)
}

// ---------------------------------------------------------------------- MINT

/// `MINT` → the one submission a `rekor-publish` run POSTs.
///
/// ```text
/// blob apex           the zone apex, as an FQDN
/// blob key_file       the zone CSK's file (read here, never streamed)
/// blob action         create | rollover | retire
/// i64  now            the certificate's notBefore
/// u8   replaces?      1 when a predecessor key tag follows
/// u16  replaces       the key tag this one replaces, for a rollover
/// blob predecessor    the predecessor CSK's file, or empty
/// blob anchor         a trust anchor file, or empty for the IANA root
/// u16  links, then per link: blob zone, blob rrs
/// u8   priors, then per prior: blob statement, blob canonicalized_body
/// ```
///
/// The chain is **validated cryptographically before the certificate is
/// built**, against the same walk every client and monitor runs. A chain that
/// does not authorize this key is a publish that fails at the terminal with
/// an operator reading the reason, rather than an entry in a permanent public
/// log that no reader can anchor. That is a stricter rule than the shape
/// check it replaces, and it is the rule that matters: the previous version
/// checked only that the extension was *present*, which let a chain that
/// stopped at the TLD reach the log.
///
/// `priors` carry what previous runs already logged for this key tag and
/// action. When one of them has a byte-identical Statement and a certificate
/// that already says everything this run has to say, its signature and
/// certificate are reused verbatim:
/// ECDSA signing is randomized and a freshly collected chain carries fresh
/// RRSIGs, so rebuilding either would mint a second Merkle leaf for one
/// claim. Rekor is content-addressed, so reuse is exactly what makes a
/// republish a refresh.
fn handle_mint(cur: &mut Cur<'_>) -> Result<Buf, Fail> {
    let apex_text = cur.text()?;
    let key_file = cur.text()?;
    let action = cur.text()?.to_string();
    let now = cur.i64()?;
    let replaces = match cur.u8()? {
        0 => {
            let _ = cur.u16()?;
            None
        }
        _ => Some(cur.u16()?),
    };
    let predecessor_file = cur.optional_text()?;
    let anchor_file = cur.optional_text()?;
    let link_count = cur.u16()?;
    let mut links = Vec::with_capacity(usize::from(link_count));
    for _ in 0..link_count {
        links.push(ChainLink {
            zone: cur.text()?.to_string(),
            rrs: cur.blob()?.to_vec(),
        });
    }
    let prior_count = cur.u8()?;
    let mut priors = Vec::with_capacity(usize::from(prior_count));
    for _ in 0..prior_count {
        priors.push((cur.blob()?.to_vec(), cur.blob()?.to_vec()));
    }
    cur.finish()?;

    let apex = parse_apex(apex_text)?;
    let csk = Csk::read(key_file)?;
    let rdata = csk.dnskey_rdata();
    let statement = ZoneKeyStatement {
        subject_name: apex.to_string(),
        subject_sha256: hex_lower(&rekor::sha256(&rdata)),
        apex: apex.to_string(),
        key_tag: chain::key_tag(&rdata),
        algorithm: rekor::ZONE_KEY_ALGORITHM,
        flags: rekor::ZONE_KEY_FLAGS,
        ds: chain::ds_fields(&apex, &rdata),
        action: action.clone(),
        replaces_key_tag: replaces,
    }
    .to_json();

    let predecessor = match predecessor_file {
        None => None,
        Some(path) => Some(Csk::read(path)?),
    };
    let (signature, certificate, reused) = match reuse(&priors, &statement, predecessor.as_ref()) {
        Some((signature, certificate)) => (signature, certificate, true),
        None => {
            let certificate = mint_certificate(
                &apex,
                &csk,
                &action,
                now,
                &links,
                anchor_file,
                predecessor.as_ref(),
            )?;
            let signature = csk.sign(&rekor::pae(rekor::DSSE_PAYLOAD_TYPE, &statement))?;
            (signature, certificate, false)
        }
    };

    let digest = rekor::sha256(&rekor::pae(rekor::DSSE_PAYLOAD_TYPE, &statement));
    let mut out = Buf::tagged(0x82);
    // The key's identity, so the caller files the record under the key rather
    // than under a 16-bit checksum of it — derived here because the DER
    // SubjectPublicKeyInfo is one of the formats that lives in one place now.
    out.raw(&rekor::sha256(&csk.spki()))
        .blob(&statement)
        .blob(&digest)
        .blob(&signature)
        .blob(&certificate)
        .u8(u8::from(reused));
    Ok(out)
}

/// The signature and certificate a previous run logged, when this run has
/// nothing new to say.
///
/// The predecessor condition is the whole reason this is not an equality
/// test. The recovery for "you forgot the predecessor keyfile" is to re-run
/// with it, and the Statement bytes are identical either way — the
/// predecessor's key tag lives in the certificate, not the Statement. Reusing
/// on Statement equality alone therefore threw the new countersignature away
/// and reported success, leaving the zone tier B in every monitor forever.
/// Statement equality is also a key identity test — the Statement names its
/// key by the SHA-256 of the DNSKEY rdata — so a row belonging to another key
/// that happens to share this 16-bit key tag can never match.
fn reuse(
    priors: &[(Vec<u8>, Vec<u8>)],
    statement: &[u8],
    predecessor: Option<&Csk>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let (_, prior_body) = priors
        .iter()
        .find(|(prior_statement, _)| prior_statement == statement)?;
    let body = rekor::HashedRekordBody::parse(prior_body).ok()?;
    if let Some(predecessor) = predecessor {
        // A predecessor was named: reuse only if the logged certificate
        // already countersigns with *that* key. Otherwise this run has
        // something to say that the stored entry does not.
        let value = body.certificate.extension(OID_SUCCESSION)?;
        let succession = Succession::decode(value).ok()?;
        if succession.predecessor_spki != predecessor.spki() {
            return None;
        }
    }
    Some((body.signature, body.certificate_der))
}

/// Builds the certificate a fresh entry carries.
///
/// `create` and `rollover` must carry a chain, and failing here is the point:
/// an entry without one is refused by every client, so discovering it now —
/// with an operator standing at the terminal — beats discovering it later
/// from a cluster that will not resolve. A `retire` is the one exception: a
/// zone being retired may have no DS left to build a chain from, and clients
/// refuse a retire as authorization outright, so the exception cannot be
/// turned into an evasion.
fn mint_certificate(
    apex: &hickory_resolver::proto::rr::Name,
    csk: &Csk,
    action: &str,
    now: i64,
    links: &[ChainLink],
    anchor_file: Option<&str>,
    predecessor: Option<&Csk>,
) -> Result<Vec<u8>, Fail> {
    let spki = csk.spki();
    let rdata = csk.dnskey_rdata();
    let mut extensions: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    match (action, links) {
        ("retire", []) => {}
        (_, []) => {
            return Err(Fail::new(
                Class::Chain,
                "a create or rollover entry must carry a DNSSEC chain, and none was \
                 collected — is the DS live in the parent yet?",
            ))
        }
        (_, links) => {
            let carried = DnssecChain {
                links: links.to_vec(),
            };
            chain::validate(&carried, apex, &rdata, &anchors(anchor_file)?)
                .map_err(|e| Fail::new(Class::Chain, e))?;
            extensions.push((OID_DNSSEC_CHAIN.to_vec(), carried.encode()));
        }
    }
    if let Some(predecessor) = predecessor {
        let predecessor_rdata = predecessor.dnskey_rdata();
        let key_tag = chain::key_tag(&predecessor_rdata);
        let signature =
            predecessor.sign(&Succession::signed_bytes(&apex.to_string(), key_tag, &spki))?;
        extensions.push((
            OID_SUCCESSION.to_vec(),
            Succession {
                predecessor_key_tag: key_tag,
                predecessor_spki: predecessor.spki(),
                signature,
            }
            .encode(),
        ));
    }
    // The serial is derived from the key, not drawn at random: re-running the
    // ceremony for the same key must produce the same certificate, or every
    // republish would mint a fresh Merkle leaf for one claim.
    let serial = rekor::sha256(&spki);
    let san = apex.to_string();
    let spec = SelfSigned {
        common_name: COMMON_NAME,
        // No trailing dot: a dNSName is a hostname, and readers parse it into
        // a name before comparing anything, so the dot is presentation rather
        // than identity.
        dns_name: san.trim_end_matches('.'),
        spki: &spki,
        serial: &serial[..20],
        not_before: x509::x509_time(now),
        not_after: x509::x509_time(now + CERTIFICATE_LIFETIME_SECONDS),
        extensions: &extensions,
    };
    // Signed before the certificate is assembled, rather than inside the
    // builder's callback, so that a key that cannot sign is a refusal rather
    // than a certificate with an empty signature in it. Nothing downstream
    // verifies this signature — but a certificate whose self-signature is
    // garbage is one some other tool will reject while reading our log entry,
    // and making the log's contents inspectable is the entire point.
    let signature = csk.sign(&spec.tbs())?;
    let certificate = spec.build(|_| signature);
    // Read back what was just written, with the same parser the client uses.
    // A certificate that lost an extension in the encoder would otherwise be
    // discovered by a client, weeks later.
    x509::Certificate::parse(&certificate)
        .map_err(|e| Fail::new(Class::Malformed, format!("the minted certificate: {e}")))?;
    Ok(certificate)
}

// -------------------------------------------------------------------- VERIFY

/// `VERIFY` → the proof record, once the entry the log returned has been
/// verified by the rules a client applies.
///
/// ```text
/// blob apex               the zone apex, as an FQDN
/// blob public             the zone key's 64-byte P-256 point
/// u16  key_tag
/// u64  log_index
/// blob statement
/// blob canonicalized_body the log's own bytes, verbatim
/// blob checkpoint
/// u8   hops, then hops × 32 bytes of audit path
/// blob log_spki           the pinned log key, from LOGKEY
/// blob action             what this run asked the log to record
/// blob anchor             a trust anchor file, or empty for the IANA root
/// ```
///
/// **This is `rekor::verify` — the client's own verifier, no second
/// implementation and no publisher-flavoured subset.** A row in
/// `rekor_records` therefore means "a client would accept this", which is the
/// single property the store exists to guarantee: the failure this whole step
/// prevents is a proof this service stores and every client refuses.
///
/// The one asymmetry is `retire`, which the client refuses outright because a
/// retirement is a monitor breadcrumb and never authorization. Those go
/// through [`Demand::Breadcrumb`], which demands the action *be* `retire` —
/// so the two demands partition the actions between them and nothing a client
/// would accept can reach the weaker path.
fn handle_verify(cur: &mut Cur<'_>) -> Result<Buf, Fail> {
    let apex_text = cur.text()?;
    let public = cur.blob()?.to_vec();
    let key_tag = cur.u16()?;
    let log_index = cur.u64()?;
    let statement = cur.blob()?.to_vec();
    let canonicalized_body = cur.blob()?.to_vec();
    let checkpoint = cur.blob()?.to_vec();
    let hops = cur.u8()?;
    let mut inclusion_path = Vec::with_capacity(usize::from(hops));
    for _ in 0..hops {
        inclusion_path.push(cur.array32()?);
    }
    let log_spki = cur.blob()?.to_vec();
    let action = cur.text()?.to_string();
    let anchor_file = cur.optional_text()?;
    cur.finish()?;

    let apex = parse_apex(apex_text)?;
    let log_key = LogKey::from_spki(&log_spki).map_err(proof_fail)?;
    let log_id = log_key.id;
    let logs = LogKeys::from_keys(vec![log_key]);
    let anchors = anchors(anchor_file)?;

    let mut rdata = Vec::with_capacity(4 + 64);
    rdata.extend_from_slice(&rekor::ZONE_KEY_FLAGS.to_be_bytes());
    rdata.push(3);
    rdata.push(rekor::ZONE_KEY_ALGORITHM);
    rdata.extend_from_slice(&public);

    let proof = RekorProof {
        key_tag,
        log_id,
        log_index,
        statement,
        canonicalized_body,
        checkpoint,
        inclusion_path,
    };
    let apex_text = apex.to_string();
    let key = ZoneKey {
        apex: &apex_text,
        key_tag,
        dnskey_rdata: &rdata,
    };
    let demand = match action.as_str() {
        "retire" => Demand::Breadcrumb,
        _ => Demand::Authorization,
    };
    let verified =
        rekor::verify_demanding(&proof, &key, &logs, &anchors, demand).map_err(proof_fail)?;
    // The entry the log returned is the entry this run asked it to record.
    // Nothing else could get this far — the digest binds the Statement, and
    // the Statement carries the action — but a publish that stored somebody
    // else's claim under this key's row would be worth failing loudly on.
    if verified.action != action {
        return Err(Fail::new(
            Class::Binding,
            format!(
                "the logged entry's action is {}, not the {action} this run submitted",
                verified.action
            ),
        ));
    }

    // What the operator is told about the entry beyond "it verifies": whether
    // a monitor will see a chain, and which predecessor countersigned it. A
    // publish that quietly lost its countersignature looks exactly like one
    // that never had a predecessor, and the difference is a tier B alert in
    // every monitor watching this zone.
    let body = rekor::HashedRekordBody::parse(&proof.canonicalized_body).map_err(proof_fail)?;
    let chainless = body.certificate.extension(OID_DNSSEC_CHAIN).is_none();
    let countersigner = body
        .succession()
        .and_then(|result| result.ok())
        .map(|succession| succession.predecessor_key_tag);

    let text = proof.to_txt().ok_or_else(|| {
        Fail::new(
            Class::Format,
            "the record does not fit the proof format: a field is longer than its \
             16-bit length, or the audit path is longer than 255 hops",
        )
    })?;
    let mut out = Buf::tagged(0x83);
    out.blob(text.as_bytes())
        .raw(&log_id)
        .u8(u8::from(chainless))
        .u8(u8::from(countersigner.is_some()))
        .u16(countersigner.unwrap_or(0))
        .u64(verified.tree_size)
        .blob(verified.origin.as_bytes())
        .blob(verified.action.as_bytes());
    Ok(out)
}

/// Lowercase hex, the spelling every digest in these formats is written in.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------------ the loop

fn main() {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut header = [0u8; 4];
    while read_exact(&mut input, &mut header) {
        let len = u32::from_be_bytes(header);
        if len == 0 || len > MAX_FRAME {
            eprintln!("synch-rekor: bad frame length");
            std::process::exit(1);
        }
        let mut payload = vec![0u8; len as usize];
        if !read_exact(&mut input, &mut payload) {
            break; // EOF mid-frame: the owner went away.
        }
        let mut cur = Cur::new(&payload);
        let handled = match cur.u8() {
            Ok(0x01) => handle_logkey(&mut cur),
            Ok(0x02) => handle_mint(&mut cur),
            Ok(0x03) => handle_verify(&mut cur),
            Ok(opcode) => Err(Fail::new(
                Class::Protocol,
                format!("unknown opcode 0x{opcode:02x}"),
            )),
            Err(fail) => Err(fail),
        };
        let frame = match handled {
            Ok(frame) => frame,
            Err(fail) => {
                let mut out = Buf::tagged(0x84);
                out.i32(fail.class as i32).blob(fail.message.as_bytes());
                out
            }
        };
        write_frame(&mut output, &frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default this service writes to must be a log clients read from.
    ///
    /// A default log key the control plane trusts but no client pins is a
    /// publish that succeeds into a zone nobody can resolve — the exact
    /// failure the verify-before-store step exists to prevent, arriving
    /// through configuration instead of through bytes.
    #[test]
    fn the_default_log_key_is_one_the_client_pins() {
        let default = LogKeys::parse(DEFAULT_LOG_KEY).expect("the default log key parses");
        let [key] = default.keys() else {
            panic!("the default is exactly one key");
        };
        assert!(
            rekor::LogKeys::embedded().find(&key.id).is_some(),
            "the default log key is not in the client's embedded pin set"
        );
    }

    #[test]
    fn a_key_file_round_trips_through_the_reader() {
        let dir = std::env::temp_dir().join(format!("synch-rekor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("csk.key");
        let private = [7u8; 32];
        let public = [9u8; 64];
        std::fs::write(
            &path,
            format!(
                "# a comment\nprivate: {}\npublic: {}\n",
                rekor::base64_encode(&private),
                rekor::base64_encode(&public)
            ),
        )
        .unwrap();
        let csk = Csk::read(path.to_str().unwrap()).expect("the key file reads");
        assert_eq!(csk.private, private);
        assert_eq!(csk.public, public);
        assert_eq!(csk.dnskey_rdata().len(), 68);

        // Truncated material is refused rather than padded into something.
        std::fs::write(&path, "private: AAAA\npublic: AAAA\n").unwrap();
        assert!(Csk::read(path.to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A truncated request is a refusal, never a panic: these bytes come from
    /// another process and this one has to stay alive to answer.
    #[test]
    fn a_truncated_request_is_refused() {
        let mut cur = Cur::new(&[0x00, 0x00, 0x00, 0x09, 0x61]);
        assert!(cur.blob().is_err());
        let mut cur = Cur::new(&[0xff]);
        assert!(cur.u16().is_err());
        let mut cur = Cur::new(&[0x00, 0x00, 0x00, 0x00, 0x7f]);
        assert_eq!(cur.blob().unwrap(), b"");
        assert!(cur.finish().is_err(), "trailing bytes are a divergence");
    }
}
