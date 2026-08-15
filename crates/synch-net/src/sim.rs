//! A signed DNSSEC zone and a transparency log served to a client that
//! cannot tell them from the real things — test support (§3.2, §9 of
//! docs/REKOR-ZONE-KEY.md).
//!
//! What the e2e suites need and the real DNS cannot give them: a zone whose
//! signing key *is* the trust anchor, served from a loopback endpoint, so the
//! full validation path — TXT, RRSIG, DNSKEY, anchor — runs against traffic
//! the test controls. [`SimLog`] does the same for the log half: it appends
//! entries, publishes checkpoints and answers with audit paths in exactly the
//! formats [`crate::rekor`] consumes, so every verification failure can be
//! provoked one at a time. Everything here is deliberate test machinery:
//! hidden from the docs, no API stability, no place in a production call path.

use std::sync::Arc;

use hickory_resolver::proto::{
    dnssec::{
        crypto::EcdsaSigningKey, rdata::DNSSECRData, rdata::DNSKEY, rdata::RRSIG, Algorithm,
        DnssecSigner, PublicKey, SigningKey,
    },
    op::Message,
    rr::{rdata::TXT, DNSClass, Name, RData, Record, RecordSet, RecordType},
};

use crate::{
    dns::TXT_PREFIX,
    rekor::{self, RekorProof, ZoneKeyStatement},
};

/// One signed zone: an origin, its TXT membership records, and the key that
/// signs both — which the test installs as the whole root of trust.
#[doc(hidden)]
#[allow(missing_debug_implementations)]
pub struct SimZone {
    origin: Name,
    signer: DnssecSigner,
    dnskey: DNSKEY,
    /// The PKCS#8 the zone key was loaded from, kept so the zone can also
    /// sign things that are not RRsets — a DSSE payload, in this design.
    pkcs8: Vec<u8>,
    txt: Vec<String>,
    ttl: u32,
    /// When true, answers carry no signatures: syntactically fine,
    /// cryptographically nothing — the tamper case.
    pub unsigned: bool,
    /// Proof records served at `_synchronicity-rekor.<origin>`, each one
    /// base64url as [`RekorProof::to_txt`] renders it. Empty is the
    /// not-yet-upgraded control plane.
    pub rekor_txt: Vec<String>,
}

impl SimZone {
    /// Builds a zone for `origin` (e.g. `cluster.example`) publishing `txt`
    /// under `_synchronicity.<origin>`, signed by a fresh ECDSA P-256 key.
    pub fn new(origin: &str, txt: Vec<String>) -> SimZone {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).expect("keygen");
        let key = EcdsaSigningKey::from_pkcs8(&pkcs8, algorithm).expect("key load");
        let public = key.to_public_key().expect("public key");
        let dnskey = DNSKEY::from_key(&public);
        let origin = Name::from_utf8(format!("{origin}.")).expect("origin name");
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            origin.clone(),
            std::time::Duration::from_secs(86_400),
        );
        SimZone {
            origin,
            signer,
            dnskey,
            pkcs8: pkcs8.secret_pkcs8_der().to_vec(),
            txt,
            ttl: 300,
            unsigned: false,
            rekor_txt: Vec::new(),
        }
    }

    /// The apex, as an FQDN with its root dot.
    pub fn apex(&self) -> String {
        self.origin.to_string()
    }

    /// The zone key's DNSKEY rdata: flags, protocol, algorithm, key.
    pub fn dnskey_rdata(&self) -> Vec<u8> {
        let mut rdata = Vec::with_capacity(4 + 64);
        rdata.extend_from_slice(&self.dnskey.flags().to_be_bytes());
        rdata.push(3);
        rdata.push(u8::from(self.dnskey.public_key().algorithm()));
        rdata.extend_from_slice(self.dnskey.public_key().public_bytes());
        rdata
    }

    /// The zone key's tag, as an RRSIG names it.
    pub fn key_tag(&self) -> u16 {
        self.dnskey.calculate_key_tag().expect("key tag")
    }

    /// The DS field the Statement carries: `<tag> <alg> 2 <sha256 hex>` over
    /// the owner name and the DNSKEY rdata (RFC 4034 §5.1.4).
    pub fn ds_field(&self) -> String {
        let rdata = self.dnskey_rdata();
        let mut input = name_wire(&self.origin);
        input.extend_from_slice(&rdata);
        format!(
            "{} {} 2 {}",
            self.key_tag(),
            rekor::ZONE_KEY_ALGORITHM,
            hex::encode(rekor::sha256(&input))
        )
    }

    /// Signs a DSSE payload with the zone key itself — §2's whole point:
    /// possession of the CSK is the authority being made transparent.
    pub fn sign_dsse(&self, payload: &[u8]) -> Vec<u8> {
        sign_p256(&self.pkcs8, &rekor::pae(rekor::DSSE_PAYLOAD_TYPE, payload))
    }

    /// The Statement this zone's control plane would publish for its key.
    pub fn zone_key_statement(&self, action: &str, replaces: Option<u16>) -> ZoneKeyStatement {
        let rdata = self.dnskey_rdata();
        ZoneKeyStatement {
            subject_name: self.apex(),
            subject_sha256: hex::encode(rekor::sha256(&rdata)),
            apex: self.apex(),
            key_tag: self.key_tag(),
            algorithm: rekor::ZONE_KEY_ALGORITHM,
            flags: rekor::ZONE_KEY_FLAGS,
            ds: self.ds_field(),
            action: action.to_string(),
            replaces_key_tag: replaces,
        }
    }

    /// The name the proof records live under.
    pub fn rekor_name(&self) -> Name {
        Name::from_utf8(format!("{}.{}", rekor::REKOR_TXT_PREFIX, self.origin)).expect("rekor name")
    }

    /// The trust-anchor line for this zone's key, in the file syntax
    /// `--dnssec-anchor` reads. Whoever anchors this line trusts this zone —
    /// and nothing signed under the real root.
    pub fn anchor_record(&self) -> String {
        format!(
            "{} IN DNSKEY 257 3 13 {}\n",
            self.origin,
            base64(self.dnskey.public_key().public_bytes())
        )
    }

    /// Serves the zone over plaintext RFC 8484 DoH on a loopback port,
    /// returning the endpoint URL. The task serves until aborted or dropped.
    pub async fn serve(self) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let zone = Arc::new(self);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let url = format!(
            "http://127.0.0.1:{}/dns-query",
            listener.local_addr().expect("local addr").port()
        );
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let zone = zone.clone();
                tokio::spawn(async move {
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 4096];
                    let query = loop {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        raw.extend_from_slice(&buf[..n]);
                        if let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
                            let length: usize = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse().ok())
                                .unwrap_or(0);
                            if raw.len() - split - 4 >= length {
                                break raw[split + 4..split + 4 + length].to_vec();
                            }
                        }
                    };
                    let Ok(request) = Message::from_vec(&query) else {
                        return;
                    };
                    let reply = zone.answer(&request).to_vec().expect("encode reply");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n",
                        reply.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(&reply).await;
                });
            }
        });
        (url, task)
    }

    /// Answers one query: the TXT set, the DNSKEY set, or an empty NOERROR.
    fn answer(&self, request: &Message) -> Message {
        let mut response = request.clone().into_response();
        let Some(query) = request.queries.first().cloned() else {
            return response;
        };
        let name = query.name().clone();
        let mut set = match query.query_type() {
            RecordType::TXT if name == self.txt_name() => {
                let mut set = RecordSet::new(name, RecordType::TXT, 0);
                for text in &self.txt {
                    set.insert(
                        Record::from_rdata(
                            self.txt_name(),
                            self.ttl,
                            RData::TXT(TXT::new(vec![text.clone()])),
                        ),
                        0,
                    );
                }
                set
            }
            RecordType::TXT if name == self.rekor_name() && !self.rekor_txt.is_empty() => {
                let mut set = RecordSet::new(name, RecordType::TXT, 0);
                for text in &self.rekor_txt {
                    // A proof is kilobytes; TXT carries it as consecutive
                    // ≤255-byte character-strings, which the client
                    // concatenates before decoding (§3).
                    let chunks = text
                        .as_bytes()
                        .chunks(255)
                        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                        .collect();
                    set.insert(
                        Record::from_rdata(self.rekor_name(), 86_400, RData::TXT(TXT::new(chunks))),
                        0,
                    );
                }
                set
            }
            RecordType::DNSKEY if name == self.origin => {
                let mut set = RecordSet::new(name, RecordType::DNSKEY, 0);
                set.insert(
                    Record::from_rdata(
                        self.origin.clone(),
                        self.ttl,
                        RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
                    ),
                    0,
                );
                set
            }
            _ => return response,
        };
        if !self.unsigned {
            // Inception an hour ago: RRSIG validity has to bracket "now".
            let inception = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
            let rrsig =
                RRSIG::from_rrset(&set, DNSClass::IN, inception, &self.signer).expect("sign rrset");
            set.insert_rrsig(Record::from_rdata(
                set.name().clone(),
                self.ttl,
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
            ));
        }
        response.add_answers(set.records(true).cloned());
        response
    }

    /// The name the membership records live under.
    pub fn txt_name(&self) -> Name {
        Name::from_utf8(format!("{TXT_PREFIX}.{}", self.origin)).expect("txt name")
    }
}

/// A deterministic in-memory transparency log (§9).
///
/// Entries go in, checkpoints and audit paths come out, in exactly the
/// formats [`crate::rekor`] parses — an RFC 6962 tree over
/// `SHA-256(0x00 || entry)` leaves, and a signed note carrying the origin,
/// the tree size and the root. Nothing here is a Rekor implementation; it is
/// the smallest thing that can produce a *correct* proof, so that a test can
/// then produce exactly one incorrect one.
#[doc(hidden)]
#[allow(missing_debug_implementations)]
pub struct SimLog {
    origin: String,
    pkcs8: Vec<u8>,
    spki: Vec<u8>,
    leaves: Vec<[u8; 32]>,
}

impl SimLog {
    /// A log named `origin` with a fresh key. The key is fixed for the life
    /// of the log, so its id, its PEM and every checkpoint it signs are one
    /// coherent universe a test can pin.
    pub fn new(origin: &str) -> SimLog {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("keygen")
        .as_ref()
        .to_vec();
        let key = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &pkcs8,
            &rng,
        )
        .expect("key load");
        // The public key comes back as an uncompressed point; the SPKI and
        // DNSSEC both want it without the 0x04 tag.
        let point = ring::signature::KeyPair::public_key(&key).as_ref()[1..].to_vec();
        SimLog {
            origin: origin.to_string(),
            pkcs8,
            spki: p256_spki(&point),
            leaves: Vec::new(),
        }
    }

    /// The pinned-key file this log's clients would carry.
    pub fn key_pem(&self) -> String {
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        let body = rekor::base64_encode(&self.spki);
        for line in body.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(line));
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem
    }

    /// The log's id: SHA-256 over its DER SubjectPublicKeyInfo.
    pub fn log_id(&self) -> [u8; 32] {
        rekor::sha256(&self.spki)
    }

    /// Appends one entry, returning its index.
    pub fn append(&mut self, entry: &[u8]) -> u64 {
        self.leaves.push(rekor::leaf_hash(entry));
        self.leaves.len() as u64 - 1
    }

    /// The current Merkle root.
    pub fn root(&self) -> [u8; 32] {
        merkle_root(&self.leaves)
    }

    /// The audit path from one entry to the current root.
    pub fn inclusion_path(&self, index: u64) -> Vec<[u8; 32]> {
        audit_path(index as usize, &self.leaves)
    }

    /// A signed note over the current tree.
    pub fn checkpoint(&self) -> Vec<u8> {
        self.note(self.leaves.len() as u64, self.root())
    }

    /// A signed note over any tree — how a test builds a checkpoint that is
    /// perfectly well signed and describes the wrong tree, or one signed by
    /// the wrong log entirely.
    pub fn note(&self, tree_size: u64, root: [u8; 32]) -> Vec<u8> {
        let body = format!(
            "{}\n{tree_size}\n{}\n",
            self.origin,
            rekor::base64_encode(&root)
        );
        let signature = sign_p256(&self.pkcs8, body.as_bytes());
        // The four-byte key hint is a selector, never a credential; the
        // verifier tries the pinned key regardless of what it says.
        let mut blob = self.log_id()[..4].to_vec();
        blob.extend_from_slice(&signature);
        format!(
            "{body}\n\u{2014} {} {}\n",
            self.origin,
            rekor::base64_encode(&blob)
        )
        .into_bytes()
    }

    /// Logs a Statement the zone key signs, and returns the whole proof —
    /// what `controlplane rekor-publish` ends up storing.
    pub fn log_statement(&mut self, zone: &SimZone, statement: &ZoneKeyStatement) -> RekorProof {
        let dsse_payload = statement.to_json();
        let dsse_signature = zone.sign_dsse(&dsse_payload);
        let mut proof = RekorProof {
            key_tag: statement.key_tag,
            log_id: self.log_id(),
            log_index: 0,
            dsse_payload,
            dsse_signature,
            checkpoint: Vec::new(),
            inclusion_path: Vec::new(),
        };
        proof.log_index = self.append(&proof.entry_bytes());
        proof.checkpoint = self.checkpoint();
        proof.inclusion_path = self.inclusion_path(proof.log_index);
        proof
    }

    /// Logs a zone's current key with the standard Statement.
    pub fn publish(&mut self, zone: &SimZone, action: &str, replaces: Option<u16>) -> RekorProof {
        let statement = zone.zone_key_statement(action, replaces);
        self.log_statement(zone, &statement)
    }

    /// Re-issues the checkpoint and audit path for an already-logged entry,
    /// which is what the control plane's refresh does once the tree grows.
    pub fn refresh(&self, proof: &mut RekorProof) {
        proof.checkpoint = self.checkpoint();
        proof.inclusion_path = self.inclusion_path(proof.log_index);
    }
}

/// RFC 6962 §2.1: the Merkle tree hash over a list of leaf hashes.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [] => rekor::sha256(&[]),
        [only] => *only,
        _ => {
            let split = split_point(leaves.len());
            rekor::node_hash(
                &merkle_root(&leaves[..split]),
                &merkle_root(&leaves[split..]),
            )
        }
    }
}

/// RFC 6962 §2.1.1: the audit path from one leaf to the root.
fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let split = split_point(leaves.len());
    if index < split {
        let mut path = audit_path(index, &leaves[..split]);
        path.push(merkle_root(&leaves[split..]));
        path
    } else {
        let mut path = audit_path(index - split, &leaves[split..]);
        path.push(merkle_root(&leaves[..split]));
        path
    }
}

/// The largest power of two strictly less than `n` — RFC 6962's split.
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Signs with ECDSA P-256/SHA-256, producing the raw `r || s` form DNSSEC
/// and this design's DSSE signatures both use.
fn sign_p256(pkcs8: &[u8], message: &[u8]) -> Vec<u8> {
    let rng = ring::rand::SystemRandom::new();
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8,
        &rng,
    )
    .expect("key load");
    key.sign(&rng, message).expect("sign").as_ref().to_vec()
}

/// A DER SubjectPublicKeyInfo around a raw uncompressed P-256 point.
fn p256_spki(point: &[u8]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    der.extend_from_slice(point);
    der
}

/// The canonical wire form of a name: lowercase labels, length-prefixed,
/// terminated by the root.
fn name_wire(name: &Name) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.to_lowercase().iter() {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out
}

/// Standard base64 with padding — enough for one DNSKEY, not a dependency.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
