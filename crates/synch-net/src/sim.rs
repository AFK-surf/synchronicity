//! A signed DNSSEC zone served over plaintext DoH — test support (§3.2).
//!
//! What the e2e suites need and the real DNS cannot give them: a zone whose
//! signing key *is* the trust anchor, served from a loopback endpoint, so the
//! full validation path — TXT, RRSIG, DNSKEY, anchor — runs against traffic
//! the test controls. Everything here is deliberate test machinery: hidden
//! from the docs, no API stability, no place in a production call path.

use std::sync::Arc;

use hickory_resolver::proto::{
    dnssec::{
        crypto::EcdsaSigningKey, rdata::DNSSECRData, rdata::DNSKEY, rdata::RRSIG, Algorithm,
        DnssecSigner, PublicKey, SigningKey,
    },
    op::Message,
    rr::{rdata::TXT, DNSClass, Name, RData, Record, RecordSet, RecordType},
};

use crate::dns::TXT_PREFIX;

/// One signed zone: an origin, its TXT membership records, and the key that
/// signs both — which the test installs as the whole root of trust.
#[doc(hidden)]
#[allow(missing_debug_implementations)]
pub struct SimZone {
    origin: Name,
    signer: DnssecSigner,
    dnskey: DNSKEY,
    txt: Vec<String>,
    ttl: u32,
    /// When true, answers carry no signatures: syntactically fine,
    /// cryptographically nothing — the tamper case.
    pub unsigned: bool,
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
            txt,
            ttl: 300,
            unsigned: false,
        }
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
