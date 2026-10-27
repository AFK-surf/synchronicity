//! DNSSEC end to end against a simulated signed zone (§3.2): the sim serves over
//! plaintext DoH, the test installs the zone's key as the entire root of trust,
//! and the real validation path runs. DNSSEC-only: transparency has its own suite.

mod common;

use iroh_base::SecretKey;
use synch_net::{sim::SimZone, DnssecResolver, RekorPolicy, ResolverOptions};

/// The resolver options this suite runs on: transparency off, TUF off.
fn options(url: String, anchor: &std::path::Path) -> ResolverOptions {
    ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.to_path_buf()),
        rekor: Some(RekorPolicy::Off),
        rekor_key: None,
        rekor_state: None,
        rekor_config: None,
        tuf_url: None,
        no_tuf: true,
        tuf_root: None,
    }
}

/// Serve `zone` over plaintext DoH, resolver anchored at it.
async fn resolve(zone: SimZone) -> (DnssecResolver, tokio::task::JoinHandle<()>) {
    let anchor = common::write(&zone.anchor_record());
    let (url, server) = zone.serve().await;
    let resolver = DnssecResolver::with_options(&options(url, anchor.path())).unwrap();
    (resolver, server)
}

/// The positive end-to-end: real hickory validation under a self-installed anchor,
/// member_set bindings and TTL. And the negative phase: under a stranger's anchor,
/// correctly signed answers refuse exactly as well as forgeries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_zone_validates_end_to_end() {
    let nas = SecretKey::generate().public();
    let laptop = SecretKey::generate().public();
    let zone = SimZone::new(
        "cluster.example",
        vec![
            format!("v=sync1 id=nas nk={}", nas.to_z32()),
            format!("v=sync1 id=laptop nk={}", laptop.to_z32()),
        ],
    );
    let (resolver, server) = resolve(zone).await;
    let validated = resolver
        .lookup_txt_ungated("cluster.example")
        .await
        .unwrap();
    assert_eq!(validated.records.len(), 2, "{validated:?}");
    assert_eq!(validated.ttl.as_secs(), 300);
    let (set, _ttl) = resolver.member_set("cluster.example").await.unwrap();
    assert_eq!(set.bindings.len(), 2, "{set:?}");
    assert!(set
        .bindings
        .iter()
        .any(|(origin, key)| origin.canonical() == "nas@cluster.example" && *key == nas));
    server.abort();

    // The same zone under a stranger's anchor: a root we never trusted validates exactly as well as forgeries.
    let nas = SecretKey::generate().public();
    let zone = SimZone::new(
        "cluster.example",
        vec![format!("v=sync1 id=nas nk={}", nas.to_z32())],
    );
    let anchor = common::write(&SimZone::new("cluster.example", Vec::new()).anchor_record());
    let (url, server) = zone.serve().await;
    let resolver = DnssecResolver::with_options(&options(url, anchor.path())).unwrap();
    resolver
        .lookup_txt_ungated("cluster.example")
        .await
        .expect_err("an unanchored signer must not validate");
    server.abort();
}

/// The forgery the owner-name filter does **not** catch: an anchored attacker
/// zone signs RRsets owned by the victim's name — hickory skips §5.3.1's signer
/// check in two places (both marked TODO) — so the transport filter strips the
/// off-path RRSIG. `rekor` is off on purpose: under `require` the apex sandwich
/// in `apex_of` happens to block this too, and the signer rule must stand alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_zone_may_not_sign_for_a_name_it_does_not_contain() {
    use hickory_resolver::proto::rr::Name;

    let attacker_key = SecretKey::generate().public();
    let mut attacker = SimZone::new("attacker.example", Vec::new());
    attacker.impersonate = Some((
        Name::from_utf8("_synchronicity.cluster.example.").unwrap(),
        vec![format!(
            "v=sync1 id=nas nk={} apex=cluster.example",
            attacker_key.to_z32()
        )],
    ));
    let (resolver, server) = resolve(attacker).await;

    let error = resolver
        .lookup_txt_ungated("cluster.example")
        .await
        .expect_err("a sibling zone must not sign for this name");
    assert!(
        error.to_string().contains("does not contain")
            || error.to_string().contains("not DNSSEC-secure")
            || error.to_string().contains("no RRSIG"),
        "refused for the wrong reason: {error}"
    );
    // And the same through the membership path — what an attacker is actually after.
    resolver
        .member_set("cluster.example")
        .await
        .expect_err("a forged membership answer must not bind anything");
    server.abort();
}

/// A record spliced into a validated answer in another class binds nothing.
/// hickory groups RRsets by `(name, type)` and stamps its verdict on the whole
/// group, while the signed-data construction filters by class — so the filter
/// matches the verifier's `(name, type, class)` triple, and the honest RRSIG
/// verifying is not enough.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_spliced_in_another_class_is_signed_by_nobody() {
    let nas = SecretKey::generate().public();
    let attacker = SecretKey::generate().public();
    let mut zone = SimZone::new(
        "cluster.example",
        vec![format!("v=sync1 id=nas nk={}", nas.to_z32())],
    );
    zone.splice_foreign_class = vec![format!("v=sync1 id=evil nk={}", attacker.to_z32())];
    let (resolver, server) = resolve(zone).await;

    let validated = resolver
        .lookup_txt_ungated("cluster.example")
        .await
        .expect("the honest RRset still validates");
    assert_eq!(
        validated.records.len(),
        1,
        "an unsigned record reached the validated set: {:?}",
        validated.records
    );

    let (set, _ttl) = resolver.member_set("cluster.example").await.unwrap();
    assert_eq!(set.bindings.len(), 1, "{set:?}");
    assert!(
        set.bindings.iter().all(|(_, key)| *key != attacker),
        "a spliced record bound a key the zone never published: {set:?}"
    );
    server.abort();
}

/// A failed fetch of the root key makes dependent RRsets bogus in hickory's
/// response. Its validation cache must not preserve that transient verdict for
/// the signed records' full TTL after the endpoint recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transient_chain_failure_expires_without_restarting_the_resolver() {
    use hickory_resolver::proto::{
        dnssec::rdata::DNSSECRData,
        op::Message,
        rr::{rdata::TXT, Name, RData, Record, RecordType},
        serialize::binary::{BinDecodable, BinDecoder},
    };
    use std::sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    };
    use synch_net::sim::SimDelegation;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let records = common::member_records();
    let ladder = SimDelegation::new("cluster.example", records.clone());
    let anchor = common::write(&ladder.root.anchor_record());
    let owner = Name::from_utf8("_synchronicity.cluster.example.").unwrap();
    // Sign once: changing the signature on every response would change the
    // cache key and conceal the failure being tested.
    let mut answers = ladder.apex.signed_txt(
        owner.clone(),
        &records[0],
        time::OffsetDateTime::now_utc() - time::Duration::hours(1),
    );
    for link in ladder.chain().links.iter().skip(1) {
        let mut decoder = BinDecoder::new(&link.rrs);
        while !decoder.is_empty() {
            answers.push(Record::read(&mut decoder).unwrap());
        }
    }
    let answers = Arc::new(answers);
    // 0: root key fetch fails; 1: healthy chain; 2: unsigned TXT substitution.
    let phase = Arc::new(AtomicU8::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/dns-query", listener.local_addr().unwrap());
    let server_phase = phase.clone();
    let server = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let answers = answers.clone();
            let phase = server_phase.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0; 4096];
                let body = loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
                        let length: usize = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .unwrap()
                            .trim()
                            .parse()
                            .unwrap();
                        if raw.len() >= split + 4 + length {
                            break &raw[split + 4..split + 4 + length];
                        }
                    }
                };
                let request = Message::from_vec(body).unwrap();
                let query = request.queries[0].clone();
                let phase = phase.load(Ordering::SeqCst);
                if phase == 0 && query.name().is_root() && query.query_type() == RecordType::DNSKEY
                {
                    stream
                        .write_all(b"HTTP/1.1 503 Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                        .await
                        .unwrap();
                    return;
                }
                let mut response = request.into_response();
                for record in answers.iter().filter(|record| {
                    record.name == *query.name()
                        && (record.record_type() == query.query_type()
                            || matches!(&record.data, RData::DNSSEC(DNSSECRData::RRSIG(sig))
                                if sig.input().type_covered == query.query_type()))
                }) {
                    let record = if phase == 2 && record.record_type() == RecordType::TXT {
                        Record::from_rdata(
                            record.name.clone(),
                            record.ttl,
                            RData::TXT(TXT::new(vec!["unsigned replacement".to_string()])),
                        )
                    } else {
                        record.clone()
                    };
                    response.add_answer(record);
                }
                let body = response.to_vec().unwrap();
                stream
                    .write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len()).as_bytes())
                    .await
                    .unwrap();
                stream.write_all(&body).await.unwrap();
            });
        }
    });
    let config = options(url, anchor.path());
    let resolver = DnssecResolver::with_options(&config).unwrap();
    resolver
        .lookup_txt_ungated("cluster.example")
        .await
        .expect_err("the chain cannot validate while the root key is unavailable");
    phase.store(1, Ordering::SeqCst);
    DnssecResolver::with_options(&config)
        .unwrap()
        .lookup_txt_ungated("cluster.example")
        .await
        .expect("a fresh resolver proves that the endpoint has recovered");
    resolver
        .lookup_txt_ungated("cluster.example")
        .await
        .expect_err("the failed validation is briefly cached");
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    let recovered = resolver
        .lookup_txt_ungated("cluster.example")
        .await
        .expect("a transient failure must expire before the records' 300-second TTL");
    assert_eq!(recovered.records, records);
    phase.store(2, Ordering::SeqCst);
    resolver
        .lookup_txt_ungated("cluster.example")
        .await
        .expect_err("recovery must still reject an unsigned substitution");
    server.abort();
}
