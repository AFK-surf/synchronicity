//! DNSSEC end to end, against a simulated signed zone (§3.2).
//!
//! The sim serves a zone over plaintext DoH whose signing key the test
//! installs as the entire root of trust, so the real validation path runs —
//! TXT, RRSIG, DNSKEY, anchor — with no network and no real root. The
//! positive case proves the machinery accepts what it should; the two
//! negative cases prove the acceptance was the validator's doing.

use iroh_base::SecretKey;
use synch_net::{sim::SimZone, DnssecResolver, ResolverOptions};

fn anchor_file(record: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), record).unwrap();
    file
}

#[tokio::test]
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
    let anchor = anchor_file(&zone.anchor_record());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: None,
        rekor_key: None,
    })
    .unwrap();

    let validated = resolver.lookup_txt("cluster.example").await.unwrap();
    assert_eq!(validated.records.len(), 2, "{validated:?}");
    assert_eq!(validated.ttl.as_secs(), 300);

    let (set, _ttl) = resolver.member_set("cluster.example").await.unwrap();
    assert_eq!(set.bindings.len(), 2, "{set:?}");
    assert!(set
        .bindings
        .iter()
        .any(|(origin, key)| origin.canonical() == "nas@cluster.example" && *key == nas));
    server.abort();
}

#[tokio::test]
async fn a_zone_signed_by_an_unanchored_key_is_refused() {
    let nas = SecretKey::generate().public();
    let zone = SimZone::new(
        "cluster.example",
        vec![format!("v=sync1 id=nas nk={}", nas.to_z32())],
    );
    // The anchor names a different zone's key: correctly signed answers from
    // a root we never trusted must validate exactly as well as forgeries.
    let stranger = SimZone::new("cluster.example", Vec::new());
    let anchor = anchor_file(&stranger.anchor_record());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: None,
        rekor_key: None,
    })
    .unwrap();
    resolver
        .lookup_txt("cluster.example")
        .await
        .expect_err("an unanchored signer must not validate");
    server.abort();
}

#[tokio::test]
async fn an_unsigned_zone_is_refused() {
    let nas = SecretKey::generate().public();
    let mut zone = SimZone::new(
        "cluster.example",
        vec![format!("v=sync1 id=nas nk={}", nas.to_z32())],
    );
    zone.unsigned = true;
    let anchor = anchor_file(&zone.anchor_record());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: None,
        rekor_key: None,
    })
    .unwrap();
    resolver
        .lookup_txt("cluster.example")
        .await
        .expect_err("answers without signatures must not validate");
    server.abort();
}
