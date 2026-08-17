//! DNSSEC end to end, against a simulated signed zone (§3.2).
//!
//! The sim serves a zone over plaintext DoH whose signing key the test
//! installs as the entire root of trust, so the real validation path runs —
//! TXT, RRSIG, DNSKEY, anchor — with no network and no real root. The
//! positive case proves the machinery accepts what it should; the two
//! negative cases prove the acceptance was the validator's doing.

use iroh_base::SecretKey;
use synch_net::{sim::SimZone, DnssecResolver, RekorPolicy, ResolverOptions};

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
        // DNSSEC-only coverage: the zone-key transparency path has its own
        // suite, and this zone logs nothing.
        rekor: Some(RekorPolicy::Off),
        rekor_key: None,
        rekor_state: None,
        tuf_url: None,
        // Nothing in this suite exercises pin refresh, and no test run
        // reaches Sigstore by accident.
        no_tuf: true,
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
        // DNSSEC-only coverage: the zone-key transparency path has its own
        // suite, and this zone logs nothing.
        rekor: Some(RekorPolicy::Off),
        rekor_key: None,
        rekor_state: None,
        tuf_url: None,
        // Nothing in this suite exercises pin refresh, and no test run
        // reaches Sigstore by accident.
        no_tuf: true,
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
        // DNSSEC-only coverage: the zone-key transparency path has its own
        // suite, and this zone logs nothing.
        rekor: Some(RekorPolicy::Off),
        rekor_key: None,
        rekor_state: None,
        tuf_url: None,
        // Nothing in this suite exercises pin refresh, and no test run
        // reaches Sigstore by accident.
        no_tuf: true,
    })
    .unwrap();
    resolver
        .lookup_txt("cluster.example")
        .await
        .expect_err("answers without signatures must not validate");
    server.abort();
}

/// The forgery the owner-name filter does **not** catch, refused.
///
/// An RRSIG is a signature over an RRset; nothing about producing one
/// requires the signer to own the name. So anybody holding a DNSSEC-signed
/// zone that chains to the reader's anchor can sign an RRset owned by
/// *somebody else's* name, and hickory will happily validate it: RFC 4035
/// §5.3.1 ("the Signer's Name field MUST be the name of the zone that
/// contains the RRset") is skipped there in two places, both marked TODO.
///
/// `Proof::Secure` therefore means "some anchored key signed this", not "the
/// zone that owns this name signed it", and the gap is a total membership
/// forgery: a forged `(origin, device key)` binding is full cluster read and
/// write (§3.2). `secure_txt` closes it, and this is the test that says so.
///
/// The suite could not have caught this before: every other negative case
/// gives the impostor the *same* name as the victim, so "a validly anchored
/// zone with a **different** name signs for our name" went unexercised.
#[tokio::test]
async fn a_zone_may_not_sign_for_a_name_it_does_not_contain() {
    use hickory_resolver::proto::rr::Name;

    let attacker_key = SecretKey::generate().public();
    // A real zone, with a real key, that the reader really does anchor —
    // everything about `attacker.example` validates. It simply is not
    // `cluster.example`, and that is the only thing wrong with the answer.
    let mut attacker = SimZone::new("attacker.example", Vec::new());
    attacker.impersonate = Some((
        Name::from_utf8("_synchronicity.cluster.example.").unwrap(),
        vec![format!(
            "v=sync1 id=nas nk={} apex=cluster.example",
            attacker_key.to_z32()
        )],
    ));
    let anchor = anchor_file(&attacker.anchor_record());
    let (url, server) = attacker.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        // `off` on purpose: under `require` the apex sandwich in `apex_of`
        // happens to block this too, which is what hid the hole. The signer
        // rule has to stand on its own, so it is tested where nothing else
        // is holding the door.
        rekor: Some(RekorPolicy::Off),
        rekor_key: None,
        rekor_state: None,
        tuf_url: None,
        no_tuf: true,
    })
    .unwrap();

    let error = resolver
        .lookup_txt("cluster.example")
        .await
        .expect_err("a sibling zone must not sign for this name");
    assert!(
        error.to_string().contains("does not contain"),
        "refused for the wrong reason: {error}"
    );
    // And the same through the membership path, which is what an attacker
    // is actually after.
    resolver
        .member_set("cluster.example")
        .await
        .expect_err("a forged membership answer must not bind anything");
    server.abort();
}
