//! The classifier, over the same real published entry the client verifier is
//! asserted against.
//!
//! One fixture, both halves of the invariant. `synch-net`'s
//! `tests/fixtures/rekor_v3` holds a genuine `hashedrekord` entry from
//! `log2025-1.rekor.sigstore.dev` (see its PROVENANCE.txt); over there the
//! client verifier accepts it end to end, and here the monitor classifies the
//! very same bytes. A client-accepted entry must land in tier A and never in
//! the silent bin — that property is exercised exhaustively over synthetic
//! shapes in `tiers.rs`, and pinned to reality here.
//!
//! It lands in **tier A**: the chain in its certificate verifies to the
//! anchor that zone is under, and covers the key the certificate carries. It
//! is therefore an authorization, and a monitor watching that apex reports it
//! the first time it sees it.
//!
//! The entry **predates the removal of the succession countersignature** and
//! still carries that extension. Nothing reads it any more, and these tests
//! are part of the evidence that nothing has to: the fixture's bytes are
//! immutable, and they classify correctly with no code left that knows what
//! `2.25.1138370866` was.

use hickory_resolver::proto::dnssec::TrustAnchors;
use synch_monitor::classify::{classify, KnownKeys, Tier};
use synch_net::rekor::HashedRekordBody;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../synch-net/tests/fixtures/rekor_v3")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

const APEX: &str = "zone-key-transparency.demo.invalid";
const LOG_INDEX: u64 = 67_966_366;

/// The zone is its own trust anchor: we own no DNSSEC-signed domain, so the
/// chain in the certificate terminates at the apex rather than at the ICANN
/// root. A public monitor rooted at ICANN would file this entry tier C — the
/// honest verdict, since nothing outside that private universe can tell
/// whether the key was delegated. Supplying the apex as the anchor is what a
/// `--dnssec-anchor` operator's own monitor would do.
fn anchors() -> (tempfile::TempDir, TrustAnchors) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("anchor.key");
    std::fs::write(&path, fixture("anchor.txt")).expect("write anchor");
    let anchors = TrustAnchors::from_file(&path).expect("the shipped anchor must parse");
    (dir, anchors)
}

#[test]
fn the_real_published_entry_classifies_tier_a() {
    let body = HashedRekordBody::parse(&fixture("canonicalized_body.json"))
        .expect("a real entry body must parse");
    let (_dir, anchors) = anchors();

    let finding = classify(&body, LOG_INDEX, &anchors)
        .expect("an entry with a P-256 key and a SAN is classifiable");

    assert_eq!(finding.tier, Tier::A, "{}", finding.line());
    assert_eq!(finding.apex, format!("{APEX}."));
    assert_eq!(finding.log_index, LOG_INDEX);
    assert_eq!(finding.key_tag, 27337);

    // The chain validated and covers this key, which is the whole verdict.
    assert!(
        finding.reasons.iter().any(|r| r.contains("chain valid")),
        "{:?}",
        finding.reasons
    );

    // Everything it says about the key it derived from the certificate's own
    // SubjectPublicKeyInfo — no DNS query anywhere, because the threat model
    // has a compromised DNS provider in it. The DS is the line a registrar
    // would show, so an operator can compare without believing the entry.
    assert!(
        finding.ds.starts_with("27337 13 2 "),
        "the derived DS: {}",
        finding.ds
    );
    assert_eq!(finding.spki_sha256.len(), 64);
}

/// The vestigial extension, asserted rather than assumed.
///
/// This entry's certificate carries `2.25.1138370866`, the succession
/// countersignature extension, and those bytes are in a public append-only
/// log forever. The claim that its removal needed no republish rests on one
/// property — the certificate parser looks extensions up by OID and never
/// refuses a certificate for carrying one it does not know — so that property
/// is checked here against the real bytes rather than reasoned about.
///
/// The extension is still *there*: if a future edit ever makes an unknown
/// extension fatal, this test names the entry it would break.
#[test]
fn the_retired_extension_is_still_in_the_certificate_and_still_ignored() {
    let body = HashedRekordBody::parse(&fixture("canonicalized_body.json"))
        .expect("the certificate parses despite carrying an extension nothing reads");

    // 2.25.1138370866, in DER content-byte form: 0x69 is 2.25 packed into the
    // first byte, then the arc in base-128 continuation form.
    const RETIRED_OID: &[u8] = &[0x69, 0x84, 0x9e, 0xe8, 0xd2, 0x32];
    assert!(
        body.certificate
            .extensions
            .iter()
            .any(|e| e.oid == RETIRED_OID),
        "the fixture is supposed to be the pre-removal entry; if this fails \
         the fixture was replaced and this test has nothing to prove"
    );

    // And it changes nothing: the same anchors, the same verdict as any
    // other well-formed entry for this zone.
    let (_dir, anchors) = anchors();
    let finding = classify(&body, LOG_INDEX, &anchors).expect("classifiable");
    assert_eq!(finding.tier, Tier::A);
}

/// Reporting, over real bytes: news once, then not again.
#[test]
fn the_real_entry_is_a_new_authorization_until_it_is_recorded() {
    let body = HashedRekordBody::parse(&fixture("canonicalized_body.json")).unwrap();
    let (_dir, anchors) = anchors();
    let finding = classify(&body, LOG_INDEX, &anchors).unwrap();
    assert_eq!(finding.tier, Tier::A);

    let apex = synch_net::chain::parse_name(APEX).unwrap();
    let mut known = KnownKeys::default();
    assert!(
        !known.contains(&apex, &body.certificate.spki),
        "a monitor that has never seen this key must report it"
    );
    known.insert(&apex, &body.certificate.spki);
    assert!(
        known.contains(&apex, &body.certificate.spki),
        "and must not report it a second time"
    );
}

/// And the invariant, at the one point where it touches real bytes: an entry
/// the client accepts is never silent.
#[test]
fn the_real_entry_is_never_in_the_silent_bin() {
    let body = HashedRekordBody::parse(&fixture("canonicalized_body.json")).unwrap();
    let (_dir, anchors) = anchors();
    let finding = classify(&body, LOG_INDEX, &anchors).unwrap();
    assert_ne!(
        finding.tier,
        Tier::C,
        "synch-net's suite verifies this same entry end to end, so classifying it \
         tier C would mean a key that works against clients and rings no bell"
    );
}
