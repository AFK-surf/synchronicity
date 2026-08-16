//! The classifier, over the same real published entry the client verifier is
//! asserted against.
//!
//! One fixture, both halves of the invariant. `synch-net`'s
//! `tests/fixtures/rekor_v3` holds a genuine `hashedrekord` entry from
//! `log2025-1.rekor.sigstore.dev` (see its PROVENANCE.txt); over there the
//! client verifier accepts it end to end, and here the monitor classifies the
//! very same bytes. A client-accepted entry must land in tier A or B and
//! never in the silent bin — that property is exercised exhaustively over
//! synthetic shapes in `tiers.rs`, and pinned to reality here.
//!
//! It lands in **tier B**, and that is the correct answer twice over: the
//! entry is a `rollover` whose predecessor key was not retained, so nobody
//! could have seeded it as known, and an uncountersigned rotation is exactly
//! the shape a monitor is supposed to make noise about.

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
const LOG_INDEX: u64 = 67_766_084;

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
fn the_real_published_entry_classifies_tier_b() {
    let body = HashedRekordBody::parse(&fixture("canonicalized_body.json"))
        .expect("a real entry body must parse");
    let (_dir, anchors) = anchors();

    let finding = classify(&body, LOG_INDEX, &KnownKeys::default(), &anchors, None)
        .expect("an entry with a P-256 key and a SAN is classifiable");

    assert_eq!(finding.tier, Tier::B, "{}", finding.line());
    assert_eq!(finding.apex, APEX);
    assert_eq!(finding.log_index, LOG_INDEX);
    assert_eq!(finding.key_tag, 1339);

    // The chain validated, and the countersignature named a predecessor this
    // monitor has never seen — which is precisely what tier B means.
    assert!(
        finding.reasons.iter().any(|r| r.contains("chain valid")),
        "{:?}",
        finding.reasons
    );
    assert_eq!(finding.predecessor_key_tag, Some(56306));
    assert!(
        finding
            .reasons
            .iter()
            .any(|r| r.contains("56306") && r.contains("not one this monitor knows")),
        "{:?}",
        finding.reasons
    );

    // Everything it says about the key it derived from the certificate's own
    // SubjectPublicKeyInfo — no DNS query anywhere, because the threat model
    // has a compromised DNS provider in it. The DS is the line a registrar
    // would show, so an operator can compare without believing the entry.
    assert!(
        finding.ds.starts_with("1339 13 2 "),
        "the derived DS: {}",
        finding.ds
    );
    assert_eq!(finding.spki_sha256.len(), 64);
}

/// With the predecessor seeded, the same bytes are a routine rotation.
///
/// This is the tier the operator of that zone would have seen, and it is the
/// half of the classifier that reality cannot demonstrate on its own: the
/// published entry's predecessor key was thrown away, so only a test can put
/// it back. The countersignature it verifies is real.
#[test]
fn the_same_entry_is_tier_a_once_its_predecessor_is_known() {
    let body = HashedRekordBody::parse(&fixture("canonicalized_body.json")).unwrap();
    let (_dir, anchors) = anchors();

    let succession = body
        .succession()
        .expect("the real certificate carries a succession extension")
        .expect("and it decodes");
    let mut known = KnownKeys::default();
    known.insert(APEX, &succession.predecessor_spki);

    let finding = classify(&body, LOG_INDEX, &known, &anchors, None).expect("classifiable");
    assert_eq!(finding.tier, Tier::A, "{}", finding.line());
    assert_eq!(finding.predecessor_key_tag, Some(56306));
}

/// And the invariant, at the one point where it touches real bytes: an entry
/// the client accepts is never silent.
#[test]
fn the_real_entry_is_never_in_the_silent_bin() {
    let body = HashedRekordBody::parse(&fixture("canonicalized_body.json")).unwrap();
    let (_dir, anchors) = anchors();
    let finding = classify(&body, LOG_INDEX, &KnownKeys::default(), &anchors, None).unwrap();
    assert_ne!(
        finding.tier,
        Tier::C,
        "synch-net's suite verifies this same entry end to end, so classifying it \
         tier C would mean a key that works against clients and rings no bell"
    );
}
