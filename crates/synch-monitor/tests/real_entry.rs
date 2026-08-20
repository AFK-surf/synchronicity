//! The classifier, over the same real published entry the client verifier is
//! asserted against: `synch-net`'s `tests/fixtures/rekor_v3` holds a genuine
//! `hashedrekord` entry from `log2025-1.rekor.sigstore.dev`, accepted end to
//! end there — the anchor that keeps the synthetic `tiers.rs` matrix honest.

use hickory_resolver::proto::dnssec::TrustAnchors;
use synch_monitor::classify::{classify, Tier};
use synch_net::rekor::HashedRekordBody;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../synch-net/tests/fixtures/rekor_v3")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

const APEX: &str = "zone-key-transparency.demo.invalid";
const LOG_INDEX: u64 = 68_295_246;

/// The zone is its own trust anchor: we own no DNSSEC-signed domain, so the
/// chain terminates at the apex (a monitor rooted at ICANN would file this
/// tier B — the honest verdict for that population).
fn anchors() -> (tempfile::TempDir, TrustAnchors) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("anchor.key");
    std::fs::write(&path, fixture("anchor.txt")).expect("write anchor");
    let anchors = TrustAnchors::from_file(&path).expect("the shipped anchor must parse");
    (dir, anchors)
}

/// The real published entry classifies tier A, with the exact key tag and DS,
/// and the reported line carries everything an operator acts on.
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
    assert!(finding.reasons.iter().any(|r| r.contains("chain valid")));
    let [key] = finding.keys.as_slice() else {
        panic!("a one-key zone proves one key: {:?}", finding.keys);
    };
    assert_eq!(key.key_tag, 32784);
    assert_eq!(key.sha256.len(), 64);
    // The DS is the line a registrar would show, comparable without belief.
    assert!(key.ds.starts_with("32784 13 2 "));
    let line = finding.line();
    assert!(line.starts_with(&format!("[A] index {LOG_INDEX} apex {APEX}.")));
    assert!(line.contains(&key.ds) && line.contains(&key.sha256));
}
