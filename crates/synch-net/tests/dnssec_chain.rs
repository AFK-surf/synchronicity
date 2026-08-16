//! The DNSSEC chain validator, against a real delegation and a synthetic one.
//!
//! `synch_net::chain` is the one piece of this design that both halves of the
//! system run: the client refuses a proof whose chain does not validate, and
//! the monitor files an entry as noise for exactly the same reason. The
//! invariant that couples them — *client-accepted implies at least tier B* —
//! only holds because there is one implementation, so this suite tests it as
//! the shared thing it is rather than through either caller.

use hickory_resolver::proto::dnssec::TrustAnchors;
use synch_net::{
    chain::{self, ChainError},
    zonecert::{ChainLink, DnssecChain},
};

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dnssec_chain")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

/// A genuine delegation, validated offline against the ICANN root anchor.
///
/// This is the reality anchor for the chain half of the design: the bytes are
/// what 8.8.8.8 answered for `cloudflare.com` in August 2026 (see
/// PROVENANCE.txt), and nothing here authored the root's or Verisign's
/// signatures. It exercises RSASHA256 at the root, ECDSAP256SHA256 below it,
/// a two-level DS ladder, and hickory's RRSIG canonical form — the places a
/// hand-written validator quietly gets wrong.
#[test]
fn a_real_delegation_validates_against_the_icann_anchor() {
    let chain = DnssecChain::decode(&fixture("cloudflare-com.der")).expect("the fixture is a chain");
    assert_eq!(chain.links.len(), 3);
    assert_eq!(chain.links[0].zone, "cloudflare.com.");
    assert_eq!(chain.links[2].zone, ".");

    let dnskey = fixture("cloudflare-com-dnskey.bin");
    assert_eq!(chain::key_tag(&dnskey), 2371);

    let anchors = TrustAnchors::default();
    let valid = chain::validate(&chain, "cloudflare.com.", &dnskey, &anchors)
        .expect("a real delegation must validate");
    assert_eq!(valid.anchor_zone, ".");
    assert!(!valid.anchored_directly);
    // One RRSIG per RRset the walk needed: root DNSKEY, com DS, com DNSKEY,
    // cloudflare.com DS.
    assert_eq!(valid.windows.len(), 4);
    // The archival property, asserted without depending on how old the
    // fixture happens to be today: at a moment outside every window this
    // chain still validates, because the validator never consults a clock.
    // (The windows are reported, for a monitor's forensics, and that is all.)
    let long_after = valid
        .windows
        .iter()
        .map(|w| u64::from(w.expiration))
        .max()
        .expect("windows")
        + 365 * 86_400;
    assert!(valid.windows.iter().all(|w| !w.covers(long_after)));
    chain::validate(&chain, "cloudflare.com.", &dnskey, &anchors)
        .expect("an expired chain still validates: that is the point");

    // Case and the trailing dot are DNS spelling, not identity.
    chain::validate(&chain, "CloudFlare.com", &dnskey, &anchors).unwrap();
}

/// The same chain, asked about a key it says nothing about.
#[test]
fn a_real_delegation_does_not_cover_a_key_it_never_named() {
    let chain = DnssecChain::decode(&fixture("cloudflare-com.der")).unwrap();
    let anchors = TrustAnchors::default();
    let mut other = fixture("cloudflare-com-dnskey.bin");
    other[20] ^= 0x01;
    assert!(matches!(
        chain::validate(&chain, "cloudflare.com.", &other, &anchors),
        Err(ChainError::KeyNotCovered(_))
    ));

    // And it says nothing about a different zone, however well it validates.
    assert!(matches!(
        chain::validate(&chain, "example.com.", &fixture("cloudflare-com-dnskey.bin"), &anchors),
        Err(ChainError::Structure(_))
    ));
}

/// Every way a chain can be broken, one at a time.
#[test]
fn a_tampered_chain_is_refused_at_the_link_that_was_touched() {
    let anchors = TrustAnchors::default();
    let dnskey = fixture("cloudflare-com-dnskey.bin");
    let original = DnssecChain::decode(&fixture("cloudflare-com.der")).unwrap();

    // No links at all: absent, not malformed — the distinction is what
    // separates "this control plane has not upgraded" from "somebody
    // stripped the evidence out".
    assert_eq!(
        chain::validate(&DnssecChain::default(), "cloudflare.com.", &dnskey, &anchors),
        Err(ChainError::Absent)
    );

    // A byte flipped inside the root's DNSKEY RRSIG: the signature no longer
    // verifies, so the chain never reaches an anchored key.
    let mut broken = original.clone();
    let last = broken.links.len() - 1;
    let at = broken.links[last].rrs.len() - 20;
    broken.links[last].rrs[at] ^= 0x01;
    assert!(matches!(
        chain::validate(&broken, "cloudflare.com.", &dnskey, &anchors),
        Err(ChainError::Signature(_))
    ));

    // The root link removed: the top of what is left is `com.`, which no
    // trust anchor names.
    let mut headless = original.clone();
    headless.links.pop();
    assert!(matches!(
        chain::validate(&headless, "cloudflare.com.", &dnskey, &anchors),
        Err(ChainError::Anchor(_))
    ));

    // The middle link removed: `cloudflare.com.` is not a child of the root,
    // so the ladder does not connect even though both remaining links are
    // internally sound.
    let mut spliced = original.clone();
    spliced.links.remove(1);
    assert!(matches!(
        chain::validate(&spliced, "cloudflare.com.", &dnskey, &anchors),
        Err(ChainError::Structure(_))
    ));

    // A link whose records are not RRs at all.
    let mut garbled = original.clone();
    garbled.links[0].rrs = b"not a resource record".to_vec();
    assert!(matches!(
        chain::validate(&garbled, "cloudflare.com.", &dnskey, &anchors),
        Err(ChainError::Malformed(_)) | Err(ChainError::Structure(_))
    ));

    // An empty trust-anchor set trusts nothing, and says so as an anchor
    // failure rather than quietly succeeding.
    assert!(matches!(
        chain::validate(&original, "cloudflare.com.", &dnskey, &TrustAnchors::empty()),
        Err(ChainError::Anchor(_))
    ));
}

/// A link that carries records owned by another name is refused outright.
///
/// Without this the ladder check could be satisfied by a link whose *label*
/// says `com.` while its records are somebody else's zone.
#[test]
fn a_link_cannot_smuggle_another_zones_records() {
    let anchors = TrustAnchors::default();
    let dnskey = fixture("cloudflare-com-dnskey.bin");
    let original = DnssecChain::decode(&fixture("cloudflare-com.der")).unwrap();
    let mut relabelled = original.clone();
    relabelled.links[1] = ChainLink {
        zone: "example.com.".into(),
        rrs: original.links[1].rrs.clone(),
    };
    assert!(matches!(
        chain::validate(&relabelled, "cloudflare.com.", &dnskey, &anchors),
        Err(ChainError::Structure(_))
    ));
}
