//! The highest-value test in the control plane: the very validator every
//! deployed synchronicity cluster runs (hickory's DnssecDnsHandle inside
//! synch-net's DnssecResolver) resolves the membership domain against the
//! control plane's DoH endpoint, anchored at the control plane's key.
//!
//! Environment (exported by control-plane/e2e/run.sh):
//!   CP_DOH_URL      e.g. http://127.0.0.1:8053/dns-query
//!   CP_ANCHOR_FILE  trust-anchor file in --dnssec-anchor syntax
//!   CP_DOMAIN       membership domain, e.g. prod.acme.sync.test
//!   CP_NAS_ACTIVE / CP_NAS_REVOKED / CP_LAPTOP_ACTIVE / CP_LAPTOP_RETIRING
//!                   z-base-32 device keys the seeded zone published

use synch_core::OriginId;
use synch_net::dns::{DnssecResolver, RekorPolicy, ResolverOptions};

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
async fn control_plane_zone_validates_and_parses() {
    let Some(doh_url) = env("CP_DOH_URL") else {
        eprintln!("CP_DOH_URL not set; skipping (run via e2e/run.sh)");
        return;
    };
    let anchor = env("CP_ANCHOR_FILE").expect("CP_ANCHOR_FILE");
    let domain = env("CP_DOMAIN").expect("CP_DOMAIN");

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(doh_url),
        trust_anchor: Some(anchor.into()),
        // DNSSEC-only coverage here: the zone-key transparency path has its
        // own suite, and this zone logs nothing — `rekor-publish` needs a
        // real Rekor v2 endpoint, and an e2e that POSTed to the public log
        // on every run would be publishing throwaway keys forever. The leg
        // below asserts that this zone's silence is fail-closed rather than
        // tolerated.
        rekor: Some(RekorPolicy::Off),
        rekor_key: None,
        rekor_state: None,
        tuf_url: None,
        no_tuf: true,
        tuf_root: None,
    })
    .expect("resolver construction");

    let (set, ttl) = resolver.member_set(&domain).await.expect(
        "DNSSEC-validated member set — validation failing here means \
                 the control plane's signatures or negative proofs are wrong",
    );

    assert!(
        set.rejected.is_empty(),
        "no record may be rejected: {:?}",
        set.rejected
    );
    assert!(
        set.ambiguous_keys.is_empty(),
        "no key may be ambiguous: {:?}",
        set.ambiguous_keys
    );

    // Structure: nas has one key; laptop is mid-rotation with two.
    let mut ids: Vec<(String, String)> = set
        .bindings
        .iter()
        .map(|(origin, key)| {
            let OriginId::Named { id, domain: d } = origin else {
                panic!("expected named origins, got {origin:?}");
            };
            assert_eq!(d, &domain);
            (id.clone(), key.to_z32())
        })
        .collect();
    ids.sort();

    let count = |label: &str| ids.iter().filter(|(id, _)| id == label).count();
    assert_eq!(count("nas"), 1, "nas has exactly one live key: {ids:?}");
    assert_eq!(
        count("laptop"),
        2,
        "laptop is mid-rotation: two keys under one id: {ids:?}"
    );
    assert_eq!(set.bindings.len(), 3);

    // Exact key membership, when the seeder's keys are handed to us.
    let has_key = |z32: &str| ids.iter().any(|(_, k)| k == z32);
    if let Some(nas_active) = env("CP_NAS_ACTIVE") {
        assert!(has_key(&nas_active), "nas active key must be published");
    }
    if let Some(laptop_active) = env("CP_LAPTOP_ACTIVE") {
        assert!(has_key(&laptop_active));
    }
    if let Some(laptop_retiring) = env("CP_LAPTOP_RETIRING") {
        assert!(
            has_key(&laptop_retiring),
            "retiring key stays published through the rotation window"
        );
    }
    if let Some(revoked) = env("CP_NAS_REVOKED") {
        assert!(
            !has_key(&revoked),
            "revoked key must be gone from the RRset"
        );
    }

    // TTL is the zone's 300s, inside the client clamp window.
    assert!(ttl.as_secs() >= 60 && ttl.as_secs() <= 86_400);

    // A domain that does not exist must fail closed (validated NXDOMAIN),
    // not hang or fall open.
    let missing = resolver.member_set(&format!("nope.{domain}")).await;
    assert!(missing.is_err(), "nonexistent domain must not resolve");
}

/// The same zone, under the default policy: refused.
///
/// The e2e zone deliberately logs nothing, and "logs nothing" must mean "no
/// client resolves it" rather than "clients quietly carry on". This is the
/// §4.3 posture asserted against a real control plane rather than a
/// simulated one — the answer is discarded entirely and a caller keeps
/// whatever it had cached.
#[tokio::test]
async fn an_unlogged_zone_fails_closed_under_the_default_policy() {
    let Some(doh_url) = env("CP_DOH_URL") else {
        eprintln!("CP_DOH_URL not set; skipping (run via e2e/run.sh)");
        return;
    };
    let anchor = env("CP_ANCHOR_FILE").expect("CP_ANCHOR_FILE");
    let domain = env("CP_DOMAIN").expect("CP_DOMAIN");

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(doh_url),
        trust_anchor: Some(anchor.into()),
        // No `rekor` field at all: `require` is the default everywhere.
        rekor: None,
        rekor_key: None,
        rekor_state: None,
        tuf_url: None,
        // The refusal below is about this zone's missing proof record, and
        // nothing about the pin set can change it — so there is no reason
        // for an e2e run to reach Sigstore's CDN.
        no_tuf: true,
        tuf_root: None,
    })
    .expect("resolver construction");

    let error = resolver
        .member_set(&domain)
        .await
        .expect_err("a zone with no proof record must not resolve by default");
    eprintln!("ok: unlogged zone refused under the default policy: {error}");

    // And the ungated TXT lookup still works — it is the member-set path that
    // gained a requirement, not every query the resolver makes. Nothing may
    // decide anything from this answer, which is what the method's name says;
    // here it only shows the refusal above came from the gate and not from the
    // zone being unresolvable.
    resolver
        .lookup_txt_ungated(&domain)
        .await
        .expect("the TXT lookup itself never consults the log");
}
