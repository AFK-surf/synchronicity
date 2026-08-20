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

/// Skips when the e2e environment is absent; run via e2e/run.sh.
fn e2e_env() -> Option<(String, String, String)> {
    Some((env("CP_DOH_URL")?, env("CP_ANCHOR_FILE")?, env("CP_DOMAIN")?))
}

/// A resolver against the control plane's zone, with or without the log gate.
fn test_resolver(doh_url: String, anchor: String, rekor: Option<RekorPolicy>) -> DnssecResolver {
    DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(doh_url),
        trust_anchor: Some(anchor.into()),
        rekor,
        rekor_key: None,
        rekor_state: None,
        tuf_url: None,
        // An e2e run never needs Sigstore's CDN: the refusal the second test
        // asserts is about this zone's missing proof, and nothing about the
        // pin set can change it.
        no_tuf: true,
        tuf_root: None,
    })
    .expect("resolver construction")
}

/// Installs the rustls provider: `DnssecResolver` builds a reqwest client
/// that panics without one, and this crate has no `main` or `sim` feature
/// to reach the install paths `synch_net::tls` describes.
fn install_provider() {
    synch_net::tls::install_crypto_provider();
}

#[tokio::test]
async fn control_plane_zone_validates_and_parses() {
    install_provider();
    let Some((doh_url, anchor, domain)) = e2e_env() else {
        eprintln!("CP_DOH_URL not set; skipping (run via e2e/run.sh)");
        return;
    };
    // DNSSEC-only coverage here: the zone-key transparency path has its own
    // suite, and this zone logs nothing — its silence is the next test's
    // subject.
    let resolver = test_resolver(doh_url, anchor, Some(RekorPolicy::Off));

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
    for (key, present) in [
        (env("CP_NAS_ACTIVE"), true),
        (env("CP_LAPTOP_ACTIVE"), true),
        (env("CP_LAPTOP_RETIRING"), true),
        (env("CP_NAS_REVOKED"), false),
    ] {
        if let Some(key) = key {
            assert_eq!(ids.iter().any(|(_, k)| k == &key), present, "{key}: {ids:?}");
        }
    }

    // TTL is the zone's 300s, inside the client clamp window.
    assert!(ttl.as_secs() >= 60 && ttl.as_secs() <= 86_400);

    // A domain that does not exist must fail closed (validated NXDOMAIN),
    // not hang or fall open.
    let missing = resolver.member_set(&format!("nope.{domain}")).await;
    assert!(missing.is_err(), "nonexistent domain must not resolve");
}

/// Every node of the control plane's fleet is named at the apex, and the
/// client returns all of them.
///
/// The two halves of this are written in different languages: the control
/// plane renders one `v=synccp1 url=` record per `CP_ENDPOINTS` entry
/// (plus its own `CP_PUBLIC_URL`), and the daemon opens a tunnel to each
/// endpoint this parses out. A disagreement about the shape would look like
/// a fleet where only one node is ever attached — which is exactly the
/// failure the record exists to prevent, and it would show up nowhere else.
#[tokio::test]
async fn the_fleets_attach_endpoints_cross_validate() {
    install_provider();
    let Some((doh_url, anchor, domain)) = e2e_env() else {
        eprintln!("CP_DOH_URL not set; skipping (run via e2e/run.sh)");
        return;
    };
    let Some(expected) = env("CP_EXPECTED_ENDPOINTS") else {
        eprintln!("CP_EXPECTED_ENDPOINTS not set; skipping (run via e2e/run.sh)");
        return;
    };
    // Gate off for the same reason as the membership test above: this zone
    // logs nothing, and the transparency path has its own suite.
    let resolver = test_resolver(doh_url, anchor, Some(RekorPolicy::Off));
    let (records, _ttl) = resolver.control_plane(&domain).await.expect(
        "the apex's attach records must validate and parse — a failure here          is the control plane and the client disagreeing about the record",
    );
    let mut got: Vec<String> = records.into_iter().map(|r| r.url).collect();
    got.sort();
    let mut want: Vec<String> = expected.split(',').map(|s| s.trim().to_string()).collect();
    want.sort();
    assert_eq!(got, want, "every node the primary named must come back");
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
    install_provider();
    let Some((doh_url, anchor, domain)) = e2e_env() else {
        eprintln!("CP_DOH_URL not set; skipping (run via e2e/run.sh)");
        return;
    };
    // No `rekor` field at all: `require` is the default everywhere.
    let resolver = test_resolver(doh_url, anchor, None);

    let error = resolver
        .member_set(&domain)
        .await
        .expect_err("a zone with no proof record must not resolve by default");
    eprintln!("ok: unlogged zone refused under the default policy: {error}");

    // And the ungated TXT lookup still works — it is the member-set path that
    // gained a requirement, not every query the resolver makes.
    resolver
        .lookup_txt_ungated(&domain)
        .await
        .expect("the TXT lookup itself never consults the log");
}
