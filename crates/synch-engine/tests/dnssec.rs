//! DNSSEC membership end to end: a simulated signed zone, the real resolver,
//! and a real node adopting what validates (§3.2).
//!
//! This is the full production path with only the world faked: the zone is
//! served over plaintext DoH by `synch_net::sim`, its key anchored as the
//! whole root of trust, and the node's ordinary refresh turns the validated
//! records into live bindings — then keeps them when the resolver goes away,
//! because a resolver outage must never shrink the member set.

use iroh_base::SecretKey;
use synch_core::OriginId;
use synch_engine::{Node, NodeConfig};
use synch_net::{sim::SimZone, DnssecResolver, RekorPolicy, ResolverOptions};

#[tokio::test]
async fn validated_records_become_bindings_and_outages_keep_them() {
    let data = tempfile::tempdir().unwrap();
    Node::init(
        data.path(),
        Some(OriginId::named("laptop", "cluster.example").unwrap()),
    )
    .unwrap();
    let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();

    let nas = SecretKey::generate().public();
    let zone = SimZone::new(
        "cluster.example",
        vec![format!("v=sync1 id=nas nk={}", nas.to_z32())],
    );
    let anchor = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(anchor.path(), zone.anchor_record()).unwrap();
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
        tuf_root: None,
    })
    .unwrap();

    node.add_domain("cluster.example").unwrap();
    let outcomes = node
        .refresh_domains_named(&resolver, Some("cluster.example"))
        .await
        .unwrap();
    assert_eq!(outcomes.len(), 1);
    let refresh = outcomes[0].result.as_ref().expect("a validated refresh");
    assert_eq!(refresh.bindings, 1, "{refresh:?}");

    let origin = OriginId::named("nas", "cluster.example").unwrap();
    let now = synch_core::now_ns();
    assert!(node.store().is_bound(&origin, &nas, now).unwrap());
    let health = node.domain_health().unwrap();
    assert_eq!(health[0].bindings, 1, "{health:?}");
    assert!(health[0].schedule.as_ref().unwrap().last_success > 0);

    // The zone goes dark; the refresh reports the failure and the binding
    // stays exactly as cached. Fail closed means the member set shrinks by
    // expiry, never by outage.
    server.abort();
    let outcomes = node
        .refresh_domains_named(&resolver, Some("cluster.example"))
        .await
        .unwrap();
    assert!(outcomes[0].result.is_err(), "{outcomes:?}");
    assert!(node.store().is_bound(&origin, &nas, now).unwrap());
    let health = node.domain_health().unwrap();
    assert!(health[0].schedule.as_ref().unwrap().last_error.is_some());

    node.shutdown().await.unwrap();
}
