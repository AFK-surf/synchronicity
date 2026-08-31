//! The data plane and a customer node, end to end
//! (`docs/CLOUD-DATAPLANE.md` §2, §4.3, §5.3).
//!
//! Everything here is real except the control plane, which is a stub HTTP
//! server speaking `/dp/v1`: a real `Node` for the customer, a real hosted
//! tenant with its own database and endpoint, a real DNSSEC-signed membership
//! zone (`synch_net::sim`), and a real object store. What it proves is the
//! claim the product is sold on — **a file published on a hosted network ends
//! up durably in the tenant's own prefix, and stays there when the customer's
//! copy goes away**.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::Json;
use synch_core::OriginId;
use synch_dp::config::{slot_label, DpConfig};
use synch_dp::control::{ControlPlane, HostedDevice, HostedNetwork};
use synch_dp::store::ObjectStore;
use synch_dp::tenant::Tenant;
use synch_engine::{Node, NodeConfig};
use synch_net::sim::SimZone;
use synch_net::{DnssecResolver, RekorPolicy, ResolverOptions};

const APEX: &str = "prod.acme.example";
const ORG: &str = "acme";
const NETWORK: &str = "prod";

/// The stub control plane's whole state: what it has been told, and what it
/// will answer.
#[derive(Debug, Default)]
struct Cp {
    /// The key the data plane registered for the hosting slot, if any.
    registered: Option<String>,
    /// Heartbeats received.
    statuses: Vec<synch_dp::control::Status>,
    /// Networks this control plane says are due for collection.
    collect: Vec<synch_dp::control::Collectable>,
    /// Networks whose storage the data plane has reported deleted.
    collected: Vec<String>,
}

type Shared = Arc<Mutex<Cp>>;

/// Serves the four `/dp/v1` routes the data plane uses.
async fn control_plane(state: Shared) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new()
        .route(
            "/dp/v1/networks",
            get(|State(state): State<Shared>| async move {
                let cp = state.lock().expect("the stub's lock");
                Json(serde_json::json!({
                    "generation": 1,
                    "networks": [{
                        "org": ORG,
                        "network": NETWORK,
                        "domain": APEX,
                        "budget_bytes": 0,
                        "retention": "current",
                        "device": cp.registered.as_ref().map(|nk| HostedDevice {
                            label: slot_label(),
                            nk: nk.clone(),
                            state: "active".into(),
                        }),
                    }],
                    "collect": cp.collect,
                }))
            }),
        )
        .route(
            "/dp/v1/networks/{org}/{network}/device",
            put(
                |State(state): State<Shared>,
                 Path((_org, _network)): Path<(String, String)>,
                 Json(body): Json<serde_json::Value>| async move {
                    let nk = body["nk"].as_str().unwrap_or_default().to_string();
                    state.lock().expect("the stub's lock").registered = Some(nk);
                    Json(serde_json::json!({"ok": true}))
                },
            ),
        )
        .route(
            "/dp/v1/networks/{org}/{network}/status",
            post(
                |State(state): State<Shared>,
                 Path((_org, _network)): Path<(String, String)>,
                 Json(status): Json<synch_dp::control::Status>| async move {
                    state.lock().expect("the stub's lock").statuses.push(status);
                    Json(serde_json::json!({"ok": true}))
                },
            ),
        )
        .route(
            "/dp/v1/networks/{org}/{network}/storage",
            axum::routing::delete(
                |State(state): State<Shared>,
                 Path((org, network)): Path<(String, String)>| async move {
                    let mut cp = state.lock().expect("the stub's lock");
                    cp.collected.push(format!("{org}/{network}"));
                    cp.collect.clear();
                    Json(serde_json::json!({"ok": true}))
                },
            ),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .expect("a loopback port");
    let addr = listener.local_addr().expect("the bound address");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// The resolver options for a simulated signed zone naming these members.
///
/// Returned rather than only the built resolver, because a tenant's node
/// builds its *own* resolver from these at open — that is where identity
/// settles.
async fn zone(
    records: Vec<String>,
) -> (
    ResolverOptions,
    Arc<DnssecResolver>,
    tokio::task::JoinHandle<()>,
) {
    let zone = SimZone::new(APEX, records);
    let anchor = tempfile::NamedTempFile::new().expect("a temp anchor file");
    std::fs::write(anchor.path(), zone.anchor_record()).expect("writing the anchor");
    let (url, server) = zone.serve().await;
    let options = ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        // The zone-key transparency path has its own suite; this zone logs
        // nothing, and membership is what is under test here.
        rekor: Some(RekorPolicy::Off),
        rekor_key: None,
        rekor_state: None,
        rekor_config: None,
        tuf_url: None,
        no_tuf: true,
        tuf_root: None,
    };
    let resolver = DnssecResolver::with_options(&options).expect("the resolver");
    // The anchor file must outlive every resolver built from these options.
    std::mem::forget(anchor);
    (options, Arc::new(resolver), server)
}

/// Polls until `check` passes, or fails the test.
async fn until(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..600 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hosted_tenant_durably_replicates_what_a_customer_publishes() {
    let _blocking = synch_core::BlockingScope::enter();
    let base = tempfile::tempdir().expect("a base dir");
    let objects = ObjectStore::memory_sealed().expect("the object store");
    let cp_state: Shared = Arc::default();
    let (cp_url, cp_server) = control_plane(cp_state.clone()).await;
    let control = ControlPlane::new(&cp_url, "synchdp_test").expect("the client");

    let mut config = DpConfig::for_test(base.path(), &cp_url);
    config.net = synch_net::NetOptions::loopback();

    let network = HostedNetwork {
        org: ORG.into(),
        network: NETWORK.into(),
        domain: APEX.into(),
        budget_bytes: 0,
        retention: "current".into(),
        device: None,
    };

    // ---- the customer's node -------------------------------------------
    let customer_dir = tempfile::tempdir().expect("the customer's dir");
    let customer_origin = OriginId::named("nas", APEX).expect("a named origin");
    {
        let dir = customer_dir.path().to_path_buf();
        let origin = customer_origin.clone();
        synch_core::offload(move || Node::init_named_by_zone(&dir, origin))
            .await
            .expect("the customer initializes");
    }
    let customer = Node::open(NodeConfig::loopback(customer_dir.path()))
        .await
        .expect("the customer opens");

    // ---- the tenant's identity, then the zone that names it ------------
    // The real order, and the reason it is this order: the tenant generates a
    // key and registers it, and only then can a zone name it. Until it does,
    // opening the node is refused — which is the `Identifying` state §4.3
    // parks in, exercised here rather than described.
    let tenant_dir = config.tenant_dir(ORG, NETWORK);
    {
        let dir = tenant_dir.clone();
        let domain = APEX.to_string();
        synch_core::offload(move || Node::init(&dir, Some(&domain)))
            .await
            .expect("the tenant initializes");
    }
    let tenant_key = {
        let dir = tenant_dir.clone();
        synch_core::offload(move || {
            let store = synch_store::Store::open(&dir)?;
            store.active_device_key()
        })
        .await
        .expect("reading the tenant's key")
        .expect("an active key")
        .node_id
    };

    let (dns, resolver, zone_server) = zone(vec![
        format!("v=sync1 id=nas nk={}", customer.node_id().to_z32()),
        format!("v=sync1 id={} nk={}", slot_label(), tenant_key.to_z32()),
    ])
    .await;
    config.dns = dns;

    // ---- provision the tenant ------------------------------------------
    // `provision` restores nothing, finds the directory already initialized
    // (the crash-between-init-and-register path), registers the key it holds,
    // and opens.
    let mut tenant = Tenant::provision(
        &config,
        &objects,
        &control,
        Some(resolver.clone()),
        network.clone(),
    )
    .await
    .expect("the tenant provisions");
    assert_eq!(
        cp_state.lock().unwrap().registered.as_deref(),
        Some(tenant_key.to_z32().as_str()),
        "the tenant registers the key it actually holds"
    );

    // ---- membership, both ways -----------------------------------------
    customer.set_domain(APEX).expect("the customer's domain");
    customer
        .refresh_domains_named(resolver.as_ref(), Some(APEX))
        .await
        .expect("the customer resolves the zone");
    tenant
        .node()
        .expect("the tenant is open")
        .refresh_domains_named(resolver.as_ref(), Some(APEX))
        .await
        .expect("the tenant resolves the zone");

    // Loopback endpoints publish no discoverable address, so each side is
    // told where the other is. On a real network this is iroh's business.
    let hosted = tenant.node().expect("the tenant is open").clone();
    customer
        .remember_peer(&hosted.net().direct_addr())
        .expect("the customer learns the tenant's address");
    hosted
        .remember_peer(&customer.net().direct_addr())
        .expect("the tenant learns the customer's address");

    // ---- the customer publishes a file ---------------------------------
    let space = tempfile::tempdir().expect("the customer's space");
    std::fs::write(space.path().join("report.txt"), b"the only copy").expect("writing the file");
    customer
        .add_filesystem_source("media", space.path())
        .expect("the source");
    let (_, head) = customer.scan_and_publish().expect("the publish");
    assert!(head.is_some(), "the customer published a head");
    let root = {
        let entries = customer
            .store()
            .list_entries(Some(customer.origin()), "media", "", None, None)
            .expect("the entries");
        let entry = entries.first().expect("one published entry");
        entry.content.expect("the entry names content")
    };

    // ---- the tenant converges ------------------------------------------
    // Anti-entropy pulls the customer's trie, `ensure_replicas` adds a replica
    // for the space it finds there, and the replica sweep acquires the root.
    hosted
        .sync_with_peer(&customer.node_id())
        .await
        .expect("one anti-entropy round with the customer");
    tenant
        .converge(&network, &config, &control)
        .await
        .expect("the tenant converges");

    let held = hosted.clone();
    until("the hosted tenant to hold the customer's file", || {
        let node = held.clone();
        // Sweep and fetch on each poll: the standing loops run on their own
        // schedule, and the test drives the same steps directly.
        futures_lite_block(async move {
            let sweep = node.clone();
            let _ = synch_core::offload(move || sweep.sweep_replicas(None)).await;
            let _ = node.fetch_content_wants().await;
            node.store()
                .blob(&root)
                .ok()
                .flatten()
                .is_some_and(|row| row.durable)
        })
    })
    .await;

    // ---- the claim: it is durable in the tenant's own store ------------
    // `durable` is set by one path only — `Cloud::finalize`, after the
    // payload *and* its bao outboard have been written to the object store
    // and acked (`docs/SERVERLESS.md` §4). So this row is the node's record
    // that the bytes are in its own prefix, not merely cached locally.
    //
    // It is asserted through the node rather than by listing the bucket
    // because OpenDAL's memory service gives every operator its own map: the
    // tenant's CAS operator is not the one this test holds. The database
    // stream below *is* shared, and is listed directly.
    let row = {
        let node = hosted.clone();
        synch_core::offload(move || node.store().blob(&root))
            .await
            .expect("the blob row")
            .expect("the tenant holds the object")
    };
    assert!(
        row.durable,
        "the hosted copy should be durable in the bucket"
    );
    assert!(row.complete, "and complete");

    // ---- and it survives the customer losing its copy ------------------
    // The last-copy case the service exists for (§5.3). The customer's node
    // goes away entirely; the bytes are still in the bucket, and the hosted
    // node still reads them.
    customer.shutdown().await.expect("the customer shuts down");
    drop(customer_dir);
    let read = hosted
        .read_range(
            "media",
            "report.txt",
            &synch_engine::VersionPolicy::default(),
            0,
            None,
        )
        .await
        .expect("the hosted replica still serves the bytes");
    assert_eq!(&read[..], b"the only copy");

    // ---- the database replica stream is real ---------------------------
    let generations = objects
        .list_dirs(&format!("db/{ORG}/{NETWORK}/"))
        .await
        .expect("listing the replica stream");
    assert!(
        !generations.is_empty(),
        "the tenant's database should be replicated to the bucket"
    );

    tenant.drain().await;
    hosted_teardown(cp_server, zone_server);
}

/// Runs a future to completion on the current thread.
///
/// The polling helper above is synchronous by design — it is a `FnMut` the
/// loop calls — and each probe does real async work.
fn futures_lite_block<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
}

fn hosted_teardown(cp: tokio::task::JoinHandle<()>, zone: tokio::task::JoinHandle<()>) {
    cp.abort();
    zone.abort();
}
