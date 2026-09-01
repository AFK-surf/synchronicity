//! What one hosted tenant costs when it serves a replica for ten thousand
//! nodes.
//!
//! `docs/CLOUD-DATAPLANE.md` §7.1 sizes a *tenant* — the per-network cost a
//! shard pays, ending at "memory: O(trie working set + cache index)" — and then
//! sizes a shard in tenants: "O(hundreds) of networks per shard". Neither
//! sizes the axis this measures. A tenant is one tenant whether the replica it
//! runs holds three origins or ten thousand, and several of the engine's
//! standing costs are per *node*, not per tenant: the binding table every
//! publish and every anti-entropy round reads, the maintenance pass that ages
//! it, the reactive push that dials the whole trusted set at once, the head and
//! entry rows a total replica accumulates for every origin it replicates, and
//! the provider walk a cold replica does per unresolved root.
//!
//! Those ten thousand nodes are not one network. A node resolves exactly one
//! membership zone (`Node::resolving_domains`: "one zone or none, never a set")
//! and that zone's members are a single TXT RRset, so they arrive across many
//! networks — a zone's worth named by DNS, the rest reaching this one as
//! delegations (§3.5). The harness models that spread rather than a single
//! implausible zone, and the first section measures where the zone's own
//! ceiling falls.
//!
//! Everything is measured on the real code paths against a real provisioned
//! tenant — the same [`Tenant::provision`] the reconciler calls, with a stub
//! control plane, a DNSSEC-signed zone, and an object store — rather than a
//! model of one. What is *not* real is how the state arrived: ten thousand iroh
//! endpoints do not fit on one machine, so bindings, heads and entries are
//! written through the store. That makes this a faithful measure of what
//! carrying the state costs and no measure at all of the sync that produces it.
//!
//! ```sh
//! cargo run --release -p synch-dp --example stress
//! cargo run --release -p synch-dp --example stress -- --members 10000 --networks 20
//! ```
//!
//! Release mode matters: ed25519 verification and BLAKE3 dominate several of
//! these numbers and are several times slower unoptimized, and §10's
//! `assert_off_runtime` abort is compiled out of release, which is what lets
//! the harness drive store work from `main`.
//!
//! Absolute numbers belong to the machine this ran on. What travels is the
//! *shape*: which costs are flat in the node count, which are linear, and which
//! are worse.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path as AxPath, State};
use axum::routing::{delete, get, put};
use axum::Json;
use iroh_base::SecretKey;
use synch_core::{now_ns, FileEntry, Hash, OriginId, SignedHead};
use synch_dp::config::{slot_label, DpConfig};
use synch_dp::control::{ControlPlane, HostedNetwork};
use synch_dp::tenant::Tenant;
use synch_engine::{Node, NodeConfig};
use synch_net::sim::SimZone;
use synch_net::{DnssecResolver, RekorPolicy, ResolverOptions};
use synch_store::{Binding, BindingSource, Slot};

/// The hosted network under test.
const APEX: &str = "prod.acme.example";
const ORG: &str = "acme";
const NETWORK: &str = "prod";

/// How many nodes the replica serves, by default.
const DEFAULT_MEMBERS: usize = 10_000;
/// How many distinct networks those nodes come from, by default.
///
/// Ten thousand nodes are not one network's membership. They arrive across
/// many — each its own zone, its own TXT RRset, its own TTL — and reach a
/// replica of any one of them through delegation (§3.5) rather than by being
/// named in its zone. The default spreads them 500 to a network, which the
/// zone probe below shows is about what one zone can carry.
const DEFAULT_NETWORKS: usize = 20;
/// How many published entries each member origin carries, by default.
///
/// Twenty is a deliberately small tree per member: the point of this harness is
/// the per-*member* cost, and a large per-member tree would drown it in the
/// per-file cost `synch-engine`'s own bench already measures.
const DEFAULT_ENTRIES: usize = 20;
/// How long the steady-state observation runs, in seconds.
const DEFAULT_STEADY_SECS: u64 = 30;
/// The per-zone membership sizes the zone probe walks.
///
/// Bounded well below `DEFAULT_MEMBERS`: what this probe is for is the size of
/// *one* network's zone, which is what decides how many networks ten thousand
/// nodes have to be spread across.
const ZONE_PROBE: &[usize] = &[100, 250, 500, 750, 1_000, 2_000];

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // The harness drives store work from `main`, which is a runtime worker.
    // Release builds compile §10's guard out; this keeps the debug build
    // honest rather than aborting.
    let _blocking = synch_core::BlockingScope::enter();
    // Silent unless `RUST_LOG` asks: the numbers below are the output, and the
    // engine's standing loops are chatty at `info`. It is wired up at all
    // because "which loop is that CPU in?" is the first question any surprising
    // number here raises, and `RUST_LOG=synch_engine=debug` answers it.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .init();
    let options = Options::parse();

    println!(
        "synch-dp stress — one hosted tenant serving a replica for {} nodes\n\
         across {} networks, {} published entries per node\n\
         host: {} logical CPUs\n",
        options.members,
        options.networks,
        options.entries,
        std::thread::available_parallelism().map_or(0, |n| n.get()),
    );

    let start = Meter::now();

    // ---- 1. the zone the membership has to fit in ----------------------
    zone_ceiling(&options).await;

    // ---- 2. a real tenant, provisioned the way the reconciler does -----
    let harness = Harness::provision().await;
    let baseline = Meter::now();
    section("a provisioned tenant, before any members");
    baseline
        .since(&start)
        .report("provision (1 tenant, 0 members)");

    // ---- 3. membership at scale ----------------------------------------
    let members = membership(&harness, &options).await;

    // ---- 4. what the reactive push costs at that membership ------------
    fanout(&harness, &members, &options).await;

    // ---- 5. what replicating every member's tree costs -----------------
    held_data(&harness, &members, &options).await;

    // ---- 6. the per-tick work the reconciler and the loops do ----------
    per_tick(&harness, &options).await;

    // ---- 7. steady state ------------------------------------------------
    steady(&harness, &options).await;

    section("totals");
    let end = Meter::now();
    end.since(&start).report("whole run");
    line("peak RSS", &format!("{:>12}", mib(end.peak_rss)));
    line(
        "tenant data directory",
        &format!("{:>12}", mib(dir_bytes(harness.tenant_dir()))),
    );
    line(
        "  of which the database",
        &format!("{:>12}", mib(db_bytes(harness.tenant_dir()))),
    );

    harness.shutdown().await;
}

// ---- 1. the zone ceiling ---------------------------------------------------

/// Finds how many members *one network's* zone can name.
///
/// One network's membership is one RRset — `_synchronicity.<domain> TXT`, one
/// `v=sync1` record per device (`synch_net::dns`) — fetched and
/// DNSSEC-validated whole on every `run_dns` refresh. A node resolves exactly
/// one such zone (`Node::resolving_domains`: "one zone or none, never a set"),
/// so this is not a ceiling on how many nodes a replica can serve. It is the
/// ceiling on how many arrive in any *one* network, and therefore the floor on
/// how many networks the rest have to be spread across — which is why it runs
/// first.
async fn zone_ceiling(_options: &Options) {
    section("one network's zone: how many members a single TXT RRset can name");

    // The probe is itself a member: a node whose membership domain is set
    // refuses to open until the zone names its own key, which is the
    // `Identifying` state §4.3 parks in. So its key is read first, and every
    // zone below names it alongside the synthetic members.
    let dir = tempfile::tempdir().expect("a probe dir");
    Node::init(dir.path(), Some(APEX)).expect("the probe node initializes");
    let probe_key = synch_store::Store::open(dir.path())
        .expect("the probe store")
        .active_device_key()
        .expect("the probe's key")
        .expect("an active key")
        .node_id;
    let probe_record = format!("v=sync1 id=probe nk={}", probe_key.to_z32());

    let (dns, _, bootstrap) = zone(vec![probe_record.clone()]).await;
    let node = Node::open(NodeConfig {
        dns,
        ..NodeConfig::loopback(dir.path())
    })
    .await
    .expect("the probe node opens");

    // A zone too large to sign fails inside the fixture's own server task, so
    // the probe silences the default hook for its duration: the failures below
    // are the *result*, not a bug, and a page of backtrace per probe would bury
    // the table. Restored before anything else runs.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut last_ok = 0usize;
    let mut first_bad = None;
    for &size in ZONE_PROBE {
        let probed = probe(&node, &probe_record, size).await;
        println!(
            "  {:<34} {:>12.2?}  {:>8} B of member TXT, {} bound",
            format!(
                "{size} members: {}",
                if probed.ok { "resolved" } else { "REFUSED" }
            ),
            probed.elapsed,
            probed.bytes,
            probed.bound,
        );
        // Resolving is not the claim; *binding every member named* is. A zone
        // whose answer came back truncated resolves perfectly well and installs
        // a fraction of the membership, which is the failure mode that would
        // otherwise pass for success here.
        if probed.ok && probed.bound >= size {
            last_ok = size;
        } else {
            first_bad = Some(size);
            break;
        }
    }

    // Bisect for the exact ceiling: "somewhere between 500 and 750" is not an
    // answer an operator can size a network against.
    if let Some(bad) = first_bad {
        let (mut lo, mut hi) = (last_ok, bad);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            let probed = probe(&node, &probe_record, mid).await;
            if probed.ok && probed.bound >= mid {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        last_ok = lo;
    }

    std::panic::set_hook(hook);

    println!(
        "\n  the largest membership one zone can name: {last_ok}\n\n\
           A node resolves one zone, and that zone's members are one RRset, so\n\
           this is how large a single *network* can get — not how many nodes a\n\
           replica can serve. Nodes past it belong to other networks and reach\n\
           this one as delegations (§3.5), which is what the membership below\n\
           models: a zone's worth named by DNS, the rest delegated.\n"
    );

    node.shutdown().await.expect("the probe node shuts down");
    bootstrap.abort();
}

/// What one zone probe found.
struct Probed {
    /// Whether the refresh returned at all.
    ok: bool,
    /// How long it took.
    elapsed: Duration,
    /// Bytes of member TXT the zone was carrying.
    bytes: usize,
    /// How many bindings the node ended up holding.
    bound: usize,
}

/// Serves a zone naming `size` members plus the probe, and asks the probe to
/// resolve it.
async fn probe(node: &Node, probe_record: &str, size: usize) -> Probed {
    let mut records: Vec<String> = vec![probe_record.to_string()];
    records.extend((0..size).map(|i| format!("v=sync1 id=node{i:05} nk={}", fake_key(i).to_z32())));
    let bytes: usize = records.iter().map(|r| r.len() + 1).sum();
    let (_, resolver, server) = zone(records).await;
    let started = Instant::now();
    let outcome = node
        .refresh_domains_named(resolver.as_ref(), Some(APEX))
        .await;
    let elapsed = started.elapsed();
    server.abort();
    Probed {
        ok: outcome.is_ok(),
        elapsed,
        bytes,
        bound: node.store().bindings().map_or(0, |b| b.len()),
    }
}

// ---- 2. membership at scale ------------------------------------------------

/// Installs one binding per node and measures what carrying them costs.
///
/// The nodes are spread across `--networks` domains, because ten thousand of
/// them are not one network's membership. Those in this tenant's own zone are
/// `Dns`-sourced and expire on a TTL; the rest belong to other networks and are
/// `Delegated`, which is the only way §3.5 lets an origin outside the zone be
/// trusted at all. The mix matters to what is measured below: the maintenance
/// pass walks expiring bindings, and delegated ones carry a scope the promotion
/// path has to consult.
///
/// Written straight to the store rather than resolved and delegated for real —
/// there is no machine that runs ten thousand iroh endpoints — so what this
/// measures is the cost of *carrying* the result, not of arriving at it.
async fn membership(harness: &Harness, options: &Options) -> Vec<Member> {
    section("membership table");
    let before = Meter::now();
    let per_network = options.members.div_ceil(options.networks);

    let started = Instant::now();
    let members: Vec<Member> = (0..options.members)
        .map(|i| {
            let network = i / per_network;
            // Network 0 is this tenant's own: its members are the ones the
            // zone names. Everything else is another network entirely.
            let domain = if network == 0 {
                APEX.to_string()
            } else {
                format!("net{network:03}.example")
            };
            Member {
                origin: OriginId::named(&format!("node{i:05}"), &domain).expect("a named origin"),
                key: fake_secret(i),
                domain,
                delegated: network != 0,
            }
        })
        .collect();
    rate(
        "generating node identities",
        started.elapsed(),
        options.members,
        "nodes",
    );

    // Only the other networks' nodes here. The zone-named ones are staged in by
    // the fan-out below, which needs to vary the dialable set and must do it by
    // *adding*: deleting ten thousand rows and reinstating them would charge
    // the push measurement for SQLite's free-page churn.
    let delegated: Vec<&Member> = members.iter().filter(|m| m.delegated).collect();
    let started = Instant::now();
    for member in &delegated {
        harness.bind(member);
    }
    rate(
        "installing bindings",
        started.elapsed(),
        delegated.len(),
        "bindings",
    );
    line(
        "  from other networks",
        &format!(
            "{:>12}",
            format!(
                "{} delegated across {} networks",
                delegated.len(),
                options.networks.saturating_sub(1).max(1),
            )
        ),
    );
    line(
        "  from this tenant's own zone",
        &format!(
            "{:>12}",
            format!(
                "{} dns-bound (staged in below)",
                members.len() - delegated.len()
            )
        ),
    );

    Meter::now().since(&before).report("membership install");
    members
}

// ---- 3. the reactive push --------------------------------------------------

/// Measures one reactive push against a growing dialable set.
///
/// `Node::push_head` dials **every trusted peer at once** — `docs/DESIGN.md`
/// §5.3 calls it "sub-second propagation on a connected cluster", sized for the
/// N ≤ 100 networks §12 assumes. On a hosted tenant it fires whenever the
/// replica's coverage materially changes (`Node::publish_material_claims`,
/// reached from the standing `run_replicas` loop), so it is not a rare event on
/// a busy network.
///
/// What varies is the *dialable* set, not the binding table: `dialable_peers`
/// is `trusted_keys`, and a delegated origin is not one — so the nodes that
/// come from other networks are never dialed, and this fan-out is bounded by
/// the tenant's own zone rather than by the ten thousand nodes it replicates.
/// The points are therefore taken by staging that zone's membership upward,
/// which is also why nothing here deletes: a table churned down and back up
/// would charge the measurement for SQLite's free pages rather than the push.
///
/// Every target is unreachable, deliberately: what is isolated is the
/// *orchestration* — building the target set, one future per peer, polled to
/// completion — with no successful handshake mixed in. It is the floor. A
/// dialable membership pays this plus a QUIC handshake per peer.
async fn fanout(harness: &Harness, members: &[Member], _options: &Options) {
    section("one reactive push (`push_head`), by dialable peers");
    let node = harness.node();
    let head = harness.head();

    // The baseline the fan-out has to be read against. A push of N peers that
    // costs N times this is doing nothing but dialling; one that costs more is
    // paying for how the dials are run, and the two have very different fixes.
    // A key alone, with no address — which is exactly what `dial_targets`
    // hands the push for a peer no discovery has located.
    let started = Instant::now();
    let before = Meter::now();
    let _ = node.net().connect_mpt(fake_key(usize::MAX / 2)).await;
    line(
        "one dial, peer unreachable",
        &format!(
            "{:>12.2?}  {} CPU",
            started.elapsed(),
            fmt_dur(Meter::now().cpu.saturating_sub(before.cpu))
        ),
    );

    // The zone-named members, in order, since those are the only dialable ones.
    let named: Vec<&Member> = members.iter().filter(|m| !m.delegated).collect();
    let mut installed = 0usize;
    for stage in [0usize, 100, 250, named.len()] {
        if stage < installed || stage > named.len() {
            continue;
        }
        for member in &named[installed..stage] {
            harness.bind(member);
        }
        installed = stage;

        let dialable = node.dialable_peers().expect("the dialable set").len();
        let before = Meter::now();
        let started = Instant::now();
        let pushed = node.push_head(&head).await.expect("the push completes");
        let elapsed = started.elapsed();
        let after = Meter::now();
        println!(
            "  {:<34} {:>12.2?}  {:>6} reached, {} CPU, RSS +{}",
            format!("{dialable} dialable peers"),
            elapsed,
            pushed,
            fmt_dur(after.cpu.saturating_sub(before.cpu)),
            mib(after.rss.saturating_sub(before.rss)),
        );
    }
}

// ---- 4. what replicating everyone costs ------------------------------------

/// Gives every member a published head and a small tree, as a replica of a
/// live network would hold.
///
/// A hosted replica is total: `synch_dp::spaces::ensure_replicas` adds a
/// replica for every space *any* origin publishes, so the tenant's store
/// carries one complete head plus that origin's entries for every member.
/// Written through the store rather than by syncing from ten thousand real
/// nodes — there is no machine that runs ten thousand iroh endpoints — so what
/// this measures is the *storage* cost of the result, not the sync that
/// produces it.
async fn held_data(harness: &Harness, members: &[Member], options: &Options) {
    section("what a replica holds for every member");
    let node = harness.node();
    let before = Meter::now();
    let baseline_db = db_bytes(harness.tenant_dir());
    let now = now_ns();

    let started = Instant::now();
    for (i, member) in members.iter().enumerate() {
        let root = fake_hash(i as u64);
        let head = SignedHead::sign(&member.key, member.origin.clone(), 1, root, now);
        node.store()
            .put_head(Slot::Complete, &head, now, now)
            .expect("the head writes");
        for e in 0..options.entries {
            let entry = FileEntry::file(
                4096,
                now,
                fake_hash((i * options.entries + e) as u64 ^ 0x5eed),
                1,
            );
            node.store()
                .put_entry(
                    &member.origin,
                    "media",
                    &format!("dir{:02}/file{e:04}", e % 8),
                    &entry,
                )
                .expect("the entry writes");
        }
    }
    let written = started.elapsed();
    let rows = members.len() * (1 + options.entries);
    rate("heads + entries written", written, rows, "rows");

    let after = Meter::now();
    after.since(&before).report("holding every node's tree");
    let db = db_bytes(harness.tenant_dir());
    line("database on disk", &format!("{:>12}", mib(db)));
    line(
        "  the database file",
        &format!("{:>12}", mib(db_part(harness.tenant_dir(), ""))),
    );
    line(
        "  the write-ahead log",
        &format!("{:>12}", mib(db_part(harness.tenant_dir(), "-wal"))),
    );
    // Net of what an empty tenant's database already costs, which at these
    // member counts is not a rounding error: reporting the total over the node
    // count would charge every node a share of the schema.
    line(
        "  attributable to these nodes",
        &format!(
            "{:>12}  ({:.0} B per node)",
            mib(db.saturating_sub(baseline_db)),
            db.saturating_sub(baseline_db) as f64 / members.len().max(1) as f64,
        ),
    );
}

// ---- 5. the per-tick work --------------------------------------------------

/// Times the queries the reconciler and the standing loops run every pass.
///
/// None of these is per-member by design — they are per *space*, per replica,
/// or per complete head — but a replica of a ten-thousand-member network has
/// ten thousand complete heads, so the ones that walk heads become per-member
/// in practice. That is the distinction this section exists to make visible.
async fn per_tick(harness: &Harness, _options: &Options) {
    section("per-tick work at this membership");
    let node = harness.node();

    // Read before every reactive push and every anti-entropy round, off the
    // blocking pool. It scans the whole binding table and returns only the
    // dialable subset, so both numbers matter: the ten thousand it walks and
    // the few hundred it hands back.
    let started = Instant::now();
    let peers = node.dialable_peers().expect("the dialable set");
    line(
        "dialable_peers()",
        &format!(
            "{:>12.2?}  {} of {} bindings",
            started.elapsed(),
            peers.len(),
            node.store().bindings().map_or(0, |b| b.len()),
        ),
    );

    // The other half of what a push does before it dials: an address lookup per
    // peer. `Node::dial_targets` is crate-private, so this is its body — the
    // same two reads, in the same order.
    let started = Instant::now();
    let located = peers
        .iter()
        .filter(|peer| node.peer_addr(peer).expect("the peer address").is_some())
        .count();
    line(
        "peer_addr() over the dialable set",
        &format!(
            "{:>12.2?}  {} of {} located",
            started.elapsed(),
            located,
            peers.len()
        ),
    );

    let started = Instant::now();
    let origins = node
        .store()
        .origins_with_complete_heads()
        .expect("the complete origins");
    line(
        "origins_with_complete_heads()",
        &format!("{:>12.2?}  {} origins", started.elapsed(), origins.len()),
    );

    let started = Instant::now();
    let roots = node.store().complete_slot_roots().expect("the roots");
    line(
        "complete_slot_roots()",
        &format!("{:>12.2?}  {} roots", started.elapsed(), roots.roots.len()),
    );

    let started = Instant::now();
    let heads = node.store().all_heads(Slot::Complete).expect("the heads");
    line(
        "all_heads(complete)",
        &format!("{:>12.2?}  {} heads", started.elapsed(), heads.len()),
    );

    // §4.5: run once per reconcile pass, per tenant.
    let started = Instant::now();
    synch_dp::spaces::ensure_replicas(node, harness.network())
        .await
        .expect("replicas converge");
    line(
        "spaces::ensure_replicas()",
        &format!("{:>12.2?}", started.elapsed()),
    );

    // §3.3: run once per metering heartbeat, per tenant.
    let started = Instant::now();
    let coverage = synch_dp::spaces::coverage(node)
        .await
        .expect("the coverage");
    line(
        "spaces::coverage()",
        &format!(
            "{:>12.2?}  {} held, {} wanted",
            started.elapsed(),
            coverage.held_roots,
            coverage.wanted
        ),
    );

    // The standing replica loop's first half.
    let started = Instant::now();
    let swept = {
        let node = node.clone();
        synch_core::offload(move || node.sweep_replicas(None))
            .await
            .expect("the sweep")
    };
    line(
        "sweep_replicas()",
        &format!("{:>12.2?}  {} spaces", started.elapsed(), swept.len()),
    );

    // The standing maintenance loop, every 300 s. This is the pass that
    // expires bindings, so it walks the membership.
    let started = Instant::now();
    let stats = {
        let node = node.clone();
        synch_core::offload(move || node.maintenance_pass()).await
    };
    match stats {
        Ok(stats) => line(
            "maintenance_pass()",
            &format!("{:>12.2?}  {stats:?}", started.elapsed()),
        ),
        Err(error) => line(
            "maintenance_pass()",
            &format!("{:>12.2?}  failed: {error}", started.elapsed()),
        ),
    }
}

// ---- 6. steady state -------------------------------------------------------

/// Watches the provisioned tenant idle at full membership.
///
/// Every standing loop `Tenant::spawn_loops` starts is running throughout, plus
/// the replication ticker — so this is what a shard pays per hosted network
/// with nothing happening on it: no publishes, no fetches, no inbound peers.
/// The floor, in other words, which is the number that decides how many
/// networks fit on one instance.
async fn steady(harness: &Harness, options: &Options) {
    section(&format!(
        "steady state, {} s at full membership",
        options.steady_secs
    ));
    let before = Meter::now();
    let mut peak_rss = before.rss;
    let mut rss = Vec::new();
    // Per-second, not just start-to-end. A replica that has just come up is
    // *cold* — every want is unresolved and every provider walk is a fresh
    // dial of the membership — and it is the settling, not the average across
    // it, that says whether an instance holds this network or merely survives
    // the first minute of it.
    let mut per_second = Vec::new();

    let started = Instant::now();
    let mut last = before;
    while started.elapsed() < Duration::from_secs(options.steady_secs) {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let now = Meter::now();
        peak_rss = peak_rss.max(now.rss);
        rss.push(now.rss);
        per_second.push(now.cpu.saturating_sub(last.cpu).as_secs_f64());
        last = now;
    }
    let after = Meter::now();
    let wall = started.elapsed();
    let cpu = after.cpu.saturating_sub(before.cpu);

    line("wall time", &format!("{wall:>12.2?}"));
    line("CPU consumed", &format!("{:>12}", fmt_dur(cpu)));
    line(
        "CPU, whole window",
        &format!(
            "{:>11.0}%  of one core",
            100.0 * cpu.as_secs_f64() / wall.as_secs_f64().max(f64::EPSILON)
        ),
    );
    let window = (per_second.len() / 4).max(1);
    line(
        "CPU, first quarter",
        &format!(
            "{:>11.0}%  of one core",
            100.0 * mean(&per_second[..window])
        ),
    );
    line(
        "CPU, last quarter",
        &format!(
            "{:>11.0}%  of one core",
            100.0 * mean(&per_second[per_second.len() - window..])
        ),
    );
    line(
        "RSS, mean",
        &format!(
            "{:>12}",
            mib((rss.iter().sum::<u64>()) / (rss.len().max(1) as u64))
        ),
    );
    line("RSS, peak", &format!("{:>12}", mib(peak_rss)));
    // The loop set is the tenant's whole job, and a panicked loop leaves a
    // tenant that looks healthy from outside while it has stopped publishing
    // or stopped renewing its membership lease (`Tenant::has_failed_loop`).
    // At this membership that is a live risk, not a formality, so the idle
    // window is also the check.
    line(
        "standing loops",
        &format!(
            "{:>12}",
            if harness.loops_healthy() {
                "all running"
            } else {
                "A LOOP DIED"
            }
        ),
    );
}

// ---- the harness -----------------------------------------------------------

/// One node the replica serves.
struct Member {
    origin: OriginId,
    key: SecretKey,
    /// The network it belongs to.
    domain: String,
    /// Whether it reaches this replica through a delegation rather than
    /// through this tenant's own zone.
    delegated: bool,
}

/// A provisioned tenant and everything standing behind it.
struct Harness {
    tenant: Option<Tenant>,
    network: HostedNetwork,
    _base: tempfile::TempDir,
    _servers: Vec<tokio::task::JoinHandle<()>>,
}

impl Harness {
    /// Provisions a tenant exactly as `Reconciler::tick` does: a stub control
    /// plane it registers with, a signed zone that names the key it registered,
    /// and `Tenant::provision` for everything in between.
    async fn provision() -> Harness {
        let base = tempfile::tempdir().expect("a base dir");
        let (cp_url, cp_server) = control_plane().await;
        let control = ControlPlane::new(&cp_url, "synchdp_test").expect("the control client");

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

        // The real order: the tenant generates a key, and only then can a zone
        // name it. `Tenant::provision` refuses to open until the zone does.
        let dir = config.tenant_dir(ORG, NETWORK);
        {
            let dir = dir.clone();
            synch_core::offload(move || Node::init(&dir, Some(APEX)))
                .await
                .expect("the tenant initializes");
        }
        let tenant_key = {
            let dir = dir.clone();
            synch_core::offload(move || {
                let store = synch_store::Store::open(&dir)?;
                store.active_device_key()
            })
            .await
            .expect("reading the tenant's key")
            .expect("an active key")
            .node_id
        };

        let (dns, resolver, zone_server) = zone(vec![format!(
            "v=sync1 id={} nk={}",
            slot_label(),
            tenant_key.to_z32()
        )])
        .await;
        config.dns = dns;

        let tenant = Tenant::provision(
            &config,
            &control,
            Some(resolver.clone()),
            network.clone(),
            Arc::new(synch_dp::metrics::Metrics::default()),
        )
        .await
        .expect("the tenant provisions");

        Harness {
            tenant: Some(tenant),
            network,
            _base: base,
            _servers: vec![cp_server, zone_server],
        }
    }

    fn node(&self) -> &Node {
        self.tenant
            .as_ref()
            .expect("the tenant is live")
            .node()
            .expect("the tenant is open")
    }

    fn network(&self) -> &HostedNetwork {
        &self.network
    }

    fn tenant_dir(&self) -> &std::path::Path {
        self.tenant.as_ref().expect("the tenant is live").dir()
    }

    /// Whether every standing loop is still running.
    fn loops_healthy(&self) -> bool {
        !self
            .tenant
            .as_ref()
            .expect("the tenant is live")
            .has_failed_loop()
    }

    /// The tenant's own current head, which `fanout` pushes.
    fn head(&self) -> SignedHead {
        let node = self.node();
        node.store()
            .complete_head(node.origin())
            .expect("reading the tenant's head")
            .unwrap_or_else(|| {
                // A tenant with nothing to say has published no head yet; sign
                // one rather than skip the section, since what is measured is
                // the fan-out and not what it carries.
                let key = node
                    .store()
                    .active_device_key()
                    .expect("the tenant's key")
                    .expect("an active key");
                SignedHead {
                    origin: node.origin().clone(),
                    seq: 1,
                    root: Hash::EMPTY,
                    created_at: now_ns(),
                    signed_by: key.node_id,
                    sig: iroh_base::Signature::from_bytes(&[0u8; 64]),
                }
            })
    }

    /// Trusts one node, the way its own network's zone or a delegation would.
    ///
    /// A zone-named member gets a `Dns` binding with a TTL, unrestricted; a
    /// node from another network gets a `Delegated` one confined to the spaces
    /// the delegation names, which is all §3.5 lets an origin outside the zone
    /// have. Both expire, because both do in production, and the maintenance
    /// pass's cost is a function of how many bindings it has to age.
    fn bind(&self, member: &Member) {
        let now = now_ns();
        let ttl = now + Duration::from_secs(3600).as_nanos() as i64;
        self.node()
            .store()
            .put_binding(&Binding {
                origin: member.origin.clone(),
                node_id: member.key.public(),
                source: if member.delegated {
                    BindingSource::Delegated
                } else {
                    BindingSource::Dns
                },
                domain: Some(member.domain.clone()),
                issuer: None,
                spaces: if member.delegated {
                    vec!["media".to_string()]
                } else {
                    Vec::new()
                },
                note: None,
                added_at: now,
                expires_at: Some(ttl),
            })
            .expect("the binding installs");
    }

    async fn shutdown(mut self) {
        if let Some(tenant) = self.tenant.take() {
            tenant.drain().await;
        }
    }
}

/// The four `/dp/v1` routes `Tenant::provision` and the reconciler touch.
///
/// A stub rather than the real control plane: what is under test is the data
/// plane's own cost, and standing up Postgres to measure a replica's RSS would
/// measure Postgres.
async fn control_plane() -> (String, tokio::task::JoinHandle<()>) {
    type Shared = Arc<Mutex<HashMap<String, String>>>;
    let state: Shared = Arc::default();
    let app = axum::Router::new()
        .route(
            "/dp/v1/networks",
            get(|| async move {
                Json(serde_json::json!({
                    "generation": 1,
                    "networks": [{
                        "org": ORG,
                        "network": NETWORK,
                        "domain": APEX,
                        "budget_bytes": 0,
                        "retention": "current",
                    }],
                    "collect": [],
                }))
            }),
        )
        .route(
            "/dp/v1/networks/{org}/{network}/device",
            put(
                |State(state): State<Shared>,
                 AxPath((org, network)): AxPath<(String, String)>,
                 Json(body): Json<serde_json::Value>| async move {
                    let nk = body
                        .get("nk")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    state
                        .lock()
                        .expect("the stub's lock")
                        .insert(format!("{org}/{network}"), nk);
                    Json(serde_json::json!({"ok": true}))
                },
            ),
        )
        .route(
            "/dp/v1/networks/{org}/{network}/status",
            axum::routing::post(|| async move { Json(serde_json::json!({"ok": true})) }),
        )
        .route(
            "/dp/v1/networks/{org}/{network}/storage",
            delete(|| async move { Json(serde_json::json!({"ok": true})) }),
        )
        .with_state(state);

    let listener =
        tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().expect("addr"))
            .await
            .expect("a loopback port");
    let addr = listener.local_addr().expect("the bound address");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// A simulated DNSSEC-signed membership zone naming `records`.
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
        // Membership is what is under test; the zone-key transparency path has
        // its own suite and would only add a network dependency here.
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

// ---- deterministic fake identities -----------------------------------------

/// A member's signing key, derived from its index so a run is reproducible.
fn fake_secret(i: usize) -> SecretKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
    seed[8] = 0xa5;
    SecretKey::from_bytes(&seed)
}

/// That key's public half.
fn fake_key(i: usize) -> synch_core::NodeId {
    fake_secret(i).public()
}

/// A distinct hash per index, standing in for a trie root or an object root.
fn fake_hash(i: u64) -> Hash {
    Hash(*blake3::hash(&i.to_le_bytes()).as_bytes())
}

// ---- measurement -----------------------------------------------------------

/// One reading of what this process is using.
#[derive(Clone, Copy)]
struct Meter {
    /// Resident set size, in bytes.
    rss: u64,
    /// The high-water mark of the same, in bytes — monotonic for the process.
    peak_rss: u64,
    /// User + system CPU consumed by the process so far.
    cpu: Duration,
}

/// The difference between two readings.
struct Delta {
    rss: i64,
    peak_rss: u64,
    cpu: Duration,
}

impl Meter {
    fn now() -> Meter {
        Meter {
            rss: proc_status_kb("VmRSS:") * 1024,
            peak_rss: proc_status_kb("VmHWM:") * 1024,
            cpu: proc_cpu(),
        }
    }

    fn since(&self, before: &Meter) -> Delta {
        Delta {
            rss: self.rss as i64 - before.rss as i64,
            peak_rss: self.peak_rss,
            cpu: self.cpu.saturating_sub(before.cpu),
        }
    }
}

impl Delta {
    fn report(&self, label: &str) {
        println!(
            "  {:<34} {:>12}  RSS {}{}, peak {}",
            label,
            fmt_dur(self.cpu) + " CPU",
            if self.rss < 0 { "-" } else { "+" },
            mib(self.rss.unsigned_abs()),
            mib(self.peak_rss),
        );
    }
}

/// Reads one `/proc/self/status` field, in kB.
///
/// Linux-only, and deliberately not abstracted: this harness answers a
/// question about a Linux pod, and a portable approximation would answer a
/// different one.
fn proc_status_kb(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with(field))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|kb| kb.parse::<u64>().ok())
                })
        })
        .unwrap_or(0)
}

/// User + system CPU for the whole process, from `/proc/self/stat`.
///
/// Fields 14 and 15, in clock ticks. `USER_HZ` is 100 on every Linux target
/// this service is built for, and the kernel exposes no other way to read it
/// without libc, so it is assumed rather than queried.
fn proc_cpu() -> Duration {
    const USER_HZ: u64 = 100;
    let stat = match std::fs::read_to_string("/proc/self/stat") {
        Ok(stat) => stat,
        Err(_) => return Duration::ZERO,
    };
    // The comm field can contain spaces and parentheses; everything after the
    // last ')' is positionally stable.
    let tail = match stat.rfind(')') {
        Some(at) => &stat[at + 1..],
        None => return Duration::ZERO,
    };
    let fields: Vec<&str> = tail.split_whitespace().collect();
    // `tail` starts at field 3 (state), so utime is index 11 and stime 12.
    let ticks = |i: usize| {
        fields
            .get(i)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let total = ticks(11) + ticks(12);
    Duration::from_secs_f64(total as f64 / USER_HZ as f64)
}

/// Total bytes under a directory, following nothing.
fn dir_bytes(dir: &std::path::Path) -> u64 {
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => total += dir_bytes(&entry.path()),
            Ok(_) => total += entry.metadata().map(|m| m.len()).unwrap_or(0),
            Err(_) => {}
        }
    }
    total
}

/// The database, its WAL, and its shared-memory file.
fn db_bytes(dir: &std::path::Path) -> u64 {
    db_part(dir, "") + db_part(dir, "-wal") + db_part(dir, "-shm")
}

/// One of the three files, by suffix.
///
/// The WAL is worth asking about separately. A hosted tenant opens under
/// [`synch_store::Checkpointing::Embedder`] so that no frame is recycled before
/// the replicator has shipped it (§5.3), which means the WAL is bounded by the
/// replication interval rather than by SQLite's autocheckpoint — and at ten
/// thousand origins that is a number an operator has to have seen before
/// sizing a pod's ephemeral volume.
fn db_part(dir: &std::path::Path, suffix: &str) -> u64 {
    let mut path = dir.join(synch_store::DB_FILE).into_os_string();
    path.push(suffix);
    std::fs::metadata(std::path::PathBuf::from(path))
        .map(|m| m.len())
        .unwrap_or(0)
}

// ---- output ----------------------------------------------------------------

struct Options {
    members: usize,
    networks: usize,
    entries: usize,
    steady_secs: u64,
}

impl Options {
    fn parse() -> Options {
        let args: Vec<String> = std::env::args().collect();
        let value = |flag: &str, default: u64| -> u64 {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        };
        Options {
            members: value("--members", DEFAULT_MEMBERS as u64).max(1) as usize,
            networks: value("--networks", DEFAULT_NETWORKS as u64).max(1) as usize,
            entries: value("--entries", DEFAULT_ENTRIES as u64) as usize,
            steady_secs: value("--steady", DEFAULT_STEADY_SECS),
        }
    }
}

fn section(name: &str) {
    println!("\n{name}");
}

fn line(label: &str, value: &str) {
    println!("  {label:<34} {value}");
}

fn rate(label: &str, elapsed: Duration, count: usize, unit: &str) {
    println!(
        "  {:<34} {:>12.2?}  {:>10.0} {unit}/s",
        label,
        elapsed,
        count as f64 / elapsed.as_secs_f64().max(f64::EPSILON),
    );
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

fn fmt_dur(d: Duration) -> String {
    format!("{:.2} s", d.as_secs_f64())
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}
