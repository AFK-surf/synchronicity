//! TUF-driven pin refresh end to end (docs/REKOR-ZONE-KEY.md §10.5).
//!
//! Three layers, because §10 makes three separate promises.
//!
//! The **conformance** half runs the real Sigstore chain, checked in
//! verbatim, through the real verifier: root 13 → 14 → 15, then timestamp,
//! snapshot, targets and the `trusted_root.json` target, ending in the pin
//! set a client would actually adopt. Canonical JSON is where TUF
//! implementations historically break, and the only way to know it is right
//! is to check it against bytes somebody else produced.
//!
//! The **synthetic** half exercises what the real repository cannot be asked
//! to do on demand: root rotation across versions, a threshold not met, an
//! expired timestamp, a rolled-back version, a tampered target, and a
//! trusted root that drops a shard key — revocation reaching the pin set.
//!
//! The **resolver** half proves the two load-bearing rules of §10.2 through
//! the whole DoH path: a zone that relays a bundle teaches a client a log
//! key its build never knew, in the same refresh that then verifies a proof
//! from that log; and nothing about the bundle can ever fail a refresh.

use synch_net::{
    dns::{DnssecResolver, RekorPolicy, ResolverOptions},
    error::NetError,
    rekor::{self, LogKeys},
    sim::{SimLog, SimTuf, SimZone},
    tuf::{self, PinState, TufBundle, TufError},
};

fn write(contents: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), contents).unwrap();
    file
}

fn member_records() -> Vec<String> {
    vec![format!(
        "v=sync1 id=nas nk={}",
        iroh_base::SecretKey::generate().public().to_z32()
    )]
}

/// A fixed moment the synthetic repositories are built and verified at, so
/// nothing in this file depends on the wall clock.
const NOW: i64 = 1_800_000_000;

// ------------------------------------------------------- real-chain fixtures

/// The checked-in Sigstore metadata both suites are asserted against.
///
/// It lives beside the Gleam tests because those can only read files from
/// their own tree; this side reaches across for it deliberately, exactly as
/// the proof fixture does.
fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../control-plane/test/fixtures/tuf")
}

fn fixture(name: &str) -> Vec<u8> {
    let path = fixture_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

fn fixture_field(name: &str) -> String {
    let meta = String::from_utf8(fixture("meta.txt")).unwrap();
    meta.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("fixture meta has no {name}"))
        .to_string()
}

fn fixture_number(name: &str) -> u64 {
    fixture_field(name).parse().expect("a fixture number")
}

/// The bundle the control plane actually relays: the root chain from the
/// floor a stock client embeds — one root today, and one more per Sigstore
/// rotation until the floor is raised.
fn fixture_bundle() -> TufBundle {
    fixture_bundle_from("bundle_roots")
}

/// The same files with the whole checked-in root history in front, so the
/// chain walk has real rotations to walk. The repository serves these
/// versions; which of them a bundle carries is the relay's choice.
fn fixture_chain_bundle() -> TufBundle {
    fixture_bundle_from("root_versions")
}

fn fixture_bundle_from(field: &str) -> TufBundle {
    TufBundle {
        roots: fixture_field(field)
            .split(',')
            .map(|version| fixture(&format!("root-{version}.json")))
            .collect(),
        timestamp: fixture("timestamp.json"),
        snapshot: fixture("snapshot.json"),
        targets: fixture("targets.json"),
        trusted_root: fixture("trusted-root.json"),
    }
}

#[test]
fn the_shared_fixture_frames_and_decodes() {
    // The framing half of the crossval: the Gleam encoder builds these same
    // bytes from these same files, so a drift in either direction fails one
    // of the two suites rather than passing both against different bytes.
    let bundle = fixture_bundle();
    assert_eq!(bundle.encode(), fixture("bundle.bin"));
    let decoded = TufBundle::decode(&fixture("bundle.bin")).expect("the fixture is a v1 bundle");
    assert_eq!(decoded, bundle);
    assert_eq!(TufBundle::from_txt(&bundle.to_txt()).unwrap(), bundle);
}

#[test]
fn the_real_sigstore_chain_verifies_and_yields_the_pin_set() {
    // Everything here is Sigstore's own bytes: if canonical JSON, the key
    // parsing, the DER signatures, the optional `meta` hashes or the RFC
    // 3339 shapes were wrong in any way, this cannot pass.
    let bundle = fixture_chain_bundle();
    let floor = fixture_number("chain_floor");
    let state = PinState {
        root: fixture(&format!("root-{floor}.json")),
        root_version: floor,
        timestamp_version: 0,
        snapshot_version: 0,
        targets_version: 0,
        trusted_root: Vec::new(),
        updated_at: 0,
    };
    // Verified at the moment the fixture was fetched: a checked-in chain
    // expires, and pinning the clock is what keeps it checkable.
    let at = fixture_number("verify_at");
    let update = tuf::update(&bundle, &state, at).expect("the real chain must verify");
    assert!(update.changed);
    assert_eq!(update.state.root_version, fixture_number("root_version"));
    assert_eq!(
        update.state.timestamp_version,
        fixture_number("timestamp_version")
    );
    assert_eq!(
        update.state.snapshot_version,
        fixture_number("snapshot_version")
    );
    assert_eq!(
        update.state.targets_version,
        fixture_number("targets_version")
    );
    assert_eq!(update.state.trusted_root, fixture("trusted-root.json"));

    // And the pin set it yields is the production log set — the same ids
    // the build-time snapshot carries, derived a completely different way.
    let derived = update.log_keys;
    for id in fixture_field("log_ids").split(',') {
        let id: [u8; 32] = hex::decode(id).unwrap().try_into().unwrap();
        assert!(derived.find(&id).is_some(), "pin set is missing {id:?}");
    }
    assert_eq!(
        derived.keys().len(),
        fixture_field("log_ids").split(',').count()
    );
    assert_eq!(
        derived,
        LogKeys::embedded(),
        "the TUF-derived pin set and the embedded bootstrap snapshot are the same logs today"
    );
}

#[test]
fn the_real_chain_expires() {
    // Expiry gates the update and nothing else: a year after the fixture was
    // fetched the same bytes are refused, and a client running on them keeps
    // whatever pins it already had.
    let at = fixture_number("verify_at") + 365 * 86_400;
    let floor = fixture_number("chain_floor");
    let state = PinState {
        root: fixture(&format!("root-{floor}.json")),
        root_version: floor,
        ..PinState::embedded()
    };
    assert!(matches!(
        tuf::update(&fixture_chain_bundle(), &state, at),
        Err(TufError::Expiry(_))
    ));
}

#[test]
fn the_real_chain_cannot_be_reached_from_below_its_floor() {
    // The floor §10.1 states per release, seen from a build below it. The
    // bundle a control plane relays starts at the version a stock client
    // embeds, so a client two rotations older has nothing to bridge the gap
    // and keeps its pins rather than guessing. The same files *with* the
    // intermediates in front verify, which is what makes this a floor and
    // not a bug.
    let floor = fixture_number("chain_floor");
    let state = PinState {
        root: fixture(&format!("root-{floor}.json")),
        root_version: floor,
        ..PinState::embedded()
    };
    let error = tuf::update(&fixture_bundle(), &state, fixture_number("verify_at"));
    assert!(matches!(error, Err(TufError::Chain(_))), "{error:?}");
    tuf::update(&fixture_chain_bundle(), &state, fixture_number("verify_at"))
        .expect("the full chain reaches the same head");
}

#[test]
fn the_embedded_root_is_the_chains_head() {
    // The build ships root 15; the fixture chain ends there. If Sigstore
    // rotates and only one of the two is refreshed, this says so.
    let embedded: serde_json::Value = serde_json::from_str(tuf::EMBEDDED_TUF_ROOT).unwrap();
    assert_eq!(
        embedded["signed"]["version"].as_u64(),
        Some(fixture_number("root_version"))
    );
    assert_eq!(
        tuf::EMBEDDED_TUF_ROOT.as_bytes(),
        fixture(&format!("root-{}.json", fixture_number("root_version")))
    );
}

#[test]
fn real_key_ids_are_the_digest_of_the_key_object_almost_always() {
    // TUF derives a key id as SHA-256 over the canonical JSON of the key
    // object, and Sigstore's roots agree — with one real exception: root 11
    // edited a key's `x-tuf-on-ci-online-uri` member while keeping the id.
    // That is why the verifier looks keys up by the id the table is keyed
    // with, and why this only asserts the derivation on the roots it holds.
    for version in fixture_field("root_versions").split(',') {
        let root: serde_json::Value =
            serde_json::from_slice(&fixture(&format!("root-{version}.json"))).unwrap();
        let keys = root["signed"]["keys"].as_object().unwrap();
        assert!(!keys.is_empty());
        for (id, key) in keys {
            assert_eq!(&tuf::key_id(key).unwrap(), id, "root {version} key {id}");
        }
    }
}

// -------------------------------------------------------------- synthetic

/// A synthetic repository whose trusted root names one log.
fn repo() -> (SimTuf, SimLog) {
    let log = SimLog::new("rekor.sim");
    let repo = SimTuf::new(NOW, &[log.spki()]);
    (repo, log)
}

fn at(now: i64) -> u64 {
    now as u64
}

#[test]
fn a_synthetic_chain_verifies_from_its_embedded_root() {
    let (repo, log) = repo();
    let update = tuf::update(&repo.bundle(), &repo.embedded_state(), at(NOW))
        .expect("a well-formed chain verifies");
    assert!(update.changed);
    assert_eq!(update.state.root_version, 1);
    assert!(update.log_keys.find(&log.log_id()).is_some());

    // Re-applying the same bundle is valid and boring: accepted, unchanged.
    let again = tuf::update(&repo.bundle(), &update.state, at(NOW)).unwrap();
    assert!(!again.changed);
    assert_eq!(again.state, update.state);
}

#[test]
fn root_rotation_walks_every_version_in_order() {
    let (mut repo, _log) = repo();
    // Three rotations, the last two re-keying the root role entirely: a
    // client embedded at version 1 must still arrive at version 4.
    repo.rotate_root(false);
    repo.rotate_root(true);
    repo.rotate_root(true);
    assert_eq!(repo.root_version(), 4);

    let update = tuf::update(&repo.bundle(), &repo.embedded_state(), at(NOW))
        .expect("a chained rotation verifies");
    assert_eq!(update.state.root_version, 4);

    // A chain with a version missing bridges nothing. The relay is free to
    // withhold; it is not free to be believed.
    let mut gapped = repo.bundle();
    gapped.roots.remove(1);
    assert!(matches!(
        tuf::update(&gapped, &repo.embedded_state(), at(NOW)),
        Err(TufError::Chain(_))
    ));

    // And a client already at version 4 accepts a bundle that only carries
    // the tail — old material may be withheld once it is passed.
    let tail = repo.bundle_from(4);
    tuf::update(&tail, &update.state, at(NOW)).expect("the tail alone still verifies");
}

#[test]
fn a_root_the_old_root_did_not_sign_is_refused() {
    let (mut repo, _log) = repo();
    let honest = repo.embedded_state();
    // A fork: rotate to a root signed only by brand-new keys, the way a
    // relay that had minted its own root would.
    repo.rotate_root(true);
    let mut forged = repo.bundle();
    // Strip the predecessor's signatures from root 2, leaving only its own.
    let mut root: serde_json::Value = serde_json::from_slice(&forged.roots[1]).unwrap();
    let keyids: Vec<String> = root["signed"]["roles"]["root"]["keyids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_string())
        .collect();
    let signatures: Vec<serde_json::Value> = root["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|sig| keyids.contains(&sig["keyid"].as_str().unwrap().to_string()))
        .cloned()
        .collect();
    root["signatures"] = serde_json::Value::Array(signatures);
    forged.roots[1] = root.to_string().into_bytes();

    assert!(matches!(
        tuf::update(&forged, &honest, at(NOW)),
        Err(TufError::Threshold(_))
    ));
}

#[test]
fn a_threshold_that_is_not_met_is_refused() {
    let (mut repo, _log) = repo();
    let state = repo.embedded_state();
    repo.rotate_root(false);
    let mut thin = repo.bundle();
    // Root version 2 needs two of its three root keys; leave it one,
    // repeated. Two signature entries, one distinct key — repeating a
    // signature must not satisfy a threshold.
    let mut root: serde_json::Value = serde_json::from_slice(&thin.roots[1]).unwrap();
    let one = root["signatures"][0].clone();
    root["signatures"] = serde_json::Value::Array(vec![one.clone(), one]);
    thin.roots[1] = root.to_string().into_bytes();

    let error = tuf::update(&thin, &state, at(NOW));
    assert!(matches!(error, Err(TufError::Threshold(_))), "{error:?}");
    // The untouched chain verifies, so the refusal is the signature count
    // and nothing incidental.
    tuf::update(&repo.bundle(), &state, at(NOW)).unwrap();
}

#[test]
fn an_expired_timestamp_is_refused() {
    let (mut repo, _log) = repo();
    repo.expires = NOW - 1;
    let error = tuf::update(&repo.bundle(), &repo.embedded_state(), at(NOW));
    assert!(matches!(error, Err(TufError::Expiry(_))), "{error:?}");
    // The same material a second before its expiry is fine: expiry is a
    // deadline, not a stigma.
    tuf::update(&repo.bundle(), &repo.embedded_state(), at(NOW - 2)).unwrap();
}

#[test]
fn an_expired_root_is_refused_but_an_expired_intermediate_is_not() {
    let (mut repo, _log) = repo();
    let state = repo.embedded_state();
    // Root 1 expired long ago; root 2 is current. TUF checks only the final
    // root's expiry (client workflow §5.3.11), and the real Sigstore chain
    // relies on it — root 14 was already expired when 15 was published.
    repo.root_expires = NOW - 1;
    repo.rotate_root(false);
    let mut bundle = repo.bundle();
    assert!(matches!(
        tuf::update(&bundle, &state, at(NOW)),
        Err(TufError::Expiry(_))
    ));

    // Re-publish the head unexpired, leaving the intermediates as they are.
    repo.root_expires = NOW + 86_400;
    repo.rotate_root(false);
    bundle = repo.bundle();
    let update = tuf::update(&bundle, &state, at(NOW)).expect("only the head's expiry gates");
    assert_eq!(update.state.root_version, 3);
}

#[test]
fn a_version_rollback_is_refused() {
    let (mut repo, _log) = repo();
    let first = tuf::update(&repo.bundle(), &repo.embedded_state(), at(NOW))
        .unwrap()
        .state;
    // The zone keeps serving the old bundle after the repository moved on:
    // valid material, and refused, because the client has seen newer.
    let stale = repo.bundle();
    repo.set_tlogs(&[SimLog::new("rekor.sim").spki()]);
    let newer = tuf::update(&repo.bundle(), &first, at(NOW)).unwrap().state;
    assert!(newer.timestamp_version > first.timestamp_version);

    let error = tuf::update(&stale, &newer, at(NOW));
    assert!(matches!(error, Err(TufError::Rollback(_))), "{error:?}");
}

#[test]
fn a_tampered_target_is_refused() {
    let (repo, _log) = repo();
    let mut bundle = repo.bundle();
    bundle.trusted_root.push(b' ');
    let error = tuf::update(&bundle, &repo.embedded_state(), at(NOW));
    assert!(matches!(error, Err(TufError::TargetHash(_))), "{error:?}");

    // A tampered *snapshot* fails one level up, where the timestamp's own
    // hash of it is checked.
    let mut bundle = repo.bundle();
    bundle.snapshot.push(b' ');
    assert!(matches!(
        tuf::update(&bundle, &repo.embedded_state(), at(NOW)),
        // Trailing whitespace does not change the canonical form, so the
        // signature still verifies and the length check is what catches it.
        Err(TufError::TargetHash(_))
    ));

    // A snapshot whose *content* changed fails on the signature instead.
    let mut bundle = repo.bundle();
    let mut snapshot: serde_json::Value = serde_json::from_slice(&bundle.snapshot).unwrap();
    snapshot["signed"]["meta"]["targets.json"]["version"] = serde_json::json!(99);
    bundle.snapshot = snapshot.to_string().into_bytes();
    assert!(matches!(
        tuf::update(&bundle, &repo.embedded_state(), at(NOW)),
        Err(TufError::TargetHash(_) | TufError::Threshold(_))
    ));
}

#[test]
fn a_trusted_root_that_drops_a_shard_drops_it_from_the_pin_set() {
    // Revocation, which is the half of §10 nothing else demonstrates: the
    // pin set *replaces*, never unions, so a key Sigstore removes is a key
    // clients drop.
    let old = SimLog::new("rekor.old");
    let new = SimLog::new("rekor.new");
    let mut repo = SimTuf::new(NOW, &[old.spki(), new.spki()]);
    let both = tuf::update(&repo.bundle(), &repo.embedded_state(), at(NOW)).unwrap();
    assert!(both.log_keys.find(&old.log_id()).is_some());
    assert!(both.log_keys.find(&new.log_id()).is_some());

    repo.set_tlogs(&[new.spki()]);
    let after = tuf::update(&repo.bundle(), &both.state, at(NOW)).unwrap();
    assert_eq!(after.log_keys.keys().len(), 1);
    assert!(
        after.log_keys.find(&old.log_id()).is_none(),
        "a log Sigstore removed must leave the pin set"
    );
    assert!(after.log_keys.find(&new.log_id()).is_some());
}

#[test]
fn a_trusted_root_naming_no_logs_is_never_adopted() {
    // Adopting an empty pin set would silently refuse every zone from then
    // on — trouble, which §10.2 says must never be worse than no record.
    let mut repo = SimTuf::new(NOW, &[]);
    let error = tuf::update(&repo.bundle(), &repo.embedded_state(), at(NOW));
    assert!(matches!(error, Err(TufError::Malformed(_))), "{error:?}");
    repo.set_tlogs(&[SimLog::new("rekor.sim").spki()]);
    tuf::update(&repo.bundle(), &repo.embedded_state(), at(NOW)).unwrap();
}

#[test]
fn state_is_monotonic_across_two_zones_sharing_one_file() {
    // §10.2: one state file, global across domains. A second zone serving
    // valid-but-older material must not walk the first one's versions back.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rekor-pins.json");
    let (mut repo, _log) = repo();
    let stale = repo.bundle();
    repo.rotate_root(false);
    repo.set_tlogs(&[SimLog::new("rekor.next").spki()]);

    let ahead = tuf::update(&repo.bundle(), &repo.embedded_state(), at(NOW)).unwrap();
    ahead.state.save(&path).unwrap();
    let reloaded = PinState::load(&path).expect("the state persists");
    assert_eq!(reloaded, ahead.state);

    let error = tuf::update(&stale, &reloaded, at(NOW));
    assert!(matches!(error, Err(TufError::Rollback(_))), "{error:?}");
}

// --------------------------------------------------------------- resolver

/// A zone that relays a bundle teaching one new log, and a proof from it.
///
/// The point of the arrangement: the client's *bootstrap* pin set knows a
/// different log entirely, so the proof can only verify if the TUF update
/// ran first and replaced the pins.
async fn zone_learning_a_new_shard() -> (SimZone, SimLog, tempfile::NamedTempFile) {
    let mut zone = SimZone::new("cluster.example", member_records());
    let mut new_shard = SimLog::new("log2099-1.rekor.sim");
    let proof = new_shard.publish(&zone, "create");
    zone.rekor_txt = vec![proof.to_txt().expect("encodes")];

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let repo = SimTuf::new(now, &[new_shard.spki()]);
    zone.tuf_txt = vec![repo.bundle().to_txt()];
    // The root this client embeds — written to a file only so the test can
    // seed a PinState from it the way a build would.
    let embedded = write(&String::from_utf8(repo.embedded_root()).unwrap());
    (zone, new_shard, embedded)
}

/// Seeds a state file at the synthetic repository's root version 1, which
/// is what "a build that embeds this root" means to the resolver.
fn seed_state(path: &std::path::Path, embedded_root: &std::path::Path) {
    let root = std::fs::read(embedded_root).unwrap();
    let state = PinState {
        root,
        root_version: 1,
        timestamp_version: 0,
        snapshot_version: 0,
        targets_version: 0,
        trusted_root: Vec::new(),
        updated_at: 0,
    };
    state.save(path).unwrap();
}

#[tokio::test]
async fn a_relayed_bundle_teaches_a_log_the_build_never_knew() {
    let (zone, new_shard, embedded) = zone_learning_a_new_shard().await;
    let anchor = write(&zone.anchor_record());
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("rekor-pins.json");
    seed_state(&state_path, embedded.path());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        // No --rekor-key: the pin set is the refreshable one, so it starts
        // as the embedded Sigstore bootstrap and knows nothing of this log.
        rekor_key: None,
        rekor_state: Some(state_path.clone()),
    })
    .unwrap();
    assert!(
        resolver.log_keys().find(&new_shard.log_id()).is_none(),
        "the build must not already know this log, or the test proves nothing"
    );

    let (set, _ttl) = resolver
        .member_set("cluster.example")
        .await
        .expect("the TUF update and the proof verification run in one refresh");
    assert_eq!(set.bindings.len(), 1);
    assert!(resolver.log_keys().find(&new_shard.log_id()).is_some());

    // And it was persisted, so the next process starts where this one ended.
    let persisted = PinState::load(&state_path).expect("the pin state is written");
    assert_eq!(persisted.root_version, 1);
    assert!(persisted.timestamp_version >= 1);
    assert!(rekor::LogKeys::default() != persisted.log_keys().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&state_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the pin state is the owner's alone");
    }
    server.abort();
}

#[tokio::test]
async fn the_same_zone_without_the_bundle_fails_with_unknown_log() {
    // The control: everything identical except the relay. If the proof
    // verified here too, the update above would have proved nothing.
    let (mut zone, _shard, embedded) = zone_learning_a_new_shard().await;
    zone.tuf_txt.clear();
    let anchor = write(&zone.anchor_record());
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("rekor-pins.json");
    seed_state(&state_path, embedded.path());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        rekor_key: None,
        rekor_state: Some(state_path),
    })
    .unwrap();
    let error = resolver.member_set("cluster.example").await.unwrap_err();
    assert!(
        matches!(error, NetError::RekorUnknownLog { .. }),
        "without the bundle the log stays unknown: {error}"
    );
    server.abort();
}

#[tokio::test]
async fn an_invalid_bundle_leaves_the_pins_alone_and_never_fails_a_refresh() {
    // The rule §10.2 calls load-bearing: TUF trouble is never worse than
    // not having the record. The zone here relays garbage *and* publishes a
    // proof from a log the client already pins — the refresh must succeed.
    let mut zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    zone.rekor_txt = vec![log.publish(&zone, "create").to_txt().expect("encodes")];
    zone.tuf_txt = vec!["this is not a bundle".to_string()];

    let anchor = write(&zone.anchor_record());
    let log_key = write(&log.key_pem());
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("rekor-pins.json");
    let (url, server) = zone.serve().await;

    // A static --rekor-key never even asks for the bundle: a different
    // universe is static in both directions.
    let stat = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url.clone()),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        rekor_key: Some(log_key.path().to_path_buf()),
        rekor_state: Some(state_path.clone()),
    })
    .unwrap();
    let (set, _ttl) = stat
        .member_set("cluster.example")
        .await
        .expect("a garbled bundle must not fail a refresh");
    assert_eq!(set.bindings.len(), 1);
    assert!(
        !state_path.exists(),
        "an explicit key file disables TUF refresh entirely"
    );

    // And the refreshable resolver says which way it broke, without that
    // ever reaching the refresh.
    let apex = hickory_resolver::proto::rr::Name::from_utf8("cluster.example.").unwrap();
    let refreshing = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        rekor_key: None,
        rekor_state: Some(state_path.clone()),
    })
    .unwrap();
    let before = refreshing.log_keys();
    let error = refreshing.refresh_tuf(&apex).await.unwrap_err();
    assert!(
        matches!(&error, NetError::Tuf { class, .. } if *class == "malformed"),
        "{error}"
    );
    assert_eq!(refreshing.log_keys(), before, "the pins did not move");
    assert!(!state_path.exists(), "and nothing was persisted");
    server.abort();
}

#[tokio::test]
async fn a_zone_that_relays_nothing_is_a_non_event() {
    let mut zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    zone.rekor_txt = vec![log.publish(&zone, "create").to_txt().expect("encodes")];
    let anchor = write(&zone.anchor_record());
    let log_key = write(&log.key_pem());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        rekor_key: Some(log_key.path().to_path_buf()),
        rekor_state: None,
    })
    .unwrap();
    let apex = hickory_resolver::proto::rr::Name::from_utf8("cluster.example.").unwrap();
    assert!(resolver.refresh_tuf(&apex).await.unwrap().is_none());
    resolver
        .member_set("cluster.example")
        .await
        .expect("a control plane that relays no TUF material changes nothing");
    server.abort();
}

// -------------------------------------------------------------- fixtures

/// Refetches the conformance fixture from the live Sigstore repository.
///
/// Not part of the suite: it reaches the network, and the metadata it writes
/// expires, so regenerating is a deliberate act with a date attached rather
/// than something a test run does behind anyone's back. The `verify_at` it
/// records is what keeps the checked-in chain checkable afterwards.
///
/// `SYNCH_TUF_FIXTURE=write cargo test -p synch-net --test tuf_pin_refresh
/// -- --ignored regenerate_the_shared_fixture`
#[tokio::test]
#[ignore]
async fn regenerate_the_shared_fixture() {
    assert_eq!(
        std::env::var("SYNCH_TUF_FIXTURE").ok().as_deref(),
        Some("write"),
        "refusing to rewrite the fixture without SYNCH_TUF_FIXTURE=write"
    );
    let base = std::env::var("CP_TUF_URL")
        .unwrap_or_else(|_| "https://tuf-repo-cdn.sigstore.dev".to_string());
    let client = reqwest::Client::new();
    let get = |path: String| {
        let client = client.clone();
        let url = format!("{base}/{path}");
        async move {
            let response = client.get(&url).send().await.expect("fetch");
            match response.status().is_success() {
                true => Some(response.bytes().await.expect("body").to_vec()),
                false => None,
            }
        }
    };
    let json = |bytes: &[u8]| -> serde_json::Value { serde_json::from_slice(bytes).expect("json") };

    // The root chain: walk versions upward until the repository has no more.
    let mut roots: Vec<(u64, Vec<u8>)> = Vec::new();
    for version in 1..1000u64 {
        match get(format!("{version}.root.json")).await {
            Some(bytes) => roots.push((version, bytes)),
            None => break,
        }
    }
    let head = roots.last().expect("at least one root").0;
    // Consistent snapshots: timestamp names the snapshot version, the
    // snapshot names the targets version, the targets name the target hash.
    let timestamp = get("timestamp.json".into()).await.expect("timestamp.json");
    let timestamp_version = json(&timestamp)["signed"]["version"]
        .as_u64()
        .expect("version");
    let snapshot_version = json(&timestamp)["signed"]["meta"]["snapshot.json"]["version"]
        .as_u64()
        .expect("the snapshot version");
    let snapshot = get(format!("{snapshot_version}.snapshot.json"))
        .await
        .expect("snapshot");
    let targets_version = json(&snapshot)["signed"]["meta"]["targets.json"]["version"]
        .as_u64()
        .expect("the targets version");
    let targets = get(format!("{targets_version}.targets.json"))
        .await
        .expect("targets");
    let digest = json(&targets)["signed"]["targets"][tuf::TRUSTED_ROOT_TARGET]["hashes"]["sha256"]
        .as_str()
        .expect("the trusted root's digest")
        .to_string();
    let trusted_root = get(format!("targets/{digest}.{}", tuf::TRUSTED_ROOT_TARGET))
        .await
        .expect("trusted root");

    // Three roots is enough chain to be a chain: the head, and the two it
    // was rotated from. All three are checked in, so the walk has real
    // rotations to walk.
    let floor = head.saturating_sub(2).max(1);
    let chain: Vec<(u64, Vec<u8>)> = roots.into_iter().filter(|(v, _)| *v >= floor).collect();
    // The bundle itself carries only the roots at or above the version this
    // build embeds — which is what the control plane's own floor produces,
    // and what the crossval fixture therefore has to be.
    let bundle = TufBundle {
        roots: chain
            .iter()
            .filter(|(version, _)| *version >= head)
            .map(|(_, bytes)| bytes.clone())
            .collect(),
        timestamp: timestamp.clone(),
        snapshot: snapshot.clone(),
        targets: targets.clone(),
        trusted_root: trusted_root.clone(),
    };
    let chain_bundle = TufBundle {
        roots: chain.iter().map(|(_, bytes)| bytes.clone()).collect(),
        ..bundle.clone()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let state = PinState {
        root: chain[0].1.clone(),
        root_version: floor,
        timestamp_version: 0,
        snapshot_version: 0,
        targets_version: 0,
        trusted_root: Vec::new(),
        updated_at: 0,
    };
    let update = tuf::update(&chain_bundle, &state, now).expect("the fetched chain must verify");

    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        std::fs::remove_file(entry.path()).unwrap();
    }
    let put = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    for (version, bytes) in &chain {
        put(&format!("root-{version}.json"), bytes);
    }
    put("timestamp.json", &timestamp);
    put("snapshot.json", &snapshot);
    put("targets.json", &targets);
    put("trusted-root.json", &trusted_root);
    put("bundle.bin", &bundle.encode());
    let log_ids: Vec<String> = update
        .log_keys
        .keys()
        .iter()
        .map(|key| hex::encode(key.id))
        .collect();
    put(
        "meta.txt",
        format!(
            "source={base}\n\
             fetched_at={now}\n\
             verify_at={now}\n\
             root_versions={}\n\
             bundle_roots={head}\n\
             chain_floor={floor}\n\
             root_version={head}\n\
             timestamp_version={timestamp_version}\n\
             snapshot_version={snapshot_version}\n\
             targets_version={targets_version}\n\
             trusted_root_sha256={digest}\n\
             log_ids={}\n",
            chain
                .iter()
                .map(|(v, _)| v.to_string())
                .collect::<Vec<_>>()
                .join(","),
            log_ids.join(","),
        )
        .as_bytes(),
    );
    // The build embeds the head of the chain it was regenerated against.
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sigstore_tuf_root.json"),
        &chain.last().expect("a head root").1,
    )
    .unwrap();
}
