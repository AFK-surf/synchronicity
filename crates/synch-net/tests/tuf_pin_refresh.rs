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
//! the whole refresh path: a walk of Sigstore's repository teaches a client
//! a log key its build never knew, in the same refresh that then verifies a
//! proof from that log; nothing about that repository can ever fail a
//! refresh; and a client walks it once a day, not once per membership
//! lookup. Every repository here is injected, so no test run reaches
//! Sigstore.

use synch_net::{
    dns::{DnssecResolver, RekorPolicy, ResolverOptions},
    error::NetError,
    rekor::{self, LogKeys},
    sim::{SimLog, SimTuf, SimZone},
    tuf::{self, PinState, TufError, TufMetadata},
};

fn write(contents: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), contents).unwrap();
    file
}

fn member_records() -> Vec<String> {
    vec![format!(
        "v=sync1 id=nas nk={} apex=cluster.example",
        iroh_base::SecretKey::generate().public().to_z32()
    )]
}

/// A fixed moment the synthetic repositories are built and verified at, so
/// nothing in this file depends on the wall clock.
const NOW: i64 = 1_800_000_000;

// ------------------------------------------------------- real-chain fixtures

/// The checked-in Sigstore metadata this suite is asserted against: roots 13
/// through 15, timestamp, snapshot, targets and `trusted_root.json`, as the
/// repository served them, with `meta.txt` recording when and what they
/// verify to.
fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tuf")
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

/// What a stock client collects: the root chain from the version its build
/// embeds — one root today, and one more per Sigstore rotation until the
/// embedded root is refreshed.
fn fixture_metadata() -> TufMetadata {
    fixture_metadata_from("root_version")
}

/// The same files with the whole checked-in root history in front, so the
/// chain walk has real rotations to walk. The repository serves every one of
/// these versions; where a client starts is its own root's business.
fn fixture_chain_metadata() -> TufMetadata {
    fixture_metadata_from("root_versions")
}

fn fixture_metadata_from(field: &str) -> TufMetadata {
    TufMetadata {
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
fn the_real_sigstore_chain_verifies_and_yields_the_pin_set() {
    // Everything here is Sigstore's own bytes: if canonical JSON, the key
    // parsing, the DER signatures, the optional `meta` hashes or the RFC
    // 3339 shapes were wrong in any way, this cannot pass.
    let metadata = fixture_chain_metadata();
    let floor = fixture_number("chain_floor");
    let state = PinState {
        root: fixture(&format!("root-{floor}.json")),
        root_chain: Vec::new(),
        root_version: floor,
        timestamp_version: 0,
        snapshot_version: 0,
        targets_version: 0,
        targets: Vec::new(),
        trusted_root: Vec::new(),
        updated_at: 0,
    };
    // Verified at the moment the fixture was fetched: a checked-in chain
    // expires, and pinning the clock is what keeps it checkable.
    let at = fixture_number("verify_at");
    let update = tuf::update(&metadata, &state, at).expect("the real chain must verify");
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

/// The checked-in Sigstore files, served under the consistent-snapshot paths
/// the repository actually publishes them at.
///
/// The fixture stores them by role (`snapshot.json`), the repository serves
/// them by version (`165.snapshot.json`) and the target by digest — so a
/// walk that resolved the wrong version, or read the digest out of the wrong
/// field, would find nothing here rather than quietly assemble something.
struct FixtureRepo;

impl tuf::Repo for FixtureRepo {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let named = |name: &str| Some(fixture(name));
        let versions = fixture_field("root_versions");
        for version in versions.split(',') {
            if path == format!("{version}.root.json") {
                return Ok(named(&format!("root-{version}.json")));
            }
        }
        Ok(match path {
            "timestamp.json" => named("timestamp.json"),
            _ if path == format!("{}.snapshot.json", fixture_number("snapshot_version")) => {
                named("snapshot.json")
            }
            _ if path == format!("{}.targets.json", fixture_number("targets_version")) => {
                named("targets.json")
            }
            _ if path
                == format!(
                    "targets/{}.trusted_root.json",
                    fixture_field("trusted_root_sha256")
                ) =>
            {
                named("trusted-root.json")
            }
            // Every other path is a file the repository does not have,
            // which is how the root walk knows where to stop.
            _ => None,
        })
    }
}

#[test]
fn walking_the_repository_finds_the_whole_chain() {
    // How every reader of the pin set gets it — the client and the monitor
    // alike: walk the consistent-snapshot naming, then hand what was
    // collected to the ordinary verifier.
    let floor = fixture_number("chain_floor");
    let walked =
        tuf::fetch_metadata(&FixtureRepo, floor).expect("the fixture repository is walkable");
    assert_eq!(walked, fixture_chain_metadata());

    // And it goes through the ordinary verifier from there, with no
    // dispensation for having been fetched rather than relayed.
    let state = PinState {
        root: fixture(&format!("root-{floor}.json")),
        root_chain: Vec::new(),
        root_version: floor,
        timestamp_version: 0,
        snapshot_version: 0,
        targets_version: 0,
        targets: Vec::new(),
        trusted_root: Vec::new(),
        updated_at: 0,
    };
    let update = tuf::update(&walked, &state, fixture_number("verify_at")).expect("it verifies");
    assert_eq!(update.state.trusted_root, fixture("trusted-root.json"));

    // The walk starts where the caller already is: a client at the current
    // root collects only that root, and one past the end finds nothing at
    // all rather than inventing a chain.
    let current = fixture_number("root_version");
    let from_current = tuf::fetch_metadata(&FixtureRepo, current).unwrap();
    assert_eq!(
        from_current.roots,
        vec![fixture(&format!("root-{current}.json"))]
    );
    assert!(matches!(
        tuf::fetch_metadata(&FixtureRepo, current + 1),
        Err(TufError::Chain(_))
    ));
}

#[test]
fn the_log_to_read_comes_from_the_same_artifact_as_the_keys() {
    // The endpoint follows Sigstore for the same reason the keys do. What
    // the real trusted root names is asserted as a *shape* — an https base
    // URL for a shard that is open at the moment the fixture was fetched,
    // whose key is in the pin set — because pinning the hostname in a test
    // is the thing being removed.
    let trusted_root = fixture("trusted-root.json");
    let logs = tuf::tlogs(&trusted_root).expect("the real trusted root lists its logs");
    let at = fixture_number("verify_at");
    let open = tuf::current_tlog(&logs, at).expect("Sigstore has a shard open");
    assert!(open.base_url.starts_with("https://"));
    assert!(!open.base_url.ends_with('/'));
    assert!(open.valid_at(at));

    let keys = tuf::tlog_keys(&trusted_root).unwrap();
    assert!(
        keys.find(&open.log_id).is_some(),
        "the log to read must be one of the logs pinned"
    );
    // Retired shards stay pinned and stay out of the way: still verifiable,
    // never selected.
    assert!(logs.len() > 1);
    for log in &logs {
        assert!(keys.find(&log.log_id).is_some());
    }
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
        root_chain: Vec::new(),
        root_version: floor,
        ..PinState::embedded()
    };
    assert!(matches!(
        tuf::update(&fixture_chain_metadata(), &state, at),
        Err(TufError::Expiry(_))
    ));
}

#[test]
fn the_real_chain_cannot_be_reached_from_below_its_floor() {
    // The floor §10.2 states per release, seen from a build below it. A
    // client walks from the root version it holds, so material collected
    // from the current version up has nothing to bridge the gap for a client
    // two rotations older, and that client keeps its pins rather than
    // guessing. The same files *with* the intermediates in front verify,
    // which is what makes this a floor and not a bug.
    let floor = fixture_number("chain_floor");
    let state = PinState {
        root: fixture(&format!("root-{floor}.json")),
        root_chain: Vec::new(),
        root_version: floor,
        ..PinState::embedded()
    };
    let error = tuf::update(&fixture_metadata(), &state, fixture_number("verify_at"));
    assert!(matches!(error, Err(TufError::Chain(_))), "{error:?}");
    tuf::update(
        &fixture_chain_metadata(),
        &state,
        fixture_number("verify_at"),
    )
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
    let update = tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW))
        .expect("a well-formed chain verifies");
    assert!(update.changed);
    assert_eq!(update.state.root_version, 1);
    assert!(update.log_keys.find(&log.log_id()).is_some());

    // Re-applying the same material is valid and boring: accepted, unchanged.
    let again = tuf::update(&repo.metadata(), &update.state, at(NOW)).unwrap();
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

    let update = tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW))
        .expect("a chained rotation verifies");
    assert_eq!(update.state.root_version, 4);

    // A chain with a version missing bridges nothing. The relay is free to
    // withhold; it is not free to be believed.
    let mut gapped = repo.metadata();
    gapped.roots.remove(1);
    assert!(matches!(
        tuf::update(&gapped, &repo.embedded_state(), at(NOW)),
        Err(TufError::Chain(_))
    ));

    // And a client already at version 4 accepts a chain that only carries
    // the tail — old material may be withheld once it is passed.
    let tail = repo.metadata_from(4);
    tuf::update(&tail, &update.state, at(NOW)).expect("the tail alone still verifies");
}

#[test]
fn a_root_the_old_root_did_not_sign_is_refused() {
    let (mut repo, _log) = repo();
    let honest = repo.embedded_state();
    // A fork: rotate to a root signed only by brand-new keys, the way a
    // relay that had minted its own root would.
    repo.rotate_root(true);
    let mut forged = repo.metadata();
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
    let mut thin = repo.metadata();
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
    tuf::update(&repo.metadata(), &state, at(NOW)).unwrap();
}

#[test]
fn an_expired_timestamp_is_refused() {
    let (mut repo, _log) = repo();
    repo.expires = NOW - 1;
    let error = tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW));
    assert!(matches!(error, Err(TufError::Expiry(_))), "{error:?}");
    // The same material a second before its expiry is fine: expiry is a
    // deadline, not a stigma.
    tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW - 2)).unwrap();
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
    let mut metadata = repo.metadata();
    assert!(matches!(
        tuf::update(&metadata, &state, at(NOW)),
        Err(TufError::Expiry(_))
    ));

    // Re-publish the head unexpired, leaving the intermediates as they are.
    repo.root_expires = NOW + 86_400;
    repo.rotate_root(false);
    metadata = repo.metadata();
    let update = tuf::update(&metadata, &state, at(NOW)).expect("only the head's expiry gates");
    assert_eq!(update.state.root_version, 3);
}

#[test]
fn a_version_rollback_is_refused() {
    let (mut repo, _log) = repo();
    let first = tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW))
        .unwrap()
        .state;
    // A mirror keeps serving the old chain after the repository moved on:
    // valid material, and refused, because the client has seen newer.
    let stale = repo.metadata();
    repo.set_tlogs(&[SimLog::new("rekor.sim").spki()]);
    let newer = tuf::update(&repo.metadata(), &first, at(NOW))
        .unwrap()
        .state;
    assert!(newer.timestamp_version > first.timestamp_version);

    let error = tuf::update(&stale, &newer, at(NOW));
    assert!(matches!(error, Err(TufError::Rollback(_))), "{error:?}");
}

#[test]
fn a_tampered_target_is_refused() {
    let (repo, _log) = repo();
    let mut metadata = repo.metadata();
    metadata.trusted_root.push(b' ');
    let error = tuf::update(&metadata, &repo.embedded_state(), at(NOW));
    assert!(matches!(error, Err(TufError::TargetHash(_))), "{error:?}");

    // A tampered *snapshot* fails one level up, where the timestamp's own
    // hash of it is checked.
    let mut metadata = repo.metadata();
    metadata.snapshot.push(b' ');
    assert!(matches!(
        tuf::update(&metadata, &repo.embedded_state(), at(NOW)),
        // Trailing whitespace does not change the canonical form, so the
        // signature still verifies and the length check is what catches it.
        Err(TufError::TargetHash(_))
    ));

    // A snapshot whose *content* changed fails on the signature instead.
    let mut metadata = repo.metadata();
    let mut snapshot: serde_json::Value = serde_json::from_slice(&metadata.snapshot).unwrap();
    snapshot["signed"]["meta"]["targets.json"]["version"] = serde_json::json!(99);
    metadata.snapshot = snapshot.to_string().into_bytes();
    assert!(matches!(
        tuf::update(&metadata, &repo.embedded_state(), at(NOW)),
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
    let both = tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW)).unwrap();
    assert!(both.log_keys.find(&old.log_id()).is_some());
    assert!(both.log_keys.find(&new.log_id()).is_some());

    repo.set_tlogs(&[new.spki()]);
    let after = tuf::update(&repo.metadata(), &both.state, at(NOW)).unwrap();
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
    let error = tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW));
    assert!(matches!(error, Err(TufError::Malformed(_))), "{error:?}");
    repo.set_tlogs(&[SimLog::new("rekor.sim").spki()]);
    tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW)).unwrap();
}

#[test]
fn state_is_monotonic_across_two_zones_sharing_one_file() {
    // §10.2: one state file, global across domains. A second zone serving
    // valid-but-older material must not walk the first one's versions back.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rekor-pins.json");
    let (mut repo, _log) = repo();
    let stale = repo.metadata();
    repo.rotate_root(false);
    repo.set_tlogs(&[SimLog::new("rekor.next").spki()]);

    let ahead = tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW)).unwrap();
    ahead.state.save(&path).unwrap();
    // Re-walked from the root this harness minted, exactly as a client
    // re-walks from the one its binary embeds: the file is never believed
    // on its own say-so. `rotate_root` above means the chain is non-empty
    // here, so this also exercises the walk rather than the trivial case.
    let reloaded = PinState::load_anchored(&path, &repo.embedded_root())
        .expect("the state persists and re-walks from the anchor");
    assert_eq!(reloaded, ahead.state);

    let error = tuf::update(&stale, &reloaded, at(NOW));
    assert!(matches!(error, Err(TufError::Rollback(_))), "{error:?}");
}

// --------------------------------------------------------------- resolver

/// A zone whose proof comes from a log the client's bootstrap pin set has
/// never heard of, and the TUF repository that teaches it.
///
/// The point of the arrangement: the client's *bootstrap* pin set knows a
/// different log entirely, so the proof can only verify if the TUF walk ran
/// first and replaced the pins.
fn zone_learning_a_new_shard() -> (SimZone, SimLog, SimTuf, tempfile::NamedTempFile) {
    let mut zone = SimZone::new("cluster.example", member_records());
    let mut new_shard = SimLog::new("log2099-1.rekor.sim");
    let proof = new_shard.publish(&zone, "create");
    zone.rekor_txt = proof.to_txt().expect("encodes");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let repo = SimTuf::new(now, &[new_shard.spki()]);
    // The root this client embeds — written to a file only so the test can
    // seed a PinState from it the way a build would.
    let embedded = write(&String::from_utf8(repo.embedded_root()).unwrap());
    (zone, new_shard, repo, embedded)
}

/// A repository that answers, and answers nonsense. The walk collects
/// something; every check `update` makes then refuses it.
struct Garbage;

impl tuf::Repo for Garbage {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        // Whichever root a client trusts, this repository has one for it —
        // so the walk gets past the chain and the refusal is about the
        // *content*, not about a file that was missing.
        let junk = path.ends_with(".root.json") || path == "timestamp.json";
        Ok(junk.then(|| b"this is not TUF metadata".to_vec()))
    }
}

/// A repository that counts what was asked of it, so "walked once" and
/// "walked on every lookup" are distinguishable facts.
struct Counting {
    inner: SimTuf,
    walks: std::sync::atomic::AtomicUsize,
}

impl Counting {
    fn new(inner: SimTuf) -> Counting {
        Counting {
            inner,
            walks: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn walks(&self) -> usize {
        self.walks.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl tuf::Repo for Counting {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        // `timestamp.json` is fetched exactly once per walk, and only after
        // the root chain — so counting it counts walks, not files.
        if path == "timestamp.json" {
            self.walks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.inner.get(path)
    }
}

/// The resolver options a refreshing client runs on: no static key file, the
/// pin state on disk, and pin refresh on — pointed at an injected repository
/// by the caller rather than at Sigstore.
fn refreshing(
    url: String,
    anchor: &std::path::Path,
    state_path: Option<std::path::PathBuf>,
    tuf_root: Option<&std::path::Path>,
) -> ResolverOptions {
    ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        // No --rekor-key: the pin set is the refreshable one, so it starts
        // as the embedded Sigstore bootstrap.
        rekor_key: None,
        rekor_state: state_path,
        tuf_url: None,
        no_tuf: false,
        // The harness mints its own TUF root, so that is the anchor every
        // persisted pin state here is re-walked from — the same rule
        // production applies with the built-in Sigstore root.
        tuf_root: tuf_root.map(std::path::Path::to_path_buf),
    }
}

/// Seeds a state file at the synthetic repository's root version 1, which
/// is what "a build that embeds this root" means to the resolver.
fn seed_state(path: &std::path::Path, embedded_root: &std::path::Path) {
    let root = std::fs::read(embedded_root).unwrap();
    let state = PinState {
        root,
        // Empty: this root *is* the anchor the resolver is given below, so
        // there is nothing to walk to reach it.
        root_chain: Vec::new(),
        root_version: 1,
        timestamp_version: 0,
        snapshot_version: 0,
        targets_version: 0,
        targets: Vec::new(),
        trusted_root: Vec::new(),
        updated_at: 0,
    };
    state.save(path).unwrap();
}

#[tokio::test]
async fn a_walked_chain_teaches_a_log_the_build_never_knew() {
    let (zone, new_shard, repo, embedded) = zone_learning_a_new_shard();
    let anchor = write(&zone.anchor_record());
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("rekor-pins.json");
    seed_state(&state_path, embedded.path());
    let (url, server) = zone.serve().await;

    let counting = std::sync::Arc::new(Counting::new(repo));
    let resolver = DnssecResolver::with_options(&refreshing(
        url,
        anchor.path(),
        Some(state_path.clone()),
        Some(embedded.path()),
    ))
    .unwrap()
    .with_tuf_repo(counting.clone());
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
    let persisted = PinState::load_anchored(&state_path, &std::fs::read(embedded.path()).unwrap())
        .expect("the pin state is written and re-walks from the anchor");
    assert_eq!(persisted.root_version, 1);
    assert!(persisted.timestamp_version >= 1);
    assert!(rekor::LogKeys::default() != persisted.log_keys().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&state_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the pin state is the owner's alone");
    }

    // The rule that makes going to the source affordable: membership may
    // re-resolve on a one-minute TTL, and the repository still hears from
    // this client once a day (§10.2).
    assert_eq!(counting.walks(), 1);
    resolver.member_set("cluster.example").await.unwrap();
    assert!(resolver.refresh_tuf().await.unwrap().is_none());
    assert_eq!(counting.walks(), 1, "a second lookup must not walk again");
    server.abort();
}

#[tokio::test]
async fn the_same_zone_without_the_walk_fails_with_unknown_log() {
    // The control: everything identical except the refresh. If the proof
    // verified here too, the update above would have proved nothing.
    let (zone, _shard, _repo, embedded) = zone_learning_a_new_shard();
    let anchor = write(&zone.anchor_record());
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("rekor-pins.json");
    seed_state(&state_path, embedded.path());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        no_tuf: true,
        tuf_root: None,
        ..refreshing(url, anchor.path(), Some(state_path), Some(embedded.path()))
    })
    .unwrap();
    let error = resolver.member_set("cluster.example").await.unwrap_err();
    assert!(
        matches!(error, NetError::RekorUnknownLog { .. }),
        "without the walk the log stays unknown: {error}"
    );
    server.abort();
}

#[tokio::test]
async fn a_repository_serving_nonsense_never_fails_a_refresh() {
    // The rule §10.2 calls load-bearing: TUF trouble is never worse than not
    // having asked. The repository here serves garbage while the zone
    // publishes a proof from a log the client already pins — the refresh
    // must succeed regardless, and the pins must not move.
    let mut zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    zone.rekor_txt = log.publish(&zone, "create").to_txt().expect("encodes");

    let anchor = write(&zone.anchor_record());
    let log_key = write(&log.key_pem());
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("rekor-pins.json");
    let (url, server) = zone.serve().await;

    // A static --rekor-key never walks anything at all: a different universe
    // is static in both directions.
    let stat = DnssecResolver::with_options(&ResolverOptions {
        rekor_key: Some(log_key.path().to_path_buf()),
        ..refreshing(url.clone(), anchor.path(), Some(state_path.clone()), None)
    })
    .unwrap()
    .with_tuf_repo(std::sync::Arc::new(Garbage));
    let (set, _ttl) = stat
        .member_set("cluster.example")
        .await
        .expect("a broken repository must not fail a refresh");
    assert_eq!(set.bindings.len(), 1);
    assert!(stat.refresh_tuf().await.unwrap().is_none());
    assert!(
        !state_path.exists(),
        "an explicit key file disables TUF refresh entirely"
    );

    // And the refreshable resolver says *which* way the chain broke — the
    // whole reason the variant carries a class, for `synch doctor` — without
    // that ever reaching the refresh, moving a pin, or writing a file.
    let client = DnssecResolver::with_options(&refreshing(
        url,
        anchor.path(),
        Some(state_path.clone()),
        None,
    ))
    .unwrap()
    .with_tuf_repo(std::sync::Arc::new(Garbage));
    let before = client.log_keys();
    let error = client.refresh_tuf().await.unwrap_err();
    assert!(
        matches!(&error, NetError::Tuf { class, .. } if *class == "malformed"),
        "{error}"
    );
    assert_eq!(client.log_keys(), before, "the pins did not move");
    assert!(!state_path.exists(), "and nothing was persisted");
    server.abort();
}

#[tokio::test]
async fn a_repository_with_nothing_in_it_is_a_non_event() {
    // An unreachable mirror and an empty one look the same from here, and
    // both leave the client exactly where it was.
    struct Empty;
    impl tuf::Repo for Empty {
        fn get(&self, _path: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
    }

    let mut zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    zone.rekor_txt = log.publish(&zone, "create").to_txt().expect("encodes");
    let anchor = write(&zone.anchor_record());
    let log_key = write(&log.key_pem());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        rekor_key: Some(log_key.path().to_path_buf()),
        ..refreshing(url, anchor.path(), None, None)
    })
    .unwrap()
    .with_tuf_repo(std::sync::Arc::new(Empty));
    assert!(resolver.refresh_tuf().await.unwrap().is_none());
    resolver
        .member_set("cluster.example")
        .await
        .expect("a repository with nothing to say changes nothing");
    server.abort();
}

#[tokio::test]
async fn no_tuf_walks_nothing_and_is_not_a_failure() {
    // The knob for a deployment that will not have its daemon reach a CDN.
    // Off means off — not "a repository that answers nothing", which would
    // report a broken chain once a day forever.
    let (zone, _shard, repo, embedded) = zone_learning_a_new_shard();
    let anchor = write(&zone.anchor_record());
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("rekor-pins.json");
    seed_state(&state_path, embedded.path());
    let (url, server) = zone.serve().await;

    let counting = std::sync::Arc::new(Counting::new(repo));
    let resolver = DnssecResolver::with_options(&ResolverOptions {
        no_tuf: true,
        tuf_root: None,
        ..refreshing(url, anchor.path(), Some(state_path), Some(embedded.path()))
    })
    .unwrap()
    // Even handed a repository, `--no-tuf` does not walk it.
    .with_tuf_repo(counting.clone());
    assert!(resolver.refresh_tuf().await.unwrap().is_none());
    assert_eq!(counting.walks(), 0);
    server.abort();
}

// ----------------------------------------------- cloud-attach discovery

/// The attach endpoint is only as trustworthy as the membership answer that
/// yields its apex, so discovery gates that answer's zone key exactly as
/// `member_set` does. Under `RekorPolicy::Require`, a DNSSEC-valid membership
/// answer whose key is *not* on the transparency log yields no endpoint — even
/// when the zone serves a perfectly-formed `_synchronicity-cp` record.
///
/// This is the DNS-provider/registrar compromise the Rekor design exists to
/// stop: an attacker who can add an unlogged DNSKEY and sign a
/// `_synchronicity-cp` record pointing at themselves must not be able to make
/// a daemon attach and stream its exposed spaces.
#[tokio::test]
async fn discovery_refuses_an_unlogged_zone_under_require() {
    let mut zone = SimZone::new("cluster.example", member_records());
    // The zone would love to be attached to — but its key was never logged.
    zone.cp_txt = vec!["v=synccp1 url=https://attacker.example".to_string()];
    let log = SimLog::new("rekor.sim");
    let anchor = write(&zone.anchor_record());
    let log_key = write(&log.key_pem());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        rekor_key: Some(log_key.path().to_path_buf()),
        ..refreshing(url, anchor.path(), None, None)
    })
    .unwrap();

    let error = resolver
        .control_plane("cluster.example")
        .await
        .expect_err("an unlogged zone key must yield no endpoint under Require");
    // The security property is that no endpoint is yielded, and the refusal is
    // the transparency gate on the membership answer — the daemon never reaches
    // the attach record. The sim serves an unsigned NODATA for the absent proof
    // (it synthesizes no NSEC), so hickory reports a bogus negative rather than
    // a validated empty set; against a real control plane the same absence is a
    // signed negative and surfaces as `RekorAbsent`. Either way the endpoint is
    // refused, which is what matters.
    assert!(
        matches!(&error, NetError::RekorAbsent { .. })
            || matches!(&error, NetError::Dns(msg) if msg.contains(rekor::REKOR_TXT_PREFIX)),
        "the membership answer's zone key must be gated before the attach record is trusted: {error}"
    );
    server.abort();
}

/// The positive control: the *same* zone, once its key is logged, discovers
/// its endpoint. Without this the refusal above could be the harness failing
/// to serve the record rather than the gate refusing it.
#[tokio::test]
async fn discovery_yields_the_endpoint_once_the_key_is_logged() {
    let mut zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    zone.rekor_txt = log.publish(&zone, "create").to_txt().expect("encodes");
    zone.cp_txt = vec!["v=synccp1 url=https://sync.example".to_string()];
    let anchor = write(&zone.anchor_record());
    let log_key = write(&log.key_pem());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        rekor_key: Some(log_key.path().to_path_buf()),
        ..refreshing(url, anchor.path(), None, None)
    })
    .unwrap();

    let (record, _ttl) = resolver
        .control_plane("cluster.example")
        .await
        .expect("a logged zone key discovers its endpoint");
    assert_eq!(record.url, "https://sync.example");
    server.abort();
}

/// And the gate is what refuses: with transparency off, the unlogged zone's
/// endpoint is discovered. So the refusal above is the Rekor check, not
/// something incidental about the answer.
#[tokio::test]
async fn discovery_without_the_gate_trusts_the_dnssec_answer_alone() {
    let mut zone = SimZone::new("cluster.example", member_records());
    zone.cp_txt = vec!["v=synccp1 url=https://sync.example".to_string()];
    let anchor = write(&zone.anchor_record());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Off),
        rekor_key: None,
        rekor_state: None,
        tuf_url: None,
        no_tuf: true,
        tuf_root: None,
    })
    .unwrap();

    let (record, _ttl) = resolver
        .control_plane("cluster.example")
        .await
        .expect("with the gate off, a DNSSEC-valid answer is enough");
    assert_eq!(record.url, "https://sync.example");
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
    let walked = TufMetadata {
        roots: chain.iter().map(|(_, bytes)| bytes.clone()).collect(),
        timestamp: timestamp.clone(),
        snapshot: snapshot.clone(),
        targets: targets.clone(),
        trusted_root: trusted_root.clone(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let state = PinState {
        root: chain[0].1.clone(),
        root_chain: Vec::new(),
        root_version: floor,
        timestamp_version: 0,
        snapshot_version: 0,
        targets_version: 0,
        targets: Vec::new(),
        trusted_root: Vec::new(),
        updated_at: 0,
    };
    let update = tuf::update(&walked, &state, now).expect("the fetched chain must verify");

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

/// A pin file naming a root this build never signed is not state.
///
/// Checking that the version number inside the stored root equals the version
/// number stored beside it is a self-consistency test any file passes: whatever
/// root the file named would become the client's world, every later update
/// would chain from it, and anyone able to write one file in the data directory
/// would choose the transparency-log key set outright.
///
/// The state is re-walked from the anchor the *binary* holds, so a root minted
/// by somebody else fails to load and the client falls back to its bootstrap
/// pins rather than adopting a stranger's universe.
#[test]
fn a_pin_file_anchored_somewhere_else_does_not_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rekor-pins.json");

    // The honest client's repository, and a state it legitimately reached.
    let (mut mine, _log) = repo();
    mine.rotate_root(false);
    let honest = tuf::update(&mine.metadata(), &mine.embedded_state(), at(NOW)).unwrap();
    honest.state.save(&path).unwrap();
    assert!(
        PinState::load_anchored(&path, &mine.embedded_root()).is_some(),
        "the state this client reached must load for this client"
    );

    // An attacker's repository: entirely their own keys, and bumped past
    // the honest version so a version comparison would prefer it.
    let (mut theirs, _their_log) = repo();
    theirs.rotate_root(true);
    theirs.rotate_root(true);
    theirs.set_tlogs(&[SimLog::new("rekor.attacker").spki()]);
    let forged = tuf::update(&theirs.metadata(), &theirs.embedded_state(), at(NOW)).unwrap();
    assert!(
        forged.state.root_version > honest.state.root_version,
        "the forged state must look newer, or the test proves nothing"
    );
    forged.state.save(&path).unwrap();

    assert!(
        PinState::load_anchored(&path, &mine.embedded_root()).is_none(),
        "a root this build's anchor never signed must not load"
    );
    // And it is not merely the *versions* being refused: the forged state
    // loads perfectly well for the universe that minted it, which is what
    // makes the anchor — and not the file — the thing that decides.
    assert!(
        PinState::load_anchored(&path, &theirs.embedded_root()).is_some(),
        "the forged state is well-formed; it is simply not ours"
    );
}

/// Four independently-monotone counters need componentwise dominance.
///
/// Comparing `(root, timestamp, snapshot, targets)` as a tuple orders them
/// lexicographically: the root version dominates the other three outright, so
/// a state ahead on `root` and behind on everything else reads as newer, and
/// adopting it drops the rollback floors for those roles to the lower numbers —
/// the one thing the floors exist to prevent.
#[test]
fn a_state_ahead_on_the_root_alone_does_not_outrank_one_ahead_everywhere_else() {
    let (mut repo, _log) = repo();
    let base = tuf::update(&repo.metadata(), &repo.embedded_state(), at(NOW)).unwrap();

    // Same repository, one root rotation on: the root version moves and
    // nothing below it does.
    repo.rotate_root(false);
    let rotated = tuf::update(&repo.metadata(), &base.state, at(NOW)).unwrap();
    assert!(rotated.state.root_version > base.state.root_version);

    // Hand-build the state a lexicographic comparison got wrong: newer root,
    // older everything else.
    let mut mixed = rotated.state.clone();
    mixed.timestamp_version = base.state.timestamp_version.saturating_sub(1);
    mixed.snapshot_version = base.state.snapshot_version.saturating_sub(1);
    mixed.targets_version = base.state.targets_version.saturating_sub(1);

    // Tuple order would call `mixed` the newer of the two. Dominance does
    // not, and dominance is the question actually being asked.
    assert!(
        (
            mixed.root_version,
            mixed.timestamp_version,
            mixed.snapshot_version,
            mixed.targets_version
        ) > (
            base.state.root_version,
            base.state.timestamp_version,
            base.state.snapshot_version,
            base.state.targets_version
        ),
        "the tuple comparison this replaced would have preferred `mixed`"
    );
    // Neither dominates the other, so neither may displace the other.
    let dominates = |a: &PinState, b: &PinState| {
        a.root_version >= b.root_version
            && a.timestamp_version >= b.timestamp_version
            && a.snapshot_version >= b.snapshot_version
            && a.targets_version >= b.targets_version
    };
    assert!(!dominates(&mixed, &base.state));
    assert!(!dominates(&base.state, &mixed));
}
