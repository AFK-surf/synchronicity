//! The pin file is authenticated end to end against the binary's TUF root.
//!
//! `<data-dir>/rekor-pins.json` decides which transparency log keys a client
//! accepts a proof from and which endpoints a monitor reads. It is a local file,
//! so the whole of its authority has to come from re-verification: the stored
//! root chain re-walked from the root *this build* holds, and the stored
//! `targets.json` re-checked against that root and against the `trusted_root`
//! it names. Anything less and the version numbers in the file are all that
//! stands between a local writer and the pin set — permanently, because a
//! rewritten set of version floors makes every honest refresh a rollback.
//!
//! The second half is the clock the same file carries: `updated_at` is a
//! monotonic floor for the TUF expiry checks, so it must be bounded against the
//! real clock in one direction and must not be able to make an expiry check
//! vacuous in the other.

use synch_net::{
    rekor::base64_encode,
    sim::{SimLog, SimTuf},
    tuf::{self, PinState},
};

const NOW: u64 = 1_760_000_000;

/// A repository, an accepted state, and the file it was written to.
fn accepted() -> (tempfile::TempDir, SimTuf, SimLog, PinState) {
    let dir = tempfile::tempdir().unwrap();
    let honest = SimLog::new("rekor.honest");
    let mut repo = SimTuf::new(NOW as i64, &[honest.spki()]);
    // A non-empty stored root chain, so the re-walk is genuinely exercised.
    repo.rotate_root(false);
    let accepted = tuf::update(&repo.metadata(), &repo.embedded_state(), NOW)
        .expect("the honest chain verifies");
    accepted
        .state
        .save(&dir.path().join("rekor-pins.json"))
        .unwrap();
    (dir, repo, honest, accepted.state)
}

fn path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("rekor-pins.json")
}

fn rewrite(path: &std::path::Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    edit(&mut state);
    std::fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
}

/// The state a walk accepted loads back, whole.
#[test]
fn an_accepted_pin_state_round_trips_through_the_file() {
    let (dir, repo, honest, state) = accepted();
    let loaded = PinState::load_anchored(&path(&dir), &repo.embedded_root())
        .expect("the state this build wrote must load");
    assert_eq!(loaded, state);
    assert!(
        loaded
            .log_keys()
            .expect("a trusted root implies a pin set")
            .find(&honest.log_id())
            .is_some(),
        "the pinned key is the one the verified trusted root names"
    );
    // The re-verification is over the targets role as well as the root chain,
    // so the file has to carry it.
    assert!(!loaded.targets.is_empty());
}

/// Swapping the *target* while keeping the genuine root chain is refused.
///
/// This is the cheap attack: a root chain is public material, so an attacker
/// holds it, and the only thing that ever made `trusted_root` believable was
/// sitting in the same file. With the targets role persisted and re-checked, the
/// substituted target does not hash to what the signed `targets.json` names and
/// the file is not loaded at all.
#[test]
fn a_substituted_trusted_root_is_refused_even_behind_a_genuine_root_chain() {
    let (dir, repo, honest, state) = accepted();
    let attacker = SimLog::new("rekor.attacker");

    let mut trusted_root: serde_json::Value = serde_json::from_slice(&state.trusted_root).unwrap();
    trusted_root["tlogs"][0]["publicKey"]["rawBytes"] =
        serde_json::Value::String(base64_encode(&attacker.spki()));
    trusted_root["tlogs"][0]["baseUrl"] =
        serde_json::Value::String("https://log.attacker.example".into());
    rewrite(&path(&dir), |state| {
        state["trusted_root"] =
            serde_json::Value::String(base64_encode(&serde_json::to_vec(&trusted_root).unwrap()));
        // And the version floors parked at the ceiling, which is what would
        // have made the substitution permanent by turning every honest refresh
        // into a rollback.
        state["targets_version"] = serde_json::json!(u64::MAX);
        state["timestamp_version"] = serde_json::json!(u64::MAX);
        state["snapshot_version"] = serde_json::json!(u64::MAX);
    });

    assert_eq!(
        PinState::load_anchored(&path(&dir), &repo.embedded_root()),
        None,
        "a trusted root the stored targets role does not name must not load"
    );

    // Which is the whole point: the client runs on the bootstrap pins, the
    // attacker's log is not pinned, and the honest walk still moves.
    let update = tuf::update(
        &repo.metadata(),
        &PinState::anchored(&repo.embedded_root()),
        NOW,
    )
    .expect("the honest chain still verifies");
    assert!(update.log_keys.find(&honest.log_id()).is_some());
    assert!(update.log_keys.find(&attacker.log_id()).is_none());
}

/// Every other field of the file is re-derived too.
#[test]
fn a_pin_file_that_does_not_check_out_against_the_binary_is_not_loaded() {
    let (dir, repo, _, state) = accepted();
    let anchor = repo.embedded_root();

    // A targets role the walked root's targets keys did not sign.
    let mut forged: serde_json::Value = serde_json::from_slice(&state.targets).unwrap();
    forged["signatures"] = serde_json::json!([]);
    for (field, value) in [
        (
            "targets",
            serde_json::Value::String(base64_encode(&serde_json::to_vec(&forged).unwrap())),
        ),
        // A targets role for some other version than the one recorded beside it.
        ("targets_version", serde_json::json!(u64::MAX - 1)),
        // A root the stored chain does not walk to.
        ("root", serde_json::Value::String(base64_encode(&anchor))),
        // A root version the walk does not produce.
        ("root_version", serde_json::json!(1)),
        // The targets role removed outright.
        ("targets", serde_json::Value::String(String::new())),
    ] {
        let (dir, repo, _, _) = accepted();
        rewrite(&path(&dir), |state| state[field] = value.clone());
        assert_eq!(
            PinState::load_anchored(&path(&dir), &repo.embedded_root()),
            None,
            "a file with a tampered {field} must not load"
        );
    }

    // And an unrelated build's anchor does not load this build's file.
    let stranger = SimTuf::new(NOW as i64, &[SimLog::new("rekor.other").spki()]);
    assert_eq!(
        PinState::load_anchored(&path(&dir), &stranger.embedded_root()),
        None
    );
    // The untouched file still loads under the right anchor, so the assertions
    // above are about the tampering and not about the harness.
    assert!(PinState::load_anchored(&path(&dir), &anchor).is_some());
}

/// A `now` past `i64::MAX` does not make every TUF expiry check pass.
///
/// `updated_at` is read from the file and floors the clock the expiry checks
/// see. A signed comparison turns `u64::MAX` into `-1`, at which point nothing
/// has ever expired and ten-year-old material from a hostile mirror is adopted —
/// and `u64::MAX` is the one value that also clears the refresh interval gate.
#[test]
fn no_clock_value_makes_a_tuf_expiry_check_vacuous() {
    let honest = SimLog::new("rekor.honest");
    let repo = SimTuf::new(NOW as i64, &[honest.spki()]);
    let metadata = repo.metadata();
    let state = repo.embedded_state();

    // The material verifies at the moment it was minted.
    tuf::update(&metadata, &state, NOW).expect("fresh material verifies");

    // And is refused at every clock past its expiry, including the extremes.
    for at in [
        NOW + 10 * 365 * 86_400,
        u64::from(u32::MAX),
        i64::MAX as u64,
        i64::MAX as u64 + 1,
        u64::MAX,
    ] {
        let refused = tuf::update(&metadata, &state, at);
        assert!(
            matches!(refused, Err(tuf::TufError::Expiry(_))),
            "material ten years expired must not be adopted at {at}: {refused:?}"
        );
    }
}

/// A retired shard's window is judged in the same unsigned domain.
#[test]
fn a_shards_service_window_is_never_vacuous_either() {
    let trusted_root = serde_json::json!({"tlogs": [{
        "baseUrl": "https://retired.example",
        "publicKey": {
            "rawBytes": "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
            "validFor": { "start": "2021-01-12T11:53:27Z", "end": "2025-09-23T00:00:00Z" },
        },
    }]})
    .to_string()
    .into_bytes();
    let logs = tuf::tlogs(&trusted_root).expect("one shard");
    for at in [i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
        assert!(
            !logs[0].valid_at(at),
            "a closed window must stay closed at {at}"
        );
    }
    assert!(logs[0].valid_at(1_700_000_000));
}
