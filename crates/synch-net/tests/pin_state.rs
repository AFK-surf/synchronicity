//! What the pin file has to get right, now that its contents are believed.
//!
//! `<data-dir>/rekor-pins.json` decides which transparency log keys a client
//! accepts a proof from and which endpoints a monitor reads. It is read as
//! written: the data directory is the owner's own (§9.3), and a writer inside
//! it can already put a `source='static'` binding straight into `synch.db`, so
//! re-deriving the pin set from the binary on every load defended against
//! nobody who was not already past the gate.
//!
//! Two things still have to hold. The state must round-trip — a walk's result
//! has to come back whole, or the client silently drops to bootstrap pins on
//! every restart. And it must not be read under the wrong *repository*:
//! [`tuf::update`] chains from the stored root rather than re-walking from the
//! binary's anchor, so a state carried across a `--tuf-root` switch would
//! extend the wrong chain forever.
//!
//! The rest is the clock the same file carries: `updated_at` is a monotonic
//! floor for the TUF expiry checks, so it must be bounded against the real
//! clock in one direction and must not be able to make an expiry check vacuous
//! in the other.

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
    let mut repo = SimTuf::new(NOW as i64, &[&honest]);
    // A non-empty stored root chain, so the round-trip carries one.
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
    // `update` enforces the targets rollback floor against these bytes, so
    // the file has to carry them.
    assert!(!loaded.targets.is_empty());
}

/// A state accumulated under one TUF repository is not read under another.
///
/// Not a tamper check — the file is this client's own. It is the `--tuf-root`
/// switch: [`tuf::update`] chains from the stored root rather than re-walking
/// from the binary's anchor, so a state kept across that switch would go on
/// extending the old repository's chain and never notice. Falling back to the
/// bootstrap costs one refresh and lands on the repository actually asked for.
#[test]
fn a_state_from_another_tuf_repository_is_not_loaded() {
    let (dir, repo, _, _) = accepted();
    let anchor = repo.embedded_root();

    let stranger = SimTuf::new(NOW as i64, &[&SimLog::new("rekor.other")]);
    assert_eq!(
        PinState::load_anchored(&path(&dir), &stranger.embedded_root()),
        None,
        "a state from another repository must not be read under this anchor"
    );
    // The same file under the anchor it was written for, so the assertion
    // above is about provenance and not about the harness.
    assert!(PinState::load_anchored(&path(&dir), &anchor).is_some());

    // And the digest is what carries that, rather than anything derived: a
    // file naming some other repository's root is refused even though every
    // other byte in it is this client's own.
    rewrite(&path(&dir), |state| {
        state["anchor_digest"] = serde_json::Value::String(base64_encode(
            &synch_net::rekor::sha256(&stranger.embedded_root()),
        ));
    });
    assert_eq!(PinState::load_anchored(&path(&dir), &anchor), None);
}

/// A file written to an older format is ignored rather than half-read.
#[test]
fn a_state_in_a_format_this_build_does_not_know_is_not_loaded() {
    let (dir, repo, _, _) = accepted();
    rewrite(&path(&dir), |state| {
        state["version"] = serde_json::json!(1);
    });
    assert_eq!(
        PinState::load_anchored(&path(&dir), &repo.embedded_root()),
        None,
        "an older on-disk format lands on the bootstrap pins"
    );
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
    let repo = SimTuf::new(NOW as i64, &[&honest]);
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
