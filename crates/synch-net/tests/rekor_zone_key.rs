//! Zone-key transparency end to end (docs/REKOR-ZONE-KEY.md §9).
//!
//! One simulated zone, one simulated log, and the real verifier. The
//! positive case proves a correctly logged key is accepted through the whole
//! path — validated TXT, apex DNSKEY, proof record, offline verification.
//! Every other case takes that same proof and breaks exactly one thing, so a
//! passing verification can never be an accident of the harness: possession,
//! binding, inclusion, checkpoint, unknown log, absent record.

use synch_net::{
    dns::{DnssecResolver, RekorPolicy, ResolverOptions},
    error::NetError,
    rekor::{self, LogKeys, ProofError, RekorProof, ZoneKey},
    sim::{SimLog, SimZone},
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

/// A zone whose key is logged, and the log that logged it.
fn logged_zone() -> (SimZone, SimLog, RekorProof) {
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let proof = log.publish(&zone, "create", None);
    (zone, log, proof)
}

fn verify(proof: &RekorProof, zone: &SimZone, log: &SimLog) -> Result<(), ProofError> {
    let apex = zone.apex();
    let rdata = zone.dnskey_rdata();
    let key = ZoneKey {
        apex: &apex,
        key_tag: zone.key_tag(),
        dnskey_rdata: &rdata,
    };
    rekor::verify(proof, &key, &LogKeys::parse(&log.key_pem()).unwrap()).map(|_| ())
}

#[test]
fn a_logged_zone_key_verifies_offline() {
    let (zone, log, proof) = logged_zone();
    verify(&proof, &zone, &log).expect("a correctly logged key must verify");

    // And it survives the round trip through a TXT record, which is how it
    // actually reaches a client.
    let decoded = RekorProof::from_txt(&proof.to_txt()).unwrap();
    assert_eq!(decoded, proof);
    verify(&decoded, &zone, &log).unwrap();
}

#[test]
fn a_forged_dsse_signature_fails_possession() {
    let (zone, _, mut proof) = logged_zone();
    proof.dsse_signature[0] ^= 0x01;
    // The entry no longer hashes to the leaf that was logged, so re-log it:
    // otherwise inclusion would fail first and possession would go untested.
    let mut log = SimLog::new("rekor.sim");
    proof.log_id = log.log_id();
    proof.log_index = log.append(&proof.entry_bytes());
    log.refresh(&mut proof);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Possession(_))
    ));
}

#[test]
fn a_key_logged_for_another_apex_fails_binding() {
    // The attack this whole design exists to make loud: a key that is on the
    // public record, but under a name that is not this zone.
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let mut statement = zone.zone_key_statement("create", None);
    statement.apex = "other.example.".into();
    statement.subject_name = "other.example.".into();
    let proof = log.log_statement(&zone, &statement);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));
}

#[test]
fn a_statement_over_another_key_fails_binding() {
    let zone = SimZone::new("cluster.example", member_records());
    let stranger = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    // Right apex, right key tag, wrong key bytes: the subject digest is the
    // only thing that can tell these apart, and it must.
    let mut statement = zone.zone_key_statement("create", None);
    statement.subject_sha256 = hex::encode(rekor::sha256(&stranger.dnskey_rdata()));
    let proof = log.log_statement(&zone, &statement);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));

    // A record for the other half of a rollover window is refused here too;
    // selecting the right one by key tag is the caller's job.
    let mut statement = zone.zone_key_statement("rollover", Some(1));
    statement.key_tag = zone.key_tag().wrapping_add(1);
    let proof = log.log_statement(&zone, &statement);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));
}

#[test]
fn a_broken_audit_path_fails_inclusion() {
    // A tree of one leaf has an empty audit path and proves nothing about
    // path handling; put the entry among neighbours first.
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    log.append(b"an earlier entry");
    let mut proof = log.publish(&zone, "create", None);
    log.append(b"a later entry");
    log.refresh(&mut proof);
    verify(&proof, &zone, &log).expect("the proof is sound before it is broken");
    assert!(!proof.inclusion_path.is_empty());

    let mut truncated = proof.clone();
    truncated.inclusion_path.pop();
    assert!(matches!(
        verify(&truncated, &zone, &log),
        Err(ProofError::Inclusion(_))
    ));

    let mut tampered = proof.clone();
    tampered.inclusion_path.push([0u8; 32]);
    assert!(matches!(
        verify(&tampered, &zone, &log),
        Err(ProofError::Inclusion(_))
    ));

    // A path that was correct for an older tree does not reach a newer
    // root: the checkpoint and the path have to describe the same tree.
    let mut stale = proof.clone();
    log.append(b"some other entry");
    log.append(b"and another");
    stale.checkpoint = log.checkpoint();
    assert!(matches!(
        verify(&stale, &zone, &log),
        Err(ProofError::Inclusion(_))
    ));

    // Refreshing the proof against the grown tree fixes it — the operation
    // the control plane's weekly refresh performs.
    let mut refreshed = proof;
    log.refresh(&mut refreshed);
    verify(&refreshed, &zone, &log).unwrap();
}

#[test]
fn a_checkpoint_from_another_log_fails() {
    let (zone, log, mut proof) = logged_zone();
    // Same entry, same tree, a perfectly valid note — signed by a log this
    // client does not pin. "The log vouches" means *this* log.
    let other = SimLog::new("impostor.sim");
    proof.checkpoint = other.note(1, log.root());
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Checkpoint(_))
    ));

    // Naming the other log outright is a different failure: the entry lives
    // somewhere this client was never told to trust.
    proof.log_id = other.log_id();
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::UnknownLog(_))
    ));
}

#[test]
fn a_pin_set_that_names_no_log_accepts_nothing() {
    let (zone, _, proof) = logged_zone();
    let apex = zone.apex();
    let rdata = zone.dnskey_rdata();
    let key = ZoneKey {
        apex: &apex,
        key_tag: zone.key_tag(),
        dnskey_rdata: &rdata,
    };
    assert!(matches!(
        rekor::verify(&proof, &key, &LogKeys::default()),
        Err(ProofError::UnknownLog(_))
    ));
}

#[tokio::test]
async fn a_zone_that_publishes_its_proof_resolves_under_require() {
    let (mut zone, log, proof) = logged_zone();
    // A rollover window publishes two records; the client picks by key tag
    // and must not be confused by the other one.
    let mut other_log = SimLog::new("rekor.sim");
    let stranger = SimZone::new("cluster.example", member_records());
    let other = other_log.publish(&stranger, "rollover", Some(zone.key_tag()));
    zone.rekor_txt = vec![other.to_txt(), proof.to_txt()];

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
    let (set, _ttl) = resolver
        .member_set("cluster.example")
        .await
        .expect("a zone whose key is on the public record resolves");
    assert_eq!(set.bindings.len(), 1);
    server.abort();
}

#[tokio::test]
async fn an_absent_proof_record_refuses_under_require_and_resolves_under_off() {
    // Phase 0 of the rollout, seen from a phase 2 client: a control plane
    // that has not published yet. Under `require` the answer is discarded
    // and the caller keeps its cached set; under `off` nothing changed.
    //
    // The sim answers a missing name with a bare NOERROR and no NSEC, so
    // this absence surfaces as the validator refusing an unproven negative
    // — fail closed either way. The `RekorAbsent` class itself is asserted
    // below, where the name exists and the record for this key does not.
    let zone = SimZone::new("cluster.example", member_records());
    let anchor = write(&zone.anchor_record());
    let log_key = write(&SimLog::new("rekor.sim").key_pem());
    let (url, server) = zone.serve().await;

    let options = |policy| ResolverOptions {
        doh_url: Some(url.clone()),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(policy),
        rekor_key: Some(log_key.path().to_path_buf()),
        rekor_state: None,
    };

    let strict = DnssecResolver::with_options(&options(RekorPolicy::Require)).unwrap();
    strict
        .member_set("cluster.example")
        .await
        .expect_err("a zone with no proof record must be refused under require");

    let lenient = DnssecResolver::with_options(&options(RekorPolicy::Off)).unwrap();
    let (set, _ttl) = lenient
        .member_set("cluster.example")
        .await
        .expect("the same zone resolves with the requirement off");
    assert_eq!(set.bindings.len(), 1);

    // The TXT lookup itself never consults the log: it is the member-set
    // path that gained a requirement, not the resolver's every query.
    strict.lookup_txt("cluster.example").await.unwrap();
    server.abort();
}

#[tokio::test]
async fn a_proof_record_for_another_key_reads_as_absent() {
    let mut zone = SimZone::new("cluster.example", member_records());
    let stranger = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    zone.rekor_txt = vec![log.publish(&stranger, "create", None).to_txt()];

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
    let error = resolver.member_set("cluster.example").await.unwrap_err();
    assert!(
        matches!(error, NetError::RekorAbsent { .. }),
        "a record for another key tag is no record for this one: {error}"
    );
    server.abort();
}

#[tokio::test]
async fn a_garbled_proof_record_is_refused_as_malformed() {
    let mut zone = SimZone::new("cluster.example", member_records());
    zone.rekor_txt = vec!["this is not a proof".to_string()];

    let anchor = write(&zone.anchor_record());
    let log_key = write(&SimLog::new("rekor.sim").key_pem());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        rekor_key: Some(log_key.path().to_path_buf()),
        rekor_state: None,
    })
    .unwrap();
    let error = resolver.member_set("cluster.example").await.unwrap_err();
    assert!(
        matches!(error, NetError::RekorMalformed { .. }),
        "a record that does not decode is malformed, not absent: {error}"
    );
    server.abort();
}

/// The checked-in proof both halves of the system are asserted against.
///
/// The control plane builds these bytes and this client reads them; a
/// fixture neither side can quietly regenerate is what keeps the Gleam
/// encoder and the Rust decoder from drifting apart in opposite directions.
/// It lives beside the Gleam tests because those can only read files from
/// their own tree; this side reaches across for it deliberately.
fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../control-plane/test/fixtures/rekor")
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

#[test]
fn the_shared_fixture_decodes_and_verifies() {
    let proof = RekorProof::decode(&fixture("proof.bin")).expect("the fixture is a v1 proof");

    // Every part the Gleam encoder is asserted against, asserted here too:
    // if the two ever disagree, one of these fails rather than both suites
    // passing against different bytes.
    assert_eq!(proof.dsse_payload, fixture("statement.json"));
    assert_eq!(proof.dsse_signature, fixture("dsse-signature.bin"));
    assert_eq!(proof.checkpoint, fixture("checkpoint.txt"));
    assert_eq!(proof.log_id.to_vec(), fixture("log-id.bin"));
    assert_eq!(
        proof.inclusion_path.concat(),
        fixture("inclusion-path.bin"),
        "the audit path is a flat run of 32-byte hashes"
    );
    assert_eq!(proof.key_tag.to_string(), fixture_field("key_tag"));
    assert_eq!(proof.log_index.to_string(), fixture_field("log_index"));
    // Re-encoding is byte-identical: the format has exactly one rendering.
    assert_eq!(proof.encode(), fixture("proof.bin"));

    let apex = fixture_field("apex");
    let dnskey_rdata = fixture("dnskey.bin");
    let key = ZoneKey {
        apex: &apex,
        key_tag: proof.key_tag,
        dnskey_rdata: &dnskey_rdata,
    };
    let logs = LogKeys::parse(&String::from_utf8(fixture("log-key.pem")).unwrap()).unwrap();
    let verified = rekor::verify(&proof, &key, &logs).expect("the fixture must verify");
    assert_eq!(verified.action, fixture_field("action"));
    assert_eq!(verified.log_index, proof.log_index);
}

/// Rewrites the shared fixture. Not part of the suite — a zone key and a log
/// key are minted here, so running it invalidates every byte downstream of
/// them; it exists so the fixture can be regenerated when the format
/// changes, deliberately and all at once.
///
/// `SYNCH_REKOR_FIXTURE=write cargo test -p synch-net --test rekor_zone_key
/// -- --ignored regenerate_the_shared_fixture`
#[test]
#[ignore]
fn regenerate_the_shared_fixture() {
    assert_eq!(
        std::env::var("SYNCH_REKOR_FIXTURE").ok().as_deref(),
        Some("write"),
        "refusing to rewrite the fixture without SYNCH_REKOR_FIXTURE=write"
    );
    let zone = SimZone::new("sync.test", member_records());
    let mut log = SimLog::new("rekor.sim");
    // Neighbours, so the audit path is a real path and not an empty list.
    log.append(b"an entry logged before this zone's key");
    let statement = zone.zone_key_statement("create", None);
    let mut proof = log.log_statement(&zone, &statement);
    log.append(b"an entry logged after it");
    log.refresh(&mut proof);
    verify(&proof, &zone, &log).expect("the fixture must verify before it is written");

    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    write("proof.bin", &proof.encode());
    write("statement.json", &proof.dsse_payload);
    write("dsse-signature.bin", &proof.dsse_signature);
    write("checkpoint.txt", &proof.checkpoint);
    write("log-id.bin", &proof.log_id);
    write("inclusion-path.bin", &proof.inclusion_path.concat());
    write("dnskey.bin", &zone.dnskey_rdata());
    write("log-key.pem", log.key_pem().as_bytes());
    write(
        "meta.txt",
        format!(
            "apex={}\nkey_tag={}\nlog_index={}\naction={}\nds={}\n",
            zone.apex(),
            proof.key_tag,
            proof.log_index,
            statement.action,
            statement.ds,
        )
        .as_bytes(),
    );
}

#[test]
fn the_policy_default_is_require_everywhere() {
    // Require is the default in every trust configuration — the embedded
    // Sigstore snapshot means a stock build can always verify — and off is
    // an explicit choice, behind an anchor as much as on the ICANN path
    // (§4.1).
    let icann = ResolverOptions::default();
    assert_eq!(icann.rekor_policy(), RekorPolicy::Require);
    let anchored = ResolverOptions {
        trust_anchor: Some("/tmp/anchor.key".into()),
        ..Default::default()
    };
    assert_eq!(anchored.rekor_policy(), RekorPolicy::Require);
    assert_eq!(
        ResolverOptions {
            rekor: Some(RekorPolicy::Require),
            ..anchored
        }
        .rekor_policy(),
        RekorPolicy::Require
    );
    assert_eq!(
        ResolverOptions {
            rekor: Some(RekorPolicy::Off),
            ..icann
        }
        .rekor_policy(),
        RekorPolicy::Off
    );
}
