//! Zone-key transparency end to end (docs/REKOR-ZONE-KEY.md §9).
//!
//! One simulated zone, one simulated log, and the real verifier. The positive
//! case proves a correctly logged key is accepted through the whole path —
//! validated TXT, apex DNSKEY, proof record, offline verification. Every other
//! case takes that same proof and breaks exactly one thing, so a passing
//! verification can never be an accident of the harness: possession, apex
//! binding, key binding, statement binding, the DNSSEC chain, inclusion,
//! checkpoint, unknown log, absent record.

use synch_net::{
    chain,
    dns::{DnssecResolver, RekorPolicy, ResolverOptions},
    error::NetError,
    rekor::{self, HashedRekordBody, LogKeys, ProofError, RekorProof, ZoneKey},
    sim::{hashedrekord_body, SimLog, SimZone},
    zonecert::{OID_DNSSEC_CHAIN, OID_SUCCESSION},
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

/// The trust anchors a client resolving a simulated zone holds: that zone's
/// own key, exactly as `--dnssec-anchor` would install it.
fn anchors(zone: &SimZone) -> hickory_resolver::proto::dnssec::TrustAnchors {
    let file = write(&zone.anchor_record());
    hickory_resolver::proto::dnssec::TrustAnchors::from_file(file.path()).unwrap()
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
    rekor::verify(
        proof,
        &key,
        &LogKeys::parse(&log.key_pem()).unwrap(),
        &anchors(zone),
    )
    .map(|_| ())
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
fn the_leaf_names_the_zone_where_a_monitor_can_see_it() {
    // The whole reason v3 exists: the apex is inside the Merkle leaf, in the
    // clear, with no DNS lookup and no cooperation from the zone required to
    // find it. Assert it of the bytes the log committed to, not of a struct.
    let (zone, _log, proof) = logged_zone();
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    assert_eq!(
        body.certificate.single_dns_name().unwrap(),
        zone.apex().trim_end_matches('.')
    );
    let text = String::from_utf8_lossy(&proof.canonicalized_body);
    assert!(text.contains("x509Certificate"), "{text}");
    assert!(
        !text.contains("publicKey"),
        "no raw-key arm survives: {text}"
    );
    // And the certificate's key is the zone key, not merely some key.
    assert_eq!(body.certificate.spki, zone.spki());
}

#[test]
fn a_raw_public_key_entry_is_refused_outright() {
    // A v2-shaped entry: perfectly valid Rekor, apex-anonymous, and therefore
    // exactly what this design abolished. There is no branch to reach.
    let (zone, mut log, _) = logged_zone();
    let statement = zone.zone_key_statement("create", None);
    let payload = statement.to_json();
    let signature = zone.sign_dsse(&payload);
    let body = format!(
        "{{\"apiVersion\":\"0.0.2\",\"kind\":\"hashedrekord\",\"spec\":{{\"hashedRekordV002\":\
         {{\"data\":{{\"algorithm\":\"SHA2_256\",\"digest\":\"{}\"}},\"signature\":\
         {{\"content\":\"{}\",\"verifier\":{{\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\",\
         \"publicKey\":{{\"rawBytes\":\"{}\"}}}}}}}}}}}}",
        rekor::base64_encode(&rekor::sha256(&rekor::pae(
            rekor::DSSE_PAYLOAD_TYPE,
            &payload
        ))),
        rekor::base64_encode(&signature),
        rekor::base64_encode(&zone.spki()),
    );
    let proof = log.log_body(zone.key_tag(), payload, body.into_bytes());
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));
}

#[test]
fn a_v2_proof_record_is_a_malformed_version_and_nothing_more() {
    let (_, _, proof) = logged_zone();
    let mut bytes = proof.encode();
    bytes[0] = 2;
    assert!(matches!(
        RekorProof::decode(&bytes),
        Err(ProofError::Malformed(_))
    ));
}

#[test]
fn a_forged_entry_signature_fails_possession() {
    // A body that is genuinely in the tree (leaf, inclusion and checkpoint
    // all sound) and whose digest matches the Statement's PAE — but whose
    // signature was made by a stranger, not this zone's key. Possession is
    // the only check that can tell that apart, and it must.
    let zone = SimZone::new("cluster.example", member_records());
    let stranger = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create", None).to_json();
    let body = hashedrekord_body(
        &statement,
        &stranger.sign_dsse(&statement),
        &zone.zone_key_certificate(None),
    );
    let proof = log.log_body(zone.key_tag(), statement, body);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Possession(_))
    ));
}

#[test]
fn a_certificate_holding_another_key_fails_binding() {
    // The zone signs the entry itself, so possession would pass — but the
    // certificate records a *stranger's* key. To a monitor watching the apex
    // that entry is about the stranger's key; the client must refuse it.
    let zone = SimZone::new("cluster.example", member_records());
    let stranger = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create", None).to_json();
    let body = hashedrekord_body(
        &statement,
        &zone.sign_dsse(&statement),
        &stranger.zone_key_certificate(None),
    );
    let proof = log.log_body(zone.key_tag(), statement, body);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));
}

#[test]
fn a_certificate_naming_another_apex_fails_binding() {
    // The attack this whole design exists to make loud, in its subtlest
    // form: the right key, on the public record, under a name that is not
    // this zone — so the operator's monitor never looks at it.
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create", None);
    let certificate = zone.certificate_for(
        "somewhere.else",
        &[(OID_DNSSEC_CHAIN.to_vec(), zone.dnssec_chain().encode())],
    );
    let proof = log.log_certified(&zone, &statement, &certificate);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));
}

#[test]
fn a_key_logged_for_another_apex_fails_binding() {
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
fn a_retire_entry_is_never_authorization() {
    // Retires may be published chainless (a retired zone can have no DS
    // left), so a client that treated one as authorization would be a client
    // that accepts an entry carrying no proof of delegation at all.
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let proof = log.publish(&zone, "retire", None);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));
}

// ------------------------------------------- the chain the client enforces

/// An entry with no DNSSEC chain is refused, even though everything else
/// about it is perfect.
///
/// This is the evasion the requirement closes, and it is worth stating in
/// full: the client does not need the chain — it validated this zone's
/// delegation natively before it ever got here. A monitor does. An entry with
/// no chain is tier C, the *silent* bin, so a client that accepted one would
/// hand an attacker a key that works against victims and rings no bell.
#[test]
fn an_entry_with_no_chain_is_refused_on_the_monitors_behalf() {
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create", None);
    let proof = log.log_certified(&zone, &statement, &zone.certificate(&[]));
    let error = verify(&proof, &zone, &log).unwrap_err();
    assert!(
        matches!(&error, ProofError::Chain(why) if why.contains("no DNSSEC chain")),
        "{error}"
    );
}

#[test]
fn a_broken_or_irrelevant_chain_is_refused_the_same_way() {
    let zone = SimZone::new("cluster.example", member_records());
    let stranger = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create", None);

    // A chain whose signature has been tampered with.
    let mut broken = zone.dnssec_chain();
    let at = broken.links[0].rrs.len() - 5;
    broken.links[0].rrs[at] ^= 0x01;
    let proof = log.log_certified(
        &zone,
        &statement,
        &zone.certificate(&[(OID_DNSSEC_CHAIN.to_vec(), broken.encode())]),
    );
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Chain(_))
    ));

    // A chain that is perfectly valid — for somebody else's zone and key.
    let proof = log.log_certified(
        &zone,
        &statement,
        &zone.certificate(&[(OID_DNSSEC_CHAIN.to_vec(), stranger.dnssec_chain().encode())]),
    );
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Chain(_))
    ));

    // A chain extension that is not even DER.
    let proof = log.log_certified(
        &zone,
        &statement,
        &zone.certificate(&[(OID_DNSSEC_CHAIN.to_vec(), b"not der".to_vec())]),
    );
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Chain(_))
    ));
}

/// A chain whose signatures expired long ago still verifies.
///
/// Archival entries are read for years while RRSIGs live for weeks. A client
/// that consulted a clock would reject every entry older than a re-signing
/// interval — and there is no trustworthy clock in the input anyway, since a
/// Rekor leaf commits to `data` and `signature` and nothing else.
#[test]
fn an_expired_chain_still_verifies_because_no_clock_is_consulted() {
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let ancient = time::OffsetDateTime::now_utc() - time::Duration::days(900);
    let statement = zone.zone_key_statement("create", None);
    let certificate = zone.certificate(&[(
        OID_DNSSEC_CHAIN.to_vec(),
        zone.dnssec_chain_at(ancient).encode(),
    )]);
    let proof = log.log_certified(&zone, &statement, &certificate);
    verify(&proof, &zone, &log).expect("an entry does not rot");

    // The window is genuinely in the past — the test would pass vacuously
    // otherwise.
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    let valid = chain::validate(
        &body.dnssec_chain().unwrap(),
        &zone.apex(),
        &zone.dnskey_rdata(),
        &anchors(&zone),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(valid.windows.iter().all(|w| !w.covers(now)));
}

/// The countersignature is the one thing a client does *not* check.
///
/// The asymmetry is the point: chain absence silences a monitor, so the
/// client enforces it; countersignature absence alarms a monitor, so the
/// client must not — requiring it would break a zone's genesis key and every
/// disaster recovery, and omitting it only makes an attacker louder.
#[test]
fn the_succession_countersignature_is_not_a_client_concern() {
    let zone = SimZone::new("cluster.example", member_records());
    let old = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("rollover", Some(old.key_tag()));

    // Present and valid: accepted.
    let succession = old.countersign(&zone.apex(), &zone.spki());
    let proof = log.log_certified(
        &zone,
        &statement,
        &zone.zone_key_certificate(Some(&succession)),
    );
    verify(&proof, &zone, &log).unwrap();

    // Absent: accepted just the same. This is a genesis key or a recovery.
    let proof = log.log_certified(&zone, &statement, &zone.zone_key_certificate(None));
    verify(&proof, &zone, &log).unwrap();

    // Present and forged: still accepted by the *client*, because the client
    // never looks. A monitor is what refuses this, loudly, as tier B.
    let mut forged = succession.clone();
    forged.signature[10] ^= 0x01;
    let proof = log.log_certified(&zone, &statement, &zone.zone_key_certificate(Some(&forged)));
    verify(&proof, &zone, &log).unwrap();

    // And the extension is really there, so the assertions above are not
    // passing because nothing was written.
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    assert!(body.certificate.extension(OID_SUCCESSION).is_some());
}

// -------------------------------------------------------- log-level checks

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
        rekor::verify(&proof, &key, &LogKeys::default(), &anchors(&zone)),
        Err(ProofError::UnknownLog(_))
    ));
}

// ------------------------------------------------------ through the resolver

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
async fn a_chainless_entry_is_refused_through_the_whole_resolver_path() {
    // The same refusal as the unit case, but reached the way a real client
    // reaches it, and surfaced as the error class `synch doctor` explains.
    let mut zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create", None);
    let certificate = zone.certificate(&[]);
    let proof = log.log_certified(&zone, &statement, &certificate);
    zone.rekor_txt = vec![proof.to_txt()];

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
    assert!(matches!(error, NetError::RekorChain { .. }), "{error}");
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

// ------------------------------------------------------ the shared fixture

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
    let proof = RekorProof::decode(&fixture("proof.bin")).expect("the fixture is a v3 proof");

    // Every part the Gleam encoder is asserted against, asserted here too:
    // if the two ever disagree, one of these fails rather than both suites
    // passing against different bytes.
    assert_eq!(proof.statement, fixture("statement.json"));
    assert_eq!(proof.canonicalized_body, fixture("canonicalized-body.bin"));
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

    // The certificate the Gleam side built, read by the Rust parser: the two
    // DER implementations have to agree about the SAN, the SPKI and the two
    // custom extensions, and this is where that is checked.
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    assert_eq!(body.certificate_der, fixture("certificate.der"));
    let apex = fixture_field("apex");
    assert_eq!(
        body.certificate.single_dns_name().unwrap(),
        apex.trim_end_matches('.')
    );
    let chain = body.dnssec_chain().expect("the fixture carries a chain");
    assert_eq!(chain.encode(), fixture("dnssec-chain.der"));

    let dnskey_rdata = fixture("dnskey.bin");
    assert_eq!(body.certificate.spki, rekor::p256_spki(&dnskey_rdata[4..]));
    let key = ZoneKey {
        apex: &apex,
        key_tag: proof.key_tag,
        dnskey_rdata: &dnskey_rdata,
    };
    let logs = LogKeys::parse(&String::from_utf8(fixture("log-key.pem")).unwrap()).unwrap();
    let anchor_file = write(&String::from_utf8(fixture("anchor.key")).unwrap());
    let anchors =
        hickory_resolver::proto::dnssec::TrustAnchors::from_file(anchor_file.path()).unwrap();
    let verified = rekor::verify(&proof, &key, &logs, &anchors).expect("the fixture must verify");
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
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();

    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let write_file = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    write_file("proof.bin", &proof.encode());
    write_file("statement.json", &proof.statement);
    write_file("canonicalized-body.bin", &proof.canonicalized_body);
    write_file("certificate.der", &body.certificate_der);
    // The chain the certificate actually carries, not a fresh one: RRSIG
    // signing is randomized, so re-deriving it would write bytes the entry
    // does not contain.
    write_file("dnssec-chain.der", &body.dnssec_chain().unwrap().encode());
    write_file("checkpoint.txt", &proof.checkpoint);
    write_file("log-id.bin", &proof.log_id);
    write_file("inclusion-path.bin", &proof.inclusion_path.concat());
    write_file("dnskey.bin", &zone.dnskey_rdata());
    write_file("log-key.pem", log.key_pem().as_bytes());
    write_file("anchor.key", zone.anchor_record().as_bytes());
    write_file(
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

// ---------------------------------------------- real Sigstore conformance

/// A real published Rekor v2 entry with a certificate verifier, read offline.
///
/// The bytes in `tests/fixtures/rekor_v3` are a genuine `hashedrekord` v0.0.2
/// entry published to `log2025-1.rekor.sigstore.dev` (see PROVENANCE.txt) and
/// read back out of the log's own static tiles; nothing in this repository
/// authored the log's half. It proves the claim the whole of v3 rests on:
/// Rekor performs no certificate validation, so an apex written into a
/// `dNSName` SAN lands, in the clear, inside the Merkle leaf.
///
/// One thing it cannot prove, and the test says so out loud: whoever
/// published this demo entry did not preserve the in-toto Statement behind
/// the digest, and a `hashedrekord` leaf commits only to that digest — which
/// is exactly *why* §3's record carries the Statement bytes alongside the
/// body. So the run below asserts that a full `rekor::verify` gets all the way
/// to the first check that needs those bytes — possession, which verifies the
/// entry signature over the Statement's PAE — and fails precisely there,
/// having passed every check the real log's bytes can answer.
mod real_rekor_v3 {
    use super::*;

    fn v3(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rekor_v3")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
    }

    /// The embedded id of `log2025-1.rekor.sigstore.dev`: the one Ed25519 key
    /// among the embedded pins, by our SHA-256(SPKI) convention.
    fn embedded_log2025_1_id() -> [u8; 32] {
        let expected: [u8; 32] =
            hex::decode("b54813cb63d8859870a5e78500cc6adcfdf59723edae93ee8d25faf2475a0690")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(
            LogKeys::embedded().find(&expected).is_some(),
            "the embedded pin set must carry log2025-1"
        );
        expected
    }

    fn proof_from_fixture() -> RekorProof {
        let path = v3("inclusion_path.bin");
        RekorProof {
            key_tag: 2143,
            log_id: embedded_log2025_1_id(),
            log_index: String::from_utf8(v3("log_index.txt"))
                .unwrap()
                .trim()
                .parse()
                .unwrap(),
            // The Statement is not recoverable — see PROVENANCE.txt.
            statement: b"{}".to_vec(),
            canonicalized_body: v3("canonicalized_body.json"),
            checkpoint: v3("checkpoint.txt"),
            inclusion_path: path
                .chunks(32)
                .map(|c| <[u8; 32]>::try_from(c).unwrap())
                .collect(),
        }
    }

    #[test]
    fn the_real_entry_is_included_in_the_real_tree() {
        let proof = proof_from_fixture();
        let checkpoint = rekor::Checkpoint::parse(&proof.checkpoint).unwrap();
        assert_eq!(checkpoint.origin, "log2025-1.rekor.sigstore.dev");
        checkpoint
            .verify_under(&LogKeys::embedded())
            .expect("a real checkpoint verifies under the embedded pin set");
        // Three witnesses cosigned it, and their timestamps decode as the
        // C2SP cosignature/v1 blobs a monitor reads its clock from.
        let cosignatures = checkpoint.cosignatures();
        assert_eq!(cosignatures.len(), 3, "{cosignatures:?}");
        assert!(cosignatures.iter().all(|c| c.timestamp > 1_700_000_000));

        rekor::verify_inclusion(
            proof.log_index,
            checkpoint.tree_size,
            proof.leaf_hash(),
            &proof.inclusion_path,
            checkpoint.root_hash,
        )
        .expect("18 hops through a real tree of 67.7 million entries");

        // With teeth: one byte off the body and the leaf is not in the tree.
        let mut tampered = proof;
        tampered.canonicalized_body[0] ^= 0x01;
        assert!(rekor::verify_inclusion(
            tampered.log_index,
            checkpoint.tree_size,
            tampered.leaf_hash(),
            &tampered.inclusion_path,
            checkpoint.root_hash,
        )
        .is_err());
    }

    #[test]
    fn the_real_entrys_certificate_carries_its_apex_into_the_leaf() {
        let body = HashedRekordBody::parse(&v3("canonicalized_body.json"))
            .expect("a real entry body must parse");
        assert_eq!(body.certificate_der, v3("certificate.der"));
        assert_eq!(
            body.certificate.single_dns_name().unwrap(),
            "zone-key-transparency.demo.invalid"
        );
        // And the apex is literally inside the bytes the Merkle leaf commits
        // to — which is the property a monitor's SAN index depends on.
        let leaf_preimage = v3("canonicalized_body.json");
        let der = &body.certificate_der;
        assert!(
            String::from_utf8_lossy(&leaf_preimage).contains(&rekor::base64_encode(der)),
            "the certificate is carried verbatim in the canonicalized body"
        );
        assert!(der
            .windows(34)
            .any(|w| w == b"zone-key-transparency.demo.invalid"));

        // The entry signature is the certificate's own key's, over the
        // entry's digest as a prehash. Because that digest is SHA-256(PAE),
        // this is the same signature the client checks over the PAE.
        assert_eq!(body.digest.len(), 32);
        assert_eq!(body.certificate.spki.len(), 91);
    }

    #[test]
    fn the_real_entry_fails_only_where_its_statement_is_missing() {
        // Everything the real log's bytes can answer, answered by running
        // the actual client verifier: the pinned log, the checkpoint, the
        // inclusion walk, the body's kind and tags, the certificate, its
        // single SAN, and the SPKI binding. The first thing it cannot answer
        // is the digest, because the Statement behind it was not preserved.
        let proof = proof_from_fixture();
        let apex = "zone-key-transparency.demo.invalid";
        let spki = HashedRekordBody::parse(&proof.canonicalized_body)
            .unwrap()
            .certificate
            .spki;
        let mut rdata = vec![0x01, 0x01, 0x03, 0x0d];
        rdata.extend_from_slice(&spki[27..]);
        let key = ZoneKey {
            apex,
            key_tag: 2143,
            dnskey_rdata: &rdata,
        };
        let error = rekor::verify(
            &proof,
            &key,
            &LogKeys::embedded(),
            &hickory_resolver::proto::dnssec::TrustAnchors::default(),
        )
        .unwrap_err();
        assert!(
            matches!(&error, ProofError::Possession(_)),
            "the first unanswerable check is possession over a statement we do not have: {error}"
        );
    }
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
