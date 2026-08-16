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
    let decoded = RekorProof::from_txt(&proof.to_txt().expect("encodes")).unwrap();
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
        body.certificate.single_dns_name().unwrap().to_string(),
        zone.apex()
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
    let mut bytes = proof.encode().expect("a sim proof encodes");
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
    // otherwise. Decoded here, because the validator keeps no record of
    // validity windows: it has no clock to compare them against.
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    let carried = body.dnssec_chain().unwrap();
    chain::validate(
        &carried,
        &chain::parse_name(&zone.apex()).unwrap(),
        &zone.dnskey_rdata(),
        &anchors(&zone),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expirations = rrsig_expirations(&carried);
    assert!(!expirations.is_empty());
    assert!(expirations.iter().all(|&e| e < now));
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
    zone.rekor_txt = vec![
        other.to_txt().expect("encodes"),
        proof.to_txt().expect("encodes"),
    ];

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
    zone.rekor_txt = vec![log
        .publish(&stranger, "create", None)
        .to_txt()
        .expect("encodes")];

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
    zone.rekor_txt = vec![proof.to_txt().expect("encodes")];

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
    assert_eq!(proof.encode().unwrap(), fixture("proof.bin"));

    // The certificate the Gleam side built, read by the Rust parser: the two
    // DER implementations have to agree about the SAN, the SPKI and the two
    // custom extensions, and this is where that is checked.
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    assert_eq!(body.certificate_der, fixture("certificate.der"));
    let apex = fixture_field("apex");
    assert_eq!(
        body.certificate.single_dns_name().unwrap().to_string(),
        apex
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

/// The certificate encoders, across two implementations of one DER format.
///
/// The bytes under `test/fixtures/rekor/crossval` are written by the Gleam
/// side (`gleam run -m tools/gen_crossval`) and asserted by both suites. It
/// is the only thing that keeps a hand-rolled DER reader here and OTP's
/// ASN.1 encoder there from agreeing with themselves and not with each
/// other — and the certificate in particular is round-tripped, not merely
/// compared, because its signature is randomized and its *contents* are what
/// both sides turn on.
#[test]
fn the_gleam_certificate_encoders_agree_with_this_one() {
    use synch_net::{
        x509::Certificate,
        zonecert::{ChainLink, DnssecChain, Succession, OID_DNSSEC_CHAIN, OID_SUCCESSION},
    };

    let chain = DnssecChain {
        links: vec![
            ChainLink {
                zone: "sync.test.".into(),
                rrs: vec![0xaa, 0xbb, 0xcc],
            },
            ChainLink {
                zone: ".".into(),
                rrs: vec![0x01, 0x02],
            },
        ],
    };
    assert_eq!(chain.encode(), fixture("crossval/chain.der"));
    assert_eq!(
        DnssecChain::decode(&fixture("crossval/chain.der")).unwrap(),
        chain
    );

    let succession = Succession {
        predecessor_key_tag: 34_918,
        predecessor_spki: vec![0x30, 0x59, 0x11],
        signature: vec![0x30, 0x44, 0x02],
    };
    assert_eq!(succession.encode(), fixture("crossval/succession.der"));
    assert_eq!(
        Succession::decode(&fixture("crossval/succession.der")).unwrap(),
        succession
    );

    // The bytes the *previous* zone key signs, which two implementations
    // have to render identically or a rotation reads as a substitution.
    assert_eq!(
        Succession::signed_payload("sync.test.", 34_918, b"spki"),
        fixture("crossval/succession-payload.json")
    );

    // And a whole certificate the Gleam side built, read here.
    let der = fixture("crossval/certificate.der");
    let certificate = Certificate::parse(&der).expect("a Gleam-built certificate must parse");
    assert_eq!(
        certificate.single_dns_name().unwrap().to_string(),
        "sync.test."
    );
    assert_eq!(certificate.spki.len(), 91);
    assert_eq!(
        certificate.extension(OID_DNSSEC_CHAIN),
        Some(fixture("crossval/chain.der").as_slice())
    );
    assert_eq!(
        certificate.extension(OID_SUCCESSION),
        Some(fixture("crossval/succession.der").as_slice())
    );
    // The two extensions X.509 requires of an end-entity key envelope are
    // there and critical, so a certificate this design mints reads correctly
    // in any toolchain that opens the log entry.
    let by_oid = |oid: &[u8]| {
        certificate
            .extensions
            .iter()
            .find(|e| e.oid == oid)
            .expect("extension")
            .critical
    };
    assert!(by_oid(synch_net::x509::OID_BASIC_CONSTRAINTS));
    assert!(by_oid(synch_net::x509::OID_KEY_USAGE));
    assert!(!by_oid(synch_net::x509::OID_SUBJECT_ALT_NAME));
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
    write_file("proof.bin", &proof.encode().expect("the fixture encodes"));
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

/// A real published Rekor v2 entry with a certificate verifier, verified in
/// full, offline.
///
/// The bytes in `tests/fixtures/rekor_v3` are a genuine `hashedrekord` v0.0.2
/// entry published to `log2025-1.rekor.sigstore.dev` (see PROVENANCE.txt) and
/// read back out of the log's own static tiles; nothing in this repository
/// authored the log's half of any of it. The certificate carries **both**
/// custom extensions under the narrowed OIDs, at 944 bytes — which is the
/// empirical answer to two questions a local test cannot settle: whether
/// Rekor accepts a certificate this size, and whether it accepts these
/// extensions at all.
///
/// It proves the claim the whole of v3 rests on: Rekor performs no
/// certificate validation, so an apex written into a `dNSName` SAN lands, in
/// the clear, inside the Merkle leaf where a monitor can index it.
///
/// This fixture is **total** — the Statement was preserved this time, so the
/// real client verifier runs to completion over real bytes rather than
/// stopping at the first check it cannot answer. The one thing it is not is
/// ICANN-rooted: we own no DNSSEC-signed domain, so the chain inside the
/// certificate is self-anchored at the apex, and the test supplies that apex
/// as the trust anchor exactly as a `--dnssec-anchor` deployment would. A
/// public monitor rooted at ICANN files this entry tier C, correctly.
/// Real-world ICANN-rooted chain validation is anchored separately by
/// `tests/fixtures/dnssec_chain` (a live `cloudflare.com` delegation); this
/// fixture is about interoperating with the log.
mod real_rekor_v3 {
    use super::*;

    fn v3(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rekor_v3")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
    }

    const APEX: &str = "zone-key-transparency.demo.invalid";
    const LOG_INDEX: u64 = 67_966_366;
    const KEY_TAG: u16 = 27337;

    /// The proof exactly as a zone serves it: the checked-in `proof.bin` is
    /// the encoded `RekorProof` v3 record, decoded here through the client's
    /// own wire decoder. Reassembling it field by field would test the
    /// fixture against itself; decoding it tests the format.
    fn proof_from_fixture() -> RekorProof {
        let proof = RekorProof::decode(&v3("proof.bin"))
            .expect("the served proof record must decode through the client's own reader");
        // The loose files are the same bytes, so a reader of this directory
        // can inspect each piece without a decoder.
        assert_eq!(proof.statement, v3("statement.json"));
        assert_eq!(proof.canonicalized_body, v3("canonicalized_body.json"));
        assert_eq!(proof.checkpoint, v3("checkpoint.txt"));
        assert_eq!(proof.log_index, LOG_INDEX);
        assert_eq!(proof.key_tag, KEY_TAG);
        proof
    }

    /// The zone's DNSKEY rdata, derived from the certificate's own
    /// SubjectPublicKeyInfo — the way a monitor derives it, with no DNS
    /// query, because the threat model has a compromised DNS provider in it.
    ///
    /// The shipped anchor file is asserted to be about the same key, so the
    /// fixture cannot drift into being two keys wearing one name.
    fn zone_dnskey_rdata() -> Vec<u8> {
        let body = HashedRekordBody::parse(&v3("canonicalized_body.json")).unwrap();
        let public = &body.certificate.spki[27..]; // the uncompressed point, sans 0x04
        let mut rdata = vec![0x01, 0x01, 0x03, 0x0d]; // flags 257, protocol 3, alg 13
        rdata.extend_from_slice(public);
        assert_eq!(
            chain::key_tag(&rdata),
            KEY_TAG,
            "the certificate's key must be the key the entry names"
        );
        let anchor = String::from_utf8(v3("anchor.txt")).expect("the anchor is text");
        assert!(
            anchor.contains(&rekor::base64_encode(public)),
            "the shipped anchor must be this same key, or the fixture is about two keys"
        );
        rdata
    }

    /// The anchor as the resolver holds it. Written to a temp file because
    /// `TrustAnchors::from_file` is the only public constructor, and using
    /// the real parser is the point — the fixture ships the anchor in the
    /// syntax an operator actually types.
    fn anchors() -> (
        tempfile::TempDir,
        hickory_resolver::proto::dnssec::TrustAnchors,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("anchor.key");
        std::fs::write(&path, v3("anchor.txt")).expect("write anchor");
        let anchors = hickory_resolver::proto::dnssec::TrustAnchors::from_file(&path)
            .expect("the shipped anchor must parse");
        (dir, anchors)
    }

    /// The embedded id of `log2025-1.rekor.sigstore.dev`.
    ///
    /// Note which id this is. Rekor's own `entry.logId.keyId` in the same
    /// JSON response is the **C2SP note key id** —
    /// `SHA-256(origin ‖ 0x0A ‖ 0x01 ‖ raw32)` — a different, equally
    /// 32-byte, entirely plausible-looking value. Copying that one instead
    /// produces a proof that fails to match any pin. Ours is
    /// `SHA-256(DER SPKI)` throughout, and `rekor::log_id` is the only place
    /// that decision is made.
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

    /// The whole client verifier, over real bytes, to a successful result.
    #[test]
    fn the_real_entry_verifies_end_to_end() {
        let proof = proof_from_fixture();
        assert_eq!(proof.log_id, embedded_log2025_1_id());
        let rdata = zone_dnskey_rdata();
        let key = ZoneKey {
            apex: APEX,
            key_tag: KEY_TAG,
            dnskey_rdata: &rdata,
        };
        let (_dir, anchors) = anchors();

        let record = rekor::verify(&proof, &key, &LogKeys::embedded(), &anchors)
            .expect("a real published entry must verify under the embedded pins");

        assert_eq!(record.log_index, LOG_INDEX);
        assert_eq!(record.tree_size, 67_966_402);
        assert_eq!(record.origin, "log2025-1.rekor.sigstore.dev");
        // A rollover: the statement names the key it replaces, and a client
        // accepts rollover as authorization (retire it would refuse).
        assert_eq!(record.action, "rollover");
    }

    /// The same bytes, offered as proof for a *different* key: refused.
    ///
    /// The binding this breaks is the one that matters — an attacker who can
    /// read the log can copy any published proof, so a proof that verified
    /// for a key it does not name would authorize every key in existence.
    #[test]
    fn the_real_entry_is_refused_for_a_different_key() {
        let proof = proof_from_fixture();
        let (_dir, anchors) = anchors();
        let mut rdata = zone_dnskey_rdata();
        rdata[8] ^= 0x40; // a different P-256 point, same shape
        let stranger = ZoneKey {
            apex: APEX,
            key_tag: KEY_TAG,
            dnskey_rdata: &rdata,
        };
        let error = rekor::verify(&proof, &stranger, &LogKeys::embedded(), &anchors)
            .expect_err("a real proof must not authorize a key it does not name");
        assert!(
            matches!(&error, ProofError::Binding(_)),
            "the certificate names another key: {error}"
        );

        // And offered for a different apex, with the right key.
        let rdata = zone_dnskey_rdata();
        let elsewhere = ZoneKey {
            apex: "somewhere.else.invalid",
            key_tag: KEY_TAG,
            dnskey_rdata: &rdata,
        };
        assert!(matches!(
            rekor::verify(&proof, &elsewhere, &LogKeys::embedded(), &anchors).unwrap_err(),
            ProofError::Binding(_)
        ));
    }

    /// Inclusion in the real tree, with teeth.
    #[test]
    fn the_real_entry_is_included_in_the_real_tree() {
        let proof = proof_from_fixture();
        let checkpoint = rekor::Checkpoint::parse(&proof.checkpoint).unwrap();
        assert_eq!(checkpoint.origin, "log2025-1.rekor.sigstore.dev");
        checkpoint
            .verify_under(&LogKeys::embedded())
            .expect("a real checkpoint verifies under the embedded pin set");
        // It verifies *among* four signature lines — the log's own plus three
        // witness cosignatures. Nothing here interprets cosignatures (§8.2),
        // but the parser must keep tolerating them or every real checkpoint
        // becomes unparseable.
        assert_eq!(
            String::from_utf8_lossy(&v3("checkpoint.txt"))
                .lines()
                .filter(|line| line.starts_with('\u{2014}'))
                .count(),
            4
        );
        rekor::verify_inclusion(
            proof.log_index,
            checkpoint.tree_size,
            proof.leaf_hash(),
            &proof.inclusion_path,
            checkpoint.root_hash,
        )
        .expect("the audit path must reach the real root");

        // One byte off the body and the leaf is not in the tree.
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

    /// The certificate really does carry the apex into the leaf, and really
    /// does carry both extensions at a size the log accepted.
    #[test]
    fn the_real_entrys_certificate_carries_its_apex_and_both_extensions() {
        let body = HashedRekordBody::parse(&v3("canonicalized_body.json"))
            .expect("a real entry body must parse");
        assert_eq!(body.certificate_der, v3("certificate.der"));
        assert_eq!(
            body.certificate.single_dns_name().unwrap().to_string(),
            format!("{APEX}.")
        );

        // The apex is literally inside the bytes the Merkle leaf commits to —
        // the property a monitor's SAN index depends on.
        assert!(
            String::from_utf8_lossy(&v3("canonicalized_body.json"))
                .contains(&rekor::base64_encode(&body.certificate_der)),
            "the certificate is carried verbatim in the canonicalized body"
        );
        assert!(body
            .certificate_der
            .windows(APEX.len())
            .any(|w| w == APEX.as_bytes()));

        // Both extensions survived the round trip, under the narrowed OIDs.
        // 945 bytes is the empirical answer to "will Rekor take a
        // certificate this size, with arcs like these": it did, HTTP 201.
        assert_eq!(body.certificate_der.len(), 945);
        let carried = body
            .certificate
            .extension(OID_DNSSEC_CHAIN)
            .expect("the real certificate carries the chain extension");
        let carried = synch_net::zonecert::DnssecChain::decode(carried).expect("and it decodes");
        assert_eq!(carried.links.first().unwrap().zone, format!("{APEX}."));
        let succession = body
            .certificate
            .extension(OID_SUCCESSION)
            .expect("the real certificate carries the succession extension");
        let succession =
            synch_net::zonecert::Succession::decode(succession).expect("and it decodes");
        assert_eq!(succession.predecessor_key_tag, 17123);

        assert_eq!(body.digest.len(), 32);
        assert_eq!(body.certificate.spki.len(), 91);
    }

    /// The real Statement round-trips through this build's canonical form,
    /// byte for byte.
    ///
    /// The control plane rendered these bytes and the log committed to their
    /// digest. Two renderers have to agree on them exactly — "equivalent
    /// JSON" is not equivalent when a Merkle leaf commits to a digest — so
    /// this is the crossval for the Statement half of the format, against
    /// bytes the log has permanently recorded.
    #[test]
    fn the_real_statement_round_trips_through_this_builds_canonical_form() {
        let statement = v3("statement.json");
        let parsed = rekor::ZoneKeyStatement::parse(&statement).expect("a real Statement parses");
        assert_eq!(
            String::from_utf8_lossy(&parsed.to_json()),
            String::from_utf8_lossy(&statement),
            "this build must re-render the logged Statement byte for byte"
        );
        assert_eq!(parsed.apex, format!("{APEX}."));
        assert_eq!(parsed.key_tag, KEY_TAG);
        assert_eq!(parsed.action, "rollover");
        assert_eq!(parsed.replaces_key_tag, Some(17123));
        assert_eq!(parsed.flags, 257);
        assert_eq!(parsed.algorithm, 13);
        assert_eq!(
            parsed.subject_sha256,
            hex::encode(rekor::sha256(&zone_dnskey_rdata()))
        );

        // And the leaf's digest is that Statement's DSSE PAE — the link
        // between the log's commitment and the bytes served beside it.
        let body = HashedRekordBody::parse(&v3("canonicalized_body.json")).unwrap();
        assert_eq!(
            body.digest,
            rekor::sha256(&rekor::pae(rekor::DSSE_PAYLOAD_TYPE, &statement))
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

/// Every RRSIG expiration in a chain, decoded here rather than reported by
/// the validator.
///
/// The validator deliberately keeps no record of validity windows — it has no
/// clock to compare them against, and nothing consumes them (see
/// `chain`'s module docs). But a test claiming "this chain is expired and
/// still validates" has to prove the first half, or it passes vacuously. So
/// the test decodes the windows itself, out of the same bytes.
fn rrsig_expirations(chain: &synch_net::zonecert::DnssecChain) -> Vec<u64> {
    use hickory_resolver::proto::{
        dnssec::rdata::DNSSECRData,
        rr::{RData, Record},
        serialize::binary::{BinDecodable, BinDecoder},
    };
    let mut out = Vec::new();
    for link in &chain.links {
        let mut decoder = BinDecoder::new(&link.rrs);
        while decoder.peek().is_some() {
            let record = Record::read(&mut decoder).expect("a well-formed link");
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = record.data {
                out.push(u64::from(sig.input().sig_expiration.get()));
            }
        }
    }
    out
}
