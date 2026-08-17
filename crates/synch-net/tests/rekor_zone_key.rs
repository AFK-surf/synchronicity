//! Zone-key transparency end to end (docs/REKOR-ZONE-KEY.md §9).
//!
//! One simulated zone, one simulated log, and the real verifier. The positive
//! case proves a correctly logged key set is accepted through the whole path —
//! validated TXT, apex DNSKEY, proof record, offline verification. Every other
//! case takes that same proof and breaks exactly one thing, so a passing
//! verification can never be an accident of the harness: attribution, apex
//! binding, key-set binding, statement binding, the DNSSEC chain, inclusion,
//! checkpoint, unknown log, absent record.

use synch_net::{
    chain,
    dns::{DnssecResolver, RekorPolicy, ResolverOptions},
    error::NetError,
    rekor::{self, HashedRekordBody, LogKeys, ProofError, RekorProof, ZoneKey},
    sim::{hashedrekord_body, SimLog, SimZone},
    tuf,
    zonecert::OID_DNSSEC_CHAIN,
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
    let proof = log.publish(&zone, "create");
    (zone, log, proof)
}

fn verify(proof: &RekorProof, zone: &SimZone, log: &SimLog) -> Result<(), ProofError> {
    let apex = zone.apex();
    let rdata = zone.dnskey_rdata();
    let key = ZoneKey {
        domain: &apex,
        signing_zone: &apex,
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
    let served = proof.to_txt().expect("encodes");
    let reassembled = rekor::proofs_from_txt(&served);
    let [Ok(decoded)] = reassembled.as_slice() else {
        panic!("one proof reassembles to one candidate: {reassembled:?}");
    };
    assert_eq!(decoded, &proof);
    verify(decoded, &zone, &log).unwrap();
}

#[test]
fn the_leaf_names_the_zone_where_a_monitor_can_see_it() {
    // The whole reason the verifier is a certificate: the apex is inside
    // the Merkle leaf, in the clear, with no DNS lookup and no cooperation
    // from the zone required to find it. Assert it of the bytes the log
    // committed to, not of a struct.
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
    // Perfectly valid Rekor, apex-anonymous — no monitor could ever have
    // seen it, so there is no branch that accepts it.
    let (zone, mut log, _) = logged_zone();
    let statement = zone.zone_key_statement("create");
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
    let proof = log.log_body(payload, body.into_bytes());
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));
}

#[test]
fn a_wrong_version_byte_is_a_malformed_record_and_nothing_more() {
    let (_, _, proof) = logged_zone();
    let mut bytes = proof.encode().expect("a sim proof encodes");
    bytes[0] = 2;
    assert!(matches!(
        RekorProof::decode(&bytes),
        Err(ProofError::Malformed(_))
    ));
}

#[test]
fn a_misattributed_entry_signature_is_refused() {
    // A body that is genuinely in the tree (leaf, inclusion and checkpoint
    // all sound) and whose digest matches the Statement's PAE — but whose
    // signature was made by a key that is not the certificate's. The entry
    // lies about who built it, so nothing it says can be believed.
    let zone = SimZone::new("cluster.example", member_records());
    let stranger = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create").to_json();
    let body = hashedrekord_body(
        &statement,
        &stranger.sign_dsse(&statement),
        &zone.zone_key_certificate(),
    );
    let proof = log.log_body(statement, body);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Attribution(_))
    ));
}

#[test]
fn a_signer_other_than_the_zone_key_is_fine() {
    // The decoupling this claim exists for: the entry is signed by a key
    // that is *not* in the zone at all — the ephemeral signer the publisher
    // mints — and verifies, because the certificate names that key as the
    // signer and the chain, not the signature, is what authorizes the
    // zone's key set. This is what makes a provider-held zone key loggable.
    let zone = SimZone::new("cluster.example", member_records());
    let ephemeral = SimZone::new("cluster.example", Vec::new());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create").to_json();
    // The certificate is built around the *ephemeral* key (its SPKI, its
    // self-signature) but names the zone's apex and carries the zone's chain.
    let certificate =
        ephemeral.certificate(&[(OID_DNSSEC_CHAIN.to_vec(), zone.dnssec_chain().encode())]);
    let body = hashedrekord_body(&statement, &ephemeral.sign_dsse(&statement), &certificate);
    let proof = log.log_body(statement, body);
    verify(&proof, &zone, &log)
        .expect("an entry attributed to its real signer authorizes the chain-proven set");
}

#[test]
fn an_observed_key_outside_the_proven_set_fails_binding() {
    // A perfectly sound entry for this zone's real key set — but the answer
    // was signed by some other key. Membership in the proven set is the key
    // binding, and it must refuse.
    let zone = SimZone::new("cluster.example", member_records());
    let stranger = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let proof = log.publish(&zone, "create");
    let apex = zone.apex();
    let rdata = stranger.dnskey_rdata();
    let key = ZoneKey {
        domain: &apex,
        signing_zone: &apex,
        key_tag: stranger.key_tag(),
        dnskey_rdata: &rdata,
    };
    assert!(matches!(
        rekor::verify(
            &proof,
            &key,
            &LogKeys::parse(&log.key_pem()).unwrap(),
            &anchors(&zone),
        ),
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
    let statement = zone.zone_key_statement("create");
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
    let mut statement = zone.zone_key_statement("create");
    statement.apex = "other.example.".into();
    let proof = log.log_statement(&zone, &statement);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));
}

#[test]
fn a_statement_describing_keys_its_chain_never_proved_fails_binding() {
    let zone = SimZone::new("cluster.example", member_records());
    let stranger = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    // Right apex, wrong key bytes: the claimed set must be exactly the set
    // the chain proves, digest for digest.
    let mut statement = zone.zone_key_statement("create");
    statement.keys[0].sha256 = hex::encode(rekor::sha256(&stranger.dnskey_rdata()));
    let proof = log.log_statement(&zone, &statement);
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Binding(_))
    ));

    // And metadata for metadata: a statement lying about a key's tag is a
    // statement describing a set its chain never proved.
    let mut statement = zone.zone_key_statement("rollover");
    statement.keys[0].key_tag = zone.key_tag().wrapping_add(1);
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
    let proof = log.publish(&zone, "retire");
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
/// no chain is tier B, the *silent* bin, so a client that accepted one would
/// hand an attacker a key that works against victims and rings no bell.
#[test]
fn an_entry_with_no_chain_is_refused_on_the_monitors_behalf() {
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create");
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
    let statement = zone.zone_key_statement("create");

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
    let statement = zone.zone_key_statement("create");
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

/// A certificate extension this build has no name for changes nothing.
///
/// The client turns on exactly one custom extension — the DNSSEC chain — and
/// reaches it by OID. Anything else in the certificate is carried into the
/// leaf and never asked for, which is why an entry carrying an extension this
/// build has no name for still verifies — the conformance fixture is exactly
/// that case.
///
/// The negative half matters as much: an unknown extension must not become a
/// *reason to accept* either. The entry with junk in it is accepted because
/// its chain is good, and the entry with junk and no chain is still refused.
#[test]
fn an_extension_the_client_does_not_know_is_carried_and_ignored() {
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create");
    // An arc this build has no name for, holding bytes that decode as
    // nothing at all.
    let unknown = (
        vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01],
        b"opaque".to_vec(),
    );

    // Chain plus an unknown extension: accepted, exactly as chain alone is.
    let certificate = zone.certificate(&[
        (OID_DNSSEC_CHAIN.to_vec(), zone.dnssec_chain().encode()),
        unknown.clone(),
    ]);
    let proof = log.log_certified(&zone, &statement, &certificate);
    verify(&proof, &zone, &log).unwrap();

    // And it is really in there, so the assertion above is not passing
    // because nothing was written.
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    assert!(body.certificate.extension(&unknown.0).is_some());

    // The unknown extension buys nothing: without a chain the entry is
    // refused just as it would be with no extensions at all.
    let proof = log.log_certified(&zone, &statement, &zone.certificate(&[unknown]));
    assert!(matches!(
        verify(&proof, &zone, &log),
        Err(ProofError::Chain(_))
    ));
}

// -------------------------------------------------------- log-level checks

#[test]
fn a_broken_audit_path_fails_inclusion() {
    // A tree of one leaf has an empty audit path and proves nothing about
    // path handling; put the entry among neighbours first.
    let zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    log.append(b"an earlier entry");
    let mut proof = log.publish(&zone, "create");
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
        domain: &apex,
        signing_zone: &apex,
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
    let other = other_log.publish(&stranger, "rollover");
    zone.rekor_txt = other.to_txt().expect("encodes");
    zone.rekor_txt.extend(proof.to_txt().expect("encodes"));

    let anchor = write(&zone.anchor_record());
    let log_key = write(&log.key_pem());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        rekor_key: Some(log_key.path().to_path_buf()),
        rekor_state: None,
        tuf_url: None,
        // Nothing in this suite exercises pin refresh, and no test run
        // reaches Sigstore by accident.
        no_tuf: true,
        tuf_root: None,
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
        tuf_url: None,
        // Nothing in this suite exercises pin refresh, and no test run
        // reaches Sigstore by accident.
        no_tuf: true,
        tuf_root: None,
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
async fn a_proof_record_covering_only_someone_elses_keys_is_refused() {
    // Under the key-set claim there is no selector to filter on: every
    // served record is a candidate, so a record whose proven set does not
    // contain the key that signed the answer is *refused* — here as a chain
    // failure, since the stranger's set anchors under a key this resolver
    // never trusted — rather than filtered into looking absent. `synch
    // doctor` reads the two very differently, and this zone did publish
    // something; it published the wrong thing.
    let mut zone = SimZone::new("cluster.example", member_records());
    let stranger = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    zone.rekor_txt = log.publish(&stranger, "create").to_txt().expect("encodes");

    let anchor = write(&zone.anchor_record());
    let log_key = write(&log.key_pem());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        rekor_key: Some(log_key.path().to_path_buf()),
        rekor_state: None,
        tuf_url: None,
        // Nothing in this suite exercises pin refresh, and no test run
        // reaches Sigstore by accident.
        no_tuf: true,
        tuf_root: None,
    })
    .unwrap();
    let error = resolver.member_set("cluster.example").await.unwrap_err();
    assert!(
        matches!(error, NetError::RekorChain { .. }),
        "a record proving someone else's keys authorizes nothing here: {error}"
    );
    server.abort();
}

#[tokio::test]
async fn a_chainless_entry_is_refused_through_the_whole_resolver_path() {
    // The same refusal as the unit case, but reached the way a real client
    // reaches it, and surfaced as the error class `synch doctor` explains.
    let mut zone = SimZone::new("cluster.example", member_records());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create");
    let certificate = zone.certificate(&[]);
    let proof = log.log_certified(&zone, &statement, &certificate);
    zone.rekor_txt = proof.to_txt().expect("encodes");

    let anchor = write(&zone.anchor_record());
    let log_key = write(&log.key_pem());
    let (url, server) = zone.serve().await;

    let resolver = DnssecResolver::with_options(&ResolverOptions {
        doh_url: Some(url),
        trust_anchor: Some(anchor.path().to_path_buf()),
        rekor: Some(RekorPolicy::Require),
        rekor_key: Some(log_key.path().to_path_buf()),
        rekor_state: None,
        tuf_url: None,
        // Nothing in this suite exercises pin refresh, and no test run
        // reaches Sigstore by accident.
        no_tuf: true,
        tuf_root: None,
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
        tuf_url: None,
        // Nothing in this suite exercises pin refresh, and no test run
        // reaches Sigstore by accident.
        no_tuf: true,
        tuf_root: None,
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
    let proof = RekorProof::decode(&fixture("proof.bin")).expect("the fixture is a v4 proof");

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
    // The sim signs with the zone key, so the certificate's key is that key
    // too — allowed, not required: the signer and the subject set are
    // independent under this claim.
    assert_eq!(body.certificate.spki, rekor::p256_spki(&dnskey_rdata[4..]));
    let key = ZoneKey {
        domain: &apex,
        signing_zone: &apex,
        key_tag: fixture_field("key_tag").parse().expect("a key tag"),
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
        zonecert::{ChainLink, DnssecChain, OID_DNSSEC_CHAIN},
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
    // The three extensions X.509 requires of an end-entity key envelope are
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
    let statement = zone.zone_key_statement("create");
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
            "apex={}\nkey_tag={}\nlog_index={}\naction={}\n",
            zone.apex(),
            zone.key_tag(),
            proof.log_index,
            statement.action,
        )
        .as_bytes(),
    );
}

/// Publishes a fresh entry to the **real** Sigstore log and rewrites
/// `tests/fixtures/rekor_v3` from what comes back.
///
/// This writes to a permanent, public, append-only log. Nothing about it can
/// be undone, so it is not part of the suite and it refuses to run without
/// being asked twice:
///
/// `SYNCH_REKOR_PUBLISH=yes-write-to-the-real-log cargo test -p synch-net
/// --test rekor_zone_key -- --ignored --nocapture publish_a_real_entry`
///
/// Run it only when the entry format changes in a way that invalidates the
/// checked-in bytes. The apex stays under `.invalid` so that no real name is
/// ever claimed in a log nobody can edit, and the chain is self-anchored for
/// the same reason — we own no DNSSEC-signed domain, and minting a
/// certificate naming somebody else's would be squatting. Afterwards the
/// index and origin asserted in this file and in `crates/synch-monitor/tests/
/// real_entry.rs` move with it, and PROVENANCE.txt is rewritten — including
/// the log it names, which this run discovers rather than assumes.
#[tokio::test]
#[ignore]
async fn publish_a_real_entry() {
    assert_eq!(
        std::env::var("SYNCH_REKOR_PUBLISH").ok().as_deref(),
        Some("yes-write-to-the-real-log"),
        "refusing to write to a permanent public log without being asked"
    );
    // Which shard to write to is discovered, not pinned here: a fixture
    // regeneration run after Sigstore rotates must reach the log that is
    // actually open, not POST into a closed one and report the 4xx as a
    // format problem. The log id follows from the same entry's key, which is
    // also the pin the verification below will select on.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs();
    let tlogs = tuf::tlogs(tuf::EMBEDDED_TRUSTED_ROOT.as_bytes())
        .expect("the embedded trusted root lists its logs");
    let open = tuf::current_tlog(&tlogs, now).expect("Sigstore has a shard open");
    let log = open.base_url.clone();
    let log_id = open.log_id;
    println!("publishing to {log}");

    let zone = SimZone::new("zone-key-transparency.demo.invalid", member_records());
    let statement = zone.zone_key_statement("rollover");
    let statement_json = statement.to_json();
    let signature = zone.sign_dsse(&statement_json);
    let certificate = zone.zone_key_certificate();
    let digest = rekor::sha256(&rekor::pae(rekor::DSSE_PAYLOAD_TYPE, &statement_json));

    // The protojson `CreateEntryRequest` the control plane sends, in the one
    // shape Rekor v2 takes.
    let request = format!(
        "{{\"hashedRekordRequestV002\":{{\"digest\":\"{}\",\"signature\":\
         {{\"content\":\"{}\",\"verifier\":{{\"x509Certificate\":\
         {{\"rawBytes\":\"{}\"}},\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\"}}}}}}}}",
        rekor::base64_encode(&digest),
        rekor::base64_encode(&signature),
        rekor::base64_encode(&certificate),
    );
    let http = reqwest::Client::builder()
        .user_agent("synch-net fixture publisher")
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("http client");
    let response = http
        .post(format!("{log}/api/v2/log/entries"))
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(request)
        .send()
        .await
        .expect("the log must be reachable");
    let status = response.status();
    let text = response.text().await.expect("a response body");
    assert!(
        status.as_u16() == 200 || status.as_u16() == 201,
        "the log answered {status}: {text}"
    );
    let entry: serde_json::Value = serde_json::from_str(&text).expect("protojson");

    // protojson renders 64-bit integers as decimal strings.
    let log_index: u64 = entry["logIndex"]
        .as_str()
        .expect("logIndex")
        .parse()
        .expect("a decimal index");
    let canonicalized_body = b64(entry["canonicalizedBody"]
        .as_str()
        .expect("canonicalizedBody"));
    let checkpoint = entry["inclusionProof"]["checkpoint"]["envelope"]
        .as_str()
        .expect("checkpoint envelope")
        .as_bytes()
        .to_vec();
    let inclusion_path: Vec<[u8; 32]> = entry["inclusionProof"]["hashes"]
        .as_array()
        .expect("hashes")
        .iter()
        .map(|hash| {
            b64(hash.as_str().expect("a hash"))
                .try_into()
                .expect("32 bytes")
        })
        .collect();

    let proof = RekorProof {
        log_id,
        log_index,
        statement: statement_json.clone(),
        canonicalized_body,
        checkpoint,
        inclusion_path,
    };

    // Verified end to end before a byte is written: the entry the log stored
    // has to be one this build's own client accepts, or the fixture would
    // pin a shape nothing can read.
    let key = ZoneKey {
        domain: &zone.apex(),
        signing_zone: &zone.apex(),
        key_tag: zone.key_tag(),
        dnskey_rdata: &zone.dnskey_rdata(),
    };
    let verified = rekor::verify(&proof, &key, &LogKeys::embedded(), &anchors(&zone))
        .expect("the published entry must verify under the real log's key");
    assert_eq!(verified.log_index, log_index);
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rekor_v3");
    std::fs::create_dir_all(&dir).unwrap();
    let write_file = |name: &str, bytes: &[u8]| std::fs::write(dir.join(name), bytes).unwrap();
    write_file("statement.json", &proof.statement);
    write_file("canonicalized_body.json", &proof.canonicalized_body);
    write_file("certificate.der", &body.certificate_der);
    write_file("checkpoint.txt", &proof.checkpoint);
    write_file("proof.bin", &proof.encode().expect("the record encodes"));
    write_file("anchor.txt", zone.anchor_record().as_bytes());
    write_file("log_index.txt", format!("{log_index}\n").as_bytes());

    println!("published logIndex {log_index}");
    println!("apex     {}", zone.apex());
    println!("key tag  {}", zone.key_tag());
    println!("cert     {} bytes", body.certificate_der.len());
    println!("proof    {} bytes", proof.encode().unwrap().len());
    println!("DS       {}", zone.ds_field());
}

/// Standard-alphabet base64, as protojson renders every `bytes` field.
#[cfg(test)]
fn b64(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("protojson bytes are base64")
}

// ---------------------------------------------- real Sigstore conformance

/// A real published Rekor v2 entry with a certificate verifier, verified in
/// full, offline.
///
/// The bytes in `tests/fixtures/rekor_v3` are a genuine `hashedrekord` v0.0.2
/// entry published to `log2025-1.rekor.sigstore.dev` (see PROVENANCE.txt);
/// nothing in this repository authored the log's half of any of it — not the
/// checkpoint, not its signature lines, not the tree the audit path walks.
///
/// It settles empirically what no local test can: that Rekor performs no
/// certificate validation at all, so an apex written into a `dNSName` SAN
/// lands in the clear inside the Merkle leaf where a monitor can index it,
/// and that the log accepts a certificate of this size carrying the chain
/// extension under the narrowed 2.25 arc.
///
/// The whole client verifier runs over it, unmodified. The chain inside the
/// certificate is self-anchored at the apex — we own no DNSSEC-signed
/// domain, and minting a certificate naming one we do not control would be
/// squatting a name in a permanent public log — so a monitor rooted at ICANN
/// classifies it tier B, correctly. Real ICANN-rooted chain validation is
/// anchored separately by `tests/fixtures/dnssec_chain`, captured from live
/// DNS for `cloudflare.com`.
mod real_rekor_v3 {
    use super::*;

    fn v3(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rekor_v3")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
    }

    const APEX: &str = "zone-key-transparency.demo.invalid";
    const LOG_INDEX: u64 = 68_295_246;
    const KEY_TAG: u16 = 32_784;

    /// The anchor the zone is under, as `--dnssec-anchor` installs it.
    fn real_anchors() -> (
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

    /// The proof record, decoded by the same parser a client runs.
    fn real_proof() -> RekorProof {
        RekorProof::decode(&v3("proof.bin")).expect("the fixture is a current proof record")
    }

    /// The entire client verifier, over a real entry in a real log.
    ///
    /// Everything at once, which is the point: attribution, apex binding,
    /// key-set binding, statement binding, the DNSSEC chain, inclusion in the
    /// real tree, and a checkpoint signed by a key this build ships. A
    /// fixture that only proved the log's half would leave the claim's half
    /// resting entirely on simulation.
    #[test]
    fn the_real_entry_verifies_end_to_end() {
        let proof = real_proof();
        assert_eq!(proof.log_index, LOG_INDEX);
        let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
        let dnskey_rdata = chain_proven_key(&body);
        assert_eq!(chain::key_tag(&dnskey_rdata), KEY_TAG);

        let key = ZoneKey {
            domain: &format!("{APEX}."),
            signing_zone: &format!("{APEX}."),
            key_tag: KEY_TAG,
            dnskey_rdata: &dnskey_rdata,
        };
        let (_dir, anchors) = real_anchors();
        let verified = rekor::verify(&proof, &key, &LogKeys::embedded(), &anchors)
            .expect("a real published entry must verify under the real log's key");
        assert_eq!(verified.log_index, LOG_INDEX);
        assert_eq!(verified.action, "rollover");
    }

    /// The key the entry's own chain proves, read out of the chain and never
    /// looked up — the same rule the monitor follows.
    fn chain_proven_key(body: &HashedRekordBody) -> Vec<u8> {
        let (_dir, anchors) = real_anchors();
        let authorized =
            chain::authorize(&body.certificate, &anchors).expect("the real chain must authorize");
        let [rdata] = authorized.proven_keys.as_slice() else {
            panic!("a one-key zone proves one key");
        };
        rdata.clone()
    }

    /// Inclusion in the real tree, with teeth.
    #[test]
    fn the_real_entry_is_included_in_the_real_tree() {
        let proof = real_proof();
        let checkpoint = rekor::Checkpoint::parse(&proof.checkpoint).unwrap();
        assert_eq!(checkpoint.origin, "log2025-1.rekor.sigstore.dev");
        checkpoint
            .verify_under(&LogKeys::embedded())
            .expect("a real checkpoint verifies under the embedded pin set");
        // It verifies *among* several signature lines — the log's own plus
        // witness cosignatures. Nothing here interprets a cosignature (§8.2),
        // but the parser must keep tolerating them or every real checkpoint
        // becomes unparseable.
        assert!(
            String::from_utf8_lossy(&proof.checkpoint)
                .lines()
                .filter(|line| line.starts_with('\u{2014}'))
                .count()
                > 1,
            "the real log's checkpoints carry witness cosignatures"
        );
        rekor::verify_inclusion(
            proof.log_index,
            checkpoint.tree_size,
            rekor::leaf_hash(&proof.canonicalized_body),
            &proof.inclusion_path,
            checkpoint.root_hash,
        )
        .expect("the audit path must reach the real root");

        // One byte off the body and the leaf is not in the tree.
        let mut tampered = proof.canonicalized_body.clone();
        tampered[0] ^= 0x01;
        assert!(rekor::verify_inclusion(
            proof.log_index,
            checkpoint.tree_size,
            rekor::leaf_hash(&tampered),
            &proof.inclusion_path,
            checkpoint.root_hash,
        )
        .is_err());
    }

    /// The certificate really does carry the apex into the leaf, and really
    /// does carry its chain at a size the log accepted.
    #[test]
    fn the_real_entrys_certificate_carries_its_apex_and_its_chain() {
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

        // The chain survived the round trip under the narrowed OID. The size
        // is the empirical answer to "will Rekor take a certificate this
        // big, with an arc like this": it did, HTTP 201.
        assert_eq!(body.certificate_der.len(), 1118);
        let carried = body
            .certificate
            .extension(OID_DNSSEC_CHAIN)
            .expect("the real certificate carries the chain extension");
        let carried = synch_net::zonecert::DnssecChain::decode(carried).expect("and it decodes");
        // The chain starts at the declaration and the apex is the link above
        // it: an entry nobody but the zone could have produced.
        assert_eq!(
            carried.links[0].zone,
            format!("{}.{APEX}.", chain::TRANSPARENCY_LABEL)
        );
        assert_eq!(carried.links[1].zone, format!("{APEX}."));

        assert_eq!(body.digest.len(), 32);
        assert_eq!(body.certificate.spki.len(), 91);
    }

    /// The Statement the log committed to is this build's claim, and the
    /// leaf's digest is that Statement's DSSE PAE.
    #[test]
    fn the_statement_parses_and_the_pae_link_holds() {
        let statement = v3("statement.json");
        let parsed = rekor::ZoneKeyStatement::parse(&statement).expect("this build's claim");
        assert_eq!(parsed.apex, format!("{APEX}."));
        assert_eq!(parsed.action, "rollover");
        let [key] = parsed.keys.as_slice() else {
            panic!("a one-key zone claims one key");
        };
        assert_eq!(key.key_tag, KEY_TAG);

        // The leaf's digest is that Statement's DSSE PAE — the link between
        // the log's commitment and the bytes served beside it.
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

/// A P-256 log's checkpoint verifies whichever ECDSA encoding it used.
///
/// ECDSA signatures travel two ways — IEEE P1363's fixed 64-byte `r ‖ s`,
/// and ASN.1/DER — and the verifier used to accept only the fixed form.
/// Sigstore signs its notes with DER (the live `rekor.sigstore.dev`
/// signature is 70 bytes opening `30 44 02 20`), so that log's checkpoints
/// could never verify. It failed closed, so nothing was wrongly accepted,
/// but the day Sigstore opens a P-256-keyed v2 shard every client would
/// refuse every proof from it.
///
/// Nothing caught it because `SimLog` signed the fixed form too: the mock
/// produced exactly the bytes the bug required. It signs DER now, so the
/// assertion below is about the world rather than about ourselves — and the
/// first half of the test says so out loud, by reading the encoding off the
/// wire rather than trusting that the simulator changed.
#[test]
fn a_p256_checkpoint_verifies_in_der_which_is_what_sigstore_signs() {
    let log = SimLog::new("rekor.sim");
    let checkpoint = log.checkpoint();
    let keys = LogKeys::parse(&log.key_pem()).expect("the log's own key");

    // The signature really is DER: an ASN.1 SEQUENCE tag, and a length that
    // is not the fixed form's 64 bytes.
    let text = String::from_utf8(checkpoint.clone()).unwrap();
    let line = text
        .lines()
        .find(|l| l.starts_with("\u{2014} rekor.sim"))
        .expect("the log's own signature line");
    let blob = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(line.rsplit(' ').next().unwrap())
            .expect("base64")
    };
    let signature = &blob[4..]; // drop the four-byte key hint
    assert_eq!(signature[0], 0x30, "not a DER SEQUENCE: {signature:02x?}");
    assert_ne!(
        signature.len(),
        64,
        "a 64-byte signature would be the fixed form, and the point is that \
         this is not it"
    );

    synch_net::rekor::Checkpoint::parse(&checkpoint)
        .expect("the note parses")
        .verify_under(&keys)
        .expect("a DER checkpoint signature must verify under a P-256 log key");
}

/// A minimal, well-formed P-256 SubjectPublicKeyInfo — the shape the
/// certificate builder wants, with a stand-in point.
fn p256_spki_stub() -> Vec<u8> {
    synch_net::rekor::p256_spki(&[0x11; 64])
}

/// A certificate that decodes two ways decodes no ways.
///
/// Each of these is a second spelling of a value that already had one, and
/// for bytes sitting in a public log that is the whole problem: the leaf
/// must mean the same thing to this reader and to an auditor reading it with
/// anything else. Go's `crypto/x509` — which Rekor itself calls — refuses
/// all of them, so the public log would not have taken such a certificate;
/// relying on that would be keeping this design's invariant in somebody
/// else's parser.
#[test]
fn a_certificate_with_two_readings_is_refused() {
    use synch_net::x509::{Certificate, SelfSigned, OID_SUBJECT_ALT_NAME};

    let spki = p256_spki_stub();
    let base = || SelfSigned {
        common_name: "synchronicity zone key",
        dns_name: "sync.example",
        spki: &spki,
        serial: &[0x01],
        not_before: synch_net::x509::x509_time(1_760_000_000),
        not_after: synch_net::x509::x509_time(1_900_000_000),
        extensions: &[],
    };
    let sig = |_: &[u8]| vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

    // Baseline: the shape this design mints really does parse.
    let good = base().build(sig);
    assert!(Certificate::parse(&good).is_ok(), "the control must parse");

    // Trailing bytes after the outer SEQUENCE.
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(
        Certificate::parse(&trailing).is_err(),
        "bytes after the certificate must be refused"
    );

    // Two copies of the chain extension: the lookup used to take the first,
    // so a reader taking the last would disagree about the evidence that
    // decides reported-versus-silent.
    let doubled = vec![
        (
            synch_net::zonecert::OID_DNSSEC_CHAIN.to_vec(),
            b"first".to_vec(),
        ),
        (
            synch_net::zonecert::OID_DNSSEC_CHAIN.to_vec(),
            b"second".to_vec(),
        ),
    ];
    let mut spec = base();
    spec.extensions = &doubled;
    let two_chains = spec.build(sig);
    let parsed = Certificate::parse(&two_chains).expect("it is still a certificate");
    assert!(
        parsed
            .extension(synch_net::zonecert::OID_DNSSEC_CHAIN)
            .is_none(),
        "an extension present twice must resolve to neither copy"
    );
    // And the SAN rule it was always supposed to match still holds.
    assert!(
        parsed.extension(OID_SUBJECT_ALT_NAME).is_some(),
        "a single extension is unaffected"
    );
}

/// One record cannot turn a refresh into a scan.
///
/// The wire format lets a record claim up to 255 parts, and the client
/// fetches parts 2..=N sequentially with a per-query timeout inside a loop
/// that walks configured domains one at a time — so `1/255` cost every
/// resolving client 254 round trips before verifying a byte, and stalled
/// every *other* domain behind it for long enough that cached bindings
/// expire. The claim is now capped at what a real proof can need.
#[test]
fn a_records_part_count_is_capped_at_what_a_proof_can_need() {
    use synch_net::rekor::{parts_claimed, MAX_PROOF_PARTS};

    assert_eq!(
        parts_claimed(&["sync1p aabbccdd 1/255 QUJD".to_string()]),
        MAX_PROOF_PARTS,
        "a lying record must not name how much work this client does"
    );
    // Honest counts are untouched, including the single-record case.
    assert_eq!(parts_claimed(&["sync1p aabbccdd 1/3 QUJD".to_string()]), 3);
    assert_eq!(parts_claimed(&["sync1p aabbccdd 1/1 QUJD".to_string()]), 1);
    assert_eq!(parts_claimed(&[]), 1);
    // The cap has to clear a real proof with room to spare: an
    // ICANN-rooted one is 8202 base64url characters (§3), five records.
    let real_proof_chars = 8202;
    assert!(
        MAX_PROOF_PARTS * synch_net::rekor::PROOF_CHUNK_CHARS > 3 * real_proof_chars,
        "the cap must admit a real proof several times over"
    );
}
