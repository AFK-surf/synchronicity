//! Classification, and the invariant that couples it to the client.
//!
//! The three tiers are only useful if tier C — the silent bin — is exactly
//! "an entry no client would have accepted either". If a client ever accepted
//! something a monitor filed as tier C, an attacker would hold a key that
//! works against victims and rings no bell, which is strictly worse than not
//! logging at all. That invariant is asserted here directly, over every shape
//! of entry the two sides can disagree about.

use hickory_resolver::proto::dnssec::TrustAnchors;
use synch_monitor::{
    classify::{classify, KnownKeys, Tier},
    tiles::{TileSource, Tree},
    MonitorError,
};
use synch_net::{
    rekor::{self, HashedRekordBody, LogKeys, RekorProof, ZoneKey},
    sim::{SimLog, SimZone},
    zonecert::{Succession, OID_DNSSEC_CHAIN, OID_SUCCESSION},
};

fn members() -> Vec<String> {
    vec!["v=sync1 id=nas nk=aaaa".to_string()]
}

fn anchors(zone: &SimZone) -> TrustAnchors {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), zone.anchor_record()).unwrap();
    TrustAnchors::from_file(file.path()).unwrap()
}

/// Would a client accept this proof? The real verifier, no re-implementation.
fn client_accepts(proof: &RekorProof, zone: &SimZone, log: &SimLog) -> bool {
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
    .is_ok()
}

/// What would a monitor call it? The real classifier, no re-implementation.
fn monitor_tier(proof: &RekorProof, zone: &SimZone, known: &KnownKeys) -> Tier {
    let body = HashedRekordBody::parse(&proof.canonicalized_body).expect("a well-formed body");
    classify(&body, proof.log_index, known, &anchors(zone), None)
        .expect("a zone-key certificate is classifiable")
        .tier
}

/// Every entry shape the two halves could disagree about.
///
/// Named, so a failure says which one broke rather than "case 3".
fn shapes() -> Vec<(&'static str, SimZone, SimLog, RekorProof, KnownKeys)> {
    let mut out = Vec::new();

    // 1. The honest genesis key: valid chain, no predecessor to countersign.
    {
        let zone = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let proof = log.publish(&zone, "create", None);
        out.push(("genesis", zone, log, proof, KnownKeys::default()));
    }

    // 2. A routine rotation: valid chain, countersigned by a known key.
    {
        let old = SimZone::new("cluster.example", members());
        let zone = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let statement = zone.zone_key_statement("rollover", Some(old.key_tag()));
        let succession = old.countersign(&zone.apex(), &zone.spki());
        let proof = log.log_certified(
            &zone,
            &statement,
            &zone.zone_key_certificate(Some(&succession)),
        );
        let mut known = KnownKeys::default();
        known.insert(&zone.apex(), &old.spki());
        out.push(("rotation", zone, log, proof, known));
    }

    // 3. A substitution: the attacker holds the DS, so the chain is real —
    //    and cannot countersign, because that needs the old private key.
    {
        let old = SimZone::new("cluster.example", members());
        let zone = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let proof = log.publish(&zone, "create", None);
        let mut known = KnownKeys::default();
        known.insert(&zone.apex(), &old.spki());
        out.push(("substitution", zone, log, proof, known));
    }

    // 4. A forged countersignature: the attacker guesses at succession.
    {
        let old = SimZone::new("cluster.example", members());
        let zone = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let mut forged = old.countersign(&zone.apex(), &zone.spki());
        forged.signature[12] ^= 0x01;
        let statement = zone.zone_key_statement("rollover", Some(old.key_tag()));
        let proof = log.log_certified(&zone, &statement, &zone.zone_key_certificate(Some(&forged)));
        let mut known = KnownKeys::default();
        known.insert(&zone.apex(), &old.spki());
        out.push(("forged countersignature", zone, log, proof, known));
    }

    // 5. No chain at all.
    {
        let zone = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let statement = zone.zone_key_statement("create", None);
        let proof = log.log_certified(&zone, &statement, &zone.certificate(&[]));
        out.push(("chainless", zone, log, proof, KnownKeys::default()));
    }

    // 6. A chain whose signature does not verify.
    {
        let zone = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let mut chain = zone.dnssec_chain();
        let at = chain.links[0].rrs.len() - 3;
        chain.links[0].rrs[at] ^= 0x01;
        let statement = zone.zone_key_statement("create", None);
        let certificate = zone.certificate(&[(OID_DNSSEC_CHAIN.to_vec(), chain.encode())]);
        let proof = log.log_certified(&zone, &statement, &certificate);
        out.push(("broken chain", zone, log, proof, KnownKeys::default()));
    }

    // 7. A chain that is valid — for a different zone's key.
    {
        let zone = SimZone::new("cluster.example", members());
        let stranger = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let statement = zone.zone_key_statement("create", None);
        let certificate =
            zone.certificate(&[(OID_DNSSEC_CHAIN.to_vec(), stranger.dnssec_chain().encode())]);
        let proof = log.log_certified(&zone, &statement, &certificate);
        out.push(("wrong-key chain", zone, log, proof, KnownKeys::default()));
    }

    // 8. A chain that was valid long ago and has expired since. Archival, and
    //    therefore still perfectly good — neither side consults a clock.
    {
        let zone = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let ancient = time::OffsetDateTime::now_utc() - time::Duration::days(900);
        let statement = zone.zone_key_statement("create", None);
        let certificate = zone.certificate(&[(
            OID_DNSSEC_CHAIN.to_vec(),
            zone.dnssec_chain_at(ancient).encode(),
        )]);
        let proof = log.log_certified(&zone, &statement, &certificate);
        out.push(("expired chain", zone, log, proof, KnownKeys::default()));
    }

    out
}

/// **The invariant.** Anything a client accepts is at least tier B.
#[test]
fn nothing_a_client_accepts_lands_in_the_silent_bin() {
    for (name, zone, log, proof, known) in shapes() {
        let accepted = client_accepts(&proof, &zone, &log);
        let tier = monitor_tier(&proof, &zone, &known);
        assert!(
            !accepted || tier != Tier::C,
            "{name}: the client accepted an entry the monitor files as noise"
        );
        // And the converse half that makes tier C safe to be quiet about: an
        // entry the monitor calls noise is one no client would take.
        assert!(
            tier != Tier::C || !accepted,
            "{name}: tier C must mean unusable"
        );
    }
}

/// The tiers themselves, case by case.
#[test]
fn each_shape_lands_where_the_design_says_it_should() {
    let expected = [
        ("genesis", Tier::B),
        ("rotation", Tier::A),
        ("substitution", Tier::B),
        ("forged countersignature", Tier::B),
        ("chainless", Tier::C),
        ("broken chain", Tier::C),
        ("wrong-key chain", Tier::C),
        ("expired chain", Tier::B),
    ];
    for (name, zone, _log, proof, known) in shapes() {
        let want = expected
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, t)| *t)
            .unwrap_or_else(|| panic!("no expectation for {name}"));
        assert_eq!(monitor_tier(&proof, &zone, &known), want, "{name}");
    }
}

/// A predecessor the monitor has never heard of does not make tier A.
///
/// Otherwise an attacker's first substituted key would be a valid predecessor
/// for their second, and every key after the first would look routine.
#[test]
fn an_unknown_predecessor_cannot_manufacture_tier_a() {
    let old = SimZone::new("cluster.example", members());
    let zone = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    let succession = old.countersign(&zone.apex(), &zone.spki());
    let statement = zone.zone_key_statement("rollover", Some(old.key_tag()));
    let proof = log.log_certified(
        &zone,
        &statement,
        &zone.zone_key_certificate(Some(&succession)),
    );

    // Signature perfectly valid, key unknown: tier B.
    assert_eq!(monitor_tier(&proof, &zone, &KnownKeys::default()), Tier::B);
    // The same entry, once the operator has told the monitor about the old
    // key: tier A.
    let mut known = KnownKeys::default();
    known.insert(&zone.apex(), &old.spki());
    assert_eq!(monitor_tier(&proof, &zone, &known), Tier::A);
}

/// A countersignature over a *different* successor does not transfer.
#[test]
fn a_countersignature_is_bound_to_the_key_it_names() {
    let old = SimZone::new("cluster.example", members());
    let zone = SimZone::new("cluster.example", members());
    let stranger = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    // A genuine countersignature — for somebody else's key, replayed here.
    let elsewhere = old.countersign(&zone.apex(), &stranger.spki());
    let statement = zone.zone_key_statement("rollover", Some(old.key_tag()));
    let proof = log.log_certified(
        &zone,
        &statement,
        &zone.zone_key_certificate(Some(&elsewhere)),
    );
    let mut known = KnownKeys::default();
    known.insert(&zone.apex(), &old.spki());
    assert_eq!(monitor_tier(&proof, &zone, &known), Tier::B);
}

/// What a monitor derives, it derives from the certificate alone.
#[test]
fn the_key_tag_and_ds_come_from_the_certificate_never_from_dns() {
    let zone = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    let proof = log.publish(&zone, "create", None);
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    let finding = classify(&body, 7, &KnownKeys::default(), &anchors(&zone), None).unwrap();

    // The same key tag and DS the zone itself would publish, arrived at with
    // no DNS query — which is the only reason a compromised provider cannot
    // steer what the monitor concludes.
    assert_eq!(finding.key_tag, zone.key_tag());
    assert_eq!(finding.ds, zone.ds_field());
    assert_eq!(finding.apex, zone.apex().trim_end_matches('.'));
    assert_eq!(finding.log_index, 7);
    assert!(finding
        .line()
        .starts_with("[B] index 7 apex cluster.example"));
}

/// The witness clock is a note on a finding, never a verdict.
#[test]
fn a_stale_chain_is_flagged_without_changing_the_tier() {
    let zone = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    let ancient = time::OffsetDateTime::now_utc() - time::Duration::days(900);
    let statement = zone.zone_key_statement("create", None);
    let certificate = zone.certificate(&[(
        OID_DNSSEC_CHAIN.to_vec(),
        zone.dnssec_chain_at(ancient).encode(),
    )]);
    let proof = log.log_certified(&zone, &statement, &certificate);
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let flagged = classify(&body, 0, &KnownKeys::default(), &anchors(&zone), Some(now)).unwrap();
    assert_eq!(flagged.tier, Tier::B);
    assert!(
        flagged
            .reasons
            .iter()
            .any(|r| r.contains("outside their validity window")),
        "{:?}",
        flagged.reasons
    );

    // With no witness timestamp there is no clock, so there is no note — and
    // the tier is the same either way, which is the property that matters.
    let unflagged = classify(&body, 0, &KnownKeys::default(), &anchors(&zone), None).unwrap();
    assert_eq!(unflagged.tier, flagged.tier);
    assert_eq!(unflagged.reasons.len(), flagged.reasons.len() - 1);
}

/// A succession extension the certificate carries but that does not decode
/// is tier B, not a crash and not tier C.
#[test]
fn an_undecodable_succession_extension_is_still_only_tier_b() {
    let zone = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    let statement = zone.zone_key_statement("create", None);
    let certificate = zone.certificate(&[
        (OID_DNSSEC_CHAIN.to_vec(), zone.dnssec_chain().encode()),
        (OID_SUCCESSION.to_vec(), b"not der".to_vec()),
    ]);
    let proof = log.log_certified(&zone, &statement, &certificate);
    assert_eq!(monitor_tier(&proof, &zone, &KnownKeys::default()), Tier::B);
}

/// The succession payload is the one both halves sign; assert its bytes here
/// too, where a Gleam signer and a Rust verifier have to meet.
#[test]
fn the_succession_payload_is_the_bytes_both_halves_agree_on() {
    let payload = Succession::signed_payload("cluster.example.", 4242, b"spki");
    assert_eq!(
        String::from_utf8(payload).unwrap(),
        format!(
            "{{\"apex\":\"cluster.example\",\"predecessorKeyTag\":4242,\
             \"successorSpkiSha256\":\"{}\"}}",
            hex::encode(rekor::sha256(b"spki"))
        )
    );
}

/// A monitor reads leaves out of tiles; assert it against a whole simulated
/// log rather than against a hand-built bundle.
#[test]
fn a_monitor_finds_a_zones_entry_by_walking_bundles() {
    struct Bundles(Vec<Vec<u8>>);
    impl TileSource for Bundles {
        fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>, MonitorError> {
            assert!(path.starts_with("api/v2/tile/entries/"), "{path}");
            let mut out = Vec::new();
            for body in &self.0 {
                out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                out.extend_from_slice(body);
            }
            Ok(Some(out))
        }
    }

    let zone = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    log.append(b"somebody else's entry");
    let proof = log.publish(&zone, "create", None);
    let bundles = Bundles(vec![
        b"somebody else's entry".to_vec(),
        proof.canonicalized_body.clone(),
    ]);
    let tree = Tree::new(&bundles, 2);

    let mut found = Vec::new();
    for (index, body) in tree.entry_bundle(0).unwrap() {
        let Ok(parsed) = HashedRekordBody::parse(&body) else {
            continue;
        };
        found.push((
            index,
            parsed.certificate.single_dns_name().unwrap().to_string(),
        ));
    }
    assert_eq!(found, vec![(1, "cluster.example".to_string())]);
}
