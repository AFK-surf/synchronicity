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
    sim::{SimDelegation, SimLog, SimZone},
    zonecert::{Succession, OID_DNSSEC_CHAIN, OID_SUCCESSION},
};

fn members() -> Vec<String> {
    vec!["v=sync1 id=nas nk=aaaa".to_string()]
}

fn anchors(record: &str) -> TrustAnchors {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), record).unwrap();
    TrustAnchors::from_file(file.path()).unwrap()
}

/// One entry, and everything both halves need to judge it.
///
/// The anchor travels with the shape rather than being derived from the zone,
/// because a root-anchored ladder is anchored at the *root's* key and a
/// self-anchored zone at its own. Deriving it from the zone is what limited
/// this suite to one chain shape.
struct Shape {
    name: &'static str,
    /// The zone whose key the entry is about — what a resolver observed.
    zone: SimZone,
    log: SimLog,
    proof: RekorProof,
    known: KnownKeys,
    /// The trust anchor a reader of this entry holds, in `--dnssec-anchor`
    /// syntax.
    anchor: String,
    /// The apex a resolver would report from the RRSIG signer field. Almost
    /// always the zone's own; a malformed-SAN shape is where it differs.
    observed_apex: String,
}

/// Would a client accept this proof? The real verifier, no re-implementation.
fn client_accepts(shape: &Shape) -> bool {
    let rdata = shape.zone.dnskey_rdata();
    let key = ZoneKey {
        apex: &shape.observed_apex,
        key_tag: shape.zone.key_tag(),
        dnskey_rdata: &rdata,
    };
    rekor::verify(
        &shape.proof,
        &key,
        &LogKeys::parse(&shape.log.key_pem()).unwrap(),
        &anchors(&shape.anchor),
    )
    .is_ok()
}

/// What would a monitor call it? The real classifier, no re-implementation.
fn monitor_tier(shape: &Shape) -> Tier {
    let body =
        HashedRekordBody::parse(&shape.proof.canonicalized_body).expect("a well-formed body");
    match classify(
        &body,
        shape.proof.log_index,
        &shape.known,
        &anchors(&shape.anchor),
    ) {
        Some(finding) => finding.tier,
        // A certificate the classifier declines to judge at all — an
        // unparseable SAN, a key that is not ours — is not in *any* tier, and
        // for the invariant that is strictly worse than tier C: the entry is
        // not even recorded. Treat it as C so the assertion below has teeth.
        None => Tier::C,
    }
}

/// How a shape's chain is built: the degenerate self-anchored form, or the
/// root → TLD → apex ladder production actually emits.
///
/// Both, always. Every shape below is generated twice, because until this
/// suite ran over a multi-link chain it was exercising exactly one branch of
/// the validator — and the divergence that let a client-accepted entry be
/// filed tier C only appears once a chain has a parent to climb to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rooted {
    /// The apex is its own trust anchor (`--dnssec-anchor` deployments).
    SelfAnchored,
    /// A synthetic root → TLD → apex delegation, anchored at the root.
    Ladder,
}

impl Rooted {
    fn label(&self) -> &'static str {
        match self {
            Rooted::SelfAnchored => "self-anchored",
            Rooted::Ladder => "ladder",
        }
    }
}

/// A zone plus the chain material for the shape being built.
struct Ground {
    zone: SimZone,
    anchor: String,
    chain: synch_net::zonecert::DnssecChain,
}

fn ground(rooted: Rooted) -> Ground {
    match rooted {
        Rooted::SelfAnchored => {
            let zone = SimZone::new("cluster.example", members());
            let anchor = zone.anchor_record();
            let chain = zone.dnssec_chain();
            Ground {
                zone,
                anchor,
                chain,
            }
        }
        Rooted::Ladder => {
            let delegation = SimDelegation::new("cluster.example", members());
            let anchor = delegation.anchor_record();
            let chain = delegation.chain();
            Ground {
                zone: delegation.apex,
                anchor,
                chain,
            }
        }
    }
}

/// Every entry shape the two halves could disagree about, in both chain
/// shapes.
///
/// Named, so a failure says which one broke rather than "case 3".
fn shapes() -> Vec<Shape> {
    let mut out = Vec::new();
    for rooted in [Rooted::SelfAnchored, Rooted::Ladder] {
        out.extend(shapes_for(rooted));
    }
    out
}

fn shapes_for(rooted: Rooted) -> Vec<Shape> {
    let mut out = Vec::new();
    let leak = |name: &str| -> &'static str { Box::leak(name.to_string().into_boxed_str()) };
    let mut push = |name: &str,
                    g: Ground,
                    log: SimLog,
                    proof: RekorProof,
                    known: KnownKeys,
                    observed: Option<String>| {
        let observed_apex = observed.unwrap_or_else(|| g.zone.apex());
        out.push(Shape {
            name: leak(&format!("{name} ({})", rooted.label())),
            zone: g.zone,
            log,
            proof,
            known,
            anchor: g.anchor,
            observed_apex,
        });
    };
    let certificate = |g: &Ground, succession: Option<&Succession>| {
        let mut extensions = vec![(OID_DNSSEC_CHAIN.to_vec(), g.chain.encode())];
        if let Some(succession) = succession {
            extensions.push((OID_SUCCESSION.to_vec(), succession.encode()));
        }
        g.zone.certificate(&extensions)
    };

    // 1. The honest genesis key: valid chain, no predecessor to countersign.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g, None));
        push("genesis", g, log, proof, KnownKeys::default(), None);
    }

    // 2. A routine rotation: valid chain, countersigned by a known key.
    {
        let g = ground(rooted);
        let old = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("rollover", Some(old.key_tag()));
        let succession = old.countersign(&g.zone.apex(), &g.zone.spki());
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g, Some(&succession)));
        let mut known = KnownKeys::default();
        known.insert(&apex_name(&g.zone), &old.spki());
        push("rotation", g, log, proof, known, None);
    }

    // 3. A substitution: the attacker holds the DS, so the chain is real —
    //    and cannot countersign, because that needs the old private key.
    {
        let g = ground(rooted);
        let old = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g, None));
        let mut known = KnownKeys::default();
        known.insert(&apex_name(&g.zone), &old.spki());
        push("substitution", g, log, proof, known, None);
    }

    // 4. A forged countersignature: the attacker guesses at succession.
    {
        let g = ground(rooted);
        let old = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let mut forged = old.countersign(&g.zone.apex(), &g.zone.spki());
        forged.signature[12] ^= 0x01;
        let statement = g.zone.zone_key_statement("rollover", Some(old.key_tag()));
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g, Some(&forged)));
        let mut known = KnownKeys::default();
        known.insert(&apex_name(&g.zone), &old.spki());
        push("forged countersignature", g, log, proof, known, None);
    }

    // 5. No chain at all.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &g.zone.certificate(&[]));
        push("chainless", g, log, proof, KnownKeys::default(), None);
    }

    // 6. A chain whose signature does not verify.
    {
        let mut g = ground(rooted);
        let at = g.chain.links[0].rrs.len() - 3;
        g.chain.links[0].rrs[at] ^= 0x01;
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g, None));
        push("broken chain", g, log, proof, KnownKeys::default(), None);
    }

    // 7. A chain that is valid — for a different zone's key.
    {
        let mut g = ground(rooted);
        g.chain = ground(rooted).chain;
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g, None));
        push("wrong-key chain", g, log, proof, KnownKeys::default(), None);
    }

    // 8. A chain that was valid long ago and has expired since. Archival, and
    //    therefore still perfectly good — neither side consults a clock.
    {
        let mut g = ground(rooted);
        let ancient = time::OffsetDateTime::now_utc() - time::Duration::days(900);
        g.chain = match rooted {
            Rooted::SelfAnchored => g.zone.dnssec_chain_at(ancient),
            // A ladder needs every level re-signed at the old inception, so
            // rebuild it rather than reaching into one link.
            Rooted::Ladder => {
                let delegation = SimDelegation::new("cluster.example", members());
                let chain = delegation.chain_at(ancient);
                g.anchor = delegation.anchor_record();
                g.zone = delegation.apex;
                chain
            }
        };
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g, None));
        push("expired chain", g, log, proof, KnownKeys::default(), None);
    }

    // 9-12. SANs that are not names, or name somebody else. This is the
    //       family that broke the invariant in production code: the client
    //       compared SANs by trimming trailing dots while the monitor parsed
    //       them, so `cluster.example..` satisfied the client *and* failed to
    //       parse for the monitor — accepted everywhere, alerted nowhere.
    for (label, san) in [
        ("malformed san (double dot)", "cluster.example.."),
        ("malformed san (triple dot)", "cluster.example..."),
        ("malformed san (upper double dot)", "CLUSTER.EXAMPLE.."),
        ("malformed san (empty)", ""),
    ] {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let certificate = g
            .zone
            .certificate_for(san, &[(OID_DNSSEC_CHAIN.to_vec(), g.chain.encode())]);
        let proof = log.log_certified(&g.zone, &statement, &certificate);
        push(label, g, log, proof, KnownKeys::default(), None);
    }

    // 13. A well-formed SAN naming a zone that is not the one the Statement
    //     and the resolver are about.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let certificate = g.zone.certificate_for(
            "somewhere.else",
            &[(OID_DNSSEC_CHAIN.to_vec(), g.chain.encode())],
        );
        let proof = log.log_certified(&g.zone, &statement, &certificate);
        push(
            "san names another zone",
            g,
            log,
            proof,
            KnownKeys::default(),
            None,
        );
    }

    out
}

/// The tier of a proof about `zone`, anchored at that zone's own key — the
/// shorthand the single-purpose tests below use.
fn tier_of(proof: &RekorProof, zone: &SimZone, known: &KnownKeys) -> Tier {
    let body = HashedRekordBody::parse(&proof.canonicalized_body).expect("a well-formed body");
    match classify(
        &body,
        proof.log_index,
        known,
        &anchors(&zone.anchor_record()),
    ) {
        Some(finding) => finding.tier,
        None => Tier::C,
    }
}

/// A zone's apex as a parsed name, for `KnownKeys`.
fn apex_name(zone: &SimZone) -> hickory_resolver::proto::rr::Name {
    synch_net::chain::parse_name(&zone.apex()).expect("a sim apex is a name")
}

/// **The invariant.** Anything a client accepts is at least tier B.
#[test]
fn nothing_a_client_accepts_lands_in_the_silent_bin() {
    for shape in shapes() {
        let name = shape.name;
        let accepted = client_accepts(&shape);
        let tier = monitor_tier(&shape);
        assert!(
            !accepted || tier != Tier::C,
            "{name}: the client accepted an entry the monitor files as noise"
        );
        // The invariant above is satisfied trivially by a client that accepts
        // nothing, so pin what acceptance actually is. These are the shapes a
        // resolver must take — including the two that alarm a monitor, because
        // the substitution *is* usable and the whole point is that it is loud
        // rather than refused here — and the three it must refuse, which are
        // exactly the tier C bin.
        let must_accept = match name.split(" (").next().expect("a shape name") {
            "genesis"
            | "rotation"
            | "substitution"
            | "forged countersignature"
            | "expired chain" => true,
            "chainless"
            | "broken chain"
            | "wrong-key chain"
            | "malformed san"
            | "san names another zone" => false,
            other => panic!("unclassified shape {other}: say whether a client takes it"),
        };
        assert_eq!(accepted, must_accept, "{name}: client acceptance");
    }
}

/// Both chain shapes really are exercised, and they really are different.
///
/// Without this the suite could silently collapse back to one branch — which
/// is exactly what it did before, and what hid the divergence above.
#[test]
fn the_suite_covers_both_a_self_anchored_chain_and_a_real_ladder() {
    let all = shapes();
    assert!(all.iter().any(|s| s.name.ends_with("(self-anchored)")));
    assert!(all.iter().any(|s| s.name.ends_with("(ladder)")));

    let genesis = |label: &str| {
        let shape = all
            .iter()
            .find(|s| s.name == format!("genesis ({label})"))
            .expect("a genesis shape");
        let body = HashedRekordBody::parse(&shape.proof.canonicalized_body).unwrap();
        synch_net::chain::authorize(&body.certificate, &anchors(&shape.anchor))
            .expect("genesis authorizes")
    };
    let self_anchored = genesis("self-anchored");
    let ladder = genesis("ladder");
    assert_eq!(self_anchored.chain.links, 1);
    assert!(self_anchored.chain.anchored_directly);
    // The ladder walks a real delegation: apex DS, TLD DNSKEY+DS, root DNSKEY.
    assert_eq!(ladder.chain.links, 3);
    assert!(!ladder.chain.anchored_directly);
    assert_eq!(ladder.chain.anchor_zone, ".");
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
        // A SAN that is not a name names no zone: nothing to classify, and
        // nothing a client takes either.
        ("malformed san", Tier::C),
        // A well-formed SAN with a chain for a *different* zone is an
        // unauthorized claim about the zone it names — tier C, and refused by
        // every client. A monitor watching the zone whose chain it stole
        // never sees it at all, because the SAN does not match.
        ("san names another zone", Tier::C),
    ];
    for shape in shapes() {
        let base = shape.name.split(" (").next().expect("a shape name");
        let want = expected
            .iter()
            .find(|(n, _)| *n == base)
            .map(|(_, t)| *t)
            .unwrap_or_else(|| panic!("no expectation for {}", shape.name));
        assert_eq!(monitor_tier(&shape), want, "{}", shape.name);
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
    assert_eq!(tier_of(&proof, &zone, &KnownKeys::default()), Tier::B);
    // The same entry, once the operator has told the monitor about the old
    // key: tier A.
    let mut known = KnownKeys::default();
    known.insert(&apex_name(&zone), &old.spki());
    assert_eq!(tier_of(&proof, &zone, &known), Tier::A);
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
    known.insert(&apex_name(&zone), &old.spki());
    assert_eq!(tier_of(&proof, &zone, &known), Tier::B);
}

/// What a monitor derives, it derives from the certificate alone.
#[test]
fn the_key_tag_and_ds_come_from_the_certificate_never_from_dns() {
    let zone = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    let proof = log.publish(&zone, "create", None);
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    let finding = classify(
        &body,
        7,
        &KnownKeys::default(),
        &anchors(&zone.anchor_record()),
    )
    .unwrap();

    // The same key tag and DS the zone itself would publish, arrived at with
    // no DNS query — which is the only reason a compromised provider cannot
    // steer what the monitor concludes.
    assert_eq!(finding.key_tag, zone.key_tag());
    assert_eq!(finding.ds, zone.ds_field());
    // The apex is reported in canonical form — parsed from the SAN, so it
    // carries its root dot however the certificate happened to spell it.
    assert_eq!(finding.apex, zone.apex());
    assert_eq!(finding.log_index, 7);
    assert!(finding
        .line()
        .starts_with("[B] index 7 apex cluster.example"));
}

/// A long-expired chain classifies exactly like a fresh one.
///
/// This is what is left of the old staleness note, and it is the half worth
/// keeping: the monitor consults **no clock at all** now, so an entry whose
/// RRSIGs expired years ago lands in the same tier as one signed this
/// morning. It has to. The client does not check windows either (there is no
/// attested time anywhere near a leaf, and archival entries are read for
/// years), so a monitor that quietly demoted an expired chain would put a
/// client-acceptable entry in the silent bin — the exact evasion the
/// invariant forbids.
#[test]
fn a_long_expired_chain_classifies_the_same_as_a_fresh_one() {
    let zone = SimZone::new("cluster.example", members());
    let statement = zone.zone_key_statement("create", None);

    let classify_chain = |chain: Vec<u8>| {
        let mut log = SimLog::new("rekor.sim");
        let certificate = zone.certificate(&[(OID_DNSSEC_CHAIN.to_vec(), chain)]);
        let proof = log.log_certified(&zone, &statement, &certificate);
        let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
        classify(
            &body,
            0,
            &KnownKeys::default(),
            &anchors(&zone.anchor_record()),
        )
        .unwrap()
    };

    let ancient = time::OffsetDateTime::now_utc() - time::Duration::days(900);
    let expired = classify_chain(zone.dnssec_chain_at(ancient).encode());
    let fresh = classify_chain(zone.dnssec_chain().encode());

    assert_eq!(expired.tier, Tier::B);
    assert_eq!(expired.tier, fresh.tier);
    // Not merely the same tier — the same reasons, because nothing in the
    // classifier looks at time at all.
    assert_eq!(expired.reasons, fresh.reasons);
    assert!(
        expired.reasons.iter().any(|r| r.contains("chain valid")),
        "{:?}",
        expired.reasons
    );
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
    assert_eq!(tier_of(&proof, &zone, &KnownKeys::default()), Tier::B);
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
    assert_eq!(found, vec![(1, "cluster.example.".to_string())]);
}
