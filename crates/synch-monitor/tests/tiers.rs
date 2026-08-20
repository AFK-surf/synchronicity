//! Classification, and the invariant coupling it to the client: tier B — the
//! silent bin — must be exactly "an entry no client would have accepted",
//! asserted over every shape the two sides can disagree about, in both chain
//! shapes.

use hickory_resolver::proto::dnssec::TrustAnchors;
use synch_monitor::classify::{classify, Tier};
use synch_net::{
    rekor::{self, HashedRekordBody, LogKeys, RekorProof, ZoneKey},
    sim::{SimDelegation, SimLog, SimZone},
    zonecert::OID_DNSSEC_CHAIN,
};

fn members() -> Vec<String> {
    vec!["v=sync1 id=nas nk=aaaa".to_string()]
}

fn anchors(record: &str) -> TrustAnchors {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), record).unwrap();
    TrustAnchors::from_file(file.path()).unwrap()
}

/// One entry, and everything both halves need to judge it. The anchor travels
/// with the shape (a root-anchored ladder is anchored at the root's key, a
/// self-anchored zone at its own).
struct Shape {
    name: &'static str,
    /// The zone whose key the entry is about — what a resolver observed.
    zone: SimZone,
    log: SimLog,
    proof: RekorProof,
    /// The trust anchor a reader of this entry holds, in `--dnssec-anchor`
    /// syntax.
    anchor: String,
}

/// Would a client accept this proof? The real verifier, no re-implementation.
fn client_accepts(shape: &Shape) -> bool {
    let observed_zone = shape.zone.apex();
    let key = ZoneKey {
        domain: &observed_zone,
        signing_zone: &observed_zone,
        key_tag: shape.zone.key_tag(),
        dnskey_rdata: &shape.zone.dnskey_rdata(),
    };
    rekor::verify(
        &shape.proof,
        &key,
        &LogKeys::parse(&shape.log.key_pem()).unwrap(),
        &anchors(&shape.anchor),
    )
    .is_ok()
}

/// What a monitor does with a leaf: a tier, or nothing at all. `classify`
/// returning `None` is **not** tier B — tier B is noted on stderr as an
/// unauthorized claim, while `None` means the leaf was never judged, not
/// even counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Tiered(Tier),
    Unclassified,
}

/// What would a monitor call it? The real classifier, no re-implementation.
fn monitor_verdict(shape: &Shape) -> Verdict {
    let body =
        HashedRekordBody::parse(&shape.proof.canonicalized_body).expect("a well-formed body");
    match classify(&body, shape.proof.log_index, &anchors(&shape.anchor)) {
        Some(finding) => Verdict::Tiered(finding.tier),
        None => Verdict::Unclassified,
    }
}

/// How a shape's chain is built: the degenerate self-anchored form, or the
/// root → TLD → apex ladder production actually emits. Both, always: every
/// shape below is generated twice, because the divergence that let a
/// client-accepted entry be filed tier B only appears once a chain has a
/// parent to climb to.
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

/// Every entry shape the two halves could disagree about, in both chain shapes.
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
    let mut push = |name: &str, g: Ground, log: SimLog, proof: RekorProof| {
        out.push(Shape {
            name: leak(&format!("{name} ({})", rooted.label())),
            zone: g.zone,
            log,
            proof,
            anchor: g.anchor,
        });
    };
    let certificate = |g: &Ground| {
        g.zone
            .certificate(&[(OID_DNSSEC_CHAIN.to_vec(), g.chain.encode())])
    };
    let certify = |g: &Ground, log: &mut SimLog| {
        let statement = g.zone.zone_key_statement("create");
        log.log_certified(&g.zone, &statement, &certificate(g))
    };

    // 1. The honest genesis key: a zone's first, with a valid chain.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let proof = certify(&g, &mut log);
        push("genesis", g, log, proof);
    }

    // 2. A routine rotation the operator performed.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("rollover");
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g));
        push("rotation", g, log, proof);
    }

    // 3. A substitution: the attacker holds the DS, so the chain is real and
    //    byte-for-byte indistinguishable from a rotation — the point: both are
    //    reported, and only the operator's records answer which happened.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let proof = certify(&g, &mut log);
        push("substitution", g, log, proof);
    }

    // 4. No chain at all.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create");
        let proof = log.log_certified(&g.zone, &statement, &g.zone.certificate(&[]));
        push("chainless", g, log, proof);
    }

    // 5. A chain whose signature does not verify.
    {
        let mut g = ground(rooted);
        let at = g.chain.links[0].rrs.len() - 3;
        g.chain.links[0].rrs[at] ^= 0x01;
        let mut log = SimLog::new("rekor.sim");
        let proof = certify(&g, &mut log);
        push("broken chain", g, log, proof);
    }

    // 6. A chain that is valid — for a different zone's key.
    {
        let mut g = ground(rooted);
        g.chain = ground(rooted).chain;
        let mut log = SimLog::new("rekor.sim");
        let proof = certify(&g, &mut log);
        push("wrong-key chain", g, log, proof);
    }

    // 7. A chain that expired long ago — archival, still perfectly good:
    //    neither side consults a clock.
    {
        let mut g = ground(rooted);
        let ancient = time::OffsetDateTime::now_utc() - time::Duration::days(900);
        g.chain = match rooted {
            Rooted::SelfAnchored => g.zone.dnssec_chain_at(ancient),
            // A ladder needs every level re-signed at the old inception.
            Rooted::Ladder => {
                let delegation = SimDelegation::new("cluster.example", members());
                let chain = delegation.chain_at(ancient);
                g.anchor = delegation.anchor_record();
                g.zone = delegation.apex;
                chain
            }
        };
        let mut log = SimLog::new("rekor.sim");
        let proof = certify(&g, &mut log);
        push("expired chain", g, log, proof);
    }

    // 8-11. SANs that are not names, or name somebody else — the family that
    //       broke the invariant: the client trimmed trailing dots while the
    //       monitor parsed them, so `cluster.example..` was accepted by the
    //       client and unparseable to the monitor — alerted nowhere.
    for (label, san) in [
        ("malformed san (double dot)", "cluster.example.."),
        ("malformed san (empty)", ""),
    ] {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let certificate = g
            .zone
            .certificate_for(san, &[(OID_DNSSEC_CHAIN.to_vec(), g.chain.encode())]);
        let statement = g.zone.zone_key_statement("create");
        let proof = log.log_certified(&g.zone, &statement, &certificate);
        push(label, g, log, proof);
    }

    // 12. A well-formed SAN naming a different zone than the Statement is about.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let certificate = g.zone.certificate_for(
            "somewhere.else",
            &[(OID_DNSSEC_CHAIN.to_vec(), g.chain.encode())],
        );
        let statement = g.zone.zone_key_statement("create");
        let proof = log.log_certified(&g.zone, &statement, &certificate);
        push("san names another zone", g, log, proof);
    }

    out
}

/// The chain may not prove a signing zone the membership answer was not signed
/// by: two ancestors of one domain need not be equal, so a parent zone's entry
/// can be offered for a child's answer. It had no test — every `ZoneKey` set
/// `signing_zone` equal to the apex, so deleting the check left the suite
/// green — and `check_binds` matches on rdata digest, so shared key material
/// would let the parent's entry authorize the child's answer.
#[test]
fn an_entry_whose_chain_proves_another_signing_zone_is_refused() {
    let g = ground(Rooted::SelfAnchored);
    let mut log = SimLog::new("rekor.sim");
    let statement = g.zone.zone_key_statement("create");
    let certificate = g
        .zone
        .certificate(&[(OID_DNSSEC_CHAIN.to_vec(), g.chain.encode())]);
    let proof = log.log_certified(&g.zone, &statement, &certificate);
    let keys = LogKeys::parse(&log.key_pem()).unwrap();
    let anchors = anchors(&g.anchor);
    let rdata = g.zone.dnskey_rdata();
    let apex = g.zone.apex();
    let child = format!("sync.{apex}"); // a name inside the zone, past every upstream guard

    // The control: the answer is signed by the zone the chain proves.
    let honest = ZoneKey {
        domain: &child,
        signing_zone: &apex,
        key_tag: g.zone.key_tag(),
        dnskey_rdata: &rdata,
    };
    rekor::verify(&proof, &honest, &keys, &anchors)
        .expect("an entry for the zone that signed the answer verifies");

    // The same entry offered for an answer signed by the child itself.
    let mismatched = ZoneKey {
        domain: &child,
        signing_zone: &child,
        key_tag: g.zone.key_tag(),
        dnskey_rdata: &rdata,
    };
    let error = rekor::verify(&proof, &mismatched, &keys, &anchors)
        .expect_err("the chain proves a zone the answer was not signed by");
    let text = error.to_string();
    assert!(
        text.contains(&apex) || text.contains(&child),
        "the refusal should name the zones: {text}"
    );
}

/// **The invariant.** Anything a client accepts is tier A — with harness
/// checks making the equivalence meaningful: both chain shapes really are
/// exercised (and different), and each shape's tier is pinned against the
/// design's table rather than left implicit.
#[test]
fn nothing_a_client_accepts_lands_in_the_silent_bin() {
    let all = shapes();

    // Both chain shapes are exercised and genuinely different (ladder: apex DS
    // → TLD DNSKEY+DS → root DNSKEY; self-anchored: one link), so the suite
    // cannot silently collapse to the single branch that hid the divergence.
    let genesis = |label: &str| {
        let shape = all
            .iter()
            .find(|s| s.name == format!("genesis ({label})"))
            .expect("a genesis shape");
        let body = HashedRekordBody::parse(&shape.proof.canonicalized_body).unwrap();
        synch_net::chain::authorize(&body.certificate, &anchors(&shape.anchor)).unwrap()
    };
    let self_anchored = genesis("self-anchored");
    let ladder = genesis("ladder");
    assert_eq!(
        (
            (
                self_anchored.chain.links,
                self_anchored.chain.anchored_directly
            ),
            (
                ladder.chain.links,
                ladder.chain.anchored_directly,
                ladder.chain.anchor_zone
            )
        ),
        ((1, true), (3, false, ".".to_string()))
    );

    for shape in all {
        let name = shape.name;
        let accepted = client_accepts(&shape);
        // Pin what acceptance actually is (the invariant is otherwise trivially
        // true): the shapes a resolver must take — including the substitution,
        // reported rather than refused — and the tier B bin it must refuse.
        let must_accept = match name.split(" (").next().expect("a shape name") {
            "genesis" | "rotation" | "substitution" | "expired chain" => true,
            "chainless"
            | "broken chain"
            | "wrong-key chain"
            | "malformed san"
            | "san names another zone" => false,
            other => panic!("unclassified shape {other}: say whether a client takes it"),
        };
        assert_eq!(accepted, must_accept, "{name}: client acceptance");
        // The tier table is the B-side of acceptance: accepted is tier A,
        // refused (or never judged) is the silent bin.
        assert_eq!(
            matches!(monitor_verdict(&shape), Verdict::Tiered(Tier::A)),
            must_accept,
            "{name}: tier"
        );

        // And which quiet outcome it is, named: a malformed SAN is never
        // judged at all — strictly quieter than tier B.
        assert_eq!(
            matches!(monitor_verdict(&shape), Verdict::Unclassified),
            name.starts_with("malformed san"),
            "{name}: tiered or never judged decides whether an operator sees anything"
        );
    }
}

/// The DS an operator is told to compare against their registrar is computed
/// over the **signing zone**, not the apex. For a control plane serving its
/// own delegated zone the names are the same, so computing over the apex
/// passed everything — while for an apex served out of a zone above it the
/// line would print a DS that matches nothing anywhere.
#[test]
fn the_reported_ds_is_over_the_signing_zone_not_the_apex() {
    use synch_net::chain::{self, TRANSPARENCY_TEXT};
    use synch_net::zonecert::{ChainLink, DnssecChain};

    // `example.` holds `sync.example.` — one zone, two names.
    let zone = SimZone::new("example", Vec::new());
    let apex = chain::parse_name("sync.example.").expect("an apex");
    let declared_at = chain::transparency_name(&apex).expect("declaration name");
    let inception = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let encode = |records: Vec<hickory_resolver::proto::rr::Record>| {
        chain::encode_rrs(&records).expect("encode link")
    };
    let carried = DnssecChain {
        links: vec![
            ChainLink {
                zone: declared_at.to_string(),
                rrs: encode(zone.signed_txt(declared_at.clone(), TRANSPARENCY_TEXT, inception)),
            },
            ChainLink {
                zone: zone.apex(),
                rrs: encode(zone.dnskey_records(inception)),
            },
        ],
    };
    let certificate = zone.certificate_for(
        "sync.example.",
        &[(OID_DNSSEC_CHAIN.to_vec(), carried.encode())],
    );
    let mut log = SimLog::new("rekor.sim");
    // The Statement names the apex, as a control plane served out of the zone above it publishes one.
    let statement = synch_net::rekor::ZoneKeyStatement::for_keys(
        "sync.example.",
        &[zone.dnskey_rdata()],
        "create",
    );
    let proof = log.log_certified(&zone, &statement, &certificate);
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    let finding = classify(&body, 3, &anchors(&zone.anchor_record())).unwrap();

    assert_eq!(finding.tier, Tier::A);
    assert_eq!(finding.apex, "sync.example.");
    let [key] = finding.keys.as_slice() else {
        panic!("one key: {:?}", finding.keys);
    };
    // `ds_field` is over `example.`, the zone that holds the records.
    assert_eq!(key.ds, zone.ds_field());
    assert!(
        finding.line().contains(&zone.ds_field()),
        "{}",
        finding.line()
    );
}
