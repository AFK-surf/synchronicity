//! Classification, and the invariant that couples it to the client.
//!
//! The two tiers are only useful if tier B — the silent bin — is exactly "an
//! entry no client would have accepted either". If a client ever accepted
//! something a monitor filed as tier B, an attacker would hold a key that
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
    match classify(&body, shape.proof.log_index, &anchors(&shape.anchor)) {
        Some(finding) => finding.tier,
        // A certificate the classifier declines to judge at all — an
        // unparseable SAN, a key that is not ours — is not in *any* tier, and
        // for the invariant that is strictly worse than tier B: the entry is
        // not even recorded. Treat it as C so the assertion below has teeth.
        None => Tier::B,
    }
}

/// How a shape's chain is built: the degenerate self-anchored form, or the
/// root → TLD → apex ladder production actually emits.
///
/// Both, always. Every shape below is generated twice, because until this
/// suite ran over a multi-link chain it was exercising exactly one branch of
/// the validator — and the divergence that let a client-accepted entry be
/// filed tier B only appears once a chain has a parent to climb to.
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
    let mut push =
        |name: &str, g: Ground, log: SimLog, proof: RekorProof, observed: Option<String>| {
            let observed_apex = observed.unwrap_or_else(|| g.zone.apex());
            out.push(Shape {
                name: leak(&format!("{name} ({})", rooted.label())),
                zone: g.zone,
                log,
                proof,
                anchor: g.anchor,
                observed_apex,
            });
        };
    let certificate = |g: &Ground| {
        g.zone
            .certificate(&[(OID_DNSSEC_CHAIN.to_vec(), g.chain.encode())])
    };

    // 1. The honest genesis key: a zone's first, with a valid chain.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g));
        push("genesis", g, log, proof, None);
    }

    // 2. A routine rotation the operator performed.
    {
        let g = ground(rooted);
        let old = SimZone::new("cluster.example", members());
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("rollover", Some(old.key_tag()));
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g));
        push("rotation", g, log, proof, None);
    }

    // 3. A substitution: the attacker holds the DS, so the chain is real.
    //
    //    This shape and shape 2 are byte-for-byte indistinguishable in every
    //    respect a monitor can see, which is the point — both are tier A,
    //    both get reported, and which of them actually happened is a question
    //    only the operator's own records answer. Keeping both here, rather
    //    than collapsing them into one, is what stops that fact from
    //    quietly ceasing to be tested.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g));
        push("substitution", g, log, proof, None);
    }

    // 4. No chain at all.
    {
        let g = ground(rooted);
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &g.zone.certificate(&[]));
        push("chainless", g, log, proof, None);
    }

    // 5. A chain whose signature does not verify.
    {
        let mut g = ground(rooted);
        let at = g.chain.links[0].rrs.len() - 3;
        g.chain.links[0].rrs[at] ^= 0x01;
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g));
        push("broken chain", g, log, proof, None);
    }

    // 6. A chain that is valid — for a different zone's key.
    {
        let mut g = ground(rooted);
        g.chain = ground(rooted).chain;
        let mut log = SimLog::new("rekor.sim");
        let statement = g.zone.zone_key_statement("create", None);
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g));
        push("wrong-key chain", g, log, proof, None);
    }

    // 7. A chain that was valid long ago and has expired since. Archival, and
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
        let proof = log.log_certified(&g.zone, &statement, &certificate(&g));
        push("expired chain", g, log, proof, None);
    }

    // 8-11. SANs that are not names, or name somebody else. This is the
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
        push(label, g, log, proof, None);
    }

    // 12. A well-formed SAN naming a zone that is not the one the Statement
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
        push("san names another zone", g, log, proof, None);
    }

    out
}

/// The tier of a proof about `zone`, anchored at that zone's own key — the
/// shorthand the single-purpose tests below use.
fn tier_of(proof: &RekorProof, zone: &SimZone) -> Tier {
    let body = HashedRekordBody::parse(&proof.canonicalized_body).expect("a well-formed body");
    match classify(&body, proof.log_index, &anchors(&zone.anchor_record())) {
        Some(finding) => finding.tier,
        None => Tier::B,
    }
}

/// A zone's apex as a parsed name, for `KnownKeys`.
fn apex_name(zone: &SimZone) -> hickory_resolver::proto::rr::Name {
    synch_net::chain::parse_name(&zone.apex()).expect("a sim apex is a name")
}

/// **The invariant.** Anything a client accepts is tier A.
#[test]
fn nothing_a_client_accepts_lands_in_the_silent_bin() {
    for shape in shapes() {
        let name = shape.name;
        let accepted = client_accepts(&shape);
        let tier = monitor_tier(&shape);
        assert!(
            !accepted || tier == Tier::A,
            "{name}: the client accepted an entry the monitor files as noise"
        );
        // The invariant above is satisfied trivially by a client that accepts
        // nothing, so pin what acceptance actually is. These are the shapes a
        // resolver must take — including the substitution, because it *is*
        // usable and the whole point is that it is reported rather than
        // refused here — and the ones it must refuse, which are exactly the
        // tier B bin.
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
        ("genesis", Tier::A),
        ("rotation", Tier::A),
        // The attacker's entry classifies exactly like the operator's. Stated
        // as an expectation rather than left implicit, because it is the
        // whole shape of what this monitor now claims: a verified chain is an
        // authorization, and nothing here says who was entitled to make it.
        ("substitution", Tier::A),
        ("chainless", Tier::B),
        ("broken chain", Tier::B),
        ("wrong-key chain", Tier::B),
        ("expired chain", Tier::A),
        // A SAN that is not a name names no zone: nothing to classify, and
        // nothing a client takes either.
        ("malformed san", Tier::B),
        // A well-formed SAN with a chain for a *different* zone is an
        // unauthorized claim about the zone it names — tier B, and refused by
        // every client. A monitor watching the zone whose chain it stole
        // never sees it at all, because the SAN does not match.
        ("san names another zone", Tier::B),
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

/// Classification takes no state, so nothing a monitor has seen can steer it.
///
/// The old classifier consulted its known-keys set to decide between two
/// tiers, which meant the verdict on an entry depended on the monitor's
/// history. It no longer does: the same bytes classify the same way against
/// an empty state and against one holding every key involved. The
/// already-seen test still exists, but it decides whether to *report*, never
/// what an entry *is* — and that separation is what keeps a recorded
/// attacker key from making the next one look ordinary.
#[test]
fn what_the_monitor_has_seen_does_not_change_what_an_entry_is() {
    let zone = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    let proof = log.publish(&zone, "create", None);
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();

    let anchors = anchors(&zone.anchor_record());
    let first = classify(&body, proof.log_index, &anchors).unwrap();

    // Whatever a monitor records about this key, the classification of the
    // entry is unchanged — there is no argument left to pass it.
    let mut known = KnownKeys::default();
    known.insert(&apex_name(&zone), &zone.spki());
    assert!(known.contains(&apex_name(&zone), &zone.spki()));

    let again = classify(&body, proof.log_index, &anchors).unwrap();
    assert_eq!(first, again);
    assert_eq!(first.tier, Tier::A);
}

/// Reporting once: a recorded key is not news, an unrecorded one is.
///
/// This is the whole of the state machine `main` runs, asserted against the
/// types rather than against the binary — the binary's part is which stream
/// each half goes to.
#[test]
fn a_key_is_news_until_it_has_been_recorded() {
    let zone = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    let proof = log.publish(&zone, "create", None);
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    let finding = classify(&body, proof.log_index, &anchors(&zone.anchor_record())).unwrap();
    assert_eq!(finding.tier, Tier::A);

    let apex = apex_name(&zone);
    let mut known = KnownKeys::default();
    // Nothing recorded: a new authorization.
    assert!(!known.contains(&apex, &zone.spki()));
    known.insert(&apex, &zone.spki());
    // Recorded: reported once, and not again.
    assert!(known.contains(&apex, &zone.spki()));

    // A different key for the same apex is still news — recording one key
    // must not vouch for the zone as a whole.
    let next = SimZone::new("cluster.example", members());
    assert!(!known.contains(&apex, &next.spki()));
}

/// What a monitor derives, it derives from the certificate alone.
#[test]
fn the_key_tag_and_ds_come_from_the_certificate_never_from_dns() {
    let zone = SimZone::new("cluster.example", members());
    let mut log = SimLog::new("rekor.sim");
    let proof = log.publish(&zone, "create", None);
    let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
    let finding = classify(&body, 7, &anchors(&zone.anchor_record())).unwrap();

    // The same key tag and DS the zone itself would publish, arrived at with
    // no DNS query — which is the only reason a compromised provider cannot
    // steer what the monitor concludes.
    assert_eq!(finding.key_tag, zone.key_tag());
    assert_eq!(finding.ds, zone.ds_field());
    // The apex is reported in canonical form — parsed from the SAN, so it
    // carries its root dot however the certificate happened to spell it.
    assert_eq!(finding.apex, zone.apex());
    assert_eq!(finding.log_index, 7);

    // The reported line carries everything an operator acts on: the zone, the
    // key tag, the DS to compare against the registrar, the full SPKI digest
    // and the index to look the entry up by.
    let line = finding.line();
    assert!(
        line.starts_with("[A] index 7 apex cluster.example"),
        "{line}"
    );
    assert!(line.contains(&zone.ds_field()), "{line}");
    assert!(line.contains(&finding.spki_sha256), "{line}");
}

/// A long-expired chain classifies exactly like a fresh one.
///
/// The monitor consults **no clock at all**, so an entry whose RRSIGs expired
/// years ago lands in the same tier as one signed this morning. It has to.
/// The client does not check windows either (there is no attested time
/// anywhere near a leaf, and archival entries are read for years), so a
/// monitor that quietly demoted an expired chain would put a
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
        classify(&body, 0, &anchors(&zone.anchor_record())).unwrap()
    };

    let ancient = time::OffsetDateTime::now_utc() - time::Duration::days(900);
    let expired = classify_chain(zone.dnssec_chain_at(ancient).encode());
    let fresh = classify_chain(zone.dnssec_chain().encode());

    assert_eq!(expired.tier, Tier::A);
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

/// An extension this build has never heard of changes nothing.
///
/// The certificate parser collects extensions and looks them up by OID, so an
/// unrecognised one is simply never asked for. A certificate may therefore
/// carry things this build says nothing about without that changing what the
/// entry *is*.
#[test]
fn an_extension_nothing_reads_does_not_disturb_the_verdict() {
    let zone = SimZone::new("cluster.example", members());
    let statement = zone.zone_key_statement("create", None);
    let chain = zone.dnssec_chain().encode();

    let classify_cert = |certificate: Vec<u8>| {
        let mut log = SimLog::new("rekor.sim");
        let proof = log.log_certified(&zone, &statement, &certificate);
        let body = HashedRekordBody::parse(&proof.canonicalized_body).unwrap();
        classify(&body, 0, &anchors(&zone.anchor_record())).unwrap()
    };

    let plain = classify_cert(zone.certificate(&[(OID_DNSSEC_CHAIN.to_vec(), chain.clone())]));
    let with_junk = classify_cert(zone.certificate(&[
        (OID_DNSSEC_CHAIN.to_vec(), chain),
        // An arc this build has no name for, carrying bytes that decode as
        // nothing at all.
        (
            vec![0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01],
            b"opaque".to_vec(),
        ),
    ]));

    assert_eq!(plain.tier, Tier::A);
    assert_eq!(plain.tier, with_junk.tier);
    assert_eq!(plain.reasons, with_junk.reasons);
    assert_eq!(plain.spki_sha256, with_junk.spki_sha256);
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
    // And the entry it found is an authorization, not noise.
    assert_eq!(tier_of(&proof, &zone), Tier::A);
}
