//! The DNSSEC chain validator: what a chain has to carry to authorize a key.
//!
//! `synch_net::chain` is the one piece of this design that both halves of the
//! system run: the client refuses a proof whose chain does not validate, and
//! the monitor files an entry as noise for exactly the same reason. The
//! invariant that couples them — *client-accepted implies tier A* — only
//! holds because there is one implementation, so this suite tests it as the
//! shared thing it is rather than through either caller.
//!
//! Everything here is signed by zones the suite holds keys for, because the
//! contract under test is not "does a delegation ladder verify" — real bytes
//! answer that, next to the walk itself in `src/chain.rs` — but "what does a
//! chain have to *say* before it authorizes anything". The answer is the
//! declaration at `_synchronicity-transparency.<apex>`, and no third party's
//! zone can be borrowed to test it.

use hickory_resolver::proto::{dnssec::TrustAnchors, rr::Name};
use synch_net::{
    chain::{self, ChainError, TRANSPARENCY_TEXT},
    sim::{SimDelegation, SimZone},
    zonecert::{ChainLink, DnssecChain},
};

fn apex(text: &str) -> Name {
    chain::parse_name(text).expect("a test apex is a name")
}

/// An hour ago: RRSIG validity has to bracket "now" for the sim's answers,
/// and the chain walk reads no clock at all.
fn inception() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() - time::Duration::hours(1)
}

/// A chain link carrying `records`, owned by `zone`.
fn link(zone: &Name, records: Vec<hickory_resolver::proto::rr::Record>) -> ChainLink {
    ChainLink {
        zone: zone.to_string(),
        rrs: chain::encode_rrs(&records).expect("encode link"),
    }
}

/// The anchors a reader of `zone`'s self-anchored chain installs.
fn anchored_at(zone: &SimZone) -> TrustAnchors {
    let mut file = tempfile::NamedTempFile::new().expect("temp anchor");
    std::io::Write::write_all(&mut file, zone.anchor_record().as_bytes()).expect("write anchor");
    TrustAnchors::from_file(file.path()).expect("read anchor")
}

/// A self-anchored zone's chain validates and proves its own key set.
#[test]
fn a_declared_zone_proves_the_keys_its_declaration_sits_under() {
    let zone = SimZone::new("cluster.example", Vec::new());
    let (proven, signing_zone, valid) = chain::validate(
        &zone.dnssec_chain(),
        &apex("cluster.example."),
        &anchored_at(&zone),
    )
    .expect("a declared zone validates");
    assert_eq!(signing_zone, apex("cluster.example."));
    assert_eq!(valid.anchor_zone, "cluster.example.");
    assert!(valid.anchored_directly, "the apex is its own anchor here");
    assert_eq!(valid.links, 1, "the declaration is not a delegation step");
    assert_eq!(proven, vec![zone.dnskey_rdata()]);
}

/// A declaration whose RRSIG names some other zone as its signer is refused.
///
/// RFC 4035 §5.3.1: the signer is the closest enclosing zone. An RRSIG
/// carries its own `signer_name`, so a signature made under a foreign name is
/// still a well-formed record sitting in a well-formed RRset — and the
/// declaration is the one link that makes an entry the *zone's own statement*
/// rather than a copy of records anyone can read. Without this check some
/// other zone can speak for this name.
///
/// It had no test: deleting the comparison left the whole suite green,
/// because nothing in the tree could build an RRSIG whose signer name was not
/// the zone's own.
#[test]
fn a_declaration_signed_under_another_zones_name_is_refused() {
    let mut zone = SimZone::new("cluster.example", Vec::new());
    zone.sign_declaration_with(zone.signer_named("somewhere.else."));
    let error = chain::validate(
        &zone.dnssec_chain(),
        &apex("cluster.example."),
        &anchored_at(&zone),
    )
    .expect_err("a declaration signed under another zone's name is not this zone's");
    let text = error.to_string();
    assert!(text.contains("somewhere.else"), "{text}");
    assert!(text.contains("cluster.example"), "{text}");
}

/// The same over a real ladder shape: root → TLD → apex, three delegation
/// links under the declaration.
#[test]
fn a_declared_zone_under_a_delegation_ladder_validates_too() {
    let ladder = SimDelegation::new("cluster.example", Vec::new());
    let (proven, signing_zone, valid) = chain::validate(
        &ladder.chain(),
        &apex("cluster.example."),
        &anchored_at(&ladder.root),
    )
    .expect("a declared zone under a ladder validates");
    assert_eq!(signing_zone, apex("cluster.example."));
    assert_eq!(valid.anchor_zone, ".");
    assert!(!valid.anchored_directly);
    assert_eq!(
        valid.links, 3,
        "apex, TLD, root — the declaration is not one"
    );
    assert_eq!(proven, vec![ladder.apex.dnskey_rdata()]);
}

/// A control plane that is not a zone of its own.
///
/// `sync.example.` has no delegation and no DNSKEY — it is a name inside the
/// `example.` zone, and `example.` signs everything under it, the declaration
/// included. The chain is the declaration at `sync.example.` over a ladder
/// that starts at `example.`, and the keys it proves are `example.`'s,
/// because those are the keys that will sign the membership answers.
#[test]
fn an_apex_served_out_of_the_zone_above_it_validates() {
    let zone = SimZone::new("example", Vec::new());
    let apex_name = apex("sync.example.");
    let declared_at = chain::transparency_name(&apex_name).expect("declaration name");

    let carried = DnssecChain {
        links: vec![
            link(
                &declared_at,
                zone.signed_txt(declared_at.clone(), TRANSPARENCY_TEXT, inception()),
            ),
            link(&apex("example."), zone.dnskey_records(inception())),
        ],
    };

    let (proven, signing_zone, valid) = chain::validate(&carried, &apex_name, &anchored_at(&zone))
        .expect("an apex inside the zone above it validates");
    assert_eq!(
        signing_zone,
        apex("example."),
        "the ladder's bottom is the zone that holds the name, not the name"
    );
    assert_eq!(valid.anchor_zone, "example.");
    assert_eq!(
        proven,
        vec![zone.dnskey_rdata()],
        "the proven set is the signing zone's, since those keys sign the answers"
    );
}

/// The signing zone has to actually contain the apex.
///
/// A ladder for some unrelated zone, with a declaration spliced under a name
/// that zone does not hold, proves nothing about the apex — and is refused on
/// the containment rule before any signature is checked.
#[test]
fn a_ladder_for_a_zone_that_does_not_contain_the_apex_is_refused() {
    let zone = SimZone::new("other.example", Vec::new());
    let apex_name = apex("sync.example.");
    let declared_at = chain::transparency_name(&apex_name).expect("declaration name");

    let carried = DnssecChain {
        links: vec![
            link(
                &declared_at,
                zone.signed_txt(declared_at.clone(), TRANSPARENCY_TEXT, inception()),
            ),
            link(&apex("other.example."), zone.dnskey_records(inception())),
        ],
    };

    let error = chain::validate(&carried, &apex_name, &anchored_at(&zone))
        .expect_err("a zone that does not contain the apex cannot speak for it");
    assert!(
        matches!(&error, ChainError::Structure(why) if why.contains("does not contain")),
        "{error}"
    );
}

/// A chain that starts at the apex authorizes nothing, however well the
/// delegation under it verifies.
///
/// This is the claim-about-a-stranger's-zone case: the ladder is public data,
/// so a chain without a declaration is something anyone could have assembled
/// about a zone that never heard of them.
#[test]
fn a_chain_that_skips_the_declaration_is_refused() {
    let ladder = SimDelegation::new("cluster.example", Vec::new());
    let mut bare = ladder.chain();
    bare.links.remove(0);
    let error = chain::validate(&bare, &apex("cluster.example."), &anchored_at(&ladder.root))
        .expect_err("a ladder alone must not authorize");
    assert!(
        matches!(&error, ChainError::Structure(why) if why.contains(chain::TRANSPARENCY_LABEL)),
        "the refusal must name the missing declaration: {error}"
    );
}

/// A declaration for one zone does not carry another.
///
/// The bottom link is checked against the apex the certificate names, so
/// splicing a zone's real declaration under somebody else's ladder fails on
/// the name before any signature is consulted.
#[test]
fn a_declaration_from_another_zone_does_not_transfer() {
    let ours = SimDelegation::new("cluster.example", Vec::new());
    let theirs = SimZone::new("other.example", Vec::new());
    let mut spliced = ours.chain();
    spliced.links[0] = link(
        &theirs.transparency_name(),
        theirs.declaration_records(inception()),
    );
    assert!(matches!(
        chain::validate(
            &spliced,
            &apex("cluster.example."),
            &anchored_at(&ours.root)
        ),
        Err(ChainError::Structure(_))
    ));
}

/// A declaration the apex's keys did not sign is refused.
///
/// Built by signing the right name, with the right text, under a key that is
/// not in the chain-proven set — the shape an attacker who can publish in
/// *some* zone but not this one would produce.
#[test]
fn a_declaration_signed_by_a_stranger_is_refused() {
    let ladder = SimDelegation::new("cluster.example", Vec::new());
    let impostor = SimZone::for_name(apex("cluster.example."), Vec::new());
    let mut forged = ladder.chain();
    // `impostor` signs as `cluster.example.` — same owner name, same signer
    // name, a key the apex's DNSKEY RRset does not contain.
    forged.links[0] = link(
        &ladder.apex.transparency_name(),
        impostor.declaration_records(inception()),
    );
    assert!(matches!(
        chain::validate(
            &forged,
            &apex("cluster.example."),
            &anchored_at(&ladder.root)
        ),
        Err(ChainError::Signature(_))
    ));
}

/// A TXT record at the declaration's name that does not say what a
/// declaration says is not one.
#[test]
fn a_record_that_does_not_read_as_a_declaration_is_not_one() {
    let zone = SimZone::new("cluster.example", Vec::new());
    let mut chain_ = zone.dnssec_chain();
    let owner = zone.transparency_name();
    chain_.links[0] = link(
        &owner,
        zone.signed_txt(owner.clone(), "v=sync1 something", inception()),
    );
    let error = chain::validate(&chain_, &apex("cluster.example."), &anchored_at(&zone))
        .expect_err("a differently-worded record is not a declaration");
    assert!(
        matches!(&error, ChainError::Structure(why) if why.contains(TRANSPARENCY_TEXT)),
        "{error}"
    );
}

/// A wildcard cannot declare on a zone's behalf.
///
/// A zone with `*.<apex> TXT` answers for every name under it, this one
/// included, and a resolver hands back a valid RRSIG for a record the zone
/// never wrote. RFC 4035 §5.3.2 gives the tell — the RRSIG's label count is
/// short — and it is checked, because otherwise a zone that happens to run a
/// catch-all TXT would be declaring things nobody in it decided.
#[test]
fn a_wildcard_expansion_is_not_a_declaration() {
    let zone = SimZone::new("cluster.example", Vec::new());
    // Signed as `*.cluster.example.` and served under the declaration's name:
    // the signature is genuine and the labels are one short, exactly as a
    // resolver would return a wildcard expansion.
    let wildcard = apex("*.cluster.example.");
    let mut records = zone.signed_txt(wildcard, TRANSPARENCY_TEXT, inception());
    let owner = zone.transparency_name();
    for record in &mut records {
        record.name = owner.clone();
    }
    let mut chain_ = zone.dnssec_chain();
    chain_.links[0] = link(&owner, records);
    let error = chain::validate(&chain_, &apex("cluster.example."), &anchored_at(&zone))
        .expect_err("a wildcard expansion must not declare");
    assert!(
        matches!(&error, ChainError::Structure(why) if why.contains("wildcard")),
        "{error}"
    );
}

/// A zone cut that spans several labels is a chain a client can walk.
///
/// DNS delegations are not one label each: `example.` may publish NS and DS for
/// `cp.acme.example.` with no zone at all at `acme.example.`. A ladder rule that
/// required each link to be exactly one label below the next left such a
/// deployment with **no valid encoding**: a link for the empty non-terminal has
/// neither a DNSKEY RRset nor a DS to prove one, so including it fails, and
/// omitting it failed the parent-name check. Every client of it refused every
/// answer, permanently, with a diagnostic that read like a misbuilt entry.
///
/// What holds the ladder together is not the label count. Each link's DS digest
/// is computed over its own `zone`, each link's records must be owned by that
/// name, and each RRSIG is verified under it — so the cut's width was never
/// load-bearing, and requiring a *proper ancestor* gives up nothing.
#[test]
fn a_delegation_that_spans_several_labels_still_validates() {
    let ladder = SimDelegation::spanning("cp.acme.example", "example", Vec::new());
    let (proven, signing_zone, valid) = chain::validate(
        &ladder.chain(),
        &apex("cp.acme.example."),
        &anchored_at(&ladder.root),
    )
    .expect("a zone delegated several labels below its parent must validate");
    assert_eq!(signing_zone, apex("cp.acme.example."));
    assert_eq!(valid.anchor_zone, ".");
    assert_eq!(
        valid.links, 3,
        "apex, the zone that delegated it, root — with nothing at acme.example."
    );
    assert_eq!(proven, vec![ladder.apex.dnskey_rdata()]);
}

/// The ladder still has to descend, which is the half of the rule that works.
#[test]
fn a_ladder_that_does_not_descend_is_refused() {
    let ladder = SimDelegation::spanning("cp.acme.example", "example", Vec::new());
    let mut sideways = ladder.chain();
    // Swap the two lower ladder links so the "parent" is below its child.
    sideways.links.swap(1, 2);
    let error = chain::validate(
        &sideways,
        &apex("cp.acme.example."),
        &anchored_at(&ladder.root),
    )
    .expect_err("a ladder that climbs the wrong way authorizes nothing");
    assert!(
        matches!(&error, ChainError::Structure(why) if why.contains("is not an ancestor of")),
        "{error}"
    );
}

/// A DNSKEY with no Zone Key flag cannot sign inside a chain (RFC 4034 §2.1.1).
///
/// hickory's `impl Verifier for DNSKEY` reads only the algorithm and the key
/// bytes — it consults neither flag — so nothing under this validator enforces
/// the rule and it has to be enforced here. A key published with flags `0x0000`
/// is not a zone key and "MUST NOT be used to verify RRSIGs that cover RRsets".
#[test]
fn a_key_that_is_not_a_zone_key_signs_nothing_and_proves_nothing() {
    let zone = SimZone::with_flags("cluster.example", Vec::new(), false, false);
    let error = chain::validate(
        &zone.dnssec_chain(),
        &apex("cluster.example."),
        &anchored_at(&zone),
    )
    .expect_err("a non-zone-key DNSKEY must not anchor or sign a chain");
    assert!(
        matches!(&error, ChainError::Anchor(why) if why.contains("zone key")),
        "{error}"
    );
}

/// An RFC 5011 REVOKE-flagged key is never a valid signer either.
#[test]
fn a_revoked_key_signs_nothing_and_proves_nothing() {
    let zone = SimZone::with_flags("cluster.example", Vec::new(), true, true);
    let error = chain::validate(
        &zone.dnssec_chain(),
        &apex("cluster.example."),
        &anchored_at(&zone),
    )
    .expect_err("a revoked DNSKEY must not anchor or sign a chain");
    assert!(
        matches!(&error, ChainError::Anchor(why) if why.contains("unrevoked")),
        "{error}"
    );
}

/// A revoked key sitting *beside* a good one is excluded from the proven set.
///
/// This is the case that bites: the DS-covered key's flags are pinned by the DS
/// digest, so it is the RRset's *other* keys that this decides. Whoever holds
/// one could otherwise sign a forged child DS and mint a chain that validates
/// against the ICANN root — forged tier-A findings against the one alarm this
/// design raises. So such a key is not in the set the chain proves, and a
/// Statement claiming it does not match.
#[test]
fn a_revoked_key_beside_a_good_one_is_not_in_the_proven_set() {
    let mut zone = SimZone::new("cluster.example", Vec::new());
    let revoked = SimZone::with_flags("cluster.example", Vec::new(), true, true);
    zone.add_dnskey(revoked.dnskey());
    let (proven, _, _) = chain::validate(
        &zone.dnssec_chain(),
        &apex("cluster.example."),
        &anchored_at(&zone),
    )
    .expect("the live key still anchors and signs");
    assert_eq!(
        proven,
        vec![zone.dnskey_rdata()],
        "the revoked key is published, verified as part of the RRset, and not authorized"
    );
    assert!(!proven.contains(&revoked.dnskey_rdata()));
}

/// A chain padded with signatures costs a bounded number of verifications.
///
/// Every candidate re-canonicalizes the whole RRset before it hashes anything,
/// and the input is a certificate an attacker chose, so pairing signatures
/// against keys is quadratic work on hostile data — bounded otherwise only by
/// the 64 KB entry frame. A legitimate link needs one verification and an
/// RFC 6781 rollover two, so a link offering dozens is refused rather than
/// walked: bounded work, and fail-closed when the bound is reached.
#[test]
fn a_chain_padded_with_signatures_is_refused_rather_than_walked() {
    let zone = SimZone::new("cluster.example", Vec::new());
    let records = zone.dnskey_records(inception());
    let rrsig = records
        .iter()
        .find(|record| {
            matches!(
                record.data,
                hickory_resolver::proto::rr::RData::DNSSEC(
                    hickory_resolver::proto::dnssec::rdata::DNSSECRData::RRSIG(_)
                )
            )
        })
        .expect("the set is signed")
        .clone();

    // Copies of the real RRSIG with one byte of the signature flipped: the same
    // owner, the same type, the same key tag — so each one is a pairing the walk
    // has to actually try — and none of them verifies. The honest records come
    // last, which is what a padded chain would do.
    let mut junk = chain::encode_rrs(&[rrsig]).expect("encode the decoy");
    *junk.last_mut().expect("a signature has bytes") ^= 0x01;
    let mut rrs = Vec::new();
    for _ in 0..64 {
        rrs.extend_from_slice(&junk);
    }
    rrs.extend_from_slice(&chain::encode_rrs(&records).expect("encode the honest set"));

    let mut padded = zone.dnssec_chain();
    padded.links[1] = ChainLink {
        zone: "cluster.example.".into(),
        rrs,
    };
    let error = chain::validate(&padded, &apex("cluster.example."), &anchored_at(&zone))
        .expect_err("a padded link must be refused, not walked");
    assert!(
        matches!(&error, ChainError::Signature(why) if why.contains("pairings")),
        "{error}"
    );
}
