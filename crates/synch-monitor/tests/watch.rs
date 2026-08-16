//! What a watch list has to cover, and why it is not an equality test.
//!
//! An operator writes down the zone they run. What they are actually
//! protecting is a *name* — `_synchronicity.<network>.<org>.<apex>` — and
//! which zone signs that name is not a property of the name. A cut can be
//! created or removed at any label boundary along it, by whoever holds the
//! zone above that boundary, and a client validates against whatever signer
//! the resulting cut produces (`docs/REKOR-ZONE-KEY.md` §4.2: the apex comes
//! from the RRSIG signer field).
//!
//! So there are three keys that can authorize themselves over
//! `_synchronicity.network.org.cluster.example`, not one:
//!
//! ```text
//!   example              withdraw the delegation, sign cluster's names here
//!   cluster.example      the zone the operator wrote down
//!   org.cluster.example  a new cut, signing the names inside it
//! ```
//!
//! Each of the three produces an entry a client **accepts** and a monitor
//! classifies **tier A**. This file builds all three for real — real chains to
//! a real anchor, run through the real client verifier and the real
//! classifier — and pins that a watch on the middle one surfaces all of them.
//! Matching the watch list by equality reported only the middle one, which
//! left the other two working against victims and silent to the operator: the
//! exact failure the tiering exists to prevent, arrived at through the watch
//! filter instead of through classification.

use hickory_resolver::proto::{dnssec::TrustAnchors, rr::Name, rr::Record};
use synch_monitor::{
    classify::{classify, KnownKeys, Tier, Watched},
    MonitorState,
};
use synch_net::{
    chain,
    rekor::{self, HashedRekordBody, LogKeys, RekorProof, ZoneKey},
    sim::{SimLog, SimZone},
    zonecert::{ChainLink, DnssecChain, OID_DNSSEC_CHAIN},
};

fn members() -> Vec<String> {
    vec!["v=sync1 id=nas nk=aaaa".to_string()]
}

fn anchors(record: &str) -> TrustAnchors {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), record).unwrap();
    TrustAnchors::from_file(file.path()).unwrap()
}

fn zone(origin: &str, txt: Vec<String>) -> SimZone {
    SimZone::for_name(Name::from_utf8(origin).expect("a zone name"), txt)
}

fn name(text: &str) -> Name {
    chain::parse_name(text).expect("a name")
}

/// The ladder every case here hangs off: root → `example` →
/// `cluster.example` → `org.cluster.example`, each level really delegating to
/// the next with a DS its own key signed.
struct Ladder {
    root: SimZone,
    tld: SimZone,
    apex: SimZone,
    deep: SimZone,
    inception: time::OffsetDateTime,
}

impl Ladder {
    fn new() -> Ladder {
        Ladder {
            root: SimZone::for_name(Name::root(), Vec::new()),
            tld: zone("example.", Vec::new()),
            apex: zone("cluster.example.", members()),
            // The cut an attacker who holds `cluster.example` (or anything
            // above it) can create: `org` delegated away, taking every
            // membership name under it out of the apex's key.
            deep: zone("org.cluster.example.", members()),
            inception: time::OffsetDateTime::now_utc() - time::Duration::hours(1),
        }
    }

    fn link(&self, zone: &SimZone, records: Vec<Record>) -> ChainLink {
        ChainLink {
            zone: zone.apex(),
            rrs: chain::encode_rrs(&records).expect("encode a chain link"),
        }
    }

    /// A zone's own DNSKEY RRset plus the DS its parent published for it —
    /// the shape every link above the bottom one has.
    fn rung(&self, zone: &SimZone, parent: &SimZone) -> ChainLink {
        let mut records = zone.dnskey_records(self.inception);
        records.extend(parent.ds_records_for(zone, self.inception));
        self.link(zone, records)
    }

    /// The chain an entry for the TLD carries: its DS from the root, then the
    /// root's DNSKEY. Two links, anchored where every public monitor is.
    fn tld_chain(&self) -> DnssecChain {
        DnssecChain {
            links: vec![
                self.link(
                    &self.tld,
                    self.root.ds_records_for(&self.tld, self.inception),
                ),
                self.link(&self.root, self.root.dnskey_records(self.inception)),
            ],
        }
    }

    /// The ordinary case: a chain for the zone the operator runs.
    fn apex_chain(&self) -> DnssecChain {
        DnssecChain {
            links: vec![
                self.link(
                    &self.apex,
                    self.tld.ds_records_for(&self.apex, self.inception),
                ),
                self.rung(&self.tld, &self.root),
                self.link(&self.root, self.root.dnskey_records(self.inception)),
            ],
        }
    }

    /// A chain for the new cut below the apex. Nothing about it is malformed:
    /// the apex really did delegate `org`, so the ladder is unbroken.
    fn deep_chain(&self) -> DnssecChain {
        DnssecChain {
            links: vec![
                self.link(
                    &self.deep,
                    self.apex.ds_records_for(&self.deep, self.inception),
                ),
                self.rung(&self.apex, &self.tld),
                self.rung(&self.tld, &self.root),
                self.link(&self.root, self.root.dnskey_records(self.inception)),
            ],
        }
    }

    fn anchor(&self) -> String {
        self.root.anchor_record()
    }
}

/// One logged entry, and the zone it is about.
struct Entry<'a> {
    zone: &'a SimZone,
    proof: RekorProof,
}

fn log_entry<'a>(log: &mut SimLog, zone: &'a SimZone, chain: &DnssecChain) -> Entry<'a> {
    let certificate = zone.certificate(&[(OID_DNSSEC_CHAIN.to_vec(), chain.encode())]);
    let statement = zone.zone_key_statement("create", None);
    Entry {
        zone,
        proof: log.log_certified(zone, &statement, &certificate),
    }
}

/// Would a client resolving a name this zone signs accept the entry? The real
/// verifier — the point of these cases is that the answer is yes.
fn client_accepts(entry: &Entry, log: &SimLog, anchor: &str) -> bool {
    let apex = entry.zone.apex();
    let rdata = entry.zone.dnskey_rdata();
    let key = ZoneKey {
        apex: &apex,
        key_tag: entry.zone.key_tag(),
        dnskey_rdata: &rdata,
    };
    rekor::verify(
        &entry.proof,
        &key,
        &LogKeys::parse(&log.key_pem()).unwrap(),
        &anchors(anchor),
    )
    .is_ok()
}

fn tier(entry: &Entry, anchor: &str) -> Tier {
    let body =
        HashedRekordBody::parse(&entry.proof.canonicalized_body).expect("a well-formed body");
    match classify(&body, entry.proof.log_index, &anchors(anchor)) {
        Some(finding) => finding.tier,
        None => Tier::B,
    }
}

/// The whole of it: three real entries, one watch, all three surfaced.
#[test]
fn a_watch_surfaces_the_zones_above_and_below_it() {
    let ladder = Ladder::new();
    let anchor = ladder.anchor();
    let mut log = SimLog::new("rekor.sim");
    let cases = [
        (
            "the zone above",
            log_entry(&mut log, &ladder.tld, &ladder.tld_chain()),
            Watched::Ancestor(name("cluster.example")),
        ),
        (
            "the zone itself",
            log_entry(&mut log, &ladder.apex, &ladder.apex_chain()),
            Watched::Directly,
        ),
        (
            "the zone below",
            log_entry(&mut log, &ladder.deep, &ladder.deep_chain()),
            Watched::Descendant(name("cluster.example")),
        ),
    ];

    let mut known = KnownKeys::default();
    known.keys.insert("cluster.example".into(), vec![]);

    for (label, entry, relation) in &cases {
        // Every one of these is a key that works: a client validating a name
        // this zone signs takes the entry and admits the devices behind it.
        // That is what makes the reporting question a security question and
        // not a matter of taste.
        assert!(
            client_accepts(entry, &log, &anchor),
            "{label}: a client must accept this — otherwise the case is moot"
        );
        assert_eq!(tier(entry, &anchor), Tier::A, "{label}: tier");

        let apex = name(&entry.zone.apex());
        assert_eq!(known.watches(&apex).as_ref(), Some(relation), "{label}");
    }

    // And the rule this replaced: equality would have reported one of three,
    // leaving two keys that clients accept and no monitor mentions.
    let reported_by_equality = cases
        .iter()
        .filter(|(_, entry, _)| {
            let apex = name(&entry.zone.apex());
            known.apexes().any(|watched| watched == apex)
        })
        .count();
    assert_eq!(reported_by_equality, 1);
}

/// A neighbour's key is recorded under its own zone, never the watched one.
///
/// The state file is what an operator reads to answer "which keys have been
/// authorized for my zone?". Filing `example`'s key under `cluster.example`
/// because that is the watch it matched would answer that question wrongly,
/// and permanently.
#[test]
fn a_neighbours_key_is_recorded_under_its_own_zone() {
    let ladder = Ladder::new();
    let watched = name("cluster.example");
    let neighbour = name(&ladder.tld.apex());

    let mut known = KnownKeys::default();
    known.keys.insert("cluster.example".into(), vec![]);
    known.insert(&neighbour, &ladder.tld.spki());

    assert!(known.contains(&neighbour, &ladder.tld.spki()));
    assert!(!known.contains(&watched, &ladder.tld.spki()));
    // Recording it makes the neighbour a watch entry in its own right, which
    // widens nothing: everything comparable with `example` was already
    // comparable with `cluster.example`.
    assert_eq!(
        known.watches(&name("other.example")),
        Some(Watched::Descendant(neighbour))
    );
}

/// The state file's shape did not change, so an existing monitor keeps its
/// history — it simply starts covering more of the tree with it.
#[test]
fn an_existing_state_file_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("monitor.json");
    std::fs::write(
        &path,
        br#"{"origin":"rekor.sim","tree_size":3,"root":"ab","next_index":3,
             "known":{"keys":{"cluster.example":["00ff"]}}}"#,
    )
    .unwrap();

    let state = MonitorState::load(&path).expect("an existing state file loads");
    assert_eq!(state.next_index, 3);
    assert_eq!(
        state.known.watches(&name("org.cluster.example")),
        Some(Watched::Descendant(name("cluster.example")))
    );
}
