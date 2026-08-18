//! Deciding what a leaf is: an authorization for a zone, or noise.
//!
//! Everything here works from the certificate inside the leaf and nothing
//! else. The authorized keys, their tags and the DS a parent would have
//! published are all read out of the leaf's own **chain-proven DNSKEY
//! RRset**, never looked up: the threat model has a compromised upstream DNS
//! provider in it, so a monitor that asked DNS what the zone's keys are
//! would be asking the attacker. The certificate's SubjectPublicKeyInfo is
//! the entry *signer* — attribution — and plays no part in the verdict.
//!
//! Classification is a pure function of the certificate and the trust
//! anchors: it takes no state, and it cannot be steered by what the monitor
//! happens to have seen before. Whether a tier A entry is *news* is a
//! separate question, answered against the monitor's own state file by the
//! caller; see the crate docs for why the two are kept apart.

use hickory_resolver::proto::{dnssec::TrustAnchors, rr::Name};
use synch_net::{
    chain,
    rekor::{sha256, HashedRekordBody},
};

/// What a leaf turned out to be.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Tier {
    /// No valid chain, or a chain covering some other key: an unauthorized
    /// claim naming this apex. Not reported — and safe to be quiet about only
    /// because **no client holding this monitor's anchor set would have
    /// accepted it either**.
    ///
    /// That condition is the whole of tier B's meaning and it is not
    /// unconditional. The verdict is computed against the anchors this process
    /// was given, and `--dnssec-anchor` *replaces* the ICANN root rather than
    /// unioning with it, so a run under one anchor set says nothing about a
    /// client population under another: the same bytes are tier B here and
    /// client-accepted there. One monitor process covers one trust surface;
    /// see the crate docs.
    B,
    /// A chain that verifies to the anchor in force and covers this key. The
    /// entry **authorizes** this key for this apex — whoever published it.
    A,
}

impl Tier {
    /// The one-letter name used in output and exit-code decisions.
    pub fn letter(&self) -> char {
        match self {
            Tier::A => 'A',
            Tier::B => 'B',
        }
    }
}

/// The keys this monitor has already reported as authorized, per apex.
///
/// This is the monitor's memory, and it does exactly one job: stop a key from
/// being reported on every pass forever. A tier A entry proving a key not in
/// here is a **new authorization** — the event an operator is running a
/// monitor to hear about — and once reported it is recorded so the next run
/// stays quiet.
///
/// It is emphatically **not** a trust store. An attacker's substituted key
/// gets recorded here the moment it is reported, exactly like the operator's
/// own, because the monitor has no way to tell them apart and does not
/// pretend to. Recording is bookkeeping about what has been *said*, not a
/// judgement about what is *legitimate*; the judgement is the operator's,
/// made against their own record of what they published.
///
/// The apexes are also the watch list: an apex with an empty key list is how
/// an operator says "tell me about this zone, I have seen nothing yet". What
/// is watched is not just that name but its whole **delegation path**, in
/// both directions — see [`KnownKeys::watches`]. An entry that is not a DNS
/// name watches nothing, which is why [`KnownKeys::unwatchable`] exists and
/// why the binary refuses to run on a list holding one.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KnownKeys {
    /// `apex` → the SHA-256 hex of each already-reported key's DNSKEY rdata.
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, Vec<String>>,
}

impl KnownKeys {
    /// Whether this DNSKEY rdata has already been seen for `apex`.
    ///
    /// Names are compared **parsed**, never trimmed: an operator's state file
    /// says `sync.example` and a certificate says `sync.example.`,
    /// and those are one zone — but `sync.example..` is not a name at all
    /// and must match nothing.
    pub fn contains(&self, apex: &Name, dnskey_rdata: &[u8]) -> bool {
        self.contains_digest(apex, &hex::encode(sha256(dnskey_rdata)))
    }

    /// The same test by the digest itself, which is what a [`Finding`]
    /// carries.
    pub fn contains_digest(&self, apex: &Name, digest_hex: &str) -> bool {
        self.keys
            .iter()
            .filter(|(known, _)| chain::parse_name(known).is_ok_and(|known| known == *apex))
            .any(|(_, digests)| digests.iter().any(|d| d.eq_ignore_ascii_case(digest_hex)))
    }

    /// Records a key as seen for `apex`.
    pub fn insert(&mut self, apex: &Name, dnskey_rdata: &[u8]) {
        self.insert_digest(apex, &hex::encode(sha256(dnskey_rdata)));
    }

    /// The same, by the digest itself.
    pub fn insert_digest(&mut self, apex: &Name, digest_hex: &str) {
        let key = apex.to_string();
        let entry = self.keys.entry(key).or_default();
        if !entry.iter().any(|d| d.eq_ignore_ascii_case(digest_hex)) {
            entry.push(digest_hex.to_string());
        }
    }

    /// The apexes this monitor watches, parsed.
    pub fn apexes(&self) -> impl Iterator<Item = Name> + '_ {
        self.keys
            .keys()
            .filter_map(|apex| chain::parse_name(apex).ok())
    }

    /// The watch-list entries that are not DNS names.
    ///
    /// The state file is hand-edited, so it can hold anything, and an entry
    /// that does not parse cannot match a certificate's SAN — which is parsed
    /// too. So it watches nothing, for as long as it sits there, and a monitor
    /// whose whole list is such entries reports "no alarm" forever. Non-empty
    /// is therefore not the test that matters; the caller refuses to run on
    /// anything this returns rather than letting it be quiet.
    pub fn unwatchable(&self) -> Vec<&str> {
        self.keys
            .keys()
            .filter(|apex| chain::parse_name(apex).is_err() || is_wildcard(apex))
            .map(String::as_str)
            .collect()
    }

    /// Whether an entry naming `apex` is this monitor's business.
    ///
    /// Not just the configured names: **anything on their delegation path**,
    /// above or below. Watching only the exact name would leave the one
    /// attack the design cannot prevent completely invisible. A zone's
    /// ancestors own its namespace outright — a parent can nullify the
    /// delegation, absorb the child, and publish a declaration and a chain
    /// about *itself* that a resolver will validate — so an entry for
    /// `example.com` is exactly how a takeover of `cp.example.com` would
    /// appear in the log. A monitor pointed at the child that ignored the
    /// parent would be watching the one place the attacker has no need to
    /// touch.
    ///
    /// Downward for the mirror case: an entry for `sub.cp.example.com` is
    /// somebody standing up a control plane inside the operator's own zone,
    /// which is either a delegation they made or one they need to hear about.
    ///
    /// Two directions is also what makes the watch complete rather than
    /// merely broad. A client bounds a certificate's apex by
    /// `signing_zone ⊇ claimed_apex ⊇ membership domain`, and the control
    /// plane publishes membership under the apex — so every apex a client
    /// would accept is a suffix of the membership domain, suffixes of one
    /// name are totally ordered, and each of them therefore sits on the
    /// delegation path of any watched name on that chain, in one direction or
    /// the other.
    ///
    /// The cost is noise, and it is the right trade. A zone's own operators
    /// are the only people who can say whether `example.com` publishing
    /// synchronicity entries is ordinary or an emergency, and they can only
    /// say it if they are told.
    pub fn watches(&self, apex: &Name) -> bool {
        self.apexes()
            .any(|watched| watched.zone_of(apex) || apex.zone_of(&watched))
    }

    /// The watched names this set holds that `covered` does not already watch.
    ///
    /// The question a resumed run has to ask before trusting its recorded
    /// positions: those positions were produced under `covered`, and an entry
    /// naming an apex outside it was stepped over rather than classified. A
    /// name that `covered` already `watches` is not a widening — it is what
    /// the auto-insert does when it records the apex of an entry it just
    /// reported, and that entry was reported precisely *because* the old set
    /// matched it. Anything else moves the boundary and leaves everything
    /// behind the position permanently unread.
    ///
    /// Compared through `watches` rather than by string equality for that
    /// reason: set difference over the literal names would call every
    /// auto-inserted subdomain a coverage change and refuse a run that lost
    /// nothing.
    pub fn widening_over(&self, covered: &[String]) -> Vec<String> {
        let old = KnownKeys {
            keys: covered
                .iter()
                .map(|name| (name.clone(), Vec::new()))
                .collect(),
        };
        self.apexes()
            .filter(|apex| !old.watches(apex))
            .map(|apex| apex.to_string())
            .collect()
    }
}

/// Whether a watch entry is spelled as a wildcard.
///
/// `*.example.com` parses — the label is legal in a name — so it survives the
/// parse check, and it then watches its *ancestors* and itself and nothing
/// else. Measured: it matches `example.com`, and matches neither
/// `cp.example.com` nor `a.b.example.com`. `cp.<apex>` is the ordinary shape
/// of both a legitimate control plane and a takeover, so the entry an
/// operator wrote to widen their coverage narrows it to almost nothing, and
/// the startup line prints the string back looking exactly as intended.
///
/// A watch list is not a matcher — `watches` already covers every name on the
/// delegation path in both directions, so the apex alone is strictly broader
/// than any wildcard spelling of it. There is no reading under which this
/// entry does what whoever typed it meant, which is what makes refusing it
/// right rather than merely strict.
fn is_wildcard(apex: &str) -> bool {
    apex.starts_with("*.") || apex == "*"
}

/// One key of a proven set, as an operator needs to see it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizedKey {
    /// The key tag, computed from the proven rdata.
    pub key_tag: u16,
    /// The SHA-256 hex of the DNSKEY rdata.
    pub sha256: String,
    /// The DS record a parent would publish for this key — derived, so an
    /// operator can compare it against what their registrar actually shows
    /// without believing anything this entry says. Only the DS-covered key
    /// of a split-key zone will match the registrar; the rest are the ZSKs
    /// the chain proved under it.
    ///
    /// Digest type 2 (SHA-256), which is what this project's own tooling
    /// hands an operator. A delegation may legitimately use type 4 instead —
    /// `chain::covers` accepts both — so `ds_sha384` carries that spelling
    /// beside it rather than sending the reader looking for a string their
    /// registrar will never show.
    pub ds: String,
    /// The same key as an RFC 4509 digest type 4 (SHA-384) DS.
    ///
    /// Additive: the field is new, `ds` keeps its meaning, and a consumer
    /// reading only `ds` is unaffected.
    #[serde(default)]
    pub ds_sha384: String,
}

/// One classified leaf.
///
/// Everything an operator needs to act without believing anything the entry
/// says: the zone, the proven key set with the DS their registrar should be
/// showing, and where in the log to look.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Where the entry sits in the log.
    pub log_index: u64,
    /// The apex the certificate names.
    pub apex: String,
    /// The chain-proven key set. Empty for a tier B entry, which proves
    /// nothing about any key.
    pub keys: Vec<AuthorizedKey>,
    /// The verdict.
    pub tier: Tier,
    /// Why, in the order the checks ran. Always non-empty.
    pub reasons: Vec<String>,
}

impl Finding {
    /// A one-line rendering for a terminal or a log.
    ///
    /// The DS is in it deliberately, and it is the longest field: the
    /// operator's first move on a new authorization is to compare this line
    /// against what their registrar is publishing, and a line they have to
    /// re-run a tool to complete is a line they will not act on.
    pub fn line(&self) -> String {
        let keys = match self.keys.is_empty() {
            true => "no proven keys".to_string(),
            false => self
                .keys
                .iter()
                .map(|key| {
                    // Both digest types. This line exists to be compared
                    // against a registrar, the registrar shows whichever type
                    // the delegation uses, and the argument above — a line
                    // they have to re-run a tool to complete is a line they
                    // will not act on — applies to a SHA-384 delegation
                    // exactly as much as to a SHA-256 one.
                    format!(
                        "keyTag {} DS {} | DS {} rdata {}",
                        key.key_tag, key.ds, key.ds_sha384, key.sha256
                    )
                })
                .collect::<Vec<_>>()
                .join(" | "),
        };
        format!(
            "[{}] index {} apex {} {} — {}",
            self.tier.letter(),
            self.log_index,
            self.apex,
            keys,
            self.reasons.join("; ")
        )
    }
}

/// Classifies one entry body.
///
/// No clock is consulted, and none is available to consult: `integratedTime`
/// sits outside the Merkle commitment and is therefore attacker-supplied, and
/// nothing else near an entry carries an attested time. So a chain is judged
/// purely on whether it validates, never on when it was signed — which is the
/// same rule the client applies, and has to be: the monitor's chain rule can
/// never be stricter than the client's, or the silent bin becomes an evasion
/// (see the crate docs).
pub fn classify(
    body: &HashedRekordBody,
    log_index: u64,
    anchors: &TrustAnchors,
) -> Option<Finding> {
    // Everything about the zone and the keys comes out of `chain::authorize`,
    // the same call the client makes — the apex parsed once from the SAN, the
    // chain walked against exactly that, the key set read out of the chain
    // itself. The monitor may not compose this itself: doing so is how the
    // two sides once disagreed about whether `victim.example..` was a zone
    // (see `chain::authorize`), which put a client-accepted entry in the
    // silent bin.
    let apex = body.certificate.single_dns_name().ok()?;
    let mut finding = Finding {
        log_index,
        apex: apex.to_string(),
        keys: Vec::new(),
        tier: Tier::B,
        reasons: Vec::new(),
    };

    match chain::authorize(&body.certificate, anchors) {
        Ok(authorized) => {
            // The chain verifies, so a resolver holding this anchor would
            // take the entry for any key in the proven set. That is the
            // whole of the verdict: these keys are authorized for this apex,
            // and the monitor does not — cannot — say by whom.
            finding.tier = Tier::A;
            // The DS is derived against the **signing zone**, not the apex:
            // these keys belong to whatever zone actually holds the apex's
            // records, and that is the zone whose registrar would show the
            // DS. For a control plane running its own delegated zone the two
            // names are the same; for one served out of a zone above it they
            // are not, and computing the digest over the apex would print a
            // DS that matches nothing anywhere.
            finding.keys = authorized
                .proven_keys
                .iter()
                .map(|rdata| AuthorizedKey {
                    key_tag: chain::key_tag(rdata),
                    sha256: hex::encode(sha256(rdata)),
                    ds: chain::ds_fields(&authorized.signing_zone, rdata),
                    ds_sha384: chain::ds_fields_sha384(&authorized.signing_zone, rdata),
                })
                .collect();
            let served_by = match authorized.signing_zone == apex {
                true => String::new(),
                false => format!(", served out of {}", authorized.signing_zone),
            };
            finding.reasons.push(format!(
                "DNSSEC chain valid to {} ({} link(s)): {} key(s) authorized for {apex}{served_by}",
                authorized.chain.anchor_zone,
                authorized.chain.links,
                finding.keys.len()
            ));
        }
        Err(why) => {
            // No client would have accepted this either — the client runs
            // this same composition and refuses what it rejects — so an entry
            // here is an unauthorized claim nobody could have been served.
            finding.reasons.push(format!("unauthorized claim: {why}"));
        }
    }
    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        chain::parse_name(text).expect("a test name")
    }

    #[test]
    fn known_keys_compare_names_the_way_dns_does() {
        let mut known = KnownKeys::default();
        known.insert(&name("Sync.Example."), b"a key");
        assert!(known.contains(&name("sync.example"), b"a key"));
        assert!(known.contains(&name("SYNC.EXAMPLE."), b"a key"));
        assert!(!known.contains(&name("other.example"), b"a key"));
        assert!(!known.contains(&name("sync.example"), b"another key"));
        // Inserting twice does not double the entry — which is what stops a
        // key being re-reported once it has been recorded.
        known.insert(&name("sync.example"), b"a key");
        assert_eq!(known.keys["sync.example."].len(), 1);
    }

    /// The watch follows the delegation path, both ways.
    ///
    /// The upward half is the one that matters: a parent can nullify its
    /// child's delegation and publish a perfectly valid entry about itself,
    /// so an operator watching only `cp.example.` would never see the
    /// takeover of `cp.example.` go by.
    #[test]
    fn watching_a_zone_watches_its_whole_delegation_path() {
        let mut known = KnownKeys::default();
        known.keys.insert("cp.example.".into(), vec![]);

        assert!(known.watches(&name("cp.example.")), "the zone itself");
        assert!(known.watches(&name("example.")), "its parent");
        assert!(known.watches(&name(".")), "the root above it");
        assert!(known.watches(&name("a.cp.example.")), "a zone beneath it");

        // Not everything, though: a sibling shares no delegation path, and
        // a name that merely ends in the same letters is not a suffix in the
        // DNS sense. That is sound rather than a gap, because a client only
        // accepts an apex that *contains* the membership domain, so every apex
        // it would accept is on one delegation path with the watched name.
        assert!(!known.watches(&name("other.example.")));
        assert!(!known.watches(&name("notcp.example.")));
    }

    /// A watch entry that is not a DNS name watches nothing, and is reported
    /// as such rather than sitting there quietly.
    ///
    /// What it must never do is match a certificate by some looser rule than
    /// the one the chain walk uses — that mismatch is what put a
    /// client-accepted entry in the silent bin. What it must never do
    /// *silently* is match nothing at all.
    #[test]
    fn an_unparseable_watch_entry_matches_nothing_and_is_reported() {
        let mut known = KnownKeys::default();
        known.keys.insert("sync.example..".into(), vec![]);
        assert_eq!(known.apexes().count(), 0);
        assert!(!known.contains(&name("sync.example"), b"a key"));
        assert_eq!(known.unwatchable(), ["sync.example.."]);

        // A list of names is watchable, and says so.
        let mut good = KnownKeys::default();
        good.keys.insert("cluster.example.com.".into(), vec![]);
        assert!(good.unwatchable().is_empty());
    }
}
