//! Deciding what a leaf is: an authorization for a zone, or noise.
//!
//! Everything here works from the certificate inside the leaf and nothing
//! else. In particular the DNSKEY, its key tag and the DS a parent would have
//! published are all **derived from the certificate's SubjectPublicKeyInfo**,
//! never looked up: the threat model has a compromised upstream DNS provider
//! in it, so a monitor that asked DNS what the zone's key is would be asking
//! the attacker.
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
    /// claim naming this apex. Recorded, not reported — and safe to be quiet
    /// about only because no client would have accepted it either (see the
    /// crate docs).
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

/// The keys this monitor has already seen authorized, per apex.
///
/// This is the monitor's memory, and it does exactly one job: stop a key from
/// being reported on every pass forever. A tier A entry whose key is not in
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
/// that list *covers* is wider than what it names — see [`KnownKeys::watches`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KnownKeys {
    /// `apex` → the SHA-256 hex of each already-reported key's DER
    /// SubjectPublicKeyInfo.
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, Vec<String>>,
}

/// How an entry's apex relates to the watch list: why this entry concerns an
/// operator who asked about some zone.
///
/// A watch list names zones, but the thing an operator actually cares about is
/// a *name* — `_synchronicity.<network>.<org>.<apex>`, the record a client
/// resolves. Which zone signs that name is not fixed: **a cut can be created
/// or removed at any label boundary along it**, and whoever controls the zone
/// above a boundary decides. So the set of zone keys that can authorize
/// themselves over a watched zone's names is every zone comparable with it in
/// the DNS tree, not the one name the operator wrote down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Watched {
    /// The entry names a watched apex itself.
    Directly,
    /// The entry names a **proper ancestor** of the watched zone it carries.
    ///
    /// An ancestor can serve the watched zone's names itself by withdrawing
    /// the delegation, at which point its own key is the one a client
    /// validates against and demands a log entry for. Nothing about that is
    /// detectable in the watched zone's own key history.
    Ancestor(Name),
    /// The entry names a **proper descendant** of the watched zone it carries.
    ///
    /// A cut created *below* a watched apex — `example.com` delegating
    /// `org.cp.example.com` away — takes the membership names inside it out of
    /// the watched zone's key entirely: the client follows the new cut, sees a
    /// different signer, and demands an entry naming the deeper zone. Again
    /// invisible in the watched zone's own history.
    Descendant(Name),
}

impl Watched {
    /// The watched zone this entry concerns, or `None` when the entry names a
    /// watched apex outright.
    pub fn zone(&self) -> Option<&Name> {
        match self {
            Watched::Directly => None,
            Watched::Ancestor(zone) | Watched::Descendant(zone) => Some(zone),
        }
    }

    /// The one-word relation, for machine-readable output.
    pub fn relation(&self) -> &'static str {
        match self {
            Watched::Directly => "direct",
            Watched::Ancestor(_) => "ancestor",
            Watched::Descendant(_) => "descendant",
        }
    }

    /// Why this entry is being reported, in a clause an operator can act on.
    pub fn note(&self) -> Option<String> {
        match self {
            Watched::Directly => None,
            Watched::Ancestor(zone) => Some(format!(
                "above watched {zone} — this zone can serve {zone}'s names by \
                 withdrawing its delegation, and its key would be the one clients validate"
            )),
            Watched::Descendant(zone) => Some(format!(
                "below watched {zone} — a cut here takes names inside {zone} out of \
                 {zone}'s key, and clients under it validate against this key instead"
            )),
        }
    }
}

impl KnownKeys {
    /// How, if at all, this watch list covers an entry naming `apex`.
    ///
    /// **Not an equality test, and that is the whole point.** Watching
    /// `cp.example.com` and matching only that spelling leaves two silent
    /// takeovers, in opposite directions along the same name:
    ///
    /// - `example.com` withdraws the `cp` delegation and serves
    ///   `_synchronicity.network.org.cp.example.com` itself. The signer a
    ///   client validates becomes `example.com`, so the entry an attacker must
    ///   publish names `example.com` — a zone an exact-match watch on
    ///   `cp.example.com` never looks at.
    /// - `example.com` (or `cp.example.com` itself, if that is what was taken)
    ///   delegates `org.cp.example.com` away. The signer becomes
    ///   `org.cp.example.com` and the entry names *that* — equally unwatched.
    ///
    /// Both produce an entry a client accepts (§4.2 apex binding is against
    /// the RRSIG signer, whatever it turns out to be) and a monitor classifies
    /// tier A. Only the watch filter stood between them and silence, so it
    /// covers every zone comparable with a watched one: the watched name
    /// itself, everything above it — `com` included, which really can withdraw
    /// `example.com`'s delegation — and everything below it. The DNS root is
    /// the single exclusion, and the body of this function says why.
    ///
    /// When several watched zones are comparable with `apex`, the report names
    /// the closest one by label count — the tightest true statement, and
    /// deterministic. The relation is what an operator acts on; which of their
    /// zones is named as the example is not.
    pub fn watches(&self, apex: &Name) -> Option<Watched> {
        // The root is the one ancestor deliberately left out. A root takeover
        // is real, but the entry it would need cannot exist: a SAN naming the
        // root is refused by `Certificate::single_dns_name`, so a client
        // served a root-signed answer fails closed instead of accepting a key
        // no monitor watched. Nothing silent is left for this filter to catch,
        // and treating the root as a watchable name would only make a stray
        // `""` in a state file match every entry in the log.
        if apex.is_root() {
            return None;
        }
        let mut closest: Option<(u8, Watched)> = None;
        for watched in self.apexes() {
            if watched == *apex {
                return Some(Watched::Directly);
            }
            let distance = watched.num_labels().abs_diff(apex.num_labels());
            let relation = match (apex.zone_of(&watched), watched.zone_of(apex)) {
                (true, _) => Watched::Ancestor(watched),
                (_, true) => Watched::Descendant(watched),
                // A zone in some other branch of the tree entirely: it cannot
                // serve a watched name and is not this operator's business.
                _ => continue,
            };
            if closest.as_ref().is_none_or(|(best, _)| distance < *best) {
                closest = Some((distance, relation));
            }
        }
        closest.map(|(_, relation)| relation)
    }

    /// Whether this SPKI has already been seen for `apex`.
    ///
    /// Names are compared **parsed**, never trimmed: an operator's state file
    /// says `sync.example` and a certificate says `sync.example.`,
    /// and those are one zone — but `sync.example..` is not a name at all
    /// and must match nothing.
    pub fn contains(&self, apex: &Name, spki: &[u8]) -> bool {
        let digest = hex::encode(sha256(spki));
        self.keys
            .iter()
            .filter(|(known, _)| chain::parse_name(known).is_ok_and(|known| known == *apex))
            .any(|(_, digests)| digests.iter().any(|d| d.eq_ignore_ascii_case(&digest)))
    }

    /// Records a key as seen for `apex`.
    pub fn insert(&mut self, apex: &Name, spki: &[u8]) {
        let key = apex.to_string();
        let digest = hex::encode(sha256(spki));
        let entry = self.keys.entry(key).or_default();
        if !entry.iter().any(|d| d.eq_ignore_ascii_case(&digest)) {
            entry.push(digest);
        }
    }

    /// The apexes this monitor watches, parsed. An entry that is not a DNS
    /// name watches nothing — it cannot match a certificate's SAN, which is
    /// parsed too.
    ///
    /// The root is dropped for the same reason, and it is the one spelling
    /// worth naming: `""` parses as the root, an empty string is the easiest
    /// thing to leave in a hand-edited state file, and the root is comparable
    /// with every name — so keeping it would turn one stray key into a watch
    /// on the entire log.
    pub fn apexes(&self) -> impl Iterator<Item = Name> + '_ {
        self.keys
            .keys()
            .filter_map(|apex| chain::parse_name(apex).ok())
            .filter(|apex| !apex.is_root())
    }
}

/// One classified leaf.
///
/// Everything an operator needs to act without believing anything the entry
/// says: the zone, the key tag and DS their registrar should be showing, the
/// exact key bytes by digest, and where in the log to look.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Where the entry sits in the log.
    pub log_index: u64,
    /// The apex the certificate names.
    pub apex: String,
    /// The key tag derived from the certificate's public key.
    pub key_tag: u16,
    /// The SHA-256 hex of the certificate's DER SubjectPublicKeyInfo.
    pub spki_sha256: String,
    /// The DS record the parent zone would have to publish for this key —
    /// derived, so an operator can compare it against what their registrar
    /// actually shows without believing anything this entry says.
    pub ds: String,
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
        format!(
            "[{}] index {} apex {} keyTag {} DS {} spki {} — {}",
            self.tier.letter(),
            self.log_index,
            self.apex,
            self.key_tag,
            self.ds,
            self.spki_sha256,
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
    // Everything about the zone and the key comes out of `chain::authorize`,
    // the same call the client makes — the apex parsed once from the SAN, the
    // key derived from the SPKI, the chain walked against exactly those. The
    // monitor may not compose this itself: doing so is how the two sides once
    // disagreed about whether `victim.example..` was a zone (see
    // `chain::authorize`), which put a client-accepted entry in the silent bin.
    let apex = body.certificate.single_dns_name().ok()?;
    // Only the P-256 keys this design logs are classifiable at all; anything
    // else in the certificate is somebody else's entry that happens to have
    // a SAN, and saying nothing about it is the honest answer.
    let dnskey_rdata = chain::zone_key_rdata(&body.certificate.spki)?;
    let mut finding = Finding {
        log_index,
        apex: apex.to_string(),
        key_tag: chain::key_tag(&dnskey_rdata),
        spki_sha256: hex::encode(sha256(&body.certificate.spki)),
        ds: chain::ds_fields(&apex, &dnskey_rdata),
        tier: Tier::B,
        reasons: Vec::new(),
    };

    match chain::authorize(&body.certificate, anchors) {
        Ok(authorized) => {
            // The chain verifies and covers this key, so a resolver holding
            // this anchor would take the entry. That is the whole of the
            // verdict: this key is authorized for this apex, and the monitor
            // does not — cannot — say by whom.
            finding.tier = Tier::A;
            finding.reasons.push(format!(
                "DNSSEC chain valid to {} ({} link(s)): this key is authorized for {apex}",
                authorized.chain.anchor_zone, authorized.chain.links
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

    /// The watch list covers the ladder, not one rung of it.
    ///
    /// Both directions are silent takeovers if this is an equality test: the
    /// zone above can withdraw the delegation and sign the watched zone's
    /// names itself, and a zone below can be delegated away and sign the names
    /// inside it. A client accepts either — it validates against whatever
    /// signer the cut produces — so a monitor that looked only for the exact
    /// spelling would report neither.
    #[test]
    fn a_watch_covers_the_zones_above_and_below_it() {
        let mut known = KnownKeys::default();
        known.keys.insert("cp.example.com".into(), vec![]);

        assert_eq!(
            known.watches(&name("cp.example.com")),
            Some(Watched::Directly)
        );
        // Above: example.com pulls the cp delegation and serves those names.
        assert_eq!(
            known.watches(&name("example.com")),
            Some(Watched::Ancestor(name("cp.example.com")))
        );
        assert_eq!(
            known.watches(&name("com")),
            Some(Watched::Ancestor(name("cp.example.com")))
        );
        // Below: a new cut takes membership names out of the watched key.
        assert_eq!(
            known.watches(&name("org.cp.example.com")),
            Some(Watched::Descendant(name("cp.example.com")))
        );
        assert_eq!(
            known.watches(&name("_synchronicity.network.org.cp.example.com")),
            Some(Watched::Descendant(name("cp.example.com")))
        );

        // A zone in another branch cannot sign a watched name, however much
        // of the spelling it shares. Suffix *string* matching would take the
        // first of these, which is a different registration entirely.
        for elsewhere in [
            "notcp.example.com",
            "cp.example.com.evil.test",
            "example.org",
            "cp.example",
        ] {
            assert_eq!(known.watches(&name(elsewhere)), None, "{elsewhere}");
        }
    }

    /// When several watched zones are comparable, the closest one is named.
    #[test]
    fn the_report_names_the_nearest_watched_zone() {
        let mut known = KnownKeys::default();
        known.keys.insert("example.com".into(), vec![]);
        known.keys.insert("cp.example.com".into(), vec![]);

        // `org.cp.example.com` sits below both; `cp.example.com` is nearer.
        assert_eq!(
            known.watches(&name("org.cp.example.com")),
            Some(Watched::Descendant(name("cp.example.com")))
        );
        // `com` sits above both; `example.com` is nearer.
        assert_eq!(
            known.watches(&name("com")),
            Some(Watched::Ancestor(name("example.com")))
        );
        // And an exact match beats any relation, whatever the order of the
        // map — the entry names a zone this operator wrote down.
        assert_eq!(known.watches(&name("example.com")), Some(Watched::Directly));
    }

    /// The root is nobody's watch entry, however it got into the file.
    ///
    /// `""` parses as the root and the root is comparable with every name, so
    /// one stray key would silently turn a watch list into a watch on the
    /// whole log. An entry naming the root is refused from the other side too
    /// (`Certificate::single_dns_name`), so nothing is lost.
    #[test]
    fn a_watch_on_the_root_watches_nothing() {
        let mut known = KnownKeys::default();
        known.keys.insert(String::new(), vec![]);
        known.keys.insert(".".into(), vec![]);
        assert_eq!(known.apexes().count(), 0);
        assert_eq!(known.watches(&name("cluster.example")), None);

        // And an entry that somehow named the root matches no watch either.
        known.keys.insert("cluster.example".into(), vec![]);
        assert_eq!(known.watches(&Name::root()), None);
    }

    /// A watch entry that is not a DNS name watches nothing.
    ///
    /// The state file is hand-edited, so it can contain anything. What it
    /// must never do is match a certificate by some looser rule than the one
    /// the chain walk uses — that mismatch is what put a client-accepted
    /// entry in the silent bin.
    #[test]
    fn an_unparseable_watch_entry_matches_nothing() {
        let mut known = KnownKeys::default();
        known.keys.insert("sync.example..".into(), vec![]);
        assert_eq!(known.apexes().count(), 0);
        assert!(!known.contains(&name("sync.example"), b"a key"));
    }

    #[test]
    fn a_spki_that_is_not_a_p256_key_is_not_classifiable() {
        assert!(chain::zone_key_rdata(&[0u8; 91]).is_none());
        let spki = synch_net::rekor::p256_spki(&[7u8; 64]);
        assert!(chain::zone_key_rdata(&spki).is_some());
        assert!(chain::zone_key_rdata(&spki[..90]).is_none());
    }
}
