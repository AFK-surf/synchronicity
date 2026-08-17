//! DNSSEC-based membership discovery (§3.2).
//!
//! The resolver queries `_synchronicity.<domain> TXT` and accepts records of
//! the form `v=sync1 id=<label> nk=<z-base-32 device key>`. The lookup MUST be
//! DNSSEC-validated end to end, in process — we do not trust an upstream
//! resolver's AD bit. If the chain of trust does not validate, the response is
//! discarded entirely and the previously cached member set is retained until
//! its own expiry. Fail closed.
//!
//! Everything above the resolver — record parsing and the malformed-set rules —
//! is pure and unit-tested here without touching the network.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    time::Duration,
};

use iroh_base::PublicKey;
use synch_core::{
    origin::{normalize_domain, normalize_label},
    NodeId, OriginId,
};

use hickory_resolver::proto::{
    dnssec::TrustAnchors,
    rr::{Name, RecordType},
};

use crate::{
    error::NetError,
    rekor::{self, LogKeys, ProofError, VerifiedRecord, ZoneKey},
    tuf::{self, PinState, Repo, TufError, TufMetadata, TufUpdate},
};

/// The label the membership TXT records live under.
pub const TXT_PREFIX: &str = "_synchronicity";

/// The version tag every accepted record must carry.
pub const RECORD_VERSION_TAG: &str = "sync1";

/// Lower clamp on the re-resolution interval (§3.2).
pub const MIN_TTL: Duration = Duration::from_secs(60);
/// Upper clamp on the re-resolution interval (§3.2).
pub const MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Extra grace before a binding that vanished from DNS expires (§3.2).
pub const DEFAULT_TRUST_GRACE: Duration = Duration::from_secs(10 * 60);

/// The DoH endpoint used when none is configured.
pub const DEFAULT_DOH_URL: &str = "https://1.1.1.1/dns-query";

/// The query name for a membership domain.
pub fn query_name(domain: &str) -> String {
    format!("{TXT_PREFIX}.{domain}")
}

/// The query name a zone's key-transparency proofs live under (§3).
///
/// One name per zone, at the apex — one zone key, one proof set. The client
/// learns the apex from the RRSIG signer field it already validates, not
/// from the membership name it asked about.
pub fn rekor_query_name(zone: &str) -> String {
    format!("{}.{}", rekor::REKOR_TXT_PREFIX, zone)
}

/// Where part `index` of a proof lives (§3).
///
/// A proof is far larger than one TXT record, and larger than what a managed
/// provider will hold at a single owner name — Cloudflare caps the combined
/// content of one name and type at 8192 wire-format bytes, which an
/// ICANN-rooted proof exceeds on its own. So the parts are spread across
/// names, one part each: part 1 at the base name, which is the only one a
/// client can compute before it has read anything, and every later part one
/// label along at `_synchronicity-rekor-<index>`. Part 1 says how many
/// there are.
pub fn rekor_part_query_name(zone: &str, index: usize) -> String {
    match index {
        0 | 1 => rekor_query_name(zone),
        n => format!("{}-{n}.{}", rekor::REKOR_TXT_PREFIX, zone),
    }
}

/// The control-plane apex a validated membership answer names, checked at
/// both ends.
///
/// Every record in the answer must agree — a set that named two apexes would
/// be pointing a client at two different control planes for one domain — and
/// the name has to sit between the domain being resolved and the zone that
/// signed the answer:
///
/// ```text
/// <signing zone>  ⊇  <apex>  ⊇  <membership domain>
/// ```
///
/// The lower bound is what stops a record from redirecting a client to a
/// control plane for a *sibling* namespace, whose monitor would never be
/// watching this one. The upper bound is what stops it pointing outside the
/// zone that actually vouched for the answer.
fn apex_of(domain: &str, signing_zone: &Name, records: &[String]) -> Result<Name, NetError> {
    let named: Vec<String> = records
        .iter()
        .filter_map(|record| parse_record(record).ok())
        .filter_map(|record| record.apex)
        .collect();
    let Some(first) = named.first() else {
        return Err(NetError::Dns(format!(
            "{domain}: no membership record names an apex= to find its \
             transparency records under"
        )));
    };
    if named.iter().any(|other| other != first) {
        return Err(NetError::Dns(format!(
            "{domain}: the membership records name more than one apex"
        )));
    }
    let mut apex =
        Name::from_utf8(first).map_err(|e| NetError::Dns(format!("apex {first}: {e}")))?;
    apex.set_fqdn(true);
    let apex = apex.to_lowercase();

    let mut owner = Name::from_utf8(domain).map_err(|e| NetError::Dns(format!("{domain}: {e}")))?;
    owner.set_fqdn(true);
    if !apex.zone_of(&owner.to_lowercase()) {
        return Err(NetError::Dns(format!(
            "{domain}: the records name apex {apex}, which does not contain it"
        )));
    }
    if !signing_zone.zone_of(&apex) {
        return Err(NetError::Dns(format!(
            "{domain}: the records name apex {apex}, which is outside {signing_zone}, \
             the zone that signed the answer"
        )));
    }
    Ok(apex)
}

/// Clamps a TTL into the §3.2 window.
pub fn clamp_ttl(ttl: Duration) -> Duration {
    ttl.clamp(MIN_TTL, MAX_TTL)
}

/// One parsed `v=sync1` TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRecord {
    /// The member label, lowercased. `None` for the id-less backward-simple
    /// form, which binds `OriginId::Key(nk)`.
    pub id: Option<String>,
    /// The device key the record binds.
    pub node_key: NodeId,
    /// An optional relay dialing hint (§3.3).
    pub relay: Option<String>,
    /// An optional direct-address dialing hint (§3.3).
    pub addr: Option<String>,
    /// The control plane this record's zone belongs to, as the operator
    /// names it — where the transparency records for it live.
    ///
    /// It is a *hint about where to look*, never an authority: the apex it
    /// names has to contain this membership domain, has to be contained by
    /// the zone whose RRSIG signed the answer, and has to be what the log
    /// entry's own certificate names. A wrong value points at a name with no
    /// usable proof, which fails closed. Its purpose is to let two control
    /// planes share one signing zone without sharing a single record name.
    pub apex: Option<String>,
}

impl MemberRecord {
    /// The origin this record binds its key to, within `domain`.
    pub fn origin(&self, domain: &str) -> Result<OriginId, NetError> {
        match &self.id {
            Some(id) => OriginId::named(id, domain).map_err(|e| NetError::Dns(e.to_string())),
            None => Ok(OriginId::Key(self.node_key)),
        }
    }
}

/// Why a TXT record was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The record did not start with `v=sync1`.
    #[error("not a v=sync1 record")]
    NotSync1,
    /// The record had no `nk=` field.
    #[error("record has no nk= field")]
    MissingKey,
    /// The `nk=` field was not a valid z-base-32 device key.
    #[error("invalid nk= device key: {0}")]
    BadKey(String),
    /// The `id=` field was not a valid member label.
    #[error("invalid id= label: {0}")]
    BadLabel(String),
    /// A field appeared more than once.
    #[error("duplicate field {0}=")]
    Duplicate(&'static str),
}

/// Parses one TXT record string.
///
/// Fields are whitespace-separated `key=value` pairs. `v=sync1` must come
/// first; unknown fields are ignored so the format can grow.
pub fn parse_record(text: &str) -> Result<MemberRecord, RecordError> {
    let mut fields = text.split_whitespace();
    match fields.next() {
        Some(first) if first == format!("v={RECORD_VERSION_TAG}") => {}
        _ => return Err(RecordError::NotSync1),
    }

    let mut id = None;
    let mut node_key = None;
    let mut relay = None;
    let mut addr = None;
    let mut apex = None;
    for field in fields {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        match key {
            "id" => {
                if id.is_some() {
                    return Err(RecordError::Duplicate("id"));
                }
                id = Some(
                    normalize_label(value).map_err(|_| RecordError::BadLabel(value.to_string()))?,
                );
            }
            "nk" => {
                if node_key.is_some() {
                    return Err(RecordError::Duplicate("nk"));
                }
                node_key = Some(
                    PublicKey::from_z32(value)
                        .map_err(|e| RecordError::BadKey(format!("{value}: {e}")))?,
                );
            }
            "relay" => relay = Some(value.to_string()),
            "addr" => addr = Some(value.to_string()),
            "apex" => apex = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }

    Ok(MemberRecord {
        id,
        node_key: node_key.ok_or(RecordError::MissingKey)?,
        relay,
        addr,
        apex,
    })
}

/// The validated membership set for one domain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemberSet {
    /// The membership domain, normalized.
    pub domain: String,
    /// The accepted `(origin, device key)` bindings.
    pub bindings: Vec<(OriginId, NodeId)>,
    /// Device keys that appear under more than one identity. Self-detection
    /// refuses to guess for these, and `synch doctor` reports the ambiguity
    /// (§3.2).
    pub ambiguous_keys: Vec<NodeId>,
    /// Records that could not be parsed, with the reason, for `synch doctor`.
    pub rejected: Vec<(String, RecordError)>,
    /// Dialing hints, by device key (§3.3).
    pub hints: BTreeMap<[u8; 32], Vec<String>>,
}

impl MemberSet {
    /// Applies the §3.2 record and malformed-set rules to a batch of TXT
    /// strings that have *already* been DNSSEC-validated.
    pub fn from_records(domain: &str, records: &[String]) -> Result<MemberSet, NetError> {
        let domain = normalize_domain(domain).map_err(|e| NetError::Dns(e.to_string()))?;
        let mut parsed = Vec::new();
        let mut rejected = Vec::new();
        for text in records {
            match parse_record(text) {
                Ok(record) => parsed.push(record),
                Err(e) => rejected.push((text.clone(), e)),
            }
        }

        // Malformed-set rule: if the same nk appears under two different ids —
        // or once with and once without an id — the key is ambiguous and every
        // binding it would create is dropped.
        let mut identities: BTreeMap<[u8; 32], BTreeSet<Option<String>>> = BTreeMap::new();
        for record in &parsed {
            identities
                .entry(*record.node_key.as_bytes())
                .or_default()
                .insert(record.id.clone());
        }
        let ambiguous: BTreeSet<[u8; 32]> = identities
            .iter()
            .filter(|(_, ids)| ids.len() > 1)
            .map(|(key, _)| *key)
            .collect();

        let mut bindings = Vec::new();
        let mut hints: BTreeMap<[u8; 32], Vec<String>> = BTreeMap::new();
        for record in &parsed {
            let key_bytes = *record.node_key.as_bytes();
            for hint in [record.relay.as_ref(), record.addr.as_ref()]
                .into_iter()
                .flatten()
            {
                hints.entry(key_bytes).or_default().push(hint.clone());
            }
            if ambiguous.contains(&key_bytes) {
                continue;
            }
            let origin = record.origin(&domain)?;
            let binding = (origin, record.node_key);
            if !bindings.contains(&binding) {
                bindings.push(binding);
            }
        }
        bindings.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.as_bytes().cmp(b.1.as_bytes())));

        let mut ambiguous_keys: Vec<NodeId> = Vec::new();
        for key in &ambiguous {
            if let Ok(k) = PublicKey::from_bytes(key) {
                ambiguous_keys.push(k);
            }
        }

        Ok(MemberSet {
            domain,
            bindings,
            ambiguous_keys,
            rejected,
            hints,
        })
    }

    /// Every device key bound to `origin` in this set. Several keys for one
    /// origin is the rotation window (§3.4), not an error.
    pub fn keys_for(&self, origin: &OriginId) -> Vec<NodeId> {
        self.bindings
            .iter()
            .filter(|(o, _)| o == origin)
            .map(|(_, k)| *k)
            .collect()
    }

    /// The origin a device key resolves to, for self-detection.
    ///
    /// Returns `None` when the key is absent *or* ambiguous: §3.2 requires an
    /// explicit `--id` rather than a guess.
    pub fn self_origin(&self, key: &NodeId) -> Option<OriginId> {
        if self.ambiguous_keys.contains(key) {
            return None;
        }
        let matches: Vec<&OriginId> = self
            .bindings
            .iter()
            .filter(|(_, k)| k == key)
            .map(|(o, _)| o)
            .collect();
        match matches.as_slice() {
            [only] => Some((*only).clone()),
            _ => None,
        }
    }

    /// Dialing hints published for a device key (§3.3).
    pub fn hints_for(&self, key: &NodeId) -> &[String] {
        self.hints
            .get(key.as_bytes())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Parses and normalizes a DoH endpoint URL.
///
/// `https://` or `http://`, host required, query path defaulting to
/// `/dns-query`. Plaintext is not the security hole it looks like: the
/// answers are DNSSEC-validated in process exactly as on the UDP-53 default
/// path, so http costs query privacy and a denial lever — the same things
/// UDP already concedes — and nothing about integrity.
fn doh_url(url: &str) -> Result<reqwest::Url, NetError> {
    let bad = |why: String| NetError::Dns(format!("DoH endpoint {url}: {why}"));
    let mut parsed = reqwest::Url::parse(url).map_err(|e| bad(e.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(bad("must be an https:// or http:// URL".into()));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(bad("no host".into()));
    }
    if matches!(parsed.path(), "" | "/") {
        parsed.set_path("/dns-query");
    }
    Ok(parsed)
}

/// A DNSSEC-validating resolver for membership domains.
///
/// One transport, DNS-over-HTTP(S), and one validator: every answer record
/// is required to carry a *secure* DNSSEC proof computed in process, so an
/// insecure or bogus answer is discarded rather than trusted. There is no
/// UDP path and no system stub resolver in the loop at all — hickory is
/// here purely as the validation engine.
#[derive(Clone)]
pub struct DnssecResolver {
    handle: hickory_resolver::net::dnssec::DnssecDnsHandle<DohHandle>,
    /// The DNSSEC trust anchors in force — the ICANN root, or whatever
    /// `--dnssec-anchor` replaced it with. Held here as well as inside the
    /// validating handle because the DNSSEC chain a log entry carries is
    /// checked against the same anchors the live answers are.
    anchors: std::sync::Arc<TrustAnchors>,
    rekor: RekorPolicy,
    pins: std::sync::Arc<std::sync::Mutex<Pins>>,
    tuf: Option<TufSource>,
}

/// The transparency-log pin set in force, and whether TUF may move it
/// (§10.2's resolution order).
///
/// An explicit `--rekor-key` file is a static, different universe: the pin
/// set is what the file says and TUF refresh is disabled entirely, so the
/// resolver never walks anything. Otherwise the pins are the last
/// TUF-verified set, else the embedded bootstrap snapshot.
#[derive(Debug)]
enum Pins {
    /// `--rekor-key` named a file. Nothing refreshes this.
    Static(LogKeys),
    /// The refreshable set: what is in force, the TUF state it came from,
    /// and where that state is persisted (`None` keeps it in memory, which
    /// is what a one-shot command or a test wants).
    Tuf {
        keys: LogKeys,
        state: PinState,
        path: Option<std::path::PathBuf>,
        /// The `root.json` every persisted state is re-walked from before it
        /// is believed — [`tuf::EMBEDDED_TUF_ROOT`] unless `--tuf-root`
        /// replaced it. Held here so a reload cannot silently anchor at
        /// something the file itself supplied.
        anchor: Vec<u8>,
        /// When the repository was last walked, successfully or not, so a
        /// membership refresh on a short TTL does not become a request to
        /// Sigstore's CDN every time it fires. Seeded from the persisted
        /// state's `updated_at`, so a restart does not reset the clock —
        /// but *not* persisted on failure, so a run that could not reach
        /// the repository retries on the next start rather than resting a
        /// full day on nothing.
        checked_at: u64,
    },
}

impl Pins {
    /// The pin set a proof is checked against right now.
    fn log_keys(&self) -> LogKeys {
        match self {
            Pins::Static(keys) => keys.clone(),
            Pins::Tuf { keys, .. } => keys.clone(),
        }
    }
}

/// Where the pin set is refreshed from (§10.2).
///
/// Held as an `Option`, and `None` — `--no-tuf`, or an explicit
/// `--rekor-key` making the whole pin set static — is the reason: refresh
/// being off is a state with no repository in it at all, rather than a
/// repository that answers nothing.
#[derive(Clone)]
enum TufSource {
    /// Sigstore's TUF repository, read over HTTPS. The URL is not trusted
    /// with anything — every byte fetched under it is checked against the
    /// embedded root — so this is a mirror knob, not a trust knob.
    Url(String),
    /// A repository supplied by the caller, so the walk is exercisable
    /// without egress. Tests use it; nothing else does.
    Repo(std::sync::Arc<dyn Repo + Send + Sync>),
}

impl std::fmt::Debug for DnssecResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DnssecResolver")
    }
}

/// A validated lookup result.
#[derive(Debug, Clone)]
pub struct ValidatedTxt {
    /// The TXT strings, one per record.
    pub records: Vec<String>,
    /// How long the answer may be cached, clamped to the §3.2 window.
    pub ttl: Duration,
    /// The zone whose RRSIG covered this answer, as the signature named it —
    /// checked to enclose the queried name before the answer was accepted
    /// (see [`secure_txt`]).
    pub signer: Name,
    /// The key tag that RRSIG selected, for the transparency lookup.
    pub key_tag: u16,
}

/// How the resolver reaches the DNS and whom it ultimately trusts (§3.2).
///
/// The defaults — the public endpoint at [`DEFAULT_DOH_URL`], the ICANN root
/// trust anchor — are what production wants; both knobs exist for the
/// environments where they are wrong: an internal DoH endpoint (http or
/// https) for closed networks, and an internal test zone signed by its own
/// root swapping the trust anchor. Neither weakens the §3.2 stance:
/// validation happens in process against whatever anchor is in force, and
/// the endpoint is a transport, never a validator we defer to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolverOptions {
    /// The DNS-over-HTTP(S) endpoint, [`DEFAULT_DOH_URL`] when unset.
    ///
    /// `https://` or `http://`, then `host[:port][/path]`; the path defaults
    /// to `/dns-query`. A plaintext endpoint is acceptable because the
    /// transport carries nothing trusted: every answer is DNSSEC-validated
    /// in process either way, so http concedes query privacy and a denial
    /// lever — what classic UDP DNS always conceded — and nothing about
    /// integrity.
    pub doh_url: Option<String>,
    /// A file of `DNSKEY` records (zone syntax, as `dig` prints them)
    /// *replacing* the ICANN root trust anchor.
    ///
    /// For internal deployments and tests that run their own signed root.
    /// With this set, nothing signed under the real root validates any more:
    /// an override is a different universe, not an addition to this one.
    pub trust_anchor: Option<std::path::PathBuf>,
    /// Whether a validated answer additionally requires a verified
    /// transparency-log record for the zone key that signed it (§4.1).
    ///
    /// `None` takes the default [`ResolverOptions::rekor_policy`] resolves:
    /// require, everywhere. The option is three-state on purpose — "unset"
    /// means the default, while an explicit `--rekor` states a choice, and
    /// `off` is a choice this design wants stated, never inherited.
    pub rekor: Option<RekorPolicy>,
    /// A file of transparency-log verification key(s) *replacing* the
    /// embedded one (§4.1).
    ///
    /// PEM `PUBLIC KEY` blocks or one base64 SubjectPublicKeyInfo per line.
    /// Same semantics as `trust_anchor`: an override is a different
    /// universe. A self-hosted log lives here.
    ///
    /// Setting it also disables TUF pin refresh outright (§10.2): a static
    /// universe is static in both directions.
    pub rekor_key: Option<std::path::PathBuf>,
    /// Where the TUF-verified pin set is persisted (§10.2).
    ///
    /// The daemon passes `<data-dir>/rekor-pins.json`; `None` keeps the
    /// state in memory, which is what a one-shot command or a test wants.
    /// The file is global across domains and monotonic on purpose — the pin
    /// set belongs to Sigstore, not to any domain being resolved, so every
    /// domain shares one floor.
    pub rekor_state: Option<std::path::PathBuf>,
    /// The Sigstore TUF repository the pin set follows, [`tuf::SIGSTORE_TUF_URL`]
    /// when unset (§10.2).
    ///
    /// A mirror knob rather than a trust knob: whatever it names, the
    /// material fetched under it is verified against the embedded TUF root
    /// before anything moves. A deployment running its *own* Sigstore points
    /// this at its repository and `rekor_key` at its log.
    pub tuf_url: Option<String>,
    /// Turns pin refresh off, leaving the client on the pins it already has
    /// — the persisted set, else the embedded bootstrap snapshot.
    ///
    /// For a deployment that will not have its daemon reach a CDN. The cost
    /// is stated in §10.4: the pin set stops following Sigstore, so the day
    /// a shard rotates is the day this client needs a new build.
    pub no_tuf: bool,
    /// A `root.json` *replacing* [`tuf::EMBEDDED_TUF_ROOT`] as the anchor
    /// every pin state is verified against.
    ///
    /// The same "an override is a different universe" semantics as
    /// `trust_anchor` and `rekor_key`: with this set, a persisted pin state
    /// chaining from the built-in Sigstore root no longer loads, and vice
    /// versa. For a deployment running its own TUF repository — the client
    /// counterpart of the control plane's `CP_TUF_ROOT` — and for the test
    /// harness, which anchors at a root it minted.
    pub tuf_root: Option<std::path::PathBuf>,
}

/// Whether zone-key transparency is enforced (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekorPolicy {
    /// A validated answer is discarded unless the zone key that signed it
    /// carries a verified log record. Fail closed, as §4.3 requires.
    Require,
    /// No log record is consulted. DNSSEC alone decides, as it did before
    /// this design existed.
    Off,
}

impl ResolverOptions {
    /// The policy in force, resolving the default when none was chosen.
    ///
    /// The default is `require`, everywhere — the embedded Sigstore
    /// snapshot means a stock build can always verify, and a zone key that
    /// is not on the public record is exactly what this design exists to
    /// refuse. That holds behind `trust_anchor` too: a pinned anchor closes
    /// the delegation chain to substitution, but the log requirement is
    /// about the key being *public*, and an internal deployment that wants
    /// neither the public log nor its own says `off` in so many words
    /// rather than inheriting it from an unrelated flag.
    pub fn rekor_policy(&self) -> RekorPolicy {
        self.rekor.unwrap_or(RekorPolicy::Require)
    }
}

impl DnssecResolver {
    /// Builds a resolver with every default: the public endpoint, the ICANN
    /// root trust anchor.
    pub fn with_defaults() -> Result<Self, NetError> {
        Self::with_options(&ResolverOptions::default())
    }

    /// Builds a resolver honoring [`ResolverOptions`], with in-process DNSSEC
    /// validation always on.
    pub fn with_options(options: &ResolverOptions) -> Result<Self, NetError> {
        let anchors = match &options.trust_anchor {
            None => std::sync::Arc::new(TrustAnchors::default()),
            Some(path) => {
                let anchors = TrustAnchors::from_file(path)
                    .map_err(|e| NetError::Dns(format!("trust anchor {}: {e}", path.display())))?;
                if anchors.is_empty() {
                    // An empty anchor set validates nothing, forever, quietly.
                    return Err(NetError::Dns(format!(
                        "trust anchor {}: no DNSKEY records in the file",
                        path.display()
                    )));
                }
                std::sync::Arc::new(anchors)
            }
        };
        let url = doh_url(options.doh_url.as_deref().unwrap_or(DEFAULT_DOH_URL))?;
        let handle = DohHandle::new(url)?;
        // §10.2's pin resolution order, decided once, here: an explicit key
        // file (static universe) ▸ the persisted TUF-accepted set ▸ the
        // embedded bootstrap snapshot.
        let pins = match &options.rekor_key {
            Some(path) => {
                Pins::Static(LogKeys::from_file(path).map_err(|e| NetError::Dns(e.to_string()))?)
            }
            None => {
                // The anchor is decided here, from the binary or from an
                // explicit override, and never from the state file — which
                // is the point of re-walking the chain at all.
                let anchor = match &options.tuf_root {
                    None => tuf::EMBEDDED_TUF_ROOT.as_bytes().to_vec(),
                    Some(path) => std::fs::read(path)
                        .map_err(|e| NetError::Dns(format!("TUF root {}: {e}", path.display())))?,
                };
                let state = options
                    .rekor_state
                    .as_deref()
                    .and_then(|path| PinState::load_anchored(path, &anchor))
                    .unwrap_or_else(|| PinState::anchored(&anchor));
                Pins::Tuf {
                    keys: state.log_keys().unwrap_or_else(LogKeys::embedded),
                    anchor,
                    // A walk is due when the last one has aged out, and a
                    // state that was never written is a client that has
                    // never walked — so a fresh install refreshes at once
                    // and a restarted one does not.
                    checked_at: state.updated_at,
                    state,
                    path: options.rekor_state.clone(),
                }
            }
        };
        let tuf = match (options.no_tuf, &options.rekor_key) {
            (true, _) | (_, Some(_)) => None,
            (false, None) => Some(TufSource::Url(
                options
                    .tuf_url
                    .clone()
                    .unwrap_or_else(|| tuf::SIGSTORE_TUF_URL.to_string()),
            )),
        };
        Ok(DnssecResolver {
            handle: hickory_resolver::net::dnssec::DnssecDnsHandle::with_trust_anchor(
                handle,
                anchors.clone(),
            ),
            // The same anchor set the live validator uses, kept so that the
            // DNSSEC chain a log entry carries is checked against the trust
            // this resolver actually holds — "an override is a different
            // universe" has to hold in both directions, or a client running
            // `--dnssec-anchor` would demand a chain to the ICANN root it
            // does not trust.
            anchors,
            rekor: options.rekor_policy(),
            pins: std::sync::Arc::new(std::sync::Mutex::new(pins)),
            tuf,
        })
    }

    /// Refreshes the pin set from `repo` instead of over HTTPS.
    ///
    /// The one seam the walk needs to be exercisable without egress, so no
    /// test run ever reaches Sigstore by accident. Has no effect when the
    /// pin set is static (`--rekor-key`) or refresh is off.
    pub fn with_tuf_repo(mut self, repo: std::sync::Arc<dyn Repo + Send + Sync>) -> Self {
        self.tuf = self.tuf.map(|_| TufSource::Repo(repo));
        self
    }

    /// Whether this resolver requires zone-key transparency (§4.1).
    pub fn rekor_policy(&self) -> RekorPolicy {
        self.rekor
    }

    /// The transparency-log keys a proof is checked against right now.
    ///
    /// A snapshot rather than a handle: under [`RekorPolicy::Require`] a TUF
    /// update can replace this between refreshes, which is the whole point
    /// of §10.
    pub fn log_keys(&self) -> LogKeys {
        self.pins().log_keys()
    }

    fn pins(&self) -> std::sync::MutexGuard<'_, Pins> {
        self.pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Resolves `_synchronicity.<domain> TXT`, discarding anything that does
    /// not validate.
    pub async fn lookup_txt(&self, domain: &str) -> Result<ValidatedTxt, NetError> {
        let domain = normalize_domain(domain).map_err(|e| NetError::Dns(e.to_string()))?;
        let name = query_name(&domain);
        let response = self.lookup(&name, RecordType::TXT).await?;
        secure_txt(&name, &response.answers)
    }

    /// Resolves and applies the §3.2 rules in one step.
    ///
    /// Under [`RekorPolicy::Require`] this is where §4.2's three validated
    /// lookups happen, over the one DoH transport: the membership TXT, the
    /// DNSKEY at the zone its RRSIG names, and the proof record beside it.
    /// A refused proof refuses the whole answer — the caller keeps its
    /// cached member set until its own expiry, exactly as for a bogus chain.
    pub async fn member_set(&self, domain: &str) -> Result<(MemberSet, Duration), NetError> {
        let domain = normalize_domain(domain).map_err(|e| NetError::Dns(e.to_string()))?;
        let name = query_name(&domain);
        let response = self.lookup(&name, RecordType::TXT).await?;
        let validated = secure_txt(&name, &response.answers)?;
        if self.rekor == RekorPolicy::Require {
            // The zone that signed the answer. Every record this client goes
            // on to fetch hangs off it, because it is the only name the
            // answer itself yields — the control plane's apex is a name only
            // the log entry knows, and it is checked against this one rather
            // than used to find anything.
            //
            // It comes out of `secure_txt`, which already held it to
            // RFC 4035 §5.3.1 before returning: a signer that does not
            // enclose the queried name never reaches this line.
            let (signing_zone, key_tag) = (validated.signer.clone(), validated.key_tag);
            // Where the control plane's transparency records live. Taken
            // from the answer this client just DNSSEC-validated, and then
            // held to both ends: it must contain the domain being resolved
            // and be contained by the zone that signed it. Two control
            // planes inside one signing zone would otherwise have to share a
            // single record name — and, on the publishing side, delete each
            // other's records forever.
            let apex = apex_of(&domain, &signing_zone, &validated.records)?;
            // The pin set is refreshed *before* the proof is verified, so a
            // proof from a shard Sigstore added since this build shipped
            // verifies in the same refresh that learned about it (§10.2).
            //
            // And nothing about it can fail this refresh: an unreachable,
            // stale or hostile TUF repository leaves the current pins
            // standing, because a client that cannot read Sigstore must
            // degrade to a frozen pin set — the behavior a build-time
            // snapshot always had — and never to a failed cluster. At most
            // once a day, too: the pins move on Sigstore's schedule, not on
            // the zone's TTL.
            match self.refresh_tuf().await {
                Ok(Some(update)) if update.changed => tracing::info!(
                    root = update.state.root_version,
                    timestamp = update.state.timestamp_version,
                    logs = update.log_keys.keys().len(),
                    "transparency-log pin set updated from Sigstore's TUF repository"
                ),
                Ok(_) => {}
                Err(e) => tracing::debug!(
                    error = %e,
                    "Sigstore's TUF repository did not update the pin set; the current pins stand"
                ),
            }
            self.verify_zone_key(&domain, &apex, &signing_zone, key_tag)
                .await?;
        }
        let set = MemberSet::from_records(&domain, &validated.records)?;
        Ok((set, validated.ttl))
    }

    /// Walks Sigstore's TUF repository and adopts what it served if it is
    /// newer (§10.2).
    ///
    /// `Ok(None)` is the ordinary case: refresh is off, or the last walk is
    /// still young. An `Err` names the class the chain broke in, for `synch
    /// doctor`; the refresh pipeline logs it and carries on, because nothing
    /// about a TUF repository is allowed to fail a membership refresh.
    ///
    /// Under an explicit `--rekor-key`, or `--no-tuf`, this does nothing at
    /// all and fetches nothing: a static universe is static in both
    /// directions.
    pub async fn refresh_tuf(&self) -> Result<Option<TufUpdate>, NetError> {
        let Some(source) = self.tuf.clone() else {
            return Ok(None);
        };
        // Two decisions under the lock and nothing else: whether a walk is
        // due, and which root version it starts from. The walk itself is
        // seconds of network, and holding a mutex across it would serialize
        // every membership refresh in the process behind a CDN.
        let (now, from_root) = {
            let mut pins = self.pins();
            let Pins::Tuf {
                state, checked_at, ..
            } = &mut *pins
            else {
                return Ok(None);
            };
            // No trustworthy clock, no refresh. Expiry is the only bound on
            // how old the metadata a mirror may serve is, and the pins
            // already in force are the safe place to stay.
            let Some(now) = now_unix(state.updated_at) else {
                return Err(tuf_error(
                    &source,
                    TufError::Expiry(
                        "the system clock is unreadable, so no expiry could be \
                         checked; the current pins stand"
                            .into(),
                    ),
                ));
            };
            if now < checked_at.saturating_add(tuf::REFRESH_INTERVAL) {
                return Ok(None);
            }
            // Stamped before the walk rather than after it, so a repository
            // that is slow or down costs one attempt a day and not one per
            // membership refresh for as long as it stays down.
            *checked_at = now;
            (now, state.root_version)
        };
        let metadata = self.walk_tuf(&source, from_root).await?;

        // The state is re-read from disk under the lock rather than trusted
        // from memory: two resolvers in one data directory share one file,
        // and monotonicity is a property of the file, not of a process.
        let mut pins = self.pins();
        let Pins::Tuf {
            keys,
            state,
            path,
            anchor,
            ..
        } = &mut *pins
        else {
            return Ok(None);
        };
        // Whichever of the two is further along, whole: a state is a
        // coherent set — the root bytes, the trusted-root bytes and the
        // versions that describe them — so taking the newer *state* is
        // right and taking the newer of each field would not be.
        //
        // Re-walked from this resolver's anchor, exactly as at startup: the
        // file is shared, so it is no more trusted here than it was there.
        let current = match path
            .as_deref()
            .and_then(|path| PinState::load_anchored(path, anchor))
        {
            Some(stored) if dominates(&stored, state) => stored,
            _ => state.clone(),
        };
        let update = tuf::update(&metadata, &current, now).map_err(|e| tuf_error(&source, e))?;
        if let Some(path) = path.as_deref() {
            if let Err(e) = update.state.save(path) {
                // A pin set that cannot be persisted is still a pin set: it
                // is adopted for this process and re-learned next time.
                tracing::warn!(path = %path.display(), error = %e, "could not persist the TUF pin state");
            }
        }
        *keys = update.log_keys.clone();
        *state = update.state.clone();
        Ok(Some(update))
    }

    /// Collects the metadata chain from the repository, off the reactor.
    ///
    /// The walk is a handful of sequential HTTPS GETs ending in a few
    /// hundred KB of `targets.json`, and [`tuf::fetch_metadata`] is the one
    /// implementation of it — the monitor runs the same function against the
    /// same trait. Running it on a blocking thread is what lets that stay
    /// true without a second, async transcription of a walk whose every step
    /// is load-bearing.
    async fn walk_tuf(&self, source: &TufSource, from_root: u64) -> Result<TufMetadata, NetError> {
        let owned = source.clone();
        let walked = tokio::task::spawn_blocking(move || match &owned {
            TufSource::Repo(repo) => tuf::fetch_metadata(&**repo, from_root),
            TufSource::Url(url) => {
                tuf::fetch_metadata(&HttpRepo::new(url).map_err(TufError::Malformed)?, from_root)
            }
        })
        .await
        .map_err(|e| NetError::Dns(format!("the TUF walk did not finish: {e}")))?;
        walked.map_err(|e| tuf_error(source, e))
    }

    /// Verifies that the zone key which signed an answer is on the public
    /// record (§4.2). Two more validated lookups, then no network at all.
    pub async fn verify_zone_key(
        &self,
        domain: &str,
        apex: &Name,
        signing_zone: &Name,
        key_tag: u16,
    ) -> Result<VerifiedRecord, NetError> {
        let zone_text = signing_zone.to_string();
        let apex_text = apex.to_string();
        let dnskey_rdata = self.zone_dnskey(signing_zone, key_tag).await?;

        // Under the **apex**, which the membership answer named: every
        // record a control plane owns hangs off its own apex, so two of them
        // in one signing zone never share a name.
        let apex_label = apex_text.trim_end_matches('.');
        let name = rekor_query_name(apex_label);
        let response = self.lookup(&name, RecordType::TXT).await?;
        let absent = || NetError::RekorAbsent {
            name: name.clone(),
            key_tag,
        };
        // A name that does not exist and a name that exists with no proof
        // for this key tag are the same fact to a client: this key was never
        // logged, as far as the zone is willing to say.
        let records = match secure_txt(&name, &response.answers) {
            Ok(validated) => validated.records,
            Err(NetError::Dns(_)) if response.answers.is_empty() => return Err(absent()),
            Err(e) => return Err(e),
        };

        // One unreadable record must not sink a readable one. During a
        // rollover the set holds a record per key, and a control plane
        // mid-upgrade can leave an old-format record beside a current one —
        // refusing the whole set then strands a client that had exactly the
        // proof it needed sitting next to the one it did not. The set is
        // DNSSEC-validated, so a record here is one the zone published;
        // skipping the ones this build cannot read is a compatibility rule,
        // not an injection risk.
        //
        // A malformed record is still reported when *nothing* matched, so
        // "the zone published gibberish" stays distinguishable from "the zone
        // published nothing for this key" — the two read very differently in
        // `synch doctor`.
        // A proof spans several records across several names. Part 1 is the
        // only name derivable from the answer; it says how many parts there
        // are, and the rest are fetched by index until the set is whole.
        // Bounded by what part 1 claims, and by the format's own 255-part
        // ceiling, so a lying record cannot turn one refresh into a scan.
        let mut records = records;
        let wanted = rekor::parts_claimed(&records);
        for index in 2..=wanted {
            let part = rekor_part_query_name(apex_label, index);
            // A part that does not resolve leaves the set incomplete, which
            // `proofs_from_txt` reports as the missing-part refusal it is —
            // better than a transport error naming a name the operator never
            // configured.
            if let Ok(answer) = self.lookup(&part, RecordType::TXT).await {
                if let Ok(validated) = secure_txt(&part, &answer.answers) {
                    records.extend(validated.records);
                }
            }
        }

        let mut candidates = Vec::new();
        let mut malformed: Option<rekor::ProofError> = None;
        for reassembled in rekor::proofs_from_txt(&records) {
            match reassembled {
                Ok(candidate) => candidates.push(candidate),
                Err(e) => malformed = Some(e),
            }
        }
        if candidates.is_empty() {
            // One unreadable record must not sink a readable one. During a
            // rollover the set holds a record per key, and a control plane
            // mid-upgrade can leave an old-format record beside a current
            // one — refusing the whole set then strands a client that had
            // exactly the proof it needed sitting next to the one it did
            // not. The set is DNSSEC-validated, so a record here is one the
            // zone published; skipping what this build cannot read is a
            // compatibility rule, not an injection risk.
            //
            // A malformed record is still reported when *nothing* matched, so
            // "the zone published gibberish" stays distinguishable from "the
            // zone published nothing for this key" — the two read very
            // differently in `synch doctor`.
            return Err(match malformed {
                Some(e) => NetError::RekorMalformed {
                    name: name.clone(),
                    reason: e.to_string(),
                },
                None => absent(),
            });
        }

        let key = ZoneKey {
            domain,
            signing_zone: &zone_text,
            key_tag,
            dnskey_rdata: &dnskey_rdata,
        };
        // Every candidate, not just the last. A record's subject is a key
        // set, so there is no selector on the wire — a zone can legitimately
        // serve more than one record (a retirement breadcrumb beside the
        // live claim), and membership in a verified set is what decides.
        let mut last = None;
        for candidate in &candidates {
            match rekor::verify(candidate, &key, &self.log_keys(), &self.anchors) {
                Ok(verified) => return Ok(verified),
                Err(e) => last = Some(e),
            }
        }
        Err(rekor_error(
            &name,
            last.expect("a non-empty candidate list yields an error"),
        ))
    }

    /// The validated DNSKEY rdata for one key tag at `apex` (§4.2 step 2).
    async fn zone_dnskey(&self, apex: &Name, key_tag: u16) -> Result<Vec<u8>, NetError> {
        use hickory_resolver::proto::{
            dnssec::{rdata::DNSSECRData, PublicKey},
            rr::RData,
        };

        let name = apex.to_string();
        let response = self.lookup(&name, RecordType::DNSKEY).await?;
        for record in &response.answers {
            if record.name != *apex || !record.proof.is_secure() {
                continue;
            }
            let RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) = &record.data else {
                continue;
            };
            if dnskey.calculate_key_tag().ok() != Some(key_tag) {
                continue;
            }
            // The rdata as the wire carries it — the exact bytes the entry's
            // subject digest commits to.
            let mut rdata = Vec::with_capacity(4 + 64);
            rdata.extend_from_slice(&dnskey.flags().to_be_bytes());
            rdata.push(3);
            rdata.push(u8::from(dnskey.public_key().algorithm()));
            rdata.extend_from_slice(dnskey.public_key().public_bytes());
            return Ok(rdata);
        }
        Err(NetError::Dns(format!(
            "{name}: no DNSSEC-secure DNSKEY with key tag {key_tag}, \
             which is the key the answer was signed by"
        )))
    }

    /// One validated lookup over the single transport.
    async fn lookup(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<hickory_resolver::proto::op::DnsResponse, NetError> {
        use futures_core::Stream;
        use hickory_resolver::{net::xfer::DnsHandle, proto::op::Query};

        let mut qname = Name::from_utf8(name).map_err(|e| NetError::Dns(format!("{name}: {e}")))?;
        qname.set_fqdn(true);
        let query = Query::query(qname, record_type);
        let mut stream = self.handle.lookup(query, Default::default());
        std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx))
            .await
            .ok_or_else(|| NetError::Dns(format!("{name}: the endpoint sent no response")))?
            .map_err(|e| NetError::Dns(format!("{name}: {e}")))
    }
}

/// Lifts a verification failure into the error class `synch doctor` explains.
fn rekor_error(name: &str, error: ProofError) -> NetError {
    let name = name.to_string();
    match error {
        ProofError::Malformed(reason) => NetError::RekorMalformed { name, reason },
        ProofError::Attribution(reason) => NetError::RekorAttribution { name, reason },
        ProofError::Binding(reason) => NetError::RekorBinding { name, reason },
        ProofError::Inclusion(reason) => NetError::RekorInclusion { name, reason },
        ProofError::Checkpoint(reason) => NetError::RekorCheckpoint { name, reason },
        ProofError::UnknownLog(reason) => NetError::RekorUnknownLog { name, reason },
        ProofError::Chain(reason) => NetError::RekorChain { name, reason },
    }
}

/// Lifts a TUF failure into the error class `synch doctor` explains, naming
/// the repository it was walking.
///
/// None of these ever reaches a caller of [`DnssecResolver::member_set`]:
/// §10.2 is explicit that TUF trouble is never worse than not having asked.
/// They exist so the refresh can say which way it broke.
fn tuf_error(source: &TufSource, error: TufError) -> NetError {
    NetError::Tuf {
        repository: match source {
            TufSource::Url(url) => url.clone(),
            TufSource::Repo(_) => "the supplied TUF repository".to_string(),
        },
        class: error.class(),
        reason: error.to_string(),
    }
}

/// A pin state's versions: the root, then each role below it.
fn versions(state: &PinState) -> [u64; 4] {
    [
        state.root_version,
        state.timestamp_version,
        state.snapshot_version,
        state.targets_version,
    ]
}

/// Whether `a` is at least as far along as `b` in **every** role.
///
/// The four versions are independently-monotone counters, so "further along"
/// is componentwise dominance and not the lexicographic order a tuple
/// comparison gives. Comparing tuples let the root version dominate the
/// other three outright: a state ahead on `root` but behind on
/// timestamp/snapshot/targets read as newer, and adopting it dropped the
/// rollback floors for those roles to the lower numbers — which is the whole
/// thing the floors exist to prevent.
///
/// When neither state dominates the other they are not comparable, and the
/// answer is to keep what is in memory rather than to pick by a tie-break
/// that means nothing.
fn dominates(a: &PinState, b: &PinState) -> bool {
    versions(a)
        .iter()
        .zip(versions(b).iter())
        .all(|(a, b)| a >= b)
}

/// Seconds since the epoch, for the expiry checks every TUF role carries,
/// floored by the last state this client accepted.
///
/// Two things it must not do, and used to do both.
///
/// A clock this code cannot read used to become `0`. Every expiry check is
/// `expires > now`, so at zero *nothing has ever expired* — root, timestamp,
/// snapshot and targets all pass. That is the wrong direction: expiry is the
/// only bound on how old the metadata a mirror serves may be, so a clock
/// failure removed the bound entirely. It now yields `None`, and a refresh
/// with no trustworthy clock does not run.
///
/// And a clock that has been moved *backwards* — a bad NTP step, a dead RTC
/// coming up at the epoch — would reopen the same window. `updated_at` is
/// already persisted with every accepted state and was read back and never
/// used; it is exactly the monotonic floor for this, so it is the floor now.
fn now_unix(floor: u64) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(now.max(floor))
}

/// How long one file of a TUF walk may take.
const TUF_TIMEOUT: Duration = Duration::from_secs(30);

/// The most a single TUF file may be.
///
/// Sigstore's `targets.json` is the big one at a few hundred KiB. The cap is
/// here for the same reason the DoH body has one: these are bytes from a
/// party nothing is trusted about, and a response with no bound is a reader
/// that can be exhausted rather than a file that can be parsed.
const MAX_TUF_BYTES: usize = 8 * 1024 * 1024;

/// Sigstore's TUF repository, read over HTTPS.
///
/// Built and used entirely inside [`tokio::task::spawn_blocking`], which is
/// what makes a blocking client the right one: the walk is sequential by
/// nature — each file names the next — so there is no concurrency to give
/// up, and running it off the reactor keeps a few hundred KB of JSON parsing
/// away from the tasks doing the actual syncing.
///
/// TLS here is not load-bearing. Every byte fetched is self-authenticating
/// and is checked against [`tuf::EMBEDDED_TUF_ROOT`] before it moves
/// anything, so a hostile mirror can deny this walk and cannot make it mean
/// anything (§10.2).
struct HttpRepo {
    base: String,
    client: reqwest::blocking::Client,
}

impl HttpRepo {
    fn new(base: &str) -> Result<HttpRepo, String> {
        Ok(HttpRepo {
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::blocking::Client::builder()
                .timeout(TUF_TIMEOUT)
                .build()
                .map_err(|e| format!("TUF client: {e}"))?,
        })
    }
}

impl Repo for HttpRepo {
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let url = format!("{}/{path}", self.base);
        let response = self
            .client
            .get(&url)
            .send()
            .map_err(|e| format!("{url}: {e}"))?;
        match response.status().as_u16() {
            200 => {
                let body = response.bytes().map_err(|e| format!("{url}: {e}"))?;
                if body.len() > MAX_TUF_BYTES {
                    return Err(format!(
                        "{url}: {} bytes, over the {MAX_TUF_BYTES}-byte cap",
                        body.len()
                    ));
                }
                Ok(Some(body.to_vec()))
            }
            // The end of the root chain is a 404, and Sigstore's CDN answers
            // 403 for an object that is not there.
            403 | 404 => Ok(None),
            status => Err(format!("{url}: the repository answered {status}")),
        }
    }
}

/// How long one plaintext DoH exchange may take end to end.
/// How long one DoH exchange may take end to end.
const DOH_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of a DoH response body we will buffer.
///
/// A DNS message is length-prefixed by 16 bits, so 65535 bytes is the whole
/// of any legitimate answer — the ~3 KB proof record and everything smaller
/// sit well inside it. The transport is untrusted and may
/// be plaintext, so an endpoint that streams a body without end is a
/// memory-exhaustion lever; we read up to this bound and refuse the rest
/// rather than buffer whatever arrives. Denial, which http already concedes,
/// never escalates to unbounded allocation.
const MAX_DOH_RESPONSE: usize = 64 * 1024;

/// An RFC 8484 DNS-over-HTTP(S) client.
///
/// This is the only transport: queries are POSTed in wire format over
/// reqwest, and every response goes through the [`DnssecDnsHandle`] wrapped
/// around this — hickory reduced to the one thing we keep it for, in-process
/// DNSSEC validation. The endpoint hostname (if it is not a literal like the
/// default 1.1.1.1) resolves through the operating system once per
/// connection, which is name-to-address plumbing for the endpoint itself,
/// not part of the membership trust path.
#[derive(Clone)]
struct DohHandle {
    client: reqwest::Client,
    url: reqwest::Url,
}

impl DohHandle {
    fn new(url: reqwest::Url) -> Result<Self, NetError> {
        // Proxies from the environment (HTTP_PROXY/HTTPS_PROXY/NO_PROXY) are
        // honored, as reqwest does by default: on networks where a proxy is
        // the only road out, refusing it would strand exactly the deployments
        // DoH exists for. An operator whose proxy name cannot be resolved
        // locally names it by address, the same as any other proxied client.
        let client = reqwest::Client::builder()
            .timeout(DOH_TIMEOUT)
            .build()
            .map_err(|e| NetError::Dns(format!("DoH client: {e}")))?;
        Ok(DohHandle { client, url })
    }

    /// POSTs one wire-format query, returning the wire-format answer.
    async fn exchange(&self, body: Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
        let response = self
            .client
            .post(self.url.clone())
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(body)
            .send()
            .await
            .map_err(|e| std::io::Error::other(format!("{}: {e}", self.url)))?;
        if !response.status().is_success() {
            return Err(std::io::Error::other(format!(
                "{} answered {}",
                self.url,
                response.status()
            )));
        }
        // A `Content-Length` past the cap is refused before a byte is read;
        // but the header is a hint an attacker can omit or lie about, so the
        // streaming loop below is the real bound — it stops buffering the
        // instant the body crosses the cap, whatever the header claimed.
        if response
            .content_length()
            .is_some_and(|n| n > MAX_DOH_RESPONSE as u64)
        {
            return Err(std::io::Error::other(format!(
                "{}: response exceeds the {MAX_DOH_RESPONSE}-byte DoH ceiling",
                self.url
            )));
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| std::io::Error::other(format!("{}: {e}", self.url)))?
        {
            if bytes.len() + chunk.len() > MAX_DOH_RESPONSE {
                return Err(std::io::Error::other(format!(
                    "{}: response exceeds the {MAX_DOH_RESPONSE}-byte DoH ceiling",
                    self.url
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

/// What one DoH exchange resolves to.
type ExchangeResult =
    Result<hickory_resolver::proto::op::DnsResponse, hickory_resolver::net::NetError>;

/// A one-shot response stream, which is all one HTTP exchange produces.
struct OnceResponse {
    future: Option<Pin<Box<dyn Future<Output = ExchangeResult> + Send>>>,
}

impl futures_core::Stream for OnceResponse {
    type Item = Result<hickory_resolver::proto::op::DnsResponse, hickory_resolver::net::NetError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.future.as_mut() {
            None => std::task::Poll::Ready(None),
            Some(future) => match future.as_mut().poll(cx) {
                std::task::Poll::Pending => std::task::Poll::Pending,
                std::task::Poll::Ready(result) => {
                    self.future = None;
                    std::task::Poll::Ready(Some(result))
                }
            },
        }
    }
}

impl hickory_resolver::net::xfer::DnsHandle for DohHandle {
    type Response = OnceResponse;
    type Runtime = hickory_resolver::net::runtime::TokioRuntimeProvider;

    fn send(&self, request: hickory_resolver::proto::op::DnsRequest) -> Self::Response {
        let handle = self.clone();
        OnceResponse {
            future: Some(Box::pin(async move {
                let body = request
                    .to_vec()
                    .map_err(hickory_resolver::net::NetError::from)?;
                let answer = handle
                    .exchange(body)
                    .await
                    .map_err(hickory_resolver::net::NetError::from)?;
                hickory_resolver::proto::op::DnsResponse::from_buffer(answer)
                    .map_err(hickory_resolver::net::NetError::from)
            })),
        }
    }
}

/// Applies the fail-closed §3.2 record checks to one answer set.
///
/// Shared by both backends so the acceptance rule cannot drift between
/// transports: every record must carry a *secure* proof, and one unvalidated
/// record poisons the whole answer.
fn secure_txt(
    name: &str,
    answers: &[hickory_resolver::proto::rr::Record],
) -> Result<ValidatedTxt, NetError> {
    use hickory_resolver::proto::{
        dnssec::rdata::DNSSECRData,
        rr::{RData, RecordType},
    };

    let mut qname = hickory_resolver::proto::rr::Name::from_utf8(name)
        .map_err(|e| NetError::Dns(format!("{name}: {e}")))?;
    qname.set_fqdn(true);

    // Step one, and it has to be first: *who* signed this. hickory marks
    // exactly one RRSIG per RRset as the one it verified under (the rest come
    // back `Indeterminate`), so there is at most one candidate here and an
    // attacker cannot steer the choice by stapling extra signatures.
    let signed_by = answers.iter().find_map(|record| {
        if record.name != qname || !record.proof.is_secure() {
            return None;
        }
        let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
            return None;
        };
        (rrsig.input().type_covered == RecordType::TXT).then(|| rrsig.input().clone())
    });
    let Some(sig) = signed_by else {
        return Err(NetError::Dns(format!(
            "{name}: the validated answer carries no RRSIG naming its signer"
        )));
    };
    let signer = sig.signer_name.to_lowercase();

    // **The check hickory does not make.** RFC 4035 §5.3.1: "The RRSIG RR's
    // Signer's Name field MUST be the name of the zone that contains the
    // RRset." hickory 0.26 skips it in two places, both marked TODO — in
    // `RrsigValidity::check` the rule is quoted verbatim and then not
    // implemented, and `verify_default_rrset` fires a DNSKEY lookup at
    // whatever signer name the answer carried. So `Proof::Secure` means only
    // "some key, at some name the answer chose, signed this" — and an
    // attacker holding *any* DNSSEC-signed zone can sign an RRset owned by
    // somebody else's name and have it validate.
    //
    // Owner-name filtering does not close it: the forged RRset is owned by
    // the queried name, which is the whole point of the forgery. The signer
    // has to enclose the name it signed for, and that is what this asserts.
    //
    // Enforced here rather than in a caller so no lookup path can be reached
    // without it — the membership answer, the proof records, the DNSKEY, and
    // the public `lookup_txt` all come through this one function.
    if !signer.zone_of(&qname) {
        return Err(NetError::Dns(format!(
            "{name}: the answer is signed by {signer}, which does not contain \
             the name it answers for — a zone may only sign for names it holds \
             (RFC 4035 §5.3.1)"
        )));
    }

    let mut records = Vec::new();
    let mut ttl = MAX_TTL;
    for record in answers {
        // DNSSEC proves an RRset is signed by a zone chaining to the trust
        // anchor — it does not bind the answer to the question. A response
        // shaped by the (untrusted) DoH transport could carry a validly
        // signed TXT from an attacker-controlled zone; accepting it would
        // bind attacker keys into the member set. Only records owned by the
        // queried name count.
        if record.name != qname {
            continue;
        }
        // Only the records this answer is *made of* have to carry a proof.
        // Co-resident records of other types do not, and RRSIGs especially
        // do not: hickory marks only the signature it verified under and
        // returns every other one `Indeterminate`. Demanding a proof on
        // those refused every answer during an RFC 6781 double-signature key
        // rollover — which several managed providers run continuously — and
        // handed anyone who could *add* a record to a response a one-packet
        // denial of service.
        if !matches!(record.data, RData::TXT(_)) {
            continue;
        }
        if !record.proof.is_secure() {
            // Fail closed: one unvalidated record poisons the answer.
            return Err(NetError::Dns(format!(
                "{name}: answer is not DNSSEC-secure (proof: {:?})",
                record.proof
            )));
        }
        ttl = ttl.min(Duration::from_secs(u64::from(record.ttl)));
        let RData::TXT(txt) = &record.data else {
            unreachable!("filtered to TXT above")
        };
        // A TXT record is a sequence of character-strings; the record
        // text is their concatenation.
        let joined: String = txt
            .txt_data
            .iter()
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect();
        records.push(joined);
    }
    if records.is_empty() {
        return Err(NetError::Dns(format!("{name}: no TXT records")));
    }
    Ok(ValidatedTxt {
        records,
        ttl: clamp_ttl(ttl),
        signer,
        key_tag: sig.key_tag,
    })
}

/// A future returning one domain's validated member set.
pub type MemberSetFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(MemberSet, Duration), NetError>> + Send + 'a>>;

/// What a membership refresh resolves through (§3.2).
///
/// [`DnssecResolver`] is the production implementation and the only one a
/// running node uses. The trait exists so that the daemon's TTL-driven refresh
/// loop — the thing that keeps a DNSSEC cluster from dissolving one TTL after
/// the last `synch domain refresh` — can be driven and asserted on without a
/// live, signed zone.
///
/// Boxed rather than `async fn` in trait so the refresh loop can hold a
/// `&dyn MemberResolver` and stay object-safe.
pub trait MemberResolver: std::fmt::Debug + Send + Sync {
    /// Resolves one domain's member set and how long the answer is good for.
    fn resolve_members<'a>(&'a self, domain: &'a str) -> MemberSetFuture<'a>;
}

impl MemberResolver for DnssecResolver {
    fn resolve_members<'a>(&'a self, domain: &'a str) -> MemberSetFuture<'a> {
        Box::pin(self.member_set(domain))
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    fn key() -> NodeId {
        SecretKey::generate().public()
    }

    #[test]
    fn doh_urls_normalize() {
        let simple = doh_url("https://1.1.1.1").unwrap();
        assert_eq!(simple.as_str(), "https://1.1.1.1/dns-query");
        // Explicit ports, paths, schemes, and IPv6 hosts survive verbatim.
        assert_eq!(
            doh_url("http://10.0.0.53:8053/resolve").unwrap().as_str(),
            "http://10.0.0.53:8053/resolve"
        );
        assert_eq!(
            doh_url("http://[::1]:8053").unwrap().as_str(),
            "http://[::1]:8053/dns-query"
        );
        assert_eq!(
            doh_url("https://dns.internal.example/dns-query")
                .unwrap()
                .as_str(),
            "https://dns.internal.example/dns-query"
        );
        let err = doh_url("ftp://1.1.1.1/dns-query").unwrap_err();
        assert!(err.to_string().contains("https:// or http://"), "{err}");
        assert!(doh_url("not a url").is_err());
    }

    #[tokio::test]
    async fn resolver_options_build_and_fail_closed() {
        // The default, an https endpoint, and a plaintext http endpoint all
        // build without touching the network.
        DnssecResolver::with_defaults().unwrap();
        for url in [
            "https://127.0.0.1:8053/dns-query",
            "http://127.0.0.1:8053/dns-query",
        ] {
            DnssecResolver::with_options(&ResolverOptions {
                doh_url: Some(url.into()),
                trust_anchor: None,
                rekor: None,
                rekor_key: None,
                rekor_state: None,
                tuf_url: None,
                no_tuf: true,
                tuf_root: None,
            })
            .unwrap();
        }

        // A missing or empty trust anchor is refused by name: an anchor set
        // with no keys would validate nothing, forever, quietly.
        let err = DnssecResolver::with_options(&ResolverOptions {
            doh_url: None,
            trust_anchor: Some("/does/not/exist.key".into()),
            rekor: None,
            rekor_key: None,
            rekor_state: None,
            tuf_url: None,
            no_tuf: true,
            tuf_root: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("trust anchor"), "{err}");

        let empty = tempfile::NamedTempFile::new().unwrap();
        let err = DnssecResolver::with_options(&ResolverOptions {
            doh_url: None,
            trust_anchor: Some(empty.path().to_path_buf()),
            rekor: None,
            rekor_key: None,
            rekor_state: None,
            tuf_url: None,
            no_tuf: true,
            tuf_root: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("no DNSKEY records"), "{err}");

        // A syntactically valid DNSKEY record is accepted and replaces the
        // ICANN root: building proves the whole path parses and loads.
        let anchor = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            anchor.path(),
            format!(". IN DNSKEY 257 3 13 {}==\n", "A".repeat(86)),
        )
        .unwrap();
        DnssecResolver::with_options(&ResolverOptions {
            doh_url: Some("http://127.0.0.1:8053/dns-query".into()),
            trust_anchor: Some(anchor.path().to_path_buf()),
            rekor: None,
            rekor_key: None,
            rekor_state: None,
            tuf_url: None,
            no_tuf: true,
            tuf_root: None,
        })
        .unwrap();
    }

    /// A live exchange against a plaintext endpoint, which must fail closed:
    /// the transport works — the query arrives, the canned answer returns —
    /// and the unsigned answer is refused by the in-process validator. This
    /// is the whole DoH-over-http security argument in one test.
    #[tokio::test]
    async fn a_plaintext_endpoint_serves_but_never_bypasses_validation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            // The validator may chase the chain with several queries; answer
            // each with an unsigned echo until the client gives up.
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let body = loop {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break None;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
                        let length: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        let have = raw.len() - split - 4;
                        if have >= length {
                            break Some(raw[split + 4..split + 4 + length].to_vec());
                        }
                    }
                };
                let Some(query) = body else { continue };
                // Echo the query back as a NOERROR answer with no records and
                // no signatures: syntactically a response, cryptographically
                // nothing.
                let message = hickory_resolver::proto::op::Message::from_vec(&query)
                    .unwrap()
                    .into_response();
                let reply = message.to_vec().unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n",
                    reply.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&reply).await;
            }
        });

        let resolver = DnssecResolver::with_options(&ResolverOptions {
            doh_url: Some(format!("http://127.0.0.1:{port}/dns-query")),
            trust_anchor: None,
            rekor: None,
            rekor_key: None,
            rekor_state: None,
            tuf_url: None,
            no_tuf: true,
            tuf_root: None,
        })
        .unwrap();
        let err = tokio::time::timeout(
            Duration::from_secs(30),
            resolver.lookup_txt("cluster.example"),
        )
        .await
        .expect("the lookup must finish, not hang")
        .expect_err("an unsigned answer must never validate");
        let text = err.to_string();
        assert!(
            !text.contains("connection refused"),
            "the transport itself must have worked: {text}"
        );
        server.abort();
    }

    fn record(id: Option<&str>, key: &NodeId) -> String {
        match id {
            Some(id) => format!("v=sync1 id={id} nk={}", key.to_z32()),
            None => format!("v=sync1 nk={}", key.to_z32()),
        }
    }

    #[test]
    fn parses_a_named_record() {
        let k = key();
        let parsed = parse_record(&record(Some("nas"), &k)).unwrap();
        assert_eq!(parsed.id.as_deref(), Some("nas"));
        assert_eq!(parsed.node_key, k);
        assert_eq!(
            parsed.origin("cluster.example.com").unwrap(),
            OriginId::named("nas", "cluster.example.com").unwrap()
        );
    }

    #[test]
    fn an_idless_record_binds_the_key_itself() {
        // §3.2: accepted for backward simplicity; binds OriginId::Key(nk),
        // non-rotatable, as if statically trusted.
        let k = key();
        let parsed = parse_record(&record(None, &k)).unwrap();
        assert_eq!(parsed.id, None);
        assert_eq!(parsed.origin("x.example").unwrap(), OriginId::Key(k));
    }

    #[test]
    fn parses_dialing_hints() {
        let k = key();
        let text = format!(
            "v=sync1 id=nas nk={} relay=https://relay.example addr=10.0.0.1:4433",
            k.to_z32()
        );
        let parsed = parse_record(&text).unwrap();
        assert_eq!(parsed.relay.as_deref(), Some("https://relay.example"));
        assert_eq!(parsed.addr.as_deref(), Some("10.0.0.1:4433"));
    }

    #[test]
    fn ignores_unknown_fields() {
        let k = key();
        let text = format!("v=sync1 id=nas nk={} future=whatever", k.to_z32());
        assert!(parse_record(&text).is_ok());
    }

    #[test]
    fn rejects_malformed_records() {
        let k = key();
        assert_eq!(
            parse_record("v=sync2 id=nas nk=x").unwrap_err(),
            RecordError::NotSync1
        );
        assert_eq!(
            parse_record("id=nas nk=x").unwrap_err(),
            RecordError::NotSync1
        );
        assert_eq!(
            parse_record("v=sync1 id=nas").unwrap_err(),
            RecordError::MissingKey
        );
        assert!(matches!(
            parse_record("v=sync1 id=nas nk=notakey").unwrap_err(),
            RecordError::BadKey(_)
        ));
        assert!(matches!(
            parse_record(&format!("v=sync1 id=BAD_LABEL nk={}", k.to_z32())).unwrap_err(),
            RecordError::BadLabel(_)
        ));
        assert_eq!(
            parse_record(&format!("v=sync1 id=a id=b nk={}", k.to_z32())).unwrap_err(),
            RecordError::Duplicate("id")
        );
    }

    #[test]
    fn labels_are_case_insensitive() {
        let k = key();
        let parsed = parse_record(&format!("v=sync1 id=NAS nk={}", k.to_z32())).unwrap();
        assert_eq!(parsed.id.as_deref(), Some("nas"));
    }

    #[test]
    fn builds_a_member_set() {
        let nas = key();
        let laptop = key();
        let records = vec![record(Some("nas"), &nas), record(Some("laptop"), &laptop)];
        let set = MemberSet::from_records("Cluster.Example.COM.", &records).unwrap();
        assert_eq!(set.domain, "cluster.example.com");
        assert_eq!(set.bindings.len(), 2);
        assert_eq!(
            set.keys_for(&OriginId::named("nas", "cluster.example.com").unwrap()),
            vec![nas]
        );
        assert!(set.ambiguous_keys.is_empty());
        assert!(set.rejected.is_empty());
    }

    #[test]
    fn two_keys_under_one_id_are_a_rotation_window() {
        // §3.2: multiple records with the same id and different nk are valid
        // and mean all listed keys are simultaneously bound.
        let old = key();
        let new = key();
        let records = vec![record(Some("nas"), &old), record(Some("nas"), &new)];
        let set = MemberSet::from_records("x.example", &records).unwrap();
        let origin = OriginId::named("nas", "x.example").unwrap();
        let mut keys = set.keys_for(&origin);
        keys.sort_by_key(|k| *k.as_bytes());
        let mut expected = vec![old, new];
        expected.sort_by_key(|k| *k.as_bytes());
        assert_eq!(keys, expected);
        assert!(set.ambiguous_keys.is_empty());
        // Self-detection still works for each key: one identity each.
        assert_eq!(set.self_origin(&old), Some(origin.clone()));
        assert_eq!(set.self_origin(&new), Some(origin));
    }

    #[test]
    fn one_key_under_two_ids_is_ambiguous() {
        // §3.2 malformed-set rule: self-detection refuses to guess and the
        // bindings the key would create are dropped.
        let k = key();
        let other = key();
        let records = vec![
            record(Some("nas"), &k),
            record(Some("laptop"), &k),
            record(Some("vps"), &other),
        ];
        let set = MemberSet::from_records("x.example", &records).unwrap();
        assert_eq!(set.ambiguous_keys, vec![k]);
        assert_eq!(set.self_origin(&k), None);
        assert_eq!(set.bindings.len(), 1);
        assert_eq!(
            set.bindings[0].0,
            OriginId::named("vps", "x.example").unwrap()
        );
    }

    #[test]
    fn a_key_with_and_without_an_id_is_ambiguous() {
        let k = key();
        let records = vec![record(Some("nas"), &k), record(None, &k)];
        let set = MemberSet::from_records("x.example", &records).unwrap();
        assert_eq!(set.ambiguous_keys, vec![k]);
        assert!(set.bindings.is_empty());
        assert_eq!(set.self_origin(&k), None);
    }

    #[test]
    fn duplicate_identical_records_collapse() {
        let k = key();
        let records = vec![record(Some("nas"), &k), record(Some("nas"), &k)];
        let set = MemberSet::from_records("x.example", &records).unwrap();
        assert_eq!(set.bindings.len(), 1);
        assert!(set.ambiguous_keys.is_empty());
    }

    #[test]
    fn unparseable_records_are_reported_not_fatal() {
        let k = key();
        let records = vec![
            record(Some("nas"), &k),
            "v=spf1 include:example.com ~all".to_string(),
            "v=sync1 id=broken".to_string(),
        ];
        let set = MemberSet::from_records("x.example", &records).unwrap();
        assert_eq!(set.bindings.len(), 1);
        assert_eq!(set.rejected.len(), 2);
    }

    #[test]
    fn hints_are_collected_per_key() {
        let k = key();
        let records = vec![format!(
            "v=sync1 id=nas nk={} addr=10.0.0.1:4433",
            k.to_z32()
        )];
        let set = MemberSet::from_records("x.example", &records).unwrap();
        assert_eq!(set.hints_for(&k), &["10.0.0.1:4433".to_string()]);
        assert!(set.hints_for(&key()).is_empty());
    }

    #[test]
    fn self_origin_of_an_absent_key_is_none() {
        let set = MemberSet::from_records("x.example", &[record(Some("nas"), &key())]).unwrap();
        assert_eq!(set.self_origin(&key()), None);
    }

    #[test]
    fn ttls_are_clamped() {
        assert_eq!(clamp_ttl(Duration::from_secs(1)), MIN_TTL);
        assert_eq!(clamp_ttl(Duration::from_secs(999_999)), MAX_TTL);
        assert_eq!(
            clamp_ttl(Duration::from_secs(300)),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn query_names_are_prefixed() {
        assert_eq!(
            query_name("cluster.example.com"),
            "_synchronicity.cluster.example.com"
        );
    }

    #[test]
    fn an_empty_domain_yields_an_empty_set() {
        let set = MemberSet::from_records("x.example", &[]).unwrap();
        assert!(set.bindings.is_empty());
        // Fail-closed: an empty validated set is not an error here, but the
        // caller keeps existing bindings until they expire on their own.
        assert!(set.rejected.is_empty());
    }
}
