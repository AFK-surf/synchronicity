//! TUF-driven pin refresh: the offline half (docs/REKOR-ZONE-KEY.md §10).
//!
//! Sigstore rotates its tiled logs — a new shard, a new key, roughly yearly
//! — and eventually removes compromised keys from its trust root. A
//! build-time snapshot of the log keys turns each of those events into a
//! client upgrade. This module makes the pin set follow Sigstore's TUF
//! repository instead, without a new transport and without a new liveness
//! coupling: **the zone relays Sigstore's TUF metadata verbatim, and the
//! client verifies it here against an embedded TUF root.**
//!
//! The principle is the proof records': the zone may carry anything that
//! verifies against something the client pins. TUF metadata is
//! self-authenticating — every byte chains to the root role — so the zone
//! never becomes an authority over the pin set. It is a relay, and a
//! tampering relay produces material that fails verification and is ignored.
//!
//! # Wire format
//!
//! `TufBundle` v1, big-endian throughout, mirroring [`crate::rekor`]'s
//! conventions (strict decode, base64url in one TXT record, chunked into
//! ≤255-byte character-strings by the zone):
//!
//! ```text
//! u8       version        = 1
//! u8       root_count       root.json versions, ascending, so a client
//! u32+[]   root_json[..]    embedded at version N can chain to current
//! u32+[]   timestamp_json   all files verbatim, exactly as the TUF
//! u32+[]   snapshot_json    repository serves them — signatures cover
//! u32+[]   targets_json     these bytes
//! u32+[]   trusted_root     the target the chain authenticates
//! ```
//!
//! # The two rules that are load-bearing
//!
//! Both come straight from §10.2, and both are about availability, so
//! neither is a detail an implementation gets to soften:
//!
//! 1. **Expiry gates updates, never operation.** An absent, stale or invalid
//!    bundle is ignored and the current pins stand. To *change* pins the
//!    chain must be valid and unexpired; to keep working, nothing is
//!    required. No error out of this module ever fails a membership refresh.
//! 2. **Monotonicity bounds hostile relays.** A zone can serve old-but-valid
//!    material, but it cannot roll a client's persisted versions back, and a
//!    freeze holds only until the served timestamp expires.
//!
//! On acceptance the pin set becomes the tlogs of the new `trusted_root` —
//! **replacing** the previous set, never unioning with it, so a key Sigstore
//! removes is a key clients drop.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use ring::signature;

use crate::rekor::{base64_encode, sha256, LogKeys};

/// The only `TufBundle` version this build accepts.
pub const BUNDLE_VERSION: u8 = 1;

/// The label the TUF bundle lives under, one below the zone apex.
pub const TUF_TXT_PREFIX: &str = "_synchronicity-tuf";

/// The target the chain has to authenticate for any of this to matter.
pub const TRUSTED_ROOT_TARGET: &str = "trusted_root.json";

/// The `signed._type` each role must declare.
const ROOT_ROLE: &str = "root";
const TIMESTAMP_ROLE: &str = "timestamp";
const SNAPSHOT_ROLE: &str = "snapshot";
const TARGETS_ROLE: &str = "targets";

/// The metadata file names the chain walks through.
const SNAPSHOT_META: &str = "snapshot.json";
const TARGETS_META: &str = "targets.json";

/// The Sigstore TUF root role this build pins — the ultimate anchor of the
/// pin set, the same standing as the ICANN trust anchor (§10.2).
///
/// `root.json` version 15, `expires` 2026-11-20T13:58:18Z, fetched
/// 2026-08-16 from `https://tuf-repo-cdn.sigstore.dev/15.root.json`. Its own
/// five root-role signatures verify under both version 14's and its own root
/// role, which is the check [`update`] applies to every later root; nothing
/// here is trusted because it was fetched, only because it is the byte
/// sequence this build ships.
///
/// Replacing it is a build, deliberately: everything else about the pin set
/// now refreshes on its own, and a root-level incident is precisely the
/// event that should still cost an upgrade (§10.4).
pub const EMBEDDED_TUF_ROOT: &str = include_str!("sigstore_tuf_root.json");

/// The Sigstore `trusted_root.json` this build boots from — the **bootstrap**
/// pin set and log directory, not the last word.
///
/// The consistent-snapshot target `6494e21e…`, its SHA-256 checked against
/// the signed `targets.json`; fetched 2026-08-16 from
/// `tuf-repo-cdn.sigstore.dev`. It is the signed artifact itself rather than
/// keys copied out of it, so which logs exist, where they are served and
/// which of them is currently in service are all read from one place — here
/// until a bundle verifies, and from that bundle's trusted root afterwards.
/// Nothing about a Sigstore log rotation reaches this file: only a root-level
/// incident does, and that is [`EMBEDDED_TUF_ROOT`]'s business.
pub const EMBEDDED_TRUSTED_ROOT: &str = include_str!("sigstore_trusted_root.json");

/// Why a TUF update was refused.
///
/// The variants are the failure *classes* `synch doctor` explains. None of
/// them fails a membership refresh — every one of them means "keep the
/// current pins" (§10.2) — so they exist to be *reported*, not to propagate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TufError {
    /// The bundle could not be decoded, or a file in it is not the JSON
    /// shape TUF metadata has.
    #[error("malformed: {0}")]
    Malformed(String),
    /// The root chain does not connect: a gap in the versions, a role the
    /// root does not define, a file claiming the wrong role.
    #[error("chain: {0}")]
    Chain(String),
    /// Too few of a role's keys signed: the material is not endorsed by the
    /// quorum the root demands.
    #[error("threshold: {0}")]
    Threshold(String),
    /// A signature does not verify over the canonical JSON of what it
    /// covers, or the key it names cannot be parsed at all.
    #[error("signature: {0}")]
    Signature(String),
    /// A role's `expires` is in the past. Gates the *update*, never the
    /// pins already in force.
    #[error("expiry: {0}")]
    Expiry(String),
    /// A version is lower than the one already accepted — the freeze/rollback
    /// attack monotonicity exists to bound.
    #[error("rollback: {0}")]
    Rollback(String),
    /// A file does not hash to what the metadata above it says it does.
    #[error("target hash: {0}")]
    TargetHash(String),
}

impl TufError {
    /// The one-word class, for logs and `synch doctor` copy.
    pub fn class(&self) -> &'static str {
        match self {
            TufError::Malformed(_) => "malformed",
            TufError::Chain(_) => "chain",
            TufError::Threshold(_) => "threshold",
            TufError::Signature(_) => "signature",
            TufError::Expiry(_) => "expiry",
            TufError::Rollback(_) => "rollback",
            TufError::TargetHash(_) => "target-hash",
        }
    }
}

/// One decoded TUF bundle: the files, verbatim, in chain order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TufBundle {
    /// `root.json` at ascending versions, so a client embedded at version N
    /// can walk to the current one.
    pub roots: Vec<Vec<u8>>,
    /// `timestamp.json`, verbatim.
    pub timestamp: Vec<u8>,
    /// `snapshot.json`, verbatim.
    pub snapshot: Vec<u8>,
    /// `targets.json`, verbatim.
    pub targets: Vec<u8>,
    /// `trusted_root.json` — the target the chain authenticates.
    pub trusted_root: Vec<u8>,
}

impl TufBundle {
    /// Encodes the bundle in the v1 wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            2 + self.roots.iter().map(|r| r.len() + 4).sum::<usize>()
                + self.timestamp.len()
                + self.snapshot.len()
                + self.targets.len()
                + self.trusted_root.len()
                + 16,
        );
        out.push(BUNDLE_VERSION);
        // A chain that cannot be length-prefixed cannot be encoded; the
        // control plane never produces one, and truncating silently would
        // produce a bundle that fails verification much later.
        let roots = u8::try_from(self.roots.len()).unwrap_or(u8::MAX);
        out.push(roots);
        for blob in self.roots.iter().take(usize::from(roots)).chain([
            &self.timestamp,
            &self.snapshot,
            &self.targets,
            &self.trusted_root,
        ]) {
            let len = u32::try_from(blob.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&blob[..len as usize]);
        }
        out
    }

    /// Decodes a v1 bundle, refusing anything with bytes left over — a
    /// record that decodes two ways is a record an attacker can steer.
    pub fn decode(bytes: &[u8]) -> Result<TufBundle, TufError> {
        let mut reader = Reader::new(bytes);
        let version = reader.u8("version")?;
        if version != BUNDLE_VERSION {
            return Err(TufError::Malformed(format!(
                "version {version} is not {BUNDLE_VERSION}"
            )));
        }
        let root_count = reader.u8("root count")?;
        if root_count == 0 {
            return Err(TufError::Malformed(
                "the bundle carries no root.json".into(),
            ));
        }
        let mut roots = Vec::with_capacity(usize::from(root_count));
        for _ in 0..root_count {
            roots.push(reader.blob32("root.json")?.to_vec());
        }
        let timestamp = reader.blob32("timestamp.json")?.to_vec();
        let snapshot = reader.blob32("snapshot.json")?.to_vec();
        let targets = reader.blob32("targets.json")?.to_vec();
        let trusted_root = reader.blob32("trusted_root.json")?.to_vec();
        reader.finish()?;
        Ok(TufBundle {
            roots,
            timestamp,
            snapshot,
            targets,
            trusted_root,
        })
    }

    /// Decodes one TXT record: base64url, with or without padding. The
    /// character-strings are concatenated before this is called — the split
    /// into ≤255-byte chunks is DNS packaging, not content.
    pub fn from_txt(text: &str) -> Result<TufBundle, TufError> {
        TufBundle::decode(&base64url_decode(text)?)
    }

    /// Renders the bundle as one base64url TXT payload.
    pub fn to_txt(&self) -> String {
        base64url_encode(&self.encode())
    }
}

/// The pin set a client is running on, and where it came from (§10.2).
///
/// Persisted as one file, global across domains: `<data-dir>/rekor-pins.json`
/// at mode 0600. Global is the point — a hostile zone must not be able to
/// roll one client's versions back by being asked about a different domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinState {
    /// The accepted `root.json`, verbatim — the next update chains from it.
    pub root: Vec<u8>,
    /// Its version.
    pub root_version: u64,
    /// The accepted `timestamp.json` version.
    pub timestamp_version: u64,
    /// The accepted `snapshot.json` version.
    pub snapshot_version: u64,
    /// The accepted `targets.json` version.
    pub targets_version: u64,
    /// The accepted `trusted_root.json`, verbatim — the pin set is derived
    /// from it rather than stored beside it, so the two cannot disagree.
    pub trusted_root: Vec<u8>,
    /// When this state was written, seconds since the epoch.
    pub updated_at: u64,
}

impl PinState {
    /// The state a build starts from: the embedded root, nothing accepted.
    ///
    /// `trusted_root` is empty here — a client that has never completed an
    /// update runs on [`EMBEDDED_TRUSTED_ROOT`], the bootstrap snapshot,
    /// exactly as it did before this module existed.
    pub fn embedded() -> PinState {
        PinState {
            root: EMBEDDED_TUF_ROOT.as_bytes().to_vec(),
            root_version: root_version(EMBEDDED_TUF_ROOT.as_bytes()).unwrap_or(0),
            timestamp_version: 0,
            snapshot_version: 0,
            targets_version: 0,
            trusted_root: Vec::new(),
            updated_at: 0,
        }
    }

    /// The pin set this state implies (§10.2's resolution order, second
    /// step): the tlogs of the accepted trusted root, or `None` when no
    /// update has ever been accepted and the bootstrap set stands.
    pub fn log_keys(&self) -> Option<LogKeys> {
        match self.trusted_root.is_empty() {
            true => None,
            false => tlog_keys(&self.trusted_root).ok(),
        }
    }

    /// The trusted root in force: the accepted one, or the embedded
    /// bootstrap snapshot when no update has ever been accepted.
    pub fn trusted_root_in_force(&self) -> &[u8] {
        match self.trusted_root.is_empty() {
            true => EMBEDDED_TRUSTED_ROOT.as_bytes(),
            false => &self.trusted_root,
        }
    }

    /// The transparency logs it names — where they are, not only their keys.
    ///
    /// This is what makes the endpoint follow Sigstore too: a reader asks
    /// its pin state which log to read rather than carrying a hostname a
    /// rotation will invalidate.
    pub fn tlogs(&self) -> Result<Vec<Tlog>, TufError> {
        tlogs(self.trusted_root_in_force())
    }

    /// Reads persisted state, returning `None` when the file is absent or
    /// unreadable as state.
    ///
    /// Unreadable is not an error worth failing on: the pin set falls back
    /// to the bootstrap snapshot and the next valid bundle rewrites the
    /// file. A client that refused to start over a corrupt cache would be
    /// exactly the availability coupling §10.2 forbids.
    pub fn load(path: &Path) -> Option<PinState> {
        let text = std::fs::read_to_string(path).ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        if value["version"].as_u64() != Some(1) {
            return None;
        }
        let blob = |key: &str| -> Option<Vec<u8>> { base64_decode(value[key].as_str()?).ok() };
        let number = |key: &str| value[key].as_u64();
        let state = PinState {
            root: blob("root")?,
            root_version: number("root_version")?,
            timestamp_version: number("timestamp_version")?,
            snapshot_version: number("snapshot_version")?,
            targets_version: number("targets_version")?,
            trusted_root: blob("trusted_root")?,
            updated_at: number("updated_at").unwrap_or(0),
        };
        // A stored root that does not parse, or whose recorded version is
        // not the one in its bytes, is not state we can chain from.
        match root_version(&state.root) == Some(state.root_version) {
            true => Some(state),
            false => None,
        }
    }

    /// Writes the state at mode 0600, replacing whatever was there.
    ///
    /// The pin set is not a secret, but the data directory is the owner's
    /// alone (§9.3) and a file another user can rewrite is a pin set another
    /// user chooses.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let text = serde_json::json!({
            "version": 1,
            "root": base64_encode(&self.root),
            "root_version": self.root_version,
            "timestamp_version": self.timestamp_version,
            "snapshot_version": self.snapshot_version,
            "targets_version": self.targets_version,
            "trusted_root": base64_encode(&self.trusted_root),
            "updated_at": self.updated_at,
        })
        .to_string();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, text)?;
        restrict(path)
    }
}

/// Narrows a file to its owner. On platforms without POSIX modes the
/// directory's own ACL is what protects it, as everywhere else in the tree.
#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// What an accepted update established, for logs and `synch doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TufUpdate {
    /// The state to persist and run on.
    pub state: PinState,
    /// The pin set the new trusted root names — replacing, never unioning.
    pub log_keys: LogKeys,
    /// Whether anything actually moved. A bundle that re-states what is
    /// already accepted is valid and boring; saying so keeps the logs quiet.
    pub changed: bool,
}

/// Verifies a bundle and, if it is newer, returns the state to adopt (§10.2).
///
/// `now` is seconds since the epoch — supplied rather than read so a
/// conformance fixture can be verified at the moment it was fetched, which
/// is the only way checked-in real metadata stays checkable.
///
/// The order is TUF's own: chain the roots, then timestamp → snapshot →
/// targets → the target itself, each step endorsed by the role the *current*
/// root names and bounded by the version the state already accepted.
pub fn update(bundle: &TufBundle, state: &PinState, now: u64) -> Result<TufUpdate, TufError> {
    let mut trusted = Root::parse(&state.root)?;

    // 1. Walk the root chain. Each step must be signed by the thresholds of
    //    *both* the old root and the new one: the old root says who may
    //    succeed it, the new one proves it holds the keys it claims.
    for bytes in &bundle.roots {
        let candidate = Root::parse(bytes)?;
        if candidate.version <= trusted.version {
            // Material for a root this client already passed. Old-but-valid
            // is allowed to travel; it just does not move anything.
            continue;
        }
        if candidate.version != trusted.version + 1 {
            return Err(TufError::Chain(format!(
                "root {} follows root {}, and nothing bridges them",
                candidate.version, trusted.version
            )));
        }
        trusted.check_role(ROOT_ROLE, &candidate.meta)?;
        candidate.check_role(ROOT_ROLE, &candidate.meta)?;
        trusted = candidate;
    }
    if trusted.version < state.root_version {
        return Err(TufError::Rollback(format!(
            "root {} is older than the accepted root {}",
            trusted.version, state.root_version
        )));
    }
    // Only the *final* root's expiry is checked (TUF client workflow
    // §5.3.11). Intermediates in a chain are expected to be expired — the
    // real Sigstore chain has been, every time a rotation ran late.
    trusted.check_expiry(now)?;

    // 2. timestamp → snapshot → targets, each signed by the role the
    //    current root names, each no older than what is already accepted.
    let timestamp = Meta::parse(&bundle.timestamp, TIMESTAMP_ROLE)?;
    trusted.check_role(TIMESTAMP_ROLE, &timestamp)?;
    timestamp.check_expiry(now)?;
    timestamp.check_rollback(state.timestamp_version)?;

    let snapshot = Meta::parse(&bundle.snapshot, SNAPSHOT_ROLE)?;
    timestamp.check_listed(SNAPSHOT_META, &bundle.snapshot, snapshot.version)?;
    trusted.check_role(SNAPSHOT_ROLE, &snapshot)?;
    snapshot.check_expiry(now)?;
    snapshot.check_rollback(state.snapshot_version)?;

    let targets = Meta::parse(&bundle.targets, TARGETS_ROLE)?;
    snapshot.check_listed(TARGETS_META, &bundle.targets, targets.version)?;
    trusted.check_role(TARGETS_ROLE, &targets)?;
    targets.check_expiry(now)?;
    targets.check_rollback(state.targets_version)?;

    // 3. The target the whole chain exists to authenticate.
    targets.check_target(TRUSTED_ROOT_TARGET, &bundle.trusted_root)?;
    let log_keys = tlog_keys(&bundle.trusted_root)?;

    let changed = trusted.version != state.root_version
        || timestamp.version != state.timestamp_version
        || snapshot.version != state.snapshot_version
        || targets.version != state.targets_version
        || bundle.trusted_root != state.trusted_root;

    Ok(TufUpdate {
        state: PinState {
            root: trusted.bytes,
            root_version: trusted.version,
            timestamp_version: timestamp.version,
            snapshot_version: snapshot.version,
            targets_version: targets.version,
            trusted_root: bundle.trusted_root.clone(),
            updated_at: now,
        },
        log_keys,
        changed,
    })
}

/// One transparency log a Sigstore trusted root names: where it is, the key
/// its checkpoints are signed with, and the window it was in service for.
///
/// The `baseUrl` matters as much as the key. A build that pins keys but
/// hardcodes an endpoint has only moved the rotation problem: the log to
/// *read* — and, for the control plane, to *write* — is named by the same
/// signed artifact that names the key, so both follow Sigstore together or
/// neither does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlog {
    /// Where the log is served, no trailing slash.
    pub base_url: String,
    /// The DER SubjectPublicKeyInfo of its verification key.
    pub spki: Vec<u8>,
    /// SHA-256 of that SPKI — what a proof's `log_id` names (and *not* the
    /// `logId.keyId` the trusted root carries beside it, which is the C2SP
    /// note key id; see [`crate::rekor::LogKeys`]).
    pub log_id: [u8; 32],
    /// `validFor.start`, seconds since the epoch. Absent means "always".
    pub valid_from: i64,
    /// `validFor.end`, if the log has been retired.
    pub valid_until: Option<i64>,
}

impl Tlog {
    /// Whether this log was in service at `now`.
    pub fn valid_at(&self, now: u64) -> bool {
        let now = now as i64;
        self.valid_from <= now && self.valid_until.is_none_or(|end| now < end)
    }
}

/// The transparency logs a Sigstore trusted root names, in the order it
/// lists them.
///
/// Only `tlogs` — the entries this design pins. Each `publicKey.rawBytes` is
/// a DER SubjectPublicKeyInfo, which is exactly what [`LogKeys`] parses and
/// what a proof's `log_id` is SHA-256 over.
pub fn tlogs(trusted_root: &[u8]) -> Result<Vec<Tlog>, TufError> {
    let bad = |why: String| TufError::Malformed(format!("trusted root: {why}"));
    let value: serde_json::Value =
        serde_json::from_slice(trusted_root).map_err(|e| bad(e.to_string()))?;
    let entries = value["tlogs"]
        .as_array()
        .ok_or_else(|| bad("tlogs is not an array".into()))?;
    let mut logs = Vec::with_capacity(entries.len());
    for tlog in entries {
        let raw = tlog["publicKey"]["rawBytes"]
            .as_str()
            .ok_or_else(|| bad("a tlog has no publicKey.rawBytes".into()))?;
        let spki = base64_decode(raw).map_err(|_| bad("a tlog key is not base64".into()))?;
        let base_url = tlog["baseUrl"]
            .as_str()
            .ok_or_else(|| bad("a tlog has no baseUrl".into()))?;
        // A window that will not parse is not a reason to drop the log —
        // its key is still pinned — but it must not read as *currently*
        // valid, so an unparseable start is treated as "not yet".
        let when = &tlog["publicKey"]["validFor"];
        let valid_from = match when.get("start") {
            None => 0,
            Some(start) => start
                .as_str()
                .and_then(parse_rfc3339)
                .ok_or_else(|| bad("a tlog's validFor.start is not RFC 3339".into()))?,
        };
        let valid_until = match when.get("end") {
            None => None,
            Some(end) => Some(
                end.as_str()
                    .and_then(parse_rfc3339)
                    .ok_or_else(|| bad("a tlog's validFor.end is not RFC 3339".into()))?,
            ),
        };
        logs.push(Tlog {
            base_url: base_url.trim_end_matches('/').to_string(),
            log_id: sha256(&spki),
            spki,
            valid_from,
            valid_until,
        });
    }
    if logs.is_empty() {
        // Adopting an empty pin set would silently refuse every zone from
        // then on. §10.2's whole posture is that TUF trouble is never worse
        // than not having the record, so this is trouble, not an update.
        return Err(bad("it names no transparency logs".into()));
    }
    Ok(logs)
}

/// The log in service at `now`, the one a submission goes to and a monitor
/// reads — the latest-started of those whose window contains `now`.
///
/// Sigstore's trusted root keeps retired shards listed so old proofs stay
/// checkable, so "the current log" is a question about windows and not about
/// list order. `None` when every listed log is retired or not yet open,
/// which is a trusted root this build cannot use for anything live.
pub fn current_tlog(logs: &[Tlog], now: u64) -> Option<&Tlog> {
    logs.iter()
        .filter(|log| log.valid_at(now))
        .max_by_key(|log| log.valid_from)
}

/// The transparency-log keys a Sigstore trusted root names — every log it
/// lists, retired ones included, because a proof from a retired shard is
/// still a proof.
pub fn tlog_keys(trusted_root: &[u8]) -> Result<LogKeys, TufError> {
    let bad = |why: String| TufError::Malformed(format!("trusted root: {why}"));
    let mut lines = String::new();
    for log in tlogs(trusted_root)? {
        lines.push_str(&base64_encode(&log.spki));
        lines.push('\n');
    }
    LogKeys::parse(&lines).map_err(|e| bad(e.to_string()))
}

/// The version of a `root.json`, without verifying anything about it.
fn root_version(bytes: &[u8]) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value["signed"]["version"].as_u64()
}

// ------------------------------------------------------------- fetching

/// The default Sigstore TUF repository, the one `EMBEDDED_TUF_ROOT` anchors.
pub const SIGSTORE_TUF_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

/// How many root versions past the one already trusted [`fetch_bundle`] will
/// probe before giving up. Sigstore rotates roughly yearly; this is decades
/// of headroom and a bound on a repository that answers 200 to everything.
const ROOT_CEILING: u64 = 200;

/// A TUF repository, as the one operation walking it needs.
///
/// Injected rather than hardwired, exactly as the control plane's relay does
/// it: everything [`fetch_bundle`] decides is then testable without egress,
/// and a caller brings whichever HTTP client it already has (the client's is
/// async, the monitor's blocking).
///
/// `Ok(None)` is a file the repository does not have — the end of the root
/// chain is precisely that answer — and `Err` a repository that could not be
/// reached at all. The two are different facts: one ends a walk, the other
/// abandons it.
#[allow(missing_debug_implementations)]
pub trait Repo {
    /// Fetches one path relative to the repository root.
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String>;
}

/// Walks a TUF repository into a bundle, starting the root chain at
/// `from_root` — the version the caller already trusts.
///
/// **This verifies nothing.** It follows the consistent-snapshot naming so
/// that the right files are collected — timestamp names the snapshot
/// version, the snapshot names the targets version, the targets name the
/// target's digest — and hands the result to [`update`], which is where
/// every signature, expiry and rollback bound is checked. Fetching over a
/// hostile transport is therefore not a vulnerability but a denial: the
/// bytes are self-authenticating, so a tampering mirror produces a bundle
/// that fails verification and leaves the current pins standing.
pub fn fetch_bundle(repo: &dyn Repo, from_root: u64) -> Result<TufBundle, TufError> {
    let fetch = |path: &str| -> Result<Vec<u8>, TufError> {
        repo.get(path)
            .map_err(TufError::Malformed)?
            .ok_or_else(|| TufError::Chain(format!("the repository has no {path}")))
    };

    // The root chain, from the version already trusted up to whatever the
    // repository last published. The walk ends at the first version the
    // repository does not have — that is how TUF says "this is current".
    let mut roots = Vec::new();
    for version in from_root..from_root.saturating_add(ROOT_CEILING) {
        match repo
            .get(&format!("{version}.root.json"))
            .map_err(TufError::Malformed)?
        {
            None => break,
            Some(bytes) => roots.push(bytes),
        }
    }
    if roots.is_empty() {
        return Err(TufError::Chain(format!(
            "the repository has no {from_root}.root.json, the root this client trusts"
        )));
    }

    let timestamp = fetch("timestamp.json")?;
    let snapshot_version = meta_version(&timestamp, SNAPSHOT_META)?;
    let snapshot = fetch(&format!("{snapshot_version}.{SNAPSHOT_META}"))?;
    let targets_version = meta_version(&snapshot, TARGETS_META)?;
    let targets = fetch(&format!("{targets_version}.{TARGETS_META}"))?;

    // The one target the whole chain exists to carry, named by its digest.
    // `update` re-derives that digest from the bytes, so a repository that
    // serves something else here fails verification rather than this fetch.
    let digest = target_digest(&targets, TRUSTED_ROOT_TARGET)?;
    let trusted_root = fetch(&format!("targets/{digest}.{TRUSTED_ROOT_TARGET}"))?;

    Ok(TufBundle {
        roots,
        timestamp,
        snapshot,
        targets,
        trusted_root,
    })
}

/// The version a role lists for the file below it, unverified — enough to
/// name the next file to fetch.
fn meta_version(bytes: &[u8], file: &str) -> Result<u64, TufError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| TufError::Malformed(format!("{file}: {e}")))?;
    value["signed"]["meta"][file]["version"]
        .as_u64()
        .ok_or_else(|| TufError::Malformed(format!("the metadata does not list {file}")))
}

/// The SHA-256 `targets.json` names for a target, unverified — enough to
/// name the consistent-snapshot file to fetch.
fn target_digest(targets: &[u8], name: &str) -> Result<String, TufError> {
    let value: serde_json::Value = serde_json::from_slice(targets)
        .map_err(|e| TufError::Malformed(format!("{TARGETS_META}: {e}")))?;
    let digest = value["signed"]["targets"][name]["hashes"]["sha256"]
        .as_str()
        .ok_or_else(|| {
            TufError::Malformed(format!("{TARGETS_META} names no {name} with a sha256"))
        })?;
    match digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        true => Ok(digest.to_ascii_lowercase()),
        false => Err(TufError::Malformed(format!(
            "{TARGETS_META} gives {name} a digest that is not a SHA-256"
        ))),
    }
}

// ---------------------------------------------------------------- metadata

/// One parsed TUF metadata file: the `signed` object, the canonical bytes
/// its signatures cover, and the signatures themselves.
#[derive(Debug, Clone)]
struct Meta {
    role: &'static str,
    version: u64,
    expires: i64,
    signed: serde_json::Value,
    /// The canonical JSON of `signed` — what every signature is over.
    canonical: Vec<u8>,
    /// `(keyid, signature)`, in the order the file lists them.
    signatures: Vec<(String, Vec<u8>)>,
}

impl Meta {
    /// Parses a metadata file and checks it declares the role it was fetched
    /// as. A snapshot served where the targets belong is a chain error, not
    /// a signature one, and saying so is how `synch doctor` stays useful.
    fn parse(bytes: &[u8], role: &'static str) -> Result<Meta, TufError> {
        let bad = |why: String| TufError::Malformed(format!("{role}.json: {why}"));
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| bad(e.to_string()))?;
        let signed = value
            .get("signed")
            .cloned()
            .ok_or_else(|| bad("no signed object".into()))?;
        let declared = signed["_type"]
            .as_str()
            .ok_or_else(|| bad("signed._type is not a string".into()))?;
        if declared != role {
            return Err(TufError::Chain(format!(
                "a file served as {role}.json declares itself {declared}"
            )));
        }
        // spec_version is `MAJOR.MINOR.FIX`; a major bump is a format this
        // build does not claim to read.
        let spec = signed["spec_version"]
            .as_str()
            .ok_or_else(|| bad("no spec_version".into()))?;
        if !spec.starts_with("1.") {
            return Err(bad(format!("spec version {spec} is not 1.x")));
        }
        let version = signed["version"]
            .as_u64()
            .ok_or_else(|| bad("version is not a whole number".into()))?;
        let expires = parse_rfc3339(
            signed["expires"]
                .as_str()
                .ok_or_else(|| bad("expires is not a string".into()))?,
        )
        .ok_or_else(|| bad("expires is not an RFC 3339 timestamp".into()))?;
        let mut signatures = Vec::new();
        for entry in value["signatures"]
            .as_array()
            .ok_or_else(|| bad("signatures is not an array".into()))?
        {
            let keyid = entry["keyid"]
                .as_str()
                .ok_or_else(|| bad("a signature has no keyid".into()))?;
            let sig = hex_decode(
                entry["sig"]
                    .as_str()
                    .ok_or_else(|| bad("a signature has no sig".into()))?,
            )
            .ok_or_else(|| bad("a signature is not hex".into()))?;
            signatures.push((keyid.to_string(), sig));
        }
        let canonical = canonical_json(&signed).map_err(bad)?;
        Ok(Meta {
            role,
            version,
            expires,
            signed,
            canonical,
            signatures,
        })
    }

    fn check_expiry(&self, now: u64) -> Result<(), TufError> {
        match self.expires > now as i64 {
            true => Ok(()),
            false => Err(TufError::Expiry(format!(
                "{}.json version {} expired at {}",
                self.role, self.version, self.expires
            ))),
        }
    }

    fn check_rollback(&self, accepted: u64) -> Result<(), TufError> {
        match self.version >= accepted {
            true => Ok(()),
            false => Err(TufError::Rollback(format!(
                "{}.json version {} is older than the accepted {accepted}",
                self.role, self.version
            ))),
        }
    }

    /// Checks a file this one lists in `meta`: version exactly, hashes and
    /// length when they are given.
    ///
    /// Sigstore's timestamp lists `snapshot.json` by version alone, and its
    /// snapshot does the same for `targets.json` — hashes are optional in
    /// the TUF spec and this repository omits them for the files that change
    /// on every publish. The version equality is what still binds them.
    fn check_listed(&self, file: &str, bytes: &[u8], version: u64) -> Result<(), TufError> {
        let entry = &self.signed["meta"][file];
        let listed = entry["version"]
            .as_u64()
            .ok_or_else(|| TufError::Chain(format!("{}.json does not list {file}", self.role)))?;
        if listed != version {
            return Err(TufError::Rollback(format!(
                "{}.json names {file} version {listed}, the bundle carries {version}",
                self.role
            )));
        }
        check_hashes(file, entry, bytes)
    }

    /// Checks the target file the chain exists to authenticate.
    ///
    /// Unlike `meta`, a target entry's `hashes` are not optional: without
    /// them nothing in the chain says anything about these bytes.
    fn check_target(&self, name: &str, bytes: &[u8]) -> Result<(), TufError> {
        let entry = &self.signed["targets"][name];
        if entry.is_null() {
            return Err(TufError::TargetHash(format!(
                "targets.json version {} names no {name}",
                self.version
            )));
        }
        if entry["hashes"]["sha256"].as_str().is_none() {
            return Err(TufError::TargetHash(format!(
                "targets.json gives no sha256 for {name}"
            )));
        }
        check_hashes(name, entry, bytes)
    }
}

/// Compares a file against the `hashes`/`length` an entry carries, when it
/// carries them.
fn check_hashes(file: &str, entry: &serde_json::Value, bytes: &[u8]) -> Result<(), TufError> {
    if let Some(length) = entry["length"].as_u64() {
        if length != bytes.len() as u64 {
            return Err(TufError::TargetHash(format!(
                "{file} is {} bytes, the metadata says {length}",
                bytes.len()
            )));
        }
    }
    if let Some(expected) = entry["hashes"]["sha256"].as_str() {
        let actual = hex::encode(sha256(bytes));
        if !expected.eq_ignore_ascii_case(&actual) {
            return Err(TufError::TargetHash(format!(
                "{file} hashes to {actual}, the metadata says {expected}"
            )));
        }
    }
    Ok(())
}

/// A parsed `root.json`: the metadata plus the role and key tables that make
/// it the thing every other file is checked against.
#[derive(Debug, Clone)]
struct Root {
    version: u64,
    meta: Meta,
    bytes: Vec<u8>,
    /// The role table: role name → (key ids, threshold).
    roles: BTreeMap<String, (Vec<String>, u64)>,
    /// The key table, by the id the roles and signatures name.
    keys: BTreeMap<String, TufKey>,
}

impl Root {
    fn parse(bytes: &[u8]) -> Result<Root, TufError> {
        let meta = Meta::parse(bytes, ROOT_ROLE)?;
        let bad = |why: String| TufError::Malformed(format!("root.json: {why}"));
        let mut roles = BTreeMap::new();
        for (name, role) in meta.signed["roles"]
            .as_object()
            .ok_or_else(|| bad("roles is not an object".into()))?
        {
            let threshold = role["threshold"]
                .as_u64()
                .ok_or_else(|| bad(format!("role {name} has no threshold")))?;
            if threshold == 0 {
                // A zero threshold is a role anything satisfies.
                return Err(bad(format!("role {name} has threshold 0")));
            }
            let keyids = role["keyids"]
                .as_array()
                .ok_or_else(|| bad(format!("role {name} has no keyids")))?
                .iter()
                .filter_map(|id| id.as_str().map(str::to_string))
                .collect();
            roles.insert(name.clone(), (keyids, threshold));
        }
        let mut keys = BTreeMap::new();
        for (id, key) in meta.signed["keys"]
            .as_object()
            .ok_or_else(|| bad("keys is not an object".into()))?
        {
            // A key this build cannot use is not an error here: it becomes a
            // threshold failure only if a role actually needs it.
            if let Ok(parsed) = TufKey::parse(key) {
                keys.insert(id.clone(), parsed);
            }
        }
        Ok(Root {
            version: meta.version,
            bytes: bytes.to_vec(),
            roles,
            keys,
            meta,
        })
    }

    fn check_expiry(&self, now: u64) -> Result<(), TufError> {
        self.meta.check_expiry(now)
    }

    /// Checks that `meta` carries signatures from at least `threshold`
    /// distinct keys of this root's `role`.
    ///
    /// Distinct is doing work: a file that repeats one key's signature five
    /// times must not satisfy a threshold of three.
    fn check_role(&self, role: &str, meta: &Meta) -> Result<(), TufError> {
        let (keyids, threshold) = self.roles.get(role).ok_or_else(|| {
            TufError::Chain(format!("root {} defines no {role} role", self.version))
        })?;
        let authorized: BTreeSet<&String> = keyids.iter().collect();
        let mut signed: BTreeSet<&str> = BTreeSet::new();
        for (keyid, signature) in &meta.signatures {
            if signed.contains(keyid.as_str()) || !authorized.contains(keyid) {
                continue;
            }
            let Some(key) = self.keys.get(keyid) else {
                continue;
            };
            if key.verify(&meta.canonical, signature).is_ok() {
                signed.insert(keyid);
            }
        }
        match signed.len() as u64 >= *threshold {
            true => Ok(()),
            false => Err(TufError::Threshold(format!(
                "{}.json version {} carries {} of the {threshold} {role} signatures root {} requires",
                meta.role,
                meta.version,
                signed.len(),
                self.version
            ))),
        }
    }
}

// -------------------------------------------------------------------- keys

/// The signature scheme a TUF key uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TufScheme {
    /// ECDSA P-256 with SHA-256. Sigstore signs with DER-encoded `r`,`s`;
    /// the fixed-width form is accepted too, being the same signature.
    EcdsaP256Sha256,
    /// Ed25519.
    Ed25519,
}

/// One key from a root's key table.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TufKey {
    scheme: TufScheme,
    /// The raw public key: an uncompressed P-256 point, or 32 Ed25519 bytes.
    point: Vec<u8>,
}

impl TufKey {
    /// Parses one entry of `signed.keys`.
    ///
    /// Dispatch is on `scheme`, never `keytype`: Sigstore's roots write the
    /// same P-256 key as keytype `ecdsa-sha2-nistp256` up to version 8 and
    /// `ecdsa` from version 9, while the scheme stayed `ecdsa-sha2-nistp256`
    /// throughout. `keyval.public` is a PEM SubjectPublicKeyInfo in every
    /// root from version 5 on, and hex-encoded raw key material before that.
    fn parse(key: &serde_json::Value) -> Result<TufKey, TufError> {
        let bad = |why: &str| TufError::Signature(format!("key: {why}"));
        let scheme = match key["scheme"].as_str() {
            Some("ecdsa-sha2-nistp256") => TufScheme::EcdsaP256Sha256,
            Some("ed25519") => TufScheme::Ed25519,
            Some(other) => return Err(bad(&format!("unsupported scheme {other}"))),
            None => return Err(bad("no scheme")),
        };
        let public = key["keyval"]["public"]
            .as_str()
            .ok_or_else(|| bad("no keyval.public"))?;
        let point = match public.contains("-----BEGIN") {
            true => spki_point(&pem_body(public)?, scheme)?,
            false => raw_point(
                &hex_decode(public.trim()).ok_or_else(|| bad("keyval.public is not hex"))?,
                scheme,
            )?,
        };
        Ok(TufKey { scheme, point })
    }

    /// Verifies one signature over the canonical bytes.
    fn verify(&self, message: &[u8], sig: &[u8]) -> Result<(), TufError> {
        let algorithms: &[&dyn signature::VerificationAlgorithm] = match self.scheme {
            // Sigstore's TUF signatures are DER; ring's fixed-width verifier
            // refuses those outright, so both encodings are tried. They are
            // two spellings of one signature — accepting either concedes
            // nothing beyond the malleability ASN.1 already has.
            TufScheme::EcdsaP256Sha256 => &[
                &signature::ECDSA_P256_SHA256_ASN1,
                &signature::ECDSA_P256_SHA256_FIXED,
            ],
            TufScheme::Ed25519 => &[&signature::ED25519],
        };
        for algorithm in algorithms {
            if signature::UnparsedPublicKey::new(*algorithm, &self.point)
                .verify(message, sig)
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(TufError::Signature("a signature does not verify".into()))
    }
}

/// The base64 body of a PEM block, whatever its label.
fn pem_body(pem: &str) -> Result<Vec<u8>, TufError> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64_decode(body.trim()).map_err(|_| TufError::Signature("a PEM key is not base64".into()))
}

/// The raw key inside a DER SubjectPublicKeyInfo.
///
/// Deliberately narrow, the same stance as [`crate::rekor::LogKey::from_spki`]
/// (whose prefixes these are): two shapes are recognized and everything else
/// is refused, rather than a general ASN.1 reader parsing whatever it is
/// handed.
fn spki_point(der: &[u8], scheme: TufScheme) -> Result<Vec<u8>, TufError> {
    const P256_SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    const ED25519_SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let bad = TufError::Signature("a key is not the SubjectPublicKeyInfo its scheme names".into());
    match scheme {
        TufScheme::EcdsaP256Sha256 => match der.strip_prefix(P256_SPKI_PREFIX) {
            Some(point) if point.len() == 64 => {
                let mut uncompressed = Vec::with_capacity(65);
                uncompressed.push(0x04);
                uncompressed.extend_from_slice(point);
                Ok(uncompressed)
            }
            _ => Err(bad),
        },
        TufScheme::Ed25519 => match der.strip_prefix(ED25519_SPKI_PREFIX) {
            Some(point) if point.len() == 32 => Ok(point.to_vec()),
            _ => Err(bad),
        },
    }
}

/// The pre-PEM form: hex key material, as Sigstore's roots 1–4 wrote it.
fn raw_point(bytes: &[u8], scheme: TufScheme) -> Result<Vec<u8>, TufError> {
    let bad = TufError::Signature("a key is not the raw material its scheme names".into());
    match scheme {
        TufScheme::EcdsaP256Sha256 => match bytes {
            [0x04, ..] if bytes.len() == 65 => Ok(bytes.to_vec()),
            _ if bytes.len() == 64 => {
                let mut uncompressed = Vec::with_capacity(65);
                uncompressed.push(0x04);
                uncompressed.extend_from_slice(bytes);
                Ok(uncompressed)
            }
            _ => Err(bad),
        },
        TufScheme::Ed25519 if bytes.len() == 32 => Ok(bytes.to_vec()),
        TufScheme::Ed25519 => Err(bad),
    }
}

/// The key id TUF derives for a key object: SHA-256 over its canonical JSON.
///
/// Informational, not a lookup path. Sigstore's roots key their table by ids
/// that agree with this for every key in every root but one — root 11 kept a
/// key's id while editing a `x-tuf-on-ci-online-uri` member inside it — so
/// the id a role names is the table's key, and this is how a fixture test
/// says the two normally agree.
pub fn key_id(key: &serde_json::Value) -> Result<String, TufError> {
    Ok(hex::encode(sha256(
        &canonical_json(key).map_err(TufError::Malformed)?,
    )))
}

// -------------------------------------------------------- canonical JSON

/// Renders a value as OLPC canonical JSON — the form TUF signatures cover.
///
/// The rules are few and every one of them is load-bearing: object members
/// sorted by key, no whitespace anywhere, strings escaping only `"` and `\`
/// (control characters travel raw, unlike in ordinary JSON), integers only.
/// This is where TUF implementations historically break, which is why the
/// conformance fixture verifies it against the real repository's bytes
/// rather than against a hand-written example.
pub(crate) fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical(value: &serde_json::Value, out: &mut String) -> Result<(), String> {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(true) => out.push_str("true"),
        serde_json::Value::Bool(false) => out.push_str("false"),
        serde_json::Value::Number(number) => match number.as_i64() {
            Some(n) => out.push_str(&n.to_string()),
            // A float has no canonical rendering, so canonical JSON has no
            // floats. Refusing is the only honest answer.
            None => match number.as_u64() {
                Some(n) => out.push_str(&n.to_string()),
                None => return Err(format!("{number} is not a whole number")),
            },
        },
        serde_json::Value::String(text) => write_canonical_string(text, out),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Object(members) => {
            // serde_json's map is already ordered by key; sorting again
            // costs nothing and means the ordering is this function's
            // promise rather than a dependency's default.
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort();
            out.push('{');
            for (at, key) in keys.into_iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_canonical_string(key, out);
                out.push(':');
                write_canonical(&members[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A canonical-JSON string: quotes and backslashes escaped, nothing else.
fn write_canonical_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ------------------------------------------------------------------ time

/// Parses the RFC 3339 timestamps TUF metadata carries, as seconds since the
/// epoch.
///
/// Narrow on purpose, and wider than the current repository needs: Sigstore's
/// roots have written `2023-04-18T18:13:43Z`, `2022-05-11T19:09:02.663975009Z`
/// and `2021-12-18T13:28:12.99008-06:00` at different times, so fractional
/// seconds and numeric offsets both have to parse or old chains stop walking.
fn parse_rfc3339(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    let number = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    // Whatever follows the seconds is a fraction, a zone, or both.
    let rest = &text[19..];
    let rest = match rest.strip_prefix('.') {
        Some(fraction) => {
            &fraction[fraction
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(fraction.len())..]
        }
        None => rest,
    };
    let offset = match rest.as_bytes() {
        [b'Z'] | [b'z'] | [] => 0,
        [sign @ (b'+' | b'-'), ..] if rest.len() == 6 && rest.as_bytes()[3] == b':' => {
            let hours: i64 = rest[1..3].parse().ok()?;
            let minutes: i64 = rest[4..6].parse().ok()?;
            let magnitude = hours * 3600 + minutes * 60;
            match sign {
                b'-' => -magnitude,
                _ => magnitude,
            }
        }
        _ => return None,
    };
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`, the standard branch-free form).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

// ------------------------------------------------------------- encodings

/// Standard base64, padding optional.
fn base64_decode(text: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine;
    let trimmed: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&trimmed)
        .map_err(|_| ())
}

/// base64url without padding — how a bundle travels in a TXT record.
fn base64url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes a base64url TXT payload, padding optional.
fn base64url_decode(text: &str) -> Result<Vec<u8>, TufError> {
    use base64::Engine;
    let trimmed: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&trimmed)
        .map_err(|e| TufError::Malformed(format!("not base64url: {e}")))
}

/// Lowercase or uppercase hex, as TUF writes signatures and digests.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    hex::decode(text).ok()
}

/// A bounds-checked reader over the wire format.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, at: 0 }
    }

    fn take(&mut self, len: usize, what: &str) -> Result<&'a [u8], TufError> {
        let end = self.at.checked_add(len).ok_or_else(|| {
            TufError::Malformed(format!("{what}: length {len} overflows the bundle"))
        })?;
        if end > self.bytes.len() {
            return Err(TufError::Malformed(format!(
                "{what}: wanted {len} bytes, {} remain",
                self.bytes.len() - self.at
            )));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self, what: &str) -> Result<u8, TufError> {
        Ok(self.take(1, what)?[0])
    }

    fn u32(&mut self, what: &str) -> Result<u32, TufError> {
        let bytes = self.take(4, what)?;
        let mut array = [0u8; 4];
        array.copy_from_slice(bytes);
        Ok(u32::from_be_bytes(array))
    }

    fn blob32(&mut self, what: &str) -> Result<&'a [u8], TufError> {
        let len = self.u32(what)?;
        self.take(len as usize, what)
    }

    fn finish(&self) -> Result<(), TufError> {
        match self.bytes.len() - self.at {
            0 => Ok(()),
            extra => Err(TufError::Malformed(format!(
                "{extra} bytes after the end of the bundle"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> TufBundle {
        TufBundle {
            roots: vec![b"{\"a\":1}".to_vec(), b"{\"a\":2}".to_vec()],
            timestamp: b"timestamp".to_vec(),
            snapshot: b"snapshot".to_vec(),
            targets: b"targets".to_vec(),
            trusted_root: b"trusted".to_vec(),
        }
    }

    #[test]
    fn bundles_round_trip() {
        let original = bundle();
        assert_eq!(TufBundle::decode(&original.encode()).unwrap(), original);
        assert_eq!(TufBundle::from_txt(&original.to_txt()).unwrap(), original);
    }

    #[test]
    fn the_wire_layout_is_pinned() {
        // Field offsets are load-bearing across two implementations; assert
        // them rather than trusting the encoder to agree with itself.
        let bytes = bundle().encode();
        assert_eq!(bytes[0], BUNDLE_VERSION);
        assert_eq!(bytes[1], 2, "root count");
        assert_eq!(&bytes[2..6], &7u32.to_be_bytes());
        assert_eq!(&bytes[6..13], b"{\"a\":1}");
        assert_eq!(&bytes[13..17], &7u32.to_be_bytes());
    }

    #[test]
    fn a_truncated_or_padded_bundle_is_malformed() {
        let bytes = bundle().encode();
        for cut in [0, 1, 2, 5, bytes.len() - 1] {
            assert!(matches!(
                TufBundle::decode(&bytes[..cut]),
                Err(TufError::Malformed(_))
            ));
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(matches!(
            TufBundle::decode(&extra),
            Err(TufError::Malformed(_))
        ));
        let mut wrong_version = bytes.clone();
        wrong_version[0] = 2;
        assert!(matches!(
            TufBundle::decode(&wrong_version),
            Err(TufError::Malformed(_))
        ));
        // A bundle with no root chains from nothing.
        let mut rootless = bytes;
        rootless[1] = 0;
        assert!(matches!(
            TufBundle::decode(&rootless),
            Err(TufError::Malformed(_))
        ));
    }

    #[test]
    fn canonical_json_is_canonical_json() {
        let value: serde_json::Value = serde_json::from_str(
            r#"{ "b": 1, "a": [true, false, null], "c": "quote \" slash \\ tab \t" }"#,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(canonical_json(&value).unwrap()).unwrap(),
            // Sorted keys, no whitespace, and — the part every
            // implementation gets wrong once — a raw tab inside the string,
            // because canonical JSON escapes only the quote and the
            // backslash.
            "{\"a\":[true,false,null],\"b\":1,\"c\":\"quote \\\" slash \\\\ tab \t\"}"
        );
        // Floats have no canonical rendering, so they are refused.
        assert!(canonical_json(&serde_json::json!({ "x": 1.5 })).is_err());
    }

    #[test]
    fn the_embedded_root_is_the_sigstore_root() {
        let root = Root::parse(EMBEDDED_TUF_ROOT.as_bytes()).expect("the embedded root parses");
        assert_eq!(root.version, 15);
        // Its own root role signs it: the property that lets a later root
        // chain to it at all.
        root.check_role(ROOT_ROLE, &root.meta)
            .expect("the embedded root is self-consistent");
        for role in [ROOT_ROLE, TIMESTAMP_ROLE, SNAPSHOT_ROLE, TARGETS_ROLE] {
            assert!(root.roles.contains_key(role), "no {role} role");
        }
        assert_eq!(root.roles[ROOT_ROLE].1, 3, "the root threshold");
        // And every key it names is one this build can actually use — a key
        // that silently failed to parse would become a threshold failure
        // later, at the worst possible moment.
        let keys = root.meta.signed["keys"].as_object().unwrap();
        assert_eq!(root.keys.len(), keys.len());
    }

    #[test]
    fn the_embedded_state_is_the_embedded_root() {
        let state = PinState::embedded();
        assert_eq!(state.root_version, 15);
        // No update accepted yet: the bootstrap snapshot stands.
        assert_eq!(state.log_keys(), None);
    }

    #[test]
    fn rfc3339_parses_every_shape_the_repository_has_written() {
        // 1970-01-01T00:00:00Z is the epoch, by construction.
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-11-20T13:58:18Z"), Some(1_795_183_098));
        // Fractional seconds are dropped, not misread as anything.
        assert_eq!(
            parse_rfc3339("2022-05-11T19:09:02.663975009Z"),
            parse_rfc3339("2022-05-11T19:09:02Z")
        );
        // A numeric offset moves the instant, and both signs work.
        assert_eq!(
            parse_rfc3339("2021-12-18T13:28:12.99008-06:00"),
            parse_rfc3339("2021-12-18T19:28:12Z")
        );
        assert_eq!(
            parse_rfc3339("2021-12-18T13:28:12+02:00"),
            parse_rfc3339("2021-12-18T11:28:12Z")
        );
        for broken in [
            "",
            "2026-11-20",
            "2026-11-20 13:58:18Z",
            "2026-13-20T13:58:18Z",
            "2026-11-20T13:58:18+0200",
            "not a time at all",
        ] {
            assert_eq!(parse_rfc3339(broken), None, "{broken:?} must not parse");
        }
    }

    #[test]
    fn a_state_file_round_trips_and_is_the_owners_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("rekor-pins.json");
        let state = PinState {
            trusted_root: br#"{"tlogs":[]}"#.to_vec(),
            timestamp_version: 7,
            snapshot_version: 8,
            targets_version: 9,
            updated_at: 1_700_000_000,
            ..PinState::embedded()
        };
        state.save(&path).unwrap();
        assert_eq!(PinState::load(&path).as_ref(), Some(&state));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // Anything unreadable as state reads as no state at all, rather
        // than as an error a client could be stopped by.
        assert_eq!(
            PinState::load(dir.path().join("absent.json").as_path()),
            None
        );
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(PinState::load(&path), None);
        std::fs::write(&path, r#"{"version":2}"#).unwrap();
        assert_eq!(PinState::load(&path), None);
    }

    #[test]
    fn a_trusted_root_with_no_logs_is_never_adopted() {
        assert!(matches!(
            tlog_keys(br#"{"tlogs":[]}"#),
            Err(TufError::Malformed(_))
        ));
        assert!(matches!(
            tlog_keys(b"not json"),
            Err(TufError::Malformed(_))
        ));
        assert!(matches!(tlogs(b"not json"), Err(TufError::Malformed(_))));
        // A log with a key but nowhere to reach it is half an answer, and
        // the half that is missing is the one this change exists to supply.
        assert!(matches!(
            tlogs(br#"{"tlogs":[{"publicKey":{"rawBytes":"MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244="}}]}"#),
            Err(TufError::Malformed(_))
        ));
    }

    /// A trusted root with three shards: one closed, one open, one not yet.
    fn three_shards() -> Vec<u8> {
        let ed25519 = "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=";
        let p256 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";
        serde_json::json!({"tlogs": [
            {
                "baseUrl": "https://retired.example/",
                "publicKey": {"rawBytes": p256, "validFor": {
                    "start": "2021-01-12T11:53:27Z",
                    "end": "2025-09-23T00:00:00Z",
                }},
            },
            {
                "baseUrl": "https://open.example",
                "publicKey": {"rawBytes": ed25519, "validFor": {
                    "start": "2025-09-23T00:00:00Z",
                }},
            },
            {
                "baseUrl": "https://next.example",
                "publicKey": {"rawBytes": ed25519, "validFor": {
                    "start": "2030-01-01T00:00:00Z",
                }},
            },
        ]})
        .to_string()
        .into_bytes()
    }

    #[test]
    fn the_current_log_is_the_one_whose_window_is_open_now() {
        let logs = tlogs(&three_shards()).unwrap();
        // 2026-08-16: the middle shard.
        let open = current_tlog(&logs, 1_786_854_774).expect("a log in service");
        assert_eq!(open.base_url, "https://open.example");
        // 2023: the first, before the middle one opened.
        assert_eq!(
            current_tlog(&logs, 1_690_000_000).unwrap().base_url,
            "https://retired.example",
            "a trailing slash is not part of a base URL"
        );
        // 2035: the last, once the others have been superseded.
        assert_eq!(
            current_tlog(&logs, 2_050_000_000).unwrap().base_url,
            "https://next.example"
        );
        // Before any of them opened, nothing is in service — which is a
        // trusted root to report on, not one to guess a hostname from.
        assert!(current_tlog(&logs, 0).is_none());

        // Every shard stays pinned regardless: a proof from the retired one
        // is still a proof, and its checkpoint still has to verify.
        assert_eq!(tlog_keys(&three_shards()).unwrap().keys().len(), 3);
    }

    #[test]
    fn the_embedded_trusted_root_names_a_log_in_service() {
        let logs = tlogs(EMBEDDED_TRUSTED_ROOT.as_bytes()).expect("the embedded trusted root");
        // The bootstrap has to be usable on its own — a build whose embedded
        // artifact names no open shard cannot make a first request at all.
        let now = 1_786_854_774;
        let open = current_tlog(&logs, now).expect("an open shard in the embedded root");
        assert!(open.base_url.starts_with("https://"));
        // And the bootstrap pin set is exactly what that artifact names, not
        // a separately maintained list that can drift from it.
        assert_eq!(
            crate::rekor::LogKeys::embedded(),
            tlog_keys(EMBEDDED_TRUSTED_ROOT.as_bytes()).unwrap()
        );
    }

    #[test]
    fn error_classes_are_named_for_the_doctor() {
        for (error, class) in [
            (TufError::Malformed(String::new()), "malformed"),
            (TufError::Chain(String::new()), "chain"),
            (TufError::Threshold(String::new()), "threshold"),
            (TufError::Signature(String::new()), "signature"),
            (TufError::Expiry(String::new()), "expiry"),
            (TufError::Rollback(String::new()), "rollback"),
            (TufError::TargetHash(String::new()), "target-hash"),
        ] {
            assert_eq!(error.class(), class);
        }
    }
}
