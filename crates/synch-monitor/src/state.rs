//! What a monitor remembers between runs, in one hand-readable JSON file: the
//! last checkpoint per log (split-view detection — a tree that does not extend
//! the last one shown *this* monitor has equivocated), the keys already
//! reported per apex (bookkeeping, not trust — without them every run
//! re-reports every key the zone ever authorized), the evidence bodies behind
//! each report (a local lookup, never a re-fetch from the log under watch),
//! and the trust surface the verdicts were computed under: tier B means "no
//! client holding *these* would have accepted it", so a later run under a
//! different surface writes verdicts about a different client population, and
//! is refused rather than merged. Plain JSON, so an operator can read it, seed
//! it by hand, and check it into a runbook.

use std::collections::BTreeMap;

use base64::Engine;

use crate::{classify::KnownKeys, MonitorError};

/// How many entry bodies are kept per log.
///
/// The evidence drawer holds the bodies behind **reported** authorizations,
/// so it grows by one entry per alarm rather than per log entry — but "per
/// alarm" is not a bound, because an attacker holding a zone's DS can mint
/// fresh keys and each is a genuine new authorization. The cap makes the file
/// bounded outright; the oldest indices go first and the run says so, because
/// silently dropping evidence would be the same mistake in a quieter place.
pub(crate) const MAX_STORED_ENTRIES: usize = 1024;

/// Where a monitor got to in one log.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LogPosition {
    /// The tree size of the last verified checkpoint.
    #[serde(default)]
    pub tree_size: u64,
    /// That checkpoint's root, lowercase hex. The next run recomputes this
    /// root from the new tree's tiles; if it does not come back, the log has
    /// shown two histories.
    #[serde(default)]
    pub root: String,
    /// The next entry index to read. Entries below it have been classified
    /// **and** everything they produced has been reported.
    #[serde(default)]
    pub next_index: u64,
}

impl LogPosition {
    /// Whether this log has ever been read.
    pub fn is_fresh(&self) -> bool {
        self.root.is_empty()
    }
}

/// The DNSSEC anchors and log keys a run's verdicts were computed against.
///
/// Two labels, and their only job is to be compared with the next run's. A
/// tier B verdict is "no client holding this would have accepted it", so the
/// verdicts in a state file belong to the surface that produced them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustSurface {
    /// The DNSSEC anchor set: `icann-root`, or a digest of the anchor file.
    #[serde(default)]
    pub anchors: String,
    /// The log key set: `tuf`, or a digest of the `--rekor-key` file.
    #[serde(default)]
    pub log_keys: String,
}

/// The monitor's persisted view of every log it reads.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MonitorState {
    /// The trust surface the recorded verdicts were computed under, once a
    /// run has recorded one.
    #[serde(default)]
    pub surface: Option<TrustSurface>,
    /// The watch list the recorded [`Self::logs`] positions actually cover,
    /// sorted, as of the last completed walk.
    ///
    /// Read coverage is one `next_index` per log, but the watch filter is
    /// applied *per entry* inside the walk: an entry naming an unwatched apex
    /// is stepped over and the position advances past it. So a `next_index`
    /// is only meaningful together with the watch list that produced it —
    /// widening the list later does not reach back, and every entry for the
    /// new apex already in the log stays unclassified for good.
    ///
    /// Kept apart from [`TrustSurface`] because it is not one: a surface
    /// change invalidates recorded *verdicts*, while this invalidates
    /// recorded *coverage*, and the remedies differ. `None` is a state file
    /// written before this field existed, which is treated as "covers
    /// whatever it currently watches" — the alternative is refusing every
    /// upgrade, and the gap it would name is one no run can close anyway.
    #[serde(default)]
    pub watched: Option<Vec<String>>,
    /// Position per log, keyed by the origin line its checkpoints carry.
    ///
    /// **A map, because the client trusts more than one log.** A monitor
    /// follows every shard whose key is pinned, so a rotation is a new key in
    /// this map rather than a hard failure that costs the split-view baseline
    /// and the record of what had already been reported.
    ///
    /// Keyed by the origin because that is the name of the *tree*: two shards
    /// both have an entry 68,295,246 and they are not the same entry, and a
    /// consistency check is a statement about one tree's history. The origin
    /// is signed — but signed by the party the consistency check exists to
    /// catch, so it is not a name that party cannot change. What that buys an
    /// equivocating log is a fresh baseline under a new name, and it is worth
    /// being clear that the persisted root is the whole of the defence here:
    /// a log willing to lie can also fork *forward* past the recorded tree
    /// size, which no single monitor can detect. Catching either needs
    /// cross-witnessing, which this design does not implement.
    #[serde(default)]
    pub logs: BTreeMap<String, LogPosition>,
    /// The apexes this monitor has reported keys for, and those keys.
    #[serde(default)]
    pub known: KnownKeys,
    /// The full body of every reported finding: the evidence behind each
    /// report, `origin → index → base64 body`.
    ///
    /// Keyed by the origin line rather than the endpoint because this is a
    /// label on a log *entry*: two shards both have an entry 68,295,246 and
    /// they are not the same entry, and the origin is how the log names the
    /// tree that one came from. A tier A line says "this key was authorized";
    /// this is *what said so*, kept locally so inspecting it is a file read,
    /// not a re-fetch from the log being watched. Base64, because the file
    /// stays hand-readable JSON.
    ///
    /// Only the entries behind **reports on stdout** are kept, and at most
    /// `MAX_STORED_ENTRIES` per log. An unauthorized claim is something
    /// anyone can publish for free by minting a self-signed certificate that
    /// names a watched apex, so keeping a body for every finding made the file
    /// grow without bound at an attacker's choosing.
    #[serde(default)]
    pub entries: BTreeMap<String, BTreeMap<u64, String>>,
}

impl MonitorState {
    /// Records one entry body under its log's origin, base64 — the file
    /// stays hand-readable JSON.
    ///
    /// Returns the indices dropped to stay under `MAX_STORED_ENTRIES`, so
    /// the run can say which evidence is no longer local.
    pub fn record_entry(&mut self, origin: &str, index: u64, body: &[u8]) -> Vec<u64> {
        let bodies = self.entries.entry(origin.to_string()).or_default();
        bodies.insert(
            index,
            base64::engine::general_purpose::STANDARD.encode(body),
        );
        let mut dropped = Vec::new();
        while bodies.len() > MAX_STORED_ENTRIES {
            let Some((oldest, _)) = bodies.pop_first() else {
                break;
            };
            dropped.push(oldest);
        }
        dropped
    }

    /// A recorded body, decoded back out — `Ok(None)` when the state holds
    /// no entry at `index` from the log `origin`.
    pub fn entry(&self, origin: &str, index: u64) -> Result<Option<Vec<u8>>, MonitorError> {
        match self
            .entries
            .get(origin)
            .and_then(|bodies| bodies.get(&index))
        {
            None => Ok(None),
            Some(encoded) => base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map(Some)
                .map_err(|e| MonitorError::State(format!("entry {index} is not base64: {e}"))),
        }
    }

    /// The origins that hold a body for `index`. An index alone names an
    /// entry only when exactly one log holds it — two shards both have an
    /// entry 68,295,246, and they are not the same entry.
    pub fn origins_holding(&self, index: u64) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(_, bodies)| bodies.contains_key(&index))
            .map(|(origin, _)| origin.as_str())
            .collect()
    }

    /// Reads a state file, treating an absent one as a fresh monitor.
    pub fn load(path: &std::path::Path) -> Result<MonitorState, MonitorError> {
        match std::fs::read(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MonitorState::default()),
            Err(e) => Err(MonitorError::State(format!("{}: {e}", path.display()))),
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| MonitorError::State(format!("{}: {e}", path.display()))),
        }
    }

    /// Writes the state so that a crash leaves either the previous file or
    /// this one, and never half of either: the shared temporary-fsync-rename
    /// ritual (`synch_core::fs::write_atomic`), whose unique temporary is what
    /// keeps two overlapping saves — a cron job that outlives its slot — from
    /// renaming each other's partial bytes over the real file.
    pub fn save(&self, path: &std::path::Path) -> Result<(), MonitorError> {
        let json =
            serde_json::to_vec_pretty(self).map_err(|e| MonitorError::State(e.to_string()))?;
        synch_core::fs::write_atomic(path, &json)
            .map_err(|e| MonitorError::State(format!("{}: {e}", path.display())))
    }

    /// Where this monitor got to in the log calling itself `origin`, or a
    /// fresh position if it has never read that one.
    ///
    /// A shard this monitor has not met is not an error — it is the ordinary
    /// state on the day Sigstore opens one, and the right response is to read
    /// it from the start rather than to refuse to run.
    pub fn position(&mut self, origin: &str) -> &mut LogPosition {
        self.logs.entry(origin.to_string()).or_default()
    }

    /// Whether this state has ever seen a checkpoint from any log.
    pub fn is_fresh(&self) -> bool {
        self.logs.values().all(LogPosition::is_fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records a position, so the tests do not spell the struct out.
    fn positioned(state: &mut MonitorState, origin: &str, size: u64, root: &str, next: u64) {
        *state.position(origin) = LogPosition {
            tree_size: size,
            root: root.to_string(),
            next_index: next,
        };
    }

    #[test]
    fn a_state_file_round_trips_and_an_absent_one_is_a_fresh_monitor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitor.json");
        assert!(MonitorState::load(&path).unwrap().is_fresh());

        let mut state = MonitorState::default();
        positioned(
            &mut state,
            "log2025-1.rekor.example",
            67_686_055,
            &"bcae".repeat(16),
            67_673_584,
        );
        // A second shard, beside the first — the client accepts proofs from both.
        positioned(
            &mut state,
            "log2026-1.rekor.example",
            12,
            &"0f0f".repeat(16),
            12,
        );
        let apex = synch_net::chain::parse_name("sync.example").unwrap();
        state.known.insert(&apex, b"a key");
        assert_eq!(state.logs.len(), 2);
        let dropped = state.record_entry("log2025-1.rekor.example", 67_673_583, b"a body");
        assert!(dropped.is_empty());
        state.save(&path).unwrap();
        assert_eq!(MonitorState::load(&path).unwrap(), state);
        assert!(!MonitorState::load(&path).unwrap().is_fresh());
        let entry = state.entry("log2025-1.rekor.example", 67_673_583).unwrap();
        assert_eq!(entry.as_deref(), Some(b"a body".as_slice()));
        // The same index under the other shard is a different entry; this state holds neither.
        assert_eq!(
            state.entry("log2026-1.rekor.example", 67_673_583).unwrap(),
            None
        );
        assert_eq!(
            state.origins_holding(67_673_583),
            ["log2025-1.rekor.example"]
        );
        assert!(state.origins_holding(1).is_empty());

        // Not this shape is an error, not a silent reset — which would stop
        // detecting split views altogether.
        std::fs::write(&path, b"{").unwrap();
        assert!(MonitorState::load(&path).is_err());
    }

    /// The evidence drawer is bounded, and says what it dropped.
    #[test]
    fn the_evidence_drawer_is_bounded_and_reports_what_it_dropped() {
        let mut state = MonitorState::default();
        for index in 0..MAX_STORED_ENTRIES as u64 {
            let dropped = state.record_entry("log.example", index, b"a body");
            assert!(dropped.is_empty());
        }
        let dropped = state.record_entry("log.example", MAX_STORED_ENTRIES as u64, b"a body");
        assert_eq!(dropped, vec![0]);
        assert_eq!(state.entries["log.example"].len(), MAX_STORED_ENTRIES);
        assert_eq!(state.entry("log.example", 0).unwrap(), None);
        let entry = state.entry("log.example", MAX_STORED_ENTRIES as u64);
        assert!(entry.unwrap().is_some());
    }

    /// Two overlapping saves write their own temporaries, even on a frozen clock.
    #[test]
    fn concurrent_saves_do_not_share_a_temporary_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitor.json");
        let mut first = MonitorState::default();
        positioned(&mut first, "one.example", 1, &"11".repeat(32), 1);
        let mut second = MonitorState::default();
        positioned(&mut second, "two.example", 2, &"22".repeat(32), 2);
        std::thread::scope(|scope| {
            scope.spawn(|| first.save(&path).unwrap());
            scope.spawn(|| second.save(&path).unwrap());
        });
        let loaded = MonitorState::load(&path).unwrap();
        // Whichever won, the file is one whole state, not a splice.
        assert!(loaded == first || loaded == second, "{loaded:?}");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left, ["monitor.json"]);
    }
}
