//! What a monitor remembers between runs.
//!
//! Three things, and each is load-bearing for a different reason. The **last
//! checkpoint** is what makes split-view detection possible at all: a log that
//! shows this monitor a tree which does not extend the one it showed last time
//! has equivocated, and that is the single strongest thing a monitor can
//! notice on its own. Note the scope — *this* monitor, over time. A log that
//! showed a **different** monitor a different history is invisible from here;
//! catching that needs either cross-witnessing, which this design does not
//! implement, or a second monitor run somewhere else and compared by hand.
//! The **known keys** are what make reporting bearable: without a record of
//! which keys have already been surfaced for an apex, every run would report
//! every key the zone has ever authorized, and an alert that fires every hour
//! about the same key is an alert nobody reads. They are bookkeeping, not
//! trust — see [`crate::classify::KnownKeys`]. The **entry bodies** are the
//! evidence: the full log entry behind every finding, per log and by index,
//! so "what exactly does the log hold for this report" is a local lookup —
//! the `entry` subcommand — never a re-fetch from the log under watch.
//! Recording a body here is not the recording tier B is denied; that rule is
//! about `known.keys`, the report-suppression memory, and evidence suppresses
//! nothing.
//!
//! The file is plain JSON on purpose: an operator has to be able to read it,
//! seed it by hand for a zone whose history predates the monitor, and check it
//! into whatever they keep their runbooks in.

use std::collections::BTreeMap;

use base64::Engine;

use crate::{classify::KnownKeys, MonitorError};

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
    /// The next entry index to read. Entries below it have been classified.
    #[serde(default)]
    pub next_index: u64,
}

impl LogPosition {
    /// Whether this log has ever been read.
    pub fn is_fresh(&self) -> bool {
        self.root.is_empty()
    }
}

/// The monitor's persisted view of every log it reads.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MonitorState {
    /// Position per log, keyed by the origin line its checkpoints carry.
    ///
    /// **A map, because the client trusts more than one log.** This used to
    /// be a single origin/size/root/index, so a monitor could follow exactly
    /// one shard — and on a rotation it hard-failed on every subsequent run
    /// ("this state is for X, the log now calls itself Y") until an operator
    /// hand-edited or deleted the file, which also destroyed the split-view
    /// baseline and the record of what had already been reported. Meanwhile
    /// the client kept accepting proofs from the shard nobody was reading.
    ///
    /// Keyed by origin rather than by URL: the origin is what the log signs,
    /// so it is the name that cannot be changed by whoever serves the tiles.
    #[serde(default)]
    pub logs: std::collections::BTreeMap<String, LogPosition>,
    /// The apexes this monitor watches, and the keys it has already reported
    /// as authorized for each.
    ///
    /// Deliberately *not* per log. A key authorized for an apex is news the
    /// first time it is seen and not the second, whichever shard it turns up
    /// in — reporting it again because a different log carried it would be
    /// noise, and noise is what stops alerts being read.
    #[serde(default)]
    pub known: KnownKeys,
    /// The full body of every finding: the evidence behind each report,
    /// `origin → index → base64 body`. Per log for the same reason the
    /// position is — two shards both have an entry 68,295,246, and they are
    /// not the same entry. A tier A line says "this key was authorized";
    /// this is *what said so*, kept locally so inspecting it is a file
    /// read, not a re-fetch from the log being watched. Base64, because
    /// the file stays hand-readable JSON. Grows only by entries that named
    /// a watched apex, so it stays small by construction.
    #[serde(default)]
    pub entries: BTreeMap<String, BTreeMap<u64, String>>,
}

impl MonitorState {
    /// Records one entry body under its log's origin, base64 — the file
    /// stays hand-readable JSON.
    pub fn record_entry(&mut self, origin: &str, index: u64, body: &[u8]) {
        self.entries.entry(origin.to_string()).or_default().insert(
            index,
            base64::engine::general_purpose::STANDARD.encode(body),
        );
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

    /// Writes the state, atomically enough that a crash mid-write leaves the
    /// previous state rather than half of this one.
    pub fn save(&self, path: &std::path::Path) -> Result<(), MonitorError> {
        let json =
            serde_json::to_vec_pretty(self).map_err(|e| MonitorError::State(e.to_string()))?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, &json)
            .map_err(|e| MonitorError::State(format!("{}: {e}", temporary.display())))?;
        std::fs::rename(&temporary, path)
            .map_err(|e| MonitorError::State(format!("{}: {e}", path.display())))
    }

    /// Where this monitor got to in the log calling itself `origin`, or a
    /// fresh position if it has never read that one.
    ///
    /// A shard this monitor has not met is not an error — it is the ordinary
    /// state on the day Sigstore opens one, and the right response is to
    /// read it from the start rather than to refuse to run.
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

    #[test]
    fn a_state_file_round_trips_and_an_absent_one_is_a_fresh_monitor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitor.json");
        assert!(MonitorState::load(&path).unwrap().is_fresh());

        let mut state = MonitorState::default();
        *state.position("log2025-1.rekor.sigstore.dev") = LogPosition {
            tree_size: 67_686_055,
            root: "bcae".repeat(16),
            next_index: 67_673_584,
        };
        // A second shard, tracked beside the first rather than instead of
        // it: the client accepts proofs from both, so the monitor follows
        // both, and a rotation is a new key in this map rather than the
        // hard failure it used to be.
        *state.position("log2026-1.rekor.sigstore.dev") = LogPosition {
            tree_size: 12,
            root: "0f0f".repeat(16),
            next_index: 12,
        };
        state.known.insert(
            &synch_net::chain::parse_name("sync.example").unwrap(),
            b"a key",
        );
        assert_eq!(state.logs.len(), 2);
        state.record_entry(
            "log2025-1.rekor.sigstore.dev",
            67_673_583,
            b"the full body of the finding's entry",
        );
        state.save(&path).unwrap();
        assert_eq!(MonitorState::load(&path).unwrap(), state);
        assert!(!MonitorState::load(&path).unwrap().is_fresh());
        assert_eq!(
            state
                .entry("log2025-1.rekor.sigstore.dev", 67_673_583)
                .unwrap()
                .as_deref(),
            Some(b"the full body of the finding's entry".as_slice())
        );
        // The same index under the other shard is a different entry, and
        // this state holds neither.
        assert_eq!(
            state
                .entry("log2026-1.rekor.sigstore.dev", 67_673_583)
                .unwrap(),
            None
        );
        assert_eq!(
            state.origins_holding(67_673_583),
            ["log2025-1.rekor.sigstore.dev"]
        );
        assert!(state.origins_holding(1).is_empty());

        // A file that is not this shape is an error, not a silent reset —
        // a monitor that quietly forgot its last checkpoint would quietly
        // stop detecting split views.
        std::fs::write(&path, b"{").unwrap();
        assert!(MonitorState::load(&path).is_err());
    }
}
