//! What a monitor remembers between runs.
//!
//! Two things, and each is load-bearing for a different reason. The **last
//! checkpoint** is what makes split-view detection possible at all: a log that
//! shows this monitor a tree which does not extend the one it showed last time
//! has equivocated, and that is the single strongest thing a monitor can
//! notice on its own. Note the scope — *this* monitor, over time. A log that
//! showed a **different** monitor a different history is invisible from here;
//! catching that needs either cross-witnessing, which this design does not
//! implement, or a second monitor run somewhere else and compared by hand.
//! The **known keys** are what separate tier A from tier B — without a record
//! of which keys the operator has already accepted, every rotation looks like
//! a first sighting.
//!
//! The file is plain JSON on purpose: an operator has to be able to read it,
//! seed it by hand for a zone whose history predates the monitor, and check it
//! into whatever they keep their runbooks in.

use crate::{classify::KnownKeys, MonitorError};

/// The monitor's persisted view of one log.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MonitorState {
    /// The log's origin line, as its checkpoints spell it. A state file that
    /// meets a different origin is a state file for a different log.
    #[serde(default)]
    pub origin: String,
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
    /// The keys this monitor accepts as predecessors, per apex.
    #[serde(default)]
    pub known: KnownKeys,
}

impl MonitorState {
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

    /// Whether this state has ever seen a checkpoint.
    pub fn is_fresh(&self) -> bool {
        self.root.is_empty()
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

        let mut state = MonitorState {
            origin: "log2025-1.rekor.sigstore.dev".into(),
            tree_size: 67_686_055,
            root: "bcae".repeat(16),
            next_index: 67_673_584,
            known: KnownKeys::default(),
        };
        state.known.insert("sync.example.dev", b"a key");
        state.save(&path).unwrap();
        assert_eq!(MonitorState::load(&path).unwrap(), state);
        assert!(!MonitorState::load(&path).unwrap().is_fresh());

        // A file that is not this shape is an error, not a silent reset —
        // a monitor that quietly forgot its last checkpoint would quietly
        // stop detecting split views.
        std::fs::write(&path, b"{").unwrap();
        assert!(MonitorState::load(&path).is_err());
    }
}
