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
//! trust — see [`crate::classify::KnownKeys`], whose apexes are also the watch
//! list, which is why a hand-edited entry that is not a domain name is refused
//! rather than left to watch nothing. The **entry bodies** are the evidence:
//! the full log entry behind every report, per log and by index, so "what
//! exactly does the log hold for this report" is a local lookup — the `entry`
//! subcommand — never a re-fetch from the log under watch.
//!
//! The file also records the **trust surface** the run was made under: which
//! DNSSEC anchor set and which log key set the verdicts were computed against.
//! Tier B means "no client holding *these* would have accepted it", so a
//! second run against a different anchor set would be writing verdicts about a
//! different client population into the same memory. That is refused rather
//! than merged.
//!
//! The file is plain JSON on purpose: an operator has to be able to read it,
//! seed it by hand for a zone whose history predates the monitor, and check it
//! into whatever they keep their runbooks in.

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
pub const MAX_STORED_ENTRIES: usize = 1024;

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
    /// [`MAX_STORED_ENTRIES`] per log. An unauthorized claim is something
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
    /// Returns the indices dropped to stay under [`MAX_STORED_ENTRIES`], so
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
    /// this one, and never half of either.
    ///
    /// Write to a temporary, flush it to the device, rename over the target,
    /// then flush the directory. The `fsync` before the rename is what makes
    /// the rename meaningful: without it the directory entry can reach the
    /// device before the bytes do, and a crash in between leaves a file that
    /// exists and is empty — the state a monitor cannot tell from "never read
    /// anything".
    ///
    /// The temporary is unique to this write because two saves over one state
    /// file are an ordinary operator mistake (a cron job that overlaps its
    /// predecessor). One shared `.tmp` name lets them rename each other's
    /// partial bytes over the real file, which is the exact accident the
    /// rename dance exists to prevent. A process id and a clock reading are
    /// not enough on their own: two writes from one process can read the same
    /// nanosecond on a coarse clock, so a sequence number separates them.
    pub fn save(&self, path: &std::path::Path) -> Result<(), MonitorError> {
        use std::io::Write;

        let json =
            serde_json::to_vec_pretty(self).map_err(|e| MonitorError::State(e.to_string()))?;
        let directory = path.parent().unwrap_or(std::path::Path::new("."));
        let temporary = unique_temporary(path);

        let write = |temporary: &std::path::Path| -> std::io::Result<()> {
            let mut file = std::fs::File::create(temporary)?;
            file.write_all(&json)?;
            file.sync_all()
        };
        if let Err(e) = write(&temporary) {
            let _ = std::fs::remove_file(&temporary);
            return Err(MonitorError::State(format!("{}: {e}", temporary.display())));
        }
        if let Err(e) = std::fs::rename(&temporary, path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(MonitorError::State(format!(
                "{} -> {}: {e}",
                temporary.display(),
                path.display()
            )));
        }
        // A directory that cannot be flushed is not a failed save: the bytes
        // are on the device and the rename is in the log. Nothing to say.
        if let Ok(dir) = std::fs::File::open(directory) {
            let _ = dir.sync_all();
        }
        Ok(())
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

/// A temporary path beside `path`, unique to this write.
///
/// A process id and a clock reading are not enough on their own: two writes
/// from one process can read the same nanosecond on a coarse clock, and two
/// saves that agree on a temporary rename each other's partial bytes over the
/// target. The sequence number is what separates them.
fn unique_temporary(path: &std::path::Path) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    temporary_at(path, nanos)
}

/// The naming proper, at a caller-supplied clock reading.
///
/// The reading is a parameter so the uniqueness that does not depend on the
/// clock can be asserted without one: hold `nanos` still and the names must
/// still differ.
fn temporary_at(path: &std::path::Path, nanos: u128) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.{nanos}.{sequence}.tmp", std::process::id()));
    path.with_file_name(name)
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
        *state.position("log2025-1.rekor.example") = LogPosition {
            tree_size: 67_686_055,
            root: "bcae".repeat(16),
            next_index: 67_673_584,
        };
        // A second shard, tracked beside the first rather than instead of it:
        // the client accepts proofs from both, so the monitor follows both.
        *state.position("log2026-1.rekor.example") = LogPosition {
            tree_size: 12,
            root: "0f0f".repeat(16),
            next_index: 12,
        };
        state.known.insert(
            &synch_net::chain::parse_name("sync.example").unwrap(),
            b"a key",
        );
        assert_eq!(state.logs.len(), 2);
        assert!(state
            .record_entry(
                "log2025-1.rekor.example",
                67_673_583,
                b"the full body of the finding's entry",
            )
            .is_empty());
        state.save(&path).unwrap();
        assert_eq!(MonitorState::load(&path).unwrap(), state);
        assert!(!MonitorState::load(&path).unwrap().is_fresh());
        assert_eq!(
            state
                .entry("log2025-1.rekor.example", 67_673_583)
                .unwrap()
                .as_deref(),
            Some(b"the full body of the finding's entry".as_slice())
        );
        // The same index under the other shard is a different entry, and
        // this state holds neither.
        assert_eq!(
            state.entry("log2026-1.rekor.example", 67_673_583).unwrap(),
            None
        );
        assert_eq!(
            state.origins_holding(67_673_583),
            ["log2025-1.rekor.example"]
        );
        assert!(state.origins_holding(1).is_empty());

        // A file that is not this shape is an error, not a silent reset — a
        // monitor that quietly forgot its baseline would quietly stop
        // detecting split views.
        std::fs::write(&path, b"{").unwrap();
        assert!(MonitorState::load(&path).is_err());
    }

    /// The evidence drawer is bounded, and says what it dropped.
    #[test]
    fn the_evidence_drawer_is_bounded_and_reports_what_it_dropped() {
        let mut state = MonitorState::default();
        for index in 0..MAX_STORED_ENTRIES as u64 {
            assert!(state
                .record_entry("log.example", index, b"a body")
                .is_empty());
        }
        assert_eq!(
            state.record_entry("log.example", MAX_STORED_ENTRIES as u64, b"a body"),
            vec![0]
        );
        assert_eq!(state.entries["log.example"].len(), MAX_STORED_ENTRIES);
        assert_eq!(state.entry("log.example", 0).unwrap(), None);
        assert!(state
            .entry("log.example", MAX_STORED_ENTRIES as u64)
            .unwrap()
            .is_some());
    }

    /// Two overlapping saves must not rename each other's partial bytes over
    /// the target: each writes its own temporary, even on a frozen clock.
    #[test]
    fn concurrent_saves_do_not_share_a_temporary_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("monitor.json");
        let mut first = MonitorState::default();
        *first.position("one.example") = LogPosition {
            tree_size: 1,
            root: "11".repeat(32),
            next_index: 1,
        };
        let mut second = MonitorState::default();
        *second.position("two.example") = LogPosition {
            tree_size: 2,
            root: "22".repeat(32),
            next_index: 2,
        };
        std::thread::scope(|scope| {
            scope.spawn(|| first.save(&path).unwrap());
            scope.spawn(|| second.save(&path).unwrap());
        });
        let loaded = MonitorState::load(&path).unwrap();
        // Whichever won, the file is one of the two whole states, not a
        // splice of both.
        assert!(loaded == first || loaded == second, "{loaded:?}");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left, ["monitor.json"]);

        // The uniqueness is pinned directly as well: on a coarse clock two
        // writes can read the same nanosecond, so the names must differ even
        // with the clock held still.
        let frozen = temporary_at(&path, 1_760_000_000);
        assert_ne!(temporary_at(&path, 1_760_000_000), frozen);
    }
}
