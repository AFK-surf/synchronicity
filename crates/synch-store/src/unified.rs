//! The unified tree: version sets, version policies, and selection (§8).
//!
//! What the system stores and syncs is unchanged — per-origin single-writer
//! tries, replicated whole. The unified tree is a *derived view* of `entries`
//! grouped by `(space, path)`: one hierarchy in which each path carries one
//! version per distinct content root published for it, with the origins
//! asserting that root as its attestors.
//!
//! Nothing here writes. Selection is presentation, not resolution: it picks
//! which version a read returns and leaves every assertion exactly as its
//! origin published it. Resolution only ever happens by a node adopting a
//! version as its own (`synch take`).

use std::str::FromStr;

use rusqlite::params;
use synch_core::{EntryKind, Hash, OriginId};

use crate::{
    db::Store,
    error::{Result, StoreError},
    views::EntryRow,
};

/// Which version of a path a reading surface takes (§8).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum VersionPolicy {
    /// The greatest `(mtime_ns, content_root, origin)` — a total order, so
    /// every node selects the same version from the same assertions.
    #[default]
    Newest,
    /// Pin to one origin's view: exactly what that origin publishes, or
    /// nothing.
    Origin(OriginId),
    /// Refuse to read a divergent path, and hand back the version list
    /// instead.
    Strict,
}

impl VersionPolicy {
    /// The stored and command-line spelling: `newest`, `origin=<id>`, `strict`.
    pub fn render(&self) -> String {
        match self {
            VersionPolicy::Newest => "newest".to_string(),
            VersionPolicy::Origin(origin) => format!("origin={}", origin.canonical()),
            VersionPolicy::Strict => "strict".to_string(),
        }
    }

    /// The origin this policy pins to, if it pins one.
    pub fn pinned_origin(&self) -> Option<&OriginId> {
        match self {
            VersionPolicy::Origin(origin) => Some(origin),
            _ => None,
        }
    }
}

impl std::fmt::Display for VersionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

impl FromStr for VersionPolicy {
    type Err = StoreError;

    fn from_str(text: &str) -> Result<VersionPolicy> {
        match text.trim() {
            "newest" => Ok(VersionPolicy::Newest),
            "strict" => Ok(VersionPolicy::Strict),
            other => match other.strip_prefix("origin=") {
                Some(origin) => OriginId::from_str(origin)
                    .map(VersionPolicy::Origin)
                    .map_err(|e| StoreError::invalid(format!("policy origin: {e}"))),
                None => Err(StoreError::invalid(format!(
                    "{other:?} is not a version policy: use newest, origin=<id>, or strict"
                ))),
            },
        }
    }
}

/// One version of a path: a distinct assertion identity, and everyone
/// asserting it.
///
/// Identity is the content root for regular files, and the pair
/// `(kind, target)` for content-less kinds (§8): two symlinks are the same
/// version iff their targets match, and a symlink is never the same version as
/// a file. Origins asserting the same identity collapse into one version with
/// several attestors — agreement is the common case, and it renders as a plain
/// file. A tombstone is a content-less version ("deleted at seq N").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// The content root, or `None` for content-less kinds.
    pub content: Option<Hash>,
    /// What the entries describe. Part of the version's identity, so a
    /// symlink and a file at one path are two versions, not one.
    pub kind: EntryKind,
    /// The link target, when this version is a symlink. The other half of a
    /// content-less kind's identity.
    pub symlink_target: Option<String>,
    /// The content length.
    pub size: u64,
    /// The greatest mtime any attestor published for it.
    pub mtime_ns: i64,
    /// The greatest seq any attestor published it at.
    pub seq: u64,
    /// Every origin currently asserting this version, canonically ordered.
    pub attestors: Vec<OriginId>,
}

impl Version {
    /// True if this is the content-less deletion version.
    pub fn is_tombstone(&self) -> bool {
        self.kind == EntryKind::Tombstone
    }

    /// True if this version is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.kind == EntryKind::Symlink
    }

    /// How this version names itself in a listing: a content root, a link
    /// target, or the deletion marker.
    pub fn identity_text(&self) -> String {
        match self.kind {
            EntryKind::Tombstone => "(deleted)".to_string(),
            EntryKind::Symlink => format!(
                "-> {}",
                self.symlink_target.as_deref().unwrap_or("(unknown target)")
            ),
            _ => self
                .content
                .map(|h| h.to_hex().to_string())
                .unwrap_or_else(|| "(no content)".into()),
        }
    }
}

/// Every version of one path, and the entries behind them (§8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSet {
    /// The space.
    pub space: String,
    /// The path within the space.
    pub path: String,
    /// The versions, in selection order: the version `newest` would pick last.
    pub versions: Vec<Version>,
    /// Every origin's entry for the path, canonically ordered.
    pub entries: Vec<EntryRow>,
}

impl VersionSet {
    /// Groups one path's entries into its versions.
    ///
    /// `entries` must all name the same `(space, path)`. `now` is the reader's
    /// clock, which is what a published `mtime_ns` is ordered under; it is
    /// never stored.
    pub fn from_entries(
        space: &str,
        path: &str,
        mut entries: Vec<EntryRow>,
        now: i64,
    ) -> VersionSet {
        entries.sort_by_key(|entry| entry.origin.canonical());
        let mut versions: Vec<Version> = Vec::new();
        for entry in &entries {
            let key = identity(entry);
            match versions.iter_mut().find(|v| identity_of_version(v) == key) {
                Some(version) => {
                    version.mtime_ns = version.mtime_ns.max(entry.mtime_ns);
                    version.seq = version.seq.max(entry.seq);
                    version.attestors.push(entry.origin.clone());
                }
                None => versions.push(Version {
                    content: content_of(entry),
                    kind: entry.kind,
                    symlink_target: entry.symlink_target.clone(),
                    size: entry.size,
                    mtime_ns: entry.mtime_ns,
                    seq: entry.seq,
                    attestors: vec![entry.origin.clone()],
                }),
            }
        }
        versions.sort_by_key(|version| version_key(version, now));
        VersionSet {
            space: space.to_string(),
            path: path.to_string(),
            versions,
            entries,
        }
    }

    /// How many versions the path carries.
    pub fn version_count(&self) -> usize {
        self.versions.len()
    }

    /// True if two or more versions exist. Divergence is data, not an error.
    pub fn is_divergent(&self) -> bool {
        self.versions.len() > 1
    }

    /// True if the path exists in the unified tree: at least one origin
    /// currently publishes a live (non-tombstone) entry for it (§8).
    pub fn exists(&self) -> bool {
        self.versions.iter().any(|v| !v.is_tombstone())
    }

    /// Applies a version policy (§8).
    ///
    /// Never writes and never merges: it picks one of the assertions, or
    /// refuses. `now` is the reader's clock, which the order clamps published
    /// times against.
    ///
    /// A tombstone is one origin's assertion about *its own* copy, so under the
    /// unified policies it takes that origin's version out of consideration
    /// rather than the path: §8's rule is that a path exists in the tree iff at
    /// least one origin currently publishes a live entry for it, and that the
    /// path stays visible until every publisher tombstones it. Pinned to an
    /// origin the deletion is the answer — that mirror follows one origin's
    /// view, deletions included.
    pub fn select(&self, policy: &VersionPolicy, now: i64) -> Selection {
        match policy {
            VersionPolicy::Origin(origin) => {
                match self.entries.iter().find(|e| &e.origin == origin) {
                    Some(entry) => Selection::Selected(Box::new(entry.clone())),
                    None => Selection::Absent,
                }
            }
            VersionPolicy::Strict if self.is_divergent() => Selection::Divergent,
            VersionPolicy::Strict | VersionPolicy::Newest => {
                match self
                    .entries
                    .iter()
                    .filter(|entry| entry.kind != EntryKind::Tombstone)
                    .max_by(|a, b| entry_key(a, now).cmp(&entry_key(b, now)))
                {
                    Some(entry) => Selection::Selected(Box::new(entry.clone())),
                    None => Selection::Absent,
                }
            }
        }
    }

    /// The versions rendered one per line, for an error body or a report.
    pub fn describe(&self) -> Vec<String> {
        self.versions
            .iter()
            .rev()
            .map(|version| {
                let attestors: Vec<String> =
                    version.attestors.iter().map(|o| o.to_string()).collect();
                format!(
                    "{} size {} mtime {} seq {} asserted by {}",
                    version.identity_text(),
                    version.size,
                    version.mtime_ns,
                    version.seq,
                    attestors.join(", ")
                )
            })
            .collect()
    }
}

/// What applying a policy to a version set produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// The policy chose this origin's assertion.
    ///
    /// Boxed because it is by far the largest variant and the other two carry
    /// nothing: every `Absent` and `Divergent` would otherwise pay for a whole
    /// entry row.
    Selected(Box<EntryRow>),
    /// Nothing to select: the path has no entries, or the pinned origin
    /// publishes none for it.
    Absent,
    /// `strict` refused a divergent path; the caller reports the versions.
    Divergent,
}

impl Selection {
    /// The selected entry, if the policy chose one.
    pub fn entry(&self) -> Option<&EntryRow> {
        match self {
            Selection::Selected(entry) => Some(entry),
            _ => None,
        }
    }
}

/// A version's identity as §8 defines it: the content root for regular files,
/// the pair `(kind, target)` for content-less kinds.
///
/// Tombstones all collapse into one version whatever else they carry — a
/// deletion is a deletion. A symlink is identified by its target and can never
/// coincide with a file, because the kind is part of the key.
type Identity = (bool, Option<[u8; 32]>, Option<String>);

fn content_of(entry: &EntryRow) -> Option<Hash> {
    match entry.kind {
        EntryKind::Tombstone | EntryKind::Symlink => None,
        _ => entry.content,
    }
}

fn identity(entry: &EntryRow) -> Identity {
    match entry.kind {
        EntryKind::Tombstone => (true, None, None),
        EntryKind::Symlink => (
            false,
            None,
            Some(entry.symlink_target.clone().unwrap_or_default()),
        ),
        _ => (false, entry.content.map(|h| *h.as_bytes()), None),
    }
}

fn identity_of_version(version: &Version) -> Identity {
    match version.kind {
        EntryKind::Tombstone => (true, None, None),
        EntryKind::Symlink => (
            false,
            None,
            Some(version.symlink_target.clone().unwrap_or_default()),
        ),
        _ => (false, version.content.map(|h| *h.as_bytes()), None),
    }
}

/// The deterministic total order `newest` maximizes: `(mtime_ns, content_root,
/// symlink target, origin)` (§8), with the published time read as no later than
/// now.
///
/// Every component is data every node holds identically, so the same assertions
/// select the same version everywhere. The content root breaks mtime ties; the
/// target breaks ties between content-less kinds, which §8 identifies by
/// `(kind, target)` and which would otherwise be indistinguishable to the order
/// while being distinct versions; and the canonical origin breaks the remaining
/// tie between two attestors of the same version — which one is named as the
/// source of the bytes, never which bytes.
///
/// `mtime_ns` is a member's own assertion and any member may publish
/// `f:<space>/<path>` for any space, so read as of now the most a stamp can
/// claim is the present instant — exactly the claim an honest publish makes.
/// An unbounded one would sit above every entry that will ever be published,
/// for every path, permanently; bounded, it wins no more than publishing right
/// now would, and what it wins is one round of a contest the rest of the key
/// settles.
///
/// Clamped here rather than on the way in, because the row is the leaf: the
/// same trie has to materialize identically on every node and after a rebuild,
/// so the time-dependence belongs to the reading and not to the data.
fn entry_key(entry: &EntryRow, now: i64) -> (i64, Option<[u8; 32]>, Option<String>, String) {
    let (_, content, target) = identity(entry);
    (
        entry.mtime_ns.min(now),
        content,
        target,
        entry.origin.canonical(),
    )
}

/// The same order at version granularity, for presenting a version list.
fn version_key(version: &Version, now: i64) -> (i64, Option<[u8; 32]>, Option<String>, String) {
    let (_, content, target) = identity_of_version(version);
    (
        version.mtime_ns.min(now),
        content,
        target,
        version
            .attestors
            .iter()
            .map(|o| o.canonical())
            .max()
            .unwrap_or_default(),
    )
}

impl Store {
    /// Every version of one path (§8).
    ///
    /// The reader's clock is taken here, once: it bounds how a published
    /// `mtime_ns` orders and is never written down.
    pub fn versions_for(&self, space: &str, path: &str) -> Result<VersionSet> {
        let entries = self.entries_for_path(space, path)?;
        Ok(VersionSet::from_entries(
            space,
            path,
            entries,
            synch_core::now_ns(),
        ))
    }

    /// The unified listing under a prefix: one version set per path, ordered by
    /// path and paginated for `synch ls` and `ListObjectsV2`.
    ///
    /// Tombstone-only paths are included — they have left the tree (`exists()`
    /// is false) but a materializing caller still has to see that they did.
    pub fn unified_listing(
        &self,
        space: &str,
        prefix: &str,
        start_after: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<VersionSet>> {
        let paths = self.unified_paths(space, prefix, start_after, limit)?;
        let (Some(first), Some(last)) = (paths.first(), paths.last()) else {
            return Ok(Vec::new());
        };
        // One query for the whole window: the paths are contiguous in path
        // order, so their bounds select exactly them.
        let rows = self.query_entries(
            "WHERE space = ?1 AND path >= ?2 AND path <= ?3 ORDER BY path, origin_id",
            params![space, first, last],
        )?;

        // One clock reading for the whole listing, so every path in it orders
        // its versions against the same instant.
        let now = synch_core::now_ns();
        let mut out: Vec<VersionSet> = Vec::new();
        let mut current: Vec<EntryRow> = Vec::new();
        for row in rows {
            if current.first().is_some_and(|f| f.path != row.path) {
                let path = current[0].path.clone();
                out.push(VersionSet::from_entries(
                    space,
                    &path,
                    std::mem::take(&mut current),
                    now,
                ));
            }
            current.push(row);
        }
        if let Some(first) = current.first() {
            let path = first.path.clone();
            out.push(VersionSet::from_entries(space, &path, current, now));
        }
        Ok(out)
    }

    /// The distinct paths of the unified tree under a prefix, for pagination.
    pub fn unified_paths(
        &self,
        space: &str,
        prefix: &str,
        start_after: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut sql = String::from(
            "SELECT DISTINCT path FROM entries
             WHERE space = ?1 AND path >= ?2",
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> =
            vec![Box::new(space.to_string()), Box::new(prefix.to_string())];
        // The prefix's byte successor bounds the scan from above, so the index
        // is walked over the prefix's range alone.
        if let Some(upper) = crate::views::prefix_upper_bound(prefix) {
            args.push(Box::new(upper));
            sql.push_str(&format!(" AND path < ?{}", args.len()));
        }
        if let Some(after) = start_after {
            args.push(Box::new(after.to_string()));
            sql.push_str(&format!(" AND path > ?{}", args.len()));
        }
        sql.push_str(" ORDER BY path");
        if let Some(limit) = limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }
        let mut stmt = conn.prepare(&sql)?;
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(refs.as_slice(), |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_core::FileEntry;

    /// A reading clock later than any time these tests publish, so the order
    /// clamps nothing except where a test is about the clamp.
    const READ_AT: i64 = i64::MAX;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).unwrap();
        (dir, s)
    }

    fn origin(name: &str) -> OriginId {
        OriginId::named(name, "x.example").unwrap()
    }

    #[test]
    fn policies_round_trip_through_their_text() {
        for text in ["newest", "strict", "origin=nas@x.example", "origin=key:abc"] {
            if text == "origin=key:abc" {
                // Not a real key, so it must be refused rather than stored.
                assert!(text.parse::<VersionPolicy>().is_err());
                continue;
            }
            let policy: VersionPolicy = text.parse().unwrap();
            assert_eq!(policy.render(), text);
        }
        assert_eq!(VersionPolicy::default(), VersionPolicy::Newest);
        assert!("origin".parse::<VersionPolicy>().is_err());
        assert!("".parse::<VersionPolicy>().is_err());
        assert_eq!(
            "origin=nas@x.example"
                .parse::<VersionPolicy>()
                .unwrap()
                .pinned_origin(),
            Some(&origin("nas"))
        );
    }

    #[test]
    fn agreeing_origins_collapse_into_one_version() {
        let (_d, store) = store();
        let content = Hash::new(b"same");
        for name in ["nas", "laptop", "vps"] {
            store
                .put_entry(
                    &origin(name),
                    "media",
                    "a.txt",
                    &FileEntry::file(4, 100, content, 1),
                )
                .unwrap();
        }
        let set = store.versions_for("media", "a.txt").unwrap();
        assert_eq!(set.version_count(), 1);
        assert!(!set.is_divergent());
        assert!(set.exists());
        assert_eq!(set.versions[0].attestors.len(), 3);
        // Agreement renders as a plain file: any policy reads the same bytes.
        for policy in [VersionPolicy::Newest, VersionPolicy::Strict] {
            let selected = set.select(&policy, READ_AT).entry().unwrap().clone();
            assert_eq!(selected.content, Some(content));
        }
    }

    #[test]
    fn divergence_is_visible_and_selection_is_deterministic() {
        let (_d, store) = store();
        store
            .put_entry(
                &origin("nas"),
                "media",
                "f",
                &FileEntry::file(1, 500, Hash::new(b"theirs"), 9),
            )
            .unwrap();
        store
            .put_entry(
                &origin("laptop"),
                "media",
                "f",
                &FileEntry::file(1, 100, Hash::new(b"ours"), 2),
            )
            .unwrap();

        let set = store.versions_for("media", "f").unwrap();
        assert_eq!(set.version_count(), 2);
        assert!(set.is_divergent());

        // `newest` takes the greater mtime, and says so identically every time.
        let selected = set
            .select(&VersionPolicy::Newest, READ_AT)
            .entry()
            .unwrap()
            .clone();
        assert_eq!(selected.origin, origin("nas"));
        for _ in 0..5 {
            assert_eq!(
                set.select(&VersionPolicy::Newest, READ_AT)
                    .entry()
                    .unwrap()
                    .origin,
                origin("nas")
            );
        }
        // A pin reads the other side.
        assert_eq!(
            set.select(&VersionPolicy::Origin(origin("laptop")), READ_AT)
                .entry()
                .unwrap()
                .content,
            Some(Hash::new(b"ours"))
        );
        // Strict refuses, and the version list is what the caller reports.
        assert_eq!(
            set.select(&VersionPolicy::Strict, READ_AT),
            Selection::Divergent
        );
        assert_eq!(set.describe().len(), 2);
        assert!(set.describe()[0].contains("nas@x.example"));
        // A pin on an origin that publishes nothing here selects nothing.
        assert_eq!(
            set.select(&VersionPolicy::Origin(origin("vps")), READ_AT),
            Selection::Absent
        );
    }

    /// The order is total: equal mtimes fall through to the content root, and
    /// equal roots to the origin — never to iteration order.
    #[test]
    fn the_selection_order_is_total() {
        let (_d, store) = store();
        for (name, content) in [("a", b"one"), ("b", b"two")] {
            store
                .put_entry(
                    &origin(name),
                    "s",
                    "tied",
                    &FileEntry::file(3, 42, Hash::new(content), 1),
                )
                .unwrap();
        }
        let set = store.versions_for("s", "tied").unwrap();
        assert!(set.is_divergent());
        let winner = set
            .select(&VersionPolicy::Newest, READ_AT)
            .entry()
            .unwrap()
            .clone();
        // Whichever root sorts greater wins, and the answer does not depend on
        // which origin happened to publish first.
        let expected = if Hash::new(b"one").as_bytes() > Hash::new(b"two").as_bytes() {
            origin("a")
        } else {
            origin("b")
        };
        assert_eq!(winner.origin, expected);
        // The presented order agrees with the selection.
        assert_eq!(
            set.versions.last().unwrap().content,
            winner.content,
            "the version list ends with the one `newest` picks"
        );
    }

    #[test]
    fn a_tombstone_is_a_content_less_version() {
        let (_d, store) = store();
        store
            .put_entry(
                &origin("nas"),
                "s",
                "f",
                &FileEntry::file(1, 100, Hash::new(b"live"), 1),
            )
            .unwrap();
        store
            .put_entry(
                &origin("laptop"),
                "s",
                "f",
                &FileEntry::tombstone(200, 3, None),
            )
            .unwrap();

        let set = store.versions_for("s", "f").unwrap();
        assert_eq!(set.version_count(), 2, "live + tombstone is divergence");
        assert!(set.exists(), "the path stays visible until it is resolved");
        // The deletion speaks for the origin that published it, so `newest`
        // reads the version that is still live (§8).
        let selected = set
            .select(&VersionPolicy::Newest, READ_AT)
            .entry()
            .unwrap()
            .clone();
        assert_eq!(selected.kind, EntryKind::File);
        assert_eq!(selected.origin, origin("nas"));

        // Once every publisher tombstones it, the path has left the tree.
        store
            .put_entry(
                &origin("nas"),
                "s",
                "f",
                &FileEntry::tombstone(300, 4, None),
            )
            .unwrap();
        let set = store.versions_for("s", "f").unwrap();
        assert_eq!(set.version_count(), 1, "tombstones collapse together");
        assert!(!set.exists());
    }

    #[test]
    fn the_unified_listing_paginates_over_paths() {
        let (_d, store) = store();
        for path in ["a/1", "a/2", "a/3", "b/1"] {
            for name in ["nas", "laptop"] {
                store
                    .put_entry(
                        &origin(name),
                        "s",
                        path,
                        &FileEntry::file(1, 0, Hash::new(name.as_bytes()), 1),
                    )
                    .unwrap();
            }
        }
        let all = store.unified_listing("s", "", None, None).unwrap();
        assert_eq!(all.len(), 4, "one row per path, not per origin");
        assert!(all.iter().all(|s| s.is_divergent()));

        let under_a = store.unified_listing("s", "a/", None, None).unwrap();
        assert_eq!(under_a.len(), 3);

        let page = store.unified_listing("s", "a/", None, Some(2)).unwrap();
        assert_eq!(
            page.iter().map(|s| s.path.as_str()).collect::<Vec<_>>(),
            vec!["a/1", "a/2"]
        );
        let rest = store.unified_listing("s", "a/", Some("a/2"), None).unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].path, "a/3");
        assert!(store
            .unified_listing("s", "zz", None, None)
            .unwrap()
            .is_empty());
    }

    fn symlink(target: &str, mtime: i64, seq: u64) -> FileEntry {
        let mut entry = FileEntry::tombstone(mtime, seq, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some(target.to_string());
        entry.size = target.len() as u64;
        entry
    }

    #[test]
    fn two_symlinks_with_different_targets_are_two_versions() {
        // §8: a content-less kind's version identity is (kind, target).
        let (_d, store) = store();
        store
            .put_entry(&origin("nas"), "media", "link", &symlink("../a", 100, 1))
            .unwrap();
        store
            .put_entry(&origin("laptop"), "media", "link", &symlink("../b", 200, 1))
            .unwrap();

        let set = store.versions_for("media", "link").unwrap();
        assert_eq!(set.version_count(), 2);
        assert!(set.is_divergent(), "different targets diverge");
        let described = set.describe().join(" | ");
        assert!(described.contains("-> ../a"), "{described}");
        assert!(described.contains("-> ../b"), "{described}");

        // The newest mtime still selects deterministically.
        let selected = set.select(&VersionPolicy::Newest, READ_AT);
        assert_eq!(
            selected.entry().unwrap().symlink_target.as_deref(),
            Some("../b")
        );
    }

    #[test]
    fn symlinks_with_the_same_target_agree() {
        let (_d, store) = store();
        for name in ["nas", "laptop"] {
            store
                .put_entry(&origin(name), "media", "link", &symlink("../a", 100, 1))
                .unwrap();
        }
        let set = store.versions_for("media", "link").unwrap();
        assert_eq!(set.version_count(), 1);
        assert!(!set.is_divergent());
        assert_eq!(set.versions[0].attestors.len(), 2);
        assert!(set.versions[0].is_symlink());
    }

    #[test]
    fn a_symlink_is_never_the_same_version_as_a_file() {
        let (_d, store) = store();
        store
            .put_entry(&origin("nas"), "media", "x", &symlink("../a", 100, 1))
            .unwrap();
        store
            .put_entry(
                &origin("laptop"),
                "media",
                "x",
                &FileEntry::file(3, 200, Hash::new(b"bytes"), 1),
            )
            .unwrap();
        let set = store.versions_for("media", "x").unwrap();
        assert_eq!(set.version_count(), 2);
        assert!(set.is_divergent());

        // Selection runs on the real mtimes both sides published, so every
        // node picks the same side: the file here, which is newer.
        let selected = set.select(&VersionPolicy::Newest, READ_AT);
        assert_eq!(selected.entry().unwrap().kind, EntryKind::File);

        // And with the link newer, the link wins — deterministically, and not
        // because a scan happened to restate it.
        store
            .put_entry(&origin("nas"), "media", "x", &symlink("../a", 300, 2))
            .unwrap();
        let set = store.versions_for("media", "x").unwrap();
        assert_eq!(
            set.select(&VersionPolicy::Newest, READ_AT)
                .entry()
                .unwrap()
                .kind,
            EntryKind::Symlink
        );
    }

    /// A tombstone speaks for its own origin's copy, not for the path (§8).
    ///
    /// The unified tree merges assertions from every member by `(space, path)`,
    /// so a deletion that removed the path outright would let any member delete
    /// any file from every `newest` reader in the cluster. §8's rule is that a
    /// path exists while at least one origin publishes a live entry for it, and
    /// stays visible until every publisher tombstones it.
    #[test]
    fn a_tombstone_removes_only_its_own_origins_version() {
        let (_d, store) = store();
        let live = Hash::new(b"still here");
        store
            .put_entry(
                &origin("nas"),
                "media",
                "f",
                &FileEntry::file(9, 100, live, 1),
            )
            .unwrap();
        // A deletion published later than the live version, which is what an
        // attacker would send and what an honest late deletion looks like too.
        store
            .put_entry(
                &origin("laptop"),
                "media",
                "f",
                &FileEntry::tombstone(9_000, 2, None),
            )
            .unwrap();

        let set = store.versions_for("media", "f").unwrap();
        assert!(set.exists(), "one origin still publishes it");
        let selected = set
            .select(&VersionPolicy::Newest, READ_AT)
            .entry()
            .unwrap()
            .clone();
        assert_eq!(selected.content, Some(live));
        assert_eq!(selected.origin, origin("nas"));

        // Pinned to the origin that deleted it, the deletion is the answer.
        let pinned = set.select(&VersionPolicy::Origin(origin("laptop")), READ_AT);
        assert_eq!(pinned.entry().unwrap().kind, EntryKind::Tombstone);

        // Once every publisher has deleted it, the path is gone for everyone.
        store
            .put_entry(
                &origin("nas"),
                "media",
                "f",
                &FileEntry::tombstone(9_000, 3, None),
            )
            .unwrap();
        let set = store.versions_for("media", "f").unwrap();
        assert!(!set.exists());
        assert_eq!(
            set.select(&VersionPolicy::Newest, READ_AT),
            Selection::Absent
        );
    }

    /// One origin publishing alone reads exactly as it always did.
    #[test]
    fn a_lone_origins_tombstone_still_empties_the_path() {
        let (_d, store) = store();
        store
            .put_entry(
                &origin("nas"),
                "media",
                "f",
                &FileEntry::file(9, 100, Hash::new(b"c"), 1),
            )
            .unwrap();
        assert!(store
            .versions_for("media", "f")
            .unwrap()
            .select(&VersionPolicy::Newest, READ_AT)
            .entry()
            .is_some());

        store
            .put_entry(
                &origin("nas"),
                "media",
                "f",
                &FileEntry::tombstone(200, 2, None),
            )
            .unwrap();
        let set = store.versions_for("media", "f").unwrap();
        assert!(!set.exists());
        assert_eq!(
            set.select(&VersionPolicy::Newest, READ_AT),
            Selection::Absent
        );
        assert_eq!(
            set.select(&VersionPolicy::Strict, READ_AT),
            Selection::Absent
        );
        // The pinned view still sees the deletion itself.
        assert_eq!(
            set.select(&VersionPolicy::Origin(origin("nas")), READ_AT)
                .entry()
                .unwrap()
                .kind,
            EntryKind::Tombstone
        );
    }

    /// What a node materializes is the leaf, not the leaf plus its clock.
    ///
    /// Every component of the selection order has to be data every node holds
    /// identically, or two nodes materializing the same trie at different times
    /// select different versions — and `doctor --rebuild` changes the answer
    /// again.
    #[test]
    fn a_leaf_materializes_to_the_same_row_whatever_the_clock_says() {
        let (_d, store) = store();
        let dated_ahead = FileEntry::file(9, i64::MAX, Hash::new(b"c"), 1);
        store
            .put_entry(&origin("nas"), "media", "f", &dated_ahead)
            .unwrap();
        let row = store.versions_for("media", "f").unwrap().entries[0].clone();
        assert_eq!(row.mtime_ns, i64::MAX, "the leaf is stored as published");

        // Materialized again — a rebuild, or another node — it is the same row.
        store
            .put_entry(&origin("nas"), "media", "f", &dated_ahead)
            .unwrap();
        assert_eq!(
            store.versions_for("media", "f").unwrap().entries[0],
            row,
            "and the second materialization agrees with the first"
        );
    }

    /// A version dated in the future orders as of now.
    ///
    /// `mtime_ns` is a member's own assertion and any member may publish for
    /// any space, so an unbounded stamp would sit above every entry that will
    /// ever be published, for every path, permanently. Read against the
    /// reader's clock it claims the present instant and no more — the same
    /// claim an honest publish at this instant makes, settled by the rest of
    /// the order rather than by a number nothing can reach.
    #[test]
    fn a_version_dated_in_the_future_orders_as_of_now() {
        let (_d, store) = store();
        store
            .put_entry(
                &origin("liar"),
                "media",
                "f",
                &FileEntry::file(9, i64::MAX, Hash::new(b"theirs"), 1),
            )
            .unwrap();
        store
            .put_entry(
                &origin("nas"),
                "media",
                "f",
                &FileEntry::file(9, 1_000, Hash::new(b"ours"), 1),
            )
            .unwrap();

        let now = 2_000;
        let set = store.versions_for("media", "f").unwrap();
        let key_of = |name: &str| {
            let entry = set
                .entries
                .iter()
                .find(|e| e.origin == origin(name))
                .expect("the entry");
            entry_key(entry, now)
        };
        assert_eq!(key_of("liar").0, now, "read as of now, never past it");
        assert_eq!(key_of("nas").0, 1_000, "an honest stamp is left alone");

        // Republished at this instant, the honest entry is its equal: what the
        // inflated stamp bought is nothing the publisher could not have had.
        store
            .put_entry(
                &origin("nas"),
                "media",
                "f",
                &FileEntry::file(9, now, Hash::new(b"ours"), 2),
            )
            .unwrap();
        let set = store.versions_for("media", "f").unwrap();
        let key_of = |name: &str| {
            let entry = set
                .entries
                .iter()
                .find(|e| e.origin == origin(name))
                .expect("the entry");
            entry_key(entry, now)
        };
        assert_eq!(key_of("liar").0, key_of("nas").0);
    }
}
