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
    /// The versions in ascending selection order, greatest last.
    ///
    /// `newest` picks the greatest *live* one, which is not always the last:
    /// `select` filters tombstones out of the running and this order does not,
    /// so a deletion dated after every live version sorts last and is still not
    /// what `newest` returns. Tombstones stay in the list because every
    /// surface that shows a version list has to show them.
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
///
/// The kind is carried whole so content-less directories and files remain
/// distinct.
type Identity = (EntryKind, Option<[u8; 32]>, Option<String>);

fn content_of(entry: &EntryRow) -> Option<Hash> {
    match entry.kind {
        EntryKind::Tombstone | EntryKind::Symlink => None,
        _ => entry.content,
    }
}

/// The one derivation, over the three fields any version carries, so an
/// `EntryRow` and a `Version` cannot come to different answers about the same
/// assertion.
fn identity_of(
    kind: EntryKind,
    content: Option<Hash>,
    symlink_target: &Option<String>,
) -> Identity {
    match kind {
        EntryKind::Tombstone => (kind, None, None),
        EntryKind::Symlink => (kind, None, Some(symlink_target.clone().unwrap_or_default())),
        _ => (kind, content.map(|h| *h.as_bytes()), None),
    }
}

fn identity(entry: &EntryRow) -> Identity {
    identity_of(entry.kind, entry.content, &entry.symlink_target)
}

fn identity_of_version(version: &Version) -> Identity {
    identity_of(version.kind, version.content, &version.symlink_target)
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
        let now = self.read_instant()?;
        Ok(VersionSet::from_entries(space, path, entries, now))
    }

    /// The instant a read orders published `mtime_ns` against (§8).
    ///
    /// Not the raw clock. The clamp above exists to stop an inflated stamp
    /// winning forever, but it cuts the other way too: on a reader whose clock
    /// *lags* the cluster, every honest entry stamped above the reading
    /// collapses to it, the primary component ties, and selection falls
    /// through to ordering by content hash. A node restored from a snapshot
    /// then picks the older edit, and a `newest` mirror on it writes different
    /// bytes than every other node, unmarked — and flips back when NTP steps
    /// the clock forward.
    ///
    /// The persisted trust floor only ever rises, so lifting the reading to it
    /// leaves the clamp doing its job against clocks that are ahead while
    /// keeping a lagging one from reordering honest entries. Taken here rather
    /// than through `trust_instant`, which returns an untrusted reading
    /// unchanged so that expiry fails closed — the worst case for selection,
    /// where a clock reading 1970 ties every path in the cluster at once.
    pub fn read_instant(&self) -> Result<i64> {
        Ok(synch_core::now_ns().max(self.trust_floor()?))
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
        let now = self.read_instant()?;
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
    use crate::testutil;
    use synch_core::FileEntry;

    /// A reading clock later than any time these tests publish, so the order clamps nothing except where a test is about the clamp.
    const READ_AT: i64 = i64::MAX;

    fn origin(name: &str) -> OriginId {
        OriginId::named(name, "x.example").unwrap()
    }

    fn put(store: &Store, space: &str, name: &str, path: &str, entry: &FileEntry) {
        store.put_entry(&origin(name), space, path, entry).unwrap();
    }

    fn symlink(target: &str, mtime: i64, seq: u64) -> FileEntry {
        let mut entry = FileEntry::tombstone(mtime, seq, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some(target.to_string());
        entry.size = target.len() as u64;
        entry
    }

    /// Config rows store the rendered policy; the round-trip plus the refusal of a malformed form is the wire-format guard.
    #[test]
    fn policies_round_trip_through_their_text() {
        for text in ["newest", "strict", "origin=nas@x.example", "origin=key:abc"] {
            let parsed: std::result::Result<VersionPolicy, _> = text.parse();
            if text == "origin=key:abc" {
                assert!(
                    parsed.is_err(),
                    "a key that is not a real key is refused rather than stored"
                );
            } else {
                assert_eq!(parsed.unwrap().render(), text);
            }
        }
        assert_eq!(VersionPolicy::default(), VersionPolicy::Newest);
        assert!("".parse::<VersionPolicy>().is_err());
        assert_eq!(
            "origin=nas@x.example"
                .parse::<VersionPolicy>()
                .unwrap()
                .pinned_origin(),
            Some(&origin("nas"))
        );
    }

    /// Three attestors publishing the same bytes collapse into one version; agreement renders as a plain file any policy reads the same.
    #[test]
    fn agreeing_origins_collapse_into_one_version() {
        let (_d, store) = testutil::store();
        let content = Hash::new(b"same");
        for name in ["nas", "laptop", "vps"] {
            put(
                &store,
                "media",
                name,
                "a.txt",
                &FileEntry::file(4, 100, content, 1),
            );
        }
        let set = store.versions_for("media", "a.txt").unwrap();
        assert_eq!(set.version_count(), 1);
        assert!(!set.is_divergent());
        assert!(set.exists());
        assert_eq!(set.versions[0].attestors.len(), 3);
        for policy in [VersionPolicy::Newest, VersionPolicy::Strict] {
            assert_eq!(
                set.select(&policy, READ_AT).entry().unwrap().content,
                Some(content),
                "any policy reads the agreed bytes"
            );
        }
    }

    /// Divergence is visible to the caller, and selection is deterministic: newest takes the greater mtime, a pin reads its side, strict refuses.
    #[test]
    fn divergence_is_visible_and_selection_is_deterministic() {
        let (_d, store) = testutil::store();
        put(
            &store,
            "media",
            "nas",
            "f",
            &FileEntry::file(1, 500, Hash::new(b"theirs"), 9),
        );
        put(
            &store,
            "media",
            "laptop",
            "f",
            &FileEntry::file(1, 100, Hash::new(b"ours"), 2),
        );
        let set = store.versions_for("media", "f").unwrap();
        assert_eq!(set.version_count(), 2);
        assert!(set.is_divergent());
        let selected = set
            .select(&VersionPolicy::Newest, READ_AT)
            .entry()
            .unwrap()
            .clone();
        assert_eq!(
            selected.origin,
            origin("nas"),
            "`newest` takes the greater mtime, identically every time"
        );
        assert_eq!(
            set.select(&VersionPolicy::Origin(origin("laptop")), READ_AT)
                .entry()
                .unwrap()
                .content,
            Some(Hash::new(b"ours")),
            "a pin reads the other side"
        );
        assert_eq!(
            set.select(&VersionPolicy::Strict, READ_AT),
            Selection::Divergent,
            "strict refuses"
        );
        assert_eq!(set.describe().len(), 2);
        assert!(set.describe()[0].contains("nas@x.example"));
        assert_eq!(
            set.select(&VersionPolicy::Origin(origin("vps")), READ_AT),
            Selection::Absent,
            "a pin on an origin that publishes nothing selects nothing"
        );
    }

    /// The order is total: equal mtimes fall through to the content root, and equal roots to the origin — never to iteration order.
    #[test]
    fn the_selection_order_is_total() {
        let (_d, store) = testutil::store();
        for (name, content) in [("a", b"one"), ("b", b"two")] {
            put(
                &store,
                "s",
                name,
                "tied",
                &FileEntry::file(3, 42, Hash::new(content), 1),
            );
        }
        let set = store.versions_for("s", "tied").unwrap();
        assert!(set.is_divergent());
        let winner = set
            .select(&VersionPolicy::Newest, READ_AT)
            .entry()
            .unwrap()
            .clone();
        // Whichever root sorts greater wins, and the answer does not depend
        // on which origin happened to publish first.
        let expected = if Hash::new(b"one").as_bytes() > Hash::new(b"two").as_bytes() {
            origin("a")
        } else {
            origin("b")
        };
        assert_eq!(winner.origin, expected);
        assert_eq!(
            set.versions.last().unwrap().content,
            winner.content,
            "the version list ends with the one `newest` picks"
        );
    }

    /// A tombstone is a content-less version that speaks only for the origin that published it: the path stays visible while any origin is still live, and once every publisher tombstones it — or as soon as a lone publisher deletes it — the path has left the tree (§8).
    #[test]
    fn a_tombstone_removes_only_its_own_origins_version() {
        let (_d, store) = testutil::store();
        let live = Hash::new(b"still here");
        put(
            &store,
            "media",
            "nas",
            "f",
            &FileEntry::file(9, 100, live, 1),
        );
        // A deletion published later than the live version: what an attacker
        // would send, and what an honest late deletion looks like too.
        put(
            &store,
            "media",
            "laptop",
            "f",
            &FileEntry::tombstone(9_000, 2, None),
        );
        let set = store.versions_for("media", "f").unwrap();
        assert_eq!(set.version_count(), 2, "live + tombstone is divergence");
        assert!(set.exists(), "one origin still publishes it");
        let selected = set
            .select(&VersionPolicy::Newest, READ_AT)
            .entry()
            .unwrap()
            .clone();
        assert_eq!(selected.content, Some(live));
        assert_eq!(selected.origin, origin("nas"));
        assert_eq!(
            set.select(&VersionPolicy::Origin(origin("laptop")), READ_AT)
                .entry()
                .unwrap()
                .kind,
            EntryKind::Tombstone,
            "pinned to the deleting origin, the deletion is the answer"
        );
        put(
            &store,
            "media",
            "nas",
            "f",
            &FileEntry::tombstone(9_000, 3, None),
        );
        let set = store.versions_for("media", "f").unwrap();
        assert_eq!(set.version_count(), 1, "tombstones collapse together");
        assert!(!set.exists());
        assert_eq!(
            set.select(&VersionPolicy::Newest, READ_AT),
            Selection::Absent
        );
        assert_eq!(
            set.select(&VersionPolicy::Strict, READ_AT),
            Selection::Absent
        );
    }

    /// Prefix bounding, start_after pagination, limit, and one-row-per-path grouping of the unified listing.
    #[test]
    fn the_unified_listing_paginates_over_paths() {
        let (_d, store) = testutil::store();
        for path in ["a/1", "a/2", "a/3", "b/1"] {
            for name in ["nas", "laptop"] {
                put(
                    &store,
                    "s",
                    name,
                    path,
                    &FileEntry::file(1, 0, Hash::new(name.as_bytes()), 1),
                );
            }
        }
        let all = store.unified_listing("s", "", None, None).unwrap();
        assert_eq!(all.len(), 4, "one row per path, not per origin");
        assert!(all.iter().all(|s| s.is_divergent()));
        assert_eq!(
            store.unified_listing("s", "a/", None, None).unwrap().len(),
            3
        );
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

    /// §8: a content-less kind's version identity is (kind, target): different targets diverge, the same target agrees.
    #[test]
    fn two_symlinks_with_different_targets_are_two_versions() {
        let (_d, store) = testutil::store();
        put(&store, "media", "nas", "link", &symlink("../a", 100, 1));
        put(&store, "media", "laptop", "link", &symlink("../b", 200, 1));
        let set = store.versions_for("media", "link").unwrap();
        assert_eq!(set.version_count(), 2);
        assert!(set.is_divergent(), "different targets diverge");
        let described = set.describe().join(" | ");
        assert!(
            described.contains("-> ../a") && described.contains("-> ../b"),
            "{described}"
        );
        assert_eq!(
            set.select(&VersionPolicy::Newest, READ_AT)
                .entry()
                .unwrap()
                .symlink_target
                .as_deref(),
            Some("../b"),
            "the newest mtime still selects deterministically"
        );
        // The same target agrees: one version, two attestors.
        let (_d2, store) = testutil::store();
        for name in ["nas", "laptop"] {
            put(&store, "media", name, "link", &symlink("../a", 100, 1));
        }
        let set = store.versions_for("media", "link").unwrap();
        assert_eq!(set.version_count(), 1);
        assert!(!set.is_divergent());
        assert_eq!(set.versions[0].attestors.len(), 2);
        assert!(set.versions[0].is_symlink());
    }

    /// Kind is part of the version key: a link and a file never collapse, and selection flips deterministically when the link overtakes.
    #[test]
    fn a_symlink_is_never_the_same_version_as_a_file() {
        let (_d, store) = testutil::store();
        put(&store, "media", "nas", "x", &symlink("../a", 100, 1));
        put(
            &store,
            "media",
            "laptop",
            "x",
            &FileEntry::file(3, 200, Hash::new(b"bytes"), 1),
        );
        let set = store.versions_for("media", "x").unwrap();
        assert_eq!(set.version_count(), 2);
        assert!(set.is_divergent());
        assert_eq!(
            set.select(&VersionPolicy::Newest, READ_AT)
                .entry()
                .unwrap()
                .kind,
            EntryKind::File,
            "the newer file wins"
        );
        put(&store, "media", "nas", "x", &symlink("../a", 300, 2));
        let set = store.versions_for("media", "x").unwrap();
        assert_eq!(
            set.select(&VersionPolicy::Newest, READ_AT)
                .entry()
                .unwrap()
                .kind,
            EntryKind::Symlink,
            "and with the link newer, the link wins"
        );
    }

    /// A version dated in the future orders as of now: `mtime_ns` is a member's own assertion, so an unbounded stamp would sit above every entry ever published, permanently — clamped to the reader's clock it claims the present instant and no more (§8).
    #[test]
    fn a_version_dated_in_the_future_orders_as_of_now() {
        let (_d, store) = testutil::store();
        let dated_ahead = FileEntry::file(9, i64::MAX, Hash::new(b"c"), 1);
        put(&store, "media", "liar", "f", &dated_ahead);
        put(
            &store,
            "media",
            "nas",
            "f",
            &FileEntry::file(9, 1_000, Hash::new(b"ours"), 1),
        );
        // The leaf is stored as published — the clamp is a reading-time fact.
        assert_eq!(
            store
                .versions_for("media", "f")
                .unwrap()
                .entries
                .iter()
                .find(|e| e.origin == origin("liar"))
                .unwrap()
                .mtime_ns,
            i64::MAX
        );
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
    }

    /// A reader whose clock lags the cluster still selects the newer edit. The clamp bounds an inflated stamp, but a raw local clock cuts the other way: honest entries stamped above the reading collapse to it, the primary component ties, and selection falls through to the content hash — so a snapshot-restored node would pick the *older* edit. The trust floor is the persisted, monotonic record of how far the cluster has got: a floor ahead of the local clock is exactly that shape.
    #[test]
    fn a_lagging_reader_still_selects_the_newer_edit() {
        let (_d, store) = testutil::store();
        let now = synch_core::now_ns();
        // Twelve hours ahead, inside the step the floor will accept.
        let ahead = now + 12 * 3_600 * 1_000_000_000;
        store.advance_trust_floor(ahead).unwrap();
        let (a, b) = (Hash::new(b"a"), Hash::new(b"b"));
        let (older, newer) = if a > b { (a, b) } else { (b, a) };
        put(
            &store,
            "media",
            "alpha",
            "f",
            &FileEntry::file(9, ahead - 7_200_000_000_000, older, 1),
        );
        put(
            &store,
            "media",
            "bravo",
            "f",
            &FileEntry::file(9, ahead - 3_600_000_000_000, newer, 1),
        );
        let set = store.versions_for("media", "f").unwrap();
        let selected = set
            .select(&VersionPolicy::Newest, store.read_instant().unwrap())
            .entry()
            .expect("a version is selected")
            .clone();
        assert_eq!(
            selected.origin,
            origin("bravo"),
            "the older edit won: honest mtimes tied against a lagging clock"
        );
    }
}
