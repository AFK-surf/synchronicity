//! Continuous read-only materialization of the unified tree (§7.2, §8).
//!
//! A mirror is a local directory, a space, and a version policy. Every pass
//! writes the policy-selected version of every path the unified tree carries
//! for that space — so a mirror follows the tree rather than one origin, and
//! `strict` skips divergent paths and reports them rather than guessing.
//!
//! Mirrored trees are never indexed back into the local origin trie, and the
//! engine refuses overlapping space and mirror roots, so "no echo" is
//! structural rather than conventional.
//!
//! Materialization is deliberately conservative about names: when two published
//! paths collide under the target filesystem's folding, or a name is invalid on
//! the platform, the entry is **skipped and reported** — never silently
//! clobbered.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use synch_core::EntryKind;
use synch_store::{MirrorRow, VersionPolicy};

use crate::{
    error::{EngineError, Result},
    node::{paths_overlap, stored_root, Node},
};

/// What one mirror pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MirrorReport {
    /// Files written or refreshed.
    pub written: usize,
    /// Files already up to date.
    pub current: usize,
    /// Files removed: the selected version is a tombstone, or the path has
    /// left the unified tree entirely.
    pub removed: usize,
    /// Entries skipped, with the reason — including every path a `strict`
    /// mirror refused to guess at.
    pub skipped: Vec<(String, String)>,
}

impl Node {
    /// Registers a continuous read-only mirror of a space of the unified tree.
    ///
    /// One mirror per directory: re-registering the same directory re-points
    /// it, which is how a policy is changed.
    pub fn add_mirror(
        &self,
        space: &str,
        local_path: impl AsRef<Path>,
        policy: &VersionPolicy,
    ) -> Result<String> {
        let path = local_path.as_ref();
        std::fs::create_dir_all(path)?;
        let path = std::fs::canonicalize(path)?;
        for existing in self.store().spaces()? {
            if paths_overlap(&path, &stored_root(&existing.local_path)) {
                return Err(EngineError::invalid(format!(
                    "mirror target {} overlaps space {}",
                    path.display(),
                    existing.id
                )));
            }
        }
        let key = path.to_string_lossy().into_owned();
        for existing in self.store().mirrors()? {
            if existing.local_path != key
                && paths_overlap(&path, &stored_root(&existing.local_path))
            {
                return Err(EngineError::invalid(format!(
                    "mirror target {} overlaps mirror {}",
                    path.display(),
                    existing.local_path
                )));
            }
        }
        self.store().put_mirror(&key, space, policy)?;
        Ok(key)
    }

    /// Removes the mirror at a directory. The materialized files are left in
    /// place.
    pub fn remove_mirror(&self, local_path: impl AsRef<Path>) -> Result<bool> {
        Ok(self
            .store()
            .remove_mirror(&mirror_key(local_path.as_ref()))?)
    }

    /// The mirror configured for a directory.
    pub fn mirror(&self, local_path: impl AsRef<Path>) -> Result<Option<MirrorRow>> {
        Ok(self.store().mirror(&mirror_key(local_path.as_ref()))?)
    }

    /// Brings one mirror up to date with the unified tree under its policy.
    pub async fn sync_mirror(&self, local_path: impl AsRef<Path>) -> Result<MirrorReport> {
        let key = mirror_key(local_path.as_ref());
        let mirror = self
            .store()
            .mirror(&key)?
            .ok_or_else(|| EngineError::not_found(format!("mirror {key}")))?;
        self.sync_mirror_row(&mirror).await
    }

    async fn sync_mirror_row(&self, mirror: &MirrorRow) -> Result<MirrorReport> {
        let root_dir = PathBuf::from(&mirror.local_path);
        let listing = self.unified_listing(&mirror.space, "", None, None)?;

        // Detect folding collisions before writing anything: the
        // lexicographically first path wins and the rest are reported.
        let mut claimed: HashMap<String, String> = HashMap::new();
        let mut report = MirrorReport::default();
        // Every path the unified tree still carries, whatever the policy makes
        // of it — what the sweep at the end uses to recognize a file whose path
        // has left the tree.
        let mut known: HashSet<String> = HashSet::new();

        for set in &listing {
            known.insert(set.path.clone());
            let target = root_dir.join(&set.path);
            let selected = match set.select(&mirror.policy) {
                synch_store::Selection::Selected(entry) => entry,
                // The policy selects nothing here — an `origin=` pin on an
                // origin that publishes no version of this path — so the path
                // is not in this mirror's view.
                synch_store::Selection::Absent => {
                    report.removed += remove_if_present(&target)?;
                    continue;
                }
                // A `strict` mirror never guesses: the path is left exactly as
                // it is and reported (§7.2).
                synch_store::Selection::Divergent => {
                    report.skipped.push((
                        set.path.clone(),
                        format!(
                            "{} versions and the policy is strict: {}",
                            set.version_count(),
                            set.describe().join("; ")
                        ),
                    ));
                    continue;
                }
            };

            // A path leaves the mirror when the version the policy selects is
            // a tombstone — the deletion is the assertion this mirror follows.
            if selected.kind == EntryKind::Tombstone {
                report.removed += remove_if_present(&target)?;
                continue;
            }
            if selected.kind == EntryKind::Dir {
                continue;
            }
            if let Some(reason) = unsafe_name(&set.path) {
                report.skipped.push((set.path.clone(), reason));
                continue;
            }
            let folded = fold(&set.path);
            match claimed.get(&folded) {
                Some(winner) if winner != &set.path => {
                    report.skipped.push((
                        set.path.clone(),
                        format!("collides with {winner} under filesystem name folding"),
                    ));
                    continue;
                }
                _ => {
                    claimed.insert(folded, set.path.clone());
                }
            }

            let Some(content) = selected.content else {
                report
                    .skipped
                    .push((set.path.clone(), "entry has no content".into()));
                continue;
            };
            if target.exists() {
                let same = std::fs::metadata(&target)
                    .map(|m| m.len() == selected.size)
                    .unwrap_or(false)
                    && std::fs::read(&target)
                        .map(|bytes| synch_core::Hash::new(&bytes) == content)
                        .unwrap_or(false);
                if same {
                    report.current += 1;
                    continue;
                }
            }

            let fetched = self.fetch_all(&content, selected.size).await?;
            if !fetched.complete {
                report.skipped.push((
                    set.path.clone(),
                    "no provider could serve the content".into(),
                ));
                continue;
            }
            let bytes = self.store().read_all(&content)?;
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target, &bytes)?;
            report.written += 1;
        }

        // A path that has left the unified tree altogether — every origin's
        // entry for it gone, tombstones included — leaves the mirror too. The
        // listing cannot report those, so the last step is to look at what is
        // on disk and drop whatever the tree no longer names.
        report.removed += sweep(&root_dir, &root_dir, &known)?;
        Ok(report)
    }

    /// Brings every configured mirror up to date.
    pub async fn sync_all_mirrors(&self) -> Result<Vec<(String, MirrorReport)>> {
        let mut out = Vec::new();
        for mirror in self.store().mirrors()? {
            let report = self.sync_mirror_row(&mirror).await?;
            out.push((mirror.local_path, report));
        }
        Ok(out)
    }
}

/// The stored key for a mirror: its canonical directory path.
fn mirror_key(path: &Path) -> String {
    stored_root(&path.to_string_lossy())
        .to_string_lossy()
        .into_owned()
}

fn remove_if_present(target: &Path) -> Result<usize> {
    if target.is_file() || target.is_symlink() {
        std::fs::remove_file(target)?;
        return Ok(1);
    }
    Ok(0)
}

/// Removes files under a mirror root whose path the unified tree no longer
/// carries, and returns how many went.
fn sweep(root: &Path, dir: &Path, known: &HashSet<String>) -> Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let mut removed = 0;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            removed += sweep(root, &path, known)?;
            continue;
        }
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let relative = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if !known.contains(&relative) {
            std::fs::remove_file(&path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Names Windows refuses, plus trailing dots and spaces, plus reserved
/// characters. Checked on every platform so a mirror behaves identically
/// everywhere (§7.2).
fn unsafe_name(path: &str) -> Option<String> {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    for component in path.split('/') {
        if component.ends_with('.') || component.ends_with(' ') {
            return Some(format!("component {component:?} ends with a dot or space"));
        }
        if component
            .chars()
            .any(|c| matches!(c, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*'))
        {
            return Some(format!("component {component:?} has a reserved character"));
        }
        let stem = component.split('.').next().unwrap_or(component);
        if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
            return Some(format!("component {component:?} is a reserved device name"));
        }
    }
    None
}

/// Folds a path the way a case-insensitive, normalizing filesystem would.
fn fold(path: &str) -> String {
    path.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use synch_core::{now_ns, FileEntry, Hash, OriginId};

    async fn node() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        (dir, node)
    }

    fn peer() -> OriginId {
        OriginId::named("nas", "x.example").unwrap()
    }

    fn other() -> OriginId {
        OriginId::named("laptop", "x.example").unwrap()
    }

    fn publish_entry(node: &Node, origin: &OriginId, path: &str, content: &[u8], mtime: i64) {
        let root = node.store().ingest_bytes(content, now_ns()).unwrap();
        node.store()
            .put_entry(
                origin,
                "media",
                path,
                &FileEntry::file(content.len() as u64, mtime, root, 1),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn a_mirror_materializes_the_unified_tree() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        publish_entry(&node, &peer(), "a/b.txt", b"hello", 1);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(
            std::fs::read(target.path().join("a/b.txt")).unwrap(),
            b"hello"
        );

        // A second pass writes nothing.
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.current, 1);
        node.shutdown().await.unwrap();
    }

    /// `newest` writes the winning version, and the mirror follows it when the
    /// winner changes — without either assertion being touched.
    #[tokio::test]
    async fn the_newest_policy_writes_the_selected_version() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        publish_entry(&node, &peer(), "f.txt", b"theirs", 100);
        publish_entry(&node, &other(), "f.txt", b"ours", 200);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(std::fs::read(target.path().join("f.txt")).unwrap(), b"ours");

        // The other origin publishes something newer still: the mirror moves.
        publish_entry(&node, &peer(), "f.txt", b"theirs again", 300);
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(
            std::fs::read(target.path().join("f.txt")).unwrap(),
            b"theirs again"
        );
        // Both assertions are still there, untouched.
        assert_eq!(node.versions("media", "f.txt").unwrap().version_count(), 2);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_origin_pinned_mirror_writes_only_that_origin() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Origin(peer()))
            .unwrap();
        publish_entry(&node, &peer(), "f.txt", b"theirs", 100);
        publish_entry(&node, &other(), "f.txt", b"ours", 200);
        publish_entry(&node, &other(), "only-theirs.txt", b"x", 1);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(
            std::fs::read(target.path().join("f.txt")).unwrap(),
            b"theirs"
        );
        assert!(
            !target.path().join("only-theirs.txt").exists(),
            "a path the pinned origin does not publish is not in its view"
        );
        node.shutdown().await.unwrap();
    }

    /// §7.2: under `strict`, divergent paths are skipped and reported — the
    /// mirror never guesses.
    #[tokio::test]
    async fn a_strict_mirror_skips_and_reports_divergence() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Strict)
            .unwrap();
        publish_entry(&node, &peer(), "agreed.txt", b"same", 1);
        publish_entry(&node, &peer(), "split.txt", b"theirs", 100);
        publish_entry(&node, &other(), "split.txt", b"ours", 200);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1, "the undisputed path is written");
        assert!(target.path().join("agreed.txt").exists());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, "split.txt");
        assert!(report.skipped[0].1.contains("strict"), "{report:?}");
        assert!(report.skipped[0].1.contains("nas@x.example"), "{report:?}");
        assert!(!target.path().join("split.txt").exists());

        // Once the publishers agree, the path stops being skipped.
        publish_entry(&node, &other(), "split.txt", b"theirs", 300);
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(
            std::fs::read(target.path().join("split.txt")).unwrap(),
            b"theirs"
        );
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_tombstoned_selection_removes_the_file() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        publish_entry(&node, &peer(), "a.txt", b"hello", 1);
        node.sync_mirror(target.path()).await.unwrap();

        // A newer tombstone is the selected version, so the file goes.
        node.store()
            .put_entry(
                &other(),
                "media",
                "a.txt",
                &FileEntry::tombstone(500, 2, None),
            )
            .unwrap();
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.removed, 1);
        assert!(!target.path().join("a.txt").exists());

        // Pinned to the origin that still publishes it, the same tree keeps it.
        node.add_mirror("media", target.path(), &VersionPolicy::Origin(peer()))
            .unwrap();
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert!(target.path().join("a.txt").exists());
        node.shutdown().await.unwrap();
    }

    /// The other half of the deletion rule: a path that has left the unified
    /// tree entirely leaves the mirror, even though no tombstone remains to
    /// point at it.
    #[tokio::test]
    async fn a_path_that_left_the_tree_leaves_the_mirror() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        publish_entry(&node, &peer(), "sub/gone.txt", b"hello", 1);
        publish_entry(&node, &peer(), "stays.txt", b"here", 1);
        node.sync_mirror(target.path()).await.unwrap();

        node.store()
            .delete_entry(&peer(), "media", "sub/gone.txt")
            .unwrap();
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.removed, 1);
        assert!(!target.path().join("sub/gone.txt").exists());
        assert!(target.path().join("stays.txt").exists());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn folding_collisions_are_skipped_not_clobbered() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        publish_entry(&node, &peer(), "README.md", b"upper", 1);
        publish_entry(&node, &peer(), "readme.md", b"lower", 1);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(report.skipped.len(), 1);
        // The lexicographically first path wins.
        assert_eq!(report.skipped[0].0, "readme.md");
        assert!(report.skipped[0].1.contains("collides"));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn platform_invalid_names_are_skipped_and_reported() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        publish_entry(&node, &peer(), "ok.txt", b"fine", 1);
        publish_entry(&node, &peer(), "aux.txt", b"reserved", 1);
        publish_entry(&node, &peer(), "trailing.", b"dot", 1);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(report.skipped.len(), 2);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn mirrors_may_not_overlap_spaces() {
        let (_d, node) = node().await;
        let shared = tempfile::tempdir().unwrap();
        node.add_space("media", shared.path()).unwrap();
        let err = node
            .add_mirror("media", shared.path(), &VersionPolicy::Newest)
            .unwrap_err();
        assert!(err.to_string().contains("overlaps space"));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn mirrors_may_not_overlap_each_other() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        assert!(node
            .add_mirror("other", target.path().join("sub"), &VersionPolicy::Newest)
            .is_err());
        // Re-registering the same directory is a legal update — it is how a
        // policy is changed.
        node.add_mirror("media", target.path(), &VersionPolicy::Strict)
            .unwrap();
        assert_eq!(
            node.mirror(target.path()).unwrap().unwrap().policy,
            VersionPolicy::Strict
        );
        assert!(node.remove_mirror(target.path()).unwrap());
        assert!(!node.remove_mirror(target.path()).unwrap());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_unfetchable_entry_is_reported_not_fatal() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        node.store()
            .put_entry(
                &peer(),
                "media",
                "missing.bin",
                &FileEntry::file(100_000, 0, Hash::new(b"nobody has this"), 1),
            )
            .unwrap();
        publish_entry(&node, &peer(), "present.txt", b"here", 1);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, "missing.bin");
        node.shutdown().await.unwrap();
    }

    #[test]
    fn name_safety_checks() {
        assert!(unsafe_name("fine/path.txt").is_none());
        assert!(unsafe_name("CON").is_some());
        assert!(unsafe_name("nul.txt").is_some());
        assert!(unsafe_name("bad<name").is_some());
        assert!(unsafe_name("trailing ").is_some());
    }
}
