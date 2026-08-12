//! Continuous read-only materialization of a peer's space (§7.2).
//!
//! Mirrored trees are never indexed back into the local origin trie, and the
//! store refuses overlapping space and mirror roots, so "no echo" is structural
//! rather than conventional.
//!
//! Materialization is deliberately conservative about names: when two published
//! paths collide under the target filesystem's folding, or a name is invalid on
//! the platform, the entry is **skipped and reported** — never silently
//! clobbered.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use synch_core::{EntryKind, OriginId};

use crate::{
    error::{EngineError, Result},
    node::{paths_overlap, Node},
};

/// What one mirror pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MirrorReport {
    /// Files written or refreshed.
    pub written: usize,
    /// Files already up to date.
    pub current: usize,
    /// Files removed because the origin tombstoned or dropped them.
    pub removed: usize,
    /// Entries skipped, with the reason.
    pub skipped: Vec<(String, String)>,
}

impl Node {
    /// Registers a continuous read-only mirror of `origin:space`.
    pub fn add_mirror(
        &self,
        origin: &OriginId,
        space: &str,
        local_path: impl AsRef<Path>,
    ) -> Result<()> {
        let path = local_path.as_ref();
        std::fs::create_dir_all(path)?;
        let path = std::fs::canonicalize(path)?;
        for existing in self.store().spaces()? {
            if paths_overlap(&path, Path::new(&existing.local_path)) {
                return Err(EngineError::invalid(format!(
                    "mirror target {} overlaps space {}",
                    path.display(),
                    existing.id
                )));
            }
        }
        for existing in self.store().mirrors()? {
            if (&existing.origin != origin || existing.space != space)
                && paths_overlap(&path, Path::new(&existing.local_path))
            {
                return Err(EngineError::invalid(format!(
                    "mirror target {} overlaps mirror {}:{}",
                    path.display(),
                    existing.origin,
                    existing.space
                )));
            }
        }
        self.store()
            .put_mirror(origin, space, &path.to_string_lossy())?;
        Ok(())
    }

    /// Removes a mirror. The materialized files are left in place.
    pub fn remove_mirror(&self, origin: &OriginId, space: &str) -> Result<bool> {
        Ok(self.store().remove_mirror(origin, space)?)
    }

    /// Brings one mirror up to date with the origin's current published view.
    pub async fn sync_mirror(&self, origin: &OriginId, space: &str) -> Result<MirrorReport> {
        let mirror = self
            .store()
            .mirrors()?
            .into_iter()
            .find(|m| &m.origin == origin && m.space == space)
            .ok_or_else(|| EngineError::not_found(format!("mirror {origin}:{space}")))?;
        let root_dir = PathBuf::from(&mirror.local_path);

        let entries = self
            .store()
            .list_entries(Some(origin), space, "", None, None)?;

        // Detect folding collisions before writing anything: the
        // lexicographically first path wins and the rest are reported.
        let mut claimed: HashMap<String, String> = HashMap::new();
        let mut report = MirrorReport::default();

        for entry in entries {
            if entry.kind == EntryKind::Tombstone {
                let target = root_dir.join(&entry.path);
                if target.exists() {
                    std::fs::remove_file(&target)?;
                    report.removed += 1;
                }
                continue;
            }
            if entry.kind == EntryKind::Dir {
                continue;
            }
            if let Some(reason) = unsafe_name(&entry.path) {
                report.skipped.push((entry.path.clone(), reason));
                continue;
            }
            let folded = fold(&entry.path);
            match claimed.get(&folded) {
                Some(winner) if winner != &entry.path => {
                    report.skipped.push((
                        entry.path.clone(),
                        format!("collides with {winner} under filesystem name folding"),
                    ));
                    continue;
                }
                _ => {
                    claimed.insert(folded, entry.path.clone());
                }
            }

            let Some(content) = entry.content else {
                report
                    .skipped
                    .push((entry.path.clone(), "entry has no content".into()));
                continue;
            };
            let target = root_dir.join(&entry.path);
            if target.exists() {
                let same = std::fs::metadata(&target)
                    .map(|m| m.len() == entry.size)
                    .unwrap_or(false)
                    && std::fs::read(&target)
                        .map(|bytes| synch_core::Hash::new(&bytes) == content)
                        .unwrap_or(false);
                if same {
                    report.current += 1;
                    continue;
                }
            }

            let fetched = self.fetch_all(&content, entry.size).await?;
            if !fetched.complete {
                report.skipped.push((
                    entry.path.clone(),
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
        Ok(report)
    }

    /// Brings every configured mirror up to date.
    pub async fn sync_all_mirrors(&self) -> Result<Vec<(OriginId, String, MirrorReport)>> {
        let mut out = Vec::new();
        for mirror in self.store().mirrors()? {
            let report = self.sync_mirror(&mirror.origin, &mirror.space).await?;
            out.push((mirror.origin, mirror.space, report));
        }
        Ok(out)
    }
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
    use synch_core::{now_ns, FileEntry, Hash};

    async fn node() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        (dir, node)
    }

    fn peer() -> OriginId {
        OriginId::named("nas", "x.example").unwrap()
    }

    fn publish_entry(node: &Node, origin: &OriginId, path: &str, content: &[u8]) -> Hash {
        let root = node.store().ingest_bytes(content, now_ns()).unwrap();
        node.store()
            .put_entry(
                origin,
                "media",
                path,
                &FileEntry::file(content.len() as u64, 0, root, 1),
            )
            .unwrap();
        root
    }

    #[tokio::test]
    async fn a_mirror_materializes_entries() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror(&peer(), "media", target.path()).unwrap();
        publish_entry(&node, &peer(), "a/b.txt", b"hello");

        let report = node.sync_mirror(&peer(), "media").await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(
            std::fs::read(target.path().join("a/b.txt")).unwrap(),
            b"hello"
        );

        // A second pass writes nothing.
        let report = node.sync_mirror(&peer(), "media").await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.current, 1);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn tombstones_remove_mirrored_files() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror(&peer(), "media", target.path()).unwrap();
        publish_entry(&node, &peer(), "a.txt", b"hello");
        node.sync_mirror(&peer(), "media").await.unwrap();

        node.store()
            .put_entry(&peer(), "media", "a.txt", &FileEntry::tombstone(0, 2, None))
            .unwrap();
        let report = node.sync_mirror(&peer(), "media").await.unwrap();
        assert_eq!(report.removed, 1);
        assert!(!target.path().join("a.txt").exists());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn folding_collisions_are_skipped_not_clobbered() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror(&peer(), "media", target.path()).unwrap();
        publish_entry(&node, &peer(), "README.md", b"upper");
        publish_entry(&node, &peer(), "readme.md", b"lower");

        let report = node.sync_mirror(&peer(), "media").await.unwrap();
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
        node.add_mirror(&peer(), "media", target.path()).unwrap();
        publish_entry(&node, &peer(), "ok.txt", b"fine");
        publish_entry(&node, &peer(), "aux.txt", b"reserved");
        publish_entry(&node, &peer(), "trailing.", b"dot");

        let report = node.sync_mirror(&peer(), "media").await.unwrap();
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
            .add_mirror(&peer(), "media", shared.path())
            .unwrap_err();
        assert!(err.to_string().contains("overlaps space"));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn mirrors_may_not_overlap_each_other() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror(&peer(), "media", target.path()).unwrap();
        let other = OriginId::named("vps", "x.example").unwrap();
        assert!(node
            .add_mirror(&other, "media", target.path().join("sub"))
            .is_err());
        // Re-registering the same mirror at the same path is a legal update.
        node.add_mirror(&peer(), "media", target.path()).unwrap();
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn an_unfetchable_entry_is_reported_not_fatal() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror(&peer(), "media", target.path()).unwrap();
        node.store()
            .put_entry(
                &peer(),
                "media",
                "missing.bin",
                &FileEntry::file(100_000, 0, Hash::new(b"nobody has this"), 1),
            )
            .unwrap();
        publish_entry(&node, &peer(), "present.txt", b"here");

        let report = node.sync_mirror(&peer(), "media").await.unwrap();
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
