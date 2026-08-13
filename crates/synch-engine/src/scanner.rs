//! The indexing pipeline for this node's own spaces (§7.1).
//!
//! A file is considered unchanged if `(size, mtime_ns, file_id)` matches the
//! `local_files` table — only then is hashing skipped. Changed files are
//! re-hashed with streaming BLAKE3, the outboard falls out as a by-product, the
//! CAS is updated, and a new `FileEntry` is staged.
//!
//! Correctness never depends on watcher completeness: the scanner is the source
//! of truth and the watcher only schedules it.

use std::path::{Path, PathBuf};

use synch_core::{blob_key, file_key, normalize_native_path, now_ns, EntryKind, FileEntry, Hash};
use synch_mpt::Trie;
use synch_store::LocalFile;

use crate::{
    error::{EngineError, Result},
    ignore::IgnoreSet,
    node::{Node, StagedChange},
};

/// What one scan found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Files hashed because they looked changed.
    pub hashed: usize,
    /// Files skipped because `(size, mtime_ns, file_id)` matched.
    pub unchanged: usize,
    /// Paths that disappeared and were tombstoned.
    pub deleted: usize,
    /// Paths skipped by ignore rules.
    pub ignored: usize,
    /// Paths skipped because they could not be indexed, with the reason.
    pub skipped: Vec<(String, String)>,
    /// The changes to publish.
    pub staged: Vec<StagedChange>,
}

impl ScanReport {
    /// True if the scan produced nothing to publish.
    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    fn merge(&mut self, other: ScanReport) {
        self.hashed += other.hashed;
        self.unchanged += other.unchanged;
        self.deleted += other.deleted;
        self.ignored += other.ignored;
        self.skipped.extend(other.skipped);
        self.staged.extend(other.staged);
    }
}

impl Node {
    /// Walks one space and stages everything that changed.
    pub fn scan_space(&self, space_id: &str) -> Result<ScanReport> {
        let space = self
            .store()
            .space(space_id)?
            .ok_or_else(|| EngineError::not_found(format!("space {space_id}")))?;
        let root_dir = PathBuf::from(&space.local_path);
        let ignore = IgnoreSet::for_space(&root_dir);
        let seq = self.next_seq()?;

        let mut report = ScanReport::default();
        let mut found = Vec::new();
        walk(&root_dir, &root_dir, &ignore, &mut report, &mut found)?;

        let mut seen: Vec<String> = Vec::with_capacity(found.len());
        for (path, rel, is_symlink) in &found {
            self.index_file(space_id, path, rel, seq, *is_symlink, &mut report)?;
            seen.push(rel.clone());
        }

        // Anything the scanner previously recorded but did not see is gone.
        // Deletion propagates by the key vanishing from the new root; the
        // tombstone exists so `synch status`/`synch log` can tell "deleted at
        // seq N" from "never existed" (§4.2).
        for known in self.store().local_files(space_id)? {
            if seen.contains(&known) {
                continue;
            }
            let prev = self
                .store()
                .entry(self.origin(), space_id, &known)?
                .and_then(|e| e.content);
            let tombstone = FileEntry::tombstone(now_ns(), seq, prev);
            report.staged.push((
                file_key(space_id, &known)?,
                Some(
                    postcard::to_stdvec(&tombstone)
                        .map_err(|e| EngineError::Record(e.to_string()))?,
                ),
            ));
            self.store().remove_local_file(space_id, &known)?;
            report.deleted += 1;
        }
        Ok(report)
    }

    fn index_file(
        &self,
        space_id: &str,
        path: &Path,
        rel: &str,
        seq: u64,
        is_symlink: bool,
        report: &mut ScanReport,
    ) -> Result<()> {
        if is_symlink {
            let target = std::fs::read_link(path)?.to_string_lossy().into_owned();
            let mut entry = FileEntry::tombstone(now_ns(), seq, None);
            entry.kind = EntryKind::Symlink;
            entry.symlink_target = Some(target);
            report.staged.push((
                file_key(space_id, rel)?,
                Some(postcard::to_stdvec(&entry).map_err(|e| EngineError::Record(e.to_string()))?),
            ));
            return Ok(());
        }

        let metadata = std::fs::metadata(path)?;
        let size = metadata.len();
        let mtime_ns = mtime_nanos(&metadata);
        let file_id = file_identity(&metadata);

        let known = self.store().local_file(space_id, rel)?;
        let unchanged = match &known {
            Some(known) => {
                known.size == size && known.mtime_ns == mtime_ns && known.file_id == file_id
            }
            None => false,
        };
        if unchanged {
            report.unchanged += 1;
            return Ok(());
        }

        let (content, size) = self.store().ingest_file(path, now_ns())?;
        report.hashed += 1;

        let previous = self
            .store()
            .entry(self.origin(), space_id, rel)?
            .and_then(|e| e.content);
        // `prev` records one-step lineage so a UI can tell "adopted theirs on
        // top of X" from "changed independently" (§8).
        let mut entry = FileEntry::file(size, mtime_ns, content, seq);
        entry.prev = previous.filter(|p| *p != content);
        entry.unix_mode = unix_mode(&metadata);

        report.staged.push((
            file_key(space_id, rel)?,
            Some(postcard::to_stdvec(&entry).map_err(|e| EngineError::Record(e.to_string()))?),
        ));
        if let Some(ad) = self.store().local_ad(&content)? {
            report.staged.push((
                blob_key(&content),
                Some(postcard::to_stdvec(&ad).map_err(|e| EngineError::Record(e.to_string()))?),
            ));
        }

        self.store().put_local_file(&LocalFile {
            space: space_id.to_string(),
            relpath: rel.to_string(),
            size,
            mtime_ns,
            file_id,
            content: Some(content),
            scanned_at: now_ns(),
        })?;
        Ok(())
    }

    /// Scans every configured space.
    pub fn scan_all(&self) -> Result<ScanReport> {
        self.scan_all_with(|_, _| {})
    }

    /// Scans every configured space, reporting each one as it completes.
    ///
    /// Hashing a large tree takes as long as it takes; `on_space` is how a
    /// caller says so while it happens, rather than after everything is done.
    pub fn scan_all_with(&self, mut on_space: impl FnMut(&str, &ScanReport)) -> Result<ScanReport> {
        let mut report = ScanReport::default();
        for space in self.store().spaces()? {
            let one = self.scan_space(&space.id)?;
            on_space(&space.id, &one);
            report.merge(one);
        }
        if !report.staged.is_empty() {
            report.staged.push(self.manifest_change()?);
        }
        Ok(report)
    }

    /// Scans every space and publishes the result as one new root, without
    /// going through the publisher's batch.
    ///
    /// The recovery gate (§3.4) is checked *before* the scan, not only at the
    /// publish: a scan records what it hashed in `local_files`, so a scan whose
    /// publish is refused would leave the node believing it had already
    /// published files it never did.
    pub fn scan_and_publish(&self) -> Result<(ScanReport, Option<synch_core::SignedHead>)> {
        self.ensure_publishable()?;
        let report = self.scan_all()?;
        let head = self.publish(&report.staged)?;
        Ok((report, head))
    }

    /// Scans every space and stages the result for the publisher (§7.1).
    ///
    /// This is what a watcher hint and the periodic rescan use: a burst of
    /// saves becomes one batch and therefore one head. Nothing is published
    /// until the batch flushes.
    ///
    /// The recovery gate is taken here for the same reason it is taken in
    /// [`Node::scan_and_publish`] — the scan writes `local_files` either way.
    pub fn scan_and_stage(&self) -> Result<ScanReport> {
        self.ensure_publishable()?;
        let report = self.scan_all()?;
        self.stage(report.staged.iter().cloned());
        Ok(report)
    }

    /// Re-indexes local paths whose staged changes never reached a root.
    ///
    /// `scan_space` records `(size, mtime_ns, file_id)` in `local_files` as it
    /// indexes, and that record is what makes the *next* scan skip the file.
    /// Batching puts a window between the two: a daemon that dies with a batch
    /// still buffered would leave rows claiming a file is published while no
    /// root mentions it, and every later scan would skip it — silent, permanent
    /// drift.
    ///
    /// So on open, every `local_files` row is checked against this node's own
    /// current trie, and any row the trie does not corroborate is dropped: the
    /// next scan re-hashes that path and stages it again. Both tables are
    /// local, so the check costs one trie lookup per indexed file and no I/O
    /// beyond the database. Returns how many rows were dropped.
    pub fn reconcile_local_files(&self) -> Result<usize> {
        let root = self.current_root()?;
        let trie = Trie::new(self.store().as_ref());
        let mut dropped = 0;
        for space in self.store().spaces()? {
            for row in self.store().local_file_rows(&space.id)? {
                let published = trie
                    .get(root, &file_key(&space.id, &row.relpath)?)?
                    .as_deref()
                    .map(decode_entry)
                    .transpose()?
                    .and_then(|entry| entry.content);
                if published == row.content {
                    continue;
                }
                tracing::debug!(
                    space = %space.id,
                    path = %row.relpath,
                    "re-indexing a path the published root does not corroborate"
                );
                self.store().remove_local_file(&space.id, &row.relpath)?;
                dropped += 1;
            }
        }
        Ok(dropped)
    }

    /// Adopts a peer's version of a path as our own (§8, `synch take`).
    ///
    /// The bytes are written into the local space directory and the ordinary
    /// indexing pipeline republishes them as this node's entry, with `prev`
    /// pointing at the content we replaced.
    pub fn adopt(&self, space_id: &str, path: &str, content: &[u8]) -> Result<PathBuf> {
        let space = self
            .store()
            .space(space_id)?
            .ok_or_else(|| EngineError::not_found(format!("space {space_id}")))?;
        let normalized =
            synch_core::normalize_path(path).map_err(|e| EngineError::invalid(e.to_string()))?;
        let target = PathBuf::from(&space.local_path).join(&normalized);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, content)?;
        Ok(target)
    }
}

/// One file the walk found: its absolute path, its normalized relative path,
/// and whether it is a symlink.
type Found = (PathBuf, String, bool);

fn walk(
    root: &Path,
    dir: &Path,
    ignore: &IgnoreSet,
    report: &mut ScanReport,
    found: &mut Vec<Found>,
) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut sorted: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    sorted.sort_by_key(|e| e.file_name());

    for entry in sorted {
        let path = entry.path();
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let rel = match normalize_native_path(relative) {
            Ok(rel) => rel,
            Err(e) => {
                report
                    .skipped
                    .push((relative.to_string_lossy().into_owned(), e.to_string()));
                continue;
            }
        };
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                report.skipped.push((rel, e.to_string()));
                continue;
            }
        };
        let is_dir = metadata.is_dir();
        if ignore.is_ignored(&rel, is_dir) {
            report.ignored += 1;
            continue;
        }
        if is_dir {
            walk(root, &path, ignore, report, found)?;
        } else {
            found.push((path, rel, metadata.is_symlink()));
        }
    }
    Ok(())
}

fn mtime_nanos(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// A platform file identity, when one is cheaply available.
///
/// Together with size and mtime this is what lets the scanner skip hashing.
fn file_identity(metadata: &std::fs::Metadata) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mut id = Vec::with_capacity(16);
        id.extend_from_slice(&metadata.dev().to_le_bytes());
        id.extend_from_slice(&metadata.ino().to_le_bytes());
        Some(id)
    }
    #[cfg(not(unix))]
    {
        // Windows exposes a file index only via `MetadataExt::file_index`,
        // which is still unstable (rust-lang/rust#63010), and reading it
        // otherwise costs an open handle per file. Identity is optional by
        // design, so change detection falls back to (size, mtime) there.
        let _ = metadata;
        None
    }
}

fn unix_mode(metadata: &std::fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// Reads a `FileEntry` out of a published entry row's origin trie.
pub fn decode_entry(bytes: &[u8]) -> Result<FileEntry> {
    postcard::from_bytes(bytes).map_err(|e| EngineError::Record(e.to_string()))
}

/// The content root a staged file entry points at, if any.
pub fn staged_content(change: &StagedChange) -> Option<Hash> {
    let value = change.1.as_ref()?;
    decode_entry(value).ok()?.content
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;

    async fn node_with_space() -> (tempfile::TempDir, tempfile::TempDir, Node) {
        let data = tempfile::tempdir().unwrap();
        let space = tempfile::tempdir().unwrap();
        Node::init(data.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
        node.add_space("media", space.path()).unwrap();
        (data, space, node)
    }

    #[tokio::test]
    async fn scans_hashes_and_publishes() {
        let (_d, space, node) = node_with_space().await;
        std::fs::create_dir_all(space.path().join("talks")).unwrap();
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(space.path().join("talks/b.bin"), vec![7u8; 40_000]).unwrap();

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 2);
        assert_eq!(report.unchanged, 0);
        let head = head.unwrap();
        assert_eq!(head.seq, 1);

        let entries = node
            .store()
            .list_entries(Some(node.origin()), "media", "", None, None)
            .unwrap();
        assert_eq!(entries.len(), 2);
        let a = entries.iter().find(|e| e.path == "a.txt").unwrap();
        assert_eq!(a.size, 5);
        assert_eq!(a.content, Some(Hash::new(b"hello")));
        // Content is in the CAS and reads back verified.
        assert_eq!(
            node.store().read_all(&a.content.unwrap()).unwrap(),
            b"hello"
        );
        // And the object is advertised.
        assert_eq!(
            node.store().providers(&a.content.unwrap()).unwrap().len(),
            1
        );
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn unchanged_files_are_not_rehashed() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
        node.scan_and_publish().unwrap();

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 0);
        assert_eq!(report.unchanged, 1);
        assert!(head.is_none(), "an unchanged tree publishes no new head");
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn edits_are_detected_and_carry_lineage() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"before").unwrap();
        node.scan_and_publish().unwrap();

        // Force a distinguishable mtime so the (size, mtime, file_id) triple
        // differs even on coarse-resolution filesystems.
        std::fs::write(space.path().join("a.txt"), b"after!!").unwrap();
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 1);
        assert_eq!(head.unwrap().seq, 2);

        let entry = node
            .store()
            .entry(node.origin(), "media", "a.txt")
            .unwrap()
            .unwrap();
        assert_eq!(entry.content, Some(Hash::new(b"after!!")));
        assert_eq!(entry.prev, Some(Hash::new(b"before")));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn deletions_become_tombstones() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
        node.scan_and_publish().unwrap();
        std::fs::remove_file(space.path().join("a.txt")).unwrap();

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(head.unwrap().seq, 2);

        let entry = node
            .store()
            .entry(node.origin(), "media", "a.txt")
            .unwrap()
            .unwrap();
        // The tombstone distinguishes "deleted at seq 2" from "never existed".
        assert_eq!(entry.kind, EntryKind::Tombstone);
        assert_eq!(entry.seq, 2);
        assert_eq!(entry.prev, Some(Hash::new(b"hello")));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ignore_rules_are_honored() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join(".syncignore"), "*.tmp\n!keep.tmp\n").unwrap();
        std::fs::write(space.path().join("a.txt"), b"x").unwrap();
        std::fs::write(space.path().join("scratch.tmp"), b"x").unwrap();
        std::fs::write(space.path().join("keep.tmp"), b"x").unwrap();
        std::fs::write(space.path().join(".DS_Store"), b"x").unwrap();

        let (report, _) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 2);
        assert!(report.ignored >= 2);
        let paths: Vec<String> = node
            .store()
            .list_entries(Some(node.origin()), "media", "", None, None)
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(paths, vec!["a.txt".to_string(), "keep.tmp".to_string()]);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn nested_directories_mirror_into_the_key_space() {
        let (_d, space, node) = node_with_space().await;
        for dir in ["a", "a/b", "a/b/c"] {
            std::fs::create_dir_all(space.path().join(dir)).unwrap();
            std::fs::write(space.path().join(dir).join("f.txt"), dir.as_bytes()).unwrap();
        }
        node.scan_and_publish().unwrap();

        // A directory listing is a range scan over the f: prefix (§4.1).
        let under_b = node
            .store()
            .list_entries(Some(node.origin()), "media", "a/b/", None, None)
            .unwrap();
        assert_eq!(under_b.len(), 2);
        assert!(under_b.iter().all(|e| e.path.starts_with("a/b/")));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn adopting_a_peer_version_republishes_it_as_ours() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"mine").unwrap();
        node.scan_and_publish().unwrap();

        node.adopt("media", "a.txt", b"theirs").unwrap();
        node.scan_and_publish().unwrap();
        let entry = node
            .store()
            .entry(node.origin(), "media", "a.txt")
            .unwrap()
            .unwrap();
        assert_eq!(entry.content, Some(Hash::new(b"theirs")));
        assert_eq!(entry.prev, Some(Hash::new(b"mine")));
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn removing_a_space_stages_its_removal() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"x").unwrap();
        node.scan_and_publish().unwrap();

        let staged = node.remove_space("media").unwrap();
        assert!(!staged.is_empty());
        node.publish(&staged).unwrap().unwrap();
        assert!(node
            .store()
            .list_entries(Some(node.origin()), "media", "", None, None)
            .unwrap()
            .is_empty());
        node.shutdown().await.unwrap();
    }

    /// The crash the batching publisher makes possible, and the countermeasure
    /// (§7.1): a scan writes `local_files` as it indexes, so a daemon that dies
    /// with the batch still buffered must not leave the next scan skipping
    /// those files forever.
    #[tokio::test]
    async fn a_batch_lost_to_a_crash_is_re_indexed_on_open() {
        let data = tempfile::tempdir().unwrap();
        let space = tempfile::tempdir().unwrap();
        Node::init(data.path(), None).unwrap();
        {
            let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
            node.add_space("media", space.path()).unwrap();
            std::fs::write(space.path().join("a.txt"), b"hello").unwrap();

            // Scan into the publisher and then lose the process: the files are
            // hashed and recorded, and nothing is ever published.
            let report = node.scan_and_stage().unwrap();
            assert_eq!(report.hashed, 1);
            assert!(node.publisher().pending() > 0);
            assert!(node.own_head().unwrap().is_none());
            assert_eq!(node.store().local_files("media").unwrap().len(), 1);
            node.shutdown().await.unwrap();
        }

        // Opening notices that `local_files` claims a file the trie does not
        // publish, and drops the row so the next scan re-hashes it.
        let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
        assert!(node.store().local_files("media").unwrap().is_empty());

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 1, "the file must be re-hashed, not skipped");
        assert_eq!(head.unwrap().seq, 1);
        let entry = node
            .store()
            .entry(node.origin(), "media", "a.txt")
            .unwrap()
            .unwrap();
        assert_eq!(entry.content, Some(Hash::new(b"hello")));
        node.shutdown().await.unwrap();
    }

    /// Reconciliation is a repair, not a re-scan: a node whose published root
    /// agrees with `local_files` keeps every row, so ordinary restarts do not
    /// re-hash the tree.
    #[tokio::test]
    async fn reconciliation_leaves_a_published_tree_alone() {
        let data = tempfile::tempdir().unwrap();
        let space = tempfile::tempdir().unwrap();
        Node::init(data.path(), None).unwrap();
        {
            let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
            node.add_space("media", space.path()).unwrap();
            std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
            node.scan_and_publish().unwrap();
            node.shutdown().await.unwrap();
        }

        let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
        assert_eq!(node.reconcile_local_files().unwrap(), 0);
        assert_eq!(node.store().local_files("media").unwrap().len(), 1);
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 0);
        assert_eq!(report.unchanged, 1);
        assert!(head.is_none());
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn scanning_an_unknown_space_fails_clearly() {
        let (_d, _s, node) = node_with_space().await;
        assert!(matches!(
            node.scan_space("nope"),
            Err(EngineError::NotFound(_))
        ));
        node.shutdown().await.unwrap();
    }
}
