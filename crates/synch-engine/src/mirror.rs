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

        // A pass runs in three phases, because only the middle one is
        // asynchronous. Deciding what each path needs is filesystem work — an
        // lstat per ancestor, a whole-file hash for anything that might already
        // be current — and so is writing the answer; only fetching the content
        // that is missing is network work. Alternating between the two inside
        // one loop would put every one of those hashes on the runtime worker
        // that happened to poll this future, so the blocking halves are hoisted
        // out and run on the blocking pool instead (§10).
        //
        // Phase 1 keeps listing order, which is what the symlink-escape guard
        // depends on: a link the mirror writes for `sub` is on disk before
        // `sub/passwd` is judged, exactly as when the two steps were
        // interleaved. Phase 2 re-checks it immediately before each write, so
        // the gap between the check and the write it guards stays one write
        // wide rather than one pass wide.
        //
        // The listing joins phase 1 rather than preceding it: it is an
        // unlimited range scan over every path in the space, plus one
        // `VersionSet` per path, which is more SQLite work than anything the
        // plan itself does.
        let plan = {
            let node = self.clone();
            let space = mirror.space.clone();
            let root_dir = root_dir.clone();
            let policy = mirror.policy.clone();
            crate::blocking::offload(move || {
                let listing = node.unified_listing(&space, "", None, None)?;
                plan_pass(&root_dir, &listing, &policy)
            })
            .await?
        };
        let MirrorPass {
            mut report,
            known,
            wanted,
        } = plan;

        // Phase 2: fetch what phase 1 could not satisfy locally, and copy each
        // object out of the CAS as it lands.
        for want in wanted {
            let fetched = self.fetch_all(&want.content, want.size).await?;
            if !fetched.complete {
                report
                    .skipped
                    .push((want.path, "no provider could serve the content".into()));
                continue;
            }
            // Copied out of the CAS a piece at a time and renamed into place: a
            // mirror of multi-gigabyte objects must not hold one in memory, and
            // a pass interrupted halfway must not leave a truncated file
            // wearing a complete file's name.
            //
            // The escape guard is taken again here, in the same blocking step
            // as the write it protects. Phase 1 checked this path too, but a
            // fetch stands between the two and the whole point of the guard is
            // to describe the directory the write is about to land in.
            let node = self.clone();
            let root = root_dir.clone();
            let path = want.path.clone();
            let written = crate::blocking::offload(move || {
                if escapes_via_symlink(&root, &path) {
                    return Ok(false);
                }
                node.write_blob_to_blocking(&want.content, want.size, &want.target)?;
                Ok(true)
            })
            .await?;
            if written {
                report.written += 1;
            } else {
                report.skipped.push((
                    want.path,
                    "path resolves through a symlink; refusing to write outside the mirror".into(),
                ));
            }
        }

        // Phase 3: a path that has left the unified tree altogether — every
        // origin's entry for it gone, tombstones included — leaves the mirror
        // too. The listing cannot report those, so the last step is to look at
        // what is on disk and drop whatever the tree no longer names.
        report.removed += crate::blocking::offload(move || {
            let root = root_dir;
            sweep(&root, &root, &known)
        })
        .await?;
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

/// One path a pass has decided it must fetch and write.
#[derive(Debug)]
struct WantedContent {
    /// The path within the space, for the report.
    path: String,
    /// Where it goes on disk.
    target: PathBuf,
    /// The object to materialize.
    content: synch_core::Hash,
    /// Its size, which is what the fetch and the copy are bounded by.
    size: u64,
}

/// What one pass settled before any content was fetched.
#[derive(Debug, Default)]
struct MirrorPass {
    /// Everything already accounted for: removals, symlinks, skips, and paths
    /// that were already current.
    report: MirrorReport,
    /// Every path the unified tree still carries, whatever the policy makes of
    /// it — what the sweep uses to recognize a file whose path has left the
    /// tree.
    known: HashSet<String>,
    /// What is left for the asynchronous half to fetch.
    wanted: Vec<WantedContent>,
}

/// Decides, and performs, everything one pass can settle without the network.
///
/// Blocking from end to end: [`Node::sync_mirror_row`] runs it on the blocking
/// pool.
fn plan_pass(
    root_dir: &Path,
    listing: &[synch_store::VersionSet],
    policy: &VersionPolicy,
) -> Result<MirrorPass> {
    // Detect folding collisions before writing anything: the
    // lexicographically first path wins and the rest are reported.
    let mut claimed: HashMap<String, String> = HashMap::new();
    let mut report = MirrorReport::default();
    let mut known: HashSet<String> = HashSet::new();
    let mut wanted: Vec<WantedContent> = Vec::new();

    {
        for set in listing {
            known.insert(set.path.clone());
            let target = root_dir.join(&set.path);
            // Defense in depth against a peer that plants a symlink and a file
            // beneath it (`sub` -> `/etc`, then `sub/passwd`): materialized in
            // path order the symlink lands first, and a later write to
            // `sub/passwd` would resolve through it to `/etc/passwd`, outside
            // the mirror root. Refuse — for writes and removals alike — any
            // path whose ancestors include a symlink the mirror itself wrote.
            if escapes_via_symlink(root_dir, &set.path) {
                report.skipped.push((
                    set.path.clone(),
                    "path resolves through a symlink; refusing to write outside the mirror".into(),
                ));
                continue;
            }
            let selected = match set.select(policy) {
                synch_store::Selection::Selected(entry) => *entry,
                // The policy selects nothing here — an `origin=` pin on an
                // origin that publishes no version of this path — so the path
                // is not in this mirror's view.
                synch_store::Selection::Absent => {
                    report.removed += remove_if_present(&target)?;
                    continue;
                }
                // A `strict` mirror never guesses (§7.2) — and that includes
                // not letting yesterday's copy stand in for a guess: a stale
                // file left behind reads as current to whoever mounts the
                // mirror, which is the silent wrong answer strict exists to
                // refuse. The path is reported and *removed* until the
                // divergence ends.
                synch_store::Selection::Divergent => {
                    let removed = remove_if_present(&target)?;
                    report.removed += removed;
                    report.skipped.push((
                        set.path.clone(),
                        format!(
                            "{} versions and the policy is strict{}: {}",
                            set.version_count(),
                            if removed > 0 {
                                " (stale copy removed)"
                            } else {
                                ""
                            },
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
            if selected.kind == EntryKind::Symlink {
                match materialize_symlink(&target, selected.symlink_target.as_deref()) {
                    Ok(true) => report.written += 1,
                    Ok(false) => report.current += 1,
                    Err(reason) => report.skipped.push((set.path.clone(), reason)),
                }
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
            if already_current(&target, selected.size, &content) {
                report.current += 1;
                continue;
            }

            wanted.push(WantedContent {
                path: set.path.clone(),
                target,
                content,
                size: selected.size,
            });
        }
    }

    Ok(MirrorPass {
        report,
        known,
        wanted,
    })
}

/// The stored key for a mirror: its canonical directory path.
fn mirror_key(path: &Path) -> String {
    stored_root(&path.to_string_lossy())
        .to_string_lossy()
        .into_owned()
}

/// Writes a symbolic link into a mirror, or explains why it could not be.
///
/// §7.2 has a mirror follow the version its policy selects, and a symlink's
/// version *is* its target — so on a platform with symbolic links the mirror
/// writes a real one. Returns whether anything changed on disk.
///
/// Windows has symlinks too, but creating one needs either Developer Mode or
/// `SeCreateSymbolicLinkPrivilege`, which a background daemon cannot assume and
/// cannot usefully acquire. Materialization's rule there is the one it already
/// applies to names the platform refuses: skip and report, never guess (§7.2) —
/// writing the target's *contents* under the link's name would silently turn a
/// link into a file and hand the next scanner on that machine a change nobody
/// made.
fn materialize_symlink(
    target: &Path,
    link_target: Option<&str>,
) -> std::result::Result<bool, String> {
    let Some(link_target) = link_target else {
        return Err("symlink entry carries no target".into());
    };
    #[cfg(unix)]
    {
        if let Ok(existing) = std::fs::read_link(target) {
            if existing.to_string_lossy() == link_target {
                return Ok(false);
            }
        }
        if target.symlink_metadata().is_ok() {
            std::fs::remove_file(target).map_err(|e| e.to_string())?;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::os::unix::fs::symlink(link_target, target).map_err(|e| e.to_string())?;
        Ok(true)
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        Err(format!(
            "symlink to {link_target}: creating symbolic links is not available to the daemon on \
             this platform, so the path is skipped rather than written as a plain file"
        ))
    }
}

/// True if `target` already holds exactly the object `content` names.
///
/// Size first, because it settles almost every case for the price of a `stat`;
/// the hash only then, and streamed, because a mirror carries objects far
/// larger than memory and this question is asked of every path on every pass.
/// Anything unreadable answers "no", and the pass rewrites it.
fn already_current(target: &Path, size: u64, content: &synch_core::Hash) -> bool {
    if std::fs::metadata(target).map(|m| m.len()).ok() != Some(size) {
        return false;
    }
    match std::fs::File::open(target) {
        Ok(file) => synch_core::hash_reader(std::io::BufReader::new(file))
            .map(|hash| hash == *content)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Returns true if any ancestor of `rel` under `root` is a symlink, so that
/// writing or deleting at `root/rel` would resolve through it and escape the
/// mirror root. The final component (the target itself) is not an ancestor and
/// is allowed to be a symlink.
fn escapes_via_symlink(root: &Path, rel: &str) -> bool {
    let mut cur = root.to_path_buf();
    let mut components: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
    components.pop();
    for component in components {
        cur.push(component);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => return true,
            _ => {}
        }
    }
    false
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
        // `is_dir` follows links, and a materialized symlink pointing at a
        // directory would then be descended into and its *contents* swept.
        // The sweep only ever looks at what the mirror itself wrote.
        let is_dir = std::fs::symlink_metadata(&path)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if is_dir {
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

    /// An object larger than any chunk crosses into the mirror in pieces, and
    /// the staging file it lands in is gone by the time the pass returns
    /// (§9.4).
    #[tokio::test]
    async fn a_large_object_is_mirrored_in_pieces_and_leaves_no_staging_file() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        let payload: Vec<u8> = (0..1_500_000u32).map(|i| (i * 13 % 251) as u8).collect();
        publish_entry(&node, &peer(), "big.bin", &payload, 1);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(
            std::fs::read(target.path().join("big.bin")).unwrap(),
            payload
        );
        let left: Vec<String> = std::fs::read_dir(target.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["big.bin".to_string()]);

        // And the "already current" check answers without reading the object
        // back into memory, so the second pass writes nothing.
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.current, 1);
        assert_eq!(report.written, 0);
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

        // A path that was materialized and *then* diverged does not leave its
        // stale copy behind: yesterday's file standing in for a guess is the
        // silent wrong answer strict exists to refuse.
        publish_entry(&node, &peer(), "agreed.txt", b"revised", 400);
        publish_entry(&node, &other(), "agreed.txt", b"opposed", 500);
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert!(
            !target.path().join("agreed.txt").exists(),
            "the stale copy must be removed while the path is divergent"
        );
        assert!(
            report
                .skipped
                .iter()
                .any(|(p, why)| p == "agreed.txt" && why.contains("stale copy removed")),
            "{report:?}"
        );

        // Once the publishers agree, the path stops being skipped.
        publish_entry(&node, &other(), "split.txt", b"theirs", 300);
        publish_entry(&node, &other(), "agreed.txt", b"revised", 600);
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

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_ancestor_is_refused() {
        // A peer publishes a symlink `sub -> /etc` and, path-ordered after it, a
        // file `sub/passwd`. The symlink materializes first; without the guard
        // the file write would resolve through it to `/etc/passwd`.
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc", root.path().join("sub")).unwrap();
        assert!(escapes_via_symlink(root.path(), "sub/passwd"));
        // A real directory ancestor is fine, and the symlink leaf itself is fine.
        std::fs::create_dir(root.path().join("real")).unwrap();
        assert!(!escapes_via_symlink(root.path(), "real/file.txt"));
        assert!(!escapes_via_symlink(root.path(), "sub"));
        assert!(!escapes_via_symlink(root.path(), "brandnew/file.txt"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_mirror_materializes_a_symlink_as_a_symlink() {
        let (_d, node) = node().await;
        let dest = tempfile::tempdir().unwrap();
        let origin = OriginId::named("nas", "x.example").unwrap();
        let mut entry = synch_core::FileEntry::tombstone(100, 1, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some("../elsewhere".into());
        node.store()
            .put_entry(&origin, "media", "link", &entry)
            .unwrap();

        node.add_mirror("media", dest.path(), &VersionPolicy::Newest)
            .unwrap();
        let report = node.sync_mirror(dest.path()).await.unwrap();
        assert_eq!(report.written, 1, "{report:?}");
        let written = dest.path().join("link");
        assert!(std::fs::symlink_metadata(&written).unwrap().is_symlink());
        assert_eq!(
            std::fs::read_link(&written).unwrap(),
            Path::new("../elsewhere")
        );

        // A second pass has nothing to do.
        let report = node.sync_mirror(dest.path()).await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.current, 1);

        // Retargeting replaces the link rather than writing beside it.
        let mut entry = synch_core::FileEntry::tombstone(200, 2, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some("../other".into());
        node.store()
            .put_entry(&origin, "media", "link", &entry)
            .unwrap();
        let report = node.sync_mirror(dest.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(std::fs::read_link(&written).unwrap(), Path::new("../other"));
        node.shutdown().await.unwrap();
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn a_mirror_skips_and_reports_a_symlink_where_it_cannot_make_one() {
        let (_d, node) = node().await;
        let dest = tempfile::tempdir().unwrap();
        let origin = OriginId::named("nas", "x.example").unwrap();
        let mut entry = synch_core::FileEntry::tombstone(100, 1, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some("../elsewhere".into());
        node.store()
            .put_entry(&origin, "media", "link", &entry)
            .unwrap();

        node.add_mirror("media", dest.path(), &VersionPolicy::Newest)
            .unwrap();
        let report = node.sync_mirror(dest.path()).await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert!(report.skipped[0].1.contains("symbolic link"), "{report:?}");
        assert!(!dest.path().join("link").exists());
        node.shutdown().await.unwrap();
    }
}
