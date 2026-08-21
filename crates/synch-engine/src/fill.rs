//! One-shot materialization into a space's *own* directory (§7.2).
//!
//! A mirror is the continuous, read-only half of materialization: it owns the
//! directory it writes into, removes whatever the tree stops carrying, and is
//! never indexed back into the local origin trie. A fill is the other half. It
//! writes into the writable directory `synch space add` named — the one this
//! node indexes and publishes from — and so it may only ever *add*:
//!
//! - nothing is removed, ever. A tombstoned version, a path the policy selects
//!   nothing for, a local file no origin publishes: all left exactly as they
//!   are. Deleting is what `synch take` of a tombstone is for, one deliberate
//!   path at a time.
//! - a local file whose bytes already differ is reported and left alone.
//!   `--force` replaces it, which is the bulk form of `synch take`.
//!
//! Nothing here publishes. The files land in an indexed directory, so the next
//! scan — the watcher's, or an explicit `synch scan` — stages and publishes
//! them as this node's own view (§7.1), exactly as it would files copied in by
//! hand.
//!
//! Which is why a filled file carries the selected version's metadata as well
//! as its bytes. The mtime that scan publishes is then the one the origin
//! published, so filling a path restates the version that was filled instead
//! of minting a newer one — and minting one would be no small thing: `newest`
//! orders on `(mtime, content root, origin)`, so a fill stamped with the wall
//! clock would make this node win the selection for every path it touched,
//! cluster-wide.

use std::path::{Path, PathBuf};

use synch_core::{EntryKind, Hash};
use synch_store::{Donor, VersionPolicy, VersionSet};

use crate::{
    error::{EngineError, Result},
    mirror::{
        apply_metadata, escapes_via_symlink, fold, materialize_symlink, same_size_root,
        unsafe_name, Metadata,
    },
    node::Node,
    scanner::target_within,
};

/// How a fill treats what is already on disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FillOptions {
    /// Replace local files whose bytes differ from the selected version,
    /// rather than reporting them and leaving them alone.
    pub force: bool,
    /// Decide everything and write nothing: the report says what a real run
    /// would do, down to which files it would replace.
    pub dry_run: bool,
}

/// What one fill did, or — under [`FillOptions::dry_run`] — would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FillReport {
    /// Files and symlinks written: the ones that were missing, plus whatever
    /// `--force` replaced.
    pub filled: usize,
    /// Paths already holding the selected version's bytes.
    pub current: usize,
    /// The paths `--force` overwrote — the subset of `filled` that had
    /// different content here first. Named rather than counted: replacing a
    /// local file is the one thing a fill does that loses something.
    pub replaced: Vec<String>,
    /// Paths whose local copy differs from the selected version and was left
    /// alone. `--force`, or `synch take` per path, is what ends the standoff.
    pub differing: Vec<String>,
    /// Paths a fill could not write, with the reason — including every path a
    /// `strict` fill refused to guess at.
    pub skipped: Vec<(String, String)>,
    /// Bytes that crossed the network for what this fill wrote.
    pub fetched_bytes: u64,
    /// Bytes that did not, because a local donor already held them
    /// (`docs/DELTA-SYNC.md` §3.3).
    pub reused_bytes: u64,
    /// Files whose bytes were not copied at all, because the space and the CAS
    /// share a filesystem. A subset of `filled`.
    pub reflinked: usize,
    /// Whether this report describes a run that wrote nothing on purpose.
    pub dry_run: bool,
}

impl Node {
    /// Fills a space's configured directory with the unified tree's content
    /// (§7.2, `synch fill`).
    ///
    /// `prefix` narrows the fill to a directory within the space, empty for
    /// all of it. The space must be one this node indexes: a fill writes where
    /// the scanner will find it, and outside a space nothing would.
    pub async fn fill_space(
        &self,
        space_id: &str,
        prefix: &str,
        policy: &VersionPolicy,
        options: FillOptions,
    ) -> Result<FillReport> {
        // Serialized against every other materialization pass on this node, so
        // two fills of one space cannot plan against each other's half-written
        // state. Mirrors take the same lock; their roots cannot overlap a
        // space's, so sharing it costs nothing but the wait.
        let _pass = self.lock_materialization().await;

        // The space row is read once and its root carried through the pass:
        // the write guard needs the root per path, and re-reading the row for
        // each would be one store acquisition per file in the space.
        let root_dir = {
            let (node, space_id) = (self.clone(), space_id.to_string());
            crate::blocking::offload(move || {
                let space = node.store().space(&space_id)?.ok_or_else(|| {
                    EngineError::not_found(format!(
                        "no local space {space_id}: `synch space add {space_id} <dir>` names the \
                         directory a fill writes into"
                    ))
                })?;
                // A detached space has no checkout to fill: its content lives
                // in the cloud CAS and is read on demand. `synch mirror add` is
                // what materializes one where a directory is wanted.
                let local_path = space.local_path.ok_or_else(|| {
                    EngineError::invalid(format!(
                        "space {space_id} is detached and has no local directory to fill; \
                         `synch mirror add {space_id} <dir>` materializes one"
                    ))
                })?;
                Ok(PathBuf::from(local_path))
            })
            .await?
        };

        // Phase 1, blocking end to end for the reasons mirror.rs lays out: the
        // listing is a range scan over every path in the space plus a version
        // set each, and deciding what a path needs is a stat and — where the
        // scanner's own record cannot answer — a whole-file hash.
        let plan = {
            let node = self.clone();
            let (space_id, prefix) = (space_id.to_string(), prefix.to_string());
            let (root_dir, policy) = (root_dir.clone(), policy.clone());
            crate::blocking::offload(move || {
                let listing = node.unified_listing(&space_id, &prefix, None, None)?;
                plan_fill(&node, &space_id, &root_dir, &listing, &policy, options)
            })
            .await?
        };
        let FillPlan { mut report, wanted } = plan;
        if options.dry_run {
            // The plan *is* the answer: everything it decided is already in the
            // report, and `wanted` is what a real run would go and fetch.
            report.filled += wanted.len();
            return Ok(report);
        }

        // Phase 2: fetch what phase 1 could not satisfy locally — building each
        // object out of a donor where the descent can — and write it as it
        // lands.
        for want in wanted {
            let Wanted {
                path,
                target,
                content,
                size,
                meta,
                donors,
                replacing,
            } = want;
            let fetched = self.fetch_all_from(&content, size, &donors).await?;
            if !fetched.complete {
                report
                    .skipped
                    .push((path, "no provider could serve the content".into()));
                continue;
            }
            report.fetched_bytes += crate::mirror::bytes_of(&fetched.fetched, size);
            report.reused_bytes += crate::mirror::bytes_of(&fetched.promoted, size);

            // Taken again immediately before the write it guards: phase 1
            // checked this path too, but a fetch stands between the two, and
            // the gap must stay one write wide rather than one pass wide.
            let (root, guarded) = (root_dir.clone(), path.clone());
            let clear =
                crate::blocking::offload(move || Ok(!escapes_via_symlink(&root, &guarded))).await?;
            let outcome = if !clear {
                Written::Escaped
            } else {
                // A materialization that fails takes its path down with it and
                // nothing else: the target is untouched.
                match self.materialize_blob(&content, size, target.clone()).await {
                    Err(e) => Written::Failed(e.to_string()),
                    Ok(kind) => {
                        // The bytes are the file; the metadata is stamped right
                        // after, and a filesystem that refuses the stamp is
                        // reported rather than allowed to fail the pass. Not
                        // cosmetic here: the stamped mtime is the one the next
                        // scan publishes.
                        crate::blocking::offload(move || {
                            Ok(match apply_metadata(&target, meta) {
                                Ok(()) => Written::Fully(kind),
                                Err(e) => Written::WithoutMetadata(kind, e.to_string()),
                            })
                        })
                        .await?
                    }
                }
            };
            match outcome {
                Written::Fully(kind) | Written::WithoutMetadata(kind, _) => {
                    report.filled += 1;
                    report.reflinked += usize::from(kind == crate::CloneKind::Reflink);
                    if replacing {
                        report.replaced.push(path.clone());
                    }
                    if let Written::WithoutMetadata(_, why) = outcome {
                        report.skipped.push((
                            path,
                            format!(
                                "content written, but its metadata could not be reproduced, so \
                                 the next scan will publish it under this node's own clock: {why}"
                            ),
                        ));
                    }
                }
                Written::Escaped => report.skipped.push((
                    path,
                    "path resolves through a symlink; refusing to write outside the space".into(),
                )),
                Written::Failed(why) => report
                    .skipped
                    .push((path, format!("content could not be written: {why}"))),
            }
        }
        Ok(report)
    }
}

/// One path a fill has decided it must fetch and write.
#[derive(Debug)]
struct Wanted {
    /// The path within the space, for the report.
    path: String,
    /// Where it goes on disk.
    target: PathBuf,
    /// The object to materialize.
    content: Hash,
    /// Its size, which bounds the fetch and the copy.
    size: u64,
    /// The metadata to stamp on once the bytes are there.
    meta: Metadata,
    /// Where the bytes might already be, in §3.2 priority order.
    donors: Vec<Donor>,
    /// Whether a local file with different bytes is being overwritten, which
    /// only `--force` reaches.
    replacing: bool,
}

/// How one write ended.
#[derive(Debug)]
enum Written {
    /// Bytes and metadata both.
    Fully(crate::CloneKind),
    /// The bytes landed; the filesystem refused the metadata.
    WithoutMetadata(crate::CloneKind, String),
    /// Refused by the symlink-escape guard: nothing was written.
    Escaped,
    /// The object could not be materialized. The target is as it was.
    Failed(String),
}

/// What one fill settled before any content was fetched.
#[derive(Debug, Default)]
struct FillPlan {
    report: FillReport,
    wanted: Vec<Wanted>,
}

/// Decides, and performs, everything a fill can settle without the network.
///
/// Blocking from end to end: [`Node::fill_space`] runs it on the blocking pool.
fn plan_fill(
    node: &Node,
    space_id: &str,
    root_dir: &Path,
    listing: &[VersionSet],
    policy: &VersionPolicy,
    options: FillOptions,
) -> Result<FillPlan> {
    // One clock reading for the pass, and the store's rather than the bare
    // clock, so every path selects against the same instant (`plan_pass`,
    // mirror.rs).
    let now = node.store().read_instant()?;
    let mut report = FillReport {
        dry_run: options.dry_run,
        ..FillReport::default()
    };
    let mut wanted: Vec<Wanted> = Vec::new();
    // Detected before anything is written, the way a mirror pass does it: the
    // first claimant of a folded name wins and the rest are reported.
    let mut claimed: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for set in listing {
        // The name is judged before the target is built, because building it
        // is already the damage on a platform that reads more out of a path
        // than the protocol puts in (`plan_pass`, mirror.rs).
        if let Some(reason) = unsafe_name(&set.path) {
            report.skipped.push((set.path.clone(), reason));
            continue;
        }
        // The same guard `synch take` and the S3 gateway write through: a
        // published path only ever lands inside the space it belongs to.
        let target = match target_within(root_dir, space_id, &set.path) {
            Ok(target) => target,
            Err(e) => {
                report.skipped.push((set.path.clone(), e.to_string()));
                continue;
            }
        };

        let selected = match set.select(policy, now) {
            synch_store::Selection::Selected(entry) => *entry,
            // The policy selects nothing here — an `origin=` pin on an origin
            // that publishes no version of this path — so the path is not in
            // this fill's view. Whatever is on disk is ours and stays.
            synch_store::Selection::Absent => continue,
            // A strict fill never guesses, and unlike a strict mirror it has
            // nothing to take back: the local copy is this node's own
            // assertion, not a materialized guess, so the path is reported and
            // left exactly as it is.
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

        // A fill adds. A tombstone asks for a removal, which is the one thing
        // it will not do — `synch take` of that version is how a deletion is
        // adopted, deliberately and one path at a time (§8).
        if selected.kind == EntryKind::Tombstone || selected.kind == EntryKind::Dir {
            continue;
        }

        // What is here now, if anything. `symlink_metadata`, so a symlink is
        // seen as the link it is rather than followed.
        let on_disk = std::fs::symlink_metadata(&target).ok();
        if on_disk.as_ref().is_some_and(|m| m.is_dir()) {
            report.skipped.push((
                set.path.clone(),
                "a directory stands here, and a fill does not remove things".into(),
            ));
            continue;
        }

        // Two published paths that fold onto one local name — `Link` and
        // `link` on a case-insensitive filesystem — are not both materializable
        // here. The first claimant wins and the rest are reported, exactly as a
        // mirror does it: without the claim, `--force` would write one over the
        // other and call both of them filled.
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

        if selected.kind == EntryKind::Symlink {
            let wanted_target = selected.symlink_target.as_deref();
            let current = std::fs::read_link(&target)
                .ok()
                .is_some_and(|link| Some(link.to_string_lossy().as_ref()) == wanted_target);
            if current {
                report.current += 1;
            } else if on_disk.is_some() && !options.force {
                report.differing.push(set.path.clone());
            } else if options.dry_run {
                report.filled += 1;
                if on_disk.is_some() {
                    report.replaced.push(set.path.clone());
                }
            } else {
                match materialize_symlink(&target, wanted_target) {
                    Ok(_) => {
                        report.filled += 1;
                        if on_disk.is_some() {
                            report.replaced.push(set.path.clone());
                        }
                    }
                    Err(reason) => report.skipped.push((set.path.clone(), reason)),
                }
            }
            continue;
        }

        let Some(content) = selected.content else {
            report
                .skipped
                .push((set.path.clone(), "entry has no content".into()));
            continue;
        };

        if let Some(stat) = &on_disk {
            // Is the file here already the selected version? The scanner's own
            // `local_files` record answers with a stat wherever it can, which
            // is what keeps a second fill of a large space from re-hashing it;
            // a file the record cannot vouch for is hashed, but only when its
            // length leaves it able to be the version at all.
            //
            // A regular file or nothing: a *symlink* standing where the tree
            // publishes a file is a different kind of thing, whatever it
            // happens to point at, and `same_size_root` would follow it and
            // call a link to an identical file current.
            let here = stat
                .is_file()
                .then(|| {
                    indexed_content(node, space_id, &set.path, stat)
                        .or_else(|| same_size_root(&target, selected.size))
                })
                .flatten();
            if here == Some(content) {
                // Right bytes. The metadata is left alone deliberately: what a
                // file here carries is this node's own assertion, and a fill
                // that restamped it would republish every path it looked at.
                report.current += 1;
                continue;
            }
            if !options.force {
                report.differing.push(set.path.clone());
                continue;
            }
        }

        wanted.push(Wanted {
            path: set.path.clone(),
            target,
            content,
            size: selected.size,
            meta: Metadata::of(&selected),
            donors: node.donors_for(&selected, set)?,
            replacing: on_disk.is_some(),
        });
    }

    // Under `--force` the plan already knows what it would overwrite, and a
    // dry run has to report it without ever reaching the write.
    if options.dry_run {
        report.replaced.extend(
            wanted
                .iter()
                .filter(|w| w.replacing)
                .map(|w| w.path.clone()),
        );
    }
    Ok(FillPlan { report, wanted })
}

/// The content root the scanner recorded for a path, when the stat on disk
/// still proves that record describes the file that is there.
///
/// The rule is the scanner's own (`index_file`, scanner.rs): size, mtime and
/// platform identity all match, and the hash was taken comfortably after the
/// mtime it vouches for, so no same-size in-place rewrite can have shared the
/// stamp. Anything less answers `None`, and the caller hashes.
fn indexed_content(
    node: &Node,
    space_id: &str,
    relpath: &str,
    stat: &std::fs::Metadata,
) -> Option<Hash> {
    if !stat.is_file() {
        return None;
    }
    let known = node.store().local_file(space_id, relpath).ok().flatten()?;
    let fresh = known.size == stat.len()
        && known.mtime_ns == crate::scanner::mtime_nanos(stat)
        && known.file_id == crate::scanner::file_identity(stat)
        && known.scanned_at.saturating_sub(known.mtime_ns) >= crate::scanner::RACY_WINDOW_NS;
    fresh.then_some(known.content).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{node_with_space, published};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use synch_core::{now_ns, FileEntry, OriginId};

    fn peer() -> OriginId {
        OriginId::named("nas", "x.example").unwrap()
    }

    fn other() -> OriginId {
        OriginId::named("laptop", "x.example").unwrap()
    }

    /// A real wall-clock stamp, not a pre-epoch one every filesystem stores
    /// exactly.
    const STAMP: i64 = 1_700_000_000_123_456_789;

    /// Publishes `origin`'s version of a path, with its bytes in this node's
    /// CAS so the fetch has a local provider.
    fn publish(node: &Node, origin: &OriginId, path: &str, content: &[u8], mtime: i64) {
        publish_with_mode(node, origin, path, content, mtime, None);
    }

    /// Publishes `origin`'s version of a path as a symbolic link.
    fn publish_link(node: &Node, origin: &OriginId, path: &str, link_target: &str) {
        let mut entry = FileEntry::tombstone(STAMP, 1, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some(link_target.into());
        node.store()
            .put_entry(origin, "media", path, &entry)
            .unwrap();
    }

    fn publish_with_mode(
        node: &Node,
        origin: &OriginId,
        path: &str,
        content: &[u8],
        mtime: i64,
        mode: Option<u32>,
    ) {
        let root = node.store().ingest_bytes(content, now_ns()).unwrap();
        let mut entry = FileEntry::file(content.len() as u64, mtime, root, 1);
        entry.unix_mode = mode;
        node.store()
            .put_entry(origin, "media", path, &entry)
            .unwrap();
    }

    /// The whole contract in one pass: what is missing arrives, what already
    /// matches is left alone, and what differs is reported rather than
    /// overwritten — until `--force` says otherwise.
    #[tokio::test]
    async fn a_fill_adds_and_reports_rather_than_overwrites() {
        let (_data, space, node) = node_with_space().await;
        publish(&node, &peer(), "missing.txt", b"theirs", STAMP);
        publish(&node, &peer(), "same.txt", b"agreed", STAMP);
        publish(&node, &peer(), "ours.txt", b"theirs", STAMP);
        std::fs::write(space.path().join("same.txt"), b"agreed").unwrap();
        std::fs::write(space.path().join("ours.txt"), b"mine").unwrap();

        let report = node
            .fill_space("media", "", &VersionPolicy::Newest, FillOptions::default())
            .await
            .unwrap();
        assert_eq!(report.filled, 1, "{report:?}");
        assert_eq!(report.current, 1, "{report:?}");
        assert_eq!(report.differing, vec!["ours.txt".to_string()], "{report:?}");
        assert!(report.replaced.is_empty(), "{report:?}");
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(
            std::fs::read(space.path().join("missing.txt")).unwrap(),
            b"theirs"
        );
        assert_eq!(
            std::fs::read(space.path().join("ours.txt")).unwrap(),
            b"mine",
            "a local file that differs is left exactly as it is"
        );

        // The second pass has nothing to do: the file it wrote is current now.
        let report = node
            .fill_space("media", "", &VersionPolicy::Newest, FillOptions::default())
            .await
            .unwrap();
        assert_eq!(report.filled, 0, "{report:?}");
        assert_eq!(report.current, 2, "{report:?}");

        // `--force` is the bulk `synch take`: it names what it overwrote.
        let report = node
            .fill_space(
                "media",
                "",
                &VersionPolicy::Newest,
                FillOptions {
                    force: true,
                    dry_run: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(report.filled, 1, "{report:?}");
        assert_eq!(report.replaced, vec!["ours.txt".to_string()], "{report:?}");
        assert!(report.differing.is_empty(), "{report:?}");
        assert_eq!(
            std::fs::read(space.path().join("ours.txt")).unwrap(),
            b"theirs"
        );
        node.shutdown().await.unwrap();
    }

    /// A fill only ever adds. A tombstoned version, and a local file nobody
    /// publishes, both survive it.
    #[tokio::test]
    async fn a_fill_removes_nothing() {
        let (_data, space, node) = node_with_space().await;
        std::fs::write(space.path().join("deleted.txt"), b"still here").unwrap();
        std::fs::write(space.path().join("private.txt"), b"only mine").unwrap();
        node.store()
            .put_entry(
                &peer(),
                "media",
                "deleted.txt",
                &FileEntry::tombstone(STAMP, 1, None),
            )
            .unwrap();

        let report = node
            .fill_space("media", "", &VersionPolicy::Newest, FillOptions::default())
            .await
            .unwrap();
        assert_eq!(report.filled, 0, "{report:?}");
        assert!(report.differing.is_empty(), "{report:?}");
        assert!(space.path().join("deleted.txt").exists());
        assert!(space.path().join("private.txt").exists());

        // Not even under --force: replacing bytes is one thing, removing a
        // path is `synch take` of the tombstone.
        let report = node
            .fill_space(
                "media",
                "",
                &VersionPolicy::Newest,
                FillOptions {
                    force: true,
                    dry_run: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(report.filled, 0, "{report:?}");
        assert!(space.path().join("deleted.txt").exists());
        node.shutdown().await.unwrap();
    }

    /// The point of stamping: a filled path publishes as the version that was
    /// filled, not as a newer one that would win every `newest` selection in
    /// the cluster.
    #[tokio::test]
    async fn filling_then_scanning_republishes_the_version_that_was_filled() {
        let (_data, _space, node) = node_with_space().await;
        publish_with_mode(&node, &peer(), "f.txt", b"theirs", STAMP, Some(0o100640));
        let theirs = node
            .store()
            .entry(&peer(), "media", "f.txt")
            .unwrap()
            .unwrap();

        let report = node
            .fill_space("media", "", &VersionPolicy::Newest, FillOptions::default())
            .await
            .unwrap();
        assert_eq!(report.filled, 1, "{report:?}");
        node.scan_publish_push().await.unwrap();

        let ours = published(&node, "media", "f.txt");
        assert_eq!(ours.content, theirs.content, "the same object");
        assert_eq!(
            ours.mtime_ns, theirs.mtime_ns,
            "the origin's mtime, so `newest` does not flip to this node"
        );
        #[cfg(unix)]
        assert_eq!(ours.unix_mode.map(|m| m & 0o777), Some(0o640));
        // And the path is no longer divergent — one version, two attestors.
        let versions = node.versions("media", "f.txt").unwrap();
        assert_eq!(versions.version_count(), 1, "{versions:?}");
        node.shutdown().await.unwrap();
    }

    /// `strict` reports a divergent path and touches nothing. Unlike a strict
    /// mirror it removes no stale copy: what is here is this node's own
    /// assertion, not a materialized guess.
    #[tokio::test]
    async fn a_strict_fill_reports_divergence_and_leaves_the_local_copy() {
        let (_data, space, node) = node_with_space().await;
        publish(&node, &peer(), "split.txt", b"theirs", 100);
        publish(&node, &other(), "split.txt", b"others", 200);
        publish(&node, &peer(), "agreed.txt", b"agreed", STAMP);
        std::fs::write(space.path().join("split.txt"), b"mine").unwrap();

        let report = node
            .fill_space("media", "", &VersionPolicy::Strict, FillOptions::default())
            .await
            .unwrap();
        assert_eq!(report.filled, 1, "the undisputed path is written");
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert_eq!(report.skipped[0].0, "split.txt");
        assert!(report.skipped[0].1.contains("strict"), "{report:?}");
        assert_eq!(
            std::fs::read(space.path().join("split.txt")).unwrap(),
            b"mine"
        );
        node.shutdown().await.unwrap();
    }

    /// An `origin=` pin fills that origin's versions, and says nothing about
    /// paths it does not publish.
    #[tokio::test]
    async fn an_origin_pinned_fill_takes_that_origins_versions() {
        let (_data, space, node) = node_with_space().await;
        publish(&node, &peer(), "f.txt", b"theirs", 100);
        publish(&node, &other(), "f.txt", b"others", 200);
        publish(&node, &other(), "only-theirs.txt", b"x", 300);

        let report = node
            .fill_space(
                "media",
                "",
                &VersionPolicy::Origin(peer()),
                FillOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(report.filled, 1, "{report:?}");
        assert_eq!(
            std::fs::read(space.path().join("f.txt")).unwrap(),
            b"theirs"
        );
        assert!(
            !space.path().join("only-theirs.txt").exists(),
            "a path the pinned origin does not publish is not in this fill's view"
        );
        node.shutdown().await.unwrap();
    }

    /// A dry run decides everything and writes nothing — including the list of
    /// what `--force` would overwrite, which is what it is for.
    #[tokio::test]
    async fn a_dry_run_writes_nothing() {
        let (_data, space, node) = node_with_space().await;
        publish(&node, &peer(), "missing.txt", b"theirs", STAMP);
        publish(&node, &peer(), "ours.txt", b"theirs", STAMP);
        std::fs::write(space.path().join("ours.txt"), b"mine").unwrap();

        let report = node
            .fill_space(
                "media",
                "",
                &VersionPolicy::Newest,
                FillOptions {
                    force: true,
                    dry_run: true,
                },
            )
            .await
            .unwrap();
        assert!(report.dry_run);
        assert_eq!(report.filled, 2, "{report:?}");
        assert_eq!(report.replaced, vec!["ours.txt".to_string()], "{report:?}");
        assert!(!space.path().join("missing.txt").exists());
        assert_eq!(
            std::fs::read(space.path().join("ours.txt")).unwrap(),
            b"mine"
        );
        node.shutdown().await.unwrap();
    }

    /// A prefix narrows the fill to one directory of the space.
    #[tokio::test]
    async fn a_prefix_fills_one_directory() {
        let (_data, space, node) = node_with_space().await;
        publish(&node, &peer(), "talks/a.txt", b"a", STAMP);
        publish(&node, &peer(), "notes/b.txt", b"b", STAMP);

        let report = node
            .fill_space(
                "media",
                "talks/",
                &VersionPolicy::Newest,
                FillOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(report.filled, 1, "{report:?}");
        assert!(space.path().join("talks/a.txt").exists());
        assert!(!space.path().join("notes/b.txt").exists());
        node.shutdown().await.unwrap();
    }

    /// A fill writes where the scanner will find it, so a space this node does
    /// not index is refused rather than materialized somewhere nothing
    /// publishes.
    #[tokio::test]
    async fn a_space_this_node_does_not_index_is_refused() {
        let (_data, _space, node) = node_with_space().await;
        publish(&node, &peer(), "f.txt", b"theirs", STAMP);
        let refused = node
            .fill_space(
                "elsewhere",
                "",
                &VersionPolicy::Newest,
                FillOptions::default(),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("no local space elsewhere"), "{refused}");
        node.shutdown().await.unwrap();
    }

    /// A symlink is a version like any other: written where nothing stands,
    /// reported where something else does. A fold collision is reported rather
    /// than resolved by whichever path happens to be written second.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_and_folded_names_are_written_or_reported_but_never_clobbered() {
        let (_data, space, node) = node_with_space().await;
        publish_link(&node, &peer(), "link", "target.txt");
        publish_link(&node, &peer(), "taken", "elsewhere.txt");
        std::fs::write(space.path().join("taken"), b"a real file").unwrap();
        // Two published paths, one local name on a case-insensitive filesystem.
        publish(&node, &peer(), "Fold.txt", b"upper", STAMP);
        publish(&node, &peer(), "fold.txt", b"lower", STAMP);

        let report = node
            .fill_space("media", "", &VersionPolicy::Newest, FillOptions::default())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_link(space.path().join("link"))
                .unwrap()
                .to_string_lossy(),
            "target.txt"
        );
        assert_eq!(
            report.differing,
            vec!["taken".to_string()],
            "a file standing where a link is published is reported, not replaced: {report:?}"
        );
        assert_eq!(
            std::fs::read(space.path().join("taken")).unwrap(),
            b"a real file"
        );
        assert_eq!(
            report.skipped.len(),
            1,
            "one of the folded pair is refused: {report:?}"
        );
        assert!(report.skipped[0].1.contains("folding"), "{report:?}");
        node.shutdown().await.unwrap();
    }

    /// The scanner's own record answers the currency check without a read: a
    /// chmod 000 proves the second fill never opened the file, because hashing
    /// it would have failed and reported the path as differing.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_indexed_file_is_believed_without_a_read() {
        let (_data, space, node) = node_with_space().await;
        let target = space.path().join("f.txt");
        std::fs::write(&target, b"agreed").unwrap();
        // Backdated past the racy window, so the record the scan leaves is one
        // a later stat is allowed to be trusted against.
        std::fs::File::options()
            .write(true)
            .open(&target)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new().set_modified(
                    std::time::SystemTime::now() - std::time::Duration::from_secs(10),
                ),
            )
            .unwrap();
        node.scan_publish_push().await.unwrap();
        publish(&node, &peer(), "f.txt", b"agreed", STAMP);

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();
        let report = node
            .fill_space("media", "", &VersionPolicy::Newest, FillOptions::default())
            .await
            .unwrap();
        assert_eq!(report.current, 1, "{report:?}");
        assert!(report.differing.is_empty(), "{report:?}");
        node.shutdown().await.unwrap();
    }
}
