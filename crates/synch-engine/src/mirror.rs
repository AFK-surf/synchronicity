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
//!
//! A materialized file carries the metadata its entry published as well as its
//! bytes: the origin's mtime, and its advisory unix mode masked to the
//! permission bits (§4.2). A mirror is meant to be usable as the tree it
//! mirrors — `rsync`ed onward, served, executed — and a directory of
//! `0644 Just Now` files is a different tree from the one the origin published.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use synch_core::{ChunkRanges, EntryKind};
use synch_store::{EntryRow, MirrorRow, VersionPolicy};

use crate::{
    error::{EngineError, Result},
    node::{paths_overlap, stored_root, MirrorWrite, Node},
};

/// What one mirror pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MirrorReport {
    /// Files written or refreshed.
    pub written: usize,
    /// Files already up to date.
    pub current: usize,
    /// Files whose bytes were already current but whose mode or mtime had
    /// drifted from the selected version, and were stamped back onto it.
    pub retouched: usize,
    /// Files removed: the selected version is a tombstone, or the path has
    /// left the unified tree entirely.
    pub removed: usize,
    /// Files whose bytes were not copied at all: the mirror shares a filesystem
    /// with the CAS, so the file and the object it came from are the same
    /// extents (`docs/DELTA-SYNC.md` §3.5). A subset of `written`.
    pub reflinked: usize,
    /// Bytes that crossed the network to write the files this pass wrote.
    pub fetched_bytes: u64,
    /// Bytes that did not, because a local donor already held them and the new
    /// version's own tree proved it (`docs/DELTA-SYNC.md` §3.3).
    ///
    /// The pair is what turns "the pass took four seconds" into "it reused
    /// 98.9 GB and fetched 1.1 GB", which is the difference between a mirror an
    /// operator trusts and one they watch suspiciously.
    pub reused_bytes: u64,
    /// Entries skipped, with the reason — including every path a `strict`
    /// mirror refused to guess at, and every path whose bytes landed but whose
    /// metadata the filesystem refused.
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
            let Some(local_path) = existing.local_path.as_deref() else {
                continue;
            };
            if paths_overlap(&path, &stored_root(local_path)) {
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
        // Wake the standing loop rather than letting the mirror wait out the
        // interval for its first pass.
        self.mirror_wake().notify_one();
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
        let mirror = {
            let store = self.store().clone();
            let key = key.clone();
            crate::blocking::offload(move || {
                store
                    .mirror(&key)?
                    .ok_or_else(|| EngineError::not_found(format!("mirror {key}")))
            })
            .await?
        };
        self.sync_mirror_row(&mirror).await
    }

    async fn sync_mirror_row(&self, mirror: &MirrorRow) -> Result<MirrorReport> {
        // Passes serialize node-wide: whether the standing loop or `synch
        // mirror sync` asked, two passes over one root would plan against
        // each other's half-written state.
        let _pass = self.lock_mirrors().await;
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
        // `sub/passwd` is judged, exactly as it would be with the two steps
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
                plan_pass(&node, &root_dir, &listing, &policy)
            })
            .await?
        };
        let MirrorPass {
            mut report,
            known,
            wanted,
        } = plan;

        // Phase 2: fetch what phase 1 could not satisfy locally — building each
        // new object in the CAS out of the old one where it can — and
        // materialize it as it lands.
        for mut want in wanted {
            if let Some(expected) = want.recoverable_donor {
                match self
                    .cas_backend()
                    .ingest_file(want.target.clone(), synch_core::now_ns())
                    .await
                {
                    Ok(ingested) if ingested.root == expected => {
                        tracing::debug!(
                            target = %want.target.display(),
                            root = %expected,
                            "re-ingested a mirrored file the CAS had collected"
                        );
                        want.donors.push(synch_store::Donor(expected));
                    }
                    Ok(_) => {}
                    Err(error) => tracing::debug!(
                        target = %want.target.display(),
                        root = %expected,
                        %error,
                        "could not recover a delta donor from the mirror"
                    ),
                }
            }
            let fetched = self
                .fetch_all_from(&want.content, want.size, &want.donors)
                .await?;
            if !fetched.complete {
                report
                    .skipped
                    .push((want.path, "no provider could serve the content".into()));
                continue;
            }
            // Counted in bytes rather than groups, and clamped to the object,
            // so the tail group of a 100-byte file does not report 16 KiB.
            let bytes_of = |groups: &ChunkRanges| {
                groups
                    .ranges
                    .iter()
                    .map(|r| {
                        let end = r
                            .end
                            .saturating_mul(synch_core::CHUNK_GROUP_SIZE)
                            .min(want.size);
                        end.saturating_sub(r.start.saturating_mul(synch_core::CHUNK_GROUP_SIZE))
                    })
                    .sum::<u64>()
            };
            report.fetched_bytes += bytes_of(&fetched.fetched);
            report.reused_bytes += bytes_of(&fetched.promoted);
            // Cloned out of the CAS and renamed into place: a mirror of
            // multi-gigabyte objects must not hold one in memory, and a pass
            // interrupted halfway must not leave a truncated file wearing a
            // complete file's name (§7.2, §9.4).
            //
            // The escape guard is taken again here, in the same blocking step
            // as the write it protects. Phase 1 checked this path too, but a
            // fetch stands between the two and the whole point of the guard is
            // to describe the directory the write is about to land in.
            let root = root_dir.clone();
            let path = want.path.clone();
            let written_target = want.target.clone();
            let target = want.target.clone();
            let ready = crate::blocking::offload(move || {
                if escapes_via_symlink(&root, &path) {
                    return Ok(false);
                }
                // A directory standing where a file belongs is cleared first, if
                // it is empty. The tree has published this path as a file and the
                // write below would meet `EISDIR`; the sweep tidies the directory
                // in phase 3, *after* this, so on its own that only fixes the
                // pass after next. A non-empty directory still fails here, which
                // is correct — its children are swept in phase 3 and the pass
                // after that succeeds.
                if target.symlink_metadata().is_ok_and(|meta| meta.is_dir()) {
                    let _ = std::fs::remove_dir(&target);
                }
                Ok(true)
            })
            .await?;
            let outcome = if !ready {
                Written::Escaped
            } else {
                // A materialization that fails takes its path down with it and
                // nothing else: the target is untouched, and the next pass
                // tries again.
                let kind = match self
                    .materialize_blob(&want.content, want.size, want.target.clone())
                    .await
                {
                    Ok(kind) => kind,
                    Err(e) => {
                        report
                            .skipped
                            .push((want.path, format!("content could not be written: {e}")));
                        continue;
                    }
                };
                let target = want.target.clone();
                let content = want.content;
                let meta = want.meta;
                crate::blocking::offload(move || {
                    // The bytes are the file; its metadata is stamped on right
                    // after, and a filesystem that refuses the stamp — a mount
                    // that will not take the mode, a foreign owner — is reported
                    // rather than allowed to fail the whole pass.
                    let stamped = apply_metadata(&target, meta);
                    // No read-back: a successful write is trusted the way the CAS
                    // trusts its own payloads (§2.1). What later passes trust is
                    // the record anchored to the fresh stat — anything that moves
                    // the file moves the stat, and the next pass hashes again.
                    Ok(match MirrorWrite::of(&target, content) {
                        Some(record) => match stamped {
                            Ok(()) => Written::Fully(kind, record),
                            Err(e) => Written::WithoutMetadata(kind, record, e.to_string()),
                        },
                        None => Written::Failed(
                            "the file was gone before its write could be recorded".into(),
                        ),
                    })
                })
                .await?
            };
            // Remembered whenever the bytes landed, so later passes can
            // believe the file's stat instead of re-hashing it
            // (`Node::note_mirror_write`).
            if let Written::Fully(_, record) | Written::WithoutMetadata(_, record, _) = &outcome {
                self.note_mirror_write(&written_target, record.clone());
            }
            match outcome {
                Written::Fully(kind, _) => {
                    report.written += 1;
                    report.reflinked += usize::from(kind == crate::CloneKind::Reflink);
                }
                Written::WithoutMetadata(kind, _, why) => {
                    report.written += 1;
                    report.reflinked += usize::from(kind == crate::CloneKind::Reflink);
                    report.skipped.push((
                        want.path,
                        format!("content written, but its metadata could not be reproduced: {why}"),
                    ));
                }
                Written::Escaped => report.skipped.push((
                    want.path,
                    "path resolves through a symlink; refusing to write outside the mirror".into(),
                )),
                Written::Failed(why) => report
                    .skipped
                    .push((want.path, format!("content could not be written: {why}"))),
            }
        }

        // Phase 3: a path that has left the unified tree altogether — every
        // origin's entry for it gone, tombstones included — leaves the mirror
        // too. The listing cannot report those, so the last step is to look at
        // what is on disk and drop whatever the tree no longer names.
        let removed = crate::blocking::offload(move || {
            let root = root_dir;
            sweep(&root, &root, &known)
        })
        .await?;
        report.removed += removed.len();
        // Whatever was proven about those targets proves nothing now: a file
        // that comes back under the same path starts unproven.
        for path in removed {
            self.forget_mirror_write(&path);
        }
        Ok(report)
    }

    /// Brings every configured mirror up to date, one pass each.
    ///
    /// A mirror whose pass fails is reported in its slot rather than stopping
    /// the rest: this is the standing loop's body, and one broken mirror must
    /// not starve the others.
    pub async fn sync_all_mirrors(&self) -> Result<Vec<(String, Result<MirrorReport>)>> {
        let mut out = Vec::new();
        let node = self.clone();
        let mirrors = crate::blocking::offload(move || Ok(node.store().mirrors()?)).await?;
        for mirror in mirrors {
            let path = mirror.local_path.clone();
            let report = self.sync_mirror_row(&mirror).await;
            out.push((path, report));
        }
        Ok(out)
    }

    /// Runs the standing mirror loop until `shutdown` resolves (§7.2).
    ///
    /// A pass runs on every wake — a head flipping complete on any exchange,
    /// a local publish, a freshly added mirror — and one runs before the
    /// first wait, so a tree the node already holds materializes at startup
    /// rather than on the first change. The `mirror_interval` fallback is the
    /// backstop for drift nobody rang about: a `chmod` moves nothing a record
    /// holds, and only a pass repairs it.
    pub async fn run_mirrors(&self, shutdown: impl std::future::Future<Output = ()>) {
        let shutdown = std::pin::pin!(shutdown);
        let mut shutdown = shutdown;
        let wake = self.mirror_wake();
        loop {
            self.sync_all_mirrors_logged().await;
            tokio::select! {
                _ = &mut shutdown => return,
                _ = wake.notified() => {}
                _ = tokio::time::sleep(crate::aae::jittered(self.config().mirror_interval)) => {}
            }
        }
    }

    /// One pass over every mirror, logged rather than streamed: the standing
    /// loop has no client on the other end. A quiet pass says nothing — a
    /// tree this size reports `current` on every interval, and that is not
    /// news.
    async fn sync_all_mirrors_logged(&self) {
        match self.sync_all_mirrors().await {
            Ok(reports) => {
                for (path, report) in reports {
                    match report {
                        Ok(report)
                            if report.written + report.removed + report.retouched > 0
                                || !report.skipped.is_empty() =>
                        {
                            tracing::info!(
                                path = %path,
                                written = report.written,
                                current = report.current,
                                retouched = report.retouched,
                                removed = report.removed,
                                skipped = report.skipped.len(),
                                fetched_bytes = report.fetched_bytes,
                                reused_bytes = report.reused_bytes,
                                "mirror pass"
                            );
                            for (skipped, reason) in &report.skipped {
                                tracing::info!(path = %path, skipped = %skipped, reason = %reason, "mirror skipped a path");
                            }
                        }
                        Ok(report) => {
                            tracing::debug!(path = %path, current = report.current, "mirror pass")
                        }
                        Err(e) => {
                            tracing::warn!(path = %path, error = %e, "mirror pass failed")
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not list mirrors"),
        }
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
    /// The metadata to stamp on once the bytes are there.
    meta: Metadata,
    /// Where the bytes might already be, in §3.2 priority order
    /// (`docs/DELTA-SYNC.md`).
    donors: Vec<synch_store::Donor>,
    /// Root the target itself can become through backend ingest before fetch.
    recoverable_donor: Option<synch_core::Hash>,
}

/// How one write in phase 2 ended.
#[derive(Debug)]
enum Written {
    /// Bytes and metadata both, how the bytes got there, and the record
    /// later passes will trust.
    Fully(crate::CloneKind, MirrorWrite),
    /// The bytes landed; the filesystem refused the metadata.
    WithoutMetadata(crate::CloneKind, MirrorWrite, String),
    /// Refused by the symlink-escape guard: nothing was written.
    Escaped,
    /// The object could not be materialized. The target is as it was.
    Failed(String),
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
    node: &Node,
    root_dir: &Path,
    listing: &[synch_store::VersionSet],
    policy: &VersionPolicy,
) -> Result<MirrorPass> {
    // Detect folding collisions before writing anything: the
    // lexicographically first path wins and the rest are reported.
    let mut claimed: HashMap<String, String> = HashMap::new();
    // One clock reading for the pass, so every path in it selects against the
    // same instant — and the store's reading rather than the bare clock, or a
    // node whose clock lags the cluster clamps every honest entry to it, ties,
    // and mirrors whichever version has the greater content hash
    // (`Store::read_instant`).
    let now = node.store().read_instant()?;
    let mut report = MirrorReport::default();
    let mut known: HashSet<String> = HashSet::new();
    let mut wanted: Vec<WantedContent> = Vec::new();

    {
        for set in listing {
            known.insert(set.path.clone());
            // Before the target path is built, because building it is already
            // the damage: on Windows `Path::join` reads a backslash as a
            // separator and a drive-prefixed argument as a root, so a published
            // `..\..\Users\x` or `C:\Windows\x` names a file outside the
            // mirror root — and the branches below remove what they are given.
            // Both bytes are ordinary in a Unix filename, so they stay legal
            // where entries are published and are refused here, at the boundary
            // where they mean something.
            if let Some(reason) = unsafe_name(&set.path) {
                report.skipped.push((set.path.clone(), reason));
                continue;
            }
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
            let selected = match set.select(policy, now) {
                synch_store::Selection::Selected(entry) => *entry,
                // The policy selects nothing here — an `origin=` pin on an
                // origin that publishes no version of this path — so the path
                // is not in this mirror's view.
                synch_store::Selection::Absent => {
                    report.removed += remove_if_present(&target)?;
                    node.forget_mirror_write(&target);
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
                    if removed > 0 {
                        node.forget_mirror_write(&target);
                    }
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
                node.forget_mirror_write(&target);
                continue;
            }
            if selected.kind == EntryKind::Dir {
                continue;
            }
            // Claim before dispatching on kind so symlinks participate in the
            // same folded-name collision rule as regular files (§7.2).
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
                match materialize_symlink(&target, selected.symlink_target.as_deref()) {
                    Ok(true) => report.written += 1,
                    Ok(false) => report.current += 1,
                    Err(reason) => report.skipped.push((set.path.clone(), reason)),
                }
                continue;
            }
            let Some(content) = selected.content else {
                report
                    .skipped
                    .push((set.path.clone(), "entry has no content".into()));
                continue;
            };
            let meta = Metadata::of(&selected);
            // The currency check: is the file on disk already the selected
            // version? A record this process holds answers with a stat — the
            // mirror wrote or hashed the file itself, and length, stored
            // mtime, and platform identity all still match, past the racy
            // window — because nothing that moves the file leaves the stat
            // standing. Without a record the content speaks for itself: a
            // file of the right length is hashed, because that hash *is* the
            // answer, and the answer becomes the record.
            let recorded = node.mirror_write_was(&target);
            if let Some(recorded) = &recorded {
                if let Ok(stat) = std::fs::metadata(&target) {
                    if stat.is_file() && still_current(recorded, &stat, &content) {
                        // Believed without a read. Only the metadata can have
                        // drifted: a bare chmod moves nothing the record
                        // holds.
                        if metadata_matches(&target, meta) {
                            report.current += 1;
                        } else if let Err(e) = apply_metadata(&target, meta) {
                            report.skipped.push((
                                set.path.clone(),
                                format!(
                                    "content is current, but its metadata could not be reproduced: {e}"
                                ),
                            ));
                        } else {
                            // The stamp moved the mtime; re-anchor the record
                            // to the stat it leaves behind.
                            note_record(node, &target, content);
                            report.retouched += 1;
                        }
                        continue;
                    }
                }
            }

            let on_disk = same_size_root(&target, selected.size);
            if on_disk == Some(content) {
                // Right bytes, and possibly the wrong mode or mtime: a local
                // `chmod`, a file this mirror wrote before it stamped metadata
                // at all, or a mode the origin has since changed without
                // touching the content. Repairing it is a `stat` and a syscall
                // or two — refetching the object to fix a permission bit is
                // not.
                if metadata_matches(&target, meta) {
                    report.current += 1;
                } else if let Err(e) = apply_metadata(&target, meta) {
                    report.skipped.push((
                        set.path.clone(),
                        format!(
                            "content is current, but its metadata could not be reproduced: {e}"
                        ),
                    ));
                } else {
                    report.retouched += 1;
                }
                // The hash just proved the file; anchor the record to the
                // stat the pass leaves behind (a retouch moved the mtime).
                // This is also what graduates a racily-clean record: once the
                // proof is comfortably newer than the mtime it vouches for,
                // later passes trust the stat and skip this hash.
                note_record(node, &target, content);
                continue;
            }

            // The file is not the selected version. A file that is not there
            // proves nothing, and whatever was recorded about it is stale.
            if on_disk.is_none() {
                node.forget_mirror_write(&target);
            }

            // Where the bytes of this version might already be (§3.2). Donors
            // are CAS objects and nothing else, so that the descent has one
            // shape of thing to reason about — but the capability a file donor
            // would buy is kept, and this is where it is paid for.
            //
            // The case is a real one: the CAS collected the version this mirror
            // is sitting on, so the lineage names a root nothing here holds,
            // while the bytes of that root are right there in the target file.
            // Rather than teach promotion about files, the file is ingested and
            // becomes the ordinary CAS donor it is a copy of — one pass over a
            // file this node was about to rewrite anyway. Only when delta would
            // use it: below `delta_min_size` there is no descent to feed.
            let donors = node.donors_for(&selected, set)?;
            let recoverable_donor =
                if donors.is_empty() && selected.size >= node.config().delta_min_size {
                    donor_copy_on_disk(node, &selected, set, &target, on_disk)?
                } else {
                    None
                };
            wanted.push(WantedContent {
                path: set.path.clone(),
                target,
                content,
                size: selected.size,
                meta,
                donors,
                recoverable_donor,
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
/// The link's own metadata is not reproduced: its mode is meaningless on every
/// unix that matters, and stamping a link's times without following it needs
/// `utimensat(AT_SYMLINK_NOFOLLOW)`, which `std` does not expose. Following the
/// link instead would stamp whatever it points at — including a file outside
/// the mirror — which is precisely what this module refuses to do everywhere
/// else.
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

/// The metadata a mirror reproduces alongside a file's bytes (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Metadata {
    /// The origin's observed mtime, in unix nanoseconds.
    mtime_ns: i64,
    /// The origin's advisory unix mode, or `None` where it published none —
    /// a Windows origin, or a row materialized before the view carried the
    /// column. Unknown means "leave the mode alone", never "reset it".
    unix_mode: Option<u32>,
}

impl Metadata {
    fn of(entry: &EntryRow) -> Metadata {
        Metadata {
            mtime_ns: entry.mtime_ns,
            unix_mode: entry.unix_mode,
        }
    }
}

/// The bits of a published mode a mirror will reproduce.
///
/// The permission bits only: setuid, setgid and the sticky bit are deliberately
/// dropped. A mirror writes bytes a *peer* chose under a name that peer chose,
/// and the daemon may be running as root; reproducing a setuid bit would turn
/// "publish a file" into "plant a setuid binary in someone else's tree". §4.2
/// calls the mode advisory and best-effort, so declining the three bits that
/// grant authority costs nothing materialization promised.
const MODE_MASK: u32 = 0o777;

/// How far a stored timestamp may sit below the published one and still count
/// as that timestamp.
///
/// Filesystems coarsen: ext4 keeps nanoseconds, HFS+ whole seconds, FAT two.
/// Demanding exact equality would make every pass over such a filesystem
/// "repair" every file it had itself just stamped, forever. A stamp is only
/// ever coarsened downward, so a stored value inside this window below the
/// published one is the published one.
const MTIME_GRANULARITY_NS: i64 = 2_000_000_000;

/// True if `target` already carries the metadata `meta` describes.
///
/// An unreadable target answers "no" and the pass tries to stamp it, which
/// reports the real error rather than this guess.
fn metadata_matches(target: &Path, meta: Metadata) -> bool {
    let Ok(on_disk) = std::fs::metadata(target) else {
        return false;
    };
    let stored = crate::scanner::mtime_nanos(&on_disk);
    if !(0..MTIME_GRANULARITY_NS).contains(&meta.mtime_ns.saturating_sub(stored)) {
        return false;
    }
    #[cfg(unix)]
    if let Some(mode) = meta.unix_mode {
        use std::os::unix::fs::PermissionsExt;
        if on_disk.permissions().mode() & MODE_MASK != mode & MODE_MASK {
            return false;
        }
    }
    true
}

/// Stamps an entry's metadata onto a materialized file.
///
/// Times first and mode second, with owner-write restored while the stamp
/// happens: setting a file's times needs a writable descriptor, so a file whose
/// published mode is read-only — `0444` is an ordinary mode for published media
/// — cannot be stamped once its own mode has been applied, and a pass that got
/// the mode right would break the pass after it.
fn apply_metadata(target: &Path, meta: Metadata) -> std::io::Result<()> {
    #[cfg(unix)]
    let stamped = {
        use std::os::unix::fs::PermissionsExt;
        let current = std::fs::metadata(target)?.permissions().mode() & 0o7777;
        let desired = meta.unix_mode.map(|m| m & MODE_MASK).unwrap_or(current);
        let borrowed_write = current & 0o200 == 0;
        if borrowed_write {
            std::fs::set_permissions(target, std::fs::Permissions::from_mode(current | 0o200))?;
        }
        // Held rather than propagated, so a failed stamp cannot leave the file
        // wearing the write bit this function lent it.
        let stamped = set_modified(target, meta.mtime_ns);
        if desired != current || borrowed_write {
            std::fs::set_permissions(target, std::fs::Permissions::from_mode(desired))?;
        }
        stamped
    };
    #[cfg(not(unix))]
    let stamped = set_modified(target, meta.mtime_ns);
    stamped
}

/// Sets a file's modification time to a unix-nanosecond stamp.
fn set_modified(target: &Path, mtime_ns: i64) -> std::io::Result<()> {
    let times = std::fs::FileTimes::new().set_modified(system_time(mtime_ns));
    std::fs::File::options()
        .write(true)
        .open(target)?
        .set_times(times)
}

/// A unix-nanosecond stamp as a [`SystemTime`], pre-epoch stamps included.
fn system_time(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

/// The content root of the file at `target`, if it is the right length to be
/// the version being materialized.
///
/// This is the currency check's evidence of last resort, asked only of paths
/// no record vouches for — a daemon restart, a moved stat, a file the mirror
/// has never seen. Size first, because it settles almost every case for the
/// price of a `stat` — and a file of the wrong length is not hashed here at
/// all, because no hash of it could answer yes.
///
/// Streamed, because a mirror carries objects far larger than memory.
/// Anything unreadable answers `None`, and the pass rewrites it.
///
/// The root rather than a bare "current?": naming the object that is on the
/// disk is also what tells the pass whether the file is a version the descent
/// wanted and could not find (`docs/DELTA-SYNC.md` §3.2).
fn same_size_root(target: &Path, wanted_size: u64) -> Option<synch_core::Hash> {
    let metadata = std::fs::metadata(target).ok().filter(|m| m.is_file())?;
    if metadata.len() != wanted_size {
        return None;
    }
    hash_file(target)
}

/// True while a record and the stat describe the same file: same object,
/// same length, same stored mtime, same platform identity — and the record
/// is comfortably newer than that mtime, so no same-size in-place rewrite
/// can have shared the stamp (the scanner's racy window, scanner.rs).
/// Anything less and the file speaks for itself, hashed on this pass.
fn still_current(
    record: &MirrorWrite,
    stat: &std::fs::Metadata,
    content: &synch_core::Hash,
) -> bool {
    record.content == *content
        && record.size == stat.len()
        && record.mtime_ns == crate::scanner::mtime_nanos(stat)
        && record.file_id == crate::scanner::file_identity(stat)
        && record.recorded_at.saturating_sub(record.mtime_ns) >= crate::scanner::RACY_WINDOW_NS
}

/// Anchors a target's record to the stat currently on disk, or drops the
/// record if the file is already gone.
fn note_record(node: &Node, target: &Path, content: synch_core::Hash) {
    match MirrorWrite::of(target, content) {
        Some(record) => node.note_mirror_write(target, record),
        None => node.forget_mirror_write(target),
    }
}

/// Streams a file through BLAKE3 for its content root.
fn hash_file(target: &Path) -> Option<synch_core::Hash> {
    std::fs::File::open(target)
        .ok()
        .and_then(|file| synch_core::hash_reader(std::io::BufReader::new(file)).ok())
}

/// Identifies a donor the CAS has lost but the mirror is still sitting on
/// (`docs/DELTA-SYNC.md` §3.2).
///
/// Delta donors are CAS objects, which leaves one capability to account for:
/// the mirror materialized the previous version, the CAS then collected the
/// object it came from, and the bytes of that version are now only on the disk.
/// Rather than a second kind of donor threaded through the descent, the file is
/// ingested and *becomes* the object it is a copy of — after which everything
/// downstream is ordinary CAS-to-CAS delta.
///
/// Deliberately narrow. It runs only when the lineage named other versions and
/// this node holds none of them, only above `delta_min_size` where a descent
/// will actually happen, and only when the file turns out to *be* one of the
/// versions named. That last check is a pass over a file the mirror is about to
/// rewrite anyway; the ingest after it is a second one, and buys a rewrite that
/// costs the change rather than the object.
///
/// The async phase performs the backend ingest after this blocking planner has
/// returned. `known` is the file's root where the currency check already
/// computed it.
fn donor_copy_on_disk(
    node: &Node,
    selected: &EntryRow,
    versions: &synch_store::VersionSet,
    target: &Path,
    known: Option<synch_core::Hash>,
) -> Result<Option<synch_core::Hash>> {
    let wanted = node.donor_roots(selected, versions);
    if wanted.is_empty() || !target.is_file() {
        return Ok(None);
    }
    let Some(on_disk) = known.or_else(|| hash_file(target)) else {
        return Ok(None);
    };
    if !wanted.contains(&on_disk) {
        return Ok(None);
    }
    Ok(Some(on_disk))
}

/// Returns true if any ancestor of `rel` under `root` is a symlink, so that
/// writing or deleting at `root/rel` would resolve through it and escape the
/// root. The final component (the target itself) is not an ancestor and is
/// allowed to be a symlink.
///
/// Used by the mirror loop and by [`Node::adoption_target`](crate::Node): a
/// space root is canonicalized when it is added, but nothing canonicalizes its
/// *interior*, and a symlinked directory inside a space is an ordinary thing
/// for a user to have. Without this a client that can name a path can write and
/// delete through it, anywhere the daemon's uid reaches.
pub(crate) fn escapes_via_symlink(root: &Path, rel: &str) -> bool {
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
/// carries, and returns the targets that went.
fn sweep(root: &Path, dir: &Path, known: &HashSet<String>) -> Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut removed = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        // `is_dir` follows links, and a materialized symlink pointing at a
        // directory would then be descended into and its *contents* swept.
        // The sweep only ever looks at what the mirror itself wrote.
        let is_dir = std::fs::symlink_metadata(&path)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if is_dir {
            removed.extend(sweep(root, &path, known)?);
            // Remove an emptied directory so a later pass can materialize a
            // non-directory at the same path. Non-empty directories fail safely.
            let _ = std::fs::remove_dir(&path);
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
            removed.push(path);
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
    use crate::testkit::node;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use synch_core::{now_ns, FileEntry, Hash, OriginId};

    fn peer() -> OriginId {
        OriginId::named("nas", "x.example").unwrap()
    }

    fn other() -> OriginId {
        OriginId::named("laptop", "x.example").unwrap()
    }

    /// A fresh node with a mirror of "media" at a fresh target directory.
    async fn mirrored(policy: &VersionPolicy) -> (tempfile::TempDir, tempfile::TempDir, Node) {
        let (data, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), policy).unwrap();
        (data, target, node)
    }

    fn publish_entry(node: &Node, origin: &OriginId, path: &str, content: &[u8], mtime: i64) {
        publish_entry_with_mode(node, origin, path, content, mtime, None);
    }

    fn publish_entry_with_mode(
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

    /// A real wall-clock stamp, not a pre-epoch one every filesystem stores exactly.
    const STAMP: i64 = 1_700_000_000_123_456_789;

    fn on_disk_mtime(path: &Path) -> i64 {
        crate::scanner::mtime_nanos(&std::fs::metadata(path).unwrap())
    }

    #[cfg(unix)]
    fn on_disk_mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// What is in a directory, by name, in order.
    fn left_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// A recorded file is believed by stat without a read: a chmod 000 proves
    /// the pass never opened it — a hash would fail and rewrite it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_recorded_file_is_believed_without_a_read() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        publish_entry_with_mode(&node, &peer(), "f.txt", b"hello", STAMP, Some(0o100644));
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1, "{report:?}");

        let written = target.path().join("f.txt");
        std::fs::set_permissions(&written, std::fs::Permissions::from_mode(0o000)).unwrap();

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.retouched, 1, "{report:?}");
        assert_eq!(report.written, 0, "{report:?}");
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(on_disk_mode(&written), 0o644);
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.current, 1, "{report:?}");
        node.shutdown().await.unwrap();
    }

    /// An atomic replace spoofing the stamp lands on a different inode: the
    /// identity half of the record catches what timestamps cannot.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_atomic_replace_with_a_spoofed_mtime_is_repaired() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        publish_entry(&node, &peer(), "f.txt", b"hello", STAMP);
        node.sync_mirror(target.path()).await.unwrap();

        let written = target.path().join("f.txt");
        let staged = target.path().join("staged-replacement");
        std::fs::write(&staged, b"world").unwrap();
        set_modified(&staged, STAMP).unwrap();
        std::fs::rename(&staged, &written).unwrap();

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1, "{report:?}");
        assert_eq!(std::fs::read(&written).unwrap(), b"hello");
        node.shutdown().await.unwrap();
    }

    /// `newest` writes the winner and follows it; `origin=` writes only that origin's.
    #[tokio::test]
    async fn the_policies_write_the_selected_version() {
        for (policy, (expected, written)) in [
            (VersionPolicy::Newest, (b"ours".as_slice(), 2)),
            (VersionPolicy::Origin(peer()), (b"theirs".as_slice(), 1)),
        ] {
            let (_d, target, node) = mirrored(&policy).await;
            publish_entry(&node, &peer(), "f.txt", b"theirs", 100);
            publish_entry(&node, &other(), "f.txt", b"ours", 200);
            publish_entry(&node, &other(), "only-theirs.txt", b"x", 1);

            let report = node.sync_mirror(target.path()).await.unwrap();
            assert_eq!(report.written, written);
            assert_eq!(
                std::fs::read(target.path().join("f.txt")).unwrap(),
                expected
            );
            assert_eq!(
                target.path().join("only-theirs.txt").exists(),
                policy == VersionPolicy::Newest,
                "a path the pinned origin does not publish is not in its view"
            );
            node.shutdown().await.unwrap();
        }

        // The other origin publishes something newer still: the mirror moves.
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        publish_entry(&node, &peer(), "f.txt", b"theirs again", 300);
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(
            std::fs::read(target.path().join("f.txt")).unwrap(),
            b"theirs again"
        );
        node.shutdown().await.unwrap();
    }

    /// §7.2: strict never guesses — divergent paths are skipped and reported,
    /// stale copies removed, until the publishers agree.
    #[tokio::test]
    async fn a_strict_mirror_skips_and_reports_divergence() {
        let (_d, target, node) = mirrored(&VersionPolicy::Strict).await;
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

        // Materialized, then diverged: a stale copy standing in is the silent
        // wrong answer strict refuses.
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

    /// §8: a path leaves once every publisher deleted it or no tombstone
    /// points at it; `origin=` follows its own origin only.
    #[tokio::test]
    async fn deletions_converge_in_the_mirror() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        publish_entry(&node, &peer(), "a.txt", b"hello", 1);
        publish_entry(&node, &other(), "a.txt", b"hello", 1);
        publish_entry(&node, &peer(), "stays.txt", b"here", 1);
        node.sync_mirror(target.path()).await.unwrap();
        assert!(target.path().join("a.txt").exists());

        // One publisher deletes its copy: the other still publishes the path.
        node.store()
            .put_entry(
                &other(),
                "media",
                "a.txt",
                &FileEntry::tombstone(500, 2, None),
            )
            .unwrap();
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.removed, 0, "{report:?}");
        assert_eq!(
            std::fs::read(target.path().join("a.txt")).unwrap(),
            b"hello",
            "the surviving publisher's version is what the mirror carries"
        );

        // The last publisher deletes it too, and the path leaves the tree.
        node.store()
            .put_entry(
                &peer(),
                "media",
                "a.txt",
                &FileEntry::tombstone(500, 2, None),
            )
            .unwrap();
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.removed, 1);
        assert!(!target.path().join("a.txt").exists());

        // Left the tree with no tombstone to point at it: on disk but unnamed is swept.
        publish_entry(&node, &peer(), "sub/gone.txt", b"bye", 1);
        node.sync_mirror(target.path()).await.unwrap();
        node.store()
            .delete_entry(&peer(), "media", "sub/gone.txt")
            .unwrap();
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.removed, 1);
        assert!(!target.path().join("sub/gone.txt").exists());
        assert!(target.path().join("stays.txt").exists());
        node.shutdown().await.unwrap();

        // Pinned: the pin's tombstone is the answer even while another origin publishes.
        let (_d, target, node) = mirrored(&VersionPolicy::Origin(peer())).await;
        publish_entry(&node, &peer(), "a.txt", b"hello", 1);
        node.store()
            .put_entry(
                &other(),
                "media",
                "a.txt",
                &FileEntry::tombstone(500, 2, None),
            )
            .unwrap();
        node.sync_mirror(target.path()).await.unwrap();
        assert!(target.path().join("a.txt").exists());

        // Re-pointing is the policy change; the new pin's deletion removes the path.
        node.add_mirror("media", target.path(), &VersionPolicy::Origin(other()))
            .unwrap();
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.removed, 1);
        assert!(!target.path().join("a.txt").exists());
        node.shutdown().await.unwrap();
    }

    /// Never silently clobber (§7.2): fold collisions and invalid names are skipped.
    #[tokio::test]
    async fn colliding_and_invalid_names_are_skipped() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        publish_entry(&node, &peer(), "README.md", b"upper", 1);
        publish_entry(&node, &peer(), "readme.md", b"lower", 1);
        publish_entry(&node, &peer(), "aux.txt", b"reserved", 1);
        publish_entry(&node, &peer(), "trailing.", b"dot", 1);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(report.skipped.len(), 3);
        let collided = report
            .skipped
            .iter()
            .find(|(p, _)| p == "readme.md")
            .expect("the fold loser is skipped");
        assert!(collided.1.contains("collides"), "{report:?}");
        // The lexicographically first path wins.
        assert_eq!(
            std::fs::read(target.path().join("README.md")).unwrap(),
            b"upper"
        );
        node.shutdown().await.unwrap();
    }

    /// §7.2: the fold claim covers symlinks too, so a link cannot replace the
    /// file it folds onto.
    #[tokio::test]
    async fn a_symlink_cannot_clobber_a_file_it_folds_onto() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        publish_entry(&node, &peer(), "Link", b"a real file", 1);
        let mut link = synch_core::FileEntry::tombstone(100, 1, None);
        link.kind = EntryKind::Symlink;
        link.symlink_target = Some("../elsewhere".into());
        node.store()
            .put_entry(&peer(), "media", "link", &link)
            .unwrap();

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1, "only the first claimant is written");
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert_eq!(report.skipped[0].0, "link");
        assert!(report.skipped[0].1.contains("collides"));
        let written = target.path().join("Link");
        assert!(!std::fs::symlink_metadata(&written).unwrap().is_symlink());
        assert_eq!(std::fs::read(&written).unwrap(), b"a real file");
        node.shutdown().await.unwrap();
    }

    /// A path that was a directory can become a file again once it empties.
    #[tokio::test]
    async fn a_directory_that_empties_stops_blocking_the_path() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        publish_entry(&node, &peer(), "x/a", b"one", 1);
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert!(target.path().join("x").is_dir());

        // The origin retires the child and publishes the parent as a file.
        node.store()
            .put_entry(
                &peer(),
                "media",
                "x/a",
                &synch_core::FileEntry::tombstone(200, 2, None),
            )
            .unwrap();
        publish_entry(&node, &peer(), "x", b"now a file", 300);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert!(
            report.skipped.is_empty(),
            "the emptied directory must not block the file: {report:?}"
        );
        assert_eq!(
            std::fs::read(target.path().join("x")).unwrap(),
            b"now a file"
        );
        node.shutdown().await.unwrap();
    }

    /// Backslashes and drive-prefixed names are refused before any write or
    /// removal branch reaches the target, across every policy.
    #[tokio::test]
    async fn a_name_this_platform_cannot_open_is_refused_before_any_removal() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;

        let tombstoned = r"sub\..\..\escape.txt";
        let divergent = r"C:\Windows\hosts";
        let unpinned = r"D:\other\thing";
        // Where these are ordinary filenames they land inside the mirror, so
        // the removal branches have something for the refusal to keep.
        #[cfg(unix)]
        for name in [tombstoned, divergent, unpinned] {
            std::fs::write(target.path().join(name), b"not the mirror's to touch").unwrap();
        }

        // The three removal selections: a tombstone, a strict divergence, an unpinned path.
        node.store()
            .put_entry(
                &peer(),
                "media",
                tombstoned,
                &FileEntry::tombstone(500, 2, None),
            )
            .unwrap();
        publish_entry(&node, &peer(), divergent, b"mine", 1);
        publish_entry(&node, &other(), divergent, b"theirs", 2);
        publish_entry(&node, &other(), unpinned, b"theirs", 1);

        for policy in [
            VersionPolicy::Newest,
            VersionPolicy::Strict,
            VersionPolicy::Origin(peer()),
        ] {
            node.add_mirror("media", target.path(), &policy).unwrap();
            let report = node.sync_mirror(target.path()).await.unwrap();
            assert_eq!(report.removed, 0, "{policy:?}: {report:?}");
            assert_eq!(report.written, 0, "{policy:?}: {report:?}");
            assert_eq!(report.skipped.len(), 3, "{policy:?}: {report:?}");
            for (_, reason) in &report.skipped {
                assert!(reason.contains("reserved character"), "{reason}");
            }
            #[cfg(unix)]
            for name in [tombstoned, divergent, unpinned] {
                assert!(
                    target.path().join(name).exists(),
                    "{policy:?} removed {name}"
                );
            }
        }
        node.shutdown().await.unwrap();
    }

    /// A read-only file can still be restamped: the mode is applied after the
    /// times, borrowing the owner-write bit for the stamp.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_read_only_file_can_still_be_restamped() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        publish_entry_with_mode(
            &node,
            &peer(),
            "ro.txt",
            b"published",
            STAMP,
            Some(0o100444),
        );
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1, "{report:?}");
        let written = target.path().join("ro.txt");
        assert_eq!(on_disk_mode(&written), 0o444);

        // Something moved the timestamp on a file the mirror made read-only.
        std::fs::set_permissions(&written, std::fs::Permissions::from_mode(0o644)).unwrap();
        set_modified(&written, 1_800_000_000_000_000_000).unwrap();
        std::fs::set_permissions(&written, std::fs::Permissions::from_mode(0o444)).unwrap();

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.retouched, 1, "{report:?}");
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(on_disk_mode(&written), 0o444, "the mode is put back too");
        assert!((0..MTIME_GRANULARITY_NS).contains(&(STAMP - on_disk_mtime(&written))));
        node.shutdown().await.unwrap();
    }

    /// The bits that grant authority (setuid, setgid, sticky) are not reproduced.
    #[cfg(unix)]
    #[tokio::test]
    async fn setuid_and_friends_are_not_materialized() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        publish_entry_with_mode(&node, &peer(), "trap", b"payload", STAMP, Some(0o104755));

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1, "{report:?}");
        let mode = std::fs::metadata(target.path().join("trap"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "the permission bits are reproduced");
        assert_eq!(mode & 0o7000, 0, "setuid, setgid and sticky are not");

        // And the dropped bits are not read back as drift on the next pass.
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.current, 1, "{report:?}");
        assert_eq!(report.retouched, 0, "{report:?}");
        node.shutdown().await.unwrap();
    }

    /// A coarse filesystem truncates stamps, never advances them; treating
    /// that as drift would re-touch every file on every pass forever.
    #[test]
    fn a_coarsened_timestamp_is_not_drift() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let whole_second = (STAMP / 1_000_000_000) * 1_000_000_000;
        set_modified(&path, whole_second).unwrap();

        let published = Metadata {
            mtime_ns: STAMP,
            unix_mode: None,
        };
        assert!(metadata_matches(&path, published));
        // A stamp that genuinely moved — in either direction — is drift.
        set_modified(&path, STAMP + 1_000_000_000).unwrap();
        assert!(!metadata_matches(&path, published));
        set_modified(&path, STAMP - 10 * 1_000_000_000).unwrap();
        assert!(!metadata_matches(&path, published));
    }

    /// Materializing replaces whatever was there whole, leaves nothing beside
    /// it, and the tiny-object path comes out of the index.
    #[tokio::test]
    async fn materializing_an_object_replaces_the_file_and_leaves_no_residue() {
        let (_d, node) = node().await;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("disk.img");
        const GROUP: usize = 16 * 1024;

        let old: Vec<u8> = (0..8 * GROUP).map(|i| (i * 11 + 1) as u8).collect();
        let mut new = old.clone();
        new[3 * GROUP..4 * GROUP].fill(0xa5);
        std::fs::write(&target, &old).unwrap();
        let root = node.store().ingest_bytes(&new, now_ns()).unwrap();

        let kind = node
            .materialize_blob(&root, new.len() as u64, &target)
            .await
            .unwrap();
        assert!(matches!(
            kind,
            crate::CloneKind::Reflink | crate::CloneKind::Copy
        ));
        assert_eq!(std::fs::read(&target).unwrap(), new);
        assert_eq!(left_in(dir.path()), vec!["disk.img".to_string()]);

        // And an object small enough to live in the index comes out of it.
        let root = node.store().ingest_bytes(b"tiny", now_ns()).unwrap();
        node.materialize_blob(&root, 4, &target).await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"tiny");
        assert_eq!(left_in(dir.path()), vec!["disk.img".to_string()]);
        node.shutdown().await.unwrap();
    }

    /// A materialization that dies partway leaves the target as it was; the
    /// abandoned staging file goes with the failure.
    #[tokio::test]
    async fn a_torn_materialization_leaves_the_target_untouched() {
        let (_d, node) = node().await;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("disk.img");
        let old: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        std::fs::write(&target, &old).unwrap();

        // An object this node does not hold at all.
        let absent = Hash::new(b"nobody has this");
        let err = node
            .materialize_blob(&absent, 100_000, &target)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not in the local store"), "{err}");

        // One removed before materialization likewise leaves the target whole.
        let new: Vec<u8> = (0..100_000).map(|i| (i % 13) as u8).collect();
        let root = node.store().ingest_bytes(&new, now_ns()).unwrap();
        node.store().delete_blob(&root).unwrap();
        assert!(node
            .materialize_blob(&root, new.len() as u64, &target)
            .await
            .is_err());

        assert_eq!(
            std::fs::read(&target).unwrap(),
            old,
            "the target must be exactly what it was"
        );
        assert_eq!(
            left_in(dir.path()),
            vec!["disk.img".to_string()],
            "the abandoned staging file went with the failure"
        );
        node.shutdown().await.unwrap();
    }

    /// The interval backstops a change no bell covered; the `add_mirror` wake
    /// drives the first pass (the whole of the wake path).
    #[tokio::test]
    async fn the_mirror_loop_falls_back_to_its_interval() {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let mut config = NodeConfig::loopback(dir.path());
        config.mirror_interval = Duration::from_millis(40);
        let node = Node::open(config).await.unwrap();
        let target = tempfile::tempdir().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let runner = node.clone();
        let handle = tokio::spawn(async move {
            runner
                .run_mirrors(async {
                    let _ = rx.await;
                })
                .await;
        });

        publish_entry(&node, &peer(), "first.txt", b"one", 1);
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        assert!(
            crate::testkit::eventually(|| target.path().join("first.txt").exists()).await,
            "the wake ran"
        );

        // Nothing rang for the second publish; only the interval carries it.
        publish_entry(&node, &peer(), "second.txt", b"two", 1);
        assert!(
            crate::testkit::eventually(|| {
                std::fs::read(target.path().join("second.txt"))
                    .ok()
                    .as_deref()
                    == Some(b"two")
            })
            .await,
            "nothing rang for this one; the interval pass carried it"
        );
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the loop must stop promptly")
            .unwrap();
        node.shutdown().await.unwrap();
    }

    /// A planted symlink ancestor cannot get the mirror to write through it out of the root.
    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_ancestor_is_refused() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc", root.path().join("sub")).unwrap();
        assert!(escapes_via_symlink(root.path(), "sub/passwd"));
        // A real directory ancestor, and the symlink leaf itself, are fine.
        std::fs::create_dir(root.path().join("real")).unwrap();
        assert!(!escapes_via_symlink(root.path(), "real/file.txt"));
        assert!(!escapes_via_symlink(root.path(), "sub"));
        assert!(!escapes_via_symlink(root.path(), "brandnew/file.txt"));
    }

    /// §7.2: a mirror writes a real symlink, idempotently; retargeting
    /// replaces rather than writing beside it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_mirror_materializes_a_symlink_as_a_symlink() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        let mut entry = synch_core::FileEntry::tombstone(100, 1, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some("../elsewhere".into());
        node.store()
            .put_entry(&peer(), "media", "link", &entry)
            .unwrap();

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1, "{report:?}");
        let written = target.path().join("link");
        assert!(std::fs::symlink_metadata(&written).unwrap().is_symlink());
        assert_eq!(
            std::fs::read_link(&written).unwrap(),
            Path::new("../elsewhere")
        );

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.current, 1);

        // Retargeting replaces the link rather than writing beside it.
        let mut entry = synch_core::FileEntry::tombstone(200, 2, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some("../other".into());
        node.store()
            .put_entry(&peer(), "media", "link", &entry)
            .unwrap();
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(std::fs::read_link(&written).unwrap(), Path::new("../other"));
        node.shutdown().await.unwrap();
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn a_mirror_skips_and_reports_a_symlink_where_it_cannot_make_one() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        let mut entry = synch_core::FileEntry::tombstone(100, 1, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some("../elsewhere".into());
        node.store()
            .put_entry(&peer(), "media", "link", &entry)
            .unwrap();

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert!(report.skipped[0].1.contains("symbolic link"), "{report:?}");
        assert!(!target.path().join("link").exists());
        node.shutdown().await.unwrap();
    }

    #[test]
    fn name_safety_checks() {
        assert!(unsafe_name("fine/path.txt").is_none());
        // Reserved device names are refused end to end (`aux.txt` in
        // `colliding_and_invalid_names_are_skipped`); here are the classes
        // no mirror test reaches: an invalid character and a trailing space.
        assert!(unsafe_name("bad<name").is_some());
        assert!(unsafe_name("trailing ").is_some());
    }

    #[tokio::test]
    async fn mirrors_may_not_overlap_spaces_or_each_other() {
        let (_d, target, node) = mirrored(&VersionPolicy::Newest).await;
        assert!(node
            .add_mirror("other", target.path().join("sub"), &VersionPolicy::Newest)
            .is_err());
        let shared = tempfile::tempdir().unwrap();
        node.add_space("media2", shared.path()).unwrap();
        assert!(node
            .add_mirror("media", shared.path(), &VersionPolicy::Newest)
            .unwrap_err()
            .to_string()
            .contains("overlaps space"));

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
}
