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

/// How far past a file's mtime its hash must have been taken before the
/// `(size, mtime_ns, file_id)` stat check is proof of "unchanged".
///
/// Two seconds covers every timestamp granularity in practice: nanoseconds
/// where the kernel grants them, a scheduler tick (1–10 ms) where it uses the
/// coarse clock, and the full-second stamps of older filesystems. Inside the
/// window a same-size in-place rewrite can share the hashed write's mtime,
/// so the stat proves nothing and the bytes are hashed again.
const RACY_WINDOW_NS: i64 = 2_000_000_000;

/// What one scan found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Paths restated because they looked changed: files whose bytes were
    /// re-hashed, and symlinks whose target or mtime moved.
    pub hashed: usize,
    /// Files skipped because `(size, mtime_ns, file_id)` matched.
    pub unchanged: usize,
    /// Paths that disappeared and were tombstoned.
    pub deleted: usize,
    /// Paths skipped by ignore rules.
    pub ignored: usize,
    /// Tombstones dropped because they outlived `tombstone_ttl` (§4.2).
    pub expired: usize,
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
        self.expired += other.expired;
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

        // A vanished space root — an unmounted drive, a renamed mount, a
        // directory momentarily gone — must not read as "every file deleted".
        // `walk` treats a missing directory as empty, so without this guard the
        // deletion sweep below would tombstone the whole space and publish that
        // cluster-wide. Refuse to scan a root that is absent or not a directory.
        match std::fs::metadata(&root_dir) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(EngineError::invalid(format!(
                    "space {space_id} root {} is not a directory",
                    root_dir.display()
                )))
            }
            Err(e) => {
                return Err(EngineError::invalid(format!(
                    "space {space_id} root {} is unavailable: {e}",
                    root_dir.display()
                )))
            }
        }

        let mut report = ScanReport::default();
        let mut found = Vec::new();
        walk(&root_dir, &root_dir, &ignore, &mut report, &mut found)?;

        // A set, not a list: the deletion sweep below asks "did the walk see
        // this?" once per row the scanner has ever recorded, and a linear
        // membership test makes a scan quadratic in the size of the space —
        // seconds of pure comparison on the 40 000-entry tree §4 uses as its
        // working example, and worse than the hashing on anything larger.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (path, rel, is_symlink) in &found {
            self.index_file(space_id, path, rel, seq, *is_symlink, &mut report)?;
            seen.insert(rel.as_str());
        }

        // Anything the scanner previously recorded but did not see is gone.
        // Deletion propagates by the key vanishing from the new root; the
        // tombstone exists so `synch status`/`synch log` can tell "deleted at
        // seq N" from "never existed" (§4.2).
        for known in self.store().local_files(space_id)? {
            if seen.contains(known.as_str()) {
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

    /// Indexes one symbolic link (§7.1).
    ///
    /// Symlinks are tracked exactly like files: a `local_files` row carrying
    /// the link's own (lstat) mtime and its target, so an unchanged symlink
    /// stages nothing. Republishing one every scan would defeat the property
    /// that an unchanged tree publishes no head — and, worse, leaving the row
    /// out meant the deletion sweep never saw the path, so a removed symlink
    /// was never tombstoned and stayed published forever.
    ///
    /// The target is the change signal, and it is carried in the row's
    /// `content` column as `blake3(target)`: content-addressing a link's
    /// target is exactly what that column already means for a file, and it
    /// costs no schema change. The staged entry keeps the link's real mtime,
    /// never `now_ns()`, so the §8 `newest` order compares stable values and a
    /// file-versus-symlink divergence resolves the same way on every node.
    fn index_symlink(
        &self,
        space_id: &str,
        path: &Path,
        rel: &str,
        seq: u64,
        report: &mut ScanReport,
    ) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        let mtime_ns = mtime_nanos(&metadata);
        let file_id = file_identity(&metadata);
        let target = std::fs::read_link(path)?.to_string_lossy().into_owned();
        let signal = symlink_signal(&target);
        let size = target.len() as u64;

        let known = self.store().local_file(space_id, rel)?;
        let unchanged = match &known {
            Some(known) => {
                known.content == Some(signal)
                    && known.mtime_ns == mtime_ns
                    && known.file_id == file_id
            }
            None => false,
        };
        if unchanged {
            report.unchanged += 1;
            return Ok(());
        }

        let mut entry = FileEntry::tombstone(mtime_ns, seq, None);
        entry.kind = EntryKind::Symlink;
        entry.symlink_target = Some(target);
        entry.size = size;
        report.staged.push((
            file_key(space_id, rel)?,
            Some(postcard::to_stdvec(&entry).map_err(|e| EngineError::Record(e.to_string()))?),
        ));
        report.hashed += 1;

        self.store().put_local_file(&LocalFile {
            space: space_id.to_string(),
            relpath: rel.to_string(),
            size,
            mtime_ns,
            file_id,
            content: Some(signal),
            scanned_at: now_ns(),
        })?;
        Ok(())
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
            return self.index_symlink(space_id, path, rel, seq, report);
        }

        let metadata = std::fs::metadata(path)?;
        let size = metadata.len();
        let mtime_ns = mtime_nanos(&metadata);
        let file_id = file_identity(&metadata);

        let known = self.store().local_file(space_id, rel)?;
        let stat_match = match &known {
            Some(known) => {
                known.size == size && known.mtime_ns == mtime_ns && known.file_id == file_id
            }
            None => false,
        };
        // A matching stat only proves "unchanged" once the hash it vouches for
        // was taken comfortably after the file's mtime. Filesystem timestamps
        // are granular — a jiffy on most Linux configurations, a full second
        // on older filesystems — so a same-size in-place rewrite landing
        // within one tick of the write we hashed is invisible to the stat.
        // Until the record has aged past that window, the stat is racily
        // clean (git's term for the same hazard) and the content must speak
        // for itself.
        let trusted = match &known {
            Some(known) => known.scanned_at.saturating_sub(known.mtime_ns) >= RACY_WINDOW_NS,
            None => false,
        };
        if stat_match && trusted {
            report.unchanged += 1;
            return Ok(());
        }

        let (content, size) = self.store().ingest_file(path, now_ns())?;

        if stat_match && known.as_ref().is_some_and(|k| k.content == Some(content)) {
            // Racily clean and actually clean. Refreshing `scanned_at` is what
            // lets the stat become trustworthy: once it is two seconds past
            // the mtime it vouches for, no unnoticed rewrite can share that
            // mtime, and the next scan skips the hash again.
            self.store().put_local_file(&LocalFile {
                space: space_id.to_string(),
                relpath: rel.to_string(),
                size,
                mtime_ns,
                file_id,
                content: Some(content),
                scanned_at: now_ns(),
            })?;
            report.unchanged += 1;
            return Ok(());
        }
        // Counted only once the content actually differs: a racy re-hash that
        // came back identical is "unchanged" to the operator, and reporting it
        // as both hashed and unchanged made a no-op scan read as work.
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
        // A scan is also where an operator can force tombstone expiry (§4.2):
        // the removals ride the same batch as everything else the scan found.
        let expired = self.expired_tombstone_changes()?;
        report.expired = expired.len();
        report.staged.extend(expired);
        if !report.staged.is_empty() {
            report.staged.push(self.manifest_change()?);
        }
        Ok(report)
    }

    /// The trie-key removals that retire this node's aged-out tombstones
    /// (§4.2).
    ///
    /// A tombstone says "deleted at seq N" rather than "never existed", which
    /// is worth carrying for a while and not forever: after `tombstone_ttl`
    /// (default 90 days) the key is removed from a later root and the path goes
    /// back to reading as absent. Only this node's own tombstones are ever
    /// considered — a replicated trie belongs to its origin, and this node
    /// cannot rewrite it.
    pub fn expired_tombstone_changes(&self) -> Result<Vec<StagedChange>> {
        let ttl = self.config().tombstone_ttl.as_nanos().min(i64::MAX as u128) as i64;
        let cutoff = now_ns().saturating_sub(ttl);
        let mut changes = Vec::new();
        for row in self.store().expired_tombstones(self.origin(), cutoff)? {
            changes.push((file_key(&row.space, &row.path)?, None));
        }
        Ok(changes)
    }

    /// Stages the removal of this node's aged-out tombstones (§4.2).
    ///
    /// Staged rather than published: expiry flows through the ordinary
    /// publisher, so it costs one head like any other batch. Returns how many
    /// tombstones were staged for removal.
    pub fn expire_tombstones(&self) -> Result<usize> {
        let changes = self.expired_tombstone_changes()?;
        let expired = changes.len();
        if expired > 0 {
            self.stage(changes);
            tracing::info!(expired, "staging expired tombstones for removal");
        }
        Ok(expired)
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

    /// [`Node::scan_and_stage`] run on the blocking pool.
    ///
    /// This is the form every async caller wants. A scan walks every space,
    /// stats every path, and re-hashes whatever moved — work bounded by the
    /// size of the tree, not by anything the runtime can preempt. Run inline on
    /// a worker thread it stops that thread from polling for as long as it
    /// takes, which on a multi-gigabyte space is the daemon going quiet: no
    /// peer answered, no control request served, no timer fired on time (§10).
    pub async fn scan_and_stage_off_runtime(&self) -> Result<ScanReport> {
        let node = self.clone();
        crate::blocking::offload(move || node.scan_and_stage()).await
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
                // The signal a row records is the content root for a file and
                // the hashed link target for a symlink, so the published entry
                // has to be read the same way or every open would re-index
                // every link.
                let published = trie
                    .get(root, &file_key(&space.id, &row.relpath)?)?
                    .as_deref()
                    .map(decode_entry)
                    .transpose()?
                    .and_then(|entry| published_signal(&entry));
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
        let target = self.adoption_target(space_id, path)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, content)?;
        Ok(target)
    }

    /// Adopts one origin's version of a path, streaming it into the local
    /// space directory (§8, `synch take`).
    ///
    /// The bytes-in-hand [`Node::adopt`] is what a caller with a small payload
    /// uses; this is the form that never has the payload in hand. `take` of a
    /// multi-gigabyte file used to read the object into memory and hand the
    /// slice over — the object is fetched into the CAS either way, so the only
    /// thing that buffering bought was a copy the size of the file.
    pub async fn adopt_from(
        &self,
        origin: &synch_core::OriginId,
        space_id: &str,
        path: &str,
    ) -> Result<PathBuf> {
        let policy = synch_store::VersionPolicy::Origin(origin.clone());
        // Resolving the target first means a path outside every indexed space
        // is refused before anything is fetched.
        let target = self.adoption_target(space_id, path)?;
        let range = self.prepare_range(space_id, path, &policy, 0, None).await?;
        self.write_blob_to(&range.root, range.size, target.clone())
            .await?;
        Ok(target)
    }

    /// Adopts a peer's *deletion* of a path as our own (§8, `synch take`).
    ///
    /// Deletions are adoptable exactly as content is: our local copy goes, and
    /// the next scan publishes our own tombstone through the ordinary indexing
    /// pipeline — the same path a deletion made with `rm` takes. Adoption is
    /// how all divergence ends, deletion divergence included: once every
    /// publisher tombstones the path, it leaves the unified tree.
    ///
    /// Returns the file that was removed, or `None` when there was nothing
    /// here to remove — which is not an error: the assertion being adopted is
    /// "this path is gone", and it already is.
    pub fn adopt_deletion(&self, space_id: &str, path: &str) -> Result<Option<PathBuf>> {
        let target = self.adoption_target(space_id, path)?;
        // `symlink_metadata`, so a symlink is removed as the link it is rather
        // than followed to whatever it points at.
        if std::fs::symlink_metadata(&target).is_err() {
            return Ok(None);
        }
        if target.is_dir() {
            return Err(EngineError::invalid(format!(
                "{} is a directory here; refusing to remove it",
                target.display()
            )));
        }
        std::fs::remove_file(&target)?;
        Ok(Some(target))
    }

    /// Opens a streamed write into a local space (§9.4).
    ///
    /// The bytes-in-hand form is [`Node::adopt`]; this is the form for a
    /// payload arriving a piece at a time — an S3 `PutObject` body relayed over
    /// the control socket — where holding the object in memory to call the
    /// other one is exactly what must not happen.
    pub fn open_adoption(&self, space_id: &str, path: &str) -> Result<Adoption> {
        let target = self.adoption_target(space_id, path)?;
        Adoption::open(target)
    }

    /// Where a path lives locally, refusing anything outside a configured
    /// space.
    ///
    /// The guard is the same for content and for deletions: `synch take` may
    /// only ever write inside a space this node indexes, because outside one
    /// nothing would publish the adoption and the write would be a silent
    /// no-op with a filesystem side effect.
    fn adoption_target(&self, space_id: &str, path: &str) -> Result<PathBuf> {
        let space = self
            .store()
            .space(space_id)?
            .ok_or_else(|| EngineError::not_found(format!("space {space_id}")))?;
        let normalized =
            synch_core::normalize_path(path).map_err(|e| EngineError::invalid(e.to_string()))?;
        Ok(PathBuf::from(&space.local_path).join(&normalized))
    }
}

/// The suffix a streamed write's staging file carries.
///
/// Matched by a built-in ignore rule ([`crate::ignore::BUILTIN_DEFAULTS`]), so
/// a scan that runs while an upload is still arriving walks straight past it.
pub const PART_SUFFIX: &str = ".synch-part";

/// A streamed write into a local space that has not landed yet (§9.4).
///
/// Bytes go to a staging file beside the target, and the target only appears
/// once the payload is complete. A client that hangs up mid-body therefore
/// leaves the space exactly as it was, rather than leaving this node to publish
/// half an object as its own assertion — and since the assertion is signed and
/// broadcast, "rather than" is doing real work there. Dropping an `Adoption`
/// without committing removes the staging file.
#[derive(Debug)]
pub struct Adoption {
    target: PathBuf,
    staging: PathBuf,
    file: Option<std::fs::File>,
    written: u64,
}

impl Adoption {
    /// Stages a write at an arbitrary path.
    ///
    /// [`Node::open_adoption`] is the form that resolves a `<space>/<path>`
    /// first; this one is for a target that is already known — a mirror's file
    /// (§7.2), which by construction lives outside every indexed space.
    pub fn at(target: impl Into<PathBuf>) -> Result<Adoption> {
        Adoption::open(target.into())
    }

    fn open(target: PathBuf) -> Result<Adoption> {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // The staging name has to be unique per write: two clients putting the
        // same key at once must not share one file and interleave their bytes.
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "object".into());
        let staging = target.with_file_name(format!(
            ".{name}.{}.{}{PART_SUFFIX}",
            std::process::id(),
            synch_core::now_ns()
        ));
        let file = std::fs::File::create(&staging)?;
        Ok(Adoption {
            target,
            staging,
            file: Some(file),
            written: 0,
        })
    }

    /// Appends one piece of the payload.
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| EngineError::invalid("this write has already been committed"))?;
        file.write_all(bytes)?;
        self.written += bytes.len() as u64;
        Ok(())
    }

    /// How many bytes have arrived so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Flushes the payload and moves it into place, returning the target.
    ///
    /// The rename is what makes the write atomic from the scanner's point of
    /// view: it sees the old file or the new one, never a partial one.
    pub fn commit(mut self) -> Result<PathBuf> {
        let file = self
            .file
            .take()
            .ok_or_else(|| EngineError::invalid("this write has already been committed"))?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&self.staging, &self.target)?;
        Ok(self.target.clone())
    }
}

impl Drop for Adoption {
    fn drop(&mut self) {
        if self.file.is_some() {
            let _ = std::fs::remove_file(&self.staging);
        }
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

/// The change signal a symlink's target reduces to.
///
/// `local_files.content` holds a content root for a file; for a link it holds
/// the hash of the target, which is the same idea applied to the only content a
/// link has.
pub(crate) fn symlink_signal(target: &str) -> Hash {
    Hash::new(target.as_bytes())
}

/// The signal a published entry implies, matching what `local_files` records.
fn published_signal(entry: &FileEntry) -> Option<Hash> {
    match entry.kind {
        EntryKind::Symlink => entry.symlink_target.as_deref().map(symlink_signal),
        _ => entry.content,
    }
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

    /// Ages every scan record past the racy window, as if the test had waited
    /// two seconds: records hashed moments after their file's mtime are
    /// racily clean and re-hashed on the next scan, which is correct but not
    /// what tests of the trusted stat check are exercising.
    fn age_quick_checks(node: &Node) {
        for space in node.store().spaces().unwrap() {
            for mut row in node.store().local_file_rows(&space.id).unwrap() {
                row.scanned_at += super::RACY_WINDOW_NS;
                node.store().put_local_file(&row).unwrap();
            }
        }
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
        age_quick_checks(&node);

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 0);
        assert_eq!(report.unchanged, 1);
        assert!(head.is_none(), "an unchanged tree publishes no new head");
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_racy_same_size_rewrite_is_still_detected() {
        // The stat quick check is (size, mtime, file_id). A same-size rewrite
        // landing within the filesystem's timestamp granularity leaves all
        // three identical — forced here with set_times, which is what a
        // coarse-clock kernel does on its own — and used to be silently
        // never published. Within the racy window the bytes speak instead.
        let (_d, space, node) = node_with_space().await;
        let path = space.path().join("rolling.txt");
        std::fs::write(&path, b"revision 1").unwrap();
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let (_, head) = node.scan_and_publish().unwrap();
        assert_eq!(head.unwrap().seq, 1);

        std::fs::write(&path, b"revision 2").unwrap();
        let times = std::fs::FileTimes::new().set_modified(mtime);
        std::fs::File::options()
            .append(true)
            .open(&path)
            .unwrap()
            .set_times(times)
            .unwrap();

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 1, "a racily clean stat proves nothing");
        assert_eq!(head.unwrap().seq, 2);
        assert_eq!(
            node.store()
                .entry(node.origin(), "media", "rolling.txt")
                .unwrap()
                .unwrap()
                .content,
            Some(Hash::new(b"revision 2"))
        );

        // An untouched file leaves the racy window by being re-hashed once:
        // the refreshed record ages into a trustworthy stat.
        age_quick_checks(&node);
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 0);
        assert_eq!(report.unchanged, 1);
        assert!(head.is_none());
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

    /// The streamed form of adoption: the object goes from the CAS into the
    /// space a piece at a time, never through a buffer the size of the file
    /// (§9.4). The staging file it passes through is invisible to a scan and
    /// gone by the time the adoption returns.
    #[tokio::test]
    async fn adopting_a_peer_version_streams_it_into_the_space() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"mine").unwrap();
        node.scan_and_publish().unwrap();

        let peer = synch_core::OriginId::named("nas", "x.example").unwrap();
        let payload: Vec<u8> = (0..1_200_000u32).map(|i| (i * 11 % 251) as u8).collect();
        let root = node.store().ingest_bytes(&payload, now_ns()).unwrap();
        node.store()
            .put_entry(
                &peer,
                "media",
                "a.txt",
                &FileEntry::file(payload.len() as u64, 9_000, root, 4),
            )
            .unwrap();

        let target = node.adopt_from(&peer, "media", "a.txt").await.unwrap();
        // The engine reports the path under the *stored* space root, which was
        // canonicalized at `space add` time — on macOS the tempdir's `/var/…`
        // is a symlink to `/private/var/…`, so the raw tempdir path would not
        // compare equal even though it names the same file.
        let canonical_space = space.path().canonicalize().unwrap();
        assert_eq!(target, canonical_space.join("a.txt"));
        assert_eq!(std::fs::read(&target).unwrap(), payload);
        let left: Vec<String> = std::fs::read_dir(space.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["a.txt".to_string()]);

        node.scan_and_publish().unwrap();
        let entry = node
            .store()
            .entry(node.origin(), "media", "a.txt")
            .unwrap()
            .unwrap();
        assert_eq!(entry.content, Some(root));
        assert_eq!(entry.prev, Some(Hash::new(b"mine")));

        // A path outside every indexed space is refused before anything is
        // fetched, exactly as the bytes-in-hand form refuses it.
        assert!(node.adopt_from(&peer, "absent", "a.txt").await.is_err());
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

    /// A node whose tombstone TTL is set for a test rather than for a cluster.
    async fn node_with_ttl(
        ttl: std::time::Duration,
    ) -> (tempfile::TempDir, tempfile::TempDir, Node) {
        let data = tempfile::tempdir().unwrap();
        let space = tempfile::tempdir().unwrap();
        Node::init(data.path(), None).unwrap();
        let mut config = NodeConfig::loopback(data.path());
        config.tombstone_ttl = ttl;
        let node = Node::open(config).await.unwrap();
        node.add_space("media", space.path()).unwrap();
        (data, space, node)
    }

    /// Rewrites a tombstone's deletion time, which is what a tombstone 90 days
    /// old looks like without waiting 90 days.
    fn backdate_tombstone(node: &Node, path: &str, mtime_ns: i64) {
        let row = node
            .store()
            .entry(node.origin(), "media", path)
            .unwrap()
            .unwrap();
        assert_eq!(row.kind, EntryKind::Tombstone);
        node.store()
            .put_entry(
                node.origin(),
                "media",
                path,
                &FileEntry::tombstone(mtime_ns, row.seq, row.prev),
            )
            .unwrap();
    }

    fn in_root(node: &Node, root: Hash, path: &str) -> bool {
        Trie::new(node.store().as_ref())
            .get(root, &file_key("media", path).unwrap())
            .unwrap()
            .is_some()
    }

    /// §4.2: tombstones are retained for `tombstone_ttl`, then dropped in a
    /// later root — and only the aged ones are.
    #[tokio::test]
    async fn an_expired_tombstone_leaves_the_next_root() {
        let (_d, space, node) = node_with_ttl(std::time::Duration::from_secs(3600)).await;
        std::fs::write(space.path().join("old.txt"), b"old").unwrap();
        std::fs::write(space.path().join("recent.txt"), b"recent").unwrap();
        node.scan_and_publish().unwrap();

        std::fs::remove_file(space.path().join("old.txt")).unwrap();
        std::fs::remove_file(space.path().join("recent.txt")).unwrap();
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.deleted, 2);
        assert_eq!(report.expired, 0, "both tombstones are brand new");
        assert!(in_root(&node, head.unwrap().root, "old.txt"));

        // One of them is now older than the TTL; the other is not.
        backdate_tombstone(&node, "old.txt", now_ns() - 2 * 3600 * 1_000_000_000);

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.expired, 1);
        let root = head
            .expect("expiry costs one head like any other batch")
            .root;
        assert!(
            !in_root(&node, root, "old.txt"),
            "the aged key must be gone"
        );
        assert!(in_root(&node, root, "recent.txt"), "the fresh one stays");
        assert!(node
            .store()
            .entry(node.origin(), "media", "old.txt")
            .unwrap()
            .is_none());
        assert_eq!(
            node.store()
                .entry(node.origin(), "media", "recent.txt")
                .unwrap()
                .unwrap()
                .kind,
            EntryKind::Tombstone
        );

        // Nothing is left to expire, so a further scan mints nothing.
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.expired, 0);
        assert!(head.is_none());
        node.shutdown().await.unwrap();
    }

    /// Expiring a tombstone is not the same as forbidding the path: creating it
    /// again republishes it as an ordinary entry.
    #[tokio::test]
    async fn a_path_can_be_re_created_after_its_tombstone_expires() {
        let (_d, space, node) = node_with_ttl(std::time::Duration::from_secs(3600)).await;
        std::fs::write(space.path().join("a.txt"), b"first").unwrap();
        node.scan_and_publish().unwrap();
        std::fs::remove_file(space.path().join("a.txt")).unwrap();
        node.scan_and_publish().unwrap();
        backdate_tombstone(&node, "a.txt", now_ns() - 2 * 3600 * 1_000_000_000);
        node.scan_and_publish().unwrap();
        assert!(node
            .store()
            .entry(node.origin(), "media", "a.txt")
            .unwrap()
            .is_none());

        std::fs::write(space.path().join("a.txt"), b"again").unwrap();
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 1);
        let root = head.unwrap().root;
        assert!(in_root(&node, root, "a.txt"));
        let entry = node
            .store()
            .entry(node.origin(), "media", "a.txt")
            .unwrap()
            .unwrap();
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(entry.content, Some(Hash::new(b"again")));
        // The lineage starts over: what it replaced is no longer published.
        assert_eq!(entry.prev, None);
        node.shutdown().await.unwrap();
    }

    /// The maintenance path: expiry stages into the publisher, so it costs one
    /// head like any other batch and needs no scan of its own.
    #[tokio::test]
    async fn maintenance_stages_expiry_through_the_publisher() {
        // A TTL of zero makes every tombstone expired the moment it exists.
        let (_d, space, node) = node_with_ttl(std::time::Duration::ZERO).await;
        std::fs::write(space.path().join("a.txt"), b"x").unwrap();
        node.scan_and_publish().unwrap();
        std::fs::remove_file(space.path().join("a.txt")).unwrap();
        node.scan_and_publish().unwrap();
        assert_eq!(
            node.store()
                .entry(node.origin(), "media", "a.txt")
                .unwrap()
                .unwrap()
                .kind,
            EntryKind::Tombstone
        );

        assert_eq!(node.publisher().pending(), 0);
        node.maintenance_pass().unwrap();
        assert_eq!(node.publisher().pending(), 1, "staged, not published");

        let head = node.flush_staged().await.unwrap().unwrap();
        assert!(!in_root(&node, head.root, "a.txt"));
        assert!(node
            .store()
            .entry(node.origin(), "media", "a.txt")
            .unwrap()
            .is_none());
        node.shutdown().await.unwrap();
    }

    /// A replicated trie belongs to its origin: expiry never touches it.
    #[tokio::test]
    async fn expiry_never_touches_another_origin() {
        let (_d, _space, node) = node_with_ttl(std::time::Duration::ZERO).await;
        let peer = synch_core::OriginId::named("laptop", "x.example").unwrap();
        node.store()
            .put_entry(
                &peer,
                "media",
                "theirs.txt",
                &FileEntry::tombstone(0, 1, None),
            )
            .unwrap();

        assert!(node.expired_tombstone_changes().unwrap().is_empty());
        assert_eq!(node.expire_tombstones().unwrap(), 0);
        assert!(node
            .store()
            .entry(&peer, "media", "theirs.txt")
            .unwrap()
            .is_some());
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
        age_quick_checks(&node);
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 0);
        assert_eq!(report.unchanged, 1);
        assert!(head.is_none());
        node.shutdown().await.unwrap();
    }

    /// §10: the scan runs off the runtime, so a node indexing a tree is still
    /// a node that answers.
    ///
    /// `#[tokio::test]` gives a current-thread runtime, which is what makes
    /// this decisive rather than probabilistic: there is exactly one thread
    /// that can poll tasks. A ticker task counts how many times it is polled
    /// across the scan. Run inline — `self.scan_and_stage()`, as this used to
    /// be — the whole scan happens between two statements of a single poll, no
    /// other task can be polled while it does, and the count cannot move at
    /// all. It moves only if the hashing genuinely left the runtime.
    #[tokio::test]
    async fn a_scan_does_not_block_the_runtime() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_d, space, node) = node_with_space().await;
        // Enough bytes that the hashing is unmistakably longer than a poll.
        for i in 0..32 {
            std::fs::write(
                space.path().join(format!("f{i}.bin")),
                vec![i as u8; 512 * 1024],
            )
            .unwrap();
        }

        let ticks = std::sync::Arc::new(AtomicUsize::new(0));
        let ticker = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    ticks.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            })
        };
        // Let the ticker reach its loop before the measurement starts.
        tokio::task::yield_now().await;

        let before = ticks.load(Ordering::Relaxed);
        let report = node.scan_and_stage_off_runtime().await.unwrap();
        let after = ticks.load(Ordering::Relaxed);

        assert_eq!(report.hashed, 32);
        assert!(
            after > before,
            "the runtime was not polling anything while the scan ran ({before} -> {after})"
        );
        ticker.abort();
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

    #[cfg(unix)]
    #[tokio::test]
    async fn an_unchanged_symlink_stages_nothing() {
        // §7.1: republishing an unchanged symlink every scan would defeat the
        // property that an unchanged tree publishes no head.
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
        std::os::unix::fs::symlink("a.txt", space.path().join("link")).unwrap();

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 2, "the file and the link");
        assert_eq!(head.unwrap().seq, 1);

        let entry = node
            .store()
            .entry(node.origin(), "media", "link")
            .unwrap()
            .unwrap();
        assert_eq!(entry.kind, EntryKind::Symlink);
        assert_eq!(entry.symlink_target.as_deref(), Some("a.txt"));
        // The link's own lstat mtime, never `now_ns()`.
        let lstat = mtime_nanos(&std::fs::symlink_metadata(space.path().join("link")).unwrap());
        assert_eq!(entry.mtime_ns, lstat);

        // Scanning again finds nothing to say.
        age_quick_checks(&node);
        let (again, head) = node.scan_and_publish().unwrap();
        assert_eq!(again.hashed, 0);
        assert_eq!(again.unchanged, 2);
        assert!(again.staged.is_empty(), "{:?}", again.staged);
        assert!(head.is_none(), "an unchanged tree publishes no head");
        node.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_retargeted_symlink_stages_an_update() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"a").unwrap();
        std::fs::write(space.path().join("b.txt"), b"b").unwrap();
        std::os::unix::fs::symlink("a.txt", space.path().join("link")).unwrap();
        node.scan_and_publish().unwrap();
        age_quick_checks(&node);

        std::fs::remove_file(space.path().join("link")).unwrap();
        std::os::unix::fs::symlink("b.txt", space.path().join("link")).unwrap();

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 1, "only the link moved");
        assert_eq!(head.unwrap().seq, 2);
        assert_eq!(
            node.store()
                .entry(node.origin(), "media", "link")
                .unwrap()
                .unwrap()
                .symlink_target
                .as_deref(),
            Some("b.txt")
        );
        node.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_deleted_symlink_is_tombstoned() {
        // Without a `local_files` row the deletion sweep never saw the path, so
        // a removed symlink stayed published forever.
        let (_d, space, node) = node_with_space().await;
        std::os::unix::fs::symlink("nowhere", space.path().join("link")).unwrap();
        node.scan_and_publish().unwrap();

        std::fs::remove_file(space.path().join("link")).unwrap();
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.deleted, 1);
        assert!(head.is_some());
        let entry = node
            .store()
            .entry(node.origin(), "media", "link")
            .unwrap()
            .unwrap();
        assert!(entry.kind == EntryKind::Tombstone);
        assert!(node.store().local_file("media", "link").unwrap().is_none());
        node.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_survives_the_open_time_reconciliation() {
        // `reconcile_local_files` compares a row's signal against the published
        // entry; reading a symlink's signal as a content root would drop every
        // link's row on every open and re-stage it forever.
        let data = tempfile::tempdir().unwrap();
        let space = tempfile::tempdir().unwrap();
        Node::init(data.path(), None).unwrap();
        {
            let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
            node.add_space("media", space.path()).unwrap();
            std::os::unix::fs::symlink("elsewhere", space.path().join("link")).unwrap();
            node.scan_and_publish().unwrap();
            node.shutdown().await.unwrap();
        }
        let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
        assert_eq!(node.reconcile_local_files().unwrap(), 0);
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 0);
        assert!(head.is_none());
        node.shutdown().await.unwrap();
    }
}
