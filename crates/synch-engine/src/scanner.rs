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

/// Distinguishes concurrent detached ingests before their content root exists.
static DETACHED_INGEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How far past a file's mtime its hash must have been taken before the
/// `(size, mtime_ns, file_id)` stat check is proof of "unchanged".
///
/// Two seconds covers every timestamp granularity in practice: nanoseconds
/// where the kernel grants them, a scheduler tick (1–10 ms) where it uses the
/// coarse clock, and the full-second stamps of older filesystems. Inside the
/// window a same-size in-place rewrite can share the hashed write's mtime,
/// so the stat proves nothing and the bytes are hashed again. The mirror's
/// currency check (mirror.rs) trusts a verified record under the same window.
pub(crate) const RACY_WINDOW_NS: i64 = 2_000_000_000;

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
    /// Whether a configured space deliberately has no local checkout.
    pub fn is_detached_space(&self, space_id: &str) -> Result<bool> {
        self.store()
            .space(space_id)?
            .map(|space| space.local_path.is_none())
            .ok_or_else(|| EngineError::not_found(format!("space {space_id}")))
    }

    /// Walks one space and stages everything that changed.
    pub fn scan_space(&self, space_id: &str) -> Result<ScanReport> {
        if self.cas_backend().remote_upload_parts() {
            return Err(EngineError::invalid(
                "cloud-CAS scans must use the async backend-aware scan path",
            ));
        }
        let store = self.store().clone();
        self.scan_space_with_ingest(space_id, &mut move |path| {
            Ok(store.ingest_file(path, now_ns())?)
        })
    }

    fn scan_space_with_ingest(
        &self,
        space_id: &str,
        ingest: &mut impl FnMut(&Path) -> Result<(Hash, u64)>,
    ) -> Result<ScanReport> {
        let space = self
            .store()
            .space(space_id)?
            .ok_or_else(|| EngineError::not_found(format!("space {space_id}")))?;
        let local_path = space.local_path.as_deref().ok_or_else(|| {
            EngineError::invalid(format!(
                "space {space_id} is detached and cannot be scanned"
            ))
        })?;
        let root_dir = PathBuf::from(local_path);
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

        // After the root guard, not before. `.syncignore` under a root that is a
        // regular file returns `ENOTDIR`, which is not `NotFound`, so reading it
        // first answered "the ignore file exists but could not be read" for a
        // space whose actual problem the guard above names plainly.
        let ignore = IgnoreSet::for_space(&root_dir)?;
        let mut report = ScanReport::default();
        let mut found = Vec::new();
        walk(&root_dir, &root_dir, &ignore, &mut report, &mut found)?;

        // A set, not a list: the deletion sweep below asks "did the walk see
        // this?" once per row the scanner has ever recorded, and a linear
        // membership test makes a scan quadratic in the size of the space —
        // seconds of pure comparison on the 40 000-entry tree §4 uses as its
        // working example, and worse than the hashing on anything larger.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for candidate in &found {
            let (_, rel, _) = candidate;
            // A path that vanished between the walk and here is skipped, not
            // fatal — the same tolerance `walk` above already applies to
            // `read_dir` and `symlink_metadata`, and for the same reason: a
            // live directory (a build tree, a browser profile) produces this
            // routinely.
            //
            // It stopped one function short of where it was needed, and the
            // consequence was not "one file missed". `index_file` commits its
            // `local_files` row as it goes and the batch it stages is published
            // only at the end, so an abort left every path indexed before it
            // durably marked as scanned and never published — and the next scan
            // reads that row, finds the stat matches, and reports the file
            // `unchanged`. The files stayed unpublished until the process was
            // restarted.
            //
            // Only failures about *this path* are tolerated. A store failure is
            // not one, and swallowing it would silently drop the file the same
            // way.
            match self.index_file(space_id, candidate, seq, &mut report, ingest) {
                Ok(()) => {}
                Err(EngineError::Io(e)) => {
                    report.skipped.push((rel.clone(), e.to_string()));
                }
                Err(e) => return Err(e),
            }
            seen.insert(rel.as_str());
        }

        // Anything the scanner previously recorded but did not see is gone.
        // Deletion propagates by the key vanishing from the new root; the
        // tombstone exists so `synch status`/`synch log` can tell "deleted at
        // seq N" from "never existed" (§4.2).
        //
        // Use the union of what the scanner recorded and what this origin has
        // published, not `local_files` alone. A staged tombstone removes the
        // local row before publication, while the published tree stays durable.
        // The published tree is durable and `local_files` is not, so the
        // published tree is what the sweep is anchored to; `local_files` still
        // contributes the paths this scan indexed but has not published yet.
        // A path the walk could not judge is not a path that is gone.
        //
        // `seen` is built from what the walk actually stat'd, so every path it
        // skipped — a child whose `symlink_metadata` failed `EACCES` because the
        // parent lost its execute bit, an `EIO` on a network space — was absent
        // from `seen` and therefore swept. The scan then reported the same path
        // in `skipped` *and* published a tombstone for it: mirrors deleted their
        // copies, GC became free to drop the origin's own object, and a later
        // successful scan republished it as a new entry with no `prev`, so every
        // peer re-fetched bytes it already had.
        //
        // The asymmetry is what gives it away: `index_file`'s failures are
        // tolerated *and* the path stays in `seen` a few lines above, for exactly
        // this reason. `walk`'s failures land in the same field and got the
        // opposite treatment.
        //
        // As a prefix, not an exact name. `walk` stats a `DirEntry` before it can
        // know whether it is a directory, so a *directory* it cannot stat is
        // skipped under its own path and never recursed into — and the published
        // paths at risk are the files beneath it, which no exact-match exemption
        // reaches.
        let unjudged: Vec<String> = report
            .skipped
            .iter()
            .map(|(path, _)| path.clone())
            .collect();

        let mut known_paths: Vec<String> = self.store().local_files(space_id)?;
        known_paths.extend(self.store().published_paths(self.origin(), space_id)?);
        known_paths.sort();
        known_paths.dedup();

        for known in known_paths {
            if seen.contains(known.as_str()) || unjudged_covers(&unjudged, &known) {
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
    /// out would hide the path from the deletion sweep, so a removed symlink
    /// would never be tombstoned and would stay published forever.
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
        candidate: &(PathBuf, String, bool),
        seq: u64,
        report: &mut ScanReport,
        ingest: &mut impl FnMut(&Path) -> Result<(Hash, u64)>,
    ) -> Result<()> {
        let (path, rel, is_symlink) = candidate;
        if *is_symlink {
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

        let (content, size) = ingest(path)?;

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
        if self.cas_backend().remote_upload_parts() {
            return Err(EngineError::invalid(
                "cloud-CAS scans must use the async backend-aware scan path",
            ));
        }
        let store = self.store().clone();
        self.scan_all_with_ingest(&mut on_space, &mut move |path| {
            Ok(store.ingest_file(path, now_ns())?)
        })
    }

    fn scan_all_with_ingest(
        &self,
        on_space: &mut impl FnMut(&str, &ScanReport),
        ingest: &mut impl FnMut(&Path) -> Result<(Hash, u64)>,
    ) -> Result<ScanReport> {
        let mut report = ScanReport::default();
        for space in self.store().spaces()? {
            if space.local_path.is_none() {
                continue;
            }
            // One space's failure does not discard the others' work. It used
            // to: `scan_space` commits the `local_files` row removal for a
            // vanished path as it goes (the tombstone that replaces it only
            // enters `report.staged`), so a later space failing — an unmounted
            // removable disk is the ordinary case — dropped the tombstone while
            // the removal stayed committed. The path then existed in no source
            // of truth this node consults: not on disk, not in `local_files`,
            // so no later scan could re-derive it, and our origin kept
            // publishing it as a live file at its old content root forever.
            //
            // Reported rather than swallowed: the space appears in `skipped`,
            // which is what `synch scan` prints and what `doctor` reads.
            match self.scan_space_with_ingest(&space.id, ingest) {
                Ok(one) => {
                    on_space(&space.id, &one);
                    report.merge(one);
                }
                Err(e) => {
                    tracing::warn!(space = %space.id, error = %e, "space skipped by this scan");
                    report.skipped.push((space.id.clone(), e.to_string()));
                }
            }
        }
        // A scan is also where an operator can force tombstone expiry (§4.2):
        // the removals ride the same batch as everything else the scan found.
        //
        // Never for a key this scan has already restated. `expired_tombstones`
        // reads `entries` as it stood *before* the scan, so a path whose
        // tombstone has aged out and which now exists on disk again appears in
        // both halves — the scan's live entry first, then a raw removal for the
        // same key. `publish` folds in order, so the removal won, and the origin
        // published nothing at all for the path: indistinguishable from "never
        // existed", gone from the unified tree and from every mirror. Worse, it
        // was self-perpetuating — `local_files` had already recorded the new
        // content, so every later scan called the path unchanged, and the
        // tombstone row the expiry deleted no longer showed up to be retired.
        // Only a restart repaired it, through `reconcile_local_files`.
        let expired = self.expired_tombstone_changes()?;
        let restated: std::collections::HashSet<&[u8]> = report
            .staged
            .iter()
            .map(|(key, _)| key.as_slice())
            .collect();
        let expired: Vec<StagedChange> = expired
            .into_iter()
            .filter(|(key, _)| !restated.contains(key.as_slice()))
            .collect();
        report.expired = expired.len();
        report.staged.extend(expired);
        if !report.staged.is_empty() {
            report.staged.push(self.manifest_change()?);
            // One record per space rather than a list inside the manifest, so
            // that what this node advertises about a space can be shown to a
            // peer delegated that space and to nobody else (§5.5).
            report.staged.extend(self.space_info_changes()?);
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

    /// Stages the removal of `b:` records for objects this node no longer
    /// holds (§6.3).
    ///
    /// An availability ad has to be retired explicitly. The scanner stages
    /// `blob_key(content) -> Some(ad)` on every hash and stages only `f:` keys
    /// as `None`, so without this every content root this origin has ever
    /// published would stay a leaf in its trie for good — replicated to every
    /// member, pinned against trie GC by the head that reaches it, and
    /// accumulating one leaf per edit per file forever.
    ///
    /// It is a correctness problem as much as a growth one: `gc_content`
    /// deletes a local payload once no entry references it, while a standing ad
    /// goes on telling every peer this node holds the object, so peers keep
    /// selecting it as a provider and keep failing.
    ///
    /// Retiring is the same shape as tombstone expiry — staged, so it costs one
    /// head like any other batch.
    pub fn retired_ad_changes(&self) -> Result<Vec<StagedChange>> {
        let mut changes = Vec::new();
        for root in self.store().provider_roots_for_origin(self.origin())? {
            // Still held, whole or in part: the ad stands, and a partial
            // holder's ad is exactly what §6.3 wants advertised.
            if self.store().local_ad(&root)?.is_some() {
                continue;
            }
            changes.push((blob_key(&root), None));
        }
        Ok(changes)
    }

    /// Stages the removal of ads for objects this node has dropped.
    ///
    /// Returns how many were staged.
    pub fn retire_ads(&self) -> Result<usize> {
        let changes = self.retired_ad_changes()?;
        let retired = changes.len();
        if retired > 0 {
            self.stage(changes);
            tracing::info!(
                retired,
                "staging availability ads for objects no longer held"
            );
        }
        Ok(retired)
    }

    /// Stages the removal of this node's aged-out tombstones (§4.2).
    ///
    /// Staged rather than published: expiry flows through the ordinary
    /// publisher, so it costs one head like any other batch. Returns how many
    /// tombstones were staged for removal.
    pub fn expire_tombstones(&self) -> Result<usize> {
        // Excluding whatever is already waiting to be published, for the reason
        // `scan_all_with` gives: a removal that lands in the same batch as a
        // live entry for the same key erases the path outright. Here the two are
        // not even ordered — the scanner and this pass stage into one buffer
        // concurrently — so the filter is what makes the outcome defined.
        let staged = self.publisher().staged_keys();
        let changes: Vec<StagedChange> = self
            .expired_tombstone_changes()?
            .into_iter()
            .filter(|(key, _)| !staged.contains(key))
            .collect();
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
    pub async fn scan_and_stage_async(&self) -> Result<ScanReport> {
        Ok(self.scan_and_stage_async_with_reports().await?.0)
    }

    /// Backend-aware scan plus the per-space reports used by an explicit CLI
    /// scan's progress output.
    pub async fn scan_and_stage_async_with_reports(
        &self,
    ) -> Result<(ScanReport, Vec<(String, ScanReport)>)> {
        let node = self.clone();
        let backend = self.cas_backend().clone();
        crate::blocking::offload(move || {
            node.ensure_publishable()?;
            let runtime = tokio::runtime::Handle::current();
            let mut spaces = Vec::new();
            let report = node.scan_all_with_ingest(
                &mut |space, report| spaces.push((space.to_string(), report.clone())),
                &mut |path| {
                    let ingested =
                        runtime.block_on(backend.ingest_file(path.to_path_buf(), now_ns()))?;
                    Ok((ingested.root, ingested.size))
                },
            )?;
            node.stage(report.staged.iter().cloned());
            Ok((report, spaces))
        })
        .await
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
            if space.local_path.is_none() {
                continue;
            }
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
    /// multi-gigabyte file would otherwise read the object into memory and hand
    /// the slice over — the object is fetched into the CAS either way, so the
    /// only thing that buffering buys is a copy the size of the file.
    pub async fn adopt_from(
        &self,
        origin: &synch_core::OriginId,
        space_id: &str,
        path: &str,
    ) -> Result<PathBuf> {
        let policy = synch_store::VersionPolicy::Origin(origin.clone());
        let detached = {
            let (node, space_id) = (self.clone(), space_id.to_string());
            crate::blocking::offload(move || node.is_detached_space(&space_id)).await?
        };
        if detached {
            // `prepare_range` fetches and verifies the complete selected
            // object. Before adoption names it as *our* version, promote it to
            // the backend's durable tier: after publication this node may be
            // the only holder peers associate with the new assertion, so a
            // scratch-only copy is not enough under any upload policy.
            let range = self.prepare_range(space_id, path, &policy, 0, None).await?;
            self.cas_backend().finalize(range.root, range.size).await?;
            let reported = PathBuf::from(format!("{space_id}/{path}"));
            let (node, space, path) = (self.clone(), space_id.to_string(), path.to_string());
            crate::blocking::offload(move || {
                node.stage_detached_reference(&space, &path, range.root, range.size, now_ns())
            })
            .await?;
            return Ok(reported);
        }
        // Resolving the target first means a path outside every indexed space
        // is refused before anything is fetched. It reads the space row, so it
        // goes to the blocking pool like every other store read on an async
        // path (§10).
        let target = {
            let (node, space_id, path) = (self.clone(), space_id.to_string(), path.to_string());
            crate::blocking::offload(move || node.adoption_target(&space_id, &path)).await?
        };
        let range = self.prepare_range(space_id, path, &policy, 0, None).await?;
        self.materialize_blob(&range.root, range.size, target.clone())
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
        if self.is_detached_space(space_id)? {
            let normalized = normalized_adoption_path(path)?;
            let previous = self
                .store()
                .entry(self.origin(), space_id, &normalized)?
                .and_then(|entry| entry.content);
            let tombstone = FileEntry::tombstone(now_ns(), self.next_seq()?, previous);
            let encoded =
                postcard::to_stdvec(&tombstone).map_err(|e| EngineError::Record(e.to_string()))?;
            self.stage([(file_key(space_id, &normalized)?, Some(encoded))]);
            return Ok(previous.map(|_| PathBuf::from(format!("{space_id}/{normalized}"))));
        }
        let target = self.adoption_target(space_id, path)?;
        // `symlink_metadata`, so a symlink is removed as the link it is rather
        // than followed to whatever it points at.
        if std::fs::symlink_metadata(&target).is_err() {
            return Ok(None);
        }
        if target.is_dir() {
            // The path stays in the log and out of the message. This error
            // reaches an S3 client verbatim, and the daemon's on-disk layout —
            // the operator's home, the space roots — is not something a client
            // that guessed a key is owed.
            tracing::warn!(
                target = %target.display(),
                "refusing to remove a directory as if it were an object"
            );
            return Err(EngineError::invalid(format!(
                "{space_id}/{path} is a directory here; refusing to remove it"
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
        if self.is_detached_space(space_id)? {
            let _ = normalized_adoption_path(path)?;
            let target = self.store().staging_dir().join(format!(
                "detached-{}-{}.payload",
                std::process::id(),
                DETACHED_INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            return Adoption::open(target);
        }
        let target = self.adoption_target(space_id, path)?;
        Adoption::open(target)
    }

    /// Ingests a committed detached-space staging file and stages its records.
    ///
    /// The durable CAS row lands before the `f:` and `b:` records enter the
    /// publisher. Until the caller acknowledges, `source` is unacknowledged
    /// backend-private scratch and may be discarded after this returns.
    pub async fn commit_detached_file(
        &self,
        space_id: &str,
        path: &str,
        source: &Path,
        mtime_ns: i64,
    ) -> Result<(Hash, u64)> {
        let (node, checked_space, checked_path, checked_source) = (
            self.clone(),
            space_id.to_string(),
            path.to_string(),
            source.to_path_buf(),
        );
        let (normalized, size) = crate::blocking::offload(move || {
            if !node.is_detached_space(&checked_space)? {
                return Err(EngineError::invalid(format!(
                    "space {checked_space} has a local checkout"
                )));
            }
            Ok((
                normalized_adoption_path(&checked_path)?,
                std::fs::metadata(&checked_source)?.len(),
            ))
        })
        .await?;

        let ingested = self
            .cas_backend()
            .ingest_file(source.to_path_buf(), now_ns())
            .await?;
        debug_assert_eq!(ingested.size, size);
        let (node, space) = (self.clone(), space_id.to_string());
        crate::blocking::offload(move || {
            node.stage_detached_reference(
                &space,
                &normalized,
                ingested.root,
                ingested.size,
                mtime_ns,
            )?;
            Ok((ingested.root, ingested.size))
        })
        .await
    }

    /// Stages a detached file entry and its durable-holder advertisement.
    pub(crate) fn stage_detached_reference(
        &self,
        space_id: &str,
        path: &str,
        root: Hash,
        size: u64,
        mtime_ns: i64,
    ) -> Result<()> {
        let normalized = normalized_adoption_path(path)?;
        let previous = self
            .store()
            .entry(self.origin(), space_id, &normalized)?
            .and_then(|entry| entry.content);
        let mut entry = FileEntry::file(size, mtime_ns, root, self.next_seq()?);
        entry.prev = previous.filter(|previous| *previous != root);
        let entry = postcard::to_stdvec(&entry).map_err(|e| EngineError::Record(e.to_string()))?;
        let ad = self.store().local_ad(&root)?.ok_or_else(|| {
            EngineError::invalid(format!(
                "the durable ingest of {root} produced no local advertisement"
            ))
        })?;
        let ad = postcard::to_stdvec(&ad).map_err(|e| EngineError::Record(e.to_string()))?;
        self.stage([
            (file_key(space_id, &normalized)?, Some(entry)),
            (blob_key(&root), Some(ad)),
        ]);
        Ok(())
    }

    /// Where a path lives locally, refusing anything outside a configured
    /// space.
    ///
    /// The guard is the same for content and for deletions: `synch take` may
    /// only ever write inside a space this node indexes, because outside one
    /// nothing would publish the adoption and the write would be a silent
    /// no-op with a filesystem side effect.
    pub(crate) fn adoption_target(&self, space_id: &str, path: &str) -> Result<PathBuf> {
        let space = self
            .store()
            .space(space_id)?
            .ok_or_else(|| EngineError::not_found(format!("space {space_id}")))?;
        let local_path = space.local_path.as_deref().ok_or_else(|| {
            EngineError::invalid(format!(
                "space {space_id} is detached and has no filesystem adoption target"
            ))
        })?;
        let normalized = normalized_adoption_path(path)?;
        // And the platform has to agree the result is purely relative before it
        // is joined onto the space root.
        //
        // `normalize_path` works in the protocol's own path language, where `/`
        // is the only separator — deliberately, so a trie key means the same
        // thing on every node. On Windows the *platform* reads more than that: a
        // key of `..\..\evil.txt` is one `Normal` component to the protocol and
        // a traversal to `Path::join`, and one of `C:/Windows/Temp/evil.txt`
        // carries a drive prefix, which makes `join` discard the space root
        // entirely. Either writes outside every space, as the daemon user, from
        // any key the S3 gateway accepts.
        //
        // A no-op on POSIX, where none of those parse as anything but `Normal`.
        // The mirror's `unsafe_name` already refuses these on the way out; this
        // is the way in.
        // Lexical safety is still not enough. A space root is canonicalized when
        // it is added but its *interior* never is, so a symlinked directory
        // inside the space resolves through to wherever it points, and the write
        // or the delete lands outside every space as whatever uid the daemon
        // runs as. The mirror loop has always checked this; every other writer
        // needs the same check, and a deletion needs it as much as a write does.
        if crate::mirror::escapes_via_symlink(Path::new(local_path), &normalized) {
            return Err(EngineError::invalid(format!(
                "{space_id}/{path} resolves through a symlinked directory and would leave the space"
            )));
        }
        Ok(PathBuf::from(local_path).join(&normalized))
    }
}

/// Normalizes a write path and applies the host platform's relative-path rules.
fn normalized_adoption_path(path: &str) -> Result<String> {
    let normalized =
        synch_core::normalize_path(path).map_err(|e| EngineError::invalid(e.to_string()))?;
    if Path::new(&normalized)
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(EngineError::invalid(format!(
            "path {path} is not a plain relative path on this platform"
        )));
    }
    Ok(normalized)
}

/// How much an [`Adoption::append_file`] fallback moves per read/write pair.
///
/// Only reached on a filesystem without `copy_file_range`, where the cost is a
/// bounce through user space and the buffer is the whole of what this process
/// holds of a part.
const APPEND_CHUNK: u64 = 1024 * 1024;

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
        // Read *and* write: the payload is written here, and a multipart
        // completion reads it straight back to take the object's root before
        // the rename. `File::create` alone is write-only, and the read then
        // fails with `EBADF` on a file this very process is holding open.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&staging)?;
        Ok(Adoption {
            target,
            staging,
            file: Some(file),
            written: 0,
        })
    }

    /// Stages a write that starts out as a clone of a file already on disk
    /// (`docs/DELTA-SYNC.md` §3.5).
    ///
    /// The atomicity invariant is unchanged — the bytes land in a staging file
    /// that is renamed over the target, so a reader sees the old file or the
    /// new one — but the staging file arrives already full. This is how an
    /// object becomes a mirrored file: the source is the CAS payload, and a
    /// 100 GB image is materialized without moving 100 GB.
    ///
    /// `FICLONE` first. On btrfs, XFS and bcachefs it shares the source's
    /// extents copy-on-write, so the write is O(1) and consumes no space until
    /// one of the two files is written to. Everywhere else — a target on a
    /// different filesystem from the source, ext4, a kernel or platform without
    /// the ioctl — it falls back to [`std::fs::copy`], which on Linux is itself
    /// a kernel-side `copy_file_range` rather than a bounce through user space.
    ///
    /// Every failure path unlinks the staging file before returning. The
    /// obvious way to write the fallback leaves one behind when the copy fails
    /// *and* the handle cannot be reopened — ENOSPC, EMFILE — and the file it
    /// strands wears a name the scanner's built-in ignore rules skip, so it
    /// would sit beside the target unnoticed and uncollected forever.
    pub fn cloning(target: impl Into<PathBuf>, source: &Path) -> Result<(Adoption, CloneKind)> {
        let mut adoption = Adoption::open(target.into())?;
        match adoption.clone_from(source) {
            Ok(kind) => Ok((adoption, kind)),
            Err(e) => {
                // `Drop` only unlinks while the handle is live, and the copy
                // fallback below has to let go of it.
                let _ = std::fs::remove_file(&adoption.staging);
                adoption.file = None;
                Err(e)
            }
        }
    }

    /// Fills the staging file from `source`, sharing its extents if it can.
    fn clone_from(&mut self, source: &Path) -> Result<CloneKind> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| EngineError::invalid("a fresh staging file has no handle"))?;
        match std::fs::File::open(source).and_then(|src| reflink_file(&src, file)) {
            Ok(()) => return Ok(CloneKind::Reflink),
            Err(e) => {
                tracing::debug!(source = %source.display(), error = %e, "reflink unavailable");
            }
        }
        // The staging file exists and is empty; `fs::copy` wants to create its
        // own, so the handle is dropped for the duration and reopened after.
        self.file = None;
        let copied = std::fs::copy(source, &self.staging);
        self.file = Some(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&self.staging)?,
        );
        copied?;
        Ok(CloneKind::Copy)
    }

    /// Sets the staging file's length, for a clone of a file whose size the new
    /// version does not share.
    pub fn set_len(&mut self, len: u64) -> Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| EngineError::invalid("this write has already been committed"))?;
        file.set_len(len)?;
        Ok(())
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

    /// The object root of what has been staged so far.
    ///
    /// What a multipart completion answers with. Taking the root here rather
    /// than reading it back off the published entry is the difference between
    /// describing the bytes this call assembled and describing whatever the
    /// tree holds for that key by the time the scan reaches it — which a
    /// concurrent write to the same key wins.
    pub fn hash_staged(&mut self) -> Result<synch_core::Hash> {
        use std::io::{Seek, Write};
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| EngineError::invalid("this write has already been committed"))?;
        file.flush()?;
        file.seek(std::io::SeekFrom::Start(0))?;
        let root = synch_core::hash_reader(std::io::BufReader::new(file.try_clone()?))?;
        // The handle is left at the end, where an append expects it.
        file.seek(std::io::SeekFrom::End(0))?;
        Ok(root)
    }

    /// Appends a whole file to the staging payload (§9.4).
    ///
    /// What assembles a multipart upload: each part is its own staged payload,
    /// and completing the upload is this call once per part in ascending
    /// order. The bytes move inside the kernel — `copy_file_range` shares
    /// extents outright on a filesystem that can, and copies without a bounce
    /// through user space on one that cannot — so a 50 GiB object assembled
    /// from 8 MiB parts never passes through this process.
    ///
    /// `FICLONE` is deliberately not used here even though [`Adoption::cloning`]
    /// prefers it: it is a *whole file* clone that replaces the destination,
    /// which is the one thing an append must not do. The range form needs
    /// block-aligned offsets that arbitrary part sizes do not have.
    ///
    /// Blocking, like every other method here — the caller runs it off the
    /// runtime.
    pub fn append_file(&mut self, source: &Path) -> Result<u64> {
        use std::io::{Read, Seek, Write};
        let mut src = std::fs::File::open(source)?;
        let len = src.metadata()?.len();
        let dest = self
            .file
            .as_mut()
            .ok_or_else(|| EngineError::invalid("this write has already been committed"))?;
        // `written` advances as the bytes move, not once at the end: a failure
        // part-way through still leaves the staging file longer than it was,
        // and a `written` that under-counts it makes every later size check —
        // and every error message quoting it — wrong.
        let mut moved = 0u64;
        #[cfg(target_os = "linux")]
        while moved < len {
            let take = usize::try_from(len - moved).unwrap_or(usize::MAX);
            // `None` for both offsets advances each file's own cursor, which is
            // exactly the append semantics wanted: the destination cursor is
            // already at the end of everything appended so far.
            match rustix::fs::copy_file_range(&src, None, &*dest, None, take) {
                // Short of the length the metadata reported: the source is
                // being written under us, or the filesystem refuses to say
                // more. The fallback below reads it and reports the real error.
                Ok(0) => break,
                Ok(count) => {
                    moved += count as u64;
                    self.written += count as u64;
                }
                // Swallowed only as a signal to fall back — `EXDEV` and
                // `ENOSYS` are the expected ones — but logged, because an
                // `ENOSPC` on the destination would otherwise be reported by
                // the fallback as whatever it happens to hit next.
                Err(e) => {
                    tracing::debug!(error = %e, "copy_file_range unavailable; copying by hand");
                    break;
                }
            }
        }
        if moved < len {
            // `copy_file_range` may have consumed part of the source already,
            // so the fallback resumes from where it stopped rather than from
            // the start.
            src.seek(std::io::SeekFrom::Start(moved))?;
            let mut buffer = vec![0u8; APPEND_CHUNK.min(len - moved) as usize];
            while moved < len {
                let take = (APPEND_CHUNK.min(len - moved)) as usize;
                let piece = &mut buffer[..take];
                src.read_exact(piece)?;
                dest.write_all(piece)?;
                moved += take as u64;
                self.written += take as u64;
            }
        }
        Ok(moved)
    }

    /// Flushes the payload and moves it into place, returning the target.
    ///
    /// The rename is what makes the write atomic from the scanner's point of
    /// view: it sees the old file or the new one, never a partial one. That is
    /// a claim about crashes, so the directory entry the rename created is
    /// flushed too — otherwise the contents survive a power cut and the name
    /// they arrived under does not, which is the old file or *no* file rather
    /// than the old file or the new one.
    /// The rename itself can fail — the target is a directory, the filesystem
    /// filled up under the fsync — and when it does, this is the only chance to
    /// unlink the staging file: [`Drop`] only cleans up while the handle is
    /// live, and committing has to let go of it to flush and rename it. Leaving
    /// it stranded would leave a full-size copy of the object beside the target
    /// under a name the scanner's built-in ignore rules skip, unnoticed and
    /// uncollected forever, on a path that is reached precisely when the disk is
    /// already in trouble.
    pub fn commit(mut self) -> Result<PathBuf> {
        match self.commit_inner() {
            Ok(()) => Ok(self.target.clone()),
            Err(e) => {
                let _ = std::fs::remove_file(&self.staging);
                Err(e)
            }
        }
    }

    fn commit_inner(&mut self) -> Result<()> {
        let file = self
            .file
            .take()
            .ok_or_else(|| EngineError::invalid("this write has already been committed"))?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&self.staging, &self.target)?;
        fsync_parent(&self.target);
        Ok(())
    }
}

/// Flushes a directory entry — a rename or a create — to stable storage.
///
/// Best effort: a platform that cannot open a directory as a file simply does
/// not get the guarantee, which is the same posture the CAS takes (§6.2).
fn fsync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// How [`Adoption::cloning`] managed to give the staging file its head start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneKind {
    /// Extents shared with the source, copy-on-write: no data was moved.
    Reflink,
    /// The source's bytes were copied.
    Copy,
}

/// Shares a file's extents with another file, where the filesystem can.
///
/// `FICLONE` is Linux's reflink ioctl; every other platform (and every
/// filesystem that does not implement it) reports it unsupported, which is a
/// perfectly good answer — the caller copies instead.
fn reflink_file(source: &std::fs::File, dest: &std::fs::File) -> std::io::Result<()> {
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "sparc", target_arch = "sparc64"))
    ))]
    {
        rustix::fs::ioctl_ficlone(dest, source).map_err(std::io::Error::from)
    }
    #[cfg(not(all(
        target_os = "linux",
        not(any(target_arch = "sparc", target_arch = "sparc64"))
    )))]
    {
        let _ = (source, dest);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "reflink is not available on this platform",
        ))
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

/// True if `path` is one of the paths this pass could not judge, or is under
/// one of them.
///
/// A prefix rule, because `walk` stats a `DirEntry` before it can know whether
/// it is a directory: a *directory* it cannot stat is skipped under its own path
/// and never recursed into, so what is actually at risk is every published file
/// beneath it. Whole components only, so `a/b` does not cover `a/bc`.
fn unjudged_covers(unjudged: &[String], path: &str) -> bool {
    unjudged
        .iter()
        .any(|u| path == u || (path.starts_with(u.as_str()) && path[u.len()..].starts_with('/')))
}

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
    // A failing `DirEntry` fails the space, exactly as a failing `read_dir`
    // does two lines up. `read_dir`'s iterator yields per-entry errors, and
    // discarding them left the child indistinguishable from one that was never
    // there — which the deletion sweep reads as "gone" and publishes a tombstone
    // for. The name is what is unknown here, so no single path can be exempted;
    // `scan_all_with` already records a failed space and keeps every other
    // space's work, which is the containment this wants.
    let mut sorted = Vec::new();
    for entry in entries {
        sorted.push(entry?);
    }
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

pub(crate) fn mtime_nanos(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// A platform file identity, when one is cheaply available.
///
/// Together with size and mtime this is what lets the scanner skip hashing,
/// and what lets a mirror trust a verified file without reading it back.
pub(crate) fn file_identity(metadata: &std::fs::Metadata) -> Option<Vec<u8>> {
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
    use crate::testkit::{node_with_space, published, reopen};

    #[tokio::test]
    async fn detached_spaces_publish_cas_direct_and_never_scan_a_checkout() {
        let (_data, node) = crate::testkit::node().await;
        node.add_detached_space("media").unwrap();
        assert!(node.is_detached_space("media").unwrap());
        assert!(node.scan_space("media").is_err());
        assert!(crate::watcher::SpaceWatcher::configured_spaces(&node)
            .unwrap()
            .is_empty());

        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("incoming");
        std::fs::write(&source, b"detached payload").unwrap();
        let (root, size) = node
            .commit_detached_file("media", "nested/a.txt", &source, 42)
            .await
            .unwrap();
        node.flush_staged().await.unwrap().unwrap();

        let entry = published(&node, "media", "nested/a.txt");
        assert_eq!(entry.content, Some(root));
        assert_eq!(entry.size, size);
        assert_eq!(entry.mtime_ns, 42);
        assert_eq!(node.store().read_all(&root).unwrap(), b"detached payload");
        assert!(node
            .store()
            .local_file("media", "nested/a.txt")
            .unwrap()
            .is_none());

        node.adopt_deletion("media", "nested/a.txt").unwrap();
        node.scan_publish_push().await.unwrap().unwrap();
        assert_eq!(
            published(&node, "media", "nested/a.txt").kind,
            EntryKind::Tombstone
        );
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn detached_cloud_ingest_is_remote_before_its_row_and_publish() {
        let data = tempfile::tempdir().unwrap();
        Node::init(data.path(), None).unwrap();
        let scratch = data.path().join("cloud-scratch");
        let mut config = NodeConfig::loopback(data.path());
        config.cloud = Some(synch_store::cloud::CloudConfig {
            service: synch_store::cloud::CloudService::Memory,
            options: Default::default(),
            scratch_dir: scratch,
            io_timeout: std::time::Duration::from_secs(5),
            upload_policy: synch_store::cloud::CloudUploadPolicy::OwnPinned,
            cache_bytes: Some(512 * 1024 * 1024),
        });
        let node = Node::open(config).await.unwrap();
        node.add_detached_space("media").unwrap();

        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("incoming");
        let payload = vec![13u8; 100_000];
        std::fs::write(&source, &payload).unwrap();
        let (root, size) = node
            .commit_detached_file("media", "large.bin", &source, 99)
            .await
            .unwrap();
        let row = node.store().blob(&root).unwrap().unwrap();
        assert!(row.durable, "the row must carry the remote durability ack");
        assert_eq!(row.size, size);
        assert_eq!(
            node.cas_backend()
                .read_range(root, 123, 45_678 - 123)
                .await
                .unwrap(),
            payload[123..45_678]
        );
        assert!(
            node.store()
                .entry(node.origin(), "media", "large.bin")
                .unwrap()
                .is_none(),
            "the entry is not visible before the publish transaction"
        );
        node.flush_staged().await.unwrap().unwrap();
        assert_eq!(published(&node, "media", "large.bin").content, Some(root));

        // Shape a self-readopted head whose older SQLite snapshot lacks the
        // blob row. Maintenance must keep the recovered own ad while the
        // provider-serving path reconstructs the cold row from final keys.
        node.store().delete_blob(&root).unwrap();
        assert!(node.store().blob(&root).unwrap().is_none());
        node.reconstruct_recovered_cloud_rows().await.unwrap();
        assert!(node.retired_ad_changes().unwrap().is_empty());
        let (encoded, served) = node
            .cas_backend()
            .encode_slice(root, synch_core::ChunkRanges::single(0, 1))
            .await
            .unwrap();
        assert_eq!(served, synch_core::ChunkRanges::single(0, 1));
        assert!(!encoded.is_empty());
        assert!(node.store().blob(&root).unwrap().unwrap().durable);

        let pinned = node
            .cas_backend()
            .ingest_bytes(b"b-only recovered pin".to_vec(), now_ns())
            .await
            .unwrap();
        let ad = node.store().local_ad(&pinned.root).unwrap().unwrap();
        node.publish(&[(
            blob_key(&pinned.root),
            Some(postcard::to_stdvec(&ad).unwrap()),
        )])
        .unwrap();
        assert!(!node.store().content_is_referenced(&pinned.root).unwrap());
        node.store().delete_blob(&pinned.root).unwrap();
        assert!(node.store().blob(&pinned.root).unwrap().is_none());
        node.reconstruct_recovered_cloud_rows().await.unwrap();
        let recovered_pin = node.store().blob(&pinned.root).unwrap().unwrap();
        assert!(recovered_pin.durable && recovered_pin.pinned);
        assert!(node.retired_ad_changes().unwrap().is_empty());

        // Simulate a replacement container: only the database and remote
        // object survive. The first read refills the cache.
        node.store().reconcile_scratch_generation("fresh").unwrap();
        assert!(!node.store().blob(&root).unwrap().unwrap().complete);
        assert_eq!(
            node.read_range(
                "media",
                "large.bin",
                &synch_store::VersionPolicy::Origin(node.origin().clone()),
                100,
                Some(900),
            )
            .await
            .unwrap(),
            payload[100..1000]
        );
        let warmed = node.store().blob(&root).unwrap().unwrap();
        assert!(
            !warmed.complete,
            "a cold range read hydrates only its groups"
        );
        assert!(warmed.verified_groups().count() < synch_core::group_count(size));
        node.shutdown().await.unwrap();
    }

    /// Ages every scan record past the racy window: fresh records are racily
    /// clean and re-hashed next scan, which stat-trust tests don't exercise.
    fn age_quick_checks(node: &Node) {
        for space in node.store().spaces().unwrap() {
            for mut row in node.store().local_file_rows(&space.id).unwrap() {
                row.scanned_at += super::RACY_WINDOW_NS;
                node.store().put_local_file(&row).unwrap();
            }
        }
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

    /// Rewrites a tombstone's deletion time, like one 90 days old without the wait.
    fn backdate_tombstone(node: &Node, path: &str, mtime_ns: i64) {
        let row = published(node, "media", path);
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

    #[tokio::test]
    async fn scans_hashes_and_publishes() {
        let (_d, space, node) = node_with_space().await;
        std::fs::create_dir_all(space.path().join("talks")).unwrap();
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(space.path().join("talks/b.bin"), vec![7u8; 40_000]).unwrap();
        // The walk honors the space's ignore set.
        std::fs::write(space.path().join(".syncignore"), "*.tmp\n").unwrap();
        std::fs::write(space.path().join("scratch.tmp"), b"x").unwrap();

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 2);
        assert!(report.ignored >= 1);
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
        // Content is in the CAS, reads back verified, and is advertised as a provider.
        assert_eq!(
            node.store().read_all(&a.content.unwrap()).unwrap(),
            b"hello"
        );
        assert_eq!(
            node.store().providers(&a.content.unwrap()).unwrap().len(),
            1
        );
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_racy_same_size_rewrite_is_still_detected() {
        // A same-size rewrite sharing the hashed mtime: inside the racy window
        // the stat proves nothing, so the bytes are hashed again.
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
            published(&node, "media", "rolling.txt").content,
            Some(Hash::new(b"revision 2"))
        );

        // The refreshed record ages into a trustworthy stat.
        age_quick_checks(&node);
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 0);
        assert_eq!(report.unchanged, 1);
        assert!(head.is_none());
        node.shutdown().await.unwrap();
    }

    /// Edits are detected with prev lineage at the replaced content; deletions
    /// become tombstones distinguishing "deleted at seq N" from "never existed".
    #[tokio::test]
    async fn edits_and_deletions_flow_through_the_lifecycle() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"before").unwrap();
        node.scan_and_publish().unwrap();

        // A distinguishable mtime, so the stat triple differs even on coarse clocks.
        std::fs::write(space.path().join("a.txt"), b"after!!").unwrap();
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 1);
        assert_eq!(head.unwrap().seq, 2);
        let entry = published(&node, "media", "a.txt");
        assert_eq!(entry.content, Some(Hash::new(b"after!!")));
        assert_eq!(entry.prev, Some(Hash::new(b"before")));

        // The delete phase of the same lifecycle.
        std::fs::remove_file(space.path().join("a.txt")).unwrap();
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(head.unwrap().seq, 3);
        let entry = published(&node, "media", "a.txt");
        assert_eq!(entry.kind, EntryKind::Tombstone);
        assert_eq!(entry.seq, 3);
        assert_eq!(entry.prev, Some(Hash::new(b"after!!")));
        node.shutdown().await.unwrap();
    }

    #[test]
    fn the_unjudged_exemption_covers_whole_subtrees_only() {
        let unjudged = vec!["d/sub".to_string(), "solo.txt".to_string()];
        // The directory itself, and anything under it at any depth.
        assert!(unjudged_covers(&unjudged, "d/sub"));
        assert!(unjudged_covers(&unjudged, "d/sub/deep.txt"));
        assert!(unjudged_covers(&unjudged, "solo.txt"));
        // Whole components only: a shared-prefix sibling is not covered, or
        // one unreadable directory would freeze its neighbours' deletions.
        assert!(!unjudged_covers(&unjudged, "d/subterfuge.txt"));
        assert!(!unjudged_covers(&unjudged, "solo.txt.bak"));
        assert!(!unjudged_covers(&[], "anything"));
    }

    /// A path the walk could not judge is not tombstoned: a published file
    /// whose stat fails (an unreadable parent) is skipped, not swept as gone.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_path_the_walk_could_not_stat_is_not_deleted() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses the EACCES this relies on; detect it by trying, not uid.
        let probe = tempfile::tempdir().unwrap();
        std::fs::write(probe.path().join("p"), b"x").unwrap();
        std::fs::set_permissions(probe.path(), std::fs::Permissions::from_mode(0o444)).unwrap();
        let bypassed = std::fs::symlink_metadata(probe.path().join("p")).is_ok();
        std::fs::set_permissions(probe.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        if bypassed {
            eprintln!("skipped: this user bypasses the EACCES this test needs");
            return;
        }
        let (_d, space, node) = node_with_space().await;
        // Both shapes: directly under and under a subdir — `walk` stats a
        // DirEntry before it recurses.
        let dir = space.path().join("d");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("keep.txt"), b"hello").unwrap();
        std::fs::write(dir.join("sub").join("deep.txt"), b"deeper").unwrap();
        node.scan_and_publish().unwrap();
        for path in ["d/keep.txt", "d/sub/deep.txt"] {
            assert_eq!(
                published(&node, "media", path).kind,
                EntryKind::File,
                "{path} must be published before the directory is locked"
            );
        }

        // Listable but not traversable: `read_dir` yields names, `symlink_metadata` fails.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o444)).unwrap();
        let report = node.scan_all().unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            !report.skipped.is_empty(),
            "the scan must report the path it could not judge"
        );
        assert_eq!(report.deleted, 0, "{:?}", report.skipped);
        for path in ["keep.txt", "deep.txt"] {
            assert!(
                !report
                    .staged
                    .iter()
                    .any(|(key, _)| String::from_utf8_lossy(key).contains(path)),
                "no tombstone may be staged for {path}, which is still there"
            );
        }
        node.shutdown().await.unwrap();
    }

    /// A key the platform reads as more than one relative component is
    /// refused (Windows backslash and drive forms; POSIX sees ordinary
    /// components, so its own path rules still refuse what matters).
    #[tokio::test]
    async fn an_adoption_target_stays_inside_its_space() {
        let (_d, _space, node) = node_with_space().await;
        // Against the root `add_space` recorded (`canonical_dir` resolves
        // `/var` to `/private/var` on macOS).
        let root = PathBuf::from(
            node.store()
                .space("media")
                .unwrap()
                .unwrap()
                .local_path
                .unwrap(),
        );
        let inside = node.adoption_target("media", "sub/ok.txt").unwrap();
        assert_eq!(inside, root.join("sub").join("ok.txt"));

        #[cfg(windows)]
        for escape in [
            "..\\..\\evil.txt",
            "C:/Windows/Temp/evil.txt",
            "\\\\srv\\s\\x",
        ] {
            assert!(
                node.adoption_target("media", escape).is_err(),
                "{escape} must not resolve outside the space"
            );
        }
        assert!(node.adoption_target("media", "../evil.txt").is_err());
        assert!(node.adoption_target("media", "/etc/passwd").is_err());
        node.shutdown().await.unwrap();
    }

    /// A path re-created while its own tombstone is expiring survives the
    /// batch: the scan's live entry restating the key beats the raw removal.
    #[tokio::test]
    async fn a_path_re_created_as_its_tombstone_expires_is_still_published() {
        let (_d, space, node) = node_with_ttl(std::time::Duration::from_secs(3600)).await;
        std::fs::write(space.path().join("a.txt"), b"first").unwrap();
        node.scan_and_publish().unwrap();
        std::fs::remove_file(space.path().join("a.txt")).unwrap();
        node.scan_and_publish().unwrap();
        assert_eq!(
            published(&node, "media", "a.txt").kind,
            EntryKind::Tombstone
        );

        // The tombstone ages out and the file returns before the next scan
        // sees either — the whole of the trigger.
        backdate_tombstone(&node, "a.txt", now_ns() - 2 * 3600 * 1_000_000_000);
        std::fs::write(space.path().join("a.txt"), b"second").unwrap();

        let report = node.scan_all().unwrap();
        assert_eq!(
            report.expired, 0,
            "the removal gives way to the entry restating the key"
        );
        node.publish(&report.staged).unwrap();

        let entry = published(&node, "media", "a.txt");
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(entry.content, Some(Hash::new(b"second")));
    }

    /// A deletion whose tombstone never reached a root is re-derived from the
    /// published tree by the next scan, and a tombstoned path is not swept
    /// again (which would republish a deletion forever).
    #[tokio::test]
    async fn a_deletion_whose_batch_was_lost_is_re_derived_by_the_next_scan() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
        node.scan_and_publish().unwrap();

        // The deletion is scanned but its batch never publishes.
        std::fs::remove_file(space.path().join("a.txt")).unwrap();
        let lost = node.scan_all().unwrap();
        assert_eq!(lost.deleted, 1, "the scan saw the deletion");
        assert!(node.store().local_files("media").unwrap().is_empty());
        assert_eq!(
            published(&node, "media", "a.txt").kind,
            EntryKind::File,
            "and it is still published as live"
        );

        // The next scan re-derives it from the published tree.
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(
            published(&node, "media", "a.txt").kind,
            EntryKind::Tombstone
        );
        assert_eq!(head.unwrap().seq, 2);

        // And a tombstoned path is not swept again.
        let (again, head) = node.scan_and_publish().unwrap();
        assert_eq!(again.deleted, 0);
        assert!(head.is_none());
        node.shutdown().await.unwrap();
    }

    /// The streamed form of adoption (§9.4): bytes go from the CAS into the
    /// space a piece at a time, through an invisible staging file that is gone
    /// by the time the adoption returns.
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
        // The path under the *stored* root, canonicalized at `space add`
        // (macOS `/var` -> `/private/var`).
        let canonical_space = space.path().canonicalize().unwrap();
        assert_eq!(target, canonical_space.join("a.txt"));
        assert_eq!(std::fs::read(&target).unwrap(), payload);
        let left: Vec<String> = std::fs::read_dir(space.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["a.txt".to_string()]);

        node.scan_and_publish().unwrap();
        let entry = published(&node, "media", "a.txt");
        assert_eq!(entry.content, Some(root));
        assert_eq!(entry.prev, Some(Hash::new(b"mine")));

        // A path outside every indexed space is refused before fetching.
        assert!(node.adopt_from(&peer, "absent", "a.txt").await.is_err());
        node.shutdown().await.unwrap();
    }

    /// §4.2: tombstones are retained for `tombstone_ttl`, then dropped in a
    /// later root — only the aged ones — and expiring one is not forbidding
    /// the path: creating it again republishes it, lineage starting over.
    #[tokio::test]
    async fn tombstone_ttl_expires_aged_keys_and_allows_recreation() {
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
        let root = head.unwrap().root;
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

        // Nothing is left to expire, so a further scan mints nothing.
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.expired, 0);
        assert!(head.is_none());

        // The expired path can be created again as an ordinary entry.
        std::fs::write(space.path().join("old.txt"), b"again").unwrap();
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 1);
        let root = head.unwrap().root;
        assert!(in_root(&node, root, "old.txt"));
        let entry = published(&node, "media", "old.txt");
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(entry.content, Some(Hash::new(b"again")));
        assert_eq!(entry.prev, None, "what it replaced is no longer published");
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
            published(&node, "media", "a.txt").kind,
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

    /// §7.1: on open, `local_files` rows the published root does not
    /// corroborate are dropped so the next scan re-indexes them; corroborated
    /// rows — a published symlink's included — survive an ordinary restart.
    #[tokio::test]
    async fn open_time_reconciliation_drops_unpublished_rows_only() {
        let data = tempfile::tempdir().unwrap();
        let space = tempfile::tempdir().unwrap();
        Node::init(data.path(), None).unwrap();
        let rows = if cfg!(unix) { 2 } else { 1 };
        {
            let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
            node.add_space("media", space.path()).unwrap();
            std::fs::write(space.path().join("a.txt"), b"hello").unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink("a.txt", space.path().join("link")).unwrap();
            // The batch is lost: hashed and recorded, never published.
            let report = node.scan_and_stage().unwrap();
            assert_eq!(report.hashed, rows);
            assert!(node.publisher().pending() > 0);
            assert!(node.own_head().unwrap().is_none());
            assert_eq!(node.store().local_files("media").unwrap().len(), rows);
            node.shutdown().await.unwrap();
        }

        // Opening drops the rows the trie does not publish, so the next scan
        // re-hashes instead of skipping forever.
        let node = reopen(data.path()).await;
        assert!(node.store().local_files("media").unwrap().is_empty());
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(
            report.hashed, rows,
            "the file must be re-hashed, not skipped"
        );
        assert_eq!(head.unwrap().seq, 1);
        node.shutdown().await.unwrap();

        // A published tree keeps every row: ordinary restarts do not re-hash.
        let node = reopen(data.path()).await;
        assert_eq!(node.reconcile_local_files().unwrap(), 0);
        assert_eq!(node.store().local_files("media").unwrap().len(), rows);
        age_quick_checks(&node);
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 0);
        assert_eq!(report.unchanged, rows);
        assert!(head.is_none());
        node.shutdown().await.unwrap();
    }

    /// §10: the scan runs off the runtime. A current-thread runtime makes this
    /// decisive: a ticker task is polled orders of magnitude more often when
    /// the hashing thread is free than when a worker does the hashing itself.
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
        let report = node.scan_and_stage_async().await.unwrap();
        let after = ticks.load(Ordering::Relaxed);

        // Calibrated to failure modes, not machine speed: an inline hash ticks
        // under a hundred times for 32 files; a free thread ~9,000 on CI runners.
        const FREE_RUNTIME_TICKS: usize = 1_000;

        assert_eq!(report.hashed, 32);
        assert!(
            after - before > FREE_RUNTIME_TICKS,
            "the runtime was barely polling while the scan ran ({before} -> {after}): the hashing is back on a runtime worker"
        );
        ticker.abort();
        node.shutdown().await.unwrap();
    }

    /// The symlink lifecycle (§7.1): tracked by lstat mtime and target signal,
    /// so an unchanged link stages nothing, a retarget stages an update, and
    /// a removed link is tombstoned — the `local_files` row is what makes the
    /// deletion sweep see the path at all.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_symlink_lifecycle() {
        let (_d, space, node) = node_with_space().await;
        std::fs::write(space.path().join("a.txt"), b"a").unwrap();
        std::fs::write(space.path().join("b.txt"), b"b").unwrap();
        std::os::unix::fs::symlink("a.txt", space.path().join("link")).unwrap();

        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 3, "the two files and the link");
        assert_eq!(head.unwrap().seq, 1);
        let entry = published(&node, "media", "link");
        assert_eq!(entry.kind, EntryKind::Symlink);
        assert_eq!(entry.symlink_target.as_deref(), Some("a.txt"));
        // The link's own lstat mtime, never `now_ns()`.
        let lstat = mtime_nanos(&std::fs::symlink_metadata(space.path().join("link")).unwrap());
        assert_eq!(entry.mtime_ns, lstat);

        // An unchanged link stages nothing.
        age_quick_checks(&node);
        let (again, head) = node.scan_and_publish().unwrap();
        assert_eq!(again.hashed, 0);
        assert_eq!(again.unchanged, 3);
        assert!(again.staged.is_empty(), "{:?}", again.staged);
        assert!(head.is_none(), "an unchanged tree publishes no head");

        // Retargeting moves the signal and stages an update.
        std::fs::remove_file(space.path().join("link")).unwrap();
        std::os::unix::fs::symlink("b.txt", space.path().join("link")).unwrap();
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.hashed, 1, "only the link moved");
        assert_eq!(head.unwrap().seq, 2);
        assert_eq!(
            published(&node, "media", "link").symlink_target.as_deref(),
            Some("b.txt")
        );

        // Removing the link is tombstoned, and its row goes with it.
        std::fs::remove_file(space.path().join("link")).unwrap();
        let (report, head) = node.scan_and_publish().unwrap();
        assert_eq!(report.deleted, 1);
        assert!(head.is_some());
        assert_eq!(published(&node, "media", "link").kind, EntryKind::Tombstone);
        assert!(node.store().local_file("media", "link").unwrap().is_none());
        node.shutdown().await.unwrap();
    }
}

/// The symlink-escape guard, exercised where a symlink can be made (creating
/// one to test against is not cross-platform).
#[cfg(all(test, unix))]
mod escape_tests {
    use crate::testkit::node_with_space;

    /// Without the ancestor check, a client naming a key could write and
    /// delete anywhere the daemon's uid reaches.
    #[tokio::test]
    async fn a_symlinked_directory_cannot_be_written_or_deleted_through() {
        let (_d, space, node) = node_with_space().await;
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"not yours").unwrap();
        std::os::unix::fs::symlink(outside.path(), space.path().join("escape")).unwrap();

        assert!(node.open_adoption("media", "escape/secret").is_err());
        assert!(node.adopt_deletion("media", "escape/secret").is_err());
        assert!(node
            .adopt_deletion("media", "escape/nested/deep.txt")
            .is_err());
        // The file outside the space is untouched by all of that.
        assert_eq!(
            std::fs::read(outside.path().join("secret")).unwrap(),
            b"not yours"
        );
        // Ordinary paths, and a symlink that *is* the final component, still work.
        assert!(node.open_adoption("media", "ordinary.txt").is_ok());
        node.shutdown().await.unwrap();
    }
}
