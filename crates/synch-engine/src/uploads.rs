//! Multipart uploads, from the daemon's side (§9.4).
//!
//! The S3 gateway holds no state and any number of gateway processes may point
//! at one daemon, so a multipart upload — which outlives every request in it —
//! lives here. The store keeps the bookkeeping ([`synch_store::uploads`]) and
//! this module owns the bytes: a directory per upload under the data dir, one
//! staged payload per part, and an assembly step that hands the finished object
//! to the ordinary ingest pipeline.
//!
//! **Assembly always goes through an [`Adoption`].** The tempting shortcut for
//! the single-part case — rename the part straight onto the target — is wrong
//! twice over. `rename(2)` fails with `EXDEV` whenever the data dir and the
//! space are on different filesystems, which is the normal shape for a NAS or
//! an external drive; and a renamed file keeps the mtime it was *uploaded*
//! with, which is what §8's `newest` policy orders versions by, so a completion
//! would publish a version that loses to content it supersedes. One path, taken
//! by every completion, avoids both.

use std::path::{Path, PathBuf};

use synch_core::Hash;
use synch_store::{UploadPart, UploadState, MAX_PART_NUMBER, MAX_PART_SIZE, MIN_PART_SIZE};

use crate::{
    error::{EngineError, Result},
    node::Node,
    scanner::Adoption,
};

/// How long an upload nobody finished stays before the sweeper collects it.
///
/// S3 leaks incomplete multipart uploads by design — that is what its lifecycle
/// rules are for — so something here has to decide. A week is long enough that
/// a genuinely slow client is never cut off and short enough that a wedged one
/// does not hold its bytes forever.
pub const DEFAULT_UPLOAD_TTL: std::time::Duration = std::time::Duration::from_secs(7 * 86_400);

/// Where a part's payload is being staged, and what it will be recorded as.
#[derive(Debug, Clone)]
pub struct PartStaging {
    /// The upload the part belongs to.
    pub upload: String,
    /// The part number.
    pub number: u32,
    /// The file the payload is written to, inside the upload's directory.
    pub path: PathBuf,
    /// The name that file is recorded under.
    pub file: String,
}

/// What a delete did, and what it left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deleted {
    /// Whether there was a local copy to remove.
    pub removed: bool,
    /// Whether some origin still publishes a live entry for the path.
    ///
    /// True means the delete did what it could and the key is still readable:
    /// another origin asserts it, and only that origin can retract it (§8).
    pub still_published: bool,
}

/// What a completion produced.
#[derive(Debug, Clone)]
pub struct CompletedUpload {
    /// The assembled object's root.
    pub root: Hash,
    /// Its size in bytes.
    pub size: u64,
    /// True when the answer came from a recorded result rather than an
    /// assembly that ran now.
    pub replayed: bool,
}

impl Node {
    /// Where an upload will land, refusing anything outside a configured space.
    ///
    /// Resolved at creation rather than at completion so a path the space
    /// cannot hold is refused before the client streams a single part.
    pub fn upload_target(&self, space: &str, path: &str) -> Result<PathBuf> {
        self.adoption_target(space, path)
    }

    /// Opens a multipart upload and returns its id.
    ///
    /// The directory and its parent are flushed before the row commits, which
    /// is the ordering the "a part row implies bytes" invariant rests on: the
    /// row is the thing that may be lost, and a lost row leaves a directory the
    /// sweeper collects rather than a pointer into nothing.
    pub fn create_upload(&self, space: &str, path: &str, _target: &Path) -> Result<String> {
        // A key the scanner would skip can never become an object, and finding
        // that out at completion — after the client has streamed gigabytes and
        // the parts have been consumed — is the worst possible moment for it.
        let space_row = self
            .store()
            .space(space)?
            .ok_or_else(|| EngineError::not_found(format!("space {space}")))?;
        let normalized =
            synch_core::normalize_path(path).map_err(|e| EngineError::invalid(e.to_string()))?;
        if crate::ignore::IgnoreSet::for_space(Path::new(&space_row.local_path))?
            .is_ignored(&normalized, false)
        {
            return Err(EngineError::invalid(format!(
                "{space}/{path} matches an ignore rule, so it could never be published"
            )));
        }
        let id = new_upload_id();
        let dir = self.store().upload_dir(&id);
        std::fs::create_dir_all(&dir)?;
        fsync_dir(&dir);
        fsync_dir(&self.store().uploads_dir());
        self.store()
            .create_upload(&id, space, path, synch_core::now_ns())?;
        Ok(id)
    }

    /// Checks an upload will still take this part, and says where to stage it.
    ///
    /// The part number is checked against S3's range here rather than at
    /// completion: a client that numbers parts wrongly should find out before
    /// it has pushed gigabytes, and without a bound a client could open an
    /// unbounded number of staged payloads against one upload.
    pub fn open_part(
        &self,
        upload: &str,
        space: &str,
        path: &str,
        number: u32,
    ) -> Result<PartStaging> {
        if number == 0 || number > MAX_PART_NUMBER {
            return Err(EngineError::invalid(format!(
                "part number {number} is outside 1..={MAX_PART_NUMBER}"
            )));
        }
        let record = self.upload_for(upload, space, path)?;
        if record.state != UploadState::Open {
            return Err(EngineError::invalid(format!(
                "upload {upload} is no longer accepting parts"
            )));
        }
        // A name per attempt, not per part number. Two clients racing the same
        // part number would otherwise share one file and interleave their
        // bytes, and the winner of the row write would describe the loser's
        // payload.
        let file = format!("{number:05}.{}{}", nonce(), crate::scanner::PART_SUFFIX);
        Ok(PartStaging {
            upload: upload.to_string(),
            number,
            path: self.store().upload_dir(upload).join(&file),
            file,
        })
    }

    /// Commits a staged part and records it.
    ///
    /// The payload is fsynced and renamed into its final name *before* the row
    /// is written, so a row never names a file that is not there. A crash
    /// between the two leaves an unreferenced payload, which the sweeper
    /// collects — the safe half of the asymmetry.
    pub fn commit_part(&self, staging: PartStaging, adoption: Adoption) -> Result<UploadPart> {
        let size = adoption.written();
        if size > MAX_PART_SIZE {
            return Err(EngineError::invalid(format!(
                "a part of {size} byte(s) is larger than the {MAX_PART_SIZE}-byte maximum"
            )));
        }
        let path = adoption.commit()?;
        let root = synch_core::hash_reader(std::io::BufReader::new(std::fs::File::open(&path)?))?;
        let part = UploadPart {
            number: staging.number,
            file: staging.file,
            size,
            root,
        };
        // A superseded attempt is left on disk deliberately: a completion may
        // already hold it open, and the sweeper collects payloads no row names.
        self.store().record_part(&staging.upload, &part)?;
        Ok(part)
    }

    /// Assembles the named parts, publishes the object, and reports its root.
    pub async fn complete_upload(
        &self,
        upload: &str,
        space: &str,
        path: &str,
        parts: &[(u32, Option<Hash>)],
    ) -> Result<CompletedUpload> {
        self.upload_for(upload, space, path)?;
        let start = self.store().begin_complete(upload)?;
        let (recorded_space, recorded_path, available) = match start {
            // A retried completion. The client never saw the first answer, so
            // it gets that answer rather than being told its upload is gone.
            synch_store::CompleteStart::AlreadyCompleted { etag, size } => {
                return Ok(CompletedUpload {
                    root: etag,
                    size,
                    replayed: true,
                })
            }
            synch_store::CompleteStart::Ready { space, path, parts } => (space, path, parts),
        };
        // From here the upload holds the latch, so every failure has to put it
        // back: the client is entitled to fix its part list and retry, and an
        // upload stuck in `completing` could never be retried at all.
        match self
            .assemble(upload, &recorded_space, &recorded_path, parts, &available)
            .await
        {
            Ok(completed) => Ok(completed),
            Err(e) => {
                if let Err(unlatch) = self.store().reopen_upload(upload) {
                    tracing::warn!(upload, error = %unlatch, "could not reopen a failed upload");
                }
                Err(e)
            }
        }
    }

    /// The assembly itself, once the upload is latched.
    async fn assemble(
        &self,
        upload: &str,
        space: &str,
        path: &str,
        wanted: &[(u32, Option<Hash>)],
        available: &[UploadPart],
    ) -> Result<CompletedUpload> {
        let chosen = choose_parts(wanted, available)?;
        let dir = self.store().upload_dir(upload);
        let target = self.adoption_target(space, path)?;
        let sources: Vec<PathBuf> = chosen.iter().map(|part| dir.join(&part.file)).collect();

        // One blocking closure for the whole assembly: `copy_file_range` is a
        // syscall per part and the fallback is a read/write loop, and neither
        // belongs on a runtime worker that is also polling every other
        // connection. The root is taken here, from the bytes that were actually
        // written, rather than read back out of the tree afterwards — a
        // read-back describes whatever the tree holds by then, which a
        // concurrent write to the same key wins.
        let (root, size) = crate::blocking::offload(move || {
            let mut adoption = Adoption::at(&target)?;
            for source in &sources {
                adoption.append_file(source)?;
            }
            let written = adoption.written();
            let root = adoption.hash_staged()?;
            adoption.commit()?;
            Ok((root, written))
        })
        .await?;

        // Past here the object is in the space and this node *will* publish it
        // — the watcher picks it up even if nothing below runs. So the result is
        // recorded before anything else can fail, and the parts are unlinked
        // only once nothing is left that could send the caller back. Unlinking
        // them any earlier, for the peak-disk saving it buys, leaves rows naming
        // payloads that are gone: every retry then dies on a missing file
        // instead of being told what was actually wrong.
        self.store()
            .finish_complete(upload, &root, size, synch_core::now_ns())?;
        for part in &chosen {
            let _ = std::fs::remove_file(dir.join(&part.file));
        }
        let _ = std::fs::remove_dir_all(&dir);

        // The ordinary indexing pipeline takes it from here — hash, CAS, stage,
        // publish — exactly as a `PutObject` does, so a completed upload is a
        // version like any other. A failure here is *not* a failed completion:
        // the object is committed and the answer recorded, and the next scan
        // publishes it. Reporting failure would tell the client to retry an
        // upload that has already landed.
        if let Err(e) = self.scan_publish_push().await {
            tracing::warn!(
                upload,
                error = %e,
                "the completed object is in the space but this publish failed; \
                 the next scan will pick it up"
            );
        }
        Ok(CompletedUpload {
            root,
            size,
            replayed: false,
        })
    }

    /// Removes this node's copy of a path and publishes its tombstone (§8,
    /// §9.4).
    ///
    /// The delete half of `PutObject`, and it obeys the same rule: a write
    /// publishes *this node's own view*, because the version model has no way
    /// to publish anyone else's. So this removes our copy and asserts our
    /// tombstone, and that is the whole of what a delete can mean here. If
    /// another origin still publishes the path, the path is still in the
    /// unified tree afterwards — with one fewer version — and the caller is
    /// told so rather than left to discover it on the next read.
    ///
    /// Removing nothing is not a failure. S3 makes `DeleteObject` idempotent
    /// and tooling leans on it hard (`rm -f`, retried deletes, `rm` of a key a
    /// concurrent writer already removed), so a path that is already absent
    /// here is a delete that has already happened.
    pub async fn delete_object(&self, space: &str, path: &str) -> Result<Deleted> {
        // Before touching the file, not after: a node that cannot publish would
        // otherwise unlink the local copy and be unable to tell anyone (§3.4),
        // which loses data — the tombstone that would have justified the
        // removal never gets signed.
        self.ensure_publishable()?;
        let node = self.clone();
        let (space_owned, path_owned) = (space.to_string(), path.to_string());
        let removed =
            crate::blocking::offload(move || node.adopt_deletion(&space_owned, &path_owned))
                .await?
                .is_some();

        // Unconditionally, and not only when a file was removed. The tombstone
        // comes from the scanner's deletion sweep, which walks `local_files`
        // rows, so a path whose file was already gone — removed out of band
        // while the daemon was down — would otherwise never be published as
        // deleted at all. An unchanged tree stages nothing, so being wrong here
        // costs one stat pass.
        self.scan_publish_push().await?;

        // The sweep tombstones what it can see, and what it can see is
        // `local_files`. If our own entry is *still live* after that, the sweep
        // never saw the path — so the tombstone is staged here, from the trie
        // rather than from the row that is missing. A row goes missing more
        // easily than it looks: `reconcile_local_files` drops any the current
        // head does not corroborate, and the control socket answers before the
        // startup scan has finished. Without this the delete returns `204` and
        // leaves this node asserting the key, signed, to every peer, with no
        // later scan or restart able to notice.
        let mine = synch_store::VersionPolicy::Origin(self.origin().clone());
        let set = self.versions(space, path)?;
        if self
            .resolve_set(&set, &mine)
            .is_ok_and(|row| row.kind != synch_core::EntryKind::Tombstone)
        {
            tracing::warn!(
                space,
                path,
                "no local record backed this path; tombstoning it from the trie"
            );
            // The same tombstone the sweep would have staged: a *record*, not a
            // removal. Staging `None` retires the key outright, which is what
            // expiring a tombstone means — the path would read as "never
            // existed" rather than "deleted at seq N", and peers would lose the
            // assertion that tells them to stop serving their own copies.
            let previous = self
                .store()
                .entry(self.origin(), space, path)?
                .and_then(|entry| entry.content);
            let tombstone =
                synch_core::FileEntry::tombstone(synch_core::now_ns(), self.next_seq()?, previous);
            let encoded =
                postcard::to_stdvec(&tombstone).map_err(|e| EngineError::Record(e.to_string()))?;
            self.stage([(synch_core::file_key(space, path)?, Some(encoded))]);
            self.flush_staged().await?;
        }

        // Whether the key survives is a question about *other* origins. Our own
        // entry is a tombstone by now, or was never there; counting it would
        // report every ordinary delete as one somebody else is still
        // publishing, which is the opposite of the warning it exists to give.
        let ours = self.origin();
        let set = self.versions(space, path)?;
        let still_published = set
            .entries
            .iter()
            .any(|entry| entry.origin != *ours && entry.kind != synch_core::EntryKind::Tombstone);
        Ok(Deleted {
            removed,
            still_published,
        })
    }

    /// Drops an upload and everything staged for it.
    pub fn abort_upload(&self, upload: &str, space: &str, path: &str) -> Result<bool> {
        match self.upload_for(upload, space, path) {
            Ok(_) => {}
            // An abort of something that is not there is a success: it is not
            // there, which is what the caller asked for.
            Err(EngineError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        }
        let existed = self.store().abort_upload(upload)?;
        if existed {
            let _ = std::fs::remove_dir_all(self.store().upload_dir(upload));
        }
        Ok(existed)
    }

    /// Every upload still accepting parts under a prefix.
    pub fn open_uploads(&self, space: &str, prefix: &str) -> Result<Vec<synch_store::Upload>> {
        Ok(self.store().open_uploads(space, prefix)?)
    }

    /// Every part recorded for one upload.
    pub fn upload_parts(&self, upload: &str, space: &str, path: &str) -> Result<Vec<UploadPart>> {
        self.upload_for(upload, space, path)?;
        Ok(self.store().upload_parts(upload)?)
    }

    /// Reads an upload, insisting it belongs to the key the caller named.
    ///
    /// An upload id is a bearer token for one key. Answering a request that
    /// quotes it against a *different* key would let a client complete an
    /// upload into a path it never named — and since two buckets may map to one
    /// space, the comparison has to be on the space and path rather than on the
    /// bucket the request arrived at.
    fn upload_for(&self, upload: &str, space: &str, path: &str) -> Result<synch_store::Upload> {
        let record = self
            .store()
            .upload(upload)?
            .ok_or_else(|| EngineError::not_found(format!("upload {upload}")))?;
        if record.space != space || record.path != path {
            return Err(EngineError::not_found(format!(
                "upload {upload} is not against {space}/{path}"
            )));
        }
        Ok(record)
    }

    /// Collects uploads nobody finished, and payloads no row names.
    ///
    /// Two sweeps, because there are two ways to leak. An *upload* leaks when a
    /// client walks away, and is collected on its age. A *payload* leaks when a
    /// crash lands between the rename and the row, or when a re-uploaded part
    /// supersedes an attempt a completion might still have had open — those sit
    /// inside a directory that is very much still live, so no directory-level
    /// sweep would ever see them.
    pub fn sweep_uploads(&self, ttl: std::time::Duration) -> Result<usize> {
        let ttl_ns = i64::try_from(ttl.as_nanos()).unwrap_or(i64::MAX);
        let cutoff = synch_core::now_ns().saturating_sub(ttl_ns);
        let mut collected = 0;
        for id in self.store().uploads_before(cutoff)? {
            // `abort_upload` refuses while a completion holds the latch, which
            // is what should happen: an assembly in flight is not abandoned. A
            // latch nothing is behind any more ages out on its own and is
            // collected on a later pass.
            match self.store().abort_upload(&id) {
                Ok(true) => {
                    let _ = std::fs::remove_dir_all(self.store().upload_dir(&id));
                    collected += 1;
                }
                Ok(false) => {}
                Err(e) => tracing::debug!(upload = %id, error = %e, "upload not swept"),
            }
        }

        let live: std::collections::HashSet<String> =
            self.store().upload_ids()?.into_iter().collect();
        let root = self.store().uploads_dir();
        let Ok(entries) = std::fs::read_dir(&root) else {
            return Ok(collected);
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if !live.contains(&name) {
                // Either a crash between the mkdir and the row, or a row already
                // swept. The grace window keeps this off a directory
                // `create_upload` made a moment ago. A stray *file* here is
                // removed as one: `remove_dir_all` refuses it, and nothing else
                // would ever come back for it.
                if older_than(&path, ORPHAN_GRACE) {
                    let removed = if path.is_dir() {
                        std::fs::remove_dir_all(&path).is_ok()
                    } else {
                        std::fs::remove_file(&path).is_ok()
                    };
                    if removed {
                        collected += 1;
                    }
                }
                continue;
            }
            // One bad row must not end the pass: everything else in this loop is
            // best-effort, and a sweep that gives up on the first oddity leaves
            // every later upload uncollected forever.
            let named: std::collections::HashSet<String> = match self.store().upload_parts(&name) {
                Ok(parts) => parts.into_iter().map(|part| part.file).collect(),
                Err(e) => {
                    tracing::debug!(upload = %name, error = %e, "parts not readable; not swept");
                    continue;
                }
            };
            let Ok(payloads) = std::fs::read_dir(&path) else {
                continue;
            };
            for payload in payloads.flatten() {
                let file = payload.file_name().to_string_lossy().into_owned();
                // An `Adoption`'s own staging file lives in this directory while
                // a part is still streaming, under a dot-prefixed name no row
                // will ever mention. It is not an orphan — it is a write in
                // progress, and a client that paused for longer than the grace
                // window would find its part unlinked from under an open handle
                // and fail for a reason it could do nothing about.
                if file.starts_with('.') {
                    continue;
                }
                if !named.contains(&file) && older_than(&payload.path(), ORPHAN_GRACE) {
                    let _ = std::fs::remove_file(payload.path());
                    collected += 1;
                }
            }
        }
        Ok(collected)
    }

    /// Returns every interrupted completion to `open`, at startup.
    ///
    /// A completion severed by a daemon stop or a crash leaves the latch set,
    /// and nothing else ever clears it: without this the upload would refuse
    /// every retry until its bytes aged out, even though every part is still
    /// there.
    pub fn reopen_interrupted_uploads(&self) -> Result<usize> {
        Ok(self.store().reopen_interrupted_uploads()?)
    }
}

/// How long an unreferenced payload or directory must sit before it is swept.
///
/// The sweep races the writers by construction — a directory exists before its
/// row, and a payload exists before the row that names it — so it only ever
/// collects what has been unreferenced for longer than any of those windows.
const ORPHAN_GRACE: std::time::Duration = std::time::Duration::from_secs(3600);

/// Whether a path was last modified longer ago than `grace`.
///
/// A path whose age cannot be read is treated as young: refusing to guess is
/// what keeps a sweep from deleting something it could not measure.
fn older_than(path: &Path, grace: std::time::Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .and_then(|at| at.elapsed().map_err(std::io::Error::other))
        .map(|age| age > grace)
        .unwrap_or(false)
}

/// Picks the parts a completion named, in the order S3 requires.
///
/// Every check S3 makes at completion time, and for its reasons: a client that
/// names parts out of order has lost track of its own upload, one that names a
/// part that is not there has lost an upload it thinks succeeded, and one whose
/// interior part is under the minimum has produced an object no other S3
/// implementation would have accepted.
fn choose_parts<'a>(
    wanted: &[(u32, Option<Hash>)],
    available: &'a [UploadPart],
) -> Result<Vec<&'a UploadPart>> {
    if wanted.is_empty() {
        return Err(EngineError::invalid("a completion names no parts"));
    }
    // Order first, then existence, then sizes — and all of each before any of
    // the next. Reporting a part as too small when a *later* part was never
    // uploaded sends the client to shrink a part that was fine, and it retries
    // into the same failure.
    let mut previous = 0;
    for (number, _) in wanted {
        if *number <= previous {
            return Err(EngineError::invalid(format!(
                "part {number} is out of order"
            )));
        }
        previous = *number;
    }
    let mut chosen = Vec::with_capacity(wanted.len());
    for (number, expected) in wanted {
        let part = available
            .iter()
            .find(|part| part.number == *number)
            .ok_or_else(|| EngineError::invalid(format!("part {number} was never uploaded")))?;
        // The client echoes back the root it was given, and checking it is the
        // point of having handed one over: a mismatch means the part it thinks
        // it uploaded is not the part that is here.
        if let Some(expected) = expected {
            if part.root != *expected {
                return Err(EngineError::invalid(format!(
                    "part {number} does not have the root the completion named"
                )));
            }
        }
        chosen.push(part);
    }
    // Every part but the last has to reach the minimum. The last one is exempt
    // because an object is rarely a whole number of parts long.
    for part in &chosen[..chosen.len() - 1] {
        if part.size < MIN_PART_SIZE {
            return Err(EngineError::invalid(format!(
                "part {} is {} byte(s), under the {MIN_PART_SIZE}-byte minimum for a part that is not the last",
                part.number, part.size
            )));
        }
    }
    Ok(chosen)
}

/// A fresh upload id: 32 hex characters.
///
/// Hex, never base64. The id travels as a query parameter, and this gateway's
/// URI decoding turns `+` into a space — a base64 id would break the first time
/// a client sent one unencoded.
fn new_upload_id() -> String {
    format!("{}{}", nonce(), nonce())
}

/// Sixteen hex characters of process-local uniqueness.
fn nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut seed = Vec::with_capacity(20);
    seed.extend_from_slice(&synch_core::now_ns().to_le_bytes());
    seed.extend_from_slice(&count.to_le_bytes());
    seed.extend_from_slice(&std::process::id().to_le_bytes());
    Hash::new(&seed).to_hex()[..16].to_string()
}

/// Flushes a directory entry, best effort — the same posture the CAS takes.
fn fsync_dir(path: &Path) {
    if let Ok(dir) = std::fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(number: u32, size: u64) -> UploadPart {
        UploadPart {
            number,
            file: format!("{number}"),
            size,
            root: Hash::new(&number.to_le_bytes()),
        }
    }

    fn named(numbers: &[u32]) -> Vec<(u32, Option<Hash>)> {
        numbers.iter().map(|n| (*n, None)).collect()
    }

    #[test]
    fn parts_are_chosen_in_order() {
        let available = vec![part(1, MIN_PART_SIZE), part(2, MIN_PART_SIZE), part(3, 10)];
        let chosen = choose_parts(&named(&[1, 2, 3]), &available).unwrap();
        assert_eq!(chosen.len(), 3);
        // A subset is legal, and the parts left out are simply discarded.
        assert_eq!(choose_parts(&named(&[1, 3]), &available).unwrap().len(), 2);
    }

    #[test]
    fn descending_and_repeated_parts_are_refused() {
        let available = vec![part(1, MIN_PART_SIZE), part(2, MIN_PART_SIZE)];
        assert!(choose_parts(&named(&[2, 1]), &available).is_err());
        assert!(choose_parts(&named(&[1, 1]), &available).is_err());
        assert!(choose_parts(&[], &available).is_err());
    }

    #[test]
    fn a_missing_part_is_refused() {
        let available = vec![part(1, MIN_PART_SIZE)];
        assert!(choose_parts(&named(&[1, 2]), &available).is_err());
    }

    #[test]
    fn a_part_that_is_not_the_one_named_is_refused() {
        let available = vec![part(1, 10)];
        let wrong = vec![(1u32, Some(Hash::new(b"something else")))];
        assert!(choose_parts(&wrong, &available).is_err());
        let right = vec![(1u32, Some(available[0].root))];
        assert!(choose_parts(&right, &available).is_ok());
    }

    /// A missing part is reported as missing even when an earlier part is also
    /// too small: the client that shrank the wrong part retries into the same
    /// failure.
    #[test]
    fn existence_is_checked_before_size() {
        let available = vec![part(1, 10)];
        let err = choose_parts(&named(&[1, 9]), &available)
            .unwrap_err()
            .to_string();
        assert!(err.contains("part 9 was never uploaded"), "{err}");
    }

    #[test]
    fn only_the_last_part_may_be_small() {
        let available = vec![part(1, 10), part(2, 10)];
        // The last part alone is exempt, so a one-part upload of ten bytes is
        // fine and a ten-byte first part is not.
        assert!(choose_parts(&named(&[1]), &available).is_ok());
        assert!(choose_parts(&named(&[1, 2]), &available).is_err());
    }

    #[test]
    fn upload_ids_are_hex() {
        let id = new_upload_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
        assert_ne!(id, new_upload_id());
    }
}

#[cfg(test)]
mod sweeper_tests {
    use super::*;
    use crate::{Node, NodeConfig};

    async fn node_with_space() -> (tempfile::TempDir, tempfile::TempDir, Node) {
        let data = tempfile::tempdir().unwrap();
        let space = tempfile::tempdir().unwrap();
        Node::init(data.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(data.path())).await.unwrap();
        node.add_space("media", space.path()).unwrap();
        (data, space, node)
    }

    /// The sweeper collects what nobody is coming back for, and nothing else.
    #[tokio::test]
    async fn the_sweeper_collects_only_what_is_abandoned() {
        let (_d, _s, node) = node_with_space().await;
        let target = node.upload_target("media", "a.bin").unwrap();
        let id = node.create_upload("media", "a.bin", &target).unwrap();

        assert_eq!(node.sweep_uploads(std::time::Duration::ZERO).unwrap(), 1);
        assert!(node.store().upload(&id).unwrap().is_none());
        assert!(!node.store().upload_dir(&id).exists());

        // A live upload with a long TTL is left alone.
        let id = node.create_upload("media", "b.bin", &target).unwrap();
        assert_eq!(node.sweep_uploads(DEFAULT_UPLOAD_TTL).unwrap(), 0);
        assert!(node.store().upload(&id).unwrap().is_some());
        node.shutdown().await.unwrap();
    }

    /// A part still streaming is not an orphan.
    ///
    /// An `Adoption`'s staging file lives in the upload directory under a
    /// dot-prefixed name no row will ever mention. Collecting it would unlink a
    /// part from under an open handle, and the client would see a failure it
    /// could do nothing about.
    #[tokio::test]
    async fn the_sweeper_leaves_a_write_in_progress_alone() {
        let (_d, _s, node) = node_with_space().await;
        let target = node.upload_target("media", "a.bin").unwrap();
        let id = node.create_upload("media", "a.bin", &target).unwrap();
        let staging = node.open_part(&id, "media", "a.bin", 1).unwrap();
        let mut adoption = crate::scanner::Adoption::at(&staging.path).unwrap();
        adoption.write(b"still arriving").unwrap();

        node.sweep_uploads(DEFAULT_UPLOAD_TTL).unwrap();
        let part = node.commit_part(staging, adoption).unwrap();
        assert_eq!(part.size, 14);
        assert_eq!(node.store().upload_parts(&id).unwrap().len(), 1);
        node.shutdown().await.unwrap();
    }

    /// A key the scanner would skip is refused before the client streams.
    #[tokio::test]
    async fn an_unpublishable_key_is_refused_at_creation() {
        let (_d, _s, node) = node_with_space().await;
        let target = node.upload_target("media", "notes.tmp").unwrap();
        assert!(
            node.create_upload("media", "notes.tmp", &target).is_err(),
            "an ignored key was accepted"
        );
        let target = node.upload_target("media", "notes.txt").unwrap();
        assert!(node.create_upload("media", "notes.txt", &target).is_ok());
        node.shutdown().await.unwrap();
    }

    /// A completion answers with the root of the bytes it assembled.
    #[tokio::test]
    async fn a_completion_hashes_what_it_assembled() {
        let (_d, space, node) = node_with_space().await;
        let target = node.upload_target("media", "joined.bin").unwrap();
        let id = node.create_upload("media", "joined.bin", &target).unwrap();

        let head = vec![7u8; MIN_PART_SIZE as usize];
        let tail = b"and the tail".to_vec();
        for (number, bytes) in [(1u32, &head), (2u32, &tail)] {
            let staging = node.open_part(&id, "media", "joined.bin", number).unwrap();
            let mut adoption = crate::scanner::Adoption::at(&staging.path).unwrap();
            adoption.write(bytes).unwrap();
            node.commit_part(staging, adoption).unwrap();
        }
        let done = node
            .complete_upload(&id, "media", "joined.bin", &[(1, None), (2, None)])
            .await
            .unwrap();

        let mut expected = head.clone();
        expected.extend_from_slice(&tail);
        assert_eq!(done.size, expected.len() as u64);
        assert_eq!(done.root, synch_core::Hash::new(&expected));
        assert_eq!(
            std::fs::read(space.path().join("joined.bin")).unwrap(),
            expected
        );
        // The parts and their directory go once the answer is recorded.
        assert!(!node.store().upload_dir(&id).exists());
        assert!(node.store().upload_parts(&id).unwrap().is_empty());
        node.shutdown().await.unwrap();
    }
}
