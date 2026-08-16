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
    node::{paths_overlap, stored_root, Node},
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
    /// Files written by patching a clone of the copy already at the target,
    /// rather than by copying the whole object out of the CAS
    /// (`docs/DELTA-SYNC.md` §3.5). A subset of `written`.
    pub patched: usize,
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
                plan_pass(&node, &root_dir, &listing, &policy)
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
            let fetched = self
                .fetch_all_from(&want.content, want.size, &want.donors)
                .await?;
            if !fetched.complete {
                report
                    .skipped
                    .push((want.path, "no provider could serve the content".into()));
                continue;
            }
            // The groups the file already at the destination was *proven* to
            // hold correctly, which the write may then leave alone. Not every
            // promoted group qualifies: bytes promoted out of some other
            // object in the CAS are right in the CAS, and say nothing about
            // what is on the disk at this path (`docs/DELTA-SYNC.md` §3.5).
            let keep = match (self.config().mirror_delta_write, &want.on_disk) {
                (crate::config::MirrorDeltaWrite::Off, _) | (_, None) => ChunkRanges::empty(),
                (_, Some(on_disk)) => fetched
                    .reused
                    .iter()
                    .filter(|(donor, _)| match donor {
                        // Bytes taken out of the file itself are, trivially,
                        // bytes the file has right.
                        synch_store::Donor::File(path) => path == &want.target,
                        // And so are bytes taken out of the CAS object the file
                        // *is* a copy of: same object, same offsets, same
                        // bytes. This is the case that carries the common
                        // mirror update, because the previous version is
                        // usually in both places and the CAS is the cheaper of
                        // the two to compare against, so it wins the donor race
                        // every time.
                        synch_store::Donor::Object(root) => on_disk.root == Some(*root),
                    })
                    .fold(ChunkRanges::empty(), |all, (_, groups)| all.union(groups)),
            };
            let reflink =
                self.config().mirror_delta_write == crate::config::MirrorDeltaWrite::Reflink;
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
            let patching = !keep.is_empty();
            let outcome = crate::blocking::offload(move || {
                if escapes_via_symlink(&root, &path) {
                    return Ok(Written::Escaped);
                }
                if patching {
                    node.patch_blob_to_blocking(
                        &want.content,
                        want.size,
                        &want.target,
                        &keep,
                        reflink,
                    )?;
                } else {
                    node.write_blob_to_blocking(&want.content, want.size, &want.target)?;
                }
                // The bytes are the file; its metadata is stamped on right
                // after, and a filesystem that refuses the stamp — a mount
                // that will not take the mode, a foreign owner — is reported
                // rather than allowed to fail the whole pass.
                Ok(match apply_metadata(&want.target, want.meta) {
                    Ok(()) => Written::Fully,
                    Err(e) => Written::WithoutMetadata(e.to_string()),
                })
            })
            .await?;
            if patching && !matches!(outcome, Written::Escaped) {
                report.patched += 1;
            }
            match outcome {
                Written::Fully => report.written += 1,
                Written::WithoutMetadata(why) => {
                    report.written += 1;
                    report.skipped.push((
                        want.path,
                        format!("content written, but its metadata could not be reproduced: {why}"),
                    ));
                }
                Written::Escaped => report.skipped.push((
                    want.path,
                    "path resolves through a symlink; refusing to write outside the mirror".into(),
                )),
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
    /// The metadata to stamp on once the bytes are there.
    meta: Metadata,
    /// Where the bytes might already be, in §3.2 priority order
    /// (`docs/DELTA-SYNC.md`).
    donors: Vec<synch_store::Donor>,
    /// What is already at the target, when anything is: the file the write may
    /// be able to patch a clone of rather than copy the object out whole
    /// (§3.5).
    on_disk: Option<OnDisk>,
}

/// How one write in phase 2 ended.
#[derive(Debug)]
enum Written {
    /// Bytes and metadata both.
    Fully,
    /// The bytes landed; the filesystem refused the metadata.
    WithoutMetadata(String),
    /// Refused by the symlink-escape guard: nothing was written.
    Escaped,
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
            let meta = Metadata::of(&selected);
            let on_disk = on_disk(&target, selected.size, node.config().delta_min_size);
            if on_disk.as_ref().and_then(|f| f.root) == Some(content) {
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
                continue;
            }

            // Where the bytes of this version might already be, in the order
            // §3.2 wants them tried: the CAS first, because a donor with an
            // outboard is compared span by span for the price of a few reads,
            // and only then the file at the destination, whose every span has
            // to be hashed to be compared at all. That file is offered whatever
            // its size — an append is the case delta serves best, and there the
            // old file is by definition the wrong length.
            let mut donors = node.donors_for(&selected, set)?;
            if on_disk.is_some() {
                donors.push(synch_store::Donor::File(target.clone()));
            }
            wanted.push(WantedContent {
                path: set.path.clone(),
                target,
                content,
                size: selected.size,
                meta,
                donors,
                on_disk,
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
/// — could not be stamped once its own mode had been applied. The pass that got
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

/// What a pass found at a mirror's target path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OnDisk {
    /// The file's length.
    size: u64,
    /// Its content root, when the pass had reason to compute one.
    root: Option<synch_core::Hash>,
}

/// Looks at the file already at `target`, hashing it when that will pay.
///
/// Size first, because it settles almost every case for the price of a `stat`;
/// the hash only then, and streamed, because a mirror carries objects far
/// larger than memory and this question is asked of every path on every pass.
/// Anything unreadable answers `None`, and the pass rewrites it.
///
/// The root rather than a bare "is this current?": naming the object that is
/// actually on the disk is what lets the write be a patch. If the file turns
/// out to be a version the descent also has in the CAS, then every group the
/// CAS donor supplies is, by definition, already correct at the same offset in
/// the file — and the staging clone can keep it (`docs/DELTA-SYNC.md` §3.2.4,
/// §3.5).
///
/// Two reasons to hash, then. When the size matches the wanted version the hash
/// is the current-check and costs nothing extra. When it does not — an appended
/// log, a truncated image — the file is going to be rewritten either way, and
/// hashing it first is only worth it if what that might save is worth saving:
/// hence the [`NodeConfig::delta_min_size`](crate::NodeConfig) floor, the same
/// one the fetch descent uses.
fn on_disk(target: &Path, wanted_size: u64, delta_min_size: u64) -> Option<OnDisk> {
    let size = std::fs::metadata(target)
        .ok()
        .filter(|m| m.is_file())?
        .len();
    if size != wanted_size && size < delta_min_size {
        return Some(OnDisk { size, root: None });
    }
    let root = std::fs::File::open(target)
        .ok()
        .and_then(|file| synch_core::hash_reader(std::io::BufReader::new(file)).ok());
    Some(OnDisk { size, root })
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
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
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

    /// A plausible published stamp: a real wall-clock nanosecond value, so the
    /// tests exercise what a scanner actually publishes rather than a stamp
    /// near the epoch that every filesystem stores exactly.
    const STAMP: i64 = 1_700_000_000_123_456_789;

    fn on_disk_mtime(path: &Path) -> i64 {
        crate::scanner::mtime_nanos(&std::fs::metadata(path).unwrap())
    }

    #[cfg(unix)]
    fn on_disk_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
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

    /// A file with no bytes is still a file: it materializes, empty, whether or
    /// not this node has ever held a copy of the (empty) object.
    #[tokio::test]
    async fn an_empty_file_is_mirrored() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        // Published by a peer and never ingested here: the local CAS has no row
        // for the empty object, which is the state a mirror actually meets.
        node.store()
            .put_entry(
                &peer(),
                "media",
                "empty.txt",
                &FileEntry::file(0, 1, Hash::new(b""), 1),
            )
            .unwrap();

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1, "{report:?}");
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(std::fs::read(target.path().join("empty.txt")).unwrap(), b"");

        // And a second pass sees it as current rather than writing it again.
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.current, 1, "{report:?}");
        assert_eq!(report.written, 0, "{report:?}");
        node.shutdown().await.unwrap();
    }

    /// §7.2: a mirrored file is the published file, which includes the mtime
    /// its origin observed — not the moment the copy happened to land.
    #[tokio::test]
    async fn a_mirror_reproduces_the_published_mtime() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        publish_entry(&node, &peer(), "a/b.txt", b"hello", STAMP);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 1, "{report:?}");
        let written = target.path().join("a/b.txt");
        let stored = on_disk_mtime(&written);
        assert!(
            (0..MTIME_GRANULARITY_NS).contains(&(STAMP - stored)),
            "the file carries {stored}, not the published {STAMP}"
        );

        // And the stamp is stable: a second pass sees a current file rather
        // than re-touching what it just wrote.
        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.current, 1, "{report:?}");
        assert_eq!(report.retouched, 0, "{report:?}");
        node.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_mirror_reproduces_the_published_mode() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        // The scanner publishes the whole `st_mode`, file-type bits included.
        publish_entry_with_mode(
            &node,
            &peer(),
            "run.sh",
            b"#!/bin/sh\n",
            STAMP,
            Some(0o100751),
        );
        // An origin that publishes no mode leaves the copy's own alone rather
        // than having some default asserted over it.
        publish_entry(&node, &peer(), "plain.txt", b"x", STAMP);

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.written, 2, "{report:?}");
        assert_eq!(on_disk_mode(&target.path().join("run.sh")), 0o751);
        assert!(target.path().join("plain.txt").exists());

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.current, 2, "{report:?}");
        node.shutdown().await.unwrap();
    }

    /// Metadata that drifts is repaired in place: the bytes are already right,
    /// and refetching an object to fix a permission bit would be absurd.
    #[cfg(unix)]
    #[tokio::test]
    async fn drifted_metadata_is_repaired_without_rewriting_the_content() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
        publish_entry_with_mode(&node, &peer(), "f.txt", b"hello", STAMP, Some(0o100640));
        node.sync_mirror(target.path()).await.unwrap();

        let written = target.path().join("f.txt");
        std::fs::set_permissions(&written, std::fs::Permissions::from_mode(0o600)).unwrap();
        set_modified(&written, 1_800_000_000_000_000_000).unwrap();

        let report = node.sync_mirror(target.path()).await.unwrap();
        assert_eq!(report.retouched, 1, "{report:?}");
        assert_eq!(report.written, 0, "the bytes were never in question");
        assert_eq!(report.current, 0, "{report:?}");
        assert_eq!(on_disk_mode(&written), 0o640);
        assert!((0..MTIME_GRANULARITY_NS).contains(&(STAMP - on_disk_mtime(&written))));
        assert_eq!(std::fs::read(&written).unwrap(), b"hello");
        node.shutdown().await.unwrap();
    }

    /// A read-only file can still be stamped. Setting a file's times needs a
    /// writable descriptor, so applying the mode before the time would leave a
    /// mirror unable to repair exactly the files whose mode it got right.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_read_only_file_can_still_be_restamped() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
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

        // Something moved the timestamp on a file the mirror had already made
        // read-only. The next pass has to put it back.
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

    /// The mode is advisory and a peer chose it: the bits that grant authority
    /// are not reproduced.
    #[cfg(unix)]
    #[tokio::test]
    async fn setuid_and_friends_are_not_materialized() {
        let (_d, node) = node().await;
        let target = tempfile::tempdir().unwrap();
        node.add_mirror("media", target.path(), &VersionPolicy::Newest)
            .unwrap();
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

    /// A coarse filesystem stores a stamp truncated, never advanced; treating
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

    /// A patch writes the groups that differ and leaves the rest of the file
    /// alone — including, on a filesystem with reflink, leaving them
    /// physically shared with the copy that was already there
    /// (`docs/DELTA-SYNC.md` §3.5).
    #[tokio::test]
    async fn a_patch_rewrites_only_the_groups_that_differ() {
        let (_d, node) = node().await;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("disk.img");
        const GROUP: usize = 16 * 1024;

        let old: Vec<u8> = (0..8 * GROUP).map(|i| (i * 11 + 1) as u8).collect();
        let mut new = old.clone();
        new[3 * GROUP..4 * GROUP].fill(0xa5);
        std::fs::write(&target, &old).unwrap();
        let root = node.store().ingest_bytes(&new, now_ns()).unwrap();

        // Everything but group three is already right on the disk.
        let keep = ChunkRanges::single(0, 8).difference(&ChunkRanges::single(3, 4));
        node.patch_blob_to_blocking(&root, new.len() as u64, &target, &keep, true)
            .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), new);
        let left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            left,
            vec!["disk.img".to_string()],
            "no staging file remains"
        );

        // A file the new version is longer than is extended, not appended to
        // twice: the clone is cut to size before anything is patched.
        let mut longer = new.clone();
        longer.extend(vec![3u8; 2 * GROUP]);
        let root = node.store().ingest_bytes(&longer, now_ns()).unwrap();
        node.patch_blob_to_blocking(&root, longer.len() as u64, &target, &keep, false)
            .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), longer);
        node.shutdown().await.unwrap();
    }

    /// A patch that dies partway leaves the target exactly as it was.
    ///
    /// The invariant §7.2 exists for, restated for the write that does not copy
    /// everything: bytes go into a staging clone, the target only changes at
    /// the rename, and a staging file that never got committed is removed
    /// rather than left lying beside the file it was going to replace.
    #[tokio::test]
    async fn a_torn_patch_leaves_the_target_untouched() {
        let (_d, node) = node().await;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("disk.img");
        let old: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        std::fs::write(&target, &old).unwrap();

        // An object this node does not hold: the patch clones the target, then
        // fails on the first read it needs out of the CAS — which is as close
        // to a crash mid-patch as a test can arrange without one.
        let absent = Hash::new(b"nobody has this");
        let err = node
            .patch_blob_to_blocking(&absent, 100_000, &target, &ChunkRanges::single(0, 2), true)
            .unwrap_err();
        assert!(err.to_string().contains("not in the local store"), "{err}");

        assert_eq!(
            std::fs::read(&target).unwrap(),
            old,
            "the target must be exactly what it was"
        );
        let left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            left,
            vec!["disk.img".to_string()],
            "the abandoned staging file went with the failure"
        );
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
