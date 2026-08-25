//! Filesystem durability helpers shared by every crate that stages and renames
//! files: one implementation of "flush the directory entry", one spelling of a
//! staging file's uniqueness, and one write-fsync-rename-fsync ritual —
//! because the copies these replace had already begun rewording each other's
//! doc comments, and had settled on three different uniqueness guarantees.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

/// Flushes a directory's entries (a rename or create inside it) to stable
/// storage so the file is findable after a crash, not just its contents. A
/// no-op on platforms that cannot open a directory as a file.
pub fn fsync_dir(dir: &Path) {
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
}

/// Flushes the directory entry `path` hangs from. See [`fsync_dir`].
pub fn fsync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        fsync_dir(parent);
    }
}

/// A name suffix unique to this call, for a staging or temporary file:
/// `{pid}-{counter}`.
///
/// The counter is what carries the uniqueness: two concurrent writers in one
/// process must not share a staging file, or each truncates the other's
/// stream and renames a corrupt payload into place. The pid separates
/// processes sharing a directory. There is deliberately no clock in it — two
/// writes can read the same nanosecond on a coarse clock, which makes a
/// time-based name collide under exactly the concurrency it exists to
/// survive. Uniqueness holds for this process's lifetime and no further:
/// whatever a crash leaves behind is reclaimed by an age-based sweep, never
/// trusted by name.
pub fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// A temporary path beside `path`, unique to this write.
pub fn unique_temporary(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", unique_suffix()));
    path.with_file_name(name)
}

/// Renames `source` over `target`, replacing it if it exists.
///
/// `std::fs::rename` already means that on Unix; on Windows it refuses an
/// existing target, so the replacement has to be asked for by flag.
#[cfg(not(windows))]
pub fn replace_file(source: &Path, target: &Path) -> std::io::Result<()> {
    std::fs::rename(source, target)
}

/// Renames `source` over `target`, replacing it if it exists.
#[cfg(windows)]
pub fn replace_file(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target_wide: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    let moved = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    match moved {
        0 => Err(std::io::Error::last_os_error()),
        _ => Ok(()),
    }
}

/// Writes `data` over `path` atomically: a unique temporary beside it, the
/// bytes flushed through the writing handle, a rename over the target, and the
/// directory entry flushed best-effort ([`fsync_parent`]).
///
/// The `fsync` before the rename is what makes the rename meaningful: without
/// it the directory entry can reach the device before the bytes do, and a
/// crash in between leaves a file that exists and is empty. The temporary is
/// unique to this write ([`unique_suffix`]) because two saves over one file
/// are an ordinary operator mistake — a cron job that overlaps its
/// predecessor — and a shared `.tmp` name lets them rename each other's
/// partial bytes over the target, the exact accident the dance exists to
/// prevent. On any failure the temporary is removed; the copies this replaces
/// disagreed on that, and a leak nobody sweeps is the worse side to err on.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_impl(path, data, false)
}

/// [`write_atomic`], with the temporary narrowed to its owner *before* a byte
/// lands, so the content is never briefly readable wider than its final self.
/// On platforms without POSIX modes the directory's own ACL is what protects
/// it, as everywhere else in the tree.
pub fn write_atomic_owner_only(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_impl(path, data, true)
}

fn write_atomic_impl(path: &Path, data: &[u8], owner_only: bool) -> std::io::Result<()> {
    let temporary = unique_temporary(path);
    let write = || -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        if owner_only {
            restrict(&temporary)?;
        }
        file.write_all(data)?;
        file.sync_all()
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&temporary);
        return Err(e);
    }
    if let Err(e) = replace_file(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(e);
    }
    fsync_parent(path);
    Ok(())
}

/// Narrows a file to its owner.
#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two concurrent writers must never share a name; held pids make the
    /// counter the whole of that guarantee.
    #[test]
    fn suffixes_are_unique_within_the_process() {
        let a = unique_suffix();
        let b = unique_suffix();
        assert_ne!(a, b);
    }

    /// The write lands whole, replaces what was there — on every platform —
    /// and leaves no temporary behind.
    #[test]
    fn write_atomic_replaces_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("state.json")]);
    }

    /// The owner-only variant narrows the file before the bytes land, and the
    /// mode survives the rename.
    #[cfg(unix)]
    #[test]
    fn owner_only_writes_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_atomic_owner_only(&path, b"s").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
