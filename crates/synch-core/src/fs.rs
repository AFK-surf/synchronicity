//! Filesystem durability helpers shared by every crate that stages and renames
//! files: one implementation of "flush the directory entry", because the copies
//! this replaces had already begun rewording each other's doc comments.

use std::path::Path;

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
