//! What the engine does with a git directory on disk (`docs/GIT.md`).
//!
//! The classifier (`synch_core::git`) is a pure function of a trie path; this
//! module is the other half — the few things a consumer looks at or does on
//! the filesystem: whether git is mid-operation in a directory, the
//! directories git needs for one to be a repository, and the first line of a
//! ref file for a report.

use std::path::Path;

/// The in-progress markers present in a git directory (`docs/GIT.md` §8.3):
/// a lock means git is running now, the rest mean a merge, rebase,
/// cherry-pick, revert or bisect is mid-way. Empty when the directory is idle
/// or does not exist.
pub(crate) fn in_progress_markers(git_dir: &Path) -> Vec<String> {
    synch_core::git::IN_PROGRESS_MARKERS
        .iter()
        .filter(|marker| git_dir.join(marker).symlink_metadata().is_ok())
        .map(|marker| marker.to_string())
        .collect()
}

/// Creates the directories git requires for `git_dir` to be a repository
/// (`docs/GIT.md` §7.1): empty directories are never published, so the first
/// write into a git directory has to make them.
pub(crate) fn ensure_required_dirs(git_dir: &Path) -> std::io::Result<()> {
    for dir in synch_core::git::REQUIRED_DIRS {
        std::fs::create_dir_all(git_dir.join(dir))?;
    }
    Ok(())
}

/// The value a loose ref file on disk holds, rendered for a report: the
/// object name, `ref: <name>` for a symbolic ref, or `None` when there is no
/// readable ref there.
pub(crate) fn ref_value(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    match synch_core::git::parse_ref(&bytes)? {
        synch_core::git::RefValue::Object(hex) => Some(hex),
        synch_core::git::RefValue::Symbolic(name) => Some(format!("ref: {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_and_required_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        assert!(in_progress_markers(&git).is_empty(), "absent is idle");
        ensure_required_dirs(&git).unwrap();
        assert!(git.join("objects").is_dir() && git.join("refs").is_dir());
        assert!(in_progress_markers(&git).is_empty());
        std::fs::write(git.join("index.lock"), b"").unwrap();
        std::fs::create_dir(git.join("rebase-merge")).unwrap();
        assert_eq!(
            in_progress_markers(&git),
            vec!["index.lock", "rebase-merge"]
        );
        std::fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        assert_eq!(
            ref_value(&git.join("HEAD")).as_deref(),
            Some("ref: refs/heads/main")
        );
        assert_eq!(ref_value(&git.join("missing")), None);
    }
}
