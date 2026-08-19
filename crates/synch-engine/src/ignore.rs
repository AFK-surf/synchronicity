//! Ignore rules for indexed spaces (§7.1).
//!
//! A `.syncignore` at the space root, plus built-in defaults. The pattern
//! language is the common gitignore subset: `*` and `?` globs, `**` for
//! any-depth, a leading `/` to anchor at the space root, a trailing `/` for
//! directories only, and a leading `!` to un-ignore.

use crate::error::{EngineError, Result};

/// The per-space ignore file name.
pub const IGNORE_FILE: &str = ".syncignore";

/// Patterns ignored regardless of configuration (§7.1).
pub const BUILTIN_DEFAULTS: &[&str] = &[
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "*.swp",
    "*.tmp",
    "*~",
    ".#*",
    "#*#",
    ".syncignore",
    // The half-written file a streamed write leaves in the space while it is
    // still arriving (§9.4). A scan that ran mid-upload would otherwise hash a
    // fragment and publish it as this node's own assertion.
    "*.synch-part",
];

/// One ignore rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    pattern: String,
    negated: bool,
    anchored: bool,
    dir_only: bool,
}

/// A compiled set of ignore rules for one space.
#[derive(Debug, Clone, Default)]
pub struct IgnoreSet {
    rules: Vec<Rule>,
}

impl IgnoreSet {
    /// The built-in defaults alone.
    pub fn builtin() -> Self {
        let mut set = IgnoreSet::default();
        set.extend(BUILTIN_DEFAULTS.iter().copied());
        set
    }

    /// The built-in defaults plus the space's `.syncignore`, if present.
    ///
    /// Absent is fine and is the common case. Present-but-unreadable is not:
    /// this used to swallow every error, so an `.syncignore` the daemon could
    /// not read — a permission change, an `EIO`, a half-written file — silently
    /// degraded the set to the builtins, and the very next scan *published*
    /// every path the operator had asked it to exclude. Exclusion is not a
    /// preference that may be dropped when convenient: the whole point of the
    /// file is that its contents leave this machine only when it says so.
    pub fn for_space(root: &std::path::Path) -> Result<Self> {
        let mut set = IgnoreSet::builtin();
        match std::fs::read_to_string(root.join(IGNORE_FILE)) {
            Ok(text) => set.extend(text.lines()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(EngineError::invalid(format!(
                    "{} exists but could not be read: {e}. Refusing to scan {} with the \
                     built-in rules alone, which would publish everything it excludes",
                    root.join(IGNORE_FILE).display(),
                    root.display()
                )))
            }
        }
        Ok(set)
    }

    /// Adds patterns, skipping blanks and `#` comments.
    pub fn extend<'a>(&mut self, lines: impl IntoIterator<Item = &'a str>) {
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (negated, rest) = match line.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, line),
            };
            let (dir_only, rest) = match rest.strip_suffix('/') {
                Some(rest) => (true, rest),
                None => (false, rest),
            };
            let (anchored, rest) = match rest.strip_prefix('/') {
                Some(rest) => (true, rest),
                None => (false, rest),
            };
            if rest.is_empty() {
                continue;
            }
            self.rules.push(Rule {
                pattern: rest.to_string(),
                negated,
                anchored,
                dir_only,
            });
        }
    }

    /// True if `path` — a normalized, `/`-separated path relative to the space
    /// root — should be skipped.
    ///
    /// Later rules win, which is what makes `!` un-ignore work.
    pub fn is_ignored(&self, path: &str, is_dir: bool) -> bool {
        let mut ignored = false;
        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                continue;
            }
            if rule.matches(path) {
                ignored = !rule.negated;
            }
        }
        ignored
    }
}

impl Rule {
    fn matches(&self, path: &str) -> bool {
        if self.anchored || self.pattern.contains('/') {
            return glob_match(&self.pattern, path);
        }
        // An unanchored pattern matches any path component sequence suffix, the
        // way gitignore matches a bare name at any depth.
        if glob_match(&self.pattern, path) {
            return true;
        }
        path.split('/').any(|part| glob_match(&self.pattern, part))
    }
}

/// Matches a glob against a whole string.
///
/// `*` matches any run of characters except `/`; `**` matches across `/`; `?`
/// matches one non-`/` character.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    matches_from(&p, 0, &t, 0)
}

fn matches_from(p: &[char], pi: usize, t: &[char], ti: usize) -> bool {
    if pi == p.len() {
        return ti == t.len();
    }
    match p[pi] {
        '*' => {
            let double = p.get(pi + 1) == Some(&'*');
            let next = if double { pi + 2 } else { pi + 1 };
            // `**/` also matches zero directories.
            if double && p.get(next) == Some(&'/') && matches_from(p, next + 1, t, ti) {
                return true;
            }
            for skip in ti..=t.len() {
                if !double && t[ti..skip].contains(&'/') {
                    break;
                }
                if matches_from(p, next, t, skip) {
                    return true;
                }
            }
            false
        }
        '?' => ti < t.len() && t[ti] != '/' && matches_from(p, pi + 1, t, ti + 1),
        c => ti < t.len() && t[ti] == c && matches_from(p, pi + 1, t, ti + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_defaults_apply() {
        let set = IgnoreSet::builtin();
        assert!(set.is_ignored(".DS_Store", false));
        assert!(set.is_ignored("photos/.DS_Store", false));
        assert!(set.is_ignored("notes.txt.swp", false));
        assert!(set.is_ignored("a/b/Thumbs.db", false));
        assert!(set.is_ignored(".syncignore", false));
        assert!(!set.is_ignored("photos/a.jpg", false));
    }

    #[test]
    fn anchored_patterns_only_match_at_the_root() {
        let mut set = IgnoreSet::default();
        set.extend(["/build"]);
        assert!(set.is_ignored("build", true));
        assert!(!set.is_ignored("src/build", true));
    }

    #[test]
    fn unanchored_patterns_match_at_any_depth() {
        let mut set = IgnoreSet::default();
        set.extend(["target"]);
        assert!(set.is_ignored("target", true));
        assert!(set.is_ignored("crates/a/target", true));
    }

    #[test]
    fn directory_only_patterns() {
        let mut set = IgnoreSet::default();
        set.extend(["cache/"]);
        assert!(set.is_ignored("cache", true));
        assert!(!set.is_ignored("cache", false));
    }

    #[test]
    fn negation_wins_when_it_comes_later() {
        let mut set = IgnoreSet::default();
        set.extend(["*.log", "!keep.log"]);
        assert!(set.is_ignored("a.log", false));
        assert!(!set.is_ignored("keep.log", false));
    }

    #[test]
    fn double_star_crosses_directories() {
        let mut set = IgnoreSet::default();
        set.extend(["/docs/**/draft.md"]);
        assert!(set.is_ignored("docs/draft.md", false));
        assert!(set.is_ignored("docs/a/b/draft.md", false));
        assert!(!set.is_ignored("other/draft.md", false));
    }

    #[test]
    fn single_star_does_not_cross_directories() {
        assert!(glob_match("a/*.txt", "a/b.txt"));
        assert!(!glob_match("a/*.txt", "a/b/c.txt"));
        assert!(glob_match("?.txt", "a.txt"));
        assert!(!glob_match("?.txt", "ab.txt"));
    }

    #[test]
    fn comments_and_blanks_are_skipped() {
        let mut set = IgnoreSet::default();
        set.extend(["", "  ", "# a comment", "real"]);
        assert!(set.is_ignored("real", false));
        assert!(!set.is_ignored("# a comment", false));
    }

    #[test]
    fn reads_a_space_ignore_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IGNORE_FILE), "*.raw\n!important.raw\n").unwrap();
        let set = IgnoreSet::for_space(dir.path()).unwrap();
        assert!(set.is_ignored("photo.raw", false));
        assert!(!set.is_ignored("important.raw", false));
        // Built-ins still apply.
        assert!(set.is_ignored(".DS_Store", false));
    }

    /// An absent ignore file is the ordinary case; an unreadable one is not.
    ///
    /// Degrading to the builtins on a read failure means the next scan
    /// publishes every path the operator excluded, which is the one outcome
    /// this file exists to prevent — so the scan is refused instead.
    #[test]
    fn an_unreadable_ignore_file_is_not_silently_ignored() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            IgnoreSet::for_space(dir.path()).is_ok(),
            "no ignore file at all is fine"
        );

        // A directory where the file should be: readable as a name, not as
        // text, on every platform this builds for.
        std::fs::create_dir(dir.path().join(IGNORE_FILE)).unwrap();
        let refused = IgnoreSet::for_space(dir.path())
            .expect_err("an ignore file that cannot be read must fail the scan");
        assert!(
            refused.to_string().contains(IGNORE_FILE),
            "the message must name the file: {refused}"
        );
    }
}
