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
    /// Absence is fine; any other read error is returned so exclusions are not
    /// silently dropped.
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
    fn single_star_does_not_cross_directories() {
        // (patterns, path, is_dir, expected): one row per pattern-semantics
        // case — `*`/`?` scope, anchoring, directory-only, negation order,
        // `**`, blanks/comments.
        let cases: &[(&[&str], &str, bool, bool)] = &[
            (&["a/*.txt"], "a/b.txt", false, true),
            (&["a/*.txt"], "a/b/c.txt", false, false),
            (&["?.txt"], "a.txt", false, true),
            (&["?.txt"], "ab.txt", false, false),
            (&["/build"], "build", true, true),
            (&["/build"], "src/build", true, false),
            (&["target"], "target", true, true),
            (&["target"], "crates/a/target", true, true),
            (&["cache/"], "cache", true, true),
            (&["cache/"], "cache", false, false),
            (&["*.log", "!keep.log"], "a.log", false, true),
            (&["*.log", "!keep.log"], "keep.log", false, false),
            (&["/docs/**/draft.md"], "docs/draft.md", false, true),
            (&["/docs/**/draft.md"], "docs/a/b/draft.md", false, true),
            (&["/docs/**/draft.md"], "other/draft.md", false, false),
            (&["", "  ", "# a comment", "real"], "real", false, true),
            (
                &["", "  ", "# a comment", "real"],
                "# a comment",
                false,
                false,
            ),
        ];
        for (patterns, path, is_dir, ignored) in cases {
            let mut set = IgnoreSet::default();
            set.extend(patterns.iter().copied());
            assert_eq!(
                set.is_ignored(path, *is_dir),
                *ignored,
                "{patterns:?} on {path}"
            );
        }
    }

    #[test]
    fn reads_a_space_ignore_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IGNORE_FILE), "*.raw\n!important.raw\n").unwrap();
        let set = IgnoreSet::for_space(dir.path()).unwrap();
        assert!(set.is_ignored("photo.raw", false));
        assert!(!set.is_ignored("important.raw", false));
        // Built-ins still compose under the space file (§2.4).
        assert!(set.is_ignored(".DS_Store", false));
        assert!(set.is_ignored("photos/.DS_Store", false));
        assert!(set.is_ignored("notes.txt.swp", false));
        assert!(set.is_ignored("a/b/Thumbs.db", false));
        assert!(set.is_ignored(".syncignore", false));
        assert!(!set.is_ignored("photos/a.jpg", false));
    }

    /// An absent ignore file is ordinary; an unreadable one refuses the scan:
    /// degrading to the builtins would publish every excluded path.
    #[test]
    fn an_unreadable_ignore_file_is_not_silently_ignored() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            IgnoreSet::for_space(dir.path()).is_ok(),
            "no ignore file at all is fine"
        );

        // A directory where the file should be: readable as a name, not as
        // text, on every platform.
        std::fs::create_dir(dir.path().join(IGNORE_FILE)).unwrap();
        let refused = IgnoreSet::for_space(dir.path())
            .expect_err("an ignore file that cannot be read must fail the scan");
        assert!(
            refused.to_string().contains(IGNORE_FILE),
            "the message must name the file: {refused}"
        );
    }
}
