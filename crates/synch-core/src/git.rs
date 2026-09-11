//! Git directories in the tree (`docs/GIT.md`).
//!
//! A git directory is several stores with different semantics sharing one
//! subtree: an object store that is a content-named *set*, a ref store whose
//! values are object names and whose deletions are updates, per-worktree
//! operation state, and files that exist only while a git process runs. The
//! classifier here says which of those a path belongs to. It is a pure function
//! of a trie path — never of what is on any node's disk — so every node derives
//! the same class from the same key, which is what lets selection
//! (`synch-store`, `unified.rs`) depend on it without giving up the invariant
//! that the same trie selects the same version everywhere.
//!
//! Nothing here reads an object, a pack or an index. The only git formats the
//! engine understands are the three trivial text shapes at the bottom of this
//! module: a loose ref, the `gitdir:` line of a `.git` file, and the markers
//! git leaves while an operation is in progress.

/// What a path inside a git directory is to the sync engine (`docs/GIT.md` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitClass {
    /// Exists only while a git process runs, or is this node's own local-only
    /// output (`refs/synch/`). Never published, never written, never swept.
    Transient,
    /// An absolute path of one machine: `objects/info/alternates`,
    /// `worktrees/<name>/gitdir`. Never published.
    MachineLocal,
    /// The `.git` *file* of a linked worktree or submodule, a pointer whose
    /// portability the scanner decides from its content.
    Pointer,
    /// A loose object, a pack or one of its companions, or an LFS object:
    /// immutable and named by its content. A set that only grows on any one
    /// machine.
    Object,
    /// Derived from the objects and validated by git: commit graphs, the
    /// multi-pack index, `objects/info/packs`.
    ObjectCache,
    /// `HEAD`, `refs/**`, `packed-refs`, `shallow`, reftables: small mutable
    /// state whose value is an object name, meaningful only once the objects
    /// it names are present, and whose deletion is an update.
    Ref,
    /// Per-worktree operation state and caches: `index`, `ORIG_HEAD`,
    /// merge/rebase/sequencer state, reflogs.
    WorktreeState,
    /// Everything else — `config`, `hooks/`, `info/`, `description` — with
    /// ordinary file semantics.
    Repository,
}

impl GitClass {
    /// The order a consumer writes classes in: repository files, then objects,
    /// then the caches derived from them, then the refs that name them, then
    /// the worktree state that describes the checked-out tree. `Transient` and
    /// `MachineLocal` are never written and sort last.
    pub fn materialize_rank(self) -> u8 {
        match self {
            GitClass::Repository | GitClass::Pointer => 0,
            GitClass::Object => 1,
            GitClass::ObjectCache => 2,
            GitClass::Ref => 3,
            GitClass::WorktreeState => 4,
            GitClass::Transient | GitClass::MachineLocal => 5,
        }
    }

    /// True for the classes a consumer never writes and a scan never publishes.
    pub fn is_excluded(self) -> bool {
        matches!(self, GitClass::Transient | GitClass::MachineLocal)
    }
}

/// A classified path inside a git directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitPath<'a> {
    /// The git directory root, as a path within the space (`src/app/.git`,
    /// `repo.git`, `src/app/.git/modules/lib`).
    pub root: &'a str,
    /// The path inside the root (`refs/heads/main`), empty for the root
    /// itself or a [`GitClass::Pointer`].
    pub inner: &'a str,
    /// What it is.
    pub class: GitClass,
}

impl GitPath<'_> {
    /// The order this path is written in relative to the rest of its git
    /// directory: the class rank first, then a within-class refinement — a
    /// `.pack` before the `.idx` that indexes it, `packed-refs` before loose
    /// refs and `HEAD` after them, `index` last of all.
    pub fn materialize_rank(&self) -> (u8, u8) {
        let sub = match self.class {
            GitClass::Object => u8::from(!self.inner.ends_with(".pack")),
            GitClass::Ref => match self.inner {
                "HEAD" => 2,
                "packed-refs" | "shallow" => 0,
                _ => 1,
            },
            GitClass::WorktreeState => u8::from(self.inner == "index"),
            _ => 0,
        };
        (self.class.materialize_rank(), sub)
    }

    /// True if this is a loose ref whose value is an object name rather than a
    /// symbolic reference, judged by the size the entry publishes: git writes
    /// `<40 hex>\n` or `<64 hex>\n`, and a symbolic ref (`ref: refs/heads/x\n`)
    /// is never one of those two lengths. `packed-refs`, `shallow` and
    /// reftables always name objects.
    ///
    /// This is what the hold rule (`docs/GIT.md` §7.2) keys on: a symbolic ref
    /// names nothing and is written at once, so a checkout is a repository git
    /// can open as soon as its refs class is reached.
    pub fn names_objects(&self, size: u64) -> bool {
        match self.class {
            GitClass::Ref => {
                let loose = self.inner == "HEAD" || self.inner.starts_with("refs/");
                !loose || size == 41 || size == 65
            }
            _ => false,
        }
    }

    /// The ref name under `refs/` this path is, if it is a loose ref there.
    pub fn loose_ref(&self) -> Option<&str> {
        match self.class {
            GitClass::Ref => self.inner.strip_prefix("refs/"),
            _ => None,
        }
    }
}

/// Classifies a normalized trie path (`docs/GIT.md` §4).
///
/// A git directory root is a component named `.git`, a non-final component
/// whose name ends in `.git` (the bare-repository convention), or
/// `modules/<name>` and `worktrees/<name>` directly under a root. The innermost
/// root wins. A final component named `.git` is the pointer file. A path
/// outside every root is `None`.
pub fn classify(path: &str) -> Option<GitPath<'_>> {
    let n = path.len();
    // Byte offsets of each component's start and end.
    let mut components: Vec<(usize, usize)> = Vec::new();
    let mut start = 0;
    for (i, byte) in path.bytes().enumerate() {
        if byte == b'/' {
            components.push((start, i));
            start = i + 1;
        }
    }
    components.push((start, n));
    let name = |i: usize| &path[components[i].0..components[i].1];
    let last = components.len() - 1;

    // `root_end` is the byte offset at which the innermost root ends.
    let mut root_end: Option<usize> = None;
    let mut i = 0;
    while i <= last {
        let component = name(i);
        match root_end {
            None => {
                if component == ".git" {
                    if i == last {
                        return Some(GitPath {
                            root: path,
                            inner: "",
                            class: GitClass::Pointer,
                        });
                    }
                    root_end = Some(components[i].1);
                } else if i < last && component.len() > 4 && component.ends_with(".git") {
                    root_end = Some(components[i].1);
                }
            }
            Some(end) => {
                // The first component inside a root may open a nested one:
                // `modules/<name>` (a submodule's git directory) or
                // `worktrees/<name>` (a linked worktree's private directory).
                let first_inside = components[i].0 == end + 1;
                if first_inside
                    && (component == "modules" || component == "worktrees")
                    && i + 2 <= last
                {
                    root_end = Some(components[i + 1].1);
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    let end = root_end?;
    let root = &path[..end];
    let inner = if end < n { &path[end + 1..] } else { "" };
    Some(GitPath {
        root,
        inner,
        class: class_of(inner),
    })
}

/// The class of a path inside a git directory. Directory paths classify as
/// the class of what they hold, so a walk can order `objects/` after `refs/`.
fn class_of(inner: &str) -> GitClass {
    let last = inner.rsplit('/').next().unwrap_or(inner);
    let starts = |prefix: &str| inner == prefix || inner.starts_with(&format!("{prefix}/"));

    // Transient first: a lock at any depth, git's temporary object and pack
    // names, the gc and fsmonitor droppings, LFS scratch, and this node's own
    // mirror refs.
    if last.ends_with(".lock")
        || inner == "gc.pid"
        || inner == "gc.log"
        || inner == "fsmonitor--daemon.ipc"
        || starts("fsmonitor--daemon")
        || starts("lfs/tmp")
        || starts("lfs/incomplete")
        || starts("refs/synch")
    {
        return GitClass::Transient;
    }
    if let Some(rest) = inner.strip_prefix("objects/") {
        let mut parts = rest.splitn(3, '/');
        let (a, b, c) = (parts.next(), parts.next(), parts.next());
        match (a, b, c) {
            (Some(a), None, None) if a.starts_with("tmp_") => return GitClass::Transient,
            (Some("pack"), Some(b), None) if b.starts_with("tmp_") || b.starts_with(".tmp-") => {
                return GitClass::Transient
            }
            (Some(a), Some(b), None) if is_hex_dir(a) && b.starts_with("tmp_obj_") => {
                return GitClass::Transient
            }
            (Some(a), Some(b), None) if is_hex_dir(a) && is_loose_object_name(b) => {
                return GitClass::Object
            }
            (Some("pack"), Some(b), None) if is_pack_file(b) => return GitClass::Object,
            (Some("pack"), Some(b), None) if b.starts_with("multi-pack-index") => {
                return GitClass::ObjectCache
            }
            (Some("info"), Some("alternates"), None) => return GitClass::MachineLocal,
            (Some("info"), Some(_), _) => return GitClass::ObjectCache,
            _ => {}
        }
    }
    if starts("objects") || starts("lfs/objects") {
        return GitClass::Object;
    }
    if inner == "gitdir" {
        // Only meaningful under `worktrees/<name>/`, which is a root of its
        // own, so `inner` is relative to it.
        return GitClass::MachineLocal;
    }
    if inner == "HEAD"
        || inner == "packed-refs"
        || inner == "shallow"
        || starts("refs")
        || starts("reftable")
    {
        return GitClass::Ref;
    }
    if inner == "index"
        || inner.starts_with("sharedindex.")
        || matches!(
            inner,
            "ORIG_HEAD"
                | "FETCH_HEAD"
                | "MERGE_HEAD"
                | "MERGE_MSG"
                | "MERGE_MODE"
                | "MERGE_RR"
                | "MERGE_AUTOSTASH"
                | "CHERRY_PICK_HEAD"
                | "REVERT_HEAD"
                | "COMMIT_EDITMSG"
                | "SQUASH_MSG"
                | "AUTO_MERGE"
                | "NOTES_MERGE_PARTIAL"
                | "NOTES_MERGE_REF"
        )
        || inner.starts_with("BISECT_")
        || starts("rebase-merge")
        || starts("rebase-apply")
        || starts("sequencer")
        || starts("logs")
        || starts("rr-cache")
    {
        return GitClass::WorktreeState;
    }
    GitClass::Repository
}

fn is_hex_dir(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_loose_object_name(name: &str) -> bool {
    (name.len() == 38 || name.len() == 62) && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_pack_file(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("pack-") else {
        return false;
    };
    let Some((hash, ext)) = rest.rsplit_once('.') else {
        return false;
    };
    !hash.is_empty()
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
        && matches!(
            ext,
            "pack" | "idx" | "rev" | "bitmap" | "keep" | "promisor" | "mtimes"
        )
}

/// The value of a loose ref file: an object name, or the ref a symbolic one
/// points at. `None` for anything that is not one line of either shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefValue {
    /// `<hex>`: the object the ref names.
    Object(String),
    /// `ref: <name>`: a symbolic reference.
    Symbolic(String),
}

/// Parses the content of a loose ref file.
pub fn parse_ref(bytes: &[u8]) -> Option<RefValue> {
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text.lines().next()?.trim_end();
    if let Some(target) = line.strip_prefix("ref: ") {
        return (!target.is_empty()).then(|| RefValue::Symbolic(target.to_string()));
    }
    let hex = line.trim();
    ((hex.len() == 40 || hex.len() == 64) && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| RefValue::Object(hex.to_string()))
}

/// The `gitdir:` target of a `.git` pointer file, or `None` if the content is
/// not one.
pub fn parse_gitdir(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text.lines().next()?;
    let target = line.strip_prefix("gitdir:")?.trim();
    (!target.is_empty()).then_some(target)
}

/// The paths inside a git directory whose presence means a git operation is
/// in progress there (`docs/GIT.md` §8.3): a lock means git is running now,
/// the rest mean a merge, rebase, cherry-pick, revert or bisect is mid-way.
pub const IN_PROGRESS_MARKERS: &[&str] = &[
    "index.lock",
    "HEAD.lock",
    "packed-refs.lock",
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "BISECT_LOG",
    "rebase-merge",
    "rebase-apply",
    "sequencer/todo",
];

/// The directories git requires for a directory to be a repository at all,
/// which a consumer creates when it first writes into a git directory: empty
/// directories are never published, and a repository with an unborn branch
/// has both of these empty.
pub const REQUIRED_DIRS: &[&str] = &["objects", "refs"];

/// The directory a checkout mirrors another origin's divergent refs under
/// (`docs/GIT.md` §7.4): `refs/synch/<origin>/<ref without refs/>`.
pub fn mirror_ref_path(origin_short: &str, ref_name: &str) -> String {
    // A ref name may not contain `:`, which a key-identified origin's short
    // form does.
    let origin: String = origin_short
        .chars()
        .map(|c| if c == ':' { '-' } else { c })
        .collect();
    format!("refs/synch/{origin}/{ref_name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(path: &str) -> Option<(&str, &str, GitClass)> {
        classify(path).map(|g| (g.root, g.inner, g.class))
    }

    #[test]
    fn roots_are_found_innermost_first() {
        assert_eq!(class("src/main.rs"), None);
        assert_eq!(class("notes.git"), None, "a file named like a bare repo");
        assert_eq!(
            class("app/.git"),
            Some(("app/.git", "", GitClass::Pointer)),
            "a final `.git` is the pointer file"
        );
        assert_eq!(
            class("app/.git/config"),
            Some(("app/.git", "config", GitClass::Repository))
        );
        assert_eq!(
            class("srv/repo.git/HEAD"),
            Some(("srv/repo.git", "HEAD", GitClass::Ref))
        );
        assert_eq!(
            class("app/.git/modules/lib/objects/ab/0123456789012345678901234567890123456789"),
            Some((
                "app/.git/modules/lib",
                "objects/ab/0123456789012345678901234567890123456789",
                GitClass::Object
            ))
        );
        assert_eq!(
            class("app/.git/modules/lib"),
            Some(("app/.git", "modules/lib", GitClass::Repository)),
            "a nested root needs something inside it"
        );
        assert_eq!(
            class("app/.git/worktrees/feature/gitdir"),
            Some((
                "app/.git/worktrees/feature",
                "gitdir",
                GitClass::MachineLocal
            ))
        );
        assert_eq!(
            class("app/.git/worktrees/feature/index"),
            Some((
                "app/.git/worktrees/feature",
                "index",
                GitClass::WorktreeState
            ))
        );
        assert_eq!(
            class("app/.git/objects"),
            Some(("app/.git", "objects", GitClass::Object)),
            "a directory classifies as what it holds"
        );
    }

    #[test]
    fn every_class_in_the_table() {
        let rows: &[(&str, GitClass)] = &[
            ("index.lock", GitClass::Transient),
            ("refs/heads/main.lock", GitClass::Transient),
            ("objects/tmp_obj_abc", GitClass::Transient),
            ("objects/ab/tmp_obj_abc", GitClass::Transient),
            ("objects/pack/tmp_pack_abc", GitClass::Transient),
            ("objects/pack/.tmp-123-pack-abc.pack", GitClass::Transient),
            ("gc.pid", GitClass::Transient),
            ("fsmonitor--daemon.ipc", GitClass::Transient),
            ("fsmonitor--daemon/cookies/x", GitClass::Transient),
            ("lfs/tmp/x", GitClass::Transient),
            ("refs/synch/nas/heads/main", GitClass::Transient),
            ("objects/info/alternates", GitClass::MachineLocal),
            (
                "objects/ab/0123456789012345678901234567890123456789",
                GitClass::Object,
            ),
            (
                "objects/ab/01234567890123456789012345678901234567890123456789012345678901",
                GitClass::Object,
            ),
            ("objects/pack/pack-0af3.pack", GitClass::Object),
            ("objects/pack/pack-0af3.idx", GitClass::Object),
            ("objects/pack/pack-0af3.keep", GitClass::Object),
            ("lfs/objects/ab/cd/abcd", GitClass::Object),
            ("objects/info/packs", GitClass::ObjectCache),
            ("objects/info/commit-graph", GitClass::ObjectCache),
            (
                "objects/info/commit-graphs/graph-1.graph",
                GitClass::ObjectCache,
            ),
            ("objects/pack/multi-pack-index", GitClass::ObjectCache),
            (
                "objects/pack/multi-pack-index-abc.bitmap",
                GitClass::ObjectCache,
            ),
            ("HEAD", GitClass::Ref),
            ("refs/heads/main", GitClass::Ref),
            ("refs/tags/v1", GitClass::Ref),
            ("packed-refs", GitClass::Ref),
            ("shallow", GitClass::Ref),
            ("reftable/tables.list", GitClass::Ref),
            ("index", GitClass::WorktreeState),
            ("sharedindex.abc", GitClass::WorktreeState),
            ("ORIG_HEAD", GitClass::WorktreeState),
            ("MERGE_HEAD", GitClass::WorktreeState),
            ("rebase-merge/todo", GitClass::WorktreeState),
            ("sequencer/todo", GitClass::WorktreeState),
            ("logs/HEAD", GitClass::WorktreeState),
            ("logs/refs/heads/main", GitClass::WorktreeState),
            ("BISECT_LOG", GitClass::WorktreeState),
            ("config", GitClass::Repository),
            ("hooks/pre-commit", GitClass::Repository),
            ("info/exclude", GitClass::Repository),
            ("description", GitClass::Repository),
            ("objects/ab/short", GitClass::Object),
        ];
        for (inner, expected) in rows {
            let path = format!("x/.git/{inner}");
            assert_eq!(classify(&path).map(|g| g.class), Some(*expected), "{inner}");
        }
    }

    #[test]
    fn ranks_order_a_git_directory_for_writing() {
        let rank = |inner: &str| {
            classify(&format!(".git/{inner}"))
                .unwrap()
                .materialize_rank()
        };
        assert!(rank("config") < rank("objects/pack/pack-a.pack"));
        assert!(rank("objects/pack/pack-a.pack") < rank("objects/pack/pack-a.idx"));
        assert!(rank("objects/pack/pack-a.idx") < rank("objects/info/commit-graph"));
        assert!(rank("objects/info/commit-graph") < rank("packed-refs"));
        assert!(rank("packed-refs") < rank("refs/heads/main"));
        assert!(rank("refs/heads/main") < rank("HEAD"));
        assert!(rank("HEAD") < rank("ORIG_HEAD"));
        assert!(rank("ORIG_HEAD") < rank("index"));
    }

    #[test]
    fn object_valued_refs_are_told_apart_by_size() {
        let names_objects = |inner: &str, size: u64| {
            classify(&format!(".git/{inner}"))
                .unwrap()
                .names_objects(size)
        };
        assert!(names_objects("refs/heads/main", 41));
        assert!(names_objects("refs/heads/main", 65));
        assert!(!names_objects("HEAD", 21), "ref: refs/heads/main");
        assert!(names_objects("HEAD", 41), "detached");
        assert!(names_objects("packed-refs", 1000));
        assert!(names_objects("shallow", 41));
        assert!(!names_objects("index", 41));
        assert_eq!(
            classify(".git/refs/heads/main").unwrap().loose_ref(),
            Some("heads/main")
        );
        assert_eq!(classify(".git/HEAD").unwrap().loose_ref(), None);
    }

    #[test]
    fn the_three_text_shapes() {
        assert_eq!(
            parse_ref(b"0123456789abcdef0123456789abcdef01234567\n"),
            Some(RefValue::Object(
                "0123456789abcdef0123456789abcdef01234567".into()
            ))
        );
        assert_eq!(
            parse_ref(b"ref: refs/heads/main\n"),
            Some(RefValue::Symbolic("refs/heads/main".into()))
        );
        assert_eq!(parse_ref(b"nonsense\n"), None);
        assert_eq!(parse_ref(b""), None);
        assert_eq!(
            parse_gitdir(b"gitdir: ../.git/modules/lib\n"),
            Some("../.git/modules/lib")
        );
        assert_eq!(parse_gitdir(b"gitdir:/abs/path"), Some("/abs/path"));
        assert_eq!(parse_gitdir(b"not a pointer"), None);
        assert_eq!(
            mirror_ref_path("key:abcdefghij", "heads/main"),
            "refs/synch/key-abcdefghij/heads/main"
        );
        assert_eq!(
            mirror_ref_path("nas@x.example", "tags/v1"),
            "refs/synch/nas@x.example/tags/v1"
        );
    }
}
