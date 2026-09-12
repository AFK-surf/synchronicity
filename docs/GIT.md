# Git repositories

Status: **implemented**. `synch-core::git` is the classifier, `synch-store`'s
`unified.rs` the selection rules, `synch-engine`'s scanner, checkout and tree
adoption the ordering, hold and guards, and `crates/synch-engine/tests/git.rs`
drives all of it against repositories made by `git` itself. Where the built
thing differs from the first draft of this design, the document says so at
that point. The document describes what the engine did with a `.git`
directory before (§1), what a git directory is to a sync engine (§2), and the
handling that makes a synced git repository a repository git can open, whose
refs never point at objects that are not there, in which no commit any member
published ever becomes unreachable, and which converges to one member's
repository whenever one member at a time is active. Section 13 is the
implementation map.

The design changes no record, no trie key, no wire message and nothing in the
Lean core. Everything it adds is interpretation: which paths the scanner
publishes, how the unified tree (DESIGN.md §8) identifies versions of a few
path shapes, and in what order a checkout or an adoption writes them. That is
where DESIGN.md §2 says the hard questions belong — "all the hard conflict
questions are pushed to the interpretation layer" — and a git directory is the
clearest case of a tree whose *semantics* are not its bytes.

## 1. Problem

Today a `.git` directory is a directory like any other. `IgnoreSet::BUILTIN_DEFAULTS`
(`crates/synch-engine/src/ignore.rs`) does not mention it, the scanner walks
it, every file in it is hashed, published, replicated, materialized by checkouts
and offered to `synch adopt tree`. That is almost right — git's own on-disk
format is unusually friendly to a file synchronizer — and wrong in the six ways
every "git over Dropbox" thread has rediscovered:

1. **Lock files travel.** `index.lock`, `HEAD.lock`, `refs/heads/main.lock`,
   `packed-refs.lock` and `config.lock` exist for milliseconds on the machine
   running git and are published if a scan catches one (the scanner tolerates
   nothing shaped like them; only `*.tmp`, `*.swp` and editor droppings are
   built in). A checkout then carries `index.lock` for as long as the
   tombstone takes to arrive, and every git command run against it fails with
   `Unable to create '.git/index.lock': File exists`.
2. **A ref can arrive before its objects.** Entries are independent: the
   checkout pass (`crates/synch-engine/src/checkout.rs`) writes paths in
   lexicographic order and holds a path back only while its *own* content is
   unfetched. `refs/heads/main` is a 41-byte file that lands at once;
   `objects/pack/pack-….pack` is the 200 MB it points into. Between the two,
   `git log` in the checkout reports `bad object`, `git status` fails, and a
   user who commits on top of that HEAD gets a repository git will refuse to
   repair.
3. **Garbage collection on one machine deletes objects on another.** `git gc`
   tombstones thousands of loose objects and publishes one pack. A checkout
   applies tombstones as removals (`checkout.rs`, `plan_pass`), so it deletes
   the loose objects the moment the head flips and has the pack only once the
   replica has fetched it. Worse, gc prunes what is unreachable *from that
   machine's refs*; a commit reachable only from another machine's local
   branch or stash is exactly what the tombstones remove there.
4. **Loose objects that differ byte-for-byte are the same object.** A loose
   object is zlib-compressed; two machines writing the same object with
   different `core.compression` produce different bytes at the same path. The
   unified tree calls that two versions and marks the path divergent
   (`crates/synch-store/src/unified.rs`, `identity_of`), and `adopt tree`
   reports every one of them as `differing`.
5. **Deletion never wins.** Under `newest` a tombstone takes only its own
   origin's version out of the running (DESIGN.md §8). For a file that is the
   right policy. For `refs/heads/feature` it means a branch deleted on one
   machine lives forever on every checkout, held up by the other machine's
   stale copy, and after `git pack-refs` on one machine every ref it packed is
   shadowed on checkouts by the other machine's older loose files.
6. **Machine-local pointers travel.** `objects/info/alternates`,
   `worktrees/<name>/gitdir` and the `.git` *file* of a linked worktree hold
   absolute paths of the machine that wrote them. Synced, they point every
   other machine at a directory it does not have.

And one that is not git-specific but git triggers reliably: git's builtin
fsmonitor daemon creates a unix socket, `.git/fsmonitor--daemon.ipc`, and a
socket anywhere in a space aborts the whole space scan
([#151](https://github.com/AFK-surf/synchronicity/issues/151)). That fix is a
precondition of this design and is not repeated here.

What is *not* a problem, and what makes the rest tractable: git never rewrites
a file in place. Objects and packs are immutable and content-named; refs,
`packed-refs`, `index` and `config` are written to a temporary file and
renamed. The scanner therefore always sees a complete file (a new inode with
a new mtime, `scanner.rs` `index_file`), and the racy-clean window it already
handles (`RACY_WINDOW_NS`) is git's own.

## 2. What a git directory is, to a sync engine

Git's directory is several stores with different semantics sharing one tree.
The design assigns every path under a git directory to one of seven classes.
Everything after this section is a statement of what each class means to the
scanner, to selection, to a checkout and to adoption.

| Class | Paths (relative to the git directory) | What it is |
|---|---|---|
| **Transient** | `**/*.lock`, `objects/tmp_*`, `objects/*/tmp_obj_*`, `objects/pack/tmp_*`, `objects/pack/.tmp-*`, `gc.pid`, `gc.log`, `fsmonitor--daemon.ipc`, `fsmonitor--daemon/**`, `lfs/tmp/**`, `lfs/incomplete/**`, `refs/synch/**` (§7.4) | Exists only while a git process runs, or is this node's own local-only output. Never published, never written, never swept. |
| **Machine-local** | `objects/info/alternates`, `worktrees/*/gitdir`, and a `.git` *file* whose `gitdir:` is absolute or leaves the space | An absolute path of one machine. Never published; the scan reports it once. |
| **Objects** | `objects/[0-9a-f][0-9a-f]/[0-9a-f]{38}` and `{62}`, `objects/pack/pack-<hex>.{pack,idx,rev,bitmap,keep,promisor,mtimes}`, `lfs/objects/**` | Immutable, named by its content. A *set* that only grows on any one machine; removal is local storage policy (`git gc`), never a sync event. |
| **Object caches** | `objects/info/packs`, `objects/info/commit-graph`, `objects/info/commit-graphs/**`, `objects/pack/multi-pack-index`, `objects/pack/multi-pack-index-*.{bitmap,rev}` | Derived from the objects; git validates them and ignores a stale one. Ordinary files written after the objects. |
| **Refs** | `HEAD`, `refs/**` (except `refs/synch/**`), `packed-refs`, `shallow`, `worktrees/*/HEAD`, `worktrees/*/refs/**`, `reftable/**` | Small mutable state whose value is an object name. Deletion is an update. Meaningful only once the objects it names are present. |
| **Worktree state** | `index`, `sharedindex.*`, `ORIG_HEAD`, `FETCH_HEAD`, `MERGE_HEAD`, `MERGE_MSG`, `MERGE_MODE`, `MERGE_RR`, `CHERRY_PICK_HEAD`, `REVERT_HEAD`, `BISECT_*`, `COMMIT_EDITMSG`, `SQUASH_MSG`, `AUTO_MERGE`, `rebase-merge/**`, `rebase-apply/**`, `sequencer/**`, `logs/**`, `rr-cache/**`, and the same names under `worktrees/*/` | Per-worktree operation state and caches. Deletion is an update. Written last, after the working tree. |
| **Repository files** | everything else: `config`, `description`, `hooks/**`, `info/**`, `branches/**`, `remotes/**`, `modules/*` (a nested git directory, classified recursively), `worktrees/*/commondir`, `worktrees/*/locked`, … | Ordinary files with ordinary semantics. |

Two of these carry the whole design. **Objects are a set**: the name is the
identity, any live copy is as good as any other, and nothing that happens on
another machine removes one here. **Refs and worktree state are state**: the
newest assertion wins *including a deletion*, and a ref is applied only once
the objects it may name are here. Everything else is what it already was.

## 3. Principles

- **Identity is git's, not the bytes'.** Two loose objects at the same path are
  one version. A ref's version is still its content root (the file is the
  object name, so that is the same thing), but a tombstone competes with live
  versions on the same footing, because to git a deleted ref *is* a value.
- **Selection reads the trie, never the disk.** `unified.rs` states the
  invariant: every node, and `repair rebuild-views` on any node, derives the
  same selection from the same trie. Every rule below that changes selection
  is a function of the trie key and the entry row alone. Whether a path is
  inside a git directory is decided from the path (§4), never from what is on
  this node's filesystem.
- **No git library, no git binary.** The engine reads three trivial text
  shapes — a loose ref (`<hex>\n` or `ref: <name>\n`), the `gitdir:` line of
  a `.git` file, and a `packed-refs` line — and treats objects, packs and the
  index as opaque bytes. It never inflates an object, never reads a pack, and
  never decides ancestry. §12 says what that rules out and why it is still
  the right cut for v1.
- **No new commands, no knobs.** The handling is unconditional for paths the
  classifier recognizes; the escape hatch is the one that already exists,
  `.git/` in `.syncignore`, which keeps repositories out of the tree
  entirely. Everything the design adds to the command surface is a report
  line or a refusal with a reason.
- **Nothing changes in the protocol or the proofs.** No record, key, message or
  Lean operation is touched. The publish that follows an adoption, the CAS
  pins and the head flip stay exactly what `docs/LEAN.md` says they are.

## 4. The classifier

`classify(path: &str) -> Option<GitPath>` is a pure function of a trie path
(the `<utf8 relative path>` of an `f:` key, DESIGN.md §4.1), returning the git
directory it belongs to, the path inside it, and the class from §2. It lives
in `synch-core` beside path normalization, because `synch-store` (selection),
`synch-engine` (scanner, checkout, adoption) and `synch-cli` (rendering) all
need the same answer.

A **git directory root** is any of:

- a path component named exactly `.git`, when it is a directory (the classifier
  cannot tell; the scanner and the materializer both know, and a `.git`
  *file* is handled in §5.2);
- a non-final component whose name ends in `.git` — the universal convention
  for bare repositories (`repo.git/`);
- `modules/<name>` directly under a git directory root — a submodule's
  git directory, classified recursively (`modules/<name>/objects/…` is an
  object of that inner repository). A submodule's name may contain slashes
  (`git submodule add ../lib lib/foo` names it `lib/foo`), so the root runs
  until the first component that is a name git keeps at the top of a git
  directory (`objects`, `refs`, `HEAD`, `config`, …);
- `worktrees/<name>` directly under a git directory root — a linked
  worktree's private directory, which holds refs and worktree state but no
  objects.

The innermost root wins. A path outside every root is `None`, and every rule
in this document then leaves it alone. Class patterns are the ones in the §2
table, matched against the path inside the root; `**/*.lock` is the only
pattern that matches at any depth, which is where git creates locks.

A space *rooted at* a bare repository (`synch source add repo /srv/repo.git`)
has no component the classifier can see, and is unsupported in v1: publish the
parent directory instead. Recording "this space is a git directory" per space
would have to travel in the trie (a `SpaceInfo` field) to keep selection
deterministic across nodes, and that is a record change this design does not
make.

## 5. Publishing

### 5.1 The walk

The scanner (`scanner.rs`, `walk`) already consults `IgnoreSet::is_ignored`
per entry. Beside it, it consults the classifier:

- **Transient** paths are skipped like ignored ones and counted in
  `report.ignored`. `Node::refuse_if_ignored` (the write-side mirror the
  adoption paths take) refuses them for the same reason it refuses `.syncignore`
  matches: a path that would be published never and swept never is not a
  path a write should land on.
- **Machine-local** paths are skipped and *named* in `report.skipped` with a
  reason, once per scan, because unlike a lock file the user may need to know:
  a repository whose `objects/info/alternates` is not synced is a repository
  whose objects are not all here (§11).
- Inside a git directory the walk **visits classes in reverse dependency
  order**: refs and worktree state first, repository files, object caches,
  objects last. `walk` sorts a directory's entries by name today; inside a git
  directory it sorts by `(class rank, name)`. The point is the scan-time
  ordering invariant:

  > Git writes an object before the ref that names it. A walk that reads
  > refs before objects therefore captures, in the same scan, every object a
  > captured ref value needs — an object written before the ref was read is
  > still there when the walk reaches `objects/`.

  With name order (`HEAD` < `objects` < `refs`) a commit landing during the
  walk can put the ref in head *N* and its objects in head *N+1*, and every
  checkout serves a dangling ref until the next scan. The class order closes
  that at the source; §7.2 closes what remains on the consumer.

  The order is a statement about the value a ref had *when the walk passed
  it*, and the walk only discovers: the bytes are ingested after the whole
  walk. A commit landing in between would put a newer value in the file
  than the walk vouched for. So the walk records each ref file's `(size,
  mtime, inode)`, and a ref whose stat has moved by the time it is ingested
  is skipped for that scan — the previously published value stands, the
  path is exempt from the deletion sweep like any skipped one, and the
  rescan the watcher already owes for that write publishes the ref and its
  objects together. The stat is taken on both sides of the read, because
  the read opens the path by name again; git replaces a ref by rename and
  never reuses an inode, so a path showing the walk's stat before and
  after the read pointed at that inode throughout.

Nothing else changes in the walk. Objects arrive as ordinary files, are hashed
with BLAKE3 and land in the CAS (loose objects are almost always under
`INLINE_BLOB_MAX` and are stored inline in SQLite rather than as CAS files);
a `.pack` is an ordinary large file and benefits from nothing here, since it
is never modified in place and has no `prev` to delta against.

### 5.2 The `.git` file

A `.git` that is a regular file contains one line, `gitdir: <path>`. A
submodule's reads `gitdir: ../.git/modules/name` and is portable; a linked
worktree's reads `gitdir: /home/me/repo/.git/worktrees/name` and is not. The
scanner reads the line (the file is tens of bytes) and publishes the file only
when the target is relative and, resolved against the file's own directory,
stays inside the space root. Otherwise it is machine-local: skipped, named in
the report with the target, and left for `git worktree repair` on the other
side (§10.5). The `gitdir` file *inside* `worktrees/<name>/` is the reverse
pointer and always absolute, hence always machine-local.

### 5.3 Cost

A loose object is one trie leaf, one `local_files` row and one inline blob;
a repository with 50 000 loose objects is a 50 000-entry space. That is the
same cost as 50 000 small files, and the same remedy: git's own auto-gc packs
loose objects at `gc.auto` (6 700 by default), so a repository that is used
normally stays small. The one thing worth knowing is that a `git gc` costs one
head carrying a few thousand tombstones and one pack — and, because objects
are a set (§6.1), the tombstones cost peers nothing but 90 days of a row each
(`tombstone_ttl`).

## 6. Selection

`VersionSet::from_entries` (`crates/synch-store/src/unified.rs`) folds entries
into versions by `identity_of(kind, content, symlink_target)` and orders them
by `entry_key = (mtime_ns.min(now), content, target, origin)`. Two classes get
a different identity or a different order; nothing else is touched, and both
are functions of the row and the key, so the determinism invariant the module
states holds unchanged.

### 6.1 Objects: the name is the identity

For a path in the **Objects** class, `identity_of` returns `(kind, None, None)`
for every live entry: all live copies collapse into one version whose
attestors are every origin publishing the path, and a tombstone is simply not
counted — it is neither a version nor a reason to mark anything. Consequences:

- An object path is never divergent. `synch ls` never marks it, `strict` never
  refuses it, `adopt tree` never lists it as `differing`.
- `Selection::Selected` still names one concrete entry — the greatest by
  `entry_key` among the live ones — and that is the copy whose bytes a
  checkout fetches and writes. Any is fine; determinism only needs it to be
  the same one everywhere.
- A path every publisher has tombstoned is `Absent`, exactly as today. What
  differs is what a consumer *does* with `Absent` for this class (§7.3): nothing.

The equivalence is a claim about git, so it is worth stating precisely: a
loose object's path is the hash of its inflated content, and a pack's name is
the checksum of the pack itself, so two live files at one object path decode
to the same object or one of them is corrupt — and git verifies the hash on
every read, so a corrupt copy fails loudly on the machine that has it and
never masquerades as the object. A pack's companions (`.idx`, `.rev`,
`.bitmap`) are derived from the pack and carry the pack's checksum in their
own name; the same argument covers them.

### 6.2 Refs and worktree state: deletion is an update

For a path in the **Refs** or **Worktree state** class, `Newest` and `Strict`
select the maximum of `entry_key` over **all** entries, tombstones included,
rather than over live entries only. The order is the same; the filter is
gone. A selected tombstone means the path is deleted, and consumers treat it
as one (§7.3, §8.2).

Why this is right for refs and wrong for files: `synch delete` on a document
is one member's decision about one member's copy, and §8 deliberately lets a
holdout keep the file alive. `git branch -d feature` is the branch being
deleted, and the other machine's copy of `refs/heads/feature` is not a
competing opinion but a stale cache. The same applies to `packed-refs`
shadowing: after `git pack-refs` on A, A's tombstones for the loose refs are
newer than B's loose copies, so the checkout removes the loose files and A's
`packed-refs` — newest, from the same operation — supplies the values. Every
ordering of the operations comes out right: B committing later produces a
loose ref newer than the tombstone, and A committing later produces a new
loose ref newer than both.

The order is on `mtime_ns`, and a tombstone's is the moment the scanner
noticed the deletion (`docs/IMPLEMENTATION-NOTES.md`, §4.2), which is later
than the deletion by up to the watcher debounce plus a scan. A ref written on
B in that window loses to A's tombstone until B writes it again. `synch
status` still shows both (§9), and the window is seconds; §11 lists it as the
one race this design accepts rather than closes.

### 6.3 Version skew

A node running software without this section selects object paths by
`entry_key` among live entries and calls two zlib encodings divergent; it
selects refs among live entries only. Both are the *presentation* differences
§8 already tolerates between nodes that hold different heads: no assertion
changes, and nothing is written into anyone's trie. The stated determinism
invariant is "from the same trie, the same selection", and it is a statement
about one software version; DESIGN.md makes no promise across versions and
this design adds none.

## 7. Materialization

A checkout is a read-only projection of a replica (`docs/DELTA-SYNC.md`
§3.5, `checkout.rs`). Its pass plans in listing order, writes each ready path
independently, and sweeps whatever the listing did not name. The design adds
ordering, a hold rule, and two exemptions.

### 7.1 Order

Phase 2 writes paths *outside* every git directory first, in listing order as
today. Then, per git directory, it writes classes in dependency order:

1. repository files;
2. objects — every `.pack` before its companions, so an `.idx` never exists
   without the pack it indexes (git sees a pack only through its `.idx`, and
   an `.idx` whose `.pack` is missing is an error; the reverse is invisible);
3. object caches;
4. refs — `packed-refs` and `shallow`, then `refs/**`, then `HEAD`;
5. worktree state — `index` last of all.

Worktree state after the repository's working tree is what makes a checkout's
`git status` come out clean once a pass completes: `index` describes the
working tree, and the working tree is the rest of the space.

The first write into a git directory also creates `objects/` and `refs/` as
directories. Empty directories are never published (the scanner emits no
`EntryKind::Dir`), and git's test for "is a repository" is `HEAD` plus those
two directories; a repository with an unborn branch has both empty.

### 7.2 The hold rule

A path in the **Refs** class whose content is an object name — a loose ref
holding `<hex>`, `packed-refs`, `shallow`, a detached `HEAD` — is written only
when, **for at least one attestor of the selected version, every path in that
attestor's Objects class for this git directory is on disk**. A symbolic ref
(`ref: refs/heads/main`) names nothing and is never held; HEAD is almost
always symbolic, so a checkout is a repository git can open as soon as the
refs class is reached. A held path is reported the way an unfetched one
already is — `skipped` with a reason, `"objects of this ref's publisher are
still being acquired"` — and retried next pass.

Why "every object of one attestor", not "the object the ref names": the ref's
target is the tip; `git log` needs its ancestors, `git status` needs its tree.
Checking the closure means reading commits and trees out of packs, which §3
rules out. What the engine *can* know is that the attestor wrote every object
the ref needs before it wrote the ref (§5.1 made that true at scan
granularity too), so "all of this attestor's objects are here" implies "the
closure is here" for any ref that attestor published — including a ref
published long ago whose loose objects have since been packed, because the
pack is one of that attestor's objects and the rule waits for it. A weaker
rule keyed on `seq` was considered and fails exactly that case: the ref's seq
is old, the pack's is new, and nothing ties them.

The rule is per pass and cheap: one set of "object paths not on disk, by
origin" for the git directory, computed from the same listing the plan reads.
In steady state objects are small, fetched within a pass or two, and a ref
lags them by that; during an initial replication of a large repository the
refs land last, which is the point.

Whether a ref names objects is judged from the size the entry publishes,
never from its bytes: git writes a loose object-valued ref as exactly 41 or
65 bytes, and a symbolic ref is never either length. `packed-refs`, `shallow`
and `reftable/**` always name objects and are always held — the first draft
of this design gave reftables the order without the hold, on the assumption
that the hold needed to parse the ref; it does not, so they get both.

### 7.3 What is never removed

Two exemptions from the removals the pass performs today:

- **Objects.** A tombstone or `Absent` for an Objects-class path removes
  nothing, and the phase-3 sweep skips Objects-class paths. A checkout's
  object store only grows, until someone runs `git gc` *in* it — and gc there
  is safe, because it removes only what that repository's own refs no longer
  reach, and every ref any member published is a ref there (§7.4). An object
  gc removes while some origin still publishes it comes back next pass; that
  is churn, not harm, and stops when the origins pack it too.
- **Transient.** The sweep skips Transient-class paths. A user running git in
  a checkout creates `index.lock`; the pass must not race git for it. This is
  also what makes §7.4's local-only refs survive the sweep.

For a **Refs** or **Worktree state** path, a selected tombstone (§6.2) removes
the file, as any tombstone does today.

### 7.4 Divergent refs are refs

Git resolves a ref from two places, a loose file first and `packed-refs`
second, and the checkout's two come from whichever origins `newest` picked
for each path. So what git resolves in the checkout can differ from what an
origin resolves in its own repository even when no path is divergent: one
origin's packed `main` is hidden by another's loose one. The mirrors are
therefore computed on *effective* refs, once the pass has seen the whole
listing. For every origin, its live loose refs over the entries of its live
`packed-refs`; for the checkout, the selected loose refs over the selected
`packed-refs`. Every origin ref whose value the checkout does not resolve to
is written at `refs/synch/<origin>/<name without refs/>` —
`refs/synch/nas/heads/main` for `nas`'s `refs/heads/main`, named by the
origin's short form (`OriginId::short`) — holding that origin's value: the
loose ref's bytes, or `<hex>\n` for a packed entry, from the bytes the
replica holds. The names are a peer's, and one git would refuse is refused
before it becomes a path. This holds when the selected version is a
deletion too: the branch is gone from
`refs/heads/`, and the other machine's copy of it, with whatever commits
only it had, stands under `refs/synch/` until that machine agrees. These
are Transient-class paths: never published (the scanner never sees a
checkout, and a source with the same layout ignores them), never swept, and
removed by the pass when the divergence ends.

This is the git-native rendering of the `☂n` mark. It costs a few bytes, and
it buys the guarantee in the first paragraph of this document: a commit any
member published is reachable from *some* ref in every checkout, so no
`git gc` anywhere can lose it, and `git log --all` in the checkout shows the
whole cluster's state. It also gives the operator the ordinary tools —
`git diff main synch/nas/heads/main`, `git merge` — where §8 would otherwise
offer only `adopt path`.

`HEAD` has no home under `refs/` and diverges on every pair of machines that
have different branches checked out; that divergence is expected, shown in
`synch status`, and not mirrored.

## 8. Adoption

`synch adopt tree` (`crates/synch-engine/src/adopt_tree.rs`) is additive,
writes into a filesystem source, and refuses to replace a differing local
file without `--replace`. `synch adopt path` writes one selected version.
Both keep every gate they have; the design adds class semantics to the
decisions and the same order and hold as §7.

### 8.1 Order and hold

`write_adoption` writes in the §7.1 order within each git directory. A
Refs-class path is written under the §7.2 rule. What it waits on is seeded
from the disk, once per repository and publishing origin: every object file
that origin publishes and that is not here by path. Not from what the run
plans to write — an object the plan passes over, excluded by `.syncignore`,
blocked by a directory, without a donor, or outside a narrowed prefix, is
exactly one the ref must keep waiting for — and only a successful write
releases one. An adoption of a whole repository from a fresh machine
therefore fetches the objects and then writes the refs, in one run, and an
adoption that cannot write the objects writes no ref. `adopt path` on a Refs-class path is
refused outright when the rule would hold it, with an error naming `adopt
tree` for the repository, because a source holds none of a peer's content
until something adopts it (`docs/DELTA-SYNC.md`, the retention model) and a
single ref is never the thing to adopt first.

### 8.2 Decisions by class

- **Objects.** A local file at the path means the path is current — no size
  check, no hash. It is never `differing`, and `--replace` never touches it.
  A selected tombstone or `Absent` is skipped silently, as today.
- **Refs and worktree state.** A differing local file is `differing` and
  `--replace` replaces it, as today. Two additions to the report: for a
  replaced Refs-class path the report carries the old and new value (the
  object names, read from the files), because "replaced `refs/heads/main`"
  is a sentence that should name what was there; and a *selected tombstone*
  for a path that is present locally is listed under a new `deleted` heading
  rather than skipped, since under §6.2 that is the newest state of the ref
  and `adopt path` of the tombstone is how the user applies it. Worktree
  state follows the same rule, so a deleted branch's reflog is listed beside
  the branch. `adopt tree` still never removes anything.
- **Transient and machine-local.** `refuse_if_ignored` refuses Transient;
  machine-local paths are never in the tree to adopt.
- **Repository files, object caches.** Unchanged.

### 8.3 The in-progress guard

Before writing anything into a git directory, `adopt tree` and `adopt path`
look at what is there and refuse if a git operation is in progress locally:
any `*.lock` under the directory, or `MERGE_HEAD`, `CHERRY_PICK_HEAD`,
`REVERT_HEAD`, `BISECT_LOG`, `rebase-merge/`, `rebase-apply/` or
`sequencer/todo`. The refusal names what it found. A lock means git is running
now and a write under it is a race git will lose; the state files mean a
human is mid-merge or mid-rebase, and replacing `index`, `HEAD` or `ORIG_HEAD`
under them is how a rebase gets finished against the wrong base. `--replace`
does not override the guard; finishing or aborting the operation does. The
guard reads the *local* directory only: adopting another member's mid-merge
state onto an idle repository is legitimate and is how a merge is carried to
another machine. Two things it does not gate: a `--dry-run`, which writes
nothing, and the adoption of a *deletion*, which is idempotent, is how a
stray file gets cleaned up, and is the path an S3 `DELETE` takes.

This is the one place the design touches the working copy's staged changes.
`index` is worktree state, `--replace` replaces it, and staged-but-uncommitted
changes on the adopting machine live only there. They are an in-progress edit
in every sense §7.2 of DESIGN.md already refuses to clobber — except that the
existing guard fires only when the *selected version is this node's own*.
The guard above fires on evidence of an operation; a plain `git add` leaves
none. The report therefore names `index` under `replaced` whenever it is,
and the CLI prints the same line git would: staged changes on this machine
were replaced by `<origin>`'s index, and `git reflog`/`git fsck --lost-found`
recover the blobs, which are objects and were not removed.

## 9. Status and reporting

- `synch ls` and `synch status` render Objects-class paths as unanimous
  (§6.1) and a Refs-class set with its tombstone in the running (§6.2), with
  no change to the renderer: both follow from the version set. Rendering a
  ref version by the object name it holds rather than by its content root
  was in the first draft and is not built: it needs the blob's bytes in the
  renderer, and `synch status` reads rows. The tree adoption report names
  ref values instead (§8.2), where the bytes are on disk.
- Scan reports name machine-local paths with their reason (§5.1) and, once
  per repository, an `objects/info/alternates` (§11).
- Checkout reports name held refs with the §7.2 reason and the `refs/synch/`
  mirrors they wrote.
- Adoption reports carry `deleted` and the replaced-ref values (§8.2) and the
  in-progress refusal (§8.3).
- `synch doctor` gains nothing. It has no divergence slot today, and per-path
  state is `synch status`'s job.

## 10. Worked flows

### 10.1 One writer at a time

Laptop and desktop both hold `~/src/app` as filesystem sources of the space
`app`; a NAS runs a replica with `--checkout`. The user commits on the laptop:
git writes objects, then `refs/heads/main`, then `index`. The watcher hints,
the scan walks refs before objects (§5.1) and publishes one head. The NAS
flips the head, fetches the objects (small, one pass), writes them, and on the
next pass writes `main` and `index` (§7.2). At the desktop the user runs
`synch adopt tree app --replace`: objects are written first, the ref and index
after, and `git status` is clean. The desktop's `refs/heads/main` was behind
the laptop's, `newest` picked the laptop's, and nothing was lost because
nothing was competing.

### 10.2 Concurrent commits

Both machines commit on `main` from the same base. Each publishes its own
`refs/heads/main`; the path is divergent (two versions, one attestor each).
The NAS checkout writes the newer as `main` and the other as
`refs/synch/<origin>/heads/main` (§7.4); `git log --all` there shows both
lines, and neither commit can be gc'd anywhere. On either source `synch
status` shows both values by object name. The user resolves it with git —
merge or rebase on one machine, which produces a `main` newer than both —
and the next adoption on the other machine carries it. `adopt tree --replace`
before that would move that machine's `main` to the other's commit and say
so, naming the old value; the old commit stays in `objects/` (never removed)
and in that machine's own reflog, which `logs/` under `--replace` would also
replace, so the report line is the record.

### 10.3 `git gc` on one machine

The laptop runs `git gc`: one head carries a new pack, tombstones for the
loose objects it absorbed, a new `packed-refs`, and tombstones for the loose
refs it packed. On the NAS, the tombstones for objects do nothing (§7.3), the
pack is fetched and written, the refs class then applies: the loose-ref
tombstones win over the desktop's older loose copies (§6.2), the files go, and
`packed-refs` supplies the values. On the desktop nothing happens until the
user adopts; `adopt tree` writes the pack, never removes the loose objects
(the desktop's own `git gc` will), and lists the packed refs under `deleted`.
The desktop's objects that the laptop never had — a local branch's commits —
were never in the laptop's tombstones, because the laptop never published
them.

### 10.4 Deleting a branch

`git branch -d feature` on the laptop tombstones `refs/heads/feature`. Under
§6.2 the tombstone is the newest version; the NAS removes the file and keeps
the desktop's copy as `refs/synch/<desktop>/heads/feature` (§7.4) until the
desktop agrees, the desktop's `adopt tree` lists it under `deleted`, and
`synch adopt path app/.git/refs/heads/feature` there applies it. The
desktop's copy was a stale cache, not a competing opinion, which is the
whole difference between this class and a document — and the mirror is
what keeps that judgement from ever costing a commit.

### 10.5 A fresh machine, and worktrees

A new machine adds the source and runs `synch adopt tree app`: objects first,
refs after, `index` last, and the result is a repository that `git status`
reports clean. If the laptop had a linked worktree beside the repository, the
worktree's `.git` file was machine-local and not published (§5.2); the new
machine has `.git/worktrees/<name>/` (published, minus its `gitdir`) and the
worktree's files, and `git worktree repair <path>` rewrites both pointers.

## 11. Failure modes and limits

- **The tombstone window (§6.2).** A ref written on B between A's deletion of
  it and A's scan noticing loses to A's tombstone until B writes it again.
  Seconds wide; visible in `synch status`; closed by a later write, not by
  time.
- **Closure, not tip.** §7.2 waits for all of one attestor's objects, which
  is sufficient because that attestor wrote them before the ref. It is not
  sufficient for a ref *adopted* from a peer into a source whose objects were
  then partially gc'd locally and never re-adopted — a sequence the
  in-progress guard does not see. `git fsck` is the tool for that, as it is
  for any repository.
- **By path, not by object name.** The same rule judges presence by the
  object *files* an origin publishes, because the engine reads no packs. A
  source that has repacked locally holds every object and none of the peer's
  paths, so `adopt path` of a single ref is refused there and the error says
  to adopt the repository whole; `adopt tree` then writes the peer's pack
  beside the local one, which git handles.
- **Alternates.** A repository whose `objects/info/alternates` names another
  store on the same machine has objects synchronicity never sees. The scan
  says so; `git repack -a -d` and removing the file make it self-contained.
- **A `.git` that is a symlink** is a symlink entry, never descended into: the
  repository is not synced, which is what a symlink means to the scanner
  everywhere.
- **Case-folded ref names** (`refs/heads/Feature` and `feature`) collide on
  case-insensitive filesystems; the existing `claim_folded_name` skips and
  reports the second, as it does for any path. Git has the same problem.
- **`config` is shared.** `core.filemode`, `core.ignorecase`,
  `core.symlinks` and `core.precomposeunicode` are written by `git init` for
  the machine it ran on; on a different platform they are wrong until the
  user sets them. Git tolerates every combination; the failure is cosmetic
  (spurious mode changes in `git status`). Making `config` machine-local
  would lose remotes, branch tracking and user settings, which is worse.
- **`index` in a checkout.** A user running `git status` in a checkout makes
  git rewrite `index`; the next pass rewrites it back. Harmless churn on a
  directory that is documented as a view.
- **A space rooted at a bare repository** is unsupported (§4).
- **Metadata volume.** A repository that is never gc'd is one entry per loose
  object (§5.3). Git's auto-gc keeps that bounded for any repository git is
  actually used in; a repository only ever *received* (a mirror) is the case
  to watch, and `git gc` there is the remedy.

## 12. What this deliberately does not do

- **Ancestry.** It never decides that one ref value is a fast-forward of
  another, so it cannot say "advanced" versus "diverged" and cannot
  auto-merge a fast-forward on a source. Doing so means reading commits out
  of loose objects (zlib) and packs (index, delta chains), which is a git
  library — `gix` is the honest Rust choice and is a hundred crates. The
  observable difference is small: a fast-forward is also the newest by mtime,
  so `newest` picks it; what is missing is the *word*, and the safety in
  §7.4 does not depend on it.
- **Logical refs.** It treats `packed-refs` as one file and each loose ref as
  one path, and relies on §6.2's order to make the layering come out right,
  rather than resolving each ref per origin from the union of both and
  selecting per ref. That would make selection depend on blob content, which
  every node holds only if it fetched it; §3 keeps selection on the row.
- **Merging** anything, including `packed-refs` or `index`. §8 of DESIGN.md.
- **Git LFS** beyond storing `lfs/objects/**` as objects; the LFS protocol is
  not served.
- **Submodule recursion into working trees.** A submodule's git directory is
  classified (§4); its working tree is ordinary files.

## 13. Implementation map

What landed, and where:

1. **#151** landed separately as #152: `walk`
   (`crates/synch-engine/src/scanner.rs`) pushes only regular files and
   symlinks, skipping a socket, FIFO or device with a reason, and an I/O
   failure in one path's ingest is that path's failure rather than the
   space's.
2. `crates/synch-core/src/git.rs`: `classify`, `GitClass`, `GitPath` with
   its write order and `names_objects`; `parse_ref`, `parse_gitdir`,
   `IN_PROGRESS_MARKERS`, `REQUIRED_DIRS`, `mirror_ref_path`. Unit tests over
   the §2 table, nested `modules/` and `worktrees/`, bare-repository names,
   and paths outside any root.
3. `crates/synch-engine/src/scanner.rs`: the class-aware walk (Transient
   ignored, machine-local named, `(class rank, name)` order inside a git
   directory, the `.git`-file check in `pointer_refusal`);
   `refuse_if_ignored` refusing the excluded classes; `refuse_git_adoption`,
   the single-path gates of §8.1 and §8.3, taken by `adopt_from` and
   `adopt_deletion`.
4. `crates/synch-store/src/unified.rs`: `identity_of` collapsing the Objects
   class and dropping its tombstones while a copy is live; `select` and
   `exists` ranking tombstones with live versions for Refs and Worktree
   state.
5. `crates/synch-engine/src/checkout.rs`: `plan_file` and the class-ordered
   phase 2; `GitWant` and `PendingObjects`, the hold rule, shared with tree
   adoption; `objects/` and `refs/` creation; Objects and Transient exempt
   from removal and from `sweep`; the `refs/synch/` mirrors and their
   cleanup; `held` and `mirrored` on `CheckoutReport`.
6. `crates/synch-engine/src/adopt_tree.rs`: the same order and hold;
   Objects present-means-current; `deleted` and `replaced_refs` on
   `AdoptTreeReport`; the in-progress guard in `plan_adoption`.
7. `crates/synch-engine/src/gitdir.rs`: the filesystem half — in-progress
   markers, required directories, a ref's value for a report.
8. `crates/synch-cli/src/control/server.rs`: the `deleted` and moved-ref
   lines of `adopt tree`, and `git refs held`/`mirrored` on the checkout
   line of `replica sync`.
9. `DESIGN.md` §7.1 points here.

## 14. Tests

`crates/synch-engine/tests/git.rs`, against repositories built with `git`
in the test and skipped where the binary is absent:

- A source containing a repository with a live `index.lock`, `tmp_obj_*`, a
  `fsmonitor--daemon.ipc` socket and a linked worktree publishes the
  repository and none of the transient or machine-local files; a socket
  beside the repository is skipped on its own (#151).
- With the refs' bytes acquired ahead of the objects, the symbolic `HEAD`
  lands, the branch is held, `git` sees a repository; once the objects are
  there the branch follows, `git fsck --strict` is clean and `git status` is
  empty.
- `git gc` on the publisher: the checkout keeps every loose object, gains
  the pack, drops the packed loose ref, resolves the branch through
  `packed-refs`, and stays `fsck`-clean.
- Two encodings of one loose object are one version with two attestors;
  `adopt tree` reports nothing differing.
- `git branch -D` on one source removes the ref from the checkout while the
  other source still publishes it; a ref written to a new value after the
  deletion wins it back.
- Concurrent commits: the checkout has the newer as the branch and the other
  under `refs/synch/`, both reachable, `git gc` there removes neither, and
  the mirror is swept once the sources agree.
- A fresh source adopting a whole repository ends `fsck`-clean with `git
  status` empty; `adopt path` of a ref before its objects is refused naming
  `adopt tree`; `adopt tree` into a repository mid-rebase is refused naming
  `rebase-merge/`, proceeds once it is gone, and names the moved ref's
  values.
- A branch the publisher deleted is listed under `deleted` and left on disk;
  `adopt path` of the deletion then removes it.
- A submodule named `lib/foo`: the pointer file is published and written as
  a file, the nested git directory is a repository in the checkout and in
  an adopted copy, and git resolves the submodule's HEAD in both.
- A lock an earlier release materialized goes once the tree tombstones it;
  a lock git itself left, unknown to the tree, stays.
- Two publishers that both packed their refs and diverged: the checkout
  expands the losing `packed-refs` into mirrors, both lines and the losing
  tag stay reachable, and the mirrors go once the publishers agree.
- An adoption whose `.syncignore` excludes `objects/` holds every ref that
  names objects and writes the symbolic `HEAD`; so does one where a
  directory stands at an object's path.
- A publisher that packed its refs and committed again: the mirror of its
  losing `main` is its current loose tip, not the stale packed entry, and
  the winner's own stale packed entry is not mirrored.
- A mixed layout, one publisher's `main` packed and the other's loose, with
  no path divergent: the packed tip the checkout's loose ref hides is
  mirrored, and a second pass writes nothing.
- (`scanner.rs`) A commit landing between the walk and the ingest of the ref
  it moves, and one landing between the stat and the read of the ref
  itself: the ref is skipped that scan, the earlier value's object is
  published, and the next scan publishes the ref with its objects.

`crates/synch-store/src/unified.rs` covers the selection rules on rows
alone: object identity by name, tombstones dropped while a copy is live and
kept when none is, a ref deletion outranking an older live copy and losing
to a newer one, and a document beside the repository keeping the §8 rule.
