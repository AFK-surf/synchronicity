# Tree writes — an in-tree file write API for sockets

Status: **implemented**. Everything here describes the built thing: the
declaration and its arming, the `sy_put_*` writer family, the engine seam a
commit lands through, and the bounds. This document began as the proposal that
revisited the first non-goal of `docs/SOCKETS.md` §12 — *writing to the tree
from a program* — and, where the built thing settled a detail differently from
the draft, the text has been corrected to describe the built thing and says so
at that point. The worked example ships as
`crates/synch-sock/examples/drop-box.c`, compiled and run by the test suite on
every build; the end-to-end engine tests are
`crates/synch-engine/tests/tree_writes.rs`.

A **tree write** is a socket program publishing a file version into the node's
own origin trie: the same act as saving a file into a filesystem-source directory, an S3
`PutObject`, or a `synch adopt path` — a new assertion of *this node's* view, entering
through the same ingest-and-publish path they all share. The caller supplies
bytes and a verified identity. It still never supplies code, and it still never
publishes anything: the program decides what is written, and the program is the
operator's, armed and reviewed.

## 1. The non-goal, and why it is revisited

§12 rejected writes with one sentence of reasoning: "a remotely-triggered
publish path is a much larger surface than a remotely-triggered read one, and
nothing here needs it." Half of that has aged: things need it now.

- Every read-*write* service currently needs a TCP upstream. A drop-box socket,
  an inbox, a paste service, a CI-artifact intake, a metrics snapshotter — each
  is forty lines of eBPF plus an entire external server holding the state, and
  the state ends up outside the tree that this system exists to replicate,
  verify and version. The composition is exactly backwards: the fabric can move
  and keep the bytes; only the *accepting* of them is missing.
- `docs/SSH-SOCKETS.md` §7.2 ships SFTP read-only, and says why: treating an
  SFTP close as a tree commit would be an implicit mutation API. The blocker is
  not SFTP; it is that no *explicit* mutation API exists to build on. This
  design is that API, and upload support in the file-transfer engine becomes an
  ordinary follow-up on the same declared capability.

The "larger surface" half of the sentence was right, and the design takes it
seriously rather than around. What made writes larger than reads is that a read
leaks what the node already chose to hold, while a write changes what the node
*says* — it can mint versions, overwrite the node's own assertions, and stamp
`mtime_ns` values that win `newest` selection cluster-wide. Three facts bound
that surface:

1. **A write is an ordinary local publish.** It enters through the same gates
   as an S3 `PUT` (§6), publishes only this node's own origin, and cannot touch
   any other origin's assertion — single-writer tries make that structural, not
   policied. A bad write is therefore *divergence*, which the version model
   already renders visible, addressable and adoptable-over (DESIGN.md §8);
   superseded roots stay readable under ordinary retention. The blast radius of
   the worst write is "this node published something ugly", which is a state
   the cluster already knows how to display and recover from.
2. **The capability is declared in the object and approved at arm time**, like
   egress: prefix, modes, size bound, printed at the arm prompt, pinned by the
   content root (§3). And unlike the read declaration §7.6 dropped, this one is
   *enforceable*: the `sy_put_*` helpers are the only way a guest can reach the
   publish path — there is no `sy_open_root`-shaped side door to mutation — so
   the gate is a boundary, not decoration.
3. **The caller still ships bytes, not decisions.** Which paths can be written,
   under what conditions, with whose input, is the program's logic — reviewed,
   armed, and disarmed by a byte of drift like everything else in §3.

What membership grants a caller therefore grows by exactly one clause: a member
may *invoke programs the callee armed*, and such a program may, within the
prefixes its operator approved, cause the callee to publish new versions of its
own view. DESIGN.md §12 says that plainly (§9 below).

## 2. What a write is — and is not

- A committed write publishes `kind: File` under `f:<space>/<path>` in this
  node's own trie: content root and size from the staged bytes, `mtime_ns`
  stamped by the host at commit, `prev` set to the node's own previous root for
  the path. On a filesystem source the file also lands in the filesystem-source directory,
  atomically, exactly where an S3 `PUT` would put it; on an API source the
  bytes go straight to CAS and the entry is staged directly through
  `commit_api_file`.
- A delete publishes this node's own tombstone, and on a filesystem source
  removes the local file — `adopt_deletion`, verbatim. It retires *our*
  version; other origins' versions survive it, per §8 of the design.
- **`mtime_ns` is now-stamped and wins `newest`.** That is not a leak, it is
  what publishing an edit means — an honest local save claims the present
  instant too — but it belongs in the operator's face: a socket armed to
  replace paths is a socket whose writes will be selected by every `newest`
  surface in the cluster until outranked or adopted over. The arm prompt says
  so (§4).
- **Files only.** No symlinks (a peer-influenced link target materializing
  into an operator's directory is an attack surface with no matching need), no
  explicit directories (parents come into being as they do for a `PUT`: created
  on disk for filesystem sources, implicit in the trie), no mode bits in v1.
- **Never a socket.** A path that has a row in the `sockets` table — declared,
  armed or not, `--auto` or not — is not writable and not deletable through
  this API, `SY_EPERM`, checked at open and re-checked inside the commit. This
  is the rule that keeps tree-write and `--auto` composable: without it, a
  socket armed to write a prefix containing an `--auto` socket's path is remote
  code persistence in two moves (write the ELF, invoke it). With it, code
  reaches executability only over the operator's own declare-and-arm acts. A
  program also cannot *declare* sockets, delegations, or anything else: the
  API stages file entries and tombstones, nothing more.
- **Not a quota system.** What a member can cause an armed write-socket to
  publish is bounded per invocation (§8) as sanity, and unbounded across
  invocations as policy — the same trust stance as §12 of the design: abuse of
  an armed socket by a member is a membership problem, and the remedy is
  `synch trust rm` or disarming the socket.

## 3. The declaration — `sy_declare_tree_write`

Follows §7.9's JSON-declaration shape (`sy_declare_process`,
`sy_declare_file_transfer`): the capability is complete data compiled into the
object, selected at runtime by a small program-local id, and approved as a
whole at arm time.

```c
/* synchronicity.init only. A tree-write capability is an object:
 * {"id", "prefix", "allow": ["create" | "replace" | "delete"],
 *  "max_bytes"?}. */
extern sy_s64 sy_declare_tree_write(sy_s64 capability_json);
```

- `id` — nonzero u32, unique among this program's tree-write declarations,
  passed to `sy_put_open`.
- `prefix` — a normalized tree path of at most 256 bytes: `space` alone grants
  the whole space, `space/dir` grants that subtree. Matching is by path
  component, never by string prefix — `code/inbox` does not admit
  `code/inbox-evil`. There is no way to spell "every space": a prefix begins
  with a space id or the declaration is invalid. The space does not have to
  exist at arm time (an operator may arm before `source add`); a write into a
  space this node does not publish fails at open with `SY_ENOENT`.
- `allow` — every mode named must be known, as with process flags:
  - `create` — commit to a path where this node currently publishes no live
    version of its own (absent, or tombstoned by us).
  - `replace` — commit over this node's own live version.
  - `delete` — publish our tombstone (and unlink the local file on a
    filesystem source).

  `create` without `replace` is the append-only inbox, and it is why the two
  are separate: it lets an operator grant "accept new files" without granting
  "rewrite what I published". The check is a condition on the commit, taken
  inside the publish transaction (§5.3), not on the open.
- `max_bytes` — per-commit size bound. Default **16 MiB** when omitted; `0`
  means unbounded and is printed in red at the arm prompt, exactly as
  `sy_declare_egress` port `0` is. The bound exists because staged bytes cost
  the callee disk before any operator-visible record exists; modest by default,
  loud when waived.

At most **16** tree-write declarations per program, alongside the existing
per-family caps. `Declaration::validate` re-checks all of the above, and the
rendered `tree-write {json}` lines travel in `socket_arms.declared` like every
other family — **no schema change**.

The honesty note that §7.2 of the SSH document carries applies inverted here,
and is worth stating in the header: the *read* side of the tree is open (§7.6
of SOCKETS.md) and a tree-write declaration does not narrow it. What the
declaration bounds is mutation, and it bounds all of it, because the helpers
are mutation's only door.

## 4. Arming

Nothing new mechanically — the init hook already runs at `synch socket arm`,
`--review` already pins root, revision and rendered declaration — but the
prompt grows teeth for this family:

```
$ synch socket arm code/drop.sock

  program   3e0c…b551
  size      38 KB  ·  jit 197 KB  ·  sections: init, stream
  declares  name        drop-box
            tree-write  code/inbox        create           ≤ 16 MiB
            tree-write  code/inbox/tmp    create, replace, delete   UNBOUNDED
  writes win `newest`: paths this program publishes are what every
  policy-default read of them serves, cluster-wide, until adopted over.
  reviewed only — approve with `synch socket arm code/drop.sock --review 77b1…9a3`
```

Bytes drifting disarms as always; a widened prefix is a changed root is a fresh
review. `--auto` re-arms tree-write declarations like any others — the §3
warning at `synch socket declare --auto` time should name writes explicitly, since
`--auto` plus tree-write means "whatever these bytes become may publish under
this prefix without me looking". `synch socket ls -l` lists armed tree-write
lines beside egress, and every commit is logged: socket, invocation, peer
origin, target path, root, size. `synch socket ps` shows live writers per
invocation (target path, bytes staged).

## 5. The helper family — `sy_put_*`

A **writer** is a new handle kind (`Slot::Writer`), beside endpoints, objects,
cursors and JSON values in the 256-slot table. It is not an endpoint — it
carries no rings and no wire — but it holds a bounded host-side staging buffer,
so like endpoints it is counted by its own cap (§8) rather than charged to the
1 MiB footprint. Lifecycle: open → write/splice → commit (or delete) → close.
`sy_close` on an uncommitted writer aborts it: the staging file is removed and
nothing was published — the same guarantee a dropped `Adoption` gives an
interrupted `PUT` today, backed by the same orphan sweep if the daemon dies
mid-write.

```c
/* ---- writing the tree (requires an armed tree-write declaration) -------- */

/* Opens a writer on `space/path` under declared capability `id`.
 * Path must be component-wise inside the declared prefix, a normal
 * normalized file path, and not a declared socket. Synchronous, like
 * sy_open: the checks are indexed reads of local state. */
extern sy_s64 sy_put_open(sy_u32 tree_write_capability,
                          const char *path, sy_u64 path_len);

/* Appends bytes to the writer's staging. A short count is backpressure,
 * SY_EAGAIN means the buffer is full — poll for SY_POLL_OUT. */
extern sy_s64 sy_put_write(sy_s64 writer, const void *buf, sy_u64 len);

/* Moves up to `max` bytes from an endpoint's rx ring into the writer,
 * host-side — sy_splice with a writer destination, and for the same
 * reason: a drop-box that never inspects the payload has no reason to
 * lift it over the pointer cage. Same returns as sy_splice: a count,
 * 0 at the source's clean EOF, SY_EAGAIN when nothing could move. */
extern sy_s64 sy_put_splice(sy_s64 writer, sy_s64 from, sy_u64 max);

/* Commits the staged bytes as this node's own new version of the path.
 * First call dispatches and returns SY_EAGAIN; the writer becomes
 * pollable; the repeated call after SY_POLL_IN returns 0 and fills
 * `root32` with the published content root — sy_pread's repeat-the-call
 * shape. After success the writer is spent: further writes SY_ESTATE. */
extern sy_s64 sy_put_commit(sy_s64 writer, void *root32);

/* Commit only if this node's own live version of the path currently has
 * content root `expected32`; all-zero expected means "no live version of
 * ours" (create). Evaluated under the engine's tree-write commit lock,
 * immediately before the staging lands (§5.3). SY_ESTALE if the tree
 * moved: re-read and decide again. */
extern sy_s64 sy_put_commit_if(sy_s64 writer, const void *expected32,
                               void *root32);

/* Publishes this node's tombstone for the path (and removes the local
 * file on a filesystem source). Requires the `delete` mode; refuses a
 * writer that has staged bytes (SY_ESTATE). Idempotent like an S3
 * delete: a path we already do not publish live returns 0. */
extern sy_s64 sy_put_delete(sy_s64 writer);
```

Two new error codes, continuing `abi.rs`'s numbering:

```c
#define SY_ESTALE -11  /* conditional commit lost: the tree moved         */
#define SY_EIO    -12  /* staging or commit failed host-side (disk, CAS)  */
```

(`SY_ESTATE -10` already exists and covers "wrong lifecycle state": writing a
committed writer, deleting after staging bytes.)

### 5.1 Backpressure and poll semantics

`sy_put_write` and `sy_put_splice` accept into a **256 KiB** staging buffer per
writer; a background task drains it to the staging file on the blocking pool
(`spawn_blocking` from a `spawn_local` task — the PTY-write precedent), and
`Readiness::bump` re-arms the guest's poll. Writer revents:

- `SY_POLL_OUT` — room in the buffer (writing phase).
- `SY_POLL_IN` — a dispatched commit/delete finished; repeat the call for the
  result.
- `SY_POLL_ERR` — staging or commit failed; `sy_errno(writer)` says why
  (`SY_EIO`, `SY_EPERM`, `SY_ELIMIT`, `SY_ESTALE`).

Bytes accepted by `sy_put_write`/`sy_put_splice` are **progress** for the §10
idle deadline — they are I/O in exactly the sense the deadline measures — and
so is a commit completing. A writer with a commit in flight keeps
`all_quiet` false, so a program that returns while its commit is dispatched is
not mistaken for finished; the commit itself, being a transaction handed to the
blocking pool, runs to completion even if the invocation is killed — it is
atomic and its result is simply discarded.

### 5.2 The per-commit size bound

`max_bytes` is enforced as bytes enter staging: the write that would exceed it
gets `SY_ELIMIT`, before the disk holds more than the declaration allows, not
at commit when it already does.

### 5.3 What a commit is, precisely

Success means what an S3 `PutObject` response means, and a little more: the
bytes are durably staged, the entry is folded into a signed head, and the head
was flushed and pushed (`scan_publish_push` — §6). The returned root is
therefore immediately readable back through `sy_open` of the same path, and
citable to the caller. The cost is symmetric: **one commit is one head**. A
program with many files to publish per invocation should know that a burst of
commits is a burst of heads — the same cost the S3 gateway pays per `PUT`
today, and the same future batching work would fix both (§10).

`sy_put_commit_if`'s comparison is against *this node's own* live entry only —
the thing this write replaces — never against other origins' versions, which a
write cannot touch anyway. It is the read-modify-write primitive: read a path
and its root with `sy_stat`, compute, commit-if. The condition is evaluated
under the node's **tree-write commit lock**, immediately before the staging
lands, so two socket commits of one path cannot interleave the check and the
write. (An earlier draft claimed "inside the publish transaction, so there is
no window"; the built thing is the lock, and the honest statement is narrower:
the window that is closed is against *other socket writers*.) The scanner does
not take that lock — on a filesystem source the comparison checks the
published entry, not the disk, so an unscanned local edit under the target
path can be overwritten and a simultaneous local save races the commit,
exactly as either races an S3 `PUT` today. That is inherited deliberately —
the tree-adoption shelf-life guards protect a directory the *operator* edits, and
a directory the operator edits by hand is a poor candidate for a `replace`
grant, which the arm prompt is where to notice.

## 6. Where a commit lands — the engine seam

No new publish machinery. `SocketHost` (the socket runtime's only view of the
node) grows one method, `put_open`, returning a `SocketWriter` — the trait a
writer's pump task drives: chunks in order, then one commit or delete. The
runtime's half is the writer handle (`Slot::Writer`): a bounded staging
buffer the guest fills, drained by a per-writer pump task that owns the
`SocketWriter`, so closing the handle uncommitted drops it and the staging
behind it. The engine's implementation (`TreeWriter`) is a re-composition of
what the control-service `Put` handler already does, gate for gate:

- open: `ensure_adoptable` (publishable + `.syncignore`),
  `normalized_adoption_path`, the declared-socket refusal, then
  `Node::open_adoption` — filesystem sources staging beside the target with the
  parent dirfd pinned, API sources staging in the daemon's scratch, both
  behind `Adoption`'s single choke point.
- write: `Adoption::write` on the blocking pool.
- commit: under the node's tree-write lock, the condition (§5.3) and the
  socket refusal are re-checked; then `Adoption::commit` (fsync + rename);
  then API source → `commit_api_file` (CAS ingest,
  `stage_api_reference` with `prev` and the `b:` ad) plus a
  `flush_staged`, filesystem source → `scan_publish_push`. The reported root is
  taken from the staged bytes (`hash_staged`), describing what this call
  assembled rather than whatever the tree holds by the time a scan reaches
  it — the multipart completion's answer semantics.
- delete: `adopt_deletion` + `scan_publish_push`, with the same
  tombstone-record fallback `delete_object` carries.
- `ensure_publishable` is re-taken inside the commit like everywhere else on
  this path (a node in recovery refuses at open *and* at commit, `SY_EPERM`),
  because the socket worker checked it in a different task at a different time.

The daemon-side work all runs off the socket worker: the worker is a
current-thread runtime, the helper dispatches to a local task, the local task
`spawn_blocking`s the store work — the established shape for every helper that
touches disk.

## 7. A whole socket, end to end

A drop-box for a delegated space: members and delegates of `code` may deposit
files into `code/inbox/<their-origin>/`, append-only, at most one per minute.

```c
#include <synch.h>

SY_INIT_ENTRY sy_s64 declare(void) {
  sy_s64 cap = sy_json_parse(SY_STR(
      "{\"id\":1,\"prefix\":\"code/inbox\",\"allow\":[\"create\"],"
      "\"max_bytes\":16777216}"));
  if (cap < 0) return cap;
  sy_s64 rc = sy_declare_tree_write(cap);
  sy_close(cap);
  if (rc < 0) return rc;
  sy_declare_name(SY_STR("drop-box"));
  sy_declare_max_streams(8);
  return 0;
}

/* `name` comes from caller-chosen Open.meta: untrusted. One flat component,
 * no dotfiles, no controls — everything else about the path is ours. */
static int name_ok(const char *s, sy_s64 n) {
  if (n <= 0 || n > 128 || s[0] == '.') return 0;
  for (sy_s64 i = 0; i < n; i++)
    if (s[i] == '/' || s[i] < 0x20) return 0;
  return 1;
}

SY_ENTRY sy_s64 entry(void) {
  /* 1. Authorization is the handshake. Nothing here parses caller input
     to decide who may deposit. */
  if (!sy_peer_has_space(SY_STR("code"))) return -1;

  /* 2. Per-caller rate limit, keyed by device key — survives a rename. */
  sy_u8 key[32];
  sy_peer_device_key(key);
  if (sy_rate_limit(key, sizeof key, 1, 60000) < 0) return -1;

  /* 3. One validated filename out of the caller's metadata. */
  char name[129];
  sy_s64 nlen = sy_conn_meta(SY_STR("name"), name, sizeof name);
  if (nlen <= 0 || nlen >= (sy_s64)sizeof name || !name_ok(name, nlen))
    return -1;

  /* 4. The rest of the path is the handshake's, not the caller's. The
     origin helper returns the origin's full length even when the copy was
     cut to fit the buffer, so the return is checked against the window
     before it becomes an offset — and the final length against the frame. */
  char path[256];
  sy_u64 plen = 11;
  sy_memcpy(path, "code/inbox/", 11);
  sy_s64 olen = sy_peer_origin(path + plen, sizeof path - plen);
  if (olen <= 0 || (sy_u64)olen >= sizeof path - plen) return -1;
  plen += (sy_u64)olen;
  if (plen + 1 + (sy_u64)nlen > sizeof path) return -1;
  path[plen++] = '/';
  sy_memcpy(path + plen, name, (sy_u64)nlen);
  plen += (sy_u64)nlen;

  sy_s64 w = sy_put_open(1, path, plen);
  if (w < 0) return w;

  /* 5. Drain the caller into staging; the payload never enters the frame. */
  for (;;) {
    sy_s64 n = sy_put_splice(w, SY_SELF, 65536);
    if (n == 0) break; /* caller's clean EOF */
    if (n == SY_EAGAIN) {
      struct sy_pollfd fds[2] = { { SY_SELF, SY_POLL_IN, 0 },
                                  { w, SY_POLL_OUT, 0 } };
      if (sy_poll(fds, 2, -1) <= 0) return -1;
      if ((fds[0].revents | fds[1].revents) & SY_POLL_ERR) return -1;
    } else if (n < 0) {
      return n;
    }
  }

  /* 6. Commit: dispatch, poll, repeat the call for the receipt. */
  sy_u8 root[32];
  sy_s64 rc;
  while ((rc = sy_put_commit(w, root)) == SY_EAGAIN) {
    struct sy_pollfd fd = { w, SY_POLL_IN, 0 };
    if (sy_poll(&fd, 1, -1) <= 0) return -1;
  }
  if (rc < 0) return rc; /* SY_EPERM: already deposited (create-only) */

  char hex[65];
  sy_hex_encode(root, sizeof root, hex, sizeof hex, 0);
  sy_write_all(SY_SELF, hex, 64, 5000);
  return 0;
}
```

The pieces the design exists to provide are visible: a target path built from
the *handshake's* identity, caller input reduced to one validated filename, a
prefix and a mode the operator approved in advance, a size bound enforced as
bytes arrive, and a commit whose root goes back to the caller as a receipt the
caller can verify against the tree.

## 8. Limits and failure

Additions to the §10 tables of `docs/SOCKETS.md`:

| Bound | Default | Note |
| --- | --- | --- |
| Tree-write declarations per program | 16 | Like the other per-family declaration caps. |
| Open writers per invocation | 4 | Each holds a 256 KiB buffer and a staging file; counted as their own role, like endpoints, not charged to the footprint. Over: `sy_put_open` returns `SY_ELIMIT`. |
| Writer staging buffer | 256 KiB | Full buffer is backpressure: `SY_EAGAIN`, poll `SY_POLL_OUT`. |
| Bytes per commit | declared `max_bytes`, default 16 MiB | Enforced as bytes enter staging (`SY_ELIMIT`), not at commit. `0` = unbounded, printed red at arm. A splice source already at EOF reports the EOF before the bound, so a payload of exactly `max_bytes` lands. |
| Commits per invocation | 64 | Deletes included. A sanity bound on heads-per-stream, not a quota; a program that batches into fewer, larger files is the intended pressure. |

| What happens | Result |
| --- | --- |
| Open outside every declared prefix, or mode not declared | `SY_EPERM`, logged once per socket per hour, like undeclared egress. |
| Target path has a `sockets` row | `SY_EPERM`, at open and re-checked in the commit transaction. |
| Space unknown on this node | `SY_ENOENT`. |
| Path `.syncignore`d (filesystem source) | `SY_EPERM` at open — the file would be invisible to the scanner forever. Deletes skip the check, as `delete_object` does. |
| Node in recovery | `SY_EPERM` at open and again at commit. |
| `commit_if` expectation does not hold | `SY_ESTALE`; nothing published, writer still committable. `SY_EPERM` refusals from the commit's condition leave the writer usable the same way. |
| `create` commit finds our own live version | `SY_EPERM` (the mode's condition, evaluated in the transaction). |
| Staging or commit fails host-side | `SY_POLL_ERR`, `sy_errno` = `SY_EIO`; nothing published — and the failure is **sticky**: the staging may already be consumed, and retrying over unknown staging could publish an empty file, so every further call on the writer answers the same and the program opens a new writer instead. |
| Invocation ends with uncommitted writers | Staging removed, nothing published; a crash leaves orphans to the §5.4 sweep. |
| Invocation killed with a commit dispatched | The commit completes or fails atomically on its own; its result is discarded. |

## 9. What this changed in the existing design

All applied in the change that built this:

- **`docs/SOCKETS.md`** — §12 drops the first non-goal, pointing here; §7.12
  names the `sy_put_*` family and §7.9 gains `sy_declare_tree_write`; the §10
  tables gain the rows above; the `--auto` warning at `synch socket declare` names
  writes.
- **`docs/SSH-SOCKETS.md` §7.2** — the "read-only in v1" rationale gains its
  second half: upload support becomes a follow-up that commits through this
  API's engine seam under a tree-write declaration, instead of inventing
  close-as-commit.
- **`DESIGN.md` §12** — the membership-capability sentence extends: invoking an
  armed socket may, where its operator approved a tree-write prefix, cause the
  callee to publish new versions of its own view. Mitigations in place: the
  operator declared the prefix and modes, the version model scopes every write
  to the callee's own origin, and divergence remains first-class.
- **Schema** — none. Declarations render into `socket_arms.declared`; writers
  are invocation state in the registry, gone on restart like everything there.
- **ABI** — two errnos (`SY_ESTALE`, `SY_EIO`), one handle kind, six helpers,
  one declaration helper; the header/ABI/helper-table agreement tests bind them
  as usual.

## 10. Non-goals, and what comes after

Not in this design:

- **Symlinks, directories, modes, mtimes as inputs.** A write is bytes at a
  path; everything else is the host's stamp. Advisory `unix_mode` could be a
  later commit option; a program-supplied `mtime_ns` never will be — it is the
  one field that games `newest` selection.
- **Atomic multi-path commit.** One commit, one path, one version. A program
  needing "both or neither" publishes a manifest last and treats it as the
  commit point — the tree's own idiom.
- **Rename/copy helpers.** A rename is read + write + delete composed in the
  program, under the modes it declared.
- **Writes from `synchronicity.init`.** Declaration context has no endpoint
  table and no tree access, unchanged.
- **Writing other origins, other record kinds, or socket declarations.**
  Structural, not policy (§2).

Worth building next:

- **SFTP upload** on the same declared capability, through the same seam —
  unblocking `docs/SSH-SOCKETS.md` §7.2's deliberate deferral.
- **Batched publishes** — a per-invocation option to stage commits into the
  publisher's ordinary quiesce batching instead of one head per commit,
  trading read-back immediacy for head economy; shared with the S3 gateway.
- **Conditional delete** (`delete_if`), once a real program wants tombstone
  CAS semantics.
- **A commit metadata object** (JSON) if modes or content-type-style operator
  config ever earn their place — the JSON-handle convention leaves room.
