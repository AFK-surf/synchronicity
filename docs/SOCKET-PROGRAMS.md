# Socket programs — one object, many sockets

Status: **proposed**. Nothing here is built. It amends `docs/SOCKETS.md`
§2, §3, §9, §10 and §11 and `docs/TREE-WRITES.md` §2; each place this changes
is named in §9 below. Where it repeats a rule from those documents it does so
to say the rule survives.

Today a socket *is* a file: `synch socket activate code/git.sock` says that the
bytes at `code/git.sock` are a program, and the path is at once the program's
location and the socket's name. One object serving two sockets means two copies
of the ELF at two paths, each activated, each deployed separately, and
`sy_socket_path` — which the host API grew "so one object can back several
sockets" (SOCKETS.md §7.2) — reachable only by duplicating the thing it exists
to share.

This proposal splits the two. A **program** is an ordinary file in this node's
tree holding an eBPF object. A **socket** is a name in this node's tree that an
activation binds to a program path, with its own configuration, stream cap,
map and statistics. Many sockets may name one program, across spaces, and
publishing a new object at the program path deploys all of them at once.

```
synch socket build gateway.c -o code/bin/gateway.o
synch socket activate code/git.sock  --program code/bin/gateway.o --config upstream=git.internal
synch socket activate code/hg.sock   --program code/bin/gateway.o --config upstream=hg.internal
synch socket activate docs/git.sock  --program code/bin/gateway.o --max-streams 4
```

## 1. What does not change

The rules the socket design is built on stay exactly as they are, and it is
worth listing them because every choice below is made to keep them.

- **A node executes only eBPF present in its own published tree.** The program
  path is in this node's own trie, in a space this node is a source of. A
  peer's object is not a program until it has been adopted into one.
- **Activation is a statement about paths, never about a content root.** It
  now names two paths instead of one — the socket and its program — and
  every write to the program path, through every channel SOCKETS.md §3
  enumerates, is a deployment. No root is an authorization pin.
- **The tree names what runs.** A socket path publishes `kind: Socket` with
  the content root a connection lands on, so `Opened::Ok { program }` and
  `synch ls` agree, delegation projects it by position, and a replica
  materializes the bytes.
- **Kind is local and not adoptable.** Adopting a peer's socket entry adopts
  its bytes as a file; nothing about a peer's activation reaches this node.
- **The record format is untouched.** `FileEntry` gains no field (SOCKETS.md
  §2 explains why it cannot), the wire protocol `sync/sock/1` is unchanged,
  and the guest ABI is unchanged.

## 2. The activation names a program

`socket_activations` gains the program's location:

```
socket_activations (
  space, path,                      -- the socket: what a caller connects to
  program_space, program_path,      -- the program: where the bytes live
  config, max_streams, note, activated_at,
  PRIMARY KEY (space, path)
)
```

An activation whose program is its own path — `program_space = space` and
`program_path = path` — is exactly today's socket, and is what the migration
writes for every existing row. Call it **self-backed**. An activation whose
program is elsewhere is **decoupled**. The two differ only in what the scanner
publishes at the socket path (§3); admission, the registry, the map store,
the fault window and every command treat them alike.

`SocketActivation` in `synch-store` gains `program_space` and `program_path`
and a `program_qualified()`; `is_self_backed()` is the equality test. Two
reverse lookups join the existing forward ones: `activations_backed_by(space,
path)` for the scanner and the deployment fan-out, and
`is_socket_or_program_path(space, path)` for the tree-write gate (§5).

### 2.1 What a program path may be

- **A source of this node's, in this node's own trie.** Filesystem or API:
  the program is published by whichever channel that source publishes through,
  and the derivation in §3 follows both.
- **Any space, not only the socket's.** One gateway backing `code/git.sock`
  and `docs/git.sock` is the case that motivates this document. The cost is
  stated at activation (§6): the socket entry in `docs` names the program's
  root, so readers of `docs` — its delegates included — may fetch those bytes,
  exactly as they could if the ELF were copied into `docs` today
  (`synch-net`'s `check_content_scope` grants a root to any peer whose granted
  spaces name it). Nothing new leaks; what was implicit in copying is now
  said out loud.
- **Not itself a socket path of another activation.** Programs are files and
  sockets are names; a socket whose program is another socket is a chain, and
  the design gains nothing from allowing one level of it. Refused at
  activation with the reason. A self-backed activation's program is, of
  course, its own socket path.
- **Not a path this node publishes as anything but a file.** A directory, a
  symlink or a tombstone at the program path resolves to nothing (§4) and
  `synch socket ls` says so; activation does not refuse it, because the
  program may simply not have been written yet — `activate` before the first
  deploy is the ordinary order today and stays so.

### 2.2 What a socket path may be

A decoupled socket path is **owned by its activation**. Activation refuses a
socket path at which this node publishes a live entry that is not already a
`Socket` — a real file lives there, and shadowing it silently would publish a
program where an operator had a document. Re-activating an existing
self-backed socket as decoupled is allowed: the operator is changing what
backs a name they already own, and the file that used to back it becomes
shadowed (§3.2) until removed.

The bound on activations per space (64, SOCKETS.md §10) is unchanged and
bounds how many sockets one program may back as a consequence.

## 3. What the tree publishes

This is the part that has to be right, because it is what every other node
sees.

- The **program path** publishes as it always would: `kind: File`, content
  root `R`, size, mtime. It is an ordinary file, readable by anyone who can
  read its space, materialized by replicas as a file.
- Each **socket path** bound to it publishes `kind: Socket` with the *same*
  content root `R`, size and mtime — a **derived entry**, copied from this
  node's own entry at the program path. A self-backed socket's derived entry
  is the entry at its own path with the kind rewritten, which is precisely
  what the scanner emits today.

The invariant every head this node signs must satisfy:

> For every activation, the socket path carries `kind: Socket` with the
> content root of this node's own live `File` (or self-backed `Socket`) entry
> at the program path in that same head — or a tombstone when there is none.

Peers therefore see nothing new. A `Socket` entry with a content root is what
they see today; two of them sharing a root with a `File` in the same origin is
a fact about this node's tree they need no new rule to hold. Version identity
(SOCKETS.md §11) is `(kind-class, root)`, so the socket entries at
`nas:code/git.sock` and `nas:docs/git.sock` are the same version of two
different paths, and `nas:code/bin/gateway.o` is a `File`-class version of a
third — no path's identity depends on another's.

### 3.1 Who derives, and when

Derivation is a function of the activation table and this node's own
entries, and it is staged **in the same batch** as the change that moves the
program, so a deployment is one signed head: no head ever names a program root
at a socket path that the program path does not also carry.

Every channel that publishes a file into this node's own trie goes through one
of two places, and both learn about programs:

- **The scanner** (`index_file`), for filesystem sources — an editor save, an
  adoption, an S3 `PUT`, a committed tree write, `synch put`. Where today it
  asks `is_activated_socket(space, rel)` to choose the kind, it asks
  `activations_backed_by(space, rel)`: the self-backed one, if any, is
  published as `Socket` at this path; every decoupled one stages a derived
  `Socket` entry at its socket path with this file's content, in the same
  `ScanReport`. The lookup is loaded once per scan, not once per file: the
  table is small by its own bound, and the scanner already pays one query per
  file for the kind.
- **The deletion sweep**, for the same sources. A program path that vanished
  tombstones itself as today *and* each decoupled socket it backed: the
  object is gone, and a socket with nothing behind it must not keep serving
  the last root out of the CAS. The sweep also **exempts** decoupled socket
  paths from being swept as vanished files — they never were files — which is
  the one place the scanner learns that a published path can be owned by
  something other than the disk.
- **`commit_api_file`**, for API sources: the same fan-out, staged beside the
  committed entry.
- **Activation and deactivation** stage their own change immediately.
  Activating a decoupled socket stages the derived entry from the program
  path's current published entry, if there is one, so `synch socket ls` shows
  the socket live without waiting for a scan of a space whose files did not
  change. Deactivating a decoupled socket stages a tombstone at the socket
  path; deactivating a self-backed one invalidates the scanner row so the
  next scan republishes the file, as today.

The `synch source scan` a fresh activation prints as its next step stays
right for the self-backed case and becomes optional for the decoupled one.

### 3.2 A file where a decoupled socket is

If a file appears on disk at a decoupled socket path — a stray copy, an
adoption aimed at the wrong name — the scanner neither publishes it nor
tombstones the socket. The path is reported in the scan's `skipped` list as
*shadowed by socket activation*, `synch socket ls` prints the same, and the
derived entry stands. The alternative, letting a file at the name quietly
become self-backed, would make "what runs here?" depend on whether a copy
happened to land, which is the ambiguity this design removes.

## 4. Resolution and admission

`resolve_socket(space, path)` reads the activation and **the socket entry**,
as it does now: kind `Socket`, content root `R`. The derived entry is the
serving truth, and §3.1 is what keeps it equal to the program path's. Reading
the program path instead would make the socket entry decorative — published
but not what a connection lands on — and would give up the property that the
tree names what runs.

Everything downstream is unchanged and shares better than it did:

- The program-bytes cache and each worker's JIT cache are keyed by root
  (SOCKETS.md §5.1), so *N* sockets on one object cost one CAS read and one
  compile per worker, not *N*.
- The registry, the per-socket concurrency cap, the fault window and the map
  are keyed by the socket's qualified path, so two sockets on one program are
  as separate as two sockets on two programs: a limit on `git.sock` says
  nothing about `hg.sock`, and a session table `git.sock` minted is not visible
  to `hg.sock`.
- The effective policy is the manifest's declaration (from `R`, the same for
  every socket it backs) capped by *this* activation's `max_streams` and
  carrying *this* activation's `config` — which is what lets one gateway
  object serve two upstreams from two `--config upstream=` lines.
- `sy_socket_path` returns the socket's own `space/path`, which is what
  distinguishes the sockets inside the program. `sy_stat(sy_open(...))` on it
  reports `R`. No helper is added.

**Deployment** is the moment the derived entries land: the next admission on
every socket the program backs runs the new root, in-flight invocations keep
their snapshot, and `socket_content_deployed` clears each socket's map and
logs one line per socket naming the program path and the sockets it moved.
The mid-admission re-check (`current.root != checked_root` →
`Refused{NotActivated}`) needs no change: the socket entry is what it reads.

## 5. Program paths are never writable through a program

`docs/TREE-WRITES.md` §2 states the rule that keeps tree-write grants and
activation composable: an activated path is never writable through the
`sy_put_*` family or a writable SFTP handle, because otherwise a program with a
grant over a prefix containing a socket is remote code persistence in two
moves — write the ELF, invoke it. With decoupling the ELF lives at the program
path, so the rule has to cover both:

> A path that is the socket path **or the program path** of any activation is
> refused by `refuse_socket_path`, at writer open and again under the
> tree-write lock at commit and delete.

This is the one security change in the proposal and it is a widening of a
refusal, not a new mechanism. `is_socket_or_program_path` is the store query.
`synch adopt path`, `synch put` and an S3 `PUT` onto a program path remain
what they are today for a socket path: sanctioned deployment channels the
operator accepted when activating, now stated for the program path at
activation (§6).

Reading a program path is unrestricted, as reading a socket path is
(SOCKETS.md §7.6): the bytes are not secret, and what executes is decided by
the activation table. The SFTP backend's `entry_kind` keeps refusing to read
a *socket* path — a socket does not read out its neighbours' code — and
serves a program path as the file it is; a program that wants to hand out its
own bytes can already do so by root.

## 6. Command surface

```
synch socket activate <space>/<path>                  make the path a socket until
        [--program <space>/<path>]                    deactivated, backed by the
        [--config k=v]… [--max-streams <n>]           program at --program, or by
        [--note <text>]                               its own bytes without it
synch socket deactivate <space>/<path>                as today; a decoupled socket
                                                      tombstones, a self-backed one
                                                      republishes as a file
synch socket ls [<space>] [-l]                        gains a program column; -l
                                                      lists the other sockets the
                                                      same program backs
```

`--program` takes a fully qualified `<space>/<path>`, never a path relative to
the socket's space: `code/bin/x.o` must not read as "path `code/bin/x.o` in
`docs`" on one line and "path `bin/x.o` in `code`" on the next, and every
other command already spells a location this way.

`activate` prints the grant it is making, and now names the program path,
because that is where the writes that deploy land:

```
$ synch socket activate docs/git.sock --program code/bin/gateway.o
activated docs/git.sock ← code/bin/gateway.o
every write to code/bin/gateway.o is a deployment to: code/git.sock, code/hg.sock, docs/git.sock
that includes adoption, S3 writes and `synch put` — activate only programs whose every writer you mean as a deployer
this publishes the program's bytes into `docs`: whoever may read docs may read them
```

The last line appears only when the program is in another space (§2.1). The
list of dependents is the point of printing it: the third activation of a
program is the moment its blast radius became three sockets, and the operator
should see that where they asked for it.

`ls -l` shows, per socket, the program path, the root the tree currently
names, the declaration from that root's manifest, the activation's policy —
and, when the derived entry and the program entry disagree (a publish in
flight, or a shadowed file), says so as `stale` with both roots, so the one
state §3.1 is designed to make brief is visible if it ever lasts.

`synch socket inspect` is untouched: stateless, one file, no table.

### 6.1 Control protocol and MCP

`SocketActivate` gains a `program` string (empty means self-backed);
`SocketLs`'s rendering carries the program. Adding a field is wire-compatible
in proto3, and that is exactly the problem: a client that sends `--program`
to a daemon that ignores the field gets a self-backed activation of a path
with nothing at it, and no error. `CONTROL_VERSION` goes to 6 so the two
refuse each other, per the rule its comment already states. The
`synch_socket_activate` MCP tool gains `program`; `synch_socket_ls` output
gains the column.

## 7. Failure and limits

| What happens | Result |
| --- | --- |
| Program path has no live file entry | Every socket it backs resolves to nothing and refuses as a self-backed socket whose file was removed does today — `Refused{NotASocket}` against the tombstone, or `NoSuchPath` when nothing was ever published — and `ls` shows `unpublished`. Deploying the object is the remedy. |
| Program path's content is not a valid program | As today, per socket: activated, published, every connection `Refused{ProgramInvalid}` naming the defect. One bad deploy is *N* unavailable sockets, and `ls` shows all of them with the same reason. |
| Program replaced | One head; every dependent socket serves the new root from its next admission; every dependent map clears; one log line per socket. |
| Program path removed from disk | Tombstoned, and every decoupled socket it backs is tombstoned in the same head. Re-creating the file republishes all of them. |
| A file appears at a decoupled socket path | Neither published nor swept; reported as shadowed (§3.2). |
| `--program` names a socket path of another activation | Refused at activation. |
| Socket path already holds a non-socket file | Refused at activation. |
| Space of the socket or of the program removed | `remove_source` already deletes the space's activations; it now also deletes activations whose *program* is in that space, and the sweep of the removed space tombstones what they published. |
| Tree write or SFTP write to a program path | `SY_EPERM` / `HostError::Denied`, at open and at commit (§5). |
| Activations per space | 64, unchanged. Also the bound on sockets per program. |

## 8. Alternatives considered

- **A symlink at the socket path, resolved by activation.** `ln -s
  bin/gateway.o git.sock; synch socket activate code/git.sock`. Cute, and
  wrong for three reasons: it does not exist on API sources or for the S3 and
  `synch put` writers that write files; it is a Windows portability problem
  the tree model has otherwise stayed clear of; and the sentence the
  activation prints — *every write to this path is a deployment* — stops
  being true of the path, since the writes that deploy go to the target.
- **Naming the program by content root.** `--program-root <hex>` would make
  a socket serve exactly one object until re-activated. It is the pin the
  design refuses: deployments are path-based so that the operator's tools —
  an editor, adoption, S3 — deploy without a second command, and SOCKETS.md
  §3 spent its argument on that.
- **A socket entry with no content, naming the program in
  `symlink_target`.** Keeps the socket path from duplicating the root, and
  breaks everything that reads the root: `has_content`, materialization,
  `synch cat`, a delegate's blob scope for a program in another space, and the
  audit that the tree names what runs. Every reader of the tree would need a
  new rule; under the derived entry none does.
- **No entry at the socket path at all** — the activation table alone. The
  socket resolves but is undiscoverable: `synch ls` cannot mark it,
  delegation cannot project it, and `Opened::Ok { program }` has nothing in the
  tree to be checked against.

## 9. What this changes in the existing documents

- **SOCKETS.md §2.** A socket entry's content root is the program's; the
  program may live at another path.
- **SOCKETS.md §3.** Activation names a program path; every write to *it* is
  a deployment to every socket it backs; §3's threat-model enumeration of
  writers applies to program paths.
- **SOCKETS.md §9.** `activate --program`, the new `ls` column, the
  activation's printed grant.
- **SOCKETS.md §10.** The table above.
- **SOCKETS.md §11.** `socket_activations` gains `program_space` and
  `program_path`; a `synch-store` migration (`v29`) backfills them from the
  socket's own path so every existing activation is self-backed and behaves
  as before.
- **TREE-WRITES.md §2.** The refusal covers program paths (§5).
- **README.md and the control-plane skill.** The activate examples gain the
  decoupled form beside the self-backed one.
- **LEAN.md.** No change: activation is local operator state outside the
  verified core, and `socketAuthority` — the one socket-adjacent Lean
  result — is about the caller's scope, which this does not touch.

## 10. Implementation order

Each step leaves the tree building and every existing test passing.

1. **Store.** Columns, migration, `SocketActivation` fields,
   `activations_backed_by`, `is_socket_or_program_path`, `remove_source`
   covering program spaces. Store tests: backfill makes rows self-backed;
   reverse lookup; refusal queries.
2. **Tree-write gate.** `refuse_socket_path` uses the widened query. Engine
   test: a grant over the program's prefix cannot write the program.
3. **Scanner and API commit.** Derivation in `index_file`, the sweep's
   exemption and fan-out, `commit_api_file`, activate/deactivate staging.
   Engine tests: one object, two sockets in one space and one in another,
   distinct `sy_config_get`/`sy_socket_path` answers and isolated maps; a
   redeploy moves all three in one head and clears all three maps; removing
   the object tombstones the decoupled sockets; a stray file at a socket path
   is shadowed and reported; a delegate of the socket's space can fetch the
   program's root.
4. **Engine API and control.** `socket_activate` validates §2.1 and §2.2;
   `SocketActivate.program`; `CONTROL_VERSION` 6; `ls -l` rendering with
   dependents and `stale`; MCP tool. CLI test for the printed grant.
5. **Docs.** The amendments in §9, and this document's status line.
