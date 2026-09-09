# Sockets by name — a socket namespace apart from spaces

Status: **proposed**. Nothing here is built. It supersedes `docs/SOCKETS.md`
§2 and §3 and amends §4, §9, §10 and §11, and `docs/TREE-WRITES.md` §2; each
place this changes is named in §11 below. Where it repeats a rule from those
documents it does so to say the rule survives.

Today a socket *is* a file: `synch socket activate code/git.sock` says that the
bytes at `code/git.sock` are a program, and the path is at once the program's
location, the socket's name, and — because it sits under `f:code/` — the
socket's authorization boundary. One object serving two sockets means two
copies of the ELF at two paths, each activated and deployed separately, and
`sy_socket_path`, which the host API grew "so one object can back several
sockets" (SOCKETS.md §7.2), is reachable only by duplicating the thing it
exists to share.

This proposal separates the three things that path was doing.

- A **program** is an ordinary file in this node's tree holding an eBPF
  object. It lives in a space, is published, replicated and materialized
  exactly as any file is, and is the thing every write channel deploys.
- A **socket** is a *name* in a namespace of its own — not a path, not in any
  space, not in the tree. An activation binds the name to a program path and
  carries the socket's own configuration, stream cap, scope, map and
  statistics. Many sockets may name one program.
- **Who may open a socket** is stated on the activation, not inferred from
  where a file happens to sit.

```
synch socket build gateway.c -o code/bin/gateway.o
synch socket activate git      --program code/bin/gateway.o --scope code --config upstream=git.internal
synch socket activate hg       --program code/bin/gateway.o --scope code --config upstream=hg.internal
synch socket activate docs/git --program code/bin/gateway.o --scope docs --max-streams 4
synch socket connect nas@cluster.example.com:git
```

## 1. What does not change

The rules the socket design is built on stay exactly as they are, and every
choice below is made to keep them.

- **A node executes only eBPF present in its own published tree.** The program
  path is in this node's own trie, in a space this node is a source of. A
  peer's object is not a program until it has been adopted into one.
- **Activation is a statement about paths, never about a content root.** It
  names the program path, and every write to that path, through every channel
  SOCKETS.md §3 enumerates, is a deployment. No root is an authorization pin.
- **Activation is local operator state**, never published, replicated, or
  derived from a peer. This design takes that sentence at its word: the
  socket itself is local state, and only the program is in the tree.
- **The caller ships bytes, not code**, and the callee resolves the name in
  its own table and its own trie. Selection policy does not apply.
- **The guest ABI is unchanged.** No helper is added or removed.
- **The verified core is untouched.** Nothing new enters the trie, so the
  Lean projection, ingest and materialization models see the same records
  they see today; `socketAuthority` still answers "who is this key and which
  spaces may it read", and the engine applies the socket's scope to that
  answer.

## 2. The socket namespace

A socket name is a string, and the grammar is the tree path grammar without
the space in front of it: non-empty, at most 256 bytes, display-safe
(`display_text_is_safe`), normalized by `normalize_path` — so `/` may group
names (`git`, `docs/git`, `ci/intake`), and `..`, empty components, a leading
`/` and control characters are refused. Names are unique per node and mean
nothing to any other node: `nas:git` and `laptop:git` are unrelated, as
`nas:code/git.sock` and `laptop:code/git.sock` are unrelated today (SOCKETS.md
§2.3).

Choosing a path-shaped grammar rather than a flat identifier is what makes
the migration invisible (§8): every existing socket `code/git.sock` becomes a
socket *named* `code/git.sock`, and `synch socket connect nas:code/git.sock`
keeps working with the same spelling and a new meaning.

### 2.1 The activation

```
socket_activations (
  name           TEXT PRIMARY KEY,      -- the socket: what a caller opens
  program_space  TEXT NOT NULL,         -- the program: where the bytes live
  program_path   TEXT NOT NULL,
  scope          TEXT NOT NULL,         -- newline-separated spaces; '' = members only
  config, max_streams, note, activated_at
)
```

`SocketActivation` becomes `{ name, program_space, program_path, scope,
config, max_streams, note, activated_at }`. Beside the forward lookups the
store gains `activations_backed_by(space, path)` — for the deployment
fan-out and the tree-write gate — and `is_program_path(space, path)`.

A program path must be in a source of this node's, filesystem or API, and
must publish as a file to serve; a directory, a symlink, a tombstone or
nothing at all makes every socket it backs `unpublished` in `ls` and refused
at admission, without touching the activation. Activating before the first
deploy is the ordinary order today and stays so.

Bounds: 256 activations per node, replacing the 64-per-space bound, which
has no space to count in. Sockets per program is bounded by it.

### 2.2 Scope: who may open

Space delegation (DESIGN.md §3.5) is the only grant a delegate holds, and it
is about *reading spaces*. Today a delegate of `code` may open `code/git.sock`
by position: the socket is in the space. With sockets out of spaces, that
implication has to be written down, and it is written on the activation.

- A **rooted member** may open any socket, as today it may open one in any
  space.
- A **delegate** may open a socket only if one of its delegated spaces is in
  the socket's `scope`. An activation with an empty scope is **members
  only**, and that is the default: offering a socket to delegates is a
  broader grant than offering it to members, so it is asked for by name. The
  migration (§8) sets the scope to the space each existing socket sat in, so
  no delegate loses a socket it can reach today.
- Inside the program, `sy_peer_has_space` and the rest of the identity family
  keep answering from the handshake, and remain the way to write rules finer
  than scope.

The refusal a delegate gets is a new `RefuseCode::OutOfScope`, appended
after `Unsupported`; `SpaceNotDelegated` stays in the enum, no longer emitted.

Scope is authorization only. It does not put the socket in the space, does
not publish the program's root into it, and does not let the delegate read
the program's bytes unless the program's own space is delegated to it —
which it does not need to; the connecting side executes nothing (SOCKETS.md
§1). That is the one place this design is *tighter* than copying an ELF into
a delegated space: the bytes of a program in `tools` stay in `tools`.

## 3. What the tree publishes

Nothing new, and one thing less.

The program path publishes `kind: File`, like any file. The scanner no longer
consults the activation table to choose a kind: `EntryKind::Socket` stays in
the enum so that records old builds published still decode, and every reader
already treats it as a file with content (materialization, `synch cat`, blob
scope), but this node stops emitting it. `synch ls` therefore stops marking
sockets, because there are none in the tree to mark; discovery moves to the
socket protocol (§5).

That is the whole of §3, and it is worth saying why the tree gets *simpler*
where the earlier draft of this proposal made it more complicated. A socket
that lived under `f:<space>/<name>` had to be a tree entry to be
authorized by position, and a tree entry whose bytes are somewhere else has
to be derived, kept in step with the program in every signed head, exempted
from the deletion sweep, and shielded from a stray file landing at its name.
A socket that is a name in a table of its own is none of those things. What
publishing bought — discovery in `synch ls`, delegation by position, an
entry for `Opened::Ok { program }` to be checked against — this design
provides directly: a list operation, a scope, and the program's path in the
`Opened` reply (§5).

SOCKETS.md §11's version-identity amendment (`Socket` as its own kind class)
becomes moot: it is harmless and may stay for old records.

## 4. Resolution, admission, deployment

`resolve_socket(name)`: the activation, then this node's own entry at
`(program_space, program_path)`, which must be a live entry with content —
`File`, or `Socket` from a build that still emitted it. Its root is the
snapshot the invocation runs.

Admission is `admit_socket` with the space checks replaced by the scope check
(§2.2), in the same position: after `socketAuthority` says who the caller is
and before anything is read from the CAS. The re-check under the
authorization lock compares the program entry's root to the one the manifest
was parsed from, as it does now, so a deployment landing mid-admission still
refuses `NotActivated` and the retry lands on the new program.

Everything downstream shares better than it did:

- The program-bytes cache and each worker's JIT cache are keyed by root
  (SOCKETS.md §5.1): *N* sockets on one object cost one CAS read and one
  compile per worker.
- The registry, the per-socket concurrency cap, the fault window, the log
  tail and the map are keyed by socket name, so two sockets on one program
  are as separate as two sockets on two programs.
- The effective policy is the manifest's declaration (from the root, the same
  for every socket it backs) capped by *this* activation's `max_streams` and
  carrying *this* activation's `config` — one gateway object, two
  `--config upstream=` lines, two upstreams.
- `sy_socket_path` returns the socket's name. The helper keeps its symbol so
  every compiled program still links; the header's comment says "name".

**Deployment** is what it is today, minus a table lookup per file. A content
change at a path with `activations_backed_by` non-empty — in `index_file` for
filesystem sources, in `commit_api_file` for API sources — clears each
dependent socket's map and logs one line naming the program path and the
sockets it moved. There are no derived entries to stage, so a deployment is
still one head and there is nothing that can lag it. A program path that
vanishes is tombstoned as any file is; its sockets resolve to nothing until
it comes back.

## 5. The wire — `sync/sock/2`

Addressing a socket by `space` and `path` is the one thing the current
`Open` cannot express, so the protocol moves: ALPN `sync/sock/2`,
`SOCK_PROTO_VERSION` 2, the same connection and stream shape, and three
changes to the frames.

```rust
enum SockRequest {                 // one per bi-stream, in place of a bare Open
    Open(SockOpen),
    List,                          // the sockets this caller may open
}

struct SockOpen {
    v: u8,
    origin: OriginId,              // must be the callee's own, as today
    socket: String,                // the name; validated like a path
    meta: Vec<(String, String)>,   // as today
}

enum SockOpened {
    Ok { program: Hash, program_path: String, invocation: u64 },
    Refused { code: RefuseCode, message: String },
}

struct SockListed { sockets: Vec<SockEntry> }        // reply to List
struct SockEntry { name: String, program: Hash, program_path: String, note: String }
```

- **`List`** is the discovery `synch ls` used to give for free. It returns
  the activations whose scope admits the caller (every one, for a member),
  bounded by the activation bound, and `synch socket ls <origin>:` prints
  it. It needs no runtime — a node that cannot serve sockets can still say
  which ones it has — and no new authorization: it applies the same scope
  rule `Open` does.
- **`program_path` in `Opened::Ok`** restores the audit the tree entry gave:
  a caller that can read the program's space can `synch cat` the path and
  compare roots. A caller that cannot still gets the root, as today.
- The `Open` frame bound (SOCKETS.md §10) is unchanged: the name is bounded
  by the same 4 KiB the path was, and the space it replaces was inside the
  1 KiB slack.

A node on v2 does not mount v1 and refuses a v1 dial at ALPN negotiation,
which the CLI reports as "this node speaks sync/sock/2; upgrade". SOCKETS.md
§11 already sets the rollout order for a change peers cannot decode:
**upgrade, then activate**. The connecting side is a byte pump with no
runtime, so upgrading it is the cheap half; and because the migration keeps
every old spelling meaningful (§8), the first thing an upgraded caller types
is the thing it typed yesterday.

## 6. Program paths are never writable through a program

`docs/TREE-WRITES.md` §2 states the rule that keeps tree-write grants and
activation composable: an activated path is never writable through the
`sy_put_*` family or a writable SFTP handle, because otherwise a program with
a grant over a prefix containing a socket is remote code persistence in two
moves — write the ELF, invoke it. The ELF now lives at the program path, so
the rule moves with it:

> A path that is the program path of any activation is refused by
> `refuse_socket_path` (renamed `refuse_program_path`), at writer open and
> again under the tree-write lock at commit and delete.

It is the one security-relevant change and it is a refusal moving, not a new
mechanism. `synch adopt path`, `synch put` and an S3 `PUT` onto a program
path remain sanctioned deployment channels the operator accepted at
activation, which says so (§7). Reading a program path is unrestricted, as
reading a socket entry is today (SOCKETS.md §7.6): the bytes are not secret,
and what executes is decided by the activation table. The SFTP backend's
`entry_kind` refusal — "a socket does not read out its neighbours' code" —
has nothing left to refuse and is removed.

## 7. Command surface

```
synch socket activate <name>                          bind a name to a program until
        --program <space>/<path>                      deactivated; every write to the
        [--scope <space>]…                            program deploys it; --scope admits
        [--config k=v]… [--max-streams <n>]           that space's delegates (default:
        [--note <text>]                               members only)
synch socket deactivate <name>                        connections refuse now; the
                                                      program file is untouched
synch socket ls [-l]                                  this node's sockets: program,
                                                      scope, root, manifest, policy
synch socket ls <origin>:                             a peer's sockets this caller may
                                                      open (List, §5)
synch socket ps [<name>] / log <name> / kill <id>     as today, by name
synch socket connect <origin>:<name> [--meta k=v]…    as today, by name
```

`--program` is required — a socket with nothing behind it is not a thing an
operator asks for by accident — and takes a fully qualified `<space>/<path>`,
as every other command spells a location. `activate` prints the grant it is
making, and names the path the deploying writes land on:

```
$ synch socket activate docs/git --program code/bin/gateway.o --scope docs
activated docs/git ← code/bin/gateway.o
open to: members, and delegates of docs
every write to code/bin/gateway.o is a deployment to: git, hg, docs/git
that includes adoption, S3 writes and `synch put` — activate only programs whose every writer you mean as a deployer
```

The list of dependents is the point: the third activation of a program is
the moment its blast radius became three sockets, and the operator should see
that where they asked for it. `ls -l` shows, per socket, the program path,
the root the tree currently names, the declaration from that root's
manifest, the scope, the policy, and the other sockets the same program
backs. `synch socket inspect` is untouched: stateless, one file, no table.

### 7.1 Control protocol and MCP

`SocketActivate { name, program, scope, config, max_streams, note }`;
`SocketDeactivate`, `SocketPs` and `SocketLog` take a name; `SocketLs` gains
an `origin` for the remote form; the `OpenSocket` stream's reference is
`<origin>:<name>`. `CONTROL_VERSION` goes to 6: a `target` that used to be a
path is now a name, and a client and daemon on different sides of that must
refuse each other rather than misaddress a socket. The MCP tools follow the
same shapes.

## 8. Migration

Schema `v29` rewrites `socket_activations` in place. For every existing row
`(space, path, …)`:

```
name          = "<space>/<path>"
program_space = space
program_path  = path
scope         = space
```

Every existing socket keeps its address, its program, its config, its cap,
and its reachability — a delegate of `code` could open `code/git.sock`
yesterday and can today, because the scope says so. The migration logs one
line per socket naming the scope it wrote, since the scope is now an explicit
grant the operator can narrow with a re-activation. The file at the old path
publishes as `File` from the next scan; nothing about its bytes changes, and
peers that materialized it as a file keep a file.

The one thing an operator may want to do afterwards is move the object: put
it at `code/bin/gateway.o`, re-activate `code/git.sock --program
code/bin/gateway.o`, and delete the old file. Until then the socket is
self-backed in all but name.

## 9. Failure and limits

| What happens | Result |
| --- | --- |
| Program path has no live file entry | Every socket it backs: `unpublished` in `ls`, `Refused{NoSuchPath}` naming the program path at admission. Deploying the object is the remedy. |
| Program content is not a valid program | As today, per socket: activated, every connection `Refused{ProgramInvalid}` naming the defect. One bad deploy is *N* unavailable sockets and `ls` shows all of them with the same reason. |
| Program replaced | Every dependent socket serves the new root from its next admission; every dependent map clears; one log line per socket. |
| Delegate opens a socket outside its scope | `Refused{OutOfScope}`. `List` did not show it. |
| Tree write or SFTP write to a program path | `SY_EPERM` / `HostError::Denied`, at open and at commit (§6). |
| Space of the program removed | `remove_source` deletes the activations it backed, as it deletes a space's activations today. |
| v1 caller dials a v2 node | ALPN refused; the CLI says which version the node speaks. |
| Activations per node | 256. |
| `List` reply | At most the activation bound; a bounded frame. |

## 10. Alternatives considered

- **Sockets under `f:<space>/<name>` with a derived entry** — the first
  draft of this proposal. Rejected on direction: a socket should not share
  the space namespace. In hindsight the machinery it needed (derived entries
  in every head, a sweep exemption, shadowed-file handling, a cross-space
  bytes disclosure) was the cost of keeping a name inside a namespace that
  had nothing to do with it.
- **A new `s:<name>` prefix in the trie.** Publishes sockets without putting
  them in spaces. SOCKETS.md §2.1 named the cost and this design agrees: a
  new prefix needs its own projection rule for delegates, a new answer in the
  Lean projection and ingest models, a GC and blob-scope rule for the root it
  carries, and a materialization rule for replicas that have nowhere to put
  it. Every one of those exists to publish something whose only readers are
  callers, who are better served by `List`.
- **Scope inferred from the program's space.** Tempting as a default, and
  wrong for the motivating case — one gateway in `tools` serving `code` and
  `docs` delegates — and wrong as a grant: moving a file must not silently
  widen who may run it.
- **Keeping `sync/sock/1` mounted with `space/path` joined into a name.**
  Would let an un-upgraded caller reach a migrated socket. Rejected: the
  protocol's stance is refuse, not negotiate, the caller side is the cheap
  half to upgrade, and a compatibility shim on the code-execution ALPN is
  the wrong place to spend the exception.

## 11. What this changes in the existing documents

- **SOCKETS.md §2** ("What a socket is in the tree") is replaced by §2–§3
  here: a program is a file, a socket is a name. §2.1's argument for `f:` is
  kept as the argument against `s:`. §2.2 becomes "programs are adoptable
  bytes; activations are not". §2.3 stands.
- **SOCKETS.md §3.** Activation names a program path and a scope; the
  threat-model enumeration of writers applies to program paths.
- **SOCKETS.md §4.** `sync/sock/2`, `SockRequest`, `List`, `OutOfScope`,
  `program_path` in `Opened`.
- **SOCKETS.md §9 and §10.** The command surface and the table above.
- **SOCKETS.md §11.** The schema, and the version-identity amendment marked
  historical.
- **TREE-WRITES.md §2.** The refusal covers program paths (§6).
- **README.md, the control-plane skill, the Hecatia client.** Examples and
  reference parsing move to `<origin>:<name>`.
- **LEAN.md.** No change.

## 12. Implementation order

Each step leaves the tree building and every existing test passing.

1. **Store.** The new table shape, the `v29` rewrite with its log line,
   `SocketActivation`, `activations_backed_by`, `is_program_path`,
   `remove_source`. Store tests: migration preserves address, program and
   scope; reverse lookups.
2. **Tree-write gate.** `refuse_program_path`. Engine test: a grant over the
   program's prefix cannot write the program.
3. **Engine.** `socket_activate` validating name and program; `resolve_socket`
   by name; scope in `admit_socket`; deployment fan-out in `index_file` and
   `commit_api_file`; the scanner stops emitting `Socket`. Engine tests: one
   object, three sockets with distinct `sy_config_get`/`sy_socket_path`
   answers and isolated maps; a redeploy moves all three and clears all
   three maps; a delegate in scope opens, one out of scope is refused
   `OutOfScope`, a member opens either; a program in an undelegated space
   serves a delegate in scope without exposing its bytes.
4. **Wire.** `sync/sock/2`, `SockRequest`, `List`, the `Opened` field; the
   net tests' fixtures move to names.
5. **Control and CLI.** Proto shapes, `CONTROL_VERSION` 6, reference parsing,
   `ls` local and remote, the printed grant, MCP tools. CLI test for the
   grant and for `ls <origin>:`.
6. **Docs.** The amendments in §11, and this document's status line.
