# Sockets

Status: **implemented**. Everything here describes the built thing: the record
kind, the activation table, the manifest, the `sync/sock/1` protocol, the host
API and its runtime, the scanner's publishing rule, the live-invocation
registry, the embedded compiler, and the command surface. The one thing named
here and not built is `synch doctor` reporting on sockets — the same facts are
in `synch socket ls -l` and `synch socket ps`, and each place below says so.

Checked against the tree it landed in. Where the built thing differs from an
earlier draft of this design, this document has been corrected to describe the
built thing, and says so at each point.

A **socket** is a file in a node's published tree whose content is an eBPF ELF
object. A peer runs `synch socket connect nas:code/git.sock`; the connection lands on
`nas`, which resolves that path *in its own trie*, loads the object from *its
own* CAS, and runs it under [async-ebpf][ae] — one invocation per incoming
stream. The caller supplies bytes and a verified identity. It never supplies
code.

The publisher may call its own socket with the same command. That path uses an
in-memory stream because iroh does not dial its own endpoint, but it still goes
through ordinary admission and the socket worker runtime with the node's bound
device identity.

[ae]: https://github.com/losfair/async-ebpf
[zs]: https://github.com/losfair/zeroserve

The host API is designed against [zeroserve][zs], which runs the same runtime
per HTTP request: flat `extern` helpers, `(ptr, len)` string pairs, `snprintf`
return semantics, small-integer handles into host-side tables, entrypoints
named by ELF section — and JSON handles (`sy_json_*`, §7.11) for everything
structured, so no C struct layout or numbered enum is part of the ABI beyond
`struct sy_pollfd`.

## 1. The asymmetry everything follows from

A socket has two sides and they are not mirror images.

> **A node executes only eBPF that is present in its own published tree.**
> Therefore the connecting side ships bytes, not programs — and needs no eBPF
> runtime at all.

The client half of `synch socket connect` is a byte pump. The server half is the whole
of the runtime. That split is what makes the security story tractable: there is
no code-shipping channel to audit, no signature scheme for programs in flight,
no question of whose sandbox a peer's program runs in. The only thing a caller
can influence is *which* of the callee's own already-published programs runs,
and the callee gates that by ordinary membership (DESIGN.md §3.2) and
delegation (§3.5).

The obvious alternative — the caller ships a program and the callee sandboxes
it — was rejected, and it is worth naming what rejecting it buys. Under that
design every member, and every delegate, becomes a code-execution grant on
every node it can reach, and the sandbox is the only thing standing between a
stranger and the machine. Under this one the sandbox is defence in depth and
the *gate* is that the callee already chose to publish the program at a path
it activated.

It also buys portability where it matters. async-ebpf runs on Linux, macOS and
OpenBSD, on x86-64 and arm64. Serving sockets is gated to those targets.
`synch socket connect` is not, because it executes nothing.

## 2. What a socket is in the tree

A socket is not a new namespace. It is a fifth `EntryKind` under the existing
`f:` prefix, so it inherits versioning, divergence, replication, delegation
scoping and materialization from the file model without a line of new plumbing.

```rust
enum EntryKind {
    File, Dir, Symlink, Tombstone,
    Socket,   // content is an eBPF ELF object; size and content root as for File
}
```

`FileEntry` is otherwise **unchanged**, and that is a deliberate retreat from an
earlier draft of this design, which carried a `socket: Option<SocketMeta>` field
holding a protocol hint and a one-line description.

The retreat is forced by how records are decoded. `postcard::from_bytes`
ignores *trailing* bytes — which is exactly why the `v` stamp exists (§4.2:
"a future record with a field appended decodes cleanly *as the current shape*")
— but it cannot invent missing ones. A field appended to `FileEntry` is
therefore readable by old builds and **unreadable by new ones**, because every
record already in every trie in the cluster is one field short of what the new
decoder demands. Carrying it would have meant a hand-written codec whose arity
depends on a field inside the record it is decoding, for the sake of a
description string.

So the entry kind carries the whole of the published claim, and the protocol
hint and description are local operator state that `synch socket ls` prints.
Discovery still works — `synch ls` marks sockets from the kind alone — and the
encoding of every non-socket record is byte-for-byte what it was.

A `Socket` entry is otherwise an ordinary file entry: `content` is the ELF's
BLAKE3 root — a content identifier, never an authorization pin — `size` is its
length, and `chunking` is
the default.

### 2.1 Why it lives under `f:`

DESIGN.md §4.1 states the constraint that decides this: *the redaction boundary
falls on key prefixes*. A socket published under a new `s:` prefix would need
its own projection rule in §5.5, its own delegation test, and its own answer to
"what does a delegate of `photos` see?". Under `f:<space>/<path>` the answer is
already written: a delegate of `code` sees the sockets in `code` and nothing
else, by position, with no new code. That is the same argument §4.1 makes for
keeping `m:space/<id>` an exact key rather than a prefix, and it is decisive.

### 2.2 Kind is an assertion, and it is not adoptable

The kind of an entry is what *this* origin says about *its own* copy — like
`unix_mode`, and unlike content. It comes from a local activation (`synch
socket activate`, §3), never from a peer. So:

- `synch adopt path nas:code/git.sock` fetches the ELF bytes and writes them into the
  local space. The next scan publishes them as `EntryKind::File`, because this
  node never activated that path. **Adopting a socket adopts its bytes, not
  its socket-ness** — and certainly not its executability. (Adopting onto a
  path this node *has* activated is the other case, and it is deliberate: an
  activated path's writers are deployment channels, §3.)
- `synch adopt tree`, `synch replica sync` and the S3 gateway behave identically: a
  `Socket` entry materializes as a regular file containing the ELF, which is
  exactly what it is on the publisher's disk too.
- A path where `nas` publishes `Socket` and `laptop` publishes `File` over the
  same bytes is *divergent*, not unanimous. That needs a small amendment to §8's
  version-identity rule (§11).

### 2.3 Selection does not apply

Reading a bare `<space>/<path>` picks a version by policy — `newest`,
`origin=`, `strict` (§8). **Connecting to one does not.** `synch socket connect`
requires an origin-qualified path, always, and the node resolves it in that
origin's trie only. There is no "the socket at `code/git.sock`"; there is only
"nas's socket".

`newest` would otherwise let any member's `mtime_ns` decide whose program a
connection lands on, and §12 already names member-supplied `mtime_ns` as the
sharpest edge of the version model. The unified tree stays a discovery surface
here and never a dispatch one.

## 3. Activation: how code gets into a node's own tree

"Only its own tree" is a strong rule, but a node's own tree is not a closed
system. Several existing commands write bytes into a filesystem-source directory that the
scanner then publishes as this node's own view. Enumerating them is the whole
threat model:

- your editor, which is the intended path;
- `synch adopt path`, which adopts a peer's bytes;
- `synch adopt tree --replace`, which does the same in bulk;
- an S3 gateway `PUT`, which writes into a filesystem-source directory over the network.

Every one of these is an existing, sanctioned way to change what this node
publishes. So publication is not, and must not be, the gate. **Activation**
is: `synch socket activate code/git.sock` records that this path, in this
space, is a socket. That is what makes the scanner publish `kind: Socket`,
and it is what admission checks before anything runs. It is local state,
never adopted from a peer, and never replicated.

Activation is a statement about the *path*, never about a content root.
While the path is activated, **every write to it is an intentional
deployment**: the new content serves as soon as the scanner publishes it,
under whatever its own manifest declares (§3.1), until `synch socket
deactivate`. That breadth is the grant, and the command says so at the moment
it is asked for: activating a path pre-approves every future write through
every channel above — adoption and a read-write S3 key included. Activate a
path only when everything that can write it is something you mean as a
deployment channel; content roots remain content identifiers everywhere
content is handled — CAS integrity, replication, caching, and the snapshot a
running invocation keeps — but no root is ever an authorization pin.

A deployment landing changes what the *next* admission runs. Invocations
already running keep the snapshot they were admitted with, and the per-socket
map (§6) is cleared: a session table the old program minted is not state the
new one agreed to inherit.

### 3.1 The manifest is what makes a deployment reviewable

An object that could reach anything would make "what can execute here?"
unanswerable. Instead the program declares its own external effects in a
`synchronicity.manifest` ELF section — **data, never code**: one versioned
JSON document, parsed with bounded, typed parsing that refuses duplicate
keys, unknown members, invalid values, oversized sections, and any executable
declaration section. There is no init hook and nothing executes at
inspection: what a file declares is a property of its bytes, the same answer
on every platform and every day.

```
$ synch socket inspect git-gateway.o

  file     git-gateway.o
  root     9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  size     41 KB
  declares name git-http
  declares egress git.internal:9418
  declares max-streams 32
  program  loads and links against this build's host API
```

`synch socket inspect` is stateless: one file snapshot, its BLAKE3 root — the
same root the tree names once the bytes are deployed — its parsed manifest
rendered canonically, and a load/link validation of the stream program. It
touches no database, no scanner, no daemon state, and publishes nothing.

Egress with no declaration is denied. Reading the tree is not among the
declared capabilities and never was denied by one (§7.6). Because the
manifest is compiled into the object, editing it changes the content root:
what an activated path serves is always exactly what its current bytes
declare, and `synch socket ls -l` shows that declaration from the same parse
admission uses. An update whose manifest does not parse — or whose program
does not load — keeps the path activated and published and refuses every
connection with a message naming the defect; deploying a fixed object is the
whole remedy.

## 4. The wire — `sync/sock/1`

A third ALPN alongside `sync/mpt/1` and `sync/blob/1`, mounted on the same
endpoint and gated by the same accept check. One QUIC connection per (caller,
callee) pair; one bidirectional stream per invocation.

```rust
// caller → callee, one length-framed postcard header per bi-stream, then raw bytes
struct Open {
    v: u8,
    origin: OriginId,            // must be the callee's own; a mismatch is refused,
                                 // so a relayed or replayed Open cannot be redirected
    space: String,
    path: String,
    meta: Vec<(String, String)>, // <= 16 pairs, <= 4 KiB total — untrusted, caller-chosen
}

// callee → caller, one header frame in reply, then raw bytes
enum Opened {
    Ok { program: Hash, invocation: u64 },   // the root actually running — auditable
    Refused { code: RefuseCode, message: String },
}

enum RefuseCode {
    NoSuchPath, NotASocket, NotActivated, Unauthorized, SpaceNotDelegated,
    Busy, ProgramInvalid, Unsupported,       // Unsupported = callee has no runtime
}

// callee → caller, one uni-stream per connection, opened at connection setup;
// begins with the fixed bytes `sync/sock/control/1\0`, then framed Closed values
struct Closed { stream_id: u64, status: Status }
enum Status { Ok(i64), Fault(FaultKind), Killed, Shutdown, Deadline }
```

### 4.1 Why the payload is unframed and the status is out of band

After `Opened::Ok` the stream carries opaque bytes in both directions with no
framing at all, and half-close maps to QUIC FIN in the obvious way. That is
deliberate: framing the payload to make room for a trailer would put a length
prefix on every proxied byte for the sake of a value that arrives once.

A QUIC `RESET_STREAM` would be the other cheap way to carry a status, and it is
wrong here — a reset discards data the peer has not yet read, so a program that
writes a final response and returns would race its own output away. The status
therefore rides a per-connection control uni-stream, and the data stream always
closes cleanly.

### 4.2 Authorization

DESIGN.md §12 enumerates where delegation is enforced; sockets add a position
with the same shape and no new mechanism.

- **Accept** — unchanged. A connection is refused unless the device key is
  bound to a trusted origin.
- **Open** — the named space must be one the caller may read: every space for a
  rooted member, the delegated list for a delegate (§3.5). A delegate that
  connects to a socket outside its list gets `SpaceNotDelegated`, which is the
  same answer §5.5 gives it for the metadata.
- **Inside the program** — `sy_peer_origin()`, `sy_peer_info()` and
  `sy_peer_has_space()` read the *handshake's* identity, never the payload's. A
  socket that wants finer rules than membership writes them itself, over facts
  the caller cannot forge.

§12 declines per-peer rate limits on the sync ALPNs on the grounds that every
peer is an authorized member and abuse is a membership problem. Sockets keep
that stance and add the same kind of sanity bounds it already permits: a
concurrency cap per socket, a handle cap per invocation, and a timeslicer that
throttles a hot program rather than letting it hold a worker. The remedy for a
member behaving badly is still `synch trust rm`.

## 5. The invocation

Every helper except one is synchronous against host-side buffers. `sy_poll` is
the only helper that suspends, and the only one that calls async-ebpf's
`HelperScope::post_task`. A socket program is therefore an ordinary event loop
— the shape every C network programmer already has in their fingers — and the
runtime gets a single, auditable suspension point instead of a dozen.

The guest loop is cooperative and the host loop is not: a program with no
`sy_poll` in it is still preempted, because async-ebpf's watcher signals the
thread rather than waiting to be asked. Everything the guest can see of the
network is a byte in a ring the host owns; a full ring stops the host reading,
which backpressures the far side.

### 5.1 Where invocations run

async-ebpf's `Program` is deliberately neither `Send` nor `Sync`: a guest
suspends inside a signal handler, so resuming it on another worker would leave
SIGUSR1 and SIGSEGV blocked on the thread that took them. That constraint sets
the daemon's threading directly.

- `synch daemon run` initializes async-ebpf's `GlobalEnv` once at startup,
  before any socket work, and spawns **N socket workers** (default
  `min(4, cores)`), each a dedicated OS thread running a current-thread runtime,
  a `LocalSet`, and its own `ThreadEnv` with the preemption watcher armed.
- Each worker holds its own `ProgramLoader` — the helper table's per-loader
  entropy makes helper indices unforgeable — and its own cache of pinned
  `Program`s keyed by content root. A program therefore JIT-compiles at most
  once per worker, and a socket under load costs N compilations, not one per
  stream.
- **The compile does not run on the worker thread.** `ProgramLoader::load`
  does the parse and the JIT and returns an `UnboundProgram`, which is `Send`;
  only `pin_to_current_thread` has to happen where the guest will run, and it
  is a struct wrap. So a cache miss goes to the blocking pool and the worker
  keeps serving everything else placed on it. It used to be inline, before the
  select loop, which meant one cold admission stopped that worker outright —
  and with a 32-entry cache and oldest-first eviction, a caller reaching more
  than 32 distinct roots made every admission a miss. Concurrent admissions of the
  same root wait on the first compile rather than each starting their own.
  The loader stays per worker: moving it to a shared compile pool would make
  one guest's discovery of a helper index worth something on every worker.
- async-ebpf's *lazy* per-function JIT — a function is compiled when the guest
  first calls it — leaves the thread the same way. It used to be pinned to the
  thread running the guest, because async preemption cannot interrupt a thread
  whose PC is inside the compiler; since 0.4.0-alpha.13 the runtime hands it to
  `Timeslicer::run_blocking` instead, and this crate sends that to the same
  blocking pool. **No compilation of either kind runs on a worker thread.**
  Both are still charged to the compiling guest's run budget, so moving the
  work buys that guest no extra CPU — only the rest of the worker its turn.
- A new stream is assigned to the least-loaded worker and stays there. This is a
  placement decision, not a scheduling one: there is no work stealing, by
  construction.
- A worker whose preemption watcher has failed refuses to start further runs
  (async-ebpf checks this itself). The daemon does not silently fall back to
  running uninterruptible guests. Surfacing the degraded worker count to an
  operator is not built.

## 6. Memory and state

The guest's memory model is severe enough that it shapes the API, so it comes
before the API. async-ebpf gives a program a pointer cage: one power-of-two
window carved into a writable stack region and a read-only data region, with
randomized guard regions around both, and a JIT that masks every load and store
address back inside it, branchlessly. After linking, code and data are frozen
read-only and *all* stores are confined to the stack.

So the guest has **no heap** and **no mutable globals**. Its stack holds at
least eight local-call frames plus 512 bytes of calldata: 128 KiB of frame
space at the 16 KiB default, with a 32 KiB floor for smaller custom frames.
Default frames are guarded on hosts whose pages are no larger than 16 KiB and
contiguous on larger-page hosts. A program compiled with another frame size
declares that size in its manifest. Everything that outlives a helper
call lives host-side:

The number that binds in practice is the **local-call frame**, not the total
stack. The SDK examples' functions keep their locals below 4 KiB, while the
runtime's guarded 16 KiB frame stride is portable to both 4 KiB- and 16
KiB-page hosts. A program built for another value must declare it as the manifest's
`"stack_frame_size"`.

| Table | Scope | Bound |
| --- | --- | --- |
| endpoint table | per invocation | 256 handles, `SY_SELF` included; at most 32 may be open endpoints, and per-role caps (§10) bound what the rest can hold |
| object table | per invocation | shares the 256-handle table with endpoints, 1 MiB footprint; JSON values (§7.11) live here too |
| socket map | per socket, outlives invocations | 4096 keys, 1 MiB; expired entries are reclaimed, otherwise a full map refuses writes |

The socket map is the only way two invocations of one socket can see each
other. It is memory-only: cleared on daemon restart and on every deployment, and
deliberately absent from SQLite.

Two conventions fall out of the absence of a heap:

- **Every out-parameter is `(ptr, len)` and returns the length it wanted.**
  Exactly `snprintf`: the return value is what a complete write would have
  needed, so a program can detect truncation without a second call. Same
  convention as zeroserve's SDK.
- **Bulk out-parameters are one contiguous struct array, never N separate
  pointers.** async-ebpf caps a single helper call at 4 mutable and 16
  immutable validated regions, and refuses a mutable region that aliases
  another. `sy_poll` taking a `struct sy_pollfd[]` costs one region no matter
  how many handles it watches; a signature with one out-pointer per handle
  would fail on the fifth.

## 7. The host API

Shipped as a single header, `synch socket sdk > synch.h`, and supplied
automatically by `synch socket build` (§9).

```c
#define SY_STR(s)   (s), sy_strlen((s))
#define SY_SELF     0                    /* the inbound stream is always handle 0 */

#define SY_ENTRY        __attribute__((section("synchronicity.stream")))
#define SY_MANIFEST(json) /* one JSON document in `synchronicity.manifest` */

#define SY_EAGAIN     -1   /* would block — poll and come back                    */
#define SY_EBADF      -2   /* no such handle in this invocation                   */
#define SY_EINVAL     -3
#define SY_EPERM      -4   /* policy: egress not in the manifest, path out of scope */
#define SY_ECONNRESET -5
#define SY_ETIMEDOUT  -6
#define SY_ELIMIT     -7   /* a documented bound in §9 was hit                    */
#define SY_ENOENT     -8
#define SY_EPIPE      -9   /* write after the peer's read side went away          */

#define SY_POLL_IN   0x1   /* readable, or EOF is pending                         */
#define SY_POLL_OUT  0x2   /* tx window has room; a connecting socket is up       */
#define SY_POLL_HUP  0x4   /* both halves shut; reported without asking           */
#define SY_POLL_ERR  0x8   /* sy_errno(h) says what                               */
#define SY_POLL_RDHUP 0x10  /* peer write-half EOF; reported only when asked        */

/* the one guest-visible struct: sy_poll is the hot path */
struct sy_pollfd { sy_s64 handle; sy_u32 events; sy_u32 revents; };
```

Everything else structured — a stat result, the caller's identity, an SSH
event, a process status, a backing-service declaration — crosses the pointer
cage as a **JSON handle** (§7.11), never as a C struct or a numbered enum. A
guest compiled against a stale header used to read a renumbered enum wrong
silently; a missing JSON key is an explicit `SY_ENOENT`.

The descriptor model every family below follows — one handle table, a generic
lifecycle plane (`sy_close`/`sy_poll`/`sy_errno`) over a typed data plane, and
one meaning per errno — is specified in `docs/HANDLES.md`.

### 7.1 Diagnostics and configuration

| Helper | What it does |
| --- | --- |
| `sy_log(msg, len)` | Line-buffered to the daemon log, tagged with socket path and invocation id. Non-ASCII and control bytes replaced. |
| `sy_now_ms()` | Wall clock, milliseconds. Never used for ordering — that lesson is in §4.4. |
| `sy_monotonic_ns()` | Monotonic since invocation start. What a timeout should be written against. |
| `sy_getrandom(out, len)` | CSPRNG bytes. |
| `sy_version(out, len)` | The daemon's version string. |
| `sy_config_get(k, klen, out, olen)` | Reads a key from `synch socket activate --config k=v`. |
| `sy_metric_add(name, len, delta)` | Bumps a named counter shown by `synch socket ps`. |
| `sy_label_set(k, klen, v, vlen)` | Labels this invocation's row in `synch socket ps`. |

`sy_config_get` is deliberately **not** `env_get`. zeroserve exposes the
process environment because a request script is local configuration; a
synchronicity socket is reachable by every member of the cluster, and on a
serverless node the daemon's environment holds cloud credentials.

### 7.2 Identity — read from the handshake, never from the payload

| Helper | What it does |
| --- | --- |
| `sy_self_origin(out, len)` | This node's own origin id. |
| `sy_socket_path(out, len)` | `space/path` of the socket being served, so one object can back several sockets. |
| `sy_peer_origin(out, len)` | The caller's origin. Bound by iroh's mutual authentication, not asserted by the caller. |
| `sy_peer_device_key(out32)` | The caller's raw 32-byte device key — stable across origin renames. |
| `sy_peer_info()` | The whole authenticated identity as one JSON handle: `{"origin", "device_key" (hex), "kind" ("member" \| "delegate"), "addr", "stream_index"}`. |
| `sy_peer_has_space(s, len)` | Whether the caller may read that space. The one-line way to write "only people I gave `code` to". |
| `sy_peer_addr(out, len)` | Remote transport address. Informational — it can be a relay. |
| `sy_conn_meta(k, klen, out, olen)` | A key from the caller's `Open.meta`. **Untrusted input.** |
| `sy_stream_index()` | Ordinal of this stream within the caller's connection. |

### 7.3 Endpoint I/O — never blocks

| Helper | What it does |
| --- | --- |
| `sy_read(h, buf, len)` | Bytes out of the rx ring; `0` at clean EOF; `SY_EAGAIN` when empty and open. |
| `sy_write(h, buf, len)` | Bytes accepted into the tx ring. A *short count is normal* and is the backpressure signal. |
| `sy_splice(from, to, max)` | Moves up to `max` bytes from one endpoint's rx ring into another's tx ring, host-side. `sy_read`'s returns for the source, plus the destination's own error — including `SY_EPIPE`, which a read never gives. |
| `sy_readable(h)` / `sy_writable(h)` | Buffered bytes / free window, for sizing a copy without a trial call. |
| `sy_shutdown(h)` | Half-close the write side once the tx ring drains. |
| `sy_close(h)` | Drop the endpoint and free the slot. What is queued on its write side still drains, in the background, under §10's teardown budget. `SY_SELF` may be closed; the invocation continues, and its slot is not reused. |
| `sy_errno(h)` | Why an endpoint has `SY_POLL_ERR` set. |

`sy_splice` is the one helper here that touches no guest memory at all, and
that is what it is for. The bytes are already in a ring the host owns (§5); a
program that only forwards them has no reason to lift them over the pointer
cage into a stack buffer and hand them straight back. What it saves is not
mainly the two copies. It is the *remainder*: because nothing is picked up that
cannot be placed, a short move leaves the bytes where they already were, in the
source's rx ring, where the far side's flow control is already accounting for
them. A splicing proxy therefore carries no buffer and no `struct sy_pump`
(§7.10) — the state that exists so that a short write cannot lose what it did
not place has nothing left to hold.

The destination is checked before anything is taken from the source, so a
failed or half-closed `to` is reported as its own error with the source
untouched, and the bytes are still there for a program that has somewhere else
to put them. Otherwise the returns are `sy_read`'s: a count, `0` at a clean EOF
on `from`, `SY_EAGAIN` when neither side could move. `max` bounds one call so
that a saturated direction cannot monopolise a loop; `0` is `SY_EINVAL`,
because `0` already means EOF. Both handles must be endpoints — an object from
`sy_open` is read with `sy_pread`, whose answer may not be here yet, and a
splice that could block is not this helper. `examples/splice-proxy.c` is
`examples/tcp-proxy.c` written this way, and the difference between the two is
the whole argument.

### 7.4 Outbound connections

| Helper | What it does |
| --- | --- |
| `sy_tcp_connect(host, len, port)` | Returns a handle immediately, in *connecting* state; poll for `SY_POLL_OUT`. |
| `sy_tcp_connect_ip(addr, alen, port)` | Same, skipping DNS, for a literal address. |
| `sy_endpoint_info(h, out, len)` | Peer address and connection state of an endpoint the program opened. |

Resolution happens host-side, and **both the name and the resolved address are
checked** against the manifest's egress list — so a program cannot reach an internal
address by way of a name that resolves to it.

Closing a connecting handle does not immediately return its place in the
per-invocation egress budget (§10). Resolution runs on a blocking pool and
cannot be cancelled once dispatched, so a budget returned at `sy_close` would
bound established connections while leaving the resolutions behind it
unbounded; the place comes back when the connection's task actually ends.

### 7.5 Poll — the only helper that suspends

`sy_poll(fds, n, timeout_ms)` waits for readiness on up to 256 handles. Returns
the number ready, `0` on timeout, negative on error; `timeout_ms < 0` means
"until something happens", clamped by the host to the invocation's idle
deadline — and the deadline is the end of the invocation itself (§10): a poll
that comes back `0` is the runtime telling the program to finish, and a
program that goes around again is ended with `Closed{Deadline}`. One validated
mutable region regardless of `n`.

Endpoint shutdown uses Linux's level-triggered `HUP`/`RDHUP` distinction and
filtering, rather than reproducing every bit returned by Linux `tcp_poll`.
`IN` means a read can make progress, including by returning zero at EOF.
`RDHUP` means the peer closed its write half and is returned only when
requested. `HUP` means both directions are shut, while `ERR` means the endpoint
failed; those two terminal events are returned whether or not the entry
requested them, and a failed endpoint reports both. `RDHUP` and `HUP` may
accompany buffered input, so drain `IN` until `sy_read` returns zero rather
than treating either bit as permission to discard the receive buffer. `OUT`
retains this ABI's narrower meaning of usable tx-ring room, so it is absent
after `sy_shutdown` when `sy_write` would return `SY_EPIPE`.

### 7.6 Reading the tree — verified, and unrestricted

A socket reads every path in every origin this node holds, and every blob in
its CAS by content root. There is no read declaration and no per-path check.

That is a deliberate retreat from an earlier design in which a program declared
`tree-read` prefixes and `sy_open_from` was refused without one. The gate was
decorative: `sy_open_root` reached the same bytes by hash with no declaration
at all, so the prefix list bought an extra status line rather than a
boundary. What a node exposes to a caller is decided by which paths it
activates,
and by membership and delegation on the way in (§3.2, §3.5) — not by a
per-program list of paths its own code may read.

Socket entries are readable like any other file. Their bytes are not secret —
any member fetches them out of the tree — and what executes on this node is
decided by the activation table, not by who can read an ELF.

| Helper | What it does |
| --- | --- |
| `sy_open(path, len)` | Opens `space/path` **in this node's own trie** — the same scope the program came from. |
| `sy_open_from(origin, olen, path, plen)` | Another origin's version. Needs no declaration; §8's mtime-trust caveat is why it is not the default. |
| `sy_open_root(root32)` | By content root — how a superseded version is read, mirroring `synch cat --root`. |
| `sy_stat(obj)` | The object's metadata as a JSON handle: `{"size", "mtime_ns", "mode", "kind" ("file" \| "dir" \| "symlink" \| "tombstone" \| "socket"), "root" (hex)}`. |
| `sy_pread(obj, buf, len, off)` | Verified range read. Bytes in the CAS return immediately; bytes that must be fetched return `SY_EAGAIN` and the handle becomes pollable — a cold read is an ordinary poll wait, not a hidden stall. |
| `sy_list_open(prefix, len)` | A cursor over `f:<space>/<prefix>`, which the trie's prefix compression makes cheap (§4.1). |
| `sy_list_next(cur, out, len)` | Next entry name; `0` at the end. |

### 7.7 State that outlives an invocation

| Helper | What it does |
| --- | --- |
| `sy_map_get(k, klen, out, olen)` | Per-socket map lookup. `SY_ENOENT` if absent or expired. |
| `sy_map_set(k, klen, v, vlen, ttl_ms)` | Insert or replace with a TTL. |
| `sy_map_delete(k, klen)` | Remove a key. |
| `sy_map_incr(k, klen, delta, ttl_ms)` | Atomic counter, returning the new value. Atomic in the sense that matters: a worker never yields inside a helper. |
| `sy_rate_limit(k, klen, limit, window_ms)` | Sliding-window limiter over the same store. `0` allowed, `SY_ELIMIT` denied. Present because a limiter written by hand out of `map_incr` is written wrong about half the time. |

### 7.8 Bytes, hashes, encodings

`sy_memcpy`, `sy_memcmp`, `sy_memset`, `sy_ct_eq` (constant time), `sy_blake3`,
`sy_sha256`, `sy_hmac_sha256`, `sy_base64_encode`,
`sy_base64_decode_in_place`, `sy_hex_encode`, `sy_hex_decode_in_place`.

`sy_blake3` is first-class because content roots are BLAKE3: a program can
verify what it just read against what the tree said. The in-place decoders exist
because there is no heap to decode into. The base64 pair takes two orthogonal
flags — `SY_BASE64_URL` and `SY_BASE64_NO_PAD` — rather than a numbered
four-alphabet enum.

### 7.9 The manifest's capability members

There are no declaration helpers: a declaration is data in the object's
`synchronicity.manifest` section (§3.1), never an API call. The scalar
members are `"name"`, `"egress"` (an array of `host` or `host:port` strings —
a bare host is any port on it, which inspection prints loudly),
`"max_streams"`, `"stack_frame_size"` (a multiple of 16 from 16 bytes through
32 KiB; omitting it keeps the 16 KiB default), and `"guarded_stack_frames"`.

The capability members are arrays of JSON objects — `"processes"`:
`{"id", "allow": ["pty" | "pipe"], "executable", "argv",
"allowed_signals": ["HUP" | "INT" | "TERM"]}`; `"file_transfers"`:
`{"id", "protocol": "sftp", "access": ["read" | "write", "recursive"?],
"scope"}`
(`docs/SSH-SOCKETS.md` §7); and `"tree_writes"`:
`{"id", "prefix", "allow": ["create" | "replace" | "delete"], "max_bytes"?}`
(`docs/TREE-WRITES.md` §3). Tree writes are the one capability family whose
gate is a boundary rather than a status line: the `sy_put_*` helpers are the
only door to mutation.

There is no read capability: reading the tree is not declared (§7.6).

`"stack_frame_size"` must match the compiler's eBPF stack-frame setting.
Frames are guarded by default when the host page is no larger than 16 KiB. On
hosts with larger pages the daemon warns at startup and explicitly selects
async-ebpf's contiguous layout; it does not use automatic guard selection. A
guarded custom size must be aligned to the executing host's page size —
checked when the program is load-validated, at inspection and admission.
`"guarded_stack_frames": false` explicitly selects the contiguous layout,
while `true` requires guards and refuses an incompatible host.

### 7.10 In the header, not in the host

Five things in `synch.h` are ordinary C rather than helpers, because they are
the same in every program and getting them wrong is silent.

`sy_strlen(s)` measures a NUL-terminated string directly in guest memory. It
is ordinary C so measuring a short stack string does not make the host probe
for the end of the stack region.

`sy_pump(from, to, buf, cap, st)` moves one buffer's worth between two handles.
The `struct sy_pump` it carries is the point: a short write is backpressure,
and the remainder stays in `buf` under `st` until a later call can place it.
`sy_pump_blocked(st)` says whether a remainder is waiting, which is what decides
whether to poll the far side for `SY_POLL_OUT` or the near side for
`SY_POLL_IN`. It is for a program that needs to *see* what it is forwarding;
one that does not wants `sy_splice` (§7.3), where the same short write leaves
nothing behind to carry.

`sy_write_all(handle, buf, len, timeout_ms)` is the same job for a program whose
whole reply is one message, where waiting is the honest thing to do. Not in a
proxy: blocking one direction on the other's window deadlocks as soon as a
payload is large enough.

`sy_utoa(value, out, cap)` writes a number in decimal. There is no `snprintf`
here, and a Content-Length has to come from somewhere.

`memset`, `memcpy` and `memmove` forward to the host helpers. Nothing calls
them by name; a struct initializer or an array assignment is enough to make any
C compiler emit a call, and without these that call would be an unresolved
symbol — a program that fails to *link*, at admission, on somebody else's node,
a long way from the line that caused it. Clang emits an intrinsic instead of a
call, which never meets these definitions; the `--clang` build rewrites those
to the same helpers (§9).

### 7.11 JSON values

Modeled on zeroserve's JSON API, and the reason the rest of §7 carries no
struct layouts: values live host-side, the guest holds handles out of the same
256-slot table endpoints and objects come from, charged against the same 1 MiB
footprint and released with `sy_close`.

| Helper | What it does |
| --- | --- |
| `sy_json_parse(data, len)` | Parses JSON text into a fresh handle. |
| `sy_json_stringify(json, out, olen)` | Serializes a handle's value; snprintf semantics. |
| `sy_json_new_object()` / `sy_json_new_array()` | Fresh empty containers. |
| `sy_json_type(json)` | `SY_JSON_NULL` … `SY_JSON_OBJECT`. |
| `sy_json_len(json)` | Elements of an array, keys of an object, bytes of a string. |
| `sy_json_get(json, key, klen)` | A **copy** of one member as a fresh handle; `SY_ENOENT` if absent. |
| `sy_json_array_get(json, index)` | A copy of one element as a fresh handle. |
| `sy_json_read_string(json, out, olen)` / `sy_json_read_i64(json, out, olen)` / `sy_json_read_bool(json)` | Scalar reads. |
| `sy_json_set(json, key, klen, value_json)` / `sy_json_array_push(json, value_json)` | Insert a **copy** of another handle's value. |
| `sy_json_remove(json, key, klen)` | Remove a key. |
| `sy_json_set_string` / `sy_json_set_i64` / `sy_json_set_bool` / `sy_json_set_null` | Replace the handle's own value in place. |

Every handle owns its own value: navigation copies out, insertion copies in,
and no two handles ever alias — so no mutation acts at a distance and no cycle
can be constructed. Documents are built bottom-up and read top-down, and the
per-value bound (64 KiB serialized, 64 levels deep) is what keeps the
host-side walks each mutation performs cheap. `sy_json_get_string`,
`sy_json_get_i64` and `sy_json_get_bool` in the header are the
get-read-close spelling of the common case.

The JSON family is pure data manipulation — the natural shape for a program
whose configuration, identity answers, and capability descriptions are all
JSON values.

### 7.12 Writing the tree — declared, and a boundary

`sy_put_open`, `sy_put_write`, `sy_put_splice`, `sy_put_commit`,
`sy_put_commit_if` and `sy_put_delete` publish file versions and tombstones
into this node's own trie, behind a `"tree_writes"` grant in the manifest
(§7.9). A committed write is an ordinary local publish through the same
ingest path an S3 `PUT` takes; an activated socket path is never writable. The
whole design — why the write declaration is enforceable where the read one
(§7.6) was decorative, the writer lifecycle, the commit conditions, and the
bounds — is **[docs/TREE-WRITES.md](TREE-WRITES.md)**.

## 8. A whole socket, end to end

A git-over-TCP gateway for a delegated space: authorized by delegation rather
than by a password, rate-limited per caller, and reaching exactly one upstream.

```c
#include <synch.h>

/* Data, never code: the whole of what this program may reach, compiled into
   the object. `synch socket inspect` shows this list; nobody reads eBPF. */
SY_MANIFEST("{\"manifest\":1,\"name\":\"git-http\","
            "\"egress\":[\"git.internal:9418\"],\"max_streams\":32}");

SY_ENTRY sy_s64 entry(void) {
  /* 1. Authorization is the handshake. Nothing here parses caller input. */
  if (!sy_peer_has_space(SY_STR("code"))) {
    sy_log(SY_STR("refused: caller is not delegated `code`\n"));
    return -1;
  }

  /* 2. Per-caller rate limit, keyed by device key — survives an origin rename. */
  sy_u8 key[32];
  sy_peer_device_key(key);
  if (sy_rate_limit(key, sizeof key, 30, 60000) < 0) {
    sy_metric_add(SY_STR("throttled"), 1);
    return -1;
  }

  char who[96];
  sy_peer_origin(who, sizeof who);
  sy_label_set(SY_STR("peer"), who, sy_strlen(who));

  /* 3. The one destination this program's manifest declares. */
  sy_s64 up = sy_tcp_connect(SY_STR("git.internal"), 9418);
  if (up < 0) return up;

  /* The binding limit is the *frame*, not the stack: this program uses the
     16 KiB default per function. `who`, `key`, the poll array and the two
     buffers all live inside that frame. */
  char upward[1536], downward[1536];

  /* One buffer and one pump per direction. `sy_pump` holds a short write's
     remainder in its buffer until there is room for it, which is why the two
     directions cannot share either: one direction's backpressure would
     otherwise stall the other's bytes, or overwrite them. */
  struct sy_pump to_upstream = SY_PUMP_INIT, to_caller = SY_PUMP_INIT;

  /* Each direction ends on its own. A loop that stopped the moment either
     side hung up would cut off the reply to the last request it forwarded,
     which is the single most common way to get this wrong. */
  int caller_done = 0, upstream_done = 0;
  while (!(caller_done && upstream_done)) {
    struct sy_pollfd fds[2] = { { SY_SELF, 0, 0 }, { up, 0, 0 } };
    /* While a pump is holding a remainder, wait for room on the far side
       rather than for more to read: there is nowhere to put more. */
    if (!caller_done) {
      if (sy_pump_blocked(&to_upstream)) fds[1].events |= SY_POLL_OUT;
      else                               fds[0].events |= SY_POLL_IN;
    }
    if (!upstream_done) {
      if (sy_pump_blocked(&to_caller)) fds[0].events |= SY_POLL_OUT;
      else                             fds[1].events |= SY_POLL_IN;
    }

    /* HUP and ERR are unconditional. Omit an inactive endpoint rather than
       leaving it in the set with events == 0, where a terminal event would
       wake an unrelated backpressure wait. */
    sy_u64 nfds;
    if (fds[0].events == 0) {
      fds[0] = fds[1];
      nfds = 1;
    } else {
      nfds = fds[1].events == 0 ? 1 : 2;
    }

    if (sy_poll(fds, nfds, -1) <= 0) break; /* host idle deadline, or all quiet */

    if (!caller_done) {
      sy_s64 n = sy_pump(SY_SELF, up, upward, sizeof upward, &to_upstream);
      if (n == 0) { sy_shutdown(up); caller_done = 1; }
      else if (n < 0 && n != SY_EAGAIN) break;
    }
    if (!upstream_done) {
      sy_s64 n = sy_pump(up, SY_SELF, downward, sizeof downward, &to_caller);
      if (n == 0) { sy_shutdown(SY_SELF); upstream_done = 1; }
      else if (n < 0 && n != SY_EAGAIN) break;
    }
    sy_u32 revents = 0;
    for (sy_u64 i = 0; i < nfds; i++) revents |= fds[i].revents;
    if (revents & SY_POLL_ERR) break;
  }

  sy_close(up);
  return 0;                                  /* → Closed{ Ok(0) } */
}
```

`sy_pump` is in the header, and the `struct sy_pump` beside it is why: it reads
once, writes what it can, and keeps the remainder *in the buffer* until a later
call can place it. A short write is backpressure, not failure, and a pump that
returned "moved 900 of 1500 bytes" with no way to say where the other 600 went
would drop them — invisibly, and only once a payload got large enough to fill
the far side's window. Writing that loop by hand is where the second most common
mistake lives; `sy_write_all` is the same job for a program whose whole reply is
one message.

Peer EOF sets `RDHUP`, not `HUP`: the local write half may remain usable long
after the caller stops writing. Because `RDHUP` is maskable, that receive-side
event does not wake an `SY_POLL_OUT`-only backpressure wait. `IN` remains ready
at EOF, so the read side of the loop still reaches `sy_read(...) == 0` without
having to request `RDHUP`. Once the program also calls `sy_shutdown`, the
endpoint is shut in both directions and `HUP` becomes an unconditional terminal
event, matching Linux's distinction between `EPOLLRDHUP` and `EPOLLHUP`.

Forty lines, no heap, no globals, one upstream, and an access-control rule that
a caller cannot lie its way past. The pieces this design exists to provide are
all visible: an identity that came from the transport, a limit that outlives the
invocation, an egress approved in advance, and a poll loop that is the only
place the program sleeps.

## 9. Command surface

```
synch socket inspect <file>                           statelessly describe an eBPF
                                                      object: root, manifest, load check
synch socket activate <space>/<path>                  make the path a socket until
                 [--config k=v]… [--max-streams <n>]  deactivated: the next scan
                 [--note <text>]                      publishes it as kind=Socket, and
                                                      every later write is a deployment
synch socket deactivate <space>/<path>                republish as an ordinary file;
                                                      admission refuses immediately
synch socket ls [<space>] [-l]                        mine: published root, manifest
                                                      declaration, validity, policy
synch socket ps [<space>/<path>]                      live invocations: peer, age, bytes,
                                                      handles, labels, counters
synch socket kill <invocation>                        end one; the stream closes Killed
synch socket log <space>/<path>                       what its sy_log calls said
synch socket sdk                                      print the C SDK header, from the
                                                      build that defines the ABI
synch socket build <file.c> [-o <file.o>]             compile C to the eBPF object a
                   [-D NAME[=VALUE]]… [--clang]       socket is made of; --clang uses
                                                      optimized system clang/llc

synch socket connect <origin>:<space>/<path>                 stdio by default: stdin → stream,
              [--meta k=v]…                           stream → stdout, exit code from
              [--listen <addr:port>] [--once]         Closed{status}
```

`synch socket ls -l` prints, per socket, what the tree currently names and
what that content's manifest declares — the same parse admission uses — so an
update whose manifest does not parse is visible as `activated, unavailable`
with the parse error, rather than only as connection failures.

`synch socket ps` reads the registry, which is what `kill` pulls, what the
concurrency cap counts, and what `log` keeps a tail in. It holds nothing
durable: a restart has no live invocations by definition, and recent log lines
and fault history are working state rather than a record — what a socket did is
what it wrote to whatever it was talking to.

`synch socket sdk` prints the header from the binary that defines the ABI.
A header on disk beside the binary is one that can be older than the binary,
and the numbers in it are the guest's only view of the ABI: a guest compiled
against a stale one gets wrong answers rather than errors.

On supported builds, `synch socket build` defaults to [tinycc], targeting eBPF
and linked into the binary. It runs in the CLI process: it needs no node, no
daemon and no data directory, and it supplies `synch.h` itself, so the first
socket somebody writes costs them a text editor and nothing else. A clang built
with the BPF backend is shipped inconsistently and macOS does not ship one at
all; requiring that toolchain before the first twenty lines of C is how a
capability goes unused.

Pass `--clang` when the program benefits from optimized code and compatible
`clang` and `llc` executables are on `PATH`. The command runs clang at `-O2` to
produce LLVM IR, then llc for BPF v3 with the runtime's 16 KiB stack frame.
It supplies the same `synch.h`, defines, and output handling as the embedded
path. Between the two tools it rewrites the memory intrinsics clang emits for
a large initializer or struct assignment into `sy_memset`/`sy_memcpy` calls:
llc would otherwise lower one past its store budget into a call to libc, and
the BPF backend, having no libc, refuses to emit it ("A call to built-in
function 'memset' is not supported"). Either object deploys exactly the same way because the runtime loads ELF
and does not care which compiler wrote it. tinycc is LGPL-2.1 and is linked
statically, under §6 of that licence.

[tinycc]: https://github.com/losfair/tinycc

Worked examples — an echo, an identity report, a read-only view of one
directory, a status page over HTTP, a proxy written twice (once copying through
a buffer, once splicing), and a shared-secret gate — are in
`crates/synch-sock/examples/`, compiled and *run* by the test suite on every
build against the same runtime that serves them.

### 9.1 Where the listener runs

DESIGN.md §9.1 is categorical that the daemon owns the node and the CLI is only
a client of it — one endpoint, one lifecycle, no second iroh endpoint sharing
the device key. `synch socket connect` obeys that: it opens a bidirectional
control-socket stream, and the daemon bridges it to a QUIC stream on the remote
node.

In `--listen` mode the **TCP listener lives in the CLI process**, not the
daemon, and each accepted connection opens another control stream. So the
foreground process owns the public port, closing it ends the exposure, and the
daemon never holds a listening socket it was not configured with. A
daemon-hosted persistent forward is a reasonable thing to want and is listed
under future work, where it can be given a config file and a lifecycle of its
own.

## 10. Limits and failure

| Bound | Default | Note |
| --- | --- | --- |
| Concurrent invocations per socket | 64 | Intersected with the manifest's and the activation's `max_streams`. Over it: `Refused{Busy}`. |
| Concurrent invocations per daemon | `workers × 64` | The pool-wide bound, taken as an admission token and given back when the invocation ends or the admission is dropped. Enforced atomically by the registry's `reserve`, so concurrent opens across different sockets cannot walk past it; over it: `Refused{Busy}`. It is a daemon-protection bound, not a quota — one caller who can reach every activated socket in the cluster must not be able to fill every worker's queue. |
| Socket workers per daemon | `min(4, cores)` | Dedicated threads; sockets never run on the sync runtime's threads. |
| Handles per invocation | 256 | Including `SY_SELF`. Also the `sy_poll` array cap (`limits.rs`, and §7.5 and the SDK header agree). Deliberately larger than any one resource's own bound; the bounds below are what stop spare slots becoming host memory or OS children. |
| Open endpoints per invocation | 32 | Including `SY_SELF` — the pre-256 table size, kept for everything ring-bearing. A per-role budget can be given back while its endpoint still holds rings (a closed process handle leaves its stdio endpoints, a wire-closed channel leaves the guest's fd, an ended egress task returns its permit), so endpoints are counted where they enter the table; over it, the opening helper returns `SY_ELIMIT`. |
| Live child processes per invocation | 16 | Pipe and PTY spawns together, counted as held process handles; over it, spawn returns `SY_ELIMIT`. Close a finished process to give its place back. |
| Open PTY masters per invocation | 16 | A master carries a full ring before any child is attached; over it, `sy_pty_open` returns `SY_ELIMIT`. |
| Open file-transfer endpoints per invocation | 16 | Each carries a ring and a bridge pipe; over it, `sy_sftp_open` returns `SY_ELIMIT`. |
| Outbound TCP per invocation | 8 | Beyond it, `sy_tcp_connect` returns `SY_ELIMIT`. A place is held by the connection's own task and given back when that task ends, not when the guest closes the handle — so the bound covers name resolution in flight, which `sy_close` cannot cancel, and not just established connections. |
| rx / tx ring per endpoint | 256 KiB each | A full ring stops the host reading, which backpressures the far side. |
| Host-side footprint per invocation | 1 MiB | Object table, decoded buffers, cursors. |
| Guest stack | `max(32 KiB, 8 × frame size)` | Plus 512 B of calldata. Frames are 16 KiB and guarded by default on hosts with pages up to 16 KiB; larger-page hosts warn and fall back to contiguous frames. Sizes from 16 B through 32 KiB may be declared. |
| JIT code per program | 1 MiB | async-ebpf's default; on arm64 a single ELF section is additionally capped near 1 MiB. |
| Program ELF size | 4 MiB | Checked at inspection and again at admission, so a synced or freshly deployed tree cannot serve an object past the bound. |
| Timeslice | 1 ms / 20 ms / 100 ms | Yield / throttle threshold / throttle sleep. zeroserve's numbers. |
| Idle deadline | 300 s | Measured from the last *progress* — bytes read, written or spliced — not from the start of the invocation. Progress pushes it out, so there is still **no total wall-clock cap**: a proxy with steady traffic is long-lived. Readiness alone is not progress: a poll that comes back with a terminal or bogus handle ready is ready forever, and counting that would let a guest re-poll a dead handle with the deadline never arriving. But the deadline is a deadline: an invocation that stops making progress is ended with `Closed{Deadline}`, because an idle invocation is a stream and a slot a caller can hold open forever while its guest spins a throttled loop into a worker. A program whose every handle has hung up is told so at once rather than waited out: nothing that can become ready means waiting for nothing. |
| Teardown drain | 5 s | One budget for the whole end of an invocation, spent by every endpoint that still owes bytes at once. A program returning is not its last write landing: what `sy_write` accepted is in a ring the host owns, and every endpoint — the caller's stream and everything the program connected to — half-closes and drains before it is dropped. A bound rather than a promise: an upstream that has stopped reading would otherwise hold a concurrency slot open with nothing to show for it. |
| Endpoints draining at once | 8 | The outbound cap again, applied to the ones the guest has closed. A closed endpoint keeps its socket and its tx ring until it drains, so an invocation can hold up to twice the outbound limit of them; past this, the oldest is dropped where it stands rather than accumulating rings. |
| Socket map | 4096 keys / 1 MiB | Per socket. Expired entries are reclaimed; a full map fails `sy_map_set` rather than evicting live state. |
| Guest duration inputs | `u32::MAX` ms (~49.7 days) | Rate-limit windows and map TTLs are clamped, not refused: the memory-only map cannot honestly promise longer, and the clamp keeps every host-side duration computation in range — `Duration::as_nanos` must not truncate into a zero window width, and `Instant + Duration` must not overflow. |
| `Open` frame | 9 KiB | Derived, not chosen: `MAX_KEY_LEN` (4 KiB, the §12 trie-key bound) + 4 KiB of metadata across ≤ 16 pairs + 1 KiB for the origin, the space and postcard's varints. A cap below what a legal frame carries would be a wedge — the resolver is deterministic, so an over-cap `Open` is over it on every retry. |
| `Open` handshake | 120 s, 8 per connection | The shared accept path's per-stream timeout and per-connection in-flight cap, applied to the one phase of a socket stream that has no runtime of its own: a stream that never finishes its `Open` is not an invocation, and without a bound it would own a task and a buffer for as long as the peer keeps the connection. The bound ends the moment the `Open` is admitted — a socket that proxies is supposed to be long-lived, and its concurrency bound is the effective `max_streams`, not this. |
| Activated sockets per space | 64 | An activation is operator state; this is a sanity bound, not a quota. |
| Tree-write declarations per program | 16 | Like the other per-family declaration caps (`docs/TREE-WRITES.md` §8). |
| Open tree writers per invocation | 4 | Each holds a 256 KiB staging buffer and, engine-side, a staging file; counted as their own role, like endpoints, not charged to the footprint. Over: `sy_put_open` returns `SY_ELIMIT`. |
| Tree-writer staging buffer | 256 KiB | Full is backpressure: `SY_EAGAIN`, poll `SY_POLL_OUT`. |
| Bytes per tree-write commit | declared `max_bytes`, default 16 MiB | Enforced as bytes enter staging (`SY_ELIMIT`), never at commit. `0` = unbounded, printed loudly at arm. |
| Tree-write commits per invocation | 64 | Deletes included. A sanity bound on heads-per-stream, not a quota; a program with many files to publish batches them into fewer, larger objects. |

| What happens | Stream | And then |
| --- | --- | --- |
| Program returns `n` | clean FIN | `Closed{Ok(n)}`. `synch socket connect` exits `n & 0xff`. Bytes still queued to any endpoint drain first, inside §10's teardown budget. |
| Idle deadline reached | clean FIN | `Closed{Deadline}`, exit 73. The deadline is measured from the last progress, so a proxy with traffic never sees it; a caller holding a stream open with nothing happening is ended and told to come back. |
| Caller's connection dies, or its stream resets | — | `Closed{Deadline}` to whoever still holds the control stream. Nothing the guest produces can be delivered to a caller whose transport has failed, so the runtime ends the invocation rather than holding a slot, a worker placement and its rings for it — one caller must not be able to pin every stream on a socket and then disconnect. The same ending covers a caller that FINs cleanly and *then* closes the connection: the stream itself never fails (the runtime's reader has already exited on the FIN), so `sync/sock/1` watches `Connection::closed` and signals the invocation separately. A caller's clean FIN alone is not this: a half-close is normal, and a proxy works past it. |
| Memory fault or trap | clean FIN | `Closed{Fault}`, exit 70. async-ebpf's SIGSEGV handler contains it: the invocation dies, the worker does not. |
| Faults on ≥ 8 of the last 16 invocations, from ≥ 2 different callers | — | One loud error in the daemon's log naming the program root. Nothing is deactivated for it — activation is the operator's statement about the path, not a judgement about these bytes, and the remedy is deploying a fixed program, which also clears the window. Faults are attributed to the caller whose invocation faulted, and the breadth is the point: any input-triggered bug in a program is a contained fault, and a caller who finds one can repeat it, so a window that counted faults alone would let whoever reached the socket first fill the log for everyone. A program that is genuinely broken faults for whoever asks. |
| Manifest invalid, no stream entrypoint, or JIT/link failure | refused | `Refused{ProgramInvalid}` naming the defect. The manifest parse and a stream-entrypoint check run at every admission; `synch socket inspect` runs the same checks plus an eager load before anything is deployed, because async-ebpf compiles functions lazily and a bad function would otherwise surface mid-stream. The path stays activated and published: deploying a fixed object is the remedy. |
| Bytes changed under an activated socket | served | A deployment: the next admission runs the new root, in-flight invocations keep their snapshot, and the per-socket map clears. A replacement landing *during* one admission refuses it `Refused{NotActivated}`; the retry lands on the new program. |
| Egress to an undeclared destination | stays open | `SY_EPERM` from `sy_tcp_connect`. The host logs it once per socket per hour. |
| Daemon shutdown | clean FIN | `Closed{Shutdown}` for every live invocation, inside the SIGTERM budget §9 already allows for. |
| Preemption watcher failed | refused | That worker refuses new runs — async-ebpf checks this itself rather than risk a guest that cannot be interrupted. Surfacing the degraded worker count in `synch doctor` is not built. |
| A socket is at its concurrency cap | refused | `Refused{Busy}` naming the cap. The slot is taken at *admission* and released when the invocation ends or the admission is dropped, so a caller that opens streams and never uses them cannot walk through the cap. |

## 11. What this changes in the existing design

- **§8, version identity.** Today identity is the content root for regular files
  and `(kind, target)` for content-less kinds. A `Socket` has content, so
  `nas`'s socket and `laptop`'s plain file over the same ELF would collapse into
  one unanimous version. Identity becomes `(kind-class, content root)`, where
  `Socket` is its own class. Two origins agree about a socket only if they agree
  that it *is* one.
- **§4.2, schema.** One new `EntryKind` discriminant, and nothing else:
  `RECORD_VERSION` stays at 1 and every existing record encodes to the same
  bytes it did before (§2). Postcard is not self-describing, so a node too old
  to know the discriminant fails to decode that record — which §12 already
  scopes correctly ("a record this node cannot apply fails its own origin and no
  other"), but it does mean one socket entry stalls the publisher's whole head
  on old peers. That is unavoidable for any new kind and is the reason the
  rollout order is: upgrade, then activate.
- **§4.1, redaction boundary.** The new record type is checked against the prefix
  rule, as §4.1 requires. It passes without a new rule because it is not a new
  record type: it is a field on `f:`, entirely inside the space prefix a
  delegation already projects.
- **§12, a new capability to name.** Membership currently grants read access and
  publish rights. It now also grants the ability to *invoke* programs at paths
  the callee has activated. The security section should say that plainly,
  alongside the mitigations: the callee chose every activated path, the caller
  supplies no code, and every capability is declared in the object itself.
  `synch socket ls -l` lists every activated socket and what its current
  content declares; surfacing the same in `synch doctor` is not built.
- **§11, crate layout.** A new `synch-sock` crate holds the helper table, the
  endpoint and reactor machinery, the program cache and the manifest reader; it
  depends on `async-ebpf` and is gated to the platforms that crate supports.
  `synch-engine` owns the worker pool and the trie/CAS resolution; `synch-net`
  gains the `sync/sock/1` protocol handler beside the two it already mounts. The
  engine crate stays embeddable — a library user gets sockets by enabling a
  feature, not by taking a dependency it cannot build.
- **§10, schema.** One table: `socket_activations` (space, path, config,
  max streams, note, activated_at). Local operator state, never published or
  replicated. The map store is memory-only and deliberately absent from
  SQLite.

## 12. Non-goals, and what comes after

An earlier revision's first non-goal — *writing to the tree from a program* —
has since been designed and built: **[docs/TREE-WRITES.md](TREE-WRITES.md)**,
the `sy_put_*` family behind the manifest's tree-write declaration (§7.12).

Not in this design:

- **Listening sockets opened by a program.** Outbound TCP only. A program that
  could bind a port would be a service the operator never configured.
- **UDP, QUIC or raw sockets as egress**, and no TLS termination inside the
  guest. A program that needs TLS speaks to an upstream that terminates it.
- **Shared memory or maps between invocations** beyond `sy_map_*`. The data
  region is read-only after link and that is load-bearing, not incidental.
- **Running a peer's program**, under any flag, at any trust level. This is the
  rule the whole design is built on.
- **Serving sockets on Windows**, until async-ebpf runs there. macOS is
  supported on x86-64 and arm64.

Worth building next:

- **Datagram and unidirectional streams.** One invocation per datagram would
  suit metrics and notification sockets, where a bidirectional stream is all
  overhead.
- **`synch socket forward`** — a daemon-hosted listener with a lifecycle, for
  the case `synch socket connect --listen` is currently standing in for.
- **`sy_synch_connect(origin, path)`** — a socket calling another node's socket
  over iroh rather than TCP, so a composition of sockets stays inside the
  authenticated fabric instead of falling back to the network underneath it.
- **Signed activation records.** Activation is local state today. An operator
  with many nodes would rather activate a path once and have every node honour
  it, which is a delegation-shaped problem and should reuse §3.5 rather than
  invent a second grant format.
- **A Rust SDK** beside the C header, following zeroserve's lead — the helper
  surface is small enough that safe wrappers around the handle table are a
  weekend, and a `#![no_std]` guest with real types is a better place to write
  forty lines of protocol than C is.
