# Sockets

Status: **implemented**, except the live-invocation surface — `synch socket ps`,
`kill` and `log` — which §12 records as not built. Everything else here
describes the built thing: the record kind, the arming tables, the
`sync/sock/1` protocol, the host API and its runtime, the scanner's publishing
rule, and the command surface.

Checked against the tree it landed in. Where the built thing differs from an
earlier draft of this design, this document has been corrected to describe the
built thing, and says so at each point.

A **socket** is a file in a node's published tree whose content is an eBPF ELF
object. A peer runs `synch connect nas:code/git.sock`; the connection lands on
`nas`, which resolves that path *in its own trie*, loads the object from *its
own* CAS, and runs it under [async-ebpf][ae] — one invocation per incoming
stream. The caller supplies bytes and a verified identity. It never supplies
code.

[ae]: https://github.com/losfair/async-ebpf
[zs]: https://github.com/losfair/zeroserve

The host API is designed against [zeroserve][zs], which runs the same runtime
per HTTP request: flat `extern` helpers, `(ptr, len)` string pairs, `snprintf`
return semantics, small-integer handles into host-side tables, and entrypoints
named by ELF section.

## 1. The asymmetry everything follows from

A socket has two sides and they are not mirror images.

> **A node executes only eBPF that is present in its own published tree.**
> Therefore the connecting side ships bytes, not programs — and needs no eBPF
> runtime at all.

The client half of `synch connect` is a byte pump. The server half is the whole
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
the *gate* is that the callee already chose to publish and arm the program.

It also buys portability where it matters. async-ebpf runs on Linux and OpenBSD
on x86-64 and arm64. Serving sockets is gated to those targets. `synch connect`
is not, because it executes nothing.

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
BLAKE3 root (this is what gets armed), `size` is its length, and `chunking` is
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
`unix_mode`, and unlike content. It comes from a local declaration (`synch
socket add`, §3), never from a peer. So:

- `synch take nas:code/git.sock` fetches the ELF bytes and writes them into the
  local space. The next scan publishes them as `EntryKind::File`, because this
  node never declared that path a socket. **Adopting a socket adopts its bytes,
  not its socket-ness** — and certainly not its executability.
- `synch fill`, `synch mirror sync` and the S3 gateway behave identically: a
  `Socket` entry materializes as a regular file containing the ELF, which is
  exactly what it is on the publisher's disk too.
- A path where `nas` publishes `Socket` and `laptop` publishes `File` over the
  same bytes is *divergent*, not unanimous. That needs a small amendment to §8's
  version-identity rule (§11).

### 2.3 Selection does not apply

Reading a bare `<space>/<path>` picks a version by policy — `newest`,
`origin=`, `strict` (§8). **Connecting to one does not.** `synch connect`
requires an origin-qualified path, always, and the node resolves it in that
origin's trie only. There is no "the socket at `code/git.sock`"; there is only
"nas's socket".

`newest` would otherwise let any member's `mtime_ns` decide whose program a
connection lands on, and §12 already names member-supplied `mtime_ns` as the
sharpest edge of the version model. The unified tree stays a discovery surface
here and never a dispatch one.

## 3. Arming: how code gets into a node's own tree

"Only its own tree" is a strong rule, but a node's own tree is not a closed
system. Several existing commands write bytes into a space directory that the
scanner then publishes as this node's own view. Enumerating them is the whole
threat model:

- your editor, which is the intended path;
- `synch take`, which adopts a peer's bytes;
- `synch fill --force`, which does the same in bulk;
- an S3 gateway `PUT`, which writes into a space directory over the network.

Every one of these is an existing, sanctioned way to change what this node
publishes. So publication is not, and must not be, the gate. Two locally-held
gates stand between a published socket entry and an invocation:

1. **Declaration.** `synch socket add code/git.sock` records that this path, in
   this space, is a socket. That is what makes the scanner publish
   `kind: Socket`. It is local state, never adopted from a peer, and never
   replicated.
2. **Arming.** The declaration pins the BLAKE3 content root it approved. The
   bytes changing changes the root, which disarms the socket: `Refused
   { NotArmed }`, naming both roots. In-flight invocations keep running the root
   they started on.

`synch socket add --auto` follows the file: it re-arms on every content change
and skips the second gate forever. It is correct for a path you are the only
writer of and wrong for any path an S3 key, a fill or a take can reach. `synch
socket ls` marks every `--auto` socket, because that list is the honest answer
to "what can execute here?", and `synch socket add` says what `--auto` costs at
the moment it is asked for.

### 3.1 The init hook is what makes arming meaningful

An approval that says only "these bytes are fine" asks the operator to read
eBPF. Instead the program declares its own external effects in a
`synchronicity.init` section, run once at arm time in a context with no
endpoint table at all, and `synch socket arm` prints the declaration for
approval:

```
$ synch socket arm code/git.sock

  program   9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  size      41 KB  ·  jit 214 KB  ·  sections: init, stream
  declares  name        git-http
            egress      git.internal:9418
            max streams 32
            tree reads  code/**  (own origin)
  operator  --allow-egress git.internal:9418        ← from `socket add`

  arm this program? [y/N]
```

Runtime policy is the **intersection** of what the program declared and what
the operator allowed; egress with no declaration is denied. Because the
declaration is compiled into the object, editing it changes the content root,
which disarms the socket. A program cannot widen its own reach without a fresh
approval, and an approval cannot silently outlive the code it approved.

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
    NoSuchPath, NotASocket, NotArmed, Unauthorized, SpaceNotDelegated,
    Busy, ProgramInvalid, Unsupported,       // Unsupported = callee has no runtime
}

// callee → caller, one uni-stream per connection, opened at connection setup
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
- **Inside the program** — `sy_peer_origin()`, `sy_peer_kind()` and
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

So the guest has **32 KiB of stack** (eight local-call frames of 4 KiB, plus
512 bytes of calldata), **no heap**, and **no mutable globals**. Everything that
outlives a helper call lives host-side:

The number that binds in practice is the **4 KiB frame**, not the 32 KiB total.
One function's locals must fit in one frame, so a `char[4096]` buffer does not
compile even though the stack is eight times that: it fills the frame and
leaves no room for the handles and counters beside it. Programs are also
compiled with `-mllvm -bpf-stack-size=4096`, because LLVM's default BPF frame
is 512 bytes and nothing useful fits in that.

| Table | Scope | Bound |
| --- | --- | --- |
| endpoint table | per invocation | 16 handles, `SY_SELF` included |
| object table | per invocation | 32 objects, 1 MiB footprint |
| socket map | per socket, outlives invocations | 4096 keys, 1 MiB, TTL then LRU |

The socket map is the only way two invocations of one socket can see each
other. It is memory-only: cleared on daemon restart and on re-arm, and
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

Shipped as a single header, `synch --dump-sdk > synch.h`.

```c
#define SY_STR(s)   (s), sy_strlen((s))
#define SY_SELF     0                    /* the inbound stream is always handle 0 */

#define SY_ENTRY        __attribute__((section("synchronicity.stream")))
#define SY_INIT_ENTRY   __attribute__((section("synchronicity.init")))

#define SY_EAGAIN     -1   /* would block — poll and come back                    */
#define SY_EBADF      -2   /* no such handle in this invocation                   */
#define SY_EINVAL     -3
#define SY_EPERM      -4   /* policy: egress not declared/armed, path out of scope */
#define SY_ECONNRESET -5
#define SY_ETIMEDOUT  -6
#define SY_ELIMIT     -7   /* a documented bound in §9 was hit                    */
#define SY_ENOENT     -8
#define SY_EPIPE      -9   /* write after the peer's read side went away          */

#define SY_POLL_IN   0x1   /* readable, or EOF is pending                         */
#define SY_POLL_OUT  0x2   /* tx window has room; a connecting socket is up       */
#define SY_POLL_HUP  0x4   /* peer half-closed                                    */
#define SY_POLL_ERR  0x8   /* sy_errno(h) says what                               */

struct sy_pollfd { sy_s64 handle; sy_u32 events; sy_u32 revents; };
struct sy_stat   { sy_u64 size; sy_s64 mtime_ns; sy_u32 mode; sy_u32 kind; sy_u8 root[32]; };
```

### 7.1 Diagnostics and configuration

| Helper | What it does |
| --- | --- |
| `sy_log(msg, len)` | Line-buffered to the daemon log, tagged with socket path and invocation id. Non-ASCII and control bytes replaced. |
| `sy_now_ms()` | Wall clock, milliseconds. Never used for ordering — that lesson is in §4.4. |
| `sy_monotonic_ns()` | Monotonic since invocation start. What a timeout should be written against. |
| `sy_getrandom(out, len)` | CSPRNG bytes. |
| `sy_version(out, len)` | The daemon's version string. |
| `sy_config_get(k, klen, out, olen)` | Reads a key from `synch socket add --config k=v`. |
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
| `sy_peer_kind()` | `1` rooted member, `2` delegate. |
| `sy_peer_has_space(s, len)` | Whether the caller may read that space. The one-line way to write "only people I gave `code` to". |
| `sy_peer_addr(out, len)` | Remote transport address. Informational — it can be a relay. |
| `sy_conn_meta(k, klen, out, olen)` | A key from the caller's `Open.meta`. **Untrusted input.** |
| `sy_stream_index()` | Ordinal of this stream within the caller's connection. |

### 7.3 Endpoint I/O — never blocks

| Helper | What it does |
| --- | --- |
| `sy_read(h, buf, len)` | Bytes out of the rx ring; `0` at clean EOF; `SY_EAGAIN` when empty and open. |
| `sy_write(h, buf, len)` | Bytes accepted into the tx ring. A *short count is normal* and is the backpressure signal. |
| `sy_readable(h)` / `sy_writable(h)` | Buffered bytes / free window, for sizing a copy without a trial call. |
| `sy_shutdown(h)` | Half-close the write side once the tx ring drains. |
| `sy_close(h)` | Drop the endpoint and free the slot. `SY_SELF` may be closed; the invocation continues. |
| `sy_errno(h)` | Why an endpoint has `SY_POLL_ERR` set. |

### 7.4 Outbound connections

| Helper | What it does |
| --- | --- |
| `sy_tcp_connect(host, len, port)` | Returns a handle immediately, in *connecting* state; poll for `SY_POLL_OUT`. |
| `sy_tcp_connect_ip(addr, alen, port)` | Same, skipping DNS, for a literal address. |
| `sy_endpoint_info(h, out, len)` | Peer address and connection state of an endpoint the program opened. |

Resolution happens host-side, and **both the name and the resolved address are
checked** against the armed egress list — so a program cannot reach an internal
address by way of a name that resolves to it.

### 7.5 Poll — the only helper that suspends

`sy_poll(fds, n, timeout_ms)` waits for readiness on up to 16 handles. Returns
the number ready, `0` on timeout, negative on error; `timeout_ms < 0` means
"until something happens", clamped by the host to the invocation's idle
deadline. One validated mutable region regardless of `n`.

### 7.6 Reading the tree — verified, scoped by default to this origin

| Helper | What it does |
| --- | --- |
| `sy_open(path, len)` | Opens `space/path` **in this node's own trie** — the same scope the program came from. Refuses a `Socket` entry, so a socket cannot read out its neighbours' code. |
| `sy_open_from(origin, olen, path, plen)` | Another origin's version. Requires `--allow-tree-read`; §8's mtime-trust caveat is why it is not the default. |
| `sy_open_root(root32)` | By content root — how a superseded version is read, mirroring `synch cat --root`. |
| `sy_stat(obj, out, len)` | Fills a `struct sy_stat`. |
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

`sy_memcpy`, `sy_memcmp`, `sy_memset`, `sy_strlen`, `sy_ct_eq` (constant time),
`sy_blake3`, `sy_sha256`, `sy_hmac_sha256`, `sy_base64_encode`,
`sy_base64_decode_in_place`, `sy_hex_encode`, `sy_hex_decode_in_place`.

`sy_blake3` is first-class because content roots are BLAKE3: a program can
verify what it just read against what the tree said. The in-place decoders exist
because there is no heap to decode into.

### 7.9 Declarations — valid only inside `synchronicity.init`

`sy_declare_name`, `sy_declare_egress(host, len, port)` (port `0` means any port
on that host and is printed in red at the arm prompt), `sy_declare_tree_read`,
`sy_declare_max_streams`.

Calling a declaration helper from `synchronicity.stream` returns `SY_EPERM`;
calling an I/O helper from `synchronicity.init` does too. The init hook runs
with no endpoint table at all, so there is nothing for it to reach.

## 8. A whole socket, end to end

A git-over-TCP gateway for a delegated space: authorized by delegation rather
than by a password, rate-limited per caller, and reaching exactly one upstream.

```c
#include <synch.h>

/* Runs once, at `synch socket arm`. The operator reads this list, not the code. */
SY_INIT_ENTRY sy_s64 declare(void) {
  sy_declare_name(SY_STR("git-http"));
  sy_declare_egress(SY_STR("git.internal"), 9418);
  sy_declare_max_streams(32);
  return 0;
}

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

  /* 3. The one destination this program declared and the operator armed. */
  sy_s64 up = sy_tcp_connect(SY_STR("git.internal"), 9418);
  if (up < 0) return up;

  struct sy_pollfd fds[2] = {
    { SY_SELF, SY_POLL_IN, 0 },
    { up,      SY_POLL_IN, 0 },
  };
  /* The binding limit is the *frame*, not the stack: 4 KiB per function, of
     which `who`, `key` and `fds` have already taken a little. A `char[4096]`
     here does not compile. */
  char buf[2048];

  /* Each direction ends on its own. A loop that stopped the moment either
     side hung up would cut off the reply to the last request it forwarded,
     which is the single most common way to get this wrong. */
  int upstream_done = 0, caller_done = 0;
  while (!(upstream_done && caller_done)) {
    if (sy_poll(fds, 2, 30000) <= 0) break;  /* 0 = 30s idle; negative = deadline */

    if (fds[0].revents & SY_POLL_IN) {
      sy_s64 n = sy_pump(SY_SELF, up, buf, sizeof buf);
      if (n == 0) { sy_shutdown(up); caller_done = 1; fds[0].events = 0; }
      else if (n < 0 && n != SY_EAGAIN) break;
    }
    if (fds[1].revents & SY_POLL_IN) {
      sy_s64 n = sy_pump(up, SY_SELF, buf, sizeof buf);
      if (n == 0) { sy_shutdown(SY_SELF); upstream_done = 1; fds[1].events = 0; }
      else if (n < 0 && n != SY_EAGAIN) break;
    }
    if ((fds[0].revents | fds[1].revents) & SY_POLL_ERR) break;
  }

  sy_close(up);
  return 0;                                  /* → Closed{ Ok(0) } */
}
```

`sy_pump` is in the header: it reads once, writes what it can, and leaves any
remainder for the next poll rather than dropping it. A short write is
backpressure, not failure, and writing that loop by hand is where the second
most common mistake lives.

The `HUP` bit is reported only once an endpoint's buffer has drained, which is
what makes the loop above safe: a peer that half-closes after sending a request
is `SY_POLL_IN` with data waiting, not `SY_POLL_HUP`, so a program that breaks
on `HUP` still gets to read what it was sent.

Forty lines, no heap, no globals, one upstream, and an access-control rule that
a caller cannot lie its way past. The pieces this design exists to provide are
all visible: an identity that came from the transport, a limit that outlives the
invocation, an egress approved in advance, and a poll loop that is the only
place the program sleeps.

## 9. Command surface

```
synch socket add <space>/<path> [--config k=v]…       declare a path in one of my spaces
                 [--allow-egress <host>[:<port>]]…    to be a socket: publishes it as
                 [--allow-tree-read <prefix>]…        kind=Socket and arms the content
                 [--max-streams <n>] [--auto]         root it has now
synch socket arm <space>/<path> [--root <hex>]        approve the current bytes, after
                                                      printing what they declare
synch socket disarm <space>/<path>                    keep publishing it, stop running it
synch socket rm <space>/<path>                        republish as an ordinary file
synch socket ls [<space>] [-l]                        mine: armed root, drift, declarations
synch socket sdk                                      print the C SDK header, from the
                                                      build that defines the ABI

synch connect <origin>:<space>/<path>                 stdio by default: stdin → stream,
              [--meta k=v]…                           stream → stdout, exit code from
              [--listen <addr:port>] [--once]         Closed{status}
```

`synch socket ls -l` prints, per socket, what the tree currently names, what
was armed, and what the program declared when it was armed — so "the bytes
changed and nobody re-approved them" is visible as a difference between two
lines rather than inferred.

`synch socket sdk` prints the header from the binary that defines the ABI.
A header on disk beside the binary is one that can be older than the binary,
and the numbers in it are the guest's only view of the ABI: a guest compiled
against a stale one gets wrong answers rather than errors.

### 9.1 Where the listener runs

DESIGN.md §9.1 is categorical that the daemon owns the node and the CLI is only
a client of it — one endpoint, one lifecycle, no second iroh endpoint sharing
the device key. `synch connect` obeys that: it opens a bidirectional
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
| Concurrent invocations per socket | 64 | Intersected with `sy_declare_max_streams`. Over it: `Refused{Busy}`. |
| Socket workers per daemon | `min(4, cores)` | Dedicated threads; sockets never run on the sync runtime's threads. |
| Endpoint handles per invocation | 16 | Including `SY_SELF`. Also the `sy_poll` array cap. |
| Outbound TCP per invocation | 8 | Beyond it, `sy_tcp_connect` returns `SY_ELIMIT`. |
| rx / tx ring per endpoint | 256 KiB each | A full ring stops the host reading, which backpressures the far side. |
| Host-side footprint per invocation | 1 MiB | Object table, decoded buffers, cursors. |
| Guest stack | 32 KiB | Fixed by async-ebpf: 8 local-call frames of 4 KiB, plus 512 B of calldata. |
| JIT code per program | 1 MiB | async-ebpf's default; on arm64 a single ELF section is additionally capped near 1 MiB. |
| Program ELF size | 4 MiB | Checked at arm time, not at connect time. |
| Timeslice | 1 ms / 20 ms / 100 ms | Yield / throttle threshold / throttle sleep. zeroserve's numbers. |
| Idle deadline | 300 s | Measured from the last *progress* — bytes copied in or out, or a poll that came back with a handle ready — not from the start of the invocation. There is deliberately **no total wall-clock cap**: a proxy is supposed to be long-lived, and CPU is bounded by the throttler instead. A program whose every handle has hung up is told so at once rather than waited out: nothing that can become ready means waiting for nothing. |
| Socket map | 4096 keys / 1 MiB | Per socket. TTL then LRU; a full map fails `sy_map_set` rather than evicting silently. |
| `Open` frame | 9 KiB | Derived, not chosen: `MAX_KEY_LEN` (4 KiB, the §12 trie-key bound) + 4 KiB of metadata across ≤ 16 pairs + 1 KiB for the origin, the space and postcard's varints. A cap below what a legal frame carries would be a wedge — the resolver is deterministic, so an over-cap `Open` is over it on every retry. |
| Declared sockets per space | 64 | A declaration is operator state; this is a sanity bound, not a quota. |

| What happens | Stream | And then |
| --- | --- | --- |
| Program returns `n` | clean FIN | `Closed{Ok(n)}`. `synch connect` exits `n & 0xff`. |
| Memory fault or trap | clean FIN | `Closed{Fault}`, exit 70. async-ebpf's SIGSEGV handler contains it: the invocation dies, the worker does not. |
| Faults on ≥ 8 of the last 16 invocations | — | *Not built.* The thresholds are written down and nothing counts against them yet — see §12. |
| JIT or link failure | refused | `Refused{ProgramInvalid}`. async-ebpf compiles functions lazily, per function and per pointer signature, so this can surface on the first stream that reaches a given path; `synch socket arm` therefore loads and runs the program's init hook, which forces the compilation early — a program that will not load cannot be armed. |
| Bytes changed under an armed socket | refused | `Refused{NotArmed}` naming both roots. In-flight invocations keep their root. |
| Egress to an unarmed destination | stays open | `SY_EPERM` from `sy_tcp_connect`. The host logs it once per socket per hour. |
| Daemon shutdown | clean FIN | `Closed{Shutdown}` for every live invocation, inside the SIGTERM budget §9 already allows for. |
| Preemption watcher failed | refused | That worker refuses new runs — async-ebpf checks this itself rather than risk a guest that cannot be interrupted. Surfacing the degraded worker count in `synch doctor` is not built. |

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
  rollout order is: upgrade, then declare.
- **§4.1, redaction boundary.** The new record type is checked against the prefix
  rule, as §4.1 requires. It passes without a new rule because it is not a new
  record type: it is a field on `f:`, entirely inside the space prefix a
  delegation already projects.
- **§12, a new capability to name.** Membership currently grants read access and
  publish rights. It now also grants the ability to *invoke* programs the callee
  has armed. The security section should say that plainly, alongside the
  mitigations: the callee chose and armed every program, the caller supplies no
  code, and egress is declared and approved in advance. `synch socket ls -l`
  lists every armed socket and what it was armed for; surfacing the same in
  `synch doctor` is not built.
- **§11, crate layout.** A new `synch-sock` crate holds the helper table, the
  endpoint and reactor machinery, the program cache and the arming logic; it
  depends on `async-ebpf` and is gated to the platforms that crate supports.
  `synch-engine` owns the worker pool and the trie/CAS resolution; `synch-net`
  gains the `sync/sock/1` protocol handler beside the two it already mounts. The
  engine crate stays embeddable — a library user gets sockets by enabling a
  feature, not by taking a dependency it cannot build.
- **§10, schema.** Two tables: `sockets` (space, path, config, allowed egress,
  allowed tree reads, max streams, auto flag) and `socket_arms` (space, path,
  approved root, declarations as approved, armed_at). Both are local operator
  state and neither is ever published or replicated. The map store is
  memory-only and deliberately absent from SQLite.

## 12. Non-goals, and what comes after

Not in this design:

- **Writing to the tree from a program.** Publishing is the scanner's job and
  stays that way. A remotely-triggered publish path is a much larger surface
  than a remotely-triggered read one, and nothing here needs it.
- **Listening sockets opened by a program.** Outbound TCP only. A program that
  could bind a port would be a service the operator never configured.
- **UDP, QUIC or raw sockets as egress**, and no TLS termination inside the
  guest. A program that needs TLS speaks to an upstream that terminates it.
- **Shared memory or maps between invocations** beyond `sy_map_*`. The data
  region is read-only after link and that is load-bearing, not incidental.
- **Running a peer's program**, under any flag, at any trust level. This is the
  rule the whole design is built on.
- **Serving sockets on macOS or Windows**, until async-ebpf runs there.

Not built yet, and named in the status line:

- **`synch socket ps`, `kill` and `log`.** Watching live invocations needs a
  registry of them, which the runtime does not keep: an invocation is placed on
  a worker and known to that worker, and nothing above collects them. The parts
  that would feed it are built and unused — `sy_label_set` and `sy_metric_add`
  come back in the invocation's outcome, and the cancellation channel that
  `kill` would pull is what a daemon shutdown already uses.
- **Fault quarantine.** The thresholds are written down (`FAULT_QUARANTINE`,
  `FAULT_WINDOW`) and nothing counts against them yet, for the same reason: it
  needs the per-socket history that the same registry would hold.

Worth building next:

- **Datagram and unidirectional streams.** One invocation per datagram would
  suit metrics and notification sockets, where a bidirectional stream is all
  overhead.
- **`synch socket forward`** — a daemon-hosted listener with a lifecycle, for
  the case `synch connect --listen` is currently standing in for.
- **`sy_synch_connect(origin, path)`** — a socket calling another node's socket
  over iroh rather than TCP, so a composition of sockets stays inside the
  authenticated fabric instead of falling back to the network underneath it.
- **Signed arming records.** Arming is local state today. An operator with many
  nodes would rather approve a content root once and have every node honour it,
  which is a delegation-shaped problem and should reuse §3.5 rather than invent
  a second grant format.
- **A Rust SDK** beside the C header, following zeroserve's lead — the helper
  surface is small enough that safe wrappers around the handle table are a
  weekend, and a `#![no_std]` guest with real types is a better place to write
  forty lines of protocol than C is.
