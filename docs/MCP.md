# MCP

`synch mcp` serves the Model Context Protocol over stdin and stdout. An MCP
client — an editor, an agent runner — launches it as a child process and speaks
newline-delimited JSON-RPC to it; every request is answered from the local
daemon's control socket.

It is a client of the node exactly as `synch ls` is (DESIGN.md §9.1). It holds
no store handle, no iroh endpoint and no signing key, and it adds nothing to the
daemon: the one control-service change it needed is `ListSpaces`, and that
exists because a program that had to recover the space list by splitting a
column-aligned line would be coupled to the width of that column (§9.4).

```sh
synch daemon start
synch mcp                    # read-only, every space
synch mcp --allow-write      # plus the tools that change state
synch mcp --space media      # confined to one space
```

Configured into a client, that is usually a `command` and `args` pair:

```json
{
  "mcpServers": {
    "synchronicity": {
      "command": "synch",
      "args": ["--data-dir", "/srv/synch", "mcp", "--allow-write"]
    }
  }
}
```

## 1. Two protocol eras

MCP dropped the `initialize` handshake in revision `2026-07-28`. The protocol is
now stateless: every request declares its own version in
`_meta["io.modelcontextprotocol/protocolVersion"]`, carries the client's
capabilities beside it, and `server/discover` is mandatory. Revisions through
`2025-11-25` negotiate once and keep the result for the connection.

This server answers both, which the spec permits and calls *dual-era*, because
refusing either would refuse real clients: the modern era is where the protocol
is going and the legacy era is what most installed clients still speak. Selection
is by how the client opens, and it changes only how a message is read and how a
result is stamped — both eras land on the same tool registry and the same
control-socket calls.

| Client opens with | Served as | `resultType` |
| --- | --- | --- |
| `_meta` carrying version **and** capabilities | modern, statelessly | stamped |
| `_meta` carrying a version at or after `2026-07-28` but no capabilities | refused `-32602` | — |
| `_meta` carrying a version before `2026-07-28` | legacy at that version | absent |
| `initialize` | legacy at the negotiated version | absent |
| nothing, on a later request | legacy at the handshake's version, or the newest legacy revision | absent |

A version this build does not implement is refused with `-32022` and the list of
the ones it does, which is the whole of negotiation in the modern era. Supported:
`2026-07-28`, `2025-11-25`, `2025-06-18`.

## 2. The tool surface

Every tool is a translation of a call the control service already answers. Where
a typed RPC exists, the tool returns `structuredContent` against a declared
`outputSchema`; where only the rendered CLI surface exists, the tool runs
`Run(Command)` and returns the daemon's own lines, so nothing is re-rendered
here and no output drifts from what `synch` prints.

### Read tier — always served

| Tool | Control call |
| --- | --- |
| `synch_node` | `Run(Id)` + `Run(DaemonStatus)` |
| `synch_spaces` | `ListSpaces` |
| `synch_list` | `List` |
| `synch_stat` | `Resolve` |
| `synch_read` | `Read` |
| `synch_versions` | `Run(Status)` |
| `synch_history` | `Run(Log)` |
| `synch_compare` | `Run(Compare)`, structured — the daemon already emits JSON |
| `synch_peer_list` | `Run(PeerLs)` |
| `synch_doctor` | `Run(Doctor)` |
| `synch_socket_list` | `Run(SocketLs)` |
| `synch_socket_ps` | `Run(SocketPs)` |
| `synch_socket_log` | `Run(SocketLog)` |
| `synch_socket_sdk` | `Run(SocketSdk)` |
| `synch_socket_build` | none — the compiler is in this process |
| `synch_socket_review` | `Run(SocketArm)` with no token: inspects only |
| `synch_socket_connect` | `OpenSocket` |

### Write tier — `--allow-write`

| Tool | Control call |
| --- | --- |
| `synch_write` | `Put` |
| `synch_delete` | `Delete` |
| `synch_adopt_path` | `Run(AdoptPath)` |
| `synch_adopt_tree` | `Run(AdoptTree)` — `dry_run` defaults to true here |
| `synch_pin` | `Run(PinAdd)` / `Run(PinRm)` |
| `synch_source_scan` | `Run(SourceScan)` |
| `synch_peer_sync` | `Run(PeerSync)` |
| `synch_socket_declare` | `Run(SocketDeclare)` |
| `synch_socket_arm` | `Run(SocketArm)` with a review token |
| `synch_socket_disarm` | `Run(SocketDisarm)` |
| `synch_socket_undeclare` | `Run(SocketUndeclare)` |
| `synch_socket_kill` | `Run(SocketKill)` |

The split is by whether a tool changes state, not by how alarming it sounds. The
tool *list* reflects the tier, so a client is shown exactly the authority it was
given rather than discovering the boundary by being refused at it.

Two placements are worth stating because they are not obvious:

- **The socket lifecycle is on the surface**, with the mutating half in the
  write tier. Arming is not a blind approval of bytes: the program declares its
  external effects in a `synchronicity.init` section, `synch_socket_review`
  prints that declaration, and the token binds the content root, the
  authorization revision and the init result together (`docs/SOCKETS.md` §3.1).
  Undeclared capabilities are denied, and editing the program changes its root,
  which disarms it.

- **Connecting is a read.** The connecting side executes nothing
  (`docs/SOCKETS.md` §1): it names a path and pipes bytes. What runs is bounded
  by the declaration the *serving* node armed, which is that node's decision.

The whole socket lifecycle is reachable over the protocol without a single
filesystem write outside a space: `synch_socket_build` takes C source and
returns the object base64-encoded, `synch_write` puts it in a space,
`synch_socket_declare` declares it, `synch_source_scan` republishes it as a socket, and
`synch_socket_review` then `synch_socket_arm` approve it.

### `--space`

Repeatable, and it confines every tool *and* every resource URI. A request for a
space outside it is refused before it reaches the daemon; a resource URI outside
it is answered as though it did not exist, because a resource this server does
not serve should not be distinguishable from one that is not there.

The filter applies to `synch_socket_connect` too. A socket on a peer is still addressed
by space, and letting one through would make the filter a local-only fiction.

A tool whose space argument is optional does not inherit the wildcard: an
omitted space means *every* space to the daemon, which is the thing the filter
exists to prevent. So under `--space`, `synch_socket_list` fills in the confined
space when there is exactly one and asks which when there are several.

Three tools take no space at all and act on everything the node holds:
`synch_source_scan`, `synch_peer_sync`, and `synch_socket_ps` when it names no socket. There
is nothing in them to narrow, so under `--space` they are refused rather than
allowed to reach past the confinement. Without `--space` they behave as before.

## 3. Resources

Paths are addressable as `synch://<space>/<path>`, percent-encoded outside the
URI unreserved set. `resources/list` pages across the in-scope spaces; MCP's
opaque cursor becomes `ListRequest.start_after` and the page size becomes
`ListRequest.limit`, so a space with a million paths is paged by the daemon and
never assembled in this process.

`resources/read` returns text when the bytes are valid UTF-8 and a base64 `blob`
otherwise, with an advisory MIME type from the path's extension. A resource read
takes no offset — the protocol has no way to express one — so an object over
1 MiB is refused with `synch_read` named in the message rather than silently
truncated into something that looks like the whole file.

Declared capabilities are `tools` and `resources`, with neither `subscribe` nor
`listChanged`: the tool catalogue is fixed at process start by the flags, and the
control service has no watch call to build subscriptions on. Claiming a
subscription this process cannot deliver would be worse than not claiming one.

## 4. Failures, and what a model can do about them

A tool that fails returns `isError: true` with the daemon's own message, not a
JSON-RPC error: the spec reserves protocol errors for what a model is unlikely
to fix, and everything below is something it can act on.

| `ControlError` | What the client sees |
| --- | --- |
| `Unavailable` | The daemon's message, which names the socket and `synch daemon start` |
| `Divergent` | The versions, plus how to pin one with `policy="origin=<id>"` |
| `NotFound` | The message; on `resources/read`, `-32602`, which the spec fixes for a missing resource |
| `Invalid` | The message |
| `Unauthorized`, `VersionMismatch` | Reconnected once first; if it persists, the message |
| `Internal` | The message, and the request id on stderr |

An unknown tool is `-32602`, and a write tool called on a read-only server is an
execution error naming `--allow-write` — the tool exists, and saying so plainly
lets a model report the actual remedy instead of guessing at a typo.

## 5. Lifecycle

An MCP client launches this when *it* starts and keeps it for hours; the daemon
does not share that lifetime.

**Nothing connects eagerly.** `server/discover`, `tools/list` and
`resources/templates/list` are answered with no daemon anywhere. A tool call is
where the connection is needed and where its absence is reported.

**The connection is cached but disposable.** `control.token` is regenerated on
every daemon start (§9.3), so a channel held across a restart fails
`Unauthorized` — which reads like a security problem and is a stale token. The
session reconnects once and retries, exactly once, on the codes that mean "this
connection, not this request".

**Requests interleave.** The spec is explicit that a connection is not a
conversation. Each request runs on its own task over a cloned control channel,
which HTTP/2 multiplexes, and every response goes back through a single writer,
which keeps one message per line true under concurrency.
`notifications/cancelled` stops a request and sends nothing further for it, which
is what the spec requires.

**Progress is forwarded.** The daemon already reports what source scans, peer
exchanges, replica reconciliation, and tree adoption are doing; a client that
sends a `progressToken` gets those frames as
`notifications/progress`.

**Shutdown is on stdin closing** — the primary signal, and the only portable
one. Requests already accepted are answered first, within a ten-second grace,
because a client that writes a batch and closes its end would otherwise get
silence for work the server had already started.

## 6. Bounds

| What | Default | Ceiling |
| --- | --- | --- |
| One read (`synch_read`) | 64 KiB | `--max-read-bytes` |
| One `resources/read` | — | 1 MiB, then refused with `synch_read` named |
| Rendered command output | — | 1 MiB, and truncation is announced |
| One listing page | 200 | 1000 |
| One `synch_socket_connect` | 30 s | 300 s |
| One input line | — | 16 MiB, then the stream is not MCP |

## 7. stdout carries protocol and nothing else

The stdio binding is categorical, and the failure mode is silent corruption
rather than an error, so the rule is enforced structurally. The module writes
through one task fed by a channel; `clippy::print_stdout` is denied inside it,
though the workspace allows it because every other command in this binary exists
to print; and tracing was already stderr-only
(`crates/synch-net/src/process.rs`). `tests/cli.rs` spawns the real binary with
`--verbose` and asserts every line of its stdout parses as a JSON-RPC message.

## 8. What is deliberately not here

- **Resource subscriptions.** `notifications/resources/updated` is the natural
  fit for a node whose whole job is convergence, and the control service has no
  watch RPC to build it on. That is a daemon-side addition and a separable
  change.
- **Prompts.** Deferred until the tool surface has been used enough to know
  which prompts would earn their place.
- **The MCP logging capability.** Forwarding daemon diagnostics as
  `notifications/message` would put them in the client's UI instead of a stderr
  the user never sees. Cheap to add later; a second output path to get wrong
  today.
