# Handles

The descriptor model behind the host API (`docs/SOCKETS.md` §7). Every helper
that names a resource names it through this model, and every new handle kind
or helper family is measured against it. This document is normative: the
conformance matrix in §7 is what `crates/synch-sock/tests/handles.rs` pins,
and a helper that deviates from the taxonomy in §6 is a bug even when nothing
crashes.

## 1. One table, one namespace

A handle is a small non-negative integer indexing one per-invocation table.
There is a single namespace: the caller's stream, a TCP connection, an open
file, a directory listing, a JSON value, a child process and a tree writer are
all rows of the same table, and a helper cannot be handed a number from some
other invocation's table because no such number exists — the table is the
invocation's.

- **Handle `0` is `SY_SELF`**, the inbound stream, present from the first
  instruction and **never reallocated**. A program may close it and keep
  running (§7.3 of `docs/SOCKETS.md`); the slot stays empty. If the freed
  slot were handed to the next `sy_tcp_connect`, every "is this the caller's
  stream?" test in the runtime would answer yes to an upstream: its bytes
  counted as the caller's, its place in the egress budget never returned, the
  teardown drain skipping it.
- **Allocation is the lowest free index ≥ 1**, bounded by the handle limit
  (`docs/SOCKETS.md` §10). Like Unix descriptors, **a closed index is reused**
  by a later open: a stale handle is `SY_EBADF` only until then, after which
  it names the new resource. An invocation is single-threaded, so this is a
  plain program bug rather than a race, but it is the reason a library-shaped
  helper should not cache handles across calls that may close them.
- **Negative values are errnos**, so every helper that returns a handle is
  checked with `< 0`, the same test as every other return.

## 2. The eight kinds

| Kind | Obtained from | Its data verbs |
| --- | --- | --- |
| Unselected stream | handle `0` at entry, before a mode is chosen | none — the first ordinary operation selects raw mode; `sy_ssh_start` selects SSH |
| Endpoint | `SY_SELF` once raw, `sy_tcp_connect`/`_ip`, `sy_ssh_channel_open`/`_lane`, `sy_process_stdio`, `sy_pty_open` | `sy_read`, `sy_write`, `sy_splice`, `sy_readable`, `sy_writable`, `sy_shutdown`, `sy_endpoint_info`, and as `sy_put_splice`'s source |
| SSH control | handle `0` after `sy_ssh_start` | the `sy_ssh_*` connection family, addressed as `SY_SELF` |
| Object | `sy_open`, `sy_open_from`, `sy_open_root` | `sy_stat`, `sy_pread` |
| Cursor | `sy_list_open` | `sy_list_next` |
| JSON value | `sy_json_*` constructors, and every helper that answers structured — `sy_peer_info`, `sy_stat`, `sy_process_status`, `sy_ssh_next` | the `sy_json_*` family; consumed by `sy_ssh_start`, `sy_pty_open`, the `sy_declare_*` family |
| Process | `sy_process_spawn`, `sy_process_spawn_pty` | `sy_process_status`, `sy_process_signal`, `sy_process_stdio` |
| Tree writer | `sy_put_open` | `sy_put_write`, `sy_put_commit`, `sy_put_commit_if`, `sy_put_delete`, and as `sy_put_splice`'s destination |

## 3. Two planes: a generic lifecycle, a typed data plane

The namespace is shared; the verbs are not. The model splits them into two
planes, and which plane a helper belongs to decides what kinds it accepts:

- **The lifecycle plane is generic.** `sy_close`, `sy_poll` and `sy_errno`
  accept every kind, with per-kind semantics given by the matrix in §7.
  Closing is universal because leaking is universal; polling is universal
  because a program waits on whatever it holds; errno is universal because
  anything that can report `SY_POLL_ERR` must be able to say why.
- **The data plane is typed.** Every verb that moves or inspects a kind's
  payload names its kind, and a handle of any other kind is `SY_EBADF` —
  `sy_read` on an object, `sy_pread` on a cursor, `sy_json_type` on a writer,
  `sy_put_write` on a JSON value are all the same refusal.

The typed data plane is a choice, not an accident, and it was litigated at
`sy_put_splice`: a polymorphic `sy_splice` that accepted a writer destination
would restore an everything-is-a-descriptor aesthetic at exactly one verb
while every neighbor stays typed, and its contract would fork by destination
(`SY_ELIMIT` from a grant bound, `SY_ESTATE` from a writer lifecycle — but
only when `to` is a writer) in an ABI programmed against from C with no types
to flag which handle is which. Unix itself concedes the point at the same
place: `splice(2)` requires a pipe on one side, and `sendfile(2)`,
`splice(2)` and `copy_file_range(2)` are three admissions that a transfer
primitive's semantics depend on what is at each end. So the rule here is
flat: **generic lifecycle, typed data, `SY_EBADF` across kinds** — and a
future kind that wants a transfer verb gets its own, as the writer did.

## 4. Roles within endpoints

Endpoints subdivide by *role* — raw inbound, TCP egress, SSH channel, SSH
lane, process stdio, PTY — and the role never changes after creation. Every
endpoint answers the whole endpoint data plane identically; the role decides
three narrower things:

- **Attribute helpers.** A helper that only makes sense for one role —
  `sy_ssh_channel_type`, `sy_ssh_channel_lane`, `sy_pty_resize` — takes an
  endpoint handle and answers `SY_ESTATE` for an endpoint of the wrong role
  (`SY_EBADF` still means "not in the table at all", §6). A PTY's extra state
  rides in a side table keyed by its endpoint handle, which is why there is
  no distinct "pty handle" kind.
- **Accounting.** Only caller-facing roles count toward the stream byte
  totals an operator sees, so a proxy is not reported as moving twice what it
  moved.
- **Teardown.** Which drain and which budget applies (`docs/SOCKETS.md` §10).

**Mode selection at handle `0`** is the one place a slot changes kind. The
stream starts unselected; the first ordinary endpoint operation (a read, a
write, a poll that watches it) selects raw mode in place, and `sy_ssh_start`
instead replaces it with the SSH control object. The choice is permanent:
endpoint verbs on the control object are `SY_ESTATE`, as is a second
selection. `sy_close(0)` before any selection declines the caller's stream.

## 5. Integers that are not handles

Three helper argument families look like handles and are not, and each has
its own refusal:

- **Capability ids** (`sy_put_open`, `sy_sftp_open`, `sy_process_spawn`,
  `sy_pty_open`) name rows of the operator-approved declaration, a namespace
  fixed at arm time. Unknown ids are `SY_EPERM`, deliberately
  indistinguishable from "declared but not granted": what a program was not
  armed for does not exist for it.
- **SSH event ids** (`sy_ssh_event_data`, `sy_ssh_channel_accept`, …) name
  entries in the connection's event queue, valid until `sy_ssh_event_done`.
  An unknown field is `SY_ENOENT`; an event of the wrong kind for the verb is
  `SY_ESTATE`.
- **Selector arguments** — `sy_ssh_start` and `sy_ssh_next` take the
  connection, which is always `SY_SELF` today. A different value is
  `SY_EINVAL`: the argument is a selector reserved for a future with more
  than one connection, not a table lookup that could dangle.

## 6. The errno taxonomy

One meaning per code, everywhere:

| Errno | Means | Never means |
| --- | --- | --- |
| `SY_EBADF` | No such handle: an empty or out-of-range index, or a kind the verb does not take. | A handle in the wrong *state* — that is `SY_ESTATE`. |
| `SY_ESTATE` | Right handle, wrong lifecycle moment: writing a committed writer, endpoint verbs on the SSH control object, collecting a commit with `sy_put_delete`, an attribute helper on the wrong endpoint role. | A malformed argument. |
| `SY_EINVAL` | The argument itself is malformed: a bad pointer range, `max == 0`, an unparseable path, a non-`SY_SELF` selector. | Policy. |
| `SY_EPERM` | Policy said no: an undeclared capability, an unarmed grant, a helper outside its mode (init vs. stream). | A transient condition — retrying cannot change the answer until the tree or the declaration does. |
| `SY_EAGAIN` | Come back after a poll: the answer is on its way. | An error. It is the *only* "not yet". |
| `SY_ELIMIT` | A documented bound was hit (`docs/SOCKETS.md` §10). | — |

The taxonomy fixes meanings, not check order: helpers parse their arguments
before looking anything up (the `guest!` pattern), so a call that is both
malformed and misaddressed answers `SY_EINVAL`, not `SY_EBADF`. A program
must not use one refusal to conclude the absence of another.

Inside `sy_poll`, a bad handle is not a refusal of the call: the row reports
`SY_POLL_ERR` and the other rows answer normally, because one stale handle in
an array must not blind a program to the fifteen live ones beside it.

## 7. The lifecycle-plane matrix

What each kind does on the generic verbs. **Quiet** is the kind's
contribution to the runtime's nothing-can-ever-become-ready test: when every
held handle is quiet, `sy_poll` returns `0` immediately rather than waiting
out its timeout, telling the program it is finished. A kind may claim quiet
only when nothing about it can ever become ready again — a poll cut short by
a wrong quiet claim is a lie with consequences, which §8 records.

| Kind | `sy_close` | `sy_poll` reports | `sy_errno` | Quiet when |
| --- | --- | --- | --- | --- |
| Unselected stream | Declines the caller's stream. | Watching it selects raw mode first, then as an endpoint. | `0` | Never — the caller can always speak. |
| Endpoint | Frees the slot; queued bytes still drain in the background under the teardown budget. | `IN`/`OUT`/`RDHUP` by request; `ERR` and terminal `HUP` unmasked. | The transport's sticky errno. | Failed, closed, or terminal with nothing readable. |
| SSH control | Best-effort disconnect, then teardown. | `IN` while an event is queued; `HUP` after the connection ends. | The connection's errno. | At `HUP` — no event will ever arrive again. |
| Process | Kills the process group. | `IN` once exited (`watch_exit` bumps readiness on the child's exit); `ERR` if status refresh fails. | The refresh failure, or `0`. | Never — a running child will exit, an exited one has a status waiting. Close it once the status is collected. |
| Object | Frees the parked answer; a fetch still in flight settles its own charge when it lands (§8). | `IN` when the read's answer is parked; `ERR` when it failed. | The parked failure, or `0`. | No fetch in flight and nothing parked. |
| Cursor | Frees the page and its footprint charge. | Always `IN` — every answer it can give is already in memory. | `0` | Never while open — an answer is always waiting. |
| JSON value | Scrubs strings and frees the charge. | Nothing, ever — inert data. | `0` | Always. |
| Tree writer | Aborts uncommitted staging (a dispatched commit still completes atomically, its result discarded). | `OUT` while the staging buffer has room; `IN` when a dispatched result is parked; `ERR` on a parked refusal or sticky failure. | The sticky failure, else the parked refusal, else `0`. | Only once its success was delivered. |

## 8. Soundness rules, and what the first audit found

The rules the matrix and taxonomy compile down to, each checked against every
helper when this document was written:

1. **Absent, wrong kind, wrong state are three different answers** —
   `SY_EBADF`, `SY_EBADF`, `SY_ESTATE` — and no helper conflates them.
2. **A bad handle in `sy_poll` is that row's `ERR`**, never the call's
   refusal.
3. **Quiet is a promise.** A kind claims it only when nothing can ever become
   ready; everything that *makes* a handle ready off the guest's back (a
   fetch landing, a child exiting, a commit finishing, bytes arriving) bumps
   the shared readiness epoch, so a suspended poll actually wakes.
4. **Handle `0` is never reallocated**, whatever closed it.
5. **Charges follow the slot, not the index.** Host-side bytes a handle holds
   are released by `sy_close`, and work still in flight settles its own
   charge against the slot it holds an `Rc` to — an index reused in the
   meantime is a different slot and untouched.
6. **Bounds are taken where a kind enters the table** — endpoints at insert
   (the pristine stream included), writers at `sy_put_open`, processes at
   spawn — so no entry path skips its kind's limit.

The audit that produced this document found three violations, fixed in the
same change:

- **A running child claimed quiet** (rule 3). `all_quiet`'s catch-all read a
  running process's empty revents as "nothing can become ready", so a program
  that closed its streams and polled for its child's exit was told it was
  finished — `sy_poll` returned `0` immediately — while the child ran.
  Processes are now never quiet.
- **A read in flight outlived its accounting** (rule 5). Closing an object
  whose `sy_pread` had not landed released nothing, and the landing fetch
  parked its bytes — still charged — in the orphaned slot for the rest of the
  invocation. The fetch now checks the slot's closed flag and gives the whole
  charge back.
- **`sy_ssh_channel_lane` conflated absent with wrong-state** (rule 1): a
  handle not in the table at all answered `SY_ESTATE` where the taxonomy says
  `SY_EBADF`.
