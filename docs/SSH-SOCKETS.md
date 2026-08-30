# SSH over sockets

Status: **implemented**. This document is the design of the built-in SSH
protocol adapter for Synchronicity sockets, and is kept consistent with the
implementation in `crates/synch-sock` (`runtime/ssh.rs`, the `sy_ssh_*`
helpers, `runtime/sftp.rs`, and `runtime/process.rs`).

The short version is:

> SSH turns one byte stream into a control fd and several data fds. It grants no
> host authority and therefore needs no declaration. An eBPF program chooses the
> authentication policy, accepts SSH channels, opens separately declared backing
> capabilities, and copies bytes between their virtual fds.

This extends the socket runtime in [`docs/SOCKETS.md`](SOCKETS.md); it does not
add another network protocol. The caller still opens one `sync/sock/1`
bidirectional stream, and the callee still runs one invocation of its own activated
eBPF program for that stream. The SSH adapter exists entirely inside that
invocation.

## 1. The boundary

There are three distinct responsibilities, and keeping them distinct is the
design.

| Layer | Responsibility | Declaration |
| --- | --- | --- |
| SSH host adapter | version exchange, key exchange, encryption, host authentication, user-authentication messages, channel multiplexing and flow control | none |
| eBPF socket | user-authentication policy, channel and request policy, routing, and copying bytes | none beyond arming the program itself |
| Backing capability | TCP egress, a process/PTY, writable or foreign tree access, an SFTP service, or another external effect | the authority that capability adds |

The SSH host adapter never on its own starts a shell, opens an authorization
file, consults PAM, discovers `authorized_keys`, connects to a destination, or
attaches a channel to a backend. It parses and emits SSH and exposes the result
as virtual fds and events. A declaration-free parser may inspect an object fd
the guest already opened, but the eBPF program chooses that object and does
everything that joins these pieces together.

This gives the runtime one reusable rule:

> **Protocol adapters transform authority already held by an fd. Helpers that
> create new authority-bearing fds are the declaration boundary.**

Hashing, base64, SSH framing, and a future TLS adapter are protocol or byte
transforms. TCP egress, process execution, a writable tree, and a listener
reach something the invocation could not otherwise reach, so they are
capabilities.

### 1.1 Why SSH itself is undeclared

Before activation, the program can already read arbitrary bytes from
`SY_SELF`, interpret them, and write arbitrary bytes back. Having the host
perform bounded SSH parsing and cryptography does not widen that authority. It
only replaces code that cannot realistically fit in an eBPF guest with a safe
host implementation.

Accepting `none` authentication is likewise application policy, not host
authority. It grants access only to behavior the already-deployed program can
perform. Any effect behind the accepted connection remains governed by its own
declaration.

This matters when a member runs `synch socket connect --listen`: many ordinary TCP
clients may then arrive under that member's authenticated Synchronicity
identity. The eBPF program can use SSH authentication to distinguish them. The
outer identity from `sy_peer_*` remains a transport-authenticated fact; SSH
usernames and credentials are additional application inputs.

### 1.2 Backing services are declared without overstating the gate

A host-provided backing service is an operator-visible capability and requires
a declaration naming its scope and mode. That includes a built-in
file-transfer service even when configured read-only. The declaration is what
allows that service endpoint to be created; it is separate from SSH and can be
used behind another protocol.

There is nevertheless an important constraint on what that declaration means.
A socket can already read its own published tree with `sy_open` and send those
bytes to its caller. A declaration on a read-only file-transfer helper therefore
prevents use of the *built-in service*, but does not prevent an eBPF program
from implementing an equivalent export itself. It must not be presented as a
general data-export boundary.

Consequently, two layers are checked:

- opening the built-in service always requires a file-transfer declaration
  naming its protocol, path scope and read/write mode;
- write mode additionally requires a same-id tree-write declaration, whose
  prefix, create/replace/delete modes, and byte bound are rechecked for every
  staged file;
- the declared scope bounds what the service exposes, which is narrower than
  what the invocation can read: reading the tree is unrestricted
  (`docs/SOCKETS.md` §7.6), so the scope is about what an SSH client is served,
  not about what the program may open;
- adding the declaration to the SFTP helper alone would give a false assurance
  if it were read as a read boundary. It is not one: a deployed program can
  always export bytes manually through `sy_open`. What the declaration buys is
  that the *built-in service* is reviewed before it serves a subtree wholesale.

### 1.3 Zero-configuration capability declarations

Every backing declaration is complete data embedded in the program artifact.
It contains the exact process executable and argv, or the exact file-transfer
scope and access. Runtime calls select one with a small integer id meaningful
only inside that program root. There is no daemon-wide registry, separate
creation command, mutable lookup record, or operator-side value for anyone to
supply. Id namespaces are also capability-specific: a process id cannot be
used with an SFTP helper or vice versa.

The operator workflow remains one decision: inspect the concrete declarations
printed by `synch socket inspect` and choose what to deploy. The host may
refuse an artifact whose executable is absent or whose feature is unsupported
on that node, but it never asks the operator to repair the declaration
interactively. Host keys and clean process environments are generated or
defined by the runtime. A socket that needs different authority is a different
program root with a different reviewed declaration.

## 2. One invocation is one SSH connection

The unit of socket execution remains the incoming `sync/sock/1` stream. One
invocation may upgrade that stream into one SSH connection, and all SSH
channels on that connection live inside the same invocation.

That shape is necessary for authentication and multiplexing. Starting a fresh
invocation per SSH channel would split connection-wide authentication state,
algorithm negotiation, channel ids, windows, and disconnect handling across
guests that cannot share mutable memory.

After activation the handle table looks like this:

```text
fd 0    SSH control fd (formerly the raw SY_SELF stream)
fd 1    accepted SSH channel: ordinary data in and out
fd 2    backing PTY or process stream
fd 3    another accepted SSH channel
fd 4    that channel's TCP or file-transfer backend
fd 5    optional SSH extended-data lane
...     ordinary objects, cursors, endpoints and other channel backends
```

The program runs one event loop over the control fd, channel fds, and backing
fds. Existing `sy_pump` state is the intended way to copy each direction
without dropping a short write.

## 3. Activating SSH

The entrypoint is:

```c
sy_s64 sy_ssh_start(sy_s64 stream, sy_u64 initial_auth_methods);
```

It has these semantics:

1. `stream` must be `SY_SELF`.
2. The raw stream must be pristine: it has not been read, written, shut down,
   closed, or polled for endpoint readiness.
3. The transition is atomic. On success, the host owns the raw stream and fd
   zero becomes the SSH control fd. On failure, it remains a usable raw stream.
4. The transition is irreversible.
5. The helper is serving-mode only and returns `SY_EPERM` from the declaration
   hook, like every other I/O helper.
6. It requires no program declaration.
7. Calling a raw endpoint helper on fd zero after the transition returns
   `SY_ESTATE`, with one deliberate exception: `sy_close` on the control fd
   is the SSH counterpart of closing the raw stream — it sends a best-effort
   orderly SSH disconnect and tears down the connection's local state.
   Polling fd zero remains valid, with the control-fd semantics in §5.

`SY_ESTATE` is a new negative result for an operation that is valid in the ABI
but invalid in the handle's current protocol state. Reusing `SY_EINVAL` would
make a malformed argument indistinguishable from touching a stream too late to
upgrade safely.

### 3.1 Lazy selection of raw mode

The runtime used to construct an `Endpoint` for `SY_SELF` and immediately
start reader and writer tasks before entering the guest. Recovering the
underlying halves from those tasks after an SSH call would be racy and would
need another pair of rings and a bridge.

Instead, `SY_SELF` is a small unselected slot holding the original
`DuplexStream`. Its first operation selects exactly one mode:

- `sy_ssh_start` consumes it directly into the SSH engine;
- **every** helper that takes an endpoint handle materializes the raw
  `Endpoint` and its pumps. That is the whole list — `sy_read`, `sy_write`,
  `sy_splice` (either side), `sy_readable`, `sy_writable`, `sy_shutdown`,
  `sy_close`, `sy_endpoint_info`, and endpoint `sy_poll`.

The rule is "any endpoint operation selects raw mode", with no exceptions to
memorize, because all of them resolve the handle through one accessor
(`Inner::endpoint_for_io`). It was not always: `sy_splice` used to resolve its
handles without selecting, so a splice-only proxy got `SY_EBADF` on `SY_SELF`
until some other call had selected for it, and `sy_endpoint_info` selected raw
mode without being listed here, which silently made a later `sy_ssh_start`
impossible. Both are fixed, and a new endpoint helper inherits the rule by
using the accessor.

Existing programs are unchanged: their first ordinary operation selects raw
mode. An SSH program must call `sy_ssh_start` before *any* other operation on
`SY_SELF`, including `sy_endpoint_info` and including a poll set that names it.

The direct handoff keeps one set of flow-control buffers rather than copying
the encrypted SSH stream through an endpoint ring before parsing it.

### 3.2 What the program controls

The program controls:

- which supported user-authentication methods may be attempted;
- acceptance, rejection, and partial success for each attempt;
- which methods may continue after an attempt;
- whether to accept each inbound channel and which outbound channels to open;
- whether to accept each PTY, environment, shell, exec, subsystem and related
  request;
- which backing fds, if any, a channel is connected to;
- exit status and orderly channel closure.

The host controls:

- a conservative set of key-exchange, host-key, cipher and MAC algorithms;
- packet parsing and structural protocol validation;
- host-key signatures and user public-key signature verification;
- hard resource, authentication-attempt and time bounds;
- SSH channel ids, windows, packet sizing and rekeying;
- rejection of protocol features the ABI does not expose.

The guest cannot weaken cryptographic negotiation or ask the host to advertise
an algorithm the build considers unsafe.

### 3.3 Outer identity policy before SSH

The transport-authenticated peer identity is available before the stream is
upgraded. In particular, these calls do not select raw mode and do not make the
stream non-pristine:

```c
sy_peer_origin(...);
sy_peer_device_key(...);
sy_peer_info();
sy_peer_has_space(...);
sy_peer_addr(...);
sy_conn_meta(...);
sy_stream_index();
```

This permits an outer gate before any SSH version or host-key bytes are sent:

```c
sy_u8 peer[32];
if (sy_peer_device_key(peer) < 0 || !peer_is_allowed(peer))
  return 1;                         /* close the raw stream */

sy_s64 methods = sy_json_parse(SY_STR("[\"none\"]"));
if (methods < 0 || sy_ssh_start(SY_SELF, methods) < 0)
  return 1;
sy_close(methods);
```

`sy_peer_device_key` is the exact 32-byte Iroh public key authenticated by the
underlying connection, not a value supplied in `Open.meta` or in stream data.
The ordinary socket admission checks still run first; this guest check can
narrow that admitted set to an exact key or guest-defined key set. Rejecting at
this stage closes the `sync/sock/1` stream without speaking SSH. A program
using the Iroh key as its sole client authentication can then accept the SSH
`none` event; another program may still require an SSH public key or a second
factor. The outer Iroh principal and inner SSH principal remain distinct facts.

## 4. User authentication

The SSH adapter has no user database. Authentication requests become events,
and the guest's reply completes the host library's authentication callback.

Methods are named, not numbered: `sy_ssh_start` takes a JSON array of
`"none"`, `"publickey"` and `"password"`, naming what the client may attempt
first.

Naming `none` controls whether a `none` request may be accepted, but `none` is
never included in SSH's advertised method name-list, as RFC 4252 requires.
Keyboard-interactive and host-based authentication can be added with new names
and event kinds without changing the lifecycle. OpenSSH user certificates use
the `publickey` method name and their own signed-auth event kind.

Authentication event kinds, as the `kind` of the event JSON (§5), are:

```text
auth_none
auth_password
auth_publickey_offer
auth_publickey_verified
auth_openssh_cert
authenticated
```

For certificate offers and signed authentication, the event's JSON carries a
`cert` object — `{"ca_public_key_sha256" (hex), "key_id", "serial", "type"
("user" | "host"), "principals"}` — and the subject key fields; the raw
certificate, CA and subject key blobs come byte-for-byte through
`sy_ssh_event_data` (§5). The host rejects host
certificates, username/principal mismatches, invalid validity/signatures and
all unsupported critical options. The guest must authorize the signing CA;
cryptographic self-consistency alone is never a trust decision.

Every event includes the username and service. A public-key offer says only
that the client asked whether a key might be acceptable. A verified event is
emitted only after the host has validated proof of possession. The guest never
parses or verifies an SSH signature.

The reply is a JSON handle:

```c
sy_s64 sy_ssh_auth_reply(sy_u64 event_id, sy_s64 reply_json);

/* {"result": "accept"        -- authentication complete
             | "reject"
             | "partial"      -- factor accepted; more required
             | "offer_accept" -- ask client to prove key possession
   ,"next_methods": ["publickey", ...]?}                            */
```

`next_methods` determines both which methods may be attempted after a
rejection or partial success — an attempt outside the set is rejected by the
host without waking the guest — and which appear in the advertised name-list,
always minus `none` per RFC 4252. An unknown method name is refused; an
absent `next_methods` leaves nothing further attemptable, fail-closed. On a
public-key *offer* only `"reject"` and `"offer_accept"` are valid results;
`"accept"` and `"partial"` on an offer return `SY_ESTATE`, because an offer
proves nothing that could complete a factor. The host keeps the protocol's
partial authentication state; the guest may keep application state in its
invocation stack.

For the first implementation, changing username or service after the first
authentication request disconnects the client. SSH permits a change only when
all accumulated state can be safely flushed; the host cannot reset arbitrary
guest stack state. Ordinary clients do not depend on changing principals
mid-connection, and disconnecting is safer than making a guest-authored state
machine silently apply one user's partial success to another.

### 4.1 Public-key identity and lifetime

Both public-key events expose three separate facts through the event fields in
§5:

- the SSH key algorithm name;
- the canonical SSH wire-format public-key blob;
- exactly 32 raw bytes equal to `SHA-256(canonical_blob)`.

The host obtains the blob by canonically re-encoding the key accepted by the
SSH library rather than hashing untrusted original packet framing. The
fingerprint therefore has one representation across offer-first and directly
signed authentication attempts. Display code may render those bytes in the
usual `SHA256:<base64-without-padding>` form, but policy should compare the raw
32 bytes. The blob and algorithm are bounded by the ordinary event-payload
limits.

An `auth_publickey_offer` carries an identity but proves nothing. Only
`auth_publickey_verified` means the host validated a signature by that exact
key over the current SSH authentication exchange. A guest must base key
authentication on the verified event; `"offer_accept"` merely asks the client
to produce that proof.

SSH user authentication is connection-wide. Before consuming a verified
event token, the guest copies any policy state it needs -- normally a compact
principal id or the 32-byte fingerprint -- into invocation-local state. If it
answers `ACCEPT`, that state applies to every subsequently accepted channel on
the connection, including sessions opened through an OpenSSH control master.
The host cannot open a channel before authentication completes. Closing one
channel does not clear the authenticated principal; changing the username
disconnects as described above. With multifactor authentication, the guest
records each accepted factor and decides which combined principal, if any, an
eventual `ACCEPT` establishes.

Authentication callbacks may wait for the guest because no channel exists
before authentication completes. The guest is concurrently suspended in
`sy_poll`, so the callback enqueues an event, wakes the control fd, and awaits a
bounded one-shot reply without blocking the worker thread.

### 4.2 Matching `authorized_keys` from the tree

Tree objects are independent of `SY_SELF`. A program may call `sy_open`, read
or poll the returned object, and retain it before `sy_ssh_start`; none of those
operations selects raw stream mode. This lets each invocation resolve its
authorization data before it emits an SSH banner:

```c
sy_s64 keys = sy_open(SY_STR("code/ssh/authorized_keys"));
if (keys < 0) return 1;
sy_s64 methods = sy_json_parse(SY_STR("[\"publickey\"]"));
if (methods < 0 || sy_ssh_start(SY_SELF, methods) < 0) return 1;
sy_close(methods);
```

The object handle identifies immutable verified content. A tree update affects
new invocations when they call `sy_open`; an invocation that already holds the
object continues evaluating the same root for the life of its SSH connection.
The program may record that root through `sy_stat` for audit output. Opening a
file in the socket owner's tree retains the existing declaration-free
`sy_open` authority. A foreign-origin or otherwise privileged source retains
its ordinary tree declaration requirements.

Parsing OpenSSH text, base64, and key encodings in eBPF would add complexity
without adding policy control. A declaration-free transform helper therefore
compares the key on a public-key event with an already-open object:

```c
sy_s64 sy_ssh_authorized_keys_match(
    sy_u64 event_id,
    sy_s64 object
);
```

It is valid only for `auth_publickey_offer` and
`auth_publickey_verified`. It decodes each option-free key record's base64
field — the SSH wire-format blob — and compares it byte for byte with the
canonical blob on the event, so a match means the exact verified key. It
returns `1` for a match, `0` after a complete scan with no match,
`SY_EAGAIN` when object bytes are not resident, or another negative error.
On `SY_EAGAIN` the host starts one bounded read of the whole object — the
size limit below is what makes reading it whole safe — charged against the
invocation's ordinary host-byte footprint, and the object becomes pollable;
the guest retains the generational event token, polls the object alongside
fd zero, and retries. The scan itself then runs once over resident bytes.

Version 1 deliberately recognizes only option-free records of the form
`key-type base64-key [comment]`, plus blank and comment lines. A record with
options such as `command=`, `from=`, or `restrict` does not match. Silently
matching while ignoring an option would widen the policy expressed by the
file. A later typed option API may expose restrictions, but it must not start a
command or grant a backing capability automatically. Unsupported key types,
malformed base64, and malformed records are skipped; skipping can only fail
to match, never authorize.
A line over 16 KiB or file over 256 KiB fails the whole match with `SY_ELIMIT`
rather than authorizing from a prefix or suffix.

The helper is optional convenience. A guest may instead compare
`public_key_blob`/`public_key_sha256` with a compact binary allowlist, use separate key files to
select different principals, or implement another policy from ordinary tree
reads. In every case it must repeat the decision on
`auth_publickey_verified`; a match on the offer only justifies returning
`"offer_accept"`.

## 5. The SSH control fd and its events

After activation, fd zero is not a byte stream. It is a pollable control
object:

- `SY_POLL_IN`: at least one event can be taken;
- `SY_POLL_HUP`: the SSH connection ended; alone it ended cleanly — a
  disconnect message from either side, including one a guest decision
  deadline produced;
- `SY_POLL_ERR`, always alongside `HUP`: parsing, cryptography or the
  underlying stream failed;
- `sy_errno(SY_SELF)`: the stable guest errno for that failure —
  `SY_ETIMEDOUT` for a transport deadline, `SY_ECONNRESET` for everything
  that broke, `0` for a clean end;
- `SY_POLL_OUT` and `SY_POLL_RDHUP`: never reported.

An event is a JSON value with bounded host-side payloads:

```c
sy_s64 sy_ssh_next(sy_s64 conn);
sy_s64 sy_ssh_event_data(sy_u64 event_id, const char *field,
                         sy_u64 field_len, void *out, sy_u64 out_len);
sy_s64 sy_ssh_event_done(sy_u64 event_id);
```

`sy_ssh_next` pops one event and returns it as a fresh JSON handle (> 0),
`SY_EAGAIN` when the ready queue is empty but the connection is live, `0` when
it is empty and the connection has reached `HUP` — no further event will ever
arrive — or another negative error. This makes it safe to drain the control fd
after one readiness notification. The JSON is a snapshot the guest closes with
`sy_close` whenever it likes; the event itself stays outstanding, addressed by
its `id`, until a decision helper or `sy_ssh_event_done` consumes it.

Every event's JSON carries `"id"` (the opaque, generational response token)
and `"kind"` (the names in §4 plus the channel kinds below); a channel event
carries `"fd"`. The decoded fields for the kind sit beside them: `"username"`,
`"service"`, `"password"`, `"public_key_algorithm"`, `"public_key_sha256"`
(hex), `"auth_attempts"`, `"channel_type"`, `"request_type"`, `"want_reply"`,
`"terminal"`, `"env_name"` / `"env_value"`, `"command"`, `"subsystem"`,
`"signal"`, `"destination_host"` / `"originator_host"` / `"port"` /
`"originator_port"`, `"columns"` / `"rows"` / `"pixel_width"` /
`"pixel_height"`, `"data_type"`, and the `"cert"` object of §4.

`sy_ssh_event_data` serves any raw field of an outstanding event by string
name, byte-for-byte as the wire carried it, with the SDK's `snprintf`
convention: it returns the complete length wanted and copies what fits. The
names are the JSON keys above plus what the JSON deliberately leaves out —
`"public_key_blob"`, `"ca_public_key_blob"`, `"cert_blob"`,
`"cert_principals"`, `"open_data"`, `"request_data"`, and a `"command"` that
is not UTF-8 (a non-UTF-8 field is simply absent from the JSON view).

The channel lifecycle uses three event kinds:

```text
channel_open           /* "fd" is absent until accepted */
channel_request        /* "fd" identifies a live channel */
channel_extended_data  /* "data_type" is an unbound numeric code */
```

EOF, close, and failure are fd readiness transitions rather than duplicate
control events. This keeps byte-stream lifecycle in the ordinary endpoint ABI.

The raw `public_key_sha256` has length exactly 32; its JSON form is the hex
spelling. Raw fields are length-delimited bytes, not NUL-terminated; JSON
string reads have the ordinary snprintf semantics. The password field exists
only on `auth_password`, is covered by the credential zeroization rules
(which extend to the event's JSON snapshot: closing it zeroizes its strings,
best-effort), and is invalid after the event token is consumed. `"command"`
and `"subsystem"` are the exact bounded request payloads and have no shell
interpretation in the SSH adapter.

Tokens, rather than one globally pinned front event, avoid head-of-line
blocking. A program may start a backend for one exec request and continue
pumping other channels before answering it. The host bounds both outstanding
tokens and their total payload bytes. A token carries a generation, so a late
reply cannot act on a recycled handle or SSH channel id.

Authentication requests remain connection-serialized by the SSH protocol.
For channel requests the host permits at most one unanswered state-changing
request per channel and queues later requests for that channel, while unrelated
channels continue.

## 6. SSH channels are generic virtual fds

The fd model is generic over SSH channel type. Every peer-initiated
`SSH_MSG_CHANNEL_OPEN` produces a `channel_open` event; the event exposes
the channel type and its bounded type-specific opening payload. Nothing is
accepted automatically and the SSH adapter has no allowlist containing only
`session`.

```c
sy_s64 sy_ssh_channel_accept(sy_u64 event_id);
/* reason: "administratively_prohibited" | "connect_failed"
         | "unknown_channel_type" | "resource_shortage"     */
sy_s64 sy_ssh_channel_reject(sy_u64 event_id, const char *reason,
                             sy_u64 reason_len);

sy_s64 sy_ssh_channel_open(
    sy_s64 conn,
    const char *type,
    sy_u64 type_len,
    const void *open_data,
    sy_u64 open_data_len
);

sy_s64 sy_ssh_channel_type(
    sy_s64 channel,
    char *out,
    sy_u64 out_len
);
```

Accepting an inbound open reserves a handle slot before confirming it and
returns the new channel fd already open: sending the confirmation completes
locally and the peer cannot refuse it. `sy_ssh_channel_open` performs the
symmetric server-initiated operation and returns a channel fd immediately;
that fd begins in the existing connecting state, becomes `SY_POLL_OUT` when
the peer's confirmation arrives, and reports the peer's rejection through
`SY_POLL_ERR` and `sy_errno`. Failure to reserve a slot rejects the inbound
open or returns `SY_ELIMIT` for an outbound one.

The type and opening data are protocol inputs, not authority. Accepting a
`direct-tcpip` channel does not connect to its requested destination;
accepting `session` does not start a process; and accepting a vendor channel
does not load an extension. The guest must independently create any backing fd
under its declaration and copy bytes itself.

Every channel fd is an ordinary nonblocking, bidirectional endpoint:

- `sy_read(fd)` receives ordinary `SSH_MSG_CHANNEL_DATA`;
- `sy_write(fd)` sends ordinary channel data;
- a short write is SSH-window or ring backpressure, not failure;
- `sy_shutdown(fd)` sends SSH EOF after queued bytes drain;
- `sy_close(fd)` sends SSH close and frees the local slot;
- peer EOF maps to the existing `IN`/`RDHUP` behavior;
- complete channel closure maps to `HUP`.

The SSH receive window advances only as the channel fd is read. When the guest
stops reading a full ring, the host stops reading that SSH channel and its
window stops advancing. In the other direction the endpoint writer waits for
SSH window room before draining the tx ring. Backpressure and closure are
therefore identical for `session`, forwarding, and extension channels.

### 6.1 Opening data

`"channel_type"` is the exact channel-type string and the raw `"open_data"`
field is a bounded copy of the type-specific bytes
following the common channel-open fields. The raw field permits a guest-defined
extension without an SSH-library change, but standard types also receive
validated fields so ordinary programs never parse SSH binary encoding.

The first typed opening-data view is:

```text
direct-tcpip
    "destination_host", "port"
    "originator_host", "originator_port"
```

Malformed opening data for a standard type is rejected by the host before an
event is emitted. Unknown types retain only their bounded opaque opening data.
The open-payload bound is charged to the connection's event budget.

### 6.2 Extended-data lanes

SSH extended data is associated with a numeric data-type code. A channel may
expose any such code as a separate bidirectional virtual fd:

```c
sy_s64 sy_ssh_channel_lane(sy_s64 channel, sy_u32 data_type);

#define SY_SSH_EXTENDED_STDERR 1
```

Creating a lane is idempotent for a live channel and data type and costs one
handle slot. Reading receives inbound extended data of that type and writing
sends it. Closing a lane does not close its parent channel; closing the parent
closes every lane. Type 1 conventionally carries stderr on a `session`
channel. A PTY normally combines output and needs no stderr lane, while a
pipe-backed process can be pumped to the type-1 lane.

The guest may create an outbound lane proactively. When inbound extended data
arrives for a type without a lane, the host holds that one packet and emits
a `channel_extended_data` event, then waits for the decision in the
connection's own read loop before reading further from the transport.
Creating the lane makes those bytes readable. Completing the event without
creating it selects bounded discard for that data type on that channel; SSH
has no per-type rejection message. Leaving the event unanswered therefore
stops the transport being read — window backpressure that, with one read
loop per connection, is connection-wide — until the event deadline expires,
which also selects bounded discard rather than ending the connection. Thus
an unknown data type can neither allocate handles automatically nor grow an
unbounded queue, and a flood of it never costs the connection.

### 6.3 Channel requests

Every `SSH_MSG_CHANNEL_REQUEST` produces a
`channel_request` event, referring to the generic channel fd. Its JSON exposes
`"request_type"`, `"want_reply"`, and validated typed fields for standard
requests; unknown requests retain their opaque payload as the raw
`"request_data"` field.

```c
/* granted: 1 grants the request, 0 refuses it */
sy_s64 sy_ssh_request_reply(sy_u64 event_id, sy_u32 granted);
```

The host sends success or failure only when requested. Otherwise the guest
finishes the event with `sy_ssh_event_done`. At most one unanswered
state-changing request is pending per channel, so delaying one channel never
blocks unrelated channels.

The initial typed request view covers the standard `session` vocabulary:

```text
pty-req       "terminal", "columns"/"rows"/"pixel_width"/"pixel_height",
              and the full spec through sy_ssh_pty_spec
env           "env_name" and "env_value"
shell
exec          "command" (raw bytes through sy_ssh_event_data)
subsystem     "subsystem"
window-change "columns"/"rows"/"pixel_width"/"pixel_height"
signal        "signal"
break         "break_ms"
x11-req       "screen_number", "single_connection"
```

These names do not start anything. The guest decides whether each request is
appropriate for that channel type, opens a backing capability when necessary,
and replies success only after it exists. The host rejects a structurally
malformed known request rather than delivering a partly decoded event.

Exit status and signal remain checked conveniences for the standard session
vocabulary, not properties of the underlying fd implementation:

```c
sy_s64 sy_ssh_exit_status(sy_s64 channel, sy_u32 status);
sy_s64 sy_ssh_exit_signal(
    sy_s64 channel,
    const char *name,
    sy_u64 name_len,
    sy_u32 core_dumped
);
```

They return `SY_ESTATE` unless `channel` has type `session`. An exit message
does not discard output or close the channel. The ordinary sequence is:
finish writes, send exit status, call `sy_shutdown`, drain until terminal, and
then `sy_close`.

### 6.4 Global requests and automatic services

Connection-global requests are not channel fds. Version 1 rejects them rather
than emitting underspecified events; a later ABI can add typed control events
for individual request families. The adapter also never automatically
implements forwarding, X11, or agent service. Generic inbound and outbound
channels provide the data-plane primitive for those features, but each still
needs guest policy, any required global negotiation, and separately declared
backing authority.

## 7. Backing fds and explicit copying

The SSH adapter never splices a channel automatically. A typical guest holds a
pair of pumps per attached channel:

```c
struct attached {
  sy_s64 channel;
  sy_s64 backend;
  struct sy_pump to_backend;
  struct sy_pump to_channel;
  char upward[1536];
  char downward[1536];
};
```

It derives poll interests from `sy_pump_blocked`, calls `sy_poll` across the
control fd and all data fds, and invokes `sy_pump` only in directions that can
make progress. Each direction has its own buffer and pump state. Half-closes
are propagated independently so a final response is not cut off when the
client finishes sending its request.

This is deliberately guest work. It lets the program inspect, rate-limit,
transform, tee, or refuse the stream, and it keeps the connection between an
SSH channel and a host effect visible in the code the operator deployed.

### 7.1 Process and PTY backing

A PTY is useful only in conjunction with process authority. The declaration
therefore contains the complete process capability rather than referring to an
external configuration record. A small capability id is local to one program
root and has no daemon-wide namespace or configuration. `synch socket
inspect` displays the concrete declaration; there is no separate setup
command.

```c
/* One entry of the manifest's "processes" array:
   {"id"              -- program-local, nonzero
   ,"allow"           -- ["pty" | "pipe", ...]
   ,"executable"      -- exact absolute path, at most 256 bytes
   ,"argv"            -- exact argv incl. argv[0]; 1..8 args of <= 128 bytes
   ,"allowed_signals" -- ["HUP" | "INT" | "TERM", ...]?}                    */
```

The manifest parse rejects duplicate or zero ids, malformed paths and
arguments, and unsupported flags.
The declaration contains no request-derived bytes. A future structured argument
facility would be a separate capability; the initial API always runs the exact
declared argv and never invokes a shell implicitly.

Processes inherit the daemon's identity and resource limits. The runtime does
not impose process-specific count, runtime, or memory ceilings, and it does not
sandbox the child. An operator who wants containment can declare a wrapper such
as `bwrap` as the executable. The runtime supplies a clean, host-defined
environment, closes unrelated inherited descriptors, and creates a fresh
process group for lifecycle and signal handling. The clean environment retains
the daemon's basic identity, home, shell, path, locale, timezone and temporary
directory variables, but not application configuration or credentials. PTYs
synthesize `TERM` from the validated terminal request.

The fresh process group is for lifecycle and signal handling, not containment,
and it is best-effort: `sy_process_signal` and teardown signal the group while
the runtime still holds the child, but once the direct child has exited and
been reaped there is no group left to signal, and a descendant that outlived it
— a daemonized child, or one that called `setsid` for itself — keeps running
under the daemon's UID until something else stops it. Nothing reaps it and
nothing bounds it. A process capability is therefore authority to leave work
running on the host after the invocation ends; an operator who does not want
that declares an executable that bounds itself.

Allocation and process start are separate so a successful `pty-req` does not
start a shell before a later `shell` request:

```c
#define PROCESS_MAINTENANCE_SHELL 1

SY_MANIFEST("{\"manifest\":1,"
            "\"processes\":[{\"id\":1,\"allow\":[\"pty\"],"
            "\"executable\":\"/bin/sh\",\"argv\":[\"sh\",\"-l\"],"
            "\"allowed_signals\":[\"HUP\",\"INT\",\"TERM\"]}]}");

/* {"term", "columns", "rows", "pixel_width", "pixel_height",
    "modes": [{"opcode", "value"}, ...]} — mode opcodes are RFC 4254 §8
   wire values, so they stay numeric.                                   */
sy_s64 sy_ssh_pty_spec(sy_u64 event_id);  /* protocol transform; no declaration */

/* spec_json is the shape sy_ssh_pty_spec returns; the same handle can be
   passed straight through. Returns the PTY data endpoint. */
sy_s64 sy_pty_open(sy_u32 process_capability, sy_s64 spec_json);

sy_s64 sy_process_spawn_pty(
    sy_u32 process_capability,
    sy_s64 pty
);                                      /* returns a process control handle */

sy_s64 sy_process_spawn(
    sy_u32 process_capability
);                                      /* exact pipe-backed process */

/* stream: "main" (write stdin, read stdout) | "stderr" (read-only) */
sy_s64 sy_process_stdio(sy_s64 process, const char *stream, sy_u64 stream_len);

sy_s64 sy_pty_resize(
    sy_s64 pty,
    sy_u32 columns,
    sy_u32 rows,
    sy_u32 pixel_width,
    sy_u32 pixel_height
);

/* SY_EAGAIN while running; after exit a fresh JSON handle:
   {"exited": true, "exit_code", "signaled", "core_dumped", "signal"?} */
sy_s64 sy_process_status(sy_s64 process);
sy_s64 sy_process_signal(
    sy_s64 process,
    const char *name,
    sy_u64 name_len
);
```

`sy_ssh_pty_spec` is valid only for a typed `pty-req` event. It bounds and
normalizes the terminal name and RFC terminal-mode opcode/value pairs; unknown
opcodes retain the protocol's ignore semantics. It returns the spec as a JSON
handle or a negative error; a request exceeding either bound (a 64-byte
terminal name, 64 modes) is rejected rather than truncated. A `window-change`
event carries the new `"columns"`, `"rows"`, `"pixel_width"` and
`"pixel_height"` in its own JSON.

`sy_pty_open` creates a master/slave PTY pair but starts no process. The selected
declaration must permit PTY allocation; the helper returns the master as an
ordinary endpoint. `sy_process_spawn_pty` starts that declaration's exact
executable and argv with the PTY slave as its controlling terminal and returns
a separate pollable process handle. `sy_process_spawn` does the same for the
declared pipe-backed form. Process exit makes the control handle readable; a
status helper returns exit code or signal. `sy_process_stdio` returns the main
duplex stdin/stdout endpoint or the optional read-only stderr endpoint for a
pipe-backed child. Closing the process handle kills and reaps a live child
under fixed host shutdown policy, while closing the PTY supplies the ordinary
terminal hangup.

`sy_process_status` returns `SY_EAGAIN` while the child is running and a
fresh JSON handle after exit; repeated reads return the same terminal status
until the handle closes. `sy_process_signal` accepts only names permitted by the
declaration and never interprets a guest-provided number.

Pipe-backed processes expose stdio endpoints separately. PTY-backed processes
use the PTY endpoint for combined stdin/stdout and the process handle for
signals and status. In either shape, session bytes move only because the guest
pumps them.

Process/PTY support is a separate design and implementation layer from the
SSH adapter, and the adapter is tested without it.

#### Selecting a forced command by authenticated key

A program's manifest may declare several exact process capabilities, for example a
status shell, release writer, and read-only Git command. On
`AUTH_PUBLICKEY_VERIFIED` it compares the raw fingerprint, records a small
principal enum, and accepts the key. On each later `SHELL_REQUEST` or
`EXEC_REQUEST` it selects the one capability id permitted for that principal.

The SSH command is policy input, not process authority. A fixed-command
capability may ignore it completely. The initial process API has no way to pass
request bytes into argv, and no helper implicitly evaluates them with
`/bin/sh -c`. Thus the key selects among concrete declared capabilities and
cannot manufacture a new executable or command line.

Authentication remains connection-wide but command selection is per session.
The same key may therefore open several concurrent sessions, each backed by a
separate instance of its allowed capability.

### 7.2 File-transfer backing

A built-in file-transfer service is likewise an endpoint independent of SSH.
Its complete scope and access are embedded in the program declaration. A
program-local id selects that declaration at runtime; there is no named service
or operator configuration:

```c
/* One entry of the manifest's "file_transfers" array:
   {"id", "protocol": "sftp",
    "access": ["read" | "write", "recursive"?],
    "scope" -- exact normalized tree path of at most 256 bytes} */

sy_s64 sy_sftp_open(sy_u32 file_transfer_capability);

#define FILE_TRANSFER_RELEASES 1

SY_MANIFEST("{\"manifest\":1,"
            "\"file_transfers\":[{\"id\":1,\"protocol\":\"sftp\","
            "\"access\":[\"read\",\"write\",\"recursive\"],"
            "\"scope\":\"code/releases\"}],"
            "\"tree_writes\":[{\"id\":1,\"prefix\":\"code/releases\","
            "\"allow\":[\"create\",\"replace\",\"delete\"]}]}");

sy_s64 sftp = sy_sftp_open(FILE_TRANSFER_RELEASES);
```

The guest accepts `subsystem "sftp"`, opens the service under its effective
tree policy, replies success, and pumps `session <-> sftp`. The SFTP engine
does not know which SSH connection carries it, and the SSH engine does not
know that the session bytes are SFTP.

`write` access requires a tree-write declaration with the same program-local
id. The file-transfer declaration selects the protocol and visible scope; the
tree-write declaration independently bounds create, replace, delete, and the
bytes staged per file. A writable handle stages random-access writes and its
`CLOSE` conditionally commits against the version opened, so a concurrent tree
change fails instead of being silently overwritten. Disconnecting or closing
the service with live handles aborts their staging. The declarations are shown
during inspection and activation. As §1.2 explains, they do not claim that a
deployed program
lacking the service is unable to export bytes manually through `sy_open`.

The SFTP v3 adapter covers regular-file reads, create/replace, random and
append writes, truncation, removal, and rename. Rename conditionally publishes
the copy and conditionally deletes the exact source version that was copied,
because the tree has one-path atomic commits. If the source changes between
those steps, the copy may already exist but the newer source is retained and
the rename reports failure. Baseline SFTP v3 rename refuses an occupied
destination; no overwrite extension is advertised. Directories in
the published tree are implicit prefixes, so empty-directory creation/removal,
symlinks, and client-supplied modes or mtimes are not mutation inputs; metadata
changes through `SETSTAT` or `FSETSTAT` return `SSH_FX_OP_UNSUPPORTED` instead
of claiming that ignored metadata was preserved. `OPEN` likewise rejects
unsupported initial metadata, but honors an initial size for a newly created
file. A staged mutation failure poisons its handle: `CLOSE` aborts rather than
publishing bytes the failed request may have written only partially. Existing
file replacements preserve the host's permission bits; later successful data
writes still advance the host-stamped mtime normally. Rename preserves both
the source permissions and mtime. A zero-length `WRITE` is a no-op, including
when its offset is beyond EOF.

Directory enumeration is paged from the virtual-tree storage API upward. An
open directory handle retains only its storage cursor and last emitted child,
never a complete subtree. Each `readdir` response is bounded to 64 entries and
64 KiB of conservatively estimated encoded data, and scans at most 32 pages of
128 storage rows. A directory whose next child cannot be found within that
work bound fails the request instead of consuming unbounded memory or CPU.

SFTP support is separate from the SSH adapter. A guest may also implement a
small subsystem itself, or proxy a session to a declared TCP backend, without
touching the built-in SFTP service.

### 7.3 Multiple channels and control masters

An OpenSSH control master is a client-side multiplexer. On the wire, every new
command requested through it is an ordinary SSH `session` channel on the
already authenticated connection. Each `channel_open` event whose type
is `session` is independently accepted and receives a new virtual fd; its
shell, exec, subsystem, data, EOF, exit status, and close lifecycle are
independent of every other session.

The simultaneous-channel limit applies only to currently live channels. A
long-lived control master may create any number sequentially over its lifetime,
subject to the connection idle deadline and other rate policy. Up to the
configured simultaneous limit may run concurrently. Closing a session frees
its fd and backing-resource charges but leaves fd zero, the SSH transport, and
the authenticated principal alive. A slow or unanswered request on one
channel is queued per §5 and does not prevent other channels from carrying
data or opening backends.

## 8. Handle types and accounting

The runtime once treated an endpoint at any handle other than `SY_SELF` as
outbound egress in parts of its accounting and cleanup. SSH invalidated that
shortcut, so every endpoint now carries an explicit role:

```rust
enum EndpointRole {
    RawInbound,
    SshChannel { channel_type: String },
    SshExtendedData,
    TcpEgress,
    ProcessStdio,
    Pty,
    FileTransfer,
}
```

The role decides:

- which operations are valid;
- which independent resource cap is charged;
- whether close releases an egress, channel, process or service slot;
- whether bytes contribute to invocation input/output statistics;
- how peer and endpoint information is rendered.

For SSH invocations, `bytes_in` and `bytes_out` count cleartext bytes the guest
reads from and writes to SSH channel and lane fds. SSH handshakes, encrypted
framing and control messages are transport overhead and are not charged as
application bytes; neither are the backends the guest pumps into, or a proxy
would report twice the bytes it moved. Optional wire-byte metrics may be
reported separately.

## 9. Limits

SSH multiplexing needs more than the former sixteen-handle default. One attached
pipe-backed channel can consume a channel fd, backend stdin/stdout, backend
stderr and an SSH extended-data lane before counting the control fd or any tree
objects. A limit that advertises eight channels but cannot represent them is
not a limit; it is a delayed refusal.

The initial bounds:

| Resource | Default / hard bound | Behavior at the bound |
| --- | --- | --- |
| Handles and poll entries | 256 | helper fails `SY_ELIMIT`; incoming channel is rejected if it cannot reserve its fd |
| Open endpoints | 32 | every ring-bearing fd, `SY_SELF` included; the opening helper fails `SY_ELIMIT` |
| Simultaneous SSH channels | 8 | bounded independently of handles; a full handle table may lower the effective count |
| Extended-data lanes per channel | 8 | `sy_ssh_channel_lane` fails `SY_ELIMIT`; an existing lane for the same `data_type` is returned, not counted again |
| Live child processes | 16 | pipe and PTY spawns together; spawn fails `SY_ELIMIT` until a process handle is closed |
| Open PTY masters | 16 | `sy_pty_open` fails `SY_ELIMIT` |
| Open file-transfer endpoints | 16 | `sy_sftp_open` fails `SY_ELIMIT` |
| SSH channel ring | 64 KiB per direction | stops reading or writing the SSH channel and applies window backpressure |
| Outstanding control events | 32 | channel request is deferred where possible; otherwise rejected or connection closed by protocol class |
| Total event payload | 64 KiB | oversized request rejected; no partial credential or command is delivered |
| One event payload | 16 KiB, with smaller field-specific limits | request rejected |
| Authentication attempts | 8 | disconnect |
| Authentication decision | 60 s | disconnect |
| `authorized_keys` object | 256 KiB, 16 KiB per line | matcher returns `SY_ELIMIT`; no prefix match is accepted |
| SFTP directory response | 64 entries, 64 KiB, 4096 scanned storage rows | enumeration continues from its bounded cursor; a scan budget containing only filtered rows fails rather than returning an empty mid-listing batch |
| SSH packet size | conservative library configuration, at most 64 KiB initially | protocol error |
| SSH connection idle | existing invocation idle deadline | invocation ends `Deadline` |

Two hundred fifty-six `struct sy_pollfd` values occupy 4 KiB, still small
beside the default 16 KiB eBPF local-call frame. The table is deliberately
larger than any one resource's own bound, and that is only sound because the
expansion is paired with the bounds above. Ring-bearing endpoints keep the
old table size as their own count — 32, checked where every endpoint enters
the table — because a per-role budget can be released while its endpoint
still holds rings: a closed process handle leaves its stdio endpoints open,
a channel closed from the wire leaves the guest's fd, an ended egress task
gives back its permit. The per-role caps bound what is behind the endpoints
— OS children, PTY masters, transfer services, lanes per channel — and
objects, cursors, and JSON values are charged to the 1 MiB footprint. A
larger integer alone would have let every spare slot allocate today's
512 KiB of rings.

The following allocations all have explicit individual bounds, and their
maximum composition is bounded by the channel, handle, and event-count caps:

- SSH library connection and channel buffers;
- every endpoint ring;
- queued and outstanding event payloads;
- bounded `authorized_keys` scan cursors attached to outstanding auth tokens;
- host-side object and cursor data already charged today.

## 10. Host key

SSH user authentication may be wholly guest-controlled, but the transport
still needs a host signing key.

The node holds one persistent Ed25519 SSH host key:

- generated once on a supported node;
- stored in the existing `0600` SQLite database or an equivalently protected
  local secret record;
- never published as socket content and never exposed to guest memory;
- shared by every SSH-using socket on that node;
- stable across socket re-arms and ordinary device-key rotation;
- restored with the database under the existing recovery model.

It is deliberately not derived from the iroh device secret. Cross-protocol key
reuse would couple SSH host identity to device rotation and turn a compromise
or implementation error in one signature context into a problem for the
other.

The daemon logs the SHA-256 fingerprint when it loads or creates the key. A
stock client can use the existing byte pump directly:

```sh
ssh -o 'ProxyCommand=synch socket connect %h:code/ssh.sock' nas
```

The first SSH host-key exchange already travels through a mutually
authenticated iroh connection to the named origin. The SSH key remains useful
for OpenSSH compatibility, stable `known_hosts` behavior, and detecting an
unexpected loss or replacement of the node database.

## 11. Runtime shape

The SSH implementation belongs in `synch-sock`, beside the endpoint reactor,
not in `synch-net`. The network layer continues handing it an opaque
`DuplexStream` and knows nothing about the bytes after `Opened::Ok`.

The implementation uses `russh` through its server-over-arbitrary-stream
entrypoint. A small reviewed in-tree patch exposes opaque server-side channel
types and their opening payloads instead of rejecting them inside the library;
that patch is pinned and covered locally with the rest of the channel adapter.

The runtime integration is:

1. `sy_ssh_start` takes the unselected `DuplexStream`, combines its boxed read
   and write halves into one async I/O object, and starts the SSH task.
2. The SSH handler owns only `Send` state and communicates through bounded
   channels. It never captures the worker's `Rc<Inner>`.
3. Handler callbacks insert events directly into the invocation's bounded,
   lock-protected control queue and bump the existing readiness epoch; no
   separate bridge task is needed.
4. Authentication handlers await one-shot guest replies. Channel opens keep a
   deferred reply handle, so waiting for eBPF policy does not block traffic on
   established channels.
5. Accepting or opening a channel turns the library's channel stream into an
   ordinary runtime endpoint with `EndpointRole::SshChannel` and retained type metadata.
6. Library output helpers for request replies, exit status, extended data and
   disconnects are driven by guest response messages.
7. Invocation cleanup aborts the SSH task, rejects or drops every pending
   response, zeroizes credential payloads, closes all channel endpoints, and
   lets the ordinary `sync/sock/1` completion path report the invocation's
   `SockStatus`.

All SSH helpers are synchronous operations over host-side state. `sy_poll`
remains the only helper that suspends the guest. The SSH task may await network
I/O independently, just as current endpoint reader and writer tasks do.

## 12. Security invariants

The host enforces these regardless of guest correctness:

1. **Outer admission is unchanged.** The socket invocation begins only after
   the `sync/sock/1` peer passed membership and delegation checks.
2. **SSH grants no host capability.** An authenticated SSH user has only the
   channel fds the guest accepts and the behavior the deployed guest implements.
3. **The guest never handles SSH private host keys or raw signature
   verification.** Public-key events distinguish an unverified offer from
   verified possession.
4. **Credentials are bounded and ephemeral.** Passwords and interactive
   responses are never logged, are charged to the payload budget, and are
   zeroized when answered, timed out or disconnected.
5. **Protocol structure fails closed.** Unknown authentication methods,
   algorithms and event responses are rejected. Unknown channel and request
   types are delivered only as bounded opaque values; accepting them invokes
   no host behavior beyond the generic channel transport.
6. **Every asynchronous response is generational.** A stale token cannot
   accept or answer a new channel that reused the same small integer fd.
7. **Backpressure is end to end.** No unbounded queue separates the SSH
   library, endpoint rings and guest pumps.
8. **Hard limits are host policy.** A guest cannot disable authentication
   deadlines, attempt limits, packet bounds, memory charges or channel caps.
9. **Backing authority is checked where the fd is created.** Naming a PTY,
   SFTP subsystem or destination in SSH data never grants it.
10. **Kill and shutdown release everything the runtime owns.** No SSH task,
    deferred channel or credential buffer outlives its invocation.
    **Spawned processes are the deliberate exception.** A declared process is
    started in its own session (`setsid`) and the runtime signals it on
    teardown, but a descendant that outlives its parent — a daemonized child, a
    process that left the group — keeps running under the daemon's UID, and
    nothing reaps it. This follows from §7.1: the runtime imposes no process
    count, runtime or memory ceiling and no descendant containment, so an
    operator who needs a process bounded declares one that bounds itself
    (`bwrap`, `systemd-run`, a wrapper that traps and kills its own group).
    Treat "declare a process capability" as "grant the ability to leave
    something running on this host".
11. **Authorization data is explicit and immutable.** The guest chooses an
    object fd, matching is tied to that object's content root and the exact
    authentication event, and unsupported `authorized_keys` options never
    degrade into a less restrictive match.
12. **Capability ids are program-local selectors.** An id resolves only inside
    the declarations of the program root currently being served; it cannot name
    mutable daemon state or a capability belonging to another socket.

The eBPF sandbox remains defence in depth. The primary execution gate is still
that the callee published, at a path it activated, the exact program root
being run.

## 13. Failure semantics

| Failure | Guest observation | SSH/client observation |
| --- | --- | --- |
| `sy_ssh_start` after raw I/O | `SY_ESTATE`; raw stream remains selected | unchanged raw stream |
| Unsupported auth method selected | `SY_EINVAL` or rejected reply | method not advertised / attempt rejected |
| Auth event times out | control fd reaches `HUP` | authentication disconnect |
| Malformed SSH packet or failed crypto | control fd `ERR` beside `HUP`; `sy_errno` is `SY_ECONNRESET`, or `SY_ETIMEDOUT` for a transport deadline | protocol disconnect |
| Channel handle cap | `sy_ssh_channel_accept` returns `SY_ELIMIT` | channel-open failure |
| Request token is stale | response helper returns `SY_ESTATE` | current channel is untouched |
| `authorized_keys` object is cold | matcher returns `SY_EAGAIN`; object fd becomes pollable | authentication remains pending within its deadline |
| `authorized_keys` exceeds its bound | matcher returns `SY_ELIMIT`; no match | guest rejects authentication or chooses another policy source |
| Backing capability refused | its existing helper error, commonly `SY_EPERM` | guest chooses request failure or channel close |
| Channel peer sends EOF | channel `IN`/`RDHUP`, then `sy_read == 0` after drain | local write half remains usable |
| Guest closes channel | fd becomes invalid | SSH EOF/close after queued output as requested |
| Guest closes fd zero | connection state torn down; later SSH helpers fail | best-effort orderly SSH disconnect |
| SSH connection closes | control fd `HUP`; all channel fds converge to `HUP` | normal disconnect |
| Operator kills invocation | final `SockStatus::Killed` | SSH disconnect/EOF and closed underlying stream |
| Daemon stops | final `SockStatus::Shutdown` | SSH disconnect/EOF inside daemon shutdown budget |

An SSH channel's exit status is separate from the socket invocation's
`SockStatus`. Several sessions can produce different exit statuses while the
one eBPF program eventually returns one value for the enclosing
`sync/sock/1` invocation.

## 14. Testing

The protocol adapter is tested before any process or file-transfer capability
is added.

### 14.1 ABI and policy

- the SDK header carries no numbered SSH constants, and every method, event
  kind and field name the runtime serves resolves through the string maps;
- `sy_ssh_start` needs no declaration and is refused in init mode;
- a pristine stream upgrades, while every raw endpoint operation selects raw
  mode and makes a later upgrade fail without losing bytes;
- every `sy_peer_*` identity query remains valid before `sy_ssh_start` without
  selecting raw mode, while endpoint byte operations still select it;
- unknown method names and malformed responses fail closed;
- event tokens cannot be reused across completion, close or fd recycling.
- capability declarations are self-contained, duplicate ids fail arming, and
  an id from another program root grants nothing;

### 14.2 Authentication

- an allowed Iroh device key reaches SSH and may use `none`, while a disallowed
  key receives a raw stream close before any SSH server bytes;
- `none` accepted and rejected by eBPF;
- username-specific method lists;
- password success and failure without credential logging;
- public-key offer followed by host-verified possession;
- a direct signed public-key attempt without an offer;
- canonical key blobs and raw fingerprints agree across both public-key paths;
- an option-free tree-backed `authorized_keys` file matches offers and verified
  attempts against the same canonical key blob;
- key-file updates affect new invocations while an already-open object remains
  pinned to its immutable root;
- cold key objects resume through `SY_EAGAIN`, and oversized files, oversized
  lines, malformed records, and records with options never authorize a key;
- a verified-key principal remains bound to all later channels on the same
  connection and never leaks to another invocation;
- partial success followed by another method;
- attempt and authentication-time bounds;
- username or service changes disconnect and clear host-side state;
- regression cases from every relevant SSH-library server advisory.

### 14.3 Channels and requests

- several simultaneous channels of the same or different types become distinct fds;
- accept, reject and resource-exhaustion paths;
- client- and server-initiated generic channel opens have the same connecting,
  flow-control, EOF, close, and generation semantics;
- shell, exec, subsystem, PTY, environment, resize, signal and break events;
- delayed response on one channel does not block data on another;
- ordinary data and stderr remain separate;
- an unknown extended-data type creates no fd until the guest asks for its
  lane, and both lane creation and bounded discard release window pressure;
- exit status arrives after final output rather than racing it away;
- EOF is a half-close and a response remains writable;
- an unknown channel type can be accepted as an inert byte stream without
  creating any backing capability;
- malformed standard opening data is rejected before reaching the guest;
- a `direct-tcpip` channel reaches only an independently declared and checked
  egress fd, while unsupported global forwarding requests fail closed;
- two fingerprints select different fixed process capabilities without evaluating
  the client command through a shell.

### 14.4 Flow control and lifecycle

- multi-megabyte transfers in both directions with deliberately tiny rings;
- two-way traffic where each side fills the other's window;
- a guest that stops reading backpressures the SSH client without growing
  memory;
- handle, channel, event-count and payload-byte exhaustion;
- idle deadline, guest fault, operator kill and daemon shutdown;
- no task, handle, pending response or credential remains after cleanup;
- invocation statistics count channel plaintext once rather than encrypted
  wire bytes or both sides of a pump.

### 14.5 Interoperability

- an in-process SSH client covers deterministic edge cases;
- OpenSSH connects through `ProxyCommand` and exercises `none`, password and
  public-key authentication;
- one OpenSSH connection opens multiple sequential and concurrent sessions;
- OpenSSH ControlMaster opens and closes repeated channel fds without repeating
  SSH authentication or leaking per-session request state;
- the hardcoded-Iroh-key shell example rejects the wrong device before SSH,
  accepts `none` for the right device, allocates a PTY without starting a
  process, starts exactly one declared shell after `shell`, applies resize and
  signal events, and delivers final PTY output before exit status;
- SFTP subsystem reads in flat and recursive declared scopes;
- host-key persistence is checked across daemon restarts and device-key
  rotation;
- Linux and macOS exercise the same eBPF example through the embedded compiler.

## 15. Example socket programs

These examples are normative ABI and policy sketches against the SDK in this
document; the shared reactor pieces they name (`struct attached`,
`run_interactive_reactor`) are shorthand for the §15.1 loop rather than
shipped SDK code. The first shows the complete control/data reactor. Later
examples reuse that reactor and
show only the declaration and policy branches that change. In all cases the
guest, not the SSH adapter, owns every call to `sy_pump`.

### 15.1 Iroh-key-authenticated generic channel echo

This socket has no backing declaration. It admits one exact Iroh device key,
uses that outer identity as the authentication factor, accepts SSH `none`, and
echoes ordinary data on any channel type. Accepting an unfamiliar type is safe
here because it creates only an inert peer byte stream.

```c
#include <synch.h>

#define MAX_CHANNELS 8

static const sy_u8 allowed_peer[32] = {
  /* operator-selected Iroh public key */
  0x12, 0x8a, 0x73, 0x44, 0x91, 0x2c, 0x08, 0xe1,
  0x59, 0xd0, 0xaa, 0x63, 0x38, 0x90, 0x1b, 0x72,
  0x04, 0x66, 0x2f, 0xbc, 0x81, 0x57, 0x09, 0x33,
  0xde, 0x28, 0x6a, 0x90, 0x3d, 0x17, 0x55, 0xc0,
};

struct echo_channel {
  sy_s64 fd;
  sy_u32 read_done;
  struct sy_pump echo;
  char buf[512];
};

static int str_is(const char *value, const char *want) {
  sy_u64 len = sy_strlen(want);
  return sy_strlen(value) == len && sy_memcmp(value, want, len) == 0;
}

static int same_key(const sy_u8 a[32], const sy_u8 b[32]) {
  sy_u8 different = 0;
  for (sy_u32 i = 0; i < 32; i++) different |= a[i] ^ b[i];
  return different == 0;
}

static sy_s64 free_slot(struct echo_channel slots[MAX_CHANNELS]) {
  for (sy_s64 i = 0; i < MAX_CHANNELS; i++)
    if (slots[i].fd < 0) return i;
  return -1;
}

SY_ENTRY sy_s64 entry(void) {
  sy_u8 peer[32];
  if (sy_peer_device_key(peer) < 0 || !same_key(peer, allowed_peer))
    return 1;                         /* no SSH bytes have been sent */

  sy_s64 methods = sy_json_parse(SY_STR("[\"none\"]"));
  if (methods < 0 || sy_ssh_start(SY_SELF, methods) < 0) return 1;
  sy_close(methods);

  struct echo_channel slots[MAX_CHANNELS] = {0};
  for (sy_u32 i = 0; i < MAX_CHANNELS; i++) slots[i].fd = -1;

  for (;;) {
    struct sy_pollfd pollfds[1 + MAX_CHANNELS];
    sy_s64 owners[1 + MAX_CHANNELS];
    sy_u64 count = 1;
    pollfds[0] = (struct sy_pollfd){ SY_SELF, SY_POLL_IN, 0 };
    owners[0] = -1;

    for (sy_u32 i = 0; i < MAX_CHANNELS; i++) {
      if (slots[i].fd < 0) continue;
      sy_u32 interest = 0;
      if (!slots[i].read_done)
        interest = sy_pump_blocked(&slots[i].echo)
            ? SY_POLL_OUT : SY_POLL_IN;
      pollfds[count] = (struct sy_pollfd){ slots[i].fd, interest, 0 };
      owners[count++] = i;
    }

    sy_s64 ready = sy_poll(pollfds, count, -1);
    if (ready <= 0) break;

    if (pollfds[0].revents & SY_POLL_IN) {
      sy_s64 event;
      while ((event = sy_ssh_next(SY_SELF)) > 0) {
        /* Capture the dispatch facts, then close the JSON snapshot: the
           event itself stays outstanding until a decision consumes it. */
        char kind[40] = {0};
        sy_json_get_string(event, SY_STR("kind"), kind, sizeof kind);
        sy_s64 id = 0;
        sy_json_get_i64(event, SY_STR("id"), &id);
        sy_s64 want_reply = sy_json_get_bool(event, SY_STR("want_reply"));
        sy_close(event);

        if (str_is(kind, "auth_none")) {
          sy_s64 accept = sy_json_parse(SY_STR("{\"result\":\"accept\"}"));
          if (accept >= 0) {
            sy_ssh_auth_reply((sy_u64)id, accept);
            sy_close(accept);
          }
          continue;
        }

        if (str_is(kind, "channel_open")) {
          sy_s64 slot = free_slot(slots);
          if (slot < 0) {
            sy_ssh_channel_reject((sy_u64)id, SY_STR("resource_shortage"));
            continue;
          }
          sy_s64 channel = sy_ssh_channel_accept((sy_u64)id);
          if (channel >= 0) {
            slots[slot].fd = channel;
            slots[slot].read_done = 0;
            slots[slot].echo = (struct sy_pump)SY_PUMP_INIT;
          }
          continue;
        }

        if (str_is(kind, "channel_request")) {
          if (want_reply == 1)
            sy_ssh_request_reply((sy_u64)id, 0);
          else
            sy_ssh_event_done((sy_u64)id);
          continue;
        }

        sy_ssh_event_done((sy_u64)id);  /* authenticated notification, etc. */
      }
    }

    for (sy_u64 p = 1; p < count; p++) {
      sy_u32 i = owners[p];
      struct echo_channel *slot = &slots[i];
      if (pollfds[p].revents & (SY_POLL_ERR | SY_POLL_HUP)) {
        sy_close(slot->fd);
        slot->fd = -1;
        continue;
      }
      if (slot->read_done) continue;

      sy_s64 moved = sy_pump(
          slot->fd, slot->fd,
          slot->buf, sizeof slot->buf,
          &slot->echo
      );
      if (moved == 0) {
        sy_shutdown(slot->fd);          /* peer EOF is only a half-close */
        slot->read_done = 1;
      } else if (moved < 0 && moved != SY_EAGAIN) {
        sy_close(slot->fd);
        slot->fd = -1;
      }
    }

    if (pollfds[0].revents & (SY_POLL_ERR | SY_POLL_HUP)) break;
  }

  for (sy_u32 i = 0; i < MAX_CHANNELS; i++)
    if (slots[i].fd >= 0) sy_close(slots[i].fd);
  return 0;
}
```

The echo pump uses the same fd as source and destination deliberately: ordinary
channel data is full duplex. Extended data remains on separate lane fds and is
not echoed unless the program explicitly opens and services those lanes.

### 15.2 Iroh-key-authenticated interactive shell

This is the conventional `ssh host` experience with a different authentication
boundary. One hardcoded Iroh device key is the user identity, SSH `none`
completes the inner authentication exchange, and a concrete process capability
starts a fixed local login shell on a PTY. The SSH username is informational
and does not select an OS account. The process runs under the runtime's fixed
service identity, while its declaration pins the executable, argv, and accepted
signals including `HUP` for channel EOF. It is not sandboxed by the runtime.

The example reuses the bounded poll/event reactor from §15.1. These are the
declaration, admission, channel-request, and pump portions that replace its
echo policy:

```c
#include <synch.h>

static const sy_u8 shell_peer[32] = {
  /* the only Iroh public key allowed to reach this shell */
  0x7b, 0x91, 0x3a, 0x20, 0xe4, 0x66, 0x12, 0x5f,
  0x8d, 0x02, 0xc8, 0x77, 0xa1, 0x49, 0x35, 0x6c,
  0xf0, 0x18, 0x42, 0xbb, 0x69, 0x5a, 0x03, 0xd1,
  0x2e, 0x84, 0x56, 0x9c, 0x31, 0xad, 0x70, 0x0f,
};

#define PROCESS_LOCAL_LOGIN_SHELL 1

SY_MANIFEST("{\"manifest\":1,"
            "\"processes\":[{\"id\":1,\"allow\":[\"pty\"],"
            "\"executable\":\"/bin/sh\",\"argv\":[\"sh\",\"-l\"],"
            "\"allowed_signals\":[\"HUP\",\"INT\",\"TERM\"]}]}");

struct terminal {
  struct attached io;                 /* channel <-> PTY */
  sy_s64 process;                     /* separate control handle */
  sy_u32 shell_started;
  sy_u32 input_done;
  sy_u32 output_done;
  /* status facts, read out of the JSON and retained until output drains */
  sy_s64 exit_code;
  sy_u32 signaled;
  sy_u32 core_dumped;
  char signal[32];
  sy_u32 have_status;
};

static int same_iroh_key(const sy_u8 a[32], const sy_u8 b[32]) {
  sy_u8 different = 0;
  for (sy_u32 i = 0; i < 32; i++) different |= a[i] ^ b[i];
  return different == 0;
}

/* `event` is the JSON handle from sy_ssh_next; `id` its outstanding token. */
static sy_s64 finish_request(sy_s64 event, sy_u64 id, sy_u32 granted) {
  if (sy_json_get_bool(event, SY_STR("want_reply")) == 1)
    return sy_ssh_request_reply(id, granted);
  return sy_ssh_event_done(id);
}

static sy_s64 handle_inner_auth(sy_s64 event, sy_u64 id) {
  char kind[40] = {0};
  sy_json_get_string(event, SY_STR("kind"), kind, sizeof kind);
  if (!str_is(kind, "auth_none")) {
    sy_s64 reject = sy_json_parse(SY_STR(
        "{\"result\":\"reject\",\"next_methods\":[\"none\"]}"));
    if (reject < 0) return reject;
    sy_s64 rc = sy_ssh_auth_reply(id, reject);
    sy_close(reject);
    return rc;
  }
  /* Reaching this event means the hardcoded Iroh-key check already passed. */
  sy_s64 accept = sy_json_parse(SY_STR("{\"result\":\"accept\"}"));
  if (accept < 0) return accept;
  sy_s64 rc = sy_ssh_auth_reply(id, accept);
  sy_close(accept);
  return rc;
}

static sy_s64 accept_shell_channel(
    sy_s64 event,
    sy_u64 id,
    struct terminal *terminal
) {
  char type[32] = {0};
  sy_json_get_string(event, SY_STR("channel_type"), type, sizeof type);
  if (terminal->io.channel >= 0 || !str_is(type, "session"))
    return sy_ssh_channel_reject(id, SY_STR("administratively_prohibited"));

  sy_s64 channel = sy_ssh_channel_accept(id);
  if (channel < 0) return channel;
  terminal->io.channel = channel;
  return 0;
}

static sy_s64 handle_shell_request(
    sy_s64 event,
    sy_u64 id,
    struct terminal *terminal
) {
  sy_s64 fd = -1;
  sy_json_get_i64(event, SY_STR("fd"), &fd);
  if (fd != terminal->io.channel)
    return finish_request(event, id, 0);

  char type[32] = {0};
  sy_json_get_string(event, SY_STR("request_type"), type, sizeof type);

  if (str_is(type, "pty-req")) {
    if (terminal->io.backend >= 0 || terminal->shell_started)
      return finish_request(event, id, 0);

    sy_s64 spec = sy_ssh_pty_spec(id);
    if (spec < 0) return finish_request(event, id, 0);

    sy_s64 pty = sy_pty_open(PROCESS_LOCAL_LOGIN_SHELL, spec);
    sy_close(spec);
    if (pty < 0) return finish_request(event, id, 0);
    terminal->io.backend = pty;        /* allocation starts no process */
    return finish_request(event, id, 1);
  }

  if (str_is(type, "shell")) {
    if (terminal->io.backend < 0 || terminal->shell_started)
      return finish_request(event, id, 0);

    sy_s64 process = sy_process_spawn_pty(
        PROCESS_LOCAL_LOGIN_SHELL, terminal->io.backend);
    if (process < 0)
      return finish_request(event, id, 0);

    terminal->process = process;
    terminal->shell_started = 1;
    terminal->io.to_backend = (struct sy_pump)SY_PUMP_INIT;
    terminal->io.to_channel = (struct sy_pump)SY_PUMP_INIT;
    return finish_request(event, id, 1);
  }

  if (str_is(type, "window-change")) {
    if (terminal->io.backend < 0)
      return finish_request(event, id, 0);
    sy_s64 columns = 0, rows = 0, width = 0, height = 0;
    sy_json_get_i64(event, SY_STR("columns"), &columns);
    sy_json_get_i64(event, SY_STR("rows"), &rows);
    sy_json_get_i64(event, SY_STR("pixel_width"), &width);
    sy_json_get_i64(event, SY_STR("pixel_height"), &height);
    sy_s64 resized = sy_pty_resize(
        terminal->io.backend,
        (sy_u32)columns, (sy_u32)rows, (sy_u32)width, (sy_u32)height);
    return finish_request(event, id, resized < 0 ? 0 : 1);
  }

  if (str_is(type, "signal")) {
    char signal[32] = {0};
    sy_s64 len = sy_json_get_string(
        event, SY_STR("signal"), signal, sizeof signal);
    sy_s64 sent = terminal->process < 0 || len < 0 ||
                          len >= (sy_s64)sizeof signal
        ? SY_EPERM
        : sy_process_signal(terminal->process, signal, (sy_u64)len);
    return finish_request(event, id, sent < 0 ? 0 : 1);
  }

  /* This interactive socket rejects exec, subsystem, env, and agent policy. */
  return finish_request(event, id, 0);
}

static sy_s64 move_terminal(struct terminal *terminal) {
  if (!terminal->input_done) {
    sy_s64 up = sy_pump(
        terminal->io.channel, terminal->io.backend,
        terminal->io.upward, sizeof terminal->io.upward,
        &terminal->io.to_backend);
    if (up == 0) {
      /* A PTY has no socket-like write half. Ask the declared shell to hang
         up, but retain the PTY master long enough to drain final output. */
      if (terminal->process >= 0)
        sy_process_signal(terminal->process, SY_STR("HUP"));
      terminal->input_done = 1;
    }
    if (up < 0 && up != SY_EAGAIN) return up;
  }

  if (!terminal->output_done) {
    sy_s64 down = sy_pump(
        terminal->io.backend, terminal->io.channel,
        terminal->io.downward, sizeof terminal->io.downward,
        &terminal->io.to_channel);
    if (down == 0) terminal->output_done = 1;
    if (down < 0 && down != SY_EAGAIN) return down;
  }
  return 0;
}

SY_ENTRY sy_s64 entry(void) {
  sy_u8 peer[32];
  if (sy_peer_device_key(peer) < 0 ||
      !same_iroh_key(peer, shell_peer))
    return 1;                           /* reject before SSH mode */

  sy_s64 methods = sy_json_parse(SY_STR("[\"none\"]"));
  if (methods < 0 || sy_ssh_start(SY_SELF, methods) < 0) return 1;
  sy_close(methods);

  struct terminal terminal = {0};
  terminal.io.channel = -1;
  terminal.io.backend = -1;
  terminal.process = -1;

  /* The §15.1 reactor now:
     - sends authentication events to handle_inner_auth;
     - sends channel_open events to accept_shell_channel;
     - sends channel_request events to handle_shell_request;
     - polls channel, PTY, process, and fd zero;
     - calls move_terminal according to both pumps' readiness;
     - reads sy_process_status when the process handle becomes readable,
       copying the status JSON's fields into `struct terminal`. */
  return run_interactive_reactor(&terminal);
}
```

`run_interactive_reactor` is the §15.1 loop with a PTY fd and process-control
handle added to its poll set; it is named here only to avoid repeating that
reactor verbatim. When the process handle becomes readable, it calls
`sy_process_status` but retains the result until `move_terminal` has observed
PTY EOF and flushed any blocked `to_channel` remainder. It then sends
`sy_ssh_exit_status` or `sy_ssh_exit_signal`, half-closes the SSH channel, and
waits for terminal close. Connection or channel teardown closes the process
handle first, ensuring that the declared child is killed and reaped, then
closes the PTY and channel.

The result behaves like an ordinary interactive SSH login: terminal modes and
initial dimensions come from `pty-req`, resize follows `window-change`, client
input and terminal output are explicitly pumped, and the final process status
is preserved. What it does not do is implicit OS login policy—the one Iroh key
maps to the one concretely declared shell capability because the deployed eBPF program
says so.

This compact example permits one live shell channel. Replacing `terminal` with
the same bounded slot array used in §15.1 permits several independent PTYs on a
control-master connection; each PTY and process is charged separately to the
invocation's ordinary handle and channel limits.

A stock client reaches it through the existing transport bridge:

```sh
ssh -o 'ProxyCommand=synch socket connect %h:code/ssh.sock' nas
```

### 15.3 Tree-backed `authorized_keys` and fixed commands

This program loads two option-free `authorized_keys` files from its own virtual
tree and declares two fixed process capabilities. The file matching the verified
key chooses a principal, and that principal chooses which already-declared
command runs. The client's `exec` bytes are inspected only to decide whether
the request kind is allowed; neither capability evaluates them as a shell command.

```c
#include <synch.h>

enum principal { PRINCIPAL_NONE, PRINCIPAL_ADMIN, PRINCIPAL_DEPLOY };

struct auth_files {
  sy_s64 admin;
  sy_s64 deploy;
};

#define PROCESS_ADMIN_STATUS    1
#define PROCESS_PUBLISH_RELEASE 2

SY_MANIFEST("{\"manifest\":1,\"processes\":["
            "{\"id\":1,\"allow\":[\"pipe\"],"
            "\"executable\":\"/usr/local/bin/admin-status\","
            "\"argv\":[\"admin-status\"]},"
            "{\"id\":2,\"allow\":[\"pipe\"],"
            "\"executable\":\"/usr/local/bin/publish-release\","
            "\"argv\":[\"publish-release\"]}]}");

/* Called at invocation start, before any endpoint operation on SY_SELF. */
static sy_s64 begin_ssh(struct auth_files *files) {
  files->admin = sy_open(SY_STR("code/ssh/admin_authorized_keys"));
  if (files->admin < 0) return files->admin;

  files->deploy = sy_open(SY_STR("code/ssh/deploy_authorized_keys"));
  if (files->deploy < 0) {
    sy_close(files->admin);
    return files->deploy;
  }

  sy_s64 methods = sy_json_parse(SY_STR("[\"publickey\"]"));
  if (methods < 0) return methods;
  sy_s64 started = sy_ssh_start(SY_SELF, methods);
  sy_close(methods);
  return started;
}

static sy_s64 auth_reply_with(sy_u64 id, const char *reply_json) {
  sy_s64 reply = sy_json_parse(reply_json, sy_strlen(reply_json));
  if (reply < 0) return reply;
  sy_s64 rc = sy_ssh_auth_reply(id, reply);
  sy_close(reply);
  return rc;
}

/* Called from the control-event branch of the reactor in example 15.1, with
   the event's JSON handle and outstanding id. SY_EAGAIN means retain the
   event, poll the key objects, and retry it. */
static sy_s64 handle_auth(
    sy_s64 event,
    sy_u64 id,
    const struct auth_files *files,
    enum principal *principal
) {
  enum principal candidate = PRINCIPAL_NONE;
  sy_s64 matched = sy_ssh_authorized_keys_match(id, files->admin);
  if (matched == SY_EAGAIN) return SY_EAGAIN;
  if (matched < 0) goto reject;
  if (matched == 1) {
    candidate = PRINCIPAL_ADMIN;
  } else {
    matched = sy_ssh_authorized_keys_match(id, files->deploy);
    if (matched == SY_EAGAIN) return SY_EAGAIN;
    if (matched < 0) goto reject;
    if (matched == 1) candidate = PRINCIPAL_DEPLOY;
  }

  if (kind_is(event, "auth_publickey_offer")) {
    return auth_reply_with(id, candidate == PRINCIPAL_NONE
        ? "{\"result\":\"reject\",\"next_methods\":[\"publickey\"]}"
        : "{\"result\":\"offer_accept\",\"next_methods\":[\"publickey\"]}");
  }

  if (kind_is(event, "auth_publickey_verified") &&
      candidate != PRINCIPAL_NONE) {
    *principal = candidate;            /* connection-wide guest state */
    return auth_reply_with(id, "{\"result\":\"accept\"}");
  }

reject:
  return auth_reply_with(id,
      "{\"result\":\"reject\",\"next_methods\":[\"publickey\"]}");
}

/* `channel` was accepted only after "channel_type" compared equal to
   "session". This uses the single-stdio-endpoint process shape from §7.1. */
static sy_s64 start_for_request(
    enum principal principal,
    sy_s64 channel,
    sy_u64 event_id,
    struct attached *out,
    sy_s64 *process_out
) {
  sy_u32 capability;
  if (principal == PRINCIPAL_ADMIN) {
    capability = PROCESS_ADMIN_STATUS;
  } else if (principal == PRINCIPAL_DEPLOY) {
    capability = PROCESS_PUBLISH_RELEASE;
  } else {
    return sy_ssh_request_reply(event_id, 0);
  }

  sy_s64 process = sy_process_spawn(capability);
  if (process < 0)
    return sy_ssh_request_reply(event_id, 0);

  sy_s64 stdio = sy_process_stdio(process, SY_STR("main"));
  if (stdio < 0) {
    sy_close(process);
    return sy_ssh_request_reply(event_id, 0);
  }

  out->channel = channel;
  out->backend = stdio;
  out->to_backend = (struct sy_pump)SY_PUMP_INIT;
  out->to_channel = (struct sy_pump)SY_PUMP_INIT;
  *process_out = process;
  sy_ssh_request_reply(event_id, 1);
  return 0;
}
```

The surrounding reactor accepts multiple `session` channels and maintains one
`struct attached` and one process-control handle per live channel. In its data
branch it calls `sy_pump(channel, backend, ...)` and
`sy_pump(backend, channel, ...)` with separate state and buffers. Consequently
an OpenSSH control master can run several instances concurrently while
authentication remains connection-wide.
Once `authenticated` arrives, the reactor closes both key objects and frees
their handle slots. A cold tree read does not block the worker thread: the
outstanding auth event is generational, and the reactor polls whichever object
returned `SY_EAGAIN` until it can retry or the host authentication deadline
expires. SSH cannot open channels until that decision completes.

### 15.4 Declared SFTP service

This program accepts only `session` channels and only the `sftp` subsystem. It
opens the declared SFTP endpoint after the request arrives, answers success,
and explicitly copies bytes in both directions.

```c
#include <synch.h>

#define FILE_TRANSFER_RELEASES 1

SY_MANIFEST("{\"manifest\":1,"
            "\"file_transfers\":[{\"id\":1,\"protocol\":\"sftp\","
            "\"access\":[\"read\"],\"scope\":\"code/releases\"}]}");

static int event_text_is(sy_s64 event, const char *key, const char *want) {
  char value[32] = {0};
  sy_s64 len = sy_json_get_string(event, key, sy_strlen(key),
                                  value, sizeof value);
  if (len < 0 || len >= (sy_s64)sizeof value) return 0;
  return str_is(value, want);
}

/* The outer reactor has already authenticated the connection and accepted
   this channel only after "channel_type" compared equal to "session". */
static sy_s64 accept_sftp_request(
    sy_s64 channel,
    sy_s64 event,
    sy_u64 id,
    struct attached *out
) {
  if (!event_text_is(event, "request_type", "subsystem") ||
      !event_text_is(event, "subsystem", "sftp")) {
    if (sy_json_get_bool(event, SY_STR("want_reply")) == 1)
      return sy_ssh_request_reply(id, 0);
    return sy_ssh_event_done(id);
  }

  sy_s64 sftp = sy_sftp_open(FILE_TRANSFER_RELEASES);
  if (sftp < 0)
    return sy_ssh_request_reply(id, 0);

  out->channel = channel;
  out->backend = sftp;
  out->to_backend = (struct sy_pump)SY_PUMP_INIT;
  out->to_channel = (struct sy_pump)SY_PUMP_INIT;
  sy_ssh_request_reply(id, 1);
  return 0;
}

static sy_s64 move_sftp(struct attached *a) {
  sy_s64 up = sy_pump(
      a->channel, a->backend,
      a->upward, sizeof a->upward,
      &a->to_backend
  );
  if (up == 0) sy_shutdown(a->backend);
  if (up < 0 && up != SY_EAGAIN) return up;

  sy_s64 down = sy_pump(
      a->backend, a->channel,
      a->downward, sizeof a->downward,
      &a->to_channel
  );
  if (down == 0) sy_shutdown(a->channel);
  if (down < 0 && down != SY_EAGAIN) return down;
  return 0;
}
```

The declaration gates creation of the `sftp` fd; accepting the SSH channel and
subsystem request does not. Adding `write` also requires a same-id tree-write
declaration, but does not change the SSH channel logic. The shipped
`crates/synch-sock/examples/ssh-shell.c` combines the shell path above with
this read/write SFTP path and declares both sides of that authority.

### 15.5 A generic `direct-tcpip` channel with declared egress

Generic channels also remove the need for a forwarding-specific byte API. A
program handling a `channel_open` event can compare the channel type with
`direct-tcpip`, inspect the host-parsed destination fields, and open an
ordinary declared TCP fd. It accepts the SSH channel only after the backend is
available, then uses the same two-pump `struct attached`:

```c
SY_MANIFEST("{\"manifest\":1,\"egress\":[\"git.internal:9418\"]}");

static sy_s64 begin_git_forward(
    sy_s64 event,
    sy_u64 id,
    sy_u64 *pending_event,
    sy_s64 *pending_tcp
) {
  sy_s64 port = -1;
  sy_json_get_i64(event, SY_STR("port"), &port);
  if (!event_text_is(event, "channel_type", "direct-tcpip") ||
      !event_text_is(event, "destination_host", "git.internal") ||
      port != 9418) {
    return sy_ssh_channel_reject(id, SY_STR("administratively_prohibited"));
  }

  sy_s64 tcp = sy_tcp_connect(SY_STR("git.internal"), 9418);
  if (tcp < 0)
    return sy_ssh_channel_reject(id, SY_STR("connect_failed"));

  *pending_event = id;                 /* event token remains outstanding */
  *pending_tcp = tcp;
  return 0;
}

/* Called only after pending_tcp reaches POLL_OUT. An ERR instead rejects the
   saved event with CONNECT_FAILED and closes the TCP fd. */
static sy_s64 finish_git_forward(
    sy_u64 pending_event,
    sy_s64 tcp,
    struct attached *out
) {
  sy_s64 channel = sy_ssh_channel_accept(pending_event);
  if (channel < 0) { sy_close(tcp); return channel; }

  out->channel = channel;
  out->backend = tcp;
  out->to_backend = (struct sy_pump)SY_PUMP_INIT;
  out->to_channel = (struct sy_pump)SY_PUMP_INIT;
  return 0;
}
```

The destination named in SSH data grants nothing. Both the guest comparison
and the manifest's egress declaration must permit the connection.

## 16. Implementation order

The adapter was built in this order, and the separation remains load-bearing
for reviewing any change to it:

1. **Endpoint roles and resource accounting.** Remove the assumption that every
   nonzero endpoint is TCP egress; charge rings and raise the handle/poll bound.
2. **Lazy `SY_SELF` selection.** Preserve every raw-stream test before adding
   SSH.
3. **SSH connection and authentication.** Persistent host key, control fd,
   bounded events, method selection, auth replies, and the tree-object
   `authorized_keys` matcher.
4. **Channel fds.** Generic inbound and outbound opens, ordinary data,
   extended-data lanes, requests, exit status, half-close and cleanup.
5. **Interop and hostile-input tests.** Include dependency-advisory regression
   cases before calling the adapter complete.
6. **Backing designs independently.** Process/PTY capabilities and a file-transfer
   service land only after the protocol adapter works against an eBPF-native
   echo or status service.

Keeping step 6 separate is load-bearing. Bundling a shell or file-transfer
server into the first SSH change would make it impossible to tell whether a
policy defect belongs to the protocol adapter or to newly introduced host
authority.

## 17. Non-goals

This design does not include:

- an automatic OS login, shell, PAM, `authorized_keys` discovery, or full
  OpenSSH option semantics;
- an implicit mapping from SSH username to Synchronicity origin;
- automatic attachment of channels to any backend;
- mutable daemon-side process or file-transfer configuration;
- arbitrary process execution merely because `exec` was requested;
- automatic direct or reverse forwarding, X11 or agent services;
- guest control over cryptographic algorithm policy or host private keys;
- a second network listener or SSH ALPN;
- one eBPF invocation per SSH channel;
- declarations whose only purpose is to label a protocol rather than approve
  additional authority.

Those omissions are what make the core useful: SSH is a bounded, programmable
multiplexer over an already-authorized socket stream, and nothing more.
