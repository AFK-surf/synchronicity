# SSH over sockets

Status: **proposed**. This document designs a built-in SSH protocol adapter for
Synchronicity sockets. Nothing described here is implemented yet.

The short version is:

> SSH turns one byte stream into a control fd and several data fds. It grants no
> host authority and therefore needs no declaration. An eBPF program chooses the
> authentication policy, accepts SSH channels, opens separately declared backing
> capabilities, and copies bytes between their virtual fds.

This extends the socket runtime in [`docs/SOCKETS.md`](SOCKETS.md); it does not
add another network protocol. The caller still opens one `sync/sock/1`
bidirectional stream, and the callee still runs one invocation of its own armed
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
authority. It grants access only to behavior the already-armed program can
perform. Any effect behind the accepted connection remains governed by its own
declaration.

This matters when a member runs `synch connect --listen`: many ordinary TCP
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
- the service may exercise only underlying tree authority the invocation also
  holds: foreign-origin reads retain the existing tree-read declaration, and
  writes or live-filesystem access require their corresponding authority;
- if the project later wants *all* exports to require review, `sy_open` itself
  must move behind a declaration. Adding a declaration only to an SFTP helper
  would give a false assurance.

### 1.3 Zero-configuration capability declarations

Every backing declaration is complete data embedded in the program artifact.
It contains the exact process executable and argv, or the exact file-transfer
scope and access. Runtime calls select one with a small integer id meaningful
only inside that program root. There is no daemon-wide registry, separate
creation command, mutable lookup record, or arm-time value for an operator to
supply. Id namespaces are also capability-specific: a process id cannot be
used with an SFTP helper or vice versa.

The operator workflow remains one decision: inspect the concrete declarations
printed by `synch socket arm` and approve or refuse the program. The host may
refuse an artifact whose executable is absent, whose feature is unsupported on
that node, or whose request exceeds hard safety limits, but it never asks the
operator to repair the declaration interactively. Host keys, process isolation
defaults, resource ceilings, and clean process environments are generated or
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

The proposed entrypoint is:

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
   `SY_ESTATE`. Polling it remains valid, with the control-fd semantics in §5.

`SY_ESTATE` is a new negative result for an operation that is valid in the ABI
but invalid in the handle's current protocol state. Reusing `SY_EINVAL` would
make a malformed argument indistinguishable from touching a stream too late to
upgrade safely.

### 3.1 Lazy selection of raw mode

Today the runtime constructs an `Endpoint` for `SY_SELF` and immediately starts
reader and writer tasks before entering the guest. Recovering the underlying
halves from those tasks after an SSH call would be racy and would need another
pair of rings and a bridge.

Instead, `SY_SELF` becomes a small unselected slot holding the original
`DuplexStream`. Its first operation selects exactly one mode:

- `sy_ssh_start` consumes it directly into the SSH engine;
- the first `sy_read`, `sy_write`, `sy_readable`, `sy_writable`, `sy_shutdown`,
  `sy_close`, or endpoint `sy_poll` materializes the existing raw `Endpoint`
  and its pumps.

Existing programs are unchanged: their first ordinary operation selects raw
mode. An SSH program must call `sy_ssh_start` before including `SY_SELF` in a
poll set.

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
sy_peer_kind();
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

if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0)
  return 1;
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

The first ABI should support:

```c
#define SY_SSH_AUTH_NONE       0x01
#define SY_SSH_AUTH_PUBLICKEY  0x02
#define SY_SSH_AUTH_PASSWORD   0x04
```

The bit for `none` controls whether a `none` request may be accepted but is
never included in SSH's advertised method name-list, as RFC 4252 requires.
Keyboard-interactive, host-based authentication and OpenSSH certificates can
be added with new bits and event kinds without changing the lifecycle.

Authentication event kinds are:

```c
SY_SSH_EVENT_AUTH_NONE
SY_SSH_EVENT_AUTH_PASSWORD
SY_SSH_EVENT_AUTH_PUBLICKEY_OFFER
SY_SSH_EVENT_AUTH_PUBLICKEY_VERIFIED
SY_SSH_EVENT_AUTHENTICATED
```

Every event includes the username and service. A public-key offer says only
that the client asked whether a key might be acceptable. A verified event is
emitted only after the host has validated proof of possession. The guest never
parses or verifies an SSH signature.

The reply is:

```c
sy_s64 sy_ssh_auth_reply(
    sy_u64 event_id,
    sy_u32 result,
    sy_u64 next_methods
);

#define SY_SSH_AUTH_ACCEPT        1  /* authentication complete */
#define SY_SSH_AUTH_REJECT        2
#define SY_SSH_AUTH_PARTIAL       3  /* factor accepted; more required */
#define SY_SSH_AUTH_OFFER_ACCEPT  4  /* ask client to prove key possession */
```

`next_methods` determines the methods advertised after rejection or partial
success. Unsupported bits are refused. The host keeps the protocol's partial
authentication state; the guest may keep application state in its invocation
stack.

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

An `AUTH_PUBLICKEY_OFFER` carries an identity but proves nothing. Only
`AUTH_PUBLICKEY_VERIFIED` means the host validated a signature by that exact
key over the current SSH authentication exchange. A guest must base key
authentication on the verified event; `OFFER_ACCEPT` merely asks the client to
produce that proof.

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
if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_PUBLICKEY) < 0) return 1;
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

It is valid only for `AUTH_PUBLICKEY_OFFER` and
`AUTH_PUBLICKEY_VERIFIED`. It canonically decodes each option-free key record
and compares its public-key blob with the canonical blob on the event. It
returns `1` for a match, `0` after a complete scan with no match,
`SY_EAGAIN` when object bytes are not resident, or another negative error.
On `SY_EAGAIN` the object becomes pollable; the guest retains the generational
event token, polls the object alongside fd zero, and retries.
The host retains a bounded scan cursor keyed by the event token and object
generation, so retry does not rescan earlier bytes. Consuming the event token
discards that cursor.

Version 1 deliberately recognizes only option-free records of the form
`key-type base64-key [comment]`, plus blank and comment lines. A record with
options such as `command=`, `from=`, or `restrict` does not match. Silently
matching while ignoring an option would widen the policy expressed by the
file. A later typed option API may expose restrictions, but it must not start a
command or grant a backing capability automatically. Unsupported key types,
malformed base64, and malformed records are skipped and counted diagnostically.
A line over 16 KiB or file over 256 KiB fails the whole match with `SY_ELIMIT`
rather than authorizing from a prefix or suffix.

The helper is optional convenience. A guest may instead compare
`PUBLIC_KEY_SHA256` with a compact binary allowlist, use separate key files to
select different principals, or implement another policy from ordinary tree
reads. In every case it must repeat the decision on
`AUTH_PUBLICKEY_VERIFIED`; a match on the offer only justifies returning
`OFFER_ACCEPT`.

## 5. The SSH control fd and its events

After activation, fd zero is not a byte stream. It is a pollable control
object:

- `SY_POLL_IN`: at least one event can be taken;
- `SY_POLL_HUP`: the SSH connection ended cleanly;
- `SY_POLL_ERR`: parsing, cryptography or the underlying stream failed;
- `sy_errno(SY_SELF)`: the stable guest errno for that failure;
- `SY_POLL_OUT` and `SY_POLL_RDHUP`: never reported.

Events have a fixed header and bounded host-side payloads:

```c
struct sy_ssh_event {
  sy_u64 id;          /* opaque, generational response token */
  sy_s64 fd;          /* channel fd, or -1 before acceptance/for connection events */
  sy_u32 kind;
  sy_u32 flags;
  sy_u32 data_len;
  sy_u32 aux_len;
  sy_u32 a;
  sy_u32 b;
  sy_u32 c;
  sy_u32 d;
};

sy_s64 sy_ssh_next(
    sy_s64 conn,
    struct sy_ssh_event *out,
    sy_u64 out_len
);

sy_s64 sy_ssh_event_data(
    sy_u64 event_id,
    sy_u32 field,
    void *out,
    sy_u64 out_len
);

sy_s64 sy_ssh_event_done(sy_u64 event_id);
```

`sy_ssh_next` returns `1` after copying and popping one event,
`SY_EAGAIN` when the ready queue is empty, or another negative error. This
makes it safe to drain the control fd after one readiness notification.

The initial field identifiers relevant to authentication and channel routing
are:

```c
#define SY_SSH_FIELD_USERNAME                  1
#define SY_SSH_FIELD_SERVICE                   2
#define SY_SSH_FIELD_PASSWORD                  3
#define SY_SSH_FIELD_PUBLIC_KEY_ALGORITHM      4
#define SY_SSH_FIELD_PUBLIC_KEY_BLOB           5
#define SY_SSH_FIELD_PUBLIC_KEY_SHA256         6
#define SY_SSH_FIELD_SIGNATURE_ALGORITHM       7
#define SY_SSH_FIELD_COMMAND                   8
#define SY_SSH_FIELD_SUBSYSTEM                 9
#define SY_SSH_FIELD_CHANNEL_TYPE             10
#define SY_SSH_FIELD_CHANNEL_OPEN_DATA        11
#define SY_SSH_FIELD_REQUEST_TYPE             12
#define SY_SSH_FIELD_REQUEST_DATA             13
#define SY_SSH_FIELD_DESTINATION_HOST         14
#define SY_SSH_FIELD_ORIGINATOR_HOST          15
#define SY_SSH_FIELD_SIGNAL                   16
```

The channel lifecycle uses three event kinds:

```c
SY_SSH_EVENT_CHANNEL_OPEN       /* fd == -1 until accepted */
SY_SSH_EVENT_CHANNEL_REQUEST    /* fd identifies a live channel */
SY_SSH_EVENT_CHANNEL_EXTENDED_DATA /* event.a is an unbound data-type code */
```

EOF, close, and failure are fd readiness transitions rather than duplicate
control events. This keeps byte-stream lifecycle in the ordinary endpoint ABI.

`PUBLIC_KEY_SHA256` has length exactly 32. All other fields are
length-delimited bytes; they are not implicitly NUL-terminated and the guest
must not treat them as C strings without making its own bounded copy.
`SIGNATURE_ALGORITHM` records the signature scheme actually verified, which
may differ from the public-key blob's key type. The password field exists only
on `AUTH_PASSWORD`, is covered by the credential zeroization rules, and is
invalid after the event token is consumed. `COMMAND` and `SUBSYSTEM` are the
exact bounded request payloads and have no shell interpretation in the SSH
adapter. Ports and other small numeric fields are stored in the fixed event
header; variable-length addresses use the named fields above.

`sy_ssh_next` removes an event from the ready queue and transfers its token to
the guest. `sy_ssh_event_data` follows the SDK's `snprintf` convention: it
returns the complete length wanted and copies what fits. A decision helper or
`sy_ssh_event_done` consumes the token and frees its payload.

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
`SSH_MSG_CHANNEL_OPEN` produces `SY_SSH_EVENT_CHANNEL_OPEN`; the event exposes
the channel type and its bounded type-specific opening payload. Nothing is
accepted automatically and the SSH adapter has no allowlist containing only
`session`.

```c
#define SY_SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 1
#define SY_SSH_OPEN_CONNECT_FAILED              2
#define SY_SSH_OPEN_UNKNOWN_CHANNEL_TYPE        3
#define SY_SSH_OPEN_RESOURCE_SHORTAGE           4

sy_s64 sy_ssh_channel_accept(sy_u64 event_id);
sy_s64 sy_ssh_channel_reject(sy_u64 event_id, sy_u32 reason);

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
returns the new channel fd. `sy_ssh_channel_open` performs the symmetric
server-initiated operation and returns a channel fd immediately. In either
case the fd begins in the existing connecting state, becomes `SY_POLL_OUT`
when confirmation arrives, and reports rejection through `SY_POLL_ERR` and
`sy_errno`. Failure to reserve a slot rejects the inbound open or returns
`SY_ELIMIT` for an outbound one.

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

`SY_SSH_FIELD_CHANNEL_TYPE` is the exact channel-type string and
`SY_SSH_FIELD_CHANNEL_OPEN_DATA` is a bounded copy of the type-specific bytes
following the common channel-open fields. The raw field permits a guest-defined
extension without an SSH-library change, but standard types also receive
validated fields so ordinary programs never parse SSH binary encoding.

The first typed opening-data view is:

```text
direct-tcpip
    DESTINATION_HOST, event.a = destination port
    ORIGINATOR_HOST, event.b = originator port
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
arrives for a type without a lane, the host buffers only the configured lane
ring and emits `SY_SSH_EVENT_CHANNEL_EXTENDED_DATA`. Creating the lane makes
those bytes readable. Completing the event without creating it selects bounded
discard for that data type on that channel; SSH has no per-type rejection
message. Leaving the event unanswered applies ordinary channel-window
backpressure and remains subject to the event deadline. Thus an unknown data
type can neither allocate handles automatically nor grow an unbounded queue.

### 6.3 Channel requests

Every `SSH_MSG_CHANNEL_REQUEST` produces
`SY_SSH_EVENT_CHANNEL_REQUEST`, referring to the generic channel fd. It exposes
the request type, `want reply`, and bounded type-specific payload. Standard
requests also expose validated typed fields; unknown requests retain their
opaque payload.

```c
#define SY_SSH_EVENT_WANT_REPLY 0x01
#define SY_SSH_REQUEST_FAILURE  0
#define SY_SSH_REQUEST_SUCCESS  1

sy_s64 sy_ssh_request_reply(sy_u64 event_id, sy_u32 result);
```

The host sends success or failure only when requested. Otherwise the guest
finishes the event with `sy_ssh_event_done`. At most one unanswered
state-changing request is pending per channel, so delaying one channel never
blocks unrelated channels.

The initial typed request view covers the standard `session` vocabulary:

```text
pty-req       terminal, dimensions, encoded terminal modes
env           name and value
shell
exec          command bytes
subsystem     subsystem name
window-change new character and pixel dimensions
signal        SSH signal name
break         duration
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
SSH channel and a host effect visible in the code the operator armed.

### 7.1 Process and PTY backing

A PTY is useful only in conjunction with process authority. The declaration
therefore contains the complete process capability rather than referring to an
external configuration record. A small capability id is local to one program
root and has no daemon-wide namespace or configuration. Arming displays and
approves the concrete declaration; there is no separate setup command.

```c
#define SY_PROCESS_MAX_ARGS 8
#define SY_PROCESS_ARG_MAX  128

struct sy_process_capability {
  sy_u32 id;                         /* program-local, nonzero */
  sy_u32 flags;                      /* PTY/pipe permission and fixed options */
  char executable[256];              /* exact absolute executable */
  sy_u32 executable_len;
  sy_u32 argc;
  char argv[SY_PROCESS_MAX_ARGS][SY_PROCESS_ARG_MAX];
  sy_u32 argv_len[SY_PROCESS_MAX_ARGS];
  sy_u64 allowed_signals;            /* host-defined signal-name bits */
  sy_u64 max_processes;              /* may only lower host hard defaults */
  sy_u64 max_runtime_ms;
  sy_u64 max_memory_bytes;
};

#define SY_PROCESS_ALLOW_PTY  0x01
#define SY_PROCESS_ALLOW_PIPE 0x02

#define SY_PROCESS_SIGNAL_HUP  (1ull << 0)
#define SY_PROCESS_SIGNAL_INT  (1ull << 1)
#define SY_PROCESS_SIGNAL_TERM (1ull << 2)

sy_s64 sy_declare_process(
    const struct sy_process_capability *capability,
    sy_u64 capability_len
);
```

The host rejects duplicate or zero ids, malformed paths and arguments, an
executable that cannot be resolved safely at arm time, limits above host hard
ceilings, and unsupported flags. The declaration contains no request-derived
bytes. A future structured argument facility would be a separate capability;
the initial API always runs the exact declared argv and never invokes a shell
implicitly. A zero resource-limit field selects the host default; a nonzero
field may only reduce it.

Processes run as the daemon's unprivileged service identity with a clean,
host-defined environment, closed inherited descriptors, a fresh process group,
and fixed host safety limits. PTYs synthesize `TERM` from the validated terminal
request. The declaration may reduce limits and permit specific signals but
cannot request another uid/gid, inherit daemon environment variables, weaken
isolation, or raise a limit. These defaults are part of the runtime, not
operator configuration.

Allocation and process start are separate so a successful `pty-req` does not
start a shell before a later `shell` request:

```c
#define PROCESS_MAINTENANCE_SHELL 1

static const struct sy_process_capability maintenance_shell = {
  .id = PROCESS_MAINTENANCE_SHELL,
  .flags = SY_PROCESS_ALLOW_PTY,
  .executable = "/bin/sh",
  .executable_len = sizeof "/bin/sh" - 1,
  .argc = 2,
  .argv = { "sh", "-l" },
  .argv_len = { 2, 2 },
  .allowed_signals = SY_PROCESS_SIGNAL_HUP |
                     SY_PROCESS_SIGNAL_INT |
                     SY_PROCESS_SIGNAL_TERM,
};

SY_INIT_ENTRY sy_s64 declare(void) {
  return sy_declare_process(&maintenance_shell, sizeof maintenance_shell);
}

struct sy_pty_mode { sy_u32 opcode; sy_u32 value; };

#define SY_PTY_MAX_MODES 64
struct sy_pty_spec {
  char term[64];
  sy_u32 term_len;
  sy_u32 columns, rows;
  sy_u32 pixel_width, pixel_height;
  sy_u32 mode_count;
  struct sy_pty_mode modes[SY_PTY_MAX_MODES];
};

sy_s64 sy_ssh_pty_spec(
    sy_u64 event_id,
    struct sy_pty_spec *out,
    sy_u64 out_len
);                                      /* protocol transform; no declaration */

sy_s64 sy_pty_open(
    sy_u32 process_capability,
    const struct sy_pty_spec *spec,
    sy_u64 spec_len
);                                      /* returns the PTY data endpoint */

sy_s64 sy_process_spawn_pty(
    sy_u32 process_capability,
    sy_s64 pty
);                                      /* returns a process control handle */

sy_s64 sy_process_spawn(
    sy_u32 process_capability
);                                      /* exact pipe-backed process */

#define SY_PROCESS_STDIO_MAIN   0       /* write stdin, read stdout */
#define SY_PROCESS_STDIO_STDERR 1       /* read-only */
sy_s64 sy_process_stdio(
    sy_s64 process,
    sy_u32 stream
);

sy_s64 sy_pty_resize(
    sy_s64 pty,
    sy_u32 columns,
    sy_u32 rows,
    sy_u32 pixel_width,
    sy_u32 pixel_height
);

struct sy_process_status {
  sy_u32 exited;
  sy_u32 exit_code;
  sy_u32 signaled;
  sy_u32 core_dumped;
  char signal[32];
  sy_u32 signal_len;
};

sy_s64 sy_process_status(
    sy_s64 process,
    struct sy_process_status *out,
    sy_u64 out_len
);
sy_s64 sy_process_signal(
    sy_s64 process,
    const char *name,
    sy_u64 name_len
);
```

`sy_ssh_pty_spec` is valid only for a typed `pty-req` event. It bounds and
normalizes the terminal name and RFC terminal-mode opcode/value pairs; unknown
opcodes retain the protocol's ignore semantics. It returns `0` with a complete
spec or a negative error; a request exceeding either fixed bound is rejected
rather than truncated. For `window-change`, the event
header carries columns, rows, pixel width, and pixel height in `a`, `b`, `c`,
and `d` respectively.

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

`sy_process_status` returns `SY_EAGAIN` while the child is running and `1`
after filling the terminal status; repeated reads return the same status until
the handle closes. `sy_process_signal` accepts only names permitted by the
declaration and never interprets a guest-provided number.

Pipe-backed processes expose stdio endpoints separately. PTY-backed processes
use the PTY endpoint for combined stdin/stdout and the process handle for
signals and status. In either shape, session bytes move only because the guest
pumps them.

Process/PTY support is a separate design and implementation layer. SSH can be
completed and tested without it.

#### Selecting a forced command by authenticated key

An armed program may declare several exact process capabilities, for example a
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
separate instance of its allowed capability and charged against that
declaration's process limit.

### 7.2 File-transfer backing

A built-in file-transfer service is likewise an endpoint independent of SSH.
Its complete scope and access are embedded in the program declaration. A
program-local id selects that declaration at runtime; there is no named service
or operator configuration:

```c
#define SY_FILE_TRANSFER_SFTP             0x01

#define SY_FILE_TRANSFER_READ             0x01
#define SY_FILE_TRANSFER_WRITE            0x02
#define SY_FILE_TRANSFER_RECURSIVE        0x04
#define SY_FILE_TRANSFER_PRESERVE_METADATA 0x08

struct sy_file_transfer_capability {
  sy_u32 id;
  sy_u32 protocol;
  sy_u32 access;
  char scope[256];
  sy_u32 scope_len;
};

sy_s64 sy_declare_file_transfer(
    const struct sy_file_transfer_capability *capability,
    sy_u64 capability_len
);

sy_s64 sy_sftp_open(sy_u32 file_transfer_capability);

#define FILE_TRANSFER_RELEASES 1
static const struct sy_file_transfer_capability releases = {
  .id = FILE_TRANSFER_RELEASES,
  .protocol = SY_FILE_TRANSFER_SFTP,
  .access = SY_FILE_TRANSFER_READ | SY_FILE_TRANSFER_RECURSIVE,
  .scope = "code/releases",
  .scope_len = sizeof "code/releases" - 1,
};

SY_INIT_ENTRY sy_s64 declare(void) {
  return sy_declare_file_transfer(&releases, sizeof releases);
}

sy_s64 sftp = sy_sftp_open(FILE_TRANSFER_RELEASES);
```

The guest accepts `subsystem "sftp"`, opens the service under its effective
tree policy, replies success, and pumps `session <-> sftp`. The SFTP engine
does not know which SSH connection carries it, and the SSH engine does not
know that the session bytes are SFTP.

The service declaration is required even for read-only operation and is shown
during arming. It gates creation of this host service endpoint. The service
also intersects its scope with the invocation's underlying tree authority:
write access, live-filesystem access, and foreign-tree scopes require their
own explicit grants. As §1.2 explains, the service declaration does not claim
that an armed program lacking it is unable to export bytes manually through
the existing `sy_open` API.

SFTP support is separate from the SSH adapter. A guest may implement a small
subsystem itself or proxy a session to a declared TCP backend before the
built-in SFTP service exists.

### 7.3 Multiple channels and control masters

An OpenSSH control master is a client-side multiplexer. On the wire, every new
command requested through it is an ordinary SSH `session` channel on the
already authenticated connection. Each `SY_SSH_EVENT_CHANNEL_OPEN` whose type
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

The current runtime treats an endpoint at any handle other than `SY_SELF` as
outbound egress in parts of its accounting and cleanup. SSH invalidates that
shortcut. Endpoints need an explicit role:

```rust
enum EndpointRole {
    RawInbound,
    SshChannel,
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
reads from and writes to SSH channel fds. SSH handshakes, encrypted framing and
control messages are transport overhead and are not charged as application
bytes. Optional wire-byte metrics may be reported separately.

## 9. Limits

SSH multiplexing needs more than the current sixteen handles. One attached
pipe-backed channel can consume a channel fd, backend stdin/stdout, backend
stderr and an SSH extended-data lane before counting the control fd or any tree
objects. A limit that advertises eight channels but cannot represent them is
not a limit; it is a delayed refusal.

Proposed initial bounds:

| Resource | Default / hard bound | Behavior at the bound |
| --- | --- | --- |
| Handles and poll entries | 32 | helper fails `SY_ELIMIT`; incoming channel is rejected if it cannot reserve its fd |
| Simultaneous SSH channels | 8 / 15 | bounded independently of handles; runtime argument may lower it |
| SSH channel ring | 64 KiB per direction | stops reading or writing the SSH channel and applies window backpressure |
| Outstanding control events | 32 | channel request is deferred where possible; otherwise rejected or connection closed by protocol class |
| Total event payload | 64 KiB | oversized request rejected; no partial credential or command is delivered |
| One event payload | 16 KiB, with smaller field-specific limits | request rejected |
| Authentication attempts | 8 | disconnect |
| Authentication time | 60 s | disconnect |
| `authorized_keys` object | 256 KiB, 16 KiB per line | matcher returns `SY_ELIMIT`; no prefix match is accepted |
| SSH packet size | conservative library configuration, at most 64 KiB initially | protocol error |
| SSH connection idle | existing invocation idle deadline | invocation ends `Deadline` |

Thirty-two `struct sy_pollfd` values occupy 512 bytes, small beside the
default 16 KiB eBPF local-call frame. Expanding the handle table must still be
paired with per-role limits and an explicit memory charge; a larger integer
alone would let thirty-one endpoints each allocate today's 512 KiB of rings.

An invocation's aggregate memory budget includes:

- SSH library connection and channel buffers;
- every endpoint ring;
- queued and outstanding event payloads;
- bounded `authorized_keys` scan cursors attached to outstanding auth tokens;
- host-side object and cursor data already charged today.

The program may request a lower channel limit in `sy_ssh_start` or a subsequent
configuration helper. This is resource policy, not an arming declaration.

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

The CLI should print the public key and SHA-256 fingerprint through a read-only
command such as `synch socket ssh-key`. A stock client can use the existing
byte pump directly:

```sh
ssh -o 'ProxyCommand=synch connect %h:code/ssh.sock' nas
```

The first SSH host-key exchange already travels through a mutually
authenticated iroh connection to the named origin. The SSH key remains useful
for OpenSSH compatibility, stable `known_hosts` behavior, and detecting an
unexpected loss or replacement of the node database.

## 11. Runtime shape

The SSH implementation belongs in `synch-sock`, beside the endpoint reactor,
not in `synch-net`. The network layer continues handing it an opaque
`DuplexStream` and knows nothing about the bytes after `Opened::Ok`.

A candidate implementation is `russh`, using its server-over-arbitrary-stream
entrypoint and handler callbacks. It must be pinned to a release containing all
known server authentication and channel-lifecycle fixes, and those historical
failures should become local regression tests rather than assumptions left to
the dependency.

The runtime integration is:

1. `sy_ssh_start` takes the unselected `DuplexStream`, combines its boxed read
   and write halves into one async I/O object, and starts the SSH task.
2. The SSH handler owns only `Send` state and communicates through bounded
   channels. It never captures the worker's `Rc<Inner>`.
3. A small local bridge task receives handler events, inserts them into the
   invocation's bounded control queue and bumps the existing readiness epoch.
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
   channel fds the guest accepts and the behavior the armed guest implements.
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
10. **Kill and shutdown are complete.** No SSH task, process, deferred channel
    or credential buffer outlives its invocation.
11. **Authorization data is explicit and immutable.** The guest chooses an
    object fd, matching is tied to that object's content root and the exact
    authentication event, and unsupported `authorized_keys` options never
    degrade into a less restrictive match.
12. **Capability ids are program-local selectors.** An id resolves only inside
    the declarations of the currently armed program root; it cannot name
    mutable daemon state or a capability belonging to another socket.

The eBPF sandbox remains defence in depth. The primary execution gate is still
that the callee published and armed the exact program root being run.

## 13. Failure semantics

| Failure | Guest observation | SSH/client observation |
| --- | --- | --- |
| `sy_ssh_start` after raw I/O | `SY_ESTATE`; raw stream remains selected | unchanged raw stream |
| Unsupported auth method selected | `SY_EINVAL` or rejected reply | method not advertised / attempt rejected |
| Auth event times out | control fd reaches `HUP` | authentication disconnect |
| Malformed SSH packet or failed crypto | control fd `ERR`, classified `sy_errno` | protocol disconnect |
| Channel handle cap | `sy_ssh_channel_accept` returns `SY_ELIMIT` | channel-open failure |
| Request token is stale | response helper returns `SY_ESTATE` | current channel is untouched |
| `authorized_keys` object is cold | matcher returns `SY_EAGAIN`; object fd becomes pollable | authentication remains pending within its deadline |
| `authorized_keys` exceeds its bound | matcher returns `SY_ELIMIT`; no match | guest rejects authentication or chooses another policy source |
| Backing capability refused | its existing helper error, commonly `SY_EPERM` | guest chooses request failure or channel close |
| Channel peer sends EOF | channel `IN`/`RDHUP`, then `sy_read == 0` after drain | local write half remains usable |
| Guest closes channel | fd becomes invalid | SSH EOF/close after queued output as requested |
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

- the SDK header and Rust constants agree on every method, event, result, lane
  and struct layout;
- `sy_ssh_start` needs no declaration and is refused in init mode;
- a pristine stream upgrades, while every raw endpoint operation selects raw
  mode and makes a later upgrade fail without losing bytes;
- every `sy_peer_*` identity query remains valid before `sy_ssh_start` without
  selecting raw mode, while endpoint byte operations still select it;
- unsupported method bits and malformed responses fail closed;
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
- SFTP subsystem transfers in every declared access mode;
- host-key persistence is checked across daemon restarts and device-key
  rotation;
- Linux and macOS exercise the same eBPF example through the embedded compiler.

## 15. Example socket programs

These examples target the proposed SDK in this document; they are normative ABI
and policy sketches, not code that the current SDK can compile yet. The first
shows the complete control/data reactor. Later examples reuse that reactor and
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

  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 1;

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
      struct sy_ssh_event event;
      while (sy_ssh_next(SY_SELF, &event, sizeof event) == 1) {
        if (event.kind == SY_SSH_EVENT_AUTH_NONE) {
          sy_ssh_auth_reply(event.id, SY_SSH_AUTH_ACCEPT, 0);
          continue;
        }

        if (event.kind == SY_SSH_EVENT_CHANNEL_OPEN) {
          sy_s64 slot = free_slot(slots);
          if (slot < 0) {
            sy_ssh_channel_reject(event.id, SY_SSH_OPEN_RESOURCE_SHORTAGE);
            continue;
          }
          sy_s64 channel = sy_ssh_channel_accept(event.id);
          if (channel >= 0) {
            slots[slot].fd = channel;
            slots[slot].read_done = 0;
            slots[slot].echo = (struct sy_pump)SY_PUMP_INIT;
          }
          continue;
        }

        if (event.kind == SY_SSH_EVENT_CHANNEL_REQUEST) {
          if (event.flags & SY_SSH_EVENT_WANT_REPLY)
            sy_ssh_request_reply(event.id, SY_SSH_REQUEST_FAILURE);
          else
            sy_ssh_event_done(event.id);
          continue;
        }

        sy_ssh_event_done(event.id);   /* AUTHENTICATED notification, etc. */
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
service identity and isolation, while its declaration pins the executable,
argv, resource ceilings, and accepted signals including `HUP` for channel EOF.

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
static const struct sy_process_capability local_login_shell = {
  .id = PROCESS_LOCAL_LOGIN_SHELL,
  .flags = SY_PROCESS_ALLOW_PTY,
  .executable = "/bin/sh",
  .executable_len = sizeof "/bin/sh" - 1,
  .argc = 2,
  .argv = { "sh", "-l" },
  .argv_len = { 2, 2 },
  .allowed_signals = SY_PROCESS_SIGNAL_HUP |
                     SY_PROCESS_SIGNAL_INT |
                     SY_PROCESS_SIGNAL_TERM,
};

SY_INIT_ENTRY sy_s64 declare(void) {
  return sy_declare_process(&local_login_shell, sizeof local_login_shell);
}

struct terminal {
  struct attached io;                 /* channel <-> PTY */
  sy_s64 process;                     /* separate control handle */
  sy_u32 shell_started;
  sy_u32 input_done;
  sy_u32 output_done;
  struct sy_process_status status;    /* retained until PTY output drains */
  sy_u32 have_status;
};

static int same_iroh_key(const sy_u8 a[32], const sy_u8 b[32]) {
  sy_u8 different = 0;
  for (sy_u32 i = 0; i < 32; i++) different |= a[i] ^ b[i];
  return different == 0;
}

static int field_is(
    sy_u64 event_id,
    sy_u32 field,
    const char *expected,
    sy_u64 expected_len
) {
  char value[32];
  sy_s64 len = sy_ssh_event_data(
      event_id, field, value, sizeof value);
  if (len != expected_len || expected_len > sizeof value) return 0;
  for (sy_u64 i = 0; i < expected_len; i++)
    if (value[i] != expected[i]) return 0;
  return 1;
}

static sy_s64 finish_request(
    const struct sy_ssh_event *event,
    sy_u32 result
) {
  if (event->flags & SY_SSH_EVENT_WANT_REPLY)
    return sy_ssh_request_reply(event->id, result);
  return sy_ssh_event_done(event->id);
}

static sy_s64 handle_inner_auth(const struct sy_ssh_event *event) {
  if (event->kind != SY_SSH_EVENT_AUTH_NONE)
    return sy_ssh_auth_reply(
        event->id, SY_SSH_AUTH_REJECT, SY_SSH_AUTH_NONE);
  /* Reaching this event means the hardcoded Iroh-key check already passed. */
  return sy_ssh_auth_reply(event->id, SY_SSH_AUTH_ACCEPT, 0);
}

static sy_s64 accept_shell_channel(
    const struct sy_ssh_event *event,
    struct terminal *terminal
) {
  if (terminal->io.channel >= 0 ||
      !field_is(event->id, SY_SSH_FIELD_CHANNEL_TYPE,
                SY_STR("session")))
    return sy_ssh_channel_reject(
        event->id, SY_SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);

  sy_s64 channel = sy_ssh_channel_accept(event->id);
  if (channel < 0) return channel;
  terminal->io.channel = channel;
  return 0;
}

static sy_s64 handle_shell_request(
    const struct sy_ssh_event *event,
    struct terminal *terminal
) {
  if (event->fd != terminal->io.channel)
    return finish_request(event, SY_SSH_REQUEST_FAILURE);

  if (field_is(event->id, SY_SSH_FIELD_REQUEST_TYPE,
               SY_STR("pty-req"))) {
    if (terminal->io.backend >= 0 || terminal->shell_started)
      return finish_request(event, SY_SSH_REQUEST_FAILURE);

    struct sy_pty_spec spec;
    if (sy_ssh_pty_spec(event->id, &spec, sizeof spec) < 0)
      return finish_request(event, SY_SSH_REQUEST_FAILURE);

    sy_s64 pty = sy_pty_open(
        PROCESS_LOCAL_LOGIN_SHELL, &spec, sizeof spec);
    if (pty < 0) return finish_request(event, SY_SSH_REQUEST_FAILURE);
    terminal->io.backend = pty;        /* allocation starts no process */
    return finish_request(event, SY_SSH_REQUEST_SUCCESS);
  }

  if (field_is(event->id, SY_SSH_FIELD_REQUEST_TYPE,
               SY_STR("shell"))) {
    if (terminal->io.backend < 0 || terminal->shell_started)
      return finish_request(event, SY_SSH_REQUEST_FAILURE);

    sy_s64 process = sy_process_spawn_pty(
        PROCESS_LOCAL_LOGIN_SHELL, terminal->io.backend);
    if (process < 0)
      return finish_request(event, SY_SSH_REQUEST_FAILURE);

    terminal->process = process;
    terminal->shell_started = 1;
    terminal->io.to_backend = (struct sy_pump)SY_PUMP_INIT;
    terminal->io.to_channel = (struct sy_pump)SY_PUMP_INIT;
    return finish_request(event, SY_SSH_REQUEST_SUCCESS);
  }

  if (field_is(event->id, SY_SSH_FIELD_REQUEST_TYPE,
               SY_STR("window-change"))) {
    if (terminal->io.backend < 0)
      return finish_request(event, SY_SSH_REQUEST_FAILURE);
    sy_s64 resized = sy_pty_resize(
        terminal->io.backend,
        event->a, event->b, event->c, event->d);
    return finish_request(
        event, resized < 0 ? SY_SSH_REQUEST_FAILURE
                           : SY_SSH_REQUEST_SUCCESS);
  }

  if (field_is(event->id, SY_SSH_FIELD_REQUEST_TYPE,
               SY_STR("signal"))) {
    char signal[32];
    sy_s64 len = sy_ssh_event_data(
        event->id, SY_SSH_FIELD_SIGNAL, signal, sizeof signal);
    sy_s64 sent = terminal->process < 0 || len < 0 || len > sizeof signal
        ? SY_EPERM
        : sy_process_signal(terminal->process, signal, len);
    return finish_request(
        event, sent < 0 ? SY_SSH_REQUEST_FAILURE
                        : SY_SSH_REQUEST_SUCCESS);
  }

  /* This interactive socket rejects exec, subsystem, env, and agent policy. */
  return finish_request(event, SY_SSH_REQUEST_FAILURE);
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

  if (sy_ssh_start(SY_SELF, SY_SSH_AUTH_NONE) < 0) return 1;

  struct terminal terminal = {0};
  terminal.io.channel = -1;
  terminal.io.backend = -1;
  terminal.process = -1;

  /* The §15.1 reactor now:
     - sends authentication events to handle_inner_auth;
     - sends CHANNEL_OPEN to accept_shell_channel;
     - sends CHANNEL_REQUEST to handle_shell_request;
     - polls channel, PTY, process, and fd zero;
     - calls move_terminal according to both pumps' readiness;
     - reads sy_process_status when the process handle becomes readable. */
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
maps to the one concretely declared shell capability because the armed eBPF program
says so.

This compact example permits one live shell channel. Replacing `terminal` with
the same bounded slot array used in §15.1 permits several independent PTYs on a
control-master connection; each PTY and process is charged separately to the
declaration and channel limits.

A stock client reaches it through the existing transport bridge:

```sh
ssh -o 'ProxyCommand=synch connect %h:code/ssh.sock' nas
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

static const struct sy_process_capability admin_status = {
  .id = PROCESS_ADMIN_STATUS,
  .flags = SY_PROCESS_ALLOW_PIPE,
  .executable = "/usr/local/bin/admin-status",
  .executable_len = sizeof "/usr/local/bin/admin-status" - 1,
  .argc = 1,
  .argv = { "admin-status" },
  .argv_len = { sizeof "admin-status" - 1 },
};

static const struct sy_process_capability publish_release = {
  .id = PROCESS_PUBLISH_RELEASE,
  .flags = SY_PROCESS_ALLOW_PIPE,
  .executable = "/usr/local/bin/publish-release",
  .executable_len = sizeof "/usr/local/bin/publish-release" - 1,
  .argc = 1,
  .argv = { "publish-release" },
  .argv_len = { sizeof "publish-release" - 1 },
};

SY_INIT_ENTRY sy_s64 declare(void) {
  sy_s64 rc = sy_declare_process(&admin_status, sizeof admin_status);
  if (rc < 0) return rc;
  return sy_declare_process(&publish_release, sizeof publish_release);
}

/* Called at invocation start, before any endpoint operation on SY_SELF. */
static sy_s64 begin_ssh(struct auth_files *files) {
  files->admin = sy_open(SY_STR("code/ssh/admin_authorized_keys"));
  if (files->admin < 0) return files->admin;

  files->deploy = sy_open(SY_STR("code/ssh/deploy_authorized_keys"));
  if (files->deploy < 0) {
    sy_close(files->admin);
    return files->deploy;
  }

  return sy_ssh_start(SY_SELF, SY_SSH_AUTH_PUBLICKEY);
}

/* Called from the control-event branch of the reactor in example 15.1.
   SY_EAGAIN means retain `event`, poll the key objects, and retry it. */
static sy_s64 handle_auth(
    const struct sy_ssh_event *event,
    const struct auth_files *files,
    enum principal *principal
) {
  enum principal candidate = PRINCIPAL_NONE;
  sy_s64 matched = sy_ssh_authorized_keys_match(event->id, files->admin);
  if (matched == SY_EAGAIN) return SY_EAGAIN;
  if (matched < 0) goto reject;
  if (matched == 1) {
    candidate = PRINCIPAL_ADMIN;
  } else {
    matched = sy_ssh_authorized_keys_match(event->id, files->deploy);
    if (matched == SY_EAGAIN) return SY_EAGAIN;
    if (matched < 0) goto reject;
    if (matched == 1) candidate = PRINCIPAL_DEPLOY;
  }

  if (event->kind == SY_SSH_EVENT_AUTH_PUBLICKEY_OFFER) {
    return sy_ssh_auth_reply(
        event->id,
        candidate == PRINCIPAL_NONE
            ? SY_SSH_AUTH_REJECT : SY_SSH_AUTH_OFFER_ACCEPT,
        SY_SSH_AUTH_PUBLICKEY
    );
  }

  if (event->kind == SY_SSH_EVENT_AUTH_PUBLICKEY_VERIFIED &&
      candidate != PRINCIPAL_NONE) {
    *principal = candidate;            /* connection-wide guest state */
    return sy_ssh_auth_reply(event->id, SY_SSH_AUTH_ACCEPT, 0);
  }

reject:
  return sy_ssh_auth_reply(event->id, SY_SSH_AUTH_REJECT,
                           SY_SSH_AUTH_PUBLICKEY);
}

/* `channel` was accepted only after CHANNEL_TYPE compared equal to "session".
   This uses the single-stdio-endpoint process shape proposed in §7.1. */
static sy_s64 start_for_request(
    enum principal principal,
    sy_s64 channel,
    const struct sy_ssh_event *event,
    struct attached *out,
    sy_s64 *process_out
) {
  sy_u32 capability;
  if (principal == PRINCIPAL_ADMIN) {
    capability = PROCESS_ADMIN_STATUS;
  } else if (principal == PRINCIPAL_DEPLOY) {
    capability = PROCESS_PUBLISH_RELEASE;
  } else {
    return sy_ssh_request_reply(event->id, SY_SSH_REQUEST_FAILURE);
  }

  sy_s64 process = sy_process_spawn(capability);
  if (process < 0)
    return sy_ssh_request_reply(event->id, SY_SSH_REQUEST_FAILURE);

  sy_s64 stdio = sy_process_stdio(process, SY_PROCESS_STDIO_MAIN);
  if (stdio < 0) {
    sy_close(process);
    return sy_ssh_request_reply(event->id, SY_SSH_REQUEST_FAILURE);
  }

  out->channel = channel;
  out->backend = stdio;
  out->to_backend = (struct sy_pump)SY_PUMP_INIT;
  out->to_channel = (struct sy_pump)SY_PUMP_INIT;
  *process_out = process;
  sy_ssh_request_reply(event->id, SY_SSH_REQUEST_SUCCESS);
  return 0;
}
```

The surrounding reactor accepts multiple `session` channels and maintains one
`struct attached` and one process-control handle per live channel. In its data
branch it calls `sy_pump(channel, backend, ...)` and
`sy_pump(backend, channel, ...)` with separate state and buffers. Consequently
an OpenSSH control master can run several instances concurrently while
authentication remains connection-wide.
Once `AUTHENTICATED` arrives, the reactor closes both key objects and frees
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
static const struct sy_file_transfer_capability releases = {
  .id = FILE_TRANSFER_RELEASES,
  .protocol = SY_FILE_TRANSFER_SFTP,
  .access = SY_FILE_TRANSFER_READ,
  .scope = "code/releases",
  .scope_len = sizeof "code/releases" - 1,
};

SY_INIT_ENTRY sy_s64 declare(void) {
  return sy_declare_file_transfer(&releases, sizeof releases);
}

static int event_field_is(
    sy_u64 id,
    sy_u32 field,
    const char *expected,
    sy_u64 expected_len
) {
  char value[32];
  sy_s64 len = sy_ssh_event_data(id, field, value, sizeof value);
  if (len != expected_len || expected_len > sizeof value) return 0;
  for (sy_u64 i = 0; i < expected_len; i++)
    if (value[i] != expected[i]) return 0;
  return 1;
}

/* The outer reactor has already authenticated the connection and accepted
   this channel only after CHANNEL_TYPE compared equal to "session". */
static sy_s64 accept_sftp_request(
    sy_s64 channel,
    const struct sy_ssh_event *event,
    struct attached *out
) {
  if (!event_field_is(event->id, SY_SSH_FIELD_REQUEST_TYPE,
                      SY_STR("subsystem")) ||
      !event_field_is(event->id, SY_SSH_FIELD_SUBSYSTEM,
                      SY_STR("sftp"))) {
    if (event->flags & SY_SSH_EVENT_WANT_REPLY)
      return sy_ssh_request_reply(event->id, SY_SSH_REQUEST_FAILURE);
    return sy_ssh_event_done(event->id);
  }

  sy_s64 sftp = sy_sftp_open(FILE_TRANSFER_RELEASES);
  if (sftp < 0)
    return sy_ssh_request_reply(event->id, SY_SSH_REQUEST_FAILURE);

  out->channel = channel;
  out->backend = sftp;
  out->to_backend = (struct sy_pump)SY_PUMP_INIT;
  out->to_channel = (struct sy_pump)SY_PUMP_INIT;
  sy_ssh_request_reply(event->id, SY_SSH_REQUEST_SUCCESS);
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
subsystem request does not. A read/write declaration changes only the backing
declaration and SFTP policy, not the SSH program's channel logic.

### 15.5 A generic `direct-tcpip` channel with declared egress

Generic channels also remove the need for a forwarding-specific byte API. A
program handling `SY_SSH_EVENT_CHANNEL_OPEN` can compare the channel type with
`direct-tcpip`, inspect the host-parsed destination fields, and open an
ordinary declared TCP fd. It accepts the SSH channel only after the backend is
available, then uses the same two-pump `struct attached`:

```c
SY_INIT_ENTRY sy_s64 declare(void) {
  sy_declare_egress(SY_STR("git.internal"), 9418);
  return 0;
}

static sy_s64 begin_git_forward(
    const struct sy_ssh_event *event,
    sy_u64 *pending_event,
    sy_s64 *pending_tcp
) {
  if (!event_field_is(event->id, SY_SSH_FIELD_CHANNEL_TYPE,
                      SY_STR("direct-tcpip")) ||
      !event_field_is(event->id, SY_SSH_FIELD_DESTINATION_HOST,
                      SY_STR("git.internal")) ||
      event->a != 9418) {
    return sy_ssh_channel_reject(
        event->id, SY_SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
  }

  sy_s64 tcp = sy_tcp_connect(SY_STR("git.internal"), 9418);
  if (tcp < 0)
    return sy_ssh_channel_reject(event->id, SY_SSH_OPEN_CONNECT_FAILED);

  *pending_event = event->id;          /* event token remains outstanding */
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
and the existing armed egress declaration must permit the connection.

## 16. Implementation order

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
