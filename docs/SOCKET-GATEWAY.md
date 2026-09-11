# Managed socket gateway

Applications use HTTP/WebSocket, not a synch daemon or node key. CP authenticates,
routes, and relays; managed DP calls the existing engine socket API. Neither
service interprets SSH, shell commands, or SFTP.

## Authority and identity

Both endpoints require an Authorization: Bearer synch_… header. They accept org
member, admin, and managed_data keys for the requested org. Join keys, fleet
keys, other orgs, expired keys, and cookie-only requests cannot connect.
WebSocket GET is an effect: rejecting ambient cookies prevents cross-site socket
opening. Credentials are not accepted in URLs.

Hosting must be enabled; browsing need not be. A managed_data key cannot reach
an unhosted network; that scope denial can be a 404 rather than disclosing state.

**The target sees the hosted member, not the API-key owner.** Accepted org keys
share that member's socket authority in their hosted networks. This is not a
per-user/per-socket grant. The target must activate a socket and authorize that
member through the existing engine and program gates. The API accepts synch
origins and socket names, not arbitrary TCP addresses or caller code.

List without an origin to obtain the controller public key before creating a
temporary device. Put that key in the device allowlist; keep its private key
local. Rotation can require a new allowlist. The successful open also returns
the controller key actually used. For SSH, use a client library over the byte
stream and keep host identity verification enabled. This is not SSH exec.
Temporary shell deadlines remain the target program and supervisor's job.

## API and stream protocol

    GET /api/orgs/:org/networks/:net/sockets?origin=<origin>
    GET /api/orgs/:org/networks/:net/sockets/connect?origin=<origin>&socket=<name>
    Upgrade: websocket
    Authorization: Bearer synch_…

URL-encode query values. An origin is a canonical named origin or key:<z32>.
For listing, omission selects the hosted member itself. Connect requires both
parameters. Use WSS outside local development.

A list response has t=socketlist, controller (public key), origin (the controller
origin, **not the target**), and sockets. Entries retain the engine's name,
program (JSON-serialized hash), program_path, and note. The tunnel-local id is
diagnostic; it is not a durable session handle or verification authority.

HTTP upgrade is not remote admission. Wait for a text socketopened frame with
controller and controller origin. Then follow this flow:

- socketopened grants **one input credit**.
- Send one nonempty binary message, at most 65,536 bytes, per input credit.
  Text {"t":"credit","n":1} returns credit after DP writes that input.
- Received binary messages are opaque output. After consuming each, send
  {"t":"ack"}. DP sends no next output chunk until acknowledged. Unsolicited
  acknowledgements are protocol errors.
- Send {"t":"eof"} once to half-close input after queued bytes. Output continues;
  further input is rejected.
- Text socketeof means the target half-closed output, not necessarily completion.
- Text socketclosed includes status: the engine SockStatus, such as {"Ok":0},
  "Deadline", or "Killed". Output has drained and the invocation has finished.
  This is **not a shell command exit status**. The WebSocket then closes.
- Text {"t":"err","message":…} reports failure. A transport close without a
  completion frame is not success.

Input/output are independent; clients must service both. Application buffering
is one chunk per direction per admitted connection plus a bounded shared tunnel
writer queue. This does not add a parser-level frame limit to Mist: the 64 KiB
validation applies to decoded WebSocket messages.

## Lifetime and errors

DP allows 32 socket requests per attached managed tunnel, separate from file
reservations. A capacity refusal is busy; it does not evict another stream.
Open/list attempts have 15-second timeouts. CP waits 20 seconds for opening and
at most 22 seconds for a listing.

Client close, HTTP worker death, tunnel loss, or transport cancellation drop the
owned socket task. CP rechecks bearer validity and hosting after the first 20
seconds and every 30 seconds thereafter. Key revocation may take up to 30 seconds
on a live connection. This is not a replacement for a target deadline.
Delegation revocation controls membership, not rollback of effects already made.

CP stores no gateway records, invitations, bytes, or replay queue. Streams do not
resume or migrate. No input is automatically replayed after disconnection.

Before upgrade, JSON error strings accompany 401 credentials, 404 scope/network,
409 hosting/protocol, 400 missing parameters, and 503 unattached DP. Listing
failures from DP return 502; CP wait expiry returns 504. After upgrade, failures
are stream events.

## Tunnel and rollout

Managed tunnel **v3** adds socketlist, socketopen, socketack, and socketeof
downward, and socketlist, socketopened, socketeof, and socketclosed upward.
Existing cancel, credit, and err frames are reused. Binary frames in either
direction have the existing big-endian request-id/sequence header (two u32s).
Sequences start at zero per direction. Socket credit is one frame; file-write
credit is unchanged.

The handshake negotiates v1–v3. Older tunnels keep their existing operations;
the gateway refuses them until they negotiate v3. Both CP and managed DP need
deployment. Merging does not upgrade running services. No schema or signed
delegation format changes. Customer browse tunnels remain read-only and encode
no socket-connect operation.

Engine authorization is unchanged. Its existing Lean proofs do not constitute
proof of the new HTTP routing or stream lifecycle.

## Tests

- cargo test -p synch-dp --lib: real loopback peer listing, bytes, half-close,
  explicit cancel, tunnel loss, output backpressure, and remote completion
  while client input stays open, plus existing DP regressions.
- cd control-plane && gleam test: bearer scope, hosting, join-key refusal,
  expiry, and existing CP regressions.
- cd control-plane && uv run e2e/socket-gateway.py: real HTTP/WebSocket edge,
  binary data, invalid credit, peer refusal, half-close, and cancellation.
  Runs in Linux CP CI with websockets 15.0.1.

The HTTP test substitutes the managed actor; the Rust test exercises the
managed tunnel and real engine/peer. This is not a deployed Cue-to-user SSH test.
