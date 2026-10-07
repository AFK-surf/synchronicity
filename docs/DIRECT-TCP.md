# Direct-TCP streamed runs and socket streams

Status: **implemented**, opt-in on both ends and off by default; benchmarked
on loopback only (see [Rollout](#rollout)). Socket invocations use the same
path under the same flags ([Sockets](#sockets)).

A transient read (`synch cat --no-cache`, a `--no-cache` S3 bucket) asks a
provider for the rest of the read as one streamed run (`GetStream`, DESIGN.md
§6.4) and verifies each 2 MiB window as it arrives. Today that run always
travels on a `sync/blob/1` QUIC stream. This document adds an **opt-in** path on
which the same run travels over a plain TCP connection between the two nodes,
encrypted under a key used for exactly one run, which the provider sends to the
requester as a message on the QUIC stream that asked for the run.

Nothing about *what* is served changes: the run is the same sequence of
windows, encoded by the same `encode_slice`, admitted by the same per-window
binding and scope checks, and verified by the requester against the object root
exactly as it is now. Only the bytes' route changes.

## Why

A streamed run is bulk, in-order, single-stream transfer between two hosts that
are usually on the same LAN or in the same datacenter — the case kernel TCP is
best at and userspace QUIC is weakest at. On the QUIC path every 1.2–1.4 KB
packet is encrypted, framed and acknowledged in userspace, under noq's
congestion controller, with QUIC's default 25 ms acknowledgement delay that we
cannot currently lower (#161; DESIGN.md §6.4). On TCP the kernel does
segmentation and acknowledgement (TSO/GRO, autotuned buffers), and the only
userspace work left per byte is one AEAD pass and the BLAKE3 verification the
read already pays for.

On loopback the direct path moves a run at 1.95× the throughput for a
quarter of the requester's CPU and under half the provider's
([results](#loopback-results)); over a real link it is still unmeasured, and
the feature stays opt-in until it is.

## Goals and non-goals

Goals:

- Higher throughput for large transient reads between directly reachable
  nodes, with no change to what a read can return.
- Confidentiality and integrity of the TCP bytes against everyone but the two
  QUIC endpoints, with a fresh key per run that only ever travels inside the
  authenticated QUIC session.
- No weakening of the provider's existing bounds (§12): memory per run, request
  concurrency, progress deadlines, and revocation mid-run.
- Silent fallback: any reason the direct path cannot be used ends in the
  existing QUIC `GetStream` path, at worst one round trip and one connect
  timeout later.

Non-goals (for now):

- Fetches that commit to the CAS (`fetch_into`, replica acquisition, delta
  sync). They are bounded by disk commits per 8 MiB window, not by transport.
  The wire is designed so they could adopt it later.
- NAT traversal for TCP. The direct path is attempted only where the QUIC
  connection already has a direct IP path, and only succeeds where that IP
  accepts TCP on the advertised port (LAN, public hosts, port forwards).
- Relay-only connections, and the multi-tenant data plane (`synch-dp`); see
  [Open questions](#open-questions).

## Overview

```text
requester                                             provider
   │  QUIC sync/blob/1 stream (control)                  │
   │── GetDirect { root, run } ────────────────────────▶ │ opted in? path ok?
   │                                                     │ fresh secret, ticket
   │◀────────────── DirectOffer { port, ticket, secret } │ ticket → table
   │                                                     │
   │  both: subkeys = BLAKE3 derive_key(secret, …)       │
   │                                                     │
   │  TCP to <QUIC path IP>:port                         │
   │── Hello { magic, ticket, mac } ───────────────────▶ │ verify, consume ticket
   │◀═══════ AEAD records: windows + SliceEnd … Final ═══│ serve_run over TCP
   │                                                     │
   │◀──────────────────────────────── control finish ────│
```

The QUIC stream that carried `GetDirect` stays open for the whole transfer. It
is the transfer's identity on the provider: the transfer runs inside that
stream's dispatch, so it holds that stream's concurrency permit, the
endpoint-wide in-flight slot, and the `STREAM_TIMEOUT` progress watchdog, and it
dies with the stream or the connection. Every existing provider-side bound
applies to a direct run without being restated.

## QUIC negotiation

Two messages are appended to `BlobMessage` after `GetStream` (postcard numbers
variants by position):

```rust
GetDirect   { root: Hash, run: GroupRange }
DirectOffer { port: u16, ticket: [u8; 16], secret: DirectSecret }

struct DirectSecret([u8; 32]);   // the run's key; see "Run key" below
```

The requester opens a `sync/blob/1` stream and sends `GetDirect`. The provider
answers `DirectOffer` — its listener port, a random 16-byte ticket id, and the
run's secret, both fresh from the OS RNG — only when all of these hold:

- it was started with a direct listener (opt-in, below);
- the connection's selected path is a direct IP path
  (`Connection::paths()`, `is_selected && is_ip`), not a relay;
- the request passes what the first window of a `GetStream` would: the peer's
  binding (§3.2) and content scope (§3.5);
- `run` is no longer than `DIRECT_MAX_RUN_BYTES` (below) and non-empty.

Otherwise the provider finishes the stream without a byte. That is also what a
provider that predates `GetDirect` does — it cannot decode the message — so one
reply covers *unsupported*, *not opted in* and *declined*, and the requester's
answer to all three is the same: fall back to `GetStream`. A requester
remembers a refusal, or a direct path that broke, per peer for ten minutes,
node-wide, so a provider without direct TCP costs one extra round trip — or
one connect timeout — every ten minutes rather than on every read.

On sending the offer the provider inserts the ticket into an in-memory table
owned by the listener, holding the run's Hello key and a oneshot channel back
to the control stream's task, and waits up to 10 s for the authenticated TCP
connection to be handed over. If none arrives, the ticket
is removed and the control stream finishes without a byte past the offer,
which the requester reads as "fall back".

## Run key

The key travels as a message: the provider draws a 32-byte secret for every
offer it makes and sends it in `DirectOffer`, on the QUIC stream that asked for
the run.

**Who draws it.** The provider, because the secret should exist only once a
transfer is actually going to happen. A requester-drawn key would be sent to
providers that predate `GetDirect`, are not opted in, or decline — none of
which would use it. The provider is also the side that registers the ticket and
encrypts the records, so all of a run's fresh material comes from one place,
and the request stays free of secrets.

**How it is protected in transit.** `DirectOffer` is carried inside QUIC's
1-RTT packet protection, keyed by a TLS 1.3 handshake that authenticated both
device keys and that the binding check (§3.2) admitted. Only the two endpoints
of that connection can read it, and because the handshake's key exchange is
ephemeral, a later compromise of either device key reveals no past offer. The
run's confidentiality is therefore exactly the QUIC session's.

**Subkeys.** One secret is sent and three keys are derived from it, so no key
ever serves two algorithms. The derivation also binds them to the ticket and
to what was asked for:

```text
input   = secret || ticket || postcard(root, run)
k_data  = BLAKE3 derive_key("synch direct-tcp v1 data",  input)  // AES-256-GCM, provider → requester
k_hello = BLAKE3 derive_key("synch direct-tcp v1 hello", input)  // requester's Hello MAC (keyed BLAKE3)
iv_data = BLAKE3 derive_key("synch direct-tcp v1 iv",    input)[0..12]  // record nonce base
```

Binding to `(root, run)` means decrypted bytes are only ever interpreted as the
run that was asked for. Bao verification would catch a substituted run anyway;
the binding makes a mix-up a decryption failure rather than a verification one.

**Once-use.** A secret is drawn per offer and never reused for another ticket,
another run, or a retry; a retry asks for a new offer. The ticket table forgets
the entry on the first authenticated Hello, on expiry, or when the control
stream is reset, and both sides discard the subkeys when the run ends. Because
every key encrypts exactly one run, the record nonce can be a plain counter
from zero.

**Lifetime: no longer than the QUIC connection.** The key reached the
requester on one QUIC connection, and it never outlives that connection on
either side:

- On the provider, the ticket (with its Hello key) and the record key live
  only in the future serving the control stream. That future races the run
  against `Connection::closed()` and against the requester stopping the
  stream, so the moment the connection closes — including a binding check
  closing it on a lapsed binding — the future ends, the ticket is forgotten,
  both keys are dropped and zeroed, and the TCP connection is closed. An offer
  whose connection closed before its Hello arrived admits nothing.
- On the requester, the record key sits behind a watcher task that awaits
  `Connection::closed()` and destroys the key when it resolves, whether or
  not a read is in progress; a read in progress is raced against the same
  event. The next read after the connection closes fails as a direct-path
  failure, and the read resumes over a new QUIC connection.

**Handling.** A key in a message lives in places a derived key would not, so
the type does the work:

- `DirectSecret` has a redacting `Debug` (`DirectSecret(..)`), no `Clone`, no
  `Display`, and zeroes itself on drop. `BlobMessage` derives `Debug`, and
  tracing a decoded message must not print the key.
- The requester reads `DirectOffer` through a helper that zeroes the frame's
  receive buffer after decoding, and the provider zeroes the buffer it
  serialized the offer into after writing it. The QUIC stack's own send and
  retransmit buffers cannot be zeroed from here, so this is hygiene, not a
  guarantee: process memory is already inside the trust boundary.
- The subkeys are derived immediately and the secret is dropped; nothing
  persists any of them.

## TCP protocol

### Listener and Hello

A provider that opts in binds one TCP listener per process. Everything that
reaches it before authentication is untrusted, so the pre-auth path does no
store access and no allocation proportional to input:

1. Accept, under a cap of 64 unauthenticated connections; past it, new
   connections are closed immediately.
2. Read exactly the fixed-size Hello within 5 s:

   ```text
   magic   [8]   "SYNCHDT1"
   ticket  [16]
   mac     [32]  BLAKE3-keyed(k_hello, "hello" || ticket)
   ```

3. Look the ticket up. Unknown → close. Known → verify `mac` in constant time.
   Wrong → close, **ticket kept** (so a third party who saw the ticket id on
   the wire cannot burn it without the key). Right → **remove the ticket** and
   hand the socket to the waiting control stream. A ticket authenticates at
   most one TCP connection, ever.

The provider does not require the TCP source address to match the QUIC peer's.
The MAC is the authentication; an address check would add nothing against an
attacker without the key and would break hosts behind NATs that map UDP and TCP
to different public addresses.

### Where the requester dials

The requester dials **the IP of the QUIC connection's selected direct path**,
with the port from `DirectOffer`. The provider names only a port, never an
address, so a provider cannot point a requester's TCP connect at a third host.
If the selected path is a relay at the time of dialing, the requester does not
try; when it gives up after an offer, it drops the control stream, which
stops it and removes the ticket on the provider at once. Connect timeout: 2 s
— a NAT'd provider with no port forward costs this once per ten minutes (the
failure is remembered as a refusal is), then everything falls back.

### Records

After the Hello, the provider writes, and the requester only reads. The
plaintext is **byte-for-byte the stream a `GetStream` answer writes on QUIC**:
per window, the 4-byte length prefix, the bao encoding, then the framed
`SliceEnd`. It is cut into AEAD records:

```text
record  = len: u32 LE  | kind: u8 | ciphertext[len] | tag[16]
kind    = 0 data, 1 final
nonce   = iv_data XOR (0u32 BE || seq: u64 BE), seq = 0, 1, 2, …
aad     = len || kind
cipher  = AES-256-GCM (aws-lc-rs, already the process's crypto provider)
len    ≤ DIRECT_RECORD_LEN = 256 KiB
```

- **Records are opened before their bytes are used.** The requester never feeds
  an unauthenticated byte to the verifier; 256 KiB matches the transient
  read's piece size, so a record buffer costs what a piece already does.
- **The provider seals in place.** A window is already one owned `Vec` from
  `encode_slice`; each record is sealed over a slice of it
  (`seal_in_place_separate_tag`), so encryption adds no copy.
- **Truncation is not a clean end.** The run ends with one `final` record
  (empty plaintext). A TCP FIN or RST before it — which an on-path attacker can
  forge — is a transport error, never the "stream ended cleanly" that
  `read_window_len` treats as end-of-run on QUIC. The reader reads nothing
  after `final`.
- **Key-use ceiling.** `DIRECT_MAX_RUN_BYTES` = 64 GiB caps one key at
  2^18 full records, far inside AES-GCM's per-key limits. A longer read simply
  asks for another direct run where this one stopped, with a fresh ticket and
  key.

AES-256-GCM rather than ChaCha20-Poly1305 because the hosts this path is for
have AES instructions, where GCM is the faster of the two, and aws-lc-rs
provides it without a new dependency. The record format names neither;
switching is a version bump of the label.

## Provider: serving a direct run

The `GetDirect` arm of `BlobProtocol::handle_stream`:

1. Check opt-in, path, binding, scope and size; on any failure finish without
   a byte.
2. Derive keys, register the ticket, write `DirectOffer`.
3. Wait for the authenticated socket (or the accept timeout, or the control
   stream being reset by the requester).
4. Run the **existing** `serve_run` loop with a sink that seals records onto
   the TCP socket instead of writing to the QUIC send stream: `admit_window`
   before every window, one window encoded ahead, `progress.mark()` after each
   window sent. TCP's flow control now plays the role QUIC's did, so a run
   still holds at most two encoded windows in memory.
5. Write the `final` record, shut down the socket, finish the control stream.

The transfer runs inside the control stream's dispatch future, so:

- the requester resetting the control stream, or the QUIC connection closing —
  including `still_admitted` closing it on a lapsed binding — drops the
  future, which drops the socket and the encode-ahead task;
- a revoked binding or scope also ends the run at the next window via
  `admit_window`, exactly as on QUIC;
- a requester that stops reading stalls TCP, stops `progress.mark()`, and the
  `STREAM_TIMEOUT` watchdog cuts the run off.

## Requester: reading a direct run

`BlobClient::stream_run_direct(root, size, run, piece)` returns the same
`RunStream` as `stream_run`, over a different byte source: `RunStream` and the
window readers read from a `Source` that is either the QUIC `RecvStream` or a
`DirectSource` that reads and opens records. The streaming verifier, the piece
layout, the partial-holder rule and the per-window deadline are the same code
on both.

`PeerReader::next_streamed` in `synch-engine` tries, per provider, in order:

1. **Direct**, when the requester opted in, the remaining read is at least
   `DIRECT_MIN_BYTES` (32 MiB — sixteen windows; below that the extra round
   trip and TCP slow start are not worth it), the client has not recorded a
   direct refusal, and the connection's selected path is a direct IP path.
2. **`GetStream`** over QUIC, as today.
3. **Window by window**, as today, for providers that predate `GetStream`.

Failure handling separates *transport* faults from *provider* faults:

| What happened | Meaning | Reaction |
| --- | --- | --- |
| No offer, connect failed/timed out, Hello rejected | direct path unavailable | record refusal on the client; same provider over `GetStream` |
| Record fails to open, truncated before `final`, TCP reset mid-run, a window stalls past the deadline, the QUIC connection closes | the TCP path failed — possibly because of a third party, not the provider | resume at the current offset over `GetStream` from the **same** provider; no more direct attempts on it for the rest of the read, and none for ten minutes after a broken record or connection |
| Window decrypts but fails bao verification | the provider served bad bytes | provider failure, dropped from the plan, exactly as today |
| Short window / run ends early | partial holder | as today |

A run already resumes from where the read stands, so a fall back mid-run
re-asks only for what was not yet handed out.

## Sockets

A socket invocation (`docs/SOCKETS.md` §4) is the other long, bulk-capable
byte stream between two members, and a proxy or an SSH session over one pays
the same per-packet userspace cost a streamed run did. It takes the same path,
under the same two flags, with the differences a bidirectional stream needs.

**Negotiation.** A caller that opted in, whose connection's selected path is
a direct IP path, sends `SockRequest::OpenDirect(open)` — appended after `List`
— instead of `Open(open)`. The callee admits it exactly as it admits `Open`;
nothing about which program runs, or for whom, depends on the transport. Then:

- with a listener and a direct path, it answers `SockOpened::Direct { program,
  program_path, invocation, port, ticket, secret }` — `Ok`'s fields plus an
  offer — written and read through zeroed buffers like `DirectOffer`;
- otherwise it answers a plain `Ok`, and the bytes travel on the QUIC stream,
  as for `Open`. No round trip is lost: the callee decides, in its one answer.

A callee that predates `OpenDirect` cannot decode it and refuses it as a
malformed frame, under `NoSuchPath`. A caller refused with that code asks
again with `Open`; if *that* is admitted, the callee is remembered as not
offering, per peer for ten minutes (a memo of its own, apart from the runs').
A socket that really does not exist is refused both ways, costing one extra
round trip and no memo. Every other refusal is final at once.

**Keys.** Five, derived as a run's are, from `secret || ticket ||
postcard(open, invocation)` — bound to the `Open` that asked and the
invocation that answered — under labels of their own, so a socket's keys are
never a run's and the two directions' are never each other's:

```text
k_hello   = derive_key("synch direct-tcp v1 sock hello",   input)
k_up      = derive_key("synch direct-tcp v1 sock up",      input)  // caller → callee
iv_up     = derive_key("synch direct-tcp v1 sock up iv",   input)[0..12]
k_down    = derive_key("synch direct-tcp v1 sock down",    input)  // callee → caller
iv_down   = derive_key("synch direct-tcp v1 sock down iv", input)[0..12]
```

The Hello, the ticket table, the pre-auth bounds and the dialing rule are the
run's, unchanged: one listener serves both.

**Records, both ways.** Each direction is a sequence of records under its own
key and counter, in the run's format. A half-close is that direction's `final`
record followed by a TCP write shutdown; a FIN or reset before it is an error
on the reading side, never an EOF a program could take for its peer's
half-close. A write returns once the record it sealed is on the socket, so
nothing waits on a flush the runtime and the bridges never make. Records carry
at most 256 KiB, and a write of less goes out at once as a shorter record:
interactive traffic is not held back to fill one.

**Confirmation.** Once the callee has the authenticated connection, the first
thing it sends is an empty data record. The caller waits up to 5 s for it
before handing the stream to anyone. Only the holder of `k_down` can seal it,
so it proves the far end is the callee rather than whatever else accepted a
TCP connection on that port — a stale forward, a middlebox — which would
otherwise leave the caller on a stream nothing will ever write to.

**Fallback.** A port that does not accept, a Hello not taken, or a missing
confirmation sends the caller back to `Open` on QUIC, remembering the peer for
ten minutes. It drops the `OpenDirect` stream first, and the callee, which was
holding the admission while it waited, drops it with nothing run — or, when
its confirmation was sent and not received in time, ends the invocation it had
started as one whose caller left. A stream that
breaks mid-invocation cannot fall back — the program has already seen its
bytes — and ends as a failed stream does on QUIC.

**Lifetime.** The `OpenDirect` stream stays open, carrying nothing, as the
invocation's identity; `SockClosed` names it as before. On the callee, the
connection closing or the caller stopping that stream is the caller having
gone: it ends the invocation (`Closed{Deadline}`), and a watcher destroys both
keys and shuts the TCP connection down at once. On the caller, the same
watcher acts when the QUIC connection closes, so a read waiting on the socket
fails immediately rather than at the next record. Both halves of a stream must
be dropped before its QUIC stream is, so a caller that has read the program's
output to the end can keep writing.

**What is unchanged.** Admission, scope, the concurrency cap, the idle
deadline, the teardown drain, `List` and the control stream. The runtime sees
a byte stream, as it did; the bridges (`synch socket connect`, the managed
gateway) see one too.

## Security summary

- **Who can read the bytes:** only the two QUIC endpoints. A TCP observer
  learns sizes and timing, as a QUIC observer does.
- **Who can alter them undetected:** nobody but the provider, and the provider
  is still held to the object root by bao verification. AEAD exists to keep
  third parties out; bao exists to keep the provider honest. Neither replaces
  the other.
- **Key secrecy:** the secret is only ever on the wire inside the QUIC
  session's packet protection, so it is as confidential as that session —
  forward secrecy included — and is never logged or persisted.
- **Requester authentication:** the Hello MAC under `k_hello`, which only the
  holder of the offer can compute.
- **Provider authentication:** implicit — only the QUIC peer that sent the
  offer could have sealed a record that opens under `k_data`.
- **Replay:** a ticket authenticates one TCP connection; every secret is drawn
  for one offer; records are counter-sequenced.
- **Downgrade:** blocking TCP only forces the QUIC path, which carries the same
  guarantees. An attacker can cost throughput, not confidentiality.
- **Redirection:** the requester dials only the validated QUIC path's IP.
- **Pre-auth DoS:** fixed-size Hello, short deadline, capped concurrency, no
  store calls; the ticket table holds at most one entry per in-flight control
  stream, which `MAX_CONCURRENT_STREAMS` and the binding already bound.
- **Revocation:** unchanged — per-window checks, and the transfer dies with its
  QUIC stream and connection.
- **Sockets:** the same properties per direction. Each direction has its own
  key and counter, a direction ends only at its `final` record, and the
  callee's confirmation authenticates it to the caller before any byte is
  trusted to the path.

## Configuration

Both ends opt in; neither changes behavior for peers that did not.

| Side | Flag | Env | Effect |
| --- | --- | --- | --- |
| Provider, callee | `--direct-tcp-listen HOST:PORT` | `SYNCH_DIRECT_TCP_LISTEN` | bind the listener; answer `GetDirect` and `OpenDirect` |
| Requester, caller | `--direct-tcp` | `SYNCH_DIRECT_TCP` | try the direct path for large transient reads and socket invocations |

Both land in `NetOptions` (`direct_listen: Option<SocketAddr>`,
`direct_dial: bool`), off by default. The listener is bound in `Net::bind` and
shut down with the endpoint. The port must be reachable from peers; on a LAN
that is usually true already, elsewhere it needs a firewall rule or port
forward, which is why it is opt-in rather than automatic.

## Code map

- `synch-core/src/wire.rs`: `GetDirect`, `DirectOffer`, `DirectSecret`.
- `synch-core/src/sock.rs`: `SockRequest::OpenDirect`, `SockOpened::Direct`.
- `synch-net/src/direct.rs`: subkey derivation, the listener with its ticket
  table and pre-auth bounds, Hello, `RecordWriter`/`RecordReader`,
  `DirectSource` and its connection watcher, the per-peer refusal memo.
- `synch-net/src/direct/stream.rs`: a socket's keys, and the two record halves
  (`DirectRead`, `DirectWrite`) with their shared watcher and confirmation.
- `synch-net/src/sock.rs`: `OpenDirect` on both sides; `SockSend`/`SockRecv`,
  the caller's halves on either path.
- `synch-net/src/blob.rs`: the `GetDirect` arm (`serve_direct`), the run's
  `Sink` and `Source`, `BlobClient::stream_run_direct`.
- `synch-net/src/endpoint.rs`: `NetOptions::{direct_listen, direct_dial}`;
  the listener's lifecycle.
- `synch-engine/src/fetcher.rs`: the three-tier choice and the failure table
  above, in `PeerReader`.
- `synch-cli`: `--direct-tcp-listen`, `--direct-tcp`.

No Lean change: which groups are served is still the `Cas/Serve` command's
decision through the same `encode_slice` boundary; this changes only the host
transport that carries the encoding, which `docs/LEAN.md` already places
outside the verified core.

## Tests

- `a_direct_run_yields_what_a_quic_run_does` — partial and whole holders,
  window for window; the ticket is spent.
- `a_run_without_a_direct_path_stays_on_quic` — no offer, no opt-in; the
  refusal is remembered.
- `a_direct_runs_key_and_ticket_end_with_its_quic_connection` — an
  unpresented ticket dies with its connection and its key admits nothing; a
  run under way loses its key when the connection closes and fails its next
  read.
- `a_ticket_admits_one_connection_and_only_with_its_key` — a wrong key does
  not burn the ticket; a second Hello is refused.
- `records_open_only_as_sealed_and_a_truncated_run_is_not_an_end` — flipped
  bit, relabelled final record, missing final record.
- `a_direct_offer_never_prints_its_secret`.
- `a_large_transient_read_streams_intact_with_or_without_a_direct_path` — the
  engine's transient read over TCP from a provider that offers, over QUIC
  from one that does not.
- `a_direct_stream_carries_both_ways_and_ends_only_at_a_final_record` — both
  directions with independent half-closes; a FIN without the final record and
  a flipped bit are failures.
- `a_socket_stream_goes_direct_where_the_callee_offers_and_on_quic_where_not`.
- `a_direct_offer_that_cannot_be_taken_up_opens_on_quic` — the untaken
  admission runs nothing; the peer is remembered.
- `a_callee_that_cannot_read_open_direct_is_asked_with_open` — and an unknown
  socket is refused both ways without being remembered.
- `a_direct_stream_ends_with_its_quic_connection`.

## Rollout

1. Land behind the two flags, off by default. *(Done.)*
2. Benchmark a large `--no-cache` read, QUIC `GetStream` vs direct, reporting
   throughput and CPU per GiB on both ends. *(Loopback done, below; LAN and
   cross-region not yet.)*
3. Keep it only if LAN throughput improves materially (target ≥ 1.5×) without
   costing more CPU per byte; otherwise remove it rather than carry an unused
   transport.
4. If it pays, consider `fetch_into` and replica acquisition next.

Socket streams are not benchmarked separately: per byte they do the run's
work minus the verification, and an interactive stream's records are small.

### Loopback results

`cargo run --release -p synch-net --example direct_bench -- --mib 2048 --rounds 5`
reads a 2 GiB object as one run, verifying every group, with the provider in a
child process so each side's CPU is measured separately. Machine: 4-vCPU Xeon
VM at 2.1 GHz with AES-NI, VAES and AVX-512, both processes on the same four
vCPUs. Medians:

| Path | Throughput | Requester CPU | Provider CPU |
| --- | --- | --- | --- |
| QUIC `GetStream` | 388 MiB/s | 3.01 s/GiB | 3.21 s/GiB |
| Direct TCP | 757 MiB/s | 0.72 s/GiB | 1.25 s/GiB |

Direct is 1.95× the throughput at 4.2× less requester CPU and 2.6× less
provider CPU per byte. A 64 MiB read, twice the threshold, gets 1.91×. The
QUIC path on this branch matches `main` within run-to-run noise.

Where the time goes (`perf`, during the run):

- **QUIC** spends it on per-packet work in userspace — packet building, ack
  processing, `memmove`, scheduler wake-ups — spread over many functions;
  packet encryption is a few percent.
- **Direct, requester:** BLAKE3 verification ~21%, socket copy ~12%,
  AES-GCM decryption ~12% (≈ 0.09 s/GiB, ~11 GB/s), buffer zero-fill ~6%.
- **Direct, provider:** AES-GCM sealing ~17% (≈ 0.22 s/GiB) and the socket
  copy ~10%; the rest is mostly kernel scheduling overhead. Sealing and
  sending run on the one serving task, so the provider tops out near one
  core: that, not encoding (3.5 GiB/s alone) or the network, is what bounds a
  direct run here.

AES-GCM is the hardware path — aws-lc-rs's VAES/VPCLMULQDQ code. On this CPU
OpenSSL's AES-256-GCM runs at ~12.5 GB/s per core, ~0.22 GB/s with AES-NI
masked off; a software cipher would cost ~5 s/GiB, several times the
provider's whole budget.

What loopback cannot show: propagation delay (which is where QUIC's 25 ms ack
delay and window growth hurt), bandwidth limits, loss, and two machines'
worth of cores. This container has no `netem`, so the LAN and cross-region
numbers are still to be taken; until then the result is "cheaper per byte on
both ends", not "faster on a real link".

## Open questions

- **Data plane.** `synch-dp` serves many tenants from one process. One shared
  listener works naturally — tickets are random and route themselves — but the
  ticket table would need to live above the per-tenant `Net`, and
  `max_inflight_per_tenant` must still account for direct runs. Deferred until
  the single-tenant path proves itself.
- **Advertising the port.** The offer carries it, which costs a round trip
  before the first byte. Putting it in the address book would let a requester
  skip `GetDirect` for providers known not to offer it, at the cost of another
  published field. Measure first.
- **Multiple TCP connections per run.** One connection is the simplest thing
  that can beat a single QUIC stream; striping windows across several is a
  later, measurable step.
