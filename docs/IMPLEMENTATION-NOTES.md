# Implementation notes

Where this implementation differs from `DESIGN.md`, and why. Everything here is
a deliberate, recorded choice. Nothing in this list weakens signature
verification, hash verification of trie nodes or content, the `(seq, root)`
acceptance rule, or binding checks — those are implemented exactly as specified.

Sections refer to `DESIGN.md`.

## Deferred, with the module boundary in place

### §3.4 — key-loss recovery quiesce

The `recovery_quiesce` / `seq_gap` protocol for a node rebuilding from an empty
database under an existing origin id is not implemented. A recovering node
currently republishes from `seq = 1`, which its peers will refuse as not newer —
visible, not silently wrong. The pieces it needs (head history, equivocation
detection, `synch doctor` reporting) are all present.

### §7.1 — ignore rules

`.syncignore` implements the common gitignore subset: `*`, `?`, `**`, a leading
`/` to anchor, a trailing `/` for directories only, and a leading `!` to
un-ignore, plus the built-in defaults. Character classes (`[a-z]`), escapes, and
nested per-directory ignore files are not implemented.

### §5.2 — abandonment across multiple advertisers

"Three full rounds **across all advertisers**" is implemented as three
unproductive rounds against the peer currently being fetched from. Since the
anti-entropy scheduler picks a random peer each round, a persistently unservable
head is still abandoned and re-selected; the difference is that the count is
per-session rather than global.

## Differences in detail

### §3.4 — which endpoint dials during the overlap window

The design says `synch key activate` "brings up a second iroh endpoint as
`K_new`" and that both endpoints stay live until the old binding has expired.
Both do. What the design does not say is which of them the node dials *out*
from, and this implementation makes the new key the primary: `K_new` signs, and
new outbound connections carry it, while `K_old`'s endpoint keeps accepting
until `synch key retire` drops it. That way the identity peers are being moved
to is the one they see on every fresh connection, and retiring the old key
becomes a pure teardown of a serving-only endpoint rather than a second
switch-over.

One consequence is visible with an explicit `--bind HOST:PORT`: two endpoints
cannot share a port, so the incoming key binds an ephemeral port on the same
interface, and the fixed port stays with the outgoing key until it is retired.

### §9.3 — `Line` frames for textual output

The design describes `cat`, `get`, and a long `ls` streaming their payload "as a
sequence of `Chunk` frames terminated by `End`". Byte payloads (`cat`, `get`) do
exactly that. Textual output (`ls`, `status`, `log`, `doctor`, …) streams
`Line` frames instead — the same incremental delivery terminated by the same
`End`, but framed per line, so the CLI does not have to re-split a byte stream
it is only going to print line by line. `Progress` and the structured `Error`
are as specified.

### §3.4 — the state of a key between `rotate` and `activate`

`device_keys.state` is `active` or `retiring` (§10), so the key that
`synch key rotate` generates is stored as `retiring` until `synch key activate`
promotes it: "held, and not the signing key". Exactly one key is `active` at any
moment, which is the invariant that matters.

## Adapted to the dependencies

### §9.3 — the control token's randomness

The 32 random bytes in `control.token` come from `SecretKey::generate()`, which
is the same OS CSPRNG that mints device keys, rather than from a separate `rand`
dependency at a version this workspace does not otherwise pin.

Filesystem permissions are enforced where the platform has them: on Unix the
data directory is `0700` and the token and socket are `0600`. The token file is
*created* `0600` rather than chmod-ed afterwards; the socket can only be
restricted once `bind` has made it, and the `0700` directory around it is what
covers that instant. Windows has no equivalent, which is the case §9.3 already
anticipates — there the token carries the whole check, and it is checked on
every request on both platforms.

### §10 — the writer task

The design specifies "single writer task (all writes funneled through one tokio
task; reads from a pool)". This implementation funnels **all** access through one
mutex-guarded `rusqlite::Connection`. The invariant the design cares about —
that every multi-step state change is one transaction and no partial state is
observable — holds identically. What is given up is read concurrency: readers
serialize behind the same mutex rather than running from a pool. WAL mode is
still enabled, so the change is a code-structure difference, not a durability
one.

### §6.2 — outboard file naming

The design writes `store/<hex[0..2]>/<hex>` for payloads and `store/<hex>.obao`
for outboards. This implementation shards both the same way:
`store/<hex[0..2]>/<hex>` and `store/<hex[0..2]>/<hex>.obao`, so a large store
does not accumulate one flat directory of outboards.

### §6.1 — outboards in memory during ingest and slice decode

`bao-tree`'s sync API builds an outboard into a caller-provided buffer, so
ingest holds the whole outboard in memory: 64 bytes per 16 KiB group, about
1/256 of the object, so ~390 MB for a 100 GB file. Slice *encoding* also reads
the outboard file whole. Slice *decoding* streams into the on-disk outboard
through `positioned-io`, so the receive path is already incremental.

Objects at or below 16 KiB are inlined in SQLite and have an empty outboard by
construction.

### §6.4 — slice framing

The design describes the response as "a bao slice stream, verified incrementally
by the requester", terminated by `SliceEnd`. This implementation sends the slice
as one length-framed payload followed by the `SliceEnd` frame, because the
decoder needs to know which ranges the encoding covers before it can verify —
and that is precisely what `SliceEnd` reports. Verification is still per-16 KiB
group and still happens before any byte is committed to the CAS; what is
buffered is one request's worth of slice, which the requester bounds by choosing
the ranges it asks for.

### §5.1 — the `Hello` exchange shape

The design lists `Hello` / `HeadsWant` / `Heads` as push-pull. This
implementation runs them as a fixed five-message exchange on one stream:

```
C→S  Hello     (client summaries)
S→C  Hello     (server summaries)
C→S  Heads     (heads the client holds that the server lacks)   — the push
C→S  HeadsWant (origins where the server is ahead)
S→C  Heads     (the wanted signed heads)                        — the pull
```

Both directions of head propagation complete in one round trip, and every
message is one of the §5.1 schema types.

One behavior the design implies but does not spell out is implemented here: a
head delivered by reactive `HeadPush` lands in the pending slot and is therefore
*not* newer than what the receiver holds, so the next `Hello` exchange would
never ask for its trie. `sync_with` additionally fetches any pending head's trie
from a peer advertising a complete head for that origin at or above its seq,
which is exactly what §5.2's peer-agnostic clause permits.

### §4.2 — `EntryKind::Dir`

The scanner does not emit `Dir` records. Directory listings come from range
scans over the `f:` prefix, which is how §4.1 describes them, so explicit
directory records would be redundant metadata. The variant exists, round-trips
on the wire, and is honored on read, so an origin that does publish them is
handled correctly.

### §7.1 — `file_id`

The `(size, mtime_ns, file_id)` change-detection triple uses `(dev, ino)` on
Unix and **no file identity at all on Windows**. `std::os::windows::fs::
MetadataExt::file_index` is still unstable (rust-lang/rust#63010) and does not
compile on stable, and obtaining the index otherwise costs an open handle per
file during every scan. Identity is `Option` by design, so Windows falls back
to comparing size and mtime, and re-hashes on ambiguity — the safe direction.

The visible consequence is narrow: a Windows file replaced by a different file
with byte-identical size and mtime is not re-hashed until the next full scan.
Restoring identity would mean calling `GetFileInformationByHandle` through a
`windows-sys` dependency; deferred as not yet worth the dependency.

### §9.4 — `PutObject` publish timing

The design says `PutObject` "responds once durably staged, with the head publish
following the usual batching". This implementation runs the scan and publish
synchronously before responding, so the ETag returned is always backed by a
published entry. It is stricter than specified, not looser.

### §9.4 — SigV4 test vectors

SigV4 verification is tested by pinning the canonical-request and
string-to-sign layouts exactly, checking the four-step key derivation reacts to
every scope component, and round-tripping sign-then-verify through the real HTTP
gateway with negative cases for unsigned, unknown-key, and tampered requests.
It is *not* checked against an external AWS-published test vector, because doing
that offline would mean hard-coding a value that could not be verified here.

## Dependency versions

Pinned in the workspace `Cargo.toml`. The notable ones:

- `iroh` 1.0.3 — the 1.0 API renamed `NodeId`/`NodeAddr` to
  `EndpointId`/`EndpointAddr`. `synch-core` re-exports `iroh_base::PublicKey` as
  `NodeId` so the design's vocabulary survives in the data model.
- `bao-tree` 0.16 — used through its synchronous `io::sync` API.
- `rusqlite` 0.40 with `bundled`, so no system SQLite is needed.
- `hickory-resolver` 0.26 with `dnssec-ring`, configured with `validate = true`
  and an additional per-record `Proof::is_secure()` check, so an insecure or
  bogus answer is discarded rather than trusted.
- No `openssl` anywhere: `rustls` throughout, via `iroh`'s `tls-ring` feature
  and `reqwest`'s `rustls` feature in tests.
