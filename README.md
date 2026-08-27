# synchronicity

omnipresent peer-to-peer file store

See [DESIGN.md](DESIGN.md) for the full architecture: iroh-based hierarchy-agnostic
networking, `mptsync` (Merkle-Patricia Trie anti-entropy) for metadata, bao/BLAKE3
hash-tree content addressing with verified random reads, static + DNSSEC-based
membership, per-node published versions, and SQLite-backed local metadata.

## Build

```sh
cargo build --release          # both binaries
cargo test --workspace         # the full suite; binds loopback only, no network
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

The binaries are `target/release/synch` (CLI and daemon) and
`target/release/synch-s3` (S3 gateway). SQLite is compiled in and TLS is rustls,
so neither needs a system library.

## Usage

Set up a node. `synch init` creates the datadir, `synch daemon start` launches
the owner process in the background, and operational commands are gRPC calls to
that daemon over a local control socket:

```sh
synch init --domain cluster.example.com   # or plain `synch init` for a key identity
synch daemon start                         # returns when the control socket is ready
synch space add media /srv/media
synch scan                                 # hash, publish a signed root
synch id                                   # print the origin, device key, and address
synch daemon status                        # what the running node is doing
synch daemon stop                          # ask it to shut down
```

The socket is `<data-dir>/control.sock` (a `\\.\pipe\synchronicity-…` named pipe
on Windows), `0600` inside a `0700` data directory, authenticated by a token
regenerated on every daemon start and sent as a header on every call. The service
schema is `crates/synch-cli/proto/control.proto`. With no daemon running, every
operational/client command fails with a message naming that socket.

## MCP

`synch mcp` serves the Model Context Protocol over stdin and stdout, so an
editor or agent runner can browse and publish into the tree. It is a client of
the daemon like every other command — it holds no key, no store and no endpoint
— and the daemon does not have to be running when it starts.

```sh
synch mcp                    # read-only, every space
synch mcp --allow-write      # plus the tools that change state
synch mcp --space media      # confined to one space
```

The surface is read-only by default and the tool list says so, so a client is
shown exactly the authority it was given. Paths are also addressable as
resources at `synch://<space>/<path>`. Both protocol eras are served: the
stateless `2026-07-28` revision and the older `initialize` handshake.

[docs/MCP.md](docs/MCP.md) has the tool table, the failure semantics, and the
bounds.

## Serverless mode

Serverless mode runs the daemon on an ephemeral local volume while keeping file
content in S3, Google Cloud Storage, or Azure Blob through OpenDAL. SQLite is
still the metadata database; run Litestream beside the daemon so that database,
including the device identity, survives replacement. This is a long-running,
scale-to-one peer, not request-scoped FaaS.

An S3-backed node can be bootstrapped like this (standard AWS environment or
workload credentials are used for authentication):

```sh
export SYNCH_DATA_DIR=/run/synch
export SYNCH_CAS_BACKEND=s3
export SYNCH_S3_BUCKET=my-synch-cas
export SYNCH_S3_REGION=us-east-1
export SYNCH_CAS_ROOT=nodes/production
export SYNCH_CAS_CACHE_BYTES=10737418240     # 10 GiB maintenance target

synch init --domain cluster.example.com     # once, only if restore found no database
synch daemon start
synch space add media --detached
```

Use `SYNCH_CAS_BACKEND=gcs` with `SYNCH_GCS_BUCKET` (and optionally
`SYNCH_GCS_CREDENTIAL_PATH`), or `SYNCH_CAS_BACKEND=azblob` with
`SYNCH_AZBLOB_CONTAINER`, `SYNCH_AZBLOB_ACCOUNT_NAME`, and credentials supplied
by the Azure environment or `SYNCH_AZBLOB_ACCOUNT_KEY`. S3-compatible stores can
set `SYNCH_S3_ENDPOINT`; GCS and Azure have corresponding
`SYNCH_GCS_ENDPOINT` and `SYNCH_AZBLOB_ENDPOINT` overrides. Run `synch --help`
for the complete provider options. The storage-policy flags are `--cas-root`,
`--cas-cache-bytes`, and `--cas-upload` when environment variables are not
used.

Only detached spaces are valid on a cloud-backed node. They have no scanner,
watcher, or local checkout: gateway writes and `synch take` ingest directly into
the cloud CAS, while `cat`, `get`, and gateway reads fill the ephemeral range
cache on demand. A durable-disk node can still mirror a detached space when a
checkout is wanted elsewhere.

The default `SYNCH_CAS_UPLOAD=own+pinned` uploads content created by this node
and peer content it pins. Use `own` to upload only locally created content, or
`all` to make the node a durable replica of every object it fetches completely.
`SYNCH_CAS_CACHE_BYTES` is a maintenance target, not a per-request hard limit;
on Unix, omitting it targets at least 20% free space.

For production deployment:

1. Restore `<data-dir>/synchronicity.db` from Litestream before starting the
   daemon; initialize only when no database exists.
2. Replicate that database continuously while the daemon runs. The replica
   contains device secret keys, so protect it separately from the CAS prefix.
3. Run exactly one daemon for a data directory/identity (`replicas: 1`, with a
   recreate rather than rolling-update strategy) and allow at least 30 seconds
   for SIGTERM shutdown.
4. Do not apply expiration or deletion lifecycle rules to the final `cas/`
   prefix. Synchronicity deliberately leaves final cloud objects append-only;
   local deletion removes only metadata and cache files.

A write is acknowledged only after its payload and Bao outboard are stored in
the provider and the durable metadata and published records commit. Provider
errors therefore fail writes closed; cold reads fall back to cache or peers when
possible. The provider is trusted to preserve acknowledged bytes—Synchronicity
does not independently detect corruption at rest. The cloud CAS is sufficient
as the only durable store for file bytes, but Litestream and signed peer heads
remain necessary to recover filenames, versions, and pins.

To convert an existing node, first ensure every space is detached, stop the
daemon, supply the destination provider settings above, and run:

```sh
synch cas migrate --to s3                 # or gcs / azblob / local
```

Migration copies every candidate before atomically changing the configured
backend and is safe to retry after interruption. See
[docs/SERVERLESS.md](docs/SERVERLESS.md) for the full durability, recovery,
failure, and Kubernetes deployment contract.

Admit a peer. Trust is unilateral, so each side runs this for the other:

```sh
synch trust add <their-device-key>         # the key is the identity; names come from zones
synch domain set cluster.example.com       # or DNSSEC membership instead
synch domain refresh                       # re-resolve the membership zone now
```

Delegate space-restricted access. A node whose own key is already trusted — statically
or through DNS — can admit one other device key to a named list of spaces, without
touching the zone and without anyone else's configuration:

```sh
synch delegate add <their-device-key> --space photos --space incoming --until 7d
synch delegate ls                          # every delegation this cluster honors
synch delegate rm <their-device-key>
```

Nothing is handed to the delegate: the grant is a record in the issuer's own trie, so
every member learns it through ordinary replication and admits the key on its own.
The delegate joins from the other side with the commands it would use anyway —
`synch init`, then `synch domain add <domain>` or `synch trust add <issuer-key>` —
because trust is unilateral and the two directions are separate problems.

A delegate sees the spaces it was delegated and nothing else, down to the filenames:
peers serve it a projection of each trie covering those spaces, and it verifies the
same signed root everyone else does. Withdrawing a delegation deletes the record, and
that propagates the way every deletion does. A delegate cannot delegate further —
a grant is only read from an origin whose own trust is static or DNS.

Membership from DNS refreshes itself: the daemon re-resolves each configured
domain when its TTL runs out, and again — rate-limited — when a peer this node
holds no binding for tries to connect, which is what the far side of a lagging
key rotation looks like. A resolver outage fails closed: the cached bindings
keep their own expiry, and the member set shrinks toward static-only rather
than falling open.

Resolution travels DNS-over-HTTP(S) only — `https://1.1.1.1/dns-query` by
default, or any endpoint named with `synch daemon run --doh <url>`
(`SYNCH_DOH`). Plain `http://` endpoints are accepted for internal networks:
answers are DNSSEC-validated in process either way, so the transport carries
nothing trusted. For an internal zone signed by its own root,
`--dnssec-anchor /path/to/root.key` (`SYNCH_DNSSEC_ANCHOR`) replaces the
ICANN trust anchor with that file of DNSKEY records — and then nothing signed
under the real root validates: an override is a different universe, not an
addition.

DNSSEC answers *is this key authorized for this zone?* by delegation, and a
compromised or coerced parent can substitute the key quietly. By default the
zone key that signed an answer must additionally appear in the public
Sigstore Rekor v2 transparency log — the production log keys are built in —
with the proof carried inside the zone and verified offline: a substituted
key then has to be a *public* substitution, where the zone's operator can
see it, or fail validation. The zone key is logged as a genuine
`hashedrekord` entry whose verifier is a **self-signed certificate naming the
apex** — Rekor validates certificates not at all and copies the DER into the
Merkle leaf verbatim, which is what puts a monitorable zone name inside the
log — carrying the zone's DNSSEC chain as a custom extension. A real
published entry is checked in as a conformance fixture, so an entry minted by
`log2025-1.rekor.sigstore.dev` verifies end to end. `synch-monitor` is the
other half: it walks the log's tiles, indexes every leaf by the name in its
certificate, and reports every newly authorized key for the zones you watch —
the CT-monitor posture, where the log tells you a key exists and your own
record of what you published tells you whether to worry.
`--rekor off` (`SYNCH_REKOR`) states the opt-out;
`--rekor-key <file>` (`SYNCH_REKOR_KEY`) points at a self-hosted log's
verification key, with the same different-universe semantics as the trust
anchor. See [docs/REKOR-ZONE-KEY.md](docs/REKOR-ZONE-KEY.md).

Sigstore rotates those log keys, so the pinned set follows them on its own.
Once a day the daemon walks Sigstore's TUF repository, verifies the chain
offline against a TUF root built into the binary, and adopts the log keys it
authenticates, persisting them in `<data-dir>/rekor-pins.json`. Nothing about
it can fail a refresh — an unreachable, stale or invalid repository simply
leaves the current pins standing — and the versions only ever move forward,
so a hostile mirror can withhold an update but never walk one back.
`--no-tuf` (`SYNCH_NO_TUF`) turns the walk off, and `--rekor-key` turns the
whole mechanism off: a named key file is a static universe in both
directions.

Rotate a device key. Every step is an explicit command: a node never polls its
own domain and never switches signing keys on its own.

```sh
synch key rotate                           # generate K_new, print the TXT record
# publish the record, wait for it to propagate
synch key activate <K_new>                 # re-sign the head, serve on both keys
# remove the old record
synch key retire <K_old>                   # drop that endpoint, delete the secret
synch key ls                               # this node's keys, and which peers hold each bound
```

`synch key ls` is what answers the only question the middle step really turns
on — *have my peers picked up the new record yet?* It asks every reachable
trusted peer which of our device keys it currently holds bound and reports the
tally per key, naming the peers it could not reach rather than counting their
silence either way. A key-identified origin has no name to rebind, so `synch
key rotate` refuses it outright rather than generating a key that could never
be activated.

Recover an origin whose device key and database are gone. The node keeps its
name, comes up on a fresh key, and finds that its peers hold history it does
not — so it refuses to publish until an operator says how far to skip ahead:

```sh
synch recover                              # collect peer summaries for an hour
synch recover --wait 90m --gap 5000        # or wait longer, or skip further
synch doctor                               # says it is in recovery, and how far peers got
```

Publishing resumes at `<highest seq any peer advertised> + gap` (default 1000),
which is what makes a collision with history held only by an unreachable peer
improbable. If such a peer turns up later, its pre-recovery heads are kept as
provable fork evidence and `synch doctor` reports them on both sides.

Read across the cluster. What you see is **one tree** aggregated from every
node, in which each path carries one version per distinct content published for
it. Content is fetched on demand and verified per 16 KiB group, so a range read
costs a range:

```sh
synch ls media/talks                       # the unified tree; divergent paths marked ⑂2
synch ls media/talks --all                 # every version of every path, with attestors
synch ls nas@cluster.example.com:media     # one origin's view instead
synch status media/talks/keynote.mp4       # every version, side by side
synch cat media/talks/keynote.mp4 --range 0..1048576
synch cat media/notes.txt --from nas@cluster.example.com   # pin one origin
synch cat media/notes.txt --strict         # refuse a divergent path, list its versions
synch get media/notes.txt -o notes.txt
synch take nas@cluster.example.com:media/notes.txt   # adopt their version as ours
synch take nas@cluster.example.com:media/gone.txt    # …including their deletion
synch doctor                               # membership, heads, equivocation, storage
```

Reading a bare `<space>/<path>` has to pick one of the versions, and does it by
an explicit policy: `newest` (the default — the greatest `(mtime, content root,
origin)`, so every node picks the same one), `origin=<id>`, or `strict`.
Selection is presentation, not resolution: nothing is written, no assertion
changes, and the other versions stay visible until a `synch take` ends the
divergence. Deletions are adoptable the same way: taking a tombstone version
removes the local copy and publishes our own tombstone, and once every
publisher has done so the path leaves the tree.

Fill a space's own directory — the writable one `synch space add` named — with
the content of the unified tree. One pass, and additive: a path missing here is
written, a path whose bytes already match is left alone, and a path whose bytes
differ is reported rather than overwritten. Nothing is ever removed.

```sh
synch fill media                                           # newest, by default
synch fill media/talks                                     # one directory of it
synch fill media --from nas@cluster.example.com            # that origin's versions
synch fill media --strict                                  # report divergent paths, skip them
synch fill media --dry-run                                 # decide everything, write nothing
synch fill media --force                                   # replace local files that differ
```

`synch space sync` is the other half of the same wish and a different thing:
replication holds the *bytes* of every version in the store and materializes
nothing, while a fill writes *files*, one selected version per path. On a
replicated space the two compose — everything the fill wants is already local.

A fill does not publish. The files land where the scanner will find them, and
the next scan publishes them as this node's own view — which is why a filled
file carries the mtime and mode the origin published rather than this machine's
clock: the version that gets republished is the one that was filled, not a
newer one that would win every `newest` selection in the cluster. `--force` is
`synch take`'s adoption in bulk, though not its publish, and it names every
file it overwrote.

A node in key-loss recovery refuses to fill. A scan would refuse there too, so
everything filled would sit unannounced — and `--force`'s guard against
overwriting a local edit no scan has published needs this node to be publishing
something, so it would be inert while the fill wrote. Run `synch recover`
first, then fill, then scan.

Mirror a space into a directory, continuously, under a policy of its own:

```sh
synch mirror add media /mnt/media                          # newest, by default
synch mirror add media /mnt/nas --policy origin=nas@cluster.example.com
synch mirror add media /mnt/safe --policy strict           # skip divergent paths, report them
synch mirror ls
synch mirror sync
synch mirror rm /mnt/safe
```

Keep bytes around regardless of retention. A pin names an object root, or a
path — in which case the version the reading policy selects supplies the root.
Pinning content this node has never read fetches it first: the pin is a
promise the bytes stay available here, and it starts by getting them.

```sh
synch pin add media/talks/keynote.mp4
synch pin add nas@cluster.example.com:media/notes.txt      # that origin's version
synch pin add 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
synch pin ls
synch pin rm media/talks/keynote.mp4
```

Hold a whole space instead of naming objects one at a time. A replicated space
is one this node keeps every version of — every origin's version of every path,
not the one a policy selects — fetched as it appears and held for as long as
its policy says. It materializes nothing: that is what a mirror is for, and the
two compose.

```sh
synch space add media /srv/media --replicate    # publish my copy, hold everyone else's
synch space add photos --replicate              # a replica with no checkout at all
synch space add cold --replicate=archive        # never release anything, ever
synch space ls                                  # what this node does about each space
synch space ls media                            # held, wanted, releasing, unreachable
synch space set media --grace 90d               # how long a deleted version stays here
synch space set media --no-replicate            # stop; `--release` also drops the bytes
```

Under the default `tree` policy a replica holds what the tree names and lets a
root go once nothing names it — after `--grace`, which is the whole recovery
story for an accidental deletion. `--replicate=archive` releases nothing and
costs the sum of every version ever published rather than the size of the tree.
See [docs/REPLICATION.md](docs/REPLICATION.md).

Read a version that no path names any more — what `synch log` prints:

```sh
synch log media/talks/keynote.mp4               # every version, with its content root
synch cat --root 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
synch get --root 9f86d081… -o keynote-v1.mp4
```

Serve the same data over S3. The gateway is a control client of the
daemon — it opens no database of its own — so a `synch daemon run` must be
live on the same data directory for any `synch-s3` command to work:

```sh
synch-s3 bucket add media media                            # newest, by default
synch-s3 bucket add nas-media nas@cluster.example.com:media  # shorthand for an origin pin
synch-s3 bucket add safe-media media --policy strict
synch-s3 key add AKIAEXAMPLE <secret>
synch-s3 serve --listen 127.0.0.1:9000
# or, for local development only:
synch-s3 serve --anonymous
```

A bucket names a space of the unified tree plus a version policy; reads serve
the selected version and ETags are that version's BLAKE3 root in hex, quoted. A
`strict` bucket answers a divergent key with `409 Conflict` naming the
versions.

`DELETE` removes this node's copy and publishes a tombstone, the same thing an
`rm` in the space directory does — so, like a write, it publishes our own view.
A key another origin still publishes stays readable until that origin tombstones
it too, and the gateway says so in its log rather than in a status code S3 has
no room for.

Multipart upload is supported, which is what makes the gateway writable from
[Mountpoint for Amazon S3](https://github.com/awslabs/mountpoint-s3) — it wraps
every write in one, whatever the file's size. The upload lives in the daemon, so
one gateway process can create it and another complete it; its parts are staged
under `<data-dir>/s3-uploads/` and swept if nobody finishes them. Bodies that
arrive `aws-chunked` are unframed and their trailing checksum verified, so a
client that checksums while it streams is actually checked rather than taken at
its word. Writes always publish the local node's own view — the version model
forbids publishing someone else's — so a bucket pinned to a foreign origin
accepts writes but keeps reading that origin's versions, and the gateway warns
about that shape.

Expose a program instead of a file. A **socket** is a file in this node's
published tree whose content is an eBPF ELF object; a peer that connects to it
runs it *here*, one invocation per incoming stream, under
[async-ebpf](https://github.com/losfair/async-ebpf):

```sh
synch socket build git.c -o code/git.sock      # C in, eBPF out; nothing to install
synch socket build git.c --clang -o git.o       # optimized; needs clang + llc on PATH
synch socket add code/git.sock
synch scan                                     # publish it as kind=Socket
synch socket arm code/git.sock                 # inspect declarations and copy the token
synch socket arm code/git.sock --review <token> # approve exactly what was inspected
synch socket ls -l                             # armed root, drift, declarations
synch socket sdk > synch.h                     # the header a program is built against
```

On supported builds the compiler is in the binary — a build of
[tinycc](https://github.com/losfair/tinycc) that targets eBPF — so writing a
socket costs a text editor and nothing else, rather than a clang built with a
BPF backend that macOS does not ship. Windows MSVC builds report the command as
unsupported unless `--clang` selects a compatible system clang/llc toolchain.
The system path compiles at `-O2` for programs that benefit from optimized
code. Six worked examples are in
[`crates/synch-sock/examples/`](crates/synch-sock/examples/), and the test
suite runs every one of them.

From the other side, `synch connect` is a byte pump and nothing else — it names
a path, and everything that decides what runs is state the named node already
holds:

```sh
synch connect nas@cluster.example.com:code/git.sock
synch connect nas@cluster.example.com:code/git.sock --listen 127.0.0.1:9418
```

**A node executes only eBPF that is present in its own published tree.** So the
connecting side ships no code, needs no runtime, and works anywhere — while
adopting somebody's socket with `synch take` adopts its bytes and not its
socket-ness, because the entry kind comes from a local declaration and is never
taken from a peer. Publishing is not permission either: an arming record pins
the BLAKE3 content root that was approved, and bytes that change leave the
socket published and not runnable until somebody approves the new program.
Serving needs Linux, macOS or OpenBSD on x86-64 or arm64, which is where
async-ebpf runs. See [docs/SOCKETS.md](docs/SOCKETS.md).

## Layout

| Crate | What it holds |
| --- | --- |
| `synch-core` | `OriginId`, `Hash`, records, signed heads, the postcard wire schemas |
| `synch-mpt` | the Merkle-Patricia Trie: nodes, hashing, diff, proofs, cursors |
| `synch-store` | the SQLite schema and the content-addressed blob store |
| `synch-net` | the iroh endpoint, both ALPNs, reconciliation, the DNSSEC resolver, and the zone-key transparency verifier |
| `synch-engine` | the embeddable node: scanner, publisher, anti-entropy, fetcher, mirrors |
| `synch-cli` | the `synch` binary: the daemon, the control service, the CLI client, and the MCP bridge |
| `synch-s3` | the `synch-s3` binary and the gateway library |
| `synch-sock` | the socket runtime: the eBPF host APIs, the endpoint reactor, the program cache |
| `synch-cc` | the embedded C-to-eBPF compiler, so writing a socket needs no toolchain |
| `synch-monitor` | the `synch-monitor` binary: walks the transparency log's tiles and classifies every entry that names a watched zone |

All logic lives in the library crates, so any Rust application can embed a full
node by depending on `synch-engine`.

[docs/IMPLEMENTATION-NOTES.md](docs/IMPLEMENTATION-NOTES.md) records where this
implementation differs from the design and why.
