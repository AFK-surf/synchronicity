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

## Container image

`ghcr.io/afk-surf/synchronicity/tools`, built from [`Dockerfile`](Dockerfile)
by [`.github/workflows/tools-image.yml`](.github/workflows/tools-image.yml) for
`linux/amd64` and `linux/arm64`. `latest` follows `main`; tagged releases get
`X.Y.Z` and `X.Y`; every build is also tagged `sha-<commit>` and carries signed
build provenance (`gh attestation verify oci://…` / `cosign verify-attestation`).
The control plane is a separate service in a separate language and keeps its own
image, [`ghcr.io/afk-surf/synchronicity/control-plane`](control-plane/README.md#container-image).

One image holds all three Linux programs — `synch`, `synch-s3` and `synch-dp` —
because they are deployed together: the gateway is a control client of the
daemon and opens no database of its own, and the data plane embeds the same
engine. There is no entrypoint wrapper, so the command names the tool:

```sh
docker volume create synch-data

# One node, its data directory on a named volume. A fresh named volume
# inherits the image's ownership, which is how the non-root service (uid
# 10001) gets a writable data directory on first run.
docker run --rm -v synch-data:/var/lib/synch \
  ghcr.io/afk-surf/synchronicity/tools \
  synch init --domain cluster.example.com

# The gateway's port is published here, not when it is started: a
# container's ports are fixed at `docker run`.
docker run -d --name synch-node \
  -v synch-data:/var/lib/synch \
  -v /srv/media:/srv/media \
  -p 9000:9000 \
  ghcr.io/afk-surf/synchronicity/tools \
  synch daemon run

# Every other command is a control client of that daemon, so it runs in
# the same container against the same data directory.
docker exec synch-node synch source add media /srv/media
docker exec synch-node synch source scan media
docker exec synch-node synch-s3 bucket add media media --read-write
printf '%s' "$S3_SECRET" |
  docker exec -i synch-node synch-s3 access-key add AKIAEXAMPLE --secret-stdin
docker exec -d synch-node synch-s3 serve --listen 0.0.0.0:9000
```

- **Volumes.** `/var/lib/synch` is the data directory — the database, the CAS
  and the control socket — and `SYNCH_DATA_DIR` points at it. That default is a
  path and not a policy, but it is not optional either: without it the CLI asks
  the platform for a data directory and a container with no `HOME` has none.
  Source directories are mounted separately, wherever you like. The data plane's
  `SYNCH_DP_BASE_DIR` is `/var/lib/synch-dp`, a plain directory rather than a
  volume, because that state is genuinely ephemeral — one directory per hosted
  tenant, restored from object storage after a reschedule.
- **Ports.** Only the gateway has a fixed one: 9000/tcp, and `synch-s3 serve`
  binds `127.0.0.1` unless `--listen` says otherwise, so a published port needs
  `--listen 0.0.0.0:9000` and real access keys (`--anonymous` refuses anything
  but loopback). The daemon's QUIC endpoint takes an ephemeral UDP port unless
  `--bind` names one.
- **Nothing else is configured.** Every setting that decides what a container
  *is* — the membership domain, the CAS backend and its credentials, the data
  plane's control URL and token — stays unset and required, so a misconfigured
  container fails at startup rather than running as something nobody asked for.
- **glibc, not the static musl of the release tarballs.** These are
  long-running servers; the image is built against the runtime's own glibc
  2.36, which is the configuration the test suite runs on.

Nothing is published until that exact image has run a node:
[`ops/image-smoke.sh`](ops/image-smoke.sh) does what this section describes —
`init`, `daemon run`, a source scanned and published, `synch cat` reading it
back, and `synch-s3` serving the same object over HTTP — and checks what only
running it can check: all three binaries present and built for this
architecture, `synch-dp` reaching its configuration check, a data directory the
uid-10001 service can write, the gateway finding the control socket, and a
clean shutdown on `synch daemon stop`. The publish job depends on it, so a
green image is one that ran.

To build and test it locally, from the repository root:

```sh
docker build -t synch-tools:dev .
./ops/image-smoke.sh synch-tools:dev
```

## Usage

Set up a node. `synch init` creates the datadir, `synch daemon start` launches
the owner process in the background, and operational commands are gRPC calls to
that daemon over a local control socket:

```sh
synch init --domain cluster.example.com   # or plain `synch init` for a key identity
synch daemon start                         # returns when the control socket is ready
synch source add media /srv/media
synch source scan media                    # hash, publish a signed root
synch source relink media /srv/media-new
synch source detach media
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
export SYNCH_REPLICA_CONCURRENCY=16           # concurrent CAS roots per replica

synch init --domain cluster.example.com     # once, only if restore found no database
synch daemon start
synch source add media --api
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

Only API sources are valid on a cloud-backed node. They have no scanner,
watcher, or local directory: gateway writes, `synch put`, `synch fetch`, and
`synch adopt path` ingest directly into the cloud CAS, while `cat`, `get`, and
gateway reads fill the ephemeral range cache on demand. A durable-disk node can
configure a replica checkout when a filesystem projection is wanted elsewhere.

The default `SYNCH_CAS_UPLOAD=own+pinned` uploads content created by this node
and peer content it pins. Use `own` to upload only locally created content, or
`all` to make the node a durable replica of every object it fetches completely.
`SYNCH_CAS_CACHE_BYTES` is a maintenance target, not a per-request hard limit;
on Unix, omitting it targets at least 20% free space.
Replica convergence fetches 16 distinct CAS objects concurrently by default;
set `SYNCH_REPLICA_CONCURRENCY` or `--replica-concurrency` to tune it from 1 to
256.

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

To convert an existing node, first ensure every local source is API-only, stop the
daemon, supply the destination provider settings above, and run:

```sh
synch cas migrate --to s3                 # or gcs / azblob / local
```

Migration copies every candidate before atomically changing the configured
backend and is safe to retry after interruption. See
[docs/SERVERLESS.md](docs/SERVERLESS.md) for the full durability, recovery,
failure, and Kubernetes deployment contract.

## Hosted replicas (the cloud data plane)

`synch-dp` is the managed side of the same idea: one process hosting a fleet of
serverless replica nodes, one per customer network, each joining that network as
an ordinary zone-named device and replicating everything it publishes into
object storage. A customer turns it on with one per-network switch in the
control plane and needs no new protocol, no configuration and no upgrade — they
gain a member that fetches eagerly and serves well.

Each data plane is named in the control plane (`controlplane dataplane
register dp-1`) and its key names it, so which networks a pod hosts is one
column there rather than arithmetic each pod does for itself. The pod is told
only where the control plane is and which token to present.

```sh
export SYNCH_DP_CONTROL_URL=https://cp.example
export SYNCH_DP_TOKEN=synchdp_…             # `controlplane dataplane-key mint <name> --dp <dp-id>`
export SYNCH_DP_BASE_DIR=/run/synch-dp      # ephemeral; nothing here survives a restart
export SYNCH_DP_CAS_BACKEND=s3
export SYNCH_DP_S3_BUCKET=synch-hosted
export SYNCH_DP_S3_REGION=us-east-1
synch-dp
```

Membership uses DNSSEC plus Rekor zone-key transparency by default. A private
deployment whose DNSSEC root is intentionally absent from the public log must
state that trust choice explicitly with `SYNCH_DP_REKOR=off`, just as a regular
node would use `synch --rekor off`.

It runs on pods with no durable disk, so it replicates each tenant's SQLite
database to the bucket itself — Litestream's LTX format via the `celld-ltx`
library, driven in-process rather than by a sidecar — and restores it on every
reschedule. Everything durable about a tenant is keyed by network rather than
by pod, so a rescheduled data plane resumes the same identities with no zone change
at all. Those streams carry device secret keys, so give the bucket encryption
at rest and do not grant the `db/` prefix more widely than the `tenants/` one.

[docs/CLOUD-DATAPLANE.md](docs/CLOUD-DATAPLANE.md) is the design: the
control-plane API it polls, the tenancy and storage model, the failure matrix,
and what hosting does and does not promise about privacy.

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
`synch init`, then `synch domain set <domain>` or `synch trust add <issuer-key>` —
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
synch cat media/notes.txt --select origin=nas@cluster.example.com  # pin one origin
synch cat media/notes.txt --select strict  # refuse a divergent path, list its versions
synch get media/notes.txt -o notes.txt
synch adopt path nas@cluster.example.com:media/notes.txt  # adopt their version as ours
synch adopt path nas@cluster.example.com:media/gone.txt  # …including their deletion
synch doctor                               # membership, heads, equivocation, storage
```

Reading a bare `<space>/<path>` has to pick one of the versions, and does it by
an explicit policy: `newest` (the default — the greatest `(mtime, content root,
origin)`, so every node picks the same one), `origin=<id>`, or `strict`.
Selection is presentation, not resolution: nothing is written, no assertion
changes, and the other versions stay visible until a `synch adopt path` ends the
divergence. Deletions are adoptable the same way: taking a tombstone version
removes the local copy and publishes our own tombstone, and once every
publisher has done so the path leaves the tree.

Write without a checkout. `put` streams a local file, or stdin, through the same
typed write the S3 gateway uses and publishes it as this node's own version;
`delete` publishes this node's tombstone. Both work on an API source, where
nothing is materialized. The end of stdin is the end of the payload — put cannot
tell a producer that finished from one that died — so when that matters, write
to a file first and put the file:

```sh
synch put notes.txt media/notes.txt                  # this node's version of the path
synch put report.pdf media/documents/                # a trailing slash keeps the file name
tar cz src | synch put - media/backups/src.tgz       # stdin, with an explicit name
synch fetch https://example.com/1.txt media/documents/  # an http(s) URL, the same way
synch delete media/notes.txt                         # our tombstone; other origins' versions stay
```

Adopt a tree into a filesystem source — the directory `synch source add` named — with
the content of the unified tree. One pass, and additive: a path missing here is
written, a path whose bytes already match is left alone, and a path whose bytes
differ is reported rather than overwritten. Nothing is ever removed.

```sh
synch adopt tree media                                     # newest, by default
synch adopt tree media/talks                               # one directory of it
synch adopt tree media --select origin=nas@cluster.example.com  # that origin's versions
synch adopt tree media --select strict                         # report divergent paths, skip them
synch adopt tree media --dry-run                           # decide everything, write nothing
synch adopt tree media --replace                           # replace local files that differ
```

`synch replica sync` is the other half of the same wish and a different thing:
replication holds the *bytes* of every version in the store and materializes
nothing, while adoption writes *files*, one selected version per path, into a
source. When the same namespace is also a replica, the two compose: retained objects need no network
read during adoption.

Tree adoption scans, publishes, and pushes successful changes before returning.
Written files carry the selected version's mtime and masked mode so adoption
restates that version rather than minting a wall-clock winner. A node in key-loss
recovery refuses adoption before writing anything; run `synch recover` first.

Materialize a replica's newest view into one managed checkout:

```sh
synch replica add media --checkout /mnt/media
synch replica set media --checkout /mnt/new-media
synch replica sync media
synch replica set media --no-checkout                      # leaves files in place
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

Hold a whole namespace instead of naming objects one at a time. A replica keeps
every version — every origin's version of every path,
not the one a policy selects — fetched as it appears and held for as long as
its retention says. A replica may optionally materialize one newest checkout.

```sh
synch source add media /srv/media                # publish my copy
synch replica add media                          # independently hold every current version
synch replica add cold --retention forever       # never release observed roots
synch ls                                         # namespace plus local roles
synch replica ls media                           # held, wanted, releasing, unreachable
synch replica set media --grace 90d              # deleted-root recovery window
synch replica rm media                           # stop and release replica holds
```

Under the default `current` retention a replica holds what the tree names and lets a
root go once nothing names it — after `--grace`, which is the whole recovery
story for an accidental deletion. `--retention forever` releases nothing and
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
synch-s3 bucket add media media --read-write
synch-s3 bucket add nas-media media --read-only --select origin=nas@cluster.example.com
synch-s3 bucket add safe-media media --read-only --select strict
printf '%s' "$S3_SECRET" | synch-s3 access-key add AKIAEXAMPLE --secret-stdin
synch-s3 serve --listen 127.0.0.1:9000
# or, for local development only:
synch-s3 serve --anonymous
```

A bucket is explicitly read-only or read-write. Read-only buckets may select
`newest`, `strict`, or one origin; a `strict` read answers a divergent key with
`409 Conflict`. Read-write buckets require a local source and read this node's
own view, following its current origin across identity adoption, so a successful
mutation is immediately visible through that bucket.
ETags are the selected version's quoted BLAKE3 root.

On a read-write bucket, `DELETE` removes this node's copy and publishes a
tombstone, the same thing an `rm` in the source directory does.
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
its word. Read-only buckets reject every mutation before consuming its body.

Expose a program instead of a file. A **socket** is a file in this node's
published tree whose content is an eBPF ELF object; a peer that connects to it
runs it *here*, one invocation per incoming stream, under
[async-ebpf](https://github.com/losfair/async-ebpf):

```sh
synch socket build git.c -o code/git.sock      # C in, eBPF out; nothing to install
synch socket build git.c --clang -o git.o       # optimized; needs clang + llc on PATH
synch socket inspect code/git.sock             # stateless: root, manifest, load check
synch socket activate code/git.sock            # the path is a socket until deactivated
synch source scan                              # publish it as kind=Socket
synch socket ls -l                             # published root, manifest, validity
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

From the other side, `synch socket connect` is a byte pump and nothing else — it names
a path, and everything that decides what runs is state the named node already
holds:

```sh
synch socket connect nas@cluster.example.com:code/git.sock
synch socket connect nas@cluster.example.com:code/git.sock --listen 127.0.0.1:9418
```

**A node executes only eBPF that is present in its own published tree, at a
path it activated.** So the connecting side ships no code, needs no runtime,
and works anywhere — while adopting somebody's socket with `synch adopt path`
adopts its bytes and not its socket-ness, because the entry kind comes from a
local activation and is never taken from a peer. What a program may reach is
declared as data in the object itself — a JSON manifest in a non-executable
ELF section — so `synch socket inspect` answers "what would this deployment
do?" without running anything, and every write to an activated path is an
intentional deployment that serves immediately under its own manifest.
Serving needs Linux, macOS or OpenBSD on x86-64 or arm64, which is where
async-ebpf runs. See [docs/SOCKETS.md](docs/SOCKETS.md).

## Layout

| Crate | What it holds |
| --- | --- |
| `synch-core` | `OriginId`, `Hash`, records, signed heads, the postcard wire schemas |
| `synch-mpt` | the Merkle-Patricia Trie: nodes, hashing, diff, proofs, cursors |
| `synch-store` | the SQLite schema and the content-addressed blob store |
| `synch-net` | the iroh endpoint, both ALPNs, reconciliation, the DNSSEC resolver, and the zone-key transparency verifier |
| `synch-engine` | the embeddable node: scanner, publisher, anti-entropy, fetcher, checkouts |
| `synch-cli` | the `synch` binary: the daemon, the control service, the CLI client, and the MCP bridge |
| `synch-s3` | the `synch-s3` binary and the gateway library |
| `synch-sock` | the socket runtime: the eBPF host APIs, the endpoint reactor, the program cache |
| `synch-cc` | the embedded C-to-eBPF compiler, so writing a socket needs no toolchain |
| `synch-monitor` | the `synch-monitor` binary: walks the transparency log's tiles and classifies every entry that names a watched zone |
| `synch-dp` | the `synch-dp` binary: the multi-tenant cloud data plane, one embedded replica node per hosted network |

All logic lives in the library crates, so any Rust application can embed a full
node by depending on `synch-engine`. `synch-dp` is the largest such embedder in
this repository, and a worked example of what embedding many nodes at once
asks for.

[docs/IMPLEMENTATION-NOTES.md](docs/IMPLEMENTATION-NOTES.md) records where this
implementation differs from the design and why.
