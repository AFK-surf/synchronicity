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

Set up a node. `synch init` is the one command that runs without a daemon — it
creates the datadir; everything after it is a request to the running daemon over a
local control socket:

```sh
synch init --id nas@cluster.example.com   # or plain `synch init` for a key identity
synch daemon run &                         # required: the daemon owns the node
synch space add media /srv/media
synch scan                                 # hash, publish a signed root
synch id                                   # print the origin, device key, and address
synch daemon status                        # what the running node is doing
synch daemon stop                          # ask it to shut down
```

The socket is `<data-dir>/control.sock` (a `\\.\pipe\synchronicity-…` named pipe
on Windows), `0600` inside a `0700` data directory, authenticated by a token
regenerated on every daemon start. With no daemon running, every command except
`synch init` fails with a message naming that socket.

Admit a peer. Trust is unilateral, so each side runs this for the other:

```sh
synch trust add <their-device-key> --as laptop --domain cluster.example.com
synch domain add cluster.example.com       # or DNSSEC membership instead
synch domain refresh cluster.example.com   # one domain now, or all of them with no argument
```

Membership from DNS refreshes itself: the daemon re-resolves each configured
domain when its TTL runs out, and again — rate-limited — when a peer this node
holds no binding for tries to connect, which is what the far side of a lagging
key rotation looks like. A resolver outage fails closed: the cached bindings
keep their own expiry, and the member set shrinks toward static-only rather
than falling open.

Rotate a device key. Every step is an explicit command: a node never polls its
own domain and never switches signing keys on its own.

```sh
synch key rotate                           # generate K_new, print the TXT record
# publish the record, wait for it to propagate
synch key activate <K_new>                 # re-sign the head, serve on both keys
# remove the old record
synch key retire <K_old>                   # drop that endpoint, delete the secret
synch key ls                               # this node's keys and their state
```

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
synch doctor                               # membership, heads, equivocation, storage
```

Reading a bare `<space>/<path>` has to pick one of the versions, and does it by
an explicit policy: `newest` (the default — the greatest `(mtime, content root,
origin)`, so every node picks the same one), `origin=<id>`, or `strict`.
Selection is presentation, not resolution: nothing is written, no assertion
changes, and the other versions stay visible until a `synch take` ends the
divergence.

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
path — in which case the version the reading policy selects supplies the root:

```sh
synch pin add media/talks/keynote.mp4
synch pin add nas@cluster.example.com:media/notes.txt      # that origin's version
synch pin add 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
synch pin ls
synch pin rm media/talks/keynote.mp4
```

Serve the same data over S3:

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
versions. Writes always publish the local node's own view — the version model
forbids publishing someone else's — so a bucket pinned to a foreign origin
accepts writes but keeps reading that origin's versions, and the gateway warns
about that shape.

## Layout

| Crate | What it holds |
| --- | --- |
| `synch-core` | `OriginId`, `Hash`, records, signed heads, the postcard wire schemas |
| `synch-mpt` | the Merkle-Patricia Trie: nodes, hashing, diff, proofs, cursors |
| `synch-store` | the SQLite schema and the content-addressed blob store |
| `synch-net` | the iroh endpoint, both ALPNs, reconciliation, the DNSSEC resolver |
| `synch-engine` | the embeddable node: scanner, publisher, anti-entropy, fetcher, mirrors |
| `synch-cli` | the `synch` binary: the daemon, the control socket, and the CLI client |
| `synch-s3` | the `synch-s3` binary and the gateway library |

All logic lives in the library crates, so any Rust application can embed a full
node by depending on `synch-engine`.

[docs/IMPLEMENTATION-NOTES.md](docs/IMPLEMENTATION-NOTES.md) records where this
implementation differs from the design and why.
