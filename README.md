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
```

Admit a peer. Trust is unilateral, so each side runs this for the other:

```sh
synch trust add <their-device-key> --as laptop --domain cluster.example.com
synch domain add cluster.example.com       # or DNSSEC membership instead
```

Read across the cluster. Content is fetched on demand and verified per 16 KiB
group, so a range read costs a range:

```sh
synch ls media/talks
synch status media/talks/keynote.mp4       # every origin's view, side by side
synch cat nas@cluster.example.com:media/talks/keynote.mp4 --range 0..1048576
synch get nas@cluster.example.com:media/notes.txt -o notes.txt
synch take nas@cluster.example.com:media/notes.txt   # adopt their version as ours
synch mirror add nas@cluster.example.com:media /mnt/nas-media
synch doctor                               # membership, heads, equivocation, storage
```

Serve the same data over S3:

```sh
synch-s3 bucket add media nas@cluster.example.com:media
synch-s3 key add AKIAEXAMPLE <secret>
synch-s3 serve --listen 127.0.0.1:9000
# or, for local development only:
synch-s3 serve --anonymous
```

ETags are the object's BLAKE3 root in hex, quoted. Buckets mapping to the local
node's own origin are writable; foreign-origin buckets are read-only.

## Layout

| Crate | What it holds |
| --- | --- |
| `synch-core` | `OriginId`, `Hash`, records, signed heads, the postcard wire schemas |
| `synch-mpt` | the Merkle-Patricia Trie: nodes, hashing, diff, proofs, cursors |
| `synch-store` | the SQLite schema and the content-addressed blob store |
| `synch-net` | the iroh endpoint, both ALPNs, reconciliation, the DNSSEC resolver |
| `synch-engine` | the embeddable node: scanner, publisher, anti-entropy, fetcher, mirrors |
| `synch-cli` | the `synch` binary |
| `synch-s3` | the `synch-s3` binary and the gateway library |

All logic lives in the library crates, so any Rust application can embed a full
node by depending on `synch-engine`.

[docs/IMPLEMENTATION-NOTES.md](docs/IMPLEMENTATION-NOTES.md) records where this
implementation differs from the design and why.
