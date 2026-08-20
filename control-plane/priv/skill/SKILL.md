---
name: synch
description: Drive the `synch` CLI — a synchronicity node: initialize it, run its daemon, index local directories as spaces, admit peers by device key or DNSSEC zone, delegate space-restricted access, read the unified tree, resolve divergent paths, mirror, pin, rotate keys, and recover a lost origin. Use whenever a task involves `synch`, `synch-s3`, a synchronicity cluster, or a node's data directory.
---

# synch

`synch` is one binary that is both a node daemon and the client that talks to
it. A node publishes **its own view** of the files it indexes, signed; peers
replicate each other's views; what you read is the **union** of everybody's
views, with the conflicts left visible instead of resolved behind your back.

Two rules explain most of the surface:

1. **The daemon owns the node.** `synch init` is the only command that runs
   without one. Everything else is a gRPC call over a unix socket at
   `<data-dir>/control.sock`. With no daemon running you get, verbatim:

   ```
   synch: no daemon is running for /var/lib/synch: nothing is listening on
   /var/lib/synch/control.sock. Start one with `synch daemon run`
   ```

2. **Nobody writes anybody else's view.** A publish always says "*this* origin
   asserts this content for this path". Adopting a peer's bytes is an explicit
   `synch take`, and it publishes *your* assertion of them.

## Getting a binary

Download a release archive from GitHub. Do not build from source — the
source tree is not expected to be present. Each release ships one archive per
platform, named `synchronicity-<version>-<target>.<ext>`, and each unpacks to
a directory holding `synch`, `synch-s3`, `synch-monitor` and the docs:

| Platform | `<target>` | Archive |
| --- | --- | --- |
| Linux, x86-64 | `x86_64-unknown-linux-musl` | `.tar.gz` |
| Linux, arm64 | `aarch64-unknown-linux-musl` | `.tar.gz` |
| macOS, Intel | `x86_64-apple-darwin` | `.tar.gz` |
| macOS, Apple silicon | `aarch64-apple-darwin` | `.tar.gz` |
| Windows, x86-64 | `x86_64-pc-windows-msvc` | `.zip` |

The musl builds are fully static, so they run on any Linux whatever its libc.
Resolve the latest tag from the API rather than hardcoding a version:

```sh
tag=$(curl -fsSL https://api.github.com/repos/AFK-surf/synchronicity/releases/latest \
  | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  target=x86_64-unknown-linux-musl ;;
  Linux-aarch64) target=aarch64-unknown-linux-musl ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Darwin-arm64)  target=aarch64-apple-darwin ;;
esac

base="https://github.com/AFK-surf/synchronicity/releases/download/$tag"
name="synchronicity-$tag-$target"
curl -fsSLO "$base/$name.tar.gz"
curl -fsSL "$base/SHA256SUMS" | grep -F "$name.tar.gz" | sha256sum -c -
tar xzf "$name.tar.gz"
sudo install -m 0755 "$name/synch" "$name/synch-s3" /usr/local/bin
```

(On macOS, where `sha256sum` does not exist, `shasum -a 256 -c -` reads the
same format.) On Windows, download the `.zip`, check its hash against
`SHA256SUMS` (`certutil -hashfile <zip> SHA256`), and expand it — `synch.exe`
and `synch-s3.exe` run from wherever they land.

SQLite is compiled in and TLS is rustls, so there is no system library to
install.

## The first five minutes

```sh
synch init                              # or: synch init --domain cluster.example.com
synch daemon run &                      # required from here on
synch space add media /srv/media        # index a local directory
synch scan                              # hash it and publish a signed root
synch ls media                          # read it back
synch id                                # who this node is, and where it listens
```

`synch init` prints the device key, the data directory, and the next step:

```
device key: qmpmjtrw6w6h5ri3taracdpajdg14d5di7i1xq3ahomw485jrezo
data dir:   /var/lib/synch
origin:     key:qmpmjtrw6w6h5ri3taracdpajdg14d5di7i1xq3ahomw485jrezo
next:       synch daemon run
```

With `--domain`, it prints the TXT record to publish instead — the node has no
name until the zone gives it one:

```
domain:     cluster.example.com
next:       publish this record, then `synch daemon run`:
  _synchronicity.cluster.example.com. IN TXT "v=sync1 id=<name> nk=<device key> apex=<apex>"
```

`scan` reports what it did and what it published:

```
scanned media: hashed 2 · unchanged 0 · deleted 0
hashed 2 · unchanged 0 · deleted 0 · ignored 0
published seq 1 root 9d3aa19d77aeb7171218857063534ab1d5ad46cf53868854bc9dc4b810aa17ae
```

You rarely need to run it by hand: `daemon run` carries a scanner and a
filesystem watcher. Run it when you want the publish *now*.

## Naming things

An **origin** is one publisher. It is either its device key
(`key:qmpmjtrw…`, when `init` had no `--domain`) or a zone-issued name
(`nas@cluster.example.com`). A **space** is an id mapped to a local directory
on the node that indexes it; the same space id on several nodes is the same
part of the tree.

Almost every read takes a **reference**:

| Form | Means |
| --- | --- |
| `media` | the whole space, unified across every origin |
| `media/talks` | a directory inside it |
| `media/notes.txt` | one path — the version the policy selects |
| `nas@cluster.example.com:media/notes.txt` | that origin's version, pinned |
| `key:qmpmjtrw…:media` | the same, for a key-identified origin |

`synch take` is the one command that *requires* the origin-prefixed form:

```
synch: take needs an explicit <origin>:<space>/<path>
```

## Reading

```sh
synch ls media                       # the unified tree; divergent paths marked ⑂N
synch ls media --all                 # every version of every path, with attestors
synch ls nas@cluster.example.com:media
synch status media/notes.txt         # the version inspector
synch status media                   # every path in the space, versions and all
synch status                         # everything this node can see
synch cat media/notes.txt
synch cat media/talks/keynote.mp4 --range 0..1048576
synch cat media/notes.txt --from nas@cluster.example.com
synch cat media/notes.txt --strict   # refuse a divergent path, list its versions
synch get media/notes.txt -o notes.txt
synch log media/notes.txt            # per-origin publish history
synch compare media --to nas@cluster.example.com          # name-status diff, no bytes fetched
synch compare media --to nas@… --from laptop@… --json
```

`ls` shows the selected version per path, and marks divergence with a count:

```
          13  file      notes.txt  ⑂2
      300000  file      talks/keynote.bin
```

`--all` expands each into its versions, `<content root prefix> <kind> <size>
seq <n> <attestors>`:

```
          13  file      notes.txt  ⑂2
    08615ee91085d812   file               13  seq 1      key:zqgii4mspx
    b3222554c775e5f0   file               13  seq 1      key:qmpmjtrw6w
```

Reads are verified per 16 KiB group as they stream, so `--range` costs a range
rather than a whole file. `get` creates its destination only when the first
byte arrives — a read that fails leaves the old file alone.

### Which version you get

A bare `<space>/<path>` has to choose one of several versions, and does it by
an explicit policy:

- **`newest`** (the default) — greatest `(mtime, content root, origin)`. It is
  a total order over data every node has, so every node picks the same one.
- **`origin=<id>`** — that origin's version. `--from <origin>` and the
  `<origin>:` prefix are the same thing at the command line.
- **`strict`** — refuse and list, exit 1:

  ```
  synch: media/notes.txt has 2 versions and the policy is strict:
    08615ee91085d812… size 13 mtime 1787193243306503556 seq 1 asserted by key:zqgii4mspx…
    b3222554c775e5f0… size 13 mtime 1787193243304782909 seq 1 asserted by key:qmpmjtrw6w…
  ```

Selection is **presentation, not resolution**. Nothing is written, no assertion
changes, and every version stays visible until somebody ends the divergence
deliberately.

### Ending a divergence

```sh
synch status media/notes.txt                       # see the versions
synch take nas@cluster.example.com:media/notes.txt # adopt one as ours
```

`take` writes the bytes into the local space directory and publishes your own
assertion of them, which is what collapses the count:

```
adopted into /srv/media/notes.txt
published seq 4
```

```
media/notes.txt  1 version(s)
    b3222554c775e5f0   file               13  seq 4      key:qmpmjtrw6w, key:zqgii4mspx
```

Deletions adopt the same way. A deleted path is a **tombstone** version, and
`status` shows it beside the surviving content:

```
media/notes.txt  2 version(s)  ⑂2
    (deleted)          deleted             0  seq 4      key:qmpmjtrw6w
    b3222554c775e5f0   file               13  seq 4      key:zqgii4mspx
```

`synch take <origin>:media/notes.txt` on that tombstone removes the local copy
and publishes your own. Once every publisher has, the path leaves the tree.

## Membership

Trust is **unilateral and per-direction**: each side admits the other. There
are three ways in.

### Static keys

```sh
synch trust add <their-device-key> --addr 10.0.0.7:4242 --note "the NAS"
synch trust ls
synch trust rm <origin>
synch trust rm <origin> --key <one-key>    # after a rotation window closes
```

The key is the identity; names come from zones. `--as <origin>` is the
deliberate exception, for a member that publishes under a name this node has
no zone to learn — and it says what it costs:

```
trusted 9qs54nyt… as laptop@cluster.example.com
this binding never expires and shadows the zone record it names; remove it with
`synch trust rm` when the zone should govern again
```

### DNSSEC zones

```sh
synch domain set cluster.example.com    # takes effect at the next daemon start
synch domain ls
synch domain refresh                    # re-resolve now
synch domain clear
```

`domain set` prints the record the zone must carry, because the consequence
lands at the next start — a zone that does not name this key leaves the node
with nothing to publish under, and `daemon run` waits rather than serving.

Membership refreshes itself: the daemon re-resolves each domain when its TTL
runs out, and again (rate-limited) when an unknown key tries to connect, which
is what the far side of a lagging rotation looks like. **A resolver outage
fails closed** — cached bindings keep their own expiry and the member set
shrinks toward static-only.

Resolution is DNS-over-HTTP(S) only (`--doh`, default
`https://1.1.1.1/dns-query`), DNSSEC-validated in process, so the transport
carries nothing trusted. By default the zone key must *also* appear in the
public Sigstore Rekor v2 transparency log, with the proof carried inside the
zone and verified offline; `--rekor off` states the opt-out.

### Delegation

A node whose own trust is static or DNS can admit one other key to a named
list of spaces — no zone edit, nobody else's configuration touched:

```sh
synch delegate add <their-device-key> --space photos --space incoming --until 7d
synch delegate ls
synch delegate rm <their-device-key>
```

```
delegated 9qs54nyt… for 6d
  media
published at seq 3
this node will serve it a projection of every trie covering media, and nothing
else — it will not learn that any other space exists
```

Nothing is handed to the delegate: the grant is a record in the issuer's trie,
so every member learns it through ordinary replication. The delegate joins from
its own side with the commands it would use anyway — `synch init`, then
`synch trust add <issuer-key>` or `synch domain set <domain>`.

On the delegate, `synch doctor` says so out loud:

```
read scope: media (§5.5)
  everything outside those spaces is absent by design, not missing: this node
  is never served it and never asks for it
```

`--until` defaults to 30d and takes `30s`, `90m`, `1h`, `2h30m`, `7d`, or plain
seconds. What `delegate add` and `delegate ls` print back is *remaining* time
read against the local clock and floored to a whole unit — a delegation is
written by the issuer's clock and read by yours — so `--until 7d` reports `6d`
a moment later. That is the rendering, not a shortened grant.

A delegate cannot delegate further, and withdrawing propagates like any other
deletion:

```
removed the delegation of 9qs54nyt…
published at seq 8 — every reachable peer within one push
```

## Materializing and keeping bytes

A **mirror** continuously writes one space into a directory under a policy of
its own. It is named by the directory it writes into.

```sh
synch mirror add media /mnt/media                              # newest
synch mirror add media /mnt/nas --policy origin=nas@cluster.example.com
synch mirror add media /mnt/safe --policy strict               # skip divergent paths
synch mirror ls
synch mirror sync                                              # bring all up to date now
synch mirror rm /mnt/safe
```

```
/mnt/media  written 0 · current 2 · retouched 0 · removed 0 · skipped 0
```

A **pin** keeps content regardless of retention. It names an object root, or a
path — in which case the reading policy supplies the root. Pinning content this
node has never read fetches it first.

```sh
synch pin add media/talks/keynote.mp4
synch pin add nas@cluster.example.com:media/notes.txt
synch pin add 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
synch pin ls
synch pin rm media/talks/keynote.mp4     # or the hex root
```

`pin ls` names the root, the size, and the path that currently selects it —
`(no current entry names it)` once nothing does. `pin rm <path>` resolves the
path *now*, so after a tombstone the path no longer names anything and you must
remove the pin by its root.

## Operating

```sh
synch daemon run                # owns the node: control socket + every standing loop
synch daemon status             # one screen
synch daemon stop               # ask it to shut down (Ctrl-C does the same)
synch peers                     # live peers, addresses, last sync, rtt
synch sync                      # one anti-entropy exchange with every dialable peer, now
synch doctor                    # the full examination
synch doctor --rebuild          # rebuild derived views from the authoritative trie
```

`daemon run` prints where it is and what socket it bound, then keeps the
anti-entropy scheduler, scanner, watcher, publisher, mirror loop, DNS refresh,
maintenance/GC and the control-plane tunnel running:

```
origin key:qmpmjtrw… on qmpmjtrw… via 127.0.0.1:47001
control socket: /var/lib/synch/control.sock
```

`doctor` is the first thing to run when something looks wrong. It reports
identity and address, clock floor, the trust configuration in force (rekor
mode, DoH endpoint, trust anchor, TUF repository, pinned log keys), every
membership binding, the read scope, each origin's head and whether it is
servable, unreconciled pre-recovery history, origins held without a live
binding, equivocation, and storage counts.

`sync` names each peer and what the exchange moved, including the ones it could
not reach:

```
key:9qs54nyt… (fbadbd0811)  unreachable: endpoint: No addressing information available
key:qmpmjtrw… (72dab4c494)  accepted 1 head(s) · completed 1 origin trie(s) · pushed 0
```

### Key rotation

Every step is explicit — a node never polls its own domain and never switches
signing keys on its own.

```sh
synch key rotate                 # generate K_new, print the TXT record
# publish the record, wait for it to propagate
synch key activate <K_new>       # re-sign the head, serve on both keys
# remove the old record
synch key retire <K_old>         # drop that endpoint, delete the secret
synch key ls
```

`synch key ls` answers the question the middle step turns on — *have my peers
picked up the new record yet?* It asks every reachable trusted peer which of
our keys it holds bound, and names the peers it could not reach rather than
counting their silence either way:

```
qmpmjtrw… active   bound by 0 of 0 reachable peer(s)
    zqgii4msp… unreachable: read: connection lost
  no peer could be reached; the tallies above count nobody
```

Rotation needs a zone-issued name. A key-identified origin refuses outright:

```
synch: origin key:9qs54nyt… is key-identified, so its device key is its
identity and cannot rotate. A rotatable name comes from a membership zone:
`synch domain set <domain>`, then publish a record for this key
```

`key retire` refuses the active key and tells you to activate the successor
first. `--bind HOST:PORT` on `key activate` names the new endpoint's address;
without it the new key takes an ephemeral port.

### Recovery

For an origin whose device key and database are gone. It keeps its name, comes
up on a fresh key, finds peers holding history it does not, and refuses to
publish until an operator says how far to skip ahead.

```sh
synch recover                       # collect peer summaries for an hour
synch recover --wait 90m --gap 5000
synch doctor                        # says it is in recovery, and how far peers got
```

```
collecting head summaries from every reachable peer for 5s
round 1: 0 peer(s) answered, 0 unreachable · highest seq seen 5 · 0s elapsed, 4s left
2 round(s) over 5s · 0 peer(s) answered, 0 unreachable
```

Publishing resumes at `<highest seq any peer advertised> + gap` (default 1000),
which makes a collision with history held only by an unreachable peer
improbable. If such a peer turns up later its pre-recovery heads are kept as
provable fork evidence, and `doctor` reports them on both sides under
`UNRECONCILED PRE-RECOVERY HISTORY`.

### The control-plane tunnel

On by default. The daemon discovers a managed control plane from
`_synchronicity-cp.<apex>` in the zone it already validates, dials out over
WSS, and proves itself with the device key that zone publishes. It is read-only
by construction, and whether anything is browsable is decided by the org admin
on the far end.

```sh
synch cloud status      # per domain: record found, attached, last error
synch cloud disable     # the only local act: opt out
synch cloud enable      # undo it
```

With no domain configured it says so rather than pretending:

```
cloud attach enabled: serving the control plane's requests for (no local spaces)
note: no membership domains are configured, so there is no zone to discover a
control plane from; `synch domain set <domain>` first
```

## Global flags

These apply to every subcommand and may appear before or after it. Each has an
environment variable.

| Flag | Env | What |
| --- | --- | --- |
| `--data-dir <DIR>` | `SYNCH_DATA_DIR` | the data directory; defaults to the platform data directory |
| `--bind <HOST:PORT>` | — | bind the endpoint here instead of an ephemeral port |
| `--offline` | — | no relays, no address discovery; direct addresses only |
| `--doh <URL>` | `SYNCH_DOH` | DoH endpoint for membership records |
| `--dnssec-anchor <FILE>` | `SYNCH_DNSSEC_ANCHOR` | replace the ICANN root anchor |
| `--rekor require\|off` | `SYNCH_REKOR` | require a transparency-log record for the zone key |
| `--rekor-key <FILE>` | `SYNCH_REKOR_KEY` | verification key(s) for a self-hosted log |
| `--tuf <URL>` | `SYNCH_TUF` | follow this Sigstore TUF repository |
| `--no-tuf` | `SYNCH_NO_TUF` | never contact it; freeze the pin set |
| `--relay <URL>` | `SYNCH_RELAY` | use these iroh relays (repeatable) |
| `--discovery <URL>` | `SYNCH_DISCOVERY` | use this pkarr relay |
| `--dht` | `SYNCH_DHT` | also publish/resolve addresses on the Mainline DHT |
| `--dht-bootstrap <HOST:PORT>` | `SYNCH_DHT_BOOTSTRAP` | your own bootstrap nodes (needs `--dht`) |
| `--dht-publish-addrs` | `SYNCH_DHT_PUBLISH_ADDRS` | publish direct IPs to the DHT (needs `--dht`) |
| `-v, --verbose` | — | more logging (`SYNCH_LOG` takes an env-filter) |

Notes that bite:

- `--offline` **conflicts with** every network flag rather than quietly
  ignoring it; `--dht-bootstrap` and `--dht-publish-addrs` require `--dht`.
- The network flags take effect **where the endpoint is bound**, which is
  `synch daemon run`. Passing them to a client command changes nothing.
- `--dnssec-anchor`, `--rekor-key` and `--tuf`-with-a-private-root are
  *different universes*, not additions: with one set, nothing signed under the
  real root or the built-in log verifies any more.
- `--strict` conflicts with `--from` on `cat` and `get` — one refuses to
  choose, the other chooses.

## Exit codes and error shapes

`0` success · `1` the command failed (the message is on stderr, prefixed
`synch:`) · `2` the arguments were wrong (clap usage error).

Failures worth recognizing:

| Message | Means |
| --- | --- |
| `no daemon is running for <dir>: nothing is listening on <sock>` | start `synch daemon run` |
| `no space <id>: not a local space, and no origin publishes one` | the space id is wrong, or nothing has published it yet |
| `not found: <space>/<path>` | no version of that path in the unified tree |
| `<path> has N versions and the policy is strict` | divergence, under `--strict`; the versions follow |
| `take needs an explicit <origin>:<space>/<path>` | `take` never guesses whose version to adopt |
| `key-identified origins cannot rotate` | rotation needs a zone-issued name |
| `<key> is the active key: run `synch key activate <new-key>` first` | retire the predecessor, not the incumbent |

## The data directory

A fresh `<data-dir>` holds `synchronicity.db` (the metadata database, device
secret included), the blob store under `store/`, `control.sock`, and
`control.token`. Two more appear with use: `rekor-pins.json`, the TUF-verified
transparency-log pin set, and `s3-uploads/`, where multipart parts are staged.

```
$ ls -a ~/.local/share/synchronicity
control.sock  control.token  store  synchronicity.db  synchronicity.db-shm  synchronicity.db-wal
```

The directory is `0700` and the socket `0600`, and every control call carries
the token, regenerated on each daemon start. **It is the owner's alone from the
moment it exists** — treat it like an SSH private key directory.

One daemon per data directory. A second `daemon run` on the same one fails at
the socket bind rather than corrupting anything.

## `synch-s3`, in one screen

An S3-compatible gateway. It is a *control client of the daemon* — it opens no
database and binds no endpoint — so `synch daemon run` must be live on the same
data directory for any `synch-s3` command to work.

```sh
synch-s3 bucket add media media                             # newest
synch-s3 bucket add nas-media nas@cluster.example.com:media  # shorthand for an origin pin
synch-s3 bucket add safe-media media --policy strict
synch-s3 key add AKIAEXAMPLE <secret>
synch-s3 serve --listen 127.0.0.1:9000
synch-s3 serve --anonymous                                   # loopback only
```

A bucket is a space plus a version policy. ETags are the selected version's
BLAKE3 root in hex, quoted. A `strict` bucket answers a divergent key with
`409 Conflict` naming the versions. `PUT` and `DELETE` publish *this node's*
view — the same thing writing or removing the file in the space directory does
— so a bucket pinned to a foreign origin accepts writes but keeps reading that
origin's versions, and the gateway warns about that shape. Multipart upload is
supported, which is what makes the gateway writable from Mountpoint for
Amazon S3.

## Where to look next

- `synch <command> --help` — every flag, with the reasoning attached.
- `synch doctor` — the state of this node, in full.
- `DESIGN.md` — the architecture; the `§` numbers in CLI help point into it.
  It ships in every release archive, next to the binaries.
- `docs/REKOR-ZONE-KEY.md` — zone-key transparency, end to end. It lives in
  the repo (github.com/AFK-surf/synchronicity), not in the archives.
