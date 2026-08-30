---
name: synch
description: >-
  Drive the `synch` CLI — a synchronicity node: initialize it, run its daemon,
  publish filesystem or API sources, retain replicas, materialize replica
  checkouts, join a control-plane-managed membership zone, delegate
  space-restricted access, read the unified tree, adopt selected content,
  build and serve Synchronicity sockets, pin, rotate keys, and recover a lost
  origin — and drive the control plane's own HTTP API with an org-scoped API
  key or a network-scoped join key, to enroll devices, manage networks and
  keys, and browse a cluster's files without a browser. Use whenever a task
  involves `synch`, `synch-s3`, a Synchronicity socket, a synchronicity
  cluster, a node's data directory, or the control-plane API.
---

# synch

`synch` is one binary that is both a node daemon and the client that talks to
it. A source publishes **its own view**, signed; trusted peers exchange those
views as metadata; what you read is the **union** of everybody's views, with
the conflicts left visible instead of resolved behind your back. Content is
fetched by a read, retained by an explicit replica or pin, or held because
this node publishes it. Merely seeing a peer's tree does not copy its bytes.

This guide assumes the cluster's membership zone is **managed by a
synchronicity control plane**: devices are enrolled on the network's page in
the web UI, and the control plane signs and serves the zone. No step here
involves editing a DNS record — where the CLI prints one, it is describing
what the control plane publishes for you. Every such step has a second way
round that needs no browser: see **The control-plane API** below.

Two rules explain most of the surface:

1. **The daemon owns the node.** `synch init` bootstraps it, `synch daemon
   start` launches it in the background and returns only when its socket is
   ready, and `synch daemon run` keeps it in the foreground for a supervisor.
   Every operational command is a gRPC call over a unix socket at
   `<data-dir>/control.sock`. With no daemon running you get, verbatim:

   ```
   synch: no daemon is running for /var/lib/synch: nothing is listening on
   /var/lib/synch/control.sock. Start one with `synch daemon start` (or keep
   `synch daemon run` in the foreground)
   ```

2. **Nobody writes anybody else's view.** A publish always says "*this* origin
   asserts this content for this path". Adopting selected peer content is an
   explicit `synch adopt path` or `synch adopt tree`, and publishes *your*
   assertion after a filesystem-source scan.

3. **Published live content is durable locally.** A node cannot publish a file
   or socket from its own source unless its CAS holds the complete object. The
   source owns a durable hold for every live root it publishes. If a read
   proves such a payload missing or corrupt, the node withdraws its false
   availability claim and automatically fetches and verifies another copy
   from an advertising peer. This repair is reactive; there is no periodic
   full-byte scrub.

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
synch init --domain cluster.acme.example.com  # the zone the network's page names
synch daemon start                      # background; returns when the socket is ready
synch source add media /srv/media       # publish a local directory
synch source scan media                 # hash it and publish a signed root
synch ls media                          # read it back
synch id                                # who this node is, and where it listens
```

`synch init --domain` prints the device key, the data directory, and the
record a zone run by hand would need:

```
device key: qmpmjtrw6w6h5ri3taracdpajdg14d5di7i1xq3ahomw485jrezo
data dir:   /var/lib/synch
domain:     cluster.acme.example.com
next:       publish this record, then `synch daemon start`:
  _synchronicity.cluster.acme.example.com. IN TXT "v=sync1 id=<name> nk=<device key> apex=<apex>"
```

The last two lines are not yours to do. Add the device on the network's page
in the control plane — a label and the device key — and the record is
signed and served in the same moment; **The control-plane API** below is the
same act as one `POST` to the network — which is the form to reach for from
this node itself, and the only one a join key can make. Until it is done,
the daemon exposes only its reduced control service and waits: the zone does
not name this key yet, so the node has no name to publish under.

`source scan` reports what it did and what it published. With no space it
scans every filesystem source:

```
scanned media: hashed 2 · unchanged 0 · deleted 0
hashed 2 · unchanged 0 · deleted 0 · ignored 0
published seq 1 root 9d3aa19d77aeb7171218857063534ab1d5ad46cf53868854bc9dc4b810aa17ae
```

You rarely need to run it by hand: `daemon run` carries a scanner and a
filesystem watcher. Run it when you want the publish *now*.

## Naming things

An **origin** is one publisher, named by the zone:
`nas@cluster.acme.example.com` — the device's label, at its network's zone.
An origin the zone does not name — a delegate is the common case — appears
as its device key, `key:qmpmjtrw…`. A **space** is a namespace in the shared
tree. A node may publish it as a source, retain it as a replica, do both, or do
neither. A filesystem source maps the namespace to a local directory; an API
source has no directory.

Almost every read takes a **reference**:

| Form | Means |
| --- | --- |
| `media` | the whole space, unified across every origin |
| `media/talks` | a directory inside it |
| `media/notes.txt` | one path — the version the policy selects |
| `nas@cluster.acme.example.com:media/notes.txt` | that origin's version, pinned |
| `key:qmpmjtrw…:media` | the same, for a key-identified origin |

An origin prefix is a shorthand for `--select origin=<origin-id>`. Commands
that accept a selection also accept `--select newest` (the default) and
`--select strict`.

## Reading

```sh
synch ls media                       # the unified tree; divergent paths marked ⑂N
synch ls media --all                 # every version of every path, with attestors
synch ls nas@cluster.acme.example.com:media
synch status media/notes.txt         # the version inspector
synch status media                   # every path in the space, versions and all
synch status                         # everything this node can see
synch cat media/notes.txt
synch cat media/talks/keynote.mp4 --range 0..1048576
synch cat media/notes.txt --select origin=nas@cluster.acme.example.com
synch cat media/notes.txt --select strict # refuse divergence, list versions
synch get media/notes.txt -o notes.txt
synch log media/notes.txt            # per-origin publish history
synch compare media --to nas@cluster.acme.example.com          # name-status diff, no bytes fetched
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
- **`origin=<id>`** — that origin's version. An `<origin>:` prefix is the same
  selection at the command line.
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
synch adopt path media/notes.txt \
  --select origin=nas@cluster.acme.example.com     # adopt one as ours
```

`adopt path` requires a filesystem source for the space. It writes the bytes
into that source and publishes your own assertion before answering, which is
what collapses the count:

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

`synch adopt path media/notes.txt --select origin=<origin-id>` on that
tombstone removes the local copy and publishes your own. Once every publisher
has, the path leaves the tree.

## Synchronicity sockets

A **socket** exposes a program at a path in this node's published tree. Its
file content is an eBPF ELF object; an incoming stream runs one invocation of
that object on the node that published it. The caller supplies bytes and a
verified peer identity, never code. This is the rule to keep in mind:

> A node executes only eBPF that is present in its own published tree.

That makes the two sides deliberately asymmetric. `synch socket ...` builds,
declares, approves and operates programs belonging to this node. `synch socket
connect ...` is only a byte pump to a socket belonging to a named origin and
needs no eBPF runtime on the caller.

### Build, publish and arm one

The normal path from C source to a runnable socket is:

```sh
synch socket build git.c -o code/git.sock       # C to eBPF; no daemon needed
synch socket declare code/git.sock              # declare the local path
synch source scan code                          # publish it as kind=Socket
synch socket arm code/git.sock                  # inspect root and declarations
synch socket arm code/git.sock --review <token> # approve exactly that inspection
synch socket ls -l                              # verify armed root and policy
```

On supported builds, `socket build` uses the compiler embedded in `synch` and
automatically supplies its matching `synch.h`; there is no libc. Use
`synch socket sdk > synch.h` to inspect that header. `--clang` instead uses
compatible `clang` and `llc` executables from `PATH` at `-O2`, and `-D
NAME[=VALUE]` supplies compile-time definitions. Windows builds need this
`--clang` route to build, but can connect normally.

The object must already be below a filesystem source registered with `synch
source add`. Declaration and arming are separate local gates:

- `synch socket declare <space>/<path>` makes the next source scan publish the
  entry as a socket. Add `--config k=v` for values read through `sy_config_get`,
  `--max-streams N` for a local concurrency ceiling, or `--note TEXT` for an
  operator note.
- The first `socket arm` runs the object's `synchronicity.init` hook and prints
  the program root, resource shape and declared effects, such as outbound TCP
  destinations or process capabilities. It does **not** approve the object. Review that
  output, then pass its opaque token to `--review`; the token binds the content
  root, current local authorization revision and exact init result.
- Approval pins the BLAKE3 content root. Replacing the object and scanning
  leaves the new root published but not runnable until it is reviewed and
  armed. In-flight invocations keep the root they started with.

`synch socket declare --auto` deliberately skips that fresh review by re-arming
on every content change. Use it only when the path has a single trusted
writer. It is unsafe for a path a read-write S3 key or adoption can write,
because either can replace bytes that this node then publishes as its own.

Serving sockets requires Linux, macOS or OpenBSD on x86-64 or arm64, where the
async-ebpf runtime is available. Connecting works on every platform supported
by `synch` because the connecting side executes nothing.

### Connect to one

Connections always require an origin-qualified reference; there is no
`newest`, `strict`, or other version-selection policy for execution:

```sh
synch socket connect nas@cluster.acme.example.com:code/git.sock
synch socket connect nas@cluster.acme.example.com:code/git.sock --meta repo=docs
synch socket connect nas@cluster.acme.example.com:code/git.sock \
  --listen 127.0.0.1:9418
synch socket connect nas@cluster.acme.example.com:code/git.sock \
  --listen 127.0.0.1:9418 --once
```

Without `--listen`, stdin goes to the stream and the reply goes to stdout.
With it, the CLI owns the TCP listener and opens one invocation per accepted
connection; ending the CLI ends the listener. `--meta k=v` is caller-chosen,
untrusted metadata the program may read. The local daemon owns the actual
Synchronicity endpoint and bridges the control-socket stream, so it must be
running on the connecting side too.

The destination resolves the path only in the named origin's trie, verifies
membership and delegation, requires the entry to be a locally declared socket,
and requires its current root to be armed. Publication alone is never execute
permission. A program's undeclared outbound connections are also denied even
after it is armed. Reading the tree needs no declaration and is not denied.

Adopting a peer's socket, materializing it in a replica checkout, or writing it
through S3 copies its bytes as an ordinary file. Socket-ness is a local
assertion created only by `synch socket declare`, and executability is a
separate local approval. If one origin publishes a socket and another
publishes a regular file with identical bytes, they are divergent versions
rather than one unanimous version.

### Operate and troubleshoot sockets

```sh
synch socket ls [<space>] -l        # declarations, current/armed roots, drift
synch socket ps [<space>/<path>]    # live invocations, ids, peers and counters
synch socket log <space>/<path>     # recent sy_log output
synch socket kill <invocation>      # end one invocation
synch socket disarm <space>/<path>  # keep publishing it; refuse new runs
synch socket undeclare <space>/<path> # next source scan publishes a file
```

The common refusals say which gate failed: `NoSuchPath` means that origin does
not publish the path, `NotASocket` that it is not a socket entry, `NotArmed`
that the current root lacks approval, `Unauthorized` that the caller is not a
member or delegate, `SpaceNotDelegated` that the socket falls outside the
caller's grant, `Busy` that its concurrency cap is full, and `ProgramInvalid`
that the object could not load or link. Repeated program faults automatically
disarm that socket; inspect `socket log` and `socket ls -l`, fix or rebuild the
object, source-scan it, and review and arm the new root.

## Membership

Membership is the zone. The control plane signs and serves one per network —
`<network>.<org>.<apex>` — and adding a device on the network's page (or over
the API; see **The control-plane API**) is the whole enrollment: a label, a
device key, and the record exists. There is nothing to publish by hand, and no
per-node configuration of anybody else's membership.

A node points at its zone once:

```sh
synch domain set cluster.acme.example.com  # takes effect at the next daemon start
synch domain set cluster.acme.example.com --delegate   # belongs to it, not named by it
synch domain ls
synch domain refresh                       # re-resolve now
synch domain clear
```

(`synch init --domain` is this same setting, made at init.) Enroll before
you serve: a zone that does not name this node's key leaves it with nothing
to publish under, so `daemon run` comes up on a reduced control socket and
waits, printing the record to publish. It re-checks until the zone answers.

`--delegate` is how a node says it belongs to that zone and expects *no*
record naming itself (§3.5). It still resolves the zone — that is how a
delegate learns its cluster's members at all — and keeps publishing under its
device key. The flag is needed because on a first start "the zone does not
name me" and "my record has not propagated yet" are the same answer, and
guessing wrong either leaves every delegate waiting for a record nobody will
publish, or lets a member silently publish under a key origin it must later
migrate away from.

A delegate that is *later* named by the zone adopts that name at the next
daemon start, migrating everything keyed by the old identity. Identity is
frozen for the life of a process, so the running daemon reports the change
(`synch doctor`, and a warning in the log) rather than switching under itself.

Membership then refreshes itself: the daemon re-resolves each domain when
its TTL runs out, and again (rate-limited) when an unknown key tries to
connect, which is what the far side of a lagging rotation looks like. **A
resolver outage fails closed** — cached bindings keep their own expiry and
the member set shrinks toward nobody.

Resolution is DNS-over-HTTPS, validated in process — the DNSSEC chain, plus
a transparency-log proof for the zone key — so the answer needs no trusted
transport and no configuration.

### Delegation

A zone member can admit one other key to a named list of spaces — no
control-plane change, nobody else's configuration touched:

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
its own side with `synch init`, then either `synch trust add <issuer-key>` — a
direct trust in the issuer alone — or, to pick up the whole cluster from DNS the
way any member does, `synch domain set <domain> --delegate`. Prefer the zone:
those bindings expire on their own TTL, so dropping a member from the zone drops
it here too.

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
deletion. Withdrawal is also how a delegate is *promoted*: a `d:` record naming
a key outranks any local `synch trust add` of it, so a node stays confined to
its grant until the issuer removes the record — trusting its key on the side
does not lift the confinement, and neither does the zone later naming it.

```
removed the delegation of 9qs54nyt…
published at seq 8 — every reachable peer within one push
```

## Materializing and keeping bytes

A node has independent **source**, **replica**, and **checkout** roles. With no
replica, peer metadata is still exchanged and foreground reads fetch on
demand, but peer content is only cache data and may be collected.

A source publishes this node's assertions:

```sh
synch source add media /srv/media    # watched filesystem publisher
synch source add uploads --api       # writes arrive through typed APIs
synch source ls [media]
synch source scan [media]            # filesystem sources only
synch source rm media                # unpublish this origin's entries
```

A filesystem source is the only role adoption can write into. An API source
has no directory or scanner; it is for APIs such as a read-write S3 bucket.
Removing a source publishes removals before deleting the role. It does not
remove a replica of the same namespace.

A replica durably acquires every visible origin's content for one space and
publishes no entries of its own:

```sh
synch replica add media                         # current roots
synch replica add archive --retention forever  # every root observed while active
synch replica add media --grace 30d --budget 8TiB
synch replica set media --checkout /srv/media-view
synch replica ls [media]
synch replica sync [media]
synch replica rm media
synch replica rm media --pin-held
```

`current` releases roots that leave the current tree after the grace period.
`forever` retains every root observed while the replica is active. A budget is
an admission ceiling: suffixes such as `GB` and `TiB` are accepted, zero admits
no non-empty object, and `--no-budget` removes the ceiling. It stops new
acquisitions and never evicts held data.
Removing a replica releases its holds; `--pin-held` converts them to explicit
operator pins first.

A replica may own one optional checkout. It materializes the unified `newest`
view only; it does not publish a local tree and does not fetch independently of
the replica. Acquisition first establishes the durable hold, then checkout
reconciliation writes content already held. Moving or disabling a checkout
leaves its existing files in place:

```sh
synch replica add media --checkout /srv/media-view
synch replica set media --checkout /srv/new-view
synch replica set media --no-checkout
```

Adoption writes selected content into a filesystem source. One path publishes
before the command answers. Tree adoption is additive by default, never
removes files, and is published by the next source scan; `--replace` permits
replacement of differing files.

```sh
synch adopt path media/notes.txt --select origin=nas@cluster.acme.example.com
synch adopt tree media                              # newest
synch adopt tree media/talks --select strict
synch adopt tree media --select origin=nas@cluster.acme.example.com
synch adopt tree media --dry-run
synch adopt tree media --replace
synch source scan media
```

A node in key-loss recovery refuses adoption because it cannot safely publish
the result. Run `synch recover` first.

Durable source and replica holds are repair intent. If a local read or cloud
backend response proves a held payload missing or invalid, the node withdraws
the false complete claim, queues a repair, fetches and verifies the object from
an advertising peer, and restores the hold. Cache-only content is not healed.

A **pin** keeps content regardless of retention. It names an object root, or a
path — in which case the reading policy supplies the root. Pinning content this
node has never read fetches it first.

```sh
synch pin add media/talks/keynote.mp4
synch pin add media/notes.txt --select origin=nas@cluster.acme.example.com
synch pin add 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
synch pin ls
synch pin rm media/talks/keynote.mp4     # or use the hex root
```

`pin ls` names the root, the size, and the path that currently selects it —
`(no current entry names it)` once nothing does. `pin rm <path>` resolves the
path *now*, so after a tombstone the path no longer names anything and you must
remove the pin by its root.

## Operating

```sh
synch daemon run                # owns the node: control socket + every standing loop
synch daemon start              # launch it in the background; wait for the socket
synch daemon status             # one screen
synch daemon stop               # ask it to shut down (Ctrl-C does the same)
synch peer ls                   # live peers, addresses, last exchange, lag
synch peer sync                 # one metadata exchange with every dialable peer, now
synch doctor                    # the full examination
synch repair rebuild-views      # rebuild derived views from the authoritative trie
```

`daemon start` runs the same daemon in the background, appends its stdout and
stderr to `<data-dir>/daemon.log`, and exits once the control socket accepts a
connection. Use `daemon run` when a service manager should own the foreground
process. `daemon run` prints where it is and what socket it bound, then keeps the
anti-entropy scheduler, source scanners and watchers, publisher, replica and
checkout reconciliation, DNS refresh, maintenance/GC and the control-plane
tunnel running:

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

`peer sync` names each peer and what the exchange moved, including the ones it
could not reach:

```
key:9qs54nyt… (fbadbd0811)  unreachable: endpoint: No addressing information available
key:qmpmjtrw… (72dab4c494)  accepted 1 head(s) · completed 1 origin trie(s) · pushed 0
```

### Key rotation

Every step is explicit — a node never polls its own domain and never switches
signing keys on its own. The DNS half of every step is the control plane's:
it happens on the device's page, and the zone is republished in the same
moment.

```sh
synch key rotate                 # generate K_new
# add the new key on the device's page — the window opens:
# K_new active, K_old retiring, both published
synch key activate <K_new>       # re-sign the head, serve on both keys
# retire K_old on the same page — the window closes
synch key retire <K_old>         # drop that endpoint, delete the secret
synch key ls
```

What `key rotate` prints is the record a zone run by hand would need; here
the `nk=` value is the whole payload, and the device's page takes it — as does
`POST …/devices/<dev>/keys`, with `POST …/keys/<old>/retire` for the last step
(**The control-plane API**).

`synch key ls` answers the question the middle step turns on — *have my peers
picked up the new record yet?* It asks every reachable trusted peer which of
our keys it holds bound, and names the peers it could not reach rather than
counting their silence either way:

```
qmpmjtrw… active   bound by 0 of 0 reachable peer(s)
    zqgii4msp… unreachable: read: connection lost
  no peer could be reached; the tallies above count nobody
```

Rotation needs a zone-issued name — the one every enrolled node has. A
key-identified origin, which is what a delegate the zone never named is,
refuses outright: its device key is its identity and cannot rotate.

`key retire` refuses the active key and tells you to activate the successor
first. `--bind HOST:PORT` on `key activate` names the new endpoint's address;
without it the new key takes an ephemeral port.

### Recovery

For an origin whose device key and database are gone. The name survives
because the zone holds it, not the key: enroll the fresh key on the device's
page, exactly as in a rotation, and retire the lost one. The node comes up on
that key, finds peers holding history it does not, and refuses to publish
until an operator says how far to skip ahead.

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
synch control-plane status  # per domain: record found, attached, last error
synch control-plane disable # the only local act: opt out
synch control-plane enable  # undo it
```

With no domain configured it says so rather than pretending:

```
control-plane tunnel enabled: serving requests for (no local sources or replicas)
note: no membership domains are configured, so there is no zone to discover a
control plane from; `synch domain set <domain>` first (add `--delegate` if this
node is not meant to be named by that zone)
```

## The control-plane API

The node whose `/SKILL.md` you are reading also serves an HTTP API at the same
base URL. **Every act this guide has so far handed to a person, a program can
take** — enrolling a device, assigning it to a network, opening and closing a
rotation window, revoking a key. What it cannot take is the handful that would
let it widen its own reach — **What a key can never reach**, below, is the
whole list.

### Getting a token

An org owner or admin mints one under **Settings → API keys**. Both kinds look
identical on the wire — `synch_` followed by 43 random characters, shown once,
because the control plane keeps only its SHA-256 — and differ in what they can
reach:

* An **org key** belongs to the org, not to whoever minted it. It names one
  org and carries its own role (`admin` or `member`, never `owner`), so it
  reaches no other org and no change to anybody's membership widens it.
* A **join key** names one *network* and can do exactly one thing: add a
  device to it. It cannot read the network, list its devices, or see anything
  else in the org — every other route answers `403 join_key_forbidden`. That
  is what makes it the credential to put somewhere a person cannot guard: a
  provisioning image, a cloud-init file, a kickstart template.

Everything below is the org key's surface unless it says otherwise; the join
key's is one route, and it has its own section.

```sh
cp=https://cp.acme.example.com
token=synch_...

curl -sS -H "Authorization: Bearer $token" "$cp/api/orgs/acme"
```

That header is the whole of it. There is no CSRF token to echo — that defends a
*cookie*, which the browser attaches to cross-site requests on its own, and
nothing attaches an `Authorization` header for you.

### Enrolling this node from this node

The one flow worth spelling out, because it is what turns a waiting
`daemon run` into a serving one. The key to hand over is the z-base-32 string
`synch init --domain` labels `device key:`; `synch id` prints the same value
indented under `origin:`, with its state in parentheses:

```sh
nk=qmpmjtrw6w6h5ri3taracdpajdg14d5di7i1xq3ahomw485jrezo   # from init, or id

curl -sS -X POST "$cp/api/orgs/acme/networks/prod/devices" \
  -H "Authorization: Bearer $token" -H 'content-type: application/json' \
  -d "{\"label\": \"nas\", \"nk\": \"$nk\"}"
# -> {"ok":true,"soa_serial":42,
#     "result":{"device_id":"0068a4c1f2…","label":"nas","network":"prod"}}
```

One call, and it has to be: a device that exists in the org but sits in no
network appears in no zone, so a caller that created one and stopped has
enrolled nothing and its daemon is still waiting. The answer carries
`soa_serial` because **the commit is the publication** — the zone is rebuilt
and re-signed inside the same transaction, so there is no cache to wait for
and no second call to make.

**This is the route a join key exists for**, and the only one it can take. A
node being provisioned needs no more reach than this, so give it no more:

```sh
# baked into the image, or handed over at first boot
token=synch_...            # a join key for acme/prod
curl -sS -X POST "$cp/api/orgs/acme/networks/prod/devices" \
  -H "Authorization: Bearer $token" -H 'content-type: application/json' \
  -d "{\"label\": \"$(hostname)\", \"nk\": \"$nk\"}"
```

Aimed at any other network — a sibling in the same org, or the same name in
another org — a join key gets `404`, the same answer a stranger gets, so a
leaked one cannot be used to find out what else the org runs. Everything else
it might try is refused, including reading the very network it may add to:
`403 join_key_forbidden` from the JSON API, and a plain-text `404` from
`…/browse/file`, which lives below that layer and collapses every reason it
will not serve you into one answer.

An org key or a person reaches the same route at the `member` floor, since it
is the same act.

### What a key can reach

`<org>` is the org slug, `<net>` a network name, `<dev>` and `<key>` the ids the
listings return.

| Method | Path | Role | What |
| --- | --- | --- | --- |
| `GET` | `/api/orgs/<org>` | member | the org: its networks, its device count, your role |
| `GET` | `/api/orgs/<org>/networks` | member | each network and how many devices it holds |
| `POST` | `/api/orgs/<org>/networks` | admin | `{"name": "prod"}` — a DNS label |
| `GET` | `/api/orgs/<org>/networks/<net>` | member | every device, its live keys, the zone's signature health |
| `DELETE` | `/api/orgs/<org>/networks/<net>` | admin | `{"confirm": "<net>"}` — typed back, as the UI asks |
| `GET` | `/api/orgs/<org>/devices` | member | every device, with its keys and its networks |
| `POST` | `/api/orgs/<org>/devices` | member | `{"label", "nk", "relay"?, "addr"?}` — org only; in no network, so in no zone |
| `PATCH` | `/api/orgs/<org>/devices/<dev>` | member | `{"relay", "addr"}` — **both**, always: an omitted one is cleared |
| `DELETE` | `/api/orgs/<org>/devices/<dev>` | admin | the device and its keys leave the zone |
| `POST` | `/api/orgs/<org>/networks/<net>/devices` | member | `{"label", "nk", "relay"?, "addr"?}` — create **and** assign, one transaction |
| `PUT` | `/api/orgs/<org>/networks/<net>/devices/<dev>` | member | assign a device that already exists; no body |
| `DELETE` | `/api/orgs/<org>/networks/<net>/devices/<dev>` | member | unassign |
| `POST` | `/api/orgs/<org>/devices/<dev>/keys` | member | `{"nk": "<key>"}` — opens the rotation window |
| `POST` | `/api/orgs/<org>/devices/<dev>/keys/<key>/retire` | member | closes it; no body |
| `POST` | `/api/orgs/<org>/devices/<dev>/keys/<key>/revoke` | admin | out of the zone, and out of every open tunnel |

The rotation of **Key rotation** above, in three calls: `POST …/keys` with the
new key (both publish, the old one `retiring`), `synch key activate` on the
device, then `POST …/<old>/retire`. A second `POST …/keys` while a window is
open is refused with `rotation_open` rather than opening a second one.

The browse surface is the same read-only tunnel `synch control-plane status`
reports from the node's side, and it stays gated on the org's per-network
switch:

| Method | Path | Role | What |
| --- | --- | --- | --- |
| `GET` | `…/networks/<net>/browse` | member | is browsing on, and which daemons are attached |
| `PUT` | `…/networks/<net>/browse/enabled` | admin | `{"enabled": true}` |
| `GET` | `…/browse/ls?space=&path=&origin=&cursor=&all=1` | member | one directory of the unified tree |
| `GET` | `…/browse/stat?space=&path=&origin=` | member | every version of one path, with attestors |
| `GET` | `…/browse/file?space=&path=&from=&origin=` | member | the bytes, streamed; `Range` honoured, plain-text refusals |
| `GET` | `…/networks/<net>/delegations` | member | the delegated keys an attached daemon reports |

Space and path are query parameters and never path segments — a file path may
contain anything, separators included.

Downloads are capped at four open at once **per credential**: a key gets its
own budget rather than spending the budget of whoever minted it, and the
fifth concurrent stream is a `429` naming the limit.

### The join key's surface

One row, and that is the point:

| Method | Path | What |
| --- | --- | --- |
| `POST` | `/api/orgs/<org>/networks/<net>/devices` | the network it was minted for, and no other |

Every other route that reads a credential — including `GET` on that same
network — refuses it: `403 join_key_forbidden` from the JSON API, and a
plain-text `404` from the streaming `…/browse/file`, which sits below that
layer. (`POST /api/logout` is the exception that proves it: it reads only the
session cookie, so a bearer-only request is a no-op `200`.) That is not a
list somebody maintains: every org-scoped route resolves its caller through
one function, and that function refuses the whole family before it reads a
rank. A join key has no rank to read.

Minting one is the ordinary create with `role: "join"` and the network named:

```json
POST /api/orgs/acme/api-keys
{"name": "rack 3 provisioning", "role": "join",
 "network": "prod", "expires_in": 2592000}
```

`expires_in` is **required** here, where it is optional on an org key. An org
key lives in a secret store somebody guards, so a permanent one is a choice; a
join key lives where nobody is guarding, and nothing bounds how many devices
one enrols — so its lifetime is the only bound it has, and leaving the field
out would have handed out a permanent credential by default. Omitting it is a
`400 bad_expiry` that says so.

Shown without a `curl` because **no key can mint a key**, this one included:
that route is a signed-in person's, so it is the dashboard's Settings → API
keys, or a session cookie and its `x-csrf` header. A key that could mint keys
could mint one that never expires.

`network` and `role: "join"` imply each other: neither is accepted without the
other, and the schema says the same thing, so a row that is one without the
other cannot exist. A key's *kind* is settled at minting — `PATCH` will move
its name and its expiry but not what it is, because a join key promoted to
admin is not an edit, it is a different credential with a secret that is
already deployed.

**What a join key does not bound is how many.** Anyone holding it can enrol
devices until it expires or is revoked — which is why the expiry is required
rather than offered, and why the audit trail records every `network.join`
under `key:<id>`, with the key's name and its minter's address on the same
row. Revoking is the same one call as any other key.

### What a key can never reach

Four families, and each is a way a scoped credential could reach past its
scope. The first three answer `403 api_key_forbidden`:

- **accounts** — creating an org, accepting an invitation, `/api/me`. These are
  about a person, and a key is not one.
- **membership** — invitations, role changes, removals, the roster read at
  `GET /api/orgs/<org>/members`, and the audit trail at
  `GET /api/orgs/<org>/audit`. An admin key that could invite an admin would be
  handing out standing human access that outlives the key; a leaked one should
  not carry the address book; and the trail carries the address book *and* an
  inventory of the org's other keys, so closing the roster while leaving it
  open would have closed nothing.
- **API keys themselves**, the listing included. A key that could mint keys
  could mint one that never expires, and revoking the one you knew about would
  not have ended the access.

**Owner-gated routes** — ownership transfer, org deletion, the SSO
configuration — refuse every key too, because no key is ever an owner. Which
code you get depends on which check runs first, so do not branch on it:
ownership transfer and org deletion name keys (`api_key_forbidden` /
`join_key_forbidden`), while the SSO configuration is refused by the ordinary
role floor and answers `forbidden`, *"requires owner role"*. **Match on the
403, not on the code.**

### Answers, and what the refusals mean

A JSON error is `{"error": {"code": "...", "message": "..."}}`, and every
zone-shaping mutation answers `{"ok": true, "soa_serial": N, "result": {...}}`.

**Two answers are not JSON**, so parse defensively: `…/browse/file` refuses in
plain text at every status (its success is a byte stream, and its failures are
not dressed as this API's), and a path *or method* no route matches is wisp's
own plain-text `404 Not found`. There is no `405` under `/api` — a wrong
method is a route that does not exist, so it is a 404 like any other.

| Status | `code` | Means |
| --- | --- | --- |
| `400` | `bad_request` (a malformed body, or a missing `space=`), `bad_name`, `bad_role`, `bad_scope`, `bad_expiry`, `confirm`, `invalid_nk`, … | the request itself; the message names the field and why |
| `401` | `unauthenticated` | no credential, one that is unknown, expired or revoked, or an unreadable `Authorization` header |
| `403` | `forbidden` | your role is under the route's floor; the message names it |
| `403` | `api_key_forbidden` | a person's endpoint, reached with a key |
| `403` | `join_key_forbidden` | anything but the one route a join key may take |
| `404` | `not_found` | it does not exist, or it is not in your org — one answer for both, on purpose |
| `409` | `conflict` | the change collides with a record that exists; the message names the invariant |
| `409` | `rotation_open` / `not_retiring` | a second rotation window while one is open; retiring a key that is not the retiring one |
| `409` | `browse-disabled` | the org has not turned browsing on for this network |
| `409` | `duplicate_label`, `ambiguous_nk`, `bad_glue`, … | the zone the change would produce is refused — the 400 vocabulary, caught later |
| `409` | `read-only-replica` | this node holds a read-only copy; the `primary` field names where writes go |
| `409` | `no_rekor_record` | the transparency gate is holding the zone key back — an operator ceremony, not your request |
| `416` | — | plain text from `…/browse/file`: a `Range` this route will not serve (multi-range, or past the end); the `Content-Range` header names the size |
| `500` | `internal` | this service's fault, not the request's — a storage failure, or a publish that could not complete. The detail is in its log, never in the body |
| `502` | `internal`, or a code relayed verbatim | the attached daemon answered wrongly, or with something this build does not know |
| `503` | `no-device-attached`, `unavailable` | no daemon is attached to answer this browse call, or the one that is went away |

**Codes come in both shapes, and the shape means nothing.** Most are
`snake_case`, but `browse-disabled`, `no-device-attached` and
`read-only-replica` are this service's own, and `not-found`, `invalid`,
`divergent` and `unavailable` are relayed from a daemon — all `kebab-case`. A
client that matches `not_found` will miss a browse 404, and one that infers
"kebab means it came from a daemon" will be wrong three times. Match the exact
strings in this table.

A `not_found` for an org you believe you can reach is worth reading twice: an
org is not enumerable by whoever cannot see it, so a key pointed at somebody
else's org gets exactly what a stranger gets.

`read-only-replica` is the one worth handling rather than retrying: a
deployment's apex names every node, and reads are answered by all of them while
writes go to one. Follow the `primary` field.

Every *change* a key makes lands in the org's audit trail as `key:<id>` — the
credential, not whoever minted it, so it stays true after that person's role
has changed or they have left. The row's `detail` also carries `key_name` and
`key_minted_by`, so it says which key and whose without a second lookup, and
still says it after the key has been revoked.

Reads are not recorded, browse reads included: they are an org reading its own
files through a tunnel its own daemon opened, and a row per download would be
a log of ordinary use.

## Global flags

These apply to every subcommand and may appear before or after it. Each has an
environment variable.

| Flag | Env | What |
| --- | --- | --- |
| `--data-dir <DIR>` | `SYNCH_DATA_DIR` | the data directory; defaults to the platform data directory |
| `--bind <HOST:PORT>` | — | bind the endpoint here instead of an ephemeral port |
| `--offline` | — | no relays, no address discovery; direct addresses only |
| `--doh <URL>` | `SYNCH_DOH` | DoH endpoint for membership records |
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
  `synch daemon run` (directly or through `daemon start`). Passing them to a
  client command changes nothing.
- `cat`, `get`, `adopt`, and path-based pins use one `--select` grammar:
  `newest`, `strict`, or `origin=<origin-id>`. An origin-qualified reference
  supplies the same origin selection and must not conflict with `--select`.

## Exit codes and error shapes

`0` success · `1` the command failed (the message is on stderr, prefixed
`synch:`) · `2` the arguments were wrong (clap usage error).

Failures worth recognizing:

| Message | Means |
| --- | --- |
| `no daemon is running for <dir>: nothing is listening on <sock>` | start `synch daemon start`, or use `synch daemon run` under a supervisor |
| `no space <id>: not a local source, and no origin publishes one` | the space id is wrong, or nothing has published it yet |
| `not found: <space>/<path>` | no version of that path in the unified tree |
| `<path> has N versions and the policy is strict` | divergence under `--select strict`; the versions follow |
| `no filesystem source <id>` | adoption needs a local directory to write |
| `key-identified origins cannot rotate` | rotation needs a zone-issued name |
| `<key> is the active key: run `synch key activate <new-key>` first` | retire the predecessor, not the incumbent |

## The data directory

A fresh `<data-dir>` holds `synchronicity.db` (the metadata database, device
secret included), the blob store under `store/`, `control.sock`, and
`control.token`. More appear with use: `daemon.log` when `daemon start` is
used, `rekor-pins.json`, the TUF-verified transparency-log pin set, and
`s3-uploads/`, where multipart parts are staged.

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
synch-s3 bucket add media media --read-only                 # newest
synch-s3 bucket add nas-media media --read-only \
  --select origin=nas@cluster.acme.example.com
synch-s3 bucket add safe-media media --read-only --select strict
synch-s3 bucket add uploads uploads --read-write            # needs a local source
synch-s3 access-key add AKIAEXAMPLE                         # prompts for the secret
synch-s3 access-key add ROBOT --secret-file /run/secrets/synch-s3
printf '%s' "$S3_SECRET" | synch-s3 access-key add CI --secret-stdin
synch-s3 serve --listen 127.0.0.1:9000
synch-s3 serve --anonymous                                   # loopback only
```

A bucket is explicitly read-only or read-write. A read-only bucket may select
`newest`, `strict`, or one origin; a read-write bucket follows this node's own
current origin across identity adoption and requires a local source for its
space. It rejects mutations early if that role is absent. ETags are the
selected version's BLAKE3 root in hex, quoted. A strict bucket answers a
divergent key with `409 Conflict` naming the versions. `PUT` and `DELETE`
through a read-write bucket publish this node's
view. Multipart upload is supported, which is what makes the gateway writable
from Mountpoint for Amazon S3. Secrets are never positional: read one from the
terminal prompt, a file, or standard input.

## Where to look next

- `synch <command> --help` — every flag, with the reasoning attached.
- `synch doctor` — the state of this node, in full.
- the control plane's own dashboard, at the host that served this document —
  the same acts as **The control-plane API**, with a person driving.
- `DESIGN.md` — the architecture; the `§` numbers in CLI help point into it.
  It ships in every release archive, next to the binaries.
- `docs/REKOR-ZONE-KEY.md` — zone-key transparency, end to end. It lives in
  the repo (github.com/AFK-surf/synchronicity), not in the archives.
