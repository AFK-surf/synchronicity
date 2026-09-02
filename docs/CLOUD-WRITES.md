# Cloud writes — write support on the control-plane file API

Status: **proposal** · 2026-09-02

This document designs **write support for the control plane's file API**: a
`PUT` and a `DELETE` beside the `GET` that `…/browse/file` already answers, so
that a dashboard user, an org key or a script can put a file into a network
and take one out of it through the same service that lets them browse it.

Two constraints are given, and the whole design is what follows from taking
them literally rather than approximately:

1. **Only for networks whose cloud hosting is enabled, and always for
   those.** There is no second switch: hosting on is writes on. Not merely
   gated on the hosting switch — *impossible without it*, because the write
   has to be *somebody's* assertion and the hosted replica is the only member
   of a customer's network that this service operates (§3).
2. **The write goes only to the cloud `synch-dp`.** The customer's own daemons
   receive nothing. The browse tunnel they open stays read-only *by wire
   construction* — no write frame is added to it, and the daemon binary gains
   no code path that could decode one (§5.1). Writes travel a second tunnel
   that only the data plane opens.

Section references (§) are to this document unless prefixed. `CLOUD-DATAPLANE
§` is docs/CLOUD-DATAPLANE.md, `TREE-WRITES §` is docs/TREE-WRITES.md,
`SERVERLESS §` is docs/SERVERLESS.md, `DESIGN §` is DESIGN.md, `CP README` is
control-plane/README.md.

---

## 1. Goals and non-goals

### Goals

- **One more verb on the file API.** `PUT …/browse/file` publishes a file;
  `DELETE …/browse/file` withdraws one. Same route, same query parameters, same
  credentials, same RBAC resolution, same streaming layer below wisp that the
  download already lives at.
- **An ordinary publish.** A write enters the cluster through the engine's
  existing tree-write seam (TREE-WRITES §6) as the hosted node's own new
  version of a path: content root, size, host-stamped `mtime_ns`, `prev`. Every
  existing guarantee — single-writer tries, the version model, divergence as
  data, adoption — applies unchanged.
- **One gate, the one that already exists.** Writes are a property of a
  hosted network: on while `cloud_hosted = 1`, off the instant it is not, with
  no switch of their own to be left on, forgotten, or misread. §4.1 says why
  a separate switch was considered and not taken.
- **Nothing stored here.** Bytes pass through the control plane's memory in
  bounded chunks and land in the tenant's object-store prefix, exactly as
  downloads pass through the other way (CP README, *Cloud browse*).
- **Nothing written here either.** A file write is a data-plane operation
  end to end: the control plane relays it and records nothing — no audit
  row, no status row, no database write of any kind (§4.4). What that buys
  is that any control-plane node takes a write, replicas included (§4.6).

### Non-goals

- **Not multipart.** One request, one object, `Content-Length` required. The
  engine's multipart machinery (SERVERLESS §9) can ride the same seam later;
  v1 bounds an upload by size instead (§11).
- **Not a way to write to a customer's device.** No frame in the browse
  tunnel writes, and none is added. A control plane that could push bytes at
  an operator's NAS is the trust widening the read design refused, and this
  design refuses it again.
- **Not a way to delete a customer's file.** A `DELETE` publishes the hosted
  node's *own* tombstone. Where a customer origin still asserts the path, the
  path stays — visible, marked, theirs. §6.6 says why this is the property and
  not the limitation.
- **Not a new source of truth.** The zone is still the only membership
  authority; the version model is still the only file-conflict model. This
  adds a writer, not a rule.

---

## 2. What the customer sees

1. An org admin turns hosting on for a network (CLOUD-DATAPLANE §2). The
   dashboard's hosting control says, in the same sentence, that a hosted
   network can be written to from here; there is nothing further to enable.
2. Once the tenant is running and `cloud-1` is in the zone, the data plane
   opens a **write tunnel** for that tenant to every node of the control
   plane (§5), beside the browse tunnels it already opens. The network's
   browse status reports it attached.
3. A member uploads a file from the file browser, or runs

   ```sh
   curl -sS -X PUT -H "Authorization: Bearer $SYNCH_TOKEN" \
     -H "Content-Length: $(stat -c %s report.pdf)" --data-binary @report.pdf \
     "https://cp.example.com/api/orgs/acme/networks/prod/browse/file?space=docs&path=q3/report.pdf"
   ```

   The answer names the version that now exists:

   ```json
   { "device": "cloud-1", "origin": "cloud-1@prod.acme.synchronicity.example",
     "space": "docs", "path": "q3/report.pdf",
     "root": "3e0c…b551", "size": 481036, "seq": 4182, "mtime_ns": 1756800000000000000 }
   ```

4. Every node in the network sees the path at its next anti-entropy round —
   the hosted node pushes the head at commit, the same as an S3 `PUT` does —
   selected by `newest` because it carries the present instant. Where a
   customer node published a different version, both are visible: the file
   browser's version drawer shows `nas` and `cloud-1` side by side, and the
   customer resolves it as they resolve any divergence (`synch adopt path`,
   or by writing again). Nothing of theirs was overwritten.
5. `DELETE` withdraws the cloud's version. If `nas` still publishes the path,
   the answer says `"still_published": true` and the file browser says so in
   words: *the cloud's copy is withdrawn; nas still publishes this file.*
6. Turning hosting off drops the write tunnel in the same request, and
   `cloud-1` leaves the zone at the same commit; its assertions cease to be
   part of the trusted view when its binding expires, as any removed member's
   do. That is the whole of turning writes off.

**Why this adds no new trust.** The control plane already signs the membership
zone and can already put any device key into any network it serves — which is
to say it could already, today, publish anything into any network under a key
of its own choosing. Hosting narrowed that latent authority to one explicit,
audited, org-controlled member, `cloud-1` (CLOUD-DATAPLANE §2). The write
surface is that member doing the one further thing a member does: publishing
its own view — in networks whose admin said yes to hosting, attributed to a
named origin, signed under a key the zone names, recorded where every
publish is recorded, in the origin's own signed history. It widens nothing
the deployment did not already hold.

---

## 3. The one decision everything follows from

**A write through the control plane is `cloud-1`'s assertion.** It lands as an
`f:<space>/<path>` entry in the hosted node's own origin trie, signed by the
hosted node's own device key, and reaches the cluster as one more head that
every member already knows how to fetch, verify and display.

Three other shapes were considered and are rejected, each for one reason.

- **Write through the browse tunnel to a customer daemon.** The tunnel's
  read-only property is a fact about `crates/synch-engine/src/cloud/frame.rs`
  — no write opcode decodes — and a test pins it (`no_frame_encodes_a_write`).
  A `put` frame gated by a daemon-side setting would turn "the control plane
  cannot write to your node" from a wire fact into a configuration check, and
  it would make the *customer's* daemon the writer of a version *the control
  plane* chose — an attribution nobody asked for. Rejected outright.
- **Write to the tenant's bucket directly from the control plane.** The
  control plane holds no bucket credentials, on purpose (CLOUD-DATAPLANE §6:
  the service holding the credentials must not hold the opinion about when
  bytes may go). And a bucket object is not a published file: the `f:` entry,
  the `b:` ad, the outboard, the blob row and the signed head are all the
  engine's work. Rejected.
- **A write queue the data plane polls.** Bytes would have to be *stored* on
  the control plane between the request and the poll, which is the one thing
  the browse design promises never happens; and a `PUT` needs an answer that
  means what an S3 `PutObject` answer means — published, durable, readable
  back — which a queue cannot give inside one request. Rejected.

What the chosen shape settles, before any route is designed:

- **The gate is structural.** With hosting off there is no `cloud-1`, so
  there is no origin of this service's in the network and nothing to write
  *as*. The gate is `cloud_hosted`, read where every other consequence of
  hosting is read (§4.1), and there is no second flag for a handler to
  forget.
- **The destination is structural.** The hosted node is the only end of the
  write tunnel (§5) and the only origin that signs the head. The customer's
  daemons learn of the write the way they learn of any peer's publish.
- **The blast radius is the version model's.** A write is one origin's new
  assertion. It cannot alter another origin's entry, cannot delete another
  origin's version, and shows up as divergence wherever it disagrees
  (DESIGN §8). The worst write is "`cloud-1` published something ugly that
  wins `newest`", which the cluster already knows how to display, adopt over
  and outrank — TREE-WRITES §1 makes exactly this argument for socket writes,
  and it holds here word for word.
- **The org holds the kill switch.** Hosting off drops the write tunnel in
  the same request and removes `cloud-1` from the zone in the same commit,
  after which its origin is no longer a trusted publisher on any member.

---

## 4. Control-plane additions

### 4.1 The gate is the hosting switch

No new column, no new route, no new audit event. A network takes writes
exactly while `networks.cloud_hosted = 1`, and every check this design
makes reads that column where hosting's other consequences already read it:
the write tunnel's attach lookup (§5.2) and the route's own resolution
(§4.2). Turning hosting off already does everything turning writes off would
need to do — it deletes the `cloud-*` devices in the same commit — and it
gains one more consequence after that commit: the network's write sessions
are dropped (`agent.drop_network` on the write registry, §4.5), for the
reason the browse switch gives when *it* drops sessions: a session that
outlived the switch would keep taking writes for a network the org has just
withdrawn from hosting.

**Why not a third switch.** An earlier draft of this document had one —
`cloud_writes`, admin-gated, off by default, with a schema `CHECK` that it
could not be on without `cloud_hosted` — on the argument that every
capability this service exercises over an org's cluster is an explicit
grant and a write is a larger act than a replica. The argument is right
about the act and wrong about the grant. What hosting grants is *a member*:
`cloud-1` is in the zone under the org's signature, admitted by every
customer node as a peer that fetches, serves and publishes, and nothing in
the protocol distinguishes a member that may publish from one that may not
— a member publishes, that is what the word means. A switch that said
"hosted but not writable" would describe a member the cluster cannot
represent, enforced only on this side of the tunnel, and would be the one
flag in the schema whose off state changed nothing a peer could observe.
Hosting on is the grant; the dashboard's hosting control says what it
grants, in words, at the moment it is asked for.

What the earlier draft was defending — an org that wants a replica and
does not want this service publishing — is met by the version model rather
than by a flag: a control-plane write is one origin's assertion, visible as
such, adoptable over, and gone with the member when hosting goes (§3).

Browse and writes stay independent, as browse and hosting are. Writes
without browse is a blind drop-box — an org key uploading CI artifacts into
a network nobody browses from here — and it is a legitimate shape; the
route needs the write tunnel, not the browse one. The dashboard's file page
lives under browse, so in practice a person uploading has browse on too,
but nothing in the API requires it.

### 4.2 The routes

| Method   | Path                                             | Role   | What |
| -------- | ------------------------------------------------ | ------ | ---- |
| `PUT`    | `…/networks/:net/browse/file?space=&path=`       | member | publish the body as `cloud-1`'s version of the path |
| `DELETE` | `…/networks/:net/browse/file?space=&path=`       | member | publish `cloud-1`'s tombstone for the path |

`GET …/networks/:net/browse` (status) gains

```json
"writes": { "enabled": true, "attached": true, "device": "cloud-1" }
```

so the file browser can show an upload control that will work, and a script
can tell "writes are off" from "writes are on and the tenant is mid-restart".

Both writes live **below wisp**, in `api/browse_file.gleam` beside the
download, because the request body streams: wisp reads a body whole and into
memory, and an upload's whole point is that it must not be. The handler reads
the body through mist's incremental request-body reader (`mist.stream`, the
`Chunk`/`Done` reader it exposes for exactly this) in `MAX_CHUNK`-sized
pieces (64 KiB, the tunnel's content-frame ceiling) and relays each piece
onto the write tunnel under credit (§5.4), so the control plane never holds
more than the credit window of any upload. The three refusal shapes are the
download's: plain text, `nosniff`, a status a client can branch on.

**Member, not admin.** A member can already enroll a device into the network
(`POST …/networks/:net/devices`, member floor), and a device publishes
whatever its operator likes; a member therefore already holds publish rights
in every network they can see. Gating the write at admin would protect nothing
and would make a CI key that uploads artifacts an admin key, which is the
wrong direction for a credential that gets baked into a pipeline. A join key
is refused as it is everywhere (`403 join_key_forbidden`).

`origin=` on a write is `400 invalid`: there is one writer. `from=` is
accepted on both verbs, and it means what it means on a read — which version
a condition is evaluated against (§4.3).

### 4.3 Request and response semantics

**`PUT`.** The body is the object. `Content-Length` is required (`411
length-required`): the size travels in the tunnel's `put` frame before any
byte does, so the data plane can refuse an upload it has no room for before
staging a byte of it, and can verify at commit that the body was whole — a
short body is an abort, never a truncated file published as complete. Bodies
above the deployment's cap answer `413 too-large` before the tunnel is
touched (§11). Chunked transfer encoding without a length is refused for the
same reason.

`mtime_ns` is stamped **by the hosted node at commit**. Never
client-supplied: it is the one field that games `newest` selection
(TREE-WRITES §10), and a service that let a caller choose it would let a
caller choose which version every reader in the cluster sees. `prev` is set
to `cloud-1`'s own previous root for the path, one-step lineage as DESIGN §8
specifies.

Success is `200` with the JSON in §2, an `ETag` of `"<root>"` and
`x-synch-root`, and it means what an S3 `PutObject` success means on a
cloud-backend node, and a little more: the bytes are durable in the tenant's
prefix, the `f:`/`b:` records are in a signed head, the head is flushed and
pushed, and the version is readable back through the same `GET` (§6.3).

**Conditions.** Two, taken from HTTP:

- `If-Match: "<root>"` — commit only if the version this API would *select*
  for the path right now has that root. "Select" is the same rule the `GET`
  uses: `newest`, or the origin `from=` names. So the precondition a caller
  can establish is the one they read a moment ago through the same query
  string, which is the only kind of precondition worth offering.
- `If-None-Match: *` — commit only if the path has no live version in the
  unified tree at all: create, not replace.

A failed condition is `412 precondition`, nothing published, and the reply
carries the version that was found (`root`, `origin`) so the caller can
decide again. The condition is evaluated on the hosted node **under its
tree-write lock** (TREE-WRITES §5.3), immediately before the staging lands,
so two control-plane writers of one path cannot interleave the check and the
write — every control-plane write passes through the one hosted node, which
is what makes that lock meaningful here. Against the rest of the cluster it is
best-effort in the way DESIGN §8 already states: the hosted node's view lags
anti-entropy, so a version published elsewhere seconds ago may not yet be in
it. The honest statement is the narrow one: the window that is closed is
against *other control-plane writers*, and nothing is lost in the other case
— the version model keeps both.

`If-Match` is deliberately not TREE-WRITES's `commit_if`, which compares
against *this node's own* live entry. That is the right primitive for a
socket program doing read-modify-write on its own lineage; it is the wrong
one for a caller who has never seen `cloud-1`'s entry and may not know one
exists. §7 adds the second condition kind rather than changing the first.

**`DELETE`.** Publishes `cloud-1`'s tombstone **where `cloud-1` has a live
version to retire**, and publishes nothing otherwise. Idempotent: a path
`cloud-1` does not currently assert answers `200` with `"withdrawn": false`
— the assertion being made is "the cloud has no version here", and it
already holds, so no record is written to say so (§6.6 says why not).
`If-Match` applies as above. The answer carries `still_published`, straight
from the engine's `Deleted`, and the dashboard reads it aloud.

**Errors**, in the vocabulary the browse routes already use, plus the ones a
write needs:

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid` | `space=`/`path=` missing, `origin=` on a write, a path `normalize_path` refuses |
| `404` | `not_found` | no such network, or a space the hosted node does not replicate (§6.2) |
| `409` | `hosting-disabled` | the network is not cloud-hosted, so nothing of this service's can publish into it |
| `411` | `length-required` | no `Content-Length` |
| `412` | `precondition` | `If-Match` / `If-None-Match` did not hold |
| `413` | `too-large` | above the deployment's per-write cap |
| `429` | `too-many-writes` | the credential's write slots are all in use |
| `503` | `no-cloud-attached` | no write tunnel for the network — hosting provisioning, or the tenant restarting |
| `503` | `unavailable` | the hosted node refused: in recovery, or out of staging room |
| `507` | `over-budget` | the write would carry the tenant past `budget_bytes` (§6.4) |

### 4.4 Authorization, CSRF, and why nothing is recorded

Credential resolution is the download's, byte for byte: `Authorization` wins
and is terminal, the cookie is the fallback. What the download does *not* do
and a write must is the **CSRF double submit**: a `PUT` or `DELETE` arriving
on a session cookie must carry `x-csrf` equal to the session's token, exactly
as `middleware.check_session` demands above the wisp line. `browse_file.
require_session` grows the check for non-`GET` methods, sharing the rule
rather than the function (it speaks mist's request, not wisp's). A bearer
key needs no token, for the reason `middleware.check_principal` spells out.

**No audit row, and no other database write.** A file write is a pure
data-plane operation: the bytes, the entry and the head all land in the
tenant, and the control plane is a relay that resolves a credential on a
pooled read connection and then talks to a tunnel. An earlier draft audited
every write as `file.put` / `file.delete`, on the reasoning that reads are
ordinary use while a write is a change. That reasoning is right about what a
write is and wrong about whose record it belongs in. The change is the
hosted node's, and the hosted node already keeps the record that matters:
the `f:` entry carries `prev`, the head is signed and sequenced, and
`synch log` on any member walks `cloud-1`'s own publishes for the path —
retained history, verifiable, not editable by this service. A row in
`audit_log` would be a second, weaker copy of that, and it would make every
upload a write transaction on the control plane's database — which is what
decides that only the primary may serve it, and what puts a customer's
upload rate on the same SQLite writer as the zone's re-signs and the
dashboard's mutations.

What the control plane keeps instead is what it already keeps: the tunnel's
session in actor memory, and the write slots below, both gone at restart and
truthful within a backoff. What a deployment that wants a per-upload log
does is what it does for downloads: read the hosted node's log line, which
names the space, the path, the root, the size and the control-plane session
that relayed it — the same line the socket runtime writes for a tree write.

The one row this surface does not write is also the one a *person* might
want most: "who uploaded this". The answer is in the head — `cloud-1`,
which is to say "somebody with member access to this org, through the
control plane" — and no further. That is a real limit and it is stated as
one: attributing a write to the individual member would mean either a
control-plane database write per upload or the member's own key signing
somewhere, and both are the things this design declines (§14).

**The write slots.** Uploads take their own per-credential cap, the download's
mechanism with its own pool: `claim_write`/`release_write` on the registry,
cap 4, lease 3600 s. Separate from downloads because an upload is longer and
because a page that can start four downloads and four uploads at once is fine
while one that can start eight of either is not.

### 4.5 The write registry, and picking a session

A second registry, `cp_writers`, of the same actor as `cp_agents` — sessions
keyed by network, single-use nonces, slot leases — holding write sessions
only. It is a second *name* rather than a second implementation: the registry
code is indifferent to what a session answers, and the two populations stay
apart so that no browse route can ever pick a write session and no write
route a browse one. The connection actor (§5) is new, because its frames are.

Routing is simpler than the download's, and that is the point of §3: there is
one origin that writes, so there is nothing to route on. The handler takes
the write session for the network whose `slot` is 1 — the only slot v1 hosts
(CLOUD-DATAPLANE §3.4) — and refuses `503 no-cloud-attached` when there is
none. When redundant hosting arrives, a second slot is a second *origin*, and
"which origin does a control-plane write speak for" becomes a question; this
design answers it for one slot and says so rather than pretending the answer
generalizes.

### 4.6 Any node serves a write

The reads/writes split in `api/router` is about the *database*: a replica
holds a read-only copy, so it mounts no route that mutates a row. A file
write mutates no row (§4.4). What it needs is a credential lookup, which is a
read, and a write tunnel for the network, which is a fact about the node's
own memory — exactly the two things a download needs. So `PUT` and `DELETE`
on `…/browse/file` are mounted where the `GET` is: in the below-wisp edge
(`api/edge`), on every role, and the data plane opens a write tunnel to
**every node of the deployment** (§5.2), for the reason the browse tunnel
does: the registry of attached sessions is one process's memory, so a node
with no tunnel could answer no write however current its copy of the
database. Primary and replicas take writes alike, and a deployment whose
primary is down keeps taking them.

Two things follow, and both are stated so they are not discovered. The
edge's wrapper has to take the three methods rather than `GET`, which makes
`…/browse/file` the first non-`GET` a read-only node mounts; `router.
elsewhere`'s reasoning — "every route a read-only node mounts is a `GET`" —
stays true of the *wisp* table it is about, and the edge's docstring says
that this one route below it is the exception, and why. And a browser or
script that reaches a replica for its write sees no `409 read-only-replica`
and no redirect to a primary; it is served, and it is served identically.

---

## 5. The write tunnel — `/dp/v1/attach`

### 5.1 Why a second tunnel and not a fifth version

The browse tunnel's protocol is versioned and additive (`PROTOCOL_VERSION`,
`settles_at`), and the obvious move is v5: add `put`, `chunk`, `commit`,
`delete` to `Down`, settle on v5 with the hosted node, and let a customer
daemon at v4 stay ignorant of them. That is *nearly* right and it is the one
thing this design will not do, because of what the version number is for.
A daemon that decodes a frame is a daemon that can be sent it; the only
thing that would keep a control plane from sending `put` to a customer's
daemon would be the control plane's own good behaviour, and the read
design's central claim is that the property does not rest on that. Today it
rests on `frame.rs`: there is no such frame. After v5 it would rest on a
`match` arm that checks a setting.

So the write frames live in a module the daemon never mounts. Concretely:
`crates/synch-dp/src/writes.rs` owns its own `Down`/`Up` types and its own
attach loop, built on public engine API — `open_tree_write` (§7), `resolve`,
`add_api_source`, `delete_object` — and `synch-engine`'s `cloud` module is
untouched. The `synch` binary does not link `synch-dp`, so there is no code in
a customer's daemon that could turn a write frame into a write. The test in
`frame.rs` that no frame encodes a write keeps passing, and keeps meaning what
it says.

The cost is a second WebSocket per hosted tenant per control-plane node, and
a second connection actor in the control plane. Both are small, and both are the price
of the property being a fact rather than a promise.

### 5.2 Handshake

`GET /dp/v1/attach`, WebSocket upgrade, with **two** credentials:

1. `Authorization: Bearer synchdp_…` on the upgrade request — the data-plane
   key, resolved through the one `with_principal`, yielding `Dataplane(_, dp)`.
   Anything else is `403 dataplane_only` before the socket opens.
2. The device-key challenge, exactly as the browse tunnel does it: `hello` →
   `challenge` → `proof` → `attached`, the proof covering
   `"synch-cloud-write-v1" || url || nonce`. A distinct domain tag from
   `synch-cloud-attach-v1`: the URL in the input already differs, but a
   separate tag is what makes "a browse proof cannot be replayed at the write
   endpoint" a statement about the signature rather than about two paths
   happening to differ, the same argument `frame.rs` makes for attach against
   head signatures.

Two credentials because they prove two different things, and a write needs
both. The data-plane key proves *which fleet member* is here and lets the
lookup check the **assignment** (`networks.cloud_dp_id = dp`), so a pod that
does not host the tenant cannot take its writes — the confusion
CLOUD-DATAPLANE §7.2 exists to remove. The device proof proves that the
connection is held by the process that holds **`cloud-1`'s secret**, which is
the key that will sign the head: writes are attributed to `cloud-1` in the
zone, and the attribution is verified, not asserted. A leaked `synchdp_`
token alone attaches nothing here (§10).

The lookup, on the pooled connection: an `active` key for a device whose
`created_by` is `system-dataplane` (ownership, not the label —
CLOUD-DATAPLANE §3.4), in the claimed network, with `cloud_hosted = 1`,
`cloud_dp_id = dp`. Refusals: `unauthorized` for an unrecognised key,
`not_found` for a network assigned elsewhere (the "not yours is not there"
rule, CLOUD-DATAPLANE §3.3), `hosting-disabled` for a network whose flag has
gone off while its device rows are still being torn down. A key that names
no data plane is `dataplane_unnamed`, as on every `/dp/v1` route. Every part
of the lookup is a read, so a replica performs it as well as the primary.

`hello` carries `{v: 1, network, origin, device, slot}` and no `spaces`
claim: there is nothing to route on. The tunnel has its own version counter,
starting at 1, negotiated by the same clamp-to-newest rule as the browse
tunnel's; the two counters are unrelated.

**Every node.** The attach route is a read of the directory and a change to
the answering node's memory, so it is mounted in `read_routes`' company —
served by primary and replicas alike — and the data plane opens one tunnel
per tenant **per endpoint** the deployment names. The endpoints come from the
same place the browse tunnel gets them: the `_synchronicity-cp.<apex>`
record in the zone the tenant already DNSSEC-validates, read through the
tenant's resolver (`DnssecResolver::control_plane`) on the record's TTL.
Not from `SYNCH_DP_CONTROL_URL`: that names where the fleet *polls*, which a
load balancer may make one address for many nodes, and a tunnel has to
reach each node by itself.

### 5.3 Frames

Control frames are JSON text tagged by `t`; content is binary behind the same
eight-byte `(id, seq)` header the browse tunnel uses — but **content travels
down**. On this tunnel a binary frame from the control plane is the payload,
and a binary frame from the node is the protocol violation.

Down (control plane → data plane):

| `t` | fields | meaning |
| --- | --- | --- |
| `put` | `id, space, path, size, from?, if_match?, if_none_match?` | open a write of exactly `size` bytes |
| *(binary)* | `id, seq, data` | one chunk, ≤ 64 KiB, in order |
| `commit` | `id` | all `size` bytes were sent; evaluate the condition and publish |
| `delete` | `id, space, path, from?, if_match?` | publish the tombstone |
| `cancel` | `id` | abandon a write; staging is dropped, nothing published |
| `ping` / `pong` | | liveness |

Up (data plane → control plane):

| `t` | fields | meaning |
| --- | --- | --- |
| `opened` | `id, credit` | the write may begin; `credit` chunks may be sent before the first grant |
| `credit` | `id, n` | `n` further chunks may be sent |
| `committed` | `id, root, size, seq, mtime_ns, origin` | the version now exists |
| `deleted` | `id, still_published, withdrawn` | the tombstone was published |
| `err` | `id?, code, message` | a coded refusal of one request or of the connection |
| `ping` / `pong` | | liveness |

Codes are the engine's own where the engine refused (`not-found`, `invalid`,
`unavailable`, `internal`, the `code_of` vocabulary), plus `precondition`,
`too-large` and `over-budget`, which are decisions this design adds.

### 5.4 Flow control and bounds

The mirror image of the download. `opened` grants an initial credit
(`credit_window`, 4 chunks); each chunk the node has **written into staging**
returns one credit; the control plane sends no chunk it has no credit for. So
a disk slower than the browser stalls the HTTP body read at the control
plane, which stalls the browser, and this process never buffers more than the
window. A `commit` arriving with fewer bytes staged than `size`, or a chunk
arriving past `size`, is `err invalid` and the staging goes: a short body is
never published as a whole file.

Per session: the browse tunnel's `MAX_INFLIGHT` (64) across writes in flight.
Per tenant: a **staging budget** (`SYNCH_DP_WRITE_STAGING_BYTES`, default 4
GiB), because staging lands on the pod's shared ephemeral disk before the
CAS ingest uploads it, and a pod is many tenants; a `put` whose `size` would
exceed what is free under the budget is refused `unavailable` before any byte
moves, which is why `size` is in the frame. Per write: the control plane's
cap (`CP_WRITE_MAX_BYTES`, default 1 GiB) is enforced at the HTTP layer from
`Content-Length`, before the tunnel sees the request. A write idle for the
relay watchdog's 60 s — no chunk, no commit — is cancelled at the source,
exactly as a stalled download is.

---

## 6. The data plane

### 6.1 `run_cloud_writes`

One more standing loop per tenant, spawned by `spawn_loops` beside
`run_cloud`, for every hosted tenant: a hosted network takes writes (§4.1),
so there is nothing in the desired-state document to consult and nothing
for the document to gain.

The loop is the browse attach loop's shape, and deliberately so: discover
the deployment's endpoints from the zone on the record's TTL, keep one child
per endpoint with its own retry clock, handshake, serve to the end, back off
with jitter, repeat. One connection per tenant per endpoint, because the
device proof is per tenant and the session registry is per node. A session
holds a per-write task each, spawned onto the runtime with the store work on
the blocking pool, under the same inbound ceiling every other request handler
on this pod runs under (CLOUD-DATAPLANE §9.1). Writes arriving on several
tunnels at once for one tenant serialize where they must — at the node's
tree-write lock (§6.3) — and nowhere else.

### 6.2 The API source, lazily

The engine's write seam requires the space to be a **source** of this node's
(`is_api_source`): a replica "publishes no file entries of its own" (docs/
REPLICATION.md), and the hosted node has so far been nothing but replicas. A
cloud-CAS node may hold only API sources, and a source and a replica may share
a space (REPLICATION's `source + replica` row) — so the first write into a
space calls `Node::add_api_source(space)`, idempotently, and from then on
`cloud-1` both replicates the space and publishes into it.

Lazily, on the first write, rather than for every replicated space at
provisioning: a source row has consequences a replica row does not — removing
one unpublishes this origin's entries, and the space's `m:space` record
starts describing this node as a publisher — and a network with writes
enabled and never used should look, to every peer, exactly as it did before.

**The space must exist.** A `put` naming a space the tenant does not
replicate is `not-found`. Writes go into the network's existing namespaces;
creating one is a larger act than putting a file in it, and the replicated-
spaces ceiling (CLOUD-DATAPLANE §9.1) exists precisely because "how many
spaces" is a number this service should not let a request choose.

### 6.3 What a commit is, precisely

The engine seam (§7), which is the socket runtime's `TreeWriter` made public,
driven gate for gate as TREE-WRITES §6 lists them:

1. **Open**: `ensure_publishable` (a node in key-loss recovery refuses),
   `normalized_adoption_path`, the space check above; then `open_adoption`,
   which for an API source stages in the tenant's scratch. Refused writes cost
   nothing.
2. **Write**: chunks into the `Adoption` on the blocking pool, credit returned
   per chunk consumed.
3. **Commit**: under `tree_write_lock`, `ensure_publishable` again and the
   condition (§4.3) — then `Adoption::commit` (fsync + rename in scratch),
   `commit_api_file` (the CAS ingest, which **uploads to the tenant's prefix
   and gets the provider's ack before the blob row exists** — SERVERLESS §4's
   order), `stage_api_reference` (the `f:` entry with `prev`, and the `b:`
   ad), then `flush_staged`, which signs one head over the batch, pushes it to
   every reachable member, and wakes the replicas. The `committed` frame is
   sent after the flush returns.

So the ack chain is SERVERLESS §4's chain with one more link:

```
object ack → blob row → f:/b: staged → head signed & pushed → committed frame → HTTP 200
```

One commit is one head, as TREE-WRITES §5.3 prices it; a caller with many
files publishes many heads, and the same future batching work would fix all
three surfaces at once.

### 6.4 Budget and metering

`budget_bytes` is enforced today as a per-replica **admission** ceiling
(CLOUD-DATAPLANE §4.5). An own-published object is held by the *source* hold,
not by a replica, so a write would pass every budget the design has. It must
not: `put` therefore checks, before `opened`, that the tenant's held bytes
across every replica **plus** its own published bytes plus `size` fit under
`budget_bytes`, and refuses `over-budget` otherwise. Approximate under
concurrent writes by at most one in-flight write per session, and convergent,
the same posture the replica budget takes.

The heartbeat gains `published_roots` and `published_bytes` — `cloud-1`'s
own assertions — beside `held_*`. Billing already falls out of the prefix
inventory (CLOUD-DATAPLANE §5.1); this is so the invoice's line items and the
status panel can say which bytes the org *put there* as against which it
*kept*.

### 6.5 The database stream and the ack window

A committed write is a row in the tenant's SQLite — the `f:` entry, the blob
row — and rides the in-process replica stream on its one-second interval
(CLOUD-DATAPLANE §5.3). A pod that dies inside that second loses the
*metadata* of an acknowledged write while its *bytes* are already durable in
the prefix: SERVERLESS §4's window, unchanged. What closes it is that the
head was **pushed at commit** to the customer's own nodes, which then hold
`cloud-1`'s signed head at a seq above what the stream restored; the next
pod's `readopt_self_on_startup` — which already runs before any loop, for
exactly this reason — fetches that trie back and continues above it. The
cluster remembers what the pod forgot. Where no member heard the push, the
residue is SERVERLESS §8.3's: bytes kept, one second of metadata gone, and
the `PUT` may be repeated (a re-put of the same content is a no-op upload).

### 6.6 Delete

Through the seam's `delete_if`, and conditionally on purpose. The engine's
`delete_object` on an API source stages this origin's tombstone whether or
not the origin ever asserted the path — the right behaviour for an S3
`DeleteObject`, which is an assertion about *this node's* view — and here
that would be wrong: a tombstone from `cloud-1` over a path only `nas`
publishes is a content-less version that DESIGN §8 calls **deletion
divergence**, marking the customer's file in every listing until the
customer resolves a conflict they never had. The dashboard user who pressed
delete did not ask to annotate `nas`'s file; they asked for the cloud's copy
to go, and where there is none there is nothing to do.

So the data plane reads `cloud-1`'s own live root for the path first. None
means `withdrawn: false`, nothing staged, no head. One means
`delete_if(PutCondition::Root(own))` under the tree-write lock, so two
control-plane deletes of one path publish one tombstone and the second is
reported `withdrawn: false` as well. What comes back is the engine's
`still_published`, and it deserves the plain statement in the dashboard and
in this document: **the control plane cannot delete a customer's file.** It
can withdraw the cloud's version of it. Where `nas` asserts the path, `nas`
is the only origin that can retract that assertion, because single-writer
tries are structural (DESIGN §8). What a `DELETE` guarantees is narrower and
exact: after it, the unified tree selects some *customer's* version or none,
never the cloud's.

Publishing the tombstone anyway — as a signal to the customer that someone
at the control plane wants the file gone — was considered and rejected: the
signal would be indistinguishable from the divergence it imitates, and the
org already has a channel for wanting things, which is not the file tree.

This is the property to want. A compromised control plane, a stolen session,
a bug in this design — none of them can make a customer's bytes vanish from
the customer's own network. They can add versions, which is divergence, and
they can withdraw their own, which is nothing.

---

## 7. Engine changes required

Two, both of independent value and both small:

- **(e) The tree-write seam becomes public.** `TreeWriter` and
  `tree_write_lock` are private to `sockets.rs`; the data plane would
  otherwise re-compose the same sequence from `open_adoption`,
  `commit_api_file`, `flush_staged` and `delete_object` — the third copy of
  the gate order, after the control-service `Put` handler and the socket
  runtime, with the condition evaluated outside the lock because the lock is
  `pub(crate)`. `Node::open_tree_write(space, path) -> TreeWriter` exposes the
  writer that already exists, so SFTP, sockets and the data plane commit
  through one seam.
- **(f) A second condition kind.** `PutCondition` gains `Selected { policy,
  expected: Option<Hash> }`: hold if the version `VersionPolicy` selects for
  the path has root `expected` (`None` meaning no live version). Evaluated
  in the same place and under the same lock as `Absent` and `Root`, against
  `Node::resolve`. The existing kinds are untouched and keep TREE-WRITES
  §5.3's meaning; the `sy_put_*` ABI does not expose the new one until a
  program needs it.

Nothing in `cloud/frame.rs`, `cloud/attach.rs`, the browse registry or the
membership code changes. The daemon binary gains no write-capable frame
decoder.

---

## 8. The dashboard and the skill

- **`NetworkFiles`** gains an upload control (a file picker and drop target)
  and a per-entry delete, shown only when `status.writes.enabled` and
  grayed with the reason when `!status.writes.attached`. Upload is one
  `fetch` with the `File` as body and `Content-Length` from its size; the SPA's
  `send` helper already carries `x-csrf`. The result row names `cloud-1` as
  the origin, and where the path was already published by a customer node
  the version drawer opens on it — divergence is the expected outcome of an
  upload over an existing file, and the UI should show it rather than a
  green tick. Delete confirms with the outcome in words: *withdraw the
  cloud's version*, and after the fact, *nas still publishes this file* when
  `still_published` is true.
- **`NetworkDetail`**'s hosting control says what hosting now grants: a
  replica that keeps everything published on the network, *and* a member of
  the network that files can be put into from here. The hosting-off
  confirmation says that uploads stop with it.
- **`priv/skill/SKILL.md`** gains the two rows in its route table, the new
  error codes in its table, one paragraph on what a delete means, and one
  sentence that uploads leave no audit row. The skill is the API's contract
  for programs, and a program that reads `still_published: true` as failure
  would retry forever.

---

## 9. Failure matrix

| failure | effect | recovery |
| --- | --- | --- |
| writes on, tenant not yet provisioned / restarting | `503 no-cloud-attached` | the tunnel attaches within a backoff of the tenant reaching `Running` |
| primary down | replicas keep taking writes; only database mutations wait | the primary returns |
| one control-plane node has no tunnel yet | that node answers `503 no-cloud-attached`; its siblings serve | the tunnel attaches within a backoff |
| body shorter than `Content-Length` | `err invalid` at commit, staging dropped, nothing published | client repeats |
| browser stalls mid-upload | credit stops, the body read stalls; watchdog cancels at 60 s idle | client repeats |
| pod dies after `committed`, before the DB ship | metadata of ≤ 1 s of writes lost locally; bytes durable | self-readoption from members that received the push (§6.5); else re-put |
| pod dies mid-write | staging is ephemeral scratch and dies with the pod; client saw no `200` | client repeats |
| provider outage | ingest fails closed; `err unavailable`; nothing acked that is not durable | client repeats |
| condition lost | `412`, nothing published, the found version in the answer | caller reads again and decides |
| hosted node in recovery | `err unavailable` at open and again at commit | recovery completes |
| tenant over budget | `507 over-budget` before any byte moves | org raises plan |
| pod staging disk full | `err unavailable` at open (staging budget) | writes resume as in-flight ones finish |
| hosting switched off mid-upload | sessions dropped, the in-flight write is cancelled at the node, nothing published; `cloud-1` leaves the zone in the same commit | re-enable hosting |
| **leaked data-plane key** | cannot attach a write tunnel: the device proof needs `cloud-1`'s secret | rotate the key (unchanged) |
| **stolen member session or org key** | can publish versions into the network as `cloud-1`; cannot alter or remove any customer version; attributable to the credential only through the hosted node's log | revoke the credential; adopt over or outrank the published versions; disable hosting |

---

## 10. Security considerations

- **What is new, precisely.** Today a compromised session cookie, org key or
  control-plane node can *read* a browse-enabled network. After this, one can
  also *publish into* a hosted network, as `cloud-1`. That is the whole
  delta, and it is bounded on every side: by the member floor (equal to what
  a member does with any device they enroll); by attribution (the origin is
  `cloud-1`, never a customer's, so a forged version is never mistaken for a
  customer's assertion); by the signed, sequenced history every publish
  leaves; by the version model (nothing altered, nothing of another origin's
  removed); and by the hosting switch, which ends it at the next request.
  What is *not* among the bounds is a per-write audit row (§4.4): a stolen
  credential's uploads are attributable to it through the hosted node's log,
  not through the org's trail.
- **The customer's daemon is untouched.** No write frame decodes on the
  browse tunnel, and the daemon binary links no code that could decode one
  (§5.1). This design does not weaken the read design's central property; it
  routes around it.
- **Two credentials on the write tunnel** (§5.2), so that neither alone
  attaches. A leaked `synchdp_` token buys enumeration and forged heartbeats,
  as before, and *not* a channel to receive an org's uploads. A leaked tenant
  DB stream — which carries `cloud-1`'s secret and is the bucket's to protect
  (CLOUD-DATAPLANE §9) — without the data-plane key buys nothing at this
  endpoint either.
- **Uploaded bytes are hostile content**, exactly as stored files are on the
  read path: served back only as `attachment` octets under `nosniff`, never
  inline. The upload path adds no rendering.
- **Path validation is the engine's.** `normalized_adoption_path` and
  `normalize_path` refuse traversal and malformed components on the hosted
  node; the control plane passes the query parameter through as opaque text,
  as the read does, and never assembles a path.
- **Activated sockets.** SOCKETS.md §3 makes activation a statement about a
  path *on the activating node's own tree*, admitted from *its own* trie, and
  §2.3 forbids `newest` from ever dispatching a connection. So a
  control-plane write to a path some customer node has activated produces
  `cloud-1`'s `File` version of that path — divergence — and never changes
  what that node runs. The hosted node itself activates nothing and runs no
  socket workers. The `refuse_socket_path` gate in the seam stays, and on the
  hosted node it is vacuously satisfied.
- **`mtime_ns` is host-stamped** (§4.3), so a caller cannot choose which
  version the cluster selects except by being the newest — which is what a
  write is.
- **Resource exhaustion** is a shared-pod concern (CLOUD-DATAPLANE §9.1) and
  a write is the first request on this pod that consumes *disk* on a
  caller's say-so. The staging budget per tenant, the size cap per write, the
  per-credential slots and the per-session in-flight ceiling are the four
  bounds, and the first is the one that keeps one org's uploads from filling
  the volume out from under another's tenant.
- **Rate.** Not limited beyond the caps above, and deliberately: a member
  abusing a write surface is a membership problem with the org's remedy
  (DESIGN §12), and here the org holds a second one — hosting off.

---

## 11. Limits

| Bound | Default | Where |
| --- | --- | --- |
| Bytes per write | 1 GiB (`CP_WRITE_MAX_BYTES`) | control plane, from `Content-Length`, before the tunnel |
| Chunk | 64 KiB | tunnel content frame |
| Credit window | 4 chunks | tunnel |
| Writes in flight per credential | 4 | control-plane registry |
| Requests in flight per session | 64 | data plane |
| Staging in flight per tenant | 4 GiB (`SYNCH_DP_WRITE_STAGING_BYTES`) | data plane |
| Idle before cancel | 60 s | control-plane watchdog |
| Spaces writable | those the tenant replicates | data plane |

---

## 12. Implementation plan and tests

1. **Engine** — (e) and (f) of §7, with a unit test that `Selected` holds and
   fails against `resolve` under the lock, and that the existing `Absent` and
   `Root` are unchanged.
2. **Control plane** — no migration. The `cp_writers` registry name; the
   write connection actor (`api/cloud_writer.gleam`); the attach route in
   the read table; `PUT`/`DELETE` in `browse_file.gleam` with CSRF and the
   write slots, mounted by the edge on every role; `writes` on the browse
   status; `set_cloud_hosting`'s disable path dropping write sessions after
   its commit. Gleam tests in the shape of `browse_test.gleam`: the attach
   lookup refuses a wrong data plane, a customer-created device, and an
   unhosted network; a `PUT` on a cookie without `x-csrf` is `403`; a
   replica-role edge serves a `PUT` rather than answering `409`; a `PUT`
   leaves `audit_log` unchanged.
3. **Data plane** — `writes.rs`: the frame types, the attach loop, the
   handler over the public seam, the lazy API source, the budget check, the
   staging budget; `spawn_loops` gated on `writes`; the heartbeat fields. A
   unit test drives `serve` over in-process channels as `attach.rs`'s tests
   do: a whole write round-trips to a readable version, a short body publishes
   nothing, `If-Match` against a stale root is `precondition`, a delete of a
   path only `nas` publishes answers `still_published: true` and
   `withdrawn: false` and stages no tombstone, and two deletes of one
   `cloud-1` path publish one.
4. **End to end** — `control-plane/e2e/cloud-dataplane.sh` grows one act:
   after both customer files are durable, enable writes, `PUT` a third file
   through the control plane, and assert that the third customer node — which
   starts only afterwards — reads it with `cloud-1` as its origin; then
   `DELETE` one of the customer files through the control plane and assert it
   is still readable, its version list naming the customer origin only.
5. **Docs** — §13.

---

## 13. What this changes in existing documents

To be applied in the change that builds this:

- **CLOUD-DATAPLANE §4.4** — the loop table gains `run_cloud_writes`, and the
  uploads-sweeper row's "v1 has no write surface at all" becomes "no
  multipart surface"; **§5.1** — `uploads/` stays unused, but staging scratch
  is now written on a caller's request; **§9** — the bullet "the hosted node
  writes nothing customer-visible but its own trie" stays true and gains the
  words "which, with writes enabled, includes file entries an org member
  asked it to publish"; **§11** — this document joins the v2 list as built.
- **CP README, *Cloud browse*** — "It is read-only by construction — the
  tunnel encodes no write opcode and the API is GET-only" narrows to the
  tunnel: the *browse tunnel* encodes no write opcode; the file API takes
  writes, and they go down a different tunnel to the hosted replica only.
  The cloud-hosting section says that a hosted network is a writable one,
  and the API-keys section's "reads are not recorded" sentence gains "and
  neither are file writes, which are the hosted node's to record".
- **TREE-WRITES §6** — the seam has three callers; **§10** — the guest-facing
  `Selected` condition is listed as available to sockets when a program
  needs it.
- **DESIGN §12** — the membership sentence gains a clause: an org that hosts
  a network on a control plane may let that control plane's hosted member
  publish versions on the org's members' behalf, attributed to that member,
  bounded by the version model as every publish is.
- **`api/router`'s header and `elsewhere`'s docstring** — the one
  non-`GET` a read-only node mounts, below wisp, and why (§4.6).
- **`priv/skill/SKILL.md`** — §8.

---

## 14. Non-goals, and what comes after

- **Multipart and resumable uploads.** The engine's upload machinery exists
  and is checkout-free on a cloud-CAS node (SERVERLESS §9); the tunnel would
  gain `part`/`complete` frames and the route a `?uploads` family. Worth
  building when a caller needs more than the per-write cap in one object.
- **Directory operations.** A rename is read + write + delete composed by
  the caller, under the conditions above; a recursive delete is a loop. A
  program that wants either has the primitives.
- **Redundant hosting.** A second slot is a second origin, and "which origin
  speaks for a control-plane write" needs an answer this design does not give
  (§4.5). The likely one is *slot 1 writes, every slot replicates*, which
  keeps the writer singular.
- **Batched publishes.** One commit, one head, as on every write surface
  today; the shared fix is TREE-WRITES §10's.
- **Writing as the caller.** A write is `cloud-1`'s, always. Attributing it
  to the member who asked would mean a key of theirs signing on this service,
  which is a different product with a different key-custody story.

---

## 15. Costs, stated

- **A second tunnel per hosted tenant per control-plane node**, and a
  second connection actor in the control plane, so that the read tunnel's
  wire fact stays a wire fact (§5.1). The alternative was cheaper by exactly
  one module and cost the property the read design is built on.
- **No trail of who uploaded what**, beyond "a member, through the control
  plane" (§4.4). The org's audit log stays a log of what credentials did to
  the org's *configuration*; what they did to its *files* is in the files'
  own history, attributed to `cloud-1`.
- **`cloud-1` becomes a publisher.** With writes used, the hosted origin's
  trie carries file entries and its source holds pin content; disabling
  hosting now removes a member whose assertions were selected somewhere.
  That is what the org asked for, and the version drawer shows it before
  they ask.
- **One head per write**, and the metadata it costs every member, until
  batching arrives.
- **Divergence by design.** Uploading over a customer-published path makes
  two versions where there was one. The UI shows it rather than hides it,
  because hiding it would be the one dishonest thing a file browser over
  this version model could do.
