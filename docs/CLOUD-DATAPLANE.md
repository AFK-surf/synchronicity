# Cloud data plane — multi-tenant hosted replicas

Status: **implemented** (v1) · 2026-08-31

The service is `crates/synch-dp`, the control-plane half is under
`control-plane/src` (migration v12, `/dp/v1`, the cloud-hosting toggle and
its dashboard switch), and the engine changes §7.3 asks for are in. §11 says
what is built and what a v2 would add.

This document designs the **cloud data plane**: a managed, multi-tenant
hosting service that runs a fleet of synchronicity replica nodes — one per
customer network — next to the control plane, and durably replicates each
hosted network's content into provider object storage. It is, deliberately,
nothing more exotic than *the replicate mode of the daemon, operated as a
service*: a hosted network gains one more member, that member holds a replica
of every space with a cloud CAS behind it, and every existing protocol,
guarantee, and dashboard panel applies to it unchanged.

The service is written in Rust and embeds `synch-engine` as a library — the
promise at the top of `crates/synch-engine/src/lib.rs` ("any Rust application
can embed a full node the same way") is exactly the promise this design
cashes. The control plane (the Gleam service under `control-plane/`) remains
the authority and the API; the data plane is cattle that polls it.

Section references (§) are to this document unless prefixed. `DESIGN §` is
DESIGN.md, `SERVERLESS §` is docs/SERVERLESS.md, `REPLICATION` is
docs/REPLICATION.md, `CP README` is control-plane/README.md.

---

## 1. Goals and non-goals

### Goals

- **Durable, managed replication.** An org admin flips one per-network
  switch and everything published on that network is thereafter durably
  replicated to service-operated object storage — every space, every origin,
  under the replica contract of REPLICATION (acquire every content root named
  by visible current entries, from every origin).
- **Ordinary membership.** The hosted node is a normal named device in the
  customer's zone. Customer nodes need no new protocol, no new
  configuration, and no software upgrade to benefit: they see one more
  trusted peer that fetches eagerly and serves well.
- **Multi-tenant economics.** One process (later: a small shard set) hosts
  hundreds of networks. Tenants share a binary, a blocking pool, a DNSSEC
  resolver, and a bucket — and share nothing else: not a key, not a
  database, not an object-store prefix.
- **Fail-closed enablement.** Hosting is off until an org admin turns it on,
  per network, exactly like cloud browse (`browse_enabled`, CP README).
  Turning it off tears the hosted member down and, after a retention hold,
  deletes what it stored.
- **Reuse over invention.** The engine's `Node`, the OpenDAL cloud CAS
  (SERVERLESS), the replica machinery (REPLICATION), the zone publisher, and
  the cloud-browse tunnel are used as they are. The new code is a
  reconciler, a control-plane client, and a modest control-plane API
  addition.

### Non-goals

- **Not compute hosting.** The data plane never admits socket work
  (docs/SOCKETS.md): a hosted replica stores and serves bytes; it does not
  execute customer code. Socket admission is closed for the life of the
  process (§4.4).
- **Not a gateway.** No S3-compatible or HTTP read surface of its own in v1.
  Reads reach hosted content the way they reach any replica: over the blob
  protocol from a member node, or through the existing read-only
  cloud-browse tunnel.
- **Not end-to-end privacy.** A hosted replica holds customer plaintext, as
  any replica does. §9 states this plainly and what bounds it.
- **Not a second source of truth for membership.** The zone remains the only
  authority. The data plane holds no trust decisions of its own; it is
  admitted the way every device is admitted — by appearing in the zone.

---

## 2. What the customer sees

The tenant contract, end to end:

1. An org admin enables **cloud hosting** for a network in the dashboard (or
   `PUT /api/orgs/:slug/networks/:net/cloud-hosting/enabled`, admin-gated,
   mirroring the browse toggle). Default off.
2. Within the reconciliation interval a device labelled `cloud-1` appears in
   the network — in the device list, and as one more
   `v=sync1 id=cloud-1 nk=…` record in the zone at
   `_synchronicity.<network>.<org>.<base>`. Customer nodes admit it at their
   next zone refresh, exactly as they admit any new member.
3. The hosted node replicates every space on the network with a cloud CAS
   behind it. Once the org has cloud **browse** enabled, it also shows up
   in the existing replication panel (CP README § cloud browse: the "what
   does each node replicate" question is asked of every attached daemon,
   and the hosted node attaches like any daemon), so the org can watch
   coverage converge without any new UI. The two toggles stay independent
   and independently fail-closed: hosting without browse replicates but is
   observable only through the status heartbeat (§3.3); the attach
   endpoint refuses a browse-disabled network's tunnel today (`browse-
   disabled`), hosted device or not, and this design does not change that.
4. Disabling the toggle removes the device from the network. The zone
   shrinks at the next publish, customer nodes drop the binding when it
   expires, the data plane drains and retires the tenant, and after a
   retention hold (default 30 days) the tenant's object-store prefix and
   database are deleted.

**Why this adds no new trust.** The control plane already signs the
membership zone: it can already, today, add any device key to any network it
serves. An org that runs its networks under this control plane has already
extended exactly the authority that cloud hosting exercises. The toggle
narrows that authority to an explicit, auditable, org-controlled grant — it
does not widen anything. This is the same shape of argument the browse
toggle makes, and it is the reason the flag lives in the control plane's
database rather than in the zone: enforcement at the data plane takes effect
at the next poll, not a TTL later, and never reaches public DNS.

---

## 3. Control-plane additions

The exploration that grounds this section: the control plane today has **no
cross-org enumeration surface and no service credential of any kind**. Every
credential names exactly one org (`api/common.check_org` treats "a
credential names one org" as load-bearing), `GET /api/me` refuses keys, and
no route returns more than one org. A data plane cannot be built against the
existing API; the additions below are the minimum that changes that without
disturbing the invariant.

### 3.1 The `cloud_hosted` flag

Migration v12, copying V9's shape and rationale verbatim:

```sql
ALTER TABLE networks ADD COLUMN cloud_hosted INTEGER NOT NULL DEFAULT 0;
```

- Exposed on `network_detail` and `list_networks`.
- Written by `PUT /api/orgs/:slug/networks/:net/cloud-hosting/enabled`,
  admin-gated, audited as `cloud-hosting.enable` / `cloud-hosting.disable`,
  mirroring `browse_api.set_enabled`.
- Deliberately **not** a zone fact. The zone carries the *consequence* (the
  hosted device's TXT record); the flag itself is enforced at the data-plane
  API, where a change takes effect within one poll interval.
- Disabling additionally deletes the network's `cloud-*` device rows in the
  same transaction (a `zone_mutation`, so the zone shrinks with the commit)
  and stamps `cloud_disabled_at`, which starts the retention clock (§6).

### 3.2 The data-plane principal

A fourth credential kind — **not** a row in `api_keys`. An `api_keys` row
names one org (`org_id NOT NULL`, and the role CHECK stops at `admin`);
bending that table would break the one-org invariant every handler leans on.
Instead:

```sql
CREATE TABLE dataplane_keys (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  prefix     TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  last_used_at INTEGER
);
```

- Minted only from the operator CLI: `controlplane dataplane-key mint
  <name>`, printing the token once, the same posture as `seed-admin`. No
  HTTP route mints or lists these keys — the credential that can see every
  org is never reachable *through* the API it authorizes.
- Sent as `Authorization: Bearer synchdp_…`. The distinct prefix keeps the
  two bearer namespaces from ever being confused in logs or middleware, and
  `check_principal` grows a `Dataplane(key_id)` constructor that is accepted
  **only** by `/dp/v1/*` routes — `check_org` refuses it outright, so a
  leaked data-plane key cannot touch the org API at all.
- The `/dp/v1` GET routes are served by read replicas too (they are reads of
  litestream-fed state, like the rest of `read_routes`); the device
  registration below is primary-only, like every write.

### 3.3 The data-plane API

Five routes under `/dp/v1`, all requiring the data-plane principal.

**`GET /dp/v1/networks`** — the desired-state document. Every network of
every org with `cloud_hosted = 1`:

```json
{ "generation": 4183,
  "collect": [ { "org": "beta", "network": "old" } ],
  "networks": [
    { "org": "acme", "network": "prod",
      "domain": "prod.acme.synchronicity.example",
      "budget_bytes": 2199023255552,
      "retention": "current",
      "device": { "label": "cloud-1", "nk": "…", "state": "active" } } ] }
```

- `domain` is the membership domain, verbatim what `Node::set_domain`
  takes; the data plane never assembles names itself.
- `budget_bytes` and `retention` are **policy, decided control-plane side**
  (from the org's plan); the data plane is mechanism only and applies them
  to every replica it configures (§4.5). `retention` is `current` or
  `forever` (REPLICATION); v1 defaults every org to `current` with the
  standard 30-day grace.
- `device` is present once the data plane has registered a key (below), so
  a restarted, disk-less data plane can tell "network I have never joined"
  from "network whose identity I must recover" (§5.3).
- `collect` names offboarded networks whose retention hold (§6) has run
  out — the fleet's instruction to delete what it stored.
- `generation` is the zone's serial, bumped by any change that shapes the
  hosted set. The response's `ETag` is derived from it **and from the
  collections now due**, which is not a refinement but a correctness fix: a
  hold elapses because a clock passed, with no transaction and no zone
  fact, so a tag built from the serial alone would answer 304 for ever and
  the collection would never happen at all. The tag folds in both a count
  and a sum of the due stamps, because a count alone is unchanged when one
  network falls due in the same interval another is collected.

**`PUT /dp/v1/networks/:org/:net/device`** — idempotent registration of the
hosted device's key:

```json
{ "label": "cloud-1", "nk": "<52-char z-base-32 device key>" }
```

Creates the `devices`, `device_keys` (`state='active'`), and
`network_devices` rows in one `zone_mutation` transaction — the same
transaction shape as `join_device`, so **the commit is the publish** and the
zone names the key immediately. Re-`PUT` with the same `(label, nk)` is a
200 no-op. `PUT` with the same label and a *new* key opens the standard
rotation window (DESIGN §3.4: two keys under one label) when the old key is
`active`, and replaces outright when the old key is already `revoked` —
which is the recovery path after a data-plane disk loss (§6). A rotation is
*completed* by the fourth route below; nothing completes it implicitly.

The body may additionally carry the zone's optional `relay` and `addr`
dialing hints (the fields `join_device` already takes); v1 leaves them
empty — an ephemeral pod has no stable address to publish, the hosted node
initiates its own fetches, and inbound reaches it through iroh discovery
and relays like any NAT-bound peer.

Constraints inherited from the schema and enforced here: `label` must begin
`cloud-` (the reserved namespace, §3.4), one live `nk` binds one
device globally (`device_keys_live_nk`), at most two records per label (the
rotation window, `zone/build.gleam` validation).

`devices.created_by` is `NOT NULL REFERENCES users(id)`; migration v12
seeds one system user (`system-dataplane`, no email, no sessions possible)
that these rows reference, so no human's id is impersonated and the audit
trail names the service.

**`DELETE /dp/v1/networks/:org/:net/device/keys/:nk`** — withdraws a key
this service registered, in the two steps the rotation window has: plain
moves `active → retiring` (the key still publishes, so peers that have not
re-resolved keep working), and `?revoke=1` withdraws it outright once the
window has run. A rotation is therefore `PUT` a new key, `DELETE` the old,
and `DELETE …?revoke=1` a TTL later; a key the service has reason to
distrust skips to the last step. Confined to keys of `cloud-*` devices in
that network, and it refuses the last `active` key unless revoking, so the
route cannot orphan a healthy tenant. Without it a rotation could be
opened and never closed — the zone would carry two keys per label forever,
which the zone validation caps but the design should never lean on.

The `cloud_hosted` flag is deliberately *not* required here, unlike the
other two writes: disabling hosting deletes these devices in its own
commit, so a key still findable belongs to a tenant still hosted or one
mid-teardown, and refusing to withdraw a key because the switch already
went off would close the door on exactly the cleanup this is for.

**`DELETE /dp/v1/networks/:org/:net/storage`** — the data plane reporting
that it has deleted an offboarded tenant's stored copy. Refused with 409
while the network is still hosted, so the record can never say "collected"
about storage that is still in use; idempotent, because the fleet retries
after a partial failure. It clears `cloud_disabled_at`, which is what takes
the network out of `collect`.

**`POST /dp/v1/networks/:org/:net/status`** — the metering heartbeat, sent
per tenant every few minutes:

```json
{ "held_roots": 12034, "held_bytes": 481036337152,
  "wanted": 3, "last_sync_ns": 1756600000000000000,
  "shard": "dp-1" }
```

Stored (last write wins, one row per network) — unlike the browse tunnel's
replication question, which is deliberately unstored, billing needs a
number that survives the tenant being down. The dashboard's live view stays
the tunnel; the stored row is for invoices and alerts.

### 3.4 The reserved label namespace

Device labels beginning `cloud-` are reserved: `join_device` and the
dashboard refuse them for customers (409 `reserved-label`), and only the
data-plane principal may create them. The **whole prefix** is reserved,
not only the `cloud-<n>` form the fleet actually uses. Reserving just the
digit form would leave `cloud-1a`, `cloud-01` and `cloud-nine` available
as customer labels that read, to a human scanning a device list, exactly
like the hosting slot beside them — and a namespace whose purpose is to
make one identity unambiguous cannot leave its own lookalikes on the
table. The cost is a handful of names nobody has a strong claim to.

**Reservation is a rule about creation; ownership decides everything
else.** `devices.created_by` is `system-dataplane` for precisely the
devices this service made, and that column — never the label — is what
`retire_hosted_devices`, the desired document's `device` field, the
key-retirement route and the customer-facing device guard all test. The
two must not be the same predicate: a device named `cloud-backup` that
predates the namespace is still the customer's to manage and delete, and
deciding by label would either lock them out of their own row or, when
they disabled hosting, delete it.

The suffix is the **hosting slot**,
*not* the shard: v1 hosts every network once, in slot 1, so the device is
always `cloud-1`, whichever shard happens to run it. A slot is a durable
identity and shards are interchangeable pods — the same distinction that
keys the DB replica stream by network rather than by shard (§5.3), and it
is what lets a tenant move between shards (§7.2) with no zone change at
all. Redundant hosting, later, is a second slot: `cloud-1` and `cloud-2`
as two ordinary devices, because two replicas of one network is already a
thing the protocol does. Which shard currently serves a slot is
operational metadata, carried in the status heartbeat, never in the zone.

---

## 4. The data plane service

One binary, `synch-dp`, one new crate, `crates/synch-dp`, depending on
`synch-engine`, `synch-net`, `synch-store` (all already library crates) plus
`reqwest` and `tokio`, which are already workspace dependencies.

### 4.1 Tenancy model: one network, one node, whole

**One hosted network = one full `Node`**: its own data dir, its own SQLite
database, its own Ed25519 device key, its own iroh endpoint, its own cloud
CAS root. There is no sub-node or virtual-node concept in the engine and
this design does not invent one: the endpoint is bound under the device
secret (`Net::bind`), the protocol handlers close over that node's store,
and the device key *is* the cluster identity — multiplexing an endpoint
would mean multiplexing an identity, which DESIGN §3.1 spent its whole
design budget keeping singular. Multiple `Node`s in one process is the supported,
tested configuration (the engine's own cluster tests run exactly this way).

What every tenant costs, and what is shared, is accounted in §7.

### 4.2 The reconciler

The core of the service is a desired-state loop, deliberately shaped like
the engine's own standing loops (interval + jitter, work is idempotent,
missing a tick costs latency not correctness):

1. **Poll** `GET /dp/v1/networks` (default every 60 s, `If-None-Match`).
   On success, persist the shard-filtered document to
   `dp/<shard>/desired.json` **in the bucket** (local disk is ephemeral,
   §5.3) before acting on it — the data plane **fails static**: if the
   control plane is unreachable for an hour, the current tenant set keeps
   replicating, and a pod rescheduled while the control plane is down
   boots from the bucket copy and resumes hosting the last-known set; no
   tenant is ever torn down because the API was down (teardown requires a
   *successful* poll that omits the network). What fail-static cannot
   cover is a *first* boot with no bucket copy and no control plane —
   there is no known set to serve; that cold start waits.
2. **Diff** desired against running, filtered to this shard (§7):
   - *new network* → provision (§4.3);
   - *running and desired* → converge policy: budget or retention changed →
     `set_replica` on every configured replica;
   - *running, not desired* → drain and retire (§4.6, §6);
   - *desired but failing* → the tenant supervisor owns retry; the
     reconciler only reports.
3. **Report**: per-tenant status POSTs (§3.3), Prometheus metrics labelled
   by org/network, one log line per state transition.

Tenant states, cached per tenant in `<tenant-dir>/state` — a convenience,
not a record: every state is re-derivable on a fresh pod from the desired
document, the control plane's `device` field, and what the bucket holds:

```
Provisioning → Identifying → Running → Draining → Retired
```

### 4.3 Provisioning and identification

For a network entering the desired set:

1. Create `<base>/tenants/<org>/<net>/` and attempt a **restore** of the
   tenant database from its replica stream (§5.3) — on an ephemeral pod
   every provisioning is potentially a re-provisioning, and a restored DB
   carries the device key and holds an existing identity. Only when
   nothing restorable exists, call `Node::init(dir, Some(domain))`, which
   generates a fresh device key into the tenant's SQLite and leaves the
   origin unset — named identity comes from the zone, as it must.
2. Read the public key back and `PUT /dp/v1/networks/:org/:net/device`
   with `{label: "cloud-1", nk}` (the slot label, §3.4). The commit
   publishes the zone.
   (After a restore this is the idempotent 200 no-op; after a fresh init
   on a network whose old key is unrecoverable, it is the key-replacement
   path.)
3. Open with the daemon's own pattern (`open_once_named`): call
   `Node::open(config)`; on `EngineError::Unidentified` — the zone answer
   has not propagated to the resolver yet — poll on the same 30 s cadence
   the daemon uses. Because the control plane's commit *is* the publish,
   this window is DoH-cache-sized, not propagation-sized.
4. On identification, install the process-shared `DnssecResolver`
   (`set_dns_resolver`), spawn the loop set (§4.4), mark `Running`.

The per-tenant `NodeConfig`:

```rust
NodeConfig {
    data_dir: tenant_dir,
    cloud: Some(CloudConfig {            // §5.1
        service, options,                // bucket + per-tenant root
        scratch_dir: tenant_dir.join("cloud"),
        upload_policy: CloudUploadPolicy::OwnPinned,   // the default, §4.5
        cache_bytes: Some(volume_budget / max_tenants), // §5.2
        ..
    }),
    net: NetOptions { bind_addr: None, .. },   // ephemeral port per tenant
    socket_workers: 0,                   // §4.4 — engine change (a)
    name: "cloud-1".into(),              // the slot label; never the hostname
    replica_release_floor: 1,            // never release the last copy
    ..NodeConfig::new(tenant_dir)
}
```

Two fields carry the multi-tenant lessons the engine's code teaches:
`name` defaults to the process hostname, which would publish one name for
every tenant, and the cloud cache's Unix default (20 % free on the
filesystem) is per-node `statvfs` on a shared volume — N tenants would each
try to close the whole shortfall alone. Both are therefore always set
explicitly.

### 4.4 The loop set

The daemon spawns eleven standing loops; a hosted replica runs the subset
that a source-less, checkout-less, socket-less member needs:

| loop | runs? | why |
|---|---|---|
| `run_anti_entropy` | yes | metadata replication is the job |
| `run_maintenance` | yes | trie GC, cache eviction, scratch sweeps |
| `run_replicas` | yes | acquisition, grace releases, material claims |
| `run_publisher` | yes | publishes this node's own trie: blob ads, `m:self`, replica claims — cheap when idle |
| `run_dns` | yes | membership *is* the tenant boundary; a lapsed zone partitions the tenant |
| `run_cloud` | yes | the browse/replication tunnel — this is what puts the hosted node in the org's replication panel (§2, once browse is enabled) |
| `run_scanner`, `run_watcher` | no | no filesystem sources exist (cloud CAS refuses them anyway) |
| `run_checkouts` | no | nothing is materialized |
| uploads sweeper | no | v1 has no write surface at all — no control socket, no gateway, no sockets — so no upload can ever exist to sweep or reopen |

Plus, of the daemon's one-shot startup helpers, `readopt_self_on_startup`
and then `scan_publish_push` per tenant (`reopen_interrupted_uploads` goes
with the sweeper, for the same reason). The order matters and the first is
not optional: a restored database can be behind what peers already hold
(§5.3), and a publisher started over that seq forks this origin's own head
— so re-adoption runs *before* any loop does.

Two of these take a resolver and so are spawned directly rather than
through the common helper. `run_dns` is the one whose absence is silent
and total: membership is a lease, `run_maintenance` expires bindings on
schedule, and nothing else renews them — a tenant without it stops
trusting every customer device a TTL and a grace after it opened, while
still reporting itself healthy.

**Sockets are refused, permanently.** The hosted node closes socket
admission at open and never reopens it. A hosted replica stores and serves
bytes; executing customer socket code is compute hosting, a different
product with a different isolation story. This wants one small engine
change — **(a)** `socket_workers: 0` makes `Node::open` skip the socket
runtime outright: no `SocketPool` (today `start_with_ssh_host_key` returns
`Some` unconditionally), no eager SSH host-key generation, and — because
the socket ALPN and dispatcher are mounted only when the pool exists — no
advertised socket capability for a peer to dial. Today's eager start costs
N tenants × default 4 OS threads for a capability this service must not
have.

Supervision copies the daemon's discipline: one broadcast shutdown channel
per tenant, every loop's `JoinError` inspected, and a loop that died by
panic restarts *that tenant* (with backoff), never the process — a silently
dead publisher is a tenant that never advertises again, and one tenant's
panic must not be another tenant's outage.

### 4.5 Replica policy: everything, automatically

REPLICATION's replica is per-space and explicit; hosting is per-network and
total. The bridge is a small standing loop per tenant (piggybacked on the
reconciler tick): enumerate the spaces visible in the tenant's unified view
and ensure a replica exists for each —

```rust
node.add_replica(space, policy_from_control_plane, grace, budget_share, None)
```

The enumeration is `store().known_spaces()` — every space any origin has
published entries for — run on the reconciler's tick. A space that appears
between ticks waits one interval, which costs latency on a new space and
nothing else.

Replicas are added and **never automatically removed**. Removal is the
wrong tool twice over: `remove_replica` without `--pin-held` releases the
replica's holds *immediately*, bypassing grace — so auto-removing on "the
space left the view" would let a transient view glitch, or a customer
briefly unpublishing, instantly drop the hosted copy the service exists to
keep. And it buys nothing: a replica of a space with no current entries
holds no roots and costs nothing, while the retention policy already
shrinks what leaves the tree through the grace machinery. Standing
replica policies leave only with the tenant, at teardown.

Decisions, with reasons:

- **`CloudUploadPolicy::OwnPinned`, the default.** Replica acquisition
  pins, and the pin path finalizes to the cloud store — this is precisely
  the daemon's replicate mode on a serverless node, and it uploads
  everything the replica holds without also making every transient
  foreground read durable (`all` would). What the replica doesn't want,
  the bucket doesn't pay for.
- **`retention: current` by default, 30-day grace.** "Replicate everything
  on the network" means what the network *has*, not everything it has ever
  had; `forever` is a plan upgrade the control plane can grant per org
  without any data-plane change (§3.3 carries it per network).
- **`replica_release_floor` stays 1.** The hosted replica never releases a
  root it cannot see another material holder for — the service must not be
  the actor that turns "leaves the current tree" into "ceases to exist"
  when it holds the last copy.
- **Budget is the org's `budget_bytes`, enforced as a moving per-replica
  ceiling.** The engine's budget is a per-replica admission ceiling
  (REPLICATION) and no org-level ceiling exists, so the tenant loop
  re-derives each replica's budget on every tick: the org budget minus
  bytes the tenant's *other* replicas hold. Approximate — concurrent
  admissions can briefly overshoot by one acquisition per space — but
  convergent, and enforcement inherits the right failure mode: hitting it
  stops new acquisition and surfaces in the status heartbeat and the
  replication panel (`held_back`) rather than evicting anything.
- **Delegations are honored, not created.** The hosted node is a full
  member and replicates delegation records like any peer, admitting the
  org's delegates on the org's say-so. It never issues delegations of its
  own.

### 4.6 Shutdown

Process shutdown (SIGTERM = SIGINT, as the daemon insists): broadcast to
every tenant's loops, `join` them, then per tenant `Node::shutdown()` —
its four-step order (close admission, drain socket streams, retire
endpoints) already handles the no-sockets case as a cheap no-op — and
finally the tail ship by that tenant's replicator (§5.3), so the pod
leaves nothing behind that the replica stream does not carry. The 30-second termination allowance from
SERVERLESS scales: tenants shut down concurrently, and the deployment
grants the pod the same 30 s it grants a serverless daemon. A pod killed
without grace loses at most the replication interval (§5.3), the same
asynchrony bound Litestream accepts.

---

## 5. Storage layout

### 5.1 One bucket, per-tenant roots

Every tenant's `CloudConfig` names the same bucket with a distinct OpenDAL
`root`:

```
tenants/<org>/<network>/        ← OpenDAL root for this tenant
  cas/<hh>/<hex>                ← payload   (append-only, SERVERLESS §6.5)
  cas/<hh>/<hex>.obao           ← outboard
  uploads/<id>/<n>              ← multipart staging (unused in v1: no write
                                   surface exists, §4.4)
db/<org>/<network>/             ← tenant DB replica stream (§5.3)
dp/<shard>/desired.json         ← fail-static desired-state cache (§4.2)
```

The CAS layer supports the alternative — many nodes on one shared root,
content-addressed dedup across them, protected by append-only finals — and
this design **rejects it for tenants**, for four reasons that outweigh the
dedup:

1. **Confidentiality.** In a shared root a content hash is a read
   capability; cross-tenant dedup is a cross-tenant oracle ("someone else
   already has this byte-identical file") and a cross-tenant read given a
   leaked hash. Between one org's own nodes that is the trust model;
   between strangers it is not.
2. **Offboarding.** "Delete the tenant" must be a prefix delete an operator
   can audit, not a refcount problem over an append-only namespace that
   deliberately has no refcounts.
3. **Metering.** Held-bytes billing falls out of a prefix inventory.
4. **Blast radius.** A bug in one tenant's node can, at worst, write
   garbage under one prefix.

The one place this supersedes "final `cas/` objects are append-only": the
retirement delete (§6) is performed by the *service*, from outside any
node, on a prefix whose node is already retired and whose identity is never
reused. The node-level invariant — no running node has a path that deletes
a final object — stands untouched.

Within a tenant, dedup still applies in full: the org's own nodes and the
hosted replica share content addresses the way SERVERLESS designed.

### 5.2 Data dirs, scratch, and the cache

`<base>/tenants/<org>/<net>/` is the tenant's `data_dir`: SQLite,
`store/` cache, `cloud/` scratch — all of it on the pod's ephemeral
volume, all of it either replicated out (§5.3) or reconstructible, none of
it mourned on reschedule. Per-tenant dirs give each tenant its own
scratch generation marker for free — one tenant's cold start wipes one
tenant's cache — and keep the engine's thread-local store-reentry guard
happy, because a blocking task naturally touches exactly one tenant's
store.

`cache_bytes` is always explicit: the volume budget divided by the shard's
tenant capacity. The Unix free-space default is a single-node policy and
is documented (by the store's own code) to thrash when N nodes share a
volume; the data plane never relies on it. Cache here is pure performance
— every cached byte is `durable` in the tenant's prefix first — so the
split can be lopsided or stingy without threatening correctness.

### 5.3 Database durability, and what a lost database costs

The data plane runs on **ephemeral pods with no durable local storage**:
everything under `<base>` — every tenant's SQLite file, cache, and scratch
— is a working copy that a reschedule deletes. So the SERVERLESS posture
(local file is a working copy, the object-store replica is what survives)
is not one deployment option here; it is the only description of the
system, and the data plane **manages the database replicas itself,
in-process**. There is no Litestream sidecar, no operator-maintained
replication config, and no volume to mount: `synch-dp` links the
replication library in and drives one replica per tenant (`dbrepl`),
against the same object store the CAS already uses.

A sidecar was considered and rejected. The tenant set is dynamic — DBs
appear and retire with every reconciler pass — and a config-file-plus-
restart cycle per membership change is exactly the kind of process
choreography an ephemeral pod is bad at. In-process replication follows a
tenant's lifecycle for free (provision starts it, drain flushes and stops
it), reads its credentials from the same environment the CAS client does,
and keeps the repository's one-self-contained-binary posture: SQLite is
already compiled in; its replication should not be the one function
outsourced to a Go binary in the image.

Shipping the stream is **not this repository's code**. `synch-dp` depends
on [`celld-ltx`](https://github.com/denoland/celld/tree/main/crates/ltx), a
Rust reimplementation of Litestream v0.5 writing the LTX format, pinned by
git revision. `crates/synch-dp/src/dbrepl.rs` is the thin part: it points
that library at a tenant's database and its prefix and drives it on an
interval.

That division is deliberate, and the earlier draft of this document got it
wrong by specifying a WAL shipper of our own. Shipping a write-ahead log
is a specialist's problem wearing an easy problem's clothes. SQLite spills
a large transaction's pages into the log *before* it commits, and rolls
back by rewinding its own high-water mark while leaving those bytes for
the next transaction to overwrite — so a shipper that goes by file length
ships frames that are about to be replaced and then misses their
replacements, silently, with the stream reporting healthy throughout.
Getting it right means tracking commit boundaries, verifying SQLite's
frame checksum chain to notice a log rewritten behind you, and ordering a
snapshot against a checkpoint so a failed upload cannot strand writes.
Litestream has learned those over years of production; inheriting them
costs one dependency, and rediscovering them costs correctness we would
only find out we lacked from a customer's lost database.

The stream lives under `db/<org>/<network>/`, in whatever layout the
library writes — LTX files by compaction level, with its own snapshot and
compaction policy. This design does not specify that layout and must not:
it is the library's, and pinning our own description of it here is how a
document starts lying after an upgrade.

- **Shipping**: on a short interval (default 1 s) the replicator captures
  what the database has committed into local LTX segments and uploads
  them. It owns checkpointing outright — engine change **(d)**, §7.3 — so
  nothing can recycle a frame it has not shipped. Acknowledged-but-
  unshipped writes are bounded by the interval; as with Litestream, the
  replica can only be *behind* the bucket's CAS state, never ahead, which
  is the direction §8.3 of SERVERLESS already reasons about.
- **A thread per tenant**: a replica owns a SQLite connection, so it is
  `Send` but not `Sync`, and the library's `sync` holds `&self` across an
  await — its future is therefore not `Send` and cannot be handed to
  `tokio::spawn` at all. Each replicator owns one thread running a
  current-thread runtime, and the type the tenant holds is a `Send + Sync`
  handle onto it. This is not a workaround: the bound is telling the truth
  about a connection that must not be touched from two threads. Two things
  fall out of it that are worth having anyway — the blocking half of a
  capture is real SQLite work and belongs off the async workers, and
  commands are served one at a time, so a final ship can never interleave
  with a tick.
- **Restore**: on provisioning, before any init, at `TXID(0)` — meaning
  "whatever is latest". A plan that comes back unsatisfiable at that TXID
  can only mean the prefix holds no LTX files at all, so the library's
  `TxNotAvailable` and `NoSnapshots` are read as *empty stream* and
  nothing else; every other failure stays a failure and parks the tenant.
  That distinction is load-bearing: "there is nothing here" initializes a
  new identity, "I could not tell" must not.
- **The stream is authoritative, not the disk**: a database found in a
  tenant directory is discarded and the stream replayed over it. These pods
  have no durable storage, so a local database is not evidence of anything
  — it is debris from a drain whose directory removal failed, or from a
  volume that outlived its last owner — and keeping it is how a stale copy
  ends up promoted over a newer stream (see **Single writer** below for why
  nothing downstream catches that). The cost is bounded and already
  accepted: writes made but not shipped, which this section caps at one
  replication interval on any ungraceful stop. The single exception is a
  stream that holds *nothing*, where the local copy is the identity: that
  is the crash-between-`init`-and-register path (§4.3), and it is why the
  disk check is not redundant with the restore.
- **Drain and shutdown**: ship the tail, then close. The close is what
  releases the library's long-running read lock, and the drain waits for
  the thread to actually end — a caller that closes in order to remove the
  data directory needs the connection gone, not merely asked to go.
- **Single writer, and nothing enforces it**: correctness of the stream
  assumes one live replicator per tenant DB, which is the same assumption
  the node itself makes (`replicas: 1`, SERVERLESS §1) and is provided by
  shard ownership (§7.2) — *only* by shard ownership. It is worth being
  blunt about this, because an earlier draft of this document claimed a
  backstop that does not exist. `check_database_behind_replica` is not a
  refusal: when the local database is behind its stream the library seeds
  the remote's newest segment as a local baseline so the next capture
  snapshots forward. That is exactly right after a restore, where the local
  copy has no segments of its own yet, and it is why the call is made — but
  it means a *stale* database is repaired into a position to ship over the
  stream rather than turned away. Two pods writing one stream therefore
  lose the loser's writes silently, and the only thing standing between the
  fleet and that is the rendezvous filter. Discarding leftover directories
  (above) closes the reprovision half of it; the rolling-shard-count half is
  a real exposure of one reconcile interval, named in §8 rather than papered
  over.
- **S3 or nothing**: the library ships two clients — S3-compatible object
  storage and a local directory — so a GCS or Azure deployment is refused
  at startup rather than per tenant. That is a real narrowing of what the
  CAS itself supports, and it is the honest one: a shard that cannot write
  a database stream would mint device keys, get them named in customer
  zones, and lose every one of them on its first reschedule.
- **Protection**: not this layer's business, and an earlier draft was
  wrong to make it so. The DB stream carries the device secret and does
  want protecting, but the place to protect it is the bucket — SSE-KMS, a
  customer-managed key, whatever the deployment already runs for
  everything else it keeps there (§9). An envelope invented here would be
  one more key to rotate, escrow and lose, buying nothing the storage
  layer does not already do better.

It is worth being precise about what the database is *for*, because it is
less than it looks:

- **File bytes**: in the tenant's CAS prefix, append-only, not in the DB.
  A rebuilt node re-adopts them (`adopt_remote_if_present` /
  `require_pair`) without re-fetching or re-uploading.
- **Customer metadata**: origin tries, re-replicated from the customer's
  own nodes by anti-entropy. Recoverable whenever the network is alive.
- **The device secret key and the replica's own holds**: the genuinely
  local state.

So a lost tenant DB with a live customer network costs: one key
replacement (a new key registered under the same label via §3.3's PUT —
the old key is revoked control-plane-side, the zone republishes, customers
re-bind), one metadata re-sync, and a `require_pair` pass over held
roots. What it does *not* cost is re-uploading — or even re-fetching —
terabytes: the engine's fetch path consults the durable backend *before*
falling back to peers (`fetch_groups_from` opens with
`ensure_ranges`, whose miss path is `adopt_remote_if_present`), so a
rebuilt node re-adopts the bucket's objects in place.

The case the replicator actually protects is the one the service exists
for:
**the hosted replica holds the last copy**. If the customer's nodes are
gone *and* the tenant DB is gone, the bytes still sit in `cas/` but the
tries that name them — filenames, versions, structure — are unrecoverable.
That is why the DB replica is part of the durability contract and not an
optimization, and why (per SERVERLESS) it is protected separately from the
CAS prefix: it also contains the device secret.

---

## 6. Lifecycle of the hosted device

**Onboard**: flag on → next poll lists the network → provision (§4.3) →
device registered, zone publishes → identify → replicate. Time to first
replicated byte is dominated by customer nodes' zone-refresh TTL (they
must admit the new member before it can fetch), which the 300 s data TTL
keeps in minutes.

**Rotate**: the hosted device rotates keys with the standard window
(DESIGN §3.4): generate, `PUT` the new key (two keys under one label),
`swap_active_endpoint`, `DELETE` the old one to mark it retiring, and
`DELETE …?revoke=1` a TTL later once customer bindings have moved. No
customer involvement; that is what the rotation design bought. The routes
are built and the client can call them; what does not exist yet is
anything that *schedules* a rotation, so today this is an operator action
rather than a standing one.

**Disable**: flag off → the control plane deletes the network's `cloud-*`
devices in the same commit (zone shrinks; customer nodes drop the binding
at expiry) and stamps `cloud_disabled_at` → next poll omits the network →
the tenant drains: loops stopped, `Node::shutdown`, state `Retired`, local
dir deleted. The object-store prefix and DB replica enter the **retention
hold** (default 30 days, control-plane policy): re-enabling within it is a
cheap re-provision that restores the DB and re-adopts the prefix.

**Collect**: once the hold elapses the control plane lists the network in
`collect`, and the fleet deletes `tenants/<org>/<net>/` and
`db/<org>/<net>/` and reports it with §3.3's `DELETE …/storage`. The order
is the whole of the safety: bytes first, record second, so a crash in
between re-collects an already-empty prefix rather than leaving the
control plane believing storage is gone while the bill continues. Two
independent locks guard it, because this is the one operation in the
design that destroys customer data — the control plane refuses to mark a
still-hosted network collected, and the data plane refuses to collect a
tenant its own shard is running. The hold is control-plane policy for the
same reason the flag is: the service holding the bucket credentials should
not also hold the opinion about when a customer's bytes may go.

**Shard loss**: a shard pod dies — the *normal* event, since pods are
ephemeral. Its tenants' desired state still lists them; the replacement
pod with the same ordinal restores each DB from its replica stream and
resumes each identity — same key, same label, no zone change at all. Only
if the DB replica is also gone does the key-replacement path (§5.3) run.

---

## 7. Scaling and sharding

### 7.1 What a tenant costs

| resource | per tenant | note |
|---|---|---|
| UDP socket (iroh endpoint) | 1 | plus shared relay/pkarr connections |
| SQLite | 1 file, 1 serialized connection | all access via the blocking pool |
| OS threads | 0 | with engine change (a); today 4 (socket pool) |
| tokio tasks | ~8 standing | §4.4 loop set |
| DB replicator | 1 standing task, 1 read connection | in-process, §5.3 |
| memory | O(trie working set + cache index) | dominated by anti-entropy peaks |

Shared, once per process: the tokio runtime and its blocking pool (sized
deliberately: every store touch of every tenant crosses it), one
`Arc<DnssecResolver>` (the TUF/Rekor pin walk is per-process state and
must be — one Sigstore outage should cost one attempt a day, not N), the
reqwest client, the metrics registry.

The practical v1 ceiling is file descriptors and blocking-pool contention,
not CPU: **O(hundreds) of networks per shard**, which one instance
("scale-to-one", the serverless posture) serves for a long time before
sharding matters.

### 7.2 Sharding, when it matters

Shards are declared, not discovered: `SYNCH_DP_SHARD=2`
`SYNCH_DP_SHARDS=4`. Each shard runs the same reconciler over the same
desired-state document, filtered by **rendezvous hashing on the network
id** — no assignment state in the control plane, no coordination between
shards, and a shard-count change moves ~1/n of tenants. Everything durable
about a tenant is keyed by network, never by shard — the CAS prefix, the
DB stream, the `cloud-1` device identity (§3.4) — so a handover is: the
losing shard's next reconcile drains the tenant (shipping the DB tail),
the gaining shard restores that stream and resumes the *same* identity; no
zone change, no key change, no customer-visible event. The race — a
rolling shard-count change where both pods briefly run the tenant — is one
identity written by two processes, and — stated plainly because §5.3's
first draft claimed otherwise — **nothing catches it**. The replication
library does not refuse a database behind its stream; it repairs it into a
position to ship over one. So for the reconcile interval in which both pods
believe they own the tenant, both replicate, and the loser's writes leave
the only durable copy. Bounded by one reconcile interval and by how rarely
the shard count changes, and mitigated by doing shard-count changes as a
stop-then-start rather than a rolling update — but a real cost of this
design and not an eliminated one. The fix that would eliminate it is a
lease on the stream, which the library has no notion of.

Redundant hosting is a second *slot* (`cloud-2`, its own key, DB stream,
and CAS claims over the same tenant prefix), assigned to a different shard
by hashing on (network, slot) — future work only because billing and the
status API assume one row per network today.

### 7.3 Engine changes required

Small, and all of independent value:

- **(a)** `socket_workers: 0` skips the socket pool (§4.4).
- **(b)** `SYNCH_CLOUD_URL` is a process-global tunnel override; the data
  plane must simply never set it (documented footgun, no code change).
- **(c)** A public equivalent of the CLI's `LifecycleLock` (flock per data
  dir) in the engine, so an embedder gets the two-daemons-one-dir refusal
  the daemon has; today it is `pub(crate)` in `synch-cli`.
- **(d)** The store yields WAL checkpointing to the embedder: a mode that
  sets `wal_autocheckpoint = 0` on the writer and exposes an explicit
  checkpoint call, so the in-process DB replicator (§5.3) checkpoints only
  after frames are shipped. Today the store assumes an external
  checkpointer (its raised `busy_timeout` is Litestream-shaped); this
  makes the same contract available to one living in the process.

None of the engine's replication, storage, or membership code changes.

---

## 8. Failure matrix

| failure | effect | recovery |
|---|---|---|
| control plane unreachable | desired state frozen (fail-static, §4.2); no teardowns, no onboards | resumes at next successful poll |
| zone never names a registering tenant | tenant parks in `Identifying`, polling at 30 s; alert after a threshold | operator inspects; the PUT is idempotent |
| provider outage | writes fail closed (SERVERLESS §4): replica wants stay pending, nothing acks that isn't durable | wants retry; no data loss by construction |
| one tenant's loop panics | that tenant restarts with backoff; process and other tenants unaffected | supervisor, §4.4 |
| tenant DB lost, network alive | key replacement + metadata re-sync + re-adoption; no re-upload | §5.3 |
| tenant DB lost *and* customer nodes gone | names and structure lost despite bytes surviving — the case DB replication exists for | prevented, not recovered: the replica stream is part of the contract |
| shard pod rescheduled | the normal event: replacement pod restores every tenant DB from its stream; identities unchanged | §6 |
| leftover tenant directory on a reused volume | discarded: the stream is replayed over it, losing at most that pod's unshipped tail | §5.3 |
| **rolling shard-count change** | **two pods may own one tenant for a reconcile interval and both write its stream; the loser's writes are lost silently — nothing detects this** | **not recovered: change `SYNCH_DP_SHARDS` as a stop-then-start, never a rolling update (§5.3, §7.2)** |
| pod killed without grace | up to one replication interval of DB writes unshipped; replica behind, never ahead | restore + re-sync closes the gap, §5.3 |
| bucket prefix deleted by mistake | `NotFound` heal (SERVERLESS §6.4): durable claims withdrawn, wants re-staged, re-fetched from customer nodes while they hold copies | the one unrecoverable case is prefix loss *and* customer loss together |
| budget exhausted | admission stops; the engine's own `held_back` shows in the replication panel; nothing evicted. The metering heartbeat does **not** carry it — `wanted` climbing against a flat `held_bytes` is what an operator reads instead | org raises plan; acquisition resumes |
| disk pressure on shard | per-tenant explicit `cache_bytes` prevents cross-tenant eviction storms; cache-only data is re-hydratable | §5.2 |

---

## 9. Security considerations

- **The operator can read hosted content.** A replica holds plaintext;
  hosting a replica means trusting the host with it, exactly as trusting
  any peer with a replica does. This is stated in the product, not
  discovered in the fine print. What bounds it: per-tenant prefixes and
  keys (no confused-deputy path from tenant A to tenant B's bytes),
  provider-side encryption at rest, access logging on the bucket, and the
  fact that enabling hosting is an explicit org-admin act. A
  partial-privacy future exists in the protocol already — delegate-scoped
  hosting, where the hosted node is admitted as a delegate (DESIGN §3.5)
  for named spaces only and scoped replication (DESIGN §5.5) redacts the
  rest down to the filenames — and is deliberately future work: it trades "replicate
  everything" for "replicate exactly this", a different product tier.
- **Device secrets live in the DB streams, and the bucket protects them.**
  A tenant's database carries its device secret key, so `db/<org>/<network>/`
  is the one prefix where read access yields identities rather than merely
  content. Protecting it is the storage layer's job and is a deployment
  requirement, not a code path: encryption at rest on the bucket (SSE-KMS
  or a customer-managed key), and a bucket policy that does not grant this
  prefix more widely than the CAS one. The service deliberately does not
  wrap an envelope of its own around these objects — that would be one
  more key to rotate, escrow and lose, buying nothing the provider does
  not already do better, and its loss would strand every tenant's identity
  at once.
- **Blast radius of a compromised data-plane host**: every hosted
  network's content and device secrets on that shard — but no customer
  device keys, no zone keys, no control-plane credentials beyond the
  data-plane key, which reaches only `/dp/v1`. Zone authority stays in the
  control plane; a compromised shard cannot admit new members anywhere.
- **Blast radius of a leaked data-plane key**: enumeration of hosted
  networks and forged heartbeats; device registration is the one write,
  and it is confined to the reserved `cloud-*` label namespace, so it
  cannot displace or impersonate a customer device. Keys are mintable and
  revocable only at the operator CLI.
- **The hosted node writes nothing customer-visible but its own trie.** A
  replica publishes no file entries (REPLICATION, by construction); the
  hosted origin's trie carries blob ads, `m:self`, and replica claims. No
  socket admission (§4.4) means no code execution surface. The browse
  tunnel it attaches is read-only by wire construction (no write opcode
  decodes).
- **In-process isolation is by ownership, not sandboxing.** Tenants share
  an address space; the guarantee against cross-tenant data flow is that
  no code path holds two tenants' stores (enforced in practice by the
  engine's own off-runtime and reentry guards, and by the reconciler's
  one-tenant-per-task structure). An org that requires hard isolation is a
  dedicated-shard tier, not a design change: the shard filter already
  makes "a shard that hosts one org" a configuration.
- **Rekor/TUF pinning** rides per-tenant DBs (the engine stores pin state
  in the node's config table), so a tenant restored from its replica
  stream keeps
  its transparency-log pins; the shared resolver bounds Sigstore traffic.

---

## 10. Observability and metering

- Prometheus per shard. What is actually exported today, rather than a
  wish list: `synch_dp_tenants_running` / `_parked`,
  `synch_dp_poll_failures`, `synch_dp_reconcile_failures`,
  `synch_dp_desired_generation`, `synch_dp_storage_collected`, and — per
  tenant, labelled `{org, network}` — `synch_dp_held_bytes`,
  `synch_dp_held_roots`, `synch_dp_wanted` and
  `synch_dp_replication_failures`.
- **`synch_dp_replication_failures` is the one to alert on**, and it is
  here because an earlier draft promised an operator could alert on a
  stalled stream while exporting nothing that showed one. It counts a
  tenant's *consecutive* failed ship attempts and resets on success, so it
  answers "is this stream stuck now". A bucket policy granting
  `ListBucket` but denying `PutObject` on `db/` is enough to make a tenant
  fail every ship while reporting `running` and heartbeating healthy
  held-byte counts, until a reschedule finds an empty stream. Anything
  above zero for more than a few scrapes is that.
- The **stored heartbeat** (§3.3) is the billing record: held bytes per
  network, written by the tenant that holds them, timestamped, surviving
  the tenant being down (a stale heartbeat *is* the alert).
- The **live view**, for orgs with browse enabled (§2), is the existing
  replication panel over the browse tunnel — the hosted node answers the
  same what-do-you-replicate question every attached daemon answers (CP
  README), labelled with its `cloud-1` identity, so "is the cloud replica
  keeping up" is a question the dashboard already knows how to ask and
  render, with zero new UI.
- `synch-dp status` (local admin socket, read-only): per-tenant state
  table, the parked-in-`Identifying` list, last poll generation.

---

## 11. Implementation plan

### Crate layout

```
crates/synch-dp/
  src/main.rs          # config from env, runtime, signals, metrics server
  src/config.rs        # the environment, the shard filter, the slot
  src/control.rs       # /dp/v1 client: poll (ETag), register, heartbeat
  src/reconciler.rs    # desired-state diff, fail-static cache, shard filter
  src/tenant.rs        # per-network lifecycle: provision, identify,
                       #   loop set, supervise, drain, retire
  src/spaces.rs        # space-driven replica ensure (§4.5 — never removes)
  src/dbrepl.rs        # per-tenant DB replica, driven over `celld-ltx` (§5.3)
  src/store.rs         # the service's own bucket client (cache, offboarding)
  src/metrics.rs
```

### What is built

1. **Engine groundwork.** Change (a) `socket_workers: 0` skips the socket
   runtime and the SSH host key entirely; change (c)
   `synch_engine::LifecycleLock` (the daemon's own lock, moved into the
   engine so an embedder gets it and the two cannot drift); change (d)
   `Checkpointing::Embedder` plus `Store::db_path` — the whole of what the
   replication library needs, which is a database to point at and a
   promise that nobody else checkpoints it.
2. **Control plane.** Migration v12 (`cloud_hosted`, `cloud_disabled_at`,
   `dataplane_keys`, `network_hosting_status`, the `system-dataplane`
   user), the admin toggle with its audit events and its dashboard switch,
   the five `/dp/v1` routes, the `Dataplane` principal that `check_org`
   refuses outright, the reserved `cloud-*` label namespace, and
   `controlplane dataplane-key mint`.
3. **`synch-dp`.** Restore-or-init, register, identify, replicate,
   converge, rotate, heartbeat, collect, drain.
4. **Offboarding is closed.** Disabling drains the tenant and removes its
   local directory; the control plane lists the network for collection
   once its hold has elapsed, and the data plane deletes the CAS prefix and
   the database stream, then reports it. Two locks guard the one operation
   here that destroys customer data: the control plane refuses to mark a
   still-hosted network collected, and the data plane refuses to collect a
   tenant this shard is running.
5. **Rotation is driven**, not merely possible: the tenant's own database
   carries the deadline, so a rotation survives the pod that started it.

### What a v2 would add

- **Redundant hosting** — a second slot (`cloud-2`) on a different shard.
  The slot model (§3.4) and the shard filter are built for it; what is
  missing is billing and a status API that assume one row per network.
- **Delegate-scoped hosting** (§9): the hosted node admitted for named
  spaces only, so the fleet never sees the rest. A different product tier,
  not a fix.
- **Cross-shard handover exercised against a live fleet.** The rendezvous
  filter is implemented and unit-tested; no test moves a running tenant
  between two processes.
- **Restore fuzzing** over torn and forked streams. Restore is exercised
  on every provisioning, and a unit test round-trips a shipped stream back
  into a database; the library carries its own tests for torn and
  non-contiguous LTX chains, and this crate adds no fuzzing of its own.

---

## 12. Costs, stated

- **Storage residue within a tenancy.** Final `cas/` objects are
  append-only for the life of the tenant; a churn-heavy network pays for
  history until roots age out of grace, and the prefix is eventually
  compacted only by offboarding. The release floor (§4.5) sharpens this:
  a root no other member still holds is *never* released, whatever the
  grace says — under `current` retention the hosted prefix converges to
  the current tree **plus every last copy**, which is the promise, priced.
  This is SERVERLESS's stated cost, inherited knowingly — the retention
  hold and per-tenant metering make it a billed cost rather than a hidden
  one.
- **No cross-tenant dedup.** Two orgs storing the same bytes pay twice.
  Chosen in §5.1; the confidentiality and offboarding wins are worth more
  than the duplicate gigabytes.
- **The database replica is load-bearing, and now in-process.** The
  last-copy case rests on replication this service drives itself rather
  than on a sidecar an operator configures — a shape ephemeral pods and a
  dynamic tenant set left without a leg to stand on (§5.3). What is *not*
  taken on is the shipping algorithm: that is `celld-ltx`, pinned by
  revision, and the cost moved rather than vanished — this fleet now owns
  keeping that pin current and reading its changelog. The other
  mitigations are owed too: restore is exercised on every pod reschedule
  rather than only in disasters, and a stalled stream is an incident, not
  a warning.
- **One more standing fleet.** The data plane is a new operated service
  with real state. Everything in this design that could be a daemon
  feature was kept a daemon feature precisely so that a customer who
  distrusts the fleet can run `synch replica add` on their own serverless
  node and get the same durability under their own account — the hosted
  product is the same mechanism with the operations bill moved, which is
  what makes it honest.
