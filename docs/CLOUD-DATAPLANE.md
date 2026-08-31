# Cloud data plane — multi-tenant hosted replicas

Status: design proposal v1 · 2026-08-31

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

Section references (§) are to DESIGN.md unless prefixed. `SERVERLESS §` is
docs/SERVERLESS.md, `REPLICATION` is docs/REPLICATION.md, `CP README` is
control-plane/README.md.

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
   behind it. It shows up in the existing replication panel (CP README §
   cloud browse: the "what does each node replicate" question is asked of
   every attached daemon, and the hosted node attaches like any daemon), so
   the org can watch coverage converge without any new UI.
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

Three routes under `/dp/v1`, all requiring the data-plane principal.

**`GET /dp/v1/networks`** — the desired-state document. Every network of
every org with `cloud_hosted = 1`:

```json
{ "generation": 4183,
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
- `generation` is a monotonic counter bumped by any change to the set or
  its fields; the response carries an `ETag` derived from it so the
  steady-state poll is one 304 per interval.

**`PUT /dp/v1/networks/:org/:net/device`** — idempotent registration of the
hosted device's key:

```json
{ "label": "cloud-1", "nk": "<52-char z-base-32 device key>" }
```

Creates the `devices`, `device_keys` (`state='active'`), and
`network_devices` rows in one `zone_mutation` transaction — the same
transaction shape as `join_device`, so **the commit is the publish** and the
zone names the key immediately. Re-`PUT` with the same `(label, nk)` is a
200 no-op. `PUT` with the same label and a *new* key opens the standard §3.4
rotation window (two keys under one label) when the old key is `active`, and
replaces outright when the old key is already `revoked` — which is the
recovery path after a data-plane disk loss (§6).

Constraints inherited from the schema and enforced here: `label` must match
`cloud-[0-9]+` (the reserved namespace, §3.4), one live `nk` binds one
device globally (`device_keys_live_nk`), at most two records per label (the
rotation window, `zone/build.gleam` validation).

`devices.created_by` is `NOT NULL REFERENCES users(id)`; migration v12
seeds one system user (`system-dataplane`, no email, no sessions possible)
that these rows reference, so no human's id is impersonated and the audit
trail names the service.

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

Device labels matching `cloud-[0-9]+` are reserved: `join_device` and the
dashboard refuse them for customers (409 `reserved-label`), and only the
data-plane principal may create them. The suffix is the **shard ordinal**
(§7), so a network hosted redundantly by two shards carries `cloud-1` and
`cloud-2` as two ordinary devices — which is all hosting redundancy has to
be, because two replicas of one network is already a thing the protocol
does.

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
would mean multiplexing an identity, which §3.1 spent its whole design
budget keeping singular. Multiple `Node`s in one process is the supported,
tested configuration (the engine's own cluster tests run exactly this way).

What every tenant costs, and what is shared, is accounted in §7.

### 4.2 The reconciler

The core of the service is a desired-state loop, deliberately shaped like
the engine's own standing loops (interval + jitter, work is idempotent,
missing a tick costs latency not correctness):

1. **Poll** `GET /dp/v1/networks` (default every 60 s, `If-None-Match`).
   On success, persist the document to `<base>/desired.json` before acting
   on it — the data plane **fails static**: if the control plane is
   unreachable for an hour, the current tenant set keeps replicating; no
   tenant is ever torn down because the API was down (teardown requires a
   *successful* poll that omits the network).
2. **Diff** desired against running, filtered to this shard (§7):
   - *new network* → provision (§4.3);
   - *running and desired* → converge policy: budget or retention changed →
     `set_replica` on every configured replica;
   - *running, not desired* → drain and retire (§4.6, §6);
   - *desired but failing* → the tenant supervisor owns retry; the
     reconciler only reports.
3. **Report**: per-tenant status POSTs (§3.3), Prometheus metrics labelled
   by org/network, one log line per state transition.

Tenant states, persisted per tenant in `<tenant-dir>/state`:

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
   with `{label: "cloud-<shard>", nk}`. The commit publishes the zone.
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
    name: format!("cloud-{shard}"),      // never the host's hostname
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
| `run_cloud` | yes | the browse/replication tunnel — this is what puts the hosted node in the org's replication panel for free |
| uploads sweeper | yes | gateway/API uploads may target the hosted node |
| `run_scanner`, `run_watcher` | no | no filesystem sources exist (cloud CAS refuses them anyway) |
| `run_checkouts` | no | nothing is materialized |

Plus the daemon's one-shot startup helpers per tenant:
`reopen_interrupted_uploads`, `readopt_self_on_startup`,
`scan_publish_push`.

**Sockets are refused, permanently.** The hosted node closes socket
admission at open and never reopens it. A hosted replica stores and serves
bytes; executing customer socket code is compute hosting, a different
product with a different isolation story. This wants one small engine
change — **(a)** `socket_workers: 0` skips starting the `SocketPool`
entirely (today `Node::open` starts it eagerly; N tenants × default 4 is
the process's largest thread bill for a capability this service must not
have).

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

— and remove replicas for spaces that have left the view entirely (no
origin publishes them and grace has elapsed), with `--pin-held` semantics
*not* used: the standing policy leaves with the space, holds release
through the ordinary grace machinery.

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
- **Budget is the org's `budget_bytes`, split across the tenant's
  replicas.** The budget is an admission ceiling (REPLICATION), so hitting
  it stops new acquisition and surfaces in the status heartbeat and the
  replication panel (`held_back`) rather than evicting anything — exactly
  the failure mode a paid quota should have.
- **Delegations are honored, not created.** The hosted node is a full
  member and replicates delegation records like any peer, admitting the
  org's delegates on the org's say-so. It never issues delegations of its
  own.

### 4.6 Shutdown

Process shutdown (SIGTERM = SIGINT, as the daemon insists): broadcast to
every tenant's loops, `join` them, then per tenant `Node::shutdown()` —
its four-step order (close admission, drain socket streams, retire
endpoints) already handles the no-sockets case as a cheap no-op — and
finally a checkpoint-and-ship of that tenant's WAL tail by the in-process
database replicator (§5.3), so the pod leaves nothing behind that the
replica stream does not carry. The 30-second termination allowance from
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
  uploads/<id>/<n>              ← multipart staging, swept
db/<org>/<network>/             ← tenant DB replica stream (§5.3)
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
replication config, and no volume to mount: `synch-dp` carries a
WAL-shipping replicator (`dbrepl`, one standing task per tenant) that
speaks the same OpenDAL operator the CAS already uses.

A sidecar was considered and rejected. The tenant set is dynamic — DBs
appear and retire with every reconciler pass — and a config-file-plus-
restart cycle per membership change is exactly the kind of process
choreography an ephemeral pod is bad at. In-process replication follows a
tenant's lifecycle for free (provision starts it, drain flushes and stops
it), shares credentials and retry/timeout layers with the CAS client, and
keeps the repository's one-self-contained-binary posture: SQLite is
already compiled in; its replication should not be the one function
outsourced to a Go binary in the image.

The replica stream follows the generation model Litestream proved:

```
db/<org>/<network>/
  <generation>/snapshot            ← compressed full copy at generation start
  <generation>/wal/<index>         ← WAL segments, shipped in order
```

- **Generation**: a random id minted whenever the replicator starts from a
  database it did not restore itself (first init, or restore from an older
  generation). Within a generation, `snapshot + wal/*` replays to the
  current database; frame salts and checksums in the WAL segments are what
  make a torn or duplicated upload detectable on restore.
- **Shipping**: the replicator holds its own read connection beside the
  store's single writer (the store's 30 s `busy_timeout` exists precisely
  because a replication checkpointer contends with it), reads new WAL
  frames on a short interval (default 1 s, batched), uploads a segment,
  and only then checkpoints. It owns checkpointing outright — engine
  change **(d)**, §7.3 — so the writer can never truncate WAL frames that
  have not been shipped. Acknowledged-but-unshipped writes are bounded by
  the interval; as with Litestream, the replica can only be *behind* the
  bucket's CAS state, never ahead, which is the direction §8.3 of
  SERVERLESS already reasons about.
- **Restore**: on provisioning, before any init — list generations, pick
  the newest with a contiguous, checksum-valid WAL, download and replay,
  then start a fresh generation. Only when nothing restorable exists does
  `Node::init` run, exactly like a serverless daemon's boot.
- **Drain and shutdown**: final checkpoint, ship the tail, write a
  generation close marker, stop. This is the last step of §4.6.
- **Single writer**: correctness of the stream assumes one live replicator
  per tenant DB, which is the same assumption the node itself makes
  (`replicas: 1`, SERVERLESS §1) and is provided by shard ownership
  (§7.2). A shard-handover race — two pods briefly believing they own a
  tenant — writes two *different generations*, not interleaved garbage;
  restore picks one, and the loser's divergence is repaired by the ordinary
  key-replacement path below. The generation model turns split-brain from
  corruption into a recoverable fork.
- **Protection**: the DB stream contains the device secret, so
  `db/<org>/<network>/` objects are additionally encrypted by the
  replicator with a per-deployment key from the environment (KMS-backed
  where available) before upload. Bucket read access alone then yields
  content — which the CAS prefix already yields — but not identities. This
  is the "protect it separately from the CAS prefix" rule of SERVERLESS,
  discharged without needing a second bucket.

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
roots. What it does *not* cost is re-uploading terabytes.

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

**Rotate**: the hosted device rotates keys with the standard §3.4 window,
driven by the data plane on its own schedule (and forced by the operator on
suspicion): generate, `PUT` the new key (two keys under one label),
`swap_active_endpoint`, then retire the old key control-plane-side. No
customer involvement; that is what the rotation design bought.

**Disable**: flag off → the control plane deletes the network's `cloud-*`
devices in the same commit (zone shrinks; customer nodes drop the binding
at expiry) and stamps `cloud_disabled_at` → next poll omits the network →
the tenant drains: loops stopped, `Node::shutdown`, state `Retired`, local
dir deleted. The object-store prefix and DB replica enter the **retention
hold** (default 30 days, control-plane policy): re-enabling within it is a
cheap re-provision that restores the DB and re-adopts the prefix; after
it, a scheduled job deletes `tenants/<org>/<net>/` and `db/<org>/<net>/`
and the hold's audit row records who disabled and when it fell due.

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
shards, and a shard-count change moves ~1/n of tenants. A tenant's bucket
prefix is keyed by network, not by shard, so a moved tenant keeps its CAS
untouched; its DB moves by replica-stream restore, or failing that by the
§5.3 rebuild. During a handover the network may briefly carry two hosted
devices (`cloud-2` draining, `cloud-3` provisioning) — which is just two
replicas, a state the protocol is indifferent to.

Redundant hosting (two shards deliberately hosting every network) is the
same mechanism run without the filter's exclusivity, and is future work
only because billing and the status API assume one row per network today.

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
| pod killed without grace | up to one replication interval of DB writes unshipped; replica behind, never ahead | restore + re-sync closes the gap, §5.3 |
| bucket prefix deleted by mistake | `NotFound` heal (SERVERLESS §6.4): durable claims withdrawn, wants re-staged, re-fetched from customer nodes while they hold copies | the one unrecoverable case is prefix loss *and* customer loss together |
| budget exhausted | admission stops; `held_back` visible in panel and heartbeat; nothing evicted | org raises plan; acquisition resumes |
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
  hosting, where the hosted node is admitted as a §3.5 delegate for named
  spaces only and scoped replication (§5.5) redacts the rest down to the
  filenames — and is deliberately future work: it trades "replicate
  everything" for "replicate exactly this", a different product tier.
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

- Prometheus per shard, labelled `{org, network}`: tenant state, held
  roots/bytes, wants outstanding, budget headroom, acquisition and release
  rates, identify latency, loop restarts, poll generation age.
- The **stored heartbeat** (§3.3) is the billing record: held bytes per
  network, written by the tenant that holds them, timestamped, surviving
  the tenant being down (a stale heartbeat *is* the alert).
- The **live view** is the existing replication panel over the browse
  tunnel — the hosted node answers the same §8.1 question every daemon
  answers, labelled with its `cloud-<shard>` identity, so "is the cloud
  replica keeping up" is a question the dashboard already knows how to ask
  and render, with zero new UI.
- `synch-dp status` (local admin socket, read-only): per-tenant state
  table, the parked-in-`Identifying` list, last poll generation.

---

## 11. Implementation plan

### Crate layout

```
crates/synch-dp/
  src/main.rs          # config from env, runtime, shard identity
  src/control.rs       # /dp/v1 client: poll (ETag), register, heartbeat
  src/reconciler.rs    # desired-state diff, fail-static cache, shard filter
  src/tenant.rs        # per-network lifecycle: provision, identify,
                       #   loop set, supervise, drain, retire
  src/spaces.rs        # view-driven replica ensure/remove (§4.5)
  src/dbrepl.rs        # in-process WAL-shipping DB replicator (§5.3)
  src/metrics.rs
```

### Phases

1. **Engine groundwork**: change (a) `socket_workers: 0`; change (c)
   engine-side lifecycle lock. Both small, both independently shippable.
2. **Control plane**: migration v12 (`cloud_hosted`, `cloud_disabled_at`,
   `dataplane_keys`, system user, reserved-label check in `join_device`),
   the toggle route + audit events, `/dp/v1` routes and the `Dataplane`
   principal, `controlplane dataplane-key mint`. The e2e harness grows one
   scenario: enable → poll → register → zone names the key.
3. **`synch-dp` v1**: single shard, provision/identify/replicate/drain
   against a real control plane and a Memory/S3-compatible store; the
   integration test is the engine's cluster testkit plus the control-plane
   e2e stack — a customer node publishes, the hosted tenant converges, the
   customer node deletes its copy, the bytes survive in the tenant prefix,
   the rebuilt-DB path re-adopts them.
4. **Operations**: replicator hardening (restore fuzzing over torn and
   forked streams), retention-hold deletion job,
   dashboards, the status heartbeat, runbook (`control-plane/ops/`).
5. **Scale-out**: shard filter + rendezvous handover, then the
   dedicated-shard and redundant-hosting tiers as configuration.

---

## 12. Costs, stated

- **Storage residue within a tenancy.** Final `cas/` objects are
  append-only for the life of the tenant; a churn-heavy network pays for
  history until roots age out of grace and the prefix is eventually
  compacted only by offboarding. This is SERVERLESS's stated cost,
  inherited knowingly — the retention hold and per-tenant metering make it
  a billed cost rather than a hidden one.
- **No cross-tenant dedup.** Two orgs storing the same bytes pay twice.
  Chosen in §5.1; the confidentiality and offboarding wins are worth more
  than the duplicate gigabytes.
- **The database replica is load-bearing, and now first-party.** The
  last-copy case rests on the in-process replicator rather than a proven
  external tool — engineering the data plane takes on knowingly, because
  ephemeral pods and a dynamic tenant set left the sidecar shape without a
  leg to stand on (§5.3). The mitigations are owed, not optional: the
  generation model is Litestream's, restore is exercised on every pod
  reschedule rather than only in disasters, and a stalled stream is an
  incident, not a warning.
- **One more standing fleet.** The data plane is a new operated service
  with real state. Everything in this design that could be a daemon
  feature was kept a daemon feature precisely so that a customer who
  distrusts the fleet can run `synch replica add` on their own serverless
  node and get the same durability under their own account — the hosted
  product is the same mechanism with the operations bill moved, which is
  what makes it honest.
