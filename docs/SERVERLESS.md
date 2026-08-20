# Serverless nodes — S3-durable storage design

Status: proposal · 2026-08-20

This document designs a deployment posture the codebase does not support today:
a **serverless node** — a daemon whose host has no durable disk, whose SQLite
database is replicated to object storage by Litestream, and whose CAS lives in
S3 as the *source of truth*. Such a node may hold the only durable copy of some
of the cluster's content, so S3 durability is a correctness property here, not
an optimization. Local checked-out data stays a property of nodes that have
durable disks; a serverless node serves and accepts writes for spaces it holds
no checkout of.

Section references (§) are to DESIGN.md unless prefixed.

---

## 1. Posture and environment contract

A serverless node is an ordinary member of the cluster — same identity model,
same trie, same protocols — with three properties:

1. **Its database is authoritative only in memory of S3.** The daemon runs
   over a local SQLite file restored by Litestream at boot and replicated
   continuously while it runs. The local file is a working copy; the replica
   in S3 is what survives.
2. **Its CAS durable tier is S3.** Local disk holds only a cache and
   in-flight staging, all of it reconstructible or unacknowledged (§4 below).
3. **It has no path-backed spaces.** Every space it publishes into is
   *detached* (§8 below): writes ingest straight to the CAS and publish, with
   no checkout, no scanner, and no watcher.

One assumption is delegated to the environment rather than designed for:
**at most one daemon per data directory / identity, ever** — enforced by the
orchestrator (in Kubernetes: one replica, `strategy: Recreate`, never
`RollingUpdate`, since an update overlap is two live signers of one origin).
The daemon keeps its existing local guard (the control-socket bind) and gains
no lease machinery; overlapping instances remain the one failure this design
does not defend against.

What "serverless" does **not** mean here is request-scoped compute. The node
is a peer: its iroh endpoint must stay dialable, its DNS refresh loop keeps
its membership current, and anti-entropy needs a standing process. The target
is an ephemeral, orchestrator-managed, scale-to-one container — not FaaS.

---

## 2. Storage tiers

```
             ┌─────────────────────────── node ────────────────────────────┐
             │                                                              │
             │   SQLite (all metadata, inline blobs ≤ 16 KiB)               │
             │        │  WAL shipped continuously                           │
             │        ▼                                                     │
             │   [Litestream]──────────────────────────────┐                │
             │                                             │                │
             │   scratch disk (ephemeral)                  │                │
             │   ├── store/            CAS cache + staging │                │
             │   ├── s3-uploads/       (removed — §7)      │                │
             │   └── control.sock, control.token           │                │
             │        │ read-through / write-back           │               │
             │        ▼                                     ▼               │
             │   ┌──────────────────── S3 bucket ────────────────────────┐  │
             │   │  db/…            Litestream generations               │  │
             │   │  cas/xx/<hex>        complete payloads (immutable)    │  │
             │   │  cas/xx/<hex>.obao   outboards (immutable)            │  │
             │   │  staging/<uuid>      ingests in flight                │  │
             │   │  uploads/<id>/<n>    S3-gateway multipart parts       │  │
             │   └───────────────────────────────────────────────────────┘  │
             └──────────────────────────────────────────────────────────────┘
```

The design is a **tier inside the existing store, not a storage trait.** The
CAS's mechanics — `write_slice`'s sparse positional writes, slice encoding's
positional reads, delta promotion's `copy_file_range`, staging-and-rename —
all stay exactly as they are, operating on scratch-disk files that are now a
cache. S3 sees only whole, immutable, content-addressed objects. Abstracting
the whole CAS behind a trait was considered and rejected: the blob API is
~50 concrete call sites across three crates, `blob_path` escapes into reflink
call sites, and every hard operation (scattered 16 KiB writes, reflinks,
mtime-driven sweeps) is one S3 cannot express — a trait would force the
lowest common denominator on the local path too. A tier leaves the fast path
alone and adds exactly one fact per blob: *is it durable in S3?*

**Only complete blobs go to S3.** Partial blobs never need durability, by
construction: a partial is either fetch progress (the providing peers still
hold the content — it is re-fetchable), or an ingest that has not been
acknowledged yet (the client still owns the retry). Losing scratch loses
work, never data. This is what makes immutable objects sufficient and spares
the design a chunked object layout with its request amplification.

Objects ≤ 16 KiB stay inline in SQLite and ride Litestream; they never touch
S3 as CAS objects. This is unchanged and is why the small-file case costs no
per-object S3 overhead.

---

## 3. The durability order

The store's core invariant today is *bytes reach stable storage before the
row that claims them* (synch-store/src/cas.rs). The serverless port keeps the
same invariant with S3 playing the role of `fsync`, and extends it through
the publish:

```
object durable in S3  →  blobs row (durable=1) commits  →  f:/b: records publish  →  client ack
```

and for deletion, the existing row-first order, extended:

```
blobs row deleted  →  cache file unlinked  →  S3 object deleted
```

Consequences, given that Litestream replication is asynchronous:

- A restored database can only be **behind** S3, never ahead: no row can
  claim a durable object that was never uploaded, because the upload
  completed before the row existed. The converse — S3 objects no restored
  row claims — is an orphan, collected by the sweep in §5.5.
- One exception exists: a restore can **roll back a deletion**, resurrecting
  a row whose S3 object is already gone. This is the one path to the
  "row claims bytes that do not exist" state, and unlike the local-disk
  version of that state — documented in `cas.rs` as never self-healing — it
  is now *cheaply detectable*, because S3 is strongly consistent and
  authoritatively answerable: a `404` on a GET or HEAD of an object the row
  claims durable is proof, not a maybe-unmounted disk. §6 makes that a
  self-healing rule.

The ack at the end of the chain deserves its own statement. A gateway `PUT`
is acknowledged after the publish transaction commits *locally*; Litestream
ships that WAL segment asynchronously (default ~1 s). A crash inside that
window loses the **metadata** of an acknowledged write while its **bytes**
survive in S3 as an orphan. §6.3 closes this window using the cluster itself
where peers exist, and quantifies the residue where they do not.

---

## 4. Blob lifecycle

### 4.1 Schema

`blobs` gains one column:

```sql
ALTER TABLE blobs ADD COLUMN durable INTEGER NOT NULL DEFAULT 0;
   -- 1: payload and outboard are objects in S3
```

The existing columns keep their meaning with one reinterpretation: on a node
with an S3 tier, `bitmap` (the verified-group ranges) and the presence of the
scratch files describe the **cache**, not the object's existence. `complete`
remains "every group verified by this node at some point"; `durable` is the
new fact. `to_ad()` advertises `Complete` when `durable = 1` regardless of
cache state — a cold cache is still servable, through §4.4.

Scratch cache validity is decided in O(1), not by auditing files: the store
writes a random **generation marker** (`store/generation`) when it creates
the CAS directory, and records the value in the database. At open, a missing
or different marker means the scratch disk is fresh; one UPDATE then clears
every row's cache claim (`bitmap`, and `complete` where `durable = 0` —
i.e. drops non-durable rows entirely, staging ad retirement for them) and a
new marker is written. A matching marker means the scratch survived the
restart and every cache claim stands. This replaces any per-file boot audit.

### 4.2 Ingest (locally originated content — the "only copy" path)

Ingest is where the node creates content the cluster may hold nowhere else,
so nothing is acknowledged before S3 has it. The shape mirrors the local
staging-and-rename discipline, translated to object storage — a staging key
plus a server-side copy, because the content address is not known until the
hash completes and S3 multipart uploads name their key up front:

1. Stream the source once, exactly as `ingest_file` does today: tee into a
   scratch staging file *and* the outboard builder, while
   **simultaneously** uploading the stream as an S3 multipart upload to
   `staging/<uuid>` (8–64 MiB parts). The scratch copy warms the cache; if
   scratch is too small for the object, the tee to scratch is dropped and
   only the upload proceeds — the outboard builder is the ~size/256 memory
   cost already accepted by the current ingest.
2. Complete the staging upload; server-side copy (`CopyObject`, or
   `UploadPartCopy` assembly above 5 GiB) to `cas/<hex[0..2]>/<hex>`; put
   the outboard to `…/<hex>.obao`; delete the staging key.
3. Commit the row (`durable = 1`), stage the `f:` entry and `b:` ad, publish.
4. Acknowledge.

A crash anywhere before step 3 leaves at most a staging key and an incomplete
multipart upload; both are swept by S3 lifecycle rules (§5.5) and the client
was never answered. The copy in step 2 is intra-bucket and does not
re-transfer the bytes.

### 4.3 Fetched content (write-back policy)

`write_slice` — the peer-fetch commit path — is untouched: verified groups
land in the sparse scratch file and the bitmap, exactly as today. What is new
is a completion hook: when the last group verifies, the store *may* upload
payload and outboard to S3 (multipart from the scratch file, then the row's
`durable` flips). Whether it does is policy:

```
cas.s3.upload = own          # locally ingested content only (always on)
              | own+pinned   # + everything pinned here      (default)
              | all          # + everything fetched
```

The default follows from the durability argument in §2: fetched content is
re-fetchable, so uploading it buys nothing unless this node is *meant* to be
its durable holder — which is exactly what a pin declares. `pin add`
therefore implies upload-on-complete, and a pin on already-complete cached
content triggers the upload immediately. `all` exists for the
serve-everything cloud replica whose whole job is durable coverage.

The upload runs off the fetch's critical path (maintenance work, not fetch
work) — with one exception: a **pinned** fetch's caller (`synch pin add`)
returns only after `durable = 1`, because a pin is a durability promise and
on this node durability means S3.

### 4.4 Reads: S3 as the ranked-first donor

The read path already has exactly the right shape: resolve the entry, compute
missing groups, fetch them from donors, serve from the CAS. S3 becomes a
donor — the first-ranked one for any blob with `durable = 1`:

- Missing groups are fetched as **range GETs** against the payload object,
  in the same ≤ 8 MiB windows the peer protocol uses, and committed through
  `write_slice`'s machinery into the cache like any fetched slice.
- The outboard object is fetched **whole** on first touch (it is 1/256 of
  the payload) and cached; every S3-read group is then verified against it
  before commit, so an S3-side bit flip or a wrongly keyed object is caught
  at the same 16 KiB granularity as a hostile peer.
- Verification failure against a durable object is **corruption of a durable
  copy** — possibly the only one — and is handled loudly, not silently: the
  object is quarantined (row marked, ad retired, `synch doctor` reports it)
  and the read falls back to peer donors if any exist. It is never treated
  as a cache miss to retry, and never deleted.
- A `404`/`NoSuchKey` against a durable-claimed object invokes the heal rule
  in §6.2.

Peers remain donors after S3, so a hot object shared by nearby peers can
still be swarmed; latency-based ranking already prefers whoever answers
fastest.

### 4.5 Cache eviction

The scratch cache is bounded (`cas.cache_bytes`, default: leave 20% of the
volume free) and evicted LRU by the existing `last_access`. Only rows with
`durable = 1` are evictable — eviction unlinks the payload and outboard
files and clears the bitmap, leaving the row and its ad untouched. Rows with
`durable = 0` are never evicted: they are either partials (cheap, bounded by
in-flight fetch windows) or ingests between hash and upload (transient by
§4.2). Pinned blobs are evictable like any durable blob — on this node the
pin's promise is kept by S3, not by the cache.

Delta promotion (docs/DELTA-SYNC.md) keeps working against whatever donors
the cache holds; a donor that has been evicted is simply not a donor, and
the fetch planner falls back to S3 ranges. Reflink economics degrade to
copy economics on cold caches — accepted; the serverless node is not the
node the delta design was optimizing for.

### 4.6 Deletion and GC

Content GC's *decision* logic (pins, retention, references) is unchanged.
Its *execution* order gains a third step: delete the row, unlink the cache
files, then delete the S3 objects (payload and outboard). An S3 delete that
fails or is lost to a crash leaves an orphan for the sweep:

**S3 orphan sweep** (a maintenance-loop pass, default daily): LIST `cas/`,
and delete any object whose hash has no `blobs` row and whose
`LastModified` is older than `s3_orphan_horizon` — default **7 days**, and
the horizon does double duty: it must exceed both the longest plausible
ingest (an object uploaded before its row commits looks like an orphan for
the duration of step 2–3 of §4.2) and the deepest plausible **database
rollback** (a Litestream restore that lost the row of an uploaded object
must not race the sweep before the heal rules or a re-publish restore it).
LIST at 1000 keys/page costs one request per thousand objects, daily —
negligible against the storage it reclaims.

**S3 lifecycle rules** back the sweep for the transient prefixes, so leaks
have a floor even if the daemon never runs again:
`AbortIncompleteMultipartUpload` after 7 days bucket-wide, expire
`staging/` after 7 days, expire `uploads/` after 7 days (matching the
existing multipart-upload TTL).

---

## 5. Bucket layout and access

```
db/…                      Litestream's own generation layout (it manages this prefix)
cas/<hex[0..2]>/<hex>     payload; immutable once written
cas/<hex[0..2]>/<hex>.obao outboard; immutable once written
staging/<uuid>            ingest staging keys (transient)
uploads/<upload-id>/<n>   gateway multipart parts (transient, §7)
```

One bucket, distinct prefixes; the two-hex shard is kept for S3's
prefix-based request-rate partitioning as much as for symmetry with the
local layout. Objects are immutable and content-addressed, so bucket
versioning is off; integrity does not come from S3 ETags (which are MD5- or
multipart-shaped) but from the address itself plus outboard verification on
every read (§4.4). Server-side encryption is the bucket's business
(SSE-S3/SSE-KMS both fine). Note that the `db/` prefix contains the node's
**device secret key** (it lives in the `device_keys` table): access to the
bucket is access to the identity, and the bucket policy is part of the
node's security boundary.

Configuration lives in the daemon (flags with env fallbacks, stored like
every other daemon option): `--s3-bucket`, `--s3-region`, `--s3-endpoint`
(any S3-compatible store), `--s3-prefix`. Credentials resolve the standard
chain — static env keys, ECS/IMDSv2 instance roles, and IRSA web-identity
tokens — with session-token support and mid-life refresh, since a
long-running daemon on a 1-hour role cannot hold one signature key forever.

---

## 6. Consistency, healing, and the failure matrix

### 6.1 What each failure costs

| Failure | State afterwards | Repair |
| --- | --- | --- |
| Scratch disk lost (container replaced) | Cache cold; partial rows stale | Generation marker mismatch clears cache claims in one UPDATE (§4.1); refill on demand |
| Crash mid-ingest | Staging key / incomplete MPU in S3; no row; client unacked | Lifecycle rules sweep; client retries |
| Crash between upload and row | Durable object, no row | Orphan sweep after horizon; or the retried ingest finds the object already present (HEAD by content address) and skips the upload |
| Crash between row and publish | Row durable, records unstaged | Existing semantics: row and staged records commit in one transaction, so this window does not exist — the publish batch either carried the entry or the ingest never acked |
| Crash between publish and Litestream ship | Acked write's metadata rolled back; bytes durable in S3 | §6.3 |
| DB restore rolls back a deletion | Row resurrected, S3 object gone | §6.2 heal on first read; sweep horizon prevents the mirror-image race |
| S3 object corrupt | Read-through verification fails | Quarantine + doctor + peer fallback; never silent (§4.4) |
| S3 unavailable | Durable tier unreachable | Reads degrade to cache + peers; ingests and pinned fetches fail closed (nothing acks without durability); doctor says so |

### 6.2 The 404 heal rule

A `NoSuchKey` on an object a row claims `durable` is authoritative — S3 is
strongly consistent, and the key is the content address, so there is no
"wrong replica" or "not mounted yet" reading. The store responds by taking
back the claim: `durable → 0`, and if the cache holds nothing either, the
row is dropped and the `b:` ad retired on the next maintenance pass. If the
content is still wanted (a read is in flight), the fetch replans against
peer donors. This turns the one documented never-self-heals state of the
local CAS into a self-healing one — the single genuine consistency *gain*
of the port.

### 6.3 The ack window, and self-readoption

The publish-before-Litestream-ships window (§3) loses acked metadata on a
crash. Two mechanisms bound it:

**Self-readoption at boot.** The cluster usually remembers what the node
forgot: peers hold the pushed head, signed by this node's own key. On
startup — after restore, before the first publish — the node collects
`Hello` summaries exactly as recovery does (§3.4 of DESIGN.md), and if a
peer advertises **this node's own origin** at a seq above its restored head,
with a signed head that verifies under a device key this node still holds,
it fetches that trie and adopts it as its own complete head, then continues
publishing above it. This is strictly stronger than the existing
restored-from-backup mitigation (which only avoids seq collision): the node
*recovers the lost publishes* rather than forking past them, because unlike
the general recovery case the heads in question are self-signed and fully
verifiable. Delegations, ads, entries — everything in the lost window comes
back. The mechanism reuses the recovery machinery's observation path and
the ordinary trie fetch; what is new is the willingness to adopt an
own-origin head, gated on the signature verifying under a currently held
key.

**The residue.** A cluster where the serverless node has no peers — or none
that heard the push — has an RPO of the Litestream sync interval (default
1 s) for *metadata only*. Bytes are never lost (they precede the ack in
S3); the orphan sweep's horizon means they linger a week for manual salvage
(`synch pin add <root>` re-publishes an ad; a re-`PUT` of the same content
is a no-op upload). This residue is documented, not designed away: closing
it would mean a synchronous redo log in S3 per publish batch, whose cost
(a PUT per publish, on the ack path) is not justified for a window that
peers already close in every multi-node deployment.

---

## 7. Gateway multipart uploads without a durable disk

`UploadPart` acks are durability promises a client relies on (Mountpoint
will not re-send a part it was told succeeded), so parts cannot stage on
scratch. Parts become S3 objects:

- `UploadPart` streams the body to `uploads/<upload-id>/<n>` and records the
  part row (size, part's own blake3 root — computed while streaming) once
  the PUT succeeds. Row implies object, same discipline as today's
  fsync-then-row.
- `CompleteMultipartUpload` reads the parts back **once**, in order,
  through the hash/outboard builder (this is the read S3 was always going
  to charge for — the content address cannot be known without it), while
  assembling the final payload **server-side**: an S3 multipart upload to a
  staging key built from `UploadPartCopy` of the part objects — zero bytes
  re-uploaded — then the §4.2 copy-to-content-address, row, entry, publish,
  ack, delete parts. Parts below S3's 5 MiB copy minimum (other than the
  last) fall back to buffered re-upload of the merged tail.
- The existing three-step latch (`open → completing → completed`) and TTL
  sweep carry over unchanged; the sweep deletes `uploads/<id>/` objects
  instead of a directory, and the lifecycle rule (§4.6) is its backstop.

The `s3-uploads/` scratch directory ceases to exist on serverless nodes.

---

## 8. Detached spaces — serving and writing without a checkout

Reads never needed a checkout: `cat`/`get`/S3 `GET`/`HEAD`/`List` resolve
from replicated `entries` and stream from the CAS. What requires one today
is the write path — `PutObject`, multipart completion, `DeleteObject`, and
`synch take` all funnel through `adoption_target` into the space's
`local_path`, then republish via a full scan. Detached spaces cut that
loop:

```sql
-- spaces.local_path becomes nullable; NULL = detached
```

- `synch space add <id> --detached` creates the row with no path. The
  scanner, watcher, and overlap guards skip detached spaces; `scan` reports
  them as not-scannable rather than empty. The present-but-empty-directory
  mass-tombstone hazard cannot arise for a space that has no directory to
  mistake for its contents.
- **Writes publish CAS-direct**: gateway `PUT`/`Complete` run the §4.2
  ingest, then stage the `f:` entry (kind, size, mtime from the request,
  content root from the ingest) and the `b:` ad in the same transaction and
  publish — no file materialized, no rescan. `DeleteObject` stages the
  tombstone directly. This is the same trie/publish machinery the scanner
  drives; the scanner stops being the only way to reach it.
- **`synch take` becomes adoption by reference** on a detached space: fetch
  the chosen version's content to durability (S3, per the pin path), then
  publish our own `f:` entry naming the same content root, `prev` set as
  §8 of DESIGN.md specifies. Taking a tombstone publishes our tombstone.
  No local file ever exists, which is consistent with what adoption *means*
  — asserting a version as our own — rather than with how the scanner
  happens to detect it.
- `held_spaces` (cloud attach) counts detached spaces, so the control plane
  routes reads to a node that can serve them.
- `m:space` records stop publishing `local_path` as the space description —
  for all spaces, not just detached ones; broadcasting local filesystem
  paths cluster-wide was an accident of convenience.

Mirrors remain the tool for keeping a checkout *somewhere*: any durable-disk
node can `mirror add` a space a serverless node publishes into. Local
checked-out data stays local; it just stops being a prerequisite for
serving.

---

## 9. Implementation shape

**A synchronous S3 client, on the blocking pool.** `synch-store` is
deliberately synchronous with no async runtime dependency, and every store
call already runs on tokio's blocking pool under the `BlockingScope` guard.
S3 calls are made the same way: a small blocking HTTP client
(`reqwest::blocking`, already in the workspace with
`rustls-no-provider + stream`) inside the store's new `s3` module. The
`aws-sdk-s3` crate is not an option as-is: the workspace pins the
`aws-lc-rs` rustls provider process-wide and a dependency that drags in
`ring` panics on first handshake. SigV4 signing already exists in
`synch-s3/src/auth.rs` (key derivation, canonical request, string-to-sign);
it moves to a shared crate — `synch-sigv4` — that both `synch-s3` (verifying
inbound) and `synch-store` (signing outbound) depend on, extended with
session-token headers and the credential-chain resolution of §5. Retries:
capped exponential backoff on 5xx/timeout; every operation used is
idempotent (PUT of immutable content, GET, DELETE, HEAD, LIST).

**Litestream fixes** (independently worthwhile):

- Raise `busy_timeout` from 5 s; `gc_trie`'s single-transaction
  mark-and-sweep can hold the write lock past Litestream's checkpoint
  attempts and 5 s turns that into spurious engine faults.
- Handle `SIGTERM` like `SIGINT` — `docker stop`/Kubernetes send SIGTERM,
  and today only Ctrl-C triggers clean shutdown; a clean exit checkpoints
  and lets Litestream ship the tail promptly.
- Litestream runs as the same uid as the daemon (the store chmods the
  datadir 0700 and db files 0600 on every open, on purpose).
- Move the Rekor pin state (`rekor-pins.json`) into the `config` table so
  it rides Litestream; otherwise every cold start re-walks Sigstore's TUF
  repository from the embedded root, whose expiry is a real date.

**Deployment shape** (Kubernetes as the worked example):

```
initContainer: litestream restore -if-replica-exists …
containers:
  - synch daemon run …            # + SIGTERM handling, terminationGracePeriod ≥ 30s
  - litestream replicate …        # sidecar, same uid, same volume
  - synch-s3 serve …              # optional; stateless control client, needs only
                                  # the shared emptyDir for control.sock/token
volumes: emptyDir (scratch)       # db working copy, CAS cache, sockets
replicas: 1, strategy: Recreate
```

**Phasing:**

1. `synch-sigv4` extraction; blocking S3 client; Litestream/SIGTERM/
   busy-timeout/pin-state fixes. No behavior change without `--s3-bucket`.
2. The durable tier: `blobs.durable`, generation marker, ingest-to-S3,
   S3-as-donor reads, upload policy, eviction, orphan sweep, 404 heal,
   quarantine. A node with a durable disk can run this too (S3 as backstop).
3. Detached spaces: nullable `local_path`, CAS-direct publish for
   put/delete/take, `held_spaces`, `m:space` description fix.
4. Multipart parts to S3; retire `s3-uploads/` on detached-only nodes.
5. Self-readoption at boot.

Each phase is independently shippable and independently testable; the
existing suites' S3 surface (`synch-s3` integration tests) gains a
MinIO-or-equivalent fixture at phase 2.

---

## 10. Costs, stated

- **Latency**: a cold read pays one S3 range GET per ≤ 8 MiB window plus a
  one-time outboard GET; a warm read is unchanged. An ingest pays its
  upload inline before the ack — that is the point.
- **Requests**: one multipart upload + one server-side copy + one outboard
  PUT per ingested object; range GETs per cold read; one LIST page per
  thousand objects per day. Multipart completion pays one full read of the
  object (the hash) and zero re-upload.
- **The reflink economy is gone on cold caches.** Delta sync's
  `copy_file_range` sharing works only within the warm cache; the
  serverless node fetches full ranges where a NAS would have reflinked.
  Accepted: this node's job is durability and availability, not disk
  thrift.
- **Egress**: an S3-donor read is billed bandwidth where a LAN peer was
  free. The donor ranking already prefers fast peers; deployments that
  care point `cas.s3.upload` at `own+pinned` and let peers serve the hot
  set.
