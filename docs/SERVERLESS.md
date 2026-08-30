# Serverless nodes — CAS backends and OpenDAL-durable cloud storage

Status: implementation contract v4 · 2026-08-21

This document defines the implemented deployment posture for
a **serverless node** — a daemon whose host has no durable disk, whose SQLite
database is replicated to object storage by Litestream, and whose CAS lives in
a cloud object store as the *source of truth*. Such a node may hold the only
durable copy of some of the cluster's content, so cloud-store durability is a
correctness property here, not an optimization. Local checked-out data stays a
property of nodes that have durable disks; a serverless node serves and accepts
writes for spaces it holds no checkout of.

The central structural change is that the CAS is abstracted behind an **async
backend trait** with two implementations — the existing local filesystem store
and an OpenDAL-backed cloud object store — selected per node. The
cloud implementation supports S3 (including compatible endpoints), Google
Cloud Storage, and Azure Blob Storage initially; adding another OpenDAL service
is an adapter/configuration addition only if it satisfies the capability and
consistency gates in §6. A node has one backend; there is no tiering visible
outside the backend boundary.

Section references (§) are to DESIGN.md unless prefixed.

---

## 1. Posture and environment contract

A serverless node is an ordinary member of the cluster — same identity model,
same trie, same protocols — with three properties:

1. **Its database is authoritative only in its remote replica.** The daemon runs
   over a local SQLite file restored by Litestream at boot and replicated
   continuously while it runs. The local file is a working copy; the configured
   Litestream object-storage replica is what survives. CAS and database storage
   may share an account/container when the deployment supports it, but their
   clients and configuration are independent.
2. **Its CAS backend is cloud object storage through OpenDAL.** Local disk
   holds only backend-internal cache and staging, all of it reconstructible or
   unacknowledged (§6).
3. **It has API sources, not filesystem sources.** Writes ingest straight to
   the CAS and publish, with no source directory, scanner, or watcher.

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

## 2. One CAS, two backends

```
   engine / net / cli ──────────► Arc<dyn CasBackend>
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    │ semantic CAS coordinator                  │
                    │ bytes durable before durable SQLite claim │
                    └─────────────────────┬─────────────────────┘
                                          │
   ┌───────────────────────────────────────────────────────────────┐
   │                                                               │
   │  LocalFs                          Cloud (OpenDAL)             │
   │  ├ store/xx/<hex> (+.obao)        ├ cas/xx/<hex> (+.obao)     │
   │  ├ store/incoming/ staging        ├ staging/<uuid> keys       │
   │  ├ fsync + rename discipline      ├ scratch spill + cache     │
   │  ├ sparse files, reflinks         │   (ephemeral, internal)   │
   │  └ mtime orphan walk              └ append-only final CAS     │
   │                                     upload lifecycle cleanup  │
   └───────────────────────────────────────────────────────────────┘
                    │                       │
                    └───────────┬───────────┘
                                ▼
             Store (SQLite blob index + inline objects;
                    non-CAS metadata remains caller-owned)
```

**Where the trait is cut.** The boundary is the *semantics* of a
content-addressed blob store — ingest an object, commit verified groups of a
partially held one, finalize, read verified ranges, materialize to a file,
delete local claims, maintain — never file operations. A file-level trait (open, write-at,
rename, fsync) was considered and rejected: it is the local backend's
implementation vocabulary, and object stores can express almost none of it —
no partial writes, no rename, no sparse files, no reflinks. Cutting at semantics lets
each backend keep its native mechanics: the local backend keeps every line of
today's discipline (staging-and-rename, sparse `write_at`, `copy_file_range`
reflinks, mtime-driven sweeps), and the cloud backend gets immutable,
append-only final objects plus OpenDAL operations.

The backend is deliberately a **CAS coordinator**, not merely a byte driver.
Each implementation receives the node's `Arc<Store>` and owns the small set of
`blobs`-index transitions needed to make its durability promises true. Other
SQLite domains — tries, entries, spaces, peers, config, and uploads — remain
ordinary `Store` operations outside the backend. This avoids splitting the
load-bearing sequence “backend ack, then durable row” across unrelated callers.
It does not create a second manifest: `blobs` remains the only CAS index, and
neither implementation keeps independent metadata.

The node constructs exactly one `Arc<dyn CasBackend>` and supplies that same
object to the engine, peer `BlobProtocol`, gateway/control write paths, scanner,
checkout materializer, and maintenance loop. Network receive paths therefore
commit through the configured backend rather than accidentally writing the
local scratch codec directly. No component selects behavior by asking which
provider is configured.

Two consequences of that cut, named up front:

- **`blob_path` is no longer a public API.** The former CAS payload-path API
  escaped the store crate and was reflinked into checkout targets
  (`Adoption::clone_from` via `fetcher.rs`). That call site is now
  `backend.materialize(root, target)`: the local backend reflinks where the
  filesystem allows, the cloud backend downloads through its cache. Nothing
  outside a backend may ever again assume a blob is a file.
- **The cloud backend contains scratch storage internally.** Partial blobs and
  pre-hash ingest staging cannot be immutable remote objects, so the cloud backend
  keeps them on ephemeral local disk. This is safe by construction: a
  partial is either fetch progress (the providing peers still hold the
  content — re-fetchable) or an unacknowledged ingest (the client owns the
  retry). Losing scratch loses work, never data. The scratch is invisible
  outside the backend; no other component knows it exists.

**Only complete blobs are durable in the cloud store**, which is what makes
immutable objects sufficient and spares the design a chunked object layout with its
request amplification. Objects ≤ 16 KiB remain inline in SQLite as a fast local
copy, but the Cloud backend also writes their payload and outboard objects before
it reports `Durable`. Litestream is asynchronous, so an inline SQLite row alone
cannot satisfy the serverless durability promise. LocalFs retains the original
inline-only behavior.

**Storage is a trusted boundary.** Once LocalFs has fsynced a write, or
OpenDAL has acknowledged it, this design trusts that backend to preserve and
return those bytes. The application does not re-hash stored payloads, compare
them with their content address on reads or migrations, quarantine objects, or
retry through another copy because stored bytes appear different. Hashing is
still required to assign a content address at ingest, and bao verification is
still required for slices and proofs received from untrusted peers; neither is
an at-rest storage integrity check. OpenDAL `Content-Length` remains
authoritative metadata: a peer-supplied size must match it before a rowless
cloud object can be adopted.

---

## 3. The backend contract

```rust
/// A content-addressed store and its blobs-index coordinator. Implementations
/// promise that any operation reporting `Durability::Durable` has reached
/// stable storage as the backend defines it (fsync for LocalFs, completed
/// payload and outboard writes for Cloud), and that the corresponding durable
/// SQLite claim was committed afterwards. Publishes and client acks are still
/// ordered by callers after the method returns (§4).
#[async_trait]
pub trait CasBackend: Send + Sync + 'static {
    /// Ingest owned bytes or a file, computing root and outboard. Owned inputs
    /// make the object-safe future `'static` and safe to move to LocalFs's
    /// blocking executor. A successful whole-object ingest is Durable.
    async fn ingest_bytes(&self, bytes: Vec<u8>, now: i64) -> Result<Ingested>;
    async fn ingest_file(&self, path: PathBuf, now: i64) -> Result<Ingested>;

    /// Hydrate a durable cold object into backend-managed scratch/cache. A staged
    /// peer fetch is already readable and is left alone.
    async fn ensure_cached(&self, root: Hash, size: u64) -> Result<()>;
    /// Hydrate only the named groups for a range read or slice request. Cloud
    /// performs ≤8 MiB range reads; LocalFs is already local. This is what
    /// keeps a one-byte tail read from downloading a multi-terabyte object.
    async fn ensure_ranges(&self, root: Hash, size: u64,
                           ranges: ChunkRanges) -> Result<()>;

    /// Encode and commit bao slices for peer transfer. `write_slice` verifies
    /// before changing the bitmap and reports both newly held groups and their
    /// durability. LocalFs answers Durable; Cloud answers Staged until final.
    async fn encode_slice(&self, root: Hash, requested: ChunkRanges)
        -> Result<(Vec<u8>, ChunkRanges)>;
    async fn write_slice(&self, root: Hash, size: u64,
                         served: ChunkRanges, encoded: Vec<u8>, now: i64)
        -> Result<GroupsWritten>;

    /// Read one byte range. Durable cold Cloud objects hydrate transparently;
    /// a local cache is an implementation detail.
    async fn read_range(&self, root: Hash, offset: u64, len: u64)
        -> Result<Vec<u8>>;

    /// Delta-sync proof operations use the same backend on both sides.
    async fn encode_proof(&self, root: Hash, requested: ChunkRanges,
                          level: u8, budget: u64)
        -> Result<(Vec<u8>, ChunkRanges)>;
    async fn write_proof(&self, root: Hash, size: u64,
                         served: ChunkRanges, level: u8,
                         encoded: Vec<u8>, now: i64) -> Result<Proven>;
    async fn promote(&self, donor: Donor, proven: Proven, now: i64)
        -> Result<ChunkRanges>;

    /// Promote a complete Staged object to Durable and only then set the
    /// durable row bit. No-op apart from validation on LocalFs.
    async fn finalize(&self, root: Hash, size: u64) -> Result<()>;

    /// Write the object's bytes to a local file (checkout / `synch get`
    /// materialization), atomically replacing the target. LocalFs reflinks
    /// where possible; Cloud downloads through its cache.
    async fn materialize(&self, root: Hash, size: u64,
                         target: PathBuf) -> Result<Materialization>;

    /// Delete the local claim/cache. LocalFs also removes its private bytes;
    /// Cloud leaves globally addressed final objects append-only.
    async fn delete(&self, root: Hash) -> Result<()>;

    /// Gateway multipart parts use the selected backend too. LocalFs reports
    /// `false` and keeps its fsync-before-row files; Cloud stores/reads/deletes
    /// `uploads/<id>/<part>` through these semantic operations before rows or
    /// acknowledgements. No engine call site receives an OpenDAL operator.
    fn remote_upload_parts(&self) -> bool;
    async fn put_upload_part(&self, key: String, source: PathBuf) -> Result<()>;
    async fn read_upload_part(&self, key: String, range: Range<u64>)
        -> Result<Vec<u8>>;
    async fn delete_upload_part(&self, key: String) -> Result<()>;
    async fn delete_upload_prefix(&self, prefix: String) -> Result<usize>;

    /// Perform backend-specific maintenance: abandoned staging cleanup and
    /// cache eviction.
    async fn maintain(&self, now: i64) -> Result<MaintenanceReport>;
}
```

Notes on the contract:

- **`Durability` is the load-bearing type.** `Durable` means the backend half
  of the §4 ordering, including its SQLite durable claim, is complete and
  publish may proceed; `Staged` means the bytes exist only in backend scratch and a
  later `finalize` is required before anything durable may reference them.
  LocalFs collapses the distinction (everything it acks is Durable), which
  is exactly why the distinction must live in the contract and not in
  call-site knowledge of which backend is configured.
- **Verification stops at the storage boundary.** `write_slice` and
  `write_proof` accept untrusted wire bytes and do not update the bitmap until
  bao verification succeeds. Whole-object ingest hashes its input because the
  hash is the object's name. After either backend acknowledges storage,
  `read_range`, `encode_slice`, materialization, and migration trust the bytes
  it returns; they do not perform a second integrity policy in the application.
- **The SQLite index stays in `Store`, but CAS transitions are encapsulated.**
  The `blobs` table (bitmap, complete, pinned, inline, and `durable` flag — §5)
  remains the single index. The backend calls its
  narrow Store APIs only after I/O awaits have completed; it never holds a
  SQLite connection or transaction across an await.
- **Dispatch** is `Arc<dyn CasBackend>` via the `async_trait` crate
  (native async-fn-in-trait is not dyn-compatible without hand-boxing);
  the per-call box is noise against I/O. There are two implementations
  today, but "backends" is a door deliberately left open. OpenDAL already
  abstracts the cloud implementation over admitted services, and the trait is
  where a backend with different CAS mechanics plugs in. A closed enum over the
  two implementations was considered and rejected only for that reason.
- **One contract test suite, run against both backends.** The cloud suite runs
  first against OpenDAL's memory service with failure injection, then as service
  integration tests against MinIO (S3), `fake-gcs-server` (GCS), and Azurite
  (Azure Blob): ingest/read/slice round-trips, partial
  commit and finalize, proof promotion, materialize, delete idempotence, and
  maintenance behavior
  with a fabricated horizon, and the durability ordering itself
  (crash-shaped: kill between backend ack and row commit, assert the durable
  residue can be adopted or overwritten idempotently). The suite is the definition of
  backend correctness; a third backend is done when it passes.

Node configuration selects the backend: `--cas-backend local|s3|gcs|azblob`
(default `local`, stored like every other daemon option). The three cloud
values construct the same OpenDAL-backed implementation with different service
builders and require the corresponding §7 settings. Changing a node's backend
or cloud service is a migration, not a flag flip — §11.

---

## 4. The durability order

The store's core invariant today is *bytes reach stable storage before the
row that claims them* (synch-store/src/cas.rs). The backend contract keeps
the same invariant with `Durability::Durable` playing the role of `fsync`,
and extends it through the publish:

```
backend object ack  →  backend commits blobs row (durable=1)  →  f:/b: records publish  →  client ack
```

Cloud deletion stops at the SQLite claim and reconstructible cache. Final
`cas/` keys are append-only: a content address may be shared by multiple nodes
using the same bucket/root, and one node cannot know that every other node has
released it without distributed reference counting. The storage residue is the
deliberate price of avoiding that machinery.

Consequences, given that Litestream replication is asynchronous:

- A restored database can only be **behind** the cloud backend, never ahead: no
  row can claim a durable object that was never uploaded, because the upload
  completed before the row existed. The converse — objects no restored row
  claims — is durable residue, reusable by retry or readoption (§6.5).
- A restore can **roll back a deletion**, resurrecting its local row. The final
  cloud object normally remains because deletion is local-only. If an operator
  or provider lifecycle rule removed it, OpenDAL `NotFound` is authoritative and
  §6.4 withdraws the stale claim.

The ack at the end of the chain deserves its own statement. A gateway `PUT`
is acknowledged after the publish transaction commits *locally*; Litestream
ships that WAL segment asynchronously (default ~1 s). A crash inside that
window loses the **metadata** of an acknowledged write while its **bytes**
survive remotely as unclaimed residue. §8.3 closes this window using the cluster itself
where peers exist, and quantifies the residue where they do not.

---

## 5. The local backend

`LocalFs` is the original CAS relocated behind the trait, mechanically: the
`store/<xx>/<hex>` layout, `incoming/` staging with fsync-then-rename,
sparse-file `write_at` commits, positional slice encoding, reflink
`materialize`, `copy_file_range` in `promote`, and the mtime-driven orphan walk
in `maintain`. Every ack is `Durable`; `finalize` is a
no-op. The relocation preserves behavior, and its contract tests require a
`local`-backend node to retain the original semantics.

Schema addition (shared by both backends):

```sql
ALTER TABLE blobs ADD COLUMN durable INTEGER NOT NULL DEFAULT 0;
```

On the local backend `durable` tracks `complete` trivially (backfilled by
the migration). On the cloud backend it is the fact that matters: *finalized
into object storage*. `to_ad()` advertises `Complete` from `durable`, so a cold cloud-side
cache is still advertised and servable.

---

## 6. The OpenDAL cloud backend

One `Cloud` implementation owns an `opendal::Operator`. Configuration chooses
the service builder (`S3`, `Gcs`, or `Azblob` initially); no provider type
escapes the constructor. OpenDAL supplies authentication, request signing,
credential refresh, retries, streaming readers/writers, range reads, listing,
and normalized error kinds. It does **not** supply CAS semantics, bao
protocol verification, durability ordering, or scratch generations — those
remain this backend's code and are tested once against the trait
contract. Integrity of bytes already accepted by the service belongs to the
service, not to a second application-level checker.

At open the backend inspects `Operator::info()` and refuses a service without
the semantic minimum: stat, whole/range read, streaming or multipart write,
delete, recursive list, and content length. Copy is an
optional acceleration, never a correctness dependency. The service must also
provide strongly consistent reads and listings after successful writes and
deletes. S3, GCS, and Azure Blob meet that requirement; merely having an
OpenDAL adapter does not admit a weaker service. Adding another service means
enabling its compile-time feature, mapping its configuration, documenting its
consistency, and passing the same contract suite.

### 6.1 Layout

```
cas/<hex[0..2]>/<hex>       payload; immutable once written
cas/<hex[0..2]>/<hex>.obao  outboard; immutable once written
staging/<uuid>              optional copy-accelerated staging (transient)
```

plus, on scratch disk, the backend's private area: spill files for partial
objects (same sparse-file mechanics as LocalFs, reused as a library), a
read cache, and a **generation marker** — a random value written beside the
scratch area and recorded in the database. At open, a missing or different
marker means the scratch disk is fresh: one UPDATE clears every row's
cached-groups claim, drops rows that were `Staged`-only (staging their ad
retirement), and writes a new marker. A matching marker means the scratch
survived and every claim stands. Cache validity is decided in O(1), never
by auditing files.

### 6.2 Ingest — the "only copy" path

Ingest is where the node creates content the cluster may hold nowhere else,
so nothing is acknowledged before the chosen service has it. Content addresses
are not known until the input ends, while portable object-store writers require
their destination up front. The provider-neutral baseline therefore uses the
backend's ephemeral scratch instead of depending on a provider's copy API:

1. Stream the source once through the hash/outboard builder into a scratch
   staging file, teeing into the read cache when it fits. The outboard builder's
   ~size/256 memory is the cost today's ingest already accepts. This full-size
   staging file is unacknowledged work; deployment scratch capacity therefore
   bounds the largest concurrent ingest.
2. Stream the scratch payload to `cas/…/<root>` with an OpenDAL writer, write
   the deterministic outboard, and wait for both operations to complete. A
   retry overwrites the same keys with the same verified content; avoiding the
   duplicate transfer is an optional optimization, not a correctness branch.
   Only then return `Durable`; the durable row may be committed and the caller
   may acknowledge.

The final keys are immutable. A crash during step 1 loses only unacknowledged
scratch. A crash during step 2 can leave one completed final object without its
mate; until the row commits it is unclaimed residue, and a retry completes or replaces
the pair idempotently. OpenDAL may choose multipart/resumable upload internally;
abandoned provider upload sessions are covered by provider lifecycle rules
where available. A future copy fast path may upload `staging/<uuid>` while
hashing and call `Operator::copy` after the root is known, but only when the
operator reports copy support; it cannot change the baseline semantics.

### 6.3 Partial fetches, finalize, reads, eviction

- **`write_slice`** commits verified slices into a scratch spill file —
  the same code path as LocalFs's sparse commit — and answers `Staged`.
  The engine's fetch loop is unchanged; the store records the bitmap as
  today and simply does not set `durable`.
- **`finalize`** runs when the last group verifies *and policy says this
  node is a durable holder of the object*: stream payload and outboard from
  the spill, then flip `durable`. Policy:

  ```
  cas.cloud.upload = own          # locally ingested content only (always on)
                   | own+pinned   # + everything pinned here      (default)
                   | all          # + everything fetched
  ```

  Fetched content is re-fetchable from its providers, so persisting it
  buys nothing unless this node is *meant* to hold it — which is exactly
  what a pin declares. `pin add` implies finalize, returns only after
  `durable = 1` (a pin is a durability promise, and on this backend
  durability means the configured cloud service), and a pin on already-complete
  cached content finalizes immediately. Content that completes without qualifying stays
  a cache entry: servable, evictable, gone on scratch loss — correctly,
  since its providers still advertise it. It may advertise partial progress,
  but a complete cache-only `b:` ad is retired: every complete cloud ad must
  remain an unambiguous durable promise after SQLite restore. `all` exists for the
  serve-everything cloud replica whose whole job is durable coverage.
- **Reads** (`read_range`/`encode_slice`) serve from the cache when the
  groups are present, else use an OpenDAL range read in ≤ 8 MiB windows,
  fetch the outboard whole on first touch (it is 1/256 of the payload),
  commit the trusted backend bytes to the cache, and serve. To the engine
  this is invisible: an object the store shows `durable` is never fetched
  from peers; a cold cache is the backend's private problem. Peers remain
  the source for objects this node does not hold at all — the fetch planner
  is untouched.
- **Eviction**: `cas.cloud.cache_bytes` is an LRU maintenance target, not a
  per-operation hard ceiling: one active read, materialization, or unacknowledged
  ingest may need more scratch than the target. Deployment scratch capacity is
  the hard bound. Without an explicit target on Unix, maintenance evicts enough
  to keep 20% of the volume free; non-Unix cloud nodes require an explicit
  target. LRU uses the existing
  `last_access`. Only `durable` objects' cache files are evictable —
  eviction unlinks spill/cache files and clears the bitmap, leaving row,
  ad, and cloud objects untouched. Pinned blobs are evictable like any
  durable blob: on this backend the pin's promise is kept remotely, not by
  the cache.
### 6.4 The NotFound heal rule

OpenDAL `ErrorKind::NotFound` on an object a row claims `durable` is
authoritative for an admitted service — the key is the content address and the
supported services are strongly consistent, so there is no "wrong replica" or
"not mounted yet" reading. The store takes back the claim: `durable → 0`, and
if the cache holds nothing either, the row is dropped and the `b:` ad retired
on the next maintenance pass. A read in flight replans against peer donors.
This turns the one documented never-self-heals state of the local CAS into a
self-healing one — the single genuine consistency *gain* of the port. Timeout,
permission, rate-limit, and generic transport errors are never translated into
NotFound; they leave the durable claim intact and make the read degrade to cache
and peers.

### 6.5 Deletion and lifecycle

Content GC's *decision* logic (pins, retention, references) is unchanged, but
on Cloud it deletes only the SQLite claim and reconstructible cache. Final
payload/outboard keys under `cas/` are never deleted by the daemon. This makes a
shared bucket/root safe: identical content has identical keys, and no node can
delete another node's durable copy.

Provider lifecycle rules may abort incomplete/resumable provider uploads and
expire `uploads/` (§9) after the multipart TTL. They must not expire `cas/`
final keys. Unclaimed final objects are accepted storage residue; re-ingest and
self-readoption reuse them by deterministic address.

---

## 7. Object namespace, providers, and access

```
db/…                        Litestream's own layout, only when colocated
cas/…                       §6.1
staging/<uuid>              §6.2
uploads/<upload-id>/<n>     §9
```

One bucket/container, distinct prefixes. The two-hex shard stays for symmetry
with the local layout and for services that partition request load by prefix.
Multiple nodes may share the same CAS root because final keys are append-only;
their SQLite claims and caches remain private.
Objects are immutable and content-addressed, so object versioning is off;
at-rest integrity is delegated to the configured storage service. The content
address names writes and peer protocol verification still rejects hostile wire
data, but backend reads are not re-hashed by the application. Server-side encryption and key selection
are provider/deployment policy.

Litestream configuration is separate. It may use a `db/` prefix in the same
namespace where supported or an entirely different service. If colocated,
remember that `db/` contains the node's **device secret key** (it lives in the
`device_keys` table): access to that prefix is access to the identity. In every
shape, CAS credentials need only the CAS/staging/uploads prefixes and namespace
policy is part of the node's security boundary.

Common configuration is `--cas-backend`, `--cas-root` (prefix),
`--cas-cache-bytes`, and `--cas-upload`. Their environment forms are
`SYNCH_CAS_BACKEND`, `SYNCH_CAS_ROOT`, `SYNCH_CAS_CACHE_BYTES`, and
`SYNCH_CAS_UPLOAD`: CAS storage deliberately does not use the
`SYNCH_CLOUD_…` namespace, which belongs to the separately named control-plane
connection. Provider configuration is explicit and also has `SYNCH_…`
environment fallbacks:

- `s3`: bucket, region, optional endpoint, access-key/secret/session-token or
  OpenDAL's AWS role/web-identity/instance credential chain; path-style mode is
  available for compatible stores such as MinIO.
- `gcs`: bucket, optional endpoint, service-account credential material or the
  OpenDAL GCS default credential chain. Trusted emulators may also opt into
  `--gcs-skip-signature --gcs-disable-vm-metadata`; neither is implied merely
  by setting an endpoint.
- `azblob`: container, optional endpoint, account name/key or bearer/SAS
  credential forms supported by OpenDAL.

Credentials are resolved and refreshed by the selected OpenDAL service rather
than copied into the CAS implementation. Raw secrets are never persisted in the
SQLite `config` table; only the backend/service choice and non-secret settings
are stored. A long-running daemon must be tested with expiring workload
credentials, not only static keys.

---

## 8. Consistency, healing, and the failure matrix

### 8.1 What each failure costs (cloud backend)

| Failure | State afterwards | Repair |
| --- | --- | --- |
| Scratch disk lost (container replaced) | Cache cold; Staged rows stale | Generation marker mismatch clears claims in one UPDATE (§6.1); refill on demand |
| Crash mid-ingest | Scratch spill and possibly an incomplete provider upload; no durable row; client unacked | Backend scratch/provider lifecycle sweeps; client retries |
| Crash between finalize and row | Durable object, no row | Retained append-only; a retried ingest or readoption reuses the deterministic keys |
| Crash between row and publish | Window does not exist — row and staged records commit in one transaction, so the publish batch either carried the entry or the ingest never acked |  |
| Crash between publish and Litestream ship | Acked write's metadata rolled back; bytes durable remotely | §8.3 |
| DB restore rolls back a deletion | Row resurrected; final object normally remains | Read succeeds; an operator-caused NotFound heals on first read (§6.4) |
| Cloud service unavailable | Durable tier unreachable | Reads degrade to cache + peers; ingests and pinned fetches fail closed (nothing acks without durability); operation and maintenance errors are logged |

### 8.2 Litestream and the database

Independent of backend, the DB fixes the port needs:

- Raise `busy_timeout` from 5 s; `gc_trie`'s single-transaction
  mark-and-sweep can hold the write lock past Litestream's checkpoint
  attempts, and 5 s turns that into spurious engine faults.
- Handle `SIGTERM` like `SIGINT` — `docker stop`/Kubernetes send SIGTERM,
  and today only Ctrl-C triggers clean shutdown; a clean exit checkpoints
  and lets Litestream ship the tail promptly.
- Litestream runs as the same uid as the daemon (the store chmods the
  datadir 0700 and db files 0600 on every open, on purpose).
- Move the Rekor pin state (`rekor-pins.json`) into the `config` table so
  it rides Litestream; otherwise every cold start re-walks Sigstore's TUF
  repository from the embedded root, whose expiry is a real date.

### 8.3 The ack window, and self-readoption

The publish-before-Litestream-ships window (§4) loses acked metadata on a
crash. Two mechanisms bound it:

**Self-readoption at boot.** The cluster usually remembers what the node
forgot: peers hold the pushed head, signed by this node's own key. On
startup — after restore, before the first publish — the node collects
`Hello` summaries exactly as recovery does (§3.4 of DESIGN.md), and if a
peer advertises **this node's own origin** at a seq above its restored
head, with a signed head that verifies under a device key this node still
holds, it fetches that trie and adopts it as its own complete head, then
continues publishing above it. This is strictly stronger than the existing
restored-from-backup mitigation (which only avoids seq collision): the
node *recovers the lost publishes* rather than forking past them, because
unlike the general recovery case these heads are self-signed and fully
verifiable. Delegations, ads, entries — everything in the lost window
comes back. Before maintenance starts, every recovered complete own `b:` ad
(including a b-only pin) supplies its signed size to the backend; the backend
locates the final cloud pair, binds that size to the payload's OpenDAL
`Content-Length`, and reconstructs any missing cold `durable` row.
Provider reads repeat that safe adoption on demand, using the signed ad size
rather than mutable object metadata. The mechanism reuses the recovery machinery's observation path
and the ordinary trie fetch; what is new is the willingness to adopt an
own-origin head, gated on the signature verifying under a currently held
key.

**The residue.** A cluster where the serverless node has no peers — or
none that heard the push — has an RPO of the Litestream sync interval
(default 1 s) for *metadata only*. Bytes are never lost (they precede the
ack remotely); append-only final keys remain available for manual
salvage (`synch pin add <root>` re-publishes an ad; a re-`PUT` of the same
content is a no-op upload). This residue is documented, not designed away:
closing it would mean a synchronous redo log in cloud storage per publish batch,
whose cost (a PUT on the ack path) is not justified for a window that
peers already close in every multi-node deployment.

---

## 9. Gateway multipart uploads without a durable disk

`UploadPart` acks are durability promises a client relies on (Mountpoint
will not re-send a part it was told succeeded), so on a cloud-backend node
parts cannot stage on scratch. Parts become cloud objects through OpenDAL:

- `UploadPart` streams the body to `uploads/<upload-id>/<n>` and records
  the part row (size, the part's own blake3 root — computed while
  streaming) once the OpenDAL write succeeds. Row implies object, the same
  discipline as today's fsync-then-row.
- `CompleteMultipartUpload` reads the parts back **once**, in order,
  through the hash/outboard builder into a scratch assembly (the remote read
  cannot be avoided because the content address is not known without it), then
  follows the same §6.2 final-key upload, row, entry, publish, ack, and part
  deletion order. The portable cost is one remote read and one remote write of
  the completed object. Where the operator reports copy support, an optimized
  path may stream the concatenation to `staging/<uuid>` while hashing and copy
  it to the final key, but the capability changes cost only, never semantics.
- The existing three-step latch (`open → completing → completed`) and TTL
  sweep carry over unchanged; the sweep recursively deletes `uploads/<id>/` objects
  instead of a directory, with the lifecycle rule as its backstop.

Local-backend nodes keep the `s3-uploads/` directory exactly as today; the
part store is selected by the same backend switch. A successful part write and
its immutable backend key are authoritative; completion does not re-hash each
part. It still hashes the concatenated assembly once to determine the final CAS
root, then removes the whole remote upload prefix so superseded attempts cannot
leak.

---

## 10. API sources — serving and writing without a filesystem source

Reads do not need a checkout: `cat`/`get`/S3 `GET`/`HEAD`/`List` resolve from
replicated `entries` and stream from the CAS. API sources make the write
path equally checkout-free: `PutObject`, multipart completion,
`DeleteObject`, and `synch adopt path` publish CAS references directly rather than
funneling through `adoption_target`, `local_path`, and a full scan:

- `synch source add <id> --api` creates a source with no path. The
  scanner, watcher, and overlap guards skip API sources; aggregate scans
  simply omit them, while any direct operation requiring a checkout refuses
  them as not-scannable. The
  present-but-empty-directory mass-tombstone hazard cannot arise for a
  space that has no directory to mistake for its contents.
- **Writes publish CAS-direct**: gateway `PUT`/`Complete` run
  `backend.ingest`, then stage the `f:` entry (kind, size, mtime from the
  request, content root from the ingest) and the `b:` ad in the same
  transaction and publish — no file materialized, no rescan.
  `DeleteObject` stages the tombstone directly. This is the same
  trie/publish machinery the scanner drives; the scanner stops being the
  only way to reach it.
- **`synch adopt path` is adoption by reference** on an API source:
  fetch the chosen version's content to durability (finalize, per the pin
  path), then publish our own `f:` entry naming the same content root,
  `prev` set as §8 of DESIGN.md specifies. Taking a tombstone publishes
  our tombstone. No local file ever exists, which is consistent with what
  adoption *means* — asserting a version as our own — rather than with
  how the scanner happens to detect it.
- cloud attachment counts sources and replicas, so the control
  plane routes reads to a node that can serve them.
- `m:space` records stop publishing `local_path` as the space
  description — for all spaces, not just API sources; broadcasting
  local filesystem paths cluster-wide was an accident of convenience.

Replica checkouts provide a filesystem projection elsewhere: any
durable-disk node can `replica add <space> --checkout <path>`. Checked-out
data stays local; it just stops being a
prerequisite for serving.

---

## 11. Implementation shape

**The async inversion.** `synch-store` began synchronous by design, with every
call offloaded to the blocking pool and guarded by `BlockingScope`. The trait
inverts that *for the CAS half only*: `Store` remains the synchronous SQLite
and local-codec implementation, while `Arc<dyn CasBackend>` is the async CAS
coordinator held by the node. Both `LocalFs` and `Cloud` own the same
`Arc<Store>` so they can perform the CAS row transitions described in §3;
callers retain `Store` for non-CAS metadata. The blocking invariant is
preserved by construction inside the one backend that blocks: `LocalFs`
dispatches its file I/O, hashing, and brief SQLite work to `spawn_blocking`
under `BlockingScope` internally. `Cloud` awaits OpenDAL with no connection
held, then offloads its brief SQLite/cache-codec step. Thus the rule "no
blocking on the runtime" moves from CAS call sites into the two
implementations. The cloud backend is natively async through OpenDAL, built
without default features and with only Tokio, the reqwest
`rustls-no-provider` transport, retry/timeout layers, and the S3/GCS/Azure Blob
service features. That preserves the workspace's process-wide `aws-lc-rs` TLS
choice and avoids pulling in a second rustls provider. Hashing between awaits
is bounded or offloaded. Sync flows that reach the CAS (scanner ingest and
checkout materialization) restructure so their CAS steps are awaited by the
async orchestration that already wraps them. The standing rule "no
`Store::conn` inside a transaction" gains a sibling: no backend await while
holding a connection. LocalFs retains its short row-delete/unlink critical
section and `WriteLease` race guard; Cloud removes only local claims/cache, so
final-CAS deletion needs no object-store await.

**The refactor surface, honestly.** The implementation wraps the CAS half of
`cas.rs`, `proof.rs`, and `gc.rs` in `LocalFs` and flips every semantic CAS call site in
`synch-net`, `synch-engine`, and `synch-cli` to the async trait — the
larger diff by far, and it is mechanical but wide (~50 call sites, three
crates). What it buys: the local path stops being load-bearing for
serverless correctness, both backends are proven by one contract suite,
`blob_path` stops leaking filesystem assumptions, and a future backend is
additive. Provider SDKs and hand-written outbound SigV4 stay out; OpenDAL owns
provider authentication and request construction. `synch-s3/src/auth.rs`
continues to verify the gateway's inbound S3 protocol and is unrelated to the
CAS operator. OpenDAL errors are mapped at one boundary: only normalized
`NotFound` triggers §6.4, temporary/rate-limit errors remain retryable, and all
other kinds retain their source chain for `doctor`.

**Deployment shape** (Kubernetes as the worked example):

```
initContainer: litestream restore -if-replica-exists …
containers:
  - synch daemon run --cas-backend s3 …   # or gcs/azblob; SIGTERM, grace ≥ 30s
  - litestream replicate …                # sidecar, same uid, same volume
  - synch-s3 serve …                      # optional; stateless control client, needs
                                          # only the shared emptyDir for control.sock/token
volumes: emptyDir (scratch)               # db working copy, backend scratch, sockets
replicas: 1, strategy: Recreate
```

**Backend migration.** `synch cas migrate --to s3|gcs|azblob` first refuses a
node with filesystem sources: converting one to an API source is an explicit
publication decision, not a storage-side effect. The command owns the same
cross-platform lifecycle lock a daemon takes before opening its Store or iroh
endpoint, so a daemon cannot start and acknowledge a source-only write
mid-migration. It probes rowless own ads and referenced entry roots against a
cloud source, then walks every durable object plus every complete cache object
whose bytes are still present (including inline content). Preserving
complete cache objects keeps their published availability ads truthful; stale
or partial nondurable filesystem rows are discarded at the switch. Every
destination uses an isolated temporary SQLite index, so target retries or
failures cannot rewrite source durability before the final transaction,
`ingest`s each into the new backend (content-addressed, so restartable and
idempotent), then flips the stored backend setting at the end; `--to
local` is the same walk in reverse, and cloud-to-cloud migration uses the same
read/ingest path. Source and destination coexist only inside the
migration command; normal mixed operation is not supported — a
node has one backend — which is the simplicity "backends" buys over
"tiers", paid for by the migration being explicit.

**Implementation evidence** — the implementation is complete only when every
gate below has executable evidence:

1. Carve the trait: `LocalFs` behind `CasBackend`, one backend instance threaded
   through node/network/engine/CLI, all runtime semantic CAS call sites async, no public
   `blob_path`, and a shared contract test suite. No behavior change; a `local`
   node is today's node, including reflink materialization.
2. OpenDAL integration and service factory; the Litestream/SIGTERM/
   busy-timeout/pin-state fixes (§8.2). Independently worthwhile.
3. The cloud backend: portable scratch ingest, spill + finalize + upload policy,
   read cache + maintenance target and eviction, generation marker,
   append-only final keys, and NotFound heal. The contract suite runs against memory failure
   injection, MinIO, fake-gcs-server, and
   Azurite in CI; those required emulator jobs cover every admitted builder's
   endpoint/auth configuration. Expiring workload credentials remain a
   deployment smoke test because CI cannot faithfully emulate their issuers.
4. Detached spaces (§10).
5. Multipart parts as OpenDAL objects (§9).
6. Self-readoption at boot (§8.3), tested with a restored database behind an
   own-origin head retained by a peer.
7. `synch cas migrate` in both directions and cloud-to-cloud, including restart
   idempotence and refusal to flip the stored backend until every copy ends.
8. Workspace unit/integration tests, lint/format gates, and serverless fault
   tests pass without requiring durable local CAS state.

---

## 12. Costs, stated

- **Latency**: a warm read is unchanged; a cold read pays one cloud range read
  per ≤ 8 MiB window plus a one-time outboard read. An ingest pays its
  upload inline before the ack — that is the point.
- **Requests and bytes**: the portable ingest baseline writes one payload and
  one outboard object after a local scratch/hash pass; cold reads use range
  operations. Gateway
  multipart completion pays one full remote read of the parts and one full
  remote write of the final payload. A capability-gated remote-copy path may
  reduce transferred bytes, but is not assumed by the contract.
- **Dispatch**: one boxed future per CAS call (`async_trait`) — noise
  against the I/O behind it.
- **The reflink economy is local-backend only.** `promote` on Cloud falls
  back to read+write through scratch; delta sync still saves peer
  bandwidth, not disk writes. Accepted: the cloud node's job is durability
  and availability, not disk thrift.
- **Egress**: a cold-cache read is billed bandwidth where a LAN peer was
  free. Deployments that care keep `cas.cloud.upload = own+pinned` and let
  peers serve the hot set.
