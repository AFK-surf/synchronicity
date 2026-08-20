# Serverless nodes — CAS backends and S3-durable storage

Status: proposal v2 · 2026-08-20

This document designs a deployment posture the codebase does not support today:
a **serverless node** — a daemon whose host has no durable disk, whose SQLite
database is replicated to object storage by Litestream, and whose CAS lives in
S3 as the *source of truth*. Such a node may hold the only durable copy of some
of the cluster's content, so S3 durability is a correctness property here, not
an optimization. Local checked-out data stays a property of nodes that have
durable disks; a serverless node serves and accepts writes for spaces it holds
no checkout of.

The central structural change is that the CAS is abstracted behind an **async
backend trait** with two implementations — the local filesystem store the
code has today, and an S3 store — selected per node. A node has one backend;
there is no tiering visible outside the backend boundary.

Section references (§) are to DESIGN.md unless prefixed.

---

## 1. Posture and environment contract

A serverless node is an ordinary member of the cluster — same identity model,
same trie, same protocols — with three properties:

1. **Its database is authoritative only in memory of S3.** The daemon runs
   over a local SQLite file restored by Litestream at boot and replicated
   continuously while it runs. The local file is a working copy; the replica
   in S3 is what survives.
2. **Its CAS backend is S3.** Local disk holds only backend-internal cache
   and staging, all of it reconstructible or unacknowledged (§6).
3. **It has no path-backed spaces.** Every space it publishes into is
   *detached* (§10): writes ingest straight to the CAS and publish, with no
   checkout, no scanner, and no watcher.

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
   engine / net / cli ──────────► Store (SQLite: index, inline blobs, tries)
        │                              │  rows ordered after backend acks
        │ async                        │
        ▼                              ▼
   ┌── dyn CasBackend ─────────────────────────────────────────────┐
   │                                                               │
   │  LocalFs                          S3                          │
   │  ├ store/xx/<hex> (+.obao)        ├ cas/xx/<hex> (+.obao)     │
   │  ├ store/incoming/ staging        ├ staging/<uuid> keys       │
   │  ├ fsync + rename discipline      ├ scratch spill + cache     │
   │  ├ sparse files, reflinks         │   (ephemeral, internal)   │
   │  └ mtime orphan walk              └ LIST orphan sweep,        │
   │                                     lifecycle backstops       │
   └───────────────────────────────────────────────────────────────┘
```

**Where the trait is cut.** The boundary is the *semantics* of a
content-addressed blob store — ingest an object, commit verified groups of a
partially held one, finalize, read verified ranges, materialize to a file,
delete, sweep — never file operations. A file-level trait (open, write-at,
rename, fsync) was considered and rejected: it is the local backend's
implementation vocabulary, and S3 can express almost none of it — no partial
writes, no rename, no sparse files, no reflinks. Cutting at semantics lets
each backend keep its native mechanics: the local backend keeps every line of
today's discipline (staging-and-rename, sparse `write_at`, `copy_file_range`
reflinks, mtime-driven sweeps), and the S3 backend gets immutable objects,
server-side copies, and LIST-driven sweeps.

Two consequences of that cut, named up front:

- **`blob_path` dies as a public API.** Today the CAS payload path escapes
  the store crate and is reflinked into mirror targets
  (`Adoption::cloning` via `fetcher.rs`). That call site becomes
  `backend.materialize(root, target)`: the local backend reflinks where the
  filesystem allows, the S3 backend downloads through its cache. Nothing
  outside a backend may ever again assume a blob is a file.
- **The S3 backend contains scratch storage internally.** Partial blobs and
  pre-hash ingest staging cannot be immutable S3 objects, so the S3 backend
  keeps them on ephemeral local disk. This is safe by construction: a
  partial is either fetch progress (the providing peers still hold the
  content — re-fetchable) or an unacknowledged ingest (the client owns the
  retry). Losing scratch loses work, never data. The scratch is invisible
  outside the backend; no other component knows it exists.

**Only complete blobs are durable in S3**, which is what makes immutable
objects sufficient and spares the design a chunked object layout with its
request amplification. Objects ≤ 16 KiB stay inline in SQLite and ride
Litestream; the store answers them before any backend is consulted, so
backends never see them and the small-file case costs no per-object S3
overhead. This is unchanged from today.

---

## 3. The backend contract

```rust
/// A content-addressed blob store. Implementations promise that any
/// operation reporting `Durability::Durable` has reached stable storage
/// as the backend defines it (fsync for LocalFs, a completed PUT/copy
/// for S3) before returning. Callers order SQLite rows, publishes, and
/// client acks strictly after that promise (§4).
#[async_trait]
pub trait CasBackend: Send + Sync + 'static {
    /// Stream a whole object in, computing its root and outboard.
    /// Durable on return.
    async fn ingest(&self, source: IngestSource<'_>) -> Result<Ingested>;

    /// Commit verified groups of a partially held object — the peer-fetch
    /// path. LocalFs answers Durable (fsync'd in place); S3 answers
    /// Staged (scratch spill).
    async fn write_groups(&self, root: &Hash, size: u64,
                          slice: VerifiedSlice) -> Result<Durability>;

    /// Promote a complete Staged object to Durable. No-op on LocalFs.
    async fn finalize(&self, root: &Hash, size: u64) -> Result<()>;

    /// Encode a verified bao slice covering `ranges`.
    async fn encode_slice(&self, root: &Hash, size: u64,
                          ranges: &ChunkRanges) -> Result<Vec<u8>>;

    /// Verified byte-range read.
    async fn read_range(&self, root: &Hash, size: u64,
                        range: Range<u64>) -> Result<Bytes>;

    /// Copy a verified range of one held object into another being
    /// assembled — the delta-sync promotion primitive. Default impl:
    /// read_range + write_groups; LocalFs overrides with
    /// copy_file_range for reflink sharing.
    async fn copy_range(&self, donor: &Hash, into: &Hash, ...) -> Result<Durability>;

    /// Write the object's bytes to a local file (mirror / `synch get`
    /// materialization). LocalFs reflinks where possible; S3 downloads
    /// through its cache.
    async fn materialize(&self, root: &Hash, size: u64,
                         target: &Path) -> Result<()>;

    /// Delete payload and outboard. Idempotent.
    async fn delete(&self, root: &Hash) -> Result<()>;

    /// Remove stored objects no live row claims, older than `horizon`,
    /// plus the backend's own abandoned staging.
    async fn sweep_orphans(&self, live: &LiveSet,
                           horizon: Duration) -> Result<SweepReport>;
}
```

Notes on the contract rather than the signatures (which will shift in
implementation):

- **`Durability` is the load-bearing type.** `Durable` means the §4 ordering
  may proceed; `Staged` means the bytes exist only in backend scratch and a
  later `finalize` is required before anything durable may reference them.
  LocalFs collapses the distinction (everything it acks is Durable), which
  is exactly why the distinction must live in the contract and not in
  call-site knowledge of which backend is configured.
- **Verification stays with the caller's data, not the backend's word.**
  `write_groups` takes slices already verified against the object root
  (unchanged from today's fetch path); `read_range`/`encode_slice` verify
  what the backend returns against the outboard before serving it, so a
  corrupt S3 object or a bit-flipped local file is caught at the same
  16 KiB granularity as a hostile peer, whichever backend is under it.
- **The SQLite index stays in `Store`, outside the trait.** The `blobs`
  table (bitmap, complete, pinned, inline, and a new `durable` flag — §5)
  remains the single index both backends are recorded in. A backend that
  kept its own manifest would be a second source of truth exactly where
  the design can least afford one.
- **Dispatch** is `Arc<dyn CasBackend>` via the `async_trait` crate
  (native async-fn-in-trait is not dyn-compatible without hand-boxing);
  the per-call box is noise against I/O. There are two implementations
  today, but "backends" is a door deliberately left open — any
  S3-compatible store already works through the endpoint override, and
  the trait is where a future backend plugs in. A closed enum over the
  two was considered and rejected only for that reason.
- **One contract test suite, run against both backends** (the S3 side
  against MinIO or s3s in CI): ingest/read/slice round-trips, partial
  commit and finalize, materialize, delete idempotence, sweep behavior
  with a fabricated horizon, and the durability ordering itself
  (crash-shaped: kill between backend ack and row commit, assert the
  orphan is swept and never resurrected). The suite is the definition of
  backend correctness; a third backend is done when it passes.

Node configuration selects the backend: `--cas-backend local|s3` (default
`local`, stored like every other daemon option; `s3` requires the §7
settings). Changing a node's backend is a migration, not a flag flip — §11.

---

## 4. The durability order

The store's core invariant today is *bytes reach stable storage before the
row that claims them* (synch-store/src/cas.rs). The backend contract keeps
the same invariant with `Durability::Durable` playing the role of `fsync`,
and extends it through the publish:

```
backend reports Durable  →  blobs row (durable=1) commits  →  f:/b: records publish  →  client ack
```

and for deletion, the existing row-first order:

```
blobs row deleted  →  backend.delete()
```

Consequences, given that Litestream replication is asynchronous:

- A restored database can only be **behind** the S3 backend, never ahead: no
  row can claim a durable object that was never uploaded, because the upload
  completed before the row existed. The converse — objects no restored row
  claims — is an orphan, collected by the sweep (§6.5).
- One exception exists: a restore can **roll back a deletion**, resurrecting
  a row whose object is already deleted. This is the one path to the "row
  claims bytes that do not exist" state — documented in `cas.rs` as never
  self-healing on the local backend — and on the S3 backend it becomes
  *cheaply detectable*, because S3 is strongly consistent and
  authoritatively answerable: a `404` on an object the row claims durable is
  proof, not a maybe-unmounted disk. §6.4 makes that a self-healing rule.

The ack at the end of the chain deserves its own statement. A gateway `PUT`
is acknowledged after the publish transaction commits *locally*; Litestream
ships that WAL segment asynchronously (default ~1 s). A crash inside that
window loses the **metadata** of an acknowledged write while its **bytes**
survive in S3 as an orphan. §8.3 closes this window using the cluster itself
where peers exist, and quantifies the residue where they do not.

---

## 5. The local backend

`LocalFs` is today's CAS relocated behind the trait, mechanically: the
`store/<xx>/<hex>` layout, `incoming/` staging with fsync-then-rename,
sparse-file `write_at` commits, positional slice encoding, reflink
`materialize`, `copy_file_range` in `copy_range`, and the mtime-driven
orphan walk in `sweep_orphans`. Every ack is `Durable`; `finalize` is a
no-op. No behavior changes; the relocation is the phase-1 refactor (§11)
and its test is that a `local`-backend node is byte-for-byte today's node.

Schema addition (shared by both backends):

```sql
ALTER TABLE blobs ADD COLUMN durable INTEGER NOT NULL DEFAULT 0;
```

On the local backend `durable` tracks `complete` trivially (backfilled by
the migration). On S3 it is the fact that matters: *finalized into object
storage*. `to_ad()` advertises `Complete` from `durable`, so a cold S3-side
cache is still advertised and servable.

---

## 6. The S3 backend

### 6.1 Layout

```
cas/<hex[0..2]>/<hex>       payload; immutable once written
cas/<hex[0..2]>/<hex>.obao  outboard; immutable once written
staging/<uuid>              ingest staging keys (transient)
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
so nothing is acknowledged before S3 has it. The shape mirrors LocalFs's
staging-and-rename, translated: a staging key plus a server-side copy,
because the content address is not known until the hash completes and S3
multipart uploads name their key up front.

1. Stream the source once through the hash/outboard builder while
   **simultaneously** uploading it as an S3 multipart upload to
   `staging/<uuid>` (8–64 MiB parts), teeing into the read cache when it
   fits. The outboard builder's ~size/256 memory is the cost today's
   ingest already accepts.
2. Complete the staging upload; server-side copy (`CopyObject`, or
   `UploadPartCopy` assembly above 5 GiB) to the content address; put the
   outboard; delete the staging key. Return `Durable`.

A crash before step 2 completes leaves at most a staging key and an
incomplete multipart upload; both are swept by lifecycle rules (§6.5) and
the client was never answered. A retried ingest of the same content finds
the object already present (HEAD by content address) and skips the upload.

### 6.3 Partial fetches, finalize, reads, eviction

- **`write_groups`** commits verified slices into a scratch spill file —
  the same code path as LocalFs's sparse commit — and answers `Staged`.
  The engine's fetch loop is unchanged; the store records the bitmap as
  today and simply does not set `durable`.
- **`finalize`** runs when the last group verifies *and policy says this
  node is a durable holder of the object*: multipart-upload payload and
  outboard from the spill, flip `durable`. Policy:

  ```
  cas.s3.upload = own          # locally ingested content only (always on)
                | own+pinned   # + everything pinned here      (default)
                | all          # + everything fetched
  ```

  Fetched content is re-fetchable from its providers, so persisting it
  buys nothing unless this node is *meant* to hold it — which is exactly
  what a pin declares. `pin add` implies finalize, returns only after
  `durable = 1` (a pin is a durability promise, and on this backend
  durability means S3), and a pin on already-complete cached content
  finalizes immediately. Content that completes without qualifying stays
  a cache entry: servable, evictable, gone on scratch loss — correctly,
  since its providers still advertise it. `all` exists for the
  serve-everything cloud replica whose whole job is durable coverage.
- **Reads** (`read_range`/`encode_slice`) serve from the cache when the
  groups are present, else range-GET the payload object in ≤ 8 MiB windows,
  fetch the outboard whole on first touch (it is 1/256 of the payload),
  verify every group against it, commit to the cache, serve. To the engine
  this is invisible: an object the store shows `durable` is never fetched
  from peers; a cold cache is the backend's private problem. Peers remain
  the source for objects this node does not hold at all — the fetch planner
  is untouched.
- **Eviction**: the scratch cache is bounded (`cas.s3.cache_bytes`;
  default: keep 20% of the volume free), LRU by the existing
  `last_access`. Only `durable` objects' cache files are evictable —
  eviction unlinks spill/cache files and clears the bitmap, leaving row,
  ad, and S3 objects untouched. Pinned blobs are evictable like any
  durable blob: on this backend the pin's promise is kept by S3, not by
  the cache.
- **Verification failure** against a durable object is **corruption of a
  durable copy** — possibly the only one — and is handled loudly: the
  object is quarantined (row marked, ad retired, `synch doctor` reports
  it) and the read falls back to peer donors if any exist. It is never
  treated as a cache miss to retry, and never deleted.

### 6.4 The 404 heal rule

A `NoSuchKey` on an object a row claims `durable` is authoritative — S3 is
strongly consistent, and the key is the content address, so there is no
"wrong replica" or "not mounted yet" reading. The backend surfaces it as a
distinct error; the store takes back the claim: `durable → 0`, and if the
cache holds nothing either, the row is dropped and the `b:` ad retired on
the next maintenance pass. A read in flight replans against peer donors.
This turns the one documented never-self-heals state of the local CAS into
a self-healing one — the single genuine consistency *gain* of the port.

### 6.5 Deletion, sweep, lifecycle

Content GC's *decision* logic (pins, retention, references) is unchanged;
`delete` removes cache files, then payload and outboard objects. A delete
that fails or is lost to a crash leaves an orphan for the sweep.

**`sweep_orphans`** (a maintenance-loop pass, default daily): LIST `cas/`,
delete any object whose hash is not in the live set and whose
`LastModified` is older than the horizon — default **7 days**, doing double
duty: it must exceed both the longest plausible ingest (an object uploaded
before its row commits looks like an orphan until step 2 of §6.2 lands)
and the deepest plausible **database rollback** (a Litestream restore that
lost the row of an uploaded object must not race the sweep before the heal
rules or a re-publish restore it). LIST at 1000 keys/page costs one
request per thousand objects, daily.

**S3 lifecycle rules** back the sweep so leaks have a floor even if the
daemon never runs again: `AbortIncompleteMultipartUpload` after 7 days
bucket-wide; expire `staging/` after 7 days; expire `uploads/` (§9) after
7 days, matching the existing multipart-upload TTL.

---

## 7. Bucket layout and access

```
db/…                        Litestream's own generation layout (it manages this prefix)
cas/…                       §6.1
staging/<uuid>              §6.2
uploads/<upload-id>/<n>     §9
```

One bucket, distinct prefixes; the two-hex shard is kept for S3's
prefix-based request-rate partitioning as much as for symmetry with the
local layout. Objects are immutable and content-addressed, so bucket
versioning is off; integrity does not come from S3 ETags (which are MD5- or
multipart-shaped) but from the address itself plus outboard verification on
every read. Server-side encryption is the bucket's business (SSE-S3/SSE-KMS
both fine). Note that the `db/` prefix contains the node's **device secret
key** (it lives in the `device_keys` table): access to the bucket is access
to the identity, and the bucket policy is part of the node's security
boundary.

Configuration: `--s3-bucket`, `--s3-region`, `--s3-endpoint` (any
S3-compatible store), `--s3-prefix`, flags with env fallbacks. Credentials
resolve the standard chain — static env keys, ECS/IMDSv2 instance roles,
IRSA web-identity tokens — with session-token support and mid-life refresh,
since a long-running daemon on a 1-hour role cannot hold one signature key
forever.

---

## 8. Consistency, healing, and the failure matrix

### 8.1 What each failure costs (S3 backend)

| Failure | State afterwards | Repair |
| --- | --- | --- |
| Scratch disk lost (container replaced) | Cache cold; Staged rows stale | Generation marker mismatch clears claims in one UPDATE (§6.1); refill on demand |
| Crash mid-ingest | Staging key / incomplete MPU; no row; client unacked | Lifecycle sweeps; client retries |
| Crash between finalize and row | Durable object, no row | Orphan sweep after horizon; a retried ingest HEADs and skips |
| Crash between row and publish | Window does not exist — row and staged records commit in one transaction, so the publish batch either carried the entry or the ingest never acked |  |
| Crash between publish and Litestream ship | Acked write's metadata rolled back; bytes durable | §8.3 |
| DB restore rolls back a deletion | Row resurrected, object gone | 404 heal on first read (§6.4); sweep horizon prevents the mirror-image race |
| S3 object corrupt | Read verification fails | Quarantine + doctor + peer fallback; never silent |
| S3 unavailable | Durable tier unreachable | Reads degrade to cache + peers; ingests and pinned fetches fail closed (nothing acks without durability); doctor says so |

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
comes back. The mechanism reuses the recovery machinery's observation path
and the ordinary trie fetch; what is new is the willingness to adopt an
own-origin head, gated on the signature verifying under a currently held
key.

**The residue.** A cluster where the serverless node has no peers — or
none that heard the push — has an RPO of the Litestream sync interval
(default 1 s) for *metadata only*. Bytes are never lost (they precede the
ack in S3); the orphan sweep's horizon means they linger a week for manual
salvage (`synch pin add <root>` re-publishes an ad; a re-`PUT` of the same
content is a no-op upload). This residue is documented, not designed away:
closing it would mean a synchronous redo log in S3 per publish batch,
whose cost (a PUT on the ack path) is not justified for a window that
peers already close in every multi-node deployment.

---

## 9. Gateway multipart uploads without a durable disk

`UploadPart` acks are durability promises a client relies on (Mountpoint
will not re-send a part it was told succeeded), so on an S3-backend node
parts cannot stage on scratch. Parts become S3 objects:

- `UploadPart` streams the body to `uploads/<upload-id>/<n>` and records
  the part row (size, the part's own blake3 root — computed while
  streaming) once the PUT succeeds. Row implies object, the same
  discipline as today's fsync-then-row.
- `CompleteMultipartUpload` reads the parts back **once**, in order,
  through the hash/outboard builder (this is the read S3 was always going
  to charge for — the content address cannot be known without it), while
  assembling the final payload **server-side**: an S3 multipart upload to
  a staging key built from `UploadPartCopy` of the part objects — zero
  bytes re-uploaded — then the §6.2 copy-to-content-address, row, entry,
  publish, ack, delete parts. Parts below S3's 5 MiB copy minimum (other
  than the last) fall back to buffered re-upload of the merged tail.
- The existing three-step latch (`open → completing → completed`) and TTL
  sweep carry over unchanged; the sweep deletes `uploads/<id>/` objects
  instead of a directory, with the lifecycle rule as its backstop.

Local-backend nodes keep the `s3-uploads/` directory exactly as today; the
part store is selected by the same backend switch.

---

## 10. Detached spaces — serving and writing without a checkout

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
  scanner, watcher, and overlap guards skip detached spaces; `scan`
  reports them as not-scannable rather than empty. The
  present-but-empty-directory mass-tombstone hazard cannot arise for a
  space that has no directory to mistake for its contents.
- **Writes publish CAS-direct**: gateway `PUT`/`Complete` run
  `backend.ingest`, then stage the `f:` entry (kind, size, mtime from the
  request, content root from the ingest) and the `b:` ad in the same
  transaction and publish — no file materialized, no rescan.
  `DeleteObject` stages the tombstone directly. This is the same
  trie/publish machinery the scanner drives; the scanner stops being the
  only way to reach it.
- **`synch take` becomes adoption by reference** on a detached space:
  fetch the chosen version's content to durability (finalize, per the pin
  path), then publish our own `f:` entry naming the same content root,
  `prev` set as §8 of DESIGN.md specifies. Taking a tombstone publishes
  our tombstone. No local file ever exists, which is consistent with what
  adoption *means* — asserting a version as our own — rather than with
  how the scanner happens to detect it.
- `held_spaces` (cloud attach) counts detached spaces, so the control
  plane routes reads to a node that can serve them.
- `m:space` records stop publishing `local_path` as the space
  description — for all spaces, not just detached ones; broadcasting
  local filesystem paths cluster-wide was an accident of convenience.

Mirrors remain the tool for keeping a checkout *somewhere*: any
durable-disk node can `mirror add` a space a serverless node publishes
into. Local checked-out data stays local; it just stops being a
prerequisite for serving.

---

## 11. Implementation shape

**The async inversion.** `synch-store` today is synchronous by design,
with every call offloaded to the blocking pool and guarded by
`BlockingScope`. The trait inverts that *for the CAS half only*: `Store`
splits into the SQLite store (sync, unchanged discipline, unchanged guard)
and `Arc<dyn CasBackend>` (async, called from the runtime), held together
by the node. The blocking invariant is preserved by construction inside
the one backend that blocks: `LocalFs` dispatches its file I/O and hashing
to `spawn_blocking` under `BlockingScope` internally, so the rule "no
blocking on the runtime" moves from a couple hundred call sites into one
implementation. The S3 backend is natively async (`reqwest` — already in
the workspace with `rustls-no-provider + stream` — with chunked hashing
between awaits or offloaded, an implementation detail). Sync flows that
reach the CAS today (the scanner's ingest, mirror materialization)
restructure so their CAS steps are awaited by the async orchestration that
already wraps them, with the SQLite steps offloaded as before. The
standing rule "no `Store::conn` inside a transaction" gains a sibling: no
backend await while holding the connection, which also retires
`delete_blob_if_collectable`'s hold-the-mutex-across-unlink trick in favor
of the existing `WriteLease` generalized over backend deletes.

**The refactor surface, honestly.** Phase 1 relocates `cas.rs` and the CAS
half of `proof.rs`/`gc.rs` into `LocalFs` and flips every CAS call site in
`synch-net`, `synch-engine`, and `synch-cli` to the async trait — the
larger diff by far, and it is mechanical but wide (~50 call sites, three
crates). What it buys: the local path stops being load-bearing for
serverless correctness, both backends are proven by one contract suite,
`blob_path` stops leaking filesystem assumptions, and a future backend is
additive. `aws-sdk-s3` stays out (the workspace pins the `aws-lc-rs`
rustls provider process-wide; a dependency dragging in `ring` panics on
first handshake); SigV4 signing already exists in `synch-s3/src/auth.rs`
and moves to a shared `synch-sigv4` crate that `synch-s3` (verifying
inbound) and the S3 backend (signing outbound) both use.

**Deployment shape** (Kubernetes as the worked example):

```
initContainer: litestream restore -if-replica-exists …
containers:
  - synch daemon run --cas-backend s3 …   # + SIGTERM, terminationGracePeriod ≥ 30s
  - litestream replicate …                # sidecar, same uid, same volume
  - synch-s3 serve …                      # optional; stateless control client, needs
                                          # only the shared emptyDir for control.sock/token
volumes: emptyDir (scratch)               # db working copy, backend scratch, sockets
replicas: 1, strategy: Recreate
```

**Backend migration.** `synch cas migrate --to s3` walks complete blobs,
`ingest`s each into the new backend (content-addressed, so restartable and
idempotent), then flips the stored backend setting at the end; `--to
local` is the same walk in reverse. Mixed operation is not supported — a
node has one backend — which is the simplicity "backends" buys over
"tiers", paid for by the migration being explicit.

**Phasing** — each independently shippable and testable:

1. Carve the trait: `LocalFs` behind `CasBackend`, all call sites async,
   contract test suite. No behavior change; a `local` node is today's
   node.
2. `synch-sigv4` extraction; the Litestream/SIGTERM/busy-timeout/pin-state
   fixes (§8.2). Independently worthwhile.
3. The S3 backend: staging-key ingest, spill + finalize + upload policy,
   read cache + eviction, generation marker, orphan sweep, 404 heal,
   quarantine. Contract suite runs against MinIO in CI.
4. Detached spaces (§10).
5. Multipart parts as S3 objects (§9).
6. Self-readoption at boot (§8.3).

---

## 12. Costs, stated

- **Latency**: a warm read is unchanged; a cold read pays one S3 range GET
  per ≤ 8 MiB window plus a one-time outboard GET. An ingest pays its
  upload inline before the ack — that is the point.
- **Requests**: one multipart upload + one server-side copy + one outboard
  PUT per ingested object; range GETs per cold read; one LIST page per
  thousand objects per day. Multipart completion pays one full read of the
  object (the hash) and zero re-upload.
- **Dispatch**: one boxed future per CAS call (`async_trait`) — noise
  against the I/O behind it.
- **The reflink economy is local-backend only.** `copy_range` on S3 falls
  back to read+write through scratch; delta sync still saves peer
  bandwidth, not disk writes. Accepted: the S3 node's job is durability
  and availability, not disk thrift.
- **Egress**: a cold-cache read is billed bandwidth where a LAN peer was
  free. Deployments that care keep `cas.s3.upload = own+pinned` and let
  peers serve the hot set.
