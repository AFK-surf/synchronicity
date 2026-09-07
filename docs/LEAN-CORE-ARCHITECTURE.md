# Lean-owned domain operations and host effects

Status: implementation architecture, 2026-09-06. This supersedes the incremental
predicate/snapshot-planner approach in PR #127. It is a target and migration
contract, not a claim that the repository already implements it everywhere.

Current production rule: whole Lean operation or pure Rust, never Rust
orchestration calling fine-grained Lean domain decisions. The user has frozen
new migrations; previously mixed paths are restored to Rust. The broader design
and historical checkpoints below do not authorize additional migrations.
[LEAN-TRIE-CAS-MIGRATION-PLAN.md](LEAN-TRIE-CAS-MIGRATION-PLAN.md) is a
proposal to lift that freeze for the Trie and CAS domains; it authorizes
nothing until accepted.

| Current owner | Operations |
| --- | --- |
| Lean with raw Rust host effects | Complete local ingestion, local read/repair, CAS acquire/delete/unpin/expiry, trie lookup, history retention |
| Rust without Lean decision calls | Partial/cloud CAS orchestration and bitmap settlement, scope authorization, missing-node walk, completeness cache coordination, other unmigrated operations |

Scalar/planner/scope/walk/cache FFI exports have been removed. Historical Lean
models remain mathematical models; their proofs do not verify the restored Rust
implementations. Only the retained whole-operation sources carry native
same-source proof claims, subject to each theorem's explicit assumptions.

## Objective and boundary

Lean implements the core system, not a second model consulted by a Rust core.
The same executable Lean operations are compiled into the native library and
checked by the proof package. Rust supplies host services and user-facing
integration. A domain operation may suspend on a typed host effect and continue
in Lean with its success or failure result.

```
CLI / RPC / scanner events
            |
     Lean domain command
            |
     executable Program
       |             ^
   host effect    host reply
       v             |
 Rust host interpreter
 storage / transport / clock / primitive crypto
```

An operation is not migrated while Rust still decodes domain metadata,
precomputes policy facts, selects its algorithmic steps, or determines recovery
or publication ordering. Moving a predicate, namespace, DTO or batch across FFI
does not satisfy this criterion. In particular, group counts, size settlement,
CAS spans, decoded trie shapes, fork classifications and scope predicates must
not be input services furnished by Rust to Lean.

## Ownership and dependencies

| Lean domain | Owns | Host services, not policy |
|---|---|---|
| CAS | Ingest/read/serve/import/promote; group arithmetic; metadata codecs; size attestation; holds/wants; healing, eviction and collection; durability ordering | Raw metadata records, object reads/writes, flush/truncate/remove, provider I/O, primitive hashes |
| Trie | Node codec and canonicality; keys/nibbles; lookup/update/diff/proofs; scoped traversal; completeness and certificate validity; trie collection | Encoded node/value storage, raw ownership/redaction records, primitive hashes |
| Authorization | Binding liveness, delegated closure, rootedness, scope and provenance rules | Raw binding/head records, authenticated transport identity, signature primitive, DNS response/clock inputs |
| Replication | Head ordering/history, adoption/reconciliation, provider selection, retries, delta/fetch orchestration, retention | Raw records, send/receive, time and entropy, CAS/Trie/Authorization **Lean** interfaces |
| Publication/materialization | Entry decoding, derived rows, row-to-content references, staged ingestion, flush-before-advertise, atomic head/view/hold transitions | Raw records, files/provider I/O and signing primitive; composed Lean domain operations |

The shared foundation contains an effect carrier, raw storage types, failures,
resource/transaction contracts and native transport. It contains no domain
policy. CAS and Trie do not import each other. Replication and publication
compose their Lean interfaces; composition must not bounce through Rust
callbacks. Authorization is not a collection of Rust SQL predicates. UI,
protocol transport engines, provider SDKs and platform adapters remain host
integrations, not reasons to retain a second core implementation.

The control plane is outside this core-language migration. Its behavior,
protocols and OpenBSD support remain unchanged. Rust targets remain Linux GNU,
macOS x86-64/arm64 and Windows gnullvm; no new opt-in or Rust fallback.

## Executable effect carrier

`VerifiedCore.Host.Program E A` is a typed free monad with two constructors:
return `A`, or issue `E B` with a Lean continuation from `B`. Domain operations
use `ExceptT Error (Program E)` so errors are ordinary inputs to the same
verified program. The carrier is executable and total; use structural bounds
or explicit fuel for bounded work, not `sorry`, `unsafe` replacements or
noncomputable algorithms. Long-lived protocols use successive finite commands.

Effects are capabilities, not an application-wide command language. Initial
storage capabilities include:

- Read raw bytes by namespace/key; later extend with bounded offset reads,
  writes, flush, truncate, rename and removal as complete operations require.
- Begin a transaction, read projected raw rows, insert/upsert/update/delete
  explicit raw values, commit or rollback. Replies distinguish absent rows,
  NULL cells, empty blobs and failures. Transaction handles are host resources.
- Row projections and equality/range/ordering scans are declarative storage
  requests chosen by Lean, not host-side application queries. Batch requests
  must preserve set-shaped behavior and index access for large collections.

`EffectSum` composes typed capabilities without merging their algebras, and
the `Inject E F` class finds the path from one capability into a composed row
so a program says `raise Error.host (Storage.readRows ..)` and never spells
the `.left`/`.right` ladder. `raise` issues an effect whose reply is a host
`Reply`; `observe` issues one with a richer reply (a `FileReply`);
`within` lifts a whole sub-operation into a wider row and translates its
error type; `transactionOver` brackets a sub-operation in begin/commit/rollback,
and storage-only `transactionWith` is its specialization.
History uses storage plus a separate `Crypto.validateEd25519` primitive. Its
requests carry only key bytes and return validity or an opaque host failure,
never a decoded origin/head. Adding crypto does not add crypto methods to
storage services.

On the Rust side one relational `Storage` trait is the host every operation
runs over, and one runner, `operation::run`, takes it together with a
`Capabilities` struct of the optional raw services (files, clock, output sink,
construction, temporaries, leases, source input, resources, crypto). A
request for a service the caller did not supply is a protocol failure, so the
Lean effect row of an operation is what says which services it can reach.

Raw cells preserve all SQLite storage classes: NULL, signed 64-bit integer,
REAL bits, text (including invalid UTF-8 bytes), and blobs. Lean owns the
interpretation of durable flags, unsigned sequence numbers stored as signed
integers, serialized bitmaps, head receipts and other metadata. SQL remains in
the Rust storage adapter: it translates whitelisted relation/column identifiers
and generic storage requests, binds values, and returns raw cells. It must not
add `isDurable`, `isComplete`, `forkedSequences`, `applyValidatedEntry`,
`settleSize` or similar policy operations. No Lean functions registered in SQL.

Preserve the existing database and wire encodings. A storage adapter is not
authorized to replace UPSERT with SQLite REPLACE, silently coerce malformed
cells, strengthen a permissive local decoder, or change a bulk scan to one
query per entry. Any necessary format migration needs a separately reviewed
compatibility/recovery plan.

Primitive crypto has a separate explicit trust contract: hashing/signing or
signature checking bytes is a primitive; validating a Bao path, selecting
attested lengths or checking a delegation chain is domain logic and stays in
Lean. Do not use an entire current Rust subsystem as a supposed primitive.

## Transactions, failures and concurrency

Lean requests the resource/transaction scope before its relevant reads and
decides all subsequent effects, commit, rollback and result. Rust preserves
the scope, snapshot and lock guarantees while interpreting requests. It does
not receive a snapshot prepared outside the operation. Operations sharing a
transaction compose inside Lean with the same token; inner operations cannot
commit the outer transaction accidentally.

Every fallible effect returns a typed failure. A failed effect is never
acknowledged as success. Commit failure is distinct from successful commit;
cleanup and publication cannot run on the failure branch. Rollback failure
must not erase the primary error or report success. Rust RAII releases locks,
rolls back uncommitted transactions and destroys abandoned native handles on
cancellation/panic; it is a host resource guarantee, not domain recovery policy.

The shared `transactionWith` helper lifts opaque host failures into a domain's
error type and preserves domain validation errors unchanged through rollback.
The host-error-only `transaction` is its specialization, not another algorithm.
Domain diagnostics are terminal results; storage never receives a domain
validation callback or interprets a domain error to choose recovery.

The runtime must reject mismatched, duplicate or stale replies and replies to
terminal programs. It must preserve one pending request across polling. SQLite
transactions stay on their owning interpreter thread/session. Do not use
unsafe lifetime extension to move guards across awaits or threads. A dropped
program cannot later publish or commit. Backend loss and durability failures
remain explicit program observations; do not conflate claimed and physical
availability or local cache and durable-tier acknowledgement.

## Native boundary

Public APIs accept domain commands and return domain results. While executing,
the shared runtime transports host requests/replies and owns opaque Lean
continuations. Creation/resumption/disposal is transport, not a new predicate
API. Do not export codecs, intermediate ranges, cache flags or state-machine
steps for Rust to orchestrate. Do not hide a sprawling semantic interface
behind one `execute(bytes)` entry point.

Use versioned, bounded request/reply records, validated discriminants, checked
length arithmetic, documented ownership and explicit buffer lifetime rules.
Large byte payloads should use bounded chunks or owned buffer capabilities,
not copy entire blobs at every suspension. Batch storage requests when needed.
Internal domain types and proof structure are not ABI. Keep domain Lean and
Rust facade files separate; the shared runtime must not import their policies.

## Proof obligations and non-regression gates

The [CAS promises](CAS-PROMISES.md) state the user-facing laws, map them to
checked theorems, and distinguish proof-host guarantees from native-host
obligations. CAS and history executions now use one
[shared simulated host](LEAN-SIMULATED-HOST.md), including state-preserving
composition across commands.

Prove executions of the actual programs under the explicit host contract, not
only pure decisions or an independently authored state machine. Required
properties include:

- Effects requested only after their guards hold on the operation's reads.
- Successful results imply the required effects completed successfully.
- Failed/cancelled operations cannot advertise success or advance durability.
- Atomic updates preserve references, ownership and current-head protection.
- Flush/provider acknowledgement precedes metadata advertisement/publication.
- Traversal coverage, canonical decoding, depth and authorization belong to
  the executed trie operation, including interrupted reads and retries.
- Cross-domain publication safety follows from composed Lean programs.
- ABI decoding/encoding and resource rules preserve the typed effect contract.

For each vertical migration: record the existing behavior and regression tests;
implement the whole program and its host interpreter; execute real storage
tests including failures at each effect; replace the production entry point;
delete its Rust algorithm and obsolete low-level exports; extend the proofs.
Do not retain a selectable Rust backend. Staged, unintegrated code is allowed
during development but must be identified as such, not counted as completion.

Run the Lean proof build (`lake build --wfail`), focused Rust tests and Clippy during
development. Before merging run workspace tests/lints and relevant engine,
cloud, recovery, hostile-input and native platform CI gates. Existing binary,
DB, wire, filesystem, error and cancellation behavior are regression contracts.
Benchmark batch cardinality, FFI calls, allocations, transferred bytes and
representative large histories/tries; green unit tests alone do not show that
performance or crash behavior was preserved. No new broad scrubbing that
destroys delta-sync's cost model.

## Current implementation and parallel work

At `c21082a`, mandatory linked Lean owns selected scope/walk/CAS decisions and
lifecycle plans, but Rust still prepares facts and orchestrates many complete
operations. This is **not** the target architecture. Uncommitted SQLite-UDF and
bitmap-adapter-only changes were withdrawn after review.

First parallel slices, selected from production code and existing regressions:

1. Shared foundation/runtime (primary): typed `Program`, failures and raw
   storage algebra; common native transport/interpreter conventions; build and
   proof wiring; integration review.
2. CAS (CAS agent): complete pin/possession operation. Lean begins the
   transaction, reads raw durable/want/pin records, interprets them, preserves
   `created_at`, clears scheduled release, mutates, commits/rolls back and
   returns the result. Delete Rust acquisition orchestration on cutover.
3. Trie (trie agent): complete `get(root,key)`, including actual postcard node
   decoding, nibble conversion, bound checking, traversal and inline/hash value
   resolution over raw byte reads. Preserve permissive local decoding versus
   strict ingress canonical validation; no exported codec predicates.
4. Replication (replication agent): complete head-history pruning. Read raw
   pointers/receipts, derive fork protection and retention/ceiling rules in
   Lean, delete exact selected keys, commit/rollback and return the count.

Agents own their domain files/proofs/tests. The primary owns this document,
shared foundation, build/ABI wiring and integration. Cross-domain signatures
must be agreed before use; no concurrent edits to shared glue without handoff.
Subsequent slices include full CAS ingest/read/promotion and healing; complete
trie mutation/sync/certification/GC; authorization; materialization/publication;
fetch/retry and convergence composition. These remain required. Neither these
first operations nor a working effect carrier redefine the overall end goal.

### Implementation checkpoint

The first slice now has source modules `VerifiedCore/Host.lean`,
`Cas/Program.lean`, `Trie/Codec.lean`, `Trie/Program.lean` and
`Replication/History.lean`. Cargo compiles them with the same pinned compiler;
the proof package imports those exact modules. The shared carrier's laws and
transaction traces cover begin failure, body failure, commit failure and
preservation of the primary error across rollback failure.

CAS pin/possession acquisition, explicit pin release, scheduled expiry and deletion now use complete Lean operations in
production. Their old snapshot/planner interfaces and Rust read/interpret/mutation
orchestration have been deleted. Deletion also owns post-commit file cleanup:
unlink failures are returned to Lean, which attempts both files and ignores
those failures only after committing the row deletion. Trie lookup also runs the complete Lean
operation in production: Rust supplies only raw node/value reads and maps the
completed result. Its former Rust decoding/traversal loop is deleted. Other
trie operations remain unfinished. History retention now runs in Lean in production,
with its Rust retention loop and receipt/fork helpers deleted. The
integration sequence for each operation is:

1. Implement the common native continuation transport with typed reply
   validation, single-use resume ownership and cancellation/resource tests.
2. Implement raw SQLite/NodeStore storage interpretation, keeping each
   transaction and its locks inside one owning session. Preserve original host
   errors through opaque tokens; map domain failures explicitly at the facade.
3. Connect each complete operation, run its existing real-storage regressions
   and inject read/mutation/commit/rollback failures. Measure request counts and
   large-input behavior; Lean fixture proofs do not replace these tests.
4. Remove the corresponding Rust implementation and obsolete FFI after each
   mandatory cutover. Do not remove a shared old helper until all its consumers
   have migrated, and do not call a staged program a production replacement.

The initial storage algebra intentionally contains only primitives used by
these slices. Extend it with raw range scans, batches and file/transport
capabilities when the next complete operation needs them, never by adding a
domain-specific policy callback. The runtime remains independent of those
domain implementations throughout migration.

Integration review has identified specific gates, not waived limitations:

- History now requests signed `seq DESC, root DESC` ordering and a mutation-time
  `NOT EXISTS heads` exclusion through generic storage parameters. SQLite
  regressions cover ordering, binding and trigger-created protection between
  deletes; Lean's request proof and scripted fixtures include the exclusion.
  Joined slot reads and column/byte-shape validation are now implemented in the
  production Lean program. Named-origin validation now runs directly in Lean,
  using a reusable Origin domain module with ASCII normalization, first-`@`
  separation, literal `key:` precedence and contextual label/domain failures.
  It follows signature-width validation and precedes root-width validation.
  Key and bare forms now pass strict Lean z-base-32 decoding: exact alphabet,
  unpadded length classes, zero trailing bits and 32-byte key width. Bare
  failures retain the original shape error; prefixed failures retain the key
  error class. The complete Lean parser composes with a byte-level validation
  action; history now requests it for key origins and signing keys at the
  appropriate validation positions. False and host failure both stop the
  operation and request rollback, retaining distinct diagnostics. These are
  conditional execution proofs. The native runner now interprets the separate
  crypto capability, and `history::prune` returns Lean-selected contextual
  terminal errors. Store now supplies the concrete Ed25519 primitive and maps
  final diagnostics to its existing error types. Real SQLite and cryptographic
  regressions exercise the production entry point, including corrupt fields.
  The old Rust retention algorithm and its receipt/fork readers are deleted.
  Specifically, read complete before pending; an orphan pointer without its
  signed-history row is absent under the existing inner join, not a malformed
  joined head. Preserve projected column errors and the validation order
  (signature width, origin, root width, public key), then receipt decoding in
  requested order. Do not replace these with a Rust `validatedHeads` service;
  Lean must consume raw storage records and invoke only genuine primitives.
  Raw cells now preserve REAL bits and invalid UTF-8 TEXT instead of rejecting
  them eagerly. Raw `scanRows` returns the observed prefix plus an optional
  trailing host failure. Lean validates the prefix before selecting that failure;
  no deletion begins if the scan failed. This preserves an earlier record error
  over a later SQLite stepping error without a Rust domain-decoding callback.
  The legacy all-or-error `readRows` uses the same raw SQLite scan internally.
  Large-history transfer/allocation benchmarks and broader platform gates remain
  required; the scan is batched, not a newly claimed streaming implementation.
  Retention uses local `recorded_at`, never signer-controlled `created_at`.
  The highest retained sequence must survive even after a pending slot expires:
  lowering that ceiling could make `next_own_seq` reuse an already published
  sequence. A fork is retired all-or-nothing only after older retained evidence
  shows a later sequence; the lowest such witness stays while its fork remains
  exempt. These policies now live in the Lean retention program, not SQL facts
  precomputed by Rust.
- Trie lookup now has soundness/completeness proofs against a stable raw graph
  interpreted by the actual decoder. Mutable-host refinement remains a
  separate obligation. Native commands must enforce the existing 32-byte root
  type before constructing an operation.
- The trie codec is now both directions in Lean (`Trie/Codec.lean`): the
  parsers consume a list of octets and return the remainder, and the encoder
  is the postcard image the write path stores. `TrieCodecProofs.decode_encode`
  proves the roundtrip for every well-formed node by induction over the
  executable parsers, including the ten-byte LEB128 bound. The canonical
  ingress boundary for peer-served nodes (`Trie/Verify.lean`) is the
  `trieAdmit`/`trieVerify` pair of whole commands: decode, re-encode
  identically, the shared `maxKeyBytes` bound on one node's nibble run, the
  structural invariants, and the origin-versus-peer fault decision, over one
  `Digest.blake3` primitive. `TrieVerifyProofs` proves that only an encoder
  image is admitted with its invariants, that acceptance and each fault follow
  from the host's digests alone, and that the served bytes are read whole
  before anything is decided. `synch-mpt`'s `hash_of_encoded`, `hashes_to`
  and `check_invariants` algorithms are deleted; the crate supplies the
  BLAKE3 primitive and names the refusal, and `reconcile.rs` maps the verdict.
  Walking, completeness and the rest of the trie remain Rust, per the
  migration plan's later slices.
- The trie write path is now the whole commands `trieInsert` and `trieRemove`
  (`Trie/Mutate.lean`) over raw node reads, content-addressed writes
  (`ByteWrites.putBytes`) and the digest primitive. The descent keeps its path
  as an explicit frame stack and rebuilds from it, so each host round trip is
  a constant-depth step. `TrieMutateProofs` proves that a store whose nodes
  the ingress boundary admits stays that way through every insert and remove
  (`insert_preserves`, `remove_preserves`), that values are written before
  the nodes naming them, and that bounds are refused before any input is
  borrowed; the denotational theorems and the key-depth invariant of whole
  paths remain open, and `properties.rs` stays their evidence. The Rust
  write helpers are deleted. The generated core C is now compiled at `-O2` in
  every profile: `deep_write_path` measures 8.9 s (Rust) against 17.5 s
  (Lean commands) in a debug test run, and 505 s before the explicit stack
  and the optimized C.
- The CAS durability transitions are now the whole commands `casMarkDurable`,
  `casAdoptDurable`, `casHealMissing`, `casReconcileScratch` and
  `casClearCache` (`Cas/Durable.lean`) over raw selections, updates, copies
  and deletes; `Selection.notEquals` (SQL `IS NOT ?`) expresses "a durable
  claim stands" without a Rust statement, and the `config` relation joined
  the store's schema capability for the scratch-generation marker.
  `clearCache` reads the writer count through `Resources`, changes the rows,
  and removes both files only after the commit, tolerating their absence;
  Rust keeps the CAS ordering guard around the command so the count it reads
  is meaningful. `CasDurableProofs` derives each transition's exact database
  on the simulated host: marking never inserts; healing withdraws only a
  standing claim and only then moves the machine roles' pins to repair
  intents, keeping the operator's pin, existing intents and other roots'
  rows, and conserving the repair obligation proved for the read path; a
  generation change drops exactly the staged rows and clears exactly the
  durable out-of-line rows' cached groups. The simulated host's literal
  predicates now have SQL `IS` semantics (NULL selects NULL), matching the
  adapter. The five Rust SQL bodies in `cas.rs` are deleted.
- Serving is now the whole commands `casEncodeSlice` and `casEncodeProof`
  (`Cas/Serve.lean`) over the read path's row statement and a new `Bao`
  host algebra (`Host/Bao.lean`). Lean decides the window: what was asked
  for, that the row's own record holds, within the object, clamped to one
  exchange for a slice; the Bao service encodes exactly those groups
  straight into the run's private output sink, as a file transfer does, and
  the program learns only the byte count. The two effects are served by the
  interpreter loop by hand for that reason. A single-group object is
  answered without the service; a proof the walk cannot fit in the node
  budget is refused whole with nothing published. `CasServeProofs` proves
  the window sound and bounded and derives each execution on the simulated
  host, including that every failed effect publishes nothing. The Bao tree,
  the slice and proof formats and the walk remain Rust (`lean_serve.rs`) as
  a trust assumption; the Rust window computation is deleted, and the
  cloud path's in-memory `encode_complete_proof` stays until C4.
- Receiving is now the whole commands `casWriteSlice`, `casWriteProof` and
  `casPromote` (`Cas/Receive.lean`) over the metadata commit, the write
  lease and six further `Bao` effects. Lean owns the lease bracket, the
  cheap size refusal, the row read and complete short-circuit, the window,
  the inline-versus-file split, the flush before the commit, the commit of
  exactly the window, the trim of a completed object, the held-nothing row a
  proof records, and the promotion eligibility rules; the service decodes a
  received encoding out of the run's byte input straight into the files or
  the inline buffer, verifies a proof and writes its nodes to their reach,
  compares a chaining value and copies a run on a match, flushes and trims.
  `CasReceiveProofs` derives the committed row and the effect order on the
  simulated host (decode and flush before the transaction, the lease around
  everything, no row and no lease after any failure before the commit) and
  proves a promotion never asks about a held group. The Rust orchestration
  of `write_slice`, `write_proof` and `promote` is deleted.
- Keeping the store within bounds is now the whole commands `casTouch`,
  `casEvict`, `casGcContent` and `casGcOrphans` (`Cas/Collect.lean`) over
  storage, access, the clock, the lease algebra and a `Sweep` algebra that
  reports what an object's files cost, when they were written and which
  objects have files, one host page at a time. `Lease.order` is the
  remover's critical section, ordered against every writer's lease, and the
  Rust service shares the connection it holds with the storage session;
  `Access.snapshotExcluding` is a snapshot with a delete's correlated
  exclusions. Lean owns the access clock's coalescing, the evictable
  selection and its least-recently-used order, the target from the limit
  and the filesystem shortfall, the collection pre-filter and the deletion
  of each candidate through the existing `Cas.delete`, and the per-file
  orphan decision (age, row, writer, unlink) inside the section.
  `CasCollectProofs` proves the pre-filter drops only rows the deletion
  refuses on the same database, derives the clock, the held refusal and
  the sweep of one file with its section order on the simulated host, and
  runs the passes on fixtures with a failure injected at every effect. The
  Rust eviction loop, cache measurement, in-memory touch coalescing,
  candidate pre-filter and per-file orphan loop are deleted; the
  staging-directory sweep stays a Rust layout sweep.
- The store's projections are now the whole commands `casBlob`, `casBlobs`,
  `casBlobCandidates`, `casPins` and `casPinnedBlobs` (`Cas/Project.lean`),
  one read transaction each over raw reads. Lean owns the statements and
  their order, the row validation the read path applies, the holder
  spelling, and the pin state: read as one join of the same relation in the
  same order and merged in one pass. `CasProjectProofs` proves the merge
  marks exactly the rows the join listed, the decoder's refusals name their
  column, and derives one object's read on the simulated host; fixtures run
  the ordered listings with a failure injected at every effect. The Rust
  SQL projections and the pins reader are deleted; the in-transaction row
  read and advertisement rule of the publish path stay with Publication.
- Serving a trie to a peer is now the whole commands `trieServeNodes`,
  `trieServeValues` and `trieResolve` (`Trie/Serve.lean`) over raw node
  reads and two snapshots (`head_history` for the root's origins,
  `trie_node_origins` for provenance). Lean owns the scope predicates a
  served view is cut along, the merged trail-sharing descent that resolves
  claimed positions, vouching under confined origins, admission (an
  unscoped peer by hash, a scoped peer refused on an unvouched root, an
  out-of-scope position missing under the claimed hash, a node judged by
  what it reveals at every position), value authorization by the holder's
  coverage, and the answer budget. The peer's scope and origins and the
  confined origins are Authorization inputs computed in Rust.
  `TrieServeProofs` proves the spine and boundary properties of scope, that
  nothing inside a grant is redacted, that a descent and the merged descent
  answer only hashes the stored graph places at the position asked about,
  the early admission decisions, the budget invariant, and fixtures with a
  failure injected at every effect. The Rust serving arms, vouching, answer
  assembly and `Scope::admits_node` are deleted; the requesting walk's own
  scope predicates stay in Rust until the walk migrates.
- Collecting the trie is now the whole command `trieCollect`
  (`Trie/Collect.lean`), one immediate transaction over the head rows, raw
  node reads, `Storage.deleteExcept` (one set-wise statement per relation
  over a host temporary table) and the new `Memo.forgetExcept`, whose
  forgetting the host binds to the transaction's edge as it binds a lease.
  Lean owns the retained roots, the mark walk over one accumulating set
  (written over a `MarkSet` interface: the command runs it over a hash set,
  the proofs over a list, both proven lawful), which certificates survive
  (the roots marked from, under the local scope and as each origin's own),
  and the order of the sweeps. The memo keys themselves (`Trie/Memo.lean`)
  are laid out in Lean and hashed by the host, and `Scope::memo_key` asks
  Lean for them (`trieMemoKey`), so every reader and the sweep share one
  layout. `TrieCollectProofs` proves the walk marks every node reachable
  from a root it started from and every value a marked node names, leaves
  the store untouched, and that a sweep keeps exactly the kept keys; pins the
  key layout; and runs the pass on a concrete store with a failure injected
  at every effect. The Rust mark loop, temp-table sweeps and key layout are
  deleted; `Trie::reachable` stays a test oracle.
- Walking a trie is now the three commands `trieScan`, `trieDiff` and
  `trieMaterialize` (`Trie/Walk.lean`, `Trie/Diff.lean`) over raw node
  reads, the new `Redaction` algebra (`isRedacted hash path`: a position the
  store lacks reads as empty when the peer recorded a refusal for it, and as
  a missing node otherwise), `Digest`, and the new `Apply` algebra
  (`applyChange key kind new`: the materialization hands each change to the
  host as the walk finds it, so a promotion never collects the diff and the
  caller's own error travels back unchanged). Lean owns the cursor, the one
  explicit-stack descent every walk shares with its hostile-shape defences
  (a depth past which no valid key begins, the absolute ceiling on positions,
  a candidate filter so a position costs one step, and `Program.iterate`, a
  trampolined loop that continues a pure iteration without nesting a native
  call), the range scan's pruning and limit, the lockstep diff that prunes a
  position both sides address alike before reading either, and the value
  comparison that reconciles inline bytes with the digest of their address
  without touching the store. `TrieWalkProofs` proves the key packing, the
  value comparison, that any descent keeps every frame under its base and
  never charges past the ceiling (`walk_sound`, `descend_refuses_past_the_ceiling`),
  that every entry a scan lists has the prefix, sorts after the cursor and
  is within the limit (`scan_sound`), and fixtures for the scan, the diff,
  the materialization and a failure injected at every effect. The Rust
  cursor, descent, scan, diff and materialization loops are deleted.
- Merkle proofs for single keys (the off-by-default `proofs` feature) are
  the commands `trieProve` and `trieVerifyProof` (`Trie/Proof.lean`).
  Proving is `get`'s descent with its node trace; verifying admits each
  node at the ingress boundary, addresses it by the digest of its tag and
  bytes through `Digest` alone, and runs `get` again over those nodes as a
  raw snapshot, so a path the proof does not cover is a missing node and a
  substituted payload a missing value. `TrieMerkleProofs` proves that a
  verified value is a path through the proof's own nodes
  (`verified_value_is_a_path`), that verification is always answered
  (`check_answers`), and the round trip on a store addressed by its
  digests (`prove_verifies`), with fixtures and a failure injected at every
  effect. The Rust descent and in-memory verification store are deleted.
- Native tests now cover acquisition transport, every effect-failure position,
  repeated polling, malformed replies and terminal resume. Generic SQLite tests
  cover UPSERT identity/time preservation, raw cells, failed commit, abandoned
  sessions and automatic SQLite rollback. These are contract tests, not a proof
  of the C/Rust implementation or physical storage behavior.

### Current native transport

The boundary is declared once, in Lean, and generated on both sides.
`Host/Codec.lean` holds the transport primitives: little-endian u64 words,
length-delimited bytes and strings, the `Encode`/`Decode` classes with an
instance per raw type, the reply and file-reply decoders, and the
`WireEffect` class whose `EffectSum` instance puts any composed algebra on the
wire. `Host/Generated.lean` is printed by `hostgen` from the effect
inductives: each algebra's tags, names, request encoder, reply decoder and
`WireEffect` instance. `Host/Wire.lean` only steps a program: `packet`
renders a terminal or the pending request, `resume` feeds a reply to the
pending continuation, and the two native exports specialize them to the
native algebra. Packets begin with version 1 and a discriminant; replies must
match the pending effect's tag and consume the whole input, and decoders
reject unknown versions/tags, wrong reply types, truncated or trailing data
and lengths that cannot fit the remaining packet before allocation.

The same generator prints the Rust side: the host traits (with the Lean
docstrings), the `Frame` enum with its decoder, the dispatch of every frame
to the storage host or the capability that serves it, and the
`host_unexpected!` macro test doubles use for the methods an operation never
requests. That file is a build product: `build.rs` runs the generator over
the compiled algebras and prints it into Cargo's output directory, where
`lib.rs` includes it, so the Rust glue is never committed. The Lean codecs
are kept in the tree, and `build.rs` fails the build when they are stale.
The interpreter loop in `operation.rs` serves by hand only the frames that
use the run's own resources: borrowed command inputs, the transfer into the
output sink and the sink append. The generator's only tables are the wire
tags and the routing of each algebra to a Rust service.

Commands cross the same way. `Commands.lean` declares the `Command`
inductive and the flat outcome types; `Commands/Generated.lean` and the Rust
mirrors with their codecs are generated. One export, `synch_lean_start`,
decodes the packet and dispatches; `Entry.lean` keeps only the mapping from
each operation's domain errors to its outcome type, host failures and
protocol failures. The Rust facades bind capabilities, encode the command and
decode the terminal; no per-command C constructor, extern declaration or
hand-written terminal codec remains.

The native state now carries the sum of storage and crypto effects. Storage-only
commands inject their effects into that sum without changing their sequencing;
same-source proofs establish that existing packets and resumptions are preserved.
Crypto tag 27 carries length-delimited key bytes and returns a strict boolean or
opaque failure. The host `Crypto` trait is independent of `Storage` and resource
traits. History's domain facade builds the complete command and decodes terminal
errors; it neither parses origins nor orchestrates validation. Malformed crypto
replies become failures to the pending Lean program and follow its rollback path.

Rust's private synchronous runner owns one thread-confined native continuation.
It exposes no handles, polling or resume API to callers/host implementations,
and consumes exactly one typed host result for each pending request. Repeated
internal polling is inert; completed programs cannot restart. The one way a
continuation leaves the runner is a `Peer` effect: a run started through
`synch_verified::suspend` comes back as a `Suspension` that owns the
continuation, names the pending request, and is resumed once with the reply
and fresh storage; it stays on its thread, and the runner only suspends while
no storage transaction is open. No SQLite guards
move across awaits or threads. The raw SQLite interpreter borrows the caller's
guarded connection for the entire operation and rejects stale transaction IDs,
including writes after SQLite has automatically rolled back. Its Drop path
releases only its own abandoned transaction. Normal rollback and primary-error
selection are requested by Lean, including for malformed reply packets.

Command inputs may be borrowed immutable byte capabilities for the duration of
the synchronous run. Lean requests a bounded range by handle, offset and count;
the runner checks capability/range validity and copies only that range. In
particular, lookup rejects oversized keys in Lean before requesting any bytes,
preserving cheap rejection without duplicating the key-limit policy in Rust.
Byte-only operations use a narrow `ByteStorage` host interface; they do not
require SQL or transaction services.

Deletion extends the host algebra with raw relational existence, keyed counter
reads and keyed file removal. Existence queries avoid materializing every pin
or reference. Counters and files use a separate `Resources` capability from
SQL, supplied only to operations that need it. The CAS facade retains connection
and cross-Store ordering guards until the complete Lean call returns. Rust
copies the active-writer registry count; Lean interprets it. Resource namespaces
are whitelisted host mappings, not policies such as “collectable object” or
“best-effort cleanup.” There is no snapshot or mutation-plan ABI for deletion.

Relational reads carry an optional list of column/direction order terms.
Deletes carry optional raw exclusion queries, each consisting of a whitelisted
relation, literal equality fields and optional base-to-excluded column equality
keys. Deletes also carry inclusive upper bounds on raw stored columns. The
interpreter qualifies both sides of each correlation with distinct aliases,
including for self-correlations, and executes all exclusions
as `NOT EXISTS` subqueries in the DELETE itself, never as preceding checks.
Thus changes caused by an earlier deletion's trigger are visible to the next
deletion. Empty parameters retain the original primitive behavior. These extend
existing read/delete effects; no history-specific service or second query
language is exposed. The private packets are internal to the same statically
linked runtime and are neither persisted nor a public compatibility protocol.

Reads may additionally specify inner equality joins from base-table columns
to distinct whitelisted relations. Projection/filter/order names can qualify
their relation; unknown relations, columns, duplicate joins and unkeyed joins
are rejected. The host constructs literal SQL and performs the join before
returning raw cells. Lean selects the joins and validates the resulting domain
records. This preserves orphan-pointer absence without introducing a
host-computed “validated head” snapshot. Joined shape validation is not yet a
claim of origin/key validity or complete corrupt-storage error compatibility.

Only a host failure's opaque token crosses into Lean; Rust retains the original
error object until Lean completes. Thus a later rollback failure cannot overwrite
the error the operation chose. The resumption API (`synch_verified::suspend`)
exports no pointer operation: a `Suspension` is a value that owns the
continuation and the errors registered so far, its request identity is the
pending frame's tag (a reply of the other kind is a protocol failure delivered
into the program), and cancellation is dropping it. It is handed out only
outside a transaction: the runner counts transactions open from a begin that
succeeded until a commit or rollback that succeeded and answers a peer request
while one is open with a protocol failure, and `SuspensionProofs` states the
same discipline over programs (`Balanced`, `Suspending`), so a program the
runner would refuse is one the proofs reject.

### Next CAS operation slices

Explicit pin release now runs in Lean in production. Its command carries the typed
holder identity, not a rendered string plus a Rust-computed role space. Lean
renders the storage key and selects the atomic live-reference exclusion.
`Other("source:x")` must remain opaque and `Source("")` must remain a role;
reparsing their rendered spellings would change the public API's behavior.
No read-before-delete protection check or intermediate release plan crosses
the boundary. A surrounding transaction uses the shared failure contract.
The old Rust release SQL and guard selection are deleted. Same-source proofs
cover the exact guarded request and success/failure traces; native tests cover
all holder variants and each effect failure, and SQLite regressions cover live
references, opaque role-like spellings, empty spaces and rollback on mutation
failure. The host adapter only adds `entries.space` to its raw column allowlist.

Both scheduled expiry commands now use a single Lean-owned bulk deletion.
Lean supplies the optional holder equality, `release_after <= now` and an
atomic `entries.content = pins.root` exclusion. The inequality already rejects
NULL schedules, so no separate non-NULL check is needed. Unlike explicit unpin,
any live reference protects an expiring claim regardless of its holder's space.
Rust does not decode schedule values: native signed integer bounds and SQLite's
raw comparison semantics preserve malformed REAL/TEXT/BLOB behavior too. The
operation uses the shared transaction/error program and returns the host's
affected count only after commit. Both old Rust expiry SQL paths are deleted.
The native boundary remains one complete domain command and generic storage
requests, with no per-pin loop or precomputed expired/protected snapshot.

Subsequent CAS work is ordered by cohesive operation requirements:

- Local reads now compose raw metadata decoding, bounds/coverage, positioned
  file reads and healing inside Lean. Preserve original I/O errors unless
  healing fails. Host callbacks cannot supply verified groups or heal domain
  state on Lean's behalf. See the local-read boundary below.
- Ingest needs bounded file capabilities, unique staging, rename, flush,
  truncate, directory durability and writer leases. Lean owns input policy,
  resource lifetime and publication ordering; the host streams, hashes and
  lays out the object as one construction service over owned temporaries.
  Keep expensive I/O outside SQL transactions.
- Remote adoption/finalization must compose raw provider I/O around metadata
  transitions. Moving only a durable-flag setter leaves the core ordering in
  Rust; provider pair validation/upload is likewise CAS policy, not a primitive.

Local reads share a Lean internal `all | range` request, with row decoding,
saturating bounds, permissive bitmap decoding,
coverage and inline/positioned reads inside that operation. These trusted local
reads do not currently verify hashes. Missing/truncated payloads invoke Lean
healing and then return the original I/O error; if healing fails, its error
takes precedence. Preserve the absent-row healing no-op, operator claims and
existing wants. Healing re-reads size transactionally and selects standing roles
using current SQLite ASCII-insensitive `LIKE` semantics, not typed-holder parsing.
It uses generic updates, conflict-ignore inserts and an on-demand clock, not a
Rust `heal` callback. Ordinary filesystem reads must not hold an immediate SQL
transaction. `read_all` now makes one metadata observation, removing the old
two-read race. Corrupt short inline payloads return an explicit failure instead
of the old slicing panic.

Local read migration alone does not complete cloud reads. The cloud wrapper
still owns adoption, missing-group hydration and success-only access touch;
eventually compose those in Lean over raw provider ranges. Bao slice serving,
import and verification are bulk byte work and stay in Rust: verified
streaming is out of scope for the Lean core, which directs those services
rather than reimplementing them.

#### Local read/healing operation and bounded output

`Cas/ReadCodec.lean` and `Cas/Read.lean` implement complete local reads and
transactional repair in shared executable Lean source. `Store::read_range` and
`Store::read_all` call this native command; the old Rust range algorithm and
`heal_missing_local_blob` transaction are deleted. The store adapter implements
raw file resources, diagnostics and a scoped SQLite session. This completes
only the local-read operation, not the surrounding cloud or Bao operations.

The program owns ordered raw row validation, postcard bitmap decoding and
coverage, range arithmetic, inline validation, the physical read request and
repair/error ordering. It opens the payload once, asks the host for one
`FileIO.transfer(handle, offset, count)` of the whole admitted range and
closes the handle before repair or return. The transfer lands the bytes
directly in a private, command-owned Rust buffer: the payload of a file read
is never a Lean value, a reply packet or a chunk to re-append, so a local
read costs the one copy from the page cache into the bytes the caller
receives. Inline payloads, which the snapshot already delivered, reach the
same buffer through `Output.append`. The terminal success carries only the
byte count; the facade checks framing and count before moving the buffer to
the caller. No partially emitted bytes escape on domain, host, protocol,
close or repair failure: a failed transfer takes back the tail it grew. The
output service has no CAS metadata, range or recovery concepts and no buffer
IDs or domain-specific finalization callback. A sink that cannot grow is
reported through the transfer reply as an unrelated I/O failure, so Lean
still closes the opened file. Rust owns allocation and byte movement; Lean
owns which bytes are asked for and what their absence means.
Missing/truncated data triggers repair; unrelated I/O failures do not.
Successful repair returns the original I/O error, whereas repair failure
takes precedence. The on-demand clock follows metadata invalidation,
preserving the existing ordering.

`Host/Access.lean` describes **raw** capabilities separately from domain
commands: statement-scoped snapshot scans, literal updates, atomic INSERT SELECT
with conflict-ignore behavior, and selected bulk deletes. A selection supplies
literal equality fields plus an optional disjunction of SQL LIKE terms. The
file capability provides open, exact positioned reads, a transfer into the
output buffer and close; clock and output are separate algebras. Native integration shares the existing
whitelisted query construction and transaction handling, not a second SQL
policy engine.
Snapshot connections end at statement completion; only the healing transaction
retains its connection scope. File handles have abandonment cleanup and original
error tokens with generic I/O classifications. Failed commits retain the lease
for rollback; failed rollback leaves final cleanup to session destruction.

Validation covers exact native effect traces, original-error and rollback
precedence, malformed replies, SQLite statement atomicity, real missing and
truncated files, retained open-file identity, released connection scopes
during the transfer, and a failed transfer leaving the sink as it was.
Isolated ignored 64-MiB read probes compare native output allocation against
a raw-file baseline; run each in a fresh memory-capped process. The earlier
chunked design, which routed every 64 KiB through a reply packet, a Lean
`ByteArray`, an append packet and the sink, made about eight copies of every
byte and read 16 MiB in 25 ms against 3 ms for a plain positioned read; the
transfer removes those copies by construction rather than by tuning them.
Proofs check actual Lean decoder fixtures and operation executions. They do
not establish the native interpreter, allocator or physical storage contracts;
those remain explicit trusted host services tested independently.

Subagents may edit disjoint domain/proof/test files, but only the primary runs
heavy validation. Inspect surviving processes after interruption; never launch
a replacement build while its original process is still alive.

### Complete ingestion: construction and publication boundary

Production local `ingest_bytes`/`ingest_file` execute as **whole Lean
operations**. Their Rust orchestration, `write_payload`, `commit_complete` and
old ingestion-only pause hooks have been deleted. Lean owns input policy,
inline selection, the temporary-resource lifecycle, writer-lease lifetime,
publication ordering, directory durability policy and the metadata
transaction. The bytes of the object are the host's: one
`Construct.build(source, payload, outboard, size)` effect streams exactly
`size` bytes of the opened source into the owned payload temporary, hashes
them into the BLAKE3 tree and writes the Bao outboard into the owned outboard
temporary, replying with the root. `Construct.hash(bytes)` answers the root
of an inline object the program already holds. Verified streaming, the
BLAKE3 tree and the outboard layout are out of scope for the Lean core: they
are bulk byte work performed by `bao-tree`/`blake3` in the store's resource
pool, the same code the cloud ingestion paths use. Lean checks the width of
every root it receives and never sees a payload byte on this path.

The mandatory native integration invokes the **whole** `Cas/Input.run` byte
or file command. Its Rust wrapper binds raw services and translates terminal
diagnostics only. Lean observes file metadata, chooses exact-length versus
EOF reads, selects inline storage, and composes `Cas/Ingest.run` for out-of-line
publication. `Store::ingest_bytes` and `Store::ingest_file` only supply a raw
input capability and translate the completed result. Same-source program
proofs cover the executed local ingestion path.

An initially small file still captures to EOF, even if it grows beyond 16 KiB.
That exceptional branch retains its captured bytes, as the previous whole-file
read did; it freezes those bytes under an immutable raw handle before invoking
construction. It never reopens the mutable path. Construction reads the source
positioned from its start in tree groups and never moves the sequential
source cursor; an appended suffix is ignored and a truncated source fails
with `UnexpectedEof` after the temporaries were partly staged, which the
program then discards. The outboard is accumulated in memory, 64 bytes per
group pair, and written whole; a 64 MiB object's outboard is 256 KiB.

The previous design drove construction from Lean at 1 KiB BLAKE3 granularity:
about 35,800 host round-trips and nine copies of every byte for a 16 MiB
object, with BLAKE3's multi-chunk SIMD path unreachable. The CI smoke
benchmark measured 139 MiB/s for that ingest against 860 MiB/s before the
Lean core. Moving construction to the host restores the single streaming
pass; the boundary the proofs cover is the request and its use, not the
tree.

Transport optimization keeps this boundary intact: resume transfers the
private owned continuation reference to Lean instead of retaining the old
state while running the next continuation. Independently held packet owners
remain live, and Rust disarms transferred handles before the foreign call so
unwinding cannot drop them again. The C ownership convention is part of the
native boundary's trust base, checked against generated code and native
lifetime/unwind tests, not claimed as a Lean theorem about C.

Lean's `appendBytes` encoder appends length-prefixed fields directly into the
packet accumulator. It avoids constructing a separate length-plus-payload
buffer for the inline hash request. `WireBufferProofs` proves exact equality
to the plain wire format for arbitrary inputs; no new capability or Rust
domain decision is introduced.

The fixed-width `word` encoder now uses eight constant shifts and a buffer
reserved for eight bytes. `WireWordProofs.word_eq_fold` proves equality for
every UInt64 to the previous little-endian fold specification. This replaces
runtime loop/index arithmetic, not the wire protocol; reply validation and
all domain control flow remain unchanged.

The native raw resource pool shares one invocation-local handle allocator
across source, frozen and temporary handles. Temporary creation uses
`create_new`; a process-wide, canonical-datadir registry protects live names
against staging GC across independently opened Store values. GC holds its
registry lock through exclusion and unlink. Raw keyed leases reuse the existing
connection/CAS ordering and counted writer protection. Unix directory-sync
failures propagate, including flushes of the new shard's namespace ancestors
down to the configured store directory; Windows reports unsupported under explicit platform policy
and retains the existing write-through replacement helper.

Native fixtures check standard roots, payloads and Bao outboard bytes across
chunk/group boundaries using real SQLite and files, plus metadata failure
cleanup. A 14-case raw-effect fault matrix checks original errors and explicit
cleanup before adapter destruction; a deferred foreign-key failure checks
rollback when COMMIT itself fails. A channel-gated test across independently
opened stores checks GC exclusion between payload and outboard publication,
then collection after lease release. The resource pool's own tests check
that construction stages the source into the owned temporaries, leaves them
flushable and discardable, refuses short sources and confused handles, and
leaves the sequential source cursor alone. Raw capability framing tests
reject truncated/trailing packets and excessive conflict expression
depth/node counts. Source capture/inline decisions remain absent from the
Rust interpreter.

Lean owns input length policy, inline choice, temporary resource lifecycle,
writer-lease lifetime, durability ordering and transactional row settlement.
The host supplies construction and the inline hash as whole services; their
cryptographic and layout correctness is a stated trust assumption on
`blake3` and `bao-tree`, tested against standard vectors and against the
same outboard encoder the slice serving path reads. There is no per-chunk
primitive, no Lean tree recurrence and no outboard placement proof: what
the ingestion proofs establish is that the program requests exactly one
construction over the two owned temporaries and the captured source,
rejects a root of the wrong width before any lease, flush or name, and
runs the same cleanup on a construction failure as on any other effect
failure.

The EOF collector retains reversed bounded chunks and an explicit byte count,
then flattens once into a preallocated buffer without an intervening host
suspension. This removes repeated prefix appends whose old continuation could
keep the accumulator shared and force quadratic copying. Universal Lean laws
prove capacity-independent contents, ordered chunk append and exact total
length; native growing-file fixtures include multiple 64-KiB reads and a
partial final chunk. Freezing still copies the whole capture, so this does
not make the exceptional path bounded-memory.

Raw source reads preserve the previous file API's non-seekable inputs. A
source handle tracks its sequential cursor: matching offsets use sequential
reads with interrupted-read retry, while other offsets retain positioned
access (and may fail on streams). Positioned reads never advance that cursor.
Unix FIFO fixtures cover inline and multi-chunk captures to actual EOF; this
avoids adding a seekability requirement to initially small file ingestion.
Metadata integration fixtures also exercise attested/unattested size changes,
noninteger durability rejection, retained nonzero integer durability, and
raw inline-cell preservation through the whole native operation.

The ignored Linux `lean_ingest_memory::isolated_ingestion_memory` probe runs
each implementation/input-kind/size in a fresh child process. File fixtures
are generated in bounded chunks and immutable byte fixtures are allocated
before the baseline. `/proc/self/status` peak RSS includes Lean allocations,
unlike a Rust-only allocator counter. It verifies roots and resource cleanup
without materializing the result for measurement. The 4-MiB and 64-MiB inputs
include three trailing bytes to exercise partial groups.

`Cas/IngestCommit.lean` stages the metadata portion as an internal Lean
transaction: read the exact claim projection, decode and settle it, then issue
one atomic raw upsert. Its accepted full-input plan is proved complete; scripted
effect proofs check validation order, conflict rejection and rollback on read,
write and commit failures. This stage is not a public Rust operation and does
not establish the preceding file/lease/durability obligations. The generic
upsert capability carries only current/excluded column references, coalesce
and maximum expressions; Rust validates identifiers and executes a single
parameter-bound SQL statement without interpreting CAS state.

The whole ingestion command must preserve these observed input semantics:

- A small initial file stat selects read-to-EOF; the captured bytes' actual
  length determines the result, even if growth crosses the inline threshold.
- A large initial stat selects exactly that many bytes. Appended suffixes are
  ignored; truncation fails. The root describes the captured stream, not a
  claimed atomic filesystem snapshot.
- A root lease starts as soon as the hash is known and before final-path
  publication, survives metadata commit, and is never acquired inside an
  active SQL session. Acquisition must preserve existing connection/CAS-order
  lock ordering, not be implemented as an unsynchronized counter increment.
- Metadata settlement remains one transaction and preserves existing inline
  bytes through COALESCE and durable values through the existing SQL maximum
  semantics. It must decode raw rows inside Lean rather than receive spans.
  Its claim projection is exactly `[size, complete, durable, bitmap]`, with
  integer diagnostics at indices 0/1/2 preceding the optional-blob diagnostic
  at index 3. Reusing the local-read row decoder would introduce unrelated
  field validation and change error ordering. Reuse scalar/bitmap codecs but
  keep operation-specific row schemas explicit. The raw UPSERT interpreter
  needs narrowly typed current/excluded value, coalesce and maximum expressions;
  a host `commitComplete` callback or a precomputed durable boolean is not an
  acceptable substitute for these storage semantics.

Required raw host resources and compatibility improvements:

- Atomically create an exclusive temporary resource and retain cleanup
  ownership until replacement/removal. Current PID/counter names combined
  with `File::create` can collide after process-ID reuse; `create_new` is
  required. Protect live temporary resources from age-only staging GC.
- Exact/EOF reads, one construction pass into owned temporaries, checked
  file flush, close, atomic replacement and explicit removal are independent
  effects. Lean requests cleanup and selects primary failures; RAII covers
  abandonment.
- Unify payload publication behind flush-before-replace. The old large-file
  branch replaces before reopening and flushing, unlike byte ingestion.
  Windows requires a writable flush handle and replacement semantics equivalent
  to the existing write-through/retry helper; Linux/macOS use atomic rename.
- Directory synchronization must report success, unsupported operation or
  failure. Existing `fsync_parent` swallows errors, so the current host cannot
  justify a theorem claiming checked directory durability. Specify the
  supported-platform contract before wiring a stronger publication guarantee.

The captured-source ingestion program composes the construction request and
the metadata transaction internally. This is not a host callback for
publishing a CAS object: the host sees the construction request and the
individual raw resource requests. Its ownership schedule is:

| Phase | Live resources | Database transaction |
| --- | --- | --- |
| Acquire fresh payload/outboard temporaries | Source and distinct unpublished files | None |
| Host constructs payload and outboard from the source | Source and both temporaries | None |
| Close source, acquire keyed writer lease | Both temporaries and lease | None |
| Flush both files, replace both names, sync parents | Lease; each temporary until replacement | None |
| Decode claim and commit metadata | Lease protecting published files | One transaction |
| Release resources | No source, temporary or lease ownership retained | Closed |

The raw temporary allocator must use exclusive creation and register ownership
atomically against staging GC. That registry must be shared by independently
opened stores on the same canonical data directory, just like writer leases.
Checking an active set and then unlinking outside its synchronization is not
sufficient. No database guard is held during expensive file I/O, or while
acquiring a lease that itself follows the existing connection/CAS lock order.

Close and lease release consume their tokens even if they report failure.
Successful replacement transfers the temporary's pathname into the target;
subsequent idempotent discard of that token must never unlink the target.
Failed replacement leaves cleanup ownership with the invocation. Cleanup
always runs, but cannot replace a prior construction/publication/SQL error.
On successful work a cleanup failure remains observable. Host RAII releases
resources on abandonment; it does not make these domain sequencing decisions.

Directory synchronization uses an explicit backend policy: require successful
sync, or accept a reported unsupported operation on a configured platform.
Actual I/O failure is never accepted. The latter policy does not prove
directory persistence and cannot be described as such; Windows replacement
must still retain the existing write-through/retry semantics. The internal
captured-source command is composed by the whole `Cas/Input.run`
command described above; it is not separately exported as a Rust planner.
The production local entrypoints use that command unconditionally.

Local cutover validation includes the ingestion program's effect-trace
proofs, root and outboard fixtures, single-pass changing-file tests, native
transfer/allocation checks, failure injection across every file/construction/
lease/SQL effect, and deterministic GC-versus-publication tests. Cloud
adoption/finalization remain unfinished migrations; Bao construction, serving
and import are host services shared with them, so `compute_outboard` and the
resource pool's tee are production code, not a retained fallback. The memory
probe exercises only the mandatory public entrypoints.

### Current scope: stabilize migrated modules

#### Updated boundary: whole operations or Rust

The subsequent user direction rejects partially migrated production paths:
an operation must either be wholly implemented in Lean with raw host services,
or remain wholly implemented in Rust. Rust orchestration calling fine-grained
Lean domain decisions is not an accepted intermediate architecture. Together
with the existing freeze on new domain migrations, this means restoring mixed
paths to Rust, not extending their Lean migration.

CAS scalar settlement/commit-plan calls, mptsync scope/walk and completeness
coordination have been restored to Rust. Correctness fixes introduced during
migration are retained: depth-aware deduplication, retryable interrupted reads,
shared-payload waiters, terminal-epoch refusal and bounded certificate retention.
Complete local ingestion/read/repair, CAS lifecycle commands, trie lookup and
history retention remain in Lean. Fine-grained exports/adapters are deleted,
not merely unused. The proof package holds only theorems about that
executable core; the standalone models of Rust paths, and the anchors that
paired them with Rust sites, are gone.

Local validation: 431 tests passed across core/mpt/store/verified (seven ignored,
including the separately run fanout stress tests); all-target Clippy with
warnings denied, formatting, the full Lean build (1000 jobs) and the
complete-lookup link smoke test passed. New-head
cross-platform CI remains necessary before claiming platform validation.

The stabilization/refactor checkpoint below describes the preceding cycle, not
completion of this new all-or-nothing boundary change.

The current user-approved scope is correctness and stabilization of modules
already substantially migrated to Lean. Do not start or continue migrations of
new domains. Cloud ingestion, partial/network ingestion and the other unfinished
operations described in this document are deferred, not prerequisites for this
stabilization checkpoint. Their existing Rust implementations remain in place.

The review inventory is the existing production Lean surface: scope/authorization,
walk validation and scheduling decisions, completeness certificates, CAS
settlement and lifecycle operations, local reads/repair and complete local
ingestion, trie lookup/codec, and history retention. Include their native
transport, runtime lifetime management and raw host adapters. A partially
migrated subsystem does not authorize migrating its remaining Rust operations.

Review the production Lean entrypoints, their same-source proof coverage and
explicit host assumptions, FFI/resource ownership, failure and concurrency
behavior, compatibility and supported-platform CI. Fix defects and misleading
claims in the migrated paths; do not expand their scope to remove every remaining
Rust domain algorithm. Performance measurements remain explicit limitations,
not correctness or throughput-parity claims.

The user explicitly accepts retaining the documented walk proof limitation:
exhaustion is not yet proved to imply complete graph coverage, and certificate
soundness assumes validity supplied by the completed walk. Completing that
end-to-end theorem is not a prerequisite for this stabilization/refactor cycle.
Keep the limitation visible; do not strengthen the claimed guarantee. The gate
for starting glue refactoring is resolution of known defects and passing the
relevant tests, existing proof checks and supported-platform CI.

The uncommitted cloud-command experiment was withdrawn before native integration.
No cloud operation was switched, and no cloud-only raw host capability was added
to the production interface.

After stabilization, a second authorized phase reduces glue complexity within
this same inventory: eliminate fake `Storage` implementations for byte-only
operations, simplify capability routing, and consolidate repeated codecs/error
conversions. Preserve whole Lean commands, strict framing, original errors,
resource lifetimes and cleanup. Start that refactor only after known correctness
defects are resolved and the relevant local/proof/platform checks pass; take
small independently verified steps instead of replacing the entire FFI at once.

#### Stabilization baseline and first refactor

The executable baseline is `e6707dc`, CI run `34006870082`. Linux, macOS
and Windows native-link and engine checks passed, as did the existing Lean
proof check. All workspace test steps passed on all three platforms, including
the Windows default-feature and ignored fanout stress tests. These are test
results, not additional formal guarantees; the accepted limitations above remain.

The first refactor removes the private read-only `Storage` substitute. The
transport loop should depend on the host error type and an explicit request
dispatcher, not require every operation to implement relational storage.
Byte-only commands receive only byte-reading dispatch; relational commands
retain their existing capabilities. Unsupported requests remain protocol errors.
This also allows relational access/upsert routing to stay beside the storage
borrow instead of encoding it as optional function pointers in the transport.

Do not change the exported Rust APIs, Lean constructors, wire tags or schemas,
continuation/packet ownership, original error registry, or output publication
rules in this step. Validate byte-only missing-key and original-error behavior,
capability rejection, and the existing operation/store regression suites before
proceeding to shared diagnostic conversion helpers. No new host framework or
domain migration is needed for either step.

The first implementation removes the fake store, its nested error wrapper, and
the access/upsert function-pointer slots. The synchronous dispatcher retains the
backend borrow on the caller's stack; no callback crosses the native ABI. A
byte-only runner rejects relational requests immediately without a host call,
rather than returning a synthetic host error to Lean. Valid trie commands do not
request relational effects. Four regressions cover this rejection (both direct
dispatch and a native program), original error allocation identity, and absent
versus empty byte values. The post-refactor store/verified suite passed (335
tests, five ignored), as did all-target Clippy with warnings denied and formatting.
These local checks do not substitute for subsequent platform checks.

The second step shares only mechanical store-side diagnostics: CAS column-type
conversion and classification of filesystem failures as missing, short-read or
other. Keep operation-specific messages and domain-error mapping at each caller.
Preserve the original `StoreError` rather than reconstructing it from text or
classifying non-I/O errors as filesystem failures. No new public error type or
host capability is required. History's separately typed diagnostics, SQL query
validation, namespace rules and connection/resource guards remain unchanged.
The shared helpers have four regressions covering all five SQLite storage
classes, native index bounds, I/O classification, raw OS codes and original error
allocation identity. The combined store/verified suite and all-target Clippy
passed again after this step. Neither refactor changes Lean sources or the ABI;
cross-platform CI is still required on the final refactor commit.

### Bounded development validation

Native compilation and the repository's Lean packages limit each Lean compiler
to one thread and 4 GiB. Cargo's job count alone does not constrain Lean's
internal worker pool. After the development-session OOM, run heavy validation
sequentially (`CARGO_BUILD_JOBS=1`, test threads 1), and check individual changed
proof targets before the aggregate build. An OS process-group memory limit adds
protection for the whole build; a virtual-address limit is not an equivalent
measure for memory-mapped proof artifacts.
Use one active build/test scope with `MemoryMax=4G` and `MemorySwapMax=0`;
subagents must not start competing builds. After an interrupted session, inspect
surviving processes/scopes before launching another job. If the cap is reached,
inspect its memory events and narrow the work instead of raising the limit.

The transport proofs import only their executable runtime modules, not the
abstract model prelude. Fixed-width integer reads use one bounds check/state
transition; literal raw-cell fixtures are checked independently. This avoids
expanding large nests of state-monad reductions in the kernel. No proof uses
`native_decide`, unchecked axioms, or a replacement executable to avoid the gate.
