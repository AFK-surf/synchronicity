# Lean-owned domain operations and host effects

Status: implementation architecture, 2026-09-05. This supersedes the incremental
predicate/snapshot-planner approach in PR #127. It is a target and migration
contract, not a claim that the repository already implements it everywhere.

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
| CAS | Ingest/read/serve/import/promote; Bao tree and group arithmetic; metadata codecs; size attestation; holds/wants; healing, eviction and collection; durability ordering | Raw metadata records, object reads/writes, flush/truncate/remove, provider I/O, primitive hashes |
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

`EffectSum` composes typed capabilities without merging their algebras. History
uses storage plus a separate `Crypto.validateEd25519` primitive. Its requests
carry only key bytes and return validity or an opaque host failure, never a
decoded origin/head. `transactionOver` injects storage requests into the chosen
composition; storage-only `transactionWith` remains a specialization of that
same algorithm. Adding crypto does not add crypto methods to storage services.

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
delete its Rust algorithm and obsolete low-level exports; update proof anchors.
Do not retain a selectable Rust backend. Staged, unintegrated code is allowed
during development but must be identified as such, not counted as completion.

Run Lean `lake build --wfail` and anchors, focused Rust tests and Clippy during
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
  interpreted by the actual decoder. Codec roundtripping/canonicality and
  mutable-host refinement remain separate obligations. Native commands must
  enforce the existing 32-byte root type before constructing an operation.
- Native tests now cover acquisition transport, every effect-failure position,
  repeated polling, malformed replies and terminal resume. Generic SQLite tests
  cover UPSERT identity/time preservation, raw cells, failed commit, abandoned
  sessions and automatic SQLite rollback. These are contract tests, not a proof
  of the C/Rust implementation or physical storage behavior.

### Current native transport

`Host/Wire.lean` encodes raw requests and decodes replies. `Entry.lean` alone
imports domains to construct commands; the shared transport imports no domain
policy. Packets begin with version 1 and a discriminant, with little-endian u64
integers/lengths and length-delimited UTF-8/bytes. Requests encode explicit
relation/projection/equality/upsert values. Replies preserve raw signed cells,
NULL, empty values, absence and original host failures. Decoders reject unknown
versions/tags, wrong effect reply types, truncated or trailing data and lengths
that cannot fit the remaining packet before allocation.

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
internal polling is inert; completed programs cannot restart. No SQLite guards
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
require SQL or transaction services. Domain command construction and terminal
result decoding live in the domain facades, not the common continuation runner.

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
the error the operation chose. This implementation does not yet expose an async
resumption API; any such API needs explicit request identity and cancellation
contracts rather than exporting the current private pointer operations.

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

- Migrate local reads with raw metadata decoding, bounds/coverage, positioned
  file reads and healing composed inside Lean. Preserve original I/O errors
  unless healing fails. Host callbacks cannot supply verified groups or heal
  domain state on Lean's behalf.
- Ingest needs bounded file capabilities, unique staging, rename, flush,
  truncate, directory durability and writer leases. Lean owns Bao construction
  and publication ordering. Preserve streaming and keep expensive I/O outside
  SQL transactions; a whole outboard builder is not a primitive hash service.
- Remote adoption/finalization must compose raw provider I/O around metadata
  transitions. Moving only a durable-flag setter leaves the core ordering in
  Rust; provider pair validation/upload is likewise CAS policy, not a primitive.

The next local-read implementation should share a Lean internal `all | range`
request, with row decoding, saturating bounds, permissive bitmap decoding,
coverage and inline/positioned reads inside that operation. These trusted local
reads do not currently verify hashes. Missing/truncated payloads invoke Lean
healing and then return the original I/O error; if healing fails, its error
takes precedence. Preserve the absent-row healing no-op, operator claims and
existing wants. Healing re-reads size transactionally and selects standing roles
using current SQLite ASCII-insensitive `LIKE` semantics, not typed-holder parsing.
It needs generic updates, conflict-ignore inserts and an on-demand clock, not a
Rust `heal` callback. Ordinary filesystem reads must not hold an immediate SQL
transaction. Consolidating `read_all`'s current two metadata reads removes a
race and needs explicit concurrency coverage; corrupt short inline payloads
need an explicit failure instead of the current slicing panic.

Local read migration alone does not complete cloud reads. The cloud wrapper
still owns adoption, missing-group hydration and success-only access touch;
eventually compose those in Lean over raw provider ranges. Bao slice serving
and import additionally require Lean traversal/verification. Do not relabel the
existing Rust range hydrator or Bao encoder/decoder as a raw host capability.

#### Staged local read/healing program

`Cas/ReadCodec.lean` and `Cas/Read.lean` now implement the proposed complete
local read and transactional repair in the shared Lean source. They are compiled
by Cargo and imported by the proof package, but **not yet called by production
Rust**. The old Rust read/healing paths must be removed on native cutover; these
definitions do not count as that cutover or as completed CAS verification.

The program owns ordered raw row validation, postcard bitmap decoding and
coverage, range arithmetic, inline validation, physical reads and repair/error
ordering. Reads retain one open file handle across at-most-64-KiB transfers and
close it before repair or return. Chunks accumulate in a list and flatten once
after I/O; appending a growing buffer across suspended continuations could
otherwise repeatedly copy retained prefixes. Native allocation benchmarks are
still required. A malformed successful file reply is an error,
not a silently shortened result. Missing/truncated data triggers repair;
unrelated I/O failures do not. Successful repair returns the original I/O error,
whereas repair failure takes precedence. The on-demand clock follows metadata
invalidation, preserving the existing ordering.

`Host/Access.lean` describes missing **raw** capabilities separately from domain
commands: statement-scoped snapshot scans, literal updates, atomic INSERT SELECT
with conflict-ignore behavior, and selected bulk deletes. A selection supplies
literal equality fields plus an optional disjunction of SQL LIKE terms. The
file capability provides open, exact positioned reads and close; the clock is a
separate algebra. Native integration must share the existing whitelisted query
construction and transaction handling, not grow a second SQL policy engine.
Snapshot connections end at statement completion; only the healing transaction
retains its connection scope. File handles need abandonment cleanup and original
error tokens with truthful generic I/O classifications.

Remaining cutover gates include native packet/terminal encoding, interpreting
these raw capabilities with scoped SQLite/file resources, real-storage failure
and concurrency tests, large-input allocation/transfer checks, replacing both
public reads and local healing, and deleting the obsolete Rust algorithms and
their old abstract-model pairing anchor. Current proofs check actual Lean
decoder fixtures and operation executions; they do not establish the pending
native interpreter or physical storage guarantees.

Subagents may edit disjoint domain/proof/test files, but only the primary runs
heavy validation. Inspect surviving processes after interruption; never launch
a replacement build while its original process is still alive.

### Bounded development validation

Native compilation and the repository's Lean packages limit each Lean compiler
to one thread and 4 GiB. Cargo's job count alone does not constrain Lean's
internal worker pool. After the development-session OOM, run heavy validation
sequentially (`CARGO_BUILD_JOBS=1`, test threads 1), and check individual changed
proof targets before the aggregate build. An OS process-group memory limit adds
protection for the whole build; a virtual-address limit is not an equivalent
measure for memory-mapped proof artifacts.

The transport proofs import only their executable runtime modules, not the
abstract model prelude. Fixed-width integer reads use one bounds check/state
transition; literal raw-cell fixtures are checked independently. This avoids
expanding large nests of state-monad reductions in the kernel. No proof uses
`native_decide`, unchecked axioms, or a replacement executable to avoid the gate.
