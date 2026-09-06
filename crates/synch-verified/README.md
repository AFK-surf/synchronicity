# Statically linked, verified Lean decisions

This is the first implementation milestone, not another handwritten model.
`lean/VerifiedCore.lean` contains the executable authorization and CAS size
settlement functions. Cargo compiles that source to C and statically links it
with Lean's runtime. `specs/lean` imports the **same source package** and proves
the functions agree with the abstract scope and CAS contracts.

## Mandatory integration

### Architecture and staged operation migration

The [Lean-core architecture](../../docs/LEAN-CORE-ARCHITECTURE.md) supersedes
the snapshot/planner boundary below. Lean owns whole operations, including raw
metadata decoding, sequencing and failure recovery; Rust supplies host effects.
CAS, trie, authorization, replication and publication follow the same rule.

`VerifiedCore/Host.lean` supplies a typed executable effect monad and transaction
combinator. New `Cas/Program`, `Trie/Program` and `Replication/History` modules
implement acquisition, lookup (including the postcard codec), and retention
over raw storage effects. CAS pin/possession acquisition now uses that complete
operation in production. The shared synchronous continuation interpreter asks
Rust only for raw storage effects; Lean owns begin/read/mutate/commit/rollback.
The old acquisition snapshot/planner API and Rust orchestration are deleted.
CAS deletion also owns raw protection reads, transaction completion and file
cleanup; its snapshot/planner ABI and Rust phase executor are removed.
Trie lookup also runs as a complete native Lean operation over raw byte reads;
the former Rust lookup traversal is removed. History retention now runs as a
complete Lean operation over raw scans and a separate Ed25519 primitive; the
Rust retention loop and receipt/fork helpers are removed. Raw scans retain
rows before a trailing host failure so Lean owns first-error selection.
No selectable backend is added.

Local CAS reads now execute `Cas/Read.lean`, including metadata/bitmap decoding,
bounds, coverage, inline/file reads and transactional missing/truncated-file
repair. Both Rust read algorithms and the local healing transaction are removed.
Raw snapshots release their connection before file I/O; one file handle survives
bounded positioned reads. Separate `Output.append` effects fill a private Rust
buffer, published only after a successful terminal byte count. Lean never
serializes a whole-object return buffer. File, clock, output and relational
capabilities remain independent of CAS policy. Same-source read/codec/healing
proofs and native/SQLite fault tests cover this boundary; cloud hydration and
Bao serving/import remain separate unfinished operations. See the architecture
document for isolated allocation measurements and remaining performance gates.

The next ingestion stage is `Cas/Bao.lean`: a bounded-buffer constructor owns
the BLAKE3 tree, chunk counters/ROOT flags and preorder outboard placement in
Lean. Its raw capabilities are exact reads, positioned writes and chunk/parent
cryptographic primitives. It is compiled from the same source as its geometry
and effect proofs, but is **not yet called by production ingestion**. No new
Rust subtree/planner facade is added. Whole-command staging/lease/publication
orchestration and primitive integration are implemented below; the complete
stateful layout proof and remaining native gates are required before deleting
Rust ingestion. The architecture document
records changing-file behavior, temporary-file/GC hazards and durability gates.

The staged `Cas/IngestCommit.lean` owns claim decoding, settlement and atomic
metadata mutation over raw storage effects, without exposing a Rust planner
facade. Its transaction/error proofs and the inner hash tree's conditional
Lean recurrence proof strengthen this stage; neither constitutes a whole
ingestion cutover or a proof of native cryptographic correctness.

`Cas/Ingest.lean` now composes construction and metadata commit with raw
temporary-file and keyed-lease effects for an already captured, out-of-line
source. Lean owns cleanup, both flushes before publication, directory-sync
policy, and lease release after the transaction. Fault traces cover every
effect on the empty-source execution path. `Cas/Input.run` now adds byte/file
input acquisition and inline/EOF policy, with a whole-command native facade
and a raw filesystem/lease interpreter. Real SQLite/file tests check roots,
payloads, Bao layout and failure cleanup, including a 19-case effect-failure
matrix, deferred COMMIT rollback and deterministic GC/publication concurrency.
`BaoGroupingProofs.build_matches_chunkTree` proves conditional agreement of
the whole builder with an ordinary chunk tree, assuming coherent immutable
reads, successful writes and the raw compression contract—not a Rust tree.
`BaoLayoutProofs` proves exact slot enumeration and links every slot to a
required executable write. Equality with an accumulated stateful write trace,
remaining transfer-memory checks and platform gates still precede production
cutover and deletion of Rust ingestion.
The raw chunk/parent cryptography adapter is staged privately in the store
crate; it contains no tree traversal or CAS decisions.

The acquisition cutover is checked against real SQLite, including abandoned
transactions, automatic rollback, deferred commit failure, UPSERT timestamp
preservation and the existing typed errors for corrupt durability cells.
`HostWireProofs` checks Lean-side reply framing and continuation behavior;
native tests check the C/Rust transport. Neither is a proof of physical I/O.

Acquisition checkpoint validation (`e543883`): all 475 tests across `synch-verified`,
`synch-store` and `synch-engine`; focused all-target Clippy with warnings denied;
the full Lean warnings-as-errors build and anchor check. Builds were run
sequentially with bounded compiler memory after the development-session OOM.
This does not claim the remaining domains or new cross-platform CI are complete.

### Domain boundary

The CAS algorithms live in `lean/VerifiedCore/Cas.lean` and `Cas/Program.lean`,
independently of the trie module. Pin/possession and deletion are complete
monadic operations. The deletion snapshot/planner ABI has been removed; its
pure decision is internal Lean code, consumed and proved by the operation.
There are no Lean callbacks registered with SQLite.

The Rust facade retains ordering locks while Lean requests raw reads,
transactional mutations, commit/rollback and post-commit file removals. Lean
selects best-effort cleanup and primary-error handling. SQL semantics, locks,
primitive I/O and ABI decoding remain explicit trust boundaries.
`CasLifecycleProofs.lean` proves the executed deletion outcome agrees with its
proved decision, transaction failure prevents cleanup, and committed deletion
attempts both files irrespective of unlink errors. Raw counter/file services
use a separate capability from SQL; relational existence reads remain bounded.
Bulk operations must remain batched; do not add per-row SQL callbacks.

This is a consolidation step, not the final API: bitmap planning/size helpers
still have their earlier adapters; trie/sync and ingestion/publication need
their own cohesive domain boundaries rather than expansion of this CAS API.

Every build uses Lean 4.30.0 for scope/path/key/node/payload decisions and CAS
size settlement and bitmap commit planning, plus completeness certificate state transitions. The corresponding Rust implementations and feature flags
have been deleted. The shared `synch-core::group_count` API also delegates to
Lean. Rust code in the native tests/example is an independent test oracle,
not a selectable production backend.

Supported targets are native Linux GNU and macOS (x86-64/arm64), and Windows
x86-64 GNU/LLVM. OpenBSD and Linux musl support has been removed. The build
rejects incompatible runtime architecture/ABI instead of linking host archives
into a cross-target binary. Release CI uses architecture-matched runners.

Install Lean 4.30.0 through elan, then from the repository root:

```sh
cargo test -p synch-verified
cargo test -p synch-mpt -p synch-store
cargo test -p synch-engine --test delegation
cargo build --release --bin synch
cargo run --release -p synch-verified --example decisions
cd specs/lean && lake build --wfail && ./check-anchors.sh
```

### Windows

Lean ships an LLVM/MinGW UCRT runtime, not an MSVC C++ runtime. Install the
MSYS2 CLANG64 toolchain and `rustup target add x86_64-pc-windows-gnullvm`.
In PowerShell (adjust the MSYS2 installation prefix if needed):

```powershell
$env:CARGO_BUILD_TARGET = "x86_64-pc-windows-gnullvm"
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER = "C:/msys64/clang64/bin/clang.exe"
$env:CC_x86_64_pc_windows_gnullvm = "C:/msys64/clang64/bin/clang.exe"
$env:AR_x86_64_pc_windows_gnullvm = "C:/msys64/clang64/bin/llvm-ar.exe"
$env:PATH = "C:/msys64/clang64/bin;" + $env:PATH
cargo test -p synch-verified
cargo build --release --bin synch
```

Windows artifacts now use the `x86_64-pc-windows-gnullvm` suffix instead of
`x86_64-pc-windows-msvc`. They remain native Windows executables. CI installs
the same toolchain through `.github/actions/setup-lean-core`. Linux release
artifacts use `linux-gnu` instead of `linux-musl` and require system glibc.

No generated C is checked in. Cargo generates it in its own `OUT_DIR`, so
parallel target/profile builds do not race on shared generated artifacts.
Mathlib is needed for the proof build, not the native build or runtime.
The build checks the Lean version and runtime target triple before linking.
The toolchain's Std, Init, runtime, GMP and libuv archives are linked statically.
Linux and Windows also link the bundled C++ support statically; macOS uses
Apple's system libc++. OS libraries remain dynamic dependencies.

## What is proved

`specs/lean/Synchronicity/VerifiedCoreProofs.lean` proves:

- scope position, subtree, key, node and payload decisions match the existing
  positional predicates, including exact grants and refused spine values;
- exported node/payload decisions implement those predicates for decoded shapes;
- UInt64 group counting agrees with the unbounded CAS definition, including
  zero and `u64::MAX`, without overflow;
- settlement accepts exactly the allowed claims, resets bits exactly when
  required, and implements `Cas.Settles` given the row's representation facts.
- CAS bitmap normalization preserves exactly the in-bound input groups; the
  production commit planner represents exactly retained plus incoming groups,
  rejects conflicting durable/complete sizes, and reports complete exactly when
  every group is covered. Output intervals are proved nonempty, bounded, sorted
  and strictly separated; exporting their UInt64 endpoints round-trips without
  truncation. Sorting and merging operate on runs, not blob bytes.
- the executable certificate cache rejects stale/terminal tickets, hides
  retained roots during mutations, retains only permitted roots at begin,
  advances nonterminal epochs, restores nesting depth at finish, and preserves
  certificate soundness when a completed walk supplies validity of its query.
- the actual frontier scheduler selects only pending, depth-bounded, unseen,
  non-reference-equal positions; checks depth before shortcuts; preserves
  pending work on resume; refuses unadmitted child positions; and cannot report
  exhaustion while deferred work or a sticky depth fault remains.
- CAS lifecycle plan proofs are in the independent `CasLifecycleProofs` module
  described above. The obsolete per-step implementations and proofs are removed.

`MissingWalk` also owns its frontier, seen set, deferred retries, per-batch
payload request set and extension-child requirements in Lean. Its sets use
persistent balanced trees: marking objects thread-shareable prevents exclusive
array updates, so a hash table would copy its bucket array on each insertion.
Rust still decodes nodes and supplies structural fields, payload and storage
observations. Lean enumerates children, pairs reference edges only at identical
relative paths in compatible shapes, and schedules admitted children. Proofs
show pairing preserves every target edge, invents none, and any retained
reference follows the exact same step. Expansion retains the parent across all
siblings. There is no production Rust child-pairing implementation.

The loaded-node observation transition also validates extension-child shapes
and absolute leaf depth before expansion, then handles payload authorization,
deduplication and deferral. The absent-node transition decides whether a
positional refusal satisfies the walk. Rust only supplies decoded shapes,
optional payload hashes and storage observations. Shape and depth failures are
sticky; neither polling, resuming nor later observations can clear them.
Proofs cover refusals inside grants, refused spines, shared-payload deferral,
authorization, leaf depth, pending extension obligations and fault persistence.

Lean also enforces the observation sequence. A selected read remains pending
until an absent/present observation acknowledges it. Poll and resume preserve
that read across I/O or decoding failures; pending reads prohibit exhaustion.
Unsolicited or duplicate observations fail closed. The Rust API exposes only
poll, observations, resume and batch reset, not independent frontier/seen-set
or obligation mutations. Native and Rust-adapter fault-injection tests exercise
this protocol; the complete graph-coverage invariant is still pending.
An execution relation over these exact Lean exports proves that every pending
read has an identified position throughout arbitrary finite operation sequences.
Repeated polling preserves that position, and expansion preserves all work
already on the frontier. These are intermediate invariants, not yet a proof
that exhaustion implies complete graph coverage.
Coverage lemmas additionally show that every admitted target edge is scheduled,
every position removed by a successful poll is selected or explicitly skipped
by the reference/seen-set guard, and the native observation export preserves
the expanded frontier through payload handling and acknowledgement. Soundness
of those shortcuts across the complete execution is still to be established.

Visit keys include absolute depth as well as hash, including inside grants.
Without depth, a shallow visit could suppress validation of the same leaf at
an invalid deeper position. Within grants, shared nodes deduplicate at the
same depth; different depths require separate validation. Outside grants the
full position is retained. Proofs show equivalent keys preserve child and
payload authorization, child visit equivalence, and leaf-depth validation.
This adds a depth factor to worst-case shared-DAG traversal, bounded by the
canonical depth ceiling; existing cold-fetch/incremental read-cost tests pass.

`Store` and `MemStore` use Lean's cache state and epoch guard. Rust owns the
mutex and supplies byte keys, retained-root inputs, and storage effects; it
does not update generations, decide retention, or implement certification.
The cache currently uses finite lists; optimizing that representation must
preserve the executable proofs rather than introduce a second Rust backend.

This does not prove the C adapter, Rust node-to-shape mapping, SQL row decoding,
or that the caller holds the transaction lock. Those remain explicit trust
boundaries tested by native property tests and real subsystem regressions.
Neither cryptographic verification nor filesystem effects have moved to Lean
in this milestone. The Lean compiler/runtime and native toolchain remain
trusted, as do the standard library's implemented primitives.

## ABI and lifecycle

Only the adapter handles `lean_object` pointers. Rust owns an opaque immutable
scope through `Arc`; it cannot construct arbitrary Lean values. The C adapter
copies input bytes, converts path arrays via Lean exports, marks the complete
scope graph multi-threaded before sharing, and supplies a fresh owned Lean
reference to each consuming export. Scope contents are never mutated.

Initialization is once per process. Foreign Rust threads are initialized lazily
and finalized through TLS. A scope stored in an older Rust TLS slot may outlive
that guard; its final destructor temporarily reinitializes the thread before
releasing the object. Dedicated tests cover cross-thread calls/drop and this
TLS destruction ordering. Allocation failure is not recoverable at this ABI.

The scalar settlement API accepts normalized booleans and bounded integers,
returns a checked discriminant, and carries no erased proof arguments. The
caller supplies the actual row facts from its transaction. Unknown shape tags
fail closed in Lean; they cannot be manufactured through the public Rust enum.

## Performance and next gates

The `decisions` example is an informational benchmark, not a CI timing gate.
An initial run here measured 330–826 ns per Lean payload decision versus
14–64 ns for the Rust oracle across full, 1-, 16- and 64-prefix scopes. The
native benchmark executable was 2.9 MiB and had no dynamic Lean dependencies.
These are workload/machine-specific observations, not production guarantees.
Per-call byte copies and conversion to lists dominate small predicates.

Next: optimize/batch the boundary, benchmark real trie walks, and expand the
source-based proofs as the incremental walker and promotion planner move.
Moving a policy into Lean does not by itself verify the external effects that
Rust performs in response.

## Remaining migration (goal not complete)

The end state is executable Lean core logic with proofs about that same Lean,
not a manually reviewed correspondence between Rust and an abstract model.
The following are still required:

- Prove completeness of the executable trie walk across its storage-observation
  protocol, including graph coverage and reference validity. Interruption and
  response-sequencing guards are now enforced and proved in Lean. Its
  scheduling, child pairing, walk canonicality and payload/boundary decisions
  are now Lean; the cache still trusts a completed walk's validity. Other trie
  operations and ingestion-time canonical encoding checks also remain Rust.
- CAS bitmap settlement now runs in Lean, with canonical output and lossless
  endpoint serialization proved. CAS row deletion policy and effect order also
  run in Lean, as do pin acquisition, want-to-pin possession, explicit unpin,
  scheduled expiry, and local reads/repair. Move remaining accounting,
  GC candidate selection, trie GC, remote cache eviction/healing, Bao
  serving/import, and publication/promotion decisions.
- Move ingestion and materialization sequencing into Lean-generated effect
  plans; discharge the flush-before-advertise and publication invariants over
  those executed plans, not over independent abstract Rust descriptions.
- Move head adoption, fetch progress/retry and provenance decision logic into
  Lean, connecting the executable transitions to system safety/liveness proofs.
- Replace remaining manually paired `LEAN-MODEL`/`rust_impl` sites as their
  algorithms move. Keep only explicit ABI, serialization, cryptographic primitive
  and I/O trust boundaries, with tests and contracts for the narrow adapters.

The abstract `Completeness` module remains useful for reasoning about changing
stores, but its old Rust-transition anchors were removed. Production cache
sites now point to theorems about the actual exported Lean implementation.
