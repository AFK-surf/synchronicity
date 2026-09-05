# CAS / mptsync / ingestion Lean models

These are mathematical models of the Rust contracts, **not isomorphic Rust
semantics or a machine-checked refinement of Rust**. Named anchors identify
implementation sites and are checked in both directions; they do not prove
the correspondence. Regression tests exercise the security and concurrency
boundaries against the implementation.

A mandatory production core now lives in
[`crates/synch-verified`](../../crates/synch-verified/README.md). Its executable
Lean source is compiled and statically linked from Rust; this proof package
imports that same source and proves its decisions match the abstract models
in `VerifiedCoreProofs`. This closes the handwritten implementation/model gap
for those decisions, not for the
entire Rust engine or its FFI/storage effects. The native package imports no
Mathlib. Builds require the pinned Lean toolchain on Linux GNU, macOS, or
Windows GNU/LLVM; there is no alternative Rust implementation.

```sh
cd specs/lean
lake build --wfail
./check-anchors.sh
```

Mathlib is pinned through the lake manifest and toolchain. Use
`lake exe cache get` to fetch compiled dependencies. Every module ends in
`#lint`; warnings, undocumented definitions and unused arguments fail CI.

## Model layers

| Module | Contract |
|---|---|
| Prelude / Anchors | Transition, System, reachability, invariant and simulation infrastructure; checked Rust anchors |
| Cas | Holder/root-indexed accounting, size settlement, partial bitmaps, counted write leases, pins/wants, source/replica/ordinary roles |
| SystemSafety | Fault-free CAS invariants: pins have available content, source references are pinned, advertised size agrees with settled size |
| FaultTolerant | Physical remote/local loss and healing; claims survive loss until observed; role pins become repair wants |
| Ingestion | Authenticated staged groups, successful flush, bitmap commit and crash as separate events |
| Scope / ScopedSync | Positional trie walk, key-level payload authorization, privacy, boundaries and sound reference pruning |
| Provenance | Per-origin ownership, delegated publication chains, anti-laundering integrity/privacy |
| TrieGraph / MptGc | Multi-root store projected to head-slot/retention state, including boundary-dissolving arrivals and mark/sweep |
| Completeness | Generation-checked walk tickets, memo certification and transaction invalidation |
| Convergence | Head selection, finite fetch progress, actual readability versus refusal |
| Materialization | Origin-indexed head identities, decoded rows, functional delta and row-derived CAS references |
| Bridge / Publication | Atomic accounting/head-flip pairing and temporal source publication contract |

## CAS and ingestion

`Cas.Invariant` survives every modeled accounting step, including heals:
roles' pins have durable claims, live roles have a pin or a want, and held bits
lie within their row's tree. `Cas.NoLoss` additionally requires physical
availability, source pins and consistent source sizes; only fault-free steps
preserve it. `SystemSafety` proves both; `FaultTolerant` keeps only the former.

Remote presence and a remote-tier acknowledgment are distinct. Cache eviction
consults the acknowledgment, not hidden physical presence. Thus eviction after
unobserved remote loss is a legal fault trace
(`eviction_after_unobserved_loss`), and healing withdraws the claim.

The row's size is a claim until durable or attested by its final group.
`Settles` and `settleHeld` model accepting a corrected untrusted size and
discarding bits from an incompatible group count. Settled sizes remain fixed.
The Rust `size_bracket` regression uses a real bao proof which verifies under
an incorrect size in the same tree bracket, then checks honest recovery.

`Ingestion` models the lower pipeline for one root and settled tree shape:
verification writes authenticated group contents, successful payload/outboard
flush moves staged contents to stable storage, and only then may a database
commit advertise them. Crashes discard unflushed writes. `complete_has_bytes`
derives actual stable content from the pipeline invariant; it does not define
byte presence as bitmap completeness. `unflushed_cannot_commit` rejects an
advertisement with no successful flush. `commit_refines_bitmap` connects the
lower committed groups to `Cas.settleHeld` at the settled size.

This lower model does not prove bao verification, inline representation or
cross-shape size settlement. Its authenticated-content equality guard and
successful-flush semantics are explicit environmental assumptions. The Rust
verifier and filesystem implementation must satisfy them. The accounting
model is intentionally coarser and is not, by itself, a physical-byte proof.

## Scoped synchronization and certificates

The responder authorizes by position under a known head. `ServeNode` protects
node coverage; `ServeValue` separately uses `AdmitsValue`. A spine branch can
reveal child hashes without granting its own payload.
`held_payload_key_granted` proves the value's key is authorized. Rust's fetch
and scoped materialization diff obey the same boundary; the wire-level
delegate regression checks denial, successful promotion and public data.

Refusals are keyed by hash and position. A refused position is a boundary only
while its node is absent. Learning a previously refused node, including adding
an already-held node to an origin's ownership view, can expose missing
descendants. `TrieGraph.LearnNode` includes that transition and projects to
`MptGc.Recheck`. An active head remains retained and materialized but need not
remain complete. A head slot is not a completeness certificate.

`Completeness` models snapshot tickets and usable cache entries separately.
Non-monotone mutations invalidate before visibility, block certification while
uncommitted, and advance the generation on both transaction edges. Old or
in-transaction tickets cannot restore stale memos. Rust shares the coordinator
across independently opened handles; resumed fetches restart without an old
pruning reference when the generation changes. Certificate comparison and
insertion share a lock. GC selects retained certificates and invalidates in
the sweep transaction. Concrete ordinary-arrival and retained-GC lemmas
instantiate the abstract certificate obligations.

`Provenance` supplies per-origin views and delegation chains. Its privacy and
integrity theorems exclude republishing nodes that no legitimate delegation
chain could have supplied; they intentionally allow a confined origin to
republish content it legitimately holds.

## Progress and materialized views

Equal heard-head sets select equal heads under the total sequence/root order.
For a whole finite trie served by an answering peer,
`fetch_reaches_complete` constructs a finite fetch trace to completeness:
the theorem no longer merely assumes a terminal state. No separate
`Productive` admission assumption is needed for payloads.

`ReadableOrRefused` is deliberately not actual readability. A granted key can
still lie below a refused spine node. `complete_reads_unobstructed` establishes
actual carrier **and payload** availability when that key has no such barrier.
No unconditional all-granted-keys availability claim is made.

`Materialization.commit` updates one origin's actual root and applies the
old/new decoded-view delta to its rows. `commit_consistent` proves those rows
match the selected root and preserves other origins; `rows_converge` proves
equality of committed rows for equal heads. `References` derives CAS live
references from these rows, and `reference_has_selected_leaf` ties them to
decoded leaves of the exact selected head. The guarded `Promote` requires
actual readable/decodable values in its store snapshot;
`promoted_row_was_readable` excludes treating refusal as a successful read.
`withReferences` computes the CAS live sets and advertised source sizes from
those rows. `row_derived_source_available` composes that projection with a
legal accounting trace, so arbitrary independent live bits cannot satisfy the
composed contract.

The older `Bridge` is an accounting projection. Its permitted microtraces
alone do not establish semantic head/row correspondence. SQL decoding,
successful readability of the decoded view, and refinement of the Rust
structural diff to the functional delta remain explicit obligations.
`Publication` proves availability and settled-size stability while a source
reference stands, conditional on that accounting correspondence.

## Trust boundary and remaining scope

- LifecycleLock excludes another process owning the data directory; handles
  within a process share CAS ordering and completeness invalidation.
- SQLite transactions are atomic. Lock ordering and SQL semantics are reviewed
  and tested, not formalized as Rust operational semantics.
- Verified content hashes identify the intended bytes. The crypto libraries
  and decoding functions are trusted.
- The filesystem/backend meets its successful-write/flush contract.
  FaultTolerant models later loss; Ingestion models loss of unflushed staging.
  Whole-node recovery and cross-file/database crash recovery remain the domain
  of `specs/Recovery.tla`, not an end-to-end Lean recovery theorem.
- Gossip delivers heads and enabled fetch steps eventually run. Scheduling,
  churn, deadlines, bounded retries, batch-resume implementation and resource
  ceilings are not proved by the finite productive-fetch theorem.
- The new semantic/physical layers strengthen the contracts, but no theorem
  composes Rust, SQL, crypto, networking and storage into full implementation
  correctness. Anchors and regression tests check, rather than prove, that
  final refinement boundary.

## Contributing

Definitions modeling Rust sites carry `@[rust_impl "anchor"]`; justification
theorems carry `@[rust_justifies "anchor"]`. The Rust site carries
`// LEAN-MODEL: anchor (Module.Decl)`. `lake exe anchors` and
`check-anchors.sh` check both directions. Keep anchors at the actual operation,
not a nearby comment after it.

State new events as guarded transitions and prove invariant preservation over
their union. Do not omit a runtime event merely because it breaks a proposed
invariant: model the event and state the narrower true guarantee. Separate
physical state from claims, head identity from flags, and actual reads from
refusals. Name theorem assumptions explicitly and add an executable regression
for each repaired implementation boundary.
