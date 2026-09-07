# Shared simulated host for Lean proofs

[SimulatedHost.lean](../specs/lean/Synchronicity/SimulatedHost.lean) interprets raw
host effects against one `State`. CAS ingestion, reading, healing, acquisition,
release, expiry, collection, and history retention use the same interpreter.
The former per-operation reply scripts and `Handlers.lean` are removed.

## State and execution

`State` contains committed database tables, an optional transaction-local copy,
files keyed by namespace and object key, open handles, temporaries, writer leases
and counters, the completeness certificates and their generation, a private
output buffer, the clock, and the effect trace.

`Interpreter` has one implementation per raw capability. Its `EffectSum` instance
composes capabilities without changing their behavior. `execute` interprets the
actual `Program` constructors; `run` starts an operation with a fresh private
output buffer. It returns the outcome and the complete updated state. For example:

```lean
let stored := SimulatedHost.run (Input.run (.bytes size) now .local) initial
let held := SimulatedHost.run (acquire root holder now false) stored.2
let read := SimulatedHost.run (Read.read root .all) held.2
```

There is no ingestion-to-reader conversion and no host callback that computes
coverage, size settlement, pin protection, or repair policy. Those decisions
remain in the imported production Lean operations. Fixtures construct raw rows
and files; they do not implement effects or provide successful replies.

`publish` exposes a buffer only after successful completion with a matching byte
count. `abandon` models invocation cleanup: abort pending database work, drop
private output, close owned handles/temporaries, and release owned leases while
preserving committed rows and published files. `execute` and `run` do not silently
invoke abandonment; tests can distinguish explicit program cleanup from the
host's abandonment contract.

## Raw semantics

[Database.lean](../specs/lean/Synchronicity/SimulatedHost/Database.lean) implements
projection, equality selection, LIKE selection, joins, ordering, correlated
exclusions, bounded deletion, updates, and upserts. It knows no CAS table names.
Affected-row counts come from mutations of actual tables.

A transaction reads its own writes. Snapshot observations use committed state;
commit publishes the transaction-local database, and rollback discards it.
The model runs sequentially and does not claim concurrent or crash refinement.

Files and resources have shared identity across commands. Opening a file retains
its bytes under a handle; replacing or removing its pathname does not change that
handle. Transfers check the requested bounds and append the actual slice. Missing
files and short reads arise from file state, not configured success/failure
replies. Temporaries are created, filled, flushed, replaced, and discarded through
raw capabilities. Lease acquisition/release changes the counter collection reads.

`Storage.deleteExcept` keeps exactly the rows whose key column names one of
the kept keys, with SQL `NOT IN` semantics for NULL (a NULL key is neither in
nor out of the set, so the row stays). It touches rows only: the payloads a
content-addressed relation serves through `readBytes` live in the file
namespace of the same name, which a fixture keeps consistent with the rows.
`Memo.forgetExcept` filters `certified` down to the kept keys and advances
`memoGeneration`; `Digest.blake3` answers with the same `hash` parameter
construction hashes with. `Redaction.isRedacted` answers whether `redacted`
records the hash, at the given position or at any; `Apply.applyChange`
appends the change to `applied`, in the order it was handed over.

`faults` selects ordinary failures by effect index in the accumulated trace.
`scanFault` models a failure after the returned scan prefix. Failed ordinary
mutations do not apply; consuming cleanup operations still consume their resource.
The clock and directory-sync support are environmental inputs. Hashing, outboard
construction, and public-key validation are explicitly parameterized primitives.

## Checked scope and limitations

This is an executable semantics for the raw operations used by the proofs, not
an implementation or verification of SQLite, a filesystem, or cryptography.
Relational comparisons cover the typed CAS/history schemas. The model does not
implement SQLite affinity, arbitrary collations, numeric mixed-type ordering, or
its full malformed-text behavior. General repair key theorems require canonical
blob roots and text holders. LIKE supports ASCII case folding, `%`, and `_`.
The Bao service is a trust parameter like the hash: `State.slice` and
`State.proof` say what the host would encode for exactly the groups it is
asked for (and whether a proof walk fits the budget); the encoding is
appended to the private output, as a file transfer is, and never becomes a
program value. On the receiving side `State.decodeInline`,
`State.decodeSlice`, `State.proven` and `State.agrees` say what a received
encoding decodes to, whether it verifies, what a proof establishes and
whether a donor's tree agrees with a run; flushes are recorded in `synced`.
The sweeps read the store as files: a file costs its length, its time is
what `State.modified` records for it, and the object roots are the keys of
the payload and outboard files on one page. The remover's critical section
(`Lease.order`) is a counted token like a lease, keyed by its space alone,
so "inside the section" is the counter of `("cas", empty)` reading one;
its exclusion against writers is a host obligation the model states, not
one it simulates. An ordered query sorts with a structural, stable
insertion sort, so a fixture over several rows can be decided by the
kernel; the order it produces is the one `ordered` states.
Literal predicates (`equals`, `notEquals`, delete bounds) have SQL `IS`
semantics, as the store adapter renders them: NULL selects NULL and `IS NOT`
NULL excludes it. Conflict detection and join correlation keep SQL `=`, where
NULL equals nothing, matching unique indexes and joins.

Files opened here have stable bytes. Mutable-file capture, concurrent mutations,
crash persistence, and allocator exhaustion are separate obligations. Fixtures
start with valid, noncolliding handle/transaction counters. Flush/sync effects are
recorded, but a successful simulation does not prove power-loss durability.

Native interpreter refinement remains unproved: the Rust host must implement
these effect contracts. The shared state makes that one explicit boundary instead
of several operation-specific assumptions.

## Verification

- `SimulatedHostProofs` checks transaction visibility, commit/rollback, fault
  behavior, actual deletion counts, correlation, conflict preservation, LIKE,
  file-handle identity, transfer bounds, and abandonment.
- `CasCompositionProofs` executes store/acquire/collect/loss/heal/restore/read and
  cancellation histories on one evolving state. These are regression histories;
  the promise modules separately contain the general theorems.
- Existing CAS and history regression modules use raw fixtures and this host.
  Structural program and decoder proofs remain direct proofs of Lean functions.
  Trie graph proofs retain their read-only mathematical snapshot semantics; they
  are not arbitrary reply scripts or CAS host implementations.

Run `cd specs/lean && lake build --wfail` and
`cd specs/lean && lake env leanchecker Synchronicity`.
