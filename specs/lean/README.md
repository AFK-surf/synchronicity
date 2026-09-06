# Proofs of the executable Lean core

This package proves properties of the Lean programs Cargo compiles and links
into `synch` from [`crates/synch-verified`](../../crates/synch-verified/README.md).
It imports that source directly, so every theorem is about the code that
runs: there is no separate model of Rust, no anchor pairing a model
definition with a Rust site, and no checker for such pairings. What Rust
still owns (SQL, the filesystem, cryptographic primitives, Bao layout, the
FFI transport and the interpreters) is a stated trust boundary, not a
verified one. The shared simulated host models these raw effects explicitly; native
interpreter refinement remains outside those theorems.

The package depends only on the core and the pinned toolchain. No Mathlib.

```sh
cd specs/lean
lake build --wfail
```

CI builds it with warnings as errors, rechecks every declaration with the
standalone kernel checker and fails on `sorryAx` or an unapproved axiom.

The user-facing [CAS promises](../../docs/CAS-PROMISES.md) map readable
statements to their checked theorems and explicit host assumptions.

## Modules

| Module | What it proves about the executable program |
|---|---|
| `HostProgramProofs` | Composition and transaction failure traces of the shared free-monad carrier |
| `HostWireProofs`, `WireBufferProofs`, `WireWordProofs` | Packet framing, continuation resumption and word/buffer encodings of the native transport |
| `HostResourceProofs` | Bracketing of owned resources: cleanup runs once, on every path, and never hides the primary error |
| `CasPromises`, `CasReadPromises`, `CasHealingPromises`, `CasStorePromises` | User-facing coverage, range/full-read, repair-obligation, ownership, and fresh store/read laws under explicit host semantics; see the CAS promises document for exact scopes |
| `CasPlanProofs` | Group counting, size settlement, span normalization and the commit plan: membership, bounds, separation and exact completeness |
| `CasProgramProofs`, `CasLifecycleProofs` | Pin acquisition and deletion: the executed outcome equals the proved decision; a failed transaction never cleans up; committed deletion attempts both files |
| `CasReleaseProofs`, `CasExpiryProofs` | Release and expiry over real simulated rows, exclusions, counts, and rollback |
| `CasReadCodecProofs`, `CasReadHealingProofs`, `CasReadProgramProofs` | Row decoding, repair of a stale local claim and whole local reads, including range clamping and the one-transfer payload path |
| `IngestCommitProofs` | The metadata commit every writer runs: the claim is read inside the transaction, a complete plan is recognized, and a refused size writes nothing |
| `IngestProgramProofs`, `IngestInputProofs` | Captured-source ingestion and input policy: exact ordering of temporaries, construction, lease, publication and commit, with the cleanup trace of every failure point |
| `TrieProgramProofs`, `TrieProgramTests` | Trie lookup soundness and completeness against a raw node graph read through the actual codec, plus decoder fixtures |
| `TrieCodecProofs` | The node encoder and decoder roundtrip for every well-formed node, by induction over the executable parsers |
| `TrieVerifyProofs` | The ingress boundary: only an encoder image is admitted, within the shared key bound and the structural invariants; acceptance and origin/peer fault follow from the host's digests alone; the served bytes are read whole before anything is decided |
| `TrieMutateProofs` | The write path over a content-addressed store: every node it stores is the canonical image its address covers, so a store whose nodes the boundary admits stays that way through every insert and remove; bounds are refused before any effect; a remove's merges push down at most one key's worth of nibbles |
| `CasDurableProofs` | The durability transitions as the exact databases they leave: marking never inserts; healing withdraws only a standing claim, then moves exactly the machine roles' pins to repair intents and conserves the read path's obligation; a generation change drops exactly the staged rows and clears the cached groups of durable out-of-line rows; every failing effect rolls back, and the cache clear commits before it unlinks |
| `CasServeProofs` | Serving: every group the program asks the Bao service for was requested, is held by the row and lies within the object; a slice window is one exchange at most; a missing row, an empty window and a single-group proof are answered without the service; an over-budget proof is refused whole; the published bytes are exactly the service's encoding of the window the answer names |
| `CasReceiveProofs` | Receiving: a slice or proof commits exactly the window it named, decoded and flushed before the transaction and under the write lease; an empty window takes no lease; a refused claim decodes nothing; a promotion asks only about eligible runs, never a held group, and commits what the donor's tree agreed with; every failure before the commit leaves no row and no lease |
| `CasCollectProofs` | Keeping the store within bounds: the access clock moves only past the interval and only forwards; eviction considers only cached durable rows, stops within its target and never clears an object a writer holds; the collection pre-filter drops only rows the deletion refuses on the same database; a stale orphan file goes with its reading, row check, writer check and unlink inside one critical section, and a fresh one is left alone; every injected failure leaves the section released |
| `CasProjectProofs` | The projections: a well-typed row decodes to its cells and each refusal names its column; the joined pin state is merged onto exactly the rows it belongs to; distinct roots are exactly the roots there were; the holder spellings that matter; one object's read with its pin state; the ordered listings on fixtures, rolling back at every injected failure |
| `TrieServeProofs` | Serving a trie to a peer: the scope's spine and boundary properties, no redaction inside a grant, a value only from a node that could travel whole; a descent, and the merged trail-sharing descent of a whole batch, answer only a hash the stored graph places at the position asked about, so a position cannot be claimed into existence; an unscoped peer and an unvouched root are decided before any node is read; the answer budget's invariant; the served, missing and redacted lists of scoped, unscoped and confined views on a concrete trie, with a failure injected at every effect |
| `HistoryProgramProofs` | Head-history retention: fork, ceiling and witness protection derived from actual receipts, and shared-host executions with injected failures |
| `OriginProgramProofs` | Origin syntax and key decoding |
| `Decidable` | Decidable equality of `Except`, which core Lean lacks and the trace proofs decide with |
| `SimulatedHost`, `SimulatedHost.Database` | Shared raw database, transaction, filesystem, resource, and output semantics; see [the host contract](../../docs/LEAN-SIMULATED-HOST.md) |
| `SimulatedHostProofs` | Checks of raw semantics independently of CAS policy |
| `CasFixtures` | Raw database/file fixtures; no effect interpreters or reply scripts |
| `CasCompositionProofs` | Store/acquire/collect/loss/heal/restore/read and cancellation histories over one state |

## Conventions

- Import the executable operation; never restate its policy in a host.
- Use `SimulatedHost.run` for operation executions and pass its final `State`
  directly to the next command. Add raw capabilities to the shared host when
  necessary; do not add a proof-specific interpreter or successful-reply script.
- Build fixtures from raw rows/files. Inject failures through shared host controls.
  Check resulting state as well as outcomes and traces.
- Keep environmental and schema assumptions explicit. Proving a program against
  the shared semantics does not verify the native Rust interpreter.
- Structural program, decoder, and mathematical graph proofs can remain direct
  proofs of those functions. For concrete shared-state executions, `decide
  +kernel` or `cbv` must produce proofs accepted by the standalone kernel checker.
