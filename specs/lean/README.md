# Proofs of the executable Lean core

This package proves properties of the Lean programs Cargo compiles and links
into `synch` from [`crates/synch-verified`](../../crates/synch-verified/README.md).
It imports that source directly, so every theorem is about the code that
runs: there is no separate model of Rust, no anchor pairing a model
definition with a Rust site, and no checker for such pairings. What Rust
still owns (SQL, the filesystem, cryptographic primitives, Bao layout, the
FFI transport and the interpreters) is a stated trust boundary, not a
verified one. Proof hosts may model these raw effects explicitly; native
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
| `CasReleaseProofs`, `CasExpiryProofs` | Release and expiry traces over scripted storage |
| `CasReadCodecProofs`, `CasReadHealingProofs`, `CasReadProgramProofs` | Row decoding, repair of a stale local claim and whole local reads, including range clamping and the one-transfer payload path |
| `IngestCommitProofs` | The metadata commit every writer runs: the claim is read inside the transaction, a complete plan is recognized, and a refused size writes nothing |
| `IngestProgramProofs`, `IngestInputProofs` | Captured-source ingestion and input policy: exact ordering of temporaries, construction, lease, publication and commit, with the cleanup trace of every failure point |
| `TrieProgramProofs`, `TrieProgramTests` | Trie lookup soundness and completeness against a raw node graph read through the actual codec, plus decoder fixtures |
| `HistoryProgramProofs` | Head-history retention: fork, ceiling and witness protection derived from actual receipts, and scripted traces of every failure position |
| `OriginProgramProofs` | Origin syntax and key decoding |
| `Decidable` | Decidable equality of `Except`, which core Lean lacks and the trace proofs decide with |
| `Handlers` | Scripted hosts for whole-program proofs: one `Handler` instance per capability, composed over `EffectSum`, run with fuel to a `(result, trace)` pair |

## Conventions

- A proof imports the executable module it is about; it never restates the
  program.
- Trace proofs script a host and decide the whole `(result, trace)` pair, so
  the executable program must stay structurally recursive. Explicit fuel is
  fine; well-founded recursion is not evaluated by `decide`.
- Keep host assumptions in the theorem statement. A theorem about a
  scripted host says what the program does given those replies, nothing
  about SQLite or the filesystem.
- Script a host per capability with `Handlers.Handler` instances on the
  proof's own state type and run the program with `Handlers.run`; the
  `EffectSum` instance composes them, so a proof never spells the
  `.left`/`.right` path of an effect.
