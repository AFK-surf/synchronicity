# CAS / mptsync / ingest Lean model

This package proves the transition systems behind the CAS safety claim, the
scoped-sync privacy claims, and mptsync convergence. It is intentionally not a
formal semantics of Rust, SQLite, or a filesystem. Instead, each transition
corresponds to a named Rust linearization point, and the anchors are checked
in both directions (below).

```sh
cd specs/lean
lake build --wfail
./check-anchors.sh
```

The package depends on Mathlib (pinned to the toolchain's tag; `lake exe
cache get` fetches the compiled oleans) for `Function.update`, the
lexicographic linear order on heads, `List.maximum`, `Set.Finite`/`Set.ncard`,
and the well-foundedness lemmas. The proofs themselves are `grind`, `omega`
and `simp`. Every module ends in `#lint`, so a public declaration without a
docstring or with an unused argument fails the build.

## Module map

Every model is an instance of `Prelude.System` — an initial state and a step
relation — and every safety theorem is `System.Reachable.invariant` applied
to an inductive invariant. `Prelude.Lift` is a store of cells in which one
cell steps and the rest stay; `subst_step` is the tactic that opens a
transition hypothesis and substitutes the successor state, so that
preservation proofs are `cases k <;> … <;> subst_step h <;> grind`.

| Module | What it states | What it proves |
|---|---|---|
| `Prelude` | `System`, `Reachable`, `Lift`, `add`/`drop`, `subst_step` | the generic induction and simulation lemmas |
| `Anchors` | the `rust_impl` attribute | — |
| `Cas` | the twenty-three cell transitions (`Kind`, `Trans`, `CellStep`) over a cell indexed by holder `H` with a `Roles` instance; `Invariant`, `NoLoss` | `invariant_step`, `noLoss_step` — the only case-by-case preservation proofs, five lines each; `sourcePublish_of_new_leaf`, `replicaPromote_of_new_leaf` |
| `SystemSafety` | the fault-free closure over a store of cells, invariant `Invariant ∧ NoLoss`; the `Holder := Nat` instance with the operator at `0` | `source_live_content_is_available`, `replica_live_content_is_pin_or_want`, and the GC/delete/staged-row corollaries |
| `FaultTolerant` | `LoseRemote`, `LoseBytes`, `HealRemote`, `HealLocal` added to the same cells | `Invariant` alone survives: `role_pin_is_available_or_lost`, `heal_converts_role_pins`, `heal_keeps_operator_pin`; `fault_free_is_reachable` embeds every `SystemSafety` execution; the operator theorems read at `Holder` |
| `MptGc` | one trie root as five bits and nine transitions, `Prune` and `Supersede` included | `Invariant`: an active head is retained, complete and materialized, a pending head is retained, only an active head is materialized |
| `Safety` | the CAS/trie bridge: publication and promotion paired with the head flip they share a transaction with, across every root the transaction touches (`Across`) | `live_leaf_flips_head` — no step stands a new source or replica leaf without an active, materialized head; the `Local` guard on free CAS steps is what this rests on |
| `Scope` | `AdmitsPath`, `ContainsSubtree`, `AdmitsKey` over nibble paths | the spine lemma `admitsPath_of_append`, `containsSubtree_append`, `admitsPath_of_admitsKey` |
| `ScopedSync` | the verified trie `At`, the guarded walk `Walk` (`Reach`, `ReachRef`), `Drained`/`CompleteWithin`, the responder `Admit`/`ServeNode`/`ServeValue`/`Redacts`, a delegate's `Learn` | `At.unique`, `prune_sound`, `held_within_scope`, `held_value_within_scope`, `diff_never_misses`, `reach_or_boundary` |
| `TrieGraph` | the multi-root trie store with reachability derived from `At`; `GcSweep`, `DropRoot`, `RetainRoot`, `LearnNode`; `proj` to `MptGc` | `gc_preserves_complete_retained_root`, `complete_iff_reach_held`, and that every transition projects to the `MptGc` transition it abstracts (`gcSweep_projects`, `dropRoot_projects`, …) |
| `Convergence` | head selection (`select`), the derived view (`HasValue`, `ScopedView`), the fetch (`FetchStep`, `Bounded`, `Whole`) | `select_eq_of_mem_iff`, `scoped_view_deterministic`, `admitted_key_readable`, `fetchStep_wf`, `stuck_complete`, and `converge`, which puts the three together |
| `Provenance` | the multi-party model: `Legit`, `Sound`, `Vouched`, `view`; `LegitVia` chains; `Withheld` | `privacy`, `integrity`, `privacy_chain`, `withheld_not_legit` and its corollaries |

Each theorem's docstring says what it means for the code; this file says how
the modules fit and what they do not cover.

## The CAS models

`Cas` states the cell transitions once, over a holder type `H` with a `Roles`
instance saying which holders are sources or replicas rather than the
operator. `Invariant` is what every transition preserves — a role's pin
stands on a durable claim; a live leaf's holder is a role with a pin or a want
behind it — and `NoLoss` is what only the fault-free transitions preserve —
every pin stands on available content; a source leaf is pinned, never merely
wanted. `SystemSafety` is the fault-free closure with invariant
`Invariant ∧ NoLoss`; `FaultTolerant` adds two unguarded loss steps and the
two heals and proves `Invariant` alone survives them; `Safety` pairs the CAS
cells with the `MptGc` head flip.

The principal theorems are `SystemSafety.source_live_content_is_available` and
`SystemSafety.replica_live_content_is_pin_or_want`. They quantify over the
actual holder and content root, so a claim for one root cannot discharge a
leaf for another. A *staged* row (`durable = 0`) may be dropped without
consulting pins; `staged_row_is_reachable` witnesses that the branch is live
and `staged_row_drop_is_unpinned` why it is safe.

`FaultTolerant` does not model that a heal ever runs, that a want is ever
satisfied, or that the backend's `NotFound` is true — a spurious one triggers
a heal that errs in the safe direction, a pin becoming a want and a refetch.

## mptsync over partial tries

`ScopedSync.Walk` is the scoped `MissingWalk` under a guard on the positions
it may enter. `Reach` is the walk with no guard; `ReachRef` prunes against a
reference root; `Paired` and `DiffReach` are `Reach` by another name — the
pairing `paired_children` computes descends through held nodes, and a held
node is never a `Boundary`, so the code's boundary check on the reference side
is not a separate premise. `prune_sound` is the §5.5 claim that a pruned walk
may write the completeness memo.

The responder authorizes by position, never by hash: for a scoped peer the
claimed hash is not consulted (`admit_ignores_claim`), the root must be a head
root, what is served is what sits at the claimed position, and a node travels
only if what it reveals is in scope. `held_within_scope` is the single-store
privacy theorem: every node a delegate holds sits at an admitted position of a
head root and spells no key material outside its scope.

Not modelled: batches, `resume`, the unproductive-round abandonment, the depth
ceiling, and the promotion refusal memo.

## Provenance

`held_within_scope` is true and too weak: the graft of issue #115 satisfies
it. `Provenance` has several participants and asks whether a node is
*legitimately* a reader's, across every trie it might be read through.
`privacy` and `integrity` hold in every reachable state; `privacy_chain`
exhibits the chain of confined origins a node passed through, each of which
legitimately held it.

The `withheld_*` theorems quantify over every confined scope, and that is a
design statement rather than a weakness of the proof: a confined origin may
re-publish, under its own root, what it legitimately holds, and a wider
confined origin's grant may legitimately carry a node to a narrower one.
Re-publication along a delegation chain is the design working; what the
theorems exclude is content that no chain can legitimately begin with. The
concrete instance lives in the Rust test
`a_delegate_cannot_launder_a_withheld_subtree_through_its_own_trie`.

## Convergence

`Convergence.converge` is the statement: two nodes that heard the same heads
select the same head; if each fetched its root under the same scope until no
step was left, each holds a trie complete within the scope, every admitted key
has the same value on both, and each can read it or finds it under a boundary
its peer refused. It assumes, as hypotheses, that heads reach every node, that
a peer holding the root's head answers, that the origin's trie is whole and
finite, and — for out-of-line values only — that a held node is admitted where
the walk meets it. Not proved: that the gossip schedule delivers heads, or how
long any of this takes.

`fetchStep_wf` is termination as well-foundedness; `fetch_terminates` is the
no-infinite-sequence corollary.

## Trust boundary

- one process owns the data directory through `LifecycleLock`; independently
  opened `Store` values in that process share one CAS writer/GC coordinator;
- SQLite immediate transactions are atomic;
- the shared CAS coordinator orders lease registration against every unlink;
- verified content hashes identify the bytes;
- in `SystemSafety`, the configured durable backend satisfies its write
  contract (`FaultTolerant` drops this);
- the refinement from Rust statements to Lean transitions. The anchors make
  that obligation auditable but do not prove SQL or lock semantics;
- crash/power-loss recovery is outside this model (see `specs/Recovery.tla`);
  the theorems describe executions between successful durable commits.

`MptGc.State.complete` is the memo the drained walk writes, not a live
predicate over the store: `Convergence.stuck_fetch_promotes` reads it as
`CompleteWithin` at the moment the fetch drains, and `TrieGraph.proj` reads
it as `Complete` for a whole trie. A later `Learn` can extend what a root's
walk reaches without invalidating the memo Rust keeps; the model does not
relate the two after the drain.

## Contributing

**Anchors.** A declaration that models a Rust linearization point carries
`@[rust_impl "anchor-name"]`; the Rust site carries
`// LEAN-MODEL: anchor-name (Module.Decl)`. `lake exe anchors` prints every
pair the attribute recorded and `check-anchors.sh` diffs it against the Rust
sources, so a rename on either side fails CI. An anchor sits on exactly one
declaration; a declaration may carry several anchors.

**Naming.** A theorem about what one transition commits is
`<transition>_<effect>` (`gc_respects_protection`,
`possession_is_atomic`); a theorem about every reachable state is
`<subject>_is_<property>` or a sentence (`source_live_content_is_available`,
`live_leaf_flips_head`); a lemma that projects one model onto another is
`<transition>_projects`. Renames keep the old name as an `abbrev` or a
one-line theorem for one release.

**Proofs.** State transitions as guards around successor equations, name them
in a `Kind`, and prove preservation with `cases k <;> unfold … at h <;>
subst_step h <;> constructor <;> grind`. If a case needs a hand-written
argument, that is a fact the invariant should probably carry. Reach for a
Mathlib structure before a hand-rolled one: an order is a `LinearOrder`, a
finite set is `Set.Finite`, a measure is `Set.ncard`.

**Lint.** `#lint` at the end of every module runs the Batteries linters over
that file. Give every definition and structure a docstring; drop arguments
the statement does not use.
