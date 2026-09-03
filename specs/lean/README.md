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
cache get` fetches the compiled oleans) for `Set`, `Function.update`, the
lexicographic linear order on heads, `List.maximum`, `Set.Finite`/`Set.ncard`,
and the well-foundedness lemmas. The proofs themselves are `grind`, `omega`
and `simp`. Every module ends in `#lint`, so a public declaration without a
docstring or with an unused argument fails the build.

## Module map

Every model is an instance of `Prelude.System` — an initial state and a step
relation — and every safety theorem is a `System.Invariant` (true initially,
preserved by every step) read at a reachable state. Every transition is a
`Prelude.Transition`: a guard and a successor function. Where the code has
two outcomes, the outcome is a parameter of the transition and of its `Kind`,
so a preservation proof is `cases k <;> simp only [transition] at h <;>
obtain ⟨hg, rfl⟩ := h <;> constructor <;> grind`. `Lift` is a store of cells
in which one cell steps and the rest stay, `Across` one in which every cell
steps or stays; `Reachable.simulate` is the simulation argument between two
systems under a projection. Every set — pins, held nodes, retained roots — is
a Mathlib `Set`.

| Module | What it states | What it proves |
|---|---|---|
| `Prelude` | `System`, `Reachable`, `Invariant`, `Transition`, `Lift`, `Across` | `Invariant.reachable`, `Reachable.simulate`, `Lift.forall`/`Across.forall` |
| `Anchors` | the `rust_impl` and `rust_justifies` attributes; the `transition` simp set | — |
| `Cas` | the cell transitions (`Kind`, `Trans`, `CellStep`, `LocalStep`) over a cell indexed by holder `H` with a `Roles` instance; the row's `size` and `held` groups, `Complete`, `Attested`, `Settles` and `settleHeld`; `Invariant`, `NoLoss` | `invariant_step`, `noLoss_step` — the only case-by-case preservation proofs, four lines each; `settled_size_is_stable`, `dropped_bit_was_a_claim`, `carried_bit_shares_tree`; `sourcePublish_of_new_leaf`, `replicaPromote_of_new_leaf`, `flipsHead_of_new_leaf` |
| `SystemSafety` | the fault-free closure over a store of cells, invariant `Invariant ∧ NoLoss`; the `Holder` instance with the operator distinguished | `source_live_content_is_available`, `replica_live_content_is_pin_or_want`, `pin_never_stands_on_partial`, `pinned_size_is_settled`, and the GC/delete/staged-row/partial-row corollaries |
| `FaultTolerant` | `LoseRemote`, `LoseBytes`, `HealRemote`, `HealLocal` added to the same cells | `Invariant` alone survives: `role_pin_is_available_or_lost`, `heal_converts_role_pins`, `heal_keeps_operator_pin`, `settled_size_survives_faults`; `fault_free_is_reachable` embeds every `SystemSafety` execution; the operator theorems read at `Holder` |
| `MptGc` | one trie root as five bits and nine transitions, `Prune` and `Supersede` included | `Invariant`: an active head is retained, complete and materialized, a pending head is retained, only an active head is materialized |
| `Bridge` | the CAS/trie bridge: publication and promotion paired with the head flip they share a transaction with, across every root the transaction touches (`Across`) | `live_leaf_flips_head` — no step stands a new source or replica leaf without an active, materialized head; the `LocalStep` guard on free CAS steps is what this rests on |
| `Scope` | `AdmitsPath`, `ContainsSubtree`, `AdmitsKey` over nibble paths | the spine lemma `admitsPath_of_append`, `containsSubtree_append`, `admitsPath_of_admitsKey` |
| `ScopedSync` | `Hash`, the verified trie `At`, the guarded walk `Walk` (`Reach`, `ReachRef`), `Drained`/`CompleteWithin`, the responder `Admit`/`ServeNode`/`ServeValue`/`Redacts`, a delegate's `Learn` | `At.unique`, `prune_sound`, `held_within_scope`, `held_value_within_scope`, `diff_never_misses`, `reach_or_boundary` |
| `TrieGraph` | the multi-root trie store under a read scope, with `Complete` read as `CompleteWithin`; every `MptGc` transition at store level, `GcSweep` as mark/sweep over held nodes and their values | `gcSweep_complete_iff` — a sweep keeps a retained root exactly as complete as it was; `step_projects` and `simulates` — `MptGc` simulates the store at every root |
| `Convergence` | head selection (`select`, `offer` over a node's heard heads and per-root slots), the derived view (`HasValue`, `ScopedView`, `Readable`), the fetch (`FetchStep`, `Bounded`, `Whole`, `Productive`) | `select_eq_of_mem_iff`, `offer_step`, `scoped_view_deterministic`, `admitted_key_readable`, `fetchStep_wf`, `stuck_complete`, and `converge`, which puts the three together |
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
two heals and proves `Invariant` alone survives them; `Bridge` pairs the CAS
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

### Partial rows and the size a row records

A row need not be complete. A cell carries the `size` its row records and
the set of groups it `held`, and `Complete` reads the row as
`cas.rs::read_claim` does: every group of the row's own size. Every writer of
verified groups — a peer slice, a delta proof, a promotion, a cloud cache
refill — is one `CommitGroups`, and an ingest is `CommitComplete`, the same
commit of every group at once, which is why `Store::commit_complete` calls
`commit_groups` over the full range rather than writing the row itself.

Until the final group is held the size is a claim off an entry rather than a
fact (`Attested` is `size_is_attested`), and `Settles` is `settle_size` as the
guard on every commit: a durable or attested size must agree, an unsettled one
yields, and `settleHeld` keeps the bits already held only when the group count
did not move. Two theorems say what that buys. `settled_size_is_stable`: no
step of the model leaves a row standing under a different size once its size
is durable or attested — the refusal in `settle_size` — and
`settled_size_survives_faults` extends it to the losses and heals.
`dropped_bit_was_a_claim`: a bit a commit drops was verified under a size that
was neither durable nor attested, so what the reset costs is a re-fetch of a
claim, never a fact (`docs/DELTA-SYNC.md` §6). `Invariant.held_within_size`
is the invariant the reset keeps — the bitmap always describes the tree of
the size the row records — and `NoLoss.durable_backed` with
`SystemSafety.pin_never_stands_on_partial` is `Store::pin`'s comment as a
theorem: a pin stands over a complete row or a remote copy, never over a
partial fetch. `partial_row_is_reachable` witnesses that the branch is live.

Not modelled: what the groups contain. A group is verified or it is not; the
bao tree, the bracket argument for why a proof can verify under an overstated
size, and the inline representation of small objects are trusted.

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
select the same head; if each fetched its root under the same scope, from
peers that heard the same heads, until no step was left, each holds a trie
complete within the scope, every admitted key has the same value on both, and
each can read it (`Readable`: it holds the carrying node, or the key lies
under a boundary its peer refused). It assumes, as hypotheses, that a peer
holding the root's head answers, that the origin's trie is whole and finite,
and — for out-of-line values only — `Productive`: that a held node is admitted
where the walk meets it. Not proved: that the gossip schedule delivers heads,
or how long any of this takes. `offer` is `offer_head` at the node: the heard
list and every root's `MptGc` bits, and `offer_step` is the fact that hearing
a head is `OfferPending` or `Retain` at its root.

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

`MptGc.State.complete` is `ScopedSync.CompleteWithin` everywhere it is read:
`Convergence.stuck_fetch_promotes` establishes it when the fetch drains, and
`TrieGraph.proj` reads it off the store. `TrieGraph.simulates` says every
store-level step is an `MptGc` step at every root, with one guard: its
`LearnNode` takes a node no position ever refused. A node refused at one
position and later held from another — Rust's `put_node` after a
`note_redacted` of the same hash — has no step in the model: holding the node
dissolves the boundary a completeness memo may rest on, so `MptGc`'s
`active → complete` would not survive it. Rust's `put_node` drops every
completeness memo when it holds such a hash
(`db.rs::put_node_forgetting_memos`), so the memo is re-derived by a walk the
next time it is asked, which is what keeps `complete` the walk's answer on
both sides.

## Contributing

**Anchors.** A definition that models a Rust linearization point carries
`@[rust_impl "anchor-name"]`; a theorem that justifies a Rust site — a memo
that may be written, a check that may be skipped — carries
`@[rust_justifies "anchor-name"]`. The Rust site carries
`// LEAN-MODEL: anchor-name (Module.Decl)` either way. `lake exe anchors`
prints every pair the attributes recorded and `check-anchors.sh` diffs it
against the Rust sources, so a rename on either side fails CI. An anchor sits
on exactly one declaration; a declaration may carry several anchors.

**Naming.** A theorem about what one transition commits is
`<transition>_<effect>` (`gc_respects_protection`,
`possession_is_atomic`); a theorem about every reachable state is
`<subject>_is_<property>` or a sentence (`source_live_content_is_available`,
`live_leaf_flips_head`); a lemma that projects one model onto another is
`<transition>_projects`. Renames keep the old name as an `abbrev` or a
one-line theorem for one release.

**Proofs.** State a transition as a `Transition` — a guard and a successor —
tagged `@[transition]`, name it in a `Kind`, and prove preservation with
`cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h <;>
constructor <;> grind`. Where the code has two outcomes, make the outcome a
parameter of the transition and of its `Kind` rather than a disjunction in
the relation. If a case needs a hand-written argument, that is a fact the
invariant should probably carry. Guards with several clauses are `Prop`
structures with named fields (`Collectable`, `Deletable`), never anonymous
conjunctions read by `.2.2.1`. Reach for a Mathlib structure before a
hand-rolled one: a set is a `Set`, an order is a `LinearOrder`, a finite set
is `Set.Finite`, a measure is `Set.ncard`. Identifiers (`Hash`, `Root`,
`Holder`, `Origin`) are one-field structures, so they cannot be confused.

**Lint.** `#lint` at the end of every module runs the Batteries linters over
that file. Give every definition and structure a docstring; drop arguments
the statement does not use.
