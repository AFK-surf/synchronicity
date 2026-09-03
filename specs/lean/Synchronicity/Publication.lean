import Synchronicity.Bridge

/-!
The publication contract: the bridged CAS/trie system read along a whole
execution rather than at one state or across one step.

Every theorem below `Bridge` is a fact about one reachable state or one
transition.  What the design promises is temporal — *what a source publishes
stays servable, at the size it was published, for as long as its tree names
it, and the step that published it committed an active, materialized head* —
and `publication_contract` is that promise.  It is composed, not proved afresh:
`Bridge.source_leaf_flips_head` says a source leaf is only ever stood by a
paired head flip; `SystemSafety`'s fault-free invariant says a standing source
leaf is pinned on available content; `Cas.settled_size_is_stable` says a
pinned, hence durable, hence settled size is moved by no step.  The execution
(`System.Exec`) is what lets the last of these be chained from the instant the
leaf was stood to any instant it still stands.

The contract is the fault-free one.  Under `FaultTolerant` the standing leaf
keeps a durable claim or a want (`source_live_is_held_or_wanted`), and the
size survives every loss and heal that leaves the row (`settled_size_survives_faults`);
what a loss takes is availability, until the heal converts the pin into a
want and the refetch begins again.
-/

namespace Synchronicity.Publication

open Cas Bridge

variable {H : Type} [Roles H]

/-- The bridged system's executions. -/
abbrev Exec (H : Type) [Roles H] := (Bridge.system H).Exec

variable {holder : H} {root : Root}

/-- The bridge invariant holds at every instant. -/
theorem state_invariant (e : Exec H) (n : Nat) : Bridge.Invariant (e.state n) :=
  Bridge.reachable_invariant (e.reachable n)

/-- `holder`'s source leaf for `root` stands at every instant from `i` to `j`. -/
def Standing (e : Exec H) (holder : H) (root : Root) (i j : Nat) : Prop :=
  ∀ k, i ≤ k → k ≤ j → holder ∈ ((e.state k).cas root).sourceLive

/-- **Birth.**  The step that stands a source leaf commits an active,
materialized head in the same transaction: a bare publication is not a step
of the system. -/
theorem publication_flips_head (e : Exec H) (n : Nat)
    (old : holder ∉ ((e.state n).cas root).sourceLive)
    (new : holder ∈ ((e.state (n + 1)).cas root).sourceLive) :
    (e.state (n + 1)).mpt.active ∧ (e.state (n + 1)).mpt.materialized :=
  source_leaf_flips_head (e.step n) new old

/-- **Life, at one instant.**  Wherever a source leaf stands, its holder pins
the content and the content is available. -/
theorem standing_is_pinned_and_available (e : Exec H) (n : Nat)
    (live : holder ∈ ((e.state n).cas root).sourceLive) :
    holder ∈ ((e.state n).cas root).pin ∧ Available ((e.state n).cas root) :=
  let safe := (state_invariant e n).1 root
  have pinned := safe.2.source_pinned holder live
  ⟨pinned, safe.2.pin_available holder pinned⟩

/-- **Life, across one step.**  While the leaf stands on both sides of a step,
the size the row records is the same on both: the content is pinned, so its
claim is durable, so its size is settled, and a settled size moves under no
transition. -/
theorem standing_size_step (e : Exec H) (n : Nat)
    (live : holder ∈ ((e.state n).cas root).sourceLive)
    (live' : holder ∈ ((e.state (n + 1)).cas root).sourceLive) :
    ((e.state (n + 1)).cas root).size = ((e.state n).cas root).size := by
  rcases step_cells (e.step n) root with ⟨_, step⟩ | same
  · have available := (standing_is_pinned_and_available e n live).2
    have available' := (standing_is_pinned_and_available e (n + 1) live').2
    exact settled_size_is_stable step available.1 (Or.inl available.2.1) available'.1
  · rw [same]

/-- **The publication contract.**  From any instant `i` at which a source leaf
stands until any later instant `j` at which it still stands, at every instant
between: the holder pins the content, the content is available — its row
present, its claim durable, a copy local or remote — and the size the row
records is the size it recorded at `i`.  Nothing the system does in between —
a peer's size claim, a cache eviction, a sweep, another node's promotion —
moves what the tree names. -/
@[rust_justifies "cas-publication-contract"]
theorem publication_contract (e : Exec H) {i j : Nat} (standing : Standing e holder root i j) :
    ∀ k, i ≤ k → k ≤ j →
      holder ∈ ((e.state k).cas root).pin ∧ Available ((e.state k).cas root) ∧
        ((e.state k).cas root).size = ((e.state i).cas root).size := by
  intro k hik hkj
  obtain ⟨pinned, available⟩ := standing_is_pinned_and_available e k (standing k hik hkj)
  refine ⟨pinned, available, ?_⟩
  obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hik
  clear hik pinned available
  revert hkj
  induction d with
  | zero => exact fun _ => rfl
  | succ d ih =>
    intro hkj
    have before := standing (i + d) (Nat.le_add_right i d) (Nat.le_of_succ_le hkj)
    have after := standing (i + (d + 1)) (Nat.le_add_right i (d + 1)) hkj
    exact (standing_size_step e (i + d) before after).trans (ih (Nat.le_of_succ_le hkj))

/-- The contract read from the birth: a leaf stood at instant `i` keeps, at
every later instant it still stands, the size the publication recorded and
an active, materialized head behind the publication. -/
theorem published_content_keeps_its_size (e : Exec H) {i j : Nat} (hij : i + 1 ≤ j)
    (born : holder ∉ ((e.state i).cas root).sourceLive)
    (standing : Standing e holder root (i + 1) j) :
    ((e.state (i + 1)).mpt.active ∧ (e.state (i + 1)).mpt.materialized) ∧
      ∀ k, i + 1 ≤ k → k ≤ j →
        Available ((e.state k).cas root) ∧
          ((e.state k).cas root).size = ((e.state (i + 1)).cas root).size :=
  ⟨publication_flips_head e i born (standing (i + 1) (Nat.le_refl _) hij),
    fun k hik hkj => (publication_contract e standing k hik hkj).2⟩

end Synchronicity.Publication

#lint
