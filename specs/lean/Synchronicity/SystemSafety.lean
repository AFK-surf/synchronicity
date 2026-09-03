import Synchronicity.Cas

/-!
The fault-free safety model: the closure of `Cas.CellStep` over a store of
cells indexed by content root, with claims indexed by holder.

Its invariant is `Cas.Invariant ∧ Cas.NoLoss`: what every transition
preserves, plus what only the fault-free ones do.  `FaultTolerant` drops
`NoLoss` and shows the rest survives backend loss.

The theorems are stated for any holder type with a `Roles` instance.
`Holder` is the instance the system runs: the operator's `synch pin add` as
one distinguished holder and every other holder a role a space configures.
`FaultTolerant` reads its operator theorems at this instance.
-/

namespace Synchronicity.SystemSafety

open Cas

/-- The system's holders: the operator's `synch pin add`, and the roles a space
configures. -/
structure Holder where
  /-- The holder's identity. -/
  id : Nat
  deriving DecidableEq

/-- The operator's holder, `synch pin add`. -/
def operator : Holder := ⟨0⟩

instance : Roles Holder := ⟨fun holder => holder ≠ operator⟩

theorem isRole_iff {holder : Holder} : IsRole holder ↔ holder ≠ operator := Iff.rfl

theorem operator_not_role : ¬ IsRole operator := fun h => h rfl

variable {H : Type} {c c' : Cell H} {holder : H}

/-! ## Facts that hold whoever the holders are -/

theorem protected_delete_cannot_delete_pinned
    (pinned : holder ∈ c.pin) (delete : ProtectedDelete.rel c c') : False :=
  delete.1.no_pin ⟨holder, pinned⟩

/-- The paths that drop a staged row never consult `pins`.  They do not need
to: a pin is only ever granted over available, hence durable, content, so a
non-durable row is unpinned in every fault-free state. -/
theorem staged_row_drop_is_unpinned
    (hnl : NoLoss c) (drop : DropStaged.rel c c') (pinned : holder ∈ c.pin) : False :=
  drop.1.1 (hnl.pin_available holder pinned).2.1

theorem staged_row_drop_has_no_source_leaf
    (hnl : NoLoss c) (drop : DropStaged.rel c c') (live : holder ∈ c.sourceLive) : False :=
  staged_row_drop_is_unpinned hnl drop (hnl.source_pinned holder live)

variable [Roles H]

/-- The fault-free cell invariant. -/
def Safe (c : Cell H) : Prop := Cas.Invariant c ∧ NoLoss c

theorem safe_step (h : Safe c) (step : CellStep c c') : Safe c' :=
  ⟨invariant_step h.1 step, noLoss_step h.1 h.2 step⟩

/-- Every cell is `Safe`. -/
def SystemInvariant (s : State H) : Prop := ∀ root, Safe (s root)

/-- One cell takes a `CellStep`; every other root is left as it was. -/
abbrev Step : State H → State H → Prop := Lift CellStep

/-- The fault-free system. -/
def system (H : Type) [Roles H] : System (State H) := ⟨Initial, Step⟩

/-- The states the fault-free system reaches. -/
abbrev Reachable (s : State H) : Prop := (system H).Reachable s

theorem invariant : (system H).Invariant SystemInvariant where
  init _ := ⟨Cas.initial_invariant, initial_noLoss⟩
  step hinv hstep := Lift.forall (fun safe step => safe_step safe step) hinv hstep

theorem reachable_invariant {s : State H} (h : Reachable s) : SystemInvariant s :=
  invariant.reachable h

/-! ## The principal theorems -/

variable {s : State H} {root : Root}

theorem source_live_content_is_available
    (reachable : Reachable s) (live : holder ∈ (s root).sourceLive) :
    Available (s root) :=
  let safe := reachable_invariant reachable root
  safe.2.pin_available holder (safe.2.source_pinned holder live)

theorem replica_live_content_is_pin_or_want
    (reachable : Reachable s) (live : holder ∈ (s root).replicaLive) :
    (holder ∈ (s root).pin ∧ Available (s root)) ∨ holder ∈ (s root).want :=
  let safe := reachable_invariant reachable root
  (safe.1.replica_live holder live).2.2.elim
    (fun pinned => Or.inl ⟨pinned.1, safe.2.pin_available holder pinned.1⟩) Or.inr

theorem live_content_has_entry
    (reachable : Reachable s)
    (live : holder ∈ (s root).sourceLive ∨ holder ∈ (s root).replicaLive ∨
      holder ∈ (s root).ordinaryLive) :
    (s root).entry := by
  have inv := (reachable_invariant reachable root).1
  rcases live with source | replica | ordinary
  · exact (inv.source_live holder source).2.1
  · exact (inv.replica_live holder replica).2.1
  · exact inv.ordinary_live holder ordinary

theorem live_holders_are_roles
    (reachable : Reachable s)
    (live : holder ∈ (s root).sourceLive ∨ holder ∈ (s root).replicaLive) :
    IsRole holder := by
  have inv := (reachable_invariant reachable root).1
  rcases live with source | replica
  · exact (inv.source_live holder source).1
  · exact (inv.replica_live holder replica).1

theorem gc_cannot_collect_live_content
    (hinv : Cas.Invariant c) (live : AnyLive c) (hgc : GcCommit.rel c c') : False := by
  obtain ⟨holder, source | replica | ordinary⟩ := live
  · exact hgc.1.no_entry (hinv.source_live holder source).2.1
  · exact hgc.1.no_entry (hinv.replica_live holder replica).2.1
  · exact hgc.1.no_entry (hinv.ordinary_live holder ordinary)

theorem protected_delete_cannot_delete_live_content
    (hinv : Cas.Invariant c) (live : AnyLive c) (delete : ProtectedDelete.rel c c') : False := by
  obtain ⟨holder, source | replica | ordinary⟩ := live
  · exact delete.1.no_entry (hinv.source_live holder source).2.1
  · exact delete.1.no_entry (hinv.replica_live holder replica).2.1
  · exact delete.1.no_entry (hinv.ordinary_live holder ordinary)

/-- Promoting a replica leaf over content that is not available records a want
and never a pin, whatever took the content away — a GC pass that ran before
the promotion included.  Under `NoLoss` no pin stands over unavailable
content, so the promoted cell carries none for this holder. -/
theorem replica_promote_unavailable_records_want {pinned : Bool}
    (hnl : NoLoss c) (promote : (ReplicaPromote holder pinned).rel c c')
    (unavailable : ¬Available c) :
    holder ∈ c'.replicaLive ∧ holder ∈ c'.want ∧ holder ∉ c'.pin := by
  simp only [transition] at promote
  obtain ⟨⟨_, _, hpinned⟩, rfl⟩ := promote
  have : pinned = false := by
    cases pinned
    · rfl
    · exact absurd (hpinned.mp rfl) unavailable
  subst this
  exact ⟨by simp, by simp, fun pinned => unavailable (hnl.pin_available holder pinned)⟩

/-- A staged row is a reachable state, not a dead branch: a complete commit
under a backend that does not make completion durable leaves a row that
`DropStaged` may then discard. -/
theorem staged_row_is_reachable (root : Root) :
    ∃ s : State H, Reachable s ∧ (s root).row ∧ ¬(s root).durable ∧
      ∃ s', Step s s' ∧ ¬(s' root).row := by
  let staged : Cell H := (Trans (H := H) (.commitComplete false 1)).post {}
  refine ⟨update Initial root staged, ?_, ?_, ?_,
    update (update Initial root staged) root ((Trans (H := H) .dropStaged).post staged), ?_, ?_⟩
  · refine .next .initial (Lift.intro ⟨.commitComplete false 1, ?_, rfl⟩)
    simp [transition, system, Initial, Settles]
  · simp [staged, transition]
  · simp [staged, transition]
  · refine Lift.intro ?_
    rw [Function.update_self]
    exact ⟨.dropStaged, by simp [staged, transition], rfl⟩
  · simp [transition]

/-! ## What a partial row is and is not -/

/-- A partial row is a reachable state too: committing one group of a
two-group object leaves a row that is neither complete nor durable. -/
theorem partial_row_is_reachable (root : Root) :
    ∃ s : State H, Reachable s ∧ (s root).row ∧ ¬Complete (s root) ∧ ¬(s root).durable := by
  let part : Cell H := (Trans (H := H) (.commitGroups true (2 * groupBytes) {0})).post {}
  have two : 1 < groupCount (2 * groupBytes) := by decide
  have missing : 1 ∉ part.held := by
    simp [part, transition, settleHeld]
  refine ⟨update Initial root part, ?_, ?_, ?_, ?_⟩
  · refine .next .initial (Lift.intro ⟨.commitGroups true (2 * groupBytes) {0}, ?_, rfl⟩)
    simp [transition, system, Initial, Settles]
  · simp [part, transition]
  · rw [Function.update_self]
    exact fun complete => missing (complete 1 two)
  · rw [Function.update_self]
    simp only [part, transition]
    rintro (⟨_, complete⟩ | absurd)
    · exact missing (complete 1 two)
    · exact absurd

/-- A pinned row's size is settled: a pin stands on a durable claim, and a
durable size is a fact.  With `Cas.settled_size_is_stable`, no writer's claim
ever moves the size of what anyone pins. -/
theorem pinned_size_is_settled (reachable : Reachable s) (pinned : holder ∈ (s root).pin) :
    Settled (s root) :=
  Or.inl ((reachable_invariant reachable root).2.pin_available holder pinned).2.1

/-- `Store::pin`'s predicate is `durable` alone, and that is enough: a pin
stands over a complete row or a remote copy, never over a partial fetch. -/
theorem pin_never_stands_on_partial (reachable : Reachable s) (pinned : holder ∈ (s root).pin)
    (cold : ¬(s root).remote) : Complete (s root) :=
  let safe := reachable_invariant reachable root
  (safe.2.durable_backed (safe.2.pin_available holder pinned).2.1).resolve_left cold

/-- A live source leaf names a complete row or a remote copy, and its size is
settled. -/
theorem source_live_size_is_settled (reachable : Reachable s)
    (live : holder ∈ (s root).sourceLive) : Settled (s root) :=
  pinned_size_is_settled reachable ((reachable_invariant reachable root).2.source_pinned holder live)

end Synchronicity.SystemSafety

#lint
