import Synchronicity.Cas

/-!
The fault-free safety model: the closure of `Cas.CellStep` over a store of
cells indexed by content root, with claims indexed by holder.

Its invariant is `Cas.Invariant ∧ Cas.NoLoss`: what every transition
preserves, plus what only the fault-free ones do.  `FaultTolerant` drops
`NoLoss` and shows the rest survives backend loss; `CasGc` reads this file
at `H := Unit`.
-/

namespace Synchronicity.SystemSafety

open Cas

/-- The system's holders.  The operator's holder is `synch pin add`; every
other holder is a role a space configures, a source or a replica. -/
abbrev Holder := Nat

def operator : Holder := 0

instance : Roles Holder := ⟨fun holder => holder ≠ operator⟩

theorem isRole_iff {holder : Holder} : IsRole holder ↔ holder ≠ operator := Iff.rfl

theorem operator_not_role : ¬ IsRole operator := fun h => h rfl

variable {H : Type} [Roles H] {c c' : Cell H} {holder : H}

/-- The fault-free cell invariant. -/
def Safe (c : Cell H) : Prop := Cas.Invariant c ∧ NoLoss c

theorem safe_step (h : Safe c) (step : CellStep c c') : Safe c' :=
  ⟨invariant_step h.1 step, noLoss_step h.1 h.2 step⟩

def SystemInvariant (s : State H) : Prop := ∀ root, Safe (s root)

inductive Step : State H → State H → Prop where
  | root {s : State H} {root : Root} {cell' : Cell H} :
      CellStep (s root) cell' → Step s (Replace s root cell')

inductive Reachable : State H → Prop where
  | initial : Reachable Initial
  | next {s s' : State H} : Reachable s → Step s s' → Reachable s'

theorem initial_invariant : SystemInvariant (Initial : State H) :=
  fun _ => ⟨Cas.initial_invariant, initial_noLoss⟩

theorem invariant_step {s s' : State H} (hinv : SystemInvariant s) (hstep : Step s s') :
    SystemInvariant s' := by
  cases hstep with
  | root step => exact replace_forall hinv (safe_step (hinv _) step)

theorem reachable_invariant {s : State H} (h : Reachable s) : SystemInvariant s := by
  induction h with
  | initial => exact initial_invariant
  | next _ step ih => exact invariant_step ih step

/-! ## The principal theorems -/

variable {s : State H} {root : Root}

theorem source_live_content_is_available
    (reachable : Reachable s) (live : (s root).sourceLive holder) :
    Available (s root) :=
  let safe := reachable_invariant reachable root
  safe.2.pin_available holder (safe.2.source_pinned holder live)

theorem replica_live_content_is_pin_or_want
    (reachable : Reachable s) (live : (s root).replicaLive holder) :
    ((s root).pin holder ∧ Available (s root)) ∨ (s root).want holder :=
  let safe := reachable_invariant reachable root
  (safe.1.replica_live holder live).2.2.elim
    (fun pinned => Or.inl ⟨pinned.1, safe.2.pin_available holder pinned.1⟩) Or.inr

theorem live_content_has_entry
    (reachable : Reachable s)
    (live : (s root).sourceLive holder ∨ (s root).replicaLive holder ∨
      (s root).ordinaryLive holder) :
    (s root).entry := by
  have inv := (reachable_invariant reachable root).1
  rcases live with source | replica | ordinary
  · exact (inv.source_live holder source).2.1
  · exact (inv.replica_live holder replica).2.1
  · exact inv.ordinary_live holder ordinary

theorem live_holders_are_roles
    (reachable : Reachable s)
    (live : (s root).sourceLive holder ∨ (s root).replicaLive holder) :
    IsRole holder := by
  have inv := (reachable_invariant reachable root).1
  rcases live with source | replica
  · exact (inv.source_live holder source).1
  · exact (inv.replica_live holder replica).1

theorem gc_cannot_collect_live_content
    (hinv : Cas.Invariant c) (live : AnyLive c) (hgc : GcCommit c c') : False := by
  obtain ⟨holder, source | replica | ordinary⟩ := live
  · exact hgc.1.2.1 (hinv.source_live holder source).2.1
  · exact hgc.1.2.1 (hinv.replica_live holder replica).2.1
  · exact hgc.1.2.1 (hinv.ordinary_live holder ordinary)

theorem protected_delete_cannot_delete_live_content
    (hinv : Cas.Invariant c) (live : AnyLive c) (delete : ProtectedDelete c c') : False := by
  obtain ⟨holder, source | replica | ordinary⟩ := live
  · exact delete.1.1 (hinv.source_live holder source).2.1
  · exact delete.1.1 (hinv.replica_live holder replica).2.1
  · exact delete.1.1 (hinv.ordinary_live holder ordinary)

omit [Roles H] in
theorem protected_delete_cannot_delete_pinned
    (pinned : c.pin holder) (delete : ProtectedDelete c c') : False :=
  delete.1.2.1 ⟨holder, pinned⟩

/- The paths that drop a staged row never consult `pins`.  They do not need
   to: a pin is only ever granted over available, hence durable, content, so a
   non-durable row is unpinned in every fault-free state. -/
omit [Roles H] in
theorem staged_row_drop_is_unpinned
    (hnl : NoLoss c) (drop : DropStaged c c') (pinned : c.pin holder) : False :=
  drop.1 (hnl.pin_available holder pinned).2.1

omit [Roles H] in
theorem staged_row_drop_has_no_source_leaf
    (hnl : NoLoss c) (drop : DropStaged c c') (live : c.sourceLive holder) : False :=
  staged_row_drop_is_unpinned hnl drop (hnl.source_pinned holder live)

/- Promoting a replica leaf over content that is not available records a want
   and never a pin, whatever took the content away — a GC pass that ran before
   the promotion included.  Under `NoLoss` no pin stands over unavailable
   content, so the promoted cell carries none for this holder. -/
theorem replica_promote_unavailable_records_want
    (hnl : NoLoss c) (promote : ReplicaPromote holder c c') (unavailable : ¬Available c) :
    c'.replicaLive holder ∧ c'.want holder ∧ ¬c'.pin holder := by
  obtain ⟨_, _, held | ⟨_, rfl⟩⟩ := promote
  · exact False.elim (unavailable held.1)
  · exact ⟨Or.inl rfl, Or.inl rfl, fun pinned => unavailable (hnl.pin_available holder pinned)⟩

/-- A staged row is a reachable state, not a dead branch: a complete commit
under a backend that does not make completion durable leaves a row that
`DropStaged` may then discard. -/
theorem staged_row_is_reachable (root : Root) :
    ∃ s : State H, Reachable s ∧ (s root).row ∧ ¬(s root).durable ∧
      ∃ s', Step s s' ∧ ¬(s' root).row := by
  let staged : Cell H := { row := True, bytes := True, fresh := True }
  refine ⟨Replace Initial root staged, ?_, ?_, ?_, Replace (Replace Initial root staged) root
    { staged with row := False, bytes := False }, ?_, ?_⟩
  · exact .next .initial (.root (.commitComplete ⟨not_false, Or.inr rfl⟩))
  · simp [Replace, staged]
  · simp [Replace, staged]
  · exact .root (.dropStaged ⟨by simp [Replace, staged], by simp [Replace, staged], by simp [Replace]⟩)
  · simp [Replace]

end Synchronicity.SystemSafety
