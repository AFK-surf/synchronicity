import Synchronicity.ReconciliationFailure
import Synchronicity.ProtectedHead
import Synchronicity.PromotionBound

/-! Acceptance cannot disturb any complete row, including on host failure.
The certificate quantifies over every possible raw reply. -/
namespace Synchronicity.AcceptanceProtection
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def allowed (row : Fields) (A : Type) : History.Effects A → Prop
  | .left effect => ProtectedHead.storageAllowed row effect
  | .right _ => True

theorem effects_retain (row : Fields) (effect : History.Effects A) (safe : allowed row _ effect)
    (state : State) (kept : ProtectedHead.retained row state) :
    ProtectedHead.retained row (Interpreter.handle effect state).2 := by
  cases effect with
  | left effect => exact ProtectedHead.storage_retains row effect safe state kept
  | right effect =>
    cases effect <;> apply ProtectedHead.reply_retains _ _ _ _ _ _ kept <;> intro s h <;> exact h

theorem framed (row : Fields) (operation : History.Action A)
    (safe : Only ReconciliationFrame.allowed operation.run) : Only (allowed row) operation.run := by
  apply safe.mono
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | exact Or.inl good | exact good | trivial
  | right _ => trivial

theorem put_pending (row : Fields) (head : Head) (now : Int64) (tx : Transaction)
    (different : ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = false) :
    Only (allowed row) (Reconcile.putSlot tx "pending" head now now).run := by
  unfold Reconcile.putSlot
  refine (framed row _ (ReconciliationFrame.record_only tx head now)).seq fun _ => ?_
  apply Only.raise
  apply Or.inr
  change conflict ["origin_id", "slot"] (ReconciliationSlots.incoming head "pending" now now) row = false
  rw [ReconciliationSlots.conflicts_iff_names, different]

theorem accept_only (row : Fields) (head : Head) (now : Int64) (keep : Nat)
    (different : ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = false) :
    Only (allowed row) (Reconcile.accept head now keep).run := by
  unfold Reconcile.accept
  refine Only.seq (Only.raise _ _ trivial) fun valid => ?_
  split
  · exact .done _
  · apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
    intro tx
    refine (framed row _ (ReconciliationFrame.auth_only _ (ReconciliationFrame.trustInstant_only tx now))).seq fun instant => ?_
    refine (framed row _ (ReconciliationFrame.auth_only _ (ReconciliationFrame.liveForKey_only tx head.signedBy instant))).seq fun live => ?_
    split
    · exact .done _
    · refine (framed row _ (ReconciliationFrame.record_only tx head now)).seq fun _ => ?_
      refine (framed row _ (ReconciliationFrame.readSlot_only tx _ "complete")).seq fun complete => ?_
      refine (framed row _ (ReconciliationFrame.readSlot_only tx _ "pending")).seq fun pending => ?_
      dsimp only
      split
      · exact (put_pending row head now tx different).seq fun _ =>
          (framed row _ (ReconciliationFrame.trimForks_only tx _ head.seq keep)).seq fun _ => .done _
      · exact (framed row _ (ReconciliationFrame.trimForks_only tx _ head.seq keep)).seq fun _ => .done _

theorem complete_retained (row : Fields) (head : Head) (now : Int64) (keep : Nat)
    (state : State) (closed : state.pending = none) (present : row ∈ rows state.db "heads")
    (complete : ReconciliationSlots.names row (Origin.canonical head.origin) "complete" = true) :
    row ∈ rows (execute (Reconcile.accept head now keep) state).2.db "heads" := by
  have different := PromotionBound.complete_not_pending row _ complete (Origin.canonical head.origin)
  exact ((accept_only row head now keep different).invariant (ProtectedHead.retained row)
    (effects_retain row) state (ProtectedHead.initial row state closed present)).1

end Synchronicity.AcceptanceProtection
