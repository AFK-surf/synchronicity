import Synchronicity.AcceptanceProtection
import Synchronicity.HeadView

namespace Synchronicity.AcceptanceTransition
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

theorem refines (head : Head) (now : Int64) (keep : Nat) (state : State) (closed : state.pending = none)
    (before : HeadView.Represents state.db view) (backed : HeadView.Backed state.db view)
    (after : HeadView.Represents (execute (Reconcile.accept head now keep) state).2.db nextView) :
    HeadTransition [] view nextView := by
  classical
  cases outcome : (execute (Reconcile.accept head now keep) state).1 with
  | error failure =>
    apply HeadView.refines_retained before after
    intro row member
    rwa [ReconciliationFailure.acceptance_failure head now keep state failure outcome]
  | ok answer =>
    by_cases accepted : answer = .pending
    · subst answer
      intro origin slot
      cases oldValue : view origin slot with
      | none => exact HeadView.initially_empty _
      | some old =>
        cases slot with
        | complete =>
          have same := HeadView.stays before after oldValue (fun row selected =>
            ((AcceptanceProtection.accept_only row head now keep
              (PromotionBound.complete_not_pending row origin selected.2 (Origin.canonical head.origin))).invariant
              (ProtectedHead.retained row) (AcceptanceProtection.effects_retain row) state
              (ProtectedHead.initial row state closed selected.1)).1)
          rw [same]
          exact .keep _ _
        | pending =>
          by_cases sameOrigin : origin = Origin.canonical head.origin
          · subst origin
            obtain ⟨⟨row, member, named⟩, written⟩ := ReconciliationAcceptance.accepted_installs_pending head now keep state outcome
            obtain ⟨next, value, stored⟩ := HeadView.selected_version (slot := .pending) after ⟨member, named⟩
            have same := HeadView.version_unique row next (⟨head.seq, head.root⟩ : HeadVersion) stored (written row member named)
            have newer := ReconciliationFloor.accepted_beats_initial_floor head now keep state "pending" (Or.inr rfl)
              old.seq.toInt64 old.root (backed _ _ old oldValue) outcome
            rw [value]
            apply HeadChange.advance _ _ next
            intro previous equal
            cases equal
            rw [same]
            apply (HeadView.newer_iff _ _).mp
            simpa using newer
          · have same := HeadView.stays before after oldValue (fun row selected =>
              ((AcceptanceProtection.accept_only row head now keep
                (HeadView.other_name selected.2 (Or.inl sameOrigin))).invariant
                (ProtectedHead.retained row) (AcceptanceProtection.effects_retain row) state
                (ProtectedHead.initial row state closed selected.1)).1)
            rw [same]
            exact .keep _ _
    · apply HeadView.refines_retained before after
      intro row member
      rwa [ReconciliationRejection.nonacceptance_preserves_heads head now keep state answer accepted outcome]

end Synchronicity.AcceptanceTransition
