import Synchronicity.TargetTransition
import Synchronicity.RetirementProtection

namespace Synchronicity.RetirementTransition
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase Goals.Mptsync

theorem fields_match (row : Fields) (pending : Promote.Pending) :
    equals row (TargetTransition.fields (TargetTransition.pendingKey pending)) =
      equals row (RetirementProtection.key pending) := by
  simp [TargetTransition.fields, TargetTransition.pendingKey, RetirementProtection.key,
    Reconcile.headKey, equals, Bool.and_assoc, Bool.and_left_comm, Bool.and_comm]

theorem refines (pending : Promote.Pending)
    (continuation rest : Program Promote.Effects (Except Promote.Error Unit))
    (reachable : Continuation (Promote.retire pending).run continuation)
    (state final : State) (closed : state.pending = none)
    (path : Prefix continuation state rest final)
    (before : HeadView.Represents state.db view) (after : HeadView.Represents final.db nextView) :
    HeadTransition [TargetTransition.pendingKey pending] view nextView := by
  have different : equals [] (RetirementProtection.key pending) = false := by
    simp [RetirementProtection.key, Reconcile.headKey, equals, cell, isCell, equalCell, BEq.beq, instBEqCell.beq]
  apply TargetTransition.refines _ before after
  · exact HeadKeyFrame.no_new_keys_prefix continuation rest
      ((RetirementProtection.retire_only [] pending different).continuation reachable)
      (fun predicate => RetirementProtection.effects_preserve_keys predicate []) state final closed path
  · intro row present unmatched
    rw [fields_match] at unmatched
    exact RetirementProtection.every_resumption_preserves pending continuation rest reachable state final closed path row present unmatched

end Synchronicity.RetirementTransition
