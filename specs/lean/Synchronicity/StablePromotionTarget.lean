import Synchronicity.PromotionProgress
import Synchronicity.AcceptanceProgress
import Synchronicity.ReconciliationFloor
import Synchronicity.StableAdvertisementProgress

/-! Connect the version selected by stable advertisement handling to the
candidate read by a later production promotion.  Selection is observed in the
raw complete/pending view; promotion obtains its candidate from a fresh raw
pending-slot read in its own transaction. -/
namespace Synchronicity.StablePromotionTarget
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
  SimulatedHost AcceptanceProgress

/-- If the complete slot is absent, an actual selected version is exactly the
pending slot.  This is a raw-view consequence, not an assumed promotion target. -/
theorem pending_of_selected_without_complete
    (complete : view origin .complete = none)
    (selected : selectedVersion view origin = some version) :
    view origin .pending = some version := by
  unfold selectedVersion at selected
  rw [complete] at selected
  cases pending : view origin .pending <;> simp_all

/-- The candidate returned by actual promotion preparation is the stable
pending version represented and backed in the promotion's starting database. -/
theorem ready_uses_observed_pending
    (ready : PromotionProgress.Ready origin now refused state)
    (stable : StableSlots state (Origin.canonical origin) latest view)
    (pending : view (Origin.canonical origin) .pending = some version) :
    ready.pending.head.seq = version.seq ∧ ready.pending.head.root = version.root := by
  have rawBegin := OperationExecution.raise_success (fun _ _ => rfl)
    Promote.Error.host Storage.begin state ready.opened ready.tx ready.began
  have snapshot := ReconciliationFloor.begin_pending state ready.opened ready.tx rawBegin
  obtain ⟨current, selected, sameSeq, sameRoot⟩ :=
    PromotionCommand.prepare_pending_floor ready.tx origin now ready.opened ready.prepared
      state.db snapshot version.seq.toInt64 version.root
      (stable.backed (Origin.canonical origin) .pending version pending)
      ready.scope ready.authority (some ready.pending) ready.old ready.preparation
  have sameCandidate : current = ready.pending := Option.some.inj selected.symm
  subst current
  exact ⟨by simpa using sameSeq, sameRoot⟩

/-- Delivery of the stable greatest signed head, its actual acceptance fold,
and an empty complete slot determine the later production promotion candidate.
No selected-version or promotion-result premise is needed. -/
theorem ready_uses_delivered_latest
    (delivered : StableAdvertisementProgress.DeliveredLatest valid origin latestHead heads)
    (accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      initialState initialView initialSlots heads final state view)
    (initialBound : initial ≤ rank latestHead)
    (complete : view (Origin.canonical origin) .complete = none)
    (ready : PromotionProgress.Ready origin now refused state) :
    ready.pending.head.seq = latestHead.seq ∧
      ready.pending.head.root = latestHead.root := by
  have selected := StableAdvertisementProgress.actual_fold_selects_latest
    delivered accepted initialBound
  have pending := pending_of_selected_without_complete complete selected
  exact ready_uses_observed_pending ready accepted.final_stable pending

end Synchronicity.StablePromotionTarget
