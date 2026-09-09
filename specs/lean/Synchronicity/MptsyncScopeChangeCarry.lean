import Synchronicity.MptsyncRetryExecution
import Synchronicity.ReconciliationPayloadFrame
import Synchronicity.ScopeChangePromotionBaseline

/-! Carry the origin-local database reset produced by a real scope change
through the actual advertisement-acceptance fold and finite retry prefix.

Acceptance may install a pending head, but it does not recreate a complete
head or materialized entries. Fetch retries preserve both relations. Hence the
promotion boundary has the clean old-view facts required by materialization,
without assuming a clean database at that later observation. -/
namespace Synchronicity.MptsyncScopeChangeCarry
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
open SimulatedHost AcceptanceProgress ScopeChangeRefinement

private theorem view_complete_none
    (absent : ¬ ∃ row, HeadView.Selected db origin .complete row)
    (represented : HeadView.Represents db view) :
    view origin .complete = none := by
  cases value : view origin .complete with
  | none => rfl
  | some version =>
      obtain ⟨row, selected, _⟩ := HeadView.existing represented value
      exact False.elim (absent ⟨row, selected⟩)

/-- A committed scope reset immediately preceding the observed acceptance and
finite retry prefix supplies the initial-view contract for the next actual
promotion. All state links are equalities between those production traces. -/
theorem initial_after_acceptance_and_retry
    (production : Successful spaces changedAt before initialState report)
    (quiet : before.faults = [])
    (reported : decision ∈ report.demotions)
    (originAligned : decision.complete.origin = Origin.canonical origin)
    (acceptance : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      initialState initialView initialSlots heads final acceptedState acceptedView)
    (retry : MptsyncRetryExecution.RetryExecution requirements)
    (acceptedStart : acceptedState = retry.state 0)
    (promotionState : retry.state retry.endAt = state)
    (laterSlots : StableSlots state (Origin.canonical origin) final acceptedView)
    (metadata : ScopeChangePromotionBaseline.MetadataContracts
      state.db origin world services) :
    PromotionInitialView.Initial state.db origin world services := by
  obtain ⟨_, raw⟩ := successful_change_raw production quiet reported
  obtain ⟨initialCompleteAbsent, initialEntriesAbsent⟩ :=
    ScopeChangePromotionBaseline.invalidated_absence raw originAligned
  have initialCompleteNone : initialView (Origin.canonical origin) .complete = none :=
    view_complete_none initialCompleteAbsent initialSlots.represents
  have acceptedCompleteNone :
      acceptedView (Origin.canonical origin) .complete = none := by
    rw [acceptance.complete_preserved]
    exact initialCompleteNone
  have completeAbsent :
      ¬ ∃ row, HeadView.Selected state.db (Origin.canonical origin) .complete row := by
    rintro ⟨row, selected⟩
    exact HeadView.absent laterSlots.represents acceptedCompleteNone selected
  have sameEntries : rows state.db "entries" = rows initialState.db "entries" := by
    calc
      rows state.db "entries" = rows (retry.state retry.endAt).db "entries" := by
        rw [promotionState]
      _ = rows (retry.state 0).db "entries" := retry.entriesAtEnd
      _ = rows acceptedState.db "entries" := by rw [acceptedStart]
      _ = rows initialState.db "entries" :=
        ReconciliationPayloadFrame.acceptance_fold_entries acceptance.actual
  have entriesAbsent :
      (rows state.db "entries").any
        (fun row => equals row
          [("origin_id", .text (Origin.canonical origin))]) = false := by
    rw [sameEntries]
    exact initialEntriesAbsent
  exact PromotionBaseline.initial_origin
    (ScopeChangePromotionBaseline.clean_origin_baseline_of_absence
      completeAbsent entriesAbsent metadata)

end Synchronicity.MptsyncScopeChangeCarry
