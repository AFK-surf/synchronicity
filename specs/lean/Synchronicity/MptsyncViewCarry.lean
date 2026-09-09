import Synchronicity.MptsyncRetryExecution
import Synchronicity.ReconciliationPayloadFrame
import Synchronicity.ReconciliationViewExecution

/-! Carry a previously published correct view through the production work
which accepts a later version and fetches its metadata before promotion.

Neither acceptance nor retry publishes a new complete slot. Their actual
executions preserve the old complete version and the materialized payload and
retention tables, so the preceding view remains the public view at the next
promotion boundary. -/
namespace Synchronicity.MptsyncViewCarry
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
open SimulatedHost AcceptanceProgress MptsyncConvergence

/-- A finite, view-indexed prefix.  Its first slot bound is supplied once;
subsequent bounds are outputs of the preceding actual event. -/
inductive StableSteps (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget) (latest : Nat)
    (world : TrieDiffCoverage.World) : State → HeadView → State → HeadView → Prop where
  | nil (state : State) (view : HeadView) :
      StableSteps services origin target latest world state view state view
  | cons
      (actual : ReconciliationExecution.Step event state next)
      (facts : ReconciliationViewExecution.StableStepFacts event state next
        services origin target latest world)
      (beforeView : facts.beforeView = view)
      (rest : StableSteps services origin target latest world next facts.afterView final finalView) :
      StableSteps services origin target latest world state view final finalView

/-- A finite production prefix carries one initial typed/backed/bounded
observation. It does not store any later upper bound, refinement, or correctness
claim. -/
structure StablePrefix (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget) (latest : Nat)
    (world : TrieDiffCoverage.World) (state final : State) where
  initialView : HeadView
  finalView : HeadView
  initial : ReconciliationViewExecution.StableSlotInputs state
    (Origin.canonical origin) latest initialView
  steps : StableSteps services origin target latest world state initialView final finalView

private theorem StableSteps.execution
    (run : StableSteps services origin target latest world state view final finalView) :
    ∃ observations, ReconciliationExecution.Execution state observations final := by
  induction run with
  | nil => exact ⟨[], .nil _⟩
  | @cons event state next view final finalView actual facts beforeView rest ih =>
      obtain ⟨observations, execution⟩ := ih
      exact ⟨⟨event, state, next⟩ :: observations, .cons actual execution⟩

/-- Erasing the raw stable contracts leaves precisely a finite production
`ReconciliationExecution.Execution`. -/
theorem StablePrefix.execution
    (run : StablePrefix services origin target latest world state final) :
    ∃ observations, ReconciliationExecution.Execution state observations final :=
  run.steps.execution

private theorem StableSteps.preserves
    (run : StableSteps services origin target latest world state view final finalView)
    (inputs : ReconciliationViewExecution.StableSlotInputs state
      (Origin.canonical origin) latest view)
    (correct : CorrectView services origin target state.db) :
    CorrectView services origin target final.db := by
  induction run with
  | nil => exact correct
  | cons actual facts beforeView rest ih =>
      cases beforeView
      have refined := ReconciliationViewExecution.stable_actual_step_refines
        actual facts inputs.bound correct
      exact ih refined.2.1 (MptsyncStableTail.refines_preserves refined.1 correct)

/-- An established public view survives every finite actual reconciliation
prefix whose per-step stability/host contracts are supplied independently. -/
theorem StablePrefix.preserves
    (run : StablePrefix services origin target latest world state final)
    (correct : CorrectView services origin target state.db) :
    CorrectView services origin target final.db := by
  exact run.steps.preserves run.initial correct

private theorem installed_of_observed
    (represented : HeadView.Represents db view)
    (sameOrigin : head.origin = origin)
    (observed : view (Origin.canonical origin) .complete =
      some ⟨head.seq, head.root⟩) :
    AtomicFileView.Installed db head := by
  have atHead : view (Origin.canonical head.origin) .complete =
      some ⟨head.seq, head.root⟩ := by
    simpa only [sameOrigin] using observed
  constructor
  · obtain ⟨row, selected, _⟩ := HeadView.existing represented atHead
    exact ⟨row, selected.1, by simpa [HeadView.Selected, HeadView.slotName,
      ReconciliationSlots.names] using selected.2⟩
  · intro row member named
    have selected : HeadView.Selected db (Origin.canonical head.origin) .complete row :=
      ⟨member, by simpa [HeadView.Selected, HeadView.slotName,
        ReconciliationSlots.names] using named⟩
    have here := represented (Origin.canonical head.origin) .complete
    rw [atHead] at here
    exact here.2 row selected

/-- The real acceptance fold and finite retry prefix transport a prior
`CorrectView` to the state at which the next promotion starts. The constructor
inputs are only raw operation witnesses and state equalities; correctness at
the later state is a theorem. -/
theorem correct_after_acceptance_and_retry
    (correct : CorrectView services origin target prior.db)
    (acceptance : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      prior initialView initialSlots heads final accepted acceptedView)
    (retry : MptsyncRetryExecution.RetryExecution requirements)
    (acceptedStart : accepted = retry.state 0)
    (promotionState : retry.state retry.endAt = state) :
    CorrectView services origin target state.db := by
  have initialObserved : initialView (Origin.canonical origin) .complete =
      some ⟨target.head.seq, target.head.root⟩ := by
    simpa only [correct.1] using
      (ReconciliationViewExecution.installed_view initialSlots.represents correct.2.1)
  have acceptedObserved : acceptedView (Origin.canonical origin) .complete =
      some ⟨target.head.seq, target.head.root⟩ := by
    rw [acceptance.complete_preserved]
    exact initialObserved
  have atRetryStart : StableSlots (retry.state 0) (Origin.canonical origin)
      final acceptedView := by
    rw [← acceptedStart]
    exact acceptance.final_stable
  have atRetryEnd := retry.stableSlotsAtEnd atRetryStart
  have endObserved : acceptedView (Origin.canonical origin) .complete =
      some ⟨target.head.seq, target.head.root⟩ := acceptedObserved
  have installedEnd : AtomicFileView.Installed state.db target.head := by
    rw [← promotionState]
    exact installed_of_observed atRetryEnd.represents correct.1 endObserved
  have acceptedFrame := ReconciliationPayloadFrame.acceptance_fold_payload acceptance.actual
  have retryFrame := retry.payloadAtEnd
  have payload : MptsyncStableTail.PayloadFrame prior.db state.db := by
    constructor
    · calc
        rows state.db "entries" = rows (retry.state retry.endAt).db "entries" := by
          rw [promotionState]
        _ = rows (retry.state 0).db "entries" := retryFrame.1
        _ = rows accepted.db "entries" := by rw [acceptedStart]
        _ = rows prior.db "entries" := acceptedFrame.1
    constructor
    · calc
        rows state.db "pins" = rows (retry.state retry.endAt).db "pins" := by
          rw [promotionState]
        _ = rows (retry.state 0).db "pins" := retryFrame.2.1
        _ = rows accepted.db "pins" := by rw [acceptedStart]
        _ = rows prior.db "pins" := acceptedFrame.2.1
    · calc
        rows state.db "content_want" =
            rows (retry.state retry.endAt).db "content_want" := by rw [promotionState]
        _ = rows (retry.state 0).db "content_want" := retryFrame.2.2
        _ = rows accepted.db "content_want" := by rw [acceptedStart]
        _ = rows prior.db "content_want" := acceptedFrame.2.2
  exact MptsyncStableTail.refines_preserves
    (Or.inr (Or.inr (Or.inl ⟨payload, installedEnd⟩))) correct

end Synchronicity.MptsyncViewCarry
