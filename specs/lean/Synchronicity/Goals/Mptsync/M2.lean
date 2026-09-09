import Synchronicity.AdvertisementSelection
import Synchronicity.AcceptanceProgress

/-! # M2 — advertisement order and duplication do not change selection

This goal observes the actual `Exchange.plan` inputs and result.  Pull origins
are interpreted as their greatest remote advertised heads, and push positions
are resolved back through the actual servable input.  Thus the property is
about selected origins and versions, not incidental list positions.

`ValidAdvertisement` is the native 32-byte root contract and does not assume an
acceptance result.  The planner helper is followed by a top-level property for
actual `Reconcile.accept` folds.  Each fold edge carries independent healthy
signature/authorization/history/floor execution evidence; eventual delivery
and promotion remain the responsibility of the later convergence goals.
-/
namespace Synchronicity.Goals.Mptsync.M2
open VerifiedCore.Replication.Exchange
open AdvertisementSelection
open AcceptanceProgress

/-- Reordering or duplicating the same valid planner inputs preserves the sets
of greatest heads selected for pulling and concrete heads selected for pushing. -/
def SelectionInvariant (ours ours' theirs theirs' served served' : List Advertised) : Prop :=
  Equivalent theirs theirs' served served'
    (plan ours theirs served) (plan ours' theirs' served')

/-- **M2.** The production exchange planner's semantic selection is invariant
under advertisement order and duplication at the checked native boundary. -/
theorem selection_invariant
    (localSet : SameValidAdvertisements ours ours')
    (remote : SameValidAdvertisements theirs theirs')
    (servable : SameValidAdvertisements served served')
    (leftBound : served.length ≤ UInt64.size)
    (rightBound : served'.length ≤ UInt64.size) :
    SelectionInvariant ours ours' theirs theirs' served served' :=
  plans_equivalent localSet remote servable leftBound rightBound

/-- Actual handling counterpart of planner selection.  Both witnesses are
finite chains of production `Reconcile.accept` executions whose positive and
negative branches are obtained from healthy authorization/history/floor
certificates. -/
def HandlingInvariant (origin : String) (keep initial : Nat)
    (left right : List VerifiedCore.Replication.Head)
    (leftState rightState leftFinalState rightFinalState : SimulatedHost.State)
    (leftInitialView rightInitialView leftFinalView rightFinalView : HeadView)
    (leftStable : StableSlots leftState origin initial leftInitialView)
    (rightStable : StableSlots rightState origin initial rightInitialView)
    (leftFinal rightFinal : Nat)
    (_leftRun : ObservedAcceptanceFold origin keep initial leftState leftInitialView leftStable
      left leftFinal leftFinalState leftFinalView)
    (_rightRun : ObservedAcceptanceFold origin keep initial rightState rightInitialView rightStable
      right rightFinal rightFinalState rightFinalView) : Prop :=
  AcceptanceExecution keep leftState left leftFinalState ∧
    AcceptanceExecution keep rightState right rightFinalState ∧
    leftFinal = rightFinal ∧
    StableSlots leftFinalState origin leftFinal leftFinalView ∧
    StableSlots rightFinalState origin rightFinal rightFinalView ∧
    selectedVersion leftFinalView origin = selectedVersion rightFinalView origin

/-- M2's complete boundary: semantic planner choices and subsequent actual
healthy acceptance handling are both insensitive to order and duplicates. -/
def OrderDuplicationInvariant
    (ours ours' theirs theirs' served served' : List Advertised)
    (origin : String) (keep initial : Nat)
    (left right : List VerifiedCore.Replication.Head)
    (leftState rightState leftFinalState rightFinalState : SimulatedHost.State)
    (leftInitialView rightInitialView leftFinalView rightFinalView : HeadView)
    (leftStable : StableSlots leftState origin initial leftInitialView)
    (rightStable : StableSlots rightState origin initial rightInitialView)
    (leftFinal rightFinal : Nat)
    (leftRun : ObservedAcceptanceFold origin keep initial leftState leftInitialView leftStable
      left leftFinal leftFinalState leftFinalView)
    (rightRun : ObservedAcceptanceFold origin keep initial rightState rightInitialView rightStable
      right rightFinal rightFinalState rightFinalView) : Prop :=
  SelectionInvariant ours ours' theirs theirs' served served' ∧
    HandlingInvariant origin keep initial left right leftState rightState
      leftFinalState rightFinalState leftInitialView rightInitialView leftFinalView rightFinalView
      leftStable rightStable leftFinal rightFinal leftRun rightRun

/-- **M2.** Reordering or duplicating the same valid advertisements changes
neither the production exchange plan's semantic choices nor the stable latest
version produced by actual healthy acceptance executions.  M3's common
`HeadTransition` refinement for every fold edge is supplied by
`newer_head_transition` and `obsolete_head_transition`. -/
theorem order_duplication_invariant
    (localSet : SameValidAdvertisements ours ours')
    (remote : SameValidAdvertisements theirs theirs')
    (servable : SameValidAdvertisements served served')
    (handled : SameValidSignedAdvertisements left right)
    (leftBound : served.length ≤ UInt64.size)
    (rightBound : served'.length ≤ UInt64.size)
    (leftStable : StableSlots leftState origin initial leftInitialView)
    (rightStable : StableSlots rightState origin initial rightInitialView)
    (leftRun : ObservedAcceptanceFold origin keep initial leftState leftInitialView leftStable
      left leftFinal leftFinalState leftFinalView)
    (rightRun : ObservedAcceptanceFold origin keep initial rightState rightInitialView rightStable
      right rightFinal rightFinalState rightFinalView) :
    OrderDuplicationInvariant ours ours' theirs theirs' served served' origin keep initial
      left right leftState rightState leftFinalState rightFinalState
      leftInitialView rightInitialView leftFinalView rightFinalView leftStable rightStable
      leftFinal rightFinal leftRun rightRun := by
  constructor
  · exact selection_invariant localSet remote servable leftBound rightBound
  · have sameFinal := actual_folds_same_latest handled.same leftRun.actual rightRun.actual
    have leftObserved := leftRun.final_stable
    have rightObserved := rightRun.final_stable
    have rightAtLeft : StableSlots rightFinalState origin leftFinal rightFinalView := by
      rwa [sameFinal]
    exact ⟨leftRun.actual.execution, rightRun.actual.execution, sameFinal,
      leftObserved, rightObserved, stable_slots_selected_equal leftObserved rightAtLeft⟩

end Synchronicity.Goals.Mptsync.M2
