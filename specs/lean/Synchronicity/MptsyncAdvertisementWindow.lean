import Synchronicity.MptsyncScheduleExecution
import Synchronicity.Goals.Mptsync.M6
import Synchronicity.StableAdvertisementProgress

/-! The execution seam from bounded advertisement scheduling to an actual
production acceptance fold.  Scheduling proves which wire attempt occurs;
signature/authority checks and host execution remain explicit observations of
that same attempt. -/
namespace Synchronicity.MptsyncAdvertisementWindow
open VerifiedCore VerifiedCore.Replication
open AcceptanceProgress MptsyncConvergence

/-- An actual acceptance fold over precisely one peer-observed Hello payload. -/
structure AcceptedLatest (valid : Head → Prop) (origin : Origin.Parsed)
    (latest : Head) (heads : List Head) where
  keep : Nat
  initial : Nat
  final : Nat
  initialState : SimulatedHost.State
  acceptedState : SimulatedHost.State
  initialView : HeadView
  acceptedView : HeadView
  initialSlots : StableSlots initialState (Origin.canonical origin) initial initialView
  delivered : StableAdvertisementProgress.DeliveredLatest valid origin latest heads
  accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
    initialState initialView initialSlots heads final acceptedState acceptedView
  initialBound : initial ≤ rank latest

/-- A stable origin item and the actual handling promised for the exact
payload delivered by its bounded production scheduler attempt. -/
structure AcceptanceOpportunity (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (valid : Head → Prop) (origin : Origin.Parsed) (latest : Head) where
  item : OriginSchedule.Item
  member : item ∈ inputs.advertisementItems
  sameHead : inputs.latest item = latest
  accept : ∀ round attempt,
    round < inputs.advertisementRounds →
    attempt ∈ (inputs.advertisements.observation round).attempts →
    attempt.item = item →
    OriginScheduleExecution.DeliveredLatest latest attempt →
    Nonempty (AcceptedLatest valid origin latest
      (OriginScheduleExecution.receivedHeads attempt))

/-- M6's raw bounded service selects an attempt, and the external healthy-host
contract executes acceptance over that very attempt's received head list. -/
theorem scheduled_acceptance
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (opportunity : AcceptanceOpportunity inputs valid origin latest) :
    ∃ heads, Nonempty (AcceptedLatest valid origin latest heads) := by
  have service := Goals.Mptsync.M6.inputs_service inputs
  obtain ⟨round, before, attempt, attempted, sameItem, delivered, contactBefore,
      peerAttempt, peerAttempted, samePeer, success⟩ :=
    service.deliveredLatest opportunity.item opportunity.member
  have targetDelivered : OriginScheduleExecution.DeliveredLatest latest attempt := by
    rw [← opportunity.sameHead]
    exact delivered
  exact ⟨OriginScheduleExecution.receivedHeads attempt,
    opportunity.accept round attempt before attempted sameItem targetDelivered⟩

end Synchronicity.MptsyncAdvertisementWindow
