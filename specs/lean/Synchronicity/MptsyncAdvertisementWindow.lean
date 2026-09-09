import Synchronicity.MptsyncScheduleExecution
import Synchronicity.StableAdvertisementProgress

/-! The execution seam from bounded advertisement scheduling to an actual
production acceptance fold.  Scheduling proves which wire attempt occurs;
signature/authority checks and host execution remain explicit observations of
that same attempt. -/
namespace Synchronicity.MptsyncAdvertisementWindow
open VerifiedCore VerifiedCore.Replication
open AcceptanceProgress MptsyncConvergence

/-- An actual acceptance fold over precisely one peer-observed Hello payload. -/
structure AcceptedLatest (origin : Origin.Parsed)
    (history : StableAdvertisementProgress.StableAuthorizedHistory origin)
    (latest : Head) (heads : List Head) where
  observedAt : Nat
  handledAt : Nat
  afterDelivery : observedAt < handledAt
  keep : Nat
  initial : Nat
  final : Nat
  initialState : SimulatedHost.State
  acceptedState : SimulatedHost.State
  initialView : HeadView
  acceptedView : HeadView
  initialSlots : StableSlots initialState (Origin.canonical origin) initial initialView
  delivered : StableAdvertisementProgress.DeliveredLatest history latest heads
  accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
    initialState initialView initialSlots heads final acceptedState acceptedView
  initialBound : initial ≤ rank latest

/-- The exact Hello attempt selected by M6, including its successful contact
provenance.  This record retains the scheduler witnesses instead of erasing
them to the received head list. -/
structure AdvertisementOccurrence
    (inputs : MptsyncScheduleExecution.StableScheduleInputs) where
  item : OriginSchedule.Item
  member : item ∈ inputs.advertisementItems
  round : Nat
  roundWithin : round < inputs.advertisementRounds
  attempt : OriginScheduleExecution.Attempt
  attempted : attempt ∈ (inputs.advertisements.observation round).attempts
  sameItem : attempt.item = item
  delivered : OriginScheduleExecution.DeliveredLatest (inputs.latest item) attempt
  contactWithin : inputs.advertisementLink.contactRound round < inputs.peerRounds
  peerAttempt : ContactExecution.Attempt
  peerAttempted : peerAttempt ∈ (inputs.contacts.observation
    (inputs.advertisementLink.contactRound round)).attempts
  samePeer : peerAttempt.peer = inputs.peer
  success : peerAttempt.outcome = .success

/-- Runtime recording of Hello occurrences on the same index axis as the
public host states.  The map is the narrow outer-runtime contract joining the
scheduler observation to that production timeline. -/
structure AdvertisementTimeline
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (_states : Nat → SimulatedHost.State) where
  occurrenceAt : Nat → Option (AdvertisementOccurrence inputs)

/-- Actual acceptance of the exact received payload of one recorded scheduler
attempt.  Both the delivery time and the handler's initial state are anchored
to the public production timeline. -/
structure AcceptedLatestOnTimeline
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (states : Nat → SimulatedHost.State)
    (timeline : AdvertisementTimeline inputs states)
    (origin : Origin.Parsed)
    (history : StableAdvertisementProgress.StableAuthorizedHistory origin) (latest : Head)
    (occurrence : AdvertisementOccurrence inputs) where
  accepted : AcceptedLatest origin history latest
    (OriginScheduleExecution.receivedHeads occurrence.attempt)
  recorded : timeline.occurrenceAt accepted.observedAt = some occurrence
  initialAt : accepted.initialState = states accepted.handledAt

/-- A stable origin item and the actual handling promised for the exact
payload delivered by its bounded production scheduler attempt. -/
structure AcceptanceOpportunity (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (states : Nat → SimulatedHost.State) (timeline : AdvertisementTimeline inputs states)
    (origin : Origin.Parsed)
    (history : StableAdvertisementProgress.StableAuthorizedHistory origin) (latest : Head) where
  item : OriginSchedule.Item
  member : item ∈ inputs.advertisementItems
  sameHead : inputs.latest item = latest
  accept : ∀ occurrence : AdvertisementOccurrence inputs,
    occurrence.item = item →
    Nonempty (AcceptedLatestOnTimeline inputs states timeline origin history latest occurrence)

/-- M6's raw bounded service selects an attempt, and the external healthy-host
contract executes acceptance over that very attempt's received head list. -/
theorem scheduled_acceptance
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (timeline : AdvertisementTimeline inputs states)
    (opportunity : AcceptanceOpportunity inputs states timeline origin history latest) :
    ∃ occurrence, Nonempty
      (AcceptedLatestOnTimeline inputs states timeline origin history latest occurrence) := by
  have service := inputs.latestDelivered
  obtain ⟨round, before, attempt, attempted, sameItem, delivered, contactBefore,
      peerAttempt, peerAttempted, samePeer, success⟩ :=
    service opportunity.item opportunity.member
  have targetDelivered : OriginScheduleExecution.DeliveredLatest latest attempt := by
    rw [← opportunity.sameHead]
    exact delivered
  let occurrence : AdvertisementOccurrence inputs :=
    { item := opportunity.item
      member := opportunity.member
      round := round
      roundWithin := before
      attempt := attempt
      attempted := attempted
      sameItem := sameItem
      delivered := by simpa only [opportunity.sameHead] using targetDelivered
      contactWithin := contactBefore
      peerAttempt := peerAttempt
      peerAttempted := peerAttempted
      samePeer := samePeer
      success := success }
  exact ⟨occurrence, opportunity.accept occurrence rfl⟩

end Synchronicity.MptsyncAdvertisementWindow
