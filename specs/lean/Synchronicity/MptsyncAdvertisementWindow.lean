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
  head : Head
  sent : head ∈ inputs.advertisementSource.sentHeads item
  round : Nat
  roundWithin : round < inputs.advertisementRounds
  attempt : OriginScheduleExecution.Attempt
  attempted : attempt ∈ (inputs.advertisements.observation round).attempts
  sameItem : attempt.item = item
  delivered : OriginScheduleExecution.DeliveredLatest head attempt
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

/-- The receiving node's next successful native pending-slot bulk read is the
state/view produced by the actual acceptance fold. Strict advancement rules
out the already-complete retain case; the fold theorem then derives the exact
pending pointer and queue membership. -/
structure AcceptedLatestQueued
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (states : Nat → SimulatedHost.State)
    (timeline : AdvertisementTimeline inputs states)
    (origin : Origin.Parsed)
    (history : StableAdvertisementProgress.StableAuthorizedHistory origin) (latest : Head)
    (occurrence : AdvertisementOccurrence inputs) where
  accepted : AcceptedLatestOnTimeline inputs states timeline origin history latest occurrence
  strict : accepted.accepted.initial < AcceptanceProgress.rank latest
  pendingState : inputs.pendingSource.state = accepted.accepted.acceptedState
  pendingView : inputs.pendingSource.view = accepted.accepted.acceptedView

theorem AcceptedLatestQueued.pendingMember
    (queued : AcceptedLatestQueued inputs states timeline origin history latest occurrence) :
    OriginQueueSource.pendingItem (Origin.canonical origin) ∈ inputs.pendingItems := by
  have selected := StableAdvertisementProgress.actual_fold_selects_latest
    queued.accepted.accepted.delivered queued.accepted.accepted.accepted
      queued.accepted.accepted.initialBound
  have strictVersion : queued.accepted.accepted.initial <
      AcceptanceProgress.versionRank
        ({ seq := latest.seq, root := latest.root } : HeadVersion) := by
    simpa [AcceptanceProgress.rank, AcceptanceProgress.versionRank] using queued.strict
  exact inputs.pendingSource.pendingItem_mem_after_acceptance
    queued.accepted.accepted.accepted queued.pendingState queued.pendingView selected strictVersion

/-- A stable stored head and the actual handling promised for the exact
payload delivered by its bounded production scheduler attempt. The planner
item is derived from the successful bulk-head snapshot; it is not a free
membership witness supplied by the caller. -/
structure AcceptanceOpportunity (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (states : Nat → SimulatedHost.State) (timeline : AdvertisementTimeline inputs states)
    (origin : Origin.Parsed)
    (history : StableAdvertisementProgress.StableAuthorizedHistory origin) (latest : Head) where
  complete : inputs.advertisementSource.view (Origin.canonical origin) .complete = some
      ({ seq := latest.seq, root := latest.root } : HeadVersion)
  listedHead : inputs.advertisementSource.completeHead
    (Origin.canonical origin) = latest
  servable : inputs.advertisementSource.nativeServable (Origin.canonical origin) = true
  accept : ∀ occurrence : AdvertisementOccurrence inputs,
    occurrence.item = OriginQueueSource.advertisementItem
      inputs.advertisementSource.view (Origin.canonical origin) →
    occurrence.head = latest →
    Nonempty (AcceptedLatestQueued inputs states timeline origin history latest occurrence)

/-- M6's raw bounded service selects an attempt, and the external healthy-host
contract executes acceptance over that very attempt's received head list. -/
theorem scheduled_acceptance
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (timeline : AdvertisementTimeline inputs states)
    (opportunity : AcceptanceOpportunity inputs states timeline origin history latest) :
    ∃ occurrence, Nonempty
      (AcceptedLatestOnTimeline inputs states timeline origin history latest occurrence) := by
  have service := inputs.sentHeadsDelivered
  let item := OriginQueueSource.advertisementItem inputs.advertisementSource.view
    (Origin.canonical origin)
  have member : item ∈ inputs.advertisementItems :=
    inputs.advertisementSource.advertisementItem_mem_of_complete opportunity.complete
  have sent : latest ∈ inputs.advertisementSource.sentHeads item := by
    have listed := inputs.advertisementSource.completeHead_mem_sentHeads opportunity.servable
    rw [opportunity.listedHead] at listed
    exact listed
  obtain ⟨round, before, attempt, attempted, sameItem, delivered, contactBefore,
      peerAttempt, peerAttempted, samePeer, success⟩ :=
    service item member latest sent
  let occurrence : AdvertisementOccurrence inputs :=
    { item := item
      member := member
      head := latest
      sent := sent
      round := round
      roundWithin := before
      attempt := attempt
      attempted := attempted
      sameItem := sameItem
      delivered := delivered
      contactWithin := contactBefore
      peerAttempt := peerAttempt
      peerAttempted := peerAttempted
      samePeer := samePeer
      success := success }
  let ⟨queued⟩ := opportunity.accept occurrence rfl rfl
  exact ⟨occurrence, ⟨queued.accepted⟩⟩

/-- Strong form retaining the acceptance-to-pending-queue bridge consumed by
the first outer pending pass. -/
theorem scheduled_acceptance_queued
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (timeline : AdvertisementTimeline inputs states)
    (opportunity : AcceptanceOpportunity inputs states timeline origin history latest) :
    ∃ occurrence, Nonempty
      (AcceptedLatestQueued inputs states timeline origin history latest occurrence) := by
  have service := inputs.sentHeadsDelivered
  let item := OriginQueueSource.advertisementItem inputs.advertisementSource.view
    (Origin.canonical origin)
  have member : item ∈ inputs.advertisementItems :=
    inputs.advertisementSource.advertisementItem_mem_of_complete opportunity.complete
  have sent : latest ∈ inputs.advertisementSource.sentHeads item := by
    have listed := inputs.advertisementSource.completeHead_mem_sentHeads opportunity.servable
    rw [opportunity.listedHead] at listed
    exact listed
  obtain ⟨round, before, attempt, attempted, sameItem, delivered, contactBefore,
      peerAttempt, peerAttempted, samePeer, success⟩ := service item member latest sent
  let occurrence : AdvertisementOccurrence inputs :=
    { item := item
      member := member
      head := latest
      sent := sent
      round := round
      roundWithin := before
      attempt := attempt
      attempted := attempted
      sameItem := sameItem
      delivered := delivered
      contactWithin := contactBefore
      peerAttempt := peerAttempt
      peerAttempted := peerAttempted
      samePeer := samePeer
      success := success }
  exact ⟨occurrence, opportunity.accept occurrence rfl rfl⟩

end Synchronicity.MptsyncAdvertisementWindow
