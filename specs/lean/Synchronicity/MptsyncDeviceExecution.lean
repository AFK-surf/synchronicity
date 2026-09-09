import Synchronicity.MptsyncAdvertisementWindow
import Synchronicity.MptsyncRetryExecution

/-! Device-shared factual registry for the finite work before promotion.

Hello/contact observations, acceptance handlers, requester retry checkpoints,
and reconciliation promotions live at different implementation layers. They
therefore retain separate factual maps, while `ownerAt` gives them one common
device-time exclusion rule. Coincident boundaries are allowed only for the
same origin; two origin runs cannot claim incompatible work at one time.
-/
namespace Synchronicity.MptsyncDeviceExecution
open VerifiedCore VerifiedCore.Replication
open StableAdvertisementProgress MptsyncConvergence

/-- Existential packaging keeps the exact schedule and occurrence together in
one device-wide map despite their dependent types. -/
structure HelloOccurrence where
  inputs : MptsyncScheduleExecution.StableScheduleInputs
  occurrence : MptsyncAdvertisementWindow.AdvertisementOccurrence inputs

/-- Shared outer observations for one device. These maps contain ownership and
operation provenance only, never acceptance, completion, promotion, or view
correctness conclusions. -/
structure Registry (_states : Nat → SimulatedHost.State) where
  ownerAt : Nat → Option Origin.Parsed
  helloAt : Nat → Option HelloOccurrence
  acceptanceAt : Nat → Option Origin.Parsed
  retryAt : Nat → Option (Origin.Parsed × Nat)
  promotionAt : Nat → Option Origin.Parsed

/-- The exact occurrence/handler/retry segment claimed by one origin run on a
shared device registry. Retry checkpoints remain in their native execution,
but every endpoint is anchored to the public state timeline and one owner. -/
structure PrePromotionSegment
    (registry : Registry states) (origin : Origin.Parsed)
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (timeline : MptsyncAdvertisementWindow.AdvertisementTimeline inputs states)
    (history : StableAuthorizedHistory origin) (latest : Head)
    (occurrence : MptsyncAdvertisementWindow.AdvertisementOccurrence inputs)
    (accepted : MptsyncAdvertisementWindow.AcceptedLatestOnTimeline inputs states timeline
      origin history latest occurrence)
    (retryStart : Nat) (retry : MptsyncRetryExecution.RetryExecution requirements) : Prop where
  helloOwner : registry.ownerAt accepted.accepted.observedAt = some origin
  hello : registry.helloAt accepted.accepted.observedAt =
    some ⟨inputs, occurrence⟩
  acceptanceOwner : ∀ n, accepted.accepted.handledAt ≤ n → n ≤ retryStart →
    registry.ownerAt n = some origin
  acceptance : registry.acceptanceAt accepted.accepted.handledAt = some origin
  acceptedAt : accepted.accepted.acceptedState = states retryStart
  retryOwner : ∀ n, n ≤ retry.endAt →
    registry.ownerAt (retryStart + n) = some origin
  retryCheckpoint : ∀ n, n < retry.endAt →
    registry.retryAt (retryStart + n) = some (origin, n)

theorem Registry.owner_unique (registry : Registry states)
    (left : registry.ownerAt now = some leftOrigin)
    (right : registry.ownerAt now = some rightOrigin) : leftOrigin = rightOrigin := by
  rw [left] at right
  exact Option.some.inj right

theorem Registry.hello_unique (registry : Registry states)
    (left : registry.helloAt now = some leftOccurrence)
    (right : registry.helloAt now = some rightOccurrence) :
    leftOccurrence = rightOccurrence := by
  rw [left] at right
  exact Option.some.inj right

/-- The primitive promotion edge is registered at its public device time. -/
structure PromotionSegment (registry : Registry states) (origin : Origin.Parsed)
    (index : Nat) : Prop where
  owner : registry.ownerAt index = some origin
  promotion : registry.promotionAt index = some origin

/-- Scenario targets are explicitly the greatest heads in the one stable,
finite, production-certified publisher history. Delivery remains a separate
scheduler obligation. -/
def StableScenarioHistory (scenario : Scenario Device)
    (history : (origin : Origin.Parsed) → StableAuthorizedHistory origin) : Prop :=
  ∀ device origin, scenario.participates device → scenario.includes origin →
    (history origin).Latest (scenario.target device origin).head

end Synchronicity.MptsyncDeviceExecution
