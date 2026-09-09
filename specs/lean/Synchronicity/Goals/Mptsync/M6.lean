import Synchronicity.OriginScheduleExecution

/-! # M6 — failed work does not starve healthy peer/origin tasks

The production contact planner first provides bounded peer turns. On a healthy
peer's usable completed contacts, the production weighted-origin planner owns
both oversized Hello pages and pending Fetch work. Each selected batch records
all attempts before persisting its cursor; cancellation therefore retains the
old cursor. Failures, timeouts and unavailable pending targets terminate their
turn and cannot pin a later origin behind a fixed prefix.

Dynamic eligibility and an infinite absence of usable network/storage windows
remain external limitations. The explicit link below requires factual
successful contact observations, not an assumed Fetch or promotion result.
-/
namespace Synchronicity.Goals.Mptsync.M6
open VerifiedCore.Replication

/-- User-facing scheduler service: every healthy peer is contacted, and every
stable advertised and pending origin is attempted during a factual usable
contact with the selected healthy peer. -/
structure BoundedService
    (healthy : ByteArray → Prop)
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (advertisements : OriginScheduleExecution.Execution .advertisement
      advertisementItems advertisementMaximum advertisementDeadline advertisementRounds)
    (advertisementLink : OriginScheduleExecution.LinkedToContact contacts peer advertisements)
    (latest : OriginSchedule.Item → Head)
    (pending : OriginScheduleExecution.Execution .pendingFetch
      pendingItems pendingMaximum pendingDeadline pendingRounds)
    (pendingLink : OriginScheduleExecution.LinkedToContact contacts peer pending)
    (pendingTarget : OriginSchedule.Item → OriginScheduleExecution.Target) : Prop where
  healthyPeers : ContactExecution.HealthyPeersAttempted healthy contacts
  selectedPeerHealthy : peer ∈ eligible ∧ healthy peer
  advertisedOrigins : OriginScheduleExecution.ItemsAttemptedOnUsableContact
    contacts peer advertisements advertisementLink
  deliveredLatest : OriginScheduleExecution.LatestDeliveredOnUsableContact
    contacts peer advertisements advertisementLink latest
  pendingOrigins : OriginScheduleExecution.ItemsAttemptedOnUsableContact
    contacts peer pending pendingLink
  pendingFetchOpportunity : OriginScheduleExecution.PendingFetchOpportunities
    contacts peer pending pendingLink pendingTarget

/-- **M6 (stable finite sets).** Actual production contact, summary-page and
pending-origin decisions provide bounded attempts to every healthy task. A
stalling earlier peer/origin may fail or time out, but cannot consume another
task's cursor turn. -/
theorem bounded_service
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peerWidth : ∀ candidate ∈ eligible, candidate.size = 32)
    (peersWithin : eligible.length ≤ UInt64.size)
    (peerMaximumPositive : 0 < peerMaximum)
    (enoughPeerRounds : (Contact.index eligible).toList.length ≤ peerRounds * peerMaximum)
    (healthy : ByteArray → Prop)
    (peerMember : peer ∈ eligible) (peerHealthy : healthy peer)
    (advertisements : OriginScheduleExecution.Execution .advertisement
      advertisementItems advertisementMaximum advertisementDeadline advertisementRounds)
    (advertisementLink : OriginScheduleExecution.LinkedToContact contacts peer advertisements)
    (latest : OriginSchedule.Item → Head)
    (advertisementPayloads : OriginScheduleExecution.AdvertisementPayloads advertisements latest)
    (advertisementDistinct : ∀ left ∈ advertisementItems, ∀ right ∈ advertisementItems,
      OriginSchedule.key left.origin = OriginSchedule.key right.origin → left = right)
    (advertisementsWithin : advertisementItems.length ≤ UInt64.size)
    (advertisementsFit : ∀ item ∈ advertisementItems,
      item.weight.toNat ≤ advertisementMaximum)
    (enoughAdvertisementRounds :
      (OriginSchedule.index advertisementItems).toList.length ≤ advertisementRounds)
    (pending : OriginScheduleExecution.Execution .pendingFetch
      pendingItems pendingMaximum pendingDeadline pendingRounds)
    (pendingLink : OriginScheduleExecution.LinkedToContact contacts peer pending)
    (pendingTarget : OriginSchedule.Item → OriginScheduleExecution.Target)
    (pendingPayloads : OriginScheduleExecution.PendingPayloads pending pendingTarget)
    (pendingDistinct : ∀ left ∈ pendingItems, ∀ right ∈ pendingItems,
      OriginSchedule.key left.origin = OriginSchedule.key right.origin → left = right)
    (pendingWithin : pendingItems.length ≤ UInt64.size)
    (pendingFit : ∀ item ∈ pendingItems, item.weight.toNat ≤ pendingMaximum)
    (enoughPendingRounds :
      (OriginSchedule.index pendingItems).toList.length ≤ pendingRounds) :
    BoundedService healthy contacts peer advertisements advertisementLink latest
      pending pendingLink pendingTarget := by
  refine ⟨ContactExecution.healthy_peers_receive_bounded_attempts contacts peerWidth peersWithin
    peerMaximumPositive enoughPeerRounds healthy, ⟨peerMember, peerHealthy⟩, ?_, ?_, ?_, ?_⟩
  · exact OriginScheduleExecution.every_item_is_attempted_on_a_usable_contact
      contacts peer advertisements advertisementLink advertisementDistinct advertisementsWithin
      advertisementsFit enoughAdvertisementRounds
  · exact OriginScheduleExecution.every_latest_is_delivered contacts peer advertisements
      advertisementLink latest advertisementPayloads advertisementDistinct advertisementsWithin
      advertisementsFit enoughAdvertisementRounds
  · exact OriginScheduleExecution.every_item_is_attempted_on_a_usable_contact
      contacts peer pending pendingLink pendingDistinct pendingWithin pendingFit enoughPendingRounds
  · exact OriginScheduleExecution.every_pending_has_a_fetch_opportunity contacts peer pending
      pendingLink pendingTarget pendingPayloads pendingDistinct pendingWithin pendingFit
      enoughPendingRounds

end Synchronicity.Goals.Mptsync.M6
