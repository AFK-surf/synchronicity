import Synchronicity.OriginScheduleExecution

/-! Stable-window runtime inputs shared by the mptsync goal hierarchy.
This module records production contact/origin executions, wire observations
and finite bounds; it contains no goal property or scheduler-service result. -/
namespace Synchronicity.MptsyncScheduleExecution
open VerifiedCore.Replication

/-- The factual stable-window scheduler inputs.  Callers retain the raw
contact trace, origin traces, wire payloads and finite bounds from which M6
derives service. -/
structure StableScheduleInputs where
  eligible : List ByteArray
  peerMaximum : Nat
  peerDeadline : Nat
  peerRounds : Nat
  contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds
  healthy : ByteArray → Prop
  peer : ByteArray
  peerWidth : ∀ candidate ∈ eligible, candidate.size = 32
  peersWithin : eligible.length ≤ UInt64.size
  peerMaximumPositive : 0 < peerMaximum
  enoughPeerRounds : (Contact.index eligible).toList.length ≤ peerRounds * peerMaximum
  peerMember : peer ∈ eligible
  peerHealthy : healthy peer
  advertisementItems : List OriginSchedule.Item
  advertisementMaximum : Nat
  advertisementDeadline : Nat
  advertisementRounds : Nat
  advertisements : OriginScheduleExecution.Execution .advertisement
    advertisementItems advertisementMaximum advertisementDeadline advertisementRounds
  advertisementLink : OriginScheduleExecution.LinkedToContact contacts peer advertisements
  latest : OriginSchedule.Item → Head
  advertisementPayloads : OriginScheduleExecution.AdvertisementPayloads advertisements latest
  advertisementDistinct : ∀ left ∈ advertisementItems, ∀ right ∈ advertisementItems,
    OriginSchedule.key left.origin = OriginSchedule.key right.origin → left = right
  advertisementsWithin : advertisementItems.length ≤ UInt64.size
  advertisementsFit : ∀ item ∈ advertisementItems,
    item.weight.toNat ≤ advertisementMaximum
  enoughAdvertisementRounds :
    (OriginSchedule.index advertisementItems).toList.length ≤ advertisementRounds
  pendingItems : List OriginSchedule.Item
  pendingMaximum : Nat
  pendingDeadline : Nat
  pendingRounds : Nat
  pending : OriginScheduleExecution.Execution .pendingFetch
    pendingItems pendingMaximum pendingDeadline pendingRounds
  pendingLink : OriginScheduleExecution.LinkedToContact contacts peer pending
  pendingTarget : OriginSchedule.Item → OriginScheduleExecution.Target
  pendingPayloads : OriginScheduleExecution.PendingPayloads pending pendingTarget
  pendingDistinct : ∀ left ∈ pendingItems, ∀ right ∈ pendingItems,
    OriginSchedule.key left.origin = OriginSchedule.key right.origin → left = right
  pendingWithin : pendingItems.length ≤ UInt64.size
  pendingFit : ∀ item ∈ pendingItems, item.weight.toNat ≤ pendingMaximum
  enoughPendingRounds : (OriginSchedule.index pendingItems).toList.length ≤ pendingRounds

/-- The raw scheduler inputs themselves entail delivery of every latest
advertisement. Goal modules may package this fact, but operation composition
depends only on this reusable execution theorem. -/
theorem StableScheduleInputs.latestDelivered
    (inputs : StableScheduleInputs) :
    OriginScheduleExecution.LatestDeliveredOnUsableContact
      inputs.contacts inputs.peer inputs.advertisements inputs.advertisementLink inputs.latest :=
  OriginScheduleExecution.every_latest_is_delivered inputs.contacts inputs.peer
    inputs.advertisements inputs.advertisementLink inputs.latest inputs.advertisementPayloads
    inputs.advertisementDistinct inputs.advertisementsWithin inputs.advertisementsFit
    inputs.enoughAdvertisementRounds

end Synchronicity.MptsyncScheduleExecution
