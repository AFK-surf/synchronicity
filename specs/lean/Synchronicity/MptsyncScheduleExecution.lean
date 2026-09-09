import Synchronicity.OriginQueueSource

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
  advertisementSource : OriginQueueSource.BulkHeadSnapshot
  advertisementMaximum : Nat
  advertisementDeadline : Nat
  advertisementRounds : Nat
  advertisements : OriginScheduleExecution.Execution .advertisement
    advertisementSource.advertisementItems advertisementMaximum advertisementDeadline
      advertisementRounds
  advertisementLink : OriginScheduleExecution.LinkedToContact contacts peer advertisements
  advertisementPayloads : OriginScheduleExecution.AdvertisementPayloads advertisements
    advertisementSource.sentHeads
  advertisementsWithin : advertisementSource.advertisementItems.length ≤ UInt64.size
  advertisementsFit : ∀ item ∈ advertisementSource.advertisementItems,
    item.weight.toNat ≤ advertisementMaximum
  enoughAdvertisementRounds :
    (OriginSchedule.index advertisementSource.advertisementItems).toList.length ≤
      advertisementRounds
  pendingSource : OriginQueueSource.BulkHeadSnapshot
  pendingMaximum : Nat
  pendingDeadline : Nat
  pendingRounds : Nat
  pending : OriginScheduleExecution.Execution .pendingFetch
    pendingSource.pendingItems pendingMaximum pendingDeadline pendingRounds
  pendingLink : OriginScheduleExecution.LinkedToContact contacts peer pending
  pendingPayloads : OriginScheduleExecution.PendingPayloads pending pendingSource.pendingTarget
  pendingWithin : pendingSource.pendingItems.length ≤ UInt64.size
  pendingFit : ∀ item ∈ pendingSource.pendingItems, item.weight.toNat ≤ pendingMaximum
  enoughPendingRounds :
    (OriginSchedule.index pendingSource.pendingItems).toList.length ≤ pendingRounds

abbrev StableScheduleInputs.advertisementItems (inputs : StableScheduleInputs) :=
  inputs.advertisementSource.advertisementItems

theorem StableScheduleInputs.advertisementDistinct (inputs : StableScheduleInputs) :
    ∀ left ∈ inputs.advertisementItems, ∀ right ∈ inputs.advertisementItems,
      OriginSchedule.key left.origin = OriginSchedule.key right.origin → left = right :=
  inputs.advertisementSource.advertisementDistinct

abbrev StableScheduleInputs.pendingItems (inputs : StableScheduleInputs) :=
  inputs.pendingSource.pendingItems

abbrev StableScheduleInputs.pendingTarget (inputs : StableScheduleInputs) :=
  inputs.pendingSource.pendingTarget

theorem StableScheduleInputs.pendingDistinct (inputs : StableScheduleInputs) :
    ∀ left ∈ inputs.pendingItems, ∀ right ∈ inputs.pendingItems,
      OriginSchedule.key left.origin = OriginSchedule.key right.origin → left = right :=
  inputs.pendingSource.pendingDistinct

/-- The raw scheduler inputs themselves entail delivery of every signed head
that the same native Hello construction marked servable. -/
theorem StableScheduleInputs.sentHeadsDelivered
    (inputs : StableScheduleInputs) :
    OriginScheduleExecution.SentHeadsDeliveredOnUsableContact
      inputs.contacts inputs.peer inputs.advertisements inputs.advertisementLink
        inputs.advertisementSource.sentHeads :=
  OriginScheduleExecution.every_sent_head_is_delivered inputs.contacts inputs.peer
    inputs.advertisements inputs.advertisementLink inputs.advertisementSource.sentHeads
      inputs.advertisementPayloads
    inputs.advertisementDistinct inputs.advertisementsWithin inputs.advertisementsFit
    inputs.enoughAdvertisementRounds

end Synchronicity.MptsyncScheduleExecution
