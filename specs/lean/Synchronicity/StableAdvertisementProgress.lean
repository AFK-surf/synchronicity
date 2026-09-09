import Synchronicity.AcceptanceProgress
import Synchronicity.MptsyncConvergence

/-! Stable input facts at the boundary between advertisement scheduling and
actual acceptance.  Validity/greatest-version facts describe the publisher
history; membership records that the scheduler really delivered the latest
advertisement.  It is intentionally not implied merely by connectivity. -/
namespace Synchronicity.StableAdvertisementProgress
open VerifiedCore VerifiedCore.Replication
open MptsyncConvergence AcceptanceProgress

/-- A finite delivered batch contains the greatest valid signed head, and no
invalid or foreign-origin candidate is smuggled into the acceptance fold. -/
structure DeliveredLatest (valid : Head → Prop) (origin : Origin.Parsed)
    (latest : Head) (heads : List Head) : Prop where
  latestValid : LatestValid valid origin latest
  latestWidth : latest.root.size = 32
  delivered : latest ∈ heads
  candidates : ∀ head ∈ heads,
    head.origin = origin ∧ valid head ∧ head.root.size = 32

theorem DeliveredLatest.rank_bounded
    (stable : DeliveredLatest valid origin latest heads) :
    ∀ head ∈ heads, rank head ≤ rank latest := by
  intro head member
  obtain ⟨named, accepted, width⟩ := stable.candidates head member
  exact rank_le_of_version_order head latest width stable.latestWidth
    (stable.latestValid.2.2 head named accepted)

/-- Once M6 has really delivered the greatest stable advertisement, an actual
healthy `Reconcile.accept` fold selects that exact typed version in the raw
complete/pending slots. -/
theorem actual_fold_selects_latest
    (stableInput : DeliveredLatest valid parsed latest heads)
    (run : ObservedAcceptanceFold (Origin.canonical parsed) keep initial state view stableSlots
      heads final finalState finalView)
    (initialBound : initial ≤ rank latest) :
    selectedVersion finalView (Origin.canonical parsed) =
      some (⟨latest.seq, latest.root⟩ : HeadVersion) :=
  run.selects_delivered_latest initialBound stableInput.delivered
    stableInput.rank_bounded stableInput.latestWidth

end Synchronicity.StableAdvertisementProgress
