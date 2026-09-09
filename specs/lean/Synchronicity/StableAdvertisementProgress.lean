import Synchronicity.AcceptanceProgress
import Synchronicity.MptsyncConvergence

/-! Stable input facts at the boundary between advertisement scheduling and
actual acceptance.  Validity/greatest-version facts describe the publisher
history; membership records that the scheduler really delivered the latest
advertisement.  It is intentionally not implied merely by connectivity. -/
namespace Synchronicity.StableAdvertisementProgress
open VerifiedCore VerifiedCore.Replication
open MptsyncConvergence AcceptanceProgress

/-- One finite stable publisher-history boundary used to interpret "valid" in
the convergence statements. `heads` is the environment's complete publisher
history once versions have stopped changing. Every listed head is certified
against one fixed production host snapshot and retention setting; delivery and
selection are deliberately absent from this structure. -/
structure StableAuthorizedHistory (origin : Origin.Parsed) where
  state : SimulatedHost.State
  keep : Nat
  heads : List Head
  certified : ∀ head ∈ heads,
    head.origin = origin ∧ head.root.size = 32 ∧
      Nonempty (HistoryReady state head keep)

/-- A member of a stable authorized history has the native root width and an
actual successful production signature/authorization/history prefix at the
history's fixed host snapshot. `HistoryReady` contains executions of signature
verification, `liveForKey`, and compatible history recording, but no premise
about the result of `Reconcile.accept`. -/
def StableAuthorizedHistory.Valid (history : StableAuthorizedHistory origin)
    (head : Head) : Prop :=
  head ∈ history.heads ∧ head.origin = origin ∧ head.root.size = 32 ∧
    Nonempty (HistoryReady history.state head history.keep)

theorem StableAuthorizedHistory.valid_of_member
    (history : StableAuthorizedHistory origin) (member : head ∈ history.heads) :
    history.Valid head :=
  ⟨member, history.certified head member⟩

/-- The greatest version in the fixed production-valid history. This says
nothing about which peer has delivered or selected it. -/
def StableAuthorizedHistory.Latest (history : StableAuthorizedHistory origin)
    (latest : Head) : Prop :=
  LatestValid history.Valid origin latest

/-- A finite delivered batch contains the greatest valid signed head, and no
invalid or foreign-origin candidate is smuggled into the acceptance fold. -/
structure DeliveredLatest (history : StableAuthorizedHistory origin)
    (latest : Head) (heads : List Head) : Prop where
  latestValid : history.Latest latest
  latestWidth : latest.root.size = 32
  delivered : latest ∈ heads
  candidates : ∀ head ∈ heads, history.Valid head

theorem DeliveredLatest.rank_bounded
    (stable : DeliveredLatest history latest heads) :
    ∀ head ∈ heads, rank head ≤ rank latest := by
  intro head member
  have candidateValid := stable.candidates head member
  exact rank_le_of_version_order head latest candidateValid.2.2.1 stable.latestWidth
    (stable.latestValid.2.2 head candidateValid.2.1 candidateValid)

/-- Once M6 has really delivered the greatest stable advertisement, an actual
healthy `Reconcile.accept` fold selects that exact typed version in the raw
complete/pending slots. -/
theorem actual_fold_selects_latest
    (stableInput : DeliveredLatest history latest heads)
    (run : ObservedAcceptanceFold (Origin.canonical parsed) keep initial state view stableSlots
      heads final finalState finalView)
    (initialBound : initial ≤ rank latest) :
    selectedVersion finalView (Origin.canonical parsed) =
      some (⟨latest.seq, latest.root⟩ : HeadVersion) :=
  run.selects_delivered_latest initialBound stableInput.delivered
    stableInput.rank_bounded stableInput.latestWidth

end Synchronicity.StableAdvertisementProgress
