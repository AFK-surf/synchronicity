import Synchronicity.AdvertisementSelection
import Synchronicity.MptsyncAdvertisementWindow

/-! # M2 — one Hello operation is insensitive to order and duplication

The goal-level execution below keeps the actual M6 occurrence, its exact wire
payload, the production `Exchange.plan` call over that payload, and the actual
`Reconcile.accept` fold together. Its constructors contain only operation
inputs/results and execution equalities; semantic selection is the conclusion.
-/
namespace Synchronicity.Goals.Mptsync.M2
open VerifiedCore VerifiedCore.Replication
open VerifiedCore.Replication.Exchange
open AdvertisementSelection AcceptanceProgress StableAdvertisementProgress

private def advertised (head : Head) : Advertised :=
  ⟨Origin.canonical head.origin, head.seq, head.root⟩

private def advertisements (heads : List Head) : List Advertised :=
  heads.map advertised

private def sentHeads (attempt : OriginScheduleExecution.Attempt) : List Head :=
  match attempt.payload with
  | .advertisement sent _ => sent
  | _ => []

/-- One actual Hello handling boundary. `planned` invokes production
`Exchange.plan` on the exact sent/received payload of `occurrence`; `accepted`
executes production acceptance on that same received list. `servable` is the
separate native planner input resolved by returned push positions. -/
structure HelloAcceptanceExecution
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (states : Nat → SimulatedHost.State)
    (timeline : MptsyncAdvertisementWindow.AdvertisementTimeline inputs states)
    (origin : Origin.Parsed) (history : StableAuthorizedHistory origin)
    (latest : Head) where
  occurrence : MptsyncAdvertisementWindow.AdvertisementOccurrence inputs
  accepted : MptsyncAdvertisementWindow.AcceptedLatestOnTimeline inputs states timeline
    origin history latest occurrence
  servable : List Head
  result : ExchangePlan
  planned : result = plan (advertisements (sentHeads occurrence.attempt))
    (advertisements (OriginScheduleExecution.receivedHeads occurrence.attempt))
    (advertisements servable)

/-- Two actual Hello operations differ only by ordering/duplication of the
same fixed-width signed heads in each planner input. In particular, the
received lists compared by the planner are exactly those consumed by the two
acceptance folds. -/
structure SameHelloAdvertisements
    (left : HelloAcceptanceExecution leftInputs leftStates leftTimeline origin history latest)
    (right : HelloAcceptanceExecution rightInputs rightStates rightTimeline origin history latest) :
    Prop where
  sent : SameValidSignedAdvertisements
    (sentHeads left.occurrence.attempt) (sentHeads right.occurrence.attempt)
  received : SameValidSignedAdvertisements
    (OriginScheduleExecution.receivedHeads left.occurrence.attempt)
    (OriginScheduleExecution.receivedHeads right.occurrence.attempt)
  servable : SameValidSignedAdvertisements left.servable right.servable
  leftBound : left.servable.length ≤ UInt64.size
  rightBound : right.servable.length ≤ UInt64.size

/-- The single user-visible outcome of a Hello operation: semantic pull/push
choices plus the typed version left by handling its received payload. -/
structure HelloOutcome where
  pulls : Advertised → Prop
  pushes : Advertised → Prop
  selected : Option HeadVersion

private theorem HelloOutcome.equal (left right : HelloOutcome)
    (pulls : left.pulls = right.pulls) (pushes : left.pushes = right.pushes)
    (selected : left.selected = right.selected) : left = right := by
  cases left
  cases right
  simp_all

private def HelloAcceptanceExecution.outcome
    (execution : HelloAcceptanceExecution inputs states timeline origin history latest) :
    HelloOutcome :=
  { pulls := Pulls
      (advertisements (OriginScheduleExecution.receivedHeads execution.occurrence.attempt))
      execution.result
    pushes := Pushes (advertisements execution.servable) execution.result
    selected := selectedVersion execution.accepted.accepted.acceptedView
      (Origin.canonical origin) }

/-- **M2 property.** Two order/duplication variants of one stable Hello history
have one equal operation outcome. This is not a conjunction of an unrelated
planner theorem and an acceptance theorem: both observations come from each
`HelloAcceptanceExecution`'s same occurrence and received payload. -/
def OrderDuplicationInvariant
    (left : HelloAcceptanceExecution leftInputs leftStates leftTimeline origin history latest)
    (right : HelloAcceptanceExecution rightInputs rightStates rightTimeline origin history latest) :
    Prop := left.outcome = right.outcome

private theorem mapped_same_valid (same : SameValidSignedAdvertisements left right) :
    SameValidAdvertisements (advertisements left) (advertisements right) := by
  refine ⟨?_, ?_, ?_⟩
  · intro head member
    obtain ⟨source, sourceMember, rfl⟩ := List.mem_map.mp member
    exact same.leftValid source sourceMember
  · intro head member
    obtain ⟨source, sourceMember, rfl⟩ := List.mem_map.mp member
    exact same.rightValid source sourceMember
  · intro head
    constructor
    · intro member
      obtain ⟨source, sourceMember, rfl⟩ := List.mem_map.mp member
      exact List.mem_map.mpr ⟨source, (same.same source).mp sourceMember, rfl⟩
    · intro member
      obtain ⟨source, sourceMember, rfl⟩ := List.mem_map.mp member
      exact List.mem_map.mpr ⟨source, (same.same source).mpr sourceMember, rfl⟩

/-- **M2.** Reordering or duplicating the exact signed heads carried by a
production Hello changes neither `Exchange.plan`'s semantic choices nor the
selected typed version after actual `Reconcile.accept` handling. The greatest
head is relative to `StableAuthorizedHistory.Valid`, whose witnesses are raw
signature, live-authorization and compatible-history executions and contain no
delivery or selection premise. -/
theorem order_duplication_invariant
    (left : HelloAcceptanceExecution leftInputs leftStates leftTimeline origin history latest)
    (right : HelloAcceptanceExecution rightInputs rightStates rightTimeline origin history latest)
    (same : SameHelloAdvertisements left right) :
    OrderDuplicationInvariant left right := by
  have planSame : Equivalent
      (advertisements (OriginScheduleExecution.receivedHeads left.occurrence.attempt))
      (advertisements (OriginScheduleExecution.receivedHeads right.occurrence.attempt))
      (advertisements left.servable) (advertisements right.servable)
      left.result right.result := by
    rw [left.planned, right.planned]
    exact plans_equivalent (mapped_same_valid same.sent)
      (mapped_same_valid same.received) (mapped_same_valid same.servable)
      (by simpa [advertisements] using same.leftBound)
      (by simpa [advertisements] using same.rightBound)
  have leftSelected := actual_fold_selects_latest
      left.accepted.accepted.delivered left.accepted.accepted.accepted
        left.accepted.accepted.initialBound
  have rightSelected := actual_fold_selects_latest
      right.accepted.accepted.delivered right.accepted.accepted.accepted
        right.accepted.accepted.initialBound
  apply HelloOutcome.equal
  · funext head
    exact propext (planSame.1 head)
  · funext head
    exact propext (planSame.2 head)
  · exact leftSelected.trans rightSelected.symm

end Synchronicity.Goals.Mptsync.M2
