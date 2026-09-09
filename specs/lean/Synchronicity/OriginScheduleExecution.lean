import Synchronicity.ContactExecution
import Synchronicity.OriginScheduleProofs
import VerifiedCore.Replication.History
import VerifiedCore.Replication.Types

/-! Runtime observations for the production weighted origin planner.

The same planner owns two bounded queues: atomic origin groups in an oversized
Hello and pending Fetch origins. A completed round records every selected item
as attempted and persists the returned cursor strictly after those attempts.
Cancellation before completion produces no `CompletedRound`, retaining the old
cursor. Outcomes are deliberately unrestricted.
-/
namespace Synchronicity.OriginScheduleExecution
open VerifiedCore.Replication
open VerifiedCore.Replication.OriginSchedule

inductive Kind where
  | advertisement
  | pendingFetch
  deriving BEq, DecidableEq

inductive AttemptOutcome where
  | success
  | failure
  | timeout
  | unavailable
  deriving BEq, DecidableEq

/-- A concrete signed target named on the wire. -/
structure Target where
  origin : String
  pointer : VerifiedCore.Replication.History.Pointer

/-- The network facts attached to one scheduler attempt. `received` is the
peer's observed Hello payload. A Fetch response is recorded separately from
whether it was authorized and handed to admission; none of these flags claims
that materialization or promotion completed. -/
structure FetchResponse where
  target : Target
  authorized : Bool
  submittedToAdmit : Bool

inductive AttemptPayload where
  | none
  | advertisement (sent received : List VerifiedCore.Replication.Head)
  | pendingFetch (request : Target) (responses : List FetchResponse)

structure Attempt where
  item : Item
  outcome : AttemptOutcome
  elapsed : Nat
  payload : AttemptPayload := .none

inductive RoundEvent where
  | attempted (attempt : Attempt)
  | cursorPersisted (cursor : Option String)

structure RoundObservation where
  attempts : List Attempt
  events : List RoundEvent

/-- Resolve positions through the stable input exactly as the Rust adapter does.
Malformed positions are absent rather than manufacturing an origin. -/
def selectedItems (items : List Item) (result : Plan) : List Item :=
  result.positions.filterMap fun position => items[position.toNat]?

/-- One factual completed batch. Failure, timeout and a peer that cannot serve
the pending target all terminate a turn. The cursor event comes last. -/
structure CompletedRound (kind : Kind) (items : List Item) (maximum deadline : Nat)
    (before after : Option String) (observation : RoundObservation) : Prop where
  attemptsMatch : observation.attempts.map Attempt.item =
    selectedItems items (plan items before maximum)
  withinDeadline : ∀ attempt ∈ observation.attempts, attempt.elapsed ≤ deadline
  eventsMatch : observation.events =
    observation.attempts.map RoundEvent.attempted ++
      [.cursorPersisted (plan items before maximum).cursor]
  afterCursor : after = (plan items before maximum).cursor

/-- Linked completed rounds over one fixed origin set. The kind distinguishes
summary observation from pending Fetch without changing scheduling semantics. -/
structure Execution (kind : Kind) (items : List Item) (maximum deadline rounds : Nat) where
  cursor : Nat → Option String
  observation : Nat → RoundObservation
  completed : ∀ round, round < rounds →
    CompletedRound kind items maximum deadline (cursor round) (cursor (round + 1))
      (observation round)

def ItemsAttempted (execution : Execution kind items maximum deadline rounds) : Prop :=
  ∀ item ∈ items, ∃ round < rounds, ∃ attempt ∈ (execution.observation round).attempts,
    attempt.item = item

theorem selected_item_was_attempted
    (execution : Execution kind items maximum deadline rounds)
    (before : round < rounds) (position : UInt64)
    (selected : position ∈ (plan items (execution.cursor round) maximum).positions)
    (source : items[position.toNat]? = some item) :
    ∃ attempt ∈ (execution.observation round).attempts, attempt.item = item := by
  have itemSelected : item ∈ selectedItems items
      (plan items (execution.cursor round) maximum) := by
    apply List.mem_filterMap.mpr
    exact ⟨position, selected, source⟩
  have itemAttempted : item ∈ (execution.observation round).attempts.map Attempt.item := by
    rw [(execution.completed round before).attemptsMatch]
    exact itemSelected
  obtain ⟨attempt, member, same⟩ := List.mem_map.mp itemAttempted
  exact ⟨attempt, member, same⟩

/-- Stable finite production origin queues cannot starve a later item once
there are enough completed batches. Earlier unavailable, failing or timing-out
items do not appear in the proof premises. -/
theorem every_item_receives_a_bounded_attempt
    (execution : Execution kind items maximum deadline rounds)
    (distinct : ∀ left ∈ items, ∀ right ∈ items,
      key left.origin = key right.origin → left = right)
    (within : items.length ≤ UInt64.size)
    (fits : ∀ item ∈ items, item.weight.toNat ≤ maximum)
    (enough : (index items).toList.length ≤ rounds) :
    ItemsAttempted execution := by
  intro item member
  have cursorSteps : ∀ round < rounds,
      execution.cursor (round + 1) =
        (plan items (execution.cursor round) maximum).cursor := by
    intro round before
    exact (execution.completed round before).afterCursor
  obtain ⟨round, before, position, selected, source⟩ :=
    OriginScheduleProofs.native_plans_give_every_origin_a_bounded_turn
      items distinct within member maximum rounds fits execution.cursor enough cursorSteps
  obtain ⟨attempt, attempted, same⟩ :=
    selected_item_was_attempted execution before position selected source
  exact ⟨round, before, attempt, attempted, same⟩

/-- Origin batches are tied to actual successful contact observations. This is
the explicit external-service seam: it records usable network opportunities,
while the production planner—not the seam—provides fairness among origins. -/
structure LinkedToContact
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : Execution kind items maximum deadline rounds) where
  contactRound : Nat → Nat
  usable : ∀ round, round < rounds →
    contactRound round < peerRounds ∧
      ∃ attempt ∈ (contacts.observation (contactRound round)).attempts,
        attempt.peer = peer ∧ attempt.outcome = .success

def ItemsAttemptedOnUsableContact
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : Execution kind items maximum deadline rounds)
    (link : LinkedToContact contacts peer origins) : Prop :=
  ∀ item ∈ items,
    ∃ round < rounds, ∃ originAttempt ∈ (origins.observation round).attempts,
      originAttempt.item = item ∧
      link.contactRound round < peerRounds ∧
      ∃ peerAttempt ∈ (contacts.observation (link.contactRound round)).attempts,
        peerAttempt.peer = peer ∧ peerAttempt.outcome = .success

def DeliveredLatest (latest : VerifiedCore.Replication.Head) (attempt : Attempt) : Prop :=
  match attempt.payload with
  | .advertisement _ received => latest ∈ received
  | _ => False

def receivedHeads (attempt : Attempt) : List VerifiedCore.Replication.Head :=
  match attempt.payload with
  | .advertisement _ received => received
  | _ => []

theorem DeliveredLatest.member (delivered : DeliveredLatest latest attempt) :
    latest ∈ receivedHeads attempt := by
  cases payload : attempt.payload <;> simp_all [DeliveredLatest, receivedHeads]

def FetchOpportunity (target : Target) (attempt : Attempt) : Prop :=
  match attempt.payload with
  | .pendingFetch request responses =>
      request = target ∧ ∃ response ∈ responses,
        response.target = target ∧ response.authorized = true ∧
          response.submittedToAdmit = true
  | _ => False

/-- The signed heads constructed for one actual planned Hello page. Every
selected atomic origin group contributes only the complete heads which the
same native snapshot marked scoped-servable. -/
def scheduledSentHeads
    (execution : Execution .advertisement items maximum deadline rounds)
    (sentFor : Item → List VerifiedCore.Replication.Head) (round : Nat) :
    List VerifiedCore.Replication.Head :=
  (selectedItems items (plan items (execution.cursor round) maximum)).flatMap sentFor

/-- Runtime payload observations required of a usable Hello attempt. The sent
list is the pure whole-page construction above, not a free per-origin payload;
the trace records only the peer-observed list and its actual containment. -/
structure AdvertisementPayloads
    (execution : Execution .advertisement items maximum deadline rounds)
    (sentFor : Item → List VerifiedCore.Replication.Head) : Prop where
  observed : ∀ round, round < rounds →
    ∀ attempt ∈ (execution.observation round).attempts,
      ∃ received,
        attempt.payload = .advertisement (scheduledSentHeads execution sentFor round) received ∧
        ∀ head ∈ scheduledSentHeads execution sentFor round, head ∈ received

/-- Runtime payload observations required of a usable pending-Fetch attempt.
The response is an actual authorized response handed to admission, not a
premise that admission, materialization or promotion succeeded. -/
structure PendingPayloads
    (execution : Execution .pendingFetch items maximum deadline rounds)
    (target : Item → Target) : Prop where
  sameOrigin : ∀ item ∈ items, (target item).origin = item.origin
  observed : ∀ round, round < rounds →
    ∀ attempt ∈ (execution.observation round).attempts,
      ∃ responses, attempt.payload = .pendingFetch (target attempt.item) responses ∧
        ∃ response ∈ responses,
          response.target = target attempt.item ∧ response.authorized = true ∧
            response.submittedToAdmit = true

def SentHeadsDeliveredOnUsableContact
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : Execution .advertisement items maximum deadline rounds)
    (link : LinkedToContact contacts peer origins)
    (sentFor : Item → List VerifiedCore.Replication.Head) : Prop :=
  ∀ item ∈ items, ∀ head ∈ sentFor item,
    ∃ round < rounds, ∃ attempt ∈ (origins.observation round).attempts,
      attempt.item = item ∧ DeliveredLatest head attempt ∧
      link.contactRound round < peerRounds ∧
      ∃ peerAttempt ∈ (contacts.observation (link.contactRound round)).attempts,
        peerAttempt.peer = peer ∧ peerAttempt.outcome = .success

def PendingFetchOpportunities
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : Execution .pendingFetch items maximum deadline rounds)
    (link : LinkedToContact contacts peer origins) (target : Item → Target) : Prop :=
  ∀ item ∈ items,
    ∃ round < rounds, ∃ attempt ∈ (origins.observation round).attempts,
      attempt.item = item ∧ FetchOpportunity (target item) attempt ∧
      link.contactRound round < peerRounds ∧
      ∃ peerAttempt ∈ (contacts.observation (link.contactRound round)).attempts,
        peerAttempt.peer = peer ∧ peerAttempt.outcome = .success

theorem every_item_is_attempted_on_a_usable_contact
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : Execution kind items maximum deadline rounds)
    (link : LinkedToContact contacts peer origins)
    (distinct : ∀ left ∈ items, ∀ right ∈ items,
      key left.origin = key right.origin → left = right)
    (within : items.length ≤ UInt64.size)
    (fits : ∀ item ∈ items, item.weight.toNat ≤ maximum)
    (enough : (index items).toList.length ≤ rounds) :
    ItemsAttemptedOnUsableContact contacts peer origins link := by
  have fair := every_item_receives_a_bounded_attempt origins distinct within fits enough
  intro item member
  obtain ⟨round, before, originAttempt, attempted, same⟩ := fair item member
  obtain ⟨contactBefore, peerAttempt, peerAttempted, samePeer, success⟩ :=
    link.usable round before
  exact ⟨round, before, originAttempt, attempted, same, contactBefore,
    peerAttempt, peerAttempted, samePeer, success⟩

/-- Bounded scheduling plus the factual Hello payload delivers every actual
servable head attached to the selected item on a successful contact. -/
theorem every_sent_head_is_delivered
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : Execution .advertisement items maximum deadline rounds)
    (link : LinkedToContact contacts peer origins)
    (sentFor : Item → List VerifiedCore.Replication.Head)
    (payloads : AdvertisementPayloads origins sentFor)
    (distinct : ∀ left ∈ items, ∀ right ∈ items,
      key left.origin = key right.origin → left = right)
    (within : items.length ≤ UInt64.size)
    (fits : ∀ item ∈ items, item.weight.toNat ≤ maximum)
    (enough : (index items).toList.length ≤ rounds) :
    SentHeadsDeliveredOnUsableContact contacts peer origins link sentFor := by
  have fair := every_item_is_attempted_on_a_usable_contact contacts peer origins link
    distinct within fits enough
  intro item member head sentMember
  obtain ⟨round, before, attempt, attempted, same, contactBefore,
    peerAttempt, peerAttempted, samePeer, success⟩ := fair item member
  obtain ⟨received, payload, receivedSent⟩ :=
    payloads.observed round before attempt attempted
  have selected : item ∈ selectedItems items
      (plan items (origins.cursor round) maximum) := by
    have mapped : item ∈ (origins.observation round).attempts.map Attempt.item :=
      List.mem_map.mpr ⟨attempt, attempted, same⟩
    rwa [(origins.completed round before).attemptsMatch] at mapped
  have sentItem : head ∈ scheduledSentHeads origins sentFor round := by
    exact List.mem_flatMap.mpr ⟨item, selected, sentMember⟩
  have delivered : DeliveredLatest head attempt := by
    unfold DeliveredLatest
    rw [payload]
    exact receivedSent _ sentItem
  exact ⟨round, before, attempt, attempted, same, delivered, contactBefore,
    peerAttempt, peerAttempted, samePeer, success⟩

/-- Bounded scheduling plus an actual authorized response handed to admission
turns every stable pending target into a Fetch opportunity. -/
theorem every_pending_has_a_fetch_opportunity
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : Execution .pendingFetch items maximum deadline rounds)
    (link : LinkedToContact contacts peer origins)
    (target : Item → Target) (payloads : PendingPayloads origins target)
    (distinct : ∀ left ∈ items, ∀ right ∈ items,
      key left.origin = key right.origin → left = right)
    (within : items.length ≤ UInt64.size)
    (fits : ∀ item ∈ items, item.weight.toNat ≤ maximum)
    (enough : (index items).toList.length ≤ rounds) :
    PendingFetchOpportunities contacts peer origins link target := by
  have fair := every_item_is_attempted_on_a_usable_contact contacts peer origins link
    distinct within fits enough
  intro item member
  obtain ⟨round, before, attempt, attempted, same, contactBefore,
    peerAttempt, peerAttempted, samePeer, success⟩ := fair item member
  obtain ⟨responses, payload, response, responseMember, responseTarget,
    authorized, submitted⟩ := payloads.observed round before attempt attempted
  have opportunity : FetchOpportunity (target item) attempt := by
    unfold FetchOpportunity
    rw [payload]
    constructor
    · exact congrArg target same
    · rw [same] at responseTarget
      exact ⟨response, responseMember, responseTarget, authorized, submitted⟩
  exact ⟨round, before, attempt, attempted, same, opportunity, contactBefore,
    peerAttempt, peerAttempted, samePeer, success⟩

end Synchronicity.OriginScheduleExecution
