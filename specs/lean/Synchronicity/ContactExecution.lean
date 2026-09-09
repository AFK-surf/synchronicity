import Synchronicity.ContactProofs

/-! Execution observations for completed production contact rounds.

The asynchronous runtime remains outside Lean.  Its narrow contract is made
explicit here: every position returned by the production `Contact.plan` gets
one terminating attempt within the per-peer deadline, and only after those
attempts does a completed round persist the planner's cursor.  Outcomes are
unrestricted; in particular, failure and timeout are ordinary observations and
do not imply successful exchange, Fetch progress, or promotion.
-/
namespace Synchronicity.ContactExecution
open VerifiedCore.Replication.Contact

/-- Every terminal result the runtime records for a planned peer attempt. -/
inductive AttemptOutcome where
  | success
  | failure
  | timeout
  deriving BEq, DecidableEq

/-- One returned runtime attempt.  Time is an abstract duration in the same
unit as the supplied deadline; no success meaning is attached to it. -/
structure Attempt where
  peer : ByteArray
  outcome : AttemptOutcome
  elapsed : Nat

/-- The observable order inside a completed round. -/
inductive RoundEvent where
  | attempted (attempt : Attempt)
  | cursorPersisted (cursor : Option ByteArray)

structure RoundObservation where
  attempts : List Attempt
  events : List RoundEvent

/-- Resolve actual planner positions through the eligible input, just as the
native adapter does.  A malformed position is absent rather than invented. -/
def selectedPeers (eligible : List ByteArray) (result : ContactPlan) : List ByteArray :=
  result.positions.filterMap fun position => eligible[position.toNat]?

/-- A completed round is a factual observation of the actual planner.  The
cursor-persistence event is last, after every planned attempt has returned. -/
structure CompletedRound (eligible : List ByteArray) (maximum deadline : Nat)
    (before after : Option ByteArray) (observation : RoundObservation) : Prop where
  attemptsMatch : observation.attempts.map Attempt.peer =
    selectedPeers eligible (plan eligible before maximum)
  withinDeadline : ∀ attempt ∈ observation.attempts, attempt.elapsed ≤ deadline
  eventsMatch : observation.events =
    observation.attempts.map RoundEvent.attempted ++
      [.cursorPersisted (plan eligible before maximum).cursor]
  afterCursor : after = (plan eligible before maximum).cursor

/-- Linked completed rounds over one fixed eligible set.  Cancellation before
completion produces no member of this relation and therefore persists no next
cursor. -/
structure Execution (eligible : List ByteArray) (maximum deadline rounds : Nat) where
  cursor : Nat → Option ByteArray
  observation : Nat → RoundObservation
  completed : ∀ round, round < rounds →
    CompletedRound eligible maximum deadline (cursor round) (cursor (round + 1))
      (observation round)

/-- A selected peer has a corresponding actual attempt in its completed round. -/
theorem selected_peer_was_attempted (execution : Execution eligible maximum deadline rounds)
    (before : round < rounds) (position : UInt64)
    (selected : position ∈ (plan eligible (execution.cursor round) maximum).positions)
    (source : eligible[position.toNat]? = some peer) :
    ∃ attempt ∈ (execution.observation round).attempts, attempt.peer = peer := by
  have peerSelected : peer ∈ selectedPeers eligible
      (plan eligible (execution.cursor round) maximum) := by
    apply List.mem_filterMap.mpr
    exact ⟨position, selected, source⟩
  have peerAttempted : peer ∈ (execution.observation round).attempts.map Attempt.peer := by
    rw [(execution.completed round before).attemptsMatch]
    exact peerSelected
  obtain ⟨attempt, member, same⟩ := List.mem_map.mp peerAttempted
  exact ⟨attempt, member, same⟩

/-- Healthy peers are distinguished only when stating which attempts callers
care about.  Neither health nor another peer's outcome is used to manufacture
an attempt. -/
def HealthyPeersAttempted (healthy : ByteArray → Prop)
    (execution : Execution eligible maximum deadline rounds) : Prop :=
  ∀ peer ∈ eligible, healthy peer →
    ∃ round < rounds, ∃ attempt ∈ (execution.observation round).attempts,
      attempt.peer = peer

/-- With a fixed eligible set, enough completed production rounds attempt every
healthy peer.  Arbitrary failures and timeouts of peers earlier in a batch do
not block this conclusion; only completed cursor transitions are used. -/
theorem healthy_peers_receive_bounded_attempts
    (execution : Execution eligible maximum deadline rounds)
    (width : ∀ peer ∈ eligible, peer.size = 32)
    (within : eligible.length ≤ UInt64.size)
    (positive : 0 < maximum)
    (enough : (index eligible).toList.length ≤ rounds * maximum)
    (healthy : ByteArray → Prop) :
    HealthyPeersAttempted healthy execution := by
  intro peer member _
  have cursorSteps : ∀ round < rounds,
      execution.cursor (round + 1) =
        (plan eligible (execution.cursor round) maximum).cursor := by
    intro round before
    exact (execution.completed round before).afterCursor
  obtain ⟨round, before, position, selected, source⟩ :=
    ContactProofs.native_plans_give_every_peer_a_bounded_turn eligible width within member
      maximum rounds positive execution.cursor enough cursorSteps
  obtain ⟨attempt, attempted, same⟩ :=
    selected_peer_was_attempted execution before position selected source
  exact ⟨round, before, attempt, attempted, same⟩

end Synchronicity.ContactExecution
