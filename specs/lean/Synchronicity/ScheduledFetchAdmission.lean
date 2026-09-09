import Synchronicity.AuthorizedFetchProgress
import Synchronicity.OriginScheduleExecution
import Synchronicity.MptsyncScheduleExecution
import Synchronicity.MptsyncRetryExecution

/-! The production origin scheduler records only wire-level Fetch opportunity
metadata.  This module states the additional, explicit bridge needed to relate
one such attempt to the receiver's actual authority-checked `Fetch.admit`
execution.  In particular, the Boolean observation flags do not manufacture
authority, bytes, hashes, or a successful admission. -/
namespace Synchronicity.ScheduledFetchAdmission
open VerifiedCore VerifiedCore.Trie VerifiedCore.Replication
open SimulatedHost TrieFetchCompletion TrieFetchAdmissionProgress AuthorizedFetchProgress

/-- The concrete requester target used by `Fetch.admit` names the same
origin/version as the scheduler's pending target and the same semantic
scope/owner/root as the finite requirement set. -/
def TargetAligned (scheduled : OriginScheduleExecution.Target)
    (actual : Fetch.Target) (scope : Serve.Scope) (owner : Option String)
    (root : ByteArray) : Prop :=
  actual.origin = scheduled.origin ∧
  actual.seq = scheduled.pointer.seq ∧
  actual.root = scheduled.pointer.root ∧
  actual.root = root ∧
  actual.context.scope = scope ∧
  actual.context.owner = owner

/-- Target-indexed form of `AuthorizedFetchProgress.Admission`. The index keeps
the production `Fetch.admit` target visible instead of trying to recover it
from a proof-irrelevant admission witness. All authority, response bytes,
digest, storage, and freshness premises remain those of the ordinary
admission constructors. -/
inductive AdmissionFor (target : Fetch.Target) :
    {publisher : TrieProgramProofs.RawSnapshot} → {scope : Serve.Scope} →
    {owner : Option String} → {root : ByteArray} →
    FiniteRequirements publisher scope owner root → State → State → Prop where
  | node
      {publisher : TrieProgramProofs.RawSnapshot} {root path hash raw : ByteArray}
      {origin : String} {serverInitial : State} {peerKey : ByteArray}
      {publisherOrigin : Origin.Parsed} {reading : Int64}
      (authority : TrieServeEvidence.ServingAuthority serverInitial peerKey publisherOrigin reading)
      (response : TrieServeEvidence.UsableResponse publisher (some origin) root authority path
        (.node hash raw))
      (requirements : FiniteRequirements publisher authority.scope (some origin) root)
      (decodedNode : Node) (receiver : State)
      (quiet : receiver.faults = []) (idle : receiver.pending = none)
      (targetOwner : target.context.owner = some origin)
      (decoded : Trie.admit raw = .ok decodedNode)
      (valid : receiver.hash (tagOf decodedNode ++ raw) = hash)
      (nodesBackend : receiver.byteRelations.contains nodeSpace = true)
      (valuesBackend : receiver.byteRelations.contains valueSpace = true)
      (freshNode : relationBytes receiver.db nodeSpace hash = .ok none)
      (freshOwner : (rows receiver.db "trie_node_origins").any
        (conflict ["origin_id", "hash"]
          [("origin_id", .text origin), ("hash", .blob hash)]) = false)
      (outstanding : ¬ Verified (replicaOfState receiver) (.node hash raw) ∨
        ¬ Verified (replicaOfState receiver) (.provenance origin hash)) :
      AdmissionFor target requirements receiver
        (SimulatedHost.run (Fetch.admit (H := Std.HashSet ByteArray) target false
          [(path, hash)] [(hash, raw)]) receiver).2
  | value
      {publisher : TrieProgramProofs.RawSnapshot} {root path hash bytes : ByteArray}
      {owner : Option String} {serverInitial : State} {peerKey : ByteArray}
      {publisherOrigin : Origin.Parsed} {reading : Int64}
      (authority : TrieServeEvidence.ServingAuthority serverInitial peerKey publisherOrigin reading)
      (response : TrieServeEvidence.UsableResponse publisher owner root authority path
        (.value hash bytes))
      (requirements : FiniteRequirements publisher authority.scope owner root)
      (receiver : State) (quiet : receiver.faults = []) (idle : receiver.pending = none)
      (valid : receiver.hash bytes = hash)
      (large : inlineValueMax < bytes.size) (bounded : bytes.size ≤ maxValueBytes)
      (nodesBackend : receiver.byteRelations.contains nodeSpace = true)
      (valuesBackend : receiver.byteRelations.contains valueSpace = true)
      (fresh : relationBytes receiver.db valueSpace hash = .ok none)
      (outstanding : ¬ Verified (replicaOfState receiver) (.value hash bytes)) :
      AdmissionFor target requirements receiver
        (SimulatedHost.run (Fetch.admit (H := Std.HashSet ByteArray) target true
          [(path, hash)] [(hash, bytes)]) receiver).2

theorem AdmissionFor.admission
    (admission : AdmissionFor target requirements before after) :
    Admission requirements before after := by
  refine AdmissionFor.rec (motive := fun {_ _ _} requirements before after _ =>
    Admission requirements before after) ?_ ?_ admission
  · intro root path hash raw origin serverInitial peerKey publisherOrigin reading
      authority response requirements decodedNode receiver quiet idle targetOwner decoded
      valid nodesBackend valuesBackend freshNode freshOwner outstanding
    exact .node authority response requirements target decodedNode receiver quiet idle targetOwner
      decoded valid nodesBackend valuesBackend freshNode freshOwner outstanding
  · intro root path hash bytes owner serverInitial peerKey publisherOrigin reading
      authority response requirements receiver quiet idle valid large bounded nodesBackend
      valuesBackend fresh outstanding
    exact .value authority response requirements target receiver quiet idle valid large bounded
      nodesBackend valuesBackend fresh outstanding

/-- One exact pending-origin attempt on a usable contact is tied to one actual
admission over the stated before/after receiver states. The final existential
is the deliberately explicit runtime bridge: it supplies the real Fetch target
and the independently proved `Admission`, including all authority and byte
contracts in that proof. -/
def ScheduledAdmission
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : OriginScheduleExecution.Execution .pendingFetch
      items maximum deadline rounds)
    (link : OriginScheduleExecution.LinkedToContact contacts peer origins)
    (targetOf : OriginSchedule.Item → OriginScheduleExecution.Target)
    (item : OriginSchedule.Item)
    (requirements : FiniteRequirements publisher scope owner root)
    (before after : State) : Prop :=
  item ∈ items ∧ ∃ round, round < rounds ∧
    ∃ attempt ∈ (origins.observation round).attempts,
      attempt.item = item ∧
      OriginScheduleExecution.FetchOpportunity (targetOf item) attempt ∧
      link.contactRound round < peerRounds ∧
      ∃ peerAttempt ∈ (contacts.observation (link.contactRound round)).attempts,
        peerAttempt.peer = peer ∧ peerAttempt.outcome = .success ∧
        ∃ actualTarget, TargetAligned (targetOf item) actualTarget scope owner root ∧
          AdmissionFor actualTarget requirements before after

/-- M6's raw opportunity supplies the exact scheduled attempt. The bridge is
required for that very witness and for the same receiver before/after states. -/
theorem of_pending_opportunity
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : OriginScheduleExecution.Execution .pendingFetch
      items maximum deadline rounds)
    (link : OriginScheduleExecution.LinkedToContact contacts peer origins)
    (targetOf : OriginSchedule.Item → OriginScheduleExecution.Target)
    (item : OriginSchedule.Item) (member : item ∈ items)
    (opportunities : OriginScheduleExecution.PendingFetchOpportunities
      contacts peer origins link targetOf)
    (requirements : FiniteRequirements publisher scope owner root)
    (before after : State)
    (bridge : ∀ round attempt,
      round < rounds → attempt ∈ (origins.observation round).attempts →
      attempt.item = item →
      OriginScheduleExecution.FetchOpportunity (targetOf item) attempt →
      ∃ actualTarget, TargetAligned (targetOf item) actualTarget scope owner root ∧
        AdmissionFor actualTarget requirements before after) :
    ScheduledAdmission contacts peer origins link targetOf item requirements before after := by
  obtain ⟨round, within, attempt, attempted, same, opportunity, contactWithin,
    peerAttempt, peerAttempted, samePeer, success⟩ := opportunities item member
  obtain ⟨actualTarget, aligned, admission⟩ :=
    bridge round attempt within attempted same opportunity
  exact ⟨member, round, within, attempt, attempted, same, opportunity, contactWithin,
    peerAttempt, peerAttempted, samePeer, success, actualTarget, aligned, admission⟩

theorem ScheduledAdmission.admission
    {peer : ByteArray}
    {link : OriginScheduleExecution.LinkedToContact contacts peer origins}
    (scheduled : ScheduledAdmission contacts peer origins link targetOf item
      requirements before after) :
    Admission requirements before after := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, admission⟩ := scheduled
  exact admission.admission

/-- Alignment all the way to the stable public target. This prevents an
admission for a different sequence or origin that happens to share a
requirement root from discharging the scheduled liveness premise. -/
def FinalTargetAligned (scheduled : OriginScheduleExecution.Target)
    (actual : Fetch.Target) (finalOrigin : String) (finalSeq : UInt64)
    (finalRoot : ByteArray) (scope : Serve.Scope) (owner : Option String)
    (root : ByteArray) : Prop :=
  scheduled.origin = finalOrigin ∧
  scheduled.pointer.seq = finalSeq ∧
  scheduled.pointer.root = finalRoot ∧
  TargetAligned scheduled actual scope owner root

/-- The pending opportunity derivable from the raw stable schedule inputs.
This is the pending projection proved by M6, kept here at the operation layer
so this shared module does not depend on a goal module. -/
theorem pendingFetchOpportunities
    (inputs : MptsyncScheduleExecution.StableScheduleInputs) :
    OriginScheduleExecution.PendingFetchOpportunities inputs.contacts inputs.peer
      inputs.pending inputs.pendingLink inputs.pendingTarget := by
  exact OriginScheduleExecution.every_pending_has_a_fetch_opportunity inputs.contacts
    inputs.peer inputs.pending inputs.pendingLink inputs.pendingTarget inputs.pendingPayloads
    inputs.pendingDistinct inputs.pendingWithin inputs.pendingFit inputs.enoughPendingRounds

/-- One completed production scheduler occurrence. `serial` distinguishes two
runtime occurrences even when their stable queues and observations happen to
be extensionally equal. -/
structure ScheduleOccurrence where
  serial : Nat
  inputs : MptsyncScheduleExecution.StableScheduleInputs

/-- Scheduler observations and receiver states share this production time
axis. `noReuse` prevents one finite occurrence from being moved to arbitrarily
many later indices; equal scheduler inputs may recur only as separately
recorded occurrences. -/
structure ProductionScheduleTimeline (states : Nat → State) where
  occurrenceAt : Nat → Option ScheduleOccurrence
  noReuse : ∀ {left right leftOccurrence rightOccurrence},
    occurrenceAt left = some leftOccurrence →
    occurrenceAt right = some rightOccurrence →
    leftOccurrence.serial = rightOccurrence.serial → left = right

/-- A fresh scheduling window recorded at one reserved progress turn on the
same production timeline. The exact selected attempt is admitted by the exact
retry checkpoint at that turn. -/
structure ResponseWindow (turn : Nat) (finalOrigin : String)
    (finalSeq : UInt64) (finalRoot : ByteArray)
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : MptsyncRetryExecution.RetryExecution requirements)
    (timeline : ProductionScheduleTimeline execution.state) where
  withinRetry : turn < execution.endAt
  occurrence : ScheduleOccurrence
  recorded : timeline.occurrenceAt turn = some occurrence
  item : OriginSchedule.Item
  member : item ∈ occurrence.inputs.pendingItems
  admit : ∀ round attempt,
    round < occurrence.inputs.pendingRounds →
    attempt ∈ (occurrence.inputs.pending.observation round).attempts →
    attempt.item = item →
    OriginScheduleExecution.FetchOpportunity (occurrence.inputs.pendingTarget item) attempt →
    occurrence.inputs.pendingLink.contactRound round < occurrence.inputs.peerRounds →
    ∀ peerAttempt,
      peerAttempt ∈ (occurrence.inputs.contacts.observation
        (occurrence.inputs.pendingLink.contactRound round)).attempts →
      peerAttempt.peer = occurrence.inputs.peer → peerAttempt.outcome = .success →
      ∃ actualTarget,
        FinalTargetAligned (occurrence.inputs.pendingTarget item) actualTarget
          finalOrigin finalSeq finalRoot scope owner root ∧
        ∃ admission : AdmissionFor actualTarget requirements (execution.state turn)
            (execution.state (turn + 1)),
          execution.step turn withinRetry =
            MptsyncRetryExecution.RetryCheckpoint.admitted admission.admission

/-- The raw schedule and exact-attempt handler in one fresh window identify
the admitted constructor of that same retry turn. -/
theorem ResponseWindow.checkpoint
    (window : ResponseWindow turn finalOrigin finalSeq finalRoot requirements
      execution timeline) :
    MptsyncRetryExecution.AdmissionCheckpoint requirements execution turn := by
  have opportunities := pendingFetchOpportunities window.occurrence.inputs
  obtain ⟨round, before, attempt, attempted, sameItem, opportunity, contactBefore,
      peerAttempt, peerAttempted, samePeer, success⟩ :=
    opportunities window.item window.member
  obtain ⟨actualTarget, aligned, admission, exactStep⟩ :=
    window.admit round attempt before attempted sameItem opportunity contactBefore
      peerAttempt peerAttempted samePeer success
  exact ⟨window.withinRetry, admission.admission, exactStep⟩

/-- An actual retry-limit exit is connected to the next raw pending-origin
schedule window. The abandoned report itself supplies no admission. -/
structure AfterRetryLimitWindow
    {origin : Origin.Parsed}
    (exit : MptsyncRetryExecution.RetryLimitExit origin expected refused
      fetchMaximum retryLimit before after)
    (exitAt turn : Nat) (finalOrigin : String) (finalSeq : UInt64) (finalRoot : ByteArray)
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : MptsyncRetryExecution.RetryExecution requirements)
    (timeline : ProductionScheduleTimeline execution.state) where
  startedAt : Nat
  startedBeforeExit : startedAt < exitAt
  startState : execution.state startedAt = before
  exitState : execution.state exitAt = after
  afterExit : exitAt < turn
  withinRetry : turn < execution.endAt
  occurrence : ScheduleOccurrence
  recorded : timeline.occurrenceAt turn = some occurrence
  item : OriginSchedule.Item
  requeued : MptsyncRetryExecution.RequeuedAfterLimit exit occurrence.inputs.contacts
    occurrence.inputs.peer occurrence.inputs.pending occurrence.inputs.pendingLink
      occurrence.inputs.pendingTarget item
  finalOriginMatchesExit : finalOrigin = Origin.canonical origin
  sequence : (occurrence.inputs.pendingTarget item).pointer.seq = finalSeq
  targetRoot : (occurrence.inputs.pendingTarget item).pointer.root = finalRoot
  admit : ∀ round attempt,
    round < occurrence.inputs.pendingRounds →
    attempt ∈ (occurrence.inputs.pending.observation round).attempts →
    attempt.item = item →
    OriginScheduleExecution.FetchOpportunity (occurrence.inputs.pendingTarget item) attempt →
    occurrence.inputs.pendingLink.contactRound round < occurrence.inputs.peerRounds →
    ∀ peerAttempt,
      peerAttempt ∈ (occurrence.inputs.contacts.observation
        (occurrence.inputs.pendingLink.contactRound round)).attempts →
      peerAttempt.peer = occurrence.inputs.peer → peerAttempt.outcome = .success →
      ∃ actualTarget,
        TargetAligned (occurrence.inputs.pendingTarget item) actualTarget scope owner root ∧
        ∃ admission : AdmissionFor actualTarget requirements (execution.state turn)
            (execution.state (turn + 1)),
          execution.step turn withinRetry =
            MptsyncRetryExecution.RetryCheckpoint.admitted admission.admission

theorem AfterRetryLimitWindow.checkpoint
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {root : ByteArray}
    {requirements : FiniteRequirements publisher scope owner root}
    {execution : MptsyncRetryExecution.RetryExecution requirements}
    {timeline : ProductionScheduleTimeline execution.state}
    (window : AfterRetryLimitWindow exit exitAt turn finalOrigin finalSeq finalRoot
      requirements execution timeline) :
    MptsyncRetryExecution.AdmissionCheckpoint requirements execution turn := by
  -- Consume the opportunity attached to this exact retry-limit requeue rather
  -- than deriving an interchangeable opportunity from the raw inputs again.
  obtain ⟨round, before, attempt, attempted, sameItem, opportunity, contactBefore,
      peerAttempt, peerAttempted, samePeer, success⟩ :=
    window.requeued.opportunities window.item window.requeued.member
  obtain ⟨actualTarget, aligned, admission, exactStep⟩ :=
    window.admit round attempt before attempted sameItem opportunity contactBefore
      peerAttempt peerAttempted samePeer success
  have finalAligned : FinalTargetAligned
      (window.occurrence.inputs.pendingTarget window.item) actualTarget
      finalOrigin finalSeq finalRoot scope owner root := by
    refine ⟨?_, window.sequence, window.targetRoot, aligned⟩
    exact ((window.occurrence.inputs.pendingPayloads.sameOrigin window.item
      window.requeued.member).trans window.requeued.sameOrigin).trans
        window.finalOriginMatchesExit.symm
  exact ⟨window.withinRetry, admission.admission, exactStep⟩

/-- One fresh response source is either an ordinary newly queued raw window,
or the next raw window causally attached to an actual retry-limit exit and
requeue observation. -/
inductive ResponseOpportunity (turn : Nat) (finalOrigin : String)
    (finalSeq : UInt64) (finalRoot : ByteArray)
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : MptsyncRetryExecution.RetryExecution requirements)
    (timeline : ProductionScheduleTimeline execution.state) where
  | fresh (window : ResponseWindow turn finalOrigin finalSeq finalRoot requirements execution
      timeline)
  | afterRetry
      {origin : Origin.Parsed} {expected : Option (UInt64 × ByteArray)}
      {refused : List (UInt64 × ByteArray × ByteArray)} {fetchMaximum retryLimit : Nat}
      {before after : State}
      (exit : MptsyncRetryExecution.RetryLimitExit origin expected refused
        fetchMaximum retryLimit before after)
      (window : AfterRetryLimitWindow exit exitAt turn finalOrigin finalSeq finalRoot
        requirements execution timeline) :
      ResponseOpportunity turn finalOrigin finalSeq finalRoot requirements execution timeline

theorem ResponseOpportunity.checkpoint
    (opportunity : ResponseOpportunity turn finalOrigin finalSeq finalRoot
      requirements execution timeline) :
    MptsyncRetryExecution.AdmissionCheckpoint requirements execution turn := by
  cases opportunity with
  | fresh window => exact window.checkpoint
  | afterRetry exit window => exact window.checkpoint

/-- A finite ordered list of reserved scheduler turns, one per unit of the
initial semantic deficit. Whenever work remains at a reserved turn, the raw
pending scheduler occurrence and handler select the admitted constructor of
that exact retry checkpoint. The structure stores no terminal zero or
completion conclusion. -/
structure BoundedScheduledResponses (finalOrigin : String) (finalSeq : UInt64)
    (finalRoot : ByteArray)
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : MptsyncRetryExecution.RetryExecution requirements)
    (timeline : ProductionScheduleTimeline execution.state) where
  turns : List Nat
  count : turns.length =
    missingEvidence requirements.items (replicaOfState (execution.state 0))
  ordered : turns.Pairwise (fun left right => left < right)
  within : ∀ turn ∈ turns, turn < execution.endAt
  responds : ∀ turn ∈ turns,
    0 < missingEvidence requirements.items (replicaOfState (execution.state turn)) →
      Nonempty (ResponseOpportunity turn finalOrigin finalSeq finalRoot
        requirements execution timeline)

/-- The scheduler payload/handler observations refine the generic bounded
admission contract over the exact same retry states and indices. -/
def BoundedScheduledResponses.boundedResponses
    (scheduled : BoundedScheduledResponses finalOrigin finalSeq finalRoot
      requirements execution timeline) :
    MptsyncRetryExecution.BoundedResponses requirements execution := by
  exact
    { turns := scheduled.turns
      count := scheduled.count
      ordered := scheduled.ordered
      within := scheduled.within
      responds := fun turn member missing =>
        let ⟨opportunity⟩ := scheduled.responds turn member missing
        opportunity.checkpoint }

/-- Finite, timeline-indexed scheduler responses establish completion at the
actual retry boundary without an infinite trace or stationary extension. -/
theorem completeAtEnd
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {root : ByteArray}
    {requirements : FiniteRequirements publisher scope owner root}
    {execution : MptsyncRetryExecution.RetryExecution requirements}
    {timeline : ProductionScheduleTimeline execution.state}
    (scheduled : BoundedScheduledResponses finalOrigin finalSeq finalRoot
      requirements execution timeline) :
    PermittedComplete publisher scope owner root
      (replicaOfState (execution.state execution.endAt)) :=
  scheduled.boundedResponses.completeAtEnd

end Synchronicity.ScheduledFetchAdmission
