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

/-- A fresh scheduling window recorded after one particular deficit
observation on the same production timeline. The exact selected attempt is
admitted from the receiver state at that scheduler occurrence, not from an
arbitrarily old deficit snapshot. -/
structure ResponseWindow (deficitAt : Nat) (finalOrigin : String)
    (finalSeq : UInt64) (finalRoot : ByteArray)
    (requirements : FiniteRequirements publisher scope owner root)
    (states : Nat → State) (timeline : ProductionScheduleTimeline states) where
  observedAt : Nat
  afterDeficit : deficitAt < observedAt
  occurrence : ScheduleOccurrence
  recorded : timeline.occurrenceAt observedAt = some occurrence
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
      ∃ later, observedAt ≤ later ∧
        ∃ actualTarget,
          FinalTargetAligned (occurrence.inputs.pendingTarget item) actualTarget
            finalOrigin finalSeq finalRoot scope owner root ∧
          AdmissionFor actualTarget requirements (states observedAt) (states later)

/-- The raw schedule and exact-attempt handler in one fresh window produce
one later ordinary authorized admission. -/
theorem ResponseWindow.responds
    (window : ResponseWindow deficitAt finalOrigin finalSeq finalRoot requirements states timeline) :
    ∃ observed later, deficitAt < observed ∧ observed ≤ later ∧
      Admission requirements (states observed) (states later) := by
  have opportunities := pendingFetchOpportunities window.occurrence.inputs
  obtain ⟨round, before, attempt, attempted, sameItem, opportunity, contactBefore,
      peerAttempt, peerAttempted, samePeer, success⟩ :=
    opportunities window.item window.member
  obtain ⟨later, afterWindow, actualTarget, aligned, admission⟩ :=
    window.admit round attempt before attempted sameItem opportunity contactBefore
      peerAttempt peerAttempted samePeer success
  exact ⟨window.observedAt, later, window.afterDeficit, afterWindow, admission.admission⟩

/-- An actual retry-limit exit is connected to the next raw pending-origin
schedule window. The abandoned report itself supplies no admission. -/
structure AfterRetryLimitWindow
    {origin : Origin.Parsed}
    (exit : MptsyncRetryExecution.RetryLimitExit origin expected refused
      fetchMaximum retryLimit before after)
    (exitAt : Nat) (finalOrigin : String) (finalSeq : UInt64) (finalRoot : ByteArray)
    (requirements : FiniteRequirements publisher scope owner root)
    (states : Nat → State) (timeline : ProductionScheduleTimeline states) where
  startedAt : Nat
  startedBeforeExit : startedAt < exitAt
  startState : states startedAt = before
  exitState : states exitAt = after
  observedAt : Nat
  afterExit : exitAt < observedAt
  occurrence : ScheduleOccurrence
  recorded : timeline.occurrenceAt observedAt = some occurrence
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
      ∃ later, observedAt ≤ later ∧
        ∃ actualTarget,
          TargetAligned (occurrence.inputs.pendingTarget item) actualTarget scope owner root ∧
          AdmissionFor actualTarget requirements (states observedAt) (states later)

theorem AfterRetryLimitWindow.responds
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {root : ByteArray}
    {requirements : FiniteRequirements publisher scope owner root}
    {states : Nat → State} {timeline : ProductionScheduleTimeline states}
    (window : AfterRetryLimitWindow exit exitAt finalOrigin finalSeq finalRoot
      requirements states timeline) :
    ∃ observed later, exitAt < observed ∧ observed ≤ later ∧
      Admission requirements (states observed) (states later) := by
  -- Consume the opportunity attached to this exact retry-limit requeue rather
  -- than deriving an interchangeable opportunity from the raw inputs again.
  obtain ⟨round, before, attempt, attempted, sameItem, opportunity, contactBefore,
      peerAttempt, peerAttempted, samePeer, success⟩ :=
    window.requeued.opportunities window.item window.requeued.member
  obtain ⟨later, afterWindow, actualTarget, aligned, admission⟩ :=
    window.admit round attempt before attempted sameItem opportunity contactBefore
      peerAttempt peerAttempted samePeer success
  have finalAligned : FinalTargetAligned
      (window.occurrence.inputs.pendingTarget window.item) actualTarget
      finalOrigin finalSeq finalRoot scope owner root := by
    refine ⟨?_, window.sequence, window.targetRoot, aligned⟩
    exact ((window.occurrence.inputs.pendingPayloads.sameOrigin window.item
      window.requeued.member).trans window.requeued.sameOrigin).trans
        window.finalOriginMatchesExit.symm
  exact ⟨window.observedAt, later, window.afterExit, afterWindow, admission.admission⟩

/-- One fresh response source is either an ordinary newly queued raw window,
or the next raw window causally attached to an actual retry-limit exit and
requeue observation. -/
inductive ResponseOpportunity (deficitAt : Nat) (finalOrigin : String)
    (finalSeq : UInt64) (finalRoot : ByteArray)
    (requirements : FiniteRequirements publisher scope owner root)
    (states : Nat → State) (timeline : ProductionScheduleTimeline states) where
  | fresh (window : ResponseWindow deficitAt finalOrigin finalSeq finalRoot requirements states
      timeline)
  | afterRetry
      {origin : Origin.Parsed} {expected : Option (UInt64 × ByteArray)}
      {refused : List (UInt64 × ByteArray × ByteArray)} {fetchMaximum retryLimit : Nat}
      {before after : State}
      (exit : MptsyncRetryExecution.RetryLimitExit origin expected refused
        fetchMaximum retryLimit before after)
      (window : AfterRetryLimitWindow exit deficitAt finalOrigin finalSeq finalRoot
        requirements states timeline) :
      ResponseOpportunity deficitAt finalOrigin finalSeq finalRoot requirements states timeline

theorem ResponseOpportunity.responds
    (opportunity : ResponseOpportunity deficitAt finalOrigin finalSeq finalRoot
      requirements states timeline) :
    ∃ observed later, deficitAt < observed ∧ observed ≤ later ∧
      Admission requirements (states observed) (states later) := by
  cases opportunity with
  | fresh window => exact window.responds
  | afterRetry exit window => exact window.responds

/-- Every deficit observation is followed by its own later raw scheduling
window. A single finite window cannot satisfy all future observations because
each witness carries an `observedAt` strictly after its indexed deficit. -/
def ScheduledSufficientResponses (finalOrigin : String) (finalSeq : UInt64)
    (finalRoot : ByteArray)
    (requirements : FiniteRequirements publisher scope owner root)
    (states : Nat → State) (timeline : ProductionScheduleTimeline states) : Prop :=
  ∀ now, 0 < missingEvidence requirements.items (replicaOfState (states now)) →
    Nonempty (ResponseOpportunity now finalOrigin finalSeq finalRoot requirements states timeline)

private theorem included_between
    (persistent : TrieFetchConvergence.PersistentEvidence (replicaOfState ∘ states))
    (before after : Nat) (ordered : before ≤ after) :
    EvidenceIncluded (replicaOfState (states before)) (replicaOfState (states after)) := by
  obtain ⟨span, rfl⟩ := Nat.exists_eq_add_of_le ordered
  induction span with
  | zero => exact EvidenceIncluded.refl _
  | succ span ih =>
      rw [Nat.add_succ]
      exact (ih (Nat.le_add_right before span)).trans (persistent (before + span))

/-- Per-deficit production-timeline windows and their exact-attempt handlers
discharge the strict progress premise. Persistence bridges the deficit
observation to the later state from which the actual admission runs. -/
theorem productiveAdmissions
    (scheduled : ScheduledSufficientResponses finalOrigin finalSeq finalRoot
      requirements states timeline)
    (persistent : TrieFetchConvergence.PersistentEvidence (replicaOfState ∘ states)) :
    TrieFetchConvergence.ProductiveAdmissions requirements (replicaOfState ∘ states) := by
  intro now missing
  obtain ⟨opportunity⟩ := scheduled now missing
  obtain ⟨observed, later, afterDeficit, afterWindow, admission⟩ := opportunity.responds
  refine ⟨later, Nat.lt_of_lt_of_le afterDeficit afterWindow, ?_⟩
  exact Nat.lt_of_lt_of_le admission.strict
    (missingEvidence_mono requirements.items
      (included_between persistent now observed (Nat.le_of_lt afterDeficit)))

/-- If an actual retry trace is stationary after its finite boundary, the
per-deficit scheduler contract forces that boundary to be complete. A positive
boundary deficit would require a strictly productive admission between two
states that stationarity identifies with the same boundary state. -/
theorem completeAtStationaryBoundary
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {root : ByteArray}
    {requirements : FiniteRequirements publisher scope owner root}
    {states : Nat → State} {timeline : ProductionScheduleTimeline states}
    (scheduled : ScheduledSufficientResponses finalOrigin finalSeq finalRoot
      requirements states timeline)
    (boundary : Nat)
    (stationary : ∀ now, boundary ≤ now → states now = states boundary) :
    PermittedComplete publisher scope owner root (replicaOfState (states boundary)) := by
  apply (TrieFetchCompletion.finite_measure_eq_zero_iff_complete requirements).mp
  apply Nat.eq_zero_of_not_pos
  intro positive
  obtain ⟨opportunity⟩ := scheduled boundary positive
  obtain ⟨observed, later, afterBoundary, afterWindow, admission⟩ := opportunity.responds
  have observedState := stationary observed (Nat.le_of_lt afterBoundary)
  have laterState := stationary later
    (Nat.le_trans (Nat.le_of_lt afterBoundary) afterWindow)
  have strict := admission.strict
  rw [observedState, laterState] at strict
  exact (Nat.lt_irrefl _ strict)

/-- Direct convergence API used by M1 after the timeline-indexed scheduler
bridge replaces the older same-state `SufficientResponses` adapter. -/
theorem scheduledResponsesConverge
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {root : ByteArray}
    {requirements : FiniteRequirements publisher scope owner root}
    {states : Nat → State} {timeline : ProductionScheduleTimeline states}
    (scheduled : ScheduledSufficientResponses finalOrigin finalSeq finalRoot
      requirements states timeline)
    (persistent : TrieFetchConvergence.PersistentEvidence (replicaOfState ∘ states))
    (start : Nat) :
    ∃ finish, start ≤ finish ∧ ∀ now, finish ≤ now →
      PermittedComplete publisher scope owner root (replicaOfState (states now)) := by
  simpa only [Function.comp_apply] using
    TrieFetchConvergence.finite_fetch_converges requirements (replicaOfState ∘ states)
      persistent (productiveAdmissions scheduled persistent) start

end Synchronicity.ScheduledFetchAdmission
