import Synchronicity.AuthorizedFetchProgress
import Synchronicity.OriginScheduleExecution

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

/-- At every remaining semantic deficit, a later admission is backed by an
exact usable scheduled attempt and an explicit target/alignment bridge. -/
def ScheduledSufficientResponses
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : OriginScheduleExecution.Execution .pendingFetch
      items maximum deadline rounds)
    (link : OriginScheduleExecution.LinkedToContact contacts peer origins)
    (targetOf : OriginSchedule.Item → OriginScheduleExecution.Target)
    (item : OriginSchedule.Item)
    (requirements : FiniteRequirements publisher scope owner root)
    (states : Nat → State) : Prop :=
  ∀ now, 0 < missingEvidence requirements.items (replicaOfState (states now)) →
    ∃ later, now < later ∧ ScheduledAdmission contacts peer origins link targetOf item
      requirements (states now) (states later)

/-- Forgetting only the scheduler witness yields the ordinary authorized
response premise used by finite Fetch convergence. -/
theorem sufficientResponses
    {peer : ByteArray}
    {link : OriginScheduleExecution.LinkedToContact contacts peer origins}
    (scheduled : ScheduledSufficientResponses contacts peer origins link targetOf item
      requirements states) :
    SufficientResponses requirements states := by
  intro now missing
  obtain ⟨later, after, admission⟩ := scheduled now missing
  exact ⟨later, after, admission.admission⟩

end Synchronicity.ScheduledFetchAdmission
