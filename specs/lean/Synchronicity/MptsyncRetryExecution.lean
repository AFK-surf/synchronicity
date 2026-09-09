import Synchronicity.AuthorizedFetchProgress
import Synchronicity.TrieFetchSuspensionProofs
import Synchronicity.ReconciliationExecution
import Synchronicity.OriginScheduleExecution
import Synchronicity.FetchPayloadFrame

/-! Production execution facts used to reason about mptsync retries.  This
module deliberately lives outside `Goals`: cancellation, resumption, fresh
restart, and outer scheduling are reusable observations of actual operations.
-/
namespace Synchronicity.MptsyncRetryExecution
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Replication
open SimulatedHost PrivateDatabase
open TrieFetchCompletion TrieFetchAdmissionProgress AuthorizedFetchProgress

/-- A production requester prefix stopped exactly at a suspending peer
effect. `Prefix` uses replies produced by the actual simulated host, and
`closed` is the runtime side of `fetch_waits_only_between_transactions`. -/
structure CancelledRequest (target : Trie.Fetch.Target) (reference : Option ByteArray)
    (maximum retryLimit : Nat) (initial suspended : SimulatedHost.State) where
  continuation : Program Trie.Fetch.Effects (Except Trie.Fetch.Error Bool)
  A : Type
  effect : Trie.Fetch.Effects A
  resume : A → Program Trie.Fetch.Effects (Except Trie.Fetch.Error Bool)
  reached : Prefix (Trie.Fetch.fetch (Std.HashSet Missing.Visit) (Std.HashSet ByteArray)
    target reference maximum retryLimit).run initial continuation suspended
  waiting : continuation = .request effect resume
  peerWait : TrieFetchSuspensionProofs.guard.suspends effect = true
  closed : suspended.pending = none

def CancelledRequest.cancelled
    (_request : CancelledRequest target reference maximum retryLimit initial suspended) :
    SimulatedHost.State :=
  SimulatedHost.abandon suspended

/-- The saved production continuation is resumed after cancellation cleanup
with one concrete reply.  Its actual execution prefix is stored once, beside
the event decomposition in `RetryCheckpoint`. -/
structure ResumedContinuation
    (request : CancelledRequest target reference maximum retryLimit initial suspended) where
  reply : request.A
  rest : Program Trie.Fetch.Effects (Except Trie.Fetch.Error Bool)
  final : SimulatedHost.State

/-- A retry-limit/cancellation can instead discard the old continuation and
start the production requester afresh for the same captured target.  As for a
resumption, the checkpoint owns the single actual prefix observation. -/
structure RestartedRequest
    (request : CancelledRequest target reference maximum retryLimit initial suspended) where
  nextReference : Option ByteArray
  continuation : Program Trie.Fetch.Effects (Except Trie.Fetch.Error Bool)
  final : SimulatedHost.State

private theorem release_fold_db (leases : List (Transaction × SimulatedHost.ObjectKey))
    (state : SimulatedHost.State) :
    (leases.foldl (fun state (_, key) => SimulatedHost.setCounter state key
      ((SimulatedHost.counter state key).toNat - 1).toUInt64) state).db = state.db := by
  induction leases generalizing state with
  | nil => rfl
  | cons lease rest ih =>
    simp only [List.foldl_cons]
    exact (ih _).trans rfl

private theorem release_fold_files (leases : List (Transaction × SimulatedHost.ObjectKey))
    (state : SimulatedHost.State) :
    (leases.foldl (fun state (_, key) => SimulatedHost.setCounter state key
      ((SimulatedHost.counter state key).toNat - 1).toUInt64) state).files = state.files := by
  induction leases generalizing state with
  | nil => rfl
  | cons lease rest ih =>
    simp only [List.foldl_cons]
    exact (ih _).trans rfl

private theorem release_fold_byteRelations
    (leases : List (Transaction × SimulatedHost.ObjectKey))
    (state : SimulatedHost.State) :
    (leases.foldl (fun state (_, key) => SimulatedHost.setCounter state key
      ((SimulatedHost.counter state key).toNat - 1).toUInt64) state).byteRelations =
        state.byteRelations := by
  induction leases generalizing state with
  | nil => rfl
  | cons lease rest ih =>
    simp only [List.foldl_cons]
    exact (ih _).trans rfl

private theorem abandon_db (state : SimulatedHost.State) :
    (SimulatedHost.abandon state).db = state.db := by
  unfold SimulatedHost.abandon
  exact release_fold_db state.leases state

private theorem abandon_files (state : SimulatedHost.State) :
    (SimulatedHost.abandon state).files = state.files := by
  unfold SimulatedHost.abandon
  exact release_fold_files state.leases state

private theorem abandon_pending (state : SimulatedHost.State) :
    (SimulatedHost.abandon state).pending = none := by
  unfold SimulatedHost.abandon
  rfl

private theorem abandon_byteRelations (state : SimulatedHost.State) :
    (SimulatedHost.abandon state).byteRelations = state.byteRelations := by
  unfold SimulatedHost.abandon
  exact release_fold_byteRelations state.leases state

/-- Cancelling at an actual peer suspension cannot roll back evidence: the
suspension is outside a transaction, and cleanup changes only invocation-owned
resources. -/
theorem cancellation_preserves_replica
    (request : CancelledRequest target reference maximum retryLimit initial suspended) :
    replicaOfState request.cancelled = replicaOfState suspended := by
  change replicaOfState (SimulatedHost.abandon suspended) = replicaOfState suspended
  unfold replicaOfState
  congr 1
  · funext space address
    change readableBytes (SimulatedHost.abandon suspended) space address =
      readableBytes suspended space address
    unfold readableBytes readByteObject
    rw [request.closed, abandon_pending]
    simp only [Option.map_none, Option.getD_none]
    rw [abandon_files, abandon_db, abandon_byteRelations]
  · funext origin address
    rw [abandon_db]

theorem cancellation_preserves_evidence
    (request : CancelledRequest target reference maximum retryLimit initial suspended) :
    EvidenceIncluded (replicaOfState suspended) (replicaOfState request.cancelled) := by
  rw [cancellation_preserves_replica request]
  exact EvidenceIncluded.refl _

theorem cancellation_preserves_heads
    (request : CancelledRequest target reference maximum retryLimit initial suspended) :
    rows request.cancelled.db "heads" = rows suspended.db "heads" := by
  rw [show request.cancelled.db = suspended.db from abandon_db suspended]

/-- An authorized admission changes only evidence tables, never public head
slots.  This is derived from the actual `Fetch.admit` program certificate. -/
theorem admission_preserves_heads
    (admission : Admission requirements before after) :
    rows after.db "heads" = rows before.db "heads" := by
  refine Admission.rec (motive := fun _ before after _ =>
    rows after.db "heads" = rows before.db "heads") ?_ ?_ admission
  · intro root path hash raw origin serverInitial peerKey publisherOrigin reading
      authority response requirements target decodedNode receiver quiet idle targetOwner
      decoded valid nodesBackend valuesBackend freshNode freshOwner outstanding
    have held := (FetchPayloadFrame.admit_only (H := Std.HashSet ByteArray)
      "heads" (by decide) (by decide) (by decide)
      target false [(path, hash)] [(hash, raw)] []).invariant
        (TableInvariant.Holds "heads" (rows receiver.db "heads"))
        (FetchPayloadFrame.effects "heads" (rows receiver.db "heads"))
        { receiver with output := [] }
        (TableInvariant.closed "heads" { receiver with output := [] } (by simpa using idle))
    exact held.1
  · intro root path hash bytes owner serverInitial peerKey publisherOrigin reading
      authority response requirements target receiver quiet idle valid large bounded
      nodesBackend valuesBackend fresh outstanding
    have held := (FetchPayloadFrame.admit_only (H := Std.HashSet ByteArray)
      "heads" (by decide) (by decide) (by decide)
      target true [(path, hash)] [(hash, bytes)] []).invariant
        (TableInvariant.Holds "heads" (rows receiver.db "heads"))
        (FetchPayloadFrame.effects "heads" (rows receiver.db "heads"))
        { receiver with output := [] }
        (TableInvariant.closed "heads" { receiver with output := [] } (by simpa using idle))
    exact held.1

/-- Evidence-relevant classification of one effect in the *same* actual
requester prefix.  Read/wait/rollback effects expose equality of the replica;
a committing effect is tied to an authorized production admission whose final
state is exactly the interpreter successor for this effect. -/
inductive PrefixEvent
    (requirements : FiniteRequirements publisher scope owner root) {A : Type}
    (effect : Trie.Fetch.Effects A) :
    SimulatedHost.State → SimulatedHost.State → Prop where
  | unchanged
      (sameReplica : replicaOfState after = replicaOfState before)
      (sameHeads : rows after.db "heads" = rows before.db "heads") :
      PrefixEvent requirements effect before after
  | admitted (admission : Admission requirements before after) :
      PrefixEvent requirements effect before after

theorem PrefixEvent.persistent
    (event : PrefixEvent requirements effect before after) :
    EvidenceIncluded (replicaOfState before) (replicaOfState after) := by
  cases event with
  | unchanged sameReplica _ =>
      rw [sameReplica]
      exact EvidenceIncluded.refl _
  | admitted admission => exact admission.included

theorem PrefixEvent.preserves_heads
    (event : PrefixEvent requirements effect before after) :
    rows after.db "heads" = rows before.db "heads" := by
  cases event with
  | unchanged _ sameHeads => exact sameHeads
  | admitted admission => exact admission_preserves_heads admission

/-- A decomposition indexed by the actual `Prefix` proof.  Unlike the old
parallel `CommittedFrames` witness, this cannot describe another state chain:
every classified event is definitionally the next interpreter step of `ran`. -/
inductive PrefixEvents
    (requirements : FiniteRequirements publisher scope owner root) :
    {A : Type} → {program tail : Program Trie.Fetch.Effects A} →
    {before after : SimulatedHost.State} →
    Prefix program before tail after → Prop where
  | refl (program : Program Trie.Fetch.Effects A) (state : SimulatedHost.State) :
      PrefixEvents requirements (.refl program state)
  | step {B : Type} {effect : Trie.Fetch.Effects B}
      {resume : B → Program Trie.Fetch.Effects A}
      {state final : SimulatedHost.State} {tail : Program Trie.Fetch.Effects A}
      {rest : Prefix (resume (Interpreter.handle effect state).1)
        (Interpreter.handle effect state).2 tail final}
      (event : PrefixEvent requirements effect state (Interpreter.handle effect state).2)
      (events : PrefixEvents requirements rest) :
      PrefixEvents requirements (.step rest)

theorem PrefixEvents.persistent
    (ran : Prefix program before tail after)
    (events : PrefixEvents requirements ran) :
    EvidenceIncluded (replicaOfState before) (replicaOfState after) := by
  induction events with
  | refl => exact EvidenceIncluded.refl _
  | step event events ih => exact event.persistent.trans ih

theorem PrefixEvents.preserves_heads
    (ran : Prefix program before tail after)
    (events : PrefixEvents requirements ran) :
    rows after.db "heads" = rows before.db "heads" := by
  induction events with
  | refl => rfl
  | step event events ih => exact ih.trans event.preserves_heads

/-- Checkpoints include only committed authorized admissions or cancellation
cleanup at an actual production peer wait. Resumption/restart evidence is
carried by the cancellation constructor, while checkpoints deliberately omit
private transaction states. -/
inductive RetryCheckpoint
    (requirements : FiniteRequirements publisher scope owner root) :
    SimulatedHost.State → SimulatedHost.State → Prop where
  | admitted (admission : Admission requirements before after) :
      RetryCheckpoint requirements before after
  | resumedCancellation
      (request : CancelledRequest target reference maximum retryLimit initial before)
      (resumed : ResumedContinuation request)
      (ran : Prefix (request.resume resumed.reply) request.cancelled
        resumed.rest resumed.final)
      (events : PrefixEvents requirements ran) :
      RetryCheckpoint requirements before resumed.final
  | restartedCancellation
      (request : CancelledRequest target reference maximum retryLimit initial before)
      (restarted : RestartedRequest request)
      (ran : Prefix (Trie.Fetch.fetch (Std.HashSet Missing.Visit) (Std.HashSet ByteArray)
        target restarted.nextReference maximum retryLimit).run request.cancelled
        restarted.continuation restarted.final)
      (events : PrefixEvents requirements ran) :
      RetryCheckpoint requirements before restarted.final

theorem RetryCheckpoint.persistent
    (step : RetryCheckpoint requirements before after) :
    EvidenceIncluded (replicaOfState before) (replicaOfState after) := by
  cases step with
  | admitted admission => exact admission.included
  | resumedCancellation request resumed ran events =>
      exact (cancellation_preserves_evidence request).trans (events.persistent ran)
  | restartedCancellation request restarted ran events =>
      exact (cancellation_preserves_evidence request).trans (events.persistent ran)

theorem RetryCheckpoint.preserves_heads
    (step : RetryCheckpoint requirements before after) :
    rows after.db "heads" = rows before.db "heads" := by
  cases step with
  | admitted admission => exact admission_preserves_heads admission
  | resumedCancellation request resumed ran events =>
      exact (events.preserves_heads ran).trans (cancellation_preserves_heads request)
  | restartedCancellation request restarted ran events =>
      exact (events.preserves_heads ran).trans (cancellation_preserves_heads request)

/-- A finite actual retry prefix.  `state` is extended stationarily after
`endAt` only to reuse the generic liveness measure API; no requester step is
claimed after that boundary, so a following promotion may use the same public
production timeline without also being classified as a retry checkpoint. -/
structure RetryExecution
    (requirements : FiniteRequirements publisher scope owner root) where
  state : Nat → SimulatedHost.State
  endAt : Nat
  step : ∀ now, now < endAt → RetryCheckpoint requirements (state now) (state (now + 1))
  stationary : ∀ now, endAt ≤ now → state now = state endAt

theorem RetryExecution.persistentEvidence
    (execution : RetryExecution requirements) :
    TrieFetchConvergence.PersistentEvidence (replicaOfState ∘ execution.state) := by
  intro now
  by_cases active : now < execution.endAt
  · exact (execution.step now active).persistent
  · have atNow := execution.stationary now (Nat.le_of_not_gt active)
    have atNext := execution.stationary (now + 1)
      (Nat.le_trans (Nat.le_of_not_gt active) (Nat.le_succ now))
    simp only [Function.comp_apply]
    rw [atNow, atNext]
    exact EvidenceIncluded.refl _

/-- Every fact committed at the beginning of a finite retry prefix is still
available at the end. This is the direct `EvidenceIncluded` API consumed by
promotion after retry. -/
theorem RetryExecution.carriedFrom (execution : RetryExecution requirements) (start span : Nat) :
    EvidenceIncluded (replicaOfState (execution.state start))
      (replicaOfState (execution.state (start + span))) := by
  induction span with
  | zero =>
    simpa using EvidenceIncluded.refl (replicaOfState (execution.state start))
  | succ span ih =>
    rw [Nat.add_succ]
    exact ih.trans (execution.persistentEvidence (start + span))

theorem RetryExecution.carried (execution : RetryExecution requirements) (finish : Nat) :
    EvidenceIncluded (replicaOfState (execution.state 0))
      (replicaOfState (execution.state finish)) := by
  simpa using execution.carriedFrom 0 finish

/-- Public complete/pending rows are unchanged throughout any observed part of
the finite retry prefix. -/
theorem RetryExecution.headsFrom (execution : RetryExecution requirements)
    (start span : Nat) (within : start + span ≤ execution.endAt) :
    rows (execution.state (start + span)).db "heads" =
      rows (execution.state start).db "heads" := by
  induction span with
  | zero => rfl
  | succ span ih =>
    rw [Nat.add_succ]
    exact (execution.step (start + span) (Nat.lt_of_succ_le within)).preserves_heads.trans
      (ih (Nat.le_trans (Nat.le_succ (start + span)) within))

theorem RetryExecution.headsAtEnd (execution : RetryExecution requirements) :
    rows (execution.state execution.endAt).db "heads" =
      rows (execution.state 0).db "heads" := by
  simpa using execution.headsFrom 0 execution.endAt (by simp)

/-- An actual bounded replication fetch returned its `abandoned` report.  In
production this report is emitted only after the inner trie requester returns
`false`, i.e. after reaching its unproductive retry limit. -/
structure RetryLimitExit (origin : Origin.Parsed)
    (expected : Option (UInt64 × ByteArray))
    (refused : List (UInt64 × ByteArray × ByteArray))
    (maximum retryLimit : Nat) (before after : SimulatedHost.State) where
  report : Commands.FetchReport
  ran : execute (Replication.Fetch.fetch origin expected refused maximum retryLimit) before =
    (.ok report, after)
  abandoned : report.abandoned = true

/-- Runtime opportunity after the request-level retry limit: an actual
bounded fetch exited, then the outer weighted pending-origin scheduler selected
the same origin on a usable contact and observed an authorized response handed
to admission. This is not inferred from the inner request's Boolean alone. -/
structure RequeuedAfterLimit
    (exit : RetryLimitExit origin expected refused fetchMaximum retryLimit before after)
    (contacts : ContactExecution.Execution eligible peerMaximum peerDeadline peerRounds)
    (peer : ByteArray)
    (origins : OriginScheduleExecution.Execution .pendingFetch
      items maximum deadline rounds)
    (link : OriginScheduleExecution.LinkedToContact contacts peer origins)
    (targetOf : OriginSchedule.Item → OriginScheduleExecution.Target)
    (item : OriginSchedule.Item) : Prop where
  member : item ∈ items
  sameOrigin : item.origin = Origin.canonical origin
  opportunities : OriginScheduleExecution.PendingFetchOpportunities
    contacts peer origins link targetOf

end Synchronicity.MptsyncRetryExecution
