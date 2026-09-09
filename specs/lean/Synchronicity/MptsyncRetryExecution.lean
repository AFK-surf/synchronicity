import Synchronicity.AuthorizedFetchProgress
import Synchronicity.TrieFetchSuspensionProofs
import Synchronicity.ReconciliationExecution
import Synchronicity.OriginScheduleExecution

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

/-- The saved production continuation is actually resumed after cancellation
cleanup, with one concrete reply and a finite execution prefix. -/
structure ResumedContinuation
    (request : CancelledRequest target reference maximum retryLimit initial suspended) where
  reply : request.A
  rest : Program Trie.Fetch.Effects (Except Trie.Fetch.Error Bool)
  final : SimulatedHost.State
  ran : Prefix (request.resume reply) request.cancelled rest final

/-- A retry-limit/cancellation can instead discard the old continuation and
start the production requester afresh for the same captured target. -/
structure RestartedRequest
    (request : CancelledRequest target reference maximum retryLimit initial suspended) where
  nextReference : Option ByteArray
  continuation : Program Trie.Fetch.Effects (Except Trie.Fetch.Error Bool)
  final : SimulatedHost.State
  ran : Prefix (Trie.Fetch.fetch (Std.HashSet Missing.Visit) (Std.HashSet ByteArray)
    target nextReference maximum retryLimit).run request.cancelled continuation final

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
      (resumed : ResumedContinuation request) :
      RetryCheckpoint requirements before request.cancelled
  | restartedCancellation
      (request : CancelledRequest target reference maximum retryLimit initial before)
      (restarted : RestartedRequest request) :
      RetryCheckpoint requirements before request.cancelled

theorem RetryCheckpoint.persistent
    (step : RetryCheckpoint requirements before after) :
    EvidenceIncluded (replicaOfState before) (replicaOfState after) := by
  cases step with
  | admitted admission => exact admission.included
  | resumedCancellation request resumed => exact cancellation_preserves_evidence request
  | restartedCancellation request restarted => exact cancellation_preserves_evidence request

/-- A linked finite-or-infinite observation trace of actual committed
admissions and actual cancelled/resumed requester prefixes. -/
structure RetryExecution
    (requirements : FiniteRequirements publisher scope owner root) where
  state : Nat → SimulatedHost.State
  step : ∀ now, RetryCheckpoint requirements (state now) (state (now + 1))

theorem RetryExecution.persistentEvidence
    (execution : RetryExecution requirements) :
    TrieFetchConvergence.PersistentEvidence (replicaOfState ∘ execution.state) := by
  intro now
  exact (execution.step now).persistent

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
    exact ih.trans (execution.step (start + span)).persistent

theorem RetryExecution.carried (execution : RetryExecution requirements) (finish : Nat) :
    EvidenceIncluded (replicaOfState (execution.state 0))
      (replicaOfState (execution.state finish)) := by
  simpa using execution.carriedFrom 0 finish

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
