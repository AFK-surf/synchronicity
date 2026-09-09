import Synchronicity.AuthorizedFetchProgress
import Synchronicity.TrieFetchSuspensionProofs
import Synchronicity.ReconciliationExecution
import Synchronicity.OriginScheduleExecution
import Synchronicity.FetchPayloadFrame
import Synchronicity.AcceptanceProgress

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

theorem cancellation_preserves_history
    (request : CancelledRequest target reference maximum retryLimit initial suspended) :
    rows request.cancelled.db "head_history" = rows suspended.db "head_history" := by
  rw [show request.cancelled.db = suspended.db from abandon_db suspended]

theorem cancellation_preserves_entries
    (request : CancelledRequest target reference maximum retryLimit initial suspended) :
    rows request.cancelled.db "entries" = rows suspended.db "entries" := by
  rw [show request.cancelled.db = suspended.db from abandon_db suspended]

/-- An authorized admission preserves any relation distinct from its three
evidence tables. This is derived from the actual `Fetch.admit` certificate. -/
theorem admission_preserves_relation (relation : String)
    (notNodes : Trie.nodeSpace ≠ relation) (notValues : Trie.valueSpace ≠ relation)
    (notOrigins : "trie_node_origins" ≠ relation)
    (admission : Admission requirements before after) :
    rows after.db relation = rows before.db relation := by
  refine Admission.rec (motive := fun _ before after _ =>
    rows after.db relation = rows before.db relation) ?_ ?_ admission
  · intro root path hash raw origin serverInitial peerKey publisherOrigin reading
      authority response requirements target decodedNode receiver quiet idle targetOwner
      decoded valid nodesBackend valuesBackend freshNode freshOwner outstanding
    have held := (FetchPayloadFrame.admit_only (H := Std.HashSet ByteArray)
      relation notNodes notValues notOrigins
      target false [(path, hash)] [(hash, raw)] []).invariant
        (TableInvariant.Holds relation (rows receiver.db relation))
        (FetchPayloadFrame.effects relation (rows receiver.db relation))
        { receiver with output := [] }
        (TableInvariant.closed relation { receiver with output := [] } (by simpa using idle))
    exact held.1
  · intro root path hash bytes owner serverInitial peerKey publisherOrigin reading
      authority response requirements target receiver quiet idle valid large bounded
      nodesBackend valuesBackend fresh outstanding
    have held := (FetchPayloadFrame.admit_only (H := Std.HashSet ByteArray)
      relation notNodes notValues notOrigins
      target true [(path, hash)] [(hash, bytes)] []).invariant
        (TableInvariant.Holds relation (rows receiver.db relation))
        (FetchPayloadFrame.effects relation (rows receiver.db relation))
        { receiver with output := [] }
        (TableInvariant.closed relation { receiver with output := [] } (by simpa using idle))
    exact held.1

theorem admission_preserves_heads
    (admission : Admission requirements before after) :
    rows after.db "heads" = rows before.db "heads" :=
  admission_preserves_relation "heads" (by decide) (by decide) (by decide) admission

theorem admission_preserves_history
    (admission : Admission requirements before after) :
    rows after.db "head_history" = rows before.db "head_history" :=
  admission_preserves_relation "head_history" (by decide) (by decide) (by decide) admission

theorem admission_preserves_entries
    (admission : Admission requirements before after) :
    rows after.db "entries" = rows before.db "entries" :=
  admission_preserves_relation "entries" (by decide) (by decide) (by decide) admission

def headKeys (db : SimulatedHost.Database) : List (List Cell) :=
  (rows db "heads").map HeadKeyFrame.key

theorem cancellation_preserves_headKeys
    (request : CancelledRequest target reference maximum retryLimit initial suspended) :
    headKeys request.cancelled.db = headKeys suspended.db := by
  unfold headKeys
  rw [cancellation_preserves_heads request]

theorem admission_preserves_headKeys
    (admission : Admission requirements before after) :
    headKeys after.db = headKeys before.db := by
  unfold headKeys
  rw [admission_preserves_heads admission]

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
      (sameHeadKeys : headKeys after.db = headKeys before.db)
      (sameHistory : rows after.db "head_history" = rows before.db "head_history")
      (sameEntries : rows after.db "entries" = rows before.db "entries") :
      PrefixEvent requirements effect before after
  | admitted (admission : Admission requirements before after) :
      PrefixEvent requirements effect before after

theorem PrefixEvent.persistent
    (event : PrefixEvent requirements effect before after) :
    EvidenceIncluded (replicaOfState before) (replicaOfState after) := by
  cases event with
  | unchanged sameReplica _ _ _ =>
      rw [sameReplica]
      exact EvidenceIncluded.refl _
  | admitted admission => exact admission.included

theorem PrefixEvent.preserves_headKeys
    (event : PrefixEvent requirements effect before after) :
    headKeys after.db = headKeys before.db := by
  cases event with
  | unchanged _ sameHeadKeys _ _ => exact sameHeadKeys
  | admitted admission => exact admission_preserves_headKeys admission

theorem PrefixEvent.preserves_history
    (event : PrefixEvent requirements effect before after) :
    rows after.db "head_history" = rows before.db "head_history" := by
  cases event with
  | unchanged _ _ sameHistory _ => exact sameHistory
  | admitted admission => exact admission_preserves_history admission

theorem PrefixEvent.preserves_entries
    (event : PrefixEvent requirements effect before after) :
    rows after.db "entries" = rows before.db "entries" := by
  cases event with
  | unchanged _ _ _ sameEntries => exact sameEntries
  | admitted admission => exact admission_preserves_entries admission

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

theorem PrefixEvents.preserves_headKeys
    (ran : Prefix program before tail after)
    (events : PrefixEvents requirements ran) :
    headKeys after.db = headKeys before.db := by
  induction events with
  | refl => rfl
  | step event events ih => exact ih.trans event.preserves_headKeys

theorem PrefixEvents.preserves_history
    (ran : Prefix program before tail after)
    (events : PrefixEvents requirements ran) :
    rows after.db "head_history" = rows before.db "head_history" := by
  induction events with
  | refl => rfl
  | step event events ih => exact ih.trans event.preserves_history

theorem PrefixEvents.preserves_entries
    (ran : Prefix program before tail after)
    (events : PrefixEvents requirements ran) :
    rows after.db "entries" = rows before.db "entries" := by
  induction events with
  | refl => rfl
  | step event events ih => exact ih.trans event.preserves_entries

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

theorem RetryCheckpoint.preserves_headKeys
    (step : RetryCheckpoint requirements before after) :
    headKeys after.db = headKeys before.db := by
  cases step with
  | admitted admission => exact admission_preserves_headKeys admission
  | resumedCancellation request resumed ran events =>
      exact (events.preserves_headKeys ran).trans (cancellation_preserves_headKeys request)
  | restartedCancellation request restarted ran events =>
      exact (events.preserves_headKeys ran).trans (cancellation_preserves_headKeys request)

theorem RetryCheckpoint.preserves_history
    (step : RetryCheckpoint requirements before after) :
    rows after.db "head_history" = rows before.db "head_history" := by
  cases step with
  | admitted admission => exact admission_preserves_history admission
  | resumedCancellation request resumed ran events =>
      exact (events.preserves_history ran).trans (cancellation_preserves_history request)
  | restartedCancellation request restarted ran events =>
      exact (events.preserves_history ran).trans (cancellation_preserves_history request)

theorem RetryCheckpoint.preserves_entries
    (step : RetryCheckpoint requirements before after) :
    rows after.db "entries" = rows before.db "entries" := by
  cases step with
  | admitted admission => exact admission_preserves_entries admission
  | resumedCancellation request resumed ran events =>
      exact (events.preserves_entries ran).trans (cancellation_preserves_entries request)
  | restartedCancellation request restarted ran events =>
      exact (events.preserves_entries ran).trans (cancellation_preserves_entries request)

/-- A finite actual retry prefix.  Every adjacent state before `endAt` is an
observed requester checkpoint; the structure deliberately says nothing about
states after that boundary. -/
structure RetryExecution
    (requirements : FiniteRequirements publisher scope owner root) where
  state : Nat → SimulatedHost.State
  endAt : Nat
  step : ∀ now, now < endAt → RetryCheckpoint requirements (state now) (state (now + 1))

theorem RetryExecution.persistentWithin
    (execution : RetryExecution requirements) (now : Nat) (active : now < execution.endAt) :
    EvidenceIncluded (replicaOfState (execution.state now))
      (replicaOfState (execution.state (now + 1))) :=
  (execution.step now active).persistent

/-- Every fact committed at the beginning of a finite retry prefix is still
available at the end. This is the direct `EvidenceIncluded` API consumed by
promotion after retry. -/
theorem RetryExecution.carriedFrom (execution : RetryExecution requirements) (start span : Nat)
    (within : start + span ≤ execution.endAt) :
    EvidenceIncluded (replicaOfState (execution.state start))
      (replicaOfState (execution.state (start + span))) := by
  induction span with
  | zero =>
    simpa using EvidenceIncluded.refl (replicaOfState (execution.state start))
  | succ span ih =>
    rw [Nat.add_succ]
    have earlier : start + span ≤ execution.endAt :=
      Nat.le_trans (Nat.le_succ (start + span)) (by simpa only [Nat.add_succ] using within)
    have active : start + span < execution.endAt :=
      Nat.lt_of_succ_le (by simpa only [Nat.add_succ] using within)
    exact (ih earlier).trans (execution.persistentWithin (start + span) active)

theorem RetryExecution.carried (execution : RetryExecution requirements) (finish : Nat)
    (within : finish ≤ execution.endAt) :
    EvidenceIncluded (replicaOfState (execution.state 0))
      (replicaOfState (execution.state finish)) := by
  simpa using execution.carriedFrom 0 finish (by simpa using within)

/-- One scheduled response is the admitted constructor of this exact adjacent
checkpoint, not merely another operation with extensionally equal endpoints. -/
structure AdmissionCheckpoint
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : RetryExecution requirements) (now : Nat) : Prop where
  active : now < execution.endAt
  admission : Admission requirements (execution.state now) (execution.state (now + 1))
  exactStep : execution.step now active = RetryCheckpoint.admitted admission

/-- Every positive deficit observed through the finite boundary has a later
actual authorized admission at one adjacent checkpoint of that same finite
retry prefix.  This is a bounded execution contract: it contains neither a
zero measure nor a semantic completion conclusion. `endAt` is the external
finite service-coverage deadline: if a deficit remained there, the contract
would require its later admitted checkpoint to still lie before that deadline. -/
def BoundedResponses
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : RetryExecution requirements) : Prop :=
  ∀ now, now ≤ execution.endAt →
    0 < missingEvidence requirements.items (replicaOfState (execution.state now)) →
    ∃ observed, now < observed ∧ AdmissionCheckpoint requirements execution observed

/-- A finite retry boundary covered by bounded actual response opportunities
cannot retain a positive deficit. -/
theorem BoundedResponses.completeAtEnd
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {root : ByteArray}
    {requirements : FiniteRequirements publisher scope owner root}
    {execution : RetryExecution requirements}
    (responses : BoundedResponses requirements execution) :
    PermittedComplete publisher scope owner root
      (replicaOfState (execution.state execution.endAt)) := by
  apply (finite_measure_eq_zero_iff_complete requirements).mp
  apply Nat.eq_zero_of_not_pos
  intro positive
  obtain ⟨observed, after, checkpoint⟩ :=
    responses execution.endAt (Nat.le_refl _) positive
  exact (Nat.not_lt_of_ge (Nat.le_of_lt after)) checkpoint.active

/-- Public complete/pending rows are unchanged throughout any observed part of
the finite retry prefix. -/
theorem RetryExecution.headKeysFrom (execution : RetryExecution requirements)
    (start span : Nat) (within : start + span ≤ execution.endAt) :
    headKeys (execution.state (start + span)).db =
      headKeys (execution.state start).db := by
  induction span with
  | zero => rfl
  | succ span ih =>
    rw [Nat.add_succ]
    exact (execution.step (start + span) (Nat.lt_of_succ_le within)).preserves_headKeys.trans
      (ih (Nat.le_trans (Nat.le_succ (start + span)) within))

theorem RetryExecution.headKeysAtEnd (execution : RetryExecution requirements) :
    headKeys (execution.state execution.endAt).db =
      headKeys (execution.state 0).db := by
  simpa using execution.headKeysFrom 0 execution.endAt (by simp)

theorem RetryExecution.historyFrom (execution : RetryExecution requirements)
    (start span : Nat) (within : start + span ≤ execution.endAt) :
    rows (execution.state (start + span)).db "head_history" =
      rows (execution.state start).db "head_history" := by
  induction span with
  | zero => rfl
  | succ span ih =>
    rw [Nat.add_succ]
    exact (execution.step (start + span) (Nat.lt_of_succ_le within)).preserves_history.trans
      (ih (Nat.le_trans (Nat.le_succ (start + span)) within))

theorem RetryExecution.historyAtEnd (execution : RetryExecution requirements) :
    rows (execution.state execution.endAt).db "head_history" =
      rows (execution.state 0).db "head_history" := by
  simpa using execution.historyFrom 0 execution.endAt (by simp)

theorem RetryExecution.entriesFrom (execution : RetryExecution requirements)
    (start span : Nat) (within : start + span ≤ execution.endAt) :
    rows (execution.state (start + span)).db "entries" =
      rows (execution.state start).db "entries" := by
  induction span with
  | zero => rfl
  | succ span ih =>
    rw [Nat.add_succ]
    exact (execution.step (start + span) (Nat.lt_of_succ_le within)).preserves_entries.trans
      (ih (Nat.le_trans (Nat.le_succ (start + span)) within))

theorem RetryExecution.entriesAtEnd (execution : RetryExecution requirements) :
    rows (execution.state execution.endAt).db "entries" =
      rows (execution.state 0).db "entries" := by
  simpa using execution.entriesFrom 0 execution.endAt (by simp)

private theorem selected_of_headKeys
    (same : headKeys after = headKeys before)
    (selected : HeadView.Selected before origin slot row) :
    ∃ next, HeadView.Selected after origin slot next ∧
      HeadKeyFrame.key next = HeadKeyFrame.key row := by
  have member : HeadKeyFrame.key row ∈ headKeys before := by
    exact List.mem_map.mpr ⟨row, selected.1, rfl⟩
  rw [← same] at member
  obtain ⟨next, nextMember, keyEq⟩ := List.mem_map.mp member
  refine ⟨next, ⟨nextMember, ?_⟩, keyEq⟩
  exact (HeadView.key_named keyEq).trans selected.2

private theorem represents_of_headKeys
    (same : headKeys after = headKeys before)
    (represented : HeadView.Represents before view) :
    HeadView.Represents after view := by
  intro origin slot
  have prior := represented origin slot
  cases observed : view origin slot with
  | none =>
      simp only [observed] at prior
      simp only
      rintro ⟨row, selected⟩
      obtain ⟨old, oldSelected, _⟩ := selected_of_headKeys same.symm selected
      exact prior ⟨old, oldSelected⟩
  | some version =>
      simp only [observed] at prior
      simp only
      obtain ⟨old, oldSelected⟩ := prior.1
      obtain ⟨next, nextSelected, keyEq⟩ := selected_of_headKeys same oldSelected
      refine ⟨⟨next, nextSelected⟩, ?_⟩
      intro row selected
      obtain ⟨old, oldSelected, oldKey⟩ := selected_of_headKeys same.symm selected
      exact HeadView.key_points oldKey.symm (prior.2 old oldSelected)

private theorem correlated_of_headKey
    (same : HeadKeyFrame.key after = HeadKeyFrame.key before) :
    correlated after history
      [("origin_id", "origin_id"), ("seq", "seq"), ("root", "root")] =
    correlated before history
      [("origin_id", "origin_id"), ("seq", "seq"), ("root", "root")] := by
  obtain ⟨originEq, _, seqEq, rootEq⟩ := HeadView.key_fields same
  simp [correlated, originEq, seqEq, rootEq]

private theorem named_of_headKeys
    (same : headKeys after = headKeys before)
    (member : row ∈ rows before "heads")
    (named : ReconciliationSlots.names row origin slot = true) :
    ∃ next, next ∈ rows after "heads" ∧
      ReconciliationSlots.names next origin slot = true ∧
      HeadKeyFrame.key next = HeadKeyFrame.key row := by
  have keyMember : HeadKeyFrame.key row ∈ headKeys before :=
    List.mem_map.mpr ⟨row, member, rfl⟩
  rw [← same] at keyMember
  obtain ⟨next, nextMember, keyEq⟩ := List.mem_map.mp keyMember
  exact ⟨next, nextMember, (HeadView.key_named keyEq).trans named, keyEq⟩

private theorem storedFloor_of_tables
    (sameHeads : headKeys after = headKeys before)
    (sameHistory : rows after "head_history" = rows before "head_history")
    (stored : ReconciliationRead.StoredFloor before origin slot seq root) :
    ReconciliationRead.StoredFloor after origin slot seq root := by
  refine ⟨?_, ?_⟩
  · obtain ⟨row, member, named, history, historyMember, linked⟩ := stored.backed
    obtain ⟨next, nextMember, nextNamed, keyEq⟩ :=
      named_of_headKeys sameHeads member named
    refine ⟨next, nextMember, nextNamed, history, ?_, ?_⟩
    · rwa [sameHistory]
    · rwa [correlated_of_headKey keyEq]
  · intro row member named
    obtain ⟨old, oldMember, oldNamed, keyEq⟩ :=
      named_of_headKeys sameHeads.symm member named
    have pointer := stored.pointer old oldMember oldNamed
    obtain ⟨_, _, seqEq, rootEq⟩ := HeadView.key_fields keyEq
    exact ⟨seqEq.symm.trans pointer.1, rootEq.symm.trans pointer.2⟩

/-- The actual finite retry prefix transports the complete typed/backed slot
observation from acceptance to the promotion boundary; it does not re-assume
the selected maximum at promotion time. -/
theorem RetryExecution.stableSlotsAtEnd (execution : RetryExecution requirements)
    (stable : AcceptanceProgress.StableSlots (execution.state 0) origin latest view) :
    AcceptanceProgress.StableSlots (execution.state execution.endAt) origin latest view := by
  refine ⟨represents_of_headKeys execution.headKeysAtEnd stable.represents, ?_, stable.valid,
    stable.maximum⟩
  intro selectedOrigin slot version observed
  exact storedFloor_of_tables execution.headKeysAtEnd execution.historyAtEnd
    (stable.backed selectedOrigin slot version observed)

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
