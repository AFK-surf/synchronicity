import Synchronicity.PromotionCommittedView

/-! Positive reachability for the production promotion command.  Existing M4
proofs establish what a reported flip means; this module establishes that a
healthy, complete and authorized execution actually reaches that report. -/
namespace Synchronicity.PromotionProgress
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication
  SimulatedHost PrivateDatabase

/-- Independent successful executions of every readiness/publication phase in
`Promote.body`.  `completeExecution` is the executable content-completeness
check, `permittedExecution` is the actual publication authority/scope walk, and
`materializeExecution` is the production materializer host contract. -/
structure BodyReady (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending : Promote.Pending) (old : Option Promote.Pending)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (state : State) where
  newer : old.any (fun old => !Reconcile.newer pending.head.seq pending.head.root
    ⟨old.head.seq, old.head.root⟩) = false
  checked : State
  authorized : State
  written : State
  cleared : State
  staged : State
  count : UInt64
  completeExecution :
    execute (((Trie.Complete.isComplete (Std.HashSet Trie.Missing.Visit)
      (Std.HashSet ByteArray)
      ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root).run.mapEffects
        (Promote.inTransaction tx)
      |> fun program => Except.mapError Promote.missingError <$> program)) state =
      (.ok true, checked)
  permittedExecution :
    execute (PromotionPublication.permitted tx pending authority) checked =
      (.ok true, authorized)
  writeExecution :
    execute (Promote.history
      (Reconcile.putSlot tx "complete" pending.head pending.received now)) authorized =
      (.ok (), written)
  clearExecution : execute (Promote.clear tx origin) written = (.ok (), cleared)
  materializeExecution :
    execute (Materialize.materialize tx origin
      (old.map (·.head.root) |>.getD Trie.emptyRoot) pending.head.root) cleared =
      (.ok count, staged)

/-- Healthy phase executions force the actual production body to flip. -/
theorem body_executes (ready : BodyReady tx origin now pending old scope authority state) :
    execute (Promote.body tx origin now pending old scope authority) state =
      (.ok .flipped, ready.staged) := by
  have tail : execute ((do
      Promote.history (Reconcile.putSlot tx "complete" pending.head pending.received now)
      Promote.clear tx origin
      let oldRoot := old.map (·.head.root) |>.getD Trie.emptyRoot
      let _ ← within Promote.materializeError
        (Materialize.materialize tx origin oldRoot pending.head.root)
      return .flipped) : Promote.Action Promotion) ready.authorized =
      (.ok .flipped, ready.staged) := by
    simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
    rw [ready.writeExecution]
    dsimp only [ExceptT.bindCont]
    rw [execute_bind, ready.clearExecution]
    dsimp only [ExceptT.bindCont]
    rw [execute_bind]
    have materialized : execute (within Promote.materializeError
        (Materialize.materialize tx origin
          (old.map (·.head.root) |>.getD Trie.emptyRoot) pending.head.root) :
          Promote.Action UInt64) ready.cleared =
        (.ok ready.count, ready.staged) := by
      rw [OperationExecution.within_eq PromotionReads.materialize_agrees,
        ready.materializeExecution]
      rfl
    rw [materialized]
    rfl
  unfold Promote.body
  simp only [ready.newer, Bool.false_eq_true, if_false]
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
  rw [ready.completeExecution]
  dsimp only [ExceptT.bindCont]
  simp only [Bool.not_true, Bool.false_eq_true, if_false]
  have permitted : execute (Promote.permitted tx pending authority) ready.checked =
      (.ok true, ready.authorized) := by
    exact ready.permittedExecution
  rw [execute_bind, permitted]
  dsimp only [ExceptT.bindCont]
  simp only [Bool.not_true, Bool.false_eq_true, if_false]
  exact tail

/-- Full healthy host certificate for one actual `Promote.promote` call.  Raw
begin/commit and the production preparation read are explicit; no premise
mentions a promotion report or assumes that it is flipped. -/
structure Ready (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state : State) where
  tx : Transaction
  opened : State
  prepared : State
  scope : Trie.Serve.Scope
  replicas : List Materialize.Target
  authority : Authorization.OriginAuthority
  pending : Promote.Pending
  old : Option Promote.Pending
  began : execute (Promote.raw .begin) state = (.ok tx, opened)
  preparation : execute (PromotionCommand.prepare tx origin now) opened =
    (.ok (scope, authority, some pending, old), prepared)
  policy : MaterializationInputs.ReadPolicy state.db origin scope replicas
  policyUnique : ∀ actualScope actualReplicas,
    MaterializationInputs.ReadPolicy state.db origin actualScope actualReplicas →
      actualScope = scope ∧ actualReplicas = replicas
  notRefused : (pending.head.seq, pending.head.root,
    old.map (·.head.root) |>.getD Trie.emptyRoot) ∉ refused
  body : BodyReady tx origin now pending old scope authority prepared
  final : State
  committed : execute (Promote.raw (.commit tx)) body.staged = (.ok (), final)

private theorem finish_executes (ready : Ready origin now refused state) :
    execute (Promote.finish ready.tx (some ready.pending)
      (some (ready.pending.head.seq, ready.pending.head.root,
        ready.old.map (·.head.root) |>.getD Trie.emptyRoot))
      (.ok .flipped)) ready.body.staged =
      (.ok ⟨.flipped, none, none⟩, ready.final) := by
  unfold Promote.finish
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk,
    execute_bind]
  have attempted := PromotionCommand.attempt_eq (Promote.raw (.commit ready.tx)) ready.body.staged
  change execute (Promote.attempt (Promote.raw (.commit ready.tx))) ready.body.staged = _ at attempted
  rw [attempted, ready.committed]
  rfl

private theorem publish_executes (ready : Ready origin now refused state) :
    execute (PromotionExecution.publish ready.tx origin now refused
      (ready.scope, ready.authority, some ready.pending, ready.old)) ready.prepared =
      (.ok ⟨.flipped, none, none⟩, ready.final) := by
  unfold PromotionExecution.publish
  simp only [Option.map_some]
  have notContained : refused.contains (ready.pending.head.seq, ready.pending.head.root,
      ready.old.map (·.head.root) |>.getD Trie.emptyRoot) = false := by
    cases contained : refused.contains (ready.pending.head.seq, ready.pending.head.root,
      ready.old.map (·.head.root) |>.getD Trie.emptyRoot) with
    | false => rfl
    | true => exact False.elim (ready.notRefused (List.contains_iff_mem.mp contained))
  simp only [Option.any_some, notContained, Bool.false_eq_true, if_false]
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
  have attemptedBody := PromotionCommand.attempt_eq
    (Promote.body ready.tx origin now ready.pending ready.old ready.scope ready.authority) ready.prepared
  change execute (Promote.attempt
    (Promote.body ready.tx origin now ready.pending ready.old ready.scope ready.authority)) ready.prepared = _
    at attemptedBody
  rw [attemptedBody, body_executes ready.body]
  dsimp only [ExceptT.bindCont]
  exact finish_executes ready

/-- Healthy preparation, completeness, authority, materialization and commit
facts directly imply a successful actual production flip. -/
theorem promotes (ready : Ready origin now refused state) :
    execute (Promote.promote origin now refused) state =
      (.ok ⟨.flipped, none, none⟩, ready.final) := by
  rw [PromotionExecution.decomposes]
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
  rw [ready.began]
  dsimp only [ExceptT.bindCont, ExceptT.run]
  rw [execute_bind]
  have attemptedPrepare := PromotionCommand.attempt_eq
    (PromotionCommand.prepare ready.tx origin now) ready.opened
  change execute (Promote.attempt (PromotionCommand.prepare ready.tx origin now)) ready.opened = _
    at attemptedPrepare
  rw [attemptedPrepare, ready.preparation]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind]
  have returned : execute
      (pure (ready.scope, ready.authority, some ready.pending, ready.old) :
        Promote.Action PromotionCommand.Prepared) ready.prepared =
      (.ok (ready.scope, ready.authority, some ready.pending, ready.old), ready.prepared) := rfl
  rw [returned]
  exact publish_executes ready

/-- The committed complete slot contains the very candidate selected by this
readiness certificate, rather than merely some head with the same origin. -/
theorem promotes_installs_pending (ready : Ready origin now refused state) :
    PromotionReady.Installed ready.final.db ready.pending.head := by
  have published := PromotionPublication.body_published ready.tx origin now ready.pending
    ready.old ready.scope ready.authority ready.prepared ready.body.staged
    (body_executes ready.body)
  obtain ⟨stagedDb, stagedTx, installed⟩ := PromotionReady.body_installed ready.tx origin now
    ready.pending ready.old ready.scope ready.authority ready.prepared ready.body.staged published
  have rawCommit := OperationExecution.raise_success (fun _ _ => rfl)
    Promote.Error.host (Storage.commit ready.tx) ready.body.staged ready.final () ready.committed
  change storage (.commit ready.tx) ready.body.staged = (.ok (), ready.final) at rawCommit
  obtain ⟨committedDb, pendingTx, committed⟩ := ReconciliationAcceptance.commit_installs
    ready.tx ready.body.staged (congrArg Prod.fst rawCommit)
  have sameDb : stagedDb = committedDb := congrArg Prod.snd
    (Option.some.inj (stagedTx.symm.trans pendingTx))
  have finalDb : ready.final.db = committedDb := by
    simpa only [rawCommit] using committed
  rw [← sameDb] at finalDb
  simpa only [finalDb] using installed

/-- Positive promotion connects directly to the existing exact committed-view
theorem. -/
theorem promotes_ready_view (ready : Ready origin now refused state)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (closed : state.pending = none) (faithful : TrieDiffCoverage.Faithful world state)
    (normalization : state.isNfc = services.nfc)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (initial : PromotionInitialView.Initial state.db origin world services) :
    ready.pending.head.origin = origin ∧
      MaterializationInputs.ReadPolicy state.db origin ready.scope ready.replicas ∧
      PromotionReady.Installed ready.final.db ready.pending.head ∧
      SnapshotViewProgress.ExactFiles services world.snapshot ready.pending.head.root
        (fun key => ready.scope.admitsKeyPath (Trie.keyNibbles key) = true)
        ready.final.db (Origin.canonical origin) ∧
      MaterializedView.CurrentRequirements ready.replicas ready.final.db ∧
      MaterializedView.ForeverRequirements ready.replicas state.db ready.final.db := by
  obtain ⟨actualScope, actualReplicas, head, sameOrigin, policy, installed, files,
      current, forever⟩ :=
    PromotionCommittedView.promote_ready origin now refused state ready.final
      ⟨.flipped, none, none⟩ world services closed faithful normalization relational initial rfl
      (promotes ready)
  obtain ⟨scopeSame, replicasSame⟩ := ready.policyUnique actualScope actualReplicas policy
  subst actualScope
  subst actualReplicas
  have pendingOrigin := PromotionExecution.prepare_origin ready.tx origin now ready.opened
    ready.prepared ready.scope ready.authority (some ready.pending) ready.old ready.preparation
    ready.pending rfl
  have pendingInstalled := promotes_installs_pending ready
  obtain ⟨row, member, pendingNamed⟩ := pendingInstalled.1
  have headNamed : equals row
      [("origin_id", .text (Origin.canonical head.origin)), ("slot", .text "complete")] = true := by
    simpa only [sameOrigin, pendingOrigin] using pendingNamed
  have pendingCells := pendingInstalled.2 row member pendingNamed
  have headCells := installed.2 row member headNamed
  have rootSame : ready.pending.head.root = head.root := by
    have blobs : Cell.blob ready.pending.head.root = Cell.blob head.root :=
      pendingCells.2.symm.trans headCells.2
    exact Cell.blob.inj blobs
  refine ⟨pendingOrigin, ready.policy, pendingInstalled, ?_, ?_, ?_⟩
  · simpa only [rootSame] using files
  · exact current
  · exact forever

end Synchronicity.PromotionProgress
