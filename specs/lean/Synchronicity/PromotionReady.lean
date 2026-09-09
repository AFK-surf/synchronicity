import Synchronicity.PromotionServices
import Synchronicity.PromotionBound
import Synchronicity.AtomicFileView

/-! Publication composes the actual installed version with the exact streamed
file view and its current/forever obligations in one private database. -/
namespace Synchronicity.PromotionReady
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase
open ReconciliationSlots

abbrev Installed := AtomicFileView.Installed

theorem clear_state (tx : Transaction) (origin : Origin.Parsed) (state final : State) (db : Database)
    (opened : state.pending = some (tx, db))
    (ran : execute (Promote.clear tx origin) state = (.ok (), final)) :
    final = record {state with pending := some (tx, MaterializationSql.erased db "heads"
      [("origin_id", .text (Origin.canonical origin)), ("slot", .text "pending")])} ("delete:" ++ "heads") := by
  simp only [Promote.clear, Promote.raw, raise, performOver, Inject.inject, ExceptT.mk,
    bind, ExceptT.bind, ExceptT.bindCont, execute_bind, execute, Interpreter.handle, storage, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError, pure, execute] at ran
  | none =>
    simp only [failed, SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte,
      Except.mapError, pure, ExceptT.pure, ExceptT.mk, execute] at ran
    have same := (congrArg Prod.snd ran).symm
    simpa only [MaterializationSql.erased, deletable, excluded, due, List.any_nil, List.all_nil,
      Bool.not_false, Bool.and_true] using same

theorem clear_installed (tx : Transaction) (origin : Origin.Parsed) (head : Head)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (installed : Installed db head) (ran : execute (Promote.clear tx origin) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Installed after head := by
  rw [clear_state tx origin state final db opened ran]
  refine ⟨_, rfl, ?_, ?_⟩
  · obtain ⟨row, member, named⟩ := installed.1
    refine ⟨row, ?_, named⟩
    simp only [MaterializationSql.erased, rows_setRows, List.mem_filter]
    exact ⟨member, by rw [PromotionBound.complete_not_pending row _ named (Origin.canonical origin)]; rfl⟩
  · intro row member named
    simp only [MaterializationSql.erased, rows_setRows, List.mem_filter] at member
    exact installed.2 row member.1 named

theorem body_installed (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending : Promote.Pending) (old : Option Promote.Pending) (scope : Trie.Serve.Scope)
    (authority : Authorization.OriginAuthority) (state final : State)
    (published : PromotionPublication.BodyPublished tx origin now pending old scope authority state final) :
    ∃ after, final.pending = some (tx, after) ∧ Installed after pending.head := by
  obtain ⟨checked, authorized, written, cleared, count, _, _, installed, erased, streamed⟩ := published.phases
  have history := OperationExecution.within_success PromotionReads.history_agrees Promote.historyError
    (Reconcile.putSlot tx "complete" pending.head pending.received now) authorized written () installed
  obtain ⟨db, opened, existsRow, allRows⟩ := ReconciliationSlots.putSlot_installs tx "complete" pending.head pending.received now
    authorized (by rw [history])
  rw [history] at opened
  obtain ⟨clearedDb, clearedTx, points⟩ := clear_installed tx origin pending.head written cleared db opened ⟨existsRow, allRows⟩ erased
  have heads := MaterializationPrivate.materialize_preserves_heads tx origin
    (old.map (·.head.root) |>.getD Trie.emptyRoot) pending.head.root cleared
  rw [streamed] at heads
  cases finalTx : final.pending with
  | none => simp [ReconciliationFrame.heads, finalTx, clearedTx] at heads
  | some pair =>
    rcases pair with ⟨token, after⟩
    have same : token = tx ∧ rows after "heads" = rows clearedDb "heads" := by
      simpa only [ReconciliationFrame.heads, finalTx, clearedTx, Option.map_some, Option.some.injEq, Prod.mk.injEq] using heads
    obtain ⟨rfl, same⟩ := same
    exact ⟨after, rfl, by simpa only [Installed, AtomicFileView.Installed, same] using points⟩

theorem body_ready (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending : Promote.Pending) (old : Option Promote.Pending) (scope : Trie.Serve.Scope)
    (authority : Authorization.OriginAuthority) (state final : State) (db : Database)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (opened : state.pending = some (tx, db))
    (faithful : TrieDiffCoverage.Faithful world state) (normalization : state.isNfc = services.nfc)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (unique : MaterializedView.UniqueAddresses services (SnapshotViewProgress.Relevant world.snapshot
      (old.map (·.head.root) |>.getD Trie.emptyRoot) pending.head.root))
    (supported : ∀ scope replicas, MaterializationInputs.ReadPolicy db origin scope replicas → ∀ key,
      scope.admitsKeyPath (Trie.keyNibbles key) = true → SnapshotDelta.ChangedKey world.snapshot
        (old.map (·.head.root) |>.getD Trie.emptyRoot) pending.head.root key → key.size ≤ Trie.maxKeyBytes)
    (schema : MaterializationKeySchema.Schema db)
    (initial : ∀ scope replicas, MaterializationInputs.ReadPolicy db origin scope replicas →
      MaterializationRequirementFrame.PoliciesAgree replicas ∧ MaterializedView.CurrentRequirements replicas db ∧
      SnapshotViewProgress.ExactFiles services world.snapshot (old.map (·.head.root) |>.getD Trie.emptyRoot)
        (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) db (Origin.canonical origin))
    (published : PromotionPublication.BodyPublished tx origin now pending old scope authority state final) :
    ∃ scope replicas after, MaterializationInputs.ReadPolicy db origin scope replicas ∧
      final.pending = some (tx, after) ∧ Installed after pending.head ∧
      SnapshotViewProgress.ExactFiles services world.snapshot pending.head.root
        (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) after (Origin.canonical origin) ∧
      MaterializedView.CurrentRequirements replicas after ∧ MaterializedView.ForeverRequirements replicas db after := by
  obtain ⟨checked, authorized, written, cleared, count, complete, permitted, installed, erased, streamed⟩ := published.phases
  have frame (relation : String) (heads : "heads" ≠ relation) (history : "head_history" ≠ relation) :
      MaterializationTableFrame.view relation cleared = MaterializationTableFrame.view relation state := by
    have first := PromotionViewFrame.executed_frame relation _
      (PromotionViewFrame.read_only relation _ (PromotionReads.complete_only tx _ _)) _ _ _ complete
    have second := PromotionViewFrame.executed_frame relation _
      (PromotionViewFrame.read_only relation _ (PromotionViewFrame.permitted_only tx pending authority)) _ _ _ permitted
    have third := PromotionViewFrame.executed_frame relation _
      (PromotionViewFrame.put_slot_only relation heads history tx _ _ _ _) _ _ _ installed
    have fourth := PromotionViewFrame.executed_frame relation _ (PromotionViewFrame.clear_only relation heads tx origin) _ _ _ erased
    exact fourth.trans (third.trans (second.trans first))
  have primitives : PromotionServices.observation cleared = PromotionServices.observation state :=
    (PromotionServices.executed_frame _ _ _ _ erased).trans
      ((PromotionServices.executed_frame _ _ _ _ installed).trans
        ((PromotionServices.executed_frame _ _ _ _ permitted).trans (PromotionServices.executed_frame _ _ _ _ complete)))
  have entriesFrame := frame "entries" (by decide) (by decide)
  obtain ⟨clearedDb, clearedTx⟩ : ∃ after, cleared.pending = some (tx, after) := by
    cases current : cleared.pending with
    | none => simp [MaterializationTableFrame.view, current, opened] at entriesFrame
    | some pair =>
      rcases pair with ⟨token, after⟩
      have same : token = tx := congrArg Prod.fst (Option.some.inj (by
        simpa only [MaterializationTableFrame.view, current, opened, Option.map_some] using entriesFrame))
      exact ⟨after, by simp only [same]⟩
  have tables (relation : String) (heads : "heads" ≠ relation) (history : "head_history" ≠ relation) :
      rows clearedDb relation = rows db relation := by
    have same := frame relation heads history
    simpa only [MaterializationTableFrame.view, clearedTx, opened, Option.map_some, Option.some.injEq,
      Prod.mk.injEq, true_and] using same
  have policyFrame {scope replicas} (read : MaterializationInputs.ReadPolicy clearedDb origin scope replicas) :
      MaterializationInputs.ReadPolicy db origin scope replicas := MaterializationInputs.read_policy_frame db clearedDb
    (tables "config" (by decide) (by decide)) (tables "replicas" (by decide) (by decide)) read
  have keys : MaterializationKeySchema.Schema clearedDb := by
    simpa only [MaterializationKeySchema.Schema, tables "pins" (by decide) (by decide),
      tables "content_want" (by decide) (by decide)] using schema
  have source := PromotionServices.relational_faithful world tx state cleared db clearedDb opened clearedTx primitives relational
    (fun relation relevant => tables relation (by rcases relevant with rfl | rfl <;> decide)
      (by rcases relevant with rfl | rfl <;> decide)) faithful
  have nfc : cleared.isNfc = services.nfc := ((Prod.mk.inj (Prod.mk.inj primitives).2).1).trans normalization
  obtain ⟨actualScope, replicas, after, policy, afterTx, files, holds, forever⟩ :=
    MaterializationInputs.materialize_ready tx origin _ _ world services unique
      (fun scope replicas read => supported scope replicas (policyFrame read)) cleared final count clearedTx source nfc keys
      (by
        intro scope replicas read
        obtain ⟨agree, current, files⟩ := initial scope replicas (policyFrame read)
        have obligations := MaterializationWholeRetention.tables_preserve replicas db db clearedDb
          (tables "entries" (by decide) (by decide)) (tables "pins" (by decide) (by decide))
          (tables "content_want" (by decide) (by decide)) ⟨current, fun _ _ _ _ held => held⟩
        refine ⟨agree, obligations.1, ?_⟩
        simpa only [SnapshotViewProgress.ExactFiles, MaterializedView.Observed, MaterializedView.Address.table,
          tables "entries" (by decide) (by decide)] using files) streamed
  obtain ⟨pointDb, pointTx, points⟩ := body_installed tx origin now pending old scope authority state final published
  have same : after = pointDb := congrArg Prod.snd (Option.some.inj (afterTx.symm.trans pointTx))
  subst pointDb
  refine ⟨actualScope, replicas, after, policyFrame policy, afterTx, points, files, holds, ?_⟩
  intro target member permanent root held
  apply forever target member permanent root
  exact MaterializationRetention.rows_retain
    (fun _ present => (tables "pins" (by decide) (by decide)).symm ▸ present)
    (fun _ present => (tables "content_want" (by decide) (by decide)).symm ▸ present) root target.holder held

end Synchronicity.PromotionReady
