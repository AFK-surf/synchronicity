import Synchronicity.PromotionCertificates
import Synchronicity.ReconciliationAcceptance
import Synchronicity.ReconciliationFailure

/-! Execution evidence for M4's publication boundary. Successful publication
must follow the actual preparation, completeness check, authority check and
materializer, and installs the materializer's entire staged database.

This is execution evidence, not a readiness definition. PromotionAtomicView
composes it with exact permitted-view and retention refinement for M4.
Arbitrary host faults are admitted; success witnesses are derived.
-/
namespace Synchronicity.PromotionPublication
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication
  SimulatedHost PrivateDatabase TransactionSuccess

/-- The authority check executed after completeness, in the same transaction. -/
def permitted (tx : Transaction) (pending : Promote.Pending)
    (authority : Authorization.OriginAuthority) : Promote.Action Bool :=
  Promote.permitted tx pending authority

/-- Actual successful phases of the body. `complete` records the executable
check's answer; it deliberately does not define the meaning of a ready view. -/
structure BodyPublished (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending : Promote.Pending) (old : Option Promote.Pending)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (state final : State) : Prop where
  newer : old.any (fun old => !Reconcile.newer pending.head.seq pending.head.root
    ⟨old.head.seq, old.head.root⟩) = false
  phases : ∃ checked authorized written cleared count,
    execute (PromotionReads.complete tx ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root)
      state = (.ok true, checked) ∧
    execute (permitted tx pending authority) checked = (.ok true, authorized) ∧
    execute (Promote.history (Reconcile.putSlot tx "complete" pending.head pending.received now))
      authorized = (.ok (), written) ∧
    execute (Promote.clear tx origin) written = (.ok (), cleared) ∧
    execute (Materialize.materialize tx origin (old.map (·.head.root) |>.getD Trie.emptyRoot)
      pending.head.root) cleared = (.ok count, final)

theorem body_published (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending : Promote.Pending) (old : Option Promote.Pending)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (state final : State)
    (ran : execute (Promote.body tx origin now pending old scope authority) state = (.ok .flipped, final)) :
    BodyPublished tx origin now pending old scope authority state final := by
  unfold Promote.body at ran
  split at ran
  · obtain ⟨_, _, _, impossible⟩ := bind_success _ _ _ _ _ ran
    cases impossible
  · rename_i newer
    obtain ⟨complete, checked, checkedRun, ran⟩ := bind_success _ _ _ _ _ ran
    cases complete with
    | false => cases ran
    | true =>
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte] at ran
      obtain ⟨allowed, authorized, authorizedRun, ran⟩ := bind_success _ _ _ _ _ ran
      cases allowed with
      | false =>
        obtain ⟨_, _, _, impossible⟩ := bind_success _ _ _ _ _ ran
        cases impossible
      | true =>
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte] at ran
        obtain ⟨_, written, writtenRun, ran⟩ := bind_success _ _ _ _ _ ran
        obtain ⟨_, cleared, clearedRun, ran⟩ := bind_success _ _ _ _ _ ran
        obtain ⟨count, staged, stagedRun, returned⟩ := bind_success _ _ _ _ _ ran
        have same : staged = final := congrArg Prod.snd returned
        subst staged
        refine ⟨by simpa using newer, checked, authorized, written, cleared, count,
          checkedRun, authorizedRun, writtenRun, clearedRun, ?_⟩
        exact OperationExecution.within_success PromotionReads.materialize_agrees
          Promote.materializeError _ _ _ _ stagedRun

/-- All effects before the body's return leave the committed database intact,
including the early complete-slot write and every retention update. -/
theorem body_private (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending : Promote.Pending) (old : Option Promote.Pending)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority) :
    Only (fun _ effect => ∀ state : State, (Interpreter.handle effect state).2.db = state.db)
      (Promote.body tx origin now pending old scope authority).run := by
  apply PromotionCertificates.body_only
  · apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
    exact storage_preserves_db (.deleteRows tx "heads"
      [("origin_id", .text (Origin.canonical origin)), ("slot", .text "pending")]) trivial
  · intro A operation safe
    exact safe.mono (fun effect good => PromotionReads.effects_db effect good)
  · apply Only.within _ _ (ReconciliationFailure.putSlot_private tx "complete" pending.head pending.received now)
    intro B effect good state
    rw [PromotionReads.history_agrees]
    exact ReconciliationFailure.effects_db effect good state
  · apply Only.within _ _ (MaterializationPrivate.materialize_private tx origin _ _)
    intro B effect good state
    rw [PromotionReads.materialize_agrees]
    exact MaterializationPrivate.effects_preserve_db effect good state

theorem body_prefix_private (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending : Promote.Pending) (old : Option Promote.Pending)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (state final : State) (tail : Program Promote.Effects (Except Promote.Error Promotion))
    (path : Prefix (Promote.body tx origin now pending old scope authority).run state tail final) :
    final.db = state.db :=
  (body_private tx origin now pending old scope authority).preserves_prefix path (fun _ good => good)

theorem attempted (operation : Promote.Action A) (state final : State)
    (result : Except Promote.Error A)
    (ran : execute (Promote.attempt operation) state = (.ok result, final)) :
    execute operation state = (result, final) := by
  have step := PromotionCommand.attempt_eq operation state
  change execute (Promote.attempt operation) state = _ at step
  rw [step] at ran
  obtain ⟨first, second⟩ := Prod.mk.inj ran
  exact Prod.ext (Except.ok.inj first) second

/-- Even with arbitrary injected faults, a successful flip report can only
come from a successful body and commit. A rollback/retirement cannot mint it. -/
theorem finish_flipped (tx : Transaction) (pending : Option Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (result : Except Promote.Error Promotion)
    (state final : State) (report : PromotionReport)
    (flipped : report.promotion = .flipped)
    (ran : execute (Promote.finish tx pending key result) state = (.ok report, final)) :
    result = .ok .flipped ∧ ∃ db,
      state.pending = some (tx, db) ∧ final.db = db ∧
      storage (.commit tx) state = (.ok (), final) := by
  unfold Promote.finish at ran
  cases result with
  | ok promotion =>
    obtain ⟨committed, closed, commitRun, ran⟩ := bind_success _ _ _ _ _ ran
    have commitRun := attempted _ _ _ _ commitRun
    cases committed with
    | error error =>
      obtain ⟨_, _, _, impossible⟩ := bind_success _ _ _ _ _ ran
      cases impossible
    | ok valueUnit =>
      cases valueUnit
      have returned : (⟨promotion, none, none⟩ : PromotionReport) = report :=
        Except.ok.inj (congrArg Prod.fst ran)
      have same : closed = final := congrArg Prod.snd ran
      subst closed
      have success : execute (Promote.raw (.commit tx)) state = (.ok (), final) := commitRun
      have rawSuccess := OperationExecution.raise_success (fun _ _ => rfl)
        Promote.Error.host (Storage.commit tx) state final () success
      change storage (.commit tx) state = (.ok (), final) at rawSuccess
      obtain ⟨db, staged, published⟩ := ReconciliationAcceptance.commit_installs tx state
        (congrArg Prod.fst rawSuccess)
      refine ⟨?_, db, staged, ?_, rawSuccess⟩
      · rw [← returned] at flipped
        exact congrArg Except.ok flipped
      · simpa only [rawSuccess] using published
  | error error =>
    dsimp only at ran
    obtain ⟨_, rolled, _, ran⟩ := bind_success _ _ _ _ _ ran
    cases error with
    | host _ => cases ran
    | domain failure =>
      dsimp only at ran
      split at ran
      · cases pending with
        | none => cases ran
        | some candidate =>
          obtain ⟨_, _, _, returned⟩ := bind_success _ _ _ _ _ ran
          have same : (⟨.refused, some failure, key⟩ : PromotionReport) = report :=
            Except.ok.inj (congrArg Prod.fst returned)
          rw [← same] at flipped
          cases flipped
      · cases ran

/-- The complete production invocation publishes exactly the database staged
by its own successful materializer. These witnesses are all actual executions,
including the initial reads and the final commit; none assumes view correctness. -/
theorem promote_flipped (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray))
    (state final : State) (report : PromotionReport)
    (flipped : report.promotion = .flipped)
    (ran : execute (Promote.promote origin now refused) state = (.ok report, final)) :
    ∃ tx opened ready scope authority pending old staged db,
      execute (Promote.raw .begin) state = (.ok tx, opened) ∧
      execute (PromotionCommand.prepare tx origin now) opened =
        (.ok (scope, authority, some pending, old), ready) ∧
      ready.pending = some (tx, state.db) ∧ ready.db = state.db ∧
      BodyPublished tx origin now pending old scope authority ready staged ∧
      staged.db = state.db ∧ staged.pending = some (tx, db) ∧
      final.db = db ∧ storage (.commit tx) staged = (.ok (), final) := by
  rw [PromotionExecution.decomposes] at ran
  obtain ⟨tx, opened, began, ran⟩ := bind_success _ _ _ _ _ ran
  obtain ⟨preparation, ready, preparedRun, ran⟩ := bind_success _ _ _ _ _ ran
  have preparedRun := attempted _ _ _ _ preparedRun
  cases preparation with
  | error error =>
    dsimp only at ran
    obtain ⟨_, _, _, ran⟩ := bind_success _ _ _ _ _ ran
    cases ran
  | ok prepared =>
    obtain ⟨scope, authority, pending, old⟩ := prepared
    have read : execute (PromotionCommand.prepare tx origin now) opened =
        (.ok (scope, authority, pending, old), ready) :=
      preparedRun
    obtain ⟨_, _, returned, ran⟩ := bind_success _ _ _ _ _ ran
    cases returned
    unfold PromotionExecution.publish at ran
    obtain ⟨result, staged, bodyRun, finishRun⟩ := bind_success _ _ _ _ _ ran
    obtain ⟨resultFlipped, db, stagedDb, published, committed⟩ :=
      finish_flipped tx pending _ result staged final report flipped finishRun
    subst result
    have bodyRun := attempted _ _ _ _ bodyRun
    cases pending with
    | none => cases bodyRun
    | some pending =>
      dsimp only at bodyRun
      split at bodyRun
      · obtain ⟨_, _, _, impossible⟩ := bind_success _ _ _ _ _ bodyRun
        cases impossible
      · have rawBegin := OperationExecution.raise_success (fun _ _ => rfl)
          Promote.Error.host Storage.begin state opened tx began
        change storage .begin state = (.ok tx, opened) at rawBegin
        have snapshot := ReconciliationFloor.begin_pending state opened tx rawBegin
        have readySnapshot := PromotionReads.executed_pending _
          (PromotionCommand.prepare_only tx origin now) opened ready _ read
        have openedDb : opened.db = state.db := by
          simpa only [rawBegin] using storage_preserves_db Storage.begin trivial state
        have readyDb : ready.db = state.db := by
          have same := (PromotionCommand.prepare_only tx origin now).preserves_db _ PromotionReads.effects_db opened
          change (execute (PromotionCommand.prepare tx origin now) opened).2.db = opened.db at same
          simpa only [read, openedDb] using same
        refine ⟨tx, opened, ready, scope, authority, pending, old, staged, db,
          began, read, readySnapshot.trans snapshot, readyDb,
          body_published tx origin now pending old scope authority ready staged bodyRun,
          ?_, stagedDb, published, committed⟩
        have privateBody := (body_private tx origin now pending old scope authority).preserves_db _ (fun _ good => good) ready
        change (execute (Promote.body tx origin now pending old scope authority) ready).2.db = ready.db at privateBody
        simpa only [bodyRun, readyDb] using privateBody

theorem rollback_private (tx : Transaction) (state : State) :
    (execute (Promote.raw (.rollback tx)) state).2.db = state.db :=
  storage_preserves_db (.rollback tx) trivial state

theorem after_attempt (operation : Promote.Action A)
    (next : Except Promote.Error A → Promote.Action B)
    (state final : State) (answer : Except Promote.Error B)
    (ran : execute (Promote.attempt operation >>= next : Promote.Action B) state = (answer, final)) :
    ∃ result middle, execute operation state = (result, middle) ∧
      execute (next result) middle = (answer, final) := by
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind] at ran
  have step := PromotionCommand.attempt_eq operation state
  change execute (Promote.attempt operation) state = _ at step
  rw [step] at ran
  exact ⟨_, _, rfl, ran⟩

private theorem failed_bind (operation : Promote.Action A) (next : A → Promote.Action B)
    (state final : State) (failure : Promote.Error)
    (ran : execute (operation >>= next : Promote.Action B) state = (.error failure, final)) :
    execute operation state = (.error failure, final) ∨
      ∃ value middle, execute operation state = (.ok value, middle) ∧
        execute (next value) middle = (.error failure, final) := by
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind] at ran
  generalize first : execute operation state = result at ran
  obtain ⟨answer, middle⟩ := result
  cases answer with
  | error e =>
    left
    have same : e = failure := Except.error.inj (congrArg Prod.fst ran)
    have after : middle = final := congrArg Prod.snd ran
    exact Prod.ext (congrArg Except.error same) after
  | ok value => exact .inr ⟨value, middle, rfl, ran⟩

theorem retire_failure (pending : Promote.Pending) (state : State)
    (failure : Promote.Error)
    (ran : (execute (Promote.retire pending) state).1 = .error failure) :
    (execute (Promote.retire pending) state).2.db = state.db := by
  apply TransactionFailure.transaction_failure Inject.inject (fun _ _ => rfl)
    Promote.Error.host _ _ state failure ran
  intro tx initial
  apply Only.preserves_db (allowed := fun _ (effect : Promote.Effects _) =>
    ∀ s : State, (Interpreter.handle effect s).2.db = s.db) _ _ (fun _ safe => safe) initial
  apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
  exact storage_preserves_db (Storage.deleteRows tx "heads"
    (Reconcile.headKey pending.head ++ [("slot", Cell.text "pending")])) trivial

/-- Failure of the actual finish stage leaves every committed relation intact,
including when commit, rollback or post-rollback retirement also fails. -/
theorem finish_failure (tx : Transaction) (pending : Option Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (result : Except Promote.Error Promotion)
    (state final : State) (failure : Promote.Error)
    (ran : execute (Promote.finish tx pending key result) state = (.error failure, final)) :
    final.db = state.db := by
  unfold Promote.finish at ran
  cases result with
  | ok promotion =>
    obtain ⟨committed, closed, commitRun, ran⟩ := after_attempt _ _ _ _ _ ran
    cases committed with
    | ok valueUnit => cases valueUnit; cases ran
    | error error =>
      obtain ⟨_, rolled, rolledRun, returned⟩ := after_attempt _ _ _ _ _ ran
      have same : rolled = final := congrArg Prod.snd returned
      subst rolled
      have commitFailed : ∃ e, storage (.commit tx) state = (.error e, closed) := by
        change ((storage (.commit tx) state).1.mapError Promote.Error.host,
          (storage (.commit tx) state).2) = (.error error, closed) at commitRun
        generalize storage (.commit tx) state = outcome at commitRun ⊢
        obtain ⟨answer, afterCommit⟩ := outcome
        cases answer with
        | ok _ => cases commitRun
        | error e =>
          have same : afterCommit = closed := congrArg Prod.snd commitRun
          exact ⟨e, Prod.ext rfl same⟩
      obtain ⟨e, committedRun⟩ := commitFailed
      have kept := TransactionFailure.commit_failure tx state e (congrArg Prod.fst committedRun)
      rw [committedRun] at kept
      have rolledKept := rollback_private tx closed
      rw [rolledRun] at rolledKept
      exact rolledKept.trans kept
  | error error =>
    dsimp only at ran
    obtain ⟨_, rolled, rolledRun, ran⟩ := after_attempt _ _ _ _ _ ran
    have rolledKept := rollback_private tx state
    rw [rolledRun] at rolledKept
    cases error with
    | host _ =>
      exact (congrArg (fun result => result.2.db) ran).symm.trans rolledKept
    | domain domain =>
      dsimp only at ran
      split at ran
      · cases pending with
        | none => exact (congrArg (fun result => result.2.db) ran).symm.trans rolledKept
        | some candidate =>
          simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind] at ran
          generalize retiredRun : execute (Promote.retire candidate) rolled = outcome at ran
          obtain ⟨answer, retired⟩ := outcome
          cases answer with
          | ok _ => cases ran
          | error e =>
            have kept := retire_failure candidate rolled e (congrArg Prod.fst retiredRun)
            rw [retiredRun] at kept
            exact (congrArg (fun result => result.2.db) ran).symm.trans (kept.trans rolledKept)
      · exact (congrArg (fun result => result.2.db) ran).symm.trans rolledKept

private theorem publish_failure (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (prepared : PromotionCommand.Prepared)
    (state final : State) (failure : Promote.Error)
    (ran : execute (PromotionExecution.publish tx origin now refused prepared) state = (.error failure, final)) :
    final.db = state.db := by
  obtain ⟨scope, authority, pending, old⟩ := prepared
  unfold PromotionExecution.publish at ran
  obtain ⟨result, staged, bodyRun, finishRun⟩ := after_attempt _ _ _ _ _ ran
  have finishDb := finish_failure tx pending _ result staged final failure finishRun
  apply finishDb.trans
  have privateWork : Only
      (fun _ (effect : Promote.Effects _) => ∀ s : State, (Interpreter.handle effect s).2.db = s.db)
      (do
        match pending with
        | none => pure Promotion.idle
        | some candidate =>
          if (pending.map (fun p => (p.head.seq, p.head.root,
              old.map (·.head.root) |>.getD Trie.emptyRoot))).any refused.contains then
            Promote.clear tx origin
            return .refused
          Promote.body tx origin now candidate old scope authority : Promote.Action Promotion).run := by
    cases pending with
    | none => exact .done _
    | some candidate =>
      dsimp only
      split
      · apply Only.seq _ fun _ => .done _
        apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
        exact storage_preserves_db (Storage.deleteRows tx "heads"
          [("origin_id", .text (Origin.canonical origin)), ("slot", .text "pending")]) trivial
      · exact body_private tx origin now candidate old scope authority
  have kept := privateWork.preserves_db _ (fun _ safe => safe) state
  exact (congrArg (fun result => result.2.db) bodyRun).symm.trans kept

/-- Any failed invocation of the complete promotion command preserves the
entire committed database. No fault-free assumption is needed, even for the
rollback and the captured-target retirement after a materialization failure. -/
theorem promote_failure (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray))
    (state final : State) (failure : Promote.Error)
    (ran : execute (Promote.promote origin now refused) state = (.error failure, final)) :
    final.db = state.db := by
  rw [PromotionExecution.decomposes] at ran
  rcases failed_bind _ _ _ _ _ ran with failed | ⟨tx, opened, began, ran⟩
  · have kept : (execute (Promote.raw .begin) state).2.db = state.db :=
      storage_preserves_db Storage.begin trivial state
    simpa only [failed] using kept
  · have openedDb : opened.db = state.db := by
      have kept : (execute (Promote.raw .begin) state).2.db = state.db :=
        storage_preserves_db Storage.begin trivial state
      simpa only [began] using kept
    obtain ⟨preparation, ready, preparedRun, ran⟩ := after_attempt _ _ _ _ _ ran
    have readyDb : ready.db = state.db := by
      have kept := (PromotionCommand.prepare_only tx origin now).preserves_db _ PromotionReads.effects_db opened
      change (execute (PromotionCommand.prepare tx origin now) opened).2.db = opened.db at kept
      rw [preparedRun] at kept
      exact kept.trans openedDb
    cases preparation with
    | error error =>
      dsimp only at ran
      obtain ⟨_, rolled, rollbackRun, ran⟩ := after_attempt _ _ _ _ _ ran
      have kept := rollback_private tx ready
      rw [rollbackRun] at kept
      exact (congrArg (fun result => result.2.db) ran).symm.trans (kept.trans readyDb)
    | ok prepared =>
      exact (publish_failure tx origin now refused prepared ready final failure ran).trans readyDb

end Synchronicity.PromotionPublication
