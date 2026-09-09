import Synchronicity.PromotionPublicFrame

/-! Whole-command non-publication, including post-rollback retirement and
cached refusals. Only the public version/entries/obligations are framed;
pending bookkeeping is allowed to change. -/
namespace Synchronicity.PromotionNonpublication
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands Replication SimulatedHost PrivateDatabase
open TransactionSuccess PromotionPublicFrame AtomicFileView

theorem finish_success (origin : String) (tx : Transaction) (pending : Option Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (result : Except Promote.Error Promotion)
    (state final : State) (report : PromotionReport)
    (ran : execute (Promote.finish tx pending key result) state = (.ok report, final)) :
    (∃ promotion db, result = .ok promotion ∧ report.promotion = promotion ∧
      state.pending = some (tx, db) ∧ final.db = db) ∨
    projection origin final.db = projection origin state.db := by
  unfold Promote.finish at ran
  cases result with
  | ok promotion =>
    obtain ⟨committed, closed, commitRun, ran⟩ := bind_success _ _ _ _ _ ran
    have commitRun := PromotionPublication.attempted _ _ _ _ commitRun
    cases committed with
    | error error =>
      obtain ⟨_, _, _, impossible⟩ := bind_success _ _ _ _ _ ran
      cases impossible
    | ok value =>
      cases value
      have returned : (⟨promotion, none, none⟩ : PromotionReport) = report := Except.ok.inj (congrArg Prod.fst ran)
      have same : closed = final := congrArg Prod.snd ran
      subst closed
      have raw := OperationExecution.raise_success (fun _ _ => rfl) Promote.Error.host (Storage.commit tx) state final () commitRun
      change storage (.commit tx) state = (.ok (), final) at raw
      obtain ⟨db, staged, published⟩ := ReconciliationAcceptance.commit_installs tx state (congrArg Prod.fst raw)
      exact Or.inl ⟨promotion, db, rfl, by rw [← returned], staged, by simpa only [raw] using published⟩
  | error error =>
    dsimp only at ran
    obtain ⟨_, rolled, rolledRun, ran⟩ := PromotionPublication.after_attempt _ _ _ _ _ ran
    have rolledFrame := PromotionPublication.rollback_private tx state
    rw [rolledRun] at rolledFrame
    cases error with
    | host _ => cases ran
    | domain failure =>
      dsimp only at ran
      split at ran
      · cases pending with
        | none => cases ran
        | some candidate =>
          obtain ⟨_, retired, retiredRun, returned⟩ := bind_success _ _ _ _ _ ran
          have same : retired = final := congrArg Prod.snd returned
          subst retired
          have frame := retire_success origin candidate rolled final retiredRun
          exact Or.inr (frame.trans (congrArg (projection origin) rolledFrame))
      · cases ran

def work (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (prepared : PromotionCommand.Prepared) : Promote.Action Promotion := do
  let (scope, authority, pending, old) := prepared
  match pending with
  | none => pure .idle
  | some candidate =>
    if (pending.map (fun p => (p.head.seq, p.head.root,
        old.map (·.head.root) |>.getD Trie.emptyRoot))).any refused.contains then
      Promote.clear tx origin
      return .refused
    Promote.body tx origin now candidate old scope authority

theorem work_private (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (prepared : PromotionCommand.Prepared) :
    Only (fun _ (effect : Promote.Effects _) => ∀ s : State, (Interpreter.handle effect s).2.db = s.db)
      (work tx origin now refused prepared).run := by
  obtain ⟨scope, authority, pending, old⟩ := prepared
  unfold work
  cases pending with
  | none => exact .done _
  | some candidate =>
    dsimp only
    split
    · apply Only.seq _ fun _ => .done _
      apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
      exact storage_preserves_db (Storage.deleteRows tx "heads"
        [("origin_id", .text (Origin.canonical origin)), ("slot", .text "pending")]) trivial
    · exact PromotionPublication.body_private tx origin now candidate old scope authority

theorem work_no_flip (publicOrigin : String) (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (prepared : PromotionCommand.Prepared)
    (state final : State) (answer : Promotion) (notFlipped : answer ≠ .flipped)
    (ran : execute (work tx origin now refused prepared) state = (.ok answer, final)) :
    pendingView publicOrigin final = pendingView publicOrigin state := by
  obtain ⟨scope, authority, pending, old⟩ := prepared
  unfold work at ran
  cases pending with
  | none => exact congrArg (fun result => pendingView publicOrigin result.2) ran.symm
  | some candidate =>
    dsimp only at ran
    split at ran
    · exact clear_return_frame publicOrigin tx origin _ _ state final ran
    · exact body_no_flip publicOrigin tx origin now candidate old scope authority state final answer notFlipped ran

theorem publish_no_flip (publicOrigin : String) (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (prepared : PromotionCommand.Prepared)
    (state final : State) (report : PromotionReport) (db : Database)
    (opened : state.pending = some (tx, db)) (initial : projection publicOrigin db = projection publicOrigin state.db)
    (notFlipped : report.promotion ≠ .flipped)
    (ran : execute (PromotionExecution.publish tx origin now refused prepared) state = (.ok report, final)) :
    projection publicOrigin final.db = projection publicOrigin state.db := by
  obtain ⟨scope, authority, pending, old⟩ := prepared
  change execute (do
    let result ← Promote.attempt (work tx origin now refused (scope, authority, pending, old))
    Promote.finish tx pending (pending.map (fun p => (p.head.seq, p.head.root,
      old.map (·.head.root) |>.getD Trie.emptyRoot))) result : Promote.Action PromotionReport) state = (.ok report, final) at ran
  obtain ⟨result, staged, bodyRun, finishRun⟩ := PromotionPublication.after_attempt _ _ _ _ _ ran
  rcases finish_success publicOrigin tx pending _ result staged final report finishRun with committed | unchanged
  · obtain ⟨promotion, after, resultSame, reportSame, stagedTx, finalDb⟩ := committed
    subst result
    have frame := work_no_flip publicOrigin tx origin now refused _ state staged promotion
      (by rwa [← reportSame]) bodyRun
    have same : projection publicOrigin after = projection publicOrigin db := by
      simpa only [pendingView, stagedTx, opened, Option.map_some, Option.some.injEq, Prod.mk.injEq, true_and] using frame
    rw [finalDb]
    exact same.trans initial
  · have frame := (work_private tx origin now refused (scope, authority, pending, old)).preserves_db _ (fun _ good => good) state
    change (execute (work tx origin now refused (scope, authority, pending, old)) state).2.db = state.db at frame
    rw [bodyRun] at frame
    exact unchanged.trans (congrArg (projection publicOrigin) frame)

theorem promote_no_flip_for (publicOrigin : String) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state final : State) (report : PromotionReport)
    (notFlipped : report.promotion ≠ .flipped)
    (ran : execute (Promote.promote origin now refused) state = (.ok report, final)) :
    projection publicOrigin final.db = projection publicOrigin state.db := by
  rw [PromotionExecution.decomposes] at ran
  obtain ⟨tx, opened, began, ran⟩ := bind_success _ _ _ _ _ ran
  obtain ⟨preparation, ready, preparedRun, ran⟩ := PromotionPublication.after_attempt _ _ _ _ _ ran
  cases preparation with
  | error error =>
    obtain ⟨_, _, _, impossible⟩ := bind_success _ _ _ _ _ ran
    cases impossible
  | ok prepared =>
    obtain ⟨_, _, returned, ran⟩ := bind_success _ _ _ _ _ ran
    cases returned
    have rawBegin := OperationExecution.raise_success (fun _ _ => rfl) Promote.Error.host Storage.begin state opened tx began
    change storage .begin state = (.ok tx, opened) at rawBegin
    have snapshot := ReconciliationFloor.begin_pending state opened tx rawBegin
    have readFrame := PromotionReads.executed_pending _ (PromotionCommand.prepare_only tx origin now) opened ready prepared preparedRun
    have openedDb : opened.db = state.db := by
      simpa only [rawBegin] using storage_preserves_db Storage.begin trivial state
    have readyDb : ready.db = state.db := by
      have frame := (PromotionCommand.prepare_only tx origin now).preserves_db _ PromotionReads.effects_db opened
      change (execute (PromotionCommand.prepare tx origin now) opened).2.db = opened.db at frame
      simpa only [preparedRun, openedDb] using frame
    have same := publish_no_flip publicOrigin tx origin now refused prepared ready final report state.db
      (readFrame.trans snapshot) (by rw [readyDb]) notFlipped ran
    exact same.trans (congrArg (projection publicOrigin) readyDb)

theorem promote_no_flip (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state final : State)
    (report : PromotionReport) (notFlipped : report.promotion ≠ .flipped)
    (ran : execute (Promote.promote origin now refused) state = (.ok report, final)) :
    projection (Origin.canonical origin) final.db =
      projection (Origin.canonical origin) state.db :=
  promote_no_flip_for (Origin.canonical origin) origin now refused state final report
    notFlipped ran

end Synchronicity.PromotionNonpublication
