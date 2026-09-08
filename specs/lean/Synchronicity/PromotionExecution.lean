import Synchronicity.PromotionCommand

/-! Expose the real read snapshot and the remainder of promotion. This is
execution evidence for captures, not a caller-supplied cleanup permission. -/
namespace Synchronicity.PromotionExecution
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication SimulatedHost PrivateDatabase

def publish (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (prepared : PromotionCommand.Prepared) : Promote.Action PromotionReport := do
  let (scope, authority, pending, old) := prepared
  let key := pending.map (fun p => (p.head.seq, p.head.root, old.map (·.head.root) |>.getD Trie.emptyRoot))
  let result ← Promote.attempt (do
    match pending with
    | none => pure Promotion.idle
    | some pending =>
      if key.any refused.contains then
        Promote.clear tx origin
        return .refused
      Promote.body tx origin now pending old scope authority : Promote.Action Promotion)
  Promote.finish tx pending key result

theorem decomposes (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray)) :
    Promote.promote origin now refused = (do
      let tx ← Promote.raw .begin
      let prepared ← Promote.attempt (PromotionCommand.prepare tx origin now)
      let value ← match prepared with
        | .ok value => pure value
        | .error error =>
          let _ ← Promote.attempt (Promote.raw (.rollback tx))
          throw error
      publish tx origin now refused value : Promote.Action PromotionReport) := rfl

theorem prepare_origin (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (state ready : State) (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (pending old : Option Promote.Pending)
    (executed : execute (PromotionCommand.prepare tx origin now) state = (.ok (scope, authority, pending, old), ready)) :
    ∀ candidate, pending = some candidate → candidate.head.origin = origin := by
  unfold PromotionCommand.prepare at executed
  obtain ⟨scopeRead, _, _, executed⟩ := TransactionSuccess.bind_success _ _ _ _ _ executed
  obtain ⟨authorityRead, authorized, _, executed⟩ := TransactionSuccess.bind_success _ _ _ _ _ executed
  obtain ⟨pendingRead, _, readPending, executed⟩ := TransactionSuccess.bind_success _ _ _ _ _ executed
  cases pendingRead with
  | none =>
    have same : (scopeRead, authorityRead, none, none) = (scope, authority, pending, old) :=
      Except.ok.inj (congrArg Prod.fst executed)
    cases same
    intro candidate impossible
    cases impossible
  | some candidate =>
    have sameOrigin := PromotionReads.slot_origin tx origin "pending" authorized candidate (congrArg Prod.fst readPending)
    obtain ⟨oldRead, _, _, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ executed
    have same : (scopeRead, authorityRead, some candidate, oldRead) = (scope, authority, pending, old) :=
      Except.ok.inj (congrArg Prod.fst returned)
    cases same
    intro current same
    cases same
    exact sameOrigin

/-- If promotion gets past preparation, this records the actual begin/read
execution and the unchanged private snapshot passed to its write phase. -/
structure PreparedAt (origin : Origin.Parsed) (now : Int64) (state : State) where
  tx : Transaction
  opened : State
  ready : State
  value : PromotionCommand.Prepared
  began : execute (Promote.raw .begin) state = (.ok tx, opened)
  read : execute (PromotionCommand.prepare tx origin now) opened = (.ok value, ready)
  snapshot : ready.pending = some (tx, state.db)
  committed : ready.db = state.db

theorem outcome (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
    (state : State) :
    rows (execute (Promote.promote origin now refused) state).2.db "heads" = rows state.db "heads" ∨
      ∃ prepared : PreparedAt origin now state,
        (execute (Promote.promote origin now refused) state).2 =
          (execute (publish prepared.tx origin now refused prepared.value) prepared.ready).2 := by
  have attempted {A : Type} (operation : Promote.Action A) (s : State) :
      execute (Promote.attempt operation) s = (.ok (execute operation s).1, (execute operation s).2) :=
    PromotionCommand.attempt_eq operation s
  rw [decomposes]
  simp only [bind, ExceptT.bind, ExceptT.mk, execute_bind]
  generalize started : execute (Promote.raw .begin) state = start
  obtain ⟨result, opened⟩ := start
  have openedDb : opened.db = state.db := by
    have frame : (execute (Promote.raw .begin) state).2.db = state.db := by
      apply reply_preserves_db
      intro s
      split <;> rfl
    simpa only [started] using frame
  cases result with
  | error _ => exact Or.inl (congrArg (fun db => rows db "heads") openedDb)
  | ok tx =>
    have began := OperationExecution.raise_success (fun _ _ => rfl) Promote.Error.host Storage.begin state opened tx started
    have snapshot := ReconciliationFloor.begin_pending state opened tx began
    dsimp only [ExceptT.bindCont, ExceptT.run]
    rw [execute_bind, attempted]
    generalize preparedRead : execute (PromotionCommand.prepare tx origin now) opened = preparation
    obtain ⟨result, ready⟩ := preparation
    have readyDb : ready.db = state.db := by
      have frame := (PromotionCommand.prepare_only tx origin now).preserves_db _ PromotionReads.effects_db opened
      change (execute (PromotionCommand.prepare tx origin now) opened).2.db = opened.db at frame
      rw [preparedRead] at frame
      exact frame.trans openedDb
    cases result with
    | error error =>
      left
      dsimp only [ExceptT.bindCont, ExceptT.run]
      rw [execute_bind, attempted]
      have rollbackDb : (execute (Promote.raw (.rollback tx)) ready).2.db = ready.db := by
        apply reply_preserves_db
        intro s
        split
        · split <;> rfl
        · rfl
      change rows (execute (Promote.raw (.rollback tx)) ready).2.db "heads" = rows state.db "heads"
      rw [rollbackDb, readyDb]
    | ok value =>
      right
      have readySnapshot := PromotionReads.executed_pending _ (PromotionCommand.prepare_only tx origin now)
        opened ready value preparedRead
      exact ⟨⟨tx, opened, ready, value, started, preparedRead, readySnapshot.trans snapshot, readyDb⟩, rfl⟩

end Synchronicity.PromotionExecution
