import Synchronicity.PromotionBound
import Synchronicity.ReconciliationFloor

/-! Whole-command promotion safety, from the initial raw complete slot to
the committed version after any result. Readiness is not assumed to mean an
exact permitted view here; that separate obligation belongs to M4. -/
namespace Synchronicity.PromotionCommand
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase
open TransactionSuccess (bind_success)

abbrev Prepared := Trie.Serve.Scope × Authorization.OriginAuthority × Option Promote.Pending × Option Promote.Pending

/-- A definitional name for the preparation already inside production promote. -/
def prepare (tx : Transaction) (origin : Origin.Parsed) (now : Int64) : Promote.Action Prepared := do
  let scope ← Promote.auth (Authorization.materializationScopeIn tx origin)
  let authority ← Promote.auth (Authorization.originAuthorityIn tx origin now)
  let pending ← Promote.slot tx origin "pending"
  let old ← if pending.isSome then Promote.slot tx origin "complete" else pure none
  return (scope, authority, pending, old)

theorem prepare_only (tx : Transaction) (origin : Origin.Parsed) (now : Int64) :
    Only PromotionReads.allowed (prepare tx origin now).run := by
  unfold prepare
  refine (PromotionReads.auth_only _ (ReconciliationReadOnly.scope_only tx origin)).seq fun scope => ?_
  refine (PromotionReads.auth_only _ (ReconciliationReadOnly.originAuthority_only tx origin now)).seq fun authority => ?_
  refine (PromotionReads.slot_only tx origin "pending").seq fun pending => ?_
  split
  · exact (PromotionReads.slot_only tx origin "complete").seq fun _ => .done _
  · exact Only.seq (.done _) fun _ => .done _

theorem prepare_floor (tx : Transaction) (origin : Origin.Parsed) (now : Int64) (state final : State)
    (db : Database) (opened : state.pending = some (tx, db)) (seq : Int64) (root : ByteArray)
    (stored : ReconciliationRead.StoredFloor db (Origin.canonical origin) "complete" seq root)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (pending old : Option Promote.Pending)
    (executed : execute (prepare tx origin now) state = (.ok (scope, authority, pending, old), final)) :
    ∀ current, pending = some current → current.head.origin = origin ∧
      ∃ previous, old = some previous ∧ previous.head.seq = seq.toUInt64 ∧ previous.head.root = root := by
  unfold prepare at executed
  obtain ⟨scopeRead, scopeState, readScope, executed⟩ := bind_success _ _ _ _ _ executed
  have scopeFrame := PromotionReads.executed_pending _
    (PromotionReads.auth_only _ (ReconciliationReadOnly.scope_only tx origin)) _ _ _ readScope
  obtain ⟨authorityRead, authorized, readAuthority, executed⟩ := bind_success _ _ _ _ _ executed
  have authorityFrame := PromotionReads.executed_pending _
    (PromotionReads.auth_only _ (ReconciliationReadOnly.originAuthority_only tx origin now)) _ _ _ readAuthority
  obtain ⟨pendingRead, selected, readPending, executed⟩ := bind_success _ _ _ _ _ executed
  have pendingFrame := PromotionReads.executed_pending _ (PromotionReads.slot_only tx origin "pending") _ _ _ readPending
  cases pendingRead with
  | none =>
    have same : (scopeRead, authorityRead, none, none) = (scope, authority, pending, old) :=
      Except.ok.inj (congrArg Prod.fst executed)
    cases same
    intro current impossible
    cases impossible
  | some current =>
    have originSame := PromotionReads.slot_origin tx origin "pending" authorized current (congrArg Prod.fst readPending)
    obtain ⟨oldRead, _, readOld, returned⟩ := bind_success _ _ _ _ _ executed
    have snapshot : selected.pending = some (tx, db) := by
      rw [pendingFrame, authorityFrame, scopeFrame, opened]
    obtain ⟨previous, oldSome, previousSeq, previousRoot⟩ := PromotionReads.slot_floor tx origin "complete"
      selected db snapshot seq root stored oldRead (congrArg Prod.fst readOld)
    have same : (scopeRead, authorityRead, some current, oldRead) = (scope, authority, pending, old) :=
      Except.ok.inj (congrArg Prod.fst returned)
    cases same
    intro candidate equal
    cases equal
    exact ⟨originSame, previous, oldSome, previousSeq, previousRoot⟩

/-- The candidate used by promotion is the pending version in its own raw
transaction snapshot, not a version supplied by a completed network request. -/
theorem prepare_pending_floor (tx : Transaction) (origin : Origin.Parsed) (now : Int64) (state final : State)
    (db : Database) (opened : state.pending = some (tx, db)) (seq : Int64) (root : ByteArray)
    (stored : ReconciliationRead.StoredFloor db (Origin.canonical origin) "pending" seq root)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (pending old : Option Promote.Pending)
    (executed : execute (prepare tx origin now) state = (.ok (scope, authority, pending, old), final)) :
    ∃ current, pending = some current ∧ current.head.seq = seq.toUInt64 ∧ current.head.root = root := by
  unfold prepare at executed
  obtain ⟨scopeRead, scopeState, readScope, executed⟩ := bind_success _ _ _ _ _ executed
  have scopeFrame := PromotionReads.executed_pending _
    (PromotionReads.auth_only _ (ReconciliationReadOnly.scope_only tx origin)) _ _ _ readScope
  obtain ⟨authorityRead, authorized, readAuthority, executed⟩ := bind_success _ _ _ _ _ executed
  have authorityFrame := PromotionReads.executed_pending _
    (PromotionReads.auth_only _ (ReconciliationReadOnly.originAuthority_only tx origin now)) _ _ _ readAuthority
  obtain ⟨pendingRead, selected, readPending, executed⟩ := bind_success _ _ _ _ _ executed
  have snapshot : authorized.pending = some (tx, db) := by rw [authorityFrame, scopeFrame, opened]
  obtain ⟨current, pendingSome, currentSeq, currentRoot⟩ := PromotionReads.slot_floor tx origin "pending"
    authorized db snapshot seq root stored pendingRead (congrArg Prod.fst readPending)
  subst pendingRead
  obtain ⟨oldRead, _, _, returned⟩ := bind_success _ _ _ _ _ executed
  have same : (scopeRead, authorityRead, some current, oldRead) = (scope, authority, pending, old) :=
    Except.ok.inj (congrArg Prod.fst returned)
  cases same
  exact ⟨current, rfl, currentSeq, currentRoot⟩

/-- A pending candidate returned by preparation was selected from an actual raw
pending row in the transaction's initial database. -/
theorem prepare_pending_selected (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (pending old : Option Promote.Pending)
    (executed : execute (prepare tx origin now) state =
      (.ok (scope, authority, pending, old), final)) :
    ∀ current, pending = some current →
      ∃ row ∈ rows db "heads",
        ReconciliationSlots.names row (Origin.canonical origin) "pending" = true := by
  unfold prepare at executed
  obtain ⟨scopeRead, scopeState, readScope, executed⟩ :=
    bind_success _ _ _ _ _ executed
  have scopeFrame := PromotionReads.executed_pending _
    (PromotionReads.auth_only _ (ReconciliationReadOnly.scope_only tx origin)) _ _ _ readScope
  obtain ⟨authorityRead, authorized, readAuthority, executed⟩ :=
    bind_success _ _ _ _ _ executed
  have authorityFrame := PromotionReads.executed_pending _
    (PromotionReads.auth_only _ (ReconciliationReadOnly.originAuthority_only tx origin now))
      _ _ _ readAuthority
  obtain ⟨pendingRead, selected, readPending, executed⟩ :=
    bind_success _ _ _ _ _ executed
  have snapshot : authorized.pending = some (tx, db) := by
    rw [authorityFrame, scopeFrame, opened]
  cases pendingRead with
  | none =>
      have same : (scopeRead, authorityRead, none, none) =
          (scope, authority, pending, old) :=
        Except.ok.inj (congrArg Prod.fst executed)
      cases same
      intro current impossible
      cases impossible
  | some candidate =>
      obtain ⟨oldRead, _, _, returned⟩ := bind_success _ _ _ _ _ executed
      have same : (scopeRead, authorityRead, some candidate, oldRead) =
          (scope, authority, pending, old) :=
        Except.ok.inj (congrArg Prod.fst returned)
      cases same
      intro current selectedCurrent
      cases Option.some.inj selectedCurrent
      exact PromotionReads.slot_selected tx origin "pending" authorized db snapshot candidate
        (congrArg Prod.fst readPending)

theorem attempt_eq (operation : Promote.Action A) (state : State) :
    execute (Promote.attempt operation).run state = (.ok (execute operation state).1, (execute operation state).2) := by
  change execute (operation.run.bind (fun result => .pure (.ok result : Except Promote.Error (Except Promote.Error A)))) state = _
  rw [execute_bind]
  rfl

theorem promote_preserves_complete_floor (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state : State)
    (closed : state.pending = none) (seq : Int64) (root : ByteArray)
    (stored : ReconciliationRead.StoredFloor state.db (Origin.canonical origin) "complete" seq root) :
    PromotionBound.good (Origin.canonical origin) ⟨seq.toUInt64, root⟩
      (rows (execute (Promote.promote origin now refused) state).2.db "heads") := by
  let predicate := PromotionBound.good (Origin.canonical origin) (⟨seq.toUInt64, root⟩ : History.Pointer)
  have initial : HeadInvariant.holds predicate state :=
    HeadInvariant.closed predicate state closed (PromotionBound.stored_good state.db _ seq root stored)
  suffices HeadInvariant.holds predicate (execute (Promote.promote origin now refused) state).2 from this.1
  unfold Promote.promote
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
  generalize started : execute (Promote.raw .begin) state = start
  obtain ⟨result, opened⟩ := start
  have openedGood : HeadInvariant.holds predicate opened := by
    have kept := HeadInvariant.begin_holds predicate state initial
    have same : opened = (storage .begin state).2 := (congrArg Prod.snd started).symm
    rw [same]
    exact kept
  cases result with
  | error error => exact openedGood
  | ok tx =>
    have rawBegin := OperationExecution.raise_success (fun _ _ => rfl) Promote.Error.host Storage.begin state opened tx started
    have snapshot : opened.pending = some (tx, state.db) := ReconciliationFloor.begin_pending state opened tx rawBegin
    change HeadInvariant.holds predicate (execute
      ((Promote.attempt (prepare tx origin now)).run.bind _) opened).2
    rw [execute_bind, attempt_eq]
    generalize prepared : execute (prepare tx origin now) opened = preparation
    obtain ⟨result, ready⟩ := preparation
    have readyGood : HeadInvariant.holds predicate ready := by
      have safe := PromotionBound.reads_only (Origin.canonical origin) ⟨seq.toUInt64, root⟩ _ (prepare_only tx origin now)
      have kept := safe.invariant (HeadInvariant.holds predicate) (fun _ good => good) opened openedGood
      change HeadInvariant.holds predicate (execute (prepare tx origin now) opened).2 at kept
      simpa only [prepared] using kept
    cases result with
    | error error =>
      apply Only.invariant (allowed := PromotionBound.safe (Origin.canonical origin) ⟨seq.toUInt64, root⟩)
        (HeadInvariant.holds predicate) _ (fun _ good => good) ready readyGood
      exact Only.seq (Only.bind (Only.raise Promote.Error.host (Storage.rollback tx)
        (HeadInvariant.rollback_holds predicate tx)) fun _ => .done _) fun _ => .done _
    | ok tuple =>
      obtain ⟨scope, authority, pending, old⟩ := tuple
      have floors := prepare_floor tx origin now opened ready state.db snapshot seq root stored scope authority pending old prepared
      apply Only.invariant (allowed := PromotionBound.safe (Origin.canonical origin) ⟨seq.toUInt64, root⟩)
        (HeadInvariant.holds predicate) _ (fun _ good => good) ready readyGood
      dsimp only [pure, ExceptT.pure, Program.bind, ExceptT.bindCont]
      apply Only.seq
      · apply Only.bind
        · cases pending with
          | none => exact .done _
          | some current =>
            obtain ⟨sameOrigin, previous, oldSome, previousSeq, previousRoot⟩ := floors current rfl
            rw [oldSome]
            dsimp only
            split
            · exact (PromotionBound.clear_only origin _ tx).seq fun _ => .done _
            · apply PromotionBound.body_only origin _ tx now current previous sameOrigin
              simp only [previousSeq, previousRoot]
        · intro _; exact .done _
      · intro result
        exact PromotionBound.finish_only (Origin.canonical origin) _ tx pending _ result

end Synchronicity.PromotionCommand
