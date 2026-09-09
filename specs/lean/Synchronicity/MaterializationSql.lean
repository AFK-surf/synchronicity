import Synchronicity.MaterializationRetention

/-! Raw relational meaning of the materializer's SQL primitives. These
lemmas admit arbitrary unrelated rows and injected faults. On success they
identify the actual private database, rather than assuming a projection delta. -/
namespace Synchronicity.MaterializationSql
open VerifiedCore VerifiedCore.Host Replication SimulatedHost

def written (db : Database) (table : String) (key values : Fields) (preserve : Bool) : Database :=
  setRows db table (upsertRows (rows db table) (key ++ values) (key.map (·.1))
    ((if preserve then [] else values.map (·.1)).map fun column => (column, .excluded column)))

def erased (db : Database) (table : String) (key : Fields) : Database :=
  setRows db table ((rows db table).filter (fun row => !equals row key))

def updated (db : Database) (table : String) (key values : Fields) : Database :=
  setRows db table ((rows db table).map fun row => if equals row key then assign row values else row)

theorem write_state (tx : Transaction) (table : String) (key values : Fields) (preserve : Bool)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (ran : execute (Materialize.write tx table key values preserve) state = (.ok (), final)) :
    final = record {state with pending := some (tx, written db table key values preserve)} ("upsert:" ++ table) := by
  simp only [Materialize.write, Materialize.raw, raise, performOver, Inject.inject, ExceptT.mk,
    execute, Interpreter.handle, storage, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError] at ran
  | none =>
    simp only [failed, SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte,
      Except.mapError, Prod.mk.injEq, true_and] at ran
    exact ran.symm

theorem erase_state (tx : Transaction) (table : String) (key : Fields)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (ran : execute (Materialize.erase tx table key) state = (.ok (), final)) :
    final = record {state with pending := some (tx, erased db table key)} ("delete:" ++ table) := by
  simp only [Materialize.erase, Materialize.raw, raise, performOver, Inject.inject, ExceptT.mk,
    bind, ExceptT.bind, ExceptT.bindCont, execute_bind, execute, Interpreter.handle, storage, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError, pure, execute] at ran
  | none =>
    simp only [failed, SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte,
      Except.mapError, pure, ExceptT.pure, ExceptT.mk, execute] at ran
    have same := (congrArg Prod.snd ran).symm
    simpa only [erased, deletable, excluded, due, List.any_nil, List.all_nil, Bool.not_false, Bool.and_true] using same

theorem update_state (tx : Transaction) (table : String) (key values : Fields)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (ran : execute (Materialize.update tx table key values) state = (.ok (), final)) :
    final = record {state with pending := some (tx, updated db table key values)} ("update:" ++ table) := by
  simp only [Materialize.update, raise, performOver, Inject.inject, ExceptT.mk,
    bind, ExceptT.bind, ExceptT.bindCont, execute_bind, execute, Interpreter.handle, access, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError, pure, execute] at ran
  | none =>
    simp only [failed, SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte,
      Except.mapError, pure, ExceptT.pure, ExceptT.mk, execute] at ran
    have same := (congrArg Prod.snd ran).symm
    simpa only [updated, selects, List.isEmpty_nil, Bool.true_or, List.all_nil, Bool.and_true] using same

theorem exists_state (tx : Transaction) (table : String) (key : Fields)
    (state final : State) (db : Database) (answer : Bool) (opened : state.pending = some (tx, db))
    (ran : execute (Materialize.raw (.existsRows tx table key)) state = (.ok answer, final)) :
    answer = (rows db table).any (fun row => equals row key) ∧ final = record state ("exists:" ++ table) := by
  simp only [Materialize.raw, raise, performOver, Inject.inject, ExceptT.mk,
    execute, Interpreter.handle, storage, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError] at ran
  | none =>
    simp only [failed, SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte,
      Except.mapError, Prod.mk.injEq, Except.ok.injEq] at ran
    exact ⟨ran.1.symm, by simpa only [← opened] using ran.2.symm⟩

theorem read_state (tx : Transaction) (table : String) (columns : List String) (key : Fields)
    (state final : State) (db : Database) (answer : List Row) (opened : state.pending = some (tx, db))
    (ran : execute (Materialize.raw (.readRows tx table columns key)) state = (.ok answer, final)) :
    answer = query db table columns key [] [] ∧ final = record state ("read:" ++ table) := by
  simp only [Materialize.raw, raise, performOver, Inject.inject, ExceptT.mk,
    execute, Interpreter.handle, storage, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError] at ran
  | none =>
    simp only [failed, SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte,
      Except.mapError, Prod.mk.injEq, Except.ok.injEq] at ran
    exact ⟨ran.1.symm, by simpa only [← opened] using ran.2.symm⟩

end Synchronicity.MaterializationSql
