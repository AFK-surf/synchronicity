import VerifiedCore.Trie.Fetch
import Synchronicity.SimulatedHost
import Std.Data.HashSet.Lemmas

/-! Properties of the whole executable requesting operation. The host is the
shared raw interpreter: byte reads and admission writes use the same database,
including its pending transaction. These checks do not yet prove general
coverage or convergence under a fair scheduler. -/
namespace Synchronicity.TrieFetchProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie SimulatedHost

@[simp] private theorem throw_eq (error : Fetch.Error) :
    (@MonadExceptOf.throw Fetch.Error (ExceptT Fetch.Error (Program Fetch.Effects)) _ A error) =
      (Program.pure (Except.error error) : Program Fetch.Effects (Except Fetch.Error A)) := rfl

/-- With no outstanding requests, a one-item answer cannot insert data into
a replica, for arbitrary payloads and pre-existing database contents. The
production hash-set implementation rejects it and closes the transaction. -/
theorem unsolicited_data_changes_no_stored_data (target : Fetch.Target) (values : Bool)
    (hash payload : ByteArray) (state : State) (quiet : state.faults = [])
    (idle : state.pending = none) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target values [] [(hash, payload)]) state
    result.1 = .error (.unsolicited values hash) ∧ result.2.db = state.db ∧
      result.2.pending = none := by
  simp [SimulatedHost.run, Fetch.admit, transactionOver, Fetch.request,
    raise, performOver, Inject.inject, bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.mk, ExceptT.run, throw, throwThe, MonadExcept.throw, execute, Program.bind, Interpreter.handle,
    storage, reply, fault, quiet, idle, record, Missing.WorkSet.empty,
    Missing.WorkSet.contains, pure, ExceptT.pure, Except.mapError]

local instance : LawfulHashable ByteArray :=
  ⟨fun {a b} (same : (a == b) = true) => by rw [eq_of_beq same]⟩

/-- A one-value answer whose bytes do not match its requested address cannot
alter previously committed data. Rejection closes the transaction. -/
theorem corrupt_value_changes_no_stored_data (target : Fetch.Target)
    (holder hash payload : ByteArray) (state : State) (quiet : state.faults = [])
    (idle : state.pending = none) (corrupt : state.hash payload ≠ hash) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target true [(holder, hash)] [(hash, payload)]) state
    result.1 = .error (.valueHash hash) ∧ result.2.db = state.db ∧
      result.2.pending = none := by
  simp [SimulatedHost.run, Fetch.admit, transactionOver, Fetch.request,
    raise, performOver, Inject.inject, bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.mk, ExceptT.run, throw, throwThe, MonadExcept.throw, execute, Program.bind, Interpreter.handle,
    storage, reply, fault, quiet, idle, record, Missing.WorkSet.empty,
    Missing.WorkSet.contains, Missing.WorkSet.insert, Missing.WorkSet.erase,
    pure, ExceptT.pure, Except.mapError, SimulatedHost.digest, corrupt]

/-- A duplicated item rejects the whole reply, including the valid value
written before the duplicate was encountered. Earlier replies stay committed. -/
theorem duplicate_value_rolls_back_the_whole_reply (target : Fetch.Target)
    (holder hash payload : ByteArray) (state : State) (quiet : state.faults = [])
    (idle : state.pending = none) (valid : state.hash payload = hash)
    (large : inlineValueMax < payload.size) (bounded : payload.size ≤ maxValueBytes) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target true [(holder, hash)]
        [(hash, payload), (hash, payload)]) state
    result.1 = .error (.unsolicited true hash) ∧ result.2.db = state.db ∧
      result.2.pending = none := by
  simp [SimulatedHost.run, Fetch.admit, transactionOver, Fetch.request,
    raise, performOver, Inject.inject, bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.mk, ExceptT.run, throw, throwThe, MonadExcept.throw, execute, Program.bind, Interpreter.handle,
    storage, SimulatedHost.transaction, reply, fault, quiet, idle, record, Missing.WorkSet.empty,
    Missing.WorkSet.contains, Missing.WorkSet.insert, Missing.WorkSet.erase,
    pure, ExceptT.pure, Except.mapError, SimulatedHost.digest, valid, large, bounded]

/-- Admission writes the raw value relation, commits, and leaves the byte
backend configuration intact. This execution lemma retains existing rows:
conflicting addresses obey the store's immutable-row policy. -/
private theorem value_admission_execution (target : Fetch.Target)
    (holder hash payload : ByteArray) (state : State) (quiet : state.faults = [])
    (idle : state.pending = none) (valid : state.hash payload = hash)
    (large : inlineValueMax < payload.size) (bounded : payload.size ≤ maxValueBytes) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target true [(holder, hash)] [(hash, payload)]) state
    result.1 = .ok 1 ∧ result.2.db = setRows state.db valueSpace
      (upsertRows (rows state.db valueSpace) [("hash", .blob hash), ("data", .blob payload)] ["hash"] []) ∧
      result.2.pending = none ∧ result.2.byteRelations = state.byteRelations ∧
      result.2.files = state.files := by
  simp [SimulatedHost.run, Fetch.admit, transactionOver, Fetch.request,
    raise, performOver, Inject.inject, bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.mk, ExceptT.run, execute, Program.bind, Interpreter.handle,
    storage, SimulatedHost.transaction, reply, fault, quiet, idle, record, Missing.WorkSet.empty,
    Missing.WorkSet.contains, Missing.WorkSet.insert, Missing.WorkSet.erase,
    pure, ExceptT.pure, Except.mapError, SimulatedHost.digest, valid, large, bounded]

private theorem fresh_value_row_is_readable (db : Database) (hash payload : ByteArray)
    (fresh : relationBytes db valueSpace hash = .ok none) :
    relationBytes (setRows db valueSpace
      (upsertRows (rows db valueSpace) [("hash", .blob hash), ("data", .blob payload)] ["hash"] []))
      valueSpace hash = .ok (some payload) := by
  have missing : (rows db valueSpace).find? (fun row => cell row "hash" == .blob hash) = none := by
    cases found : (rows db valueSpace).find? (fun row => cell row "hash" == .blob hash) with
    | none => rfl
    | some row =>
      simp only [relationBytes, found] at fresh
      cases data : cell row "data" <;> simp_all
  have distinct : ∀ row ∈ rows db valueSpace, cell row "hash" ≠ .blob hash := by
    simpa using (List.find?_eq_none.mp missing)
  have noConflict : (rows db valueSpace).any
      (conflict ["hash"] [("hash", .blob hash), ("data", .blob payload)]) = false := by
    apply List.any_eq_false.mpr
    intro row member
    have different := distinct row member
    simp only [conflict, List.all_cons, List.all_nil, Bool.and_true, cell,
      List.find?_cons, beq_self_eq_true, Option.map_some, Option.getD_some]
    change ¬ equalCell (.blob hash) (cell row "hash") = true
    generalize cell row "hash" = value at different ⊢
    cases value <;> simp [equalCell, beq_iff_eq] at different ⊢
    exact Ne.symm different
  simp only [relationBytes, rows_setRows, upsertRows_doNothing, noConflict, Bool.false_eq_true,
    ↓reduceIte, List.find?_append, missing]
  simp [cell]

/-- A fresh, valid requested value is readable after admission through the
same SQL-backed byte service used by the next missing-data inspection. No
second copy in the file service is needed or created. Other rows are arbitrary. -/
theorem admitted_value_is_readable_by_the_next_inspection (target : Fetch.Target)
    (holder hash payload : ByteArray) (state : State) (quiet : state.faults = [])
    (idle : state.pending = none) (valid : state.hash payload = hash)
    (large : inlineValueMax < payload.size) (bounded : payload.size ≤ maxValueBytes)
    (nodesBackend : state.byteRelations.contains nodeSpace = true)
    (valuesBackend : state.byteRelations.contains valueSpace = true)
    (fresh : relationBytes state.db valueSpace hash = .ok none) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target true [(holder, hash)] [(hash, payload)]) state
    result.1 = .ok 1 ∧ readByteObject result.2 valueSpace hash = .ok (some payload) ∧
      result.2.pending = none ∧ result.2.files = state.files ∧
      result.2.byteRelations.contains nodeSpace = true := by
  obtain ⟨accepted, database, closed, backend, files⟩ :=
    value_admission_execution target holder hash payload state quiet idle valid large bounded
  refine ⟨accepted, ?_, closed, files, by simpa [backend] using nodesBackend⟩
  simp only [readByteObject, backend, valuesBackend, ↓reduceIte, closed,
    Option.map_none, Option.getD_none, database]
  exact fresh_value_row_is_readable state.db hash payload fresh

end Synchronicity.TrieFetchProofs
