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

end Synchronicity.TrieFetchProofs
