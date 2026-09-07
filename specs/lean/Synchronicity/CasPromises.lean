import Synchronicity.CasLifecycleProofs
import Synchronicity.CasReadProgramProofs

/-! User-facing CAS lifecycle promises on actual stored state. -/
namespace Synchronicity.CasPromises
open VerifiedCore

open VerifiedCore.Host VerifiedCore.Cas SimulatedHost

/-- A cancelled request stays cancelled in the shared database. The raw
observation is decoded by the production operation inside its transaction. -/
theorem a_cancelled_request_stays_cancelled (root : ByteArray) (holder : String)
    (now : Int64) (state : State) (durable : Bool)
    (quiet : state.faults = []) (idle : state.pending = none)
    (decoded : decodeDurability (query state.db "blobs" ["durable"] [("root", .blob root)] [] []) = .ok durable)
    (cancelled : query state.db "content_want" ["root"] [("root", .blob root), ("holder", .text holder)] [] [] = []) :
    let result := SimulatedHost.run (acquire root holder now true) state
    result.1 = .ok false ∧ result.2.db = state.db := by
  cases durable <;>
    simp [SimulatedHost.run, acquire, acquireIn, transactionWith, transactionOver,
      request, performWith, execute, Interpreter.handle, storage, reply, fault, record,
      SimulatedHost.transaction, quiet, idle, decoded, cancelled, Except.mapError,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

set_option maxHeartbeats 2000000 in
/-- Kept content is protected from collection: neither the database nor files
change. The host computes protection from actual rows and writer counters. -/
theorem kept_content_is_protected_from_collection (root : ByteArray) (before : Option Int64)
    (state : State) (accessed : Option Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (decoded : decodeAccess (query state.db "blobs" ["last_access"] [("root", .blob root)] [] []) = .ok accessed)
    (kept : (rows state.db "pins").any (fun row => equals row [("root", .blob root)]) = true ∨
      (rows state.db "entries").any (fun row => equals row [("content", .blob root)]) = true ∨
      counter state ("cas_writers", root) ≠ 0) :
    let result := SimulatedHost.run (delete root before) state
    result.1 ≠ .ok .applied ∧ result.2.db = state.db ∧ result.2.files = state.files := by
  generalize hp : (rows state.db "pins").any (fun row => equals row [("root", .blob root)]) = pinned at kept
  generalize hr : (rows state.db "entries").any (fun row => equals row [("content", .blob root)]) = referenced at kept
  cases pinned <;> cases referenced <;>
    by_cases writing : counter state ("cas_writers", root) = 0 <;>
    simp only [Bool.false_eq_true, false_or] at kept <;> (try contradiction)
  all_goals unfold counter at writing
  all_goals simp (config := { maxSteps := 100000 }) [SimulatedHost.run, delete, deleteIn, transactionWith, transactionOver,
      request, performWith, execute, Interpreter.handle, storage, reply, fault, record,
      SimulatedHost.transaction, counter, planLifecycle, Except.mapError,
      quiet, idle, decoded, hp, hr, writing,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

end Synchronicity.CasPromises
