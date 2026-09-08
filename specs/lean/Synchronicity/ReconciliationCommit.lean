import VerifiedCore.Replication.Promote
import Synchronicity.SimulatedHost

/-! The executed promotion's commit boundary over arbitrary staged database
contents. Atomic publication is not yet the exact-view theorem: this file does
not assume that completing a walk establishes the permitted view. -/
namespace Synchronicity.ReconciliationCommit
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost

/-- Every staged relation is published together, including the head, entries,
bindings, wants and pins. No relation-by-relation publication is possible. -/
theorem finish_success (tx : Transaction) (pending : Option Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (promotion : Promotion)
    (state : State) (staged : Database) (opened : state.pending = some (tx, staged))
    (healthy : state.faults = []) :
    (run (Promote.finish tx pending key (.ok promotion)) state).1 =
        .ok ⟨promotion, none, none⟩ ∧
    (run (Promote.finish tx pending key (.ok promotion)) state).2.db = staged ∧
    (run (Promote.finish tx pending key (.ok promotion)) state).2.pending = none := by
  simp [run, Promote.finish, Promote.attempt, Promote.raw, raise, performOver,
    Inject.inject, ExceptT.mk, execute, Interpreter.handle, storage, reply, fault,
    healthy, opened, record, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.run,
    pure, ExceptT.pure, Program.bind, Except.mapError, Functor.map]

/-- A domain body's host failure rolls back even a partially materialized
database; no accepted relation is changed and the original error is retained. -/
theorem finish_host_failure (tx : Transaction) (pending : Option Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (failure : Failure)
    (state : State) (staged : Database) (opened : state.pending = some (tx, staged))
    (healthy : state.faults = []) :
    (run (Promote.finish tx pending key (.error (.host failure))) state).1 = .error (.host failure) ∧
    (run (Promote.finish tx pending key (.error (.host failure))) state).2.db = state.db ∧
    (run (Promote.finish tx pending key (.error (.host failure))) state).2.pending = none := by
  simp [run, Promote.finish, Promote.attempt, Promote.raw, raise, performOver,
    Inject.inject, ExceptT.mk, execute, Interpreter.handle, storage, reply, fault,
    healthy, opened, record, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.run,
    Program.bind, Except.mapError, Functor.map]
  exact ⟨rfl, rfl, rfl⟩

/-- A failed commit never publishes even part of the staged view. The rollback
reply may also fail; this theorem does not turn that into successful promotion
or assume the host reports a closed transaction in that case. -/
theorem finish_commit_failure (tx : Transaction) (pending : Option Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (promotion : Promotion)
    (state : State) (failure : Failure)
    (failed : fault { state with output := [] } = some failure) :
    (run (Promote.finish tx pending key (.ok promotion)) state).1 = .error (.host failure) ∧
    (run (Promote.finish tx pending key (.ok promotion)) state).2.db = state.db := by
  simp [run, Promote.finish, Promote.attempt, Promote.raw, raise, performOver,
    Inject.inject, ExceptT.mk, execute, Interpreter.handle, storage, reply,
    failed, record, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.run,
    Program.bind, Except.mapError, Functor.map]
  split <;> simp only
  all_goals
    repeat' first | exact ⟨rfl, rfl⟩ | split

/-- A retryable metadata failure has the same all-or-nothing behavior as a
host failure, and does not retire the pending target. -/
theorem finish_retryable_failure (tx : Transaction) (pending : Option Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (failure : Commands.ReconcileDomainError)
    (retryable : Promote.originFault failure = false)
    (state : State) (staged : Database) (opened : state.pending = some (tx, staged))
    (healthy : state.faults = []) :
    (run (Promote.finish tx pending key (.error (.domain failure))) state).1 = .error (.domain failure) ∧
    (run (Promote.finish tx pending key (.error (.domain failure))) state).2.db = state.db ∧
    (run (Promote.finish tx pending key (.error (.domain failure))) state).2.pending = none := by
  simp [run, Promote.finish, Promote.attempt, Promote.raw, raise, performOver,
    Inject.inject, ExceptT.mk, execute, Interpreter.handle, storage, reply, fault,
    healthy, opened, record, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.run,
    Program.bind, Except.mapError, Functor.map, retryable]
  exact ⟨rfl, rfl, rfl⟩

/-- A published-record refusal discards all staged changes before deleting
only the captured pending row from the original committed database. -/
theorem finish_origin_failure (tx : Transaction) (pending : Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (failure : Commands.ReconcileDomainError)
    (refused : Promote.originFault failure = true)
    (state : State) (staged : Database) (opened : state.pending = some (tx, staged))
    (healthy : state.faults = []) :
    (run (Promote.finish tx (some pending) key (.error (.domain failure))) state).1 =
      .ok ⟨.refused, some failure, key⟩ ∧
    (run (Promote.finish tx (some pending) key (.error (.domain failure))) state).2.db =
      setRows state.db "heads" ((rows state.db "heads").filter fun row =>
        !equals row (Reconcile.headKey pending.head ++ [("slot", .text "pending")])) ∧
    (run (Promote.finish tx (some pending) key (.error (.domain failure))) state).2.pending = none := by
  simp [run, Promote.finish, Promote.retire, transactionOver, Promote.attempt, Promote.raw,
    raise, performOver, Inject.inject, ExceptT.mk, execute, Interpreter.handle,
    storage, reply, fault, healthy, opened, record, SimulatedHost.transaction,
    bind, ExceptT.bind, ExceptT.bindCont, ExceptT.run, pure, ExceptT.pure,
    Program.bind, Except.mapError, Functor.map, refused, deletable, excluded, due]

theorem refused_view_is_not_partially_published (tx : Transaction) (pending : Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (failure : Commands.ReconcileDomainError)
    (refused : Promote.originFault failure = true)
    (state : State) (staged : Database) (opened : state.pending = some (tx, staged))
    (healthy : state.faults = []) (relation : String) (other : "heads" ≠ relation) :
    rows (run (Promote.finish tx (some pending) key (.error (.domain failure))) state).2.db relation =
      rows state.db relation := by
  rw [(finish_origin_failure tx pending key failure refused state staged opened healthy).2.1]
  exact rows_setRows_other _ _ _ _ other

end Synchronicity.ReconciliationCommit
