import VerifiedCore.Replication.Promote
import VerifiedCore.Trie.Fetch
import Synchronicity.SimulatedHost

/-! Exact-target SQL semantics used by suspended reconciliation. The database
at resumption is arbitrary: in particular, it need not be the database from
which the continuation selected its target. These are safety results, not a
fairness or permission-change theorem. -/
namespace Synchronicity.ReconciliationTargets
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie SimulatedHost

/-- Observe every row not belonging to the captured pending target, including
its timestamps. This protects different roots at the same sequence as well as
different sequences, origins and the complete slot. -/
def otherHeads (target : Fetch.Target) (db : Database) : List Fields :=
  (rows db "heads").filter fun row => !equals row (Fetch.targetRows target)

/-- This executes the production abandonment command on arbitrary committed
rows. Thus a replacement committed during a peer wait is the starting state,
not an assumed unchanged selection snapshot. -/
theorem abandon_exact (target : Fetch.Target) (state : State)
    (closed : state.pending = none) (healthy : state.faults = []) :
    (run (Fetch.abandon target) state).1 = .ok () ∧
    (run (Fetch.abandon target) state).2.pending = none ∧
    (run (Fetch.abandon target) state).2.db =
      setRows state.db "heads" (otherHeads target state.db) := by
  simp [run, Fetch.abandon, transactionOver, Fetch.request, raise, performOver,
    Inject.inject, ExceptT.mk, execute, Interpreter.handle, storage, reply, fault,
    healthy, closed, record, SimulatedHost.transaction, otherHeads, deletable, excluded, due,
    bind, ExceptT.bind, ExceptT.bindCont, ExceptT.run, pure, ExceptT.pure,
    Program.bind, Except.mapError]

theorem abandon_preserves_other_heads (target : Fetch.Target) (state : State)
    (closed : state.pending = none) (healthy : state.faults = []) :
    otherHeads target (run (Fetch.abandon target) state).2.db = otherHeads target state.db := by
  rw [(abandon_exact target state closed healthy).2.2]
  simp [otherHeads, List.filter_filter]

theorem abandon_preserves_other_relations (target : Fetch.Target) (state : State)
    (closed : state.pending = none) (healthy : state.faults = [])
    (relation : String) (other : "heads" ≠ relation) :
    rows (run (Fetch.abandon target) state).2.db relation = rows state.db relation := by
  rw [(abandon_exact target state closed healthy).2.2]
  exact rows_setRows_other _ _ _ _ other

theorem touch_exact (target : Fetch.Target) (state : State)
    (closed : state.pending = none) (healthy : state.faults = []) :
    (run (Fetch.touch target) state).1 = .ok () ∧
    (run (Fetch.touch target) state).2.pending = none ∧
    (run (Fetch.touch target) state).2.db = setRows state.db "heads"
      ((rows state.db "heads").map fun row =>
        if equals row (Fetch.targetRows target) then
          assign row [("received_at", .integer state.now)] else row) := by
  simp [run, Fetch.touch, transactionOver, Fetch.request, raise, performOver,
    Inject.inject, ExceptT.mk, execute, Interpreter.handle, storage, access, clock,
    reply, fault, healthy, closed, record, SimulatedHost.transaction, selects,
    bind, ExceptT.bind, ExceptT.bindCont, ExceptT.run, pure, ExceptT.pure,
    Program.bind, Except.mapError]

/-- Even the progress timestamp of a replacement is not extended by a stale
worker. Membership is of the entire original row, not just its version key. -/
theorem touch_preserves_other_head (target : Fetch.Target) (state : State)
    (closed : state.pending = none) (healthy : state.faults = [])
    (row : Fields) (present : row ∈ rows state.db "heads")
    (different : equals row (Fetch.targetRows target) = false) :
    row ∈ rows (run (Fetch.touch target) state).2.db "heads" := by
  rw [(touch_exact target state closed healthy).2.2, rows_setRows]
  exact List.mem_map.mpr ⟨row, present, by simp [different]⟩

theorem different_root_does_not_match (target : Fetch.Target) (row : Fields)
    (root : ByteArray) (stored : cell row "root" = .blob root)
    (different : root ≠ target.root) : equals row (Fetch.targetRows target) = false := by
  simp [equals, Fetch.targetRows, stored, equalCell, different]

theorem complete_does_not_match (target : Fetch.Target) (row : Fields)
    (complete : cell row "slot" = .text "complete") :
    equals row (Fetch.targetRows target) = false := by
  simp [equals, Fetch.targetRows, complete, equalCell]

theorem abandon_preserves_replacement (target : Fetch.Target) (state : State)
    (closed : state.pending = none) (healthy : state.faults = [])
    (row : Fields) (present : row ∈ rows state.db "heads")
    (root : ByteArray) (stored : cell row "root" = .blob root)
    (different : root ≠ target.root) :
    row ∈ rows (run (Fetch.abandon target) state).2.db "heads" := by
  rw [(abandon_exact target state closed healthy).2.2, rows_setRows]
  exact List.mem_filter.mpr ⟨present, by
    simp [different_root_does_not_match target row root stored different]⟩

/-- Reconciliation cannot abandon any accepted version, regardless of the
captured version's relationship to it. -/
theorem abandon_preserves_complete (target : Fetch.Target) (state : State)
    (closed : state.pending = none) (healthy : state.faults = [])
    (row : Fields) (present : row ∈ rows state.db "heads")
    (complete : cell row "slot" = .text "complete") :
    row ∈ rows (run (Fetch.abandon target) state).2.db "heads" := by
  rw [(abandon_exact target state closed healthy).2.2, rows_setRows]
  exact List.mem_filter.mpr ⟨present, by simp [complete_does_not_match target row complete]⟩

open Replication

/-- The post-rollback retirement is executed on the database at the new
transaction, not on the snapshot which failed materialization. -/
theorem retire_exact (pending : Promote.Pending) (state : State)
    (closed : state.pending = none) (healthy : state.faults = []) :
    (run (Promote.retire pending) state).1 = .ok () ∧
    (run (Promote.retire pending) state).2.pending = none ∧
    (run (Promote.retire pending) state).2.db = setRows state.db "heads"
      ((rows state.db "heads").filter fun row =>
        !equals row (Reconcile.headKey pending.head ++ [("slot", .text "pending")])) := by
  simp [run, Promote.retire, transactionOver, Promote.raw, raise, performOver,
    Inject.inject, ExceptT.mk, execute, Interpreter.handle, storage, reply, fault,
    healthy, closed, record, SimulatedHost.transaction, deletable, excluded, due,
    bind, ExceptT.bind, ExceptT.bindCont, ExceptT.run, pure, ExceptT.pure,
    Program.bind, Except.mapError]

/-- A later replacement with a different root survives the entire executed
retirement, even when the publisher reused the old sequence number. -/
theorem retire_preserves_replacement (pending : Promote.Pending) (state : State)
    (closed : state.pending = none) (healthy : state.faults = [])
    (row : Fields) (present : row ∈ rows state.db "heads")
    (root : ByteArray) (stored : cell row "root" = .blob root)
    (different : root ≠ pending.head.root) :
    row ∈ rows (run (Promote.retire pending) state).2.db "heads" := by
  rw [(retire_exact pending state closed healthy).2.2, rows_setRows]
  apply List.mem_filter.mpr
  refine ⟨present, ?_⟩
  simp [equals, Reconcile.headKey, stored, equalCell, different]

end Synchronicity.ReconciliationTargets
