import VerifiedCore.Cas
import VerifiedCore.Cas.Program
import Synchronicity.CasProgramProofs

/-! Proofs of complete CAS lifecycle plans. No trie or sync model imports. -/
namespace Synchronicity.CasLifecycleProofs
open VerifiedCore.Cas VerifiedCore.Host

/-- Deletion's accepted plan requires no active writer, pin or reference;
collection additionally needs an existing row strictly before its horizon. -/
theorem deletion_authorized (s : DeletionSnapshot) (before : Option Int64) :
    (planLifecycle (.delete s before)).outcome = .applied ↔
      s.writing = false ∧ s.pinned = false ∧ s.referenced = false ∧
      (∀ cutoff ∈ before, s.row = true ∧ s.lastAccess < cutoff) := by
  rcases s with ⟨row, writing, pinned, referenced, lastAccess⟩
  cases before <;> cases row <;> cases writing <;> cases pinned <;> cases referenced <;>
    simp [planLifecycle]
  split <;> simp_all

/-- Failed lifecycle requests have no mutation or cleanup effects. -/
theorem refusal_effect_free (request : LifecycleRequest)
    (refused : (planLifecycle request).outcome ≠ .applied) :
    (planLifecycle request).transaction = [] ∧ (planLifecycle request).afterCommit = [] := by
  obtain ⟨⟨row, writing, pinned, referenced, lastAccess⟩, before⟩ := request
  cases before <;> cases row <;> cases writing <;> cases pinned <;> cases referenced <;>
    simp [planLifecycle] at refused ⊢ <;> (try split) <;> simp_all

/-- Every nonempty cleanup phase follows a transaction deleting exactly the
object row. The plan is now consumed only inside Lean's deletion program. -/
theorem cleanup_requires_row_deletion (request : LifecycleRequest)
    (cleanup : (planLifecycle request).afterCommit ≠ []) :
    (planLifecycle request).transaction = [.deleteRow] ∧
    (planLifecycle request).afterCommit = [.payload, .outboard] ∧
    (planLifecycle request).outcome = .applied := by
  obtain ⟨⟨row, writing, pinned, referenced, lastAccess⟩, before⟩ := request
  cases before <;> cases row <;> cases writing <;> cases pinned <;> cases referenced <;>
    simp [planLifecycle] at cleanup ⊢ <;> (try split) <;> simp_all

/-- The fixed-width ABI has room for every action; there is no truncated plan. -/
theorem lifecycle_plan_bounds (request : LifecycleRequest) :
    (planLifecycle request).transaction.length ≤ 2 ∧
    (planLifecycle request).afterCommit.length ≤ 2 := by
  obtain ⟨⟨row, writing, pinned, referenced, lastAccess⟩, before⟩ := request
  cases before <;> cases row <;> cases writing <;> cases pinned <;> cases referenced <;>
    simp [planLifecycle] <;> (try split) <;> simp


/-- Any failed transactional execution terminates deletion without requesting
file cleanup. The transaction's own proofs cover rollback and primary errors. -/
theorem failed_transaction_has_no_cleanup (root : ByteArray) (before : Option Int64)
    (failure : Error)
    (failed : (transactionWith Error.host (fun tx => deleteIn tx root before)).run =
      Program.pure (.error failure)) :
    (delete root before).run = Program.pure (.error failure) := by
  unfold delete
  change Program.bind (transactionWith Error.host (fun tx => deleteIn tx root before)).run _ = _
  rw [failed]
  rfl

/-- Cleanup has exactly two raw requests, regardless of either host result.
Ignoring errors is Lean's policy, not a best-effort host callback. -/
theorem cleanup_attempts_both_files (root : ByteArray) :
    (cleanup root).run = Program.request (.removeFile "cas_payload" root) (fun _ =>
      Program.request (.removeFile "cas_outboard" root) (fun _ =>
        Program.pure (.ok ()))) := by
  change Program.request _ _ = Program.request _ _
  congr 1
  funext first
  cases first with
  | error failure =>
    change Program.request _ _ = Program.request _ _
    congr 1
    funext second
    cases second <;> rfl
  | ok value =>
    cases value
    change Program.request _ _ = Program.request _ _
    congr 1
    funext second
    cases second <;> rfl

/-- File effects are downstream of successful transaction completion. -/
theorem committed_deletion_runs_cleanup (root : ByteArray) (before : Option Int64)
    (committed : (transactionWith Error.host (fun tx => deleteIn tx root before)).run =
      Program.pure (.ok .applied)) :
    (delete root before).run = Program.request (.removeFile "cas_payload" root) (fun _ =>
      Program.request (.removeFile "cas_outboard" root) (fun _ =>
        Program.pure (.ok .applied))) := by
  unfold delete
  change Program.bind (transactionWith Error.host (fun tx => deleteIn tx root before)).run _ = _
  rw [committed]
  change Program.bind (cleanup root).run _ = _
  rw [cleanup_attempts_both_files]
  rfl

open CasProgramProofs in
/-- The actual production program performs every observation before mutation,
then commit, then both unlinks. This includes explicit deletion of a missing
row, which still cleans orphan files. No Rust phase executor is assumed. -/
theorem explicit_deletion_trace (root : ByteArray) (accessed : Option Int64) :
    execute { access := .ok (accessed.toList.map fun n => [.integer n]) }
      (delete root none).run =
    (.ok .applied,
      [.begin,
       .existsRows 7 "pins" [("root", .blob root)],
       .existsRows 7 "entries" [("content", .blob root)],
       .readRows 7 "blobs" ["last_access"] [("root", .blob root)],
       .readCounter "cas_writers" root,
       .deleteRows 7 "blobs" [("root", .blob root)],
       .commit 7,
       .removeFile "cas_payload" root,
       .removeFile "cas_outboard" root]) := by
  cases accessed <;> rfl

-- Keep this case-heavy proof serial: asynchronous elaboration in the pinned
-- compiler emits an internal Option.get! diagnostic despite accepting it.
-- This changes scheduling only; all kernel and lint checks remain enabled.
set_option Elab.async false in
open CasProgramProofs in
/-- The completed operation's outcome is the internal proved decision for
every well-typed access row, not merely for the successful fixture above. -/
theorem deletion_execution_outcome (root : ByteArray) (accessed : Option Int64)
    (pinned referenced : Bool) (writers : UInt64) (before : Option Int64) :
    (execute
      { access := .ok (accessed.toList.map fun n => [.integer n])
        pinned := .ok pinned
        referenced := .ok referenced
        writers := .ok writers }
      (delete root before).run).1 =
    .ok (planLifecycle (.delete
      ⟨accessed.isSome, writers != 0, pinned, referenced, accessed.getD 0⟩ before)).outcome := by
  cases accessed <;> cases before <;> cases pinned <;> cases referenced <;>
    by_cases writing : writers = 0 <;>
    simp [delete, deleteIn, cleanup, transactionWith, transactionOver, request, performWith,
      execute, answer, event, Except.mapError, Except.map,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
      ExceptT.run, ExceptT.mk, decodeAccess, Codec.integerField, planLifecycle, writing]
  all_goals (try split) <;> rfl

open CasProgramProofs in
/-- Authorization of the executed operation follows from the internal decision
theorem through the checked execution equality, with no Rust model premise. -/
theorem executed_deletion_authorized (root : ByteArray) (accessed : Option Int64)
    (pinned referenced : Bool) (writers : UInt64) (before : Option Int64) :
    (execute
      { access := .ok (accessed.toList.map fun n => [.integer n])
        pinned := .ok pinned
        referenced := .ok referenced
        writers := .ok writers }
      (delete root before).run).1 = .ok .applied ↔
    (writers != 0) = false ∧ pinned = false ∧ referenced = false ∧
      (∀ cutoff ∈ before, accessed.isSome = true ∧ accessed.getD 0 < cutoff) := by
  rw [deletion_execution_outcome]
  simpa using deletion_authorized
    ⟨accessed.isSome, writers != 0, pinned, referenced, accessed.getD 0⟩ before

end Synchronicity.CasLifecycleProofs
