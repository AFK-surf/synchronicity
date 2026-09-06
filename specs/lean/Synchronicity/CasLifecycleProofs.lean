import VerifiedCore.Cas
import VerifiedCore.Cas.Program
import Synchronicity.CasFixtures

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

open SimulatedHost CasFixtures

private def check (state : State := stored) (before : Option Int64 := none) :=
  traceResult (delete root before) state

theorem explicit_deletion_trace : check = (.ok .applied,
    ["begin", "exists:pins", "exists:entries", "read:blobs", "counter:cas_writers", "delete:blobs", "commit", "remove:cas_payload", "remove:cas_outboard"]) := by decide +kernel

theorem committed_deletion_removes_actual_rows_and_files :
    let result := SimulatedHost.run (delete root none) stored
    rows result.2.db "blobs" == [] ∧ (lookupFile result.2.files ("cas_payload", root)).isNone := by decide +kernel

theorem pinned_content_has_no_cleanup :
    check { stored with db := [("blobs", [blob]), ("pins", [pin])] } =
      (.ok .protectedClaim, ["begin", "exists:pins", "exists:entries", "read:blobs", "counter:cas_writers", "commit"]) := by decide +kernel

theorem referenced_content_has_no_cleanup :
    check { stored with db := [("blobs", [blob]), ("entries", [entry])] } =
      (.ok .protectedClaim, ["begin", "exists:pins", "exists:entries", "read:blobs", "counter:cas_writers", "commit"]) := by decide +kernel

theorem active_writer_has_no_cleanup :
    check { stored with counters := [(("cas_writers", root), 1)] } =
      (.ok .writing, ["begin", "exists:pins", "exists:entries", "read:blobs", "counter:cas_writers", "commit"]) := by decide +kernel

theorem collection_respects_strict_access_horizon : check stored (some 0) =
    (.ok .skipped, ["begin", "exists:pins", "exists:entries", "read:blobs", "counter:cas_writers", "commit"]) := by decide +kernel

theorem every_failed_transaction_stage_preserves_files :
    (List.range 7).all (fun index =>
      let result := SimulatedHost.run (delete root none) (fail stored index)
      failed result.1 && (result.2.db == stored.db) && (result.2.files == stored.files)) = true := by decide +kernel

theorem cleanup_failure_does_not_skip_second_file :
    check (fail stored 7) = (.ok .applied,
      ["begin", "exists:pins", "exists:entries", "read:blobs", "counter:cas_writers", "delete:blobs", "commit", "remove:cas_payload", "remove:cas_outboard"]) := by decide +kernel

end Synchronicity.CasLifecycleProofs
