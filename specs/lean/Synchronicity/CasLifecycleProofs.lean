import VerifiedCore.Cas
import Synchronicity.Prelude
import Synchronicity.Anchors

/-! Proofs of complete CAS lifecycle plans. No trie or sync model imports. -/
namespace Synchronicity.CasLifecycleProofs
open VerifiedCore.Cas

/-- Acquisition produces exactly its atomic mutation batch or an empty refusal.
No acquisition plan can request filesystem cleanup. -/
theorem acquisition_plan (s : AcquisitionSnapshot) (possession : Bool) :
    planLifecycle (.acquire s possession) =
      if s.row && s.durable && (!possession || s.wanted) then
        ⟨.applied, (if possession then [.deleteWant] else []) ++ [.upsertPin], []⟩
      else ⟨.skipped, [], []⟩ := by
  rcases s with ⟨row, durable, wanted⟩
  cases row <;> cases durable <;> cases wanted <;> cases possession <;> rfl

/-- Accepted acquisition requires a durable existing row and, for possession,
the holder's still-live want. -/
@[rust_justifies "cas-lifecycle-acquisition"]
theorem acquisition_authorized (s : AcquisitionSnapshot) (possession : Bool) :
    (planLifecycle (.acquire s possession)).outcome = .applied ↔
      s.row = true ∧ s.durable = true ∧ (possession = true → s.wanted = true) := by
  rw [acquisition_plan]
  rcases s with ⟨row, durable, wanted⟩
  cases row <;> cases durable <;> cases wanted <;> cases possession <;> simp

/-- Deletion's accepted plan requires no active writer, pin or reference;
collection additionally needs an existing row strictly before its horizon. -/
@[rust_justifies "cas-lifecycle-deletion"]
theorem deletion_authorized (s : DeletionSnapshot) (before : Option Int64) :
    (planLifecycle (.delete s before)).outcome = .applied ↔
      s.writing = false ∧ s.pinned = false ∧ s.referenced = false ∧
      (∀ cutoff ∈ before, s.row = true ∧ s.lastAccess < cutoff) := by
  rcases s with ⟨row, writing, pinned, referenced, lastAccess⟩
  cases before <;> cases row <;> cases writing <;> cases pinned <;> cases referenced <;>
    simp [planLifecycle]
  split_ifs <;> simp_all

/-- Failed lifecycle requests have no mutation or cleanup effects. -/
@[rust_justifies "cas-lifecycle-refusal"]
theorem refusal_effect_free (request : LifecycleRequest)
    (refused : (planLifecycle request).outcome ≠ .applied) :
    (planLifecycle request).transaction = [] ∧ (planLifecycle request).afterCommit = [] := by
  cases request <;> simp only [planLifecycle] at refused ⊢ <;>
    split_ifs at refused ⊢ <;> simp_all

/-- Every nonempty cleanup phase follows a transaction deleting exactly the
object row. Rust's phase executor commits that whole transaction before cleanup. -/
@[rust_justifies "cas-lifecycle-cleanup"]
theorem cleanup_requires_row_deletion (request : LifecycleRequest)
    (cleanup : (planLifecycle request).afterCommit ≠ []) :
    (planLifecycle request).transaction = [.deleteRow] ∧
    (planLifecycle request).afterCommit = [.payload, .outboard] ∧
    (planLifecycle request).outcome = .applied := by
  cases request <;> simp only [planLifecycle] at cleanup ⊢ <;>
    split_ifs at cleanup ⊢ <;> simp_all

/-- The fixed-width ABI has room for every action; there is no truncated plan. -/
theorem lifecycle_plan_bounds (request : LifecycleRequest) :
    (planLifecycle request).transaction.length ≤ 2 ∧
    (planLifecycle request).afterCommit.length ≤ 2 := by
  cases request <;> simp only [planLifecycle] <;> split_ifs <;> simp

/-- Native records always contain exactly the agreed five bytes. -/
theorem lifecycle_encoding_width (plan : LifecyclePlan) : (encodeLifecycle plan).size = 5 := by
  rfl

/-- Possession emits want removal and pin insertion together in that order. -/
theorem possession_atomic_batch (s : AcquisitionSnapshot)
    (accepted : (planLifecycle (.acquire s true)).outcome = .applied) :
    (planLifecycle (.acquire s true)).transaction = [.deleteWant, .upsertPin] := by
  rw [acquisition_plan] at accepted ⊢
  split_ifs at accepted ⊢ <;> simp_all

end Synchronicity.CasLifecycleProofs

#lint
