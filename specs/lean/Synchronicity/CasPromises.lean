import Synchronicity.CasPlanProofs
import Synchronicity.CasLifecycleProofs
import Synchronicity.CasReadProgramProofs

/-! User-facing CAS promises for arbitrary objects and group sets. -/
namespace Synchronicity.CasPromises
open VerifiedCore

/-- The production commit planner at an unchanged size. Complete rows can be
represented by their full coverage instead of their absent bitmap. -/
def addParts (size : UInt64) (held incoming : List GroupSpan) : List GroupSpan :=
  (planCasCommit true false false size size held incoming).spans

/-- Equality of available groups, independent of interval representation. -/
def SameCoverage (left right : List GroupSpan) : Prop :=
  ∀ group, spansContain left group = spansContain right group

theorem addParts_membership (size : UInt64) (held incoming : List GroupSpan) (group : Nat) :
    spansContain (addParts size held incoming) group = true ↔
      (spansContain held group = true ∨ spansContain incoming group = true) ∧
        group < (groupCount size).toNat := by
  simpa [addParts, settleSize, spansContain, List.any_append, Bool.or_eq_true] using
    CasPlanProofs.cas_plan_membership true false false size size held incoming group

/-- Downloading more preserves what you already have within the object. -/
theorem downloading_more_preserves_what_you_have (size : UInt64)
    (held incoming : List GroupSpan) (group : Nat)
    (inside : group < (groupCount size).toNat)
    (present : spansContain held group = true) :
    spansContain (addParts size held incoming) group = true :=
  (addParts_membership ..).2 ⟨Or.inl present, inside⟩

/-- Repeating a batch does not change which groups are available. -/
theorem duplicate_downloads_do_not_matter (size : UInt64)
    (held incoming : List GroupSpan) :
    SameCoverage (addParts size (addParts size held incoming) incoming)
      (addParts size held incoming) := by
  intro group
  apply Bool.eq_iff_iff.mpr
  simp only [addParts_membership]
  constructor
  · rintro ⟨h | h, inside⟩
    · exact h
    · exact ⟨Or.inr h, inside⟩
  · intro h
    exact ⟨Or.inl h, h.2⟩

/-- Reordering batches does not change which groups are available. -/
theorem download_order_does_not_matter (size : UInt64)
    (held first second : List GroupSpan) :
    SameCoverage (addParts size (addParts size held first) second)
      (addParts size (addParts size held second) first) := by
  intro group
  apply Bool.eq_iff_iff.mpr
  simp only [addParts_membership]
  constructor
  · rintro ⟨⟨h | h, _⟩ | h, inside⟩
    · exact ⟨Or.inl ⟨Or.inl h, inside⟩, inside⟩
    · exact ⟨Or.inr h, inside⟩
    · exact ⟨Or.inl ⟨Or.inr h, inside⟩, inside⟩
  · rintro ⟨⟨h | h, _⟩ | h, inside⟩
    · exact ⟨Or.inl ⟨Or.inl h, inside⟩, inside⟩
    · exact ⟨Or.inr h, inside⟩
    · exact ⟨Or.inl ⟨Or.inr h, inside⟩, inside⟩

open VerifiedCore.Host VerifiedCore.Cas CasProgramProofs

/-- Deleting metadata or attempting to remove a physical file is destructive. -/
def destructive : Event → Bool
  | .deleteRows .. | .removeFile .. => true
  | _ => false

set_option maxHeartbeats 2000000 in
/-- Kept content is protected from collection: the actual operation neither
accepts deletion nor requests metadata deletion or physical cleanup. Raw
observations must come from the protected transaction/ordering session. -/
theorem kept_content_is_protected_from_collection (root : ByteArray)
    (accessed : Option Int64) (pinned referenced : Bool) (writers : UInt64)
    (before : Option Int64)
    (kept : pinned = true ∨ referenced = true ∨ writers ≠ 0) :
    let result := execute
      { access := .ok (accessed.toList.map fun n => [.integer n])
        pinned := .ok pinned, referenced := .ok referenced, writers := .ok writers }
      (delete root before).run
    result.1 ≠ .ok .applied ∧ result.2.all (fun event => !destructive event) = true := by
  cases accessed <;> cases pinned <;> cases referenced <;>
    by_cases writing : writers = 0 <;> simp_all [delete, deleteIn, transactionWith,
      transactionOver, request, performWith, execute, answer, event, decodeAccess,
      Codec.integerField, planLifecycle, destructive, Except.mapError, Except.map,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
      ExceptT.run, ExceptT.mk]

/-- A cancelled request stays cancelled: for any decoded durability state,
a late possession attempt observes no want, returns false, and requests no
pin UPSERT. The absence premise is at the transaction's observation point. -/
theorem a_cancelled_request_stays_cancelled (tx : Transaction) (root : ByteArray)
    (holder : String) (now : Int64) (rows : List Row) (durable : Bool)
    (decoded : decodeDurability rows = .ok durable) :
    let result := CasProgramProofs.run
      { begin := .ok tx, durable := .ok rows, wanted := .ok [] } root holder now true
    result.1 = .ok false ∧
      result.2.all (fun event => match event with | .upsert .. => false | _ => true) = true := by
  rw [decoded_execution tx root holder now true durable rows [] decoded]
  cases durable <;> exact ⟨rfl, rfl⟩

end Synchronicity.CasPromises
