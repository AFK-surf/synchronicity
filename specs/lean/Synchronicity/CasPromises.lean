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
