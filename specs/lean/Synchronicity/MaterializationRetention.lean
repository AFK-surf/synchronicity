import Synchronicity.MaterializationPrivate
import Synchronicity.CasHealingPromises

/-! Retention requirements of a published view are about roots and holders,
not a materializer's return code. These are operation refinements supporting
M4; preservation of requirements across the whole diff remains to be composed. -/
namespace Synchronicity.MaterializationRetention
open VerifiedCore VerifiedCore.Host Replication SimulatedHost

/-- Any current file reference, regardless of its origin or space, protects
the content from release while the streamed view is being updated. -/
def Referenced (db : Database) (root : ByteArray) : Prop :=
  ∃ row ∈ rows db "entries", cell row "content" = .blob root

/-- A current replica requirement is represented either by a hold with no
scheduled release, or by a persistent acquisition/repair request. A pin
already scheduled for release is not by itself a current requirement. -/
def Required (db : Database) (root : ByteArray) (holder : String) : Prop :=
  (∃ row ∈ rows db "pins", CasHealingPromises.keyOf row = some (root, holder) ∧
    cell row "release_after" = .null) ∨
  CasHealingPromises.hasKey (rows db "content_want") (root, holder)

/-- Forever retention does not cancel an acquisition or schedule any hold
for release, even if no file currently refers to the content. -/
theorem forever_unchanged (tx : Transaction) (target : Materialize.Target)
    (root : ByteArray) (now : Int64) (state : State) (forever : target.releases = false) :
    execute (Materialize.release tx target root now) state = (.ok (), state) := by
  simp only [Materialize.release, forever, Bool.not_false, ↓reduceIte]
  rfl

/-- The production release operation cannot remove a requirement for a root
still named by any staged entry. This covers arbitrary storage failures and
does not assume that the rest of the new view has already been processed. -/
theorem referenced_unchanged (tx : Transaction) (target : Materialize.Target)
    (root : ByteArray) (now : Int64) (state : State) (db : Database)
    (openTx : state.pending = some (tx, db)) (live : Referenced db root) :
    (execute (Materialize.release tx target root now) state).2.pending = state.pending ∧
    (execute (Materialize.release tx target root now) state).2.db = state.db := by
  obtain ⟨row, member, content⟩ := live
  have hasReference : (rows db "entries").any
      (fun row => equals row [("content", .blob root)]) = true := by
    apply List.any_eq_true.mpr
    exact ⟨row, member, by simp [equals, content]⟩
  unfold Materialize.release
  split
  · exact ⟨rfl, rfl⟩
  · simp only [Materialize.raw, raise, performOver, Inject.inject, bind, ExceptT.bind,
      ExceptT.bindCont, ExceptT.mk, execute, execute_bind, Interpreter.handle,
      storage, reply]
    cases failed : fault state with
    | some failure => exact ⟨rfl, rfl⟩
    | none =>
      simp only [SimulatedHost.transaction, openTx, hasReference, record, Except.mapError,
        beq_self_eq_true, ↓reduceIte,
        pure, ExceptT.pure, ExceptT.mk, execute]
      trivial

/-- The acquisition branch's actual INSERT establishes the persistent
requirement. An existing request is retained, including its original age;
the table's typed keys are a raw schema assumption, not a policy answer. -/
theorem request_establishes_requirement (tx : Transaction) (target : Materialize.Target)
    (file : Records.File) (root : ByteArray) (now : Int64) (state final : State) (db : Database)
    (openTx : state.pending = some (tx, db))
    (typed : CasHealingPromises.WellKeyed (rows db "content_want"))
    (ran : execute (Materialize.write tx "content_want"
      [("root", .blob root), ("holder", .text target.holder)]
      [("size", .integer file.size.toUInt64.toInt64), ("prev", Records.nullable .blob file.prev),
        ("first_wanted", .integer now)] true) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Required after root target.holder ∧
      ∀ row ∈ rows db "content_want", row ∈ rows after "content_want" := by
  let incoming : Fields := [("root", .blob root), ("holder", .text target.holder),
    ("size", .integer file.size.toUInt64.toInt64), ("prev", Records.nullable .blob file.prev),
    ("first_wanted", .integer now)]
  have key : CasHealingPromises.keyOf incoming = some (root, target.holder) := by
    simp [incoming, CasHealingPromises.keyOf, cell]
  have request := (CasHealingPromises.upsert_hasKey (rows db "content_want") incoming
    (root, target.holder) typed (by simp [key])).mpr (.inr key)
  simp only [Materialize.write, Materialize.raw, raise, performOver, Inject.inject, ExceptT.mk,
    execute, Interpreter.handle, storage, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError] at ran
  | none =>
    simp only [failed, SimulatedHost.transaction, openTx, beq_self_eq_true, ↓reduceIte,
      Except.mapError, Prod.mk.injEq, true_and] at ran
    have same : final.pending = some (tx, setRows db "content_want"
        (upsertRows (rows db "content_want") incoming ["root", "holder"] [])) := by
      rw [← ran]
      rfl
    refine ⟨_, same, Or.inr ?_, ?_⟩
    · simpa only [rows_setRows] using request
    · intro row present
      rw [rows_setRows, upsertRows_doNothing]
      split
      · exact present
      · exact List.mem_append_left _ present

end Synchronicity.MaterializationRetention
