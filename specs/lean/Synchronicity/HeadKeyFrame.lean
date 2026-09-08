import Synchronicity.HeadInvariant
import Synchronicity.ReconciliationSlots

/-! Deletion and timestamp refresh cannot invent a different head version.
This is a universal invariant of the raw four-column version projection. -/
namespace Synchronicity.HeadKeyFrame
open VerifiedCore.Host SimulatedHost PrivateDatabase

def columns : List String := ["origin_id", "slot", "seq", "root"]
def key (row : Fields) : List Cell := columns.map (cell row)
def allKeys (predicate : List Cell → Prop) (table : List Fields) : Prop :=
  ∀ row ∈ table, predicate (key row)

def storageAllowed : Storage A → Prop
  | .upsert _ relation _ _ _ => relation ≠ "heads"
  | _ => True

def accessAllowed : Access A → Prop
  | .update _ selection values => selection.relation ≠ "heads" ∨ ∀ field ∈ values, field.1 ∉ columns
  | .copyRows _ target _ _ _ => target ≠ "heads"
  | _ => True

theorem key_assign (row values : Fields) (absent : ∀ field ∈ values, field.1 ∉ columns) :
    key (assign row values) = key row := by
  unfold key
  apply List.map_congr_left
  intro column member
  apply ReconciliationSlots.cell_assign_absent
  intro field fieldMember equal
  exact absent field fieldMember (equal ▸ member)

theorem filtered (predicate : List Cell → Prop) (table : List Fields) (test : Fields → Bool)
    (initial : allKeys predicate table) : allKeys predicate (table.filter test) := by
  intro row member
  exact initial row (List.mem_filter.mp member).1

theorem storage_safe (predicate : List Cell → Prop) (effect : Storage A) (safe : storageAllowed effect) :
    HeadInvariant.effectSafe (allKeys predicate) _ effect := by
  intro state initial
  cases effect with
  | begin => exact HeadInvariant.begin_holds _ state initial
  | commit tx => exact HeadInvariant.commit_holds _ tx state initial
  | rollback tx => exact HeadInvariant.rollback_holds _ tx state initial
  | upsert tx relation fields conflicts updates =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    apply HeadInvariant.transaction_holds _ _ _ _ _ h
    intro db prior
    rwa [rows_setRows_other _ _ _ _ safe]
  | deleteRows tx relation fields blockers bounds =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    apply HeadInvariant.transaction_holds _ _ _ _ _ h
    intro db prior
    by_cases same : relation = "heads"
    · subst relation
      rw [rows_setRows]
      exact filtered _ _ _ prior
    · rwa [rows_setRows_other _ _ _ _ same]
  | deleteExcept tx relation column keys =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    apply HeadInvariant.transaction_holds _ _ _ _ _ h
    intro db prior
    by_cases same : relation = "heads"
    · subst relation
      rw [rows_setRows]
      exact filtered _ _ _ prior
    · rwa [rows_setRows_other _ _ _ _ same]
  | readRows | scanRows | existsRows =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    exact HeadInvariant.transaction_holds _ _ _ _ (fun _ prior => prior) h
  | readCounter | readBytes | removeFile =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    exact h
  | readInput =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    split
    · exact h
    · split <;> exact h

theorem access_safe (predicate : List Cell → Prop) (effect : Access A) (safe : accessAllowed effect) :
    HeadInvariant.effectSafe (allKeys predicate) _ effect := by
  intro state initial
  cases effect with
  | snapshot | snapshotExcluding =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    exact h
  | update tx selection values =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    apply HeadInvariant.transaction_holds _ _ _ _ _ h
    intro db prior
    by_cases same : selection.relation = "heads"
    · rw [same, rows_setRows]
      have absent := safe.resolve_left (by simp [same])
      intro row member
      obtain ⟨old, oldMember, changed⟩ := List.mem_map.mp member
      subst row
      split
      · rw [key_assign _ _ absent]
        exact prior old oldMember
      · exact prior old oldMember
    · rwa [rows_setRows_other _ _ _ _ same]
  | delete tx selection =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    apply HeadInvariant.transaction_holds _ _ _ _ _ h
    intro db prior
    by_cases same : selection.relation = "heads"
    · rw [same, rows_setRows]
      exact filtered _ _ _ prior
    · rwa [rows_setRows_other _ _ _ _ same]
  | copyRows tx target source values conflicts =>
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    apply HeadInvariant.transaction_holds _ _ _ _ _ h
    intro db prior
    simpa only [copyRows, rows_setRows_other _ _ _ _ safe] using prior

theorem no_new_keys [Interpreter E] (program : Program E A) (certificate : Only allowed program)
    (effects : ∀ (predicate : List Cell → Prop) {B} (effect : E B), allowed _ effect →
      HeadInvariant.effectSafe (allKeys predicate) _ effect)
    (state : State) (closed : state.pending = none) :
    ∀ row ∈ rows (execute program state).2.db "heads", ∃ old ∈ rows state.db "heads", key row = key old := by
  let predicate := fun k => ∃ old ∈ rows state.db "heads", k = key old
  have initial : HeadInvariant.holds (allKeys predicate) state :=
    HeadInvariant.closed _ state closed (fun row member => ⟨row, member, rfl⟩)
  exact (certificate.invariant (HeadInvariant.holds (allKeys predicate)) (effects predicate) state initial).1

theorem no_new_keys_prefix [Interpreter E] (program tail : Program E A) (certificate : Only allowed program)
    (effects : ∀ (predicate : List Cell → Prop) {B} (effect : E B), allowed _ effect →
      HeadInvariant.effectSafe (allKeys predicate) _ effect)
    (state final : State) (closed : state.pending = none) (path : Prefix program state tail final) :
    ∀ row ∈ rows final.db "heads", ∃ old ∈ rows state.db "heads", key row = key old := by
  let predicate := fun k => ∃ old ∈ rows state.db "heads", k = key old
  have initial : HeadInvariant.holds (allKeys predicate) state :=
    HeadInvariant.closed _ state closed (fun row member => ⟨row, member, rfl⟩)
  exact (certificate.invariant_prefix (HeadInvariant.holds (allKeys predicate)) path (effects predicate) initial).1

end Synchronicity.HeadKeyFrame
