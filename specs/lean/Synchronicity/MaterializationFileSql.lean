import Synchronicity.MaterializationRecords
import Synchronicity.RelationalFields
import Synchronicity.RowReplacement

/-! Exact file-row installation by the production SQL write. Unrelated rows
remain verbatim, and the selected row contains the actual decoded record. -/
namespace Synchronicity.MaterializationFileSql
open VerifiedCore VerifiedCore.Host Replication SimulatedHost MaterializedView
open MaterializationRecords RelationalFields

def key (origin space path : String) := (Address.file space path).key origin
def columns := (Address.file "" "").columns
def incoming (origin space path : String) (file : Records.File) := key origin space path ++ file.fields
def assignments : List (String × ConflictValue) := columns.map fun column => (column, .excluded column)

theorem conflict_selected (origin space path : String) (file : Records.File) (row : Fields) :
    conflict ((key origin space path).map Prod.fst) (incoming origin space path file) row =
      equals row (key origin space path) := by
  have text_comm (text : String) (value : Cell) : equalCell (.text text) value = isCell value (.text text) := by
    cases value <;> simp [isCell, equalCell, BEq.beq, instBEqCell.beq, eq_comm]
  simp [key, Address.key, incoming, conflict, equals, cell, text_comm]

theorem incoming_selected (origin space path : String) (file : Records.File) :
    equals (incoming origin space path file) (key origin space path) = true := by
  simp [incoming, key, Address.key, equals, cell, isCell, equalCell]

theorem incoming_payload (origin space path : String) (file : Records.File) :
    project columns (incoming origin space path file) = project columns file.fields := by
  apply List.map_congr_left
  intro column member
  apply cell_suffix
  simp only [columns, Address.columns, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp [key, Address.key]

theorem assigned_selected (origin space path : String) (file : Records.File) (row : Fields) :
    equals (assign row (assignments.map fun (column, v) =>
      (column, conflictValue row (incoming origin space path file) v))) (key origin space path) =
      equals row (key origin space path) := by
  have other (column : String) (absent : column ∉ columns) :=
    assigned_other row (incoming origin space path file) columns column absent
  simp only [assignments, List.map_map, conflictValue, Function.comp_def]
  simp only [key, Address.key, equals, List.all_cons, List.all_nil, Bool.and_true]
  rw [other "origin_id" (by decide), other "space" (by decide), other "path" (by decide)]

theorem assigned_payload (origin space path : String) (file : Records.File) (row : Fields) :
    project columns (assign row (assignments.map fun (column, v) =>
      (column, conflictValue row (incoming origin space path file) v))) = project columns file.fields := by
  simp only [assignments, List.map_map, conflictValue, Function.comp_def]
  exact (assigned_projection row (incoming origin space path file) columns).trans (incoming_payload ..)

theorem write_replaces (db : Database) (origin space path : String) (file : Records.File)
    (schema : FileSchema file) :
    RowReplacement.Replaces (fun row => equals row (key origin space path)) (project columns)
      (rows db "entries")
      (rows (MaterializationSql.written db "entries" (key origin space path) file.fields false) "entries")
      true (some (project columns file.fields)) := by
  simp only [MaterializationSql.written, rows_setRows, Bool.false_eq_true, ↓reduceIte]
  rw [schema.1]
  exact RowReplacement.upsert_replaces _ _ _ _ _ assignments true _
    (incoming_selected ..) (incoming_payload ..)
    (fun row => by change conflict _ (incoming origin space path file) row = true ↔ _
                   rw [conflict_selected])
    (assigned_selected origin space path file) (assigned_payload origin space path file)

theorem write_keeps_other_row (db : Database) (origin space path : String) (file : Records.File)
    (schema : FileSchema file) (row : Fields) (outside : equals row (key origin space path) = false) :
    row ∈ rows (MaterializationSql.written db "entries" (key origin space path) file.fields false) "entries" ↔
      row ∈ rows db "entries" := by
  simp only [MaterializationSql.written, rows_setRows, Bool.false_eq_true, ↓reduceIte]
  rw [schema.1]
  exact RowReplacement.upsert_frame (fun row => equals row (key origin space path)) _
    (incoming origin space path file) _ assignments (incoming_selected origin space path file)
    (conflict_selected origin space path file) (assigned_selected origin space path file) row outside

theorem selected_unique (row : Fields) (origin space path otherSpace otherPath : String)
    (first : equals row (key origin space path) = true)
    (second : equals row (key origin otherSpace otherPath) = true) :
    (space, path) = (otherSpace, otherPath) := by
  simp only [key, Address.key, equals, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] at first second
  exact Prod.ext (text_match_unique _ _ _ first.2.1 second.2.1) (text_match_unique _ _ _ first.2.2 second.2.2)

theorem replacement_other (before after : Database) (origin space path : String) (value : Option ByteArray)
    (refined : ReplacesRecord before after origin (.file space path) value)
    (otherSpace otherPath : String) (different : (otherSpace, otherPath) ≠ (space, path)) (values : List Cell) :
    Observed after origin (.file otherSpace otherPath) values ↔ Observed before origin (.file otherSpace otherPath) values := by
  have outside (row : Fields) (selected : equals row (key origin otherSpace otherPath) = true) :
      equals row (key origin space path) = false := by
    cases h : equals row (key origin space path)
    · rfl
    · exact False.elim (different (selected_unique row origin otherSpace otherPath space path selected h))
  constructor
  · rintro ⟨row, member, selected, payload⟩
    exact ⟨row, (refined.2 row (outside row selected)).mp member, selected, payload⟩
  · rintro ⟨row, member, selected, payload⟩
    exact ⟨row, (refined.2 row (outside row selected)).mpr member, selected, payload⟩

end Synchronicity.MaterializationFileSql
