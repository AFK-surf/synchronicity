import Synchronicity.MaterializationFileSql

/-! The provider projection uses the published object root and issuer as its
identity. Successful writes install the decoded size/completeness/span record. -/
namespace Synchronicity.MaterializationProviderSql
open VerifiedCore VerifiedCore.Host Replication SimulatedHost MaterializedView
open MaterializationRecords RelationalFields

def key (origin : String) (root : ByteArray) := (Address.provider root).key origin
def columns := (Address.provider ByteArray.empty).columns
def incoming (origin : String) (root : ByteArray) (fields : Fields) := key origin root ++ fields
def assignments : List (String × ConflictValue) := columns.map fun column => (column, .excluded column)

theorem conflict_selected (origin : String) (root : ByteArray) (fields row : Fields) :
    conflict ((key origin root).map Prod.fst) (incoming origin root fields) row = equals row (key origin root) := by
  have text_comm (text : String) (value : Cell) : equalCell (.text text) value = isCell value (.text text) := by
    cases value <;> simp [isCell, equalCell, BEq.beq, instBEqCell.beq, eq_comm]
  have blob_comm (bytes : ByteArray) (value : Cell) : equalCell (.blob bytes) value = isCell value (.blob bytes) := by
    cases value <;> simp [isCell, equalCell, BEq.beq, instBEqCell.beq]
    change (bytes == _) = (_ == bytes)
    apply Bool.eq_iff_iff.mpr
    constructor <;> intro same
    all_goals exact (beq_iff_eq).mpr ((beq_iff_eq).mp same).symm
  simp [key, Address.key, incoming, conflict, equals, cell, text_comm, blob_comm]

theorem incoming_selected (origin : String) (root : ByteArray) (fields : Fields) :
    equals (incoming origin root fields) (key origin root) = true := by
  simp [incoming, key, Address.key, equals, cell, isCell, equalCell]

theorem incoming_payload (origin : String) (root : ByteArray) (fields : Fields) :
    project columns (incoming origin root fields) = project columns fields := by
  apply List.map_congr_left
  intro column member
  apply cell_suffix
  simp only [columns, Address.columns, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl <;> simp [key, Address.key]

theorem assigned_selected (origin : String) (root : ByteArray) (fields row : Fields) :
    equals (assign row (assignments.map fun (column, v) =>
      (column, conflictValue row (incoming origin root fields) v))) (key origin root) = equals row (key origin root) := by
  have other (column : String) (absent : column ∉ columns) := assigned_other row (incoming origin root fields) columns column absent
  simp only [assignments, List.map_map, conflictValue, Function.comp_def]
  simp only [key, Address.key, equals, List.all_cons, List.all_nil, Bool.and_true]
  rw [other "origin_id" (by decide), other "object_root" (by decide)]

theorem assigned_payload (origin : String) (root : ByteArray) (fields row : Fields) :
    project columns (assign row (assignments.map fun (column, v) =>
      (column, conflictValue row (incoming origin root fields) v))) = project columns fields := by
  simp only [assignments, List.map_map, conflictValue, Function.comp_def]
  exact (assigned_projection row (incoming origin root fields) columns).trans (incoming_payload ..)

theorem write_replaces (db : Database) (origin : String) (root : ByteArray) (fields : Fields)
    (schema : fields.map Prod.fst = columns) :
    RowReplacement.Replaces (fun row => equals row (key origin root)) (project columns)
      (rows db "blob_providers")
      (rows (MaterializationSql.written db "blob_providers" (key origin root) fields false) "blob_providers")
      true (some (project columns fields)) := by
  simp only [MaterializationSql.written, rows_setRows, Bool.false_eq_true, ↓reduceIte]
  rw [schema]
  exact RowReplacement.upsert_replaces _ _ _ _ _ assignments true _
    (incoming_selected ..) (incoming_payload ..)
    (fun row => by change conflict _ (incoming origin root fields) row = true ↔ _
                   rw [conflict_selected])
    (assigned_selected origin root fields) (assigned_payload origin root fields)

theorem write_keeps_other_row (db : Database) (origin : String) (root : ByteArray) (fields : Fields)
    (schema : fields.map Prod.fst = columns) (row : Fields) (outside : equals row (key origin root) = false) :
    row ∈ rows (MaterializationSql.written db "blob_providers" (key origin root) fields false) "blob_providers" ↔
      row ∈ rows db "blob_providers" := by
  simp only [MaterializationSql.written, rows_setRows, Bool.false_eq_true, ↓reduceIte]
  rw [schema]
  exact RowReplacement.upsert_frame (fun row => equals row (key origin root)) _
    (incoming origin root fields) _ assignments (incoming_selected origin root fields)
    (conflict_selected origin root fields) (assigned_selected origin root fields) row outside

end Synchronicity.MaterializationProviderSql
