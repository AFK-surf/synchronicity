import Synchronicity.ReconciliationSlots

/-! Field lookup laws for actual SQL assignment, including partial updates.
These do not assume that decoder outputs already implement a view transition. -/
namespace Synchronicity.RelationalFields
open VerifiedCore.Host SimulatedHost

theorem cell_prefix (front suffix : Fields) (column : String)
    (present : column ∈ front.map Prod.fst) :
    cell (front ++ suffix) column = cell front column := by
  have found : ∃ field, front.find? (fun field => field.1 == column) = some field := by
    cases h : front.find? (fun field => field.1 == column) with
    | some field => exact ⟨field, rfl⟩
    | none =>
      obtain ⟨field, member, same⟩ := List.mem_map.mp present
      have impossible := List.find?_eq_none.mp h field member
      simp [same] at impossible
  obtain ⟨field, found⟩ := found
  simp [cell, List.find?_append, found]

theorem cell_copied (columns : List String) (source : Fields) (column : String)
    (present : column ∈ columns) :
    cell (columns.map fun name => (name, cell source name)) column = cell source column := by
  induction columns with
  | nil => contradiction
  | cons name rest ih =>
    by_cases same : name = column
    · subst name
      simp [cell]
    · have member : column ∈ rest := (List.mem_cons.mp present).resolve_left (Ne.symm same)
      simpa [cell, same] using ih member

theorem cell_suffix (front suffix : Fields) (column : String)
    (absent : column ∉ front.map Prod.fst) : cell (front ++ suffix) column = cell suffix column := by
  have missing : front.find? (fun field => field.1 == column) = none := by
    apply List.find?_eq_none.mpr
    intro field member
    intro same
    exact absent (List.mem_map.mpr ⟨field, member, eq_of_beq same⟩)
  simp [cell, List.find?_append, missing]

theorem assigned_column (row source : Fields) (columns : List String) (column : String)
    (present : column ∈ columns) :
    cell (assign row (columns.map fun name => (name, cell source name))) column = cell source column := by
  unfold assign
  rw [cell_prefix]
  · exact cell_copied columns source column present
  · simpa using present

theorem assigned_projection (row source : Fields) (columns : List String) :
    project columns (assign row (columns.map fun name => (name, cell source name))) = project columns source := by
  apply List.map_congr_left
  intro column member
  exact assigned_column row source columns column member

theorem assigned_other (row source : Fields) (columns : List String) (column : String)
    (absent : column ∉ columns) :
    cell (assign row (columns.map fun name => (name, cell source name))) column = cell row column := by
  apply ReconciliationSlots.cell_assign_absent
  intro field member
  obtain ⟨name, inColumns, rfl⟩ := List.mem_map.mp member
  exact fun same => absent (same ▸ inColumns)

theorem text_match_unique (value : Cell) (left right : String)
    (first : isCell value (.text left) = true) (second : isCell value (.text right) = true) : left = right := by
  cases value <;> simp_all [isCell, equalCell, BEq.beq, instBEqCell.beq]
  rename_i bytes
  have same : left.toUTF8 = right.toUTF8 := congrArg ByteArray.mk ((eq_of_beq first).symm.trans (eq_of_beq second))
  exact String.toByteArray_inj.mp same

end Synchronicity.RelationalFields
