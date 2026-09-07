import Synchronicity.CasReceiveStateProofs
import Synchronicity.CasBitmapProofs
import Synchronicity.CasContentProofs
import Synchronicity.CasDurableProofs

namespace Synchronicity.CasPersistenceProofs
open VerifiedCore VerifiedCore.Host SimulatedHost

private theorem upsert_selected_existing (table : List Fields) (incoming : Fields)
    (keys : List String) (assignments : List (String × ConflictValue)) (prior : Fields)
    (selected : table.filter (conflict keys incoming) = [prior])
    (stable : ∀ row, conflict keys incoming
      (assign row (assignments.map fun (column, value) =>
        (column, conflictValue row incoming value))) = conflict keys incoming row) :
    (upsertRows table incoming keys assignments).filter (conflict keys incoming) =
      [assign prior (assignments.map fun (column, value) =>
        (column, conflictValue prior incoming value))] := by
  let predicate := conflict keys incoming
  let update := fun current => if predicate current then
    assign current (assignments.map fun (column, value) =>
      (column, conflictValue current incoming value)) else current
  have member : prior ∈ table.filter predicate := by rw [selected]; simp
  obtain ⟨present, matched⟩ := List.mem_filter.mp member
  have any : table.any predicate = true := List.any_eq_true.mpr ⟨prior, present, matched⟩
  have same (row : Fields) : predicate (update row) = predicate row := by
    dsimp [update]
    split
    · exact stable row
    · rfl
  have commute (rs : List Fields) : (rs.map update).filter predicate = (rs.filter predicate).map update := by
    induction rs with
    | nil => rfl
    | cons row rest ih =>
      simp only [List.map_cons, List.filter_cons, same, ih]
      split <;> rfl
  change (if table.any predicate then table.map update else table ++ [incoming]).filter predicate = _
  rw [if_pos any, commute, selected]
  simp only [List.map_cons, List.map_nil, update, if_pos matched]

private theorem root_conflict (root : ByteArray) (incoming : Fields)
    (named : cell incoming "root" = .blob root) :
    conflict ["root"] incoming = fun row => equals row [("root", .blob root)] := by
  funext row
  simp only [conflict, List.all_cons, List.all_nil, Bool.and_true, named, equals]
  cases h : cell row "root" <;> simp only [isCell, equalCell] <;> try rfl
  rename_i other
  change (root == other) = (other == root)
  exact Bool.beq_comm

/-- Upserting one object leaves exactly its updated record selected, even
among arbitrary unrelated objects and irrespective of physical field order. -/
theorem receive_upsert_selects_record (table : List Fields) (prior : Fields)
    (root : ByteArray) (size : UInt64) (complete : Bool) (bitmap : Option ByteArray)
    (now : Int64) (tier : Cas.IngestCommit.Tier)
    (selected : table.filter (fun row => equals row [("root", .blob root)]) = [prior]) :
    let incoming := Cas.IngestCommit.values root size complete bitmap none now tier
    (upsertRows table incoming ["root"] Cas.IngestCommit.assignments).filter
      (fun row => equals row [("root", .blob root)]) =
      [assign prior (Cas.IngestCommit.assignments.map fun (column, value) =>
        (column, conflictValue prior incoming value))] := by
  let incoming := Cas.IngestCommit.values root size complete bitmap none now tier
  have named : cell incoming "root" = .blob root := by simp [incoming, Cas.IngestCommit.values, cell]
  have same := root_conflict root incoming named
  rw [← same] at selected ⊢
  apply upsert_selected_existing _ _ _ _ _ selected
  intro row
  have rootUnchanged : cell (assign row (Cas.IngestCommit.assignments.map fun (column, value) =>
      (column, conflictValue row incoming value))) "root" = cell row "root" := by
    apply CasDurableProofs.cell_assign_other
    simp [Cas.IngestCommit.assignments]
  simp [conflict, rootUnchanged]

/-- A first receive inserts exactly one selected record without requiring
an otherwise empty database. -/
theorem receive_upsert_selects_new_record (table : List Fields)
    (root : ByteArray) (size : UInt64) (complete : Bool) (bitmap : Option ByteArray)
    (now : Int64) (tier : Cas.IngestCommit.Tier)
    (absent : table.filter (fun row => equals row [("root", .blob root)]) = [])
    (inline : Option ByteArray := none) :
    let incoming := Cas.IngestCommit.values root size complete bitmap inline now tier
    (upsertRows table incoming ["root"] Cas.IngestCommit.assignments).filter
      (fun row => equals row [("root", .blob root)]) = [incoming] := by
  let incoming := Cas.IngestCommit.values root size complete bitmap inline now tier
  have named : cell incoming "root" = .blob root := by simp [incoming, Cas.IngestCommit.values, cell]
  have same := root_conflict root incoming named
  have empty : table.any (conflict ["root"] incoming) = false := by
    rw [same]
    apply Bool.eq_false_iff.mpr
    intro found
    obtain ⟨row, present, matched⟩ := List.any_eq_true.mp found
    have member : row ∈ table.filter (fun row => equals row [("root", .blob root)]) :=
      List.mem_filter.mpr ⟨present, matched⟩
    rw [absent] at member
    simp at member
  change (upsertRows table incoming ["root"] Cas.IngestCommit.assignments).filter _ = [incoming]
  simp only [upsertRows, empty, Bool.false_eq_true, if_false, List.filter_append, absent, List.nil_append]
  simp [incoming, Cas.IngestCommit.values, equals, cell]

/-- The actual conflict assignment preserves a file-backed record's absence
of inline bytes and exposes exactly the newly committed read metadata. -/
theorem updated_record_decodes (prior : Fields) (root : ByteArray) (size : UInt64)
    (complete : Bool) (bitmap : Option ByteArray) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (durable : Int64) (width : root.size = 32)
    (named : cell prior "root" = .blob root)
    (fileBacked : cell prior "inline" = .null)
    (durability : cell prior "durable" = .integer durable) :
    let incoming := Cas.IngestCommit.values root size complete bitmap none now tier
    let updated := assign prior (Cas.IngestCommit.assignments.map fun (column, value) =>
      (column, conflictValue prior incoming value))
    Cas.Read.decodeRow (project ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"] updated) =
      .ok ⟨size, complete, bitmap, none⟩ := by
  let incoming := Cas.IngestCommit.values root size complete bitmap none now tier
  have rootUnchanged : cell (assign prior (Cas.IngestCommit.assignments.map fun (column, value) =>
      (column, conflictValue prior incoming value))) "root" = .blob root := by
    rw [CasDurableProofs.cell_assign_other]
    · exact named
    · simp [Cas.IngestCommit.assignments]
  change Cas.Read.decodeRow (project _ (assign prior (Cas.IngestCommit.assignments.map fun (column, value) =>
    (column, conflictValue prior incoming value)))) = _
  simp only [project, List.map_cons, List.map_nil, rootUnchanged]
  simp only [cell] at fileBacked durability
  cases complete <;> cases bitmap <;> cases tier <;>
    simp [incoming, Cas.IngestCommit.values, Cas.IngestCommit.assignments, conflictValue,
      assign, cell, fileBacked, durability, Cas.Read.decodeRow,
      Cas.Read.blobField, Cas.Read.integerField, Cas.Read.optionalBlobField,
      Cas.Codec.blobField, Cas.Codec.integerField, Cas.Codec.optionalBlobField,
      width, bind, pure, Except.bind, Except.pure]

/-- Metadata written by the actual upsert is observed by the next read; all
unrelated rows may remain in the shared database. -/
theorem upsert_result_metadata (before after : State) (prior : Fields)
    (root : ByteArray) (size : UInt64) (complete : Bool) (bitmap : Option ByteArray)
    (now : Int64) (tier : Cas.IngestCommit.Tier) (durable : Int64)
    (selected : (rows before.db "blobs").filter
      (fun row => equals row [("root", .blob root)]) = [prior])
    (width : root.size = 32) (named : cell prior "root" = .blob root)
    (fileBacked : cell prior "inline" = .null)
    (durability : cell prior "durable" = .integer durable)
    (stored : rows after.db "blobs" = upsertRows (rows before.db "blobs")
      (Cas.IngestCommit.values root size complete bitmap none now tier)
      ["root"] Cas.IngestCommit.assignments) :
    ∃ raw, CasReadPromises.observation after root = [raw] ∧
      Cas.Read.decodeRow raw = .ok ⟨size, complete, bitmap, none⟩ := by
  let incoming := Cas.IngestCommit.values root size complete bitmap none now tier
  let updated := assign prior (Cas.IngestCommit.assignments.map fun (column, value) =>
    (column, conflictValue prior incoming value))
  refine ⟨project ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"] updated, ?_, ?_⟩
  · have predicate : selects ⟨"blobs", [("root", .blob root)], [], []⟩ =
        fun row => equals row [("root", .blob root)] := by
      funext row
      simp [selects]
    simp only [CasReadPromises.observation, predicate]
    rw [stored, receive_upsert_selects_record _ prior root size complete bitmap now tier selected]
    rfl
  · exact updated_record_decodes prior root size complete bitmap now tier durable width named fileBacked durability

end Synchronicity.CasPersistenceProofs
