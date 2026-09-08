import Synchronicity.ReconciliationGuards

/-! Connect the production slot write to raw relational observations. A
successful policy guard is not by itself a theorem about the installed rows. -/
namespace Synchronicity.ReconciliationSlots
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost

def names (row : Fields) (origin slot : String) : Bool :=
  equals row [("origin_id", .text origin), ("slot", .text slot)]

def pointsTo (row : Fields) (head : Head) : Prop :=
  cell row "seq" = .integer head.seq.toInt64 ∧ cell row "root" = .blob head.root

private theorem equalCell_text_comm (value : Cell) (text : String) :
    equalCell (.text text) value = isCell value (.text text) := by
  cases value <;> simp [isCell, equalCell, BEq.beq, instBEqCell.beq, eq_comm]

private theorem cell_assign_absent (row values : Fields) (column : String)
    (absent : ∀ field ∈ values, field.1 ≠ column) : cell (assign row values) column = cell row column := by
  have noneFound : values.find? (fun field => field.1 == column) = none := by
    apply List.find?_eq_none.mpr
    intro field member
    simp [absent field member]
  have filtered : (row.filter (fun field => !values.any (fun v => v.1 == field.1))).find?
      (fun field => field.1 == column) = row.find? (fun field => field.1 == column) := by
    induction row with
    | nil => rfl
    | cons field rest ih =>
      by_cases same : field.1 = column
      · have kept : values.any (fun v => v.1 == column) = false := by
          apply List.any_eq_false.mpr
          intro value member
          simp [absent value member]
        simp only [List.filter_cons, same, kept, Bool.not_false, ↓reduceIte, List.find?_cons,
          beq_self_eq_true]
      · by_cases removed : values.any (fun v => v.1 == field.1) = true <;>
          simp_all
  simp [assign, cell, List.find?_append, noneFound, filtered]

def incoming (head : Head) (slot : String) (received verified : Int64) : Fields :=
  Reconcile.headKey head ++ [("slot", .text slot), ("received_at", .integer received),
    ("verified_at", .integer verified)]

def updates (slot : String) : List String :=
  ["seq", "root", "verified_at"] ++ if slot == "pending" then [] else ["received_at"]

theorem conflicts_iff_names (head : Head) (slot : String) (received verified : Int64)
    (row : Fields) : conflict ["origin_id", "slot"] (incoming head slot received verified) row =
      names row (Origin.canonical head.origin) slot := by
  simp [conflict, incoming, Reconcile.headKey, cell, names, equals, equalCell_text_comm]

private theorem assigned_points_to (head : Head) (slot : String) (received verified : Int64)
    (row : Fields) :
    pointsTo (assign row ((updates slot).map fun column =>
      (column, conflictValue row (incoming head slot received verified) (.excluded column)))) head := by
  simp [updates, pointsTo, assign, conflictValue, incoming, Reconcile.headKey, cell]

private theorem assigned_names (head : Head) (slot : String) (received verified : Int64)
    (row : Fields) (origin otherSlot : String) :
    names (assign row ((updates slot).map fun column =>
      (column, conflictValue row (incoming head slot received verified) (.excluded column)))) origin otherSlot =
    names row origin otherSlot := by
  unfold names equals
  simp only [List.all_cons, List.all_nil, Bool.and_true]
  congr 1
  all_goals
    congr 1
    apply cell_assign_absent
    intro field member
    obtain ⟨column, hcolumn, rfl⟩ := List.mem_map.mp member
    simp only [updates] at hcolumn
    split at hcolumn <;> simp_all <;> grind

/-- Every selected row after the actual upsert denotes the candidate, for
both insertion and replacement, independently of old row order or contents. -/
theorem upsert_installs_candidate (table : List Fields) (head : Head) (slot : String)
    (received verified : Int64) (row : Fields)
    (present : row ∈ upsertRows table (incoming head slot received verified) ["origin_id", "slot"]
      ((updates slot).map fun column => (column, .excluded column)))
    (selected : names row (Origin.canonical head.origin) slot = true) : pointsTo row head := by
  unfold upsertRows at present
  split at present
  · obtain ⟨before, _, changed⟩ := List.mem_map.mp present
    split at changed
    · subst row
      exact assigned_points_to ..
    · subst row
      rename_i noConflict
      rw [conflicts_iff_names] at noConflict
      exact False.elim (noConflict selected)
  · rcases List.mem_append.mp present with old | new
    · rename_i noneConflict
      have : table.any (conflict ["origin_id", "slot"] (incoming head slot received verified)) = true :=
        List.any_eq_true.mpr ⟨row, old, by rw [conflicts_iff_names]; exact selected⟩
      exact False.elim (noneConflict this)
    · have same := List.mem_singleton.mp new
      subst row
      simp [pointsTo, incoming, Reconcile.headKey, cell]

/-- Other origins and the other slot retain each complete row, not just a
root or sequence projection. -/
theorem upsert_preserves_other_head (table : List Fields) (head : Head) (slot : String)
    (received verified : Int64) (row : Fields) (present : row ∈ table)
    (other : names row (Origin.canonical head.origin) slot = false) :
    row ∈ upsertRows table (incoming head slot received verified) ["origin_id", "slot"]
      ((updates slot).map fun column => (column, .excluded column)) := by
  unfold upsertRows
  split
  · exact List.mem_map.mpr ⟨row, present, by simp [conflicts_iff_names, other]⟩
  · exact List.mem_append_left _ present

/-- Installation is not vacuous: insertion and replacement both leave a row
for the selected slot, whose sequence/root are exactly the candidate's. -/
theorem upsert_candidate_exists (table : List Fields) (head : Head) (slot : String)
    (received verified : Int64) :
    ∃ row ∈ upsertRows table (incoming head slot received verified) ["origin_id", "slot"]
      ((updates slot).map fun column => (column, .excluded column)),
      names row (Origin.canonical head.origin) slot = true ∧ pointsTo row head := by
  unfold upsertRows
  split
  · rename_i found
    obtain ⟨row, member, matched⟩ := List.any_eq_true.mp found
    refine ⟨assign row ((updates slot).map fun column =>
      (column, conflictValue row (incoming head slot received verified) (.excluded column))),
      List.mem_map.mpr ⟨row, member, by simp [matched, Function.comp_def]⟩, ?_,
      assigned_points_to head slot received verified row⟩
    rw [assigned_names]
    rwa [← conflicts_iff_names]
  · refine ⟨incoming head slot received verified, List.mem_append_right _ (by simp), ?_, ?_⟩
    · simp [names, equals, incoming, Reconcile.headKey, cell, isCell, equalCell]
    · simp [pointsTo, incoming, Reconcile.headKey, cell]

/-- Raw SQL success proves a write to the named private transaction; host
faults or an absent/wrong transaction cannot manufacture this postcondition. -/
theorem upsert_success (tx : Transaction) (relation : String) (fields : Fields)
    (conflicts columns : List String) (state : State)
    (succeeded : (storage (.upsert tx relation fields conflicts columns) state).1 = .ok ()) :
    ∃ db, state.pending = some (tx, db) ∧
      (storage (.upsert tx relation fields conflicts columns) state).2.pending =
        some (tx, setRows db relation (upsertRows (rows db relation) fields conflicts
          (columns.map fun column => (column, .excluded column)))) ∧
      (storage (.upsert tx relation fields conflicts columns) state).2.db = state.db := by
  simp only [storage, reply] at succeeded ⊢
  split at succeeded
  · cases succeeded
  · rename_i quiet
    unfold SimulatedHost.transaction at succeeded ⊢
    split at succeeded
    · rename_i token db opened
      simp only [opened]
      split at succeeded
      · rename_i correct
        have same : token = tx := by simpa using correct
        subst token
        exact ⟨db, rfl, by simp [record], by simp [record]⟩
      · cases succeeded
    · cases succeeded

def slotWrite (tx : Transaction) (slot : String) (head : Head) (received verified : Int64) :
    History.Action Unit :=
  History.request (.upsert tx "heads" (incoming head slot received verified)
    ["origin_id", "slot"] (updates slot))

/-- The proof follows the production write after immutable history succeeds;
this is a definitional decomposition, not a second acceptance algorithm. -/
theorem putSlot_decomposition (tx : Transaction) (slot : String) (head : Head) (received verified : Int64) :
    Reconcile.putSlot tx slot head received verified =
      (do Reconcile.record tx head received; slotWrite tx slot head received verified) := rfl

theorem slot_write_installs (tx : Transaction) (slot : String) (head : Head) (received verified : Int64)
    (state : State) (succeeded : (execute (slotWrite tx slot head received verified) state).1 = .ok ()) :
    ∃ db, (execute (slotWrite tx slot head received verified) state).2.pending = some (tx, db) ∧
      (∃ row ∈ rows db "heads", names row (Origin.canonical head.origin) slot = true) ∧
      (∀ row ∈ rows db "heads", names row (Origin.canonical head.origin) slot = true → pointsTo row head) := by
  have rawSuccess : (storage (.upsert tx "heads" (incoming head slot received verified)
      ["origin_id", "slot"] (updates slot)) state).1 = .ok () := by
    change ((storage (.upsert tx "heads" (incoming head slot received verified)
      ["origin_id", "slot"] (updates slot)) state).1.mapError History.Error.host) = .ok () at succeeded
    cases h : (storage (.upsert tx "heads" (incoming head slot received verified)
      ["origin_id", "slot"] (updates slot)) state).1 <;> simp_all [Except.mapError]
  obtain ⟨db, _, changed, _⟩ := upsert_success _ _ _ _ _ state rawSuccess
  refine ⟨setRows db "heads" (upsertRows (rows db "heads") (incoming head slot received verified)
    ["origin_id", "slot"] ((updates slot).map fun column => (column, .excluded column))), ?_, ?_, ?_⟩
  · exact changed
  · rw [rows_setRows]
    obtain ⟨row, member, named, _⟩ := upsert_candidate_exists (rows db "heads") head slot received verified
    exact ⟨row, member, named⟩
  · rw [rows_setRows]
    exact upsert_installs_candidate (rows db "heads") head slot received verified

/-- The production `putSlot`, not only the raw SQL lemma: any successful
execution installs exactly its candidate after recording immutable history.
No assumption that storage calls succeed is needed. -/
theorem putSlot_installs (tx : Transaction) (slot : String) (head : Head) (received verified : Int64)
    (state : State) (succeeded : (execute (Reconcile.putSlot tx slot head received verified) state).1 = .ok ()) :
    ∃ db, (execute (Reconcile.putSlot tx slot head received verified) state).2.pending = some (tx, db) ∧
      (∃ row ∈ rows db "heads", names row (Origin.canonical head.origin) slot = true) ∧
      (∀ row ∈ rows db "heads", names row (Origin.canonical head.origin) slot = true → pointsTo row head) := by
  rw [putSlot_decomposition] at succeeded ⊢
  obtain ⟨_, middle, recorded, written⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ succeeded
  have executed : execute (do Reconcile.record tx head received; slotWrite tx slot head received verified : History.Action Unit) state =
      execute (slotWrite tx slot head received verified) middle := by
    simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind, recorded]
  rw [executed]
  exact slot_write_installs tx slot head received verified middle written

end Synchronicity.ReconciliationSlots
