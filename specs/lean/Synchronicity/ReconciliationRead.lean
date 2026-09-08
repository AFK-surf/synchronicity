import Synchronicity.ReconciliationRejection

/-! Relate slot reads to stored pointers and their backing history records.
The hypotheses describe raw relational keys, not a successful policy answer. -/
namespace Synchronicity.ReconciliationRead
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost
open ReconciliationSlots (names)
open TransactionSuccess (bind_success)

def qualify (relation : String) (row : Fields) : Fields :=
  row.map fun (column, value) => (relation ++ "." ++ column, value)

def base (row : Fields) : Fields := row ++ qualify "heads" row

def joined (row history : Fields) : Fields := base row ++ qualify "head_history" history

theorem cell_append_absent (row extra : Fields) (column : String)
    (absent : ∀ field ∈ extra, field.1 ≠ column) : cell (row ++ extra) column = cell row column := by
  have missing : extra.find? (fun field => field.1 == column) = none := by
    apply List.find?_eq_none.mpr
    intro field member
    simp [absent field member]
  simp [cell, List.find?_append, missing]

theorem qualify_absent (relation : String) (row : Fields) (column : String)
    (different : ∀ name, relation ++ "." ++ name ≠ column) :
    ∀ field ∈ qualify relation row, field.1 ≠ column := by
  intro field member
  obtain ⟨⟨name, value⟩, _, rfl⟩ := List.mem_map.mp member
  exact different name

theorem base_cell (row : Fields) (column : String)
    (key : column ∈ ["origin_id", "slot", "seq", "root"]) : cell (base row) column = cell row column := by
  apply cell_append_absent
  apply qualify_absent
  intro name same
  have same := congrArg String.toList same
  simp only [List.mem_cons, List.not_mem_nil, or_false] at key
  rcases key with rfl | rfl | rfl | rfl <;> simp [String.toList_append] at same

theorem joined_cell (row history : Fields) (column : String)
    (key : column ∈ ["origin_id", "slot", "seq", "root"]) :
    cell (joined row history) column = cell row column := by
  unfold joined
  rw [cell_append_absent, base_cell row column key]
  apply qualify_absent
  intro name same
  have same := congrArg String.toList same
  simp only [List.mem_cons, List.not_mem_nil, or_false] at key
  rcases key with rfl | rfl | rfl | rfl <;> simp [String.toList_append] at same

theorem joined_names (row history : Fields) (origin slot : String) :
    names (joined row history) origin slot = names row origin slot := by
  simp [names, equals, joined_cell]

theorem base_correlated (row history : Fields) :
    correlated (base row) history [("origin_id", "origin_id"), ("seq", "seq"), ("root", "root")] =
    correlated row history [("origin_id", "origin_id"), ("seq", "seq"), ("root", "root")] := by
  simp [correlated, base_cell]

theorem slot_query (db : Database) (origin slot : String) :
    query db "heads" History.headColumns [("origin_id", .text origin), ("slot", .text slot)] [] History.headJoin =
      (((rows db "heads").flatMap fun row =>
        ((rows db "head_history").filter fun history =>
          correlated row history [("origin_id", "origin_id"), ("seq", "seq"), ("root", "root")]).map
            (joined row)).filter fun row => names row origin slot).map (project History.headColumns) := by
  have sorted (rs : List Fields) : sortRows (ordered []) rs = rs := by
    induction rs with
    | nil => rfl
    | cons row rest ih => rw [sortRows, ih]; cases rest <;> rfl
  simp only [query, History.headJoin, List.isEmpty_cons, Bool.false_eq_true, ↓reduceIte,
    joinedRows, List.foldl_cons, List.foldl_nil, List.flatMap_map, sorted]
  congr 3
  funext row
  change ((rows db "head_history").filter fun history => correlated (base row) history
    [("origin_id", "origin_id"), ("seq", "seq"), ("root", "root")]).map (joined row) = _
  simp only [base_correlated]

/-- A stored slot has a backing history key, and every row selected by its
origin/slot key agrees on its pointer. Ordinary primary-key uniqueness implies
the latter; neither a successful decoder nor a comparison result is assumed. -/
structure StoredFloor (db : Database) (origin slot : String) (seq : Int64) (root : ByteArray) : Prop where
  backed : ∃ row ∈ rows db "heads", names row origin slot = true ∧
    ∃ history ∈ rows db "head_history",
      correlated row history [("origin_id", "origin_id"), ("seq", "seq"), ("root", "root")] = true
  pointer : ∀ row ∈ rows db "heads", names row origin slot = true →
    cell row "seq" = .integer seq ∧ cell row "root" = .blob root

def pointerProjection (row : Row) (seq : Int64) (root : ByteArray) : Prop :=
  ∃ origin created key sig received verified,
    row = [origin, .integer seq, .blob root, created, key, sig, received, verified]

theorem query_has_floor (db : Database) (origin slot : String) (seq : Int64) (root : ByteArray)
    (stored : StoredFloor db origin slot seq root) :
    let result := query db "heads" History.headColumns
      [("origin_id", .text origin), ("slot", .text slot)] [] History.headJoin
    result ≠ [] ∧ ∀ row ∈ result, pointerProjection row seq root := by
  rw [slot_query]
  constructor
  · obtain ⟨row, member, named, history, retained, linked⟩ := stored.backed
    have present : joined row history ∈
        (((rows db "heads").flatMap fun row =>
          ((rows db "head_history").filter fun history => correlated row history
            [("origin_id", "origin_id"), ("seq", "seq"), ("root", "root")]).map (joined row)).filter
              fun row => names row origin slot) := by
      apply List.mem_filter.mpr
      refine ⟨List.mem_flatMap.mpr ⟨row, member, ?_⟩, ?_⟩
      · exact List.mem_map.mpr ⟨history, List.mem_filter.mpr ⟨retained, linked⟩, rfl⟩
      · simpa only [joined_names] using named
    intro empty
    have := (List.mem_map (f := project History.headColumns)).mpr ⟨joined row history, present, rfl⟩
    rw [empty] at this
    exact List.not_mem_nil this
  · intro projected member
    obtain ⟨joinedRow, selected, rfl⟩ := List.mem_map.mp member
    obtain ⟨joinedMember, named⟩ := List.mem_filter.mp selected
    obtain ⟨row, rowMember, historyMember⟩ := List.mem_flatMap.mp joinedMember
    obtain ⟨history, _, rfl⟩ := List.mem_map.mp historyMember
    rw [joined_names] at named
    obtain ⟨sequence, hash⟩ := stored.pointer row rowMember named
    refine ⟨cell (joined row history) "origin_id", cell (joined row history) "head_history.created_at",
      cell (joined row history) "head_history.signed_by", cell (joined row history) "head_history.sig",
      cell (joined row history) "received_at", cell (joined row history) "verified_at", ?_⟩
    simp [project, History.headColumns, joined_cell, sequence, hash]

theorem decoded_fields_pointer (row : Row) (seq : Int64) (root : ByteArray)
    (shape : pointerProjection row seq root) (head : History.JoinedHead)
    (decoded : History.decodeJoinedFields row = .ok head) :
    head.pointer = ⟨seq.toUInt64, root⟩ := by
  obtain ⟨origin, created, key, sig, received, verified, rfl⟩ := shape
  simp only [History.decodeJoinedFields, History.integerField, History.blobField,
    bind, Except.bind, pure, Except.pure] at decoded
  repeat' first
    | split at decoded
    | (cases decoded; rfl)
    | contradiction

theorem decoded_head_pointer (row : Row) (seq : Int64) (root : ByteArray)
    (shape : pointerProjection row seq root) (state : State) (head : History.JoinedHead)
    (decoded : (execute (History.decodeJoinedHead row) state).1 = .ok head) :
    head.pointer = ⟨seq.toUInt64, root⟩ := by
  unfold History.decodeJoinedHead at decoded
  obtain ⟨fields, _, projected, decoded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ decoded
  have projected : History.decodeJoinedFields row = .ok fields := congrArg Prod.fst projected
  have pointer := decoded_fields_pointer row seq root shape fields projected
  obtain ⟨_, _, _, decoded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ decoded
  obtain ⟨_, _, _, decoded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ decoded
  obtain ⟨_, _, _, decoded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ decoded
  split at decoded
  · cases decoded
  · obtain ⟨_, _, _, decoded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ decoded
    split at decoded
    · cases decoded
    · have same : fields = head := Except.ok.inj decoded
      subst head
      exact pointer

theorem scan_rows (tx : Transaction) (db : Database) (state : State)
    (opened : state.pending = some (tx, db)) (origin slot : String) (scan : Scan)
    (succeeded : (execute (History.request (.scanRows tx "heads" History.headColumns
      [("origin_id", .text origin), ("slot", .text slot)] [] History.headJoin)) state).1 = .ok scan) :
    scan.rows = query db "heads" History.headColumns
      [("origin_id", .text origin), ("slot", .text slot)] [] History.headJoin := by
  change ((storage (.scanRows tx "heads" History.headColumns
    [("origin_id", .text origin), ("slot", .text slot)] [] History.headJoin) state).1.mapError
      History.Error.host) = .ok scan at succeeded
  simp only [storage, reply] at succeeded
  split at succeeded
  · cases succeeded
  · simp only [SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte,
      Except.mapError] at succeeded
    cases succeeded
    rfl

/-- A successful real slot read cannot forget a backed stored floor. Malformed
metadata or primitive failures may make the read fail; they cannot manufacture
successful absence or a different pointer. No fault-free premise is required. -/
theorem readSlot_retains_floor (tx : Transaction) (db : Database) (state : State)
    (opened : state.pending = some (tx, db)) (origin slot : String) (seq : Int64) (root : ByteArray)
    (stored : StoredFloor db origin slot seq root) (result : List History.JoinedHead)
    (succeeded : (execute (History.readSlot tx origin slot) state).1 = .ok result) :
    ∃ head, result = [head] ∧ head.pointer = ⟨seq.toUInt64, root⟩ := by
  unfold History.readSlot at succeeded
  obtain ⟨scan, middle, scanned, succeeded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ succeeded
  have queried := scan_rows tx db state opened origin slot scan (congrArg Prod.fst scanned)
  obtain ⟨nonempty, pointers⟩ := query_has_floor db origin slot seq root stored
  rw [← queried] at nonempty pointers
  split at succeeded
  · rename_i empty
    exact False.elim (nonempty empty)
  · rename_i row rest nonemptyRows
    obtain ⟨head, _, decoded, returned⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ succeeded
    have shape : pointerProjection row seq root := by
      apply pointers
      rw [nonemptyRows]
      exact List.mem_cons_self
    refine ⟨head, (Except.ok.inj returned).symm, ?_⟩
    exact decoded_head_pointer row seq root shape middle head (congrArg Prod.fst decoded)

end Synchronicity.ReconciliationRead
