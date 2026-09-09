import Synchronicity.TrieDiffSemantics

/-! Stored graph meaning of the cursors used by the production diff.
The reference snapshot may contain records that the local replica lacks.
Successful raw reads, not a readiness flag, connect each loaded cursor to it. -/
namespace Synchronicity.TrieCursorSemantics
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie Walk SimulatedHost
open TrieProgramProofs TrieSnapshotProofs TrieSnapshotClosure

def CursorEntry (store : RawSnapshot) : Cursor → Path → ByteArray → Prop
  | .empty, _, _ => False
  | .at node, key, bytes => NodeEntries store node key bytes

def ReferenceEntry (store : RawSnapshot) : Option ByteArray → Path → ByteArray → Prop
  | none, _, _ => False
  | some hash, key, bytes => GraphValue store hash key bytes

theorem read_result (state : State) (space : String) (hash : ByteArray)
    (value : Option ByteArray) (after : State)
    (ran : execute (Walk.storage (E := Diff.Effects) (.readBytes space hash)) state =
      (.ok value, after)) : readByteObject state space hash = .ok value := by
  simp only [Walk.storage, raise, performOver, Inject.inject, ExceptT.mk, execute,
    Interpreter.handle, SimulatedHost.storage, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError] at ran
  | none =>
    cases read : readByteObject state space hash with
    | error failure => simp [failed, read, Except.mapError] at ran
    | ok bytes =>
      simp only [failed, read, Except.mapError, Prod.mk.injEq, Except.ok.injEq] at ran
      exact congrArg Except.ok ran.1

/-- Successful loading describes exactly the referenced graph, even when
other local records are absent and any host request can fail. -/
theorem cursor_at_exact (state : State) (snapshot : RawSnapshot) (reference : Option ByteArray)
    (cursor : Cursor) (included : RecordsIncluded (readableBytes state) snapshot)
    (ran : (execute (cursorAt (E := Diff.Effects) reference) state).1 = .ok cursor) :
    ∀ key bytes, CursorEntry snapshot cursor key bytes ↔ ReferenceEntry snapshot reference key bytes := by
  cases reference with
  | none => cases ran; intro key bytes; rfl
  | some hash =>
    unfold cursorAt at ran
    obtain ⟨value, middle, read, rest⟩ := TrieServePrivacyProofs.bind_ok _ _ state cursor ran
    have rawRead := read_result state nodeSpace hash value middle read
    cases value with
    | none => cases rest
    | some raw =>
      have held : snapshot nodeSpace hash = some raw :=
        included _ _ _ (.inl rfl) (by simp [readableBytes, rawRead])
      cases decoded : decode raw with
      | error message => simp [decoded, execute] at rest
      | ok node =>
        simp only [decoded] at rest
        cases rest
        intro key bytes
        exact (graph_node_entries held decoded).symm

private theorem array_list (path : List UInt8) :
    (ByteArray.mk path.toArray).toList = path := by simp [TrieWalkProofs.toList_eq]

/-- Taking one nibble in an actual cursor preserves precisely that slice
of the snapshot's entries, including compressed leaves and extensions. -/
theorem cursor_child_exact (state : State) (snapshot : RawSnapshot) (parent child : Cursor)
    (nibble : UInt8) (included : RecordsIncluded (readableBytes state) snapshot)
    (ran : (execute (cursorChild (E := Diff.Effects) parent nibble) state).1 = .ok child) :
    ∀ tail bytes, CursorEntry snapshot child tail bytes ↔
      CursorEntry snapshot parent (nibble :: tail) bytes := by
  cases parent with
  | empty => cases ran; intro tail bytes; rfl
  | «at» node =>
    cases node with
    | leaf suffix value =>
      cases path : suffix.toList with
      | nil =>
        simp only [cursorChild, path] at ran
        cases ran
        simp [CursorEntry, NodeEntries, path]
      | cons first rest =>
        by_cases same : first = nibble
        · subst first
          simp only [cursorChild, path, beq_self_eq_true, ↓reduceIte] at ran
          cases ran
          simp [CursorEntry, NodeEntries, path, array_list]
        · simp only [cursorChild, path, beq_iff_eq, same, ↓reduceIte] at ran
          cases ran
          simp [CursorEntry, NodeEntries, path, Ne.symm same]
    | extension segment address =>
      cases path : segment.toList with
      | nil =>
        simp only [cursorChild, path] at ran
        cases ran
        simp [CursorEntry, NodeEntries, path]
      | cons first rest =>
        by_cases same : first = nibble
        · subst first
          cases rest with
          | nil =>
            simp only [cursorChild, path, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte,
              List.isEmpty_nil] at ran
            have loaded := cursor_at_exact state snapshot (some address) child included ran
            simpa [CursorEntry, ReferenceEntry, NodeEntries, path] using loaded
          | cons next rest =>
            simp only [cursorChild, path, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte,
              List.isEmpty_cons] at ran
            cases ran
            simp [CursorEntry, NodeEntries, path, array_list]
        · have unequal : (first != nibble) = true := by simp [same]
          simp only [cursorChild, path, unequal, ↓reduceIte] at ran
          cases ran
          simp [CursorEntry, NodeEntries, path, Ne.symm same]
    | branch children value =>
      have loaded := cursor_at_exact state snapshot ((children[nibble.toNat]?).getD none)
        child included ran
      cases edge : children[nibble.toNat]? with
      | none => simpa [edge, CursorEntry, ReferenceEntry, NodeEntries] using loaded
      | some value =>
        cases value <;> simpa [edge, CursorEntry, ReferenceEntry, NodeEntries] using loaded
    | route children value =>
      have loaded := cursor_at_exact state snapshot ((children[nibble.toNat]?).getD none)
        child included ran
      cases edge : children[nibble.toNat]? with
      | none => simpa [edge, CursorEntry, ReferenceEntry, NodeEntries] using loaded
      | some value =>
        cases value <;> simpa [edge, CursorEntry, ReferenceEntry, NodeEntries] using loaded

private theorem occupied_before_entry (children : List (Option ByteArray)) (offset index : Nat)
    (address : ByteArray) (edge : children[index]? = some (some address)) :
    ∃ found, offset ≤ found ∧ found ≤ offset + index ∧
      Cursor.nextChild.occupied children offset = some (UInt8.ofNat found) := by
  induction children generalizing offset index with
  | nil => simp at edge
  | cons first rest ih =>
    cases first with
    | some _ => exact ⟨offset, Nat.le_refl _, Nat.le_add_right _ _, rfl⟩
    | none =>
      cases index with
      | zero => simp at edge
      | succ index =>
        have tail : rest[index]? = some (some address) := by simpa using edge
        obtain ⟨found, lower, upper, selected⟩ := ih (offset + 1) index tail
        exact ⟨found, by omega, by omega, selected⟩

private theorem branch_next_before_entry (children : List (Option ByteArray))
    (start nibble : UInt8) (child : ByteArray)
    (edge : children[nibble.toNat]? = some (some child)) (lower : start.toNat ≤ nibble.toNat)
    (bounded : nibble.toNat < 16) :
    ∃ found, start.toNat ≤ found.toNat ∧ found.toNat ≤ nibble.toNat ∧
      Cursor.nextChild.occupied (children.drop start.toNat) start.toNat = some found := by
  have remaining : (children.drop start.toNat)[nibble.toNat - start.toNat]? = some (some child) := by
    simpa [List.getElem?_drop, Nat.add_sub_of_le lower] using edge
  obtain ⟨found, first, last, selected⟩ := occupied_before_entry
    (children.drop start.toNat) start.toNat (nibble.toNat - start.toNat) child remaining
  have upper : found ≤ nibble.toNat := by omega
  have converted : (UInt8.ofNat found).toNat = found := by
    exact TrieCodecProofs.toNat_ofNat_of_lt (by omega)
  exact ⟨UInt8.ofNat found, by simpa only [converted] using first,
    by simpa only [converted] using upper, selected⟩

private theorem byte_get_optional (bytes : ByteArray) (index : Nat) :
    bytes[index]? = bytes.data[index]? := by
  simp [getElem?_def, ByteArray.getElem_eq_getElem_data]

/-- A queued entry prevents the cursor's child enumerator from skipping
past its nibble. This is about the actual occupied-slot implementation. -/
theorem next_before_entry (entry : CursorEntry store cursor (nibble :: tail) bytes)
    (start : UInt8) (lower : start.toNat ≤ nibble.toNat) (bounded : nibble.toNat < 16) :
    ∃ found, start.toNat ≤ found.toNat ∧ found.toNat ≤ nibble.toNat ∧
      cursor.nextChild start = some found := by
  cases cursor with
  | empty => cases entry
  | «at» node =>
    cases node with
    | leaf suffix value =>
      obtain ⟨same, _⟩ := entry
      have first : suffix[0]? = some nibble := by
        have index := congrArg (fun path : Path => path[0]?) same.symm
        simpa [TrieWalkProofs.toList_eq, byte_get_optional] using index
      refine ⟨nibble, lower, Nat.le_refl _, ?_⟩
      simp [Cursor.nextChild, first, UInt8.le_iff_toNat_le, lower]
    | extension segment child =>
      obtain ⟨nonempty, rest, same, _⟩ := entry
      cases segmentList : segment.toList with
      | nil => exact False.elim (nonempty segmentList)
      | cons first remaining =>
        have sameFirst : nibble = first := by simpa [segmentList] using congrArg List.head? same
        subst first
        have index : segment[0]? = some nibble := by
          have first := congrArg (fun path : Path => path[0]?) segmentList
          simpa [TrieWalkProofs.toList_eq, byte_get_optional] using first
        refine ⟨nibble, lower, Nat.le_refl _, ?_⟩
        simp [Cursor.nextChild, index, UInt8.le_iff_toNat_le, lower]
    | branch children value =>
      obtain ⟨child, edge, _⟩ := entry
      exact branch_next_before_entry children start nibble child edge lower bounded
    | route children value =>
      obtain ⟨child, edge, _⟩ := entry
      exact branch_next_before_entry children start nibble child edge lower bounded

/-- Pruning a shared addressed child loses no entry on either side. In
particular, a routing node and an ordinary branch can share a child without
their distinct payload representations affecting its meaning. -/
theorem same_child_exact (store : RawSnapshot) (left right : Cursor) (nibble : UInt8)
    (shared : Diff.sameChild left right nibble = true) :
    ∀ tail bytes, CursorEntry store left (nibble :: tail) bytes ↔
      CursorEntry store right (nibble :: tail) bytes := by
  cases left with
  | empty => cases right <;> cases shared
  | «at» a =>
    cases right with
    | empty => cases a <;> cases shared
    | «at» b =>
      cases a <;> cases b <;> simp only [Diff.sameChild] at shared
      all_goals first | contradiction | skip
      all_goals
        split at shared
        · rename_i x y leftAt rightAt
          have same : x = y := eq_of_beq shared
          subst y
          intro tail bytes
          simp only [CursorEntry, NodeEntries]
          have edge (children : List (Option ByteArray))
              (atChild : (children[nibble.toNat]?).getD none = some x) :
              children[nibble.toNat]? = some (some x) := by
            cases h : children[nibble.toNat]? <;> simp_all
          simp [edge _ leftAt, edge _ rightAt]
        · cases shared

/-- The actual lockstep enumerator cannot jump past an entry on either
side. No tree-size bound or termination assumption is used here. -/
theorem next_before_either (left right : Cursor) (store : RawSnapshot)
    (nibble : UInt8) (tail : Path) (bytes : ByteArray) (start : UInt8)
    (entry : CursorEntry store left (nibble :: tail) bytes ∨
      CursorEntry store right (nibble :: tail) bytes)
    (lower : start.toNat ≤ nibble.toNat) (bounded : nibble.toNat < 16) :
    ∃ found, found.toNat ≤ nibble.toNat ∧ Diff.nextChild (left, right) start = some found := by
  rcases entry with entry | entry
  · obtain ⟨found, _, upper, selected⟩ := next_before_entry entry start lower bounded
    cases other : right.nextChild start with
    | none => exact ⟨found, upper, by simp [Diff.nextChild, selected, other]⟩
    | some next =>
      refine ⟨min found next, ?_, by simp [Diff.nextChild, selected, other]⟩
      exact Nat.le_trans (UInt8.le_iff_toNat_le.mp Std.min_le_left) upper
  · obtain ⟨found, _, upper, selected⟩ := next_before_entry entry start lower bounded
    cases other : left.nextChild start with
    | none => exact ⟨found, upper, by simp [Diff.nextChild, selected, other]⟩
    | some next =>
      refine ⟨min next found, ?_, by simp [Diff.nextChild, selected, other]⟩
      exact Nat.le_trans (UInt8.le_iff_toNat_le.mp Std.min_le_right) upper

end Synchronicity.TrieCursorSemantics
