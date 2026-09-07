import VerifiedCore.Trie.ScopeCheck
import Synchronicity.TrieSnapshotClosure
import Synchronicity.TrieWalkProofs

/-! A publication scope check must account for independently defined snapshot
entries, rather than assuming that the walk visited everything it needed to.
All executable observations below use the shared raw host interpreter. -/
namespace Synchronicity.TrieScopeCheckProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie Walk SimulatedHost
open TrieProgramProofs TrieSnapshotProofs TrieSnapshotClosure

/-- The raw snapshot visible to the current storage transaction. -/
private def view (state : State) : RawSnapshot := readableBytes state

/-- Meaning of the real walk cursor, including virtual compressed suffixes. -/
private def CursorEntry (store : RawSnapshot) : Cursor → Path → ByteArray → Prop
  | .empty, _, _ => False
  | .at node, path, bytes => NodeEntries store node path bytes

@[simp] private theorem view_record (state : State) (event : String) :
    view (record state event) = view state := rfl

private theorem held_reply {state : State} {space : String} {hash raw : ByteArray} (held : view state space hash = some raw) :
    readByteObject state space hash = .ok (some raw) := by
  cases reply : readByteObject state space hash with
  | error _ => simp [view, readableBytes, reply] at held
  | ok bytes => simpa [view, readableBytes, reply] using held

private theorem cursor_at_reads (state : State) (hash raw : ByteArray) (node : Node)
    (quiet : state.faults = []) (held : view state nodeSpace hash = some raw)
    (decoded : decode raw = .ok node) :
    SimulatedHost.execute (cursorAt (E := Walk.Effects) (some hash)).run state =
      (.ok (.at node), record state ("bytes:" ++ nodeSpace)) := by
  have rawRead := held_reply held
  simp [cursorAt, Walk.storage, raise, performOver, Inject.inject,
    bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, ExceptT.run, execute,
    Program.bind, Interpreter.handle, SimulatedHost.storage, reply, fault, quiet,
    rawRead, decoded, pure, ExceptT.pure, Except.mapError, record]

private theorem load_entry (state : State) (hash : ByteArray) (key : Path) (bytes : ByteArray)
    (quiet : state.faults = []) (entry : GraphValue (view state) hash key bytes) :
    let result := SimulatedHost.execute (cursorAt (E := Walk.Effects) (some hash)).run state
    ∃ cursor, result.1 = .ok cursor ∧ view result.2 = view state ∧ result.2.faults = [] ∧
      CursorEntry (view state) cursor key bytes := by
  have stored : ∃ raw node, view state nodeSpace hash = some raw ∧ decode raw = .ok node := by
    cases entry <;> exact ⟨_, _, by assumption, by assumption⟩
  obtain ⟨raw, node, held, decoded⟩ := stored
  rw [cursor_at_reads state hash raw node quiet held decoded]
  exact ⟨.at node, rfl, rfl, quiet, (graph_node_entries held decoded).mp entry⟩

private theorem terminal_has_value (entry : CursorEntry store cursor [] bytes) :
    cursor.value.isSome = true := by
  cases cursor with
  | empty => cases entry
  | «at» node =>
    cases node with
    | leaf suffix value =>
      obtain ⟨same, _⟩ := entry
      have zero : suffix.size = 0 := by
        have length := congrArg List.length same
        simpa only [byte_array_list_length, List.length_nil] using length.symm
      simp [Cursor.value, zero]
    | extension segment child =>
      obtain ⟨nonempty, tail, same, _⟩ := entry
      have empty : segment.toList = [] := by
        have lengths := congrArg List.length same
        have zero : segment.toList.length = 0 := by
          simp only [List.length_nil, List.length_append] at lengths
          omega
        exact List.eq_nil_of_length_eq_zero zero
      exact False.elim (nonempty empty)
    | branch children value =>
      obtain ⟨v, same, _⟩ := entry
      simp [Cursor.value, same]
    | route children value =>
      obtain ⟨v, same, _⟩ := entry
      simp [Cursor.value, same]

/-- Following an entry's next nibble preserves its independently defined
meaning and the raw snapshot, using the real cursor loader when necessary. -/
private theorem child_entry (state : State) (cursor : Cursor) (nibble : UInt8)
    (tail : Path) (bytes : ByteArray) (quiet : state.faults = [])
    (entry : CursorEntry (view state) cursor (nibble :: tail) bytes) :
    let result := SimulatedHost.execute (cursorChild (E := Walk.Effects) cursor nibble).run state
    ∃ child, result.1 = .ok child ∧ view result.2 = view state ∧ result.2.faults = [] ∧
      CursorEntry (view state) child tail bytes := by
  cases cursor with
  | empty => cases entry
  | «at» node =>
    cases node with
    | leaf suffix value =>
      obtain ⟨same, denotes⟩ := entry
      have suffixList : suffix.toList = nibble :: tail := same.symm
      simp only [cursorChild, suffixList, beq_self_eq_true, ↓reduceIte,
        pure, ExceptT.pure, ExceptT.run]
      refine ⟨_, rfl, rfl, quiet, ?_⟩
      exact ⟨by simp [TrieWalkProofs.toList_eq], denotes⟩
    | extension segment child =>
      obtain ⟨nonempty, rest, same, below⟩ := entry
      cases segmentList : segment.toList with
      | nil => exact False.elim (nonempty segmentList)
      | cons first remaining =>
        simp only [segmentList, List.cons_append, List.cons.injEq] at same
        obtain ⟨rfl, rfl⟩ := same
        cases remaining with
        | nil =>
          simpa only [cursorChild, segmentList, beq_self_eq_true, bne_self_eq_false,
            Bool.false_eq_true, ↓reduceIte, List.isEmpty_nil, List.nil_append] using
            load_entry state child rest bytes quiet below
        | cons next remaining =>
          simp only [cursorChild, segmentList, bne_self_eq_false, Bool.false_eq_true,
            ↓reduceIte, List.isEmpty_cons, pure, ExceptT.pure, ExceptT.run]
          refine ⟨_, rfl, rfl, quiet, ?_⟩
          exact ⟨by simp [TrieWalkProofs.toList_eq], rest, by simp [TrieWalkProofs.toList_eq], below⟩
    | branch children value =>
      obtain ⟨child, edge, below⟩ := entry
      simpa only [cursorChild, edge, Option.getD_some] using load_entry state child tail bytes quiet below
    | route children value =>
      obtain ⟨child, edge, below⟩ := entry
      simpa only [cursorChild, edge, Option.getD_some] using load_entry state child tail bytes quiet below

private theorem subtree_grants_entry (scope : Serve.Scope) (path tail : Path)
    (granted : scope.containsSubtree path = true) : scope.admitsKeyPath (path ++ tail) = true := by
  simp only [Serve.Scope.admitsKeyPath, Bool.or_eq_true]
  exact .inl (TrieServeProofs.containsSubtree_append scope path tail granted)

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
private theorem next_before_entry (entry : CursorEntry store cursor (nibble :: tail) bytes)
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

private theorem cursor_at_preserves (state : State) (hash : Option ByteArray)
    (quiet : state.faults = []) :
    let result := execute (cursorAt (E := Walk.Effects) hash).run state
    view result.2 = view state ∧ result.2.faults = [] := by
  cases hash with
  | none => exact ⟨rfl, quiet⟩
  | some hash =>
    cases rawRead : readByteObject state nodeSpace hash with
    | error failure =>
      simp [cursorAt, Walk.storage, raise, performOver, Inject.inject,
        bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, ExceptT.run, execute,
        Program.bind, Interpreter.handle, SimulatedHost.storage, reply, fault, quiet,
        rawRead, pure, ExceptT.pure, Except.mapError, record]
      rfl
    | ok value =>
      cases value with
      | none =>
        simp [cursorAt, Walk.storage, raise, performOver, Inject.inject,
          bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, ExceptT.run, execute,
          Program.bind, Interpreter.handle, SimulatedHost.storage, reply, fault, quiet,
          rawRead, pure, ExceptT.pure, Except.mapError, record]
        rfl
      | some bytes =>
        cases decoded : decode bytes <;>
          simp [cursorAt, Walk.storage, raise, performOver, Inject.inject,
            bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, ExceptT.run, execute,
            Program.bind, Interpreter.handle, SimulatedHost.storage, reply, fault, quiet,
            rawRead, decoded, pure, ExceptT.pure, Except.mapError, record] <;> rfl

private theorem child_preserves (state : State) (cursor : Cursor) (nibble : UInt8)
    (quiet : state.faults = []) :
    let result := execute (cursorChild (E := Walk.Effects) cursor nibble).run state
    view result.2 = view state ∧ result.2.faults = [] := by
  cases cursor with
  | empty => exact ⟨rfl, quiet⟩
  | «at» node =>
    cases node with
    | leaf suffix value =>
      simp only [cursorChild]
      split
      · split <;> exact ⟨rfl, quiet⟩
      · exact ⟨rfl, quiet⟩
    | extension segment child =>
      simp only [cursorChild]
      split
      · split
        · exact ⟨rfl, quiet⟩
        · split
          · exact cursor_at_preserves state (some child) quiet
          · exact ⟨rfl, quiet⟩
      · exact ⟨rfl, quiet⟩
    | branch children value => exact cursor_at_preserves state _ quiet
    | route children value => exact cursor_at_preserves state _ quiet

/-- The actual position check cannot quietly discard a cursor that still
contains an entry outside the publisher's grant. -/
private theorem inspect_keeps_ungranted (state : State) (scope : Serve.Scope)
    (cursor : Cursor) (path tail : Path) (bytes : ByteArray)
    (entry : CursorEntry (view state) cursor tail bytes)
    (outside : scope.admitsKeyPath (path ++ tail) = false)
    (decision : Step Cursor)
    (success : (execute (ScopeCheck.inspect scope cursor path).run state).1 =
      .ok (decision, none)) : decision = .descend cursor ∧ tail ≠ [] := by
  have notSubtree : scope.containsSubtree path = false := by
    cases granted : scope.containsSubtree path with
    | false => rfl
    | true => have := subtree_grants_entry scope path tail granted; simp [outside] at this
  have nonterminal : tail ≠ [] := by
    intro empty
    subst tail
    have occupied := terminal_has_value entry
    simp only [List.append_nil] at outside
    simp [ScopeCheck.inspect, notSubtree, occupied, outside, pure, ExceptT.pure,
      ExceptT.mk, ExceptT.run, execute] at success
  constructor
  · simp only [ScopeCheck.inspect, notSubtree, Bool.false_eq_true, ↓reduceIte] at success
    split at success
    · simp [pure, ExceptT.pure, ExceptT.mk, ExceptT.run, execute] at success
    · split at success
      · simp [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, ExceptT.run, Program.bind] at success
      · simpa [pure, ExceptT.pure, ExceptT.mk, ExceptT.run, execute] using success.symm
  · exact nonterminal

private theorem inspect_preserves_state (state : State) (scope : Serve.Scope)
    (cursor : Cursor) (path : Path) :
    (execute (ScopeCheck.inspect scope cursor path).run state).2 = state := by
  simp only [ScopeCheck.inspect]
  split
  · rfl
  · split
    · rfl
    · split <;> rfl

private theorem inspect_stop_reports_violation (state : State) (scope : Serve.Scope)
    (cursor : Cursor) (path : Path)
    (success : (execute (ScopeCheck.inspect scope cursor path).run state).1 = .ok (.stop, none)) :
    False := by
  simp only [ScopeCheck.inspect] at success
  split at success
  · cases success
  · split at success
    · cases success
    · split at success <;> cases success

private theorem step_keeps_ungranted (state : State) (scope : Serve.Scope)
    (parent : Cursor) (path : Path) (nibble : UInt8) (tail : Path) (bytes : ByteArray)
    (quiet : state.faults = [])
    (entry : CursorEntry (view state) parent (nibble :: tail) bytes)
    (outside : scope.admitsKeyPath (path ++ tail) = false)
    (acc : Option ByteArray) (decision : Step Cursor)
    (success : (execute (ScopeCheck.step scope acc parent nibble path).run state).1 =
      .ok (decision, none)) :
    ∃ child, decision = .descend child ∧ tail ≠ [] ∧
      CursorEntry (view state) child tail bytes := by
  have notSubtree : scope.containsSubtree path = false := by
    cases granted : scope.containsSubtree path with
    | false => rfl
    | true => have := subtree_grants_entry scope path tail granted; simp [outside] at this
  simp only [ScopeCheck.step, notSubtree, Bool.false_eq_true, ↓reduceIte] at success
  split at success
  · cases success
  · obtain ⟨child, loaded, sameView, quiet', meaning⟩ := child_entry state parent nibble tail bytes quiet entry
    simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run] at success
    rw [execute_bind] at success
    simp only [ExceptT.run] at loaded
    simp only [ExceptT.bindCont, loaded] at success
    have meaning' : CursorEntry
        (view (execute (cursorChild (E := Walk.Effects) parent nibble).run state).2) child tail bytes := by
      simpa only [sameView] using meaning
    obtain ⟨same, remaining⟩ := inspect_keeps_ungranted _ scope child path tail bytes
      meaning' outside decision success
    exact ⟨child, same, remaining, meaning⟩

private theorem inspect_continues_none (state : State) (scope : Serve.Scope)
    (cursor : Cursor) (path : Path) (decision : Step Cursor) (answer : Option ByteArray)
    (success : (execute (ScopeCheck.inspect scope cursor path).run state).1 = .ok (decision, answer))
    (continues : decision ≠ .stop) : answer = none := by
  simp only [ScopeCheck.inspect] at success
  split at success
  · cases success; rfl
  · split at success
    · cases success; exact False.elim (continues rfl)
    · split at success
      · cases success
      · cases success; rfl

private theorem step_continues_none (state : State) (scope : Serve.Scope)
    (parent : Cursor) (path : Path) (nibble : UInt8) (acc : Option ByteArray)
    (decision : Step Cursor) (answer : Option ByteArray)
    (success : (execute (ScopeCheck.step scope acc parent nibble path).run state).1 = .ok (decision, answer))
    (continues : decision ≠ .stop) : answer = none := by
  simp only [ScopeCheck.step] at success
  split at success
  · cases success; rfl
  · split at success
    · cases success; exact False.elim (continues rfl)
    · simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run] at success
      rw [execute_bind] at success
      generalize execute (cursorChild (E := Walk.Effects) parent nibble) state = childResult at success
      obtain ⟨reply, after⟩ := childResult
      cases reply with
      | error error => cases success
      | ok child => exact inspect_continues_none after scope child path decision answer success continues

private theorem step_preserves (state : State) (scope : Serve.Scope)
    (parent : Cursor) (path : Path) (nibble : UInt8) (acc : Option ByteArray)
    (quiet : state.faults = []) :
    let result := execute (ScopeCheck.step scope acc parent nibble path).run state
    view result.2 = view state ∧ result.2.faults = [] ∧
      result.1 ≠ .ok (.stop, none) := by
  simp only [ScopeCheck.step]
  split
  · exact ⟨rfl, quiet, by intro impossible; cases impossible⟩
  · split
    · exact ⟨rfl, quiet, by intro impossible; cases impossible⟩
    · simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run]
      rw [execute_bind]
      have preserved := child_preserves state parent nibble quiet
      simp only [ExceptT.run] at preserved
      generalize execute (cursorChild (E := Walk.Effects) parent nibble) state = childResult at preserved ⊢
      obtain ⟨answer, after⟩ := childResult
      obtain ⟨same, quiet'⟩ := preserved
      cases answer with
      | error error => exact ⟨same, quiet', by intro impossible; cases impossible⟩
      | ok child =>
        simp only [ExceptT.bindCont]
        have unchanged := inspect_preserves_state after scope child path
        simp only [ExceptT.run] at unchanged
        exact ⟨by simpa only [ExceptT.run, unchanged] using same,
          by simpa only [ExceptT.run, unchanged] using quiet',
          inspect_stop_reports_violation after scope child path⟩

/-- A still-unchecked entry is attached to a real queued frame, at or after
that frame's next child. Empty suffixes have already been checked by inspect. -/
private def PendingEntry (store : RawSnapshot) (key : Path) (bytes : ByteArray)
    (stack : List (Frame Cursor)) : Prop :=
  ∃ frame ∈ stack, ∃ nibble tail,
    key = frame.2.2 ++ (nibble :: tail) ∧
    frame.2.1.toNat ≤ nibble.toNat ∧
    CursorEntry store frame.1 (nibble :: tail) bytes

private theorem pending_cons_of_tail (pending : PendingEntry store key bytes stack)
    (frame : Frame Cursor) : PendingEntry store key bytes (frame :: stack) := by
  obtain ⟨witness, member, nibble, tail, rest⟩ := pending
  exact ⟨witness, List.mem_cons_of_mem frame member, nibble, tail, rest⟩

private theorem pending_head_cannot_be_pruned
    (key : Path) (bytes : ByteArray) (frame : Cursor) (start : UInt8) (path : Path)
    (nibble : UInt8) (tail : Path)
    (same : key = path ++ (nibble :: tail))
    (length : key.length ≤ maxDepthNibbles)
    (nibbles : ∀ n ∈ key, n.toNat < 16)
    (lower : start.toNat ≤ nibble.toNat)
    (entry : CursorEntry store frame (nibble :: tail) bytes) :
    ∃ found,
      (if start.toNat ≥ 16 || path.length ≥ maxDepthNibbles then none
       else (frame.nextChild start).filter (·.toNat < 16)) = some found ∧
      found.toNat ≤ nibble.toNat := by
  have member : nibble ∈ key := by simp [same]
  have bounded := nibbles nibble member
  have depth : path.length < maxDepthNibbles := by
    simp only [same, List.length_append, List.length_cons] at length
    omega
  obtain ⟨found, _, upper, selected⟩ := next_before_entry entry start lower bounded
  refine ⟨found, ?_, upper⟩
  have startBound : ¬start.toNat ≥ 16 := by omega
  have foundBound : found.toNat < 16 := by omega
  simp [startBound, Nat.not_le_of_lt depth, selected, foundBound]

private theorem pending_after_earlier (store : RawSnapshot) (key : Path) (bytes : ByteArray)
    (frame : Cursor) (path : Path) (stack : List (Frame Cursor))
    (nibble chosen : UInt8) (tail : Path)
    (same : key = path ++ (nibble :: tail))
    (entry : CursorEntry store frame (nibble :: tail) bytes)
    (earlier : chosen.toNat < nibble.toNat) (bounded : nibble.toNat < 16) :
    PendingEntry store key bytes ((frame, chosen + 1, path) :: stack) := by
  refine ⟨(frame, chosen + 1, path), List.mem_cons_self .., nibble, tail, same, ?_, entry⟩
  simp only [UInt8.toNat_add, UInt8.toNat_ofNat]
  omega

private theorem pending_after_target (store : RawSnapshot) (key : Path) (bytes : ByteArray)
    (child : Cursor) (path : Path) (nibble : UInt8) (tail : Path) (stack : List (Frame Cursor))
    (same : key = path ++ (nibble :: tail))
    (nonempty : tail ≠ []) (entry : CursorEntry store child tail bytes) :
    PendingEntry store key bytes ((child, 0, path ++ [nibble]) :: stack) := by
  cases tail with
  | nil => exact False.elim (nonempty rfl)
  | cons next rest =>
    refine ⟨(child, 0, path ++ [nibble]), List.mem_cons_self .., next, rest, ?_, Nat.zero_le _, entry⟩
    simpa only [List.append_assoc, List.singleton_append] using same

private theorem queue_after_step (state : State) (scope : Serve.Scope)
    (key : Path) (bytes : ByteArray) (frame : Cursor) (start chosen : UInt8)
    (path : Path) (stack : List (Frame Cursor)) (acc : Option ByteArray) (decision : Step Cursor)
    (quiet : state.faults = []) (length : key.length ≤ maxDepthNibbles)
    (nibbles : ∀ n ∈ key, n.toNat < 16)
    (outside : scope.admitsKeyPath key = false)
    (pending : PendingEntry (view state) key bytes ((frame, start, path) :: stack))
    (selected : (if start.toNat ≥ 16 || path.length ≥ maxDepthNibbles then none
      else (frame.nextChild start).filter (·.toNat < 16)) = some chosen)
    (success : (execute (ScopeCheck.step scope acc frame chosen (path ++ [chosen])).run state).1 =
      .ok (decision, none)) :
    (∀ child, decision = .descend child → PendingEntry (view state) key bytes
      ((child, 0, path ++ [chosen]) :: (frame, chosen + 1, path) :: stack)) ∧
    (decision = .skip ∨ decision = .visited → PendingEntry (view state) key bytes
      ((frame, chosen + 1, path) :: stack)) := by
  obtain ⟨queued, member, nibble, tail, same, lower, entry⟩ := pending
  rcases List.mem_cons.mp member with head | later
  · subst queued
    obtain ⟨found, foundAt, upper⟩ := pending_head_cannot_be_pruned key bytes frame start path nibble tail
      same length nibbles lower entry
    have foundChosen : found = chosen := Option.some.inj (foundAt.symm.trans selected)
    subst found
    have bounded : nibble.toNat < 16 := nibbles nibble (by simp [same])
    by_cases target : chosen = nibble
    · subst chosen
      have denied : scope.admitsKeyPath ((path ++ [nibble]) ++ tail) = false := by
        simpa only [List.append_assoc, List.singleton_append, ← same] using outside
      obtain ⟨child, decisionIs, remaining, meaning⟩ := step_keeps_ungranted state scope frame
        (path ++ [nibble]) nibble tail bytes quiet entry denied acc decision success
      constructor
      · intro actual sameChild
        have : child = actual := by cases decisionIs.symm.trans sameChild; rfl
        subst actual
        exact pending_after_target (view state) key bytes child path nibble tail _ same remaining meaning
      · intro skipped
        rcases skipped with skipped | visited
        · cases decisionIs.symm.trans skipped
        · cases decisionIs.symm.trans visited
    · have earlier : chosen.toNat < nibble.toNat := by
        have different : chosen.toNat ≠ nibble.toNat := fun equal => target (UInt8.toNat_inj.mp equal)
        omega
      have retained := pending_after_earlier (view state) key bytes frame path stack nibble chosen tail
        same entry earlier bounded
      exact ⟨fun child _ => pending_cons_of_tail retained _, fun _ => retained⟩
  · have retained : PendingEntry (view state) key bytes stack :=
      ⟨queued, later, nibble, tail, same, lower, entry⟩
    exact ⟨fun child _ => pending_cons_of_tail (pending_cons_of_tail retained _) _,
      fun _ => pending_cons_of_tail retained _⟩

private theorem descend_preserves_pending (state : State) (scope : Serve.Scope)
    (key : Path) (bytes : ByteArray) (d : Descent Cursor (Option ByteArray))
    (quiet : state.faults = []) (length : key.length ≤ maxDepthNibbles)
    (nibbles : ∀ n ∈ key, n.toNat < 16)
    (outside : scope.admitsKeyPath key = false)
    (pending : PendingEntry (view state) key bytes d.stack) :
    let result := execute (descend Cursor.nextChild (ScopeCheck.step scope) d).run state
    (∀ next, result.1 = .ok (.inl next) →
      result.2.faults = [] ∧ PendingEntry (view result.2) key bytes next.stack) ∧
    result.1 ≠ .ok (.inr none) := by
  match d with
  | ⟨[], positions, acc⟩ =>
    obtain ⟨_, member, _⟩ := pending
    cases member
  | ⟨(frame, start, path) :: stack, positions, acc⟩ =>
    simp only [Walk.descend]
    split
    · rename_i absent
      have remaining : PendingEntry (view state) key bytes stack := by
        obtain ⟨queued, member, nibble, tail, same, lower, entry⟩ := pending
        rcases List.mem_cons.mp member with head | later
        · subst queued
          obtain ⟨found, selected, _⟩ := pending_head_cannot_be_pruned key bytes frame start path nibble tail
            same length nibbles lower entry
          simp only [absent] at selected
          cases selected
        · exact ⟨queued, later, nibble, tail, same, lower, entry⟩
      constructor
      · intro next same
        cases same
        exact ⟨quiet, remaining⟩
      · intro impossible; cases impossible
    · rename_i chosen selected
      simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run]
      rw [execute_bind]
      have preserved := step_preserves state scope frame (path ++ [chosen]) chosen acc quiet
      have queues := fun decision => queue_after_step state scope key bytes frame start chosen path stack acc
        decision quiet length nibbles outside pending selected
      have continues := fun decision answer => step_continues_none state scope frame (path ++ [chosen])
        chosen acc decision answer
      simp only [ExceptT.run] at preserved queues continues
      generalize execute (ScopeCheck.step scope acc frame chosen (path ++ [chosen])) state = stepResult
        at preserved queues continues ⊢
      obtain ⟨reply, after⟩ := stepResult
      obtain ⟨sameView, quiet', noSilentStop⟩ := preserved
      cases reply with
      | error error => simp [ExceptT.bindCont]
      | ok reply =>
        obtain ⟨decision, answer⟩ := reply
        cases decision with
        | descend child =>
          have noStop : Step.descend child ≠ (Step.stop : Step Cursor) := by intro impossible; cases impossible
          have answerNone := continues (.descend child) answer rfl noStop
          subst answer
          have kept := (queues (.descend child) rfl).1 child rfl
          have kept' : PendingEntry (view after) key bytes
              ((child, 0, path ++ [chosen]) :: (frame, chosen + 1, path) :: stack) := by
            simpa only [sameView] using kept
          simp only [ExceptT.bindCont]
          split
          · simp [Program.bind, ExceptT.bindCont]
          · constructor
            · intro next same; cases same; exact ⟨quiet', kept'⟩
            · intro impossible; cases impossible
        | visited =>
          have noStop : (Step.visited : Step Cursor) ≠ .stop := by intro impossible; cases impossible
          have answerNone := continues .visited answer rfl noStop
          subst answer
          have kept := (queues .visited rfl).2 (.inr rfl)
          have kept' : PendingEntry (view after) key bytes ((frame, chosen + 1, path) :: stack) := by
            simpa only [sameView] using kept
          simp only [ExceptT.bindCont]
          split
          · simp [Program.bind, ExceptT.bindCont]
          · constructor
            · intro next same; cases same; exact ⟨quiet', kept'⟩
            · intro impossible; cases impossible
        | skip =>
          have noStop : (Step.skip : Step Cursor) ≠ .stop := by intro impossible; cases impossible
          have answerNone := continues .skip answer rfl noStop
          subst answer
          have kept := (queues .skip rfl).2 (.inl rfl)
          have kept' : PendingEntry (view after) key bytes ((frame, chosen + 1, path) :: stack) := by
            simpa only [sameView] using kept
          constructor
          · intro next same; cases same; exact ⟨quiet', kept'⟩
          · intro impossible; cases impossible
        | stop =>
          cases answer with
          | none => exact False.elim (noSilentStop rfl)
          | some answer =>
            constructor
            · intro next impossible; cases impossible
            · intro impossible; cases impossible

/-- State-aware induction over the same effect-counted interpreter loop.
The postcondition is required only on successful returns, so an exhausted
budget cannot accidentally turn an unchecked entry into a certificate. -/
private theorem iterate_state_sound [Interpreter E]
    (body : S → Program E (Except ε (S ⊕ R))) (exhausted : ε)
    (P : State → S → Prop) (Q : R → Prop)
    (kept : ∀ start state next, P state start →
      (execute (body start) state).1 = .ok (.inl next) → P (execute (body start) state).2 next)
    (stopped : ∀ start state result, P state start →
      (execute (body start) state).1 = .ok (.inr result) → Q result)
    (fuel : Nat) : ∀ (program : Program E (Except ε (S ⊕ R))) (state : State),
    (∀ next, (execute program state).1 = .ok (.inl next) → P (execute program state).2 next) →
    (∀ result, (execute program state).1 = .ok (.inr result) → Q result) →
    ∀ result, (execute (Program.iterate body exhausted fuel program) state).1 = .ok result →
      Q result := by
  induction fuel with
  | zero => intro program state _ _ result ran; simp [Program.iterate, execute] at ran
  | succ fuel ih =>
    intro program state keeps stops result ran
    match program with
    | .pure (.error error) => simp [Program.iterate, execute] at ran
    | .pure (.ok (.inr answer)) =>
      simp only [Program.iterate, execute, Except.ok.injEq] at ran
      exact ran ▸ stops answer rfl
    | .pure (.ok (.inl next)) =>
      simp only [Program.iterate] at ran
      exact ih (body next) state (kept next state · (keeps next rfl))
        (stopped next state · (keeps next rfl)) result ran
    | .request effect resume =>
      rw [execute_iterate_request] at ran
      simp only [execute] at keeps stops
      exact ih _ _ keeps stops result ran

private theorem walk_reports_pending_entry (state : State) (scope : Serve.Scope)
    (key : Path) (bytes : ByteArray) (cursor : Cursor) (path : Path)
    (quiet : state.faults = []) (length : key.length ≤ maxDepthNibbles)
    (nibbles : ∀ n ∈ key, n.toNat < 16)
    (outside : scope.admitsKeyPath key = false)
    (pending : PendingEntry (view state) key bytes [(cursor, 0, path)]) :
    (execute (walk Cursor.nextChild (ScopeCheck.step scope) cursor path none).run state).1 ≠ .ok none := by
  intro ran
  let P := fun state (d : Descent Cursor (Option ByteArray)) =>
    state.faults = [] ∧ PendingEntry (view state) key bytes d.stack
  have round := fun d state (holds : P state d) =>
    descend_preserves_pending state scope key bytes d holds.1 length nibbles outside holds.2
  have kept : ∀ d state next, P state d →
      (execute (descend Cursor.nextChild (ScopeCheck.step scope) d).run state).1 = .ok (.inl next) →
      P (execute (descend Cursor.nextChild (ScopeCheck.step scope) d).run state).2 next :=
    fun d state next holds success => (round d state holds).1 next success
  have stopped : ∀ d state result, P state d →
      (execute (descend Cursor.nextChild (ScopeCheck.step scope) d).run state).1 = .ok (.inr result) →
      result ≠ none := by
    intro d state result holds success empty
    subst result
    exact (round d state holds).2 success
  have initial : P state ⟨[(cursor, 0, path)], 0, none⟩ := ⟨quiet, pending⟩
  unfold walk OperationOver.iterate at ran
  exact iterate_state_sound _ Walk.Error.ceiling P (· ≠ none) kept stopped walkFuel _ state
    (kept _ state · initial) (stopped _ state · initial) none ran rfl

/-- A successful publication scope check certifies that every stored entry
belongs to the publisher's grant. Entries are defined independently from
traversal, over the raw records visible to this invocation (including its
pending transaction). Missing or malformed records may make the check fail;
they cannot make a successful check authorize an ungranted stored entry. -/
private theorem successful_check_grants_held_entry (state : State) (root : ByteArray)
    (scope : Serve.Scope) (quiet : state.faults = [])
    (checked : (SimulatedHost.run (ScopeCheck.firstOutside root scope) state).1 = .ok none)
    (key bytes : ByteArray) (entry : Entry (view state) root key bytes) :
    scope.admitsKeyPath (keyNibbles key) = true := by
  cases granted : scope.admitsKeyPath (keyNibbles key) with
  | true => rfl
  | false =>
    obtain ⟨keyBound, nonempty, graph⟩ := entry
    let initial := { state with output := [] }
    have initialQuiet : initial.faults = [] := quiet
    have initialGraph : GraphValue (view initial) root (keyNibbles key) bytes := graph
    have notSubtree : scope.containsSubtree [] = false := by
      cases all : scope.containsSubtree [] with
      | false => rfl
      | true =>
        have allowed := subtree_grants_entry scope [] (keyNibbles key) all
        simp [granted] at allowed
    have depth : (keyNibbles key).length ≤ maxDepthNibbles := by
      rw [key_nibbles_length]
      exact Nat.mul_le_mul_right 2 keyBound
    have nibbles : ∀ n ∈ keyNibbles key, n.toNat < 16 := by
      intro n member
      have := TrieMutateProofs.nibbles_keyNibbles key n member
      omega
    obtain ⟨cursor, loaded, sameView, afterQuiet, meaning⟩ :=
      load_entry initial root (keyNibbles key) bytes initialQuiet initialGraph
    change (execute (ScopeCheck.firstOutside root scope).run initial).1 = .ok none at checked
    simp only [ScopeCheck.firstOutside, rootOf, nonempty, notSubtree, Bool.false_eq_true,
      ↓reduceIte, Option.isNone_some, Bool.or_self, bind, ExceptT.bind, ExceptT.mk, ExceptT.run] at checked
    rw [execute_bind] at checked
    simp only [ExceptT.run] at loaded
    simp only [ExceptT.bindCont, loaded] at checked
    let after := (execute (cursorAt (E := Walk.Effects) (some root)).run initial).2
    have afterMeaning : CursorEntry (view after) cursor (keyNibbles key) bytes := by
      change view after = view initial at sameView
      rw [sameView]
      exact meaning
    rw [execute_bind] at checked
    have unchanged := inspect_preserves_state after scope cursor []
    have inspectOutcome := fun decision answer =>
      inspect_continues_none after scope cursor [] decision answer
    have inspectEntry := fun decision => inspect_keeps_ungranted after scope cursor [] (keyNibbles key)
      bytes afterMeaning (by simpa using granted) decision
    simp only [ExceptT.run] at unchanged inspectOutcome inspectEntry
    generalize inspectRun : execute (ScopeCheck.inspect scope cursor []) after = inspected
      at unchanged inspectOutcome inspectEntry
    obtain ⟨reply, finalState⟩ := inspected
    have finalSame : finalState = after := unchanged
    subst finalState
    change (execute (ExceptT.bindCont _ (execute (ScopeCheck.inspect scope cursor []) after).1)
      (execute (ScopeCheck.inspect scope cursor []) after).2).1 = .ok none at checked
    rw [inspectRun] at checked
    cases reply with
    | error error => cases checked
    | ok reply =>
      obtain ⟨decision, answer⟩ := reply
      cases decision with
      | descend child =>
        have answerNone := inspectOutcome (.descend child) answer rfl (by intro impossible; cases impossible)
        subst answer
        obtain ⟨same, remaining⟩ := inspectEntry (.descend child) rfl
        have childSame : child = cursor := by cases same; rfl
        subst child
        have pending : PendingEntry (view after) (keyNibbles key) bytes [(cursor, 0, [])] := by
          cases keyShape : keyNibbles key with
          | nil => exact False.elim (remaining keyShape)
          | cons nibble tail =>
            exact ⟨(cursor, 0, []), List.mem_singleton_self _, nibble, tail, rfl,
              Nat.zero_le _, by simpa only [keyShape] using afterMeaning⟩
        exact False.elim (walk_reports_pending_entry after scope (keyNibbles key) bytes cursor []
          afterQuiet depth nibbles granted pending checked)
      | visited =>
        cases checked
        obtain ⟨impossible, _⟩ := inspectEntry .visited rfl
        cases impossible
      | skip =>
        cases checked
        obtain ⟨impossible, _⟩ := inspectEntry .skip rfl
        cases impossible
      | stop =>
        cases checked
        obtain ⟨impossible, _⟩ := inspectEntry .stop rfl
        cases impossible

/-- If the publisher's snapshot is available to the checker, a successful
check means every entry in that snapshot is within the publisher's grant.
Availability is an explicit raw-record contract, independent of traversal:
the supplied snapshot's records must be readable by this invocation. The
snapshot may be SQL-backed and may include the current transaction's writes.
No hash injectivity, complete-walk premise, or refusal-as-absence rule is used. -/
theorem successful_scope_check_grants_every_entry (state : State) (snapshot : RawSnapshot)
    (root : ByteArray) (scope : Serve.Scope)
    (available : RecordsIncluded snapshot (readableBytes state)) (quiet : state.faults = [])
    (checked : (SimulatedHost.run (ScopeCheck.firstOutside root scope) state).1 = .ok none) :
    ∀ key bytes, Entry snapshot root key bytes → scope.admitsKeyPath (keyNibbles key) = true := by
  intro key bytes entry
  exact successful_check_grants_held_entry state root scope quiet checked key bytes
    ⟨entry.1, entry.2.1, graph_value_preserved available entry.2.2⟩

end Synchronicity.TrieScopeCheckProofs
