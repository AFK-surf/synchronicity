import Synchronicity.TrieNormalizeProofs

/-! Insertion changes exactly the requested key while preserving the other
entries and every saved complete snapshot. The semantic target is an update
of independently defined entry sets; the implementation proof follows the
actual descent stack, node writes, and ancestor rebuild. -/
namespace Synchronicity.TrieInsertSemantics
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open TrieProgramProofs TrieSnapshotProofs TrieMutateProofs TrieWriteSemantics
open TrieSnapshotClosure TrieNormalizeProofs

/-- The requested key receives these bytes; every other key keeps precisely
its prior contents. No lookup or traversal result defines this relation. -/
def Overwrite (entries : Entries) (key : List UInt8) (bytes : ByteArray) : Entries :=
  fun probe result => (probe = key ∧ result = bytes) ∨ (probe ≠ key ∧ entries probe result)

/-- The existing part of one ancestor, with the selected child represented
by an independent entry set. Both ordinary and routing branches retain their
own payload and all unselected children. -/
def FrameEntries (store : RawSnapshot) : InsertFrame → Entries → Entries
  | .extension segment, inside, key, bytes =>
    segment.toList ≠ [] ∧ ∃ tail, key = segment.toList ++ tail ∧ inside tail bytes
  | .branch children value position, inside, key, bytes =>
    match key with
    | [] => NodeEntries store (.branch children value) [] bytes
    | nibble :: tail => if nibble = position then inside tail bytes
      else NodeEntries store (.branch children value) (nibble :: tail) bytes
  | .route children value position, inside, key, bytes =>
    match key with
    | [] => NodeEntries store (.route children value) [] bytes
    | nibble :: tail => if nibble = position then inside tail bytes
      else NodeEntries store (.route children value) (nibble :: tail) bytes

/-- Descent records the nearest ancestor first, exactly the order in which
production `rebuild` replaces them. -/
def ContextEntries (store : RawSnapshot) : List InsertFrame → Entries → Entries
  | [], inside => inside
  | frame :: rest, inside => ContextEntries store rest (FrameEntries store frame inside)

/-- The node actually written when rebuilding one frame. This is a pure
constructor mapping, not an alternative interpreter for insertion. -/
def FrameNode : InsertFrame → ByteArray → Node
  | .extension segment, child => .extension segment child
  | .branch children value nibble, child => .branch (setChild children nibble (some child)) value
  | .route children value nibble, child => .route (setChild children nibble (some child)) value

/-- A remembered ancestor has valid shape and a complete stored meaning.
Its selected edge is a real nibble, including when that edge was absent. -/
def FrameReady (store : RawSnapshot) : InsertFrame → Prop
  | .extension segment => nibblesWf segment ∧ segment.toList ≠ [] ∧ segment.size ≠ 0
  | .branch children value nibble => BranchOk children value ∧
    NodeClosed store (.branch children value) ∧ nibble.toNat < 16 ∧ 2 ≤ occupants children value
  | .route children value nibble => RouteOk children value ∧
    NodeClosed store (.route children value) ∧ nibble.toNat < 16 ∧
      1 ≤ occupants children (value.map Value.hash)

private theorem frame_ready_preserved (ready : FrameReady before frame)
    (included : RecordsIncluded before after) : FrameReady after frame := by
  cases frame with
  | extension segment => exact ready
  | branch children value nibble =>
    exact ⟨ready.1, node_closed_preserved ready.2.1 included, ready.2.2⟩
  | route children value nibble =>
    exact ⟨ready.1, node_closed_preserved ready.2.1 included, ready.2.2⟩

private theorem frame_entries_unchanged (ready : FrameReady before frame)
    (included : RecordsIncluded before after) :
    FrameEntries after frame inside key bytes ↔ FrameEntries before frame inside key bytes := by
  cases frame with
  | extension segment => exact Iff.rfl
  | branch children value position =>
    cases key with
    | nil => exact node_entries_unchanged (key := []) (bytes := bytes) ready.2.1 included
    | cons nibble tail =>
      by_cases same : nibble = position
      · simp [FrameEntries, same]
      · simpa only [FrameEntries, same, ↓reduceIte] using
          (node_entries_unchanged (key := nibble :: tail) (bytes := bytes) ready.2.1 included)
  | route children value position =>
    cases key with
    | nil => exact node_entries_unchanged (key := []) (bytes := bytes) ready.2.1 included
    | cons nibble tail =>
      by_cases same : nibble = position
      · simp [FrameEntries, same]
      · simpa only [FrameEntries, same, ↓reduceIte] using
          (node_entries_unchanged (key := nibble :: tail) (bytes := bytes) ready.2.1 included)

private theorem set_child_closed {position : UInt8}
    (closed : ∀ (index : Nat) child, children[index]? = some (some child) → Closed store child)
    (width : children.length = 16) (bound : position.toNat < 16)
    (childClosed : Closed store root) :
    ∀ (index : Nat) child, (setChild children position (some root))[index]? = some (some child) →
      Closed store child := by
  intro index child edge
  by_cases same : position.toNat = index
  · subst index
    rw [setChild, List.getElem?_set_self (by rw [width]; exact bound)] at edge
    cases edge
    exact childClosed
  · rw [setChild, List.getElem?_set_ne same] at edge
    exact closed index child edge

/-- Rebuilding an ancestor preserves its canonical shape and completeness,
including unary and terminal routing nodes. -/
theorem frame_node_ready (ready : FrameReady store frame) (width : root.size = 32)
    (closed : Closed store root) :
    (FrameNode frame root).wf ∧ NodeClosed store (FrameNode frame root) ∧
      checkInvariants (FrameNode frame root) = .ok () := by
  cases frame with
  | extension segment =>
    exact ⟨⟨ready.1, width⟩, ⟨ready.2.1, closed⟩, by
      simp [FrameNode, checkInvariants, ready.2.2]⟩
  | branch children value nibble =>
    exact ⟨wf_branch (branchOk_setChild ready.1 nibble width),
      ⟨ready.2.1.1, set_child_closed ready.2.1.2 ready.1.1 ready.2.2.1 closed⟩,
      checkInvariants_branch (branchOk_setChild ready.1 nibble width)
        (Nat.le_trans ready.2.2.2 (occupants_setChild_ge ..))⟩
  | route children value nibble =>
    exact ⟨wf_route (branchOk_setChild ready.1 nibble width),
      ⟨ready.2.1.1, set_child_closed ready.2.1.2 ready.1.1 ready.2.2.1 closed⟩,
      checkInvariants_route (Nat.le_trans ready.2.2.2 (occupants_setChild_ge ..))⟩

/-- The node constructor fills exactly the selected child position. -/
theorem frame_node_entries (ready : FrameReady store frame)
    (inside : ∀ key bytes, GraphValue store root key bytes ↔ entries key bytes) :
    NodeEntries store (FrameNode frame root) key bytes ↔ FrameEntries store frame entries key bytes := by
  cases frame with
  | extension segment =>
    simp only [FrameNode, FrameEntries, NodeEntries]
    exact and_congr Iff.rfl (exists_congr fun tail => and_congr Iff.rfl (inside tail bytes))
  | branch children value position =>
    cases key with
    | nil => exact Iff.rfl
    | cons nibble tail =>
      by_cases same : nibble = position
      · subst nibble
        simp only [FrameNode, FrameEntries, NodeEntries, ↓reduceIte, setChild,
          List.getElem?_set_self (by rw [ready.1.1]; exact ready.2.2.1), Option.some.injEq]
        simpa using inside tail bytes
      · simp only [FrameNode, FrameEntries, NodeEntries, same, ↓reduceIte,
          setChild_getElem_ne children (Ne.symm same)]
  | route children value position =>
    cases key with
    | nil => exact Iff.rfl
    | cons nibble tail =>
      by_cases same : nibble = position
      · subst nibble
        simp only [FrameNode, FrameEntries, NodeEntries, ↓reduceIte, setChild,
          List.getElem?_set_self (by rw [ready.1.1]; exact ready.2.2.1), Option.some.injEq]
        simpa using inside tail bytes
      · simp only [FrameNode, FrameEntries, NodeEntries, same, ↓reduceIte,
          setChild_getElem_ne children (Ne.symm same)]

/-- One actual ancestor write has exactly the remembered entries around its
replacement child, and preserves every previously stored record. -/
theorem put_frame_exact (digestWidth : Width d) (shaped : Shaped before)
    (ready : FrameReady before.read frame) (width : child.size = 32)
    (closed : Closed before.read child)
    (safe : SafeWrites d before (put (FrameNode frame child)).run)
    (ran : execute d before (put (FrameNode frame child)).run = some (.ok root, after)) :
    RecordsIncluded before.read after.read ∧ Shaped after ∧ root.size = 32 ∧ Closed after.read root ∧
      ∀ key bytes, GraphValue after.read root key bytes ↔
        FrameEntries before.read frame (GraphValue before.read child) key bytes := by
  obtain ⟨wf, nodeClosed, canonical⟩ := frame_node_ready ready width closed
  have collision : CompatibleWrite before nodeSpace
      (d (tagOf (FrameNode frame child) ++ encode (FrameNode frame child)))
      (encode (FrameNode frame child)) := by
    simpa only [put_requests_tagged_digest, SafeWrites, and_true] using safe
  have included := (put_stores_node_and_preserves collision ran).1
  have closedAfter := put_node_closed nodeClosed wf collision ran
  have exactEntries := fun key bytes => (put_node_exact (key := key) (bytes := bytes)
    nodeClosed wf collision ran).trans (frame_node_entries ready (fun _ _ => Iff.rfl))
  rw [execute_put] at ran
  cases ran
  exact ⟨included, shaped_write_node shaped (canonical_encode wf canonical), digestWidth _,
    closedAfter, exactEntries⟩

private theorem frame_entries_congr
    (same : ∀ key bytes, first key bytes ↔ second key bytes) :
    FrameEntries store frame first key bytes ↔ FrameEntries store frame second key bytes := by
  cases frame with
  | extension segment =>
    exact and_congr Iff.rfl (exists_congr fun tail => and_congr Iff.rfl (same tail bytes))
  | branch children value position =>
    cases key with
    | nil => exact Iff.rfl
    | cons nibble tail =>
      simp only [FrameEntries]
      split <;> first | exact same tail bytes | exact Iff.rfl
  | route children value position =>
    cases key with
    | nil => exact Iff.rfl
    | cons nibble tail =>
      simp only [FrameEntries]
      split <;> first | exact same tail bytes | exact Iff.rfl

private theorem context_entries_congr (stack : List InsertFrame)
    (same : ∀ key bytes, first key bytes ↔ second key bytes) :
    ContextEntries store stack first key bytes ↔ ContextEntries store stack second key bytes := by
  induction stack generalizing first second with
  | nil => exact same key bytes
  | cons frame stack ih =>
    exact ih (fun key bytes => frame_entries_congr (key := key) (bytes := bytes) same)

/-- Every ancestor remembers complete existing entries, independently of
whether its replacement child was present before the insertion. -/
def ContextReady (store : RawSnapshot) (stack : List InsertFrame) : Prop :=
  ∀ frame ∈ stack, FrameReady store frame

private theorem context_ready_preserved (ready : ContextReady before stack)
    (included : RecordsIncluded before after) : ContextReady after stack :=
  fun frame member => frame_ready_preserved (ready frame member) included

private theorem context_entries_unchanged (stack : List InsertFrame)
    (ready : ContextReady before stack) (included : RecordsIncluded before after) :
    ContextEntries after stack inside key bytes ↔ ContextEntries before stack inside key bytes := by
  induction stack generalizing inside with
  | nil => exact Iff.rfl
  | cons frame stack ih =>
    have tailReady : ContextReady before stack :=
      fun ancestor member => ready ancestor (List.mem_cons_of_mem _ member)
    exact (ih tailReady).trans
      (context_entries_congr stack (fun key bytes => frame_entries_unchanged
        (key := key) (bytes := bytes) (ready frame (by simp)) included))

private theorem rebuild_cons_run :
    (rebuild built (frame :: stack)).run =
      (do let root ← put (FrameNode frame built); rebuild root stack).run := by
  cases frame <;> rfl

/-- Rebuilding the entire actual ancestor stack fills exactly its selected
subtree. All surrounding entries and every previously stored record retain
their meaning, for both ordinary and routing ancestors. -/
theorem rebuild_exact (digestWidth : Width d) (stack : List InsertFrame)
    (shaped : Shaped before) (ready : ContextReady before.read stack)
    (width : built.size = 32) (closed : Closed before.read built)
    (safe : SafeWrites d before (rebuild built stack).run)
    (ran : execute d before (rebuild built stack).run = some (.ok root, after)) :
    RecordsIncluded before.read after.read ∧ Shaped after ∧ root.size = 32 ∧ Closed after.read root ∧
      ∀ key bytes, GraphValue after.read root key bytes ↔
        ContextEntries before.read stack (GraphValue before.read built) key bytes := by
  induction stack generalizing before built with
  | nil =>
    simp only [rebuild, run_pure, TrieMutateProofs.execute_pure,
      Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨fun _ _ _ _ held => held, shaped, width, closed, fun _ _ => Iff.rfl⟩
  | cons frame stack ih =>
    have headReady : FrameReady before.read frame := ready frame (by simp)
    have tailReady : ContextReady before.read stack :=
      fun ancestor member => ready ancestor (List.mem_cons_of_mem _ member)
    rw [rebuild_cons_run] at safe ran
    simp only [run_bind] at safe
    have firstSafe := safe_bind_left _ safe
    rw [execute_run_bind] at ran
    cases first : execute d before (put (FrameNode frame built)).run with
    | none => simp [first] at ran
    | some reply =>
      obtain ⟨reply, middle⟩ := reply
      cases reply with
      | error error => simp [first] at ran
      | ok parent =>
        have restSafe := safe_bind_right _ safe first
        simp only [bindCont_ok] at restSafe
        simp only [first] at ran
        obtain ⟨included, middleShaped, parentWidth, parentClosed, parentEntries⟩ :=
          put_frame_exact digestWidth shaped headReady width closed firstSafe first
        obtain ⟨laterIncluded, finalShaped, rootWidth, rootClosed, finalEntries⟩ :=
          ih middleShaped (context_ready_preserved tailReady included)
            parentWidth parentClosed restSafe ran
        refine ⟨fun space key bytes admitted held => laterIncluded space key bytes admitted
          (included space key bytes admitted held), finalShaped, rootWidth, rootClosed, ?_⟩
        intro key bytes
        exact (finalEntries key bytes).trans
          ((context_entries_unchanged stack tailReady included).trans
            (context_entries_congr stack parentEntries))

end Synchronicity.TrieInsertSemantics
