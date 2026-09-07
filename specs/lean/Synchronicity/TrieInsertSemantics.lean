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

/-- The remaining key at a child becomes this key at its remembered parent. -/
def FrameKey : InsertFrame → List UInt8 → List UInt8
  | .extension segment, key => segment.toList ++ key
  | .branch _ _ nibble, key => nibble :: key
  | .route _ _ nibble, key => nibble :: key

def ContextKey : List InsertFrame → List UInt8 → List UInt8
  | [], key => key
  | frame :: stack, key => ContextKey stack (FrameKey frame key)

private theorem prefixed_overwrite (pathPrefix : List UInt8) :
    (∃ tail, probe = pathPrefix ++ tail ∧ Overwrite inside key bytes tail result) ↔
    Overwrite (fun query value => ∃ tail, query = pathPrefix ++ tail ∧ inside tail value)
      (pathPrefix ++ key) bytes probe result := by
  constructor
  · rintro ⟨tail, rfl, changed | unchanged⟩
    · exact Or.inl ⟨congrArg (pathPrefix ++ ·) changed.1, changed.2⟩
    · exact Or.inr ⟨fun eq => unchanged.1 (List.append_cancel_left eq),
        ⟨tail, rfl, unchanged.2⟩⟩
  · rintro (⟨rfl, rfl⟩ | ⟨different, tail, rfl, prior⟩)
    · exact ⟨key, rfl, Or.inl ⟨rfl, rfl⟩⟩
    · exact ⟨tail, rfl, Or.inr ⟨fun eq => different (congrArg (pathPrefix ++ ·) eq), prior⟩⟩

/-- Replacing one key inside a child replaces exactly the corresponding
whole key, including when another key terminates at the ancestor itself. -/
theorem frame_overwrite (ready : FrameReady store frame) :
    FrameEntries store frame (Overwrite inside key bytes) probe result ↔
      Overwrite (FrameEntries store frame inside) (FrameKey frame key) bytes probe result := by
  cases frame with
  | extension segment =>
    have nonempty : segment.toList ≠ [] := ready.2.1
    simpa [FrameEntries, FrameKey, Overwrite, nonempty] using
      (prefixed_overwrite (inside := inside) (key := key) (bytes := bytes)
        (probe := probe) (result := result) segment.toList)
  | branch children value position =>
    cases probe with
    | nil => simp [FrameEntries, FrameKey, Overwrite]
    | cons nibble tail =>
      by_cases same : nibble = position
      · subst nibble
        simp [FrameEntries, FrameKey, Overwrite]
      · simp [FrameEntries, FrameKey, Overwrite, same]
  | route children value position =>
    cases probe with
    | nil => simp [FrameEntries, FrameKey, Overwrite]
    | cons nibble tail =>
      by_cases same : nibble = position
      · subst nibble
        simp [FrameEntries, FrameKey, Overwrite]
      · simp [FrameEntries, FrameKey, Overwrite, same]

/-- A local replacement travels through the actual ancestor order to exactly
one whole key. No unrelated entry or ancestor payload is changed. -/
theorem context_overwrite (stack : List InsertFrame) (ready : ContextReady store stack) :
    ContextEntries store stack (Overwrite inside key bytes) probe result ↔
      Overwrite (ContextEntries store stack inside) (ContextKey stack key) bytes probe result := by
  induction stack generalizing inside key with
  | nil => exact Iff.rfl
  | cons frame stack ih =>
    exact (context_entries_congr stack (fun _ _ => frame_overwrite (ready frame (by simp)))).trans
      (ih (fun ancestor member => ready ancestor (List.mem_cons_of_mem _ member)))

/-- The actual compressed-path wrapper prefixes exactly its child's entries;
it also retains the child's saved snapshot and every existing stored record. -/
theorem wrap_exact (digestWidth : Width d) (shaped : Shaped before)
    (nibbles : Nibbles segment) (small : segment.length < 2 ^ 64)
    (width : child.size = 32) (closed : Closed before.read child)
    (safe : SafeWrites d before (wrapInExtension segment child).run)
    (ran : execute d before (wrapInExtension segment child).run = some (.ok root, after)) :
    RecordsIncluded before.read after.read ∧ Shaped after ∧ root.size = 32 ∧ Closed after.read root ∧
      ∀ key bytes, GraphValue after.read root key bytes ↔
        ∃ tail, key = segment ++ tail ∧ GraphValue before.read child tail bytes := by
  cases segment with
  | nil =>
    simp only [wrapInExtension, List.isEmpty_nil, ↓reduceIte, run_pure,
      TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    refine ⟨fun _ _ _ _ held => held, shaped, width, closed, ?_⟩
    intro key bytes
    simp
  | cons nibble tail =>
    have ready : FrameReady before.read (.extension (nibblesOf (nibble :: tail))) := by
      refine ⟨nibblesOf_wf nibbles small, ?_, ?_⟩ <;> simp [nibblesOf, ByteArray.size, TrieWalkProofs.toList_eq]
    simp only [wrapInExtension, List.isEmpty_cons, Bool.false_eq_true, ↓reduceIte] at safe ran
    obtain ⟨included, finalShape, rootWidth, rootClosed, exactEntries⟩ :=
      put_frame_exact digestWidth shaped ready width closed safe ran
    refine ⟨included, finalShape, rootWidth, rootClosed, ?_⟩
    intro key bytes
    simpa [FrameEntries, nibblesOf, TrieWalkProofs.toList_eq] using exactEntries key bytes

private theorem put_exact (digestWidth : Width d) (shaped : Shaped before)
    (wellFormed : node.wf) (canonical : checkInvariants node = .ok ())
    (closed : NodeClosed before.read node)
    (safe : SafeWrites d before (put node).run)
    (ran : execute d before (put node).run = some (.ok root, after)) :
    RecordsIncluded before.read after.read ∧ Shaped after ∧ root.size = 32 ∧ Closed after.read root ∧
      ∀ key bytes, GraphValue after.read root key bytes ↔ NodeEntries before.read node key bytes := by
  have compatible : CompatibleWrite before nodeSpace (d (tagOf node ++ encode node)) (encode node) := by
    simpa only [put_requests_tagged_digest, SafeWrites, and_true] using safe
  have included := (put_stores_node_and_preserves compatible ran).1
  have finalClosed := put_node_closed closed wellFormed compatible ran
  have entries := fun key bytes => put_node_exact (key := key) (bytes := bytes)
    closed wellFormed compatible ran
  rw [execute_put] at ran
  cases ran
  exact ⟨included, shaped_write_node shaped (canonical_encode wellFormed canonical),
    digestWidth _, finalClosed, entries⟩

/-- Insertion at an existing leaf's exact key replaces its contents, while
retaining all previously stored records for saved roots. -/
theorem replace_leaf_exact (digestWidth : Width d) (shaped : Shaped before)
    (nibbles : Nibbles suffix) (small : suffix.length < 2 ^ 64)
    (validValue : ValueOk value) (denotes : ValueDenotes before.read value bytes)
    (safe : SafeWrites d before (splitLeaf suffix old suffix value).run)
    (ran : execute d before (splitLeaf suffix old suffix value).run = some (.ok root, after)) :
    RecordsIncluded before.read after.read ∧ Shaped after ∧ root.size = 32 ∧ Closed after.read root ∧
      ∀ probe result, GraphValue after.read root probe result ↔
        Overwrite (NodeEntries before.read (.leaf (nibblesOf suffix) old)) suffix bytes probe result := by
  simp only [splitLeaf, beq_self_eq_true, ↓reduceIte] at safe ran
  have wf : (Node.leaf (nibblesOf suffix) value).wf := ⟨nibblesOf_wf nibbles small, validValue.1⟩
  obtain ⟨included, finalShape, rootWidth, rootClosed, _⟩ :=
    put_exact digestWidth shaped wf (by simpa [checkInvariants] using validValue.2)
      ⟨bytes, denotes⟩ safe ran
  refine ⟨included, finalShape, rootWidth, rootClosed, ?_⟩
  intro probe result
  have entries := put_leaf_exact (key := probe) (result := result) wf denotes ran
  by_cases same : probe = suffix <;>
    simpa [Overwrite, NodeEntries, nibblesOf, TrieWalkProofs.toList_eq, same] using entries

private theorem commonPrefix_shared (left right : List UInt8) :
    left.take (commonPrefix left right) = right.take (commonPrefix left right) := by
  induction left generalizing right with
  | nil => simp [commonPrefix]
  | cons first rest ih =>
    cases right with
    | nil => simp [commonPrefix]
    | cons second tail =>
      simp only [commonPrefix]
      split
      · rename_i same
        have equal : first = second := beq_iff_eq.mp same
        subst second
        simp only [List.take_succ_cons]
        exact congrArg (first :: ·) (ih tail)
      · rfl

private theorem commonPrefix_reconstruct (left right : List UInt8) :
    right.take (commonPrefix left right) ++ left.drop (commonPrefix left right) = left := by
  rw [← commonPrefix_shared]
  exact List.take_append_drop _ _

private theorem distinct_leaf_update (different : suffix ≠ key) :
    Overwrite (fun probe result => probe = suffix ∧ ValueDenotes store old result)
      key bytes probe result ↔
    (probe = key ∧ result = bytes) ∨ (probe = suffix ∧ ValueDenotes store old result) := by
  constructor
  · rintro (changed | ⟨_, prior⟩)
    · exact Or.inl changed
    · exact Or.inr prior
  · rintro (changed | ⟨rfl, prior⟩)
    · exact Or.inl changed
    · exact Or.inr ⟨different, rfl, prior⟩

private theorem branch_one_entries {position : UInt8} (bound : position.toNat < 16) :
    NodeEntries store (.branch (setChild emptyChildren position (some child)) (some own)) key bytes ↔
      (key = [] ∧ ValueDenotes store own bytes) ∨
        ∃ tail, key = position :: tail ∧ GraphValue store child tail bytes := by
  cases key with
  | nil => simp [NodeEntries]
  | cons nibble tail =>
    by_cases same : nibble = position
    · subst nibble
      simp only [NodeEntries, setChild,
        List.getElem?_set_self (show position.toNat < emptyChildren.length from bound), Option.some.injEq]
      simp
    · simp only [NodeEntries, setChild_getElem_ne emptyChildren (Ne.symm same)]
      have empty : ∀ root, emptyChildren[nibble.toNat]? ≠ some (some root) := by
        intro root selected
        have member := List.mem_of_getElem? selected
        simp only [emptyChildren, List.mem_replicate] at member
        cases member.2
      simp [empty, same]

private theorem branch_one_closed {position : UInt8}
    (childClosed : Closed store child) (ownClosed : ∃ bytes, ValueDenotes store own bytes)
    (bound : position.toNat < 16) :
    NodeClosed store (.branch (setChild emptyChildren position (some child)) (some own)) := by
  refine ⟨fun value selected => ?_, ?_⟩
  · cases selected
    exact ownClosed
  · intro index root selected
    by_cases same : index = position.toNat
    · subst index
      simp only [setChild,
        List.getElem?_set_self (show position.toNat < emptyChildren.length from bound), Option.some.injEq] at selected
      cases selected
      exact childClosed
    · rw [setChild, List.getElem?_set_ne (Ne.symm same)] at selected
      have member := List.mem_of_getElem? selected
      simp only [emptyChildren, List.mem_replicate] at member
      cases member.2

/-- The branch written when one split key ends above the other retains both
the ancestor payload and the complete child subtree, with no extra entries. -/
theorem branch_one_write (digestWidth : Width d) (shaped : Shaped before)
    {position : UInt8} (bound : position.toNat < 16)
    (childWidth : child.size = 32) (childClosed : Closed before.read child)
    (ownValid : ValueOk own) (ownClosed : ∃ bytes, ValueDenotes before.read own bytes)
    (safe : SafeWrites d before
      (put (.branch (setChild emptyChildren position (some child)) (some own))).run)
    (ran : execute d before
      (put (.branch (setChild emptyChildren position (some child)) (some own))).run =
        some (.ok root, after)) :
    RecordsIncluded before.read after.read ∧ Shaped after ∧ root.size = 32 ∧ Closed after.read root ∧
      ∀ key bytes, GraphValue after.read root key bytes ↔
        (key = [] ∧ ValueDenotes before.read own bytes) ∨
          ∃ tail, key = position :: tail ∧ GraphValue before.read child tail bytes := by
  have valid := branchOk_value (branchOk_setChild branchOk_empty position childWidth) ownValid
  have slot : emptyChildren[position.toNat]? = some none := emptyChildren_none bound
  have occupied : 2 ≤ occupants (setChild emptyChildren position (some child)) (some own) := by
    rw [occupants_setChild_of_none slot, occupants_value, occupants_empty_none]
    decide
  obtain ⟨included, finalShape, rootWidth, rootClosed, entries⟩ :=
    put_exact digestWidth shaped (wf_branch valid) (checkInvariants_branch valid occupied)
      (branch_one_closed childClosed ownClosed bound) safe ran
  exact ⟨included, finalShape, rootWidth, rootClosed,
    fun _ _ => (entries _ _).trans (branch_one_entries bound)⟩

private theorem branch_one_wrap (digestWidth : Width d) (shaped : Shaped before)
    {position : UInt8} (bound : position.toNat < 16)
    (nibbles : Nibbles segment) (small : segment.length < 2 ^ 64)
    (childWidth : child.size = 32) (childClosed : Closed before.read child)
    (ownValid : ValueOk own) (ownClosed : ∃ bytes, ValueDenotes before.read own bytes)
    (safe : SafeWrites d before (do
      let branch ← put (.branch (setChild emptyChildren position (some child)) (some own))
      wrapInExtension segment branch).run)
    (ran : execute d before (do
      let branch ← put (.branch (setChild emptyChildren position (some child)) (some own))
      wrapInExtension segment branch).run = some (.ok root, after)) :
    RecordsIncluded before.read after.read ∧ Shaped after ∧ root.size = 32 ∧ Closed after.read root ∧
      ∀ key bytes, GraphValue after.read root key bytes ↔
        (key = segment ∧ ValueDenotes before.read own bytes) ∨
          ∃ tail, key = segment ++ position :: tail ∧ GraphValue before.read child tail bytes := by
  simp only [run_bind] at safe
  have firstSafe := safe_bind_left _ safe
  rw [execute_run_bind] at ran
  cases first : execute d before
      (put (.branch (setChild emptyChildren position (some child)) (some own))).run with
  | none => simp [first] at ran
  | some reply =>
    obtain ⟨reply, middle⟩ := reply
    cases reply with
    | error error => simp [first] at ran
    | ok branch =>
      have restSafe := safe_bind_right _ safe first
      simp only [bindCont_ok] at restSafe
      simp only [first] at ran
      obtain ⟨included, middleShape, branchWidth, branchClosed, branchEntries⟩ :=
        branch_one_write digestWidth shaped bound childWidth childClosed ownValid ownClosed firstSafe first
      obtain ⟨laterIncluded, finalShape, rootWidth, rootClosed, entries⟩ :=
        wrap_exact digestWidth middleShape nibbles small branchWidth branchClosed restSafe ran
      refine ⟨fun space key bytes admitted held => laterIncluded space key bytes admitted
        (included space key bytes admitted held), finalShape, rootWidth, rootClosed, ?_⟩
      intro key bytes
      rw [entries]
      constructor
      · rintro ⟨tail, spelling, meaning⟩
        rcases (branchEntries tail bytes).mp meaning with ⟨rfl, ownMeaning⟩ | ⟨below, rfl, childMeaning⟩
        · exact Or.inl ⟨by simpa using spelling, ownMeaning⟩
        · exact Or.inr ⟨below, spelling, childMeaning⟩
      · rintro (⟨rfl, ownMeaning⟩ | ⟨tail, rfl, childMeaning⟩)
        · exact ⟨[], by simp, (branchEntries [] bytes).mpr (Or.inl ⟨rfl, ownMeaning⟩)⟩
        · exact ⟨position :: tail, rfl,
            (branchEntries _ bytes).mpr (Or.inr ⟨tail, rfl, childMeaning⟩)⟩

/-- When the old key is a proper prefix of the inserted key, the actual split
retains its payload at the ancestor and adds precisely the new descendant. -/
theorem split_leaf_old_prefix (digestWidth : Width d) (shaped : Shaped before)
    (keyNibbles : Nibbles key)
    (small : key.length < 2 ^ 64) (different : suffix ≠ key)
    (oldValid : ValueOk old) (oldClosed : ∃ bytes, ValueDenotes before.read old bytes)
    (valueValid : ValueOk value) (valueMeaning : ValueDenotes before.read value bytes)
    (oldEnds : suffix.drop (commonPrefix suffix key) = [])
    {position : UInt8} (newContinues : key.drop (commonPrefix suffix key) = position :: tail)
    (safe : SafeWrites d before (splitLeaf suffix old key value).run)
    (ran : execute d before (splitLeaf suffix old key value).run = some (.ok root, after)) :
    RecordsIncluded before.read after.read ∧ Shaped after ∧ root.size = 32 ∧ Closed after.read root ∧
      ∀ probe result, GraphValue after.read root probe result ↔
        Overwrite (NodeEntries before.read (.leaf (nibblesOf suffix) old)) key bytes probe result := by
  have beqDifferent : (suffix == key) = false := beq_eq_false_iff_ne.mpr different
  simp only [splitLeaf, beqDifferent, Bool.false_eq_true, ↓reduceIte, oldEnds, newContinues] at safe ran
  have tailNibbles : Nibbles tail := nibbles_tail (newContinues ▸ nibbles_drop keyNibbles _)
  have tailSmall : tail.length < 2 ^ 64 := by
    have length := congrArg List.length newContinues
    simp only [List.length_drop, List.length_cons] at length
    omega
  have bound : position.toNat < 16 := by
    have := nibbles_head (newContinues ▸ nibbles_drop keyNibbles _)
    omega
  have leafWf : (Node.leaf (nibblesOf tail) value).wf :=
    ⟨nibblesOf_wf tailNibbles tailSmall, valueValid.1⟩
  simp only [run_bind] at safe
  have firstSafe := safe_bind_left _ safe
  rw [execute_run_bind] at ran
  cases first : execute d before (put (.leaf (nibblesOf tail) value)).run with
  | none => simp [first] at ran
  | some reply =>
    obtain ⟨reply, middle⟩ := reply
    cases reply with
    | error error => simp [first] at ran
    | ok child =>
      have restSafe := safe_bind_right _ safe first
      simp only [bindCont_ok] at restSafe
      simp only [first] at ran
      obtain ⟨included, middleShape, childWidth, childClosed, _⟩ :=
        put_exact digestWidth shaped leafWf (by simpa [checkInvariants] using valueValid.2)
          ⟨bytes, valueMeaning⟩ firstSafe first
      have oldAfter : ∃ result, ValueDenotes middle.read old result :=
        node_closed_preserved (node := .leaf ByteArray.empty old) oldClosed included
      have oldSame : ∀ result, ValueDenotes middle.read old result ↔ ValueDenotes before.read old result := by
        intro result
        simpa [NodeEntries] using (node_entries_unchanged (node := .leaf ByteArray.empty old)
          (key := []) (bytes := result) oldClosed included)
      have prefixSmall : (key.take (commonPrefix suffix key)).length < 2 ^ 64 := by
        simp only [List.length_take]
        omega
      obtain ⟨laterIncluded, finalShape, rootWidth, rootClosed, entries⟩ :=
        branch_one_wrap digestWidth middleShape bound (nibbles_take keyNibbles _) prefixSmall
          childWidth childClosed oldValid oldAfter restSafe ran
      have oldSpelling : key.take (commonPrefix suffix key) = suffix := by
        have spelling := commonPrefix_reconstruct suffix key
        simpa only [oldEnds, List.append_nil] using spelling
      have newSpelling : key.take (commonPrefix suffix key) ++ position :: tail = key := by
        rw [← newContinues]
        exact List.take_append_drop _ _
      refine ⟨fun space address data admitted held => laterIncluded space address data admitted
        (included space address data admitted held), finalShape, rootWidth, rootClosed, ?_⟩
      intro probe result
      have leafEntries : ∀ query, GraphValue middle.read child query result ↔ query = tail ∧ result = bytes := by
        intro query
        simpa [nibblesOf, TrieWalkProofs.toList_eq] using
          (put_leaf_exact (key := query) (result := result) leafWf valueMeaning first)
      rw [entries]
      have target := distinct_leaf_update (store := before.read) (old := old)
        (bytes := bytes) (probe := probe) (result := result) different
      have oldMeaning : NodeEntries before.read (.leaf (nibblesOf suffix) old) =
          (fun probe result => probe = suffix ∧ ValueDenotes before.read old result) := by
        funext probe result
        simp [NodeEntries, nibblesOf, TrieWalkProofs.toList_eq]
      rw [oldMeaning, target]
      simp only [oldSame, leafEntries]
      constructor
      · rintro (⟨ownKey, ownMeaning⟩ | ⟨below, newKey, rfl, newMeaning⟩)
        · exact Or.inr ⟨ownKey.trans oldSpelling, ownMeaning⟩
        · exact Or.inl ⟨newKey.trans newSpelling, newMeaning⟩
      · rintro (⟨newKey, newMeaning⟩ | ⟨ownKey, ownMeaning⟩)
        · exact Or.inr ⟨tail, newKey.trans newSpelling.symm, rfl, newMeaning⟩
        · exact Or.inl ⟨ownKey.trans oldSpelling.symm, ownMeaning⟩

end Synchronicity.TrieInsertSemantics
