import Synchronicity.TrieSnapshotClosure
import VerifiedCore.Trie.Normalize

/-! Publication changes a version's representation so shared descendants can
be authenticated without exposing a private ancestor's payload. Its logical
entries are defined by the stored graph, independently of the normalization
work stack. The final target is equality of all entries before and after the
actual publication operation; finite storage alone does not imply its fixed
work and path budgets suffice. -/
namespace Synchronicity.TrieNormalizeProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open TrieProgramProofs TrieSnapshotProofs TrieMutateProofs TrieWriteSemantics TrieSnapshotClosure

/-- Moving a payload out of a routing spine preserves exactly its contents,
including payloads below the ordinary inline threshold. The same raw effect
interpreter used by mutation checks executes this operation. -/
theorem addressValue_exact
    (safe : SafeWrites d before (addressValue value).run)
    (ran : execute d before (addressValue value).run = some (.ok address, after)) :
    RecordsIncluded before.read after.read ∧
      ∀ bytes, ValueDenotes after.read (.hash address) bytes ↔ ValueDenotes before.read value bytes := by
  refine ⟨execution_preserves_records _ safe ran, ?_⟩
  cases value with
  | hash existing =>
    simp only [addressValue, run_pure, TrieMutateProofs.execute_pure,
      Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact fun _ => Iff.rfl
  | inline original =>
    simp only [addressValue, run_bind, digest_run, program_bind_request,
      program_bind_pure, execute_digest, mapError_ok, bindCont_ok, write_run,
      execute_write, run_pure, TrieMutateProofs.execute_pure, Option.some.injEq,
      Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    have held : (before.write valueSpace (d original) original).read valueSpace (d original) =
        some original := by
      simp [Store.write, Store.read, Store.lookup, nodeSpace, valueSpace]
    intro bytes
    constructor
    · intro denotes
      cases denotes with
      | stored _ _ now =>
        rw [held] at now
        cases now
        exact .inline original
    · intro denotes
      cases denotes
      exact .stored _ _ held

/-- Optional values keep absence distinct from an addressed empty payload. -/
theorem addressOptional_exact
    (safe : SafeWrites d before (Normalize.addressOptional value).run)
    (ran : execute d before (Normalize.addressOptional value).run = some (.ok addressed, after)) :
    RecordsIncluded before.read after.read ∧
      ∀ bytes, (∃ address, addressed = some address ∧ ValueDenotes after.read (.hash address) bytes) ↔
        ∃ original, value = some original ∧ ValueDenotes before.read original bytes := by
  cases value with
  | none =>
    simp only [Normalize.addressOptional, run_pure, TrieMutateProofs.execute_pure,
      Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨fun _ _ _ _ h => h, fun _ => by simp⟩
  | some value =>
    have firstSafe : SafeWrites d before (addressValue value).run := by
      simp only [Normalize.addressOptional, run_bind] at safe
      exact safe_bind_left _ safe
    simp only [Normalize.addressOptional] at ran
    rw [execute_run_bind] at ran
    cases first : execute d before (addressValue value).run with
    | none => simp [first] at ran
    | some result =>
      obtain ⟨reply, middle⟩ := result
      cases reply with
      | error error => simp [first] at ran
      | ok address =>
        simp only [first, run_pure, TrieMutateProofs.execute_pure,
          Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
        obtain ⟨rfl, rfl⟩ := ran
        obtain ⟨included, exactBytes⟩ := addressValue_exact firstSafe first
        exact ⟨included, fun bytes => by simpa using exactBytes bytes⟩

/-- Addressing a branch payload preserves every entry at that node. Its
children keep their original meanings while the payload is moved out of line. -/
theorem addressed_branch_entries_exact
    (closed : NodeClosed before.read (.branch children value))
    (safe : SafeWrites d before (Normalize.addressOptional value).run)
    (ran : execute d before (Normalize.addressOptional value).run = some (.ok addressed, after)) :
    NodeEntries after.read (.route children addressed) key bytes ↔
      NodeEntries before.read (.branch children value) key bytes := by
  obtain ⟨included, payload⟩ := addressOptional_exact safe ran
  cases key with
  | nil => exact payload bytes
  | cons nibble tail =>
    constructor
    · rintro ⟨child, edge, entry⟩
      exact ⟨child, edge, closed_snapshot_no_new_entries (closed.2 _ _ edge) included entry⟩
    · rintro ⟨child, edge, entry⟩
      exact ⟨child, edge, graph_value_preserved included entry⟩

/-- A queued visit means the entries of its existing subtree or constructed
node. This definition mentions no traversal result or completion flag. -/
def CursorEntries (store : RawSnapshot) : Normalize.Cursor → List UInt8 → ByteArray → Prop
  | .stored root => GraphValue store root
  | .node node => NodeEntries store node

/-- Every record needed to interpret the queued subtree is present. -/
def CursorClosed (store : RawSnapshot) : Normalize.Cursor → Prop
  | .stored root => Closed store root
  | .node node => NodeClosed store node

/-- Previously queued work retains precisely its meaning while normalization
writes other nodes. Closure is needed to exclude entries revealed by filling
holes in an older partial snapshot. -/
theorem cursor_entries_unchanged (closed : CursorClosed before cursor)
    (included : RecordsIncluded before after) :
    CursorEntries after cursor key bytes ↔ CursorEntries before cursor key bytes := by
  cases cursor with
  | stored root =>
    exact ⟨closed_snapshot_no_new_entries closed included, graph_value_preserved included⟩
  | node node => exact node_entries_unchanged closed included

/-- A logical version is a set of key/payload pairs, not a completed walk. -/
abbrev Entries := List UInt8 → ByteArray → Prop

/-- The disjoint key positions represented by a routing node. Child views
are relative to their edge; the optional payload belongs only to this key. -/
def RoutedEntries (payload : Option ByteArray) (children : List (UInt8 × Entries)) : Entries
  | [], bytes => payload = some bytes
  | nibble :: tail, bytes => ∃ entries, (nibble, entries) ∈ children ∧ entries tail bytes

/-- The child views selected by the production scheduler's sixteen slots. -/
def SelectedViews (store : RawSnapshot) (children : List (Option ByteArray)) :
    List (UInt8 × Entries) :=
  (List.range 16).filterMap fun index =>
    ((children[index]?).getD none).map fun address => (index.toUInt8, GraphValue store address)

/-- Scheduling visits exactly the existing child entries, including empty
slots and out-of-range nibble queries, rather than trusting a traversal flag. -/
theorem selected_views_exact {children : List (Option ByteArray)} (width : children.length = 16) :
    (∃ view, (nibble, view) ∈ SelectedViews store children ∧ view tail bytes) ↔
      ∃ child, children[nibble.toNat]? = some (some child) ∧ GraphValue store child tail bytes := by
  constructor
  · rintro ⟨view, selected, entry⟩
    obtain ⟨index, member, selected⟩ := List.mem_filterMap.mp selected
    have bound : index < 16 := List.mem_range.mp member
    cases probe : children[index]? with
    | none => simp [probe] at selected
    | some slot =>
      cases slot with
      | none => simp [probe] at selected
      | some child =>
        simp only [probe, Option.getD_some, Option.map_some, Option.some.injEq,
          Prod.mk.injEq] at selected
        obtain ⟨same, rfl⟩ := selected
        have indexSame : nibble.toNat = index := by
          rw [← same]
          exact TrieCodecProofs.toNat_ofNat_of_lt (by omega)
        exact ⟨child, by simpa [indexSame] using probe, entry⟩
  · rintro ⟨child, selected, entry⟩
    have bound : nibble.toNat < 16 := by
      obtain ⟨bound, _⟩ := List.getElem?_eq_some_iff.mp selected
      omega
    refine ⟨GraphValue store child, ?_, entry⟩
    apply List.mem_filterMap.mpr
    refine ⟨nibble.toNat, List.mem_range.mpr bound, ?_⟩
    simp [selected]

/-- A pending addressed payload is backed by its actual stored bytes. -/
inductive PayloadMeaning (store : RawSnapshot) : Option ByteArray → Option ByteArray → Prop where
  | absent : PayloadMeaning store none none
  | present (width : address.size = 32) (held : store valueSpace address = some bytes) :
      PayloadMeaning store (some address) (some bytes)

private theorem payload_preserved (payload : PayloadMeaning before address bytes)
    (included : RecordsIncluded before after) : PayloadMeaning after address bytes := by
  cases payload with
  | absent => exact .absent
  | present width held => exact .present width (included _ _ _ (.inr rfl) held)

/-- Constructed cursors have canonical shape as well as a complete meaning;
stored cursors obtain shape from the store invariant when they are read. -/
def CursorValid (store : RawSnapshot) : Normalize.Cursor → Prop
  | .stored root => root.size = 32 ∧ Closed store root
  | .node node => NodeClosed store node ∧ node.wf ∧ checkInvariants node = .ok ()

private theorem cursor_valid_closed (valid : CursorValid store cursor) : CursorClosed store cursor := by
  cases cursor with
  | stored root => exact valid.2
  | node node => exact valid.1

private theorem node_closed_preserved (closed : NodeClosed before node)
    (included : RecordsIncluded before after) : NodeClosed after node := by
  have payload : ∀ {value bytes}, ValueDenotes before value bytes → ValueDenotes after value bytes := by
    intro value bytes denotes
    cases denotes with
    | inline bytes => exact .inline bytes
    | stored address bytes held => exact .stored _ _ (included _ _ _ (.inr rfl) held)
  cases node with
  | leaf suffix value => exact closed.imp (fun _ => payload)
  | extension segment child => exact ⟨closed.1, closed_preserved closed.2 included⟩
  | branch children value =>
    exact ⟨fun v selected => (closed.1 v selected).imp (fun _ => payload),
      fun index child selected => closed_preserved (closed.2 index child selected) included⟩
  | route children value =>
    exact ⟨fun v selected => (closed.1 v selected).imp (fun _ => payload),
      fun index child selected => closed_preserved (closed.2 index child selected) included⟩

private theorem cursor_valid_preserved (valid : CursorValid before cursor)
    (included : RecordsIncluded before after) : CursorValid after cursor := by
  cases cursor with
  | stored root => exact ⟨valid.1, closed_preserved valid.2 included⟩
  | node node => exact ⟨node_closed_preserved valid.1 included, valid.2⟩

/-- The work stack is a forest of existing subtree meanings and unfinished
routing parents. The result stack supplies already completed child meanings.
This invariant never assumes what the operation's eventual output means. -/
inductive Pending (store : RawSnapshot) : List Normalize.Work → List Entries → Entries → Prop where
  | done (entries : Entries) : Pending store [] [entries] entries
  | visit (valid : CursorValid store cursor)
      (meaning : ∀ key bytes, CursorEntries store cursor key bytes ↔ entries key bytes)
      (below : Pending store work (entries :: results) target) :
      Pending store (.visit path cursor :: work) results target
  | assemble (children : List (UInt8 × Entries))
      (distinct : (children.map Prod.fst).Nodup)
      (nibbles : ∀ position ∈ children.map Prod.fst, position.toNat < 16)
      (occupied : children ≠ [] ∨ payload.isSome = true)
      (value : PayloadMeaning store address payload)
      (below : Pending store work (RoutedEntries payload children :: results) target) :
      Pending store (.assemble (children.map Prod.fst) address :: work)
        ((children.map Prod.snd).reverse ++ results) target

/-- Actual child slots realize these relative entry sets. Width and closure
allow their enclosing routing node to be stored and read canonically. -/
structure ChildrenMeaning (store : RawSnapshot) (children : List (Option ByteArray))
    (views : List (UInt8 × Entries)) : Prop where
  slots : RouteOk children none
  closed : ∀ (index : Nat) child, children[index]? = some (some child) → Closed store child
  positions : ∀ nibble, (∃ child, children[nibble.toNat]? = some (some child)) ↔
    nibble ∈ views.map Prod.fst
  entries : ∀ nibble tail bytes,
    (∃ child, children[nibble.toNat]? = some (some child) ∧ GraphValue store child tail bytes) ↔
      RoutedEntries none views (nibble :: tail) bytes

private theorem empty_children_meaning : ChildrenMeaning store emptyChildren [] := by
  refine ⟨branchOk_empty, ?_, ?_, ?_⟩
  · intro index child edge
    simp only [emptyChildren, List.getElem?_replicate] at edge
    split at edge <;> cases edge
  · intro nibble
    simp only [emptyChildren, List.getElem?_replicate, List.map_nil, List.not_mem_nil]
    split <;> simp
  · intro nibble tail bytes
    simp only [emptyChildren, List.getElem?_replicate, RoutedEntries, List.not_mem_nil,
      false_and, exists_false]
    split <;> simp

/-- Assembling one completed child replaces exactly its edge, leaving all
other completed child views alone. -/
theorem set_child_meaning (meaning : ChildrenMeaning store children views)
    (bound : position.toNat < 16) (fresh : position ∉ views.map Prod.fst)
    (width : root.size = 32) (closed : Closed store root)
    (entries : ∀ key bytes, GraphValue store root key bytes ↔ view key bytes) :
    ChildrenMeaning store (setChild children position (some root)) ((position, view) :: views) := by
  refine ⟨branchOk_setChild meaning.slots position width, ?_, ?_, ?_⟩
  · intro index child edge
    simp only [setChild] at edge
    by_cases same : position.toNat = index
    · subst index
      rw [List.getElem?_set_self (by rw [meaning.slots.1]; exact bound)] at edge
      cases edge
      exact closed
    · rw [List.getElem?_set_ne same] at edge
      exact meaning.closed _ _ edge
  · intro nibble
    by_cases same : nibble = position
    · subst nibble
      simp [setChild, List.getElem?_set_self (by rw [meaning.slots.1]; exact bound)]
    · rw [setChild_getElem_ne children (Ne.symm same)]
      simpa [List.map_cons, List.mem_cons, same] using meaning.positions nibble
  · intro nibble tail bytes
    by_cases same : nibble = position
    · subst nibble
      have absent : ∀ other, (position, other) ∉ views := by
        intro other member
        exact fresh (List.mem_map.mpr ⟨(position, other), member, rfl⟩)
      simp only [setChild, List.getElem?_set_self (by rw [meaning.slots.1]; exact bound),
        Option.some.injEq]
      simpa [RoutedEntries, List.mem_cons, Prod.mk.injEq, absent] using entries tail bytes
    · rw [setChild_getElem_ne children (Ne.symm same)]
      simpa [RoutedEntries, List.mem_cons, Prod.mk.injEq, same] using meaning.entries nibble tail bytes

/-- The assembled routing node has exactly the assembled child views and
its own addressed payload, and is a valid complete node for actual `put`. -/
theorem assembled_node_meaning (meaning : ChildrenMeaning store children views)
    (payload : PayloadMeaning store address contents)
    (occupied : views ≠ [] ∨ contents.isSome = true) :
    (Node.route children address).wf ∧ checkInvariants (.route children address) = .ok () ∧
      NodeClosed store (.route children address) ∧
      ∀ key bytes, NodeEntries store (.route children address) key bytes ↔
        RoutedEntries contents views key bytes := by
  have valueWidth : ∀ hash, address = some hash → hash.size = 32 := by
    cases payload with
    | absent => simp
    | present width held => intro hash same; cases same; exact width
  have payloadClosed : ∀ hash, address = some hash → ∃ bytes, ValueDenotes store (.hash hash) bytes := by
    cases payload with
    | absent => simp
    | present width held => intro hash same; cases same; exact ⟨_, .stored _ _ held⟩
  have nonzero : 1 ≤ occupants children (address.map Value.hash) := by
    rcases occupied with child | value
    · cases views with
      | nil => contradiction
      | cons pair rest =>
        obtain ⟨position, view⟩ := pair
        obtain ⟨child, edge⟩ := (meaning.positions position).mpr (by simp)
        have positive : 0 < children.countP Option.isSome :=
          List.countP_pos_iff.mpr ⟨some child, List.mem_of_getElem? edge, rfl⟩
        simp only [occupants]
        omega
    · cases payload with
      | absent => simp at value
      | present width held => simp [occupants]
  refine ⟨⟨meaning.slots.1, meaning.slots.2.1, valueWidth⟩,
    checkInvariants_route nonzero, ⟨payloadClosed, meaning.closed⟩, ?_⟩
  intro key bytes
  cases key with
  | cons nibble tail => exact meaning.entries nibble tail bytes
  | nil =>
    cases payload with
    | absent => simp [NodeEntries, RoutedEntries]
    | present width held =>
      simp only [NodeEntries, RoutedEntries, Option.some.injEq]
      constructor
      · rintro ⟨hash, same, denotes⟩
        cases same
        cases denotes with
        | stored _ _ now => exact Option.some.inj (held.symm.trans now)
      · intro same
        cases same
        exact ⟨_, rfl, .stored _ _ held⟩

/-- Completed child roots and their independent entry sets, in stack order. -/
inductive Completed (store : RawSnapshot) : List ByteArray → List Entries → Prop where
  | nil : Completed store [] []
  | cons (meaning : root.size = 32 ∧ Closed store root ∧
      ∀ key bytes, GraphValue store root key bytes ↔ view key bytes)
      (below : Completed store roots views) : Completed store (root :: roots) (view :: views)

private theorem completed_preserved (completed : Completed before roots views)
    (included : RecordsIncluded before after) : Completed after roots views := by
  induction completed with
  | nil => exact .nil
  | cons current _ ih =>
    obtain ⟨width, closed, exactEntries⟩ := current
    refine .cons ⟨width, closed_preserved closed included, fun key bytes => ?_⟩ ih
    exact (Iff.intro (closed_snapshot_no_new_entries closed included)
      (graph_value_preserved included)).trans (exactEntries key bytes)

private theorem completed_split (first : List Entries)
    (completed : Completed store roots (first ++ rest)) :
    ∃ left right, roots = left ++ right ∧ Completed store left first ∧ Completed store right rest := by
  induction first generalizing roots with
  | nil => exact ⟨[], roots, rfl, .nil, completed⟩
  | cons view first ih =>
    cases completed with
    | cons current below =>
      obtain ⟨left, right, same, leftMeaning, rightMeaning⟩ := ih below
      exact ⟨_ :: left, right, by simp [same], .cons current leftMeaning, rightMeaning⟩

/-- The production assembler consumes precisely its child results and
reconstructs exactly their relative entries. Other pending results survive. -/
theorem assemble_children_exact (pairs : List (UInt8 × Entries))
    (ready : Completed store roots (pairs.map Prod.snd))
    (meaning : ChildrenMeaning store children views)
    (distinct : (pairs.map Prod.fst ++ views.map Prod.fst).Nodup)
    (nibbles : ∀ position ∈ pairs.map Prod.fst, position.toNat < 16)
    (rest : List ByteArray) :
    ∃ built, Normalize.assembleChildren (pairs.map Prod.fst) (roots ++ rest) children =
      some (built, rest) ∧ ChildrenMeaning store built (pairs.reverse ++ views) := by
  induction pairs generalizing roots children views with
  | nil =>
    cases ready
    exact ⟨children, rfl, meaning⟩
  | cons pair pairs ih =>
    obtain ⟨position, view⟩ := pair
    cases ready with
    | cons current below =>
      obtain ⟨width, closed, exactEntries⟩ := current
      have full : (position :: (pairs.map Prod.fst ++ views.map Prod.fst)).Nodup := by
        simpa using distinct
      have absent := (List.nodup_cons.mp full).1
      have next := set_child_meaning meaning (nibbles position (by simp))
        (fun member => absent (List.mem_append.mpr (.inr member))) width closed exactEntries
      have reordered : (pairs.map Prod.fst ++ ((position, view) :: views).map Prod.fst).Nodup := by
        exact full.perm List.perm_middle.symm
      obtain ⟨built, ran, assembled⟩ := ih below next reordered
        (fun selected member => nibbles selected (by simp only [List.map_cons]; exact List.mem_cons_of_mem _ member))
      refine ⟨built, ?_, ?_⟩
      · simpa only [List.map_cons, List.cons_append, Normalize.assembleChildren] using ran
      · simpa only [List.reverse_cons, List.append_assoc, List.singleton_append] using assembled

/-- The machine state realizes this independent forest using actual stored
result roots. Every completed child is finite and its entries are exact. -/
def StateMeaning (store : RawSnapshot) (state : Normalize.State) (target : Entries) : Prop :=
  ∃ entries, Pending store state.work entries target ∧
    Completed store state.results entries

private theorem pending_preserved (pending : Pending before work results target)
    (included : RecordsIncluded before after) : Pending after work results target := by
  induction pending with
  | done entries => exact .done entries
  | visit valid meaning _ ih =>
    exact .visit (cursor_valid_preserved valid included)
      (fun key bytes => (cursor_entries_unchanged (cursor_valid_closed valid) included).trans
        (meaning key bytes)) ih
  | assemble children distinct nibbles occupied value _ ih =>
    exact .assemble children distinct nibbles occupied (payload_preserved value included) ih

/-- Writing a completed child cannot silently change either a queued subtree
or another completed child waiting on the same work stack. -/
theorem state_meaning_preserved (meaning : StateMeaning before state target)
    (included : RecordsIncluded before after) : StateMeaning after state target := by
  obtain ⟨entries, pending, completed⟩ := meaning
  exact ⟨entries, pending_preserved pending included, completed_preserved completed included⟩

private theorem expand_unary_meaning
    (meaning : StateMeaning store ⟨.visit path cursor :: work, results⟩ target)
    (valid : CursorValid store child)
    (bound : nibble.toNat < 16)
    (same : ∀ key bytes, CursorEntries store cursor key bytes ↔
      RoutedEntries none [(nibble, CursorEntries store child)] key bytes) :
    StateMeaning store ⟨.visit (path ++ [nibble]) child :: .assemble [nibble] none :: work,
      results⟩ target := by
  obtain ⟨entries, pending, completed⟩ := meaning
  cases pending with
  | visit original originalEntries below =>
    rename_i expected
    have replacement : expected = RoutedEntries none [(nibble, CursorEntries store child)] := by
      funext key bytes
      exact propext ((originalEntries key bytes).symm.trans (same key bytes))
    rw [replacement] at below
    refine ⟨entries, .visit valid (fun _ _ => Iff.rfl) ?_, completed⟩
    exact .assemble [(nibble, CursorEntries store child)] (by simp)
      (fun position member => by simpa using List.mem_singleton.mp member ▸ bound)
      (.inl (by simp)) .absent below

/-- Expanding one compressed leaf edge is a pure scheduling step, and
preserves exactly the original key and payload. -/
theorem leaf_edge_step_preserves
    (meaning : StateMeaning before.read ⟨.visit path (.node (.leaf suffix value)) :: work, results⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (spelling : suffix.toList = nibble :: rest)
    (ran : execute d before
      (Normalize.step ⟨.visit path (.node (.leaf suffix value)) :: work, results⟩).run =
      some (.ok (.inl next), after)) : after = before ∧ StateMeaning after.read next target := by
  have valid : CursorValid before.read (.node (.leaf suffix value)) := by
    obtain ⟨entries, pending, _⟩ := meaning
    cases pending with
    | visit valid _ _ => exact valid
  obtain ⟨closed, wf, inv⟩ := valid
  have nibbles : Nibbles (nibble :: rest) := by
    simpa only [← TrieWalkProofs.toList_eq, spelling] using nibbles_of_nibblesWf wf.1
  have bound : nibble.toNat < 16 := by
    have := nibbles nibble (List.mem_cons_self ..)
    omega
  have small : rest.length < 2 ^ 64 := by
    have size := wf.1.1
    have length : suffix.toList.length = suffix.size := by
      rw [TrieWalkProofs.toList_eq]
      exact Array.length_toList
    rw [spelling] at length
    simp only [List.length_cons] at length
    omega
  have childValid : CursorValid before.read (.node (.leaf (nibblesOf rest) value)) :=
    ⟨closed, ⟨nibblesOf_wf (nibbles_tail nibbles) small, wf.2⟩, inv⟩
  have tailSpelling : (nibblesOf rest).toList = rest := by
    simp [TrieWalkProofs.toList_eq, nibblesOf]
  have same : ∀ key bytes, CursorEntries before.read (.node (.leaf suffix value)) key bytes ↔
      RoutedEntries none [(nibble, CursorEntries before.read (.node (.leaf (nibblesOf rest) value)))]
        key bytes := by
    intro key bytes
    cases key <;> simp [CursorEntries, NodeEntries, RoutedEntries, spelling, tailSpelling,
      List.mem_cons, Prod.mk.injEq, and_assoc, exists_and_left]
  simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, spine,
    Bool.false_eq_true, run_bind, run_pure, program_bind_pure, bindCont_ok, spelling,
    TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq, Except.ok.injEq,
    Sum.inl.injEq] at ran
  obtain ⟨rfl, rfl⟩ := ran
  exact ⟨rfl, expand_unary_meaning meaning childValid bound same⟩

/-- Expanding an extension edge preserves the entire descendant view,
whether the remaining label is empty or still compressed. -/
theorem extension_edge_step_preserves
    (meaning : StateMeaning before.read ⟨.visit path (.node (.extension segment child)) :: work, results⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (spelling : segment.toList = nibble :: rest)
    (ran : execute d before
      (Normalize.step ⟨.visit path (.node (.extension segment child)) :: work, results⟩).run =
      some (.ok (.inl next), after)) : after = before ∧ StateMeaning after.read next target := by
  have valid : CursorValid before.read (.node (.extension segment child)) := by
    obtain ⟨entries, pending, _⟩ := meaning
    cases pending with
    | visit valid _ _ => exact valid
  obtain ⟨closed, wf, inv⟩ := valid
  have nibbles : Nibbles (nibble :: rest) := by
    simpa only [← TrieWalkProofs.toList_eq, spelling] using nibbles_of_nibblesWf wf.1
  have bound : nibble.toNat < 16 := by
    have := nibbles nibble (List.mem_cons_self ..)
    omega
  have small : rest.length < 2 ^ 64 := by
    have size := wf.1.1
    have length : segment.toList.length = segment.size := by
      rw [TrieWalkProofs.toList_eq]
      exact Array.length_toList
    rw [spelling] at length
    simp only [List.length_cons] at length
    omega
  let cursor := if rest.isEmpty then Normalize.Cursor.stored child
    else .node (.extension (nibblesOf rest) child)
  have tailSpelling : (nibblesOf rest).toList = rest := by
    simp [TrieWalkProofs.toList_eq, nibblesOf]
  have childValid : CursorValid before.read cursor := by
    cases rest with
    | nil => exact ⟨wf.2, closed.2⟩
    | cons head tail =>
      refine ⟨⟨by simp [tailSpelling], closed.2⟩,
        ⟨nibblesOf_wf (nibbles_tail nibbles) small, wf.2⟩, ?_⟩
      simp [checkInvariants, nibblesOf, ByteArray.size]
  have same : ∀ key bytes, CursorEntries before.read (.node (.extension segment child)) key bytes ↔
      RoutedEntries none [(nibble, CursorEntries before.read cursor)] key bytes := by
    intro key bytes
    cases rest <;> cases key <;>
      simp [cursor, CursorEntries, NodeEntries, RoutedEntries, spelling, tailSpelling,
        List.mem_cons, Prod.mk.injEq, and_assoc, exists_and_left]
  simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, spine,
    Bool.false_eq_true, run_bind, run_pure, program_bind_pure, bindCont_ok, spelling,
    TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq, Except.ok.injEq,
    Sum.inl.injEq] at ran
  obtain ⟨rfl, rfl⟩ := ran
  exact ⟨rfl, expand_unary_meaning meaning childValid bound same⟩

private theorem load_cursor_meaning (shaped : Shaped before)
    (valid : CursorValid before.read (.stored root))
    (ran : execute d before (load root).run = some (.ok node, after)) :
    after = before ∧ CursorValid after.read (.node node) ∧
      ∀ key bytes, CursorEntries before.read (.stored root) key bytes ↔
        CursorEntries after.read (.node node) key bytes := by
  simp only [load, run_bind, read_run, program_bind_request, program_bind_pure,
    mapError_ok, bindCont_ok, execute_read] at ran
  cases held : before.read nodeSpace root with
  | none => simp [held] at ran
  | some raw =>
    obtain ⟨stored, decoded, _, wf, inv⟩ := shaped root raw held
    simp only [held, decoded, run_pure, TrieMutateProofs.execute_pure,
      Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨rfl, ⟨loaded_node_closed valid.2 held decoded, wf, inv⟩,
      fun _ _ => graph_node_entries held decoded⟩

private theorem stored_step_as_node
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false) :
    (Normalize.step ⟨.visit path (.stored root) :: work, results⟩).run =
      (do let node ← load root
          Normalize.step ⟨.visit path (.node node) :: work, results⟩).run := by
  simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, spine,
    Bool.false_eq_true, run_bind]
  congr 1

private theorem replace_cursor_meaning
    (meaning : StateMeaning store ⟨.visit path cursor :: work, results⟩ target)
    (valid : CursorValid store replacement)
    (same : ∀ key bytes, CursorEntries store cursor key bytes ↔ CursorEntries store replacement key bytes) :
    StateMeaning store ⟨.visit path replacement :: work, results⟩ target := by
  obtain ⟨entries, pending, completed⟩ := meaning
  cases pending with
  | visit original originalEntries below =>
    exact ⟨entries, .visit valid
      (fun key bytes => (same key bytes).symm.trans (originalEntries key bytes)) below, completed⟩

private theorem addressValue_shape {value : Value} (digestWidth : Width d) (shaped : Shaped before)
    (wf : value.wf)
    (ran : execute d before (addressValue value).run = some (.ok address, after)) :
    Shaped after ∧ address.size = 32 := by
  cases value with
  | hash existing =>
    simp only [addressValue, run_pure, TrieMutateProofs.execute_pure,
      Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨shaped, wf⟩
  | inline bytes =>
    simp only [addressValue, run_bind, digest_run, program_bind_request,
      program_bind_pure, execute_digest, mapError_ok, bindCont_ok, write_run,
      execute_write, run_pure, TrieMutateProofs.execute_pure, Option.some.injEq,
      Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨shaped_write_value shaped _ _, digestWidth _⟩

/-- The actual terminal-leaf visit moves its value behind an address and
stores a routing node with exactly the same key and contents. -/
theorem terminal_leaf_step_preserves (digestWidth : Width d) (shaped : Shaped before)
    (meaning : StateMeaning before.read ⟨.visit path (.node (.leaf suffix value)) :: work, results⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (spelling : suffix.toList = [])
    (safe : SafeWrites d before
      (Normalize.step ⟨.visit path (.node (.leaf suffix value)) :: work, results⟩).run)
    (ran : execute d before
      (Normalize.step ⟨.visit path (.node (.leaf suffix value)) :: work, results⟩).run =
      some (.ok (.inl next), after)) : Shaped after ∧ StateMeaning after.read next target := by
  obtain ⟨entries, pending, completed⟩ := meaning
  cases pending with
  | visit valid originalEntries below =>
    obtain ⟨closed, wf, inv⟩ := valid
    obtain ⟨original, denotes⟩ := closed
    simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, spine,
      Bool.false_eq_true, run_bind, run_pure, program_bind_pure, bindCont_ok, spelling] at safe ran
    have firstSafe := safe_bind_left _ safe
    rw [execute_bind] at ran
    cases first : execute d before (addressValue value).run with
    | none => simp [first] at ran
    | some reply =>
      obtain ⟨reply, middle⟩ := reply
      cases reply with
      | error error => simp [first] at ran
      | ok addressed =>
        have restSafe := safe_bind_right _ safe first
        simp only [first, bindCont_ok] at ran
        obtain ⟨middleShaped, addressWidth⟩ := addressValue_shape digestWidth shaped wf.2 first
        obtain ⟨firstIncluded, payloadExact⟩ := addressValue_exact firstSafe first
        have routeWf : (Node.route emptyChildren (some addressed)).wf :=
          ⟨rfl, branchOk_empty.2.1, fun hash same => by cases same; exact addressWidth⟩
        have routeInv : checkInvariants (.route emptyChildren (some addressed)) = .ok () :=
          checkInvariants_route (by simp [occupants])
        have routeClosed : NodeClosed middle.read (.route emptyChildren (some addressed)) :=
          ⟨fun hash same => by cases same; exact ⟨original, (payloadExact original).mpr denotes⟩,
            empty_children_meaning.closed⟩
        have routeEntries : ∀ key bytes, NodeEntries middle.read (.route emptyChildren (some addressed)) key bytes ↔
            CursorEntries before.read (.node (.leaf suffix value)) key bytes := by
          intro key bytes
          cases key with
          | nil => simpa [NodeEntries, CursorEntries, spelling] using payloadExact bytes
          | cons nibble tail =>
            simp only [NodeEntries, CursorEntries, spelling, List.cons_ne_nil, false_and,
              emptyChildren, List.getElem?_replicate]
            split <;> simp
        simp only [bindCont_ok, run_bind] at restSafe
        have safePut := safe_bind_left _ restSafe
        have collision : CompatibleWrite middle nodeSpace
            (d (tagOf (.route emptyChildren (some addressed)) ++ encode (.route emptyChildren (some addressed))))
            (encode (.route emptyChildren (some addressed))) := by
          simpa only [put_requests_tagged_digest, SafeWrites, and_true] using safePut
        rw [execute_run_bind, execute_put] at ran
        simp only [run_pure, TrieMutateProofs.execute_pure, Option.some.injEq,
          Prod.mk.injEq, Except.ok.injEq, Sum.inl.injEq] at ran
        obtain ⟨rfl, rfl⟩ := ran
        have putRan := execute_put d middle (.route emptyChildren (some addressed))
        have lastIncluded := (put_stores_node_and_preserves collision putRan).1
        have included : RecordsIncluded before.read _ := fun space key bytes relevant held =>
          lastIncluded space key bytes relevant (firstIncluded space key bytes relevant held)
        refine ⟨shaped_write_node middleShaped (canonical_encode routeWf routeInv),
          ⟨_, pending_preserved below included, .cons ⟨digestWidth _,
            put_node_closed routeClosed routeWf collision putRan, ?_⟩
            (completed_preserved completed included)⟩⟩
        intro key bytes
        exact (put_node_exact routeClosed routeWf collision putRan).trans
          ((routeEntries key bytes).trans (originalEntries key bytes))

/-- Inside a complete sharing prefix, the actual visit keeps the entire
subtree compressed without changing any of its entries. -/
theorem boundary_visit_preserves (digestWidth : Width d) (shaped : Shaped before)
    (meaning : StateMeaning before.read ⟨.visit path cursor :: work, results⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (inside : Normalize.belowBoundary path = true)
    (safe : SafeWrites d before (Normalize.step ⟨.visit path cursor :: work, results⟩).run)
    (ran : execute d before (Normalize.step ⟨.visit path cursor :: work, results⟩).run =
      some (.ok (.inl next), after)) : Shaped after ∧ StateMeaning after.read next target := by
  obtain ⟨entries, pending, completed⟩ := meaning
  cases pending with
  | visit valid originalEntries below =>
    cases cursor with
    | stored root =>
      simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, inside,
        run_bind, run_pure, program_bind_pure, bindCont_ok,
        TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq,
        Except.ok.injEq, Sum.inl.injEq] at ran
      obtain ⟨rfl, rfl⟩ := ran
      exact ⟨shaped, ⟨_, below, .cons ⟨valid.1, valid.2, originalEntries⟩ completed⟩⟩
    | node node =>
      obtain ⟨closed, wf, inv⟩ := valid
      simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, inside, run_bind] at safe
      have safePut := safe_bind_left _ safe
      have collision : CompatibleWrite before nodeSpace (d (tagOf node ++ encode node)) (encode node) := by
        simpa only [put_requests_tagged_digest, SafeWrites, and_true] using safePut
      simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, inside] at ran
      rw [execute_run_bind, execute_put] at ran
      simp only [run_pure, TrieMutateProofs.execute_pure, Option.some.injEq,
        Prod.mk.injEq, Except.ok.injEq, Sum.inl.injEq] at ran
      obtain ⟨rfl, rfl⟩ := ran
      have putRan := execute_put d before node
      have included := (put_stores_node_and_preserves collision putRan).1
      refine ⟨shaped_write_node shaped (canonical_encode wf inv),
        ⟨_, pending_preserved below included, .cons ⟨digestWidth _,
          put_node_closed closed wf collision putRan, ?_⟩
          (completed_preserved completed included)⟩⟩
      intro key bytes
      exact (put_node_exact closed wf collision putRan).trans (originalEntries key bytes)

/-- The actual assembly step stores a valid parent with exactly the child
entries already normalized, preserving both queued work and sibling results. -/
theorem assembly_step_preserves (digestWidth : Width d) (shaped : Shaped before)
    (meaning : StateMeaning before.read ⟨.assemble positions address :: work, results⟩ target)
    (safe : SafeWrites d before (Normalize.step ⟨.assemble positions address :: work, results⟩).run)
    (ran : execute d before (Normalize.step ⟨.assemble positions address :: work, results⟩).run =
      some (.ok (.inl next), after)) : Shaped after ∧ StateMeaning after.read next target := by
  obtain ⟨views, pending, completed⟩ := meaning
  cases pending with
  | assemble children distinct nibbles occupied payload below =>
    obtain ⟨left, right, rfl, leftMeaning, rightMeaning⟩ :=
      completed_split _ completed
    have ready : Completed before.read left ((children.reverse).map Prod.snd) := by
      simpa only [List.map_reverse] using leftMeaning
    obtain ⟨built, assembled, childMeaning⟩ := assemble_children_exact children.reverse ready
      empty_children_meaning (by simpa using distinct.perm (List.reverse_perm _).symm)
      (fun position member => nibbles position (by simpa using member)) right
    simp only [List.map_reverse, List.reverse_reverse, List.append_nil] at assembled childMeaning
    obtain ⟨wf, inv, closed, exactEntries⟩ := assembled_node_meaning childMeaning payload occupied
    simp only [Normalize.step, assembled, run_bind] at safe
    have safePut := safe_bind_left _ safe
    have collision : CompatibleWrite before nodeSpace
        (d (tagOf (.route built address) ++ encode (.route built address)))
        (encode (.route built address)) := by
      simpa only [put_requests_tagged_digest, SafeWrites, and_true] using safePut
    simp only [Normalize.step, assembled] at ran
    rw [execute_run_bind, execute_put] at ran
    simp only [run_pure, TrieMutateProofs.execute_pure, Option.some.injEq,
      Prod.mk.injEq, Except.ok.injEq, Sum.inl.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    have putRan := execute_put d before (.route built address)
    have included := (put_stores_node_and_preserves collision putRan).1
    refine ⟨shaped_write_node shaped (canonical_encode wf inv),
      ⟨_, pending_preserved below included, .cons ⟨digestWidth _,
        put_node_closed closed wf collision putRan, ?_⟩
        (completed_preserved rightMeaning included)⟩⟩
    intro key bytes
    exact (put_node_exact closed wf collision putRan).trans (exactEntries key bytes)

/-- The initial machine state represents exactly the input version. -/
theorem initial_state_meaning (width : root.size = 32) (closed : Closed store root) :
    StateMeaning store ⟨[.visit [] (.stored root)], []⟩ (GraphValue store root) := by
  exact ⟨[], .visit ⟨width, closed⟩ (fun _ _ => Iff.rfl) (.done _), .nil⟩

/-- When all pending parents have been assembled, the one resulting root
has exactly the original forest's entries. -/
theorem state_meaning_finished (meaning : StateMeaning store ⟨[], [root]⟩ target) :
    root.size = 32 ∧ Closed store root ∧
      ∀ key bytes, GraphValue store root key bytes ↔ target key bytes := by
  obtain ⟨entries, pending, completed⟩ := meaning
  cases pending with
  | done entries =>
    cases completed with
    | cons rootMeaning tail => exact rootMeaning

/-- The actual terminal step returns the original entry set and leaves
storage untouched; an invalid result stack cannot report success. -/
theorem finish_step_returns_exact
    (meaning : StateMeaning before.read ⟨[], results⟩ target)
    (ran : execute d before (Normalize.step ⟨[], results⟩).run =
      some (.ok (.inr root), after)) :
    after = before ∧ root.size = 32 ∧ Closed after.read root ∧
      ∀ key bytes, GraphValue after.read root key bytes ↔ target key bytes := by
  cases results with
  | nil => simp [Normalize.step] at ran
  | cons result rest =>
    cases rest with
    | cons next rest => simp [Normalize.step] at ran
    | nil =>
      simp only [Normalize.step, run_pure, TrieMutateProofs.execute_pure,
        Option.some.injEq, Prod.mk.injEq, Except.ok.injEq, Sum.inr.injEq] at ran
      obtain ⟨rfl, rfl⟩ := ran
      exact ⟨rfl, state_meaning_finished meaning⟩

/-- Lift a state invariant through the actual effect-counted loop. Unlike a
value-only loop invariant, this tracks the store after each iteration and
requires compatibility only for writes actually encountered. -/
theorem iterate_store_invariant
    (body : S → Program MutateEffects (Except ε (S ⊕ R))) (exhausted : ε)
    (invariant : Store → S → Prop) (finished : Store → R → Prop)
    (step : ∀ start before reply after, invariant before start →
      SafeWrites d before (body start) → execute d before (body start) = some (.ok reply, after) →
      match reply with | .inl next => invariant after next | .inr result => finished after result)
    (fuel : Nat) : ∀ (program : Program MutateEffects (Except ε (S ⊕ R))) before,
    (∀ reply after, SafeWrites d before program → execute d before program = some (.ok reply, after) →
      match reply with | .inl next => invariant after next | .inr result => finished after result) →
    ∀ result after, SafeWrites d before (Program.iterate body exhausted fuel program) →
      execute d before (Program.iterate body exhausted fuel program) = some (.ok result, after) →
      finished after result := by
  induction fuel with
  | zero => intro program before post result after safe ran; cases ran
  | succ fuel ih =>
    intro program before post result after safe ran
    cases program with
    | pure reply =>
      cases reply with
      | error error => cases ran
      | ok reply =>
        cases reply with
        | inr answer =>
          simp only [Program.iterate, TrieMutateProofs.execute_pure,
            Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
          obtain ⟨rfl, rfl⟩ := ran
          exact post (.inr answer) before trivial rfl
        | inl next =>
          exact ih (body next) before
            (fun reply after => step next before reply after (post (.inl next) before trivial rfl))
            result after safe ran
    | request effect resume =>
      cases effect with
      | left storage =>
        cases storage <;> first
          | contradiction
          | exact ih (resume (.ok (before.read _ _))) before
              (fun reply after tailSafe tailRan => post reply after tailSafe tailRan)
              result after safe ran
      | right effect =>
        cases effect with
        | left digest =>
          cases digest
          exact ih (resume (.ok (d _))) before
            (fun reply after tailSafe tailRan => post reply after tailSafe tailRan)
            result after safe ran
        | right write =>
          cases write
          exact ih _ _ (fun reply after tailSafe tailRan => post reply after ⟨safe.1, tailSafe⟩ tailRan)
            result after safe.2 ran

end Synchronicity.TrieNormalizeProofs
