import Synchronicity.TrieWriteSemantics

/-! A saved snapshot has its records, rather than a flag saying it is complete.

Finite structural closure makes the meaning of an old version stable when
other data is written. Without it, adding a previously missing referenced
record could reveal an entry that the partial local store could not read. -/
namespace Synchronicity.TrieSnapshotClosure
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open TrieProgramProofs TrieSnapshotProofs TrieMutateProofs TrieWriteSemantics

/-- Collision compatibility of an actual composition includes its first
operation. These two composition lemmas let edit proofs reuse the same
encountered-image contract at each rebuilt node. -/
theorem safe_bind_left (program : Program MutateEffects A)
    (safe : SafeWrites d s (program >>= continuation)) : SafeWrites d s program := by
  induction program generalizing s with
  | pure _ => trivial
  | request effect next ih =>
    cases effect with
    | left storage =>
      cases storage <;> first
        | contradiction
        | exact ih _ safe
    | right effect =>
      cases effect with
      | left digest => cases digest; exact ih _ safe
      | right write => cases write; exact ⟨safe.1, ih _ safe.2⟩

theorem safe_bind_right (program : Program MutateEffects A)
    (safe : SafeWrites d s (program >>= continuation))
    (ran : execute d s program = some (value, middle)) : SafeWrites d middle (continuation value) := by
  induction program generalizing s with
  | pure _ => cases ran; exact safe
  | request effect next ih =>
    cases effect with
    | left storage =>
      cases storage <;> first
        | contradiction
        | exact ih _ safe ran
    | right effect =>
      cases effect with
      | left digest => cases digest; exact ih _ safe ran
      | right write => cases write; exact ih _ safe.2 ran

/-- The finite stored representation of a snapshot: every node has its
decoded image, every payload has bytes, and every child has its own finite
representation. This is independent of any traversal, cache, or refusal. -/
inductive Closed (store : RawSnapshot) : ByteArray → Prop where
  | leaf (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.leaf suffix value))
      (payload : ∃ bytes, ValueDenotes store value bytes) : Closed store root
  | extension (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.extension segment child))
      (nonempty : segment.toList ≠ []) (below : Closed store child) : Closed store root
  | branch (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.branch children value))
      (payload : ∀ v, value = some v → ∃ bytes, ValueDenotes store v bytes)
      (below : ∀ (index : Nat) child, children[index]? = some (some child) → Closed store child) :
      Closed store root
  | route (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.route children value))
      (payload : ∀ address, value = some address → ∃ bytes, ValueDenotes store (.hash address) bytes)
      (below : ∀ (index : Nat) child, children[index]? = some (some child) → Closed store child) :
      Closed store root

/-- A saved version is either the distinguished empty snapshot or a finite
stored graph containing all its referenced records. -/
def StoredSnapshot (store : RawSnapshot) (root : ByteArray) : Prop :=
  root.data.all (· == 0) = true ∨ Closed store root

private theorem value_preserved (included : RecordsIncluded before after)
    (denotes : ValueDenotes before value bytes) : ValueDenotes after value bytes := by
  cases denotes with
  | inline bytes => exact .inline bytes
  | stored hash bytes held => exact .stored _ _ (included _ _ _ (.inr rfl) held)

/-- A finite stored representation remains such when existing records are
preserved. New unrelated data cannot invalidate its representation. -/
theorem closed_preserved (closed : Closed before root) (included : RecordsIncluded before after) :
    Closed after root := by
  induction closed with
  | leaf held decoded payload =>
    obtain ⟨bytes, denotes⟩ := payload
    exact .leaf (included _ _ _ (.inl rfl) held) decoded ⟨bytes, value_preserved included denotes⟩
  | extension held decoded nonempty _ ih =>
    exact .extension (included _ _ _ (.inl rfl) held) decoded nonempty ih
  | branch held decoded payload _ ih =>
    apply Closed.branch (included _ _ _ (.inl rfl) held) decoded _ ih
    intro value selected
    obtain ⟨bytes, denotes⟩ := payload value selected
    exact ⟨bytes, value_preserved included denotes⟩
  | route held decoded payload _ ih =>
    apply Closed.route (included _ _ _ (.inl rfl) held) decoded _ ih
    intro address selected
    obtain ⟨bytes, denotes⟩ := payload address selected
    exact ⟨bytes, value_preserved included denotes⟩

private theorem original_value (included : RecordsIncluded before after)
    (payload : ∃ bytes, ValueDenotes before value bytes)
    (found : ValueDenotes after value bytes) : ValueDenotes before value bytes := by
  obtain ⟨original, originalDenotes⟩ := payload
  cases originalDenotes with
  | inline original => cases found; exact .inline _
  | stored hash original held =>
    have retained := included _ _ _ (.inr rfl) held
    cases found with
    | stored _ _ now =>
      have same := retained.symm.trans now
      cases same
      exact .stored _ _ held

/-- Adding records cannot create entries in a snapshot whose complete
stored representation was already present. This is the missing reverse
direction of preservation for partial replicas. -/
theorem closed_snapshot_no_new_entries (closed : Closed before root)
    (included : RecordsIncluded before after) (entry : GraphValue after root key bytes) :
    GraphValue before root key bytes := by
  induction closed generalizing key bytes with
  | leaf held decoded payload =>
    have retained := included _ _ _ (.inl rfl) held
    cases entry with
    | leaf address raw suffix value bytes now parsed denotes =>
      have same := retained.symm.trans now
      cases same
      simp only [decoded, Except.ok.injEq, Node.leaf.injEq] at parsed
      obtain ⟨rfl, rfl⟩ := parsed
      exact .leaf _ _ _ _ _ held decoded (original_value included payload denotes)
    | branchValue _ _ _ _ _ now parsed _ => simp_all
    | extension _ _ _ _ _ _ now parsed _ _ => simp_all
    | branchChild _ _ _ _ _ _ _ _ now parsed _ _ => simp_all
    | routeValue _ _ _ _ _ now parsed _ => simp_all
    | routeChild _ _ _ _ _ _ _ _ now parsed _ _ => simp_all
  | extension held decoded nonempty below ih =>
    have retained := included _ _ _ (.inl rfl) held
    cases entry with
    | leaf _ _ _ _ _ now parsed _ => simp_all
    | branchValue _ _ _ _ _ now parsed _ => simp_all
    | extension address raw segment child tail bytes now parsed _ path =>
      have same := retained.symm.trans now
      cases same
      simp only [decoded, Except.ok.injEq, Node.extension.injEq] at parsed
      obtain ⟨rfl, rfl⟩ := parsed
      exact .extension _ _ _ _ _ _ held decoded nonempty (ih path)
    | branchChild _ _ _ _ _ _ _ _ now parsed _ _ => simp_all
    | routeValue _ _ _ _ _ now parsed _ => simp_all
    | routeChild _ _ _ _ _ _ _ _ now parsed _ _ => simp_all
  | branch held decoded payload below ih =>
    have retained := included _ _ _ (.inl rfl) held
    cases entry with
    | leaf _ _ _ _ _ now parsed _ => simp_all
    | branchValue address raw children value bytes now parsed denotes =>
      have same := retained.symm.trans now
      cases same
      simp only [decoded, Except.ok.injEq, Node.branch.injEq] at parsed
      obtain ⟨rfl, rfl⟩ := parsed
      exact .branchValue _ _ _ _ _ held decoded (original_value included (payload _ rfl) denotes)
    | extension _ _ _ _ _ _ now parsed _ _ => simp_all
    | branchChild address raw children value nibble child tail bytes now parsed edge path =>
      have same := retained.symm.trans now
      cases same
      simp only [decoded, Except.ok.injEq, Node.branch.injEq] at parsed
      obtain ⟨rfl, rfl⟩ := parsed
      exact .branchChild _ _ _ _ _ _ _ _ held decoded edge (ih _ _ edge path)
    | routeValue _ _ _ _ _ now parsed _ => simp_all
    | routeChild _ _ _ _ _ _ _ _ now parsed _ _ => simp_all
  | route held decoded payload below ih =>
    have retained := included _ _ _ (.inl rfl) held
    cases entry with
    | leaf _ _ _ _ _ now parsed _ => simp_all
    | branchValue _ _ _ _ _ now parsed _ => simp_all
    | extension _ _ _ _ _ _ now parsed _ _ => simp_all
    | branchChild _ _ _ _ _ _ _ _ now parsed _ _ => simp_all
    | routeValue address raw children value bytes now parsed denotes =>
      have same := retained.symm.trans now
      cases same
      simp only [decoded, Except.ok.injEq, Node.route.injEq] at parsed
      obtain ⟨rfl, rfl⟩ := parsed
      exact .routeValue _ _ _ _ _ held decoded (original_value included (payload _ rfl) denotes)
    | routeChild address raw children value nibble child tail bytes now parsed edge path =>
      have same := retained.symm.trans now
      cases same
      simp only [decoded, Except.ok.injEq, Node.route.injEq] at parsed
      obtain ⟨rfl, rfl⟩ := parsed
      exact .routeChild _ _ _ _ _ _ _ _ held decoded edge (ih _ _ edge path)

/-- Any executed mutation with nonconflicting writes leaves every entry of
an already stored version exactly unchanged. The new root may describe a
new version; it cannot silently rewrite the meaning of the saved old root. -/
theorem saved_version_entries_unchanged (stored : StoredSnapshot s.read root)
    (operation : Mutate A) (safe : SafeWrites d s operation.run)
    (ran : execute d s operation.run = some (result, after)) :
    Entry after.read root key bytes ↔ Entry s.read root key bytes := by
  rcases stored with empty | closed
  · unfold Entry
    rw [empty]
    simp
  have included := execution_preserves_records operation.run safe ran
  constructor
  · rintro ⟨bounded, nonzero, entry⟩
    exact ⟨bounded, nonzero, closed_snapshot_no_new_entries closed included entry⟩
  · rintro ⟨bounded, nonzero, entry⟩
    exact ⟨bounded, nonzero, graph_value_preserved included entry⟩

/-- The entries contributed by one stored node: a leaf labels its payload,
an extension prefixes its child, and a branch labels each child's entries
with its slot. This is a compositional reading of `GraphValue`. -/
def NodeEntries (store : RawSnapshot) : Node → List UInt8 → ByteArray → Prop
  | .leaf suffix value, key, bytes => key = suffix.toList ∧ ValueDenotes store value bytes
  | .extension segment child, key, bytes =>
    segment.toList ≠ [] ∧ ∃ tail, key = segment.toList ++ tail ∧ GraphValue store child tail bytes
  | .branch _ value, [], bytes => ∃ v, value = some v ∧ ValueDenotes store v bytes
  | .branch children _, nibble :: tail, bytes =>
    ∃ child, children[nibble.toNat]? = some (some child) ∧ GraphValue store child tail bytes
  | .route _ value, [], bytes =>
    ∃ address, value = some address ∧ ValueDenotes store (.hash address) bytes
  | .route children _, nibble :: tail, bytes =>
    ∃ child, children[nibble.toNat]? = some (some child) ∧ GraphValue store child tail bytes

theorem graph_node_entries (held : store nodeSpace root = some raw)
    (decoded : decode raw = .ok node) :
    GraphValue store root key bytes ↔ NodeEntries store node key bytes := by
  constructor
  · intro entry
    cases entry with
    | leaf address raw suffix value bytes now parsed denotes =>
      simp_all [NodeEntries]
    | branchValue address raw children value bytes now parsed denotes =>
      simp_all [NodeEntries]
    | extension address raw segment child tail bytes now parsed nonempty below =>
      simp_all [NodeEntries]
    | branchChild address raw children value nibble child tail bytes now parsed edge below =>
      simp_all [NodeEntries]
    | routeValue address raw children value bytes now parsed denotes => simp_all [NodeEntries]
    | routeChild address raw children value nibble child tail bytes now parsed edge below =>
      simp_all [NodeEntries]
  · intro entry
    cases node with
    | leaf suffix value =>
      obtain ⟨rfl, denotes⟩ := entry
      exact .leaf _ _ _ _ _ held decoded denotes
    | extension segment child =>
      obtain ⟨nonempty, tail, rfl, below⟩ := entry
      exact .extension _ _ _ _ _ _ held decoded nonempty below
    | branch children value =>
      cases key with
      | nil =>
        obtain ⟨v, rfl, denotes⟩ := entry
        exact .branchValue _ _ _ _ _ held decoded denotes
      | cons nibble tail =>
        obtain ⟨child, edge, below⟩ := entry
        exact .branchChild _ _ _ _ _ _ _ _ held decoded edge below
    | route children value =>
      cases key with
      | nil =>
        obtain ⟨address, rfl, denotes⟩ := entry
        exact .routeValue _ _ _ _ _ held decoded denotes
      | cons nibble tail =>
        obtain ⟨child, edge, below⟩ := entry
        exact .routeChild _ _ _ _ _ _ _ _ held decoded edge below

/-- The references a freshly constructed node needs are already present.
This is the induction invariant used while rebuilding a modified path. -/
def NodeClosed (store : RawSnapshot) : Node → Prop
  | .leaf _ value => ∃ bytes, ValueDenotes store value bytes
  | .extension segment child => segment.toList ≠ [] ∧ Closed store child
  | .branch children value =>
    (∀ v, value = some v → ∃ bytes, ValueDenotes store v bytes) ∧
    (∀ (index : Nat) child, children[index]? = some (some child) → Closed store child)
  | .route children value =>
    (∀ address, value = some address → ∃ bytes, ValueDenotes store (.hash address) bytes) ∧
    (∀ (index : Nat) child, children[index]? = some (some child) → Closed store child)

theorem loaded_node_closed (closed : Closed store root)
    (held : store nodeSpace root = some raw) (decoded : decode raw = .ok node) :
    NodeClosed store node := by
  cases closed <;> simp_all [NodeClosed]
  all_goals assumption

theorem node_entries_unchanged (closed : NodeClosed before node)
    (included : RecordsIncluded before after) :
    NodeEntries after node key bytes ↔ NodeEntries before node key bytes := by
  cases node with
  | leaf suffix value =>
    constructor
    · rintro ⟨key, found⟩
      exact ⟨key, original_value included closed found⟩
    · rintro ⟨key, found⟩
      exact ⟨key, value_preserved included found⟩
  | extension segment child =>
    constructor
    · rintro ⟨nonempty, tail, key, found⟩
      exact ⟨nonempty, tail, key, closed_snapshot_no_new_entries closed.2 included found⟩
    · rintro ⟨nonempty, tail, key, found⟩
      exact ⟨nonempty, tail, key, graph_value_preserved included found⟩
  | branch children value =>
    cases key with
    | nil =>
      constructor
      · rintro ⟨v, selected, found⟩
        exact ⟨v, selected, original_value included (closed.1 v selected) found⟩
      · rintro ⟨v, selected, found⟩
        exact ⟨v, selected, value_preserved included found⟩
    | cons nibble tail =>
      constructor
      · rintro ⟨child, edge, found⟩
        exact ⟨child, edge, closed_snapshot_no_new_entries (closed.2 _ _ edge) included found⟩
      · rintro ⟨child, edge, found⟩
        exact ⟨child, edge, graph_value_preserved included found⟩
  | route children value =>
    cases key with
    | nil =>
      constructor
      · rintro ⟨v, selected, found⟩
        exact ⟨v, selected, original_value included (closed.1 v selected) found⟩
      · rintro ⟨v, selected, found⟩
        exact ⟨v, selected, value_preserved included found⟩
    | cons nibble tail =>
      constructor
      · rintro ⟨child, edge, found⟩
        exact ⟨child, edge, closed_snapshot_no_new_entries (closed.2 _ _ edge) included found⟩
      · rintro ⟨child, edge, found⟩
        exact ⟨child, edge, graph_value_preserved included found⟩

/-- The actual node write gives the constructed node exactly its intended
entries. Existing child snapshots are complete; a local hash collision is
excluded only at the address this write encounters. -/
theorem put_node_exact (closed : NodeClosed s.read node) (wellFormed : node.wf)
    (safe : CompatibleWrite s nodeSpace (d (tagOf node ++ encode node)) (encode node))
    (ran : execute d s (put node).run = some (.ok root, after)) :
    GraphValue after.read root key bytes ↔ NodeEntries s.read node key bytes := by
  obtain ⟨included, held⟩ := put_stores_node_and_preserves safe ran
  rw [graph_node_entries held (TrieCodecProofs.decode_encode wellFormed)]
  exact node_entries_unchanged closed included

theorem put_node_closed (closed : NodeClosed s.read node) (wellFormed : node.wf)
    (safe : CompatibleWrite s nodeSpace (d (tagOf node ++ encode node)) (encode node))
    (ran : execute d s (put node).run = some (.ok root, after)) : Closed after.read root := by
  obtain ⟨included, held⟩ := put_stores_node_and_preserves safe ran
  have decoded := TrieCodecProofs.decode_encode wellFormed
  cases node with
  | leaf suffix value =>
    obtain ⟨bytes, denotes⟩ := closed
    exact .leaf held decoded ⟨bytes, value_preserved included denotes⟩
  | extension segment child =>
    exact .extension held decoded closed.1 (closed_preserved closed.2 included)
  | branch children value =>
    apply Closed.branch held decoded
    · intro v selected
      obtain ⟨bytes, denotes⟩ := closed.1 v selected
      exact ⟨bytes, value_preserved included denotes⟩
    · intro index child edge
      exact closed_preserved (closed.2 index child edge) included
  | route children value =>
    apply Closed.route held decoded
    · intro address selected
      obtain ⟨bytes, denotes⟩ := closed.1 address selected
      exact ⟨bytes, value_preserved included denotes⟩
    · intro index child edge
      exact closed_preserved (closed.2 index child edge) included

end Synchronicity.TrieSnapshotClosure
