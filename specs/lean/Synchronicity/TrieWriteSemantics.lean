import Synchronicity.TrieMutateProofs
import Synchronicity.TrieSnapshotProofs
import Synchronicity.TrieWalkProofs

/-! Content-addressed writes preserve versions already stored.

The collision assumption concerns only addresses actually written by an
execution. It does not assert that a fixed-width hash is globally injective.
These lemmas supply the storage part of exact edit semantics; preserving an
old root alone does not prove the meaning of the newly returned root. -/
namespace Synchronicity.TrieWriteSemantics
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open TrieMutateProofs TrieProgramProofs TrieSnapshotProofs

/-- The image being written does not conflict with any existing image at
that address. Equal repeated images are allowed. Receive/import integrity
and collision resistance on encountered images justify this contract. -/
def CompatibleWrite (s : Store) (space : String) (address bytes : ByteArray) : Prop :=
  ∀ previous, s.read space address = some previous → previous = bytes

private theorem read_after_write (s : Store) (space probeSpace : String)
    (address bytes probe : ByteArray) :
    (s.write space address bytes).read probeSpace probe =
      if (space = nodeSpace ∨ space = valueSpace) ∧ space = probeSpace ∧ address = probe
      then some bytes else s.read probeSpace probe := by
  by_cases node : space = nodeSpace
  · subst space
    by_cases same : probeSpace = nodeSpace
    · subst probeSpace
      simpa only [beq_iff_eq, true_or, true_and, and_true] using read_write_node s address bytes probe
    · have reverse := Ne.symm same
      simp_all [Store.write, Store.read, nodeSpace, valueSpace]
  · by_cases value : space = valueSpace
    · subst space
      by_cases same : probeSpace = valueSpace
      · subst probeSpace
        simp [Store.write, Store.read, Store.lookup, nodeSpace, valueSpace, List.find?_cons]
        split <;> simp_all
      · have reverse := Ne.symm same
        simp_all [Store.write, Store.read, nodeSpace, valueSpace]
    · simp [Store.write, node, value]

theorem compatible_write_preserves_records (safe : CompatibleWrite s space address bytes) :
    RecordsIncluded s.read (s.write space address bytes).read := by
  intro probeSpace probe previous _ held
  rw [read_after_write]
  split
  · rename_i same
    obtain ⟨_, rfl, rfl⟩ := same
    rw [← safe previous held]
  · exact held

private theorem included_trans (first : RecordsIncluded a b) (second : RecordsIncluded b c) :
    RecordsIncluded a c := fun space key bytes relevant held =>
  second space key bytes relevant (first space key bytes relevant held)

/-- No conflicting image is written anywhere in this actual execution.
Reads and digests use the same raw interpreter as the operation proofs.
Unsupported effects are excluded, rather than assigned invented replies. -/
def SafeWrites (d : ByteArray → ByteArray) (s : Store) : Program MutateEffects A → Prop
  | .pure _ => True
  | .request (.left (.readBytes space key)) next => SafeWrites d s (next (.ok (s.read space key)))
  | .request (.right (.left (.blake3 bytes))) next => SafeWrites d s (next (.ok (d bytes)))
  | .request (.right (.right (.putBytes space key bytes))) next =>
    CompatibleWrite s space key bytes ∧ SafeWrites d (s.write space key bytes) (next (.ok ()))
  | .request (.left _) _ => False

/-- Even an execution that eventually returns an error preserves all
previously held records, provided its encountered writes do not collide. -/
theorem execution_preserves_records (program : Program MutateEffects A)
    (safe : SafeWrites d s program) (ran : execute d s program = some (result, after)) :
    RecordsIncluded s.read after.read := by
  induction program generalizing s with
  | pure value =>
    cases ran
    exact fun _ _ _ _ held => held
  | request effect next ih =>
    cases effect with
    | left storage =>
      cases storage <;> first
        | contradiction
        | exact ih _ safe ran
    | right effect =>
      cases effect with
      | left digest => cases digest; exact ih _ safe ran
      | right write =>
        cases write
        exact included_trans (compatible_write_preserves_records safe.1) (ih _ safe.2 ran)

/-- Editing another version cannot change a value already readable from an
old saved root. This applies to both production insertion and removal, and
also to valid partial progress followed by an error. The new root's exact
contents are a separate, stronger edit obligation. -/
theorem mutation_preserves_saved_read (operation : Mutate A)
    (safe : SafeWrites d s operation.run)
    (ran : execute d s operation.run = some (result, after))
    (read : executeReads s.read (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some bytes)))) :
    executeReads after.read (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some bytes))) :=
  retained_snapshot_still_reads (execution_preserves_records operation.run safe ran) read

/-- Storing the node preserves existing snapshot entries and establishes
exactly the canonical bytes at the returned address. -/
theorem put_stores_node_and_preserves (safe : CompatibleWrite s nodeSpace
    (d (tagOf node ++ encode node)) (encode node))
    (ran : execute d s (put node).run = some (.ok address, after)) :
    RecordsIncluded s.read after.read ∧ after.read nodeSpace address = some (encode node) := by
  rw [execute_put] at ran
  cases ran
  refine ⟨compatible_write_preserves_records safe, ?_⟩
  rw [read_write_node]
  simp

/-- The value reference produced by the actual write operation denotes the
caller's bytes. Existing records survive both inline and stored values. -/
theorem valueRef_stores_exact_bytes (safe : SafeWrites d s (valueRef bytes).run)
    (ran : execute d s (valueRef bytes).run = some (.ok value, after)) :
    RecordsIncluded s.read after.read ∧ ValueDenotes after.read value bytes := by
  refine ⟨execution_preserves_records _ safe ran, ?_⟩
  unfold valueRef at ran
  split at ran
  · simp only [run_pure, TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq,
      Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact .inline bytes
  · simp only [run_bind, digest_run, program_bind_request, program_bind_pure, execute_digest,
      mapError_ok, bindCont_ok, write_run, execute_write, run_pure,
      TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    apply ValueDenotes.stored
    rw [read_after_write]
    simp

private theorem valueRef_denotes_and_wf (width : Width d) (small : bytes.size < 2 ^ 64)
    (ran : execute d s (valueRef bytes).run = some (.ok value, after)) :
    ValueDenotes after.read value bytes ∧ value.wf := by
  unfold valueRef at ran
  split at ran
  · simp only [run_pure, TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq,
      Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨.inline bytes, small⟩
  · simp only [run_bind, digest_run, program_bind_request, program_bind_pure, execute_digest,
      mapError_ok, bindCont_ok, write_run, execute_write, run_pure,
      TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq, Except.ok.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    refine ⟨ValueDenotes.stored _ _ ?_, width _⟩
    rw [read_after_write]
    simp

private theorem value_denotes_unique (first : ValueDenotes store value a)
    (second : ValueDenotes store value b) : a = b := by
  cases first <;> cases second <;> simp_all

private theorem leaf_graph_iff (held : store nodeSpace root = some raw)
    (decoded : decode raw = .ok (.leaf suffix value)) :
    GraphValue store root key bytes ↔ key = suffix.toList ∧ ValueDenotes store value bytes := by
  constructor
  · intro entry
    cases entry <;> simp_all
  · rintro ⟨rfl, denotes⟩
    exact .leaf _ _ _ _ _ held decoded denotes

/-- The node written for a singleton snapshot denotes exactly its one key
and value, regardless of unrelated data already present in storage. -/
theorem put_leaf_exact (wellFormed : (Node.leaf suffix value).wf)
    (denotes : ValueDenotes s.read value bytes)
    (ran : execute d s (put (.leaf suffix value)).run = some (.ok address, after)) :
    GraphValue after.read address key result ↔ key = suffix.toList ∧ result = bytes := by
  rw [execute_put] at ran
  cases ran
  have held : (s.write nodeSpace (d (tagOf (.leaf suffix value) ++ encode (.leaf suffix value)))
      (encode (.leaf suffix value))).read nodeSpace
      (d (tagOf (.leaf suffix value) ++ encode (.leaf suffix value))) =
      some (encode (.leaf suffix value)) := by
    rw [read_write_node]
    simp
  rw [leaf_graph_iff held (TrieCodecProofs.decode_encode wellFormed)]
  have persists : ValueDenotes
      (s.write nodeSpace (d (tagOf (.leaf suffix value) ++ encode (.leaf suffix value)))
        (encode (.leaf suffix value))).read value bytes := by
    cases denotes with
    | inline bytes => exact .inline bytes
    | stored hash bytes held =>
      apply ValueDenotes.stored
      rw [read_after_write]
      simpa [nodeSpace, valueSpace] using held
  constructor
  · rintro ⟨same, found⟩
    exact ⟨same, value_denotes_unique found persists⟩
  · rintro ⟨same, rfl⟩
    exact ⟨same, persists⟩

/-- The first insertion creates exactly the requested entry, with no other
entries. This is the base case of full edit semantics over arbitrary keys
and payloads, executed through the production value and node writes. -/
theorem insert_into_empty_exact (width : Width d)
    (empty : isEmptyRoot oldRoot = true) (keyBound : key.size ≤ maxKeyBytes)
    (valueBound : bytes.size ≤ maxValueBytes)
    (ran : execute d s (Trie.insert oldRoot key bytes).run = some (.ok root, after))
    (nonzero : root.data.all (· == 0) = false) :
    Entry after.read root probe result ↔ probe = key ∧ result = bytes := by
  unfold Trie.insert at ran
  simp only [Nat.not_lt.mpr keyBound, Nat.not_lt.mpr valueBound, ↓reduceIte] at ran
  rw [execute_run_bind] at ran
  cases prepared : execute d s (valueRef bytes).run with
  | none => simp only [prepared] at ran; cases ran
  | some outcome =>
    obtain ⟨reply, middle⟩ := outcome
    cases reply with
    | error failure => simp only [prepared] at ran; cases ran
    | ok value =>
      simp only [prepared, empty, ↓reduceIte] at ran
      have ⟨denotes, valueWf⟩ := valueRef_denotes_and_wf width
        (bytes := bytes) (by unfold maxValueBytes at valueBound; omega) prepared
      have keyWf := nibblesOf_wf (nibbles_keyNibbles key)
        (by rw [TrieProgramProofs.key_nibbles_length]; unfold maxKeyBytes at keyBound; omega)
      have leafRun : execute d middle (put (.leaf (nibblesOf (keyNibbles key)) value)).run =
          some (.ok root, after) := by
        simpa [insertAt, depthBudget, maxKeyBytes, descend, rebuild, run_bind, execute_bind, execute_put] using ran
      have exactLeaf := put_leaf_exact (key := keyNibbles probe) (result := result)
        ⟨keyWf, valueWf⟩ denotes leafRun
      have nibbles : (nibblesOf (keyNibbles key)).toList = keyNibbles key := by
        simp [TrieWalkProofs.toList_eq, nibblesOf]
      rw [nibbles] at exactLeaf
      constructor
      · rintro ⟨_, _, entry⟩
        obtain ⟨same, content⟩ := exactLeaf.mp entry
        have keys := congrArg Walk.bytesOfNibbles same
        simp only [TrieWalkProofs.bytesOfNibbles_keyNibbles, Option.some.injEq] at keys
        exact ⟨keys, content⟩
      · rintro ⟨rfl, rfl⟩
        exact ⟨keyBound, nonzero, exactLeaf.mpr ⟨rfl, rfl⟩⟩

end Synchronicity.TrieWriteSemantics
