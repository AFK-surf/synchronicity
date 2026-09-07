import Synchronicity.TrieMutateProofs
import Synchronicity.TrieWalkProofs
import Synchronicity.TrieSnapshotProofs

/-! Removing an absent entry leaves the selected snapshot and its storage
unchanged. Absence is established from stored key labels and empty slots;
a missing record or a peer refusal is never evidence of absence. -/
namespace Synchronicity.TrieRemoveSemantics
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open TrieMutateProofs TrieProgramProofs

/-- Negative membership in the stored snapshot. Each witness ends at an
actual differing label or empty slot; missing records have no constructor. -/
inductive Absent (store : RawSnapshot) : ByteArray → List UInt8 → Prop where
  | leaf (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.leaf suffix value))
      (different : suffix.data.toList ≠ key) : Absent store root key
  | extensionOutside (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.extension segment child))
      (outside : segment.data.toList.isPrefixOf key = false) : Absent store root key
  | extensionBelow (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.extension segment child))
      (inside : segment.data.toList.isPrefixOf key = true)
      (nonempty : segment.data.toList ≠ [])
      (below : Absent store child (key.drop segment.data.toList.length)) : Absent store root key
  | branchValue (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.branch children none)) : Absent store root []
  | branchEmpty (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.branch children value))
      (empty : childAt children nibble = none) : Absent store root (nibble :: key)
  | branchBelow (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.branch children value))
      (edge : childAt children nibble = some child)
      (below : Absent store child key) : Absent store root (nibble :: key)

private theorem execute_load (held : s.read nodeSpace address = some raw)
    (decoded : decode raw = .ok node) :
    execute d s (load address).run = some (.ok node, s) := by
  simp only [load, run_bind, read_run, program_bind_request, program_bind_pure,
    execute_read, mapError_ok, bindCont_ok, held, decoded, run_pure, TrieMutateProofs.execute_pure]

/-- Structural absence is observable as a successful missing-key read,
not a storage error or an exhausted budget. -/
theorem absent_lookup (absent : Absent store root key)
    (fuel budget : Nat) (enough : key.length < fuel) (reads : fuel < budget) :
    executeReads store budget (lookup fuel (some root) key).run = some (.ok (.ok none)) := by
  induction absent generalizing fuel budget with
  | leaf held decoded different =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace _) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        simp only [held, decoded, TrieWalkProofs.toList_eq, beq_iff_eq, different, ↓reduceIte]
        exact TrieProgramProofs.execute_pure _ _ _
  | extensionOutside held decoded outside =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace _) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        simp only [held, decoded, TrieWalkProofs.toList_eq, outside, Bool.not_false,
          Bool.or_true, ↓reduceIte]
        exact TrieProgramProofs.execute_pure _ _ _
  | @extensionBelow root raw segment child key held decoded inside nonempty below ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace _) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        have notEmpty : segment.data.toList.isEmpty = false := by simpa using nonempty
        simp only [held, decoded, TrieWalkProofs.toList_eq, notEmpty, inside,
          Bool.not_true, Bool.or_false, Bool.false_eq_true, ↓reduceIte]
        have positive := List.length_pos_iff.mpr nonempty
        have bounded := (List.isPrefixOf_iff_prefix.mp inside).length_le
        exact ih fuel budget (by simp only [List.length_drop]; omega) (by omega)
  | branchValue held decoded =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace _) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        simp only [held, decoded]
        exact TrieProgramProofs.execute_pure _ _ _
  | branchEmpty held decoded empty =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace _) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        simp only [held, decoded]
        change executeReads store budget (lookup fuel (childAt _ _) _).run = _
        rw [empty]
        cases fuel with
        | zero => simp only [List.length_cons] at enough; omega
        | succ fuel => exact TrieProgramProofs.execute_pure _ _ _
  | branchBelow held decoded edge below ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace _) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        simp only [held, decoded]
        change executeReads store budget (lookup fuel (childAt _ _) _).run = _
        rw [edge]
        exact ih fuel budget (by simp only [List.length_cons] at enough; omega) (by omega)

theorem absent_has_no_entry (absent : Absent store root key) :
    ¬ GraphValue store root key bytes := by
  intro entry
  have missing := absent_lookup absent (key.length + 1) (key.length + 2) (by omega) (by omega)
  have present := lookup_semantic_complete entry (key.length + 1) (key.length + 2)
    (by omega) (by omega)
  rw [missing] at present
  cases present

/-- The complete removal continuation, including its actual reconstruction
stack, preserves all storage when the key is absent. -/
theorem absent_removal_continuation (absent : Absent s.read root key)
    (fuel : Nat) (enough : key.length < fuel) (stack : List RemoveFrame) :
    execute d s (do
      let (replacement, frames) ← descendRemove fuel root key stack
      unwind replacement frames).run =
    execute d s (unwind (some root) stack).run := by
  induction absent generalizing fuel stack with
  | leaf held decoded different =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [descendRemove, execute_run_bind, execute_run_bind, execute_load held decoded]
      simp [different]
  | extensionOutside held decoded outside =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [descendRemove, execute_run_bind, execute_run_bind, execute_load held decoded]
      simp [outside]
  | @extensionBelow root raw segment child key held decoded inside nonempty below ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [descendRemove, execute_run_bind, execute_run_bind, execute_load held decoded]
      simp only [inside, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      have positive := List.length_pos_iff.mpr nonempty
      have bounded := (List.isPrefixOf_iff_prefix.mp inside).length_le
      have tailSmall : (key.drop segment.data.toList.length).length < fuel := by
        simp only [List.length_drop]
        omega
      rw [← execute_run_bind, ih fuel tailSmall]
      simp [unwind]
  | branchValue held decoded =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [descendRemove, execute_run_bind, execute_run_bind, execute_load held decoded]
      simp
  | branchEmpty held decoded empty =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [descendRemove, execute_run_bind, execute_run_bind, execute_load held decoded]
      simp [empty]
  | branchBelow held decoded edge below ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [descendRemove, execute_run_bind, execute_run_bind, execute_load held decoded]
      simp only [edge]
      rw [← execute_run_bind, ih fuel (by simp only [List.length_cons] at enough; omega)]
      simp [unwind]

/-- Deleting an entry known absent from stored snapshot structure answers
the same root and performs no writes, even to unrelated stored snapshots. -/
theorem remove_absent_preserves_snapshot (absent : Absent s.read root (keyNibbles key))
    (bounded : key.size ≤ maxKeyBytes) (nonempty : isEmptyRoot root = false) :
    execute d s (Trie.remove root key).run = some (.ok root, s) := by
  unfold Trie.remove
  simp only [Nat.not_lt.mpr bounded, ↓reduceIte, nonempty, Bool.false_eq_true]
  rw [execute_run_bind]
  have unchanged := absent_removal_continuation (d := d) absent depthBudget
    (by rw [TrieProgramProofs.key_nibbles_length]; unfold depthBudget; omega) []
  change execute d s (removeAt depthBudget root (keyNibbles key)).run = _ at unchanged
  rw [unchanged]
  rfl

end Synchronicity.TrieRemoveSemantics
