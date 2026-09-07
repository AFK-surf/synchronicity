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
  | routeValue (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.route children none)) : Absent store root []
  | routeEmpty (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.route children value))
      (empty : childAt children nibble = none) : Absent store root (nibble :: key)
  | routeBelow (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.route children value))
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
  | routeValue held decoded =>
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
  | routeEmpty held decoded empty =>
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
  | routeBelow held decoded edge below ih =>
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

private theorem value_ne_missing (value : Value) (budget : Nat) :
    executeReads store budget (resolveValue value).run ≠ some (.ok (.ok none)) := by
  cases value with
  | inline bytes =>
    change executeReads store budget (.pure (.ok (.ok (some bytes)) : Reply LookupResult)) ≠ _
    simp
  | hash hash =>
    cases budget with
    | zero => change none ≠ _; simp
    | succ budget =>
      change executeReads store (budget + 1) (.request (.readBytes valueSpace hash) _) ≠ _
      rw [executeReads]
      dsimp only [Program.bind, ExceptT.bindCont]
      cases store valueSpace hash with
      | none =>
        change executeReads store budget (.pure (.ok (.error (.missingValue hash)) : Reply LookupResult)) ≠ _
        simp
      | some bytes =>
        change executeReads store budget (.pure (.ok (.ok (some bytes)) : Reply LookupResult)) ≠ _
        simp

/-- A successful missing-key answer supplies structural absence in a
canonical store. This direction matters: callers need not manufacture an
extra absence certificate independently of the actual read. -/
theorem lookup_missing_is_absent (shaped : Shaped s)
    (fuel budget : Nat) (root : ByteArray) (key : List UInt8)
    (missing : executeReads s.read budget (lookup fuel (some root) key).run =
      some (.ok (.ok none))) : Absent s.read root key := by
  induction fuel generalizing root key budget with
  | zero =>
    change executeReads s.read budget (.pure (.ok (.error .depthExceeded) : Reply LookupResult)) = _ at missing
    simp at missing
  | succ fuel ih =>
    cases budget with
    | zero => contradiction
    | succ budget =>
      change executeReads s.read (budget + 1) (.request (.readBytes nodeSpace root) _) = _ at missing
      rw [executeReads] at missing
      dsimp only [Program.bind, ExceptT.bindCont] at missing
      cases held : s.read nodeSpace root with
      | none =>
        simp only [held] at missing
        change executeReads s.read budget (.pure (.ok (.error (.missingNode root)) : Reply LookupResult)) = _ at missing
        simp at missing
      | some raw =>
        obtain ⟨node, decoded, _, _, invariants⟩ := shaped root raw held
        simp only [held, decoded] at missing
        cases node with
        | leaf suffix value =>
          dsimp only at missing
          split at missing
          · exact (value_ne_missing value budget missing).elim
          · rename_i different
            apply Absent.leaf held decoded
            simpa only [TrieWalkProofs.toList_eq, beq_iff_eq] using different
        | extension segment child =>
          dsimp only at missing
          have nonempty : segment.data.toList ≠ [] := by
            intro empty
            have zero : segment.size = 0 := by
              have := Array.length_toList (xs := segment.data)
              rw [empty] at this
              exact this.symm
            simp [checkInvariants, zero] at invariants
          split at missing
          · rename_i outside
            have notEmpty : segment.toList.isEmpty = false := by
              simpa [TrieWalkProofs.toList_eq] using nonempty
            apply Absent.extensionOutside held decoded
            rw [notEmpty] at outside
            simpa only [Bool.false_or, Bool.not_eq_true', TrieWalkProofs.toList_eq] using outside
          · rename_i inside
            simp only [Bool.or_eq_true, not_or] at inside
            have starts : segment.data.toList.isPrefixOf key = true := by
              simpa [TrieWalkProofs.toList_eq] using inside.2
            apply Absent.extensionBelow held decoded starts nonempty
            apply ih budget child
            simpa only [TrieWalkProofs.toList_eq, ExceptT.run] using missing
        | branch children value =>
          cases key with
          | nil =>
            cases value with
            | none => exact .branchValue held decoded
            | some value => exact (value_ne_missing value budget missing).elim
          | cons nibble key =>
            change executeReads s.read budget (lookup fuel (childAt children nibble) key).run = _ at missing
            cases edge : childAt children nibble with
            | none => exact .branchEmpty held decoded edge
            | some child =>
              rw [edge] at missing
              exact .branchBelow held decoded edge (ih budget child key missing)
        | route children value =>
          cases key with
          | nil =>
            cases value with
            | none => exact .routeValue held decoded
            | some value => exact (value_ne_missing (.hash value) budget missing).elim
          | cons nibble key =>
            change executeReads s.read budget (lookup fuel (childAt children nibble) key).run = _ at missing
            cases edge : childAt children nibble with
            | none => exact .routeEmpty held decoded edge
            | some child =>
              rw [edge] at missing
              exact .routeBelow held decoded edge (ih budget child key missing)

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
  | routeValue held decoded =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [descendRemove, execute_run_bind, execute_run_bind, execute_load held decoded]
      simp
  | routeEmpty held decoded empty =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [descendRemove, execute_run_bind, execute_run_bind, execute_load held decoded]
      simp [empty]
  | routeBelow held decoded edge below ih =>
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

/-- If reading a key says it is absent, deleting it leaves the snapshot and
all stored bytes unchanged. Canonicality is the existing invariant maintained
by production insertion and removal; no completeness/refusal flag is assumed. -/
theorem remove_missing_key_changes_nothing (shaped : Shaped s)
    (bounded : key.size ≤ maxKeyBytes) (nonempty : isEmptyRoot root = false)
    (missing : executeReads s.read (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok none))) :
    execute d s (Trie.remove root key).run = some (.ok root, s) := by
  apply remove_absent_preserves_snapshot (bounded := bounded) (nonempty := nonempty)
  apply lookup_missing_is_absent shaped (maxKeyBytes * 2 + 1) (maxKeyBytes * 2 + 2)
  unfold Trie.get at missing
  change root.data.all (· == 0) = false at nonempty
  simpa only [Nat.not_lt.mpr bounded, ↓reduceIte, nonempty, Bool.false_eq_true] using missing

end Synchronicity.TrieRemoveSemantics
