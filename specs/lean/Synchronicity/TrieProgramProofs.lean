import VerifiedCore.Trie.Program
import Synchronicity.Prelude

/-! Properties of the executable trie lookup, not a second traversal model. -/
namespace Synchronicity.TrieProgramProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie

/-- Every possible host reply retains the bound. Thus failures, corrupt bytes
and absent records are covered, not only successful fixture executions. -/
inductive ReadBound : Nat → Program Storage A → Prop where
  | done (value : A) : ReadBound n (.pure value)
  | read (space : String) (key : ByteArray)
      (allowed : space = nodeSpace ∨ space = valueSpace)
      (next : Reply (Option ByteArray) → Program Storage A)
      (bounded : ∀ reply, ReadBound n (next reply)) :
      ReadBound (n + 1) (.request (.readBytes space key) next)

theorem read_bound_mono (h : ReadBound n p) : ReadBound (n + k) p := by
  induction h with
  | done => exact .done _
  | read space key allowed next bounded ih =>
    simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
      ReadBound.read space key allowed next ih

theorem resolve_read_bound (v : Value) : ReadBound 1 (resolveValue v).run := by
  cases v with
  | inline b => exact .done _
  | hash address =>
    apply ReadBound.read valueSpace address (Or.inr rfl)
    intro reply
    cases reply with
    | error failure => exact .done _
    | ok bytes => cases bytes <;> exact .done _

theorem lookup_read_bound (fuel : Nat) (address : Option ByteArray) (key : List UInt8) :
    ReadBound (fuel + 1) (lookup fuel address key).run := by
  induction fuel generalizing address key with
  | zero => exact .done _
  | succ fuel ih =>
    cases address with
    | none => exact .done _
    | some address =>
      apply ReadBound.read nodeSpace address (Or.inl rfl)
      intro reply
      cases reply with
      | error failure => exact .done _
      | ok raw =>
        cases raw with
        | none => exact .done _
        | some raw =>
          simp only [Program.bind, ExceptT.bindCont]
          cases decoded : decode raw with
          | error message => exact .done _
          | ok node =>
            cases node with
            | leaf suffix value =>
              dsimp only
              split
              · simpa [Nat.add_comm] using read_bound_mono (k := fuel) (resolve_read_bound value)
              · exact .done _
            | extension segment child =>
              dsimp only
              split
              · exact .done _
              · exact ih _ _
            | branch children value =>
              cases key with
              | nil =>
                cases value with
                | none => exact .done _
                | some v =>
                  simpa [Nat.add_comm] using read_bound_mono (k := fuel) (resolve_read_bound v)
              | cons nibble rest => exact ih _ _

/-- A caller cannot cause writes, transactions or unrelated namespace reads;
even hostile stored nodes admit at most 8194 primitive reads. -/
theorem get_read_bound (root key : ByteArray) :
    ReadBound (maxKeyBytes * 2 + 2) (get root key).run := by
  unfold Trie.get
  split
  · exact .done _
  · exact lookup_read_bound _ _ _

theorem oversized_key_no_storage (root key : ByteArray) (h : key.size > maxKeyBytes) :
    (get root key).run = .pure (.ok (.error (.keyTooLong key.size))) := by
  unfold Trie.get
  rw [if_pos h]
  rfl

/-- A host read failure is returned unchanged, including its original error
token; no further read or success continuation runs after it. -/
theorem failed_node_read (fuel : Nat) (address : ByteArray) (key : List UInt8) :
    ∃ next, (lookup (fuel + 1) (some address) key).run =
      .request (.readBytes nodeSpace address) next ∧
      ∀ failure, next (.error failure) = .pure (.error failure) := by
  refine ⟨_, rfl, ?_⟩
  intro failure
  rfl

theorem failed_value_read (address : ByteArray) :
    ∃ next, (resolveValue (.hash address)).run =
      .request (.readBytes valueSpace address) next ∧
      ∀ failure, next (.error failure) = .pure (.error failure) := by
  refine ⟨_, rfl, ?_⟩
  intro failure
  rfl

/-- The host contract used for graph semantics is a stable raw snapshot.
Content addressing supplies that stability during a lookup; neither nodes
nor value references are decoded or interpreted by this host function. -/
abbrev RawSnapshot := String → ByteArray → Option ByteArray

def executeReads (store : RawSnapshot) : Nat → Program Storage A → Option A
  | _, .pure result => some result
  | 0, .request _ _ => none
  | fuel + 1, .request (.readBytes space key) next =>
    executeReads store fuel (next (.ok (store space key)))
  | _ + 1, .request .begin _ => none
  | _ + 1, .request (.commit _) _ => none
  | _ + 1, .request (.rollback _) _ => none
  | _ + 1, .request (.readRows _ _ _ _ _ _) _ => none
  | _ + 1, .request (.scanRows _ _ _ _ _ _) _ => none
  | _ + 1, .request (.upsert _ _ _ _ _) _ => none
  | _ + 1, .request (.deleteRows _ _ _ _) _ => none
  | _ + 1, .request (.readInput _ _ _) _ => none
  | _ + 1, .request (.readCounter _ _) _ => none
  | _ + 1, .request (.removeFile _ _) _ => none
  | _ + 1, .request (.existsRows _ _ _) _ => none

@[simp] theorem execute_pure (store : RawSnapshot) (fuel : Nat) (result : A) :
    executeReads store fuel (.pure result) = some result := by
  cases fuel <;> rfl

@[simp] theorem execute_operation_pure (store : RawSnapshot) (fuel : Nat) (result : A) :
    executeReads store fuel (pure result : Operation A).run = some (.ok result) :=
  execute_pure store fuel (.ok result : Reply A)

/-- Values denote their inline bytes or the bytes at their own address. -/
inductive ValueDenotes (store : RawSnapshot) : Value → ByteArray → Prop where
  | inline (bytes : ByteArray) : ValueDenotes store (.inline bytes) bytes
  | stored (hash bytes : ByteArray) (held : store valueSpace hash = some bytes) :
      ValueDenotes store (.hash hash) bytes

/-- A finite root-to-key path in the decoded stored graph. Unlike `lookup`,
this relation has no execution budget, interpreter state, or search algorithm:
extension labels concatenate and branch labels contribute one nibble. -/
inductive GraphValue (store : RawSnapshot) : ByteArray → List UInt8 → ByteArray → Prop where
  | leaf (address raw suffix : ByteArray) (value : Value) (bytes : ByteArray)
      (held : store nodeSpace address = some raw)
      (decoded : decode raw = .ok (.leaf suffix value))
      (denotes : ValueDenotes store value bytes) :
      GraphValue store address suffix.toList bytes
  | branchValue (address raw : ByteArray) (children : List (Option ByteArray))
      (value : Value) (bytes : ByteArray)
      (held : store nodeSpace address = some raw)
      (decoded : decode raw = .ok (.branch children (some value)))
      (denotes : ValueDenotes store value bytes) : GraphValue store address [] bytes
  | extension (address raw segment child : ByteArray) (tail : List UInt8) (bytes : ByteArray)
      (held : store nodeSpace address = some raw)
      (decoded : decode raw = .ok (.extension segment child))
      (nonempty : segment.toList ≠ [])
      (below : GraphValue store child tail bytes) :
      GraphValue store address (segment.toList ++ tail) bytes
  | branchChild (address raw : ByteArray) (children : List (Option ByteArray))
      (value : Option Value) (nibble : UInt8) (child : ByteArray)
      (tail : List UInt8) (bytes : ByteArray)
      (held : store nodeSpace address = some raw)
      (decoded : decode raw = .ok (.branch children value))
      (edge : children[nibble.toNat]? = some (some child))
      (below : GraphValue store child tail bytes) :
      GraphValue store address (nibble :: tail) bytes

theorem resolve_semantic_sound (store : RawSnapshot) (budget : Nat)
    (value : Value) (bytes : ByteArray)
    (returned : executeReads store budget (resolveValue value).run =
      some (.ok (.ok (some bytes)))) : ValueDenotes store value bytes := by
  cases value with
  | inline b =>
    change executeReads store budget (.pure (.ok (.ok (some b)) : Reply LookupResult)) = _ at returned
    have same : b = bytes := by simpa using returned
    subst b
    exact .inline _
  | hash hash =>
    cases budget with
    | zero => contradiction
    | succ budget =>
      change executeReads store (budget + 1) (.request (.readBytes valueSpace hash) _) = _ at returned
      rw [executeReads] at returned
      dsimp only [Program.bind, ExceptT.bindCont] at returned
      cases held : store valueSpace hash with
      | none =>
        simp only [held] at returned
        change executeReads store budget (.pure (.ok (.error (.missingValue hash)) : Reply LookupResult)) = _ at returned
        simp at returned
      | some b =>
        simp only [held] at returned
        change executeReads store budget (.pure (.ok (.ok (some b)) : Reply LookupResult)) = _ at returned
        have same : b = bytes := by
          simpa using returned
        subst b
        exact .stored _ _ held

theorem lookup_semantic_sound (store : RawSnapshot) (fuel budget : Nat)
    (address : Option ByteArray) (key : List UInt8) (bytes : ByteArray)
    (returned : executeReads store budget (lookup fuel address key).run =
      some (.ok (.ok (some bytes)))) :
    ∃ root, address = some root ∧ GraphValue store root key bytes := by
  induction fuel generalizing budget address key with
  | zero =>
    change executeReads store budget (.pure (.ok (.error LookupError.depthExceeded) : Reply LookupResult)) = _ at returned
    simp at returned
  | succ fuel ih =>
    cases address with
    | none =>
      change executeReads store budget (.pure (.ok (.ok none) : Reply LookupResult)) = _ at returned
      simp at returned
    | some address =>
      refine ⟨address, rfl, ?_⟩
      cases budget with
      | zero => contradiction
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace address) _) = _ at returned
        rw [executeReads] at returned
        dsimp only [Program.bind, ExceptT.bindCont] at returned
        cases held : store nodeSpace address with
        | none =>
          simp only [held] at returned
          change executeReads store budget (.pure (.ok (.error (.missingNode address)) : Reply LookupResult)) = _ at returned
          simp at returned
        | some raw =>
          simp only [held] at returned
          cases decoded : decode raw with
          | error message =>
            simp only [decoded] at returned
            change executeReads store budget (.pure (.ok (.error (.decode message)) : Reply LookupResult)) = _ at returned
            simp at returned
          | ok node =>
            cases node with
            | leaf suffix value =>
              simp only [decoded] at returned
              split at returned
              next same =>
                have same : suffix.toList = key := by simpa using same
                rw [← same]
                exact .leaf _ _ _ _ _ held decoded
                  (resolve_semantic_sound store budget value bytes returned)
              next =>
                change executeReads store budget (.pure (.ok (.ok none) : Reply LookupResult)) = _ at returned
                simp at returned
            | extension segment child =>
              simp only [decoded] at returned
              split at returned
              next =>
                change executeReads store budget (.pure (.ok (.ok none) : Reply LookupResult)) = _ at returned
                simp at returned
              next admitted =>
                simp only [Bool.or_eq_true, Bool.not_eq_true, List.isEmpty_iff,
                  not_or] at admitted
                have nonempty : segment.toList ≠ [] := by
                  exact admitted.1
                have starts : segment.toList.isPrefixOf key = true := by
                  simpa using admitted.2
                have splitKey := List.prefix_iff_eq_append.mp
                  (List.isPrefixOf_iff_prefix.mp starts)
                have below := ih budget (some child) (key.drop segment.toList.length) returned
                obtain ⟨root, same, path⟩ := below
                cases same
                rw [← splitKey]
                exact .extension _ _ _ _ _ _ held decoded nonempty path
            | branch children value =>
              simp only [decoded] at returned
              cases key with
              | nil =>
                cases value with
                | none =>
                  change executeReads store budget (.pure (.ok (.ok none) : Reply LookupResult)) = _ at returned
                  simp at returned
                | some value =>
                  exact .branchValue _ _ _ _ _ held decoded
                    (resolve_semantic_sound store budget value bytes returned)
              | cons nibble rest =>
                obtain ⟨child, selected, below⟩ :=
                  ih budget ((children[nibble.toNat]?).getD none) rest returned
                have edge : children[nibble.toNat]? = some (some child) := by
                  cases h : children[nibble.toNat]? with
                  | none => simp [h] at selected
                  | some entry => simpa [h] using selected
                exact .branchChild _ _ _ _ _ _ _ _ held decoded edge below

/-- Successful execution of the exported domain operation witnesses an
actual root-to-key path and that path's own payload, not merely a successful
return tag. Arbitrary malformed nodes may fail but cannot invent membership.
-/
theorem get_semantic_sound (store : RawSnapshot) (budget : Nat)
    (root key bytes : ByteArray)
    (returned : executeReads store budget (Trie.get root key).run =
      some (.ok (.ok (some bytes)))) :
    key.size ≤ maxKeyBytes ∧ root.data.all (· == 0) = false ∧
      GraphValue store root (keyNibbles key) bytes := by
  unfold Trie.get at returned
  split at returned
  next oversized =>
    change executeReads store budget
      (.pure (.ok (.error (.keyTooLong key.size)) : Reply LookupResult)) = _ at returned
    simp at returned
  next bounded =>
    refine ⟨by omega, ?_⟩
    obtain ⟨address, selected, path⟩ :=
      lookup_semantic_sound store (maxKeyBytes * 2 + 1) budget _ _ bytes returned
    split at selected
    · contradiction
    · have nonzero : root.data.all (· == 0) = false := Bool.eq_false_iff.mpr ‹¬_›
      cases selected
      exact ⟨nonzero, path⟩

theorem resolve_semantic_complete (denotes : ValueDenotes store value bytes)
    (budget : Nat) (enough : 0 < budget) :
    executeReads store budget (resolveValue value).run = some (.ok (.ok (some bytes))) := by
  cases denotes with
  | inline bytes => exact execute_pure _ _ _
  | stored hash bytes held =>
    cases budget with
    | zero => contradiction
    | succ budget =>
      change executeReads store (budget + 1) (.request (.readBytes valueSpace hash) _) = _
      rw [executeReads]
      dsimp only [Program.bind, ExceptT.bindCont]
      rw [held]
      exact execute_pure _ _ _

/-- Every stored key path is found, with no false negative, when lookup has
one descent per key nibble plus its terminal node and one payload-read slot.
The proof follows graph witnesses, not a copy of the lookup algorithm. -/
theorem lookup_semantic_complete (path : GraphValue store root key bytes)
    (fuel budget : Nat) (enough : key.length < fuel) (reads : fuel < budget) :
    executeReads store budget (lookup fuel (some root) key).run =
      some (.ok (.ok (some bytes))) := by
  induction path generalizing fuel budget with
  | leaf address raw suffix value bytes held decoded denotes =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace address) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        simp only [held, decoded]
        simp only [BEq.rfl, ↓reduceIte]
        exact resolve_semantic_complete denotes budget (by omega)
  | branchValue address raw children value bytes held decoded denotes =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace address) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        simp only [held, decoded]
        exact resolve_semantic_complete denotes budget (by omega)
  | extension address raw segment child tail bytes held decoded nonempty below ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace address) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        simp only [held, decoded]
        have empty : segment.toList.isEmpty = false := by simpa using nonempty
        have starts : segment.toList.isPrefixOf (segment.toList ++ tail) = true := by simp
        simp only [empty, starts, Bool.not_true, Bool.or_false, Bool.false_eq_true, ↓reduceIte,
          List.drop_left]
        have positive : 0 < segment.toList.length := List.length_pos_iff.mpr nonempty
        exact ih fuel budget (by simp only [List.length_append] at enough; omega) (by omega)
  | branchChild address raw children value nibble child tail bytes held decoded edge below ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      cases budget with
      | zero => omega
      | succ budget =>
        change executeReads store (budget + 1) (.request (.readBytes nodeSpace address) _) = _
        rw [executeReads]
        dsimp only [Program.bind, ExceptT.bindCont]
        simp only [held, decoded]
        rw [edge]
        exact ih fuel budget (by simp only [List.length_cons] at enough; omega) (by omega)

theorem byte_array_loop_length (bytes : ByteArray) (i : Nat) (acc : List UInt8) :
    (ByteArray.toList.loop bytes i acc).length = bytes.size - i + acc.length := by
  rw [ByteArray.toList.loop]
  split
  · rw [byte_array_loop_length]
    simp only [List.length_cons]
    omega
  · simp only [List.length_reverse]
    omega
termination_by bytes.size - i

theorem byte_array_list_length (bytes : ByteArray) : bytes.toList.length = bytes.size := by
  simpa [ByteArray.toList] using byte_array_loop_length bytes 0 []

theorem key_nibbles_length (key : ByteArray) : (keyNibbles key).length = key.size * 2 := by
  have expand (bs : List UInt8) :
      (bs.flatMap (fun b => [b / 16, b % 16])).length = bs.length * 2 := by
    induction bs with
    | nil => rfl
    | cons b bs ih => simp [ih, Nat.add_mul, Nat.add_assoc]
  simpa only [keyNibbles, byte_array_list_length] using expand key.toList

theorem get_semantic_complete (path : GraphValue store root (keyNibbles key) bytes)
    (bounded : key.size ≤ maxKeyBytes) (nonzero : root.data.all (· == 0) = false) :
    executeReads store (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some bytes))) := by
  unfold Trie.get
  rw [if_neg (by omega), nonzero]
  simp only [Bool.false_eq_true, ↓reduceIte]
  have length := key_nibbles_length key
  exact lookup_semantic_complete path _ _ (by omega) (by omega)

/-- Exact lookup semantics over the stored decoded graph, at the concrete
production budget. Neither direction assumes the result of a Rust algorithm.
-/
@[rust_justifies "mpt-trie-get"]
theorem get_semantics_iff (store : RawSnapshot) (root key bytes : ByteArray)
    (bounded : key.size ≤ maxKeyBytes) (nonzero : root.data.all (· == 0) = false) :
    executeReads store (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some bytes))) ↔ GraphValue store root (keyNibbles key) bytes := by
  constructor
  · intro returned
    exact (get_semantic_sound store _ root key bytes returned).2.2
  · intro path
    exact get_semantic_complete path bounded nonzero

theorem graph_value_unique (first : GraphValue store root key left)
    (second : GraphValue store root key right) : left = right := by
  have a := lookup_semantic_complete first (key.length + 1) (key.length + 2)
    (by omega) (by omega)
  have b := lookup_semantic_complete second (key.length + 1) (key.length + 2)
    (by omega) (by omega)
  have same := a.symm.trans b
  simpa using same

/-- Oversized command keys are refused before even copying their raw bytes. -/
theorem getInput_oversized (root : ByteArray) (handle size : UInt64)
    (large : size.toNat > maxKeyBytes) :
    (getInput root handle size).run = .pure (.ok (.error (.keyTooLong size.toNat))) := by
  simp only [getInput, large, ↓reduceIte]
  rfl

/-- A bounded borrowed input is the sole preliminary request; host errors and
length mismatches cannot reach lookup. An exact reply runs the proved get. -/
@[rust_justifies "mpt-trie-get-input"]
theorem getInput_admitted (root : ByteArray) (handle size : UInt64)
    (bounded : size.toNat ≤ maxKeyBytes) :
    (getInput root handle size).run = .request (.readInput handle 0 size) (fun response =>
      match response with
      | .error failure => .pure (.error failure)
      | .ok key => if key.size != size.toNat then .pure (.error ⟨3, 0⟩)
          else (get root key).run) := by
  simp only [getInput, Nat.not_lt.mpr bounded, ↓reduceIte]
  change Program.request _ _ = Program.request _ _
  congr 1
  funext response
  cases response with
  | error failure => rfl
  | ok key =>
    dsimp only [Program.bind, ExceptT.bindCont]
    split <;> rfl

end Synchronicity.TrieProgramProofs
