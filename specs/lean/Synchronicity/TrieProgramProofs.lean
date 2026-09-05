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

end Synchronicity.TrieProgramProofs
