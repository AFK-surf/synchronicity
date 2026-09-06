import Synchronicity.BaoProgramProofs

/-! Conditional correctness of the executable inner BLAKE3 tree. The raw
primitive contract is a hypothesis, not an axiom about a native library.
The interpreter follows the actual Program constructors, without a second
effectful hashing implementation or concrete large-buffer evaluation. -/
namespace Synchronicity.BaoHashProofs
open VerifiedCore.Host VerifiedCore.Cas.Bao
set_option Elab.async false

abbrev Responder := {A : Type} → Effects A → A

/-- One deterministic raw environment. It may return arbitrary failures or
malformed successful bytes; validation theorems do not assume honesty. -/
def interpret {A : Type} (respond : Responder) : Program Effects A → A
  | .pure value => value
  | .request effect resume => interpret respond (resume (respond effect))

theorem interpret_bind {A B : Type} (respond : Responder) (program : Program Effects A)
    (next : A → Program Effects B) :
    interpret respond (Program.bind program next) = interpret respond (next (interpret respond program)) := by
  induction program with
  | pure value => rfl
  | request effect resume ih => exact ih (respond effect)

theorem interpret_action_bind {A B : Type} (respond : Responder)
    (action : Action A) (next : A → Action B) :
    interpret respond (action >>= next).run =
      (interpret respond action.run).bind (fun value => interpret respond (next value).run) := by
  change interpret respond (Program.bind action.run _) = _
  rw [interpret_bind]
  cases interpret respond action.run <;> rfl

theorem bind_success_property {A B : Type} (respond : Responder)
    (action : Action A) (next : A → Action B) (property : B → Prop)
    (continuation : ∀ value result,
      interpret respond (next value).run = .ok result → property result)
    (result : B) (success : interpret respond (action >>= next).run = .ok result) :
    property result := by
  rw [interpret_action_bind] at success
  cases outcome : interpret respond action.run with
  | error error => simp [outcome, Except.bind] at success
  | ok value => exact continuation value result (by simpa [outcome, Except.bind] using success)

/-- Pure notation for the checked terminal reply of the actual hash action. -/
def checked : Reply ByteArray → Except Error ByteArray
  | .error failure => .error (.host failure)
  | .ok bytes => if bytes.size == 32 then .ok bytes else .error .protocol

theorem interpret_hash (respond : Responder) (effect : Blake3 (Reply ByteArray)) :
    interpret respond (VerifiedCore.Cas.Bao.hash effect).run =
      checked (respond (.right (.right effect))) := by
  change interpret respond (.request (.right (.right effect)) _) = _
  rw [interpret]
  generalize respond (.right (.right effect)) = reply
  cases reply with
  | error failure => rfl
  | ok bytes =>
    simp only [Program.bind, ExceptT.bindCont, Except.mapError]
    by_cases width : bytes.size = 32 <;> simp only [checked, width, beq_iff_eq,
      if_true, if_false, bne_iff_ne, ne_eq, not_true_eq_false, not_false_eq_true] <;> rfl

theorem checked_success_width (reply : Reply ByteArray) (digest : ByteArray)
    (accepted : checked reply = .ok digest) : digest.size = 32 := by
  cases reply with
  | error failure => cases accepted
  | ok bytes =>
    by_cases width : bytes.size = 32
    · have same : bytes = digest := by simpa [checked, width] using accepted
      exact same ▸ width
    · simp [checked, width] at accepted

/-- Every accepted primitive digest has the required width, for every raw
host reply, including environments that return malformed successful values. -/
theorem hash_success_width (respond : Responder) (effect : Blake3 (Reply ByteArray))
    (digest : ByteArray)
    (accepted : interpret respond (VerifiedCore.Cas.Bao.hash effect).run = .ok digest) :
    digest.size = 32 := by
  rw [interpret_hash] at accepted
  exact checked_success_width _ _ accepted

/-- Composing the actual inner tree cannot bypass the final width check.
This statement does not assume the primitive contract or fuel sufficiency. -/
theorem hashAux_success_width (respond : Responder) (fuel counter : Nat) (root : Bool)
    (bytes digest : ByteArray)
    (accepted : interpret respond (hashAux fuel counter root bytes).run = .ok digest) :
    digest.size = 32 := by
  cases fuel with
  | zero =>
    by_cases leaf : bytes.size ≤ 1024
    · rw [hashAux] at accepted
      simp only [if_pos leaf] at accepted
      exact hash_success_width respond _ _ accepted
    · rw [hashAux] at accepted
      simp [leaf, interpret] at accepted
  | succ fuel =>
    by_cases leaf : bytes.size ≤ 1024
    · rw [hashAux] at accepted
      simp only [if_pos leaf] at accepted
      exact hash_success_width respond _ _ accepted
    · rw [BaoProgramProofs.hash_branch_program fuel counter root bytes (by omega)] at accepted
      apply bind_success_property respond _ _ (fun digest => digest.size = 32) _ digest accepted
      intro left result success
      apply bind_success_property respond _ _ (fun digest => digest.size = 32) _ result success
      intro right result success
      exact hash_success_width respond _ _ success

/-- Abstract standard BLAKE3 chunk and parent primitives. Their meaning and
width are explicit premises; this structure does not assert native correctness. -/
structure PrimitiveModel where
  chunk : UInt64 → Bool → ByteArray → ByteArray
  parent : Bool → ByteArray → ByteArray → ByteArray
  chunkWidth : ∀ counter root bytes, (chunk counter root bytes).size = 32
  parentWidth : ∀ root left right, (parent root left right).size = 32

def PrimitiveContract (model : PrimitiveModel) (respond : Responder) : Prop :=
  (∀ (counter : UInt64) (root : Bool) (bytes : ByteArray),
    bytes.size ≤ 1024 → (root = true → counter = 0) →
    respond (.right (.right (.chunk counter root bytes))) =
    .ok (model.chunk counter root bytes)) ∧
  (∀ (root : Bool) (left right : ByteArray), left.size = 32 → right.size = 32 →
    respond (.right (.right (.parent root left right))) =
    .ok (model.parent root left right))

/-- Pure reference recurrence: chunk leaves, largest-power-of-two split,
original chunk counters, non-root child chaining values, and a flagged parent.
Fuel exhaustion stays explicit; adequate fuel is proved separately by geometry. -/
def reference (model : PrimitiveModel) : Nat → Nat → Bool → ByteArray → Except Error ByteArray
  | fuel, counter, root, bytes =>
    if bytes.size ≤ 1024 then .ok (model.chunk counter.toUInt64 root bytes)
    else match fuel with
      | 0 => .error .protocol
      | fuel + 1 => do
        let split := splitBytes 1024 bytes.size
        let left ← reference model fuel counter false (bytes.extract 0 split)
        let right ← reference model fuel (counter + split / 1024) false
          (bytes.extract split bytes.size)
        return model.parent root left right

theorem chunk_under_contract (model : PrimitiveModel) (respond : Responder)
    (contract : PrimitiveContract model respond) (counter : UInt64) (root : Bool) (bytes : ByteArray)
    (bounded : bytes.size ≤ 1024) (rootCounter : root = true → counter = 0) :
    interpret respond (VerifiedCore.Cas.Bao.hash (.chunk counter root bytes)).run =
      .ok (model.chunk counter root bytes) := by
  calc
    _ = checked (respond (.right (.right (.chunk counter root bytes)))) :=
      interpret_hash respond (.chunk counter root bytes)
    _ = checked (.ok (model.chunk counter root bytes)) :=
      congrArg checked (contract.1 counter root bytes bounded rootCounter)
    _ = _ := by simp [checked, model.chunkWidth]

theorem parent_under_contract (model : PrimitiveModel) (respond : Responder)
    (contract : PrimitiveContract model respond) (root : Bool) (left right : ByteArray)
    (leftWidth : left.size = 32) (rightWidth : right.size = 32) :
    interpret respond (VerifiedCore.Cas.Bao.hash (.parent root left right)).run =
      .ok (model.parent root left right) := by
  calc
    _ = checked (respond (.right (.right (.parent root left right)))) :=
      interpret_hash respond (.parent root left right)
    _ = checked (.ok (model.parent root left right)) :=
      congrArg checked (contract.2 root left right leftWidth rightWidth)
    _ = _ := by simp [checked, model.parentWidth]

/-- Under the raw primitive contract, the executable inner tree evaluates to
the reference recurrence. No Rust tree construction is assumed or compared. -/
theorem hashAux_matches_reference (model : PrimitiveModel) (respond : Responder)
    (contract : PrimitiveContract model respond) (fuel counter : Nat) (root : Bool)
    (bytes : ByteArray) (rootCounter : root = true → counter.toUInt64 = 0) :
    interpret respond (hashAux fuel counter root bytes).run = reference model fuel counter root bytes := by
  induction fuel generalizing counter root bytes with
  | zero =>
    by_cases leaf : bytes.size ≤ 1024
    · rw [hashAux, reference]
      simp only [if_pos leaf]
      exact chunk_under_contract model respond contract _ _ _ leaf rootCounter
    · rw [hashAux, reference]
      simp [leaf, interpret]
  | succ fuel ih =>
    by_cases leaf : bytes.size ≤ 1024
    · rw [hashAux, reference]
      simp only [if_pos leaf]
      exact chunk_under_contract model respond contract _ _ _ leaf rootCounter
    · rw [BaoProgramProofs.hash_branch_program fuel counter root bytes (by omega), reference]
      simp only [if_neg leaf]
      let split := splitBytes 1024 bytes.size
      have leftCorrect := ih counter false (bytes.extract 0 split) (by simp)
      have rightCorrect := ih (counter + split / 1024) false (bytes.extract split bytes.size) (by simp)
      simp only [interpret_action_bind]
      rw [← leftCorrect, ← rightCorrect]
      cases leftResult : interpret respond (hashAux fuel counter false (bytes.extract 0 split)).run with
      | error error => simp [bind, Except.bind]
      | ok left =>
        have leftWidth := hashAux_success_width respond fuel counter false _ left leftResult
        cases rightResult : interpret respond
            (hashAux fuel (counter + split / 1024) false (bytes.extract split bytes.size)).run with
        | error error => simp [bind, Except.bind]
        | ok right =>
          have rightWidth := hashAux_success_width respond fuel (counter + split / 1024) false _ right rightResult
          simpa [leftResult, rightResult, bind, Except.bind, pure, Except.pure] using
            parent_under_contract model respond contract root left right leftWidth rightWidth

end Synchronicity.BaoHashProofs
