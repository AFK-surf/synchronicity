import Synchronicity.TrieWalkProofs
import Synchronicity.TrieSnapshotClosure
import Synchronicity.TrieServePrivacyProofs

/-! Semantic obligations for the production structural diff. Equality is of
snapshot payloads, not reference representations or successful walk results.
These lemmas support exact view replacement; they are not an M4 entry point. -/
namespace Synchronicity.TrieDiffSemantics
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open TrieProgramProofs TrieSnapshotClosure SimulatedHost

deriving instance ReflBEq, LawfulBEq for Value
deriving instance ReflBEq, LawfulBEq for Node

/-- An optional value denotes absence or its actual payload in the snapshot. -/
inductive OptionalValue (store : RawSnapshot) : Option Value → Option ByteArray → Prop where
  | absent : OptionalValue store none none
  | present (denotes : ValueDenotes store value bytes) :
      OptionalValue store (some value) (some bytes)

/-- Addressed payloads have their actual content address. This is the raw
ingress/digest contract, not a claim that comparison or diff is correct. -/
def Addressed (store : RawSnapshot) (hash : ByteArray → ByteArray) : Prop :=
  ∀ address bytes, store valueSpace address = some bytes → hash bytes = address

/-- Collision freedom is needed only for the two payloads being compared,
not global injectivity of a finite digest. Absence needs no digest premise. -/
def Distinguishes (hash : ByteArray → ByteArray)
    (left right : Option ByteArray) : Prop :=
  ∀ a b, left = some a → right = some b → hash a = hash b → a = b

private theorem mixed_result (bytes address : ByteArray) (state : State) (answer : Bool)
    (ran : (execute (Diff.sameValue (E := Diff.Effects)
      (some (.inline bytes)) (some (.hash address))) state).1 = .ok answer) :
    answer = (state.hash bytes == address) := by
  unfold Diff.sameValue at ran
  obtain ⟨digest, middle, hashed, compared⟩ := TrieServePrivacyProofs.bind_ok _ _ state answer ran
  have returned : digest = state.hash bytes := by
    simp only [Diff.digest, raise, performOver, Inject.inject, ExceptT.mk, execute,
      Interpreter.handle, SimulatedHost.digest, reply, fault] at hashed
    split at hashed
    · simp_all [record, Except.mapError]
    · simp_all [record, Except.mapError]
  simpa [returned, pure, ExceptT.pure, ExceptT.mk, execute] using compared.symm

/-- Every successful production comparison answers exactly byte equality,
including mixed inline/addressed representations and arbitrary host faults.
Payload presence and the encountered-image hash contract supply the meaning;
neither the comparison's desired answer nor a healthy execution is assumed. -/
theorem same_value_exact (left right : Option Value) (a b : Option ByteArray)
    (store : RawSnapshot) (state : State) (answer : Bool)
    (leftValue : OptionalValue store left a) (rightValue : OptionalValue store right b)
    (addressed : Addressed store state.hash) (distinct : Distinguishes state.hash a b)
    (ran : (execute (Diff.sameValue (E := Diff.Effects) left right) state).1 = .ok answer) :
    answer = true ↔ a = b := by
  cases leftValue with
  | absent =>
    cases rightValue with
    | absent => simpa [Diff.sameValue, pure, ExceptT.pure, ExceptT.mk, execute] using ran
    | present denotes =>
      cases denotes <;>
        simp_all [Diff.sameValue, pure, ExceptT.pure, ExceptT.mk, execute]
  | @present leftBytes leftRef leftDenotes =>
    cases rightValue with
    | absent =>
      cases leftDenotes <;>
        simp_all [Diff.sameValue, pure, ExceptT.pure, ExceptT.mk, execute]
    | @present rightBytes rightRef rightDenotes =>
      cases leftDenotes with
      | inline x =>
        cases rightDenotes with
        | inline y =>
          simp only [Diff.sameValue, pure, ExceptT.pure, ExceptT.mk, execute,
            Except.ok.injEq] at ran
          rw [← ran]
          simp
        | stored address y held =>
          rw [mixed_result leftRef address state answer ran, ← addressed address rightRef held]
          simp only [beq_iff_eq, Option.some.injEq]
          exact ⟨distinct leftRef rightRef rfl rfl, congrArg state.hash⟩
      | stored address x held =>
        cases rightDenotes with
        | inline y =>
          have compared := mixed_result rightRef address state answer ran
          rw [compared, ← addressed address leftRef held]
          simp only [beq_iff_eq, Option.some.injEq]
          exact ⟨fun same => distinct leftRef rightRef rfl rfl same.symm,
            fun same => congrArg state.hash same.symm⟩
        | stored other y otherHeld =>
          have compared : answer = (address == other) := by
            simpa [Diff.sameValue, pure, ExceptT.pure, ExceptT.mk, execute] using ran.symm
          rw [compared, ← addressed address leftRef held, ← addressed other rightRef otherHeld]
          simp only [beq_iff_eq, Option.some.injEq]
          exact ⟨distinct leftRef rightRef rfl rfl, congrArg state.hash⟩

theorem optional_value_unique (left : OptionalValue store value a)
    (right : OptionalValue store value b) : a = b := by
  cases left with
  | absent => cases right; rfl
  | present denotes =>
    cases right with
    | present other =>
      cases denotes with
      | inline bytes => cases other; rfl
      | stored hash bytes held =>
        cases other with
        | stored _ other now => exact congrArg some (Option.some.inj (held.symm.trans now))

/-- The real position inspector emits exactly a payload change at this
position. Equal decoded nodes can be pruned without losing a change here;
the general subtree/whole-walk coverage obligation is separate. -/
theorem enter_exact (old new : Walk.Cursor) (path : Walk.Path)
    (store : RawSnapshot) (state : State) (a b : Option ByteArray)
    (leftValue : OptionalValue store old.value a) (rightValue : OptionalValue store new.value b)
    (addressed : Addressed store state.hash) (distinct : Distinguishes state.hash a b)
    (change : Option Diff.Change) (worth : Bool)
    (ran : (execute (Diff.enter (E := Diff.Effects) old new path) state).1 = .ok (change, worth)) :
    (change.isSome = true ↔ a ≠ b) ∧
      (∀ emitted, change = some emitted →
        Walk.bytesOfNibbles path = some emitted.key ∧
        emitted.old = old.value ∧ emitted.new = new.value) := by
  have notWorth : (match old.node, new.node with
      | none, none => false | some x, some y => x != y | _, _ => true) = false → a = b := by
    intro pruned
    have same : old = new := by
      cases old <;> cases new <;> simp_all [Walk.Cursor.node]
    subst new
    exact optional_value_unique leftValue rightValue
  have active (ran : (execute (do
      let answer ← Diff.sameValue (E := Diff.Effects) old.value new.value
      if answer then pure (none, true) else
        match Walk.bytesOfNibbles path with
        | none => throw Walk.Error.oddDepthValue
        | some key => pure (some (Diff.Change.mk key old.value new.value), true)
      : OperationOver Diff.Effects Walk.Error (Option Diff.Change × Bool)) state).1 =
        .ok (change, worth)) :
      (change.isSome = true ↔ a ≠ b) ∧
      (∀ emitted, change = some emitted → Walk.bytesOfNibbles path = some emitted.key ∧
        emitted.old = old.value ∧ emitted.new = new.value) := by
    obtain ⟨answer, middle, compared, continued⟩ := TrieServePrivacyProofs.bind_ok _ _ state _ ran
    have exactAnswer := same_value_exact old.value new.value a b store state answer
      leftValue rightValue addressed distinct (congrArg Prod.fst compared)
    split at continued
    · cases continued
      simp [exactAnswer.mp ‹_›]
    · rename_i unequal
      have different : a ≠ b := fun equal => unequal (exactAnswer.mpr equal)
      split at continued
      · cases continued
      · rename_i key packed
        cases continued
        exact ⟨by simp [different], fun emitted same => by
          cases same
          exact ⟨packed, rfl, rfl⟩⟩
  unfold Diff.enter at ran
  split at ran
  · have equal := notWorth (by simp_all)
    simp only [Bool.not_false, ↓reduceIte] at ran
    cases ran
    simp [equal]
  · rename_i x y oldAt newAt
    by_cases same : x = y
    · have equal := notWorth (by simp [oldAt, newAt, same])
      simp only [same, bne_self_eq_false, Bool.not_false, ↓reduceIte] at ran
      cases ran
      simp [equal]
    · have unequal : (x != y) = true := by simp [same]
      simp only [unequal, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at ran
      exact active ran
  · exact active ran

end Synchronicity.TrieDiffSemantics
