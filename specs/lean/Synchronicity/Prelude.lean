import Lean

/-!
What every model in this package shares.

- `System` is a transition system: an initial state and a step relation.
  `System.Reachable` is its reachable set, `Reachable.invariant` is the one
  induction every safety theorem in the package performs, and
  `Reachable.mono` is the simulation argument: a system whose steps are steps
  of another reaches only what that one reaches.
- `update` and `Lift` are a store of cells indexed by some `ι`: one cell takes
  a transition, every other cell is left as it was.  `Lift.forall` lifts a
  per-cell invariant through it.
- `add` and `drop` are sets as predicates.
-/

namespace Synchronicity

/-- A transition system. -/
structure System (σ : Type) where
  init : σ
  step : σ → σ → Prop

namespace System

variable {σ : Type} (S : System σ)

inductive Reachable : σ → Prop where
  | initial : Reachable S.init
  | next {s s' : σ} : Reachable s → S.step s s' → Reachable s'

variable {S}

/-- An inductive invariant holds of every reachable state. -/
theorem Reachable.invariant {I : σ → Prop} (hinit : I S.init)
    (hstep : ∀ {s s'}, I s → S.step s s' → I s') {s : σ} (h : S.Reachable s) : I s := by
  induction h with
  | initial => exact hinit
  | next _ step ih => exact hstep ih step

/-- Simulation: if every step of `S` is a step of `T` from the same initial
state, every state `S` reaches `T` reaches. -/
theorem Reachable.mono {T : System σ} (hinit : S.init = T.init)
    (hstep : ∀ {s s'}, S.step s s' → T.step s s') {s : σ} (h : S.Reachable s) : T.Reachable s := by
  induction h with
  | initial => exact hinit ▸ Reachable.initial (S := T)
  | next _ step ih => exact .next ih (hstep step)

end System

/-! ## Stores of cells -/

section Store

variable {ι α : Type} [DecidableEq ι]

/-- Pointwise update of a store. -/
def update (s : ι → α) (i : ι) (a : α) : ι → α :=
  fun j => if j = i then a else s j

@[simp] theorem update_self (s : ι → α) (i : ι) (a : α) : update s i a i = a := by
  simp [update]

@[simp] theorem update_of_ne (s : ι → α) {i j : ι} (a : α) (h : j ≠ i) : update s i a j = s j := by
  simp [update, h]

/-- One cell takes the transition `R`; every other cell stays. -/
def Lift (R : α → α → Prop) (s s' : ι → α) : Prop :=
  ∃ i a', R (s i) a' ∧ s' = update s i a'

variable {R T : α → α → Prop} {s s' : ι → α}

theorem Lift.intro {i : ι} {a' : α} (h : R (s i) a') : Lift R s (update s i a') :=
  ⟨i, a', h, rfl⟩

/-- A property of every cell survives a lifted step that preserves it. -/
theorem Lift.forall {P : α → Prop} (hP : ∀ {a a'}, P a → R a a' → P a')
    (h : ∀ i, P (s i)) (hl : Lift R s s') : ∀ i, P (s' i) := by
  obtain ⟨i, a', step, rfl⟩ := hl
  intro j
  by_cases hj : j = i
  · subst hj; simpa using hP (h j) step
  · simpa [hj] using h j

theorem Lift.mono (hRT : ∀ {a a'}, R a a' → T a a') (hl : Lift R s s') : Lift T s s' := by
  obtain ⟨i, a', step, rfl⟩ := hl
  exact ⟨i, a', hRT step, rfl⟩

/-- The cell a lifted step changed took the transition. -/
theorem Lift.changed (hl : Lift R s s') {i : ι} (h : s' i ≠ s i) : R (s i) (s' i) := by
  obtain ⟨j, a', step, rfl⟩ := hl
  by_cases hij : i = j
  · subst hij; simpa using step
  · exact absurd (by simp [hij]) h

end Store

/-! ## Stepping through a transition hypothesis -/

/-- `subst_step h` takes a transition hypothesis `h : guard ∧ (s' = a ∨ s' = b)`
apart — every conjunct kept, every disjunct its own goal — and substitutes the
`s' = …` equations, so that what follows sees the successor state's fields
directly.  The shape it handles is the one every transition in this package
has: conjunctions of guards around equations for the successor state, with
disjunctions for transitions that have more than one outcome. -/
syntax "subst_step " ident : tactic

open Lean Meta Elab Tactic in
/-- Split conjunctions, case on disjunctions, substitute equations, recursively. -/
partial def substStepCore (g : MVarId) (h : FVarId) : MetaM (List MVarId) := g.withContext do
  let ty ← instantiateMVars (← h.getType)
  if ty.isAppOfArity ``And 2 || ty.isAppOfArity ``Or 2 then
    let subgoals ← g.cases h
    subgoals.toList.flatMapM fun sg => do
      let mut goals := [sg.mvarId]
      for f in sg.fields do
        if f.isFVar then
          goals ← goals.flatMapM fun g' => do
            if (← g'.getDecl).lctx.contains f.fvarId! then substStepCore g' f.fvarId!
            else return [g']
      return goals
  else if ty.isAppOfArity ``Eq 3 then
    return [← trySubst g h]
  else
    return [g]

open Lean Elab Tactic in
elab_rules : tactic
  | `(tactic| subst_step $h:ident) => withMainContext do
    let fvar ← getFVarId h
    let g ← getMainGoal
    let goals ← substStepCore g fvar
    replaceMainGoal goals

/-! ## Sets as predicates -/

section Sets

variable {α : Type}

def add (p : α → Prop) (x : α) : α → Prop :=
  fun y => y = x ∨ p y

def drop (p : α → Prop) (x : α) : α → Prop :=
  fun y => p y ∧ y ≠ x

@[simp] theorem add_apply (p : α → Prop) (x y : α) : add p x y ↔ (y = x ∨ p y) := Iff.rfl
@[simp] theorem drop_apply (p : α → Prop) (x y : α) : drop p x y ↔ (p y ∧ y ≠ x) := Iff.rfl

end Sets

end Synchronicity
