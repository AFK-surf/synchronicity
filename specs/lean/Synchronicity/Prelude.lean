import Mathlib.Logic.Function.Basic
import Mathlib.Data.Set.Insert
import Synchronicity.Anchors

/-!
What every model in this package shares.

- `System` is a transition system: an initial state and a step relation.
  `System.Reachable` is its reachable set, `System.Invariant` packages the one
  induction every safety theorem performs, and `Reachable.simulate` is the
  simulation argument: a system whose steps project to steps of another
  reaches only what that one reaches, under the projection.
- `Transition` is one guarded deterministic step, `guard` and `post`, and
  `Transition.rel` the relation it induces.  Every transition in the package
  has this shape; where the code has more than one outcome, the outcome is a
  parameter of the transition and a case of its `Kind`.
- `Lift` and `Across` are stores of cells indexed by some `ι`: under `Lift`
  one cell steps and every other is left as it was, under `Across` every cell
  either steps or stays.  `Lift.forall` and `Across.forall` lift a per-cell
  invariant through them.
- The `transition` simp set collects the transition definitions so that a
  preservation proof opens them all with `simp only [transition]`.
-/

namespace Synchronicity

/-- A transition system. -/
structure System (σ : Type) where
  /-- The initial state. -/
  init : σ
  /-- The step relation. -/
  step : σ → σ → Prop

namespace System

variable {σ τ : Type} (S : System σ)

/-- The states reachable from `S.init` by `S.step`. -/
inductive Reachable : σ → Prop where
  | initial : Reachable S.init
  | next {s s' : σ} : Reachable s → S.step s s' → Reachable s'

/-- An inductive invariant: true initially and preserved by every step. -/
structure Invariant (I : σ → Prop) : Prop where
  /-- The initial state satisfies it. -/
  init : I S.init
  /-- Every step preserves it. -/
  step : ∀ {s s'}, I s → S.step s s' → I s'

variable {S}

/-- An inductive invariant holds of every reachable state. -/
theorem Invariant.reachable {I : σ → Prop} (hI : S.Invariant I) {s : σ} (h : S.Reachable s) :
    I s := by
  induction h with
  | initial => exact hI.init
  | next _ step ih => exact hI.step ih step

/-- Simulation: if `S`'s initial state projects to `T`'s and every step of `S`
projects to a step of `T`, every state `S` reaches projects to one `T`
reaches. -/
theorem Reachable.simulate {T : System τ} (f : σ → τ) (hinit : f S.init = T.init)
    (hstep : ∀ {s s'}, S.step s s' → T.step (f s) (f s')) {s : σ} (h : S.Reachable s) :
    T.Reachable (f s) := by
  induction h with
  | initial => exact hinit ▸ Reachable.initial (S := T)
  | next _ step ih => exact .next ih (hstep step)

/-- Simulation on the same state space: every step of `S` is a step of `T`. -/
theorem Reachable.mono {T : System σ} (hinit : S.init = T.init)
    (hstep : ∀ {s s'}, S.step s s' → T.step s s') {s : σ} (h : S.Reachable s) : T.Reachable s :=
  h.simulate id hinit hstep

end System

/-! ## Guarded deterministic transitions -/

/-- One transition: a guard on the state it may fire in, and the state it
leaves. -/
structure Transition (σ : Type) where
  /-- When the transition may fire. -/
  guard : σ → Prop
  /-- The successor state. -/
  post : σ → σ

/-- The relation a transition induces. -/
def Transition.rel {σ : Type} (t : Transition σ) (s s' : σ) : Prop :=
  t.guard s ∧ s' = t.post s

attribute [transition] Transition.rel

/-! ## Stores of cells -/

section Store

variable {ι α : Type} {R T : α → α → Prop} {s s' : ι → α}

/-- Every cell either takes the transition `R` or stays: one transaction over
several cells. -/
def Across (R : α → α → Prop) (s s' : ι → α) : Prop :=
  ∀ i, R (s i) (s' i) ∨ s' i = s i

/-- A property of every cell survives a step across the store that preserves
it. -/
theorem Across.forall {P : α → Prop} (hP : ∀ {a a'}, P a → R a a' → P a')
    (h : ∀ i, P (s i)) (hl : Across R s s') : ∀ i, P (s' i) := fun i =>
  (hl i).elim (hP (h i)) (fun e => e ▸ h i)

/-- The cell a step across the store changed took the transition. -/
theorem Across.changed (hl : Across R s s') {i : ι} (h : s' i ≠ s i) : R (s i) (s' i) :=
  (hl i).resolve_right h

variable [DecidableEq ι]

-- Pointwise update of a store is `Function.update`.
export Function (update)

/-- One cell takes the transition `R`; every other cell stays. -/
def Lift (R : α → α → Prop) (s s' : ι → α) : Prop :=
  ∃ i a', R (s i) a' ∧ s' = update s i a'

theorem Lift.intro {i : ι} {a' : α} (h : R (s i) a') : Lift R s (update s i a') :=
  ⟨i, a', h, rfl⟩

/-- A lifted step is a step across the store. -/
theorem Lift.across (hl : Lift R s s') : Across R s s' := by
  obtain ⟨i, a', step, rfl⟩ := hl
  intro j
  by_cases hj : j = i
  · subst hj; exact Or.inl (by simpa using step)
  · exact Or.inr (Function.update_of_ne hj _ _)

/-- A property of every cell survives a lifted step that preserves it. -/
theorem Lift.forall {P : α → Prop} (hP : ∀ {a a'}, P a → R a a' → P a')
    (h : ∀ i, P (s i)) (hl : Lift R s s') : ∀ i, P (s' i) :=
  Across.forall hP h hl.across

theorem Lift.mono (hRT : ∀ {a a'}, R a a' → T a a') (hl : Lift R s s') : Lift T s s' := by
  obtain ⟨i, a', step, rfl⟩ := hl
  exact ⟨i, a', hRT step, rfl⟩

/-- The cell a lifted step changed took the transition. -/
theorem Lift.changed (hl : Lift R s s') {i : ι} (h : s' i ≠ s i) : R (s i) (s' i) :=
  hl.across.changed h

end Store

end Synchronicity

#lint
