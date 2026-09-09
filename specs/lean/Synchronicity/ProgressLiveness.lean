/-! Well-founded liveness for persistent finite work.

This module is deliberately independent of mptsync operations.  Concrete
execution proofs supply a natural-valued measure, prove that committed steps
do not increase it, and derive a later strict decrease from an actual usable
service opportunity.  The theorem below then rules out an infinite execution
which keeps doing safe but unproductive work.
-/
namespace Synchronicity.ProgressLiveness

variable {measure : Nat → Nat}

/-- Committed observations never recreate already discharged work. -/
def Nonincreasing (measure : Nat → Nat) : Prop :=
  ∀ now, measure (now + 1) ≤ measure now

/-- Whenever work remains, some later committed observation has discharged
at least one unit.  Callers must derive this from scheduler and operation
refinement; it is intentionally not named merely `Fair`. -/
def EffectiveOpportunities (measure : Nat → Nat) : Prop :=
  ∀ now, 0 < measure now → ∃ later, now < later ∧ measure later < measure now

theorem nonincreasing_later (monotone : Nonincreasing measure)
    (before : start ≤ finish) : measure finish ≤ measure start := by
  obtain ⟨distance, rfl⟩ := Nat.exists_eq_add_of_le before
  clear before
  induction distance with
  | zero => exact Nat.le_refl _
  | succ distance ih =>
    rw [Nat.add_succ]
    exact Nat.le_trans (monotone (start + distance)) ih

/-- A persistent finite measure and recurring effective opportunities reach
zero after finitely many observations. -/
theorem eventually_zero (effective : EffectiveOpportunities measure) (start : Nat) :
    ∃ finish, start ≤ finish ∧ measure finish = 0 := by
  have descend : ∀ bound now, measure now ≤ bound →
      ∃ finish, now ≤ finish ∧ measure finish = 0 := by
    intro bound
    induction bound with
    | zero =>
      intro now bounded
      exact ⟨now, Nat.le_refl _, Nat.eq_zero_of_le_zero bounded⟩
    | succ bound ih =>
      intro now bounded
      by_cases done : measure now = 0
      · exact ⟨now, Nat.le_refl _, done⟩
      · have positive : 0 < measure now := Nat.zero_lt_of_ne_zero done
        obtain ⟨later, after, smaller⟩ := effective now positive
        have within : measure later ≤ bound :=
          Nat.le_of_lt_succ (Nat.lt_of_lt_of_le smaller bounded)
        obtain ⟨finish, reached, empty⟩ := ih later within
        exact ⟨finish, Nat.le_trans (Nat.le_of_lt after) reached, empty⟩
  exact descend (measure start) start (Nat.le_refl _)

/-- Once the persistent measure reaches zero it stays zero. -/
theorem eventually_always_zero (monotone : Nonincreasing measure)
    (effective : EffectiveOpportunities measure) (start : Nat) :
    ∃ finish, start ≤ finish ∧ ∀ now, finish ≤ now → measure now = 0 := by
  obtain ⟨finish, after, empty⟩ := eventually_zero effective start
  refine ⟨finish, after, fun now later => ?_⟩
  have bounded := nonincreasing_later monotone later
  rw [empty] at bounded
  exact Nat.eq_zero_of_le_zero bounded

end Synchronicity.ProgressLiveness
