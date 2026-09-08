import Synchronicity.ReconciliationExecution

/-! # M3 — delayed replies and obsolete work cannot damage newer versions

This entry point mirrors M3 in docs/LEAN.md. The specification is the uniform
keep/advance/exact-pending-consumption relation in HeadTransition. Command cases
belong to ReconciliationExecution.Step.refines, not to the goal's property.

Represents describes typed, consistent raw slot pointers at the observed
boundaries; Backed supplies their initial history rows. Neither assumes a
transition outcome. Corrupt/orphan-pointer recovery, the native scheduler,
eventual convergence and M4's exact-view/atomic-publication result are outside
this contract. Failures, obsolete/new inputs and arbitrary requesting replies
are not filtered out of Execution.
-/
namespace Synchronicity.Goals.Mptsync.M3
open ReconciliationExecution

/-- At every observed boundary, every origin and both slots keep their version
or strictly advance; only the exact captured pending version may disappear.
The concrete execution, not an assumed safety policy, supplies capture evidence.
Typed/raw backing contracts make the observation meaningful; timestamps are not
part of a version. Quantification over all observations covers every trace prefix. -/
def Safety (trace : List Observation) : Prop :=
  ∀ observation ∈ trace, ∀ before after,
    HeadView.Represents observation.before.db before →
    HeadView.Backed observation.before.db before →
    HeadView.Represents observation.after.db after →
    HeadTransition (captures observation.event observation.before) before after

/-- **M3.** Every finite production-command/resumption execution refines the
same head transition rule, under the explicit raw-host/slot contracts. -/
theorem safety (execution : Execution initial trace final) : Safety trace := by
  induction execution with
  | nil _ => intro observation member; cases member
  | cons step rest ih =>
    intro observation member
    rcases List.mem_cons.mp member with same | member
    · subst observation
      intro before after
      exact step.refines
    · exact ih observation member

end Synchronicity.Goals.Mptsync.M3
