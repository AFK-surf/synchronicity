import Synchronicity.ScopeChangeRefinement

/-! # M8 — changed permissions invalidate old conclusions and can rebuild

`PermissionLifecycle` is the common transition model used for enlargement,
narrowing, expiry and revocation.  A real change advances its logical
credential, clears conclusions made under the old permission, and requeues the
best signed target using the production reconciliation order.  Captured work
can settle only when its credential and exact pending target are still current.

This theorem does not assume that a cached completion already describes the
new view.  After permissions stop changing it derives the fresh completion
transition from pending signed work.  The outer convergence theorem still has
to supply the fair usable synchronization opportunity and M4's exact-view
materialization assumptions.  SQLite transaction isolation and the Rust
scheduler remain host/runtime contracts. -/
namespace Synchronicity.Goals.Mptsync.M8
open Synchronicity.PermissionLifecycle

/-- The production whole-domain command has the same atomic failure boundary:
even malformed stored heads or arbitrary host/commit failures expose none of a
new scope beside old derived state. -/
theorem production_change_failure_is_atomic (next : Option (List String)) (now : Int64)
    (state : SimulatedHost.State) (failure : VerifiedCore.Replication.History.Error)
    (failed : (SimulatedHost.execute
      (VerifiedCore.Replication.ScopeChange.change next now) state).1 = .error failure) :
    (SimulatedHost.execute
      (VerifiedCore.Replication.ScopeChange.change next now) state).2.db = state.db :=
  ScopeChangeAtomicity.failure_preserves_committed_database next now state failure failed

/-- The actual raw scope-change execution and its subsequent lifecycle form one
property. The raw command has removed the old derived authority and retained
the greatest signed target; the logical trace then permits only current
credentials. A stable pending target can recover the credential/readiness
premise required by the fixed-scope proofs; this is not an eventual Fetch or
promotion claim. -/
def ApplicableChangedPermissions (spaces : Option (List String)) (now : Int64)
    (rawAfter : SimulatedHost.State)
    (decision : VerifiedCore.Replication.ScopeChange.Demotion) : Prop :=
  ∃ source : ScopeChangeRefinement.DecisionSource spaces decision,
    ScopeChangeRefinement.RawInvalidated decision now rawAfter.db ∧
    ∀ generation refusals trace final,
      let oldScope := ScopeChangeRefinement.effectiveScope source.current
      let before := ofDemotion oldScope generation refusals decision
      let after := PermissionLifecycle.change before
        (ScopeChangeRefinement.effectiveScope spaces)
      Fresh before → Execution after trace final →
      (ScopeChangeRefinement.effectiveScope spaces ≠ oldScope →
        InvalidatesOld before after (ScopeChangeRefinement.effectiveScope spaces) ∧
        after.pending = some (ofPointer decision.selected)) ∧
      Safety (⟨.permission (ScopeChangeRefinement.effectiveScope spaces), before, after⟩ :: trace) ∧
      Fresh final ∧
      ∀ target, StableOpportunity final target →
        ∃ work recovered,
          work = begin final target ∧
          Step (.completed work) final recovered ∧ Ready recovered target

/-- **M8.** Enlargement, narrowing, expiry and revocation are all permission
events in the same execution relation.  Old completion/refusal credentials and
suspended work cannot authorize the changed scope; the best known signed target
is retained/requeued, and a stable usable opportunity rebuilds under the now
current permission. -/
theorem applicable_changed_permissions
    (production : ScopeChangeRefinement.Successful spaces now rawBefore rawAfter report)
    (quiet : rawBefore.faults = [])
    (reported : decision ∈ report.demotions) :
    ApplicableChangedPermissions spaces now rawAfter decision := by
  obtain ⟨source, rawInvalidated⟩ :=
    ScopeChangeRefinement.successful_change_raw production quiet reported
  refine ⟨source, rawInvalidated, ?_⟩
  intro generation refusals trace final
  dsimp only
  intro initiallyFresh execution
  let oldScope := ScopeChangeRefinement.effectiveScope source.current
  let before := ofDemotion oldScope generation refusals decision
  let after := PermissionLifecycle.change before (ScopeChangeRefinement.effectiveScope spaces)
  let full : Execution before
      (⟨.permission (ScopeChangeRefinement.effectiveScope spaces), before, after⟩ :: trace) final :=
    .cons (.permission before _) execution
  refine ⟨?_, execution_safe full, full.preserves_fresh initiallyFresh, ?_⟩
  · intro changed
    exact ⟨change_invalidates _ _, production_demotion_retains_max
      decision oldScope (ScopeChangeRefinement.effectiveScope spaces)
        generation refusals changed⟩
  intro target opportunity
  let work := begin final target
  let recovered := finish final work
  obtain ⟨step, ready⟩ := stable_rebuild opportunity
  exact ⟨work, recovered, rfl, step, ready⟩

end Synchronicity.Goals.Mptsync.M8
