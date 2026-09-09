import Synchronicity.MptsyncProductionConvergence

/-! # M1 — eventual convergence of the production reconciliation trace

After the latest valid versions and permissions stabilize, bounded production
scheduling delivers each covered origin, actual authorized admissions exhaust
its finite permitted metadata deficit across cancellation/retry, and a later
healthy primitive promotion opportunity atomically installs the exact allowed
view.  Actual stable-tail steps then preserve it.

The explicit environmental contracts are retained authorized sources,
finite/supported metadata, sufficiently many valid network/deadline/storage
opportunities, and the documented host/crypto/SQLite/materializer contracts.
Permanent partition, infinite cancellation, source loss, and continuing local
publication or external recovery are outside this stable suffix; those paths
must first establish the stable latest/source inputs consumed here. -/
namespace Synchronicity.Goals.Mptsync.M1
open VerifiedCore VerifiedCore.Replication
open MptsyncConvergence

/-- User-facing M1 property: from one finite observation onward every covered
participant exposes its exact permitted directory for the common latest valid
sequence/root and retains the corresponding acquisition duties. -/
def EventuallyConverges (services : MaterializedView.Services)
    (scenario : Scenario Device) (databases : Nat → Device → SimulatedHost.Database) : Prop :=
  Converges services scenario databases

/-- **M1.** Finite production coverage lifts the per-device/per-origin actual
execution theorem to one common stabilization point for the whole system.
The statement consumes raw executions and independent host opportunities via
`SystemExecution`; it assumes neither successful Fetch/Complete/promotion
results nor a pre-existing correct view or tail refinement. -/
theorem eventual_convergence
    (coverage : FiniteCoverage scenario)
    (execution : MptsyncProductionConvergence.SystemExecution
      services scenario databases coverage valid) :
    EventuallyConverges services scenario databases := by
  apply finite_targets_converge services scenario databases coverage
  intro pair member
  have convergence := (execution.run pair member).converges
    (execution.tailObserved pair.1) (scenario.target_origin pair.1 pair.2)
  obtain ⟨start, stable⟩ := convergence
  refine ⟨start, fun now after => ?_⟩
  dsimp only
  rw [← execution.observed pair.1 now]
  exact stable now after

end Synchronicity.Goals.Mptsync.M1
