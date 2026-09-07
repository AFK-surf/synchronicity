import Synchronicity.CasFixtures

namespace Synchronicity.CasExpiryProofs
open VerifiedCore.Host VerifiedCore.Cas SimulatedHost CasFixtures

private def scheduled : State :=
  { db := [("pins", [pin root "operator" (.integer 10), pin otherRoot "operator" (.integer 11), pin root "source:media"])] }

theorem expiry_is_inclusive_and_ignores_unscheduled :
    let result := SimulatedHost.run (expire none 10) scheduled
    result.1 == .ok 1 ∧ rows result.2.db "pins" ==
      [pin otherRoot "operator" (.integer 11), pin root "source:media"] := by decide +kernel

theorem live_entry_protects_every_holder :
    let initial := { scheduled with db := scheduled.db ++ [("entries", [entry])] }
    let result := SimulatedHost.run (expire none 10) initial
    result.1 == .ok 0 ∧ rows result.2.db "pins" == rows initial.db "pins" := by decide +kernel

theorem every_failure_restores_pins :
    (List.range 3).all (fun index =>
      let result := SimulatedHost.run (expire none 10) (fail scheduled index)
      failed result.1 && (result.2.db == scheduled.db)) = true := by decide +kernel

end Synchronicity.CasExpiryProofs
