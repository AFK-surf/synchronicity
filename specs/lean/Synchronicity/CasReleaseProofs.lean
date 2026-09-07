import Synchronicity.CasFixtures

namespace Synchronicity.CasReleaseProofs
open VerifiedCore.Host VerifiedCore.Cas SimulatedHost CasFixtures

private def pinned : State := { stored with db := [("blobs", [blob]), ("pins", [pin, pin root "operator"])] }

theorem release_removes_only_requested_holder :
    let result := SimulatedHost.run (unpin root .operator) pinned
    result.1 == .ok true ∧ rows result.2.db "pins" == [pin] := by decide +kernel

theorem live_entry_protects_standing_role :
    let initial := { pinned with db := pinned.db ++ [("entries", [entry])] }
    let result := SimulatedHost.run (unpin root (.source "media")) initial
    result.1 == .ok false ∧ rows result.2.db "pins" == rows initial.db "pins" := by decide +kernel

theorem every_failure_restores_pins :
    (List.range 3).all (fun index =>
      let result := SimulatedHost.run (unpin root .operator) (fail pinned index)
      failed result.1 && (result.2.db == pinned.db)) = true := by decide +kernel

end Synchronicity.CasReleaseProofs
