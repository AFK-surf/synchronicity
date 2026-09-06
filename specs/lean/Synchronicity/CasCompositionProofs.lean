import Synchronicity.CasFixtures

/-! Multi-command histories over one shared state. No metadata/file adapters
occur between commands; faults and external loss change raw state only. -/
deriving instance DecidableEq for VerifiedCore.Cas.Input.Result

namespace Synchronicity.CasCompositionProofs
open VerifiedCore.Host VerifiedCore.Cas SimulatedHost CasFixtures

private def initial : State :=
  { files := [(("input", ByteArray.empty), bytes)], handles := [(1, bytes)], nextHandle := 2, now := 123 }
private def ingested := SimulatedHost.run (Ingest.run 1 4 123 .local) initial
private def held := SimulatedHost.run (acquire root "source:media" 123 false) ingested.2
private def lost := SimulatedHost.run (perform (.removeFile "cas_payload" root)) held.2
private def repaired := SimulatedHost.run (Read.read root .all) lost.2
private def restored := SimulatedHost.run (Input.run (.bytes 4) 124 .local) repaired.2
private def reacquired := SimulatedHost.run (acquire root "source:media" 124 true) restored.2
private def reread := SimulatedHost.run (Read.read root .all) reacquired.2

theorem stored_content_can_be_acquired_and_read :
    ingested.1 == .ok root ∧ held.1 == .ok true ∧
    let result := SimulatedHost.run (Read.read root .all) held.2
    publish Read.Error.protocol result.1 result.2 == .ok [10, 20, 30, 40] := by decide +kernel

theorem acquisition_protects_subsequent_collection :
    let result := SimulatedHost.run (delete root none) held.2
    result.1 = .ok .protectedClaim ∧ result.2.db == held.2.db ∧ result.2.files == held.2.files := by decide +kernel

theorem physical_loss_transfers_real_possession_to_repair :
    repaired.1 == .error (.host absent) ∧
    rows repaired.2.db "pins" == [] ∧
    rows repaired.2.db "content_want" == [want root "source:media" 4 .null 123] := by decide +kernel

theorem repeated_reads_do_not_retry_known_missing_bytes :
    let next := SimulatedHost.run (Read.read root .all) repaired.2
    next.1 == .error .unavailable ∧ next.2.trace == repaired.2.trace ++ ["snapshot:blobs"] := by decide +kernel

theorem repeated_healing_changes_no_persistent_state :
    let again := SimulatedHost.run (Read.heal root) { repaired.2 with now := 999 }
    again.1 == .ok () ∧ again.2.db == repaired.2.db ∧ again.2.files == repaired.2.files := by decide +kernel

theorem restoring_content_settles_the_preserved_obligation :
    restored.1 == .ok ⟨root, 4⟩ ∧ reacquired.1 == .ok true ∧
    rows reacquired.2.db "content_want" == [] ∧
    (rows reacquired.2.db "pins").map (fun row => cell row "holder") == [.text "source:media"] ∧
    publish Read.Error.protocol reread.1 reread.2 == .ok [10, 20, 30, 40] := by decide +kernel

theorem cancelling_repair_prevents_late_possession :
    let cancelled := SimulatedHost.run (VerifiedCore.Host.transaction fun tx =>
      perform (.deleteRows tx "content_want" [("root", .blob root), ("holder", .text "source:media")])) repaired.2
    let fetched := SimulatedHost.run (Input.run (.bytes 4) 124 .local) cancelled.2
    let late := SimulatedHost.run (acquire root "source:media" 124 true) fetched.2
    late.1 == .ok false ∧ rows late.2.db "pins" == [] := by decide +kernel

end Synchronicity.CasCompositionProofs
