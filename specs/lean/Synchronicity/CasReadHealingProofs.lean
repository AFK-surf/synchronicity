import VerifiedCore.Cas.Read
import Synchronicity.CasFixtures

/-! The actual repair program requests raw storage operations. These fixtures
interpret its constructors, not a duplicate repair policy. Raw host contracts
remain the explicit execution boundary. -/
namespace Synchronicity.CasReadHealingProofs
open VerifiedCore.Host VerifiedCore.Cas.Read
set_option Elab.async false

theorem heal_begins_transaction (root : ByteArray) :
    ∃ resume, (heal root).run = .request (.left .begin) resume := by
  exact ⟨_, rfl⟩

/-- Repair observes the size itself under the transaction's token. -/
theorem heal_reads_size (tx : Transaction) (root : ByteArray) :
    ∃ resume, (healIn tx root).run = .request
      (.left (.readRows tx "blobs" ["size"] [("root", .blob root)])) resume := by
  exact ⟨_, rfl⟩

/-- An unsuccessful raw query cannot request any invalidation or clock read. -/
theorem heal_read_failure (tx : Transaction) (root : ByteArray) (failure : Failure) :
    ∃ resume, (healIn tx root).run = .request
      (.left (.readRows tx "blobs" ["size"] [("root", .blob root)])) resume ∧
      resume (.error failure) = .pure (.error (.host failure)) := by
  exact ⟨_, rfl, rfl⟩

open SimulatedHost CasFixtures

private def check (state : State := repairing) := traceResult (heal root) state
private def success := ["begin", "read:blobs", "update:blobs", "clock", "copy:content_want", "delete:pins", "commit"]

theorem healing_exact_success_trace : check = (.ok (), success) := by decide +kernel

theorem absent_blob_has_no_clock_or_mutation : check { repairing with db := [] } =
    (.ok (), ["begin", "read:blobs", "commit"]) := by decide +kernel

theorem null_size_is_not_absence : check { repairing with db := [("blobs", [[("root", .blob root)]])] } =
    (.error (.columnType 0 "size" .null), ["begin", "read:blobs", "rollback"]) := by decide +kernel

theorem begin_failure_has_no_rollback : check (fail repairing 0) =
    (.error (.host primary), ["begin"]) := by decide +kernel

theorem every_failed_stage_rolls_back :
    (List.range 6).all (fun index =>
      check (fail repairing (index + 1)) ==
        (.error (.host primary), success.take (index + 2) ++ ["rollback"])) = true := by decide +kernel

theorem rollback_failure_preserves_primary : check (fail (fail repairing 4) 5 secondary) =
    (.error (.host primary), success.take 5 ++ ["rollback"]) := by decide +kernel

/-- Unlike a reply script, the shared host proves the database was restored. -/
theorem failed_copy_restores_pins_and_availability :
    (SimulatedHost.run (heal root) (fail repairing 4)).2.db == repairing.db := by decide +kernel

theorem commit_failure_restores_all_rows :
    (SimulatedHost.run (heal root) (fail repairing 6)).2.db == repairing.db := by decide +kernel

end Synchronicity.CasReadHealingProofs
