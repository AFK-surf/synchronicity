import VerifiedCore.Cas.IngestCommit
import Synchronicity.CasPlanProofs
import Synchronicity.CasFixtures

/-! Proofs of the internal ingestion metadata program itself. The production
whole Lean command composes it; the outer resource, construction-request and
input obligations are covered by the ingestion program and input modules. -/
namespace Synchronicity.IngestCommitProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Cas.IngestCommit
set_option Elab.async false

/-- Supplying all groups to the actual existing planner recognizes completion,
not merely coverage, whenever the size claim is accepted. -/
theorem full_input_accepted_complete (row durable complete : Bool) (recorded size : UInt64)
    (old : List GroupSpan)
    (accepted : (planCasCommit row durable complete recorded size old
      [⟨0, (groupCount size).toNat⟩]).accepted = true) :
    (planCasCommit row durable complete recorded size old
      [⟨0, (groupCount size).toNat⟩]).complete = true := by
  apply CasPlanProofs.cas_plan_coverage_completes
  intro group inside
  have membership := CasPlanProofs.cas_plan_membership row durable complete recorded size
    old [⟨0, (groupCount size).toNat⟩] group
  dsimp only at membership
  apply membership.mpr
  constructor
  · intro refused
    simp [planCasCommit, refused] at accepted
  · constructor
    · simp [spansContain, List.any_append, inside]
    · exact inside

theorem complete_plan_accepted_complete (claim : Option Claim) (size : UInt64)
    (accepted : (completePlan claim size).accepted = true) :
    (completePlan claim size).complete = true := by
  cases claim with
  | none => exact full_input_accepted_complete false false false 0 size [] accepted
  | some claim =>
    exact full_input_accepted_complete true claim.durable claim.complete
      claim.size size (oldSpans claim) accepted

theorem commit_begins_transaction (root : ByteArray) (size : UInt64)
    (inline : Option ByteArray) (now : Int64) (tier : Tier) :
    ∃ resume, (commitComplete root size inline now tier).run =
      .request (.left .begin) resume := ⟨_, rfl⟩

theorem claim_read_is_inside_transaction (tx : Transaction) (root : ByteArray) (size : UInt64)
    (inline : Option ByteArray) (now : Int64) (tier : Tier) :
    ∃ resume, (commitCompleteIn tx root size inline now tier).run = .request
      (.left (.readRows tx "blobs" ["size", "complete", "durable", "bitmap"]
        [("root", .blob root)])) resume := ⟨_, rfl⟩

theorem claim_read_failure_has_no_mutation (tx : Transaction) (root : ByteArray) (size : UInt64)
    (inline : Option ByteArray) (now : Int64) (tier : Tier) (failure : Failure) :
    ∃ resume, (commitCompleteIn tx root size inline now tier).run = .request
      (.left (.readRows tx "blobs" ["size", "complete", "durable", "bitmap"]
        [("root", .blob root)])) resume ∧
      resume (.error failure) = .pure (.error (.host failure)) := ⟨_, rfl, rfl⟩

open SimulatedHost CasFixtures

private def check (state : State := {}) :=
  traceResult (commitComplete root 4 none 123 .local) state

theorem fresh_commit_succeeds : check = (.ok (), ["begin", "read:blobs", "upsert:blobs", "commit"]) := by decide +kernel

theorem conflicting_attested_size_is_refused :
    check { stored with db := [("blobs", [blob root 5])] } =
      (.error (.sizeMismatch root 5 4), ["begin", "read:blobs", "rollback"]) := by decide +kernel

theorem every_failed_commit_stage_restores_database :
    (List.range 4).all (fun index =>
      let result := SimulatedHost.run (commitComplete root 4 none 123 .local) (fail stored index)
      failed result.1 && (result.2.db == stored.db) && result.2.pending.isNone) = true := by decide +kernel

theorem rollback_failure_preserves_primary : check (fail (fail {} 2) 3 secondary) =
    (.error (.host primary), ["begin", "read:blobs", "upsert:blobs", "rollback"]) := by decide +kernel

end Synchronicity.IngestCommitProofs
