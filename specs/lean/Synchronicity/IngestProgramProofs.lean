import VerifiedCore.Cas.Ingest
import Synchronicity.CasFixtures

/-! Fault traces of the actual captured-source ingestion program. No host
callback implements publication or metadata policy. These fixtures use an
empty captured source; construction itself is one host effect whose reply
the program only width-checks. -/
namespace Synchronicity.IngestProgramProofs
open VerifiedCore.Host VerifiedCore.Cas.Ingest
set_option Elab.async false

/-- A malformed host cannot make the program construct into one temporary
twice. This boundary check is structural, not an impossible simulated success. -/
theorem duplicate_temporary_rejected_before_construction (source size temporary : UInt64)
    (now : Int64) (tier : VerifiedCore.Cas.IngestCommit.Tier) (policy : DirectoryPolicy) :
    ∃ first second closed,
      (run source size now tier policy).run =
        .request (.right (.right (.left (.createTemporary "cas_payload")))) first ∧
      first (.ok temporary) =
        .request (.right (.right (.left (.createTemporary "cas_outboard")))) second ∧
      second (.ok temporary) = .request (.left (.left (.close source))) closed := by
  refine ⟨_, _, (fun _ => .request (.right (.right (.left (.discard temporary))))
    (fun _ => .pure (.error .protocol))), rfl, rfl, ?_⟩
  simp [ensure, closeSource, resource, raise, performOver, Inject.inject,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.run, ExceptT.mk, Except.mapError, Except.map]
  rfl

open SimulatedHost CasFixtures

/-- An already opened immutable source, not scripted successful replies. -/
private def initial : State := { handles := [(1, ByteArray.empty)], nextHandle := 2, now := 123 }
private def check (state : State := initial) (policy : DirectoryPolicy := .requireSync) :=
  traceResult (VerifiedCore.Cas.Ingest.run 1 0 123 .local policy) state
private def beforePublish := ["temporary:cas_payload", "temporary:cas_outboard", "build", "close", "lease:cas_writers"]
private def publication := ["flush", "flush", "replace:cas_payload", "replace:cas_outboard", "sync:cas_payload", "sync:cas_outboard"]
private def finalCleanup := ["release", "discard", "discard"]
private def success := beforePublish ++ publication ++ ["begin", "read:blobs", "upsert:blobs", "commit"] ++ finalCleanup

theorem success_has_complete_ordered_trace : check = (.ok root, success) := by decide +kernel

theorem first_acquisition_failure_closes_source : check (fail initial 0) =
    (.error (.host primary), ["temporary:cas_payload", "close"]) := by decide +kernel

theorem second_acquisition_failure_discards_first_temporary : check (fail initial 1) =
    (.error (.host primary), ["temporary:cas_payload", "temporary:cas_outboard", "close", "discard"]) := by decide +kernel

theorem construction_failure_survives_cleanup_failures :
    check (fail (fail (fail (fail initial 2) 3 secondary) 4 secondary) 5 secondary) =
      (.error (.host primary), ["temporary:cas_payload", "temporary:cas_outboard", "build", "close", "discard", "discard"]) := by decide +kernel

theorem narrow_root_reply_publishes_nothing : check { initial with hash := fun _ => ByteArray.empty } =
    (.error .protocol, ["temporary:cas_payload", "temporary:cas_outboard", "build", "close", "discard", "discard"]) := by decide +kernel

theorem failed_source_close_is_not_retried : check (fail initial 3) =
    (.error (.host primary), ["temporary:cas_payload", "temporary:cas_outboard", "build", "close", "discard", "discard"]) := by decide +kernel

theorem second_flush_failure_publishes_nothing : check (fail initial 6) =
    (.error (.host primary), beforePublish ++ ["flush", "flush"] ++ finalCleanup) := by decide +kernel

theorem second_replace_failure_does_not_commit_metadata :
    (SimulatedHost.run (VerifiedCore.Cas.Ingest.run 1 0 123 .local) (fail initial 8)).2.db == [] := by decide +kernel

theorem sync_failure_does_not_commit_metadata :
    (SimulatedHost.run (VerifiedCore.Cas.Ingest.run 1 0 123 .local) (fail initial 10)).2.db == [] := by decide +kernel

theorem failed_commit_rolls_back_before_releasing_lease : check (fail initial 14) =
    (.error (.metadata (.host primary)), beforePublish ++ publication ++
      ["begin", "read:blobs", "upsert:blobs", "commit", "rollback"] ++ finalCleanup) := by decide +kernel

theorem successful_commit_still_reports_release_failure : check (fail initial 15) =
    (.error (.host primary), success) := by decide +kernel

theorem unsupported_sync_is_rejected_by_default : check { initial with directorySync := .unsupported } =
    (.error .directorySyncUnsupported, beforePublish ++ publication.take 5 ++ finalCleanup) := by decide +kernel

theorem explicitly_configured_unsupported_sync_can_commit :
    check { initial with directorySync := .unsupported } .allowUnsupported = (.ok root, success) := by decide +kernel

theorem permissive_platform_policy_never_swallows_io_errors : check (fail initial 10) .allowUnsupported =
    (.error (.host primary), beforePublish ++ publication ++ finalCleanup) := by decide +kernel

theorem failed_commit_survives_all_later_cleanup_failures :
    check (fail (fail (fail (fail initial 14) 16 secondary) 17 secondary) 18 secondary) =
      (.error (.metadata (.host primary)), beforePublish ++ publication ++
        ["begin", "read:blobs", "upsert:blobs", "commit", "rollback"] ++ finalCleanup) := by decide +kernel

theorem failed_lease_acquisition_never_releases_unowned_token : check (fail initial 4) =
    (.error (.host primary), beforePublish ++ ["discard", "discard"]) := by decide +kernel

theorem failed_discard_does_not_skip_other_temporary_cleanup : check (fail initial 16) =
    (.error (.host primary), success) := by decide +kernel

/-- Every successful-path effect is failed independently in the same host. -/
theorem every_success_path_effect_failure_cleans_resources :
    (List.range 18).all (fun index =>
      let result := SimulatedHost.run (VerifiedCore.Cas.Ingest.run 1 0 123 .local) (fail initial index)
      failed result.1 && result.2.handles.isEmpty && result.2.temporaries.isEmpty &&
        result.2.leases.isEmpty && result.2.pending.isNone) = true := by decide +kernel

end Synchronicity.IngestProgramProofs
