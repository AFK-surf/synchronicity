import VerifiedCore.Cas.Ingest
import Synchronicity.Prelude

/-! Fault traces of the actual captured-source ingestion program. No host
callback implements publication or metadata policy. These fixtures use an
empty captured source; construction itself is one host effect whose reply
the program only width-checks. -/
namespace Synchronicity.IngestProgramProofs
open VerifiedCore.Host VerifiedCore.Cas.Ingest
set_option Elab.async false

private def digest : ByteArray := ⟨Array.replicate 32 0⟩
private def narrow : ByteArray := ⟨Array.replicate 31 0⟩
private def primary : Failure := ⟨1, 71⟩
private def secondary : Failure := ⟨1, 72⟩

private structure Script where
  failOn : Option String := none
  cleanupFails : Bool := false
  lateCleanupFails : Bool := false
  duplicate : Bool := false
  unsupported : Bool := false
  narrowRoot : Bool := false

private def cleanup (label : String) : Bool :=
  ["close", "release", "discard-outboard", "discard-payload"].contains label

private def reply (script : Script) (label : String) (value : A) : Reply A :=
  if script.failOn == some label then .error primary
  else if (script.cleanupFails || (script.lateCleanupFails && label != "close")) && cleanup label then .error secondary
  else .ok value

private def execute (script : Script) : Nat → Program Effects (Except Error ByteArray) →
    Option (Except Error ByteArray × List String)
  | 0, _ => none
  | _ + 1, .pure value => some (value, [])
  | fuel + 1, .request effect resume =>
    let step (label : String) (next : Program Effects (Except Error ByteArray)) :=
      (execute script fuel next).map fun (result, trace) => (result, label :: trace)
    match effect with
    | .left effect => match effect with
      | .left effect => match effect with
        | .open _ _ => none
        | .close handle => if handle == 1 then
            step "close" (resume (reply script "close" ())) else none
        | .readAt _ _ _ => none
        | .transfer _ _ _ => none
      | .right effect => match effect with
        | .build source payload outboard size =>
          if source == 1 && payload == 2 && outboard == 3 && size == 0 then
            step "build" (resume (reply script "build"
              (if script.narrowRoot then narrow else digest))) else none
        | .hash _ => none
    | .right effect => match effect with
      | .left effect => match effect with
        | .left effect => match effect with
          | .begin => step "begin" (resume (reply script "begin" 7))
          | .commit tx => if tx == 7 then step "commit" (resume (reply script "commit" ())) else none
          | .rollback tx => if tx == 7 then step "rollback" (resume (.ok ())) else none
          | .readRows tx relation columns equals order joins =>
            if tx == 7 && relation == "blobs" && columns == ["size", "complete", "durable", "bitmap"] &&
                equals == [("root", .blob digest)] && order.isEmpty && joins.isEmpty then
              step "claim" (resume (reply script "claim" [])) else none
          | _ => none
        | .right effect => match effect with
          | .write tx relation fields conflicts updates =>
            if tx == 7 && relation == "blobs" && conflicts == ["root"] &&
                fields == VerifiedCore.Cas.IngestCommit.values digest 0 none 123 .local &&
                updates == VerifiedCore.Cas.IngestCommit.assignments then
              step "upsert" (resume (reply script "upsert" ())) else none
      | .right effect => match effect with
        | .left effect => match effect with
          | .createTemporary space =>
            if space == "cas_payload" then step "temp-payload" (resume (reply script "temp-payload" 2))
            else if space == "cas_outboard" then step "temp-outboard"
              (resume (reply script "temp-outboard" (if script.duplicate then 2 else 3))) else none
          | .flush handle =>
            let label := if handle == 2 then "flush-payload" else "flush-outboard"
            if handle == 2 || handle == 3 then step label (resume (reply script label ())) else none
          | .replace handle space key =>
            let label := if handle == 2 then "replace-payload" else "replace-outboard"
            if key == digest && ((handle == 2 && space == "cas_payload") ||
                (handle == 3 && space == "cas_outboard")) then
              step label (resume (reply script label ())) else none
          | .discard handle =>
            let label := if handle == 2 then "discard-payload" else "discard-outboard"
            if handle == 2 || handle == 3 then step label (resume (reply script label ())) else none
          | .syncParent space key =>
            let label := if space == "cas_payload" then "sync-payload" else "sync-outboard"
            if key == digest && (space == "cas_payload" || space == "cas_outboard") then
              step label (resume (reply script label
                (if script.unsupported then .unsupported else .synced))) else none
        | .right effect => match effect with
          | .acquire space key => if space == "cas_writers" && key == digest then
              step "lease" (resume (reply script "lease" 9)) else none
          | .release token => if token == 9 then step "release" (resume (reply script "release" ())) else none

private def check (script : Script) (policy : DirectoryPolicy := .requireSync) :=
  execute script 32 (run 1 0 123 .local policy).run

private def beforePublish := ["temp-payload", "temp-outboard", "build", "close", "lease"]
private def publication := ["flush-payload", "flush-outboard", "replace-payload", "replace-outboard",
  "sync-payload", "sync-outboard"]
private def finalCleanup := ["release", "discard-outboard", "discard-payload"]

theorem success_has_complete_ordered_trace : check {} = some (.ok digest,
    beforePublish ++ publication ++ ["begin", "claim", "upsert", "commit"] ++ finalCleanup) := by decide

theorem first_acquisition_failure_closes_source : check { failOn := some "temp-payload" } =
    some (.error (.host primary), ["temp-payload", "close"]) := by decide

theorem second_acquisition_failure_discards_first_temporary :
    check { failOn := some "temp-outboard", cleanupFails := true } =
      some (.error (.host primary), ["temp-payload", "temp-outboard", "close", "discard-payload"]) := by decide

theorem duplicate_temporary_rejected_before_construction : check { duplicate := true } =
    some (.error .protocol, ["temp-payload", "temp-outboard", "close", "discard-payload"]) := by decide

/-- Construction is requested only over the two owned temporaries and the
captured source, exactly once, and its failure survives cleanup failures. -/
theorem construction_failure_survives_cleanup_failures :
    check { failOn := some "build", cleanupFails := true } =
      some (.error (.host primary),
        ["temp-payload", "temp-outboard", "build", "close", "discard-outboard", "discard-payload"]) := by decide

/-- A root of the wrong width never reaches a lease, a flush or a name: the
program rejects it as a protocol failure before anything is published. -/
theorem narrow_root_reply_publishes_nothing : check { narrowRoot := true } =
    some (.error .protocol,
      ["temp-payload", "temp-outboard", "build", "close", "discard-outboard", "discard-payload"]) := by decide

theorem failed_source_close_is_not_retried : check { failOn := some "close" } =
    some (.error (.host primary), ["temp-payload", "temp-outboard", "build", "close",
      "discard-outboard", "discard-payload"]) := by decide

theorem second_flush_failure_publishes_nothing : check { failOn := some "flush-outboard" } =
    some (.error (.host primary), beforePublish ++ ["flush-payload", "flush-outboard"] ++ finalCleanup) := by decide

theorem second_replace_failure_does_not_commit_metadata : check { failOn := some "replace-outboard" } =
    some (.error (.host primary), beforePublish ++
      ["flush-payload", "flush-outboard", "replace-payload", "replace-outboard"] ++ finalCleanup) := by decide

theorem sync_failure_does_not_commit_metadata : check { failOn := some "sync-outboard" } =
    some (.error (.host primary), beforePublish ++ publication ++ finalCleanup) := by decide

theorem failed_commit_rolls_back_before_releasing_lease : check { failOn := some "commit" } =
    some (.error (.metadata (.host primary)), beforePublish ++ publication ++
      ["begin", "claim", "upsert", "commit", "rollback"] ++ finalCleanup) := by decide

theorem successful_commit_still_reports_release_failure : check { failOn := some "release" } =
    some (.error (.host primary), beforePublish ++ publication ++
      ["begin", "claim", "upsert", "commit"] ++ finalCleanup) := by decide

theorem unsupported_sync_is_rejected_by_default : check { unsupported := true } =
    some (.error .directorySyncUnsupported, beforePublish ++
      ["flush-payload", "flush-outboard", "replace-payload", "replace-outboard", "sync-payload"] ++
      finalCleanup) := by decide

theorem explicitly_configured_unsupported_sync_can_commit :
    check { unsupported := true } .allowUnsupported = some (.ok digest,
      beforePublish ++ publication ++ ["begin", "claim", "upsert", "commit"] ++ finalCleanup) := by decide

theorem permissive_platform_policy_never_swallows_io_errors :
    check { failOn := some "sync-outboard" } .allowUnsupported =
      some (.error (.host primary), beforePublish ++ publication ++ finalCleanup) := by decide

theorem failed_commit_survives_all_later_cleanup_failures :
    check { failOn := some "commit", lateCleanupFails := true } =
      some (.error (.metadata (.host primary)), beforePublish ++ publication ++
        ["begin", "claim", "upsert", "commit", "rollback"] ++ finalCleanup) := by decide

theorem failed_lease_acquisition_never_releases_unowned_token : check { failOn := some "lease" } =
    some (.error (.host primary), beforePublish ++ ["discard-outboard", "discard-payload"]) := by decide

theorem failed_discard_does_not_skip_other_temporary_cleanup : check { failOn := some "discard-outboard" } =
    some (.error (.host primary), beforePublish ++ publication ++
      ["begin", "claim", "upsert", "commit"] ++ finalCleanup) := by decide

/-- Every operation in the successful trace has an explicit failure case.
Expected prefixes stop mutation at the first failure, but cleanup still runs.
This is exhaustive for this execution shape, not all possible source sizes. -/
private def failureCases : List (String × Error × List String) :=
  [("temp-payload", .host primary, ["temp-payload", "close"]),
   ("temp-outboard", .host primary, ["temp-payload", "temp-outboard", "close", "discard-payload"]),
   ("build", .host primary, ["temp-payload", "temp-outboard", "build", "close", "discard-outboard", "discard-payload"]),
   ("close", .host primary, ["temp-payload", "temp-outboard", "build", "close", "discard-outboard", "discard-payload"]),
   ("lease", .host primary, beforePublish ++ ["discard-outboard", "discard-payload"])] ++
  (publication.zipIdx.map fun (label, index) =>
    (label, .host primary, beforePublish ++ publication.take (index + 1) ++ finalCleanup)) ++
  [("begin", .metadata (.host primary), beforePublish ++ publication ++ ["begin"] ++ finalCleanup),
   ("claim", .metadata (.host primary), beforePublish ++ publication ++ ["begin", "claim", "rollback"] ++ finalCleanup),
   ("upsert", .metadata (.host primary), beforePublish ++ publication ++ ["begin", "claim", "upsert", "rollback"] ++ finalCleanup),
   ("commit", .metadata (.host primary), beforePublish ++ publication ++ ["begin", "claim", "upsert", "commit", "rollback"] ++ finalCleanup)] ++
  (finalCleanup.map fun label => (label, .host primary,
    beforePublish ++ publication ++ ["begin", "claim", "upsert", "commit"] ++ finalCleanup))

theorem every_success_path_effect_failure_has_exact_cleanup_trace :
    failureCases.all (fun (label, error, trace) =>
      check { failOn := some label } == some (.error error, trace)) = true := by decide

end Synchronicity.IngestProgramProofs
