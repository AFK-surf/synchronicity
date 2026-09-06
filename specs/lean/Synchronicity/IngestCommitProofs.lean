import VerifiedCore.Cas.IngestCommit
import Synchronicity.VerifiedCoreProofs
import Synchronicity.Prelude

/-! Proofs of the internal ingestion metadata program itself. The production
whole Lean command composes it; outer resource and construction obligations
are covered separately by the corresponding ingestion and Bao proof modules. -/
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
  apply VerifiedCoreProofs.cas_plan_coverage_completes
  intro group inside
  have membership := VerifiedCoreProofs.cas_plan_membership row durable complete recorded size
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

private def root : ByteArray := ByteArray.empty
private def primary : Failure := ⟨1, 71⟩
private def secondary : Failure := ⟨1, 72⟩

private structure Script where
  rows : List Row := []
  tier : Tier := .local
  failAt : Option Nat := none
  rollbackFailure : Bool := false

private def reply (script : Script) (index : Nat) (value : A) : Reply A :=
  if script.failAt == some index then .error primary else .ok value

/-- Only exact raw statements are accepted; there is no metadata interpretation
or settlement implementation in this effect interpreter. -/
private def execute (script : Script) : Nat → Nat →
    Program Effects (Except Error Unit) → Option (Except Error Unit × List String)
  | 0, _, _ => none
  | _ + 1, _, .pure result => some (result, [])
  | fuel + 1, index, .request effect resume =>
    let step (label : String) (next : Program Effects (Except Error Unit)) :=
      (execute script fuel (index + 1) next).map fun (result, trace) => (result, label :: trace)
    match effect with
    | .left effect => match effect with
      | .begin => step "begin" (resume (reply script index 7))
      | .commit tx => if tx == 7 then step "commit" (resume (reply script index ())) else none
      | .rollback tx => if tx == 7 then step "rollback"
          (resume (if script.rollbackFailure then .error secondary else .ok ())) else none
      | .readRows tx relation columns equals order joins =>
        if tx == 7 && relation == "blobs" && columns == ["size", "complete", "durable", "bitmap"] &&
            equals == [("root", .blob root)] && order.isEmpty && joins.isEmpty then
          step "claim" (resume (reply script index script.rows))
        else none
      | _ => none
    | .right effect => match effect with
      | .write tx relation fields conflicts updates =>
        if tx == 7 && relation == "blobs" && conflicts == ["root"] &&
            fields == [("root", .blob root), ("size", .integer 8),
              ("complete", .integer 1), ("bitmap", .null), ("inline", .null),
              ("last_access", .integer 123),
              ("durable", .integer (if script.tier == .local then 1 else 0))] &&
            updates == [("size", .excluded "size"), ("complete", .excluded "complete"),
              ("bitmap", .excluded "bitmap"),
              ("inline", .coalesce (.excluded "inline") (.current "inline")),
              ("last_access", .excluded "last_access"),
              ("durable", .max (.current "durable") (.excluded "durable"))] then
          step "write" (resume (reply script index ()))
        else none

private def run (script : Script) :=
  execute script 8 0 (commitComplete root 8 none 123 script.tier).run

theorem local_commit_exact_raw_mutations : run {} =
    some (.ok (), ["begin", "claim", "write", "commit"]) := by decide

theorem cache_commit_stays_staged : run { tier := .cache } =
    some (.ok (), ["begin", "claim", "write", "commit"]) := by decide

theorem existing_noncanonical_durability_uses_raw_max :
    run { rows := [[.integer 8, .integer 0, .integer 2, .null]], tier := .cache } =
      some (.ok (), ["begin", "claim", "write", "commit"]) := by decide

theorem conflicting_complete_size_rolls_back_without_write :
    run { rows := [[.integer 9, .integer 1, .integer 0, .null]] } =
      some (.error (.sizeMismatch root 9 8), ["begin", "claim", "rollback"]) := by decide

theorem unattested_size_yields_to_ingestion :
    run { rows := [[.integer 32768, .integer 0, .integer 0, .null]] } =
      some (.ok (), ["begin", "claim", "write", "commit"]) := by decide

theorem malformed_bitmap_means_no_attestation :
    run { rows := [[.integer 32768, .integer 0, .integer 0, .blob ByteArray.empty]] } =
      some (.ok (), ["begin", "claim", "write", "commit"]) := by decide

theorem size_type_error_precedes_all_later_errors :
    run { rows := [[.null, .null, .null, .integer 1]] } =
      some (.error (.metadata (.columnType 0 "size" .null)), ["begin", "claim", "rollback"]) := by decide

theorem complete_type_error_precedes_durable_and_bitmap :
    run { rows := [[.integer 8, .null, .null, .integer 1]] } =
      some (.error (.metadata (.columnType 1 "complete" .null)), ["begin", "claim", "rollback"]) := by decide

theorem durable_type_error_precedes_bitmap :
    run { rows := [[.integer 8, .integer 1, .null, .integer 1]] } =
      some (.error (.metadata (.columnType 2 "durable" .null)), ["begin", "claim", "rollback"]) := by decide

theorem complete_does_not_skip_bitmap_type_error :
    run { rows := [[.integer 8, .integer 1, .integer 1, .integer 1]] } =
      some (.error (.metadata (.columnType 3 "bitmap" .integer)), ["begin", "claim", "rollback"]) := by decide

theorem begin_failure_does_not_rollback : run { failAt := some 0 } =
    some (.error (.host primary), ["begin"]) := by decide

theorem read_failure_rolls_back : run { failAt := some 1, rollbackFailure := true } =
    some (.error (.host primary), ["begin", "claim", "rollback"]) := by decide

theorem write_failure_rolls_back : run { failAt := some 2, rollbackFailure := true } =
    some (.error (.host primary), ["begin", "claim", "write", "rollback"]) := by decide

theorem commit_failure_rolls_back : run { failAt := some 3, rollbackFailure := true } =
    some (.error (.host primary), ["begin", "claim", "write", "commit", "rollback"]) := by decide

end Synchronicity.IngestCommitProofs
