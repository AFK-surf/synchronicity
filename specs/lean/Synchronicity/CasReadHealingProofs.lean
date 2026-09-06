import VerifiedCore.Cas.Read
import Synchronicity.Decidable

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

private def root : ByteArray := ByteArray.empty
private def failure : Failure := ⟨1, 77⟩
private def secondary : Failure := ⟨1, 88⟩

private structure Script where
  rows : List Row := [[.integer 42]]
  failAt : Option Nat := none
  rollbackFailure : Bool := false

private def reply (script : Script) (index : Nat) (value : A) : Reply A :=
  if script.failAt == some index then .error failure else .ok value

/-- The raw interpreter checks exact relations, predicates and field values,
including conflict semantics; unexpected effects do not silently succeed. -/
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
      | .readRows tx relation columns equals order joined =>
        if tx == 7 && relation == "blobs" && columns == ["size"] &&
            equals == [("root", .blob root)] && order.isEmpty && joined.isEmpty then
          step "size" (resume (reply script index script.rows))
        else none
      | _ => none
    | .right effect => match effect with
      | .left effect => match effect with
        | .snapshot .. => none
        | .update tx selection fields =>
          if tx == 7 && selection == ⟨"blobs", [("root", .blob root)], []⟩ &&
              fields == [("complete", .integer 0), ("durable", .integer 0),
                ("bitmap", .null), ("inline", .null)] then
            step "invalidate" (resume (reply script index 1))
          else none
        | .copyRows tx target source fields conflicts =>
          if tx == 7 && target == "content_want" && source == repairPins root &&
              fields == [("root", .column "root"), ("holder", .column "holder"),
                ("size", .literal (.integer 42)), ("prev", .literal .null),
                ("first_wanted", .literal (.integer 123))] &&
              conflicts == ["root", "holder"] then
            step "copy" (resume (reply script index 1))
          else none
        | .delete tx selection =>
          if tx == 7 && selection == repairPins root then
            step "delete" (resume (reply script index 1))
          else none
      | .right effect => match effect with
        | .left _ => none
        | .right effect => match effect with
          | .left effect => match effect with
            | .nowNs => step "clock" (resume (reply script index 123))
          | .right _ => none

private def run (script : Script) := execute script 20 0 (heal root).run

theorem healing_exact_success_trace : run {} = some (.ok (),
    ["begin", "size", "invalidate", "clock", "copy", "delete", "commit"]) := by decide

theorem absent_blob_has_no_clock_or_mutation : run { rows := [] } =
    some (.ok (), ["begin", "size", "commit"]) := by decide

theorem null_size_is_not_absence : run { rows := [[.null]] } =
    some (.error (.columnType 0 "size" .null), ["begin", "size", "rollback"]) := by decide

theorem malformed_projection_has_no_mutation : run { rows := [[]] } =
    some (.error .malformed, ["begin", "size", "rollback"]) := by decide

theorem begin_failure_has_no_rollback : run { failAt := some 0 } =
    some (.error (.host failure), ["begin"]) := by decide

theorem read_failure_rolls_back : run { failAt := some 1 } =
    some (.error (.host failure), ["begin", "size", "rollback"]) := by decide

theorem invalidation_failure_does_not_sample_clock : run { failAt := some 2 } =
    some (.error (.host failure), ["begin", "size", "invalidate", "rollback"]) := by decide

theorem clock_failure_rolls_back_invalidation : run { failAt := some 3 } =
    some (.error (.host failure), ["begin", "size", "invalidate", "clock", "rollback"]) := by decide

theorem copy_failure_retains_pins : run { failAt := some 4 } =
    some (.error (.host failure), ["begin", "size", "invalidate", "clock", "copy", "rollback"]) := by decide

theorem delete_failure_rolls_back_transfer : run { failAt := some 5 } =
    some (.error (.host failure), ["begin", "size", "invalidate", "clock", "copy", "delete", "rollback"]) := by decide

theorem commit_failure_rolls_back_every_mutation : run { failAt := some 6 } =
    some (.error (.host failure), ["begin", "size", "invalidate", "clock", "copy", "delete", "commit", "rollback"]) := by decide

theorem rollback_failure_preserves_primary :
    run { failAt := some 4, rollbackFailure := true } =
      some (.error (.host failure), ["begin", "size", "invalidate", "clock", "copy", "rollback"]) := by decide

end Synchronicity.CasReadHealingProofs
