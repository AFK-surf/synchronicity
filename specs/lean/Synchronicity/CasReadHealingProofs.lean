import VerifiedCore.Cas.Read
import Synchronicity.Handlers

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

/-- The scripted host checks exact relations, predicates and field values,
including conflict semantics; unexpected effects are refused, never answered. -/
private structure State where
  script : Script
  index : Nat := 0

private def step (state : State) (label : String) (value : A) : Option (String × Reply A × State) :=
  some (label, reply state.script state.index value, { state with index := state.index + 1 })

private instance : Handlers.Handler Storage State String where
  handle
    | .begin, s => step s "begin" 7
    | .commit tx, s => if tx == 7 then step s "commit" () else none
    | .rollback tx, s => if tx == 7 then
        some ("rollback", (if s.script.rollbackFailure then .error secondary else .ok ()),
          { s with index := s.index + 1 }) else none
    | .readRows tx relation columns equals order joined, s =>
      if tx == 7 && relation == "blobs" && columns == ["size"] &&
          equals == [("root", .blob root)] && order.isEmpty && joined.isEmpty then
        step s "size" s.script.rows
      else none
    | _, _ => none

private instance : Handlers.Handler Access State String where
  handle
    | .snapshot .., _ => none
    | .update tx selection fields, s =>
      if tx == 7 && selection == ⟨"blobs", [("root", .blob root)], []⟩ &&
          fields == [("complete", .integer 0), ("durable", .integer 0),
            ("bitmap", .null), ("inline", .null)] then
        step s "invalidate" 1
      else none
    | .copyRows tx target source fields conflicts, s =>
      if tx == 7 && target == "content_want" && source == repairPins root &&
          fields == [("root", .column "root"), ("holder", .column "holder"),
            ("size", .literal (.integer 42)), ("prev", .literal .null),
            ("first_wanted", .literal (.integer 123))] &&
          conflicts == ["root", "holder"] then
        step s "copy" 1
      else none
    | .delete tx selection, s =>
      if tx == 7 && selection == repairPins root then step s "delete" 1 else none

private instance : Handlers.Handler Clock State String where
  handle
    | .nowNs, s => step s "clock" 123

private instance : Handlers.Handler FileIO State String := Handlers.refuse
private instance : Handlers.Handler Output State String := Handlers.refuse

private def run (script : Script) := Handlers.run 20 (heal root).run (⟨script, 0⟩ : State)

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
