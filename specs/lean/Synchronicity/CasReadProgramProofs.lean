import VerifiedCore.Cas.Read
import Synchronicity.CasFixtures

/-! Executions of the whole read program. The shared host
computes observations from raw rows and files, without availability or recovery decisions. -/
namespace Synchronicity.CasReadProgramProofs
open VerifiedCore.Host VerifiedCore.Cas.Read
set_option Elab.async false

/-- The production read owns its initial raw observation; Rust supplies no
decoded row, bitmap or coverage snapshot to the operation. -/
theorem read_observes_metadata (key : ByteArray) (request : Request) :
    ∃ resume, (read key request).run = .request
      (.right (.left (.snapshot ⟨"blobs", [("root", .blob key)], [], []⟩
        ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"]))) resume := by
  exact ⟨_, rfl⟩

/-- The whole requested range is one host transfer into the private output,
for every object, offset and count: the program never asks for the bytes
themselves, so no payload is ever a Lean value. -/
theorem payload_read_is_one_transfer (key : ByteArray) (offset count : Nat) (handle : UInt64) :
    ∃ opened next, (readPayload key offset count).run =
        .request (.right (.right (.left (.open "cas_payload" key)))) opened ∧
      opened (.ok handle) =
        .request (.right (.right (.left (.transfer handle offset.toUInt64 count.toUInt64)))) next := by
  exact ⟨_, _, rfl, rfl⟩

/-- An unrelated open error is returned directly, for every original token;
it cannot start a repair transaction. -/
theorem unrelated_open_failure_is_terminal (key : ByteArray) (offset count : Nat)
    (failure : Failure) :
    ∃ resume, (readPayload key offset count).run =
        .request (.right (.right (.left (.open "cas_payload" key)))) resume ∧
      resume (.error ⟨failure, .other⟩) = .pure (.error (.host failure)) := by
  exact ⟨_, rfl, rfl⟩

/-- Every transfer reply, including any failure classification, is followed by
close before the program interprets the result. No host reply script is needed. -/
theorem every_transfer_reply_closes_first (key : ByteArray) (offset count : Nat)
    (handle : UInt64) (result : FileReply Unit) :
    ∃ opened transferred closed,
      (readPayload key offset count).run =
        .request (.right (.right (.left (.open "cas_payload" key)))) opened ∧
      opened (.ok handle) =
        .request (.right (.right (.left (.transfer handle offset.toUInt64 count.toUInt64)))) transferred ∧
      transferred result = .request (.right (.right (.left (.close handle)))) closed := by
  exact ⟨_, _, _, rfl, rfl, rfl⟩

open SimulatedHost CasFixtures

private def state (complete : Int64 := 1) (inline : Cell := .null) : State :=
  { stored with db := [("blobs", [blob root 4 complete inline])] }

private def healing := ["begin", "read:blobs", "update:blobs", "clock", "copy:content_want", "delete:pins", "commit"]

theorem empty_precedes_availability_and_file :
    readResult (state 0) (.range 2 0) = (.ok [], ["snapshot:blobs"]) := by decide +kernel

theorem empty_at_end_precedes_availability :
    readResult (state 0) (.range 4 9) = (.ok [], ["snapshot:blobs"]) := by decide +kernel

theorem missing_row_fails_before_file :
    readResult { stored with db := [] } = (.error .missingBlob, ["snapshot:blobs"]) := by decide +kernel

theorem absent_row_exposes_scan_failure :
    readResult { stored with db := [], scanFault := some (0, primary) } =
      (.error (.host primary), ["snapshot:blobs"]) := by decide +kernel

theorem snapshot_failure_is_not_absence :
    readResult (fail stored 0) = (.error (.host primary), ["snapshot:blobs"]) := by decide +kernel

theorem out_of_range_precedes_availability :
    readResult (state 0) (.range 5 0) = (.error (.range 5 4 4), ["snapshot:blobs"]) := by decide +kernel

theorem unavailable_does_not_open_file :
    readResult (state 0) = (.error .unavailable, ["snapshot:blobs"]) := by decide +kernel

theorem inline_slice_requires_no_file :
    readResult (state 1 (.blob bytes)) (.range 1 2) = (.ok [20, 30], ["snapshot:blobs", "append"]) := by decide +kernel

theorem overflowing_range_length_clamps_to_size :
    readResult (state 1 (.blob bytes)) (.range 2 18446744073709551615) =
      (.ok [30, 40], ["snapshot:blobs", "append"]) := by decide +kernel

theorem short_inline_is_explicit_without_healing :
    readResult (state 1 (.blob ByteArray.empty)) = (.error .shortInline, ["snapshot:blobs"]) := by decide +kernel

theorem first_row_precedes_later_scan_failure :
    readResult { (state 1 (.blob bytes)) with scanFault := some (0, primary) } =
      (.ok [10, 20, 30, 40], ["snapshot:blobs", "append"]) := by decide +kernel

theorem first_row_decode_error_precedes_later_scan_failure :
    readResult { stored with db := [("blobs", [[("root", .blob root)]])], scanFault := some (0, primary) } =
      (.error (.columnType 1 "size" .null), ["snapshot:blobs"]) := by decide +kernel

theorem successful_file_read_closes_handle : readResult =
    (.ok [10, 20, 30, 40], ["snapshot:blobs", "open:cas_payload", "transfer", "close"]) := by decide +kernel

theorem ranged_file_read_transfers_only_the_range : readResult stored (.range 1 2) =
    (.ok [20, 30], ["snapshot:blobs", "open:cas_payload", "transfer", "close"]) := by decide +kernel

theorem other_open_failure_does_not_heal : readResult (fail stored 1) =
    (.error (.host primary), ["snapshot:blobs", "open:cas_payload"]) := by decide +kernel

theorem missing_open_heals_and_preserves_error : readResult { stored with files := [] } =
    (.error (.host absent), ["snapshot:blobs", "open:cas_payload"] ++ healing) := by decide +kernel

theorem healing_error_overrides_missing_open : readResult (fail { stored with files := [] } 2) =
    (.error (.host primary), ["snapshot:blobs", "open:cas_payload", "begin"]) := by decide +kernel

theorem other_transfer_failure_closes_without_healing : readResult (fail stored 2) =
    (.error (.host primary), ["snapshot:blobs", "open:cas_payload", "transfer", "close"]) := by decide +kernel

theorem truncated_transfer_closes_before_healing :
    readResult { stored with files := [(("cas_payload", root), ByteArray.empty)] } =
      (.error (.host truncated), ["snapshot:blobs", "open:cas_payload", "transfer", "close"] ++ healing) := by decide +kernel

theorem healing_error_overrides_truncated_transfer_after_close :
    readResult (fail { stored with files := [(("cas_payload", root), ByteArray.empty)] } 4) =
      (.error (.host primary), ["snapshot:blobs", "open:cas_payload", "transfer", "close", "begin"]) := by decide +kernel

theorem inline_output_failure_has_no_file_or_healing : readResult (fail (state 1 (.blob bytes)) 1) =
    (.error (.host primary), ["snapshot:blobs", "append"]) := by decide +kernel

theorem close_failure_discards_transferred_output : readResult (fail stored 3) =
    (.error (.host primary), ["snapshot:blobs", "open:cas_payload", "transfer", "close"]) := by decide +kernel

theorem terminal_count_must_match_collected_output :
    publish Error.protocol (.ok 3) { stored with output := [10, 20, 30, 40] } = .error .protocol := by decide +kernel

end Synchronicity.CasReadProgramProofs
