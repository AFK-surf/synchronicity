import VerifiedCore.Cas.Read
import Synchronicity.Prelude

/-! Executions of the whole staged read program. The scripted interpreter
supplies raw observations only, without availability or recovery decisions. -/
namespace Synchronicity.CasReadProgramProofs
open VerifiedCore.Host VerifiedCore.Cas.Read
set_option Elab.async false

/-- Every next nonempty chunk request uses an explicit bound; this is the
actual program constructor for arbitrary file, offset and accumulated bytes. -/
theorem next_chunk_request_is_bounded (fuel : Nat) (handle : UInt64)
    (offset remaining : Nat) (output : List ByteArray) :
    ∃ resume,
      (readChunks (fuel + 1) handle offset (remaining + 1) output).run =
        .request (.right (.right (.left (.readAt handle offset.toUInt64
          (min (remaining + 1) chunkSize).toUInt64)))) resume ∧
      min (remaining + 1) chunkSize ≤ chunkSize := by
  exact ⟨_, rfl, Nat.min_le_right _ _⟩

/-- An unrelated open error is returned directly, for every original token;
it cannot start a repair transaction. -/
theorem unrelated_open_failure_is_terminal (key : ByteArray) (offset count : Nat)
    (failure : Failure) :
    ∃ resume, (readPayload key offset count).run =
        .request (.right (.right (.left (.open "cas_payload" key)))) resume ∧
      resume (.error ⟨failure, .other⟩) = .pure (.error (.host failure)) := by
  exact ⟨_, rfl, rfl⟩

private def root : ByteArray := ⟨Array.replicate 32 0⟩
private def bytes : ByteArray := ⟨#[10, 20, 30, 40]⟩

theorem completed_chunks_flatten_in_read_order :
    (match (readChunks 0 9 4 0 [⟨#[30, 40]⟩, ⟨#[10, 20]⟩]).run with
      | .pure (.ok (.ok data)) => data.data.toList
      | _ => []) = [10, 20, 30, 40] := by decide

private def ioFailure : Failure := ⟨1, 71⟩
private def healFailure : Failure := ⟨1, 72⟩
private def row (complete : Int64 := 1) (inline : Cell := .null) : Row :=
  [.blob root, .integer 4, .integer complete, .null, inline, .integer 0, .integer 0]

private structure Script where
  scan : Scan := ⟨[row], none⟩
  snapshotFailure : Option Failure := none
  opened : FileReply UInt64 := .ok 9
  readReply : FileReply ByteArray := .ok bytes
  beginFailure : Option Failure := none

private inductive Event where
  | snapshot | begin | size | invalidate | clock | copy | delete | commit | rollback
  | open | close (handle : UInt64)
  | readAt (handle offset count : UInt64)
  deriving DecidableEq

private def execute (script : Script) : Nat →
    Program Effects (Except Error ByteArray) →
      Option (Except Error (List UInt8) × List Event)
  | 0, _ => none
  | _ + 1, .pure result => some (result.map (fun value => value.data.toList), [])
  | fuel + 1, .request effect resume =>
    let step (event : Event) (next : Program Effects (Except Error ByteArray)) :=
      (execute script fuel next).map fun (result, trace) => (result, event :: trace)
    match effect with
    | .left effect => match effect with
      | .begin => step .begin (resume (match script.beginFailure with
          | none => .ok 7 | some failure => .error failure))
      | .commit _ => step .commit (resume (.ok ()))
      | .rollback _ => step .rollback (resume (.ok ()))
      | .readRows _ _ _ _ _ _ => step .size (resume (.ok [[.integer 4]]))
      | _ => none
    | .right effect => match effect with
      | .left effect => match effect with
        | .snapshot selection columns =>
          if selection == ⟨"blobs", [("root", .blob root)], []⟩ &&
              columns == ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"] then
            step .snapshot (resume (match script.snapshotFailure with
              | none => .ok script.scan | some failure => .error failure))
          else none
        | .update .. => step .invalidate (resume (.ok 1))
        | .copyRows .. => step .copy (resume (.ok 1))
        | .delete .. => step .delete (resume (.ok 1))
      | .right effect => match effect with
        | .left effect => match effect with
          | .open space key => if space == "cas_payload" && key == root then
              step .open (resume script.opened) else none
          | .readAt handle offset count =>
              step (.readAt handle offset count) (resume script.readReply)
          | .close handle => step (.close handle) (resume ())
        | .right effect => match effect with
          | .nowNs => step .clock (resume (.ok 123))

private def run (script : Script := {}) (request : Request := .all) :=
  execute script 30 (read root request).run

theorem empty_precedes_availability_and_file :
    run { scan := ⟨[row 0], none⟩ } (.range 2 0) =
      some (.ok [], [.snapshot]) := by decide

theorem empty_at_end_precedes_availability :
    run { scan := ⟨[row 0], none⟩ } (.range 4 9) =
      some (.ok [], [.snapshot]) := by decide

theorem missing_row_fails_before_file :
    run { scan := ⟨[], none⟩ } = some (.error .missingBlob, [.snapshot]) := by decide

theorem absent_row_exposes_scan_failure :
    run { scan := ⟨[], some ioFailure⟩ } =
      some (.error (.host ioFailure), [.snapshot]) := by decide

theorem snapshot_failure_is_not_absence :
    run { snapshotFailure := some ioFailure } =
      some (.error (.host ioFailure), [.snapshot]) := by decide

theorem out_of_range_precedes_availability :
    run { scan := ⟨[row 0], none⟩ } (.range 5 0) =
      some (.error (.range 5 4 4), [.snapshot]) := by decide

theorem unavailable_does_not_open_file :
    run { scan := ⟨[row 0], none⟩ } = some (.error .unavailable, [.snapshot]) := by decide

theorem inline_slice_requires_no_file :
    run { scan := ⟨[row 1 (.blob bytes)], none⟩ } (.range 1 2) =
      some (.ok [20, 30], [.snapshot]) := by decide

theorem overflowing_range_length_clamps_to_size :
    run { scan := ⟨[row 1 (.blob bytes)], none⟩ } (.range 2 18446744073709551615) =
      some (.ok [30, 40], [.snapshot]) := by decide

theorem short_inline_is_explicit_without_healing :
    run { scan := ⟨[row 1 (.blob ByteArray.empty)], none⟩ } =
      some (.error .shortInline, [.snapshot]) := by decide

theorem first_row_precedes_later_scan_failure :
    run { scan := ⟨[row 1 (.blob bytes), []], some ioFailure⟩ } =
      some (.ok [10, 20, 30, 40], [.snapshot]) := by decide

theorem first_row_decode_error_precedes_later_scan_failure :
    run { scan := ⟨[[], row], some ioFailure⟩ } =
      some (.error .malformed, [.snapshot]) := by decide

theorem successful_file_read_closes_handle : run {} =
    some (.ok [10, 20, 30, 40], [.snapshot, .open, .readAt 9 0 4, .close 9]) := by decide

theorem other_open_failure_does_not_heal :
    run { opened := .error ⟨ioFailure, .other⟩ } =
      some (.error (.host ioFailure), [.snapshot, .open]) := by decide

theorem missing_open_heals_and_preserves_error :
    run { opened := .error ⟨ioFailure, .missing⟩ } =
      some (.error (.host ioFailure), [.snapshot, .open, .begin, .size,
        .invalidate, .clock, .copy, .delete, .commit]) := by decide

theorem healing_error_overrides_missing_open :
    run { opened := .error ⟨ioFailure, .missing⟩, beginFailure := some healFailure } =
      some (.error (.host healFailure), [.snapshot, .open, .begin]) := by decide

theorem other_read_failure_closes_without_healing :
    run { readReply := .error ⟨ioFailure, .other⟩ } =
      some (.error (.host ioFailure), [.snapshot, .open, .readAt 9 0 4, .close 9]) := by decide

theorem truncated_read_closes_before_healing :
    run { readReply := .error ⟨ioFailure, .shortRead⟩ } =
      some (.error (.host ioFailure), [.snapshot, .open, .readAt 9 0 4, .close 9,
        .begin, .size, .invalidate, .clock, .copy, .delete, .commit]) := by decide

theorem missing_read_closes_before_healing :
    run { readReply := .error ⟨ioFailure, .missing⟩ } =
      some (.error (.host ioFailure), [.snapshot, .open, .readAt 9 0 4, .close 9,
        .begin, .size, .invalidate, .clock, .copy, .delete, .commit]) := by decide

theorem healing_error_overrides_truncated_read_after_close :
    run { readReply := .error ⟨ioFailure, .shortRead⟩, beginFailure := some healFailure } =
      some (.error (.host healFailure),
        [.snapshot, .open, .readAt 9 0 4, .close 9, .begin]) := by decide

theorem malformed_success_closes_without_healing :
    run { readReply := .ok ByteArray.empty } =
      some (.error .protocol, [.snapshot, .open, .readAt 9 0 4, .close 9]) := by decide

/-- A large request still issues only one bounded chunk at a time. The failure
fixture avoids constructing large payloads in the proof evaluator. -/
theorem large_read_first_chunk_is_bounded :
    execute { readReply := .error ⟨ioFailure, .other⟩ } 30
      (readPayload root 17 65537).run =
      some (.error (.host ioFailure), [.open, .readAt 9 17 65536, .close 9]) := by decide

end Synchronicity.CasReadProgramProofs
