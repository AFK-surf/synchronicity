import VerifiedCore.Cas.Read
import Synchronicity.Prelude
import Init.Data.ByteArray.Lemmas

/-! Executions of the whole read program. The scripted interpreter
supplies raw observations only, without availability or recovery decisions. -/
namespace Synchronicity.CasReadProgramProofs
open VerifiedCore.Host VerifiedCore.Cas.Read
set_option Elab.async false

/-- The production read owns its initial raw observation; Rust supplies no
decoded row, bitmap or coverage snapshot to the operation. -/
@[rust_impl "cas-local-read-operation"]
theorem read_observes_metadata (key : ByteArray) (request : Request) :
    ∃ resume, (read key request).run = .request
      (.right (.left (.snapshot ⟨"blobs", [("root", .blob key)], []⟩
        ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"]))) resume := by
  exact ⟨_, rfl⟩

/-- Every next nonempty chunk request uses an explicit bound; this is the
actual program constructor for arbitrary file and offset. -/
theorem next_chunk_request_is_bounded (fuel : Nat) (handle : UInt64)
    (offset remaining : Nat) :
    ∃ resume,
      (readChunks (fuel + 1) handle offset (remaining + 1)).run =
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

theorem completed_chunks_do_not_retain_payload (fuel : Nat) (handle : UInt64) (offset : Nat) :
    (readChunks fuel handle offset 0).run = .pure (.ok (.ok ())) := by
  cases fuel <;> rfl

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
  appendFailure : Option Failure := none

private inductive Event where
  | snapshot | begin | size | invalidate | clock | copy | delete | commit | rollback
  | open | close (handle : UInt64)
  | readAt (handle offset count : UInt64)
  | append (count : Nat)
  deriving DecidableEq

private def execute (script : Script) : Nat → List UInt8 →
    Program Effects (Except Error UInt64) →
      Option (Except Error UInt64 × List UInt8 × List Event)
  | 0, _, _ => none
  | _ + 1, output, .pure result => some (result, output, [])
  | fuel + 1, output, .request effect resume =>
    let step (event : Event) (next : Program Effects (Except Error UInt64)) :=
      (execute script fuel output next).map fun (result, bytes, trace) => (result, bytes, event :: trace)
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
          | .close handle => step (.close handle) (resume (.ok ()))
        | .right effect => match effect with
          | .left effect => match effect with
            | .nowNs => step .clock (resume (.ok 123))
          | .right effect => match effect with
            | .append bytes => match script.appendFailure with
              | some failure => step (.append bytes.size) (resume (.error failure))
              | none => (execute script fuel (output ++ bytes.data.toList) (resume (.ok ()))).map
                  fun (result, output, trace) => (result, output, .append bytes.size :: trace)

/-- A raw output buffer is an unobservable prefix until successful termination.
The completed byte count must agree with the collected append effects. -/
private def observe : Option (Except Error UInt64 × List UInt8 × List Event) →
    Option (Except Error (List UInt8) × List Event)
  | none => none
  | some (.error error, _, trace) => some (.error error, trace)
  | some (.ok count, output, trace) =>
    some ((if count.toNat == output.length then .ok output else .error .protocol), trace)

private def run (script : Script := {}) (request : Request := .all) :=
  observe (execute script 30 [] (read root request).run)

theorem failed_command_never_publishes_prefix (error : Error) (partialBytes : List UInt8)
    (trace : List Event) : observe (some (.error error, partialBytes, trace)) =
      some (.error error, trace) := by rfl

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
      some (.ok [20, 30], [.snapshot, .append 2]) := by decide

theorem overflowing_range_length_clamps_to_size :
    run { scan := ⟨[row 1 (.blob bytes)], none⟩ } (.range 2 18446744073709551615) =
      some (.ok [30, 40], [.snapshot, .append 2]) := by decide

theorem short_inline_is_explicit_without_healing :
    run { scan := ⟨[row 1 (.blob ByteArray.empty)], none⟩ } =
      some (.error .shortInline, [.snapshot]) := by decide

theorem first_row_precedes_later_scan_failure :
    run { scan := ⟨[row 1 (.blob bytes), []], some ioFailure⟩ } =
      some (.ok [10, 20, 30, 40], [.snapshot, .append 4]) := by decide

theorem first_row_decode_error_precedes_later_scan_failure :
    run { scan := ⟨[[], row], some ioFailure⟩ } =
      some (.error .malformed, [.snapshot]) := by decide

theorem successful_file_read_closes_handle : run {} =
    some (.ok [10, 20, 30, 40], [.snapshot, .open, .readAt 9 0 4, .append 4, .close 9]) := by decide

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
    observe (execute { readReply := .error ⟨ioFailure, .other⟩ } 30 []
      (do readPayload root 17 65537; return 65537 : Action UInt64).run) =
      some (.error (.host ioFailure), [.open, .readAt 9 17 65536, .close 9]) := by decide

theorem output_failure_closes_without_healing :
    run { appendFailure := some ioFailure } =
      some (.error (.host ioFailure),
        [.snapshot, .open, .readAt 9 0 4, .append 4, .close 9]) := by decide

theorem output_failure_is_not_file_failure (bytes : ByteArray) (failure : Failure) :
    ∃ resume, (requestOutput bytes).run =
      .request (.right (.right (.right (.right (.append bytes))))) resume ∧
      resume (.error failure) = .pure (.error (.host failure)) := by
  exact ⟨_, rfl, rfl⟩

theorem inline_output_failure_has_no_file_or_healing :
    run { scan := ⟨[row 1 (.blob bytes)], none⟩, appendFailure := some ioFailure } =
      some (.error (.host ioFailure), [.snapshot, .append 4]) := by decide

/-- The interpreter collects append effects in order; completion carries only
the count. This fixture runs the production chunk emitter twice, with no
second read implementation or payload accumulator in the program. -/
theorem appended_chunks_preserve_order_and_terminal_count :
    execute {} 10 []
      (do inlineChunks 1 ⟨#[10, 20]⟩ 0 2
          inlineChunks 1 ⟨#[30, 40]⟩ 0 2
          return 4 : Action UInt64).run =
      some (.ok 4, [10, 20, 30, 40], [.append 2, .append 2]) := by decide

theorem next_inline_append_has_bounded_slice (fuel offset remaining : Nat) (bytes : ByteArray) :
    ∃ resume,
      (inlineChunks (fuel + 1) bytes offset (remaining + 1)).run =
        .request (.right (.right (.right (.right (.append
          (bytes.extract offset (offset + min (remaining + 1) chunkSize))))))) resume ∧
      (bytes.extract offset (offset + min (remaining + 1) chunkSize)).size ≤ chunkSize := by
  refine ⟨_, rfl, ?_⟩
  rw [ByteArray.size_extract]
  exact le_trans (Nat.sub_le_sub_right (Nat.min_le_left _ _) offset)
    (by simp)

end Synchronicity.CasReadProgramProofs
