import VerifiedCore.Cas.Read
import Synchronicity.Handlers

/-! Executions of the whole read program. The scripted interpreter
supplies raw observations only, without availability or recovery decisions. -/
namespace Synchronicity.CasReadProgramProofs
open VerifiedCore.Host VerifiedCore.Cas.Read
set_option Elab.async false

/-- The production read owns its initial raw observation; Rust supplies no
decoded row, bitmap or coverage snapshot to the operation. -/
theorem read_observes_metadata (key : ByteArray) (request : Request) :
    ∃ resume, (read key request).run = .request
      (.right (.left (.snapshot ⟨"blobs", [("root", .blob key)], []⟩
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

private def root : ByteArray := ⟨Array.replicate 32 0⟩
private def bytes : ByteArray := ⟨#[10, 20, 30, 40]⟩

private def ioFailure : Failure := ⟨1, 71⟩
private def healFailure : Failure := ⟨1, 72⟩
private def row (complete : Int64 := 1) (inline : Cell := .null) : Row :=
  [.blob root, .integer 4, .integer complete, .null, inline, .integer 0, .integer 0]

private structure Script where
  scan : Scan := ⟨[row], none⟩
  snapshotFailure : Option Failure := none
  opened : FileReply UInt64 := .ok 9
  /-- The bytes a successful transfer moves into the output. -/
  payload : ByteArray := bytes
  transferReply : FileReply Unit := .ok ()
  beginFailure : Option Failure := none
  appendFailure : Option Failure := none

private inductive Event where
  | snapshot | begin | size | invalidate | clock | copy | delete | commit | rollback
  | open | close (handle : UInt64)
  | transfer (handle offset count : UInt64)
  | append (count : Nat)
  deriving DecidableEq

/-- The script and the bytes the host has moved into the private output. -/
private structure State where
  script : Script
  output : List UInt8 := []

private def step (state : State) (event : Event) (value : A) : Option (Event × A × State) :=
  some (event, value, state)

private instance : Handlers.Handler Storage State Event where
  handle
    | .begin, s => step s .begin (match s.script.beginFailure with
        | none => .ok 7 | some failure => .error failure)
    | .commit _, s => step s .commit (.ok ())
    | .rollback _, s => step s .rollback (.ok ())
    | .readRows _ _ _ _ _ _, s => step s .size (.ok [[.integer 4]])
    | _, _ => none

private instance : Handlers.Handler Access State Event where
  handle
    | .snapshot selection columns, s =>
      if selection == ⟨"blobs", [("root", .blob root)], []⟩ &&
          columns == ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"] then
        step s .snapshot (match s.script.snapshotFailure with
          | none => .ok s.script.scan | some failure => .error failure)
      else none
    | .update .., s => step s .invalidate (.ok 1)
    | .copyRows .., s => step s .copy (.ok 1)
    | .delete .., s => step s .delete (.ok 1)

private instance : Handlers.Handler FileIO State Event where
  handle
    | .open space key, s =>
      if space == "cas_payload" && key == root then step s .open s.script.opened else none
    | .readAt _ _ _, _ => none
    | .transfer handle offset count, s => match s.script.transferReply with
      | .error failure => step s (.transfer handle offset count) (.error failure)
      | .ok () => some (.transfer handle offset count, .ok (), { s with output := s.output ++
          (s.script.payload.extract offset.toNat (offset.toNat + count.toNat)).data.toList })
    | .close handle, s => step s (.close handle) (.ok ())

private instance : Handlers.Handler Clock State Event where
  handle
    | .nowNs, s => step s .clock (.ok 123)

private instance : Handlers.Handler Output State Event where
  handle
    | .append bytes, s => match s.script.appendFailure with
      | some failure => step s (.append bytes.size) (.error failure)
      | none => some (.append bytes.size, .ok (), { s with output := s.output ++ bytes.data.toList })

/-- A raw output buffer is an unobservable prefix until successful termination.
The completed byte count must agree with the collected append effects. -/
private def observe : Option (Except Error UInt64 × State × List Event) →
    Option (Except Error (List UInt8) × List Event)
  | none => none
  | some (.error error, _, trace) => some (.error error, trace)
  | some (.ok count, state, trace) =>
    some ((if count.toNat == state.output.length then .ok state.output else .error .protocol), trace)

private def run (script : Script := {}) (request : Request := .all) :=
  observe (Handlers.execute 30 (read root request).run (⟨script, []⟩ : State))

theorem failed_command_never_publishes_prefix (error : Error) (partialBytes : List UInt8)
    (trace : List Event) : observe (some (.error error, ⟨{}, partialBytes⟩, trace)) =
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
    some (.ok [10, 20, 30, 40], [.snapshot, .open, .transfer 9 0 4, .close 9]) := by decide

theorem ranged_file_read_transfers_only_the_range : run {} (.range 1 2) =
    some (.ok [20, 30], [.snapshot, .open, .transfer 9 1 2, .close 9]) := by decide

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

/-- A transfer the host could not complete for any reason other than the
object being missing or short, including a sink that cannot grow, is
returned as it was reported, after the handle is closed and without repair. -/
theorem other_transfer_failure_closes_without_healing :
    run { transferReply := .error ⟨ioFailure, .other⟩ } =
      some (.error (.host ioFailure), [.snapshot, .open, .transfer 9 0 4, .close 9]) := by decide

theorem truncated_transfer_closes_before_healing :
    run { transferReply := .error ⟨ioFailure, .shortRead⟩ } =
      some (.error (.host ioFailure), [.snapshot, .open, .transfer 9 0 4, .close 9,
        .begin, .size, .invalidate, .clock, .copy, .delete, .commit]) := by decide

theorem missing_transfer_closes_before_healing :
    run { transferReply := .error ⟨ioFailure, .missing⟩ } =
      some (.error (.host ioFailure), [.snapshot, .open, .transfer 9 0 4, .close 9,
        .begin, .size, .invalidate, .clock, .copy, .delete, .commit]) := by decide

theorem healing_error_overrides_truncated_transfer_after_close :
    run { transferReply := .error ⟨ioFailure, .shortRead⟩, beginFailure := some healFailure } =
      some (.error (.host healFailure),
        [.snapshot, .open, .transfer 9 0 4, .close 9, .begin]) := by decide

/-- A large request is still one transfer; no chunking policy lives in the
program. The failure fixture avoids materializing a large payload. -/
theorem large_read_is_one_transfer :
    observe (Handlers.execute 30
      (do readPayload root 17 65537; return 65537 : Action UInt64).run
      (⟨{ transferReply := .error ⟨ioFailure, .other⟩ }, []⟩ : State)) =
      some (.error (.host ioFailure), [.open, .transfer 9 17 65537, .close 9]) := by decide

theorem output_failure_is_not_file_failure (bytes : ByteArray) (failure : Failure) :
    ∃ resume, (requestOutput bytes).run =
      .request (.right (.right (.right (.right (.append bytes))))) resume ∧
      resume (.error failure) = .pure (.error (.host failure)) := by
  exact ⟨_, rfl, rfl⟩

theorem inline_output_failure_has_no_file_or_healing :
    run { scan := ⟨[row 1 (.blob bytes)], none⟩, appendFailure := some ioFailure } =
      some (.error (.host ioFailure), [.snapshot, .append 4]) := by decide

/-- The interpreter collects output in order and completion carries only the
count: a terminal count that disagrees with the collected bytes is a protocol
failure, never a shorter or longer published result. -/
theorem terminal_count_must_match_collected_output :
    (Handlers.execute 10
      (do requestOutput ⟨#[10, 20]⟩
          requestOutput ⟨#[30, 40]⟩
          return 3 : Action UInt64).run (⟨{}, []⟩ : State)).map
        (fun (value, state, trace) => (value, state.output, trace)) =
      some (.ok 3, [10, 20, 30, 40], [.append 2, .append 2]) ∧
    observe (Handlers.execute 10
      (do requestOutput ⟨#[10, 20]⟩
          requestOutput ⟨#[30, 40]⟩
          return 3 : Action UInt64).run (⟨{}, []⟩ : State)) =
      some (.error .protocol, [.append 2, .append 2]) := by decide

end Synchronicity.CasReadProgramProofs
