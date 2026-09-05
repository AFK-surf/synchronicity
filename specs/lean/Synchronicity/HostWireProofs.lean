import VerifiedCore.Host.Wire
import VerifiedCore.Entry

/-! Lean-side native packet transport and actual continuation behavior.
These proofs do not establish C ownership, Rust packet decoding, or host I/O.
-/
namespace Synchronicity.HostWireProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Host.Wire
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

-- The transport needs decidable result equality, not the mathematical model
-- prelude. Keep this proof-local instance out of the executable core.
@[reducible] private def replyDecEq [DecidableEq A] : DecidableEq (Reply A) := by
  intro left right
  cases left with
  | error a =>
    cases right with
    | error b => exact if h : a = b then .isTrue (by cases h; rfl)
        else .isFalse (by intro h'; cases h'; exact h rfl)
    | ok _ => exact .isFalse (by intro h; cases h)
  | ok a =>
    cases right with
    | error _ => exact .isFalse (by intro h; cases h)
    | ok b => exact if h : a = b then .isTrue (by cases h; rfl)
        else .isFalse (by intro h'; cases h'; exact h rfl)

attribute [local instance] replyDecEq

theorem decode_success_consumes_all (expected : UInt8) (read : Reader A)
    (input : ByteArray) (value : A)
    (success : decodeReply expected read input = .ok value) :
    ∃ cursor, (readReply expected read).run ⟨input, 0⟩ = .ok (.ok value, cursor) ∧
      cursor.offset = input.size := by
  unfold decodeReply at success
  cases parsed : (readReply expected read).run ⟨input, 0⟩ with
  | error err => simp [parsed] at success
  | ok result =>
    obtain ⟨reply, cursor⟩ := result
    simp only [parsed] at success
    split at success
    next consumed =>
      cases success
      exact ⟨cursor, rfl, by simpa using consumed⟩
    next => contradiction

theorem parser_failure_is_protocol_failure (expected : UInt8) (read : Reader A)
    (input : ByteArray)
    (failed : (readReply expected read).run ⟨input, 0⟩ = .error ()) :
    decodeReply expected read input = .error protocolFailure := by
  simp [decodeReply, failed]

theorem terminal_cannot_restart (result : Reply ByteArray) (input : ByteArray) :
    resume (.pure result) input = .pure (.error protocolFailure) := rfl

theorem rejected_terminal_stays_terminal (result : Reply ByteArray)
    (first second : ByteArray) :
    resume (resume (.pure result) first) second = .pure (.error protocolFailure) := rfl

private def b (data : List UInt8) : ByteArray := ⟨data.toArray⟩

-- Version, exact pending kind and full-consumption checks. No reader accepts
-- the tag of a different successful operation, even if its payload is empty.
theorem wrong_version_rejected :
    reply (.commit 7) (b [2, 17]) = .error protocolFailure := by decide

theorem wrong_pending_kind_rejected :
    reply (.commit 7) (b [1, 18]) = .error protocolFailure := by decide

theorem trailing_byte_rejected :
    reply (.commit 7) (b [1, 17, 0]) = .error protocolFailure := by decide

theorem exact_unit_reply_accepted :
    reply (.commit 7) (b [1, 17]) = .ok () := by decide

-- A generic failure packet is deliberately valid for any pending effect.
-- Both the full-width token and the complete 32-bit error code survive.
theorem failure_token_preserved :
    reply (.begin) (b [1, 0, 255, 255, 255, 255, 0, 0, 0, 0,
      239, 205, 171, 137, 103, 69, 35, 1]) =
      .error ⟨0xffffffff, 0x0123456789abcdef⟩ := by rfl

theorem oversized_failure_code_rejected :
    reply (.begin) (b [1, 0, 0, 0, 0, 0, 1, 0, 0, 0,
      1, 0, 0, 0, 0, 0, 0, 0]) = .error protocolFailure := by rfl

-- Raw bytes retain absent versus present-empty. Fixtures use parser output
-- views since ByteArray has no proof-level decidable equality instance.
private def byteReplyView : Reply (Option ByteArray) → Option (Option (List UInt8))
  | .error _ => none
  | .ok none => some none
  | .ok (some bytes) => some (some bytes.toList)

theorem absent_bytes_preserved :
    byteReplyView (reply (.readBytes "raw" .empty) (b [1, 22, 0])) = some none := by decide

theorem empty_bytes_preserved :
    byteReplyView (reply (.readBytes "raw" .empty)
      (b [1, 22, 1, 0, 0, 0, 0, 0, 0, 0, 0])) = some (some []) := by
  change some (some ByteArray.empty.toList) = some (some [])
  rw [ByteArray.toList_empty]

private def cellView : Cell → Nat × Int × List UInt8
  | .null => (0, 0, [])
  | .integer n => (1, n.toInt, [])
  | .text s => (2, 0, s.toUTF8.toList)
  | .blob bytes => (3, 0, bytes.toList)
  | .real bits => (4, bits.toNat, [])
  | .rawText bytes => (5, 0, bytes.data.toList)

private def cellReplyView : Reply (List Row) → Option (List (List (Nat × Int × List UInt8)))
  | .error _ => none
  | .ok rows => some (rows.map (List.map cellView))

private def oneCell (encoded : List UInt8) :=
  cellReplyView (reply (.readRows 7 "raw" [] [])
    (b ([1, 19, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0] ++ encoded)))

-- Check each raw-cell representation independently. Combining all the closed
-- state-monad reductions into a single fixture needlessly duplicates work in
-- the kernel; the representations and full row-reply envelope are unchanged.
theorem raw_cell_distinctions_preserved :
    oneCell [0] = some [[(0, 0, [])]] ∧
    oneCell [3, 0, 0, 0, 0, 0, 0, 0, 0] = some [[(3, 0, [])]] ∧
    oneCell [2, 0, 0, 0, 0, 0, 0, 0, 0] = some [[(2, 0, [])]] ∧
    oneCell [1, 255, 255, 255, 255, 255, 255, 255, 255] = some [[(1, -1, [])]] ∧
    oneCell [1, 0, 0, 0, 0, 0, 0, 0, 128] = some [[(1, -9223372036854775808, [])]] := by
  refine ⟨rfl, ?_, ?_, rfl, rfl⟩
  · change some [[(3, 0, ByteArray.empty.toList)]] = some [[(3, 0, [])]]
    rw [ByteArray.toList_empty]
  · change some [[(2, 0, "".toUTF8.toList)]] = some [[(2, 0, [])]]
    simp

theorem real_bits_preserved :
    oneCell [4, 255, 255, 255, 255, 255, 255, 255, 255] =
      some [[(4, 18446744073709551615, [])]] := by rfl

theorem invalid_text_bytes_preserved :
    oneCell [5, 3, 0, 0, 0, 0, 0, 0, 0, 255, 0, 254] =
      some [[(5, 0, [255, 0, 254])]] := by
  change some [[(5, 0, ((b [1, 19, 1, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 5, 3, 0, 0, 0, 0, 0, 0, 0,
    255, 0, 254]).extract 27 30).data.toList)]] = _
  simp [ByteArray.data_extract, b]

private def transactionalRead : State :=
  (transaction (fun _ => do
    let value ← perform (.readBytes "raw" .empty)
    return value.getD .empty)).run

private def begunRead : State :=
  resume transactionalRead (b [1, 16, 7, 0, 0, 0, 0, 0, 0, 0])

private def malformedRead : State := resume begunRead (b [1, 17])

/-- Malformed input is delivered to the pending program as a failed read.
It does not replace the program and skip its rollback continuation. -/
theorem malformed_read_requests_rollback :
    ∃ next, malformedRead = .request (.rollback 7) next := ⟨_, rfl⟩

theorem successful_rollback_preserves_primary_failure :
    resume malformedRead (b [1, 18]) = .pure (.error protocolFailure) := by rfl

theorem failed_rollback_preserves_primary_failure :
    resume malformedRead
      (b [1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0]) =
      .pure (.error protocolFailure) := by rfl

/-- Capability injection changes neither existing packets nor reply behavior.
These concern the actual native exports, not a separate transport model. -/
theorem native_storage_packet (state : State) :
    nativePacket (state.mapEffects EffectSum.left) = packet state := by
  cases state with
  | pure result => cases result <;> rfl
  | request effect next => rfl

theorem native_storage_resume (state : State) (input : ByteArray) :
    nativeResume (state.mapEffects EffectSum.left) input =
      (resume state input).mapEffects EffectSum.left := by
  cases state <;> rfl

theorem invalid_crypto_boolean_rejected :
    cryptoReply (.validateEd25519 []) (b [1, 27, 2]) = .error protocolFailure := by decide

theorem crypto_wrong_reply_kind_rejected :
    cryptoReply (.validateEd25519 []) (b [1, 26, 1]) = .error protocolFailure := by decide

theorem crypto_false_is_not_host_failure :
    cryptoReply (.validateEd25519 []) (b [1, 27, 0]) = .ok false := by decide

private def cryptoTransaction : NativeState :=
  (transactionOver EffectSum.left id (fun _ => do
    let _ ← performOver id (.right (.left (.validateEd25519 [])))
    return ByteArray.empty) : OperationOver NativeEffects Failure ByteArray).run

private def pendingCrypto : NativeState :=
  nativeResume cryptoTransaction (b [1, 16, 7, 0, 0, 0, 0, 0, 0, 0])

theorem malformed_crypto_requests_rollback :
    ∃ next, nativeResume pendingCrypto (b [1, 27, 2]) =
      .request (.left (.rollback 7)) next := ⟨_, rfl⟩

theorem crypto_rollback_preserves_protocol_error :
    nativeResume (nativeResume pendingCrypto (b [1, 27, 2])) (b [1, 18]) =
      .pure (.error protocolFailure) := by rfl

theorem file_missing_preserves_original_error :
    fileReply (.open "cas_payload" .empty)
      (b [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0]) =
      .error ⟨⟨1, 9⟩, .missing⟩ := by rfl

theorem invalid_file_classification_is_protocol_failure :
    fileReply (.open "cas_payload" .empty)
      (b [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 3]) =
      .error ⟨protocolFailure, .other⟩ := by rfl

theorem file_reply_rejects_storage_failure_without_classification :
    fileReply (.readAt 7 0 1)
      (b [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]) =
      .error ⟨protocolFailure, .other⟩ := by rfl

theorem file_close_requires_exact_acknowledgement :
    fileReply (.close 7) (b [1, 35, 0]) = .error protocolFailure := by decide

theorem file_close_accepts_acknowledgement :
    fileReply (.close 7) (b [1, 35]) = .ok () := by decide

theorem snapshot_rejects_invalid_trailing_failure_flag :
    accessReply (.snapshot ⟨"blobs", [], []⟩ [])
      (b [1, 29, 0, 0, 0, 0, 0, 0, 0, 0, 2]) = .error protocolFailure := by rfl

theorem update_rejects_copy_reply :
    accessReply (.update 7 ⟨"blobs", [], []⟩ [])
      (b [1, 31, 0, 0, 0, 0, 0, 0, 0, 0]) = .error protocolFailure := by decide

theorem clock_rejects_wrong_reply_kind :
    clockReply .nowNs (b [1, 33, 0, 0, 0, 0, 0, 0, 0, 0]) = .error protocolFailure := by decide

theorem output_append_requires_exact_acknowledgement :
    outputReply (.append (b [41, 42])) (b [1, 37, 0]) = .error protocolFailure := by decide

theorem output_append_accepts_acknowledgement :
    outputReply (.append (b [41, 42])) (b [1, 37]) = .ok () := by decide

theorem output_append_rejects_wrong_reply_kind :
    outputReply (.append (b [41, 42])) (b [1, 35]) = .error protocolFailure := by decide

theorem output_append_rejects_truncated_acknowledgement :
    outputReply (.append (b [41, 42])) (b [1]) = .error protocolFailure := by decide

theorem output_append_preserves_original_failure :
    outputReply (.append (b [41, 42]))
      (b [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]) =
      .error ⟨1, 9⟩ := by rfl

theorem output_append_packet_carries_only_raw_bytes :
    outputRequest (.append (b [41, 42])) =
      b [1, 37, 2, 0, 0, 0, 0, 0, 0, 0, 41, 42] := by rfl

end Synchronicity.HostWireProofs
