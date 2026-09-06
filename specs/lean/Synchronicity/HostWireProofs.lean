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

theorem native_output_injection_preserves_packet (effect : Output A) :
    nativeRequest (.right (.right (.right (.right (.right (.left effect)))))) =
      outputRequest effect := rfl

theorem native_output_injection_preserves_reply (effect : Output A) (input : ByteArray) :
    nativeReply (.right (.right (.right (.right (.right (.left effect)))))) input =
      outputReply effect input := rfl

theorem native_write_injection_preserves_packet (effect : WriteEffects A) :
    nativeRequest (.right (.right (.right (.right (.right (.right effect)))))) =
      writeRequest effect := rfl

theorem native_write_injection_preserves_reply (effect : WriteEffects A) (input : ByteArray) :
    nativeReply (.right (.right (.right (.right (.right (.right effect)))))) input =
      writeReply effect input := rfl

theorem writer_request_has_only_handle_offset_and_bytes (handle offset : UInt64) (chunk : ByteArray) :
    writerRequest (.writeAt handle offset chunk) =
      octet 1 ++ octet 38 ++ word handle ++ word offset ++ bytes chunk := rfl

theorem writer_requires_exact_unit_reply :
    writerReply (.writeAt 9 8 .empty) (b [1, 38, 0]) = .error protocolFailure := by decide

theorem writer_accepts_acknowledgement :
    writerReply (.writeAt 9 8 .empty) (b [1, 38]) = .ok () := by decide

theorem chunk_request_preserves_counter_root_and_bytes (counter : UInt64) (root : Bool)
    (chunk : ByteArray) : blake3Request (.chunk counter root chunk) =
      octet 1 ++ octet 39 ++ word counter ++ octet (if root then 1 else 0) ++ bytes chunk := rfl

theorem parent_request_preserves_root_and_children (root : Bool) (left right : ByteArray) :
    blake3Request (.parent root left right) = octet 1 ++ octet 40 ++
      octet (if root then 1 else 0) ++ bytes left ++ bytes right := rfl

theorem hash_wrong_variant_rejected :
    blake3Reply (.chunk 0 true .empty) (b [1, 40, 0, 0, 0, 0, 0, 0, 0, 0]) =
      .error protocolFailure := by decide

theorem hash_truncated_payload_rejected :
    blake3Reply (.parent false .empty .empty) (b [1, 40, 1, 0, 0, 0, 0, 0, 0, 0]) =
      .error protocolFailure := by decide

theorem conflict_expression_tree_tags (column : String) :
    conflictValue (.coalesce (.excluded column) (.max (.current column) (.excluded column))) =
      octet 2 ++ (octet 1 ++ string column) ++
        (octet 3 ++ (octet 0 ++ string column) ++ (octet 1 ++ string column)) := rfl

theorem upsert_requires_exact_unit_reply :
    upsertReply (.write 7 "blobs" [] ["root"] []) (b [1, 41, 0]) =
      .error protocolFailure := by decide

theorem upsert_accepts_acknowledgement :
    upsertReply (.write 7 "blobs" [] ["root"] []) (b [1, 41]) = .ok () := by decide

theorem temporary_handle_preserves_all_bits :
    resourcesReply (.createTemporary "cas_payload")
      (b [1, 42, 255, 255, 255, 255, 255, 255, 255, 255]) =
      .ok 18446744073709551615 := by decide

theorem temporary_truncated_handle_rejected :
    resourcesReply (.createTemporary "cas_payload") (b [1, 42, 0]) =
      .error protocolFailure := by decide

theorem flush_accepts_acknowledgement :
    resourcesReply (.flush 7) (b [1, 43]) = .ok () := by decide

theorem replace_accepts_acknowledgement :
    resourcesReply (.replace 7 "cas_payload" .empty) (b [1, 44]) = .ok () := by decide

theorem discard_accepts_acknowledgement :
    resourcesReply (.discard 7) (b [1, 45]) = .ok () := by decide

theorem directory_sync_synced_is_distinct_from_unsupported :
    resourcesReply (.syncParent "cas_payload" .empty) (b [1, 46, 0]) = .ok .synced ∧
    resourcesReply (.syncParent "cas_payload" .empty) (b [1, 46, 1]) = .ok .unsupported := by decide

theorem directory_sync_invalid_enum_rejected :
    resourcesReply (.syncParent "cas_payload" .empty) (b [1, 46, 2]) =
      .error protocolFailure := by decide

theorem directory_sync_truncated_enum_rejected :
    resourcesReply (.syncParent "cas_payload" .empty) (b [1, 46]) =
      .error protocolFailure := by decide

theorem directory_sync_trailing_bytes_rejected :
    resourcesReply (.syncParent "cas_payload" .empty) (b [1, 46, 0, 0]) =
      .error protocolFailure := by decide

theorem directory_sync_original_failure_not_unsupported :
    resourcesReply (.syncParent "cas_payload" .empty)
      (b [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]) =
      .error ⟨1, 9⟩ := by rfl

theorem lease_handle_preserved :
    leaseReply (.acquire "cas_writers" .empty) (b [1, 47, 9, 0, 0, 0, 0, 0, 0, 0]) =
      .ok 9 := by decide

theorem lease_release_requires_exact_acknowledgement :
    leaseReply (.release 9) (b [1, 48, 0]) = .error protocolFailure := by decide

theorem lease_release_accepts_acknowledgement :
    leaseReply (.release 9) (b [1, 48]) = .ok () := by decide

theorem stat_reply_preserves_unsigned_size :
    sourceReply (.stat "source" .empty) (b [1, 49, 255, 255, 255, 255, 255, 255, 255, 255]) =
      .ok 18446744073709551615 := by decide

theorem stat_reply_rejects_truncated_size :
    sourceReply (.stat "source" .empty) (b [1, 49, 0]) = .error protocolFailure := by decide

theorem read_some_reply_allows_eof :
    sourceReply (.readSome 7 0 8) (b [1, 50, 0, 0, 0, 0, 0, 0, 0, 0]) =
      .ok ByteArray.empty := by rfl

theorem read_some_reply_rejects_truncated_payload :
    sourceReply (.readSome 7 0 8) (b [1, 50, 2, 0, 0, 0, 0, 0, 0, 0, 42]) =
      .error protocolFailure := by decide

theorem freeze_reply_preserves_handle :
    sourceReply (.freeze .empty) (b [1, 51, 7, 0, 0, 0, 0, 0, 0, 0]) = .ok 7 := by decide

theorem freeze_reply_rejects_trailing_bytes :
    sourceReply (.freeze .empty) (b [1, 51, 7, 0, 0, 0, 0, 0, 0, 0, 0]) =
      .error protocolFailure := by decide

end Synchronicity.HostWireProofs
