import VerifiedCore.Cas.ReadCodec
import Synchronicity.Prelude

/-! Same-source regression theorems for the executable CAS read decoder.
These are deliberately not a second model of Rust decoding. -/
namespace Synchronicity.CasReadCodecProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Cas.Read
set_option maxRecDepth 4096

private def bytes (values : List UInt8) : ByteArray := ⟨values.toArray⟩
private def root : ByteArray := bytes (List.replicate 32 0)
private def endpoints (input : List UInt8) (groups : UInt64) : List (Nat × Nat) :=
  (decodeBitmap (bytes input) groups).map fun span => (span.start, span.stop)

/-- Type validation finishes before the stored hash width is inspected. -/
theorem last_access_type_precedes_root_width (hash : ByteArray) (size complete : Int64) :
    decodeRow [.blob hash, .integer size, .integer complete, .null, .null,
      .real 0, .null] = .error (.columnType 6 "last_access" .real) := by rfl

theorem durable_type_precedes_root_width (hash : ByteArray) :
    decodeRow [.blob hash, .integer 0, .integer 0, .null, .null,
      .integer 0, .null] = .error (.columnType 7 "durable" .null) := by rfl

theorem root_type_is_first :
    decodeRow [.null, .null, .null, .null, .null, .null, .null] =
      .error (.columnType 0 "root" .null) := by rfl

theorem size_type_precedes_complete :
    decodeRow [.blob root, .text "0", .null, .null, .null, .null, .null] =
      .error (.columnType 1 "size" .text) := by rfl

theorem complete_requires_integer :
    decodeRow [.blob root, .integer 0, .blob (bytes []), .null, .null, .null, .null] =
      .error (.columnType 2 "complete" .blob) := by rfl

theorem bitmap_type_precedes_inline :
    decodeRow [.blob root, .integer 0, .integer 0, .integer 0, .real 0, .null, .null] =
      .error (.columnType 3 "bitmap" .integer) := by rfl

theorem inline_raw_text_is_text :
    decodeRow [.blob root, .integer 0, .integer 0, .null, .rawText (bytes [255]),
      .integer 0, .integer 0] = .error (.columnType 4 "inline" .text) := by rfl

theorem malformed_projection_rejected : decodeRow [] = .error .malformed := by rfl

theorem root_width_checked_after_types :
    decodeRow [.blob (bytes []), .integer 0, .integer 0, .null, .null,
      .integer 0, .integer 0] = .error (.column "blobs.root" "0 bytes, not 32") := by rfl

/-- Signed storage bits are retained; negative flags are true, not rejected. -/
theorem signed_size_and_nonzero_complete :
    (decodeRow [.blob root, .integer (-1), .integer (-1), .null, .null,
      .integer (-1), .integer (-1)]).map (fun value => (value.size, value.complete)) =
      .ok (18446744073709551615, true) := by decide +kernel

theorem durable_is_not_local_completion :
    (decodeRow [.blob root, .integer 32768, .integer 0, .null, .null,
      .integer 0, .integer 1]).map (fun value => covered value 0 1) = .ok false := by decide +kernel

theorem absent_size_is_not_corruption : decodeSize [] = .ok none := by rfl
theorem healing_preserves_signed_size : decodeSize [[.integer (-1)]] = .ok (some (-1)) := by rfl
theorem healing_size_type_checked :
    decodeSize [[.null]] = .error (.columnType 0 "size" .null) := by rfl
theorem healing_duplicate_rows_rejected :
    decodeSize [[.integer 1], [.integer 2]] = .error .malformed := by rfl

theorem empty_bitmap_holds_nothing : endpoints [] 4 = [] := by decide +kernel
theorem empty_vector_ignores_trailing_bytes : endpoints [0, 255] 4 = [] := by decide +kernel
theorem one_pair_decoded : endpoints [1, 1, 3] 4 = [(1, 3)] := by decide +kernel
theorem nonminimal_count_and_endpoints_accepted :
    endpoints [129, 0, 129, 0, 131, 0] 4 = [(1, 3)] := by decide +kernel
theorem trailing_bitmap_bytes_ignored :
    endpoints [1, 1, 3, 255, 255] 4 = [(1, 3)] := by decide +kernel
theorem truncated_pair_holds_nothing : endpoints [1, 1] 4 = [] := by decide +kernel
theorem truncated_integer_holds_nothing : endpoints [1, 0, 128] 4 = [] := by decide +kernel
theorem oversized_count_holds_nothing : endpoints [127, 0, 1] 4 = [] := by decide +kernel
theorem overflowing_endpoint_holds_nothing :
    endpoints [1, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2] 4 = [] := by decide +kernel
theorem unterminated_tenth_octet_holds_nothing :
    endpoints [1, 0, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128] 4 = [] := by decide +kernel
theorem maximal_endpoint_clamped :
    endpoints [1, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1] 4 = [(0, 4)] := by decide +kernel
theorem runs_sorted_clipped_and_touching_merged :
    endpoints [4, 3, 9, 0, 2, 2, 3, 7, 6] 5 = [(0, 5)] := by
  change (normalizeSpans 5 [⟨3, 9⟩, ⟨0, 2⟩, ⟨2, 3⟩, ⟨7, 6⟩]).map
    (fun span => (span.start, span.stop)) = [(0, 5)]
  simp [normalizeSpans, List.mergeSort, mergeSpans]
theorem separated_runs_not_filled :
    endpoints [2, 3, 4, 0, 1] 4 = [(0, 1), (3, 4)] := by
  change (normalizeSpans 4 [⟨3, 4⟩, ⟨0, 1⟩]).map
    (fun span => (span.start, span.stop)) = [(0, 1), (3, 4)]
  simp [normalizeSpans, List.mergeSort, mergeSpans]
theorem outside_and_reversed_runs_discarded :
    endpoints [3, 4, 5, 2, 1, 1, 1] 4 = [] := by decide +kernel

theorem complete_ignores_corrupt_bitmap :
    covered ⟨32768, true, some (bytes [255]), none⟩ 0 32768 = true := by decide +kernel
theorem incomplete_corrupt_bitmap_is_unavailable :
    covered ⟨32768, false, some (bytes [255]), none⟩ 0 1 = false := by decide +kernel
theorem coverage_includes_both_boundary_groups :
    covered ⟨32768, false, some (bytes [1, 0, 1]), none⟩ 16383 16385 = false := by decide +kernel
theorem exact_group_boundary_does_not_require_next_group :
    covered ⟨32768, false, some (bytes [1, 0, 1]), none⟩ 1 16384 = true := by decide +kernel
theorem empty_request_needs_no_groups (metadata : Metadata) (atByte : UInt64) :
    covered metadata atByte atByte = true := by simp [covered]

end Synchronicity.CasReadCodecProofs
