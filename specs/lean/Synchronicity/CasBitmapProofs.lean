import Synchronicity.PostcardProofs
import Synchronicity.CasPlanProofs
import VerifiedCore.Cas.IngestCommit
import VerifiedCore.Cas.Serve

/-! Persisted coverage is not a second model of what is held. These lemmas
connect the actual bitmap encoder/decoder and Read metadata to the planner's
verified groups, so histories can use union laws without dropping storage. -/
namespace Synchronicity.CasBitmapProofs
open VerifiedCore

/-- A representable bitmap is read back with exactly the stored endpoints. -/
theorem bitmap_roundtrip (spans : List GroupSpan)
    (count : spans.length < 2 ^ 64)
    (bounded : ∀ span ∈ spans, span.start < 2 ^ 64 ∧ span.stop < 2 ^ 64) :
    Cas.Codec.decodeRawBitmap (Cas.Codec.encodeRawBitmap spans) = spans := by
  have pairBounds : ∀ p ∈ spans.map (fun span => (span.start, span.stop)),
      p.1 < 2 ^ 64 ∧ p.2 < 2 ^ 64 := by
    intro p member
    obtain ⟨span, belongs, rfl⟩ := List.mem_map.mp member
    exact bounded span belongs
  have decoded := PostcardProofs.pair_list_roundtrip
    (spans.map fun span => (span.start, span.stop)) [] (by simpa using count) pairBounds
  simp only [List.append_nil] at decoded
  simp [Cas.Codec.decodeRawBitmap, Cas.Codec.encodeRawBitmap, decoded, List.map_map,
    Function.comp_def]

private theorem separated_length_bound (total : Nat) (spans : List GroupSpan)
    (bounded : ∀ span ∈ spans, span.start < span.stop ∧ span.stop ≤ total)
    (separated : spans.Pairwise (fun a b => a.stop < b.start)) :
    spans.length ≤ total := by
  have unique : (spans.map GroupSpan.start).Nodup := by
    change (spans.map GroupSpan.start).Pairwise (fun a b => a ≠ b)
    rw [List.pairwise_map]
    apply separated.imp_of_mem
    intro a b ha _ gap
    have valid := bounded a ha
    omega
  have subset : spans.map GroupSpan.start ⊆ List.range total := by
    intro start member
    obtain ⟨span, belongs, rfl⟩ := List.mem_map.mp member
    have valid := bounded span belongs
    simp only [List.mem_range]
    omega
  have result := unique.length_le_of_subset subset
  simpa using result

/-- Every production plan's bitmap is representable. This is established from
bounded separated ranges, not an extra assumption on each receive call. -/
theorem planned_bitmap_roundtrip (row durable complete : Bool) (recorded size : UInt64)
    (old incoming : List GroupSpan) :
    let planned := planCasCommit row durable complete recorded size old incoming
    Cas.Codec.decodeRawBitmap (Cas.Codec.encodeRawBitmap planned.spans) = planned.spans := by
  have bounded := CasPlanProofs.cas_plan_bounds row durable complete recorded size old incoming
  have separated := CasPlanProofs.cas_plan_separated row durable complete recorded size old incoming
  have count := separated_length_bound _ _ bounded separated
  have sizeBound : (groupCount size).toNat < 2 ^ 64 := (groupCount size).toNat_lt
  apply bitmap_roundtrip
  · omega
  · intro span member
    have bounds := bounded span member
    omega

/-- The row fields the receive operation writes, interpreted by Read. -/
def metadata (size : UInt64) (plan : CasPlan) : Cas.Read.Metadata :=
  ⟨size, plan.complete,
    if plan.complete || plan.spans.isEmpty then none
    else some (Cas.Codec.encodeRawBitmap plan.spans), none⟩

/-- Reading the committed bitmap recovers exactly the production planner's
verified groups, including its complete and held-nothing encodings. -/
theorem persisted_plan_has_exact_coverage (row durable complete : Bool)
    (recorded size : UInt64) (old incoming : List GroupSpan) (group : Nat) :
    let planned := planCasCommit row durable complete recorded size old incoming
    spansContain (Cas.Serve.held (metadata size planned)) group =
      spansContain planned.spans group := by
  let planned := planCasCommit row durable complete recorded size old incoming
  change spansContain (Cas.Serve.held (metadata size planned)) group = spansContain planned.spans group
  have bound := CasPlanProofs.cas_plan_bounds row durable complete recorded size old incoming
  have roundtrip : Cas.Codec.decodeRawBitmap (Cas.Codec.encodeRawBitmap planned.spans) = planned.spans :=
    planned_bitmap_roundtrip row durable complete recorded size old incoming
  by_cases full : planned.complete = true
  · have coverage := CasPlanProofs.cas_plan_complete_covers row durable complete recorded size old incoming
    apply Bool.eq_iff_iff.mpr
    simp only [metadata, Cas.Serve.held, full, ↓reduceIte, spansContain,
      List.any_cons, List.any_nil, Bool.or_false, Bool.and_eq_true, decide_eq_true_eq,
      Nat.zero_le, true_and]
    constructor
    · intro inside
      exact coverage full group inside
    · intro member
      obtain ⟨span, member, inside⟩ := List.any_eq_true.mp member
      simp only [Bool.and_eq_true, decide_eq_true_eq] at inside
      have limit := bound span member
      omega
  · by_cases empty : planned.spans = []
    · simp [metadata, Cas.Serve.held, full, empty, spansContain]
    · change spansContain (Cas.Serve.held (metadata size planned)) group = _
      have notFull : planned.complete = false := Bool.eq_false_iff.mpr full
      simp only [metadata, Cas.Serve.held, notFull, Bool.false_or, List.isEmpty_eq_false_iff.mpr empty,
        Bool.false_eq_true, if_false, Cas.Read.decodeBitmap, Cas.Read.decodeRawBitmap, roundtrip]
      apply Bool.eq_iff_iff.mpr
      rw [CasPlanProofs.normalize_spans_membership]
      constructor
      · exact And.left
      · intro member
        obtain ⟨span, belongs, inside⟩ := List.any_eq_true.mp member
        simp only [Bool.and_eq_true, decide_eq_true_eq] at inside
        have limit := bound span belongs
        exact ⟨member, by omega⟩

end Synchronicity.CasBitmapProofs
