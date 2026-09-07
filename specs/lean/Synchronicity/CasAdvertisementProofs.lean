import Synchronicity.CasPlanProofs
import Synchronicity.CasContentProofs
import Synchronicity.CasReceiveHistoryProofs
import Synchronicity.CasProjectProofs
import VerifiedCore.Cas.Project

/-! Availability advertisements never round into content the holder lacks.
These are the canonical fields computed by the native blob projection. -/
namespace Synchronicity.CasAdvertisementProofs
open VerifiedCore

/-- A non-durable partial holder advertises only bytes covered by its verified
groups, even at the maximum object size or when the advertisement is capped. -/
theorem partial_advertisements_only_offer_verified_bytes (size : UInt64)
    (groups : List GroupSpan) (span : UInt64 × UInt64)
    (advertised : span ∈ Cas.Project.advertised size false false groups)
    (i : Nat) (lower : span.1.toNat ≤ i) (upper : i < span.2.toNat) :
    i < size.toNat ∧ spansContain groups (i / 16384) = true := by
  let rounded := groups.map fun span =>
    let first := min (span.start * 16384) size.toNat
    let last := min (span.stop * 16384) size.toNat
    (⟨min (((first + 16777216 - 1) / 16777216) * 16777216) size.toNat,
      if last == size.toNat then last else last / 16777216 * 16777216⟩ : GroupSpan)
  change span ∈ Cas.Serve.pairsOf ((normalizeSpans size.toNat rounded).take 1024) at advertised
  obtain ⟨run, belongs, pair⟩ := List.mem_map.mp advertised
  have normalized := List.mem_of_mem_take belongs
  have bounds := CasPlanProofs.normalize_spans_bounds size.toNat rounded run normalized
  have startBound : run.start < UInt64.size := by change run.start < 18446744073709551616; have limit := size.toNat_lt; omega
  have stopBound : run.stop < UInt64.size := Nat.lt_of_le_of_lt bounds.2 size.toNat_lt
  have start := UInt64.toNat_ofNat_of_lt' startBound
  have stop := UInt64.toNat_ofNat_of_lt' stopBound
  cases pair
  simp only [start, stop] at lower upper
  have atRun : spansContain (normalizeSpans size.toNat rounded) i = true := by
    apply List.any_eq_true.mpr
    exact ⟨run, normalized, by simp only [Bool.and_eq_true, decide_eq_true_eq]; exact ⟨lower, upper⟩⟩
  have covered := (CasPlanProofs.normalize_spans_membership _ _ _).1 atRun
  obtain ⟨inward, member, inside⟩ := List.any_eq_true.mp covered.1
  obtain ⟨original, originalMember, rfl⟩ := List.mem_map.mp member
  simp only [Bool.and_eq_true, decide_eq_true_eq] at inside
  refine ⟨covered.2, List.any_eq_true.mpr ⟨original, originalMember, ?_⟩⟩
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  split at inside <;> simp only [beq_iff_eq] at * <;> omega

/-- Every byte offered by a partial advertisement has its actual backing and
matches the named content; inward rounding cannot turn missing bytes into an
offer. Cryptographic agreement is the same verified-content invariant as Read. -/
theorem advertised_content_matches_saved_content (size : UInt64)
    (payload content : ByteArray) (groups : List GroupSpan)
    (sameSize : size.toNat = content.size)
    (saved : CasContentProofs.AgreesOn payload content groups)
    (span : UInt64 × UInt64) (advertised : span ∈ Cas.Project.advertised size false false groups)
    (i : Nat) (lower : span.1.toNat ≤ i) (upper : i < span.2.toNat) :
    ∃ (inside : i < content.size) (backed : i < payload.size),
      payload[i]'backed = content[i]'inside := by
  have covered := partial_advertisements_only_offer_verified_bytes size groups span advertised i lower upper
  have inside : i < content.size := by omega
  obtain ⟨backed, same⟩ := saved i inside covered.2
  exact ⟨inside, backed, same⟩

/-- The actual metadata command only advertises locally verified bytes for a
partial non-durable object. Every advertised byte exists in the same stored
file and matches the named content; arbitrary unrelated rows are permitted. -/
theorem stored_partial_advertisements_offer_saved_content
    (saved : CasReceiveHistoryProofs.StoredFile state root content)
    (incomplete : saved.complete = false) (localOnly : saved.durable = 0)
    (quiet : state.faults = []) (idle : state.pending = none) :
    ∃ ad,
      (SimulatedHost.run (Cas.Project.blob root) state).1 = .ok (some ad) ∧
      ∀ span ∈ ad.advertisedSpans, ∀ i, span.1.toNat ≤ i → i < span.2.toNat →
        ∃ (inside : i < content.size)
          (backed : i < (CasReceiveHistoryProofs.payload state root).size),
          (CasReceiveHistoryProofs.payload state root)[i]'backed = content[i]'inside := by
  let raw := SimulatedHost.project Cas.Project.blobColumns saved.row
  let decoded := Cas.Project.projected root saved.size saved.complete
    (saved.durable != 0) saved.bitmap none saved.accessed
  have observed : SimulatedHost.query state.db "blobs" Cas.Project.blobColumns
      [("root", .blob root)] [] [] = [raw] := by
    rw [SimulatedHost.unordered_query, saved.selected]
    rfl
  have typed : Cas.Project.decodeBlob raw = .ok decoded := by
    dsimp only [raw, Cas.Project.blobColumns]
    simp only [SimulatedHost.project, List.map_cons, List.map_nil,
      saved.recorded.named, saved.recorded.sized, saved.recorded.completion,
      saved.recorded.coverage, saved.recorded.fileBacked, saved.recorded.clock, saved.recorded.durability]
    cases complete : saved.complete <;> cases bitmap : saved.bitmap <;>
      simp [Cas.Project.decodeBlob, Cas.Project.blobField, Cas.Project.integerField,
        Cas.Project.optionalBlobField, Cas.Codec.blobField, Cas.Codec.integerField,
        Cas.Codec.optionalBlobField, saved.width, decoded, complete, bitmap,
        bind, pure, Except.bind, Except.pure]
  have result := CasProjectProofs.blob_present state root raw decoded quiet idle observed typed
  refine ⟨_, result.1, ?_⟩
  intro span offered i lower upper
  have advertised : span ∈ Cas.Project.advertised saved.size false false (Cas.Serve.held saved.metadata) := by
    simpa [decoded, Cas.Project.projected, CasReceiveHistoryProofs.StoredFile.metadata,
      incomplete, localOnly] using offered
  exact advertised_content_matches_saved_content saved.size
    (CasReceiveHistoryProofs.payload state root) content (Cas.Serve.held saved.metadata)
    saved.sameSize saved.read_sound span advertised i lower upper

end Synchronicity.CasAdvertisementProofs
