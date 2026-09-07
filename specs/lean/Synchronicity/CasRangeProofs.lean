import Synchronicity.CasPlanProofs
import VerifiedCore.Cas.Serve

/-! A readable range means that every group it crosses is held. This connects
coverage-set preservation to the actual Read admission predicate, including
ranges spanning several received batches. -/
namespace Synchronicity.CasRangeProofs
open VerifiedCore

private theorem interval_of_pointwise (spans : List GroupSpan) (first past : Nat)
    (positive : first < past)
    (separated : spans.Pairwise (fun a b => a.stop < b.start))
    (covered : ∀ g, first ≤ g → g < past → spansContain spans g = true) :
    spans.any (fun r => r.start ≤ first && past ≤ r.stop) = true := by
  induction spans with
  | nil => simpa [spansContain] using covered first (by omega) positive
  | cons head rest ih =>
    have after := (List.pairwise_cons.mp separated).1
    by_cases before : head.stop ≤ first
    · have tailCovered : ∀ g, first ≤ g → g < past → spansContain rest g = true := by
        intro g lower upper
        have haveGroup := covered g lower upper
        simpa [spansContain, show ¬ g < head.stop by omega] using haveGroup
      have result := ih separated.of_cons tailCovered
      simp [result]
    · have start : head.start ≤ first := by
        obtain ⟨r, member, contains⟩ := List.any_eq_true.mp (covered first (by omega) positive)
        simp only [Bool.and_eq_true, decide_eq_true_eq] at contains
        rcases List.mem_cons.mp member with rfl | member
        · exact contains.1
        · have gap := after r member
          omega
      have stop : past ≤ head.stop := by
        by_cases short : past ≤ head.stop
        · exact short
        exfalso
        obtain ⟨r, member, contains⟩ := List.any_eq_true.mp
          (covered head.stop (by omega) (by omega))
        simp only [Bool.and_eq_true, decide_eq_true_eq] at contains
        rcases List.mem_cons.mp member with rfl | member
        · omega
        · have gap := after r member
          omega
      simp [start, stop]

private theorem pointwise_of_interval (spans : List GroupSpan) (first past : Nat)
    (covered : spans.any (fun r => r.start ≤ first && past ≤ r.stop) = true) :
    ∀ g, first ≤ g → g < past → spansContain spans g = true := by
  obtain ⟨r, member, contains⟩ := List.any_eq_true.mp covered
  simp only [Bool.and_eq_true, decide_eq_true_eq] at contains
  intro g lower upper
  apply List.any_eq_true.mpr
  exact ⟨r, member, by simp only [Bool.and_eq_true, decide_eq_true_eq]; omega⟩

private theorem held_separated (row : Cas.Read.Metadata) :
    (Cas.Serve.held row).Pairwise (fun a b => a.stop < b.start) := by
  unfold Cas.Serve.held
  split
  · simp
  · cases row.bitmap with
    | none => simp
    | some bytes => exact CasPlanProofs.normalize_spans_separated _ _

/-- Read admits a nonempty byte range exactly when every group it crosses is
held, regardless of how those groups arrived or were represented on disk. -/
theorem read_range_iff_groups (row : Cas.Read.Metadata) (start stop : UInt64)
    (positive : start < stop) :
    Cas.Read.covered row start stop = true ↔
      ∀ g, start.toNat / 16384 ≤ g → g < (stop.toNat + 16383) / 16384 →
        spansContain (Cas.Serve.held row) g = true := by
  have byteOrder : start.toNat < stop.toNat := positive
  have groupOrder : start.toNat / 16384 < (stop.toNat + 16383) / 16384 := by omega
  change (if start ≥ stop then true else
    (Cas.Serve.held row).any (fun span =>
      span.start ≤ start.toNat / 16384 && (stop.toNat + 16383) / 16384 ≤ span.stop)) = true ↔ _
  rw [if_neg (by change ¬ stop.toNat ≤ start.toNat; omega)]
  exact ⟨pointwise_of_interval _ _ _,
    interval_of_pointwise _ _ _ groupOrder (held_separated row)⟩

/-- Preserving verified groups preserves every readable byte range, not just
requests aligned to group boundaries. -/
theorem additional_groups_preserve_readable_ranges (before after : Cas.Read.Metadata)
    (start stop : UInt64)
    (preserved : ∀ g, spansContain (Cas.Serve.held before) g = true →
      spansContain (Cas.Serve.held after) g = true)
    (readable : Cas.Read.covered before start stop = true) :
    Cas.Read.covered after start stop = true := by
  by_cases positive : start < stop
  · apply (read_range_iff_groups after start stop positive).2
    intro g lower upper
    exact preserved g ((read_range_iff_groups before start stop positive).1 readable g lower upper)
  · have noPositive : ¬ start.toNat < stop.toNat := positive
    have reverse : start ≥ stop := by change stop.toNat ≤ start.toNat; omega
    simp [Cas.Read.covered, reverse]

end Synchronicity.CasRangeProofs
