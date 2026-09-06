import Synchronicity.BaoBuildProofs
import Init.Data.ByteArray.Lemmas

/-! Exact preorder byte-region partition for the executable Bao splitter,
linked to the actual branch's required pair write. A complete accumulated
execution-trace theorem (every slot written exactly once) remains separate;
these compositional facts do not assert native filesystem correctness. -/
namespace Synchronicity.BaoLayoutProofs
open VerifiedCore.Host VerifiedCore.Cas.Bao BaoHashProofs BaoBuildProofs
set_option Elab.async false

/-- Empty and single-group inputs have no outboard pair. For positive sizes
this is ceil(size / 16384)-1, without an overflowing rounded-up addition. -/
def pairCount (size : Nat) : Nat := (size - 1) / 16384

theorem pairCount_is_rounded_groups_minus_one (size : Nat) :
    pairCount size + 1 = max 1 ((size + 16383) / 16384) := by
  unfold pairCount
  omega

theorem leaf_has_no_pairs (size : Nat) (leaf : size ≤ 16384) : pairCount size = 0 := by
  unfold pairCount
  omega

/-- The exact aligned splitter gives one parent plus all pairs in its two
children; the left subtree's group count is the offset multiplier in buildAux. -/
theorem branch_pair_counts (size : Nat) (branch : 16384 < size) :
    let split := splitBytes 16384 size
    pairCount split + 1 = split / 16384 ∧
    pairCount size = 1 + pairCount split + pairCount (size - split) := by
  have positive := BaoProgramProofs.split_positive 16384 size (by decide)
  have strict := BaoProgramProofs.split_strict 16384 size (by decide) branch
  have aligned : splitBytes 16384 size % 16384 = 0 :=
    Nat.mod_eq_zero_of_dvd (BaoProgramProofs.split_aligned 16384 size)
  dsimp only
  unfold pairCount
  omega

/-- Byte coverage, including every byte of each 64-byte pair. -/
def Region (base size byte : Nat) : Prop :=
  base ≤ byte ∧ byte < base + 64 * pairCount size

def ParentRegion (base byte : Nat) : Prop := base ≤ byte ∧ byte < base + 64

theorem branch_regions_are_contiguous (base size : Nat) (branch : 16384 < size) :
    let split := splitBytes 16384 size
    base + 64 + 64 * pairCount split = base + 64 * (split / 16384) ∧
    base + 64 * (split / 16384) + 64 * pairCount (size - split) =
      base + 64 * pairCount size := by
  have counts := branch_pair_counts size branch
  dsimp only at counts ⊢
  omega

/-- Parent, left and right cover precisely the full outboard region: no hole
or out-of-region byte is introduced by the actual child-base calculations. -/
theorem branch_region_partition (base size byte : Nat) (branch : 16384 < size) :
    let split := splitBytes 16384 size
    Region base size byte ↔ ParentRegion base byte ∨
      Region (base + 64) split byte ∨
      Region (base + 64 * (split / 16384)) (size - split) byte := by
  have adjacent := branch_regions_are_contiguous base size branch
  dsimp only at adjacent ⊢
  unfold Region ParentRegion
  omega

/-- The same three regions are pairwise disjoint, including partial right
groups and empty child outboards. -/
theorem branch_regions_disjoint (base size byte : Nat) (branch : 16384 < size) :
    let split := splitBytes 16384 size
    ¬ (ParentRegion base byte ∧ Region (base + 64) split byte) ∧
    ¬ (ParentRegion base byte ∧ Region (base + 64 * (split / 16384)) (size - split) byte) ∧
    ¬ (Region (base + 64) split byte ∧
      Region (base + 64 * (split / 16384)) (size - split) byte) := by
  have adjacent := branch_regions_are_contiguous base size branch
  dsimp only at adjacent ⊢
  unfold Region ParentRegion
  omega

theorem child_bases_preserve_pair_alignment (base size : Nat) (aligned : 64 ∣ base) :
    64 ∣ base + 64 ∧ 64 ∣ base + 64 * (splitBytes 16384 size / 16384) := by
  exact ⟨Nat.dvd_add aligned (Nat.dvd_refl 64), Nat.dvd_add aligned (Nat.dvd_mul_right _ _)⟩

/-- Every UInt64-sized input's complete outboard is below 2^56 bytes, hence
all pair starts and their end offsets fit the native UInt64 addressing width. -/
theorem outboard_byte_length_bound (size : UInt64) :
    64 * pairCount size.toNat ≤ 72057594037927872 := by
  have bounded := size.toNat_lt
  unfold pairCount
  omega

theorem region_offsets_fit_uint64 (size : UInt64) (byte : Nat) (inside : Region 0 size.toNat byte) :
    byte < 18446744073709551616 := by
  have := outboard_byte_length_bound size
  unfold Region at inside
  omega

theorem complete_pair_fits_region (base size index : Nat) (inside : index < pairCount size) :
    base ≤ base + 64 * index ∧ base + 64 * index + 64 ≤ base + 64 * pairCount size := by
  omega

/-- Converting either endpoint of a valid top-level pair to the native offset
type loses no bits. This includes the maximum UInt64 input length. -/
theorem top_pair_offsets_roundtrip (size : UInt64) (index : Nat)
    (inside : index < pairCount size.toNat) :
    (64 * index).toUInt64.toNat = 64 * index ∧
    (64 * index + 64).toUInt64.toNat = 64 * index + 64 := by
  have bounded := outboard_byte_length_bound size
  constructor <;> apply UInt64.toNat_ofNat_of_lt' <;> simp only [UInt64.size] <;> omega

/-- This is a statement about the executable constructor, not only a layout
recurrence: successful branching requires an actual 64-byte write at `base`.
Its child bases are exactly those covered by the partition theorem above. -/
theorem successful_branch_writes_bounded_pair (respond : Responder) (fuel : Nat)
    (source payload outboard : UInt64) (offset size base : Nat) (root : Bool)
    (branch : 16384 < size) (digest : ByteArray)
    (accepted : interpret respond
      (buildAux (fuel + 1) source payload outboard offset size base root).run = .ok digest) :
    ∃ (left right : ByteArray),
      (left ++ right).size = 64 ∧
      interpret respond (VerifiedCore.Cas.Bao.writeAt outboard base (left ++ right)).run = .ok () ∧
      base + 64 ≤ base + 64 * pairCount size := by
  obtain ⟨left, right, leftDone, rightDone, pairDone, _⟩ :=
    branch_success_requires_children_and_pair respond fuel source payload outboard offset size base
      root branch digest accepted
  have leftWidth := buildAux_success_width respond fuel source payload outboard offset
    (splitBytes 16384 size) (base + 64) false left leftDone
  have rightWidth := buildAux_success_width respond fuel source payload outboard
    (offset + splitBytes 16384 size) (size - splitBytes 16384 size)
    (base + 64 * (splitBytes 16384 size / 16384)) false right rightDone
  refine ⟨left, right, ?_, pairDone, ?_⟩
  · simp [leftWidth, rightWidth]
  · have counts := branch_pair_counts size branch
    dsimp only at counts
    omega

/-- A pure enumeration of pair-slot indices in write order (children before
parent), using the executable splitter. It records no host replies or bytes. -/
def pairSlots : Nat → Nat → Nat → List Nat
  | 0, _, _ => []
  | fuel + 1, size, first =>
      if size ≤ 16384 then [] else
        let split := splitBytes 16384 size
        (pairSlots fuel split (first + 1) ++
          pairSlots fuel (size - split) (first + split / 16384)) ++ [first]

/-- With sufficient recursion fuel, the pure enumeration contains each slot
of the full region exactly once, and contains no slot outside that region. -/
theorem pairSlots_count (fuel size first slot : Nat)
    (fits : BaoProgramProofs.GeometryFits 16384 fuel size) :
    (pairSlots fuel size first).count slot =
      if first ≤ slot ∧ slot < first + pairCount size then 1 else 0 := by
  induction fuel generalizing size first with
  | zero =>
    have leaf : size ≤ 16384 := fits
    simp [pairSlots, leaf_has_no_pairs size leaf]
  | succ fuel ih =>
    by_cases leaf : size ≤ 16384
    · simp [pairSlots, leaf, leaf_has_no_pairs size leaf]
    · have children : BaoProgramProofs.GeometryFits 16384 fuel (splitBytes 16384 size) ∧
          BaoProgramProofs.GeometryFits 16384 fuel (size - splitBytes 16384 size) :=
        fits.resolve_left leaf
      have counts := branch_pair_counts size (by omega)
      dsimp only at counts
      simp only [pairSlots, if_neg leaf, List.count_append, List.count_singleton,
        ih _ _ children.1, ih _ _ children.2, beq_iff_eq]
      split_ifs <;> omega

theorem top_pairSlots_exactly_once (size : UInt64) (slot : Nat) :
    (pairSlots 64 size.toNat 0).count slot =
      if slot < pairCount size.toNat then 1 else 0 := by
  simpa using pairSlots_count 64 size.toNat 0 slot
    (BaoProgramProofs.uint64_input_fits_outer_fuel size)

/-- Every enumerated slot is linked to a successful write in the actual
recursive executable, with exactly 64 bytes. This pointwise interpreter fact
does not yet establish equality with an accumulated stateful host trace. -/
theorem enumerated_slot_requires_actual_write (respond : Responder) (fuel : Nat)
    (source payload outboard : UInt64) (offset size first : Nat) (root : Bool)
    (digest : ByteArray)
    (accepted : interpret respond
      (buildAux fuel source payload outboard offset size (64 * first) root).run = .ok digest)
    (slot : Nat) (member : slot ∈ pairSlots fuel size first) :
    ∃ bytes : ByteArray, bytes.size = 64 ∧
      interpret respond (VerifiedCore.Cas.Bao.writeAt outboard (64 * slot) bytes).run = .ok () := by
  induction fuel generalizing offset size first root digest with
  | zero => simp [pairSlots] at member
  | succ fuel ih =>
    by_cases leaf : size ≤ 16384
    · simp [pairSlots, leaf] at member
    · obtain ⟨left, right, leftDone, rightDone, pairDone, _⟩ :=
        branch_success_requires_children_and_pair respond fuel source payload outboard
          offset size (64 * first) root (by omega) digest accepted
      have leftBase : 64 * first + 64 = 64 * (first + 1) := by omega
      have rightBase : 64 * first + 64 * (splitBytes 16384 size / 16384) =
          64 * (first + splitBytes 16384 size / 16384) := by omega
      rw [leftBase] at leftDone
      rw [rightBase] at rightDone
      simp only [pairSlots, if_neg leaf, List.mem_append, List.mem_singleton] at member
      rcases member with (inLeft | inRight) | atParent
      · exact ih offset (splitBytes 16384 size) (first + 1) false left leftDone inLeft
      · exact ih (offset + splitBytes 16384 size) (size - splitBytes 16384 size)
          (first + splitBytes 16384 size / 16384) false right rightDone inRight
      · subst slot
        have leftWidth := buildAux_success_width respond fuel source payload outboard offset
          (splitBytes 16384 size) (64 * (first + 1)) false left leftDone
        have rightWidth := buildAux_success_width respond fuel source payload outboard
          (offset + splitBytes 16384 size) (size - splitBytes 16384 size)
          (64 * (first + splitBytes 16384 size / 16384)) false right rightDone
        exact ⟨left ++ right, by simp [leftWidth, rightWidth], pairDone⟩

end Synchronicity.BaoLayoutProofs
