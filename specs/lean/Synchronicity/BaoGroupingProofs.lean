import Synchronicity.BaoBuildProofs

/-! The grouped constructor and the ordinary chunk tree choose the same
branch boundary above one group. This is arithmetic about the executable
splitter, not a comparison with a handwritten Rust implementation. -/
namespace Synchronicity.BaoGroupingProofs
open VerifiedCore.Cas.Bao
set_option Elab.async false

/-- Changing the leaf unit from one chunk to sixteen chunks does not change
any branch above that group boundary. -/
theorem group_split_eq_chunk_split (size : Nat) (branch : 16384 < size) :
    splitBytes 16384 size = splitBytes 1024 size := by
  let groups := (size - 1) / 16384
  have nonzero : groups ≠ 0 := by dsimp [groups]; omega
  have low := Nat.log2_self_le nonzero
  have high := Nat.lt_log2_self (n := groups)
  rw [Nat.pow_succ] at high
  have chunksNonzero : (size - 1) / 1024 ≠ 0 := by omega
  have logarithm : ((size - 1) / 1024).log2 = groups.log2 + 4 := by
    apply (Nat.log2_eq_iff chunksNonzero).2
    simp only [Nat.pow_succ] at *
    dsimp [groups] at low high ⊢
    constructor <;> omega
  rw [splitBytes, splitBytes, logarithm]
  simp [Nat.pow_add, groups]
  omega

/-- The ordinary unkeyed chunk tree: at most 1024 bytes per leaf, the
largest-power-of-two chunk prefix at each branch, absolute chunk counters,
and ROOT applied only to the requested node. Compression is still the
explicit primitive model, not an axiom about the native library. -/
def chunkTree (model : BaoHashProofs.PrimitiveModel) (counter : Nat) (root : Bool)
    (bytes : ByteArray) : ByteArray :=
  if leaf : bytes.size ≤ 1024 then model.chunk counter.toUInt64 root bytes
  else
    let split := splitBytes 1024 bytes.size
    model.parent root
      (chunkTree model counter false (bytes.extract 0 split))
      (chunkTree model (counter + split / 1024) false (bytes.extract split bytes.size))
termination_by bytes.size
decreasing_by
  all_goals
    have positive := BaoProgramProofs.split_positive 1024 bytes.size (by decide)
    have strict := BaoProgramProofs.split_strict 1024 bytes.size (by decide) (by omega)
    simp only [ByteArray.size_extract]
    omega

/-- Sufficient traversal fuel affects termination checking only, not the
ordinary chunk-tree result. This removes a difference between grouped leaves
(fuel 4) and a flat whole-input traversal. -/
theorem reference_eq_chunkTree (model : BaoHashProofs.PrimitiveModel)
    (fuel counter : Nat) (root : Bool) (bytes : ByteArray)
    (fits : BaoProgramProofs.GeometryFits 1024 fuel bytes.size) :
    BaoHashProofs.reference model fuel counter root bytes = .ok (chunkTree model counter root bytes) := by
  induction fuel generalizing counter root bytes with
  | zero =>
    have leaf : bytes.size ≤ 1024 := fits
    rw [BaoHashProofs.reference, chunkTree]
    simp only [if_pos leaf, dif_pos leaf]
  | succ fuel ih =>
    by_cases leaf : bytes.size ≤ 1024
    · rw [BaoHashProofs.reference, chunkTree]
      simp only [if_pos leaf, dif_pos leaf]
    · have strict := BaoProgramProofs.split_strict 1024 bytes.size (by decide) (by omega)
      have leftSize : (bytes.extract 0 (splitBytes 1024 bytes.size)).size = splitBytes 1024 bytes.size := by
        simp only [ByteArray.size_extract]; omega
      have rightSize : (bytes.extract (splitBytes 1024 bytes.size) bytes.size).size =
          bytes.size - splitBytes 1024 bytes.size := by simp [ByteArray.size_extract]
      have children := fits.resolve_left leaf
      have left := ih counter false (bytes.extract 0 (splitBytes 1024 bytes.size))
        (by simpa only [leftSize] using children.1)
      have right := ih (counter + splitBytes 1024 bytes.size / 1024) false
        (bytes.extract (splitBytes 1024 bytes.size) bytes.size)
        (by simpa only [rightSize] using children.2)
      rw [BaoHashProofs.reference, chunkTree]
      simp only [if_neg leaf, dif_neg leaf, left, right, bind, Except.bind, pure, Except.pure]

/-- Raw source views are slices of one immutable byte sequence. Only bounded
reads are required to satisfy this contract; no host-side tree is assumed. -/
def CoherentSource (input : BaoBuildProofs.SourceModel) (bytes : ByteArray) : Prop :=
  input.size.toNat = bytes.size ∧
  ∀ offset count, count ≤ 16384 → offset + count ≤ bytes.size →
    input.view offset count = bytes.extract offset (offset + count)

/-- Grouping changes I/O granularity, not the chunk tree or its counters. -/
theorem groupedReference_eq_chunkTree (model : BaoHashProofs.PrimitiveModel)
    (input : BaoBuildProofs.SourceModel) (bytes : ByteArray)
    (coherent : CoherentSource input bytes) (fuel offset size : Nat) (root : Bool)
    (within : offset + size ≤ bytes.size)
    (fits : BaoProgramProofs.GeometryFits 16384 fuel size) :
    BaoBuildProofs.groupedReference model input fuel offset size root =
      .ok (chunkTree model (offset / 1024) root (bytes.extract offset (offset + size))) := by
  induction fuel generalizing offset size root with
  | zero =>
    have leaf : size ≤ 16384 := fits
    rw [BaoBuildProofs.groupedReference, if_pos leaf, coherent.2 offset size leaf within]
    apply reference_eq_chunkTree
    apply BaoProgramProofs.group_input_fits_inner_fuel
    simp only [ByteArray.size_extract]
    omega
  | succ fuel ih =>
    by_cases leaf : size ≤ 16384
    · rw [BaoBuildProofs.groupedReference, if_pos leaf, coherent.2 offset size leaf within]
      apply reference_eq_chunkTree
      apply BaoProgramProofs.group_input_fits_inner_fuel
      simp only [ByteArray.size_extract]
      omega
    · let split := splitBytes 16384 size
      have strict : split < size := BaoProgramProofs.split_strict 16384 size (by decide) (by omega)
      have children := fits.resolve_left leaf
      have left := ih offset split false (by omega) children.1
      have right := ih (offset + split) (size - split) false (by omega) children.2
      have sliceSize : (bytes.extract offset (offset + size)).size = size := by
        simp only [ByteArray.size_extract]; omega
      have flatSplit : splitBytes 1024 size = split :=
        (group_split_eq_chunk_split size (by omega)).symm
      have flatBranch : ¬ (bytes.extract offset (offset + size)).size ≤ 1024 := by omega
      have leftSlice : (bytes.extract offset (offset + size)).extract 0 split =
          bytes.extract offset (offset + split) := by
        rw [ByteArray.extract_extract]
        congr 1; omega
      have rightSlice : (bytes.extract offset (offset + size)).extract split size =
          bytes.extract (offset + split) (offset + split + (size - split)) := by
        rw [ByteArray.extract_extract]
        congr 1; omega
      have aligned : 1024 ∣ split :=
        Nat.dvd_trans (by decide : 1024 ∣ 16384) (BaoProgramProofs.split_aligned 16384 size)
      have counter : (offset + split) / 1024 = offset / 1024 + split / 1024 := by
        have := Nat.mod_eq_zero_of_dvd aligned
        omega
      rw [BaoBuildProofs.groupedReference, if_neg leaf]
      dsimp only [split] at left right
      simp only [left, right, bind, Except.bind, pure, Except.pure]
      conv_rhs => rw [chunkTree, dif_neg flatBranch]
      dsimp only [split] at flatSplit leftSlice rightSlice counter
      simp only [sliceSize, flatSplit, leftSlice, rightSlice, counter]

/-- Conditional root correctness of the executable whole streaming builder,
against the ordinary chunk tree in Lean. Native compression and immutable
source reads remain explicit raw capability assumptions. -/
theorem build_matches_chunkTree (model : BaoHashProofs.PrimitiveModel)
    (respond : BaoHashProofs.Responder) (crypto : BaoHashProofs.PrimitiveContract model respond)
    (input : BaoBuildProofs.SourceModel) (bytes : ByteArray) (coherent : CoherentSource input bytes)
    (source payload outboard : UInt64) (reads : BaoBuildProofs.ReadsSucceed respond source input)
    (payloadWrites : BaoBuildProofs.WritesSucceed respond payload)
    (pairWrites : BaoBuildProofs.WritesSucceed respond outboard) :
    BaoHashProofs.interpret respond (build source payload outboard input.size).run =
      .ok (chunkTree model 0 true bytes) := by
  rw [BaoBuildProofs.build_matches_grouped_reference model respond crypto input source payload
    outboard reads payloadWrites pairWrites]
  have result := groupedReference_eq_chunkTree model input bytes coherent 64 0 input.size.toNat true
    (by simp only [Nat.zero_add, coherent.1, Nat.le_refl]) (BaoProgramProofs.uint64_input_fits_outer_fuel input.size)
  simpa only [Nat.zero_add, Nat.zero_div, coherent.1, ByteArray.extract_zero_size] using result

end Synchronicity.BaoGroupingProofs
