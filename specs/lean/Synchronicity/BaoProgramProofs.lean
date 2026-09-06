import VerifiedCore.Cas.Bao
import Synchronicity.Prelude
import Init.Data.ByteArray.Lemmas

/-! Geometry and executions of the actual streaming constructor. These prove
neither the native cryptographic implementation nor a full conditional
root/layout correctness theorem; those remain separate production gates. -/
namespace Synchronicity.BaoProgramProofs
open VerifiedCore.Host VerifiedCore.Cas.Bao
set_option Elab.async false

theorem split_positive (unit size : Nat) (positive : 0 < unit) :
    0 < splitBytes unit size := by
  exact Nat.mul_pos positive (Nat.two_pow_pos _)

theorem split_aligned (unit size : Nat) : unit ∣ splitBytes unit size := by
  exact ⟨_, rfl⟩

/-- A genuine branch has two strictly smaller, nonempty children. -/
theorem split_strict (unit size : Nat) (positive : 0 < unit) (branch : unit < size) :
    splitBytes unit size < size := by
  have quotient : (size - 1) / unit ≠ 0 := by
    have : 0 < (size - 1) / unit := (Nat.div_pos_iff).2 ⟨positive, by omega⟩
    omega
  have power := Nat.log2_self_le quotient
  have bounded : splitBytes unit size ≤ size - 1 :=
    le_trans (Nat.mul_le_mul_left unit power) (Nat.mul_div_le (size - 1) unit)
  omega

theorem children_strictly_smaller (unit size : Nat) (positive : 0 < unit)
    (branch : unit < size) :
    0 < splitBytes unit size ∧ splitBytes unit size < size ∧
    0 < size - splitBytes unit size ∧ size - splitBytes unit size < size := by
  have := split_positive unit size positive
  have := split_strict unit size positive branch
  omega

/-- Both recursive children fit the next lower power-of-two budget. This
connects the actual splitter to the fuel used by buildAux and hashAux. -/
theorem children_fit_lower_power (unit size fuel : Nat) (positive : 0 < unit)
    (branch : unit < size) (bounded : size ≤ unit * 2 ^ (fuel + 1)) :
    splitBytes unit size ≤ unit * 2 ^ fuel ∧
    size - splitBytes unit size ≤ unit * 2 ^ fuel := by
  have quotient : (size - 1) / unit ≠ 0 := by
    have : 0 < (size - 1) / unit := (Nat.div_pos_iff).2 ⟨positive, by omega⟩
    omega
  have quotientBound : (size - 1) / unit < 2 ^ (fuel + 1) := by
    apply (Nat.div_lt_iff_lt_mul positive).2
    have : size ≤ 2 ^ (fuel + 1) * unit := by simpa [Nat.mul_comm] using bounded
    omega
  have logBound : ((size - 1) / unit).log2 ≤ fuel := by
    have := (Nat.log2_lt quotient).2 quotientBound
    omega
  have left : splitBytes unit size ≤ unit * 2 ^ fuel :=
    Nat.mul_le_mul_left unit (Nat.pow_le_pow_right (by decide) logBound)
  have balance : size ≤ splitBytes unit size * 2 := by
    have : size - 1 < 2 ^ (((size - 1) / unit).log2 + 1) * unit :=
      (Nat.div_lt_iff_lt_mul positive).1 Nat.lt_log2_self
    have rearrange : 2 ^ (((size - 1) / unit).log2 + 1) * unit =
        splitBytes unit size * 2 := by
      simp [splitBytes, Nat.pow_succ, Nat.mul_comm, Nat.mul_left_comm]
    rw [rearrange] at this
    omega
  exact ⟨left, by omega⟩

/-- Every branch of the executable splitter reaches a leaf before its fuel
is exhausted. This predicate uses the same splitter, not a second tree plan. -/
def GeometryFits (unit : Nat) : Nat → Nat → Prop
  | 0, size => size ≤ unit
  | fuel + 1, size => size ≤ unit ∨
      (GeometryFits unit fuel (splitBytes unit size) ∧
       GeometryFits unit fuel (size - splitBytes unit size))

theorem power_budget_suffices (unit fuel size : Nat) (positive : 0 < unit)
    (bounded : size ≤ unit * 2 ^ fuel) : GeometryFits unit fuel size := by
  induction fuel generalizing size with
  | zero => simpa [GeometryFits] using bounded
  | succ fuel ih =>
    by_cases leaf : size ≤ unit
    · exact .inl leaf
    · have bounds := children_fit_lower_power unit size fuel positive (by omega) bounded
      exact .inr ⟨ih _ bounds.1, ih _ bounds.2⟩

theorem uint64_input_fits_outer_fuel (size : UInt64) :
    GeometryFits 16384 64 size.toNat := by
  apply power_budget_suffices _ _ _ (by decide)
  have bound := size.toNat_lt
  exact le_trans (Nat.le_of_lt bound) (by decide)

theorem group_input_fits_inner_fuel (bytes : ByteArray) (bounded : bytes.size ≤ 16384) :
    GeometryFits 1024 4 bytes.size := by
  exact power_budget_suffices _ _ _ (by decide) bounded

/-- One parent pair followed by the left subtree's L-1 pairs places the right
subtree exactly at the byte offset used in buildAux. -/
theorem right_preorder_offset (base leftGroups : Nat) (nonempty : 0 < leftGroups) :
    base + 64 + 64 * (leftGroups - 1) = base + 64 * leftGroups := by omega

theorem first_group_branch : splitBytes 16384 16385 = 16384 := by decide
theorem exact_two_group_branch : splitBytes 16384 32768 = 16384 := by decide
theorem three_group_branch : splitBytes 16384 49152 = 32768 := by decide
theorem power_boundary_left_shape : splitBytes 16384 65536 = 32768 := by decide
theorem beyond_power_boundary_left_shape : splitBytes 16384 65537 = 65536 := by decide
theorem maximal_size_left_shape :
    splitBytes 16384 18446744073709551615 = 9223372036854775808 := by decide
theorem first_chunk_branch : splitBytes 1024 1025 = 1024 := by decide
theorem complete_group_chunk_branch : splitBytes 1024 16384 = 8192 := by decide

/-- A cryptographic reply is checked before it can become an outboard pair or
an input to another parent primitive. -/
theorem malformed_hash_is_rejected (effect : Blake3 (Reply ByteArray)) :
    ∃ resume, (hash effect).run = .request (.right (.right effect)) resume ∧
      resume (.ok ByteArray.empty) = .pure (.error .protocol) := by
  exact ⟨_, rfl, rfl⟩

theorem input_failure_has_no_write (handle : UInt64) (offset size : Nat)
    (failure : FileFailure) :
    ∃ resume, (readAt handle offset size).run =
      .request (.left (.readAt handle offset.toUInt64 size.toUInt64)) resume ∧
      resume (.error failure) = .pure (.error (.host failure.failure)) := by
  exact ⟨_, rfl, rfl⟩

/-- Every leaf read is bounded by the actual branch guard. -/
theorem leaf_read_is_bounded (fuel : Nat) (source payload outboard : UInt64)
    (offset size base : Nat) (isRoot : Bool) (leaf : size ≤ 16384) :
    ∃ resume, (buildAux fuel source payload outboard offset size base isRoot).run =
      .request (.left (.readAt source offset.toUInt64 size.toUInt64)) resume ∧ size ≤ 16384 := by
  cases fuel <;> simp only [buildAux, if_pos leaf] <;> exact ⟨_, rfl, leaf⟩

/-- The host hashes only a single standard BLAKE3 chunk, never a Bao group. -/
theorem primitive_chunk_is_bounded (fuel counter : Nat) (isRoot : Bool)
    (bytes : ByteArray) (chunk : bytes.size ≤ 1024) :
    ∃ resume, (hashAux fuel counter isRoot bytes).run =
      .request (.right (.right (.chunk counter.toUInt64 isRoot bytes))) resume ∧
      bytes.size ≤ 1024 := by
  cases fuel <;> simp only [hashAux, if_pos chunk] <;> exact ⟨_, rfl, chunk⟩

private def digest : ByteArray := ⟨Array.replicate 32 7⟩
private def input : ByteArray := ⟨#[5]⟩
private def failure : Failure := ⟨1, 77⟩

private inductive Event where
  | read (handle offset count : UInt64)
  | write (handle offset : UInt64) (size : Nat)
  | chunk (counter : UInt64) (root : Bool) (size : Nat)
  | parent (root : Bool)
  deriving DecidableEq

private structure Script where
  readReply : FileReply ByteArray := .ok input
  writeFailure : Option Failure := none
  hashReply : Reply ByteArray := .ok digest

private def execute (script : Script) : Nat → Program Effects (Except Error ByteArray) →
    Option (Except Error (List UInt8) × List Event)
  | 0, _ => none
  | _ + 1, .pure result => some (result.map (fun value => value.data.toList), [])
  | fuel + 1, .request effect resume =>
    let step (event : Event) (next : Program Effects (Except Error ByteArray)) :=
      (execute script fuel next).map fun (result, trace) => (result, event :: trace)
    match effect with
    | .left effect => match effect with
      | .readAt handle offset count => step (.read handle offset count) (resume script.readReply)
      | _ => none
    | .right effect => match effect with
      | .left effect => match effect with
        | .writeAt handle offset bytes => step (.write handle offset bytes.size)
            (resume (match script.writeFailure with
              | none => .ok () | some failure => .error failure))
      | .right effect => match effect with
        | .chunk counter root bytes => step (.chunk counter root bytes.size) (resume script.hashReply)
        | .parent root _ _ => step (.parent root) (resume script.hashReply)

theorem empty_object_is_one_root_chunk_and_no_outboard :
    execute { readReply := .ok ByteArray.empty } 10 (build 1 2 3 0).run =
      some (.ok (List.replicate 32 7), [.read 1 0 0, .write 2 0 0, .chunk 0 true 0]) := by decide

theorem small_object_stages_exact_input_before_root_hash :
    execute {} 10 (build 1 2 3 1).run =
      some (.ok (List.replicate 32 7), [.read 1 0 1, .write 2 0 1, .chunk 0 true 1]) := by decide

theorem short_successful_input_is_rejected_before_write :
    execute { readReply := .ok ByteArray.empty } 10 (build 1 2 3 1).run =
      some (.error .protocol, [.read 1 0 1]) := by decide

theorem oversized_successful_input_is_rejected_before_write :
    execute {} 10 (build 1 2 3 0).run =
      some (.error .protocol, [.read 1 0 0]) := by decide

theorem failed_staging_write_prevents_hash :
    execute { writeFailure := some failure } 10 (build 1 2 3 1).run =
      some (.error (.host failure), [.read 1 0 1, .write 2 0 1]) := by decide

theorem malformed_primitive_digest_is_not_a_root :
    execute { hashReply := .ok ByteArray.empty } 10 (build 1 2 3 1).run =
      some (.error .protocol, [.read 1 0 1, .write 2 0 1, .chunk 0 true 1]) := by decide

theorem primitive_failure_retains_opaque_error :
    execute { hashReply := .error failure } 10 (build 1 2 3 1).run =
      some (.error (.host failure), [.read 1 0 1, .write 2 0 1, .chunk 0 true 1]) := by decide

theorem depleted_branch_fuel_never_requests_effects :
    (buildAux 0 1 2 3 0 16385 0 true).run = .pure (.error .protocol) := by rfl

theorem nonzero_leaf_offset_sets_original_chunk_counter :
    execute {} 10 (buildAux 0 1 2 3 32768 1 128 false).run =
      some (.ok (List.replicate 32 7), [.read 1 32768 1, .write 2 32768 1, .chunk 32 false 1]) := by decide

/-- The actual outer branch preserves left-to-right execution, marks both
children non-root, and writes its exact pair before hashing the parent. Child
programs remain opaque here: this composes without evaluating large buffers. -/
theorem build_branch_program (fuel : Nat) (source payload outboard : UInt64)
    (offset size base : Nat) (isRoot : Bool) (branch : 16384 < size) :
    buildAux (fuel + 1) source payload outboard offset size base isRoot =
      (do
        let split := splitBytes 16384 size
        let left ← buildAux fuel source payload outboard offset split (base + 64) false
        let right ← buildAux fuel source payload outboard (offset + split) (size - split)
          (base + 64 * (split / 16384)) false
        VerifiedCore.Cas.Bao.writeAt outboard base (left ++ right)
        VerifiedCore.Cas.Bao.hash (.parent isRoot left right)) := by
  rw [buildAux]
  simp only [if_neg (Nat.not_le.mpr branch)]

/-- The actual inner BLAKE3 branch retains original chunk coordinates and
never marks either child ROOT, even when this parent is the object root. -/
theorem hash_branch_program (fuel counter : Nat) (isRoot : Bool) (bytes : ByteArray)
    (branch : 1024 < bytes.size) :
    hashAux (fuel + 1) counter isRoot bytes =
      (do
        let split := splitBytes 1024 bytes.size
        let left ← hashAux fuel counter false (bytes.extract 0 split)
        let right ← hashAux fuel (counter + split / 1024) false
          (bytes.extract split bytes.size)
        VerifiedCore.Cas.Bao.hash (.parent isRoot left right)) := by
  rw [hashAux]
  simp only [if_neg (Nat.not_le.mpr branch)]

/-- A two-group object places its only pair at zero. Its partial right group
starts at byte 16384 (chunk counter 16); neither group receives ROOT. -/
theorem two_group_top_level_layout (source payload outboard : UInt64) :
    build source payload outboard 16385 =
      (do
        let left ← buildAux 63 source payload outboard 0 16384 64 false
        let right ← buildAux 63 source payload outboard 16384 1 64 false
        VerifiedCore.Cas.Bao.writeAt outboard 0 (left ++ right)
        VerifiedCore.Cas.Bao.hash (.parent true left right)) := by
  change buildAux 64 source payload outboard 0 16385 0 true = _
  exact build_branch_program 63 source payload outboard 0 16385 0 true (by decide)

/-- Three groups split into a two-group left child and one right group. The
left pair is at byte 64, the top pair at zero; the right leaf writes no pair. -/
theorem three_group_top_level_layout (source payload outboard : UInt64) :
    build source payload outboard 49152 =
      (do
        let left ← buildAux 63 source payload outboard 0 32768 64 false
        let right ← buildAux 63 source payload outboard 32768 16384 128 false
        VerifiedCore.Cas.Bao.writeAt outboard 0 (left ++ right)
        VerifiedCore.Cas.Bao.hash (.parent true left right)) := by
  change buildAux 64 source payload outboard 0 49152 0 true = _
  exact build_branch_program 63 source payload outboard 0 49152 0 true (by decide)

theorem three_group_left_child_layout (source payload outboard : UInt64) :
    buildAux 63 source payload outboard 0 32768 64 false =
      (do
        let left ← buildAux 62 source payload outboard 0 16384 128 false
        let right ← buildAux 62 source payload outboard 16384 16384 128 false
        VerifiedCore.Cas.Bao.writeAt outboard 64 (left ++ right)
        VerifiedCore.Cas.Bao.hash (.parent false left right)) := by
  exact build_branch_program 62 source payload outboard 0 32768 64 false (by decide)

/-- A final 1025-byte group uses adjacent original counters for its two
cryptographic chunks; both are chaining values and the parent keeps its flag. -/
theorem partial_group_chunk_coordinates (counter : Nat) (isRoot : Bool) (bytes : ByteArray)
    (size : bytes.size = 1025) :
    hashAux 4 counter isRoot bytes =
      (do
        let left ← hashAux 3 counter false (bytes.extract 0 1024)
        let right ← hashAux 3 (counter + 1) false (bytes.extract 1024 1025)
        VerifiedCore.Cas.Bao.hash (.parent isRoot left right)) := by
  simpa only [size] using hash_branch_program 3 counter isRoot bytes (by omega)

end Synchronicity.BaoProgramProofs
