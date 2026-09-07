import VerifiedCore.Postcard

/-! The shared postcard representation preserves bounded unsigned values.
These codec lemmas connect persisted coverage to read availability; they are
support for the user promise, rather than separate user-facing guarantees. -/
namespace Synchronicity.PostcardProofs
open VerifiedCore.Postcard

@[simp] theorem bind_ok (a : α) (f : α → Except ε β) : (Except.ok a >>= f) = f a := rfl
@[simp] theorem map_ok (f : α → β) (a : α) : Except.map f (.ok a : Except ε α) = .ok (f a) := rfl

theorem toNat_ofNat_of_lt {n : Nat} (h : n < 256) : (UInt8.ofNat n).toNat = n :=
  UInt8.toNat_ofNat_of_lt' h

/-! ## Varints -/

/-- How large a value a varint of `fuel` remaining bytes may still carry: the
last byte may only carry the top bit of a u64. -/
def bound : Nat → Nat
  | 0 => 1
  | 1 => 2
  | k + 2 => 128 * bound (k + 1)

theorem bound_ten : bound 10 = 2 ^ 64 := by decide

theorem leb128_small {n : Nat} (h : n < 128) : leb128 n = [n.toUInt8] := by
  rw [leb128]; simp [h]

theorem leb128_large {n : Nat} (h : 128 ≤ n) :
    leb128 n = (n % 128 + 128).toUInt8 :: leb128 (n / 128) := by
  rw [leb128]; simp [Nat.not_lt.mpr h]

theorem varint_roundtrip (fuel : Nat) : ∀ (n shift acc : Nat) (rest : List UInt8),
    1 ≤ fuel → n < bound fuel →
    varintAux fuel (if fuel == 1 then 1 else 255) shift acc (leb128 n ++ rest) =
      .ok (acc + n * 2 ^ shift, rest) := by
  induction fuel with
  | zero => intro _ _ _ _ h; omega
  | succ fuel ih =>
    intro n shift acc rest _ small
    cases fuel with
    | zero =>
      -- The last byte: at most the top bit of a u64.
      simp only [bound] at small
      have lt : n < 128 := by omega
      have mod : n % 128 = n := Nat.mod_eq_of_lt lt
      show varintAux 1 1 shift acc (leb128 n ++ rest) = _
      rw [leb128_small lt, varintAux]
      simp only [List.cons_append, parseByte, bind_ok, toNat_ofNat_of_lt (by omega : n < 256)]
      simp [show ¬ (1 < n) by omega, lt, mod]
    | succ fuel =>
      simp only [bound] at small
      show varintAux (fuel + 2) 255 shift acc (leb128 n ++ rest) = _
      by_cases lt : n < 128
      · have mod : n % 128 = n := Nat.mod_eq_of_lt lt
        rw [leb128_small lt, varintAux]
        simp only [List.cons_append, parseByte, bind_ok, toNat_ofNat_of_lt (by omega : n < 256)]
        simp [show ¬ (255 < n) by omega, lt, mod]
      · have ge : 128 ≤ n := Nat.not_lt.mp lt
        have head : n % 128 + 128 < 256 := by omega
        have below : n / 128 < bound (fuel + 1) := by omega
        have step := ih (n / 128) (shift + 7) (acc + (n % 128 + 128) % 128 * 2 ^ shift) rest
          (by omega) below
        rw [leb128_large ge, varintAux]
        simp only [List.cons_append, parseByte, bind_ok, toNat_ofNat_of_lt head]
        simp only [show ¬ (n % 128 + 128 > 255) by omega, show ¬ (n % 128 + 128 < 128) by omega,
          ↓reduceIte]
        rw [step]
        congr 2
        have mod : (n % 128 + 128) % 128 = n % 128 := by omega
        have split : n = n % 128 + 128 * (n / 128) := (Nat.mod_add_div n 128).symm
        rw [mod, Nat.pow_add]
        conv => rhs; rw [split]
        rw [Nat.add_mul, Nat.add_assoc, show (2 : Nat) ^ 7 = 128 by decide]
        ac_rfl

theorem length_roundtrip {n : Nat} (h : n < 2 ^ 64) (rest : List UInt8) :
    parseLength (leb128 n ++ rest) = .ok (n, rest) := by
  have := varint_roundtrip 10 n 0 0 rest (by omega) (by rw [bound_ten]; exact h)
  simpa [parseLength] using this

theorem leb128_nonempty (n : Nat) : 0 < (leb128 n).length := by
  rw [leb128]
  split <;> simp

/-- Every encoded pair contributes at least its two unsigned octets. -/
theorem pairs_bytes_bound (pairs : List (Nat × Nat)) :
    2 * pairs.length ≤ (encodePairs pairs).length := by
  induction pairs with
  | nil => simp [encodePairs]
  | cons pair rest ih =>
    have first := leb128_nonempty pair.1
    have second := leb128_nonempty pair.2
    simp only [encodePairs, List.flatMap_cons, List.length_append, List.length_cons] at *
    omega

private theorem pairs_into_roundtrip (pairs acc : List (Nat × Nat)) (rest : List UInt8)
    (bounded : ∀ p ∈ pairs, p.1 < 2 ^ 64 ∧ p.2 < 2 ^ 64) :
    parsePairsInto pairs.length acc (encodePairs pairs ++ rest) = .ok (acc.reverse ++ pairs, rest) := by
  induction pairs generalizing acc with
  | nil => simp [encodePairs, parsePairsInto]
  | cons pair pairs ih =>
    have head := bounded pair (by simp)
    have tail : ∀ p ∈ pairs, p.1 < 2 ^ 64 ∧ p.2 < 2 ^ 64 :=
      fun p member => bounded p (by simp [member])
    have tailResult := ih (pair :: acc) tail
    simp only [encodePairs] at tailResult
    simp [encodePairs, parsePairsInto, List.append_assoc, length_roundtrip head.1,
      length_roundtrip head.2, tailResult]

theorem pairs_roundtrip (pairs : List (Nat × Nat)) (rest : List UInt8)
    (bounded : ∀ p ∈ pairs, p.1 < 2 ^ 64 ∧ p.2 < 2 ^ 64) :
    parsePairs pairs.length (encodePairs pairs ++ rest) = .ok (pairs, rest) := by
  simpa [parsePairs] using pairs_into_roundtrip pairs [] rest bounded

/-- Every representable vector written to storage decodes to the same pairs,
including when the decoder is allowed to ignore trailing bytes. -/
theorem pair_list_roundtrip (pairs : List (Nat × Nat)) (rest : List UInt8)
    (count : pairs.length < 2 ^ 64)
    (bounded : ∀ p ∈ pairs, p.1 < 2 ^ 64 ∧ p.2 < 2 ^ 64) :
    parsePairList (encodePairList pairs ++ rest) = .ok (pairs, rest) := by
  have bytes := pairs_bytes_bound pairs
  have fits : ¬ pairs.length > (encodePairs pairs ++ rest).length / 2 := by
    simp only [List.length_append]
    omega
  simp only [List.length_append] at fits
  simp [parsePairList, encodePairList, List.append_assoc,
    length_roundtrip count, fits, pairs_roundtrip pairs rest bounded]

end Synchronicity.PostcardProofs
