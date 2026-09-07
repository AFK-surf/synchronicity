import VerifiedCore.Replication.Exchange
import Init.Data.List.Lex
import Init.Data.Array.Lemmas
import Std.Tactic

/-! The exchange command must use the product's version order: first the
unsigned sequence number, then the root's bytes in lexicographic order.
This connects its actual numeric key to that independent order. Native
admission's 32-byte root check supplies the fixed-width premise. -/
namespace Synchronicity.ExchangeVersionProofs
open VerifiedCore.Replication.Exchange

private theorem fold_order (left right : List UInt8) (sameLength : left.length = right.length)
    (a b : Nat) :
    left.foldl (fun n byte => n * 256 + byte.toNat) a <
        right.foldl (fun n byte => n * 256 + byte.toNat) b ↔
      a < b ∨ a = b ∧ List.Lex (· < ·) left right := by
  induction left generalizing right a b with
  | nil =>
    cases right with
    | nil => simp
    | cons y ys => simp at sameLength
  | cons x xs ih =>
    cases right with
    | nil => simp at sameLength
    | cons y ys =>
      have tails : xs.length = ys.length := by simpa using sameLength
      simp only [List.foldl_cons, ih ys tails, List.cons_lex_cons_iff,
        UInt8.lt_iff_toNat_lt, ← UInt8.toNat_inj]
      have hx := x.toNat_lt
      have hy := y.toNat_lt
      by_cases hlex : List.Lex (fun x y : UInt8 => x.toNat < y.toNat) xs ys
      all_goals simp only [hlex, and_true, and_false, or_false]
      all_goals omega

/-- Among valid published heads, the exchange command compares the sequence
first and breaks equal-sequence ties by the root's unsigned bytes. Origin
names do not alter this per-origin version order. -/
theorem version_order_is_sequence_then_root (left right : Advertised)
    (leftRoot : left.root.size = 32) (rightRoot : right.root.size = 32) :
    version left < version right ↔
      left.seq < right.seq ∨ left.seq = right.seq ∧
        List.Lex (· < ·) left.root.data.toList right.root.data.toList := by
  have sameLength : left.root.data.toList.length = right.root.data.toList.length := by
    simpa using leftRoot.trans rightRoot.symm
  unfold version
  rw [← Array.foldl_toList, ← Array.foldl_toList]
  simp only [Nat.add_lt_add_iff_left]
  rw [fold_order _ _ sameLength]
  simp only [UInt64.lt_iff_toNat_lt, ← UInt64.toNat_inj]

end Synchronicity.ExchangeVersionProofs
