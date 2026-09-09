/-! Small extensional facts missing from Lean's executable `ByteArray` API. -/
namespace Synchronicity.ByteArrayProofs

private theorem toList_loop_eq (bytes : ByteArray) (index : Nat) (acc : List UInt8) :
    ByteArray.toList.loop bytes index acc =
      acc.reverse ++ bytes.data.toList.drop index := by
  fun_induction ByteArray.toList.loop bytes index acc with
  | case1 index acc within ih =>
    rw [ih]
    simp only [List.reverse_cons, List.append_assoc]
    have arrayWithin : index < bytes.data.toList.length := by
      simpa [ByteArray.size_data] using within
    have dropEq := List.drop_eq_getElem_cons (l := bytes.data.toList) arrayWithin
    rw [dropEq]
    simp [ByteArray.get!, getElem!_pos, within]
  | case2 index acc beyond =>
    have lengthLe : bytes.data.toList.length ≤ index := by
      simpa [ByteArray.size_data] using Nat.le_of_not_gt beyond
    simp [List.drop_eq_nil_iff.mpr lengthLe]

/-- The allocation-free runtime conversion and the underlying array view
denote the same list of octets. -/
theorem toList_eq_data (bytes : ByteArray) : bytes.toList = bytes.data.toList := by
  unfold ByteArray.toList
  simpa using toList_loop_eq bytes 0 []

end Synchronicity.ByteArrayProofs
