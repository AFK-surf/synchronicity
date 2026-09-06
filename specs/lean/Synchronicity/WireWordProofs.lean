import VerifiedCore.Host.Wire

/-! The actual fixed-width encoder preserves the previous little-endian
fold specification. Capacity is unobservable in Lean; each emitted byte
retains the same shift and truncation. -/
namespace Synchronicity.WireWordProofs
open VerifiedCore.Host.Wire
set_option Elab.async false

/-- Kernel reduction checks all eight positions for every UInt64, without
evaluating a concrete input or appealing to a native implementation. -/
theorem word_eq_fold (n : UInt64) : word n =
    (List.range 8).foldl (fun out i => out.push (n >>> (i * 8).toUInt64).toUInt8) ByteArray.empty := by
  rfl

end Synchronicity.WireWordProofs
