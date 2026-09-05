import VerifiedCore.Host.Wire
import VerifiedCore.Cas.Program

/-! Domain command constructors. The transport itself imports no domain policy. -/
namespace VerifiedCore.Entry

@[export synch_lean_cas_acquire]
def acquire (root holder : ByteArray) (now : Int64) (possession : Bool) : Host.Wire.State :=
  if root.size != 32 then .pure (.error ⟨2, 0⟩)
  else match String.fromUTF8? holder with
  | none => .pure (.error ⟨2, 0⟩)
  | some holder => (do
      let acquired ← Cas.acquire root holder now possession
      return Host.Wire.octet (if acquired then 1 else 0) : Host.Operation ByteArray).run

end VerifiedCore.Entry
