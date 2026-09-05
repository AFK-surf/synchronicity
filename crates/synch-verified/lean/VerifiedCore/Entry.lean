import VerifiedCore.Host.Wire
import VerifiedCore.Cas.Program
import VerifiedCore.Trie.Program

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

private def encodeLookup : Trie.LookupResult → ByteArray
  | .ok none => Host.Wire.octet 0
  | .ok (some value) => Host.Wire.octet 1 ++ Host.Wire.bytes value
  | .error (.keyTooLong size) => Host.Wire.octet 2 ++ Host.Wire.word size.toUInt64
  | .error (.missingNode address) => Host.Wire.octet 3 ++ Host.Wire.bytes address
  | .error (.missingValue address) => Host.Wire.octet 4 ++ Host.Wire.bytes address
  | .error (.decode message) => Host.Wire.octet 5 ++ Host.Wire.string message
  | .error .depthExceeded => Host.Wire.octet 6

@[export synch_lean_trie_get]
def lookup (root : ByteArray) (keySize : UInt64) : Host.Wire.State :=
  if root.size != 32 then .pure (.error ⟨2, 0⟩)
  else (do return encodeLookup (← Trie.getInput root 0 keySize) : Host.Operation ByteArray).run

end VerifiedCore.Entry
