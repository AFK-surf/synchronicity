import VerifiedCore.Host.Wire
import VerifiedCore.Cas.Program
import VerifiedCore.Trie.Program
import VerifiedCore.Replication.History

/-! Domain command constructors. The transport itself imports no domain policy. -/
namespace VerifiedCore.Entry

/-- Decode the holder constructor, not its rendered storage spelling. In
particular an opaque future holder can resemble a known role's spelling. -/
private def decodeHolder (kind : UInt8) (payload : ByteArray) : Option Cas.PinHolder := do
  let text ← String.fromUTF8? payload
  match kind.toNat with
  | 0 => if text.isEmpty then some .operator else none
  | 1 => some (.source text)
  | 2 => some (.replica text)
  | 3 => some (.other text)
  | _ => none

@[export synch_lean_cas_unpin]
def unpin (root payload : ByteArray) (kind : UInt8) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error Host.Wire.protocolFailure)
  else match decodeHolder kind payload with
  | none => .pure (.error Host.Wire.protocolFailure)
  | some holder => (do
      let dropped ← Cas.unpin root holder
      return Host.Wire.octet (if dropped then 1 else 0) : Host.Operation ByteArray).run.mapEffects Host.EffectSum.left

@[export synch_lean_cas_delete]
def delete (root : ByteArray) (hasBefore : Bool) (before : Int64) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error ⟨2, 0⟩)
  else (do
    let outcome ← Cas.delete root (if hasBefore then some before else none)
    return Host.Wire.octet (match outcome with
      | .skipped => 0 | .writing => 1 | .protectedClaim => 2 | .applied => 3)
    : Host.Operation ByteArray).run.mapEffects Host.EffectSum.left

@[export synch_lean_cas_acquire]
def acquire (root holder : ByteArray) (now : Int64) (possession : Bool) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error ⟨2, 0⟩)
  else match String.fromUTF8? holder with
  | none => .pure (.error ⟨2, 0⟩)
  | some holder => (do
      let acquired ← Cas.acquire root holder now possession
      return Host.Wire.octet (if acquired then 1 else 0) : Host.Operation ByteArray).run.mapEffects Host.EffectSum.left

private def encodeLookup : Trie.LookupResult → ByteArray
  | .ok none => Host.Wire.octet 0
  | .ok (some value) => Host.Wire.octet 1 ++ Host.Wire.bytes value
  | .error (.keyTooLong size) => Host.Wire.octet 2 ++ Host.Wire.word size.toUInt64
  | .error (.missingNode address) => Host.Wire.octet 3 ++ Host.Wire.bytes address
  | .error (.missingValue address) => Host.Wire.octet 4 ++ Host.Wire.bytes address
  | .error (.decode message) => Host.Wire.octet 5 ++ Host.Wire.string message
  | .error .depthExceeded => Host.Wire.octet 6

@[export synch_lean_trie_get]
def lookup (root : ByteArray) (keySize : UInt64) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error ⟨2, 0⟩)
  else (do return encodeLookup (← Trie.getInput root 0 keySize) : Host.Operation ByteArray).run.mapEffects Host.EffectSum.left

private def encodeHistory (result : Replication.History.Result Nat) : Host.Reply ByteArray :=
  open Host.Wire in
  match result with
  | .ok count => .ok (octet 0 ++ word count.toUInt64)
  | .error (.host hostFailure) => .error hostFailure
  | .error .malformed => .ok (octet 1)
  | .error (.columnType index column actual) => .ok
      (octet 2 ++ word index.toUInt64 ++ string column ++ octet (match actual with
        | .null => 0 | .integer => 1 | .real => 2 | .text => 3 | .blob => 4))
  | .error (.invalidText text) => .ok (octet 3 ++ bytes ⟨text.toArray⟩)
  | .error (.column column reason) => .ok (octet 4 ++ string column ++ string reason)
  | .error (.origin error) => .ok (octet 5 ++ match error with
      | .label original => octet 0 ++ string original
      | .domain original => octet 1 ++ string original
      | .keyDecode => octet 2
      | .keyData => octet 3
      | .shape original => octet 4 ++ string original)

/-- Complete retention command; terminal domain errors do not enter the host
effect protocol or require Rust to repeat record validation. -/
@[export synch_lean_history_prune]
def pruneHistory (origin : ByteArray) (before : Int64) : Host.Wire.NativeState :=
  match String.fromUTF8? origin with
  | none => .pure (.error Host.Wire.protocolFailure)
  | some origin => do
    let result ← (Replication.History.prune origin before).run
    return encodeHistory result

end VerifiedCore.Entry
