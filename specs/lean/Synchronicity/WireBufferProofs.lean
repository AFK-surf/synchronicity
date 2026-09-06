import VerifiedCore.Host.Wire
import Init.Data.ByteArray.Lemmas

/-! The accumulator optimization preserves the exact existing wire bytes
for every input, including malformed primitive inputs. No host behavior,
cryptographic assumption, or alternative native implementation is involved. -/
namespace Synchronicity.WireBufferProofs
open VerifiedCore.Host VerifiedCore.Host.Wire
set_option Elab.async false

/-- Encoding into an existing packet is byte-for-byte equal to separately
encoding the length-prefixed field and appending it. -/
theorem appendBytes_eq (out payload : ByteArray) :
    appendBytes out payload = out ++ bytes payload := by
  exact ByteArray.append_assoc

theorem writerRequest_preserves_bytes (handle offset : UInt64) (chunk : ByteArray) :
    writerRequest (.writeAt handle offset chunk) =
      octet 1 ++ octet 38 ++ word handle ++ word offset ++ bytes chunk := by
  simp only [writerRequest, appendBytes_eq]

theorem chunkRequest_preserves_bytes (counter : UInt64) (root : Bool) (chunk : ByteArray) :
    blake3Request (.chunk counter root chunk) =
      octet 1 ++ octet 39 ++ word counter ++ octet (if root then 1 else 0) ++ bytes chunk := by
  simp only [blake3Request, appendBytes_eq]

theorem parentRequest_preserves_bytes (root : Bool) (left right : ByteArray) :
    blake3Request (.parent root left right) =
      octet 1 ++ octet 40 ++ octet (if root then 1 else 0) ++ bytes left ++ bytes right := by
  simp only [blake3Request, appendBytes_eq]

end Synchronicity.WireBufferProofs
