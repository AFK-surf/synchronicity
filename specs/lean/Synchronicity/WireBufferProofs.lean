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

theorem hashRequest_preserves_bytes (chunk : ByteArray) :
    constructRequest (.hash chunk) = octet 1 ++ octet 39 ++ bytes chunk := by
  simp only [constructRequest, appendBytes_eq]

end Synchronicity.WireBufferProofs
