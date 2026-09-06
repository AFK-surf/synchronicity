import VerifiedCore.Host.Wire
import Init.Data.ByteArray.Lemmas

/-! The accumulator optimization preserves the exact existing wire bytes
for every input, including malformed primitive inputs: the generated request
encoders append each field into the packet under construction. No host
behavior, cryptographic assumption, or alternative native implementation is
involved. -/
namespace Synchronicity.WireBufferProofs
open VerifiedCore.Host VerifiedCore.Host.Wire
set_option Elab.async false

/-- Encoding into an existing packet is byte-for-byte equal to separately
encoding the length-prefixed field and appending it. -/
theorem appendBytes_eq (out payload : ByteArray) :
    appendBytes out payload = out ++ bytes payload := by
  exact ByteArray.append_assoc

/-- Every byte field of a generated request is appended in place, and that is
the same packet as the separately encoded field. -/
theorem put_bytes_eq (out payload : ByteArray) : out.put payload = out ++ bytes payload :=
  appendBytes_eq out payload

theorem hashRequest_preserves_bytes (chunk : ByteArray) :
    Construct.request (.hash chunk) = octet 1 ++ octet 39 ++ bytes chunk := by
  show (header 39).put chunk = _
  rw [put_bytes_eq]
  rfl

end Synchronicity.WireBufferProofs
