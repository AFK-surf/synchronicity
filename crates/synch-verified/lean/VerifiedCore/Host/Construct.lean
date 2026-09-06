import VerifiedCore.Host

/-! Object construction is a host service. Streaming the bytes of an object,
hashing them into a BLAKE3 tree and laying out the Bao outboard are bulk byte
work that the verified core does not perform itself: the requesting Lean
operation owns what is constructed, from which source, into which owned
resources, and everything that happens before and after. -/
namespace VerifiedCore.Host

/-- Bulk construction over resources the requesting operation already owns.
`build` streams exactly `size` bytes of the opened source, from its start,
into the owned payload temporary, writes the object's Bao outboard into the
owned outboard temporary and replies with the 32-byte root. A source shorter
than `size` is a failure; success does not imply flush, publication or a
metadata transition, and the handles remain the operation's to close,
publish or discard. `hash` replies with the BLAKE3 root of bytes the
operation already holds. Every successful reply has 32 bytes; the operation
checks the width before using it as a root. -/
inductive Construct : Type → Type where
  | build (source payload outboard size : UInt64) : Construct (Reply ByteArray)
  | hash (bytes : ByteArray) : Construct (Reply ByteArray)

end VerifiedCore.Host
