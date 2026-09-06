import VerifiedCore.Host

namespace VerifiedCore.Host

/-- Raw positioned writes to already-owned resources. Success means every byte
was accepted at the requested offset; it does not imply durability, final-name
publication, an object hash or a metadata transition. Failure may leave a
partial write, so the caller must not publish the resource after an error.
Opening, temporary ownership, flushing and replacement are separate concerns. -/
inductive ByteWriter : Type → Type where
  | writeAt (handle offset : UInt64) (bytes : ByteArray) : ByteWriter (Reply Unit)

end VerifiedCore.Host
