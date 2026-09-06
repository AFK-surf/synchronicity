import VerifiedCore.Host

/-! Primitive hashing, separate from storage, signatures and object
construction. A digest request carries the exact bytes to hash, domain tag
included; which bytes, and what equality of the digest means, is the
requesting operation's decision. -/
namespace VerifiedCore.Host

inductive Digest : Type → Type where
  /-- The 32-byte BLAKE3 digest of the bytes. -/
  | blake3 (bytes : ByteArray) : Digest (Reply ByteArray)

end VerifiedCore.Host
