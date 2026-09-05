import VerifiedCore.Host

namespace VerifiedCore.Host

/-- Primitive crypto only. No origin parser, certificate validator, Bao path or
delegation policy is a host capability. False means invalid point bytes; a host
failure remains distinct and retains its original error token. -/
inductive Crypto : Type → Type where
  | validateEd25519 (bytes : List UInt8) : Crypto (Reply Bool)

end VerifiedCore.Host
