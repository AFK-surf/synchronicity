import VerifiedCore.Origin

namespace VerifiedCore.Replication

structure Head where
  origin : Origin.Parsed
  seq : UInt64
  root : ByteArray
  createdAt : Int64
  signedBy : ByteArray
  signature : ByteArray
  deriving BEq, DecidableEq

inductive Acceptance where
  | badSignature | unbound | notNewer | pending
  deriving BEq, DecidableEq

inductive Promotion where
  | flipped | waiting | refused | idle
  deriving BEq, DecidableEq

end VerifiedCore.Replication
