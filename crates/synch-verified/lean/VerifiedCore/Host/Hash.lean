import VerifiedCore.Host

/-! Cryptographic primitives for constructing BLAKE3 trees in Lean.
These are not Bao builders, subtree traversal callbacks or CAS verification
services. The requesting Lean operation chooses every chunk and parent edge.
Native integration belongs to the complete ingestion command, not a new
standalone Rust-to-Lean subtree facade. -/
namespace VerifiedCore.Host

/-- Unkeyed BLAKE3 primitives. `chunk` accepts at most 1024 bytes and uses the
explicit chunk counter; a root chunk must have counter zero. `parent` consumes
two 32-byte chaining values. Non-root replies are chaining values, root replies
are the first 32 bytes of the root output. Every successful reply has 32 bytes.
The provider must implement these cryptographic operations faithfully; this is
an explicit primitive trust contract, not a theorem about a Rust hash library. -/
inductive Blake3 : Type → Type where
  | chunk (counter : UInt64) (root : Bool) (bytes : ByteArray) : Blake3 (Reply ByteArray)
  | parent (root : Bool) (left right : ByteArray) : Blake3 (Reply ByteArray)

end VerifiedCore.Host
