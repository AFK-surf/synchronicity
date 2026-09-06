import VerifiedCore.Host

/-! The Bao tree as a host service. The tree, its chaining values, the slice
and proof formats and their verification stay on the Rust side as a stated
trust assumption on `bao-tree`/`blake3`; the operation decides which object,
which groups and which budget, and what an answer means. Encoded bytes go
straight into the invocation's private output sink, never through the
program: like a file transfer, a served window is never a Lean value. -/
namespace VerifiedCore.Host

inductive Bao : Type → Type where
  /-- Append the Bao slice of exactly these half-open group spans of the
  object to the output sink, from its inline bytes or its payload and outboard
  files, and reply with the byte count appended. The host validates the local
  copy against the root while encoding. -/
  | encodeSlice (root : ByteArray) (size : UInt64) (inline : Option ByteArray)
      (spans : List (UInt64 × UInt64)) : Bao (Reply UInt64)
  /-- Append the interior tree nodes over these group spans, descending no
  deeper than `level`, and reply with the byte count appended; or reply
  `none`, appending nothing, when the walk would exceed `budget` nodes. -/
  | encodeProof (root : ByteArray) (size : UInt64) (spans : List (UInt64 × UInt64))
      (level budget : UInt64) : Bao (Reply (Option UInt64))

end VerifiedCore.Host
