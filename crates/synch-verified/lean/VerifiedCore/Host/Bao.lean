import VerifiedCore.Host

/-! The Bao tree as a host service. The tree, its chaining values, the slice
and proof formats and their verification stay on the Rust side as a stated
trust assumption on `bao-tree`/`blake3`; the operation decides which object,
which groups and which budget, and what an answer means. Served encodings go
straight into the invocation's private output sink, never through the
program, and received encodings are decoded out of the run's byte inputs
straight into the object's files: like a file transfer, neither is ever a
Lean value. -/
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
  /-- Decode the run's byte input `input`, a slice of exactly these spans,
  against the root into the object's inline buffer: `inline` when the row
  already holds one, otherwise zeroes, filled out to `size`. Replies the
  buffer. A slice that does not verify is the host's failure. -/
  | decodeInline (root : ByteArray) (size : UInt64) (inline : Option ByteArray)
      (spans : List (UInt64 × UInt64)) (input : UInt64) : Bao (Reply ByteArray)
  /-- Decode the run's byte input `input`, a slice of exactly these spans,
  against the root into the object's payload and outboard files, created as
  needed, grown only as far as verified groups land and never shrunk. The
  files are left unflushed. -/
  | decodeSlice (root : ByteArray) (size : UInt64) (spans : List (UInt64 × UInt64))
      (input : UInt64) : Bao (Reply Unit)
  /-- Flush the object's payload and outboard, contents and directory entries,
  to stable storage; a file that does not exist has nothing to flush. -/
  | flushObject (root : ByteArray) : Bao (Reply Unit)
  /-- Shorten the object's payload and outboard to the length a completed
  commit settled, best effort: a file left long costs disk, not correctness. -/
  | trimObject (root : ByteArray) (size : UInt64) : Bao (Reply Unit)
  /-- Verify the run's byte input `input`, a proof over these spans no deeper
  than `level`, by recomputation up to the root, and write its interior nodes
  into the object's outboard as far as they reach, unflushed. Replies whether
  any node was written and the subtrees the proof established: start, groups,
  chaining value, and whether the subtree is whole. A proof that does not
  verify, claims more than one window or carries trailing bytes is the host's
  failure. -/
  | writeProof (root : ByteArray) (size : UInt64) (spans : List (UInt64 × UInt64))
      (level input : UInt64) : Bao (Reply (Bool × List (UInt64 × UInt64 × ByteArray × Bool)))
  /-- Copy the donor's run of `groups` groups from `start`, with the interior
  nodes beneath it, into the object's payload and outboard, if and only if
  the donor's own tree holds the chaining value `cv` at that position. Replies
  whether it did; a donor whose tree cannot speak to the position, or whose
  files cannot be read, answers false rather than failing. -/
  | promoteRun (donor root : ByteArray) (size : UInt64) (start groups : UInt64) (cv : ByteArray) :
      Bao (Reply Bool)

end VerifiedCore.Host
