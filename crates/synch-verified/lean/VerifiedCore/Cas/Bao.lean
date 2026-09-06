import VerifiedCore.Cas
import VerifiedCore.Host.Access
import VerifiedCore.Host.Hash
import VerifiedCore.Host.Write

/-! Streaming Bao construction. The program chooses the BLAKE3 tree, root
flags, chunk counters, preorder pair layout and every byte transfer. Hosts
interpret only exact file reads, positioned writes and fixed cryptographic
primitives. This internal program has no Rust-facing planner ABI. -/
namespace VerifiedCore.Cas.Bao
open Host

abbrev Effects := EffectSum FileIO (EffectSum ByteWriter Blake3)

inductive Error where
  | host (failure : Failure)
  | protocol
  deriving BEq, DecidableEq

abbrev Action (A : Type) := OperationOver Effects Error A

def writeAt (handle : UInt64) (offset : Nat) (bytes : ByteArray) : Action Unit :=
  performOver Error.host (.right (.left (.writeAt handle offset.toUInt64 bytes)))

def hash (effect : Blake3 (Reply ByteArray)) : Action ByteArray := do
  let digest ← performOver Error.host (.right (.right effect))
  if digest.size != 32 then throw .protocol
  return digest

/-- The largest aligned power-of-two prefix strictly smaller than `size`,
for a branch whose leaves have `unit` bytes. Callers branch only above unit. -/
def splitBytes (unit size : Nat) : Nat := unit * 2 ^ ((size - 1) / unit).log2

/-- Hash one bounded read buffer using 1024-byte cryptographic chunks.
Even the tree inside a Bao group is Lean-owned; no subtree-hash callback is
allowed. Only the final node gets ROOT; children always produce chaining
values, and chunk counters are offsets in the original object. -/
def hashAux : Nat → Nat → Bool → ByteArray → Action ByteArray
  | fuel, counter, isRoot, bytes => do
    if bytes.size ≤ 1024 then
      hash (.chunk counter.toUInt64 isRoot bytes)
    else
      match fuel with
      | 0 => throw .protocol
      | fuel + 1 =>
        let split := splitBytes 1024 bytes.size
        let left ← hashAux fuel counter false (bytes.extract 0 split)
        let right ← hashAux fuel (counter + split / 1024) false
          (bytes.extract split bytes.size)
        hash (.parent isRoot left right)

/-- Read exactly the requested bytes, preserving the original I/O failure.
There is no CAS recovery on an ingestion input read. A malformed successful
reply is rejected before either staging write or hashing. -/
def readAt (handle : UInt64) (offset size : Nat) : Action ByteArray := do
  let reply ← ExceptT.mk (.request (.left (.readAt handle offset.toUInt64 size.toUInt64))
    (fun reply => .pure (.ok reply)))
  match reply with
  | .error failure => throw (.host failure.failure)
  | .ok bytes =>
    if bytes.size != size then throw .protocol
    return bytes

/-- Depth-first left-to-right reads are sequential. The two child chaining
values are stored at their parent's preorder slot after both children finish.
For a left subtree of L groups, there are L-1 pairs before the right subtree,
so its byte offset is `base + 64*L`. No outboard-sized allocation is needed. -/
def buildAux : Nat → UInt64 → UInt64 → UInt64 → Nat → Nat → Nat → Bool → Action ByteArray
  | fuel, source, payload, outboard, offset, size, base, isRoot => do
    if size ≤ 16384 then
      let bytes ← readAt source offset size
      writeAt payload offset bytes
      hashAux 4 (offset / 1024) isRoot bytes
    else
      match fuel with
      | 0 => throw .protocol
      | fuel + 1 =>
        let split := splitBytes 16384 size
        let left ← buildAux fuel source payload outboard offset split (base + 64) false
        let right ← buildAux fuel source payload outboard (offset + split) (size - split)
          (base + 64 * (split / 16384)) false
        writeAt outboard base (left ++ right)
        hash (.parent isRoot left right)

/-- Complete bounded-memory construction for a known UInt64 input length.
The public ingestion operation will supply invocation-owned staging handles;
this program never publishes files or metadata itself. Sixty-four levels
cover every possible UInt64-sized object, including the empty object. -/
def build (source payload outboard size : UInt64) : Action ByteArray :=
  buildAux 64 source payload outboard 0 size.toNat 0 true

end VerifiedCore.Cas.Bao
