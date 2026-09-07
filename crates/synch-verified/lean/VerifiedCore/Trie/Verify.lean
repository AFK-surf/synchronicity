import VerifiedCore.Host
import VerifiedCore.Host.Digest
import VerifiedCore.Trie.Codec
import VerifiedCore.Trie.Program

/-! The canonical ingress boundary for peer-served trie nodes: what this node
stores under a hash is exactly what the hash covers, in the one encoding the
write path produces, within the key bound every reader shares, and shaped as
the trie invariants require. The host supplies only the digest primitive. -/
namespace VerifiedCore.Trie

open Host

/-- Why served bytes are not a node this build stores. Each constructor is one
of the store's existing diagnostics. -/
inductive Refusal where
  /-- Undecodable, or decodable only from a non-canonical image. -/
  | decode (message : String)
  /-- Decodable and canonical, but breaking a structural invariant. -/
  | nonCanonical (message : String)
  /-- A single node's nibble run exceeds twice the key bound. -/
  | keyTooLong (bytes : Nat)
  deriving BEq, DecidableEq

/-- The inline-value ceiling of the write path. -/
def inlineValueMax : Nat := 128

/-- Decode, then require the image to be the one the encoder produces, so a
peer cannot smuggle padding or non-minimal varints past the hash. -/
def canonical (bytes : ByteArray) : Except Refusal Node :=
  match decode bytes with
  | .error message => .error (.decode message)
  | .ok n => if encode n == bytes then .ok n else .error (.decode "non-canonical node encoding")

/-- The nibbles one node contributes to a key. -/
def nibbleRun : Node → Nat
  | .leaf suffix _ => suffix.size
  | .extension segment _ => segment.size
  | .branch _ _ => 0
  | .route _ _ => 0

def checkValue : Value → Except Refusal Unit
  | .inline bytes =>
    if bytes.size > inlineValueMax then
      .error (.nonCanonical
        s!"inline value of {bytes.size} bytes exceeds the {inlineValueMax}-byte ceiling")
    else .ok ()
  | .hash _ => .ok ()

def occupants (children : List (Option ByteArray)) (value : Option Value) : Nat :=
  children.countP Option.isSome + (if value.isSome then 1 else 0)

/-- The structural invariants the node kinds document: a non-empty extension
prefix, inline values within the ceiling, at least two occupants of a branch. -/
def checkInvariants : Node → Except Refusal Unit
  | .leaf _ v => checkValue v
  | .extension segment _ =>
    if segment.size == 0 then .error (.nonCanonical "an extension prefix is empty") else .ok ()
  | .branch cs v => do
    match v with
    | some v => checkValue v
    | none => pure ()
    if occupants cs v < 2 then throw (.nonCanonical "a branch has fewer than two occupants")
  | .route cs v =>
    if occupants cs (v.map Value.hash) == 0 then
      .error (.nonCanonical "a routing node has no occupants") else .ok ()

/-- Everything the boundary checks before hashing: canonical image, the key
bound `get` and the walks share, and the invariants. -/
def admit (bytes : ByteArray) : Except Refusal Node := do
  let n ← canonical bytes
  if nibbleRun n > maxKeyBytes * 2 then throw (.keyTooLong (nibbleRun n / 2))
  checkInvariants n
  return n

def leafTag : ByteArray := "synch-mpt/1/leaf".toUTF8
def extensionTag : ByteArray := "synch-mpt/1/ext".toUTF8
def branchTag : ByteArray := "synch-mpt/1/branch".toUTF8
def routeTag : ByteArray := "synch-mpt/2/route".toUTF8

/-- Domain separation: `BLAKE3(tag ‖ canonical encoding)` per node kind. -/
def tagOf : Node → ByteArray
  | .leaf _ _ => leafTag
  | .extension _ _ => extensionTag
  | .branch _ _ => branchTag
  | .route _ _ => routeTag

def tags : List ByteArray := [leafTag, extensionTag, branchTag, routeTag]

abbrev Effects := EffectSum Storage Digest
abbrev Action (A : Type) := OperationOver Effects Failure A

def digest (bytes : ByteArray) : Action ByteArray := raise id (Digest.blake3 bytes)

/-- The hash an admitted node is stored under; refusals request nothing. -/
def hashAdmitted (bytes : ByteArray) : Action (Except Refusal ByteArray) := do
  match admit bytes with
  | .error refusal => return .error refusal
  | .ok n => return .ok (← digest (tagOf n ++ bytes))

/-- Whether served bytes are the node they were requested as and, when they
are not, whose fault that is. Bytes that hash to the requested hash under
some kind's tag are the origin's own, whatever shape they take: no relay can
have produced them. Bytes that hash to nothing wanted are the peer's. -/
inductive Verdict where
  | accepted
  | originFault (refusal : Refusal)
  | peerFault
  deriving BEq, DecidableEq

def hashesToAny (expected bytes : ByteArray) : List ByteArray → Action Bool
  | [] => pure false
  | tag :: rest => do
    if (← digest (tag ++ bytes)) == expected then return true
    hashesToAny expected bytes rest

def verify (expected bytes : ByteArray) : Action Verdict := do
  match admit bytes with
  | .ok n => return if (← digest (tagOf n ++ bytes)) == expected then .accepted else .peerFault
  | .error refusal =>
    return if ← hashesToAny expected bytes tags then .originFault refusal else .peerFault

/-- Served bytes are a borrowed command input; a short read is a protocol failure. -/
def readInput (handle size : UInt64) : Action ByteArray := do
  let bytes ← raise id (Storage.readInput handle 0 size)
  if bytes.size != size.toNat then throw ⟨3, 0⟩
  return bytes

def admitInput (handle size : UInt64) : Action (Except Refusal ByteArray) := do
  hashAdmitted (← readInput handle size)

def verifyInput (expected : ByteArray) (handle size : UInt64) : Action Verdict := do
  verify expected (← readInput handle size)

end VerifiedCore.Trie
