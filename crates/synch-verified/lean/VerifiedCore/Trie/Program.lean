import VerifiedCore.Host
import VerifiedCore.Trie.Codec

/-! Complete trie operations over raw host storage. Node shape, key position,
value representation and read sequencing never cross the native boundary. -/
namespace VerifiedCore.Trie

open Host

def nodeSpace : String := "trie_nodes"
def valueSpace : String := "trie_values"
def maxKeyBytes : Nat := 4096

inductive LookupError where
  | keyTooLong (bytes : Nat)
  | missingNode (address : ByteArray)
  | missingValue (address : ByteArray)
  | decode (message : String)
  | depthExceeded

abbrev LookupResult := Except LookupError (Option ByteArray)

def resolveValue : Value → Operation LookupResult
  | .inline b => pure (.ok (some b))
  | .hash address => do
    match ← perform (.readBytes valueSpace address) with
    | none => return .error (.missingValue address)
    | some b => return .ok (some b)

def keyNibbles (key : ByteArray) : List UInt8 :=
  key.toList.flatMap (fun b => [b / 16, b % 16])

/-- Each nonterminal descent consumes at least one nibble. The explicit
budget retains the existing corrupted-store behavior independently of that
property; no partial/unsafe recursion participates in the production lookup.
-/
def lookup : Nat → Option ByteArray → List UInt8 → Operation LookupResult
  | 0, _, _ => pure (.error .depthExceeded)
  | _ + 1, none, _ => pure (.ok none)
  | fuel + 1, some address, rest => do
    match ← perform (.readBytes nodeSpace address) with
    | none => return .error (.missingNode address)
    | some raw =>
      match decode raw with
      | .error message => return .error (.decode message)
      | .ok (.leaf suffix value) =>
        if suffix.toList == rest then resolveValue value else pure (.ok none)
      | .ok (.extension segment child) =>
        let path := segment.toList
        if path.isEmpty || !path.isPrefixOf rest then return .ok none
        lookup fuel (some child) (rest.drop path.length)
      | .ok (.branch children value) =>
        match rest with
        | [] =>
          match value with
          | none => return .ok none
          | some value => resolveValue value
        | nibble :: rest => lookup fuel ((children[nibble.toNat]?).getD none) rest

/-- Lookup the caller's byte key in a root. The zero root is the empty trie,
but zero-valued child hashes are ordinary stored addresses, as before.
Failures from storage remain in the outer Host.Reply unchanged. The native
command validates the fixed 32-byte root address; that wire-shape check is not
delegated to the storage interpreter.
-/
def get (root key : ByteArray) : Operation LookupResult :=
  if key.size > maxKeyBytes then pure (.error (.keyTooLong key.size))
  else lookup (maxKeyBytes * 2 + 1)
    (if root.data.all (· == 0) then none else some root) (keyNibbles key)

/-- Native commands borrow their input rather than copying an unbounded key
before Lean can enforce the key limit. Only admitted keys request raw bytes. -/
def getInput (root : ByteArray) (handle keySize : UInt64) : Operation LookupResult := do
  if keySize.toNat > maxKeyBytes then return .error (.keyTooLong keySize.toNat)
  let key ← perform (.readInput handle 0 keySize)
  if key.size != keySize.toNat then throw ⟨3, 0⟩
  get root key

end VerifiedCore.Trie
