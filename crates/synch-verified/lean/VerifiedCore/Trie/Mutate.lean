import VerifiedCore.Host
import VerifiedCore.Host.Digest
import VerifiedCore.Host.Writes
import VerifiedCore.Trie.Codec
import VerifiedCore.Trie.Program
import VerifiedCore.Trie.Verify

/-! The trie write path: insert and remove over raw node reads, the digest
primitive and raw content-addressed writes. Canonical form is maintained on
every mutation, so any two tries holding the same key/value map have the
same root regardless of the operations that produced them: an extension
always sits above a branch and never has an empty segment, a branch always
has at least two occupants, and a removed key never rewrites a path it did
not change. -/
namespace VerifiedCore.Trie

open Host

inductive MutationError where
  | keyTooLong (bytes : Nat)
  | valueTooLong (bytes : Nat)
  | missingNode (address : ByteArray)
  | decode (message : String)
  | depthExceeded
  deriving BEq, DecidableEq

/-- The largest a trie value may be, inline or out of line. -/
def maxValueBytes : Nat := 32768

inductive Error where
  | host (failure : Failure)
  | domain (error : MutationError)

abbrev MutateEffects := EffectSum Storage (EffectSum Digest ByteWrites)
abbrev Mutate (A : Type) := OperationOver MutateEffects Error A

def request [Inject E MutateEffects] (effect : E (Reply A)) : Mutate A := raise Error.host effect

/-- The empty trie's root: the zero address, which is never a stored node. -/
def emptyRoot : ByteArray := ⟨(List.replicate 32 (0 : UInt8)).toArray⟩

def isEmptyRoot (root : ByteArray) : Bool := root.data.all (· == 0)

def load (address : ByteArray) : Mutate Node := do
  match ← request (Storage.readBytes nodeSpace address) with
  | none => throw (.domain (.missingNode address))
  | some raw =>
    match decode raw with
    | .error message => throw (.domain (.decode message))
    | .ok node => return node

/-- Store a node under `BLAKE3(tag ‖ canonical encoding)`: exactly the bytes
the ingress boundary will re-encode and admit at every peer. -/
def put (node : Node) : Mutate ByteArray := do
  let bytes := encode node
  let hash ← request (Digest.blake3 (tagOf node ++ bytes))
  request (ByteWrites.putBytes nodeSpace hash bytes)
  return hash

/-- Small values travel inside the node; larger ones are stored out of line
under their plain BLAKE3 digest, before the node that references them. -/
def valueRef (bytes : ByteArray) : Mutate Value := do
  if bytes.size ≤ inlineValueMax then return .inline bytes
  let hash ← request (Digest.blake3 bytes)
  request (ByteWrites.putBytes valueSpace hash bytes)
  return .hash hash

/-- A routing position never embeds its payload. Reuse an existing address
or store the inline bytes under their digest, including small payloads. -/
def addressValue : Value → Mutate ByteArray
  | .hash address => pure address
  | .inline bytes => do
    let address ← request (Digest.blake3 bytes)
    request (ByteWrites.putBytes valueSpace address bytes)
    return address

def commonPrefix : List UInt8 → List UInt8 → Nat
  | a :: as, b :: bs => if a == b then commonPrefix as bs + 1 else 0
  | _, _ => 0

def emptyChildren : List (Option ByteArray) := List.replicate 16 none

def childAt (children : List (Option ByteArray)) (nibble : UInt8) : Option ByteArray :=
  (children[nibble.toNat]?).getD none

def setChild (children : List (Option ByteArray)) (nibble : UInt8) (child : Option ByteArray) :
    List (Option ByteArray) :=
  children.set nibble.toNat child

def nibblesOf (ns : List UInt8) : ByteArray := ⟨ns.toArray⟩

/-- An extension never has an empty segment: nothing wraps nothing. -/
def wrapInExtension (segment : List UInt8) (child : ByteArray) : Mutate ByteArray :=
  if segment.isEmpty then pure child else put (.extension (nibblesOf segment) child)

/-- A leaf that shares only part of its key with the inserted one becomes a
branch under their common segment; an identical key replaces the value. -/
def splitLeaf (suffix : List UInt8) (old : Value) (key : List UInt8) (value : Value) :
    Mutate ByteArray := do
  if suffix == key then return ← put (.leaf (nibblesOf suffix) value)
  let cp := commonPrefix suffix key
  let mut children := emptyChildren
  let mut branchValue : Option Value := none
  match suffix.drop cp with
  | [] => branchValue := some old
  | nibble :: rest =>
    let child ← put (.leaf (nibblesOf rest) old)
    children := setChild children nibble (some child)
  match key.drop cp with
  | [] => branchValue := some value
  | nibble :: rest =>
    let child ← put (.leaf (nibblesOf rest) value)
    children := setChild children nibble (some child)
  let branch ← put (.branch children branchValue)
  wrapInExtension (key.take cp) branch

/-- An extension whose segment diverges from the inserted key becomes a
branch under the shared part, with the rest of the extension pushed down. -/
def splitExtension (segment : List UInt8) (child : ByteArray) (key : List UInt8) (value : Value) :
    Mutate ByteArray := do
  let cp := commonPrefix segment key
  match segment.drop cp with
  | [] => return child
  | nibble :: below =>
    let down ← if below.isEmpty then pure child else put (.extension (nibblesOf below) child)
    let mut children := setChild emptyChildren nibble (some down)
    let mut branchValue : Option Value := none
    match key.drop cp with
    | [] => branchValue := some value
    | nibble :: rest =>
      let leaf ← put (.leaf (nibblesOf rest) value)
      children := setChild children nibble (some leaf)
    let branch ← put (.branch children branchValue)
    wrapInExtension (key.take cp) branch

/-- One level of an insert's descent: how the level above was entered, so
the path can be rebuilt once the changed subtree below it is known. Keeping
the path as data rather than as nested continuations keeps each host round
trip a constant-depth step, whatever the trie's depth. -/
inductive InsertFrame where
  | extension (segment : ByteArray)
  | branch (children : List (Option ByteArray)) (value : Option Value) (nibble : UInt8)
  | route (children : List (Option ByteArray)) (value : Option ByteArray) (nibble : UInt8)

/-- Descend to the one position an insert changes, answering the subtree
that replaces it and the frames above it. Each level is entered by consuming
nibbles; the budget covers every key and refuses a store whose extensions
consume none. -/
def descend : Nat → Option ByteArray → List UInt8 → Value → List InsertFrame →
    Mutate (ByteArray × List InsertFrame)
  | 0, _, _, _, _ => throw (.domain .depthExceeded)
  | _ + 1, none, rest, value, stack => do return (← put (.leaf (nibblesOf rest) value), stack)
  | fuel + 1, some address, rest, value, stack => do
    match ← load address with
    | .extension segment child =>
      let path := segment.data.toList
      let cp := commonPrefix path rest
      if cp == path.length then
        descend fuel (some child) (rest.drop cp) value (.extension segment :: stack)
      else return (← splitExtension path child rest value, stack)
    | .branch children branchValue =>
      match rest with
      | [] => return (← put (.branch children (some value)), stack)
      | nibble :: rest =>
        descend fuel (childAt children nibble) rest value (.branch children branchValue nibble :: stack)
    | .leaf suffix old => return (← splitLeaf suffix.data.toList old rest value, stack)
    | .route children routeValue =>
      match rest with
      | [] => return (← put (.route children (some (← addressValue value))), stack)
      | nibble :: rest =>
        descend fuel (childAt children nibble) rest value (.route children routeValue nibble :: stack)

/-- Rebuild the path above a replaced subtree, innermost frame first. -/
def rebuild : ByteArray → List InsertFrame → Mutate ByteArray
  | built, [] => pure built
  | built, .extension segment :: stack => do rebuild (← put (.extension segment built)) stack
  | built, .branch children value nibble :: stack => do
    rebuild (← put (.branch (setChild children nibble (some built)) value)) stack
  | built, .route children value nibble :: stack => do
    rebuild (← put (.route (setChild children nibble (some built)) value)) stack

def insertAt (fuel : Nat) (cursor : Option ByteArray) (rest : List UInt8) (value : Value) :
    Mutate ByteArray := do
  let (built, stack) ← descend fuel cursor rest value []
  rebuild built stack

def depthBudget : Nat := maxKeyBytes * 2 + 1

/-- Insert or replace a key, answering the new root. -/
def insert (root key value : ByteArray) : Mutate ByteArray := do
  if key.size > maxKeyBytes then throw (.domain (.keyTooLong key.size))
  if value.size > maxValueBytes then throw (.domain (.valueTooLong value.size))
  let value ← valueRef value
  insertAt depthBudget (if isEmptyRoot root then none else some root) (keyNibbles key) value

/-- Push `segment` down into `child`, preserving canonical form: an
extension sits above a branch, never above a leaf or another extension. -/
def mergeDown (segment : List UInt8) (child : ByteArray) : Mutate ByteArray := do
  match ← load child with
  | .leaf suffix value => put (.leaf (nibblesOf (segment ++ suffix.data.toList)) value)
  | .extension below grandchild =>
    put (.extension (nibblesOf (segment ++ below.data.toList)) grandchild)
  | .branch _ _ | .route _ _ => put (.extension (nibblesOf segment) child)

/-- The occupied slots of a branch, with their nibbles, from slot `first`. -/
def occupiedFrom : Nat → List (Option ByteArray) → List (UInt8 × ByteArray)
  | _, [] => []
  | first, none :: rest => occupiedFrom (first + 1) rest
  | first, some child :: rest => (first.toUInt8, child) :: occupiedFrom (first + 1) rest

def occupiedChildren (children : List (Option ByteArray)) : List (UInt8 × ByteArray) :=
  occupiedFrom 0 children

/-- A branch with fewer than two occupants collapses: into nothing, into a
leaf for its own value, or into its one child with the nibble pushed down. -/
def collapse (children : List (Option ByteArray)) (value : Option Value) :
    Mutate (Option ByteArray) := do
  match occupiedChildren children, value with
  | [], none => return none
  | [], some value => return some (← put (.leaf (nibblesOf []) value))
  | [(nibble, child)], none => return some (← mergeDown [nibble] child)
  | _, value => return some (← put (.branch children value))

/-- Existing routing ancestors keep their routing form through edits. Only
the empty node disappears; a terminal or unary route remains meaningful. -/
def retainRoute (children : List (Option ByteArray)) (value : Option ByteArray) :
    Mutate (Option ByteArray) := do
  if occupants children (value.map Value.hash) == 0 then return none
  return some (← put (.route children value))

/-- One level of a removal's descent. Carries the level's own address as
well, so an unchanged child is answered with the node already stored rather
than an identical rebuild. -/
inductive RemoveFrame where
  | extension (address : ByteArray) (segment : List UInt8) (child : ByteArray)
  | branch (address : ByteArray) (children : List (Option ByteArray)) (value : Option Value)
      (nibble : UInt8) (child : ByteArray)
  | route (address : ByteArray) (children : List (Option ByteArray)) (value : Option ByteArray)
      (nibble : UInt8) (child : ByteArray)

/-- Descend to the key, answering what replaces the lowest level (`none` for
nothing at all) and the frames above it. -/
def descendRemove : Nat → ByteArray → List UInt8 → List RemoveFrame →
    Mutate (Option ByteArray × List RemoveFrame)
  | 0, _, _, _ => throw (.domain .depthExceeded)
  | fuel + 1, address, rest, stack => do
    match ← load address with
    | .leaf suffix _ => return (if suffix.data.toList == rest then none else some address, stack)
    | .extension segment child =>
      let path := segment.data.toList
      if !path.isPrefixOf rest then return (some address, stack)
      descendRemove fuel child (rest.drop path.length) (.extension address path child :: stack)
    | .branch children value =>
      match rest with
      | [] =>
        match value with
        | none => return (some address, stack)
        | some _ => return (← collapse children none, stack)
      | nibble :: rest =>
        match childAt children nibble with
        | none => return (some address, stack)
        | some child =>
          descendRemove fuel child rest (.branch address children value nibble child :: stack)
    | .route children value =>
      match rest with
      | [] =>
        match value with
        | none => return (some address, stack)
        | some _ => return (← retainRoute children none, stack)
      | nibble :: rest =>
        match childAt children nibble with
        | none => return (some address, stack)
        | some child =>
          descendRemove fuel child rest (.route address children value nibble child :: stack)

/-- Unwind the path above a replaced level. A level whose child came back
unchanged is itself unchanged, which is what keeps removing an absent key
from rewriting the path and so from giving one map a second root. -/
def unwind : Option ByteArray → List RemoveFrame → Mutate (Option ByteArray)
  | result, [] => pure result
  | result, .extension address segment child :: stack =>
    match result with
    | none => unwind none stack
    | some replacement =>
      if replacement == child then unwind (some address) stack
      else do unwind (some (← mergeDown segment replacement)) stack
  | result, .branch address children value nibble child :: stack =>
    if result == some child then unwind (some address) stack
    else do unwind (← collapse (setChild children nibble result) value) stack
  | result, .route address children value nibble child :: stack =>
    if result == some child then unwind (some address) stack
    else do unwind (← retainRoute (setChild children nibble result) value) stack

def removeAt (fuel : Nat) (address : ByteArray) (rest : List UInt8) : Mutate (Option ByteArray) := do
  let (result, stack) ← descendRemove fuel address rest []
  unwind result stack

/-- Remove a key, answering the new root; an absent key leaves it unchanged. -/
def remove (root key : ByteArray) : Mutate ByteArray := do
  if key.size > maxKeyBytes then throw (.domain (.keyTooLong key.size))
  if isEmptyRoot root then return emptyRoot
  match ← removeAt depthBudget root (keyNibbles key) with
  | none => return emptyRoot
  | some replacement => return replacement

/-! ## Native entry: borrowed inputs -/

def readMutationInput (handle size : UInt64) : Mutate ByteArray := do
  let bytes ← request (Storage.readInput handle 0 size)
  if bytes.size != size.toNat then throw (.host ⟨3, 0⟩)
  return bytes

/-- Bounds are refused before any input is borrowed, so an oversized key or
value never crosses the boundary. -/
def insertInput (root : ByteArray) (keySize valueSize : UInt64) : Mutate ByteArray := do
  if keySize.toNat > maxKeyBytes then throw (.domain (.keyTooLong keySize.toNat))
  if valueSize.toNat > maxValueBytes then throw (.domain (.valueTooLong valueSize.toNat))
  let key ← readMutationInput 0 keySize
  let value ← readMutationInput 1 valueSize
  insert root key value

def removeInput (root : ByteArray) (keySize : UInt64) : Mutate ByteArray := do
  if keySize.toNat > maxKeyBytes then throw (.domain (.keyTooLong keySize.toNat))
  remove root (← readMutationInput 0 keySize)

end VerifiedCore.Trie
