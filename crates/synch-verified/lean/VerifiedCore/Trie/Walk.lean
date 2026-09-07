import VerifiedCore.Trie.Program
import VerifiedCore.Trie.Serve
import VerifiedCore.Host.Walk

/-! Structural walks over a trie: a cursor that moves one nibble at a time
through stored and compressed nodes alike, one explicit-stack descent that
holds the hostile-shape defences for every walk (a depth past which no
valid key can begin, an absolute ceiling on positions visited), and the
range scan, the directory-listing primitive. Depth is attacker-controlled:
a peer's trie is fetched by hash and nothing canonicalizes its shape, so
the frames live on the heap and the walk stops rather than overflows. -/
namespace VerifiedCore.Trie.Walk

open Host

/-- A position in a trie, one nibble per element. -/
abbrev Path := List UInt8

inductive Error where
  | host (failure : Failure)
  | missingNode (hash : ByteArray)
  | missingValue (hash : ByteArray)
  | decode (message : String)
  /-- A value sits at an odd nibble depth, where no byte key ends. -/
  | oddDepthValue
  /-- The walk visited more positions than a trie of the permitted size has. -/
  | ceiling
  deriving BEq, DecidableEq

/-- How deep, in nibbles, any walk descends: a key is at most `maxKeyBytes`,
so a value below this depth belongs to a key that could never have been
inserted, and walks prune there rather than following it down. -/
def maxDepthNibbles : Nat := maxKeyBytes * 2

/-- An absolute ceiling on the positions any one walk may visit, which
keeps a walk proportional to the trie: a fan-out DAG cannot turn a handful
of nodes into an unbounded walk. -/
def walkPositionCeiling : Nat := 8000000

/-- What a walk may spend: every iteration of the descent either advances
a frame's nibble or pops the frame, and a frame is pushed only for a
position charged against the ceiling, so a walk the ceiling admits takes at
most seventeen iterations per position, each requesting a handful of
effects, each paid for once. The budget is never reached by a walk the
ceiling admits. -/
def walkFuel : Nat := 256 * (walkPositionCeiling + 1)

def storage [Inject Storage E] (effect : Storage (Reply A)) : OperationOver E Error A :=
  raise Error.host effect
def redaction [Inject Redaction E] (effect : Redaction (Reply A)) : OperationOver E Error A :=
  raise Error.host effect

/-! ## Cursors -/

/-- A position: nothing, or a node, possibly the virtual remainder of a
compressed node the cursor sits part-way through. -/
inductive Cursor where
  | empty
  | at (node : Node)
  deriving BEq, DecidableEq

def Cursor.isEmpty : Cursor → Bool
  | .empty => true
  | .at _ => false

def Cursor.node : Cursor → Option Node
  | .empty => none
  | .at node => some node

/-- The value sitting exactly at the cursor's position. -/
def Cursor.value : Cursor → Option Value
  | .empty => none
  | .at (.leaf suffix value) => if suffix.size == 0 then some value else none
  | .at (.extension _ _) => none
  | .at (.branch _ value) => value

/-- The node at an address. A missing referenced node is an incomplete
snapshot, even if a peer refused it. A refusal is not authenticated evidence
that the subtree contains no permitted entries. -/
def cursorAt [Inject Storage E] [Inject Redaction E] : Option ByteArray → OperationOver E Error Cursor
  | none => pure .empty
  | some hash => do
    match ← storage (.readBytes nodeSpace hash) with
    | some raw =>
      match decode raw with
      | .error message => throw (.decode message)
      | .ok node => pure (.at node)
    | none => throw (.missingNode hash)

/-- One nibble down from a cursor. -/
def cursorChild [Inject Storage E] [Inject Redaction E] (cursor : Cursor) (nibble : UInt8) :
    OperationOver E Error Cursor :=
  match cursor with
  | .empty => pure .empty
  | .at (.leaf suffix value) =>
    match suffix.toList with
    | first :: rest =>
      if first == nibble then pure (.at (.leaf ⟨rest.toArray⟩ value)) else pure .empty
    | [] => pure .empty
  | .at (.extension segment child) =>
    match segment.toList with
    | first :: rest =>
      if first != nibble then pure .empty
      else if rest.isEmpty then cursorAt (some child)
      else pure (.at (.extension ⟨rest.toArray⟩ child))
    | [] => pure .empty
  | .at (.branch children _) => cursorAt ((children[nibble.toNat]?).getD none)

/-- One nibble of `follow`: the run is over, or the cursor's child under
the next nibble, empty as soon as one leads nowhere. -/
def followStep [Inject Storage E] [Inject Redaction E] :
    Cursor × List UInt8 → OperationOver E Error ((Cursor × List UInt8) ⊕ Cursor)
  | (cursor, []) => pure (.inr cursor)
  | (cursor, nibble :: rest) => do
    let child ← cursorChild cursor nibble
    if child.isEmpty then return .inr .empty else return .inl (child, rest)

/-- A cursor after each of a run of nibbles, empty as soon as one leads
nowhere. A nibble costs one iteration and at most two effects, so the
budget is never reached. -/
def follow [Inject Storage E] [Inject Redaction E] (cursor : Cursor) (nibbles : List UInt8) :
    OperationOver E Error Cursor :=
  OperationOver.iterate followStep .ceiling (3 * (nibbles.length + 1)) (cursor, nibbles)

/-! ## The descent -/

/-- What one step decided about a child position. -/
inductive Step (T : Type) where
  /-- A real position worth descending: charged against the ceiling, pushed. -/
  | descend (child : T)
  /-- A real position not worth descending. Charged, not pushed. -/
  | visited
  /-- Nothing there, or pruned before it was read. Uncharged. -/
  | skip
  /-- The walk is done. -/
  | stop

/-- The least nibble at or past `nibble` under which a cursor may have a
child: a compressed node's next nibble, a branch's next occupied slot. A
walk asks this before reading, so a position costs one step, not sixteen. -/
def Cursor.nextChild : Cursor → UInt8 → Option UInt8
  | .empty, _ => none
  | .at (.leaf suffix _), nibble => (suffix[0]?).filter (nibble ≤ ·)
  | .at (.extension segment _), nibble => (segment[0]?).filter (nibble ≤ ·)
  | .at (.branch children _), nibble => occupied (children.drop nibble.toNat) nibble.toNat
where
  occupied : List (Option ByteArray) → Nat → Option UInt8
    | [], _ => none
    | some _ :: _, index => some (UInt8.ofNat index)
    | none :: rest, index => occupied rest (index + 1)

/-- One frame of a descent: a parent's state, the next nibble to try under
it, and the parent's path. -/
abbrev Frame (T : Type) := T × UInt8 × Path

/-- One descent's state: the frames, the positions charged so far, and the
accumulator. -/
structure Descent (T A : Type) where
  stack : List (Frame T)
  positions : Nat
  acc : A

/-- One iteration of a structural walk over an explicit stack. `next` names
the nibbles worth a step; `step` is handed the accumulator, the parent's
state, the child nibble and the child's path, and the ceiling is charged on
its answer, so the position that trips it has done its own work before the
walk refuses. A frame is popped once its nibbles are spent or its path is as
deep as any key reaches. -/
def descend [Inject Storage E] [Inject Redaction E] (next : T → UInt8 → Option UInt8)
    (step : A → T → UInt8 → Path → OperationOver E Error (Step T × A)) :
    Descent T A → OperationOver E Error (Descent T A ⊕ A)
  | ⟨[], _, acc⟩ => pure (.inr acc)
  | ⟨(frame, nibble, path) :: stack, positions, acc⟩ =>
    let candidate :=
      if nibble.toNat ≥ 16 || path.length ≥ maxDepthNibbles then none
      else (next frame nibble).filter (·.toNat < 16)
    match candidate with
    | none => pure (.inl ⟨stack, positions, acc⟩)
    | some nibble => do
      let below := path ++ [nibble]
      let (answer, acc) ← step acc frame nibble below
      match answer with
      | .descend child =>
        if positions + 1 > walkPositionCeiling then throw .ceiling
        pure (.inl ⟨(child, 0, below) :: (frame, nibble + 1, path) :: stack, positions + 1, acc⟩)
      | .visited =>
        if positions + 1 > walkPositionCeiling then throw .ceiling
        pure (.inl ⟨(frame, nibble + 1, path) :: stack, positions + 1, acc⟩)
      | .skip => pure (.inl ⟨(frame, nibble + 1, path) :: stack, positions, acc⟩)
      | .stop => pure (.inr acc)

/-- Runs a descent from `start` at `base`, over the whole budget. -/
def walk [Inject Storage E] [Inject Redaction E] (next : T → UInt8 → Option UInt8)
    (step : A → T → UInt8 → Path → OperationOver E Error (Step T × A)) (start : T) (base : Path)
    (acc : A) : OperationOver E Error A :=
  OperationOver.iterate (descend next step) .ceiling walkFuel ⟨[(start, 0, base)], 0, acc⟩

/-! ## Keys and values -/

/-- An even run of nibbles packed back into bytes; an odd run is no byte key. -/
def bytesOfNibbles : List UInt8 → Option ByteArray
  | [] => some ByteArray.empty
  | hi :: lo :: rest => (bytesOfNibbles rest).map fun tail => ⟨#[hi * 16 + lo]⟩ ++ tail
  | [_] => none

/-- Every key under a position sorts at or before `after`, so the subtree
can be pruned when resuming a scan past it. A prefix of `after` may
straddle the cursor, so it is descended. -/
def subtreeIsBelow (path after : Path) : Bool :=
  let shared := min path.length after.length
  Serve.before (path.take shared) (after.take shared)

/-- A value's bytes, fetching an out-of-line payload. -/
def resolve [Inject Storage E] : Value → OperationOver E Error ByteArray
  | .inline bytes => pure bytes
  | .hash address => do
    match ← storage (.readBytes valueSpace address) with
    | none => throw (.missingValue address)
    | some bytes => pure bytes

/-! ## The range scan -/

abbrev Entry := ByteArray × ByteArray

/-- The value sitting exactly at `path`, if there is one and the scan has
passed `after`, prepended to the entries found so far. -/
def takeValue [Inject Storage E] (cursor : Cursor) (path : Path) (after : Option ByteArray)
    (limit : Option Nat) (out : List Entry) : OperationOver E Error (List Entry) := do
  if limit.any (fun bound => out.length ≥ bound) then return out
  match cursor.value with
  | none => return out
  | some value =>
    match bytesOfNibbles path with
    | none => throw .oddDepthValue
    | some key =>
      let passed := match after with
        | some bound => Serve.before bound.toList key.toList
        | none => true
      if passed then return (key, ← resolve value) :: out else return out

/-- One step of the collection: done once the limit is full, past a
subtree every key of which sorts before the cursor, and otherwise into the
child, taking the value at it. -/
def collectStep [Inject Storage E] [Inject Redaction E] (after : Option ByteArray) (limit : Option Nat)
    (out : List Entry) (parent : Cursor) (nibble : UInt8) (below : Path) :
    OperationOver E Error (Step Cursor × List Entry) := do
  if limit.any (fun bound => out.length ≥ bound) then return (.stop, out)
  if after.any (fun bound => subtreeIsBelow below (keyNibbles bound)) then return (.skip, out)
  let child ← cursorChild parent nibble
  if child.isEmpty then return (.skip, out)
  let out ← takeValue child below after limit out
  return (.descend child, out)

/-- Everything at and below a cursor, in key order, resuming strictly after
`after` and capped at `limit`. -/
def collect [Inject Storage E] [Inject Redaction E] (cursor : Cursor) (path : Path)
    (after : Option ByteArray) (limit : Option Nat) : OperationOver E Error (List Entry) := do
  let out ← takeValue cursor path after limit []
  let out ← walk Cursor.nextChild (collectStep after limit) cursor path out
  return out.reverse

/-- Every pair whose key starts with `keyPrefix`, in key order, optionally
resuming strictly after `startAfter` and capped at `limit` results: the
directory-listing primitive and the S3 listing cursor. -/
def scan [Inject Storage E] [Inject Redaction E] (root keyPrefix : ByteArray)
    (startAfter : Option ByteArray) (limit : Option UInt64) : OperationOver E Error (List Entry) := do
  let nibbles := keyNibbles keyPrefix
  let cursor ← follow (← cursorAt (rootOf root)) nibbles
  if cursor.isEmpty then return []
  collect cursor nibbles startAfter (limit.map (·.toNat))

/-- The scan's own effect algebra: raw reads and the refusals. -/
abbrev Effects := EffectSum Storage Redaction

end VerifiedCore.Trie.Walk
