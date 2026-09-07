import VerifiedCore.Trie.Walk
import VerifiedCore.Host.Digest

/-! The structural diff between two roots: both tries walked in lockstep,
pruning every subtree whose two sides are the same node, which, because
nodes are content-addressed, is exactly what makes re-materializing the
entries after a head flip cost the change rather than the tree. A value is
compared as a value, not as a representation: inline bytes and the address
of the same bytes out of line are one value, and telling them apart would
let a peer force a full re-materialization by republishing with the
representations flipped. -/
namespace VerifiedCore.Trie.Diff

open Host Walk

/-- One key's difference between two roots. -/
structure Change where
  key : ByteArray
  old : Option Value
  new : Option Value
  deriving BEq, DecidableEq

/-- Added (0), changed (1) or deleted (2). -/
def Change.kind (change : Change) : UInt64 :=
  match change.old, change.new with
  | none, some _ => 0
  | some _, none => 2
  | _, _ => 1

def digest [Inject Digest E] (bytes : ByteArray) : OperationOver E Error ByteArray :=
  raise Error.host (Digest.blake3 bytes)
def apply [Inject Apply E] (effect : Apply (Reply A)) : OperationOver E Error A :=
  raise Error.host effect

/-- Whether two value references denote the same bytes, decided without
touching the store: an out-of-line address is the digest of the value, so
the inline side is hashed and compared. -/
def sameValue [Inject Digest E] : Option Value → Option Value → OperationOver E Error Bool
  | none, none => pure true
  | some (.inline p), some (.inline q) => pure (p == q)
  | some (.hash p), some (.hash q) => pure (p == q)
  | some (.inline p), some (.hash q) => do return (← digest p) == q
  | some (.hash q), some (.inline p) => do return (← digest p) == q
  | _, _ => pure false

/-- The difference at one position, if any, and whether the subtree below
is worth descending: not when both sides are absent, and not when they are
the same node, whose subtrees are then the same. -/
def enter [Inject Digest E] (a b : Cursor) (path : Path) :
    OperationOver E Error (Option Change × Bool) := do
  let worth := match a.node, b.node with
    | none, none => false
    | some x, some y => x != y
    | _, _ => true
  if !worth then return (none, false)
  let va := a.value
  let vb := b.value
  if ← sameValue va vb then return (none, true)
  match bytesOfNibbles path with
  | none => throw .oddDepthValue
  | some key => return (some ⟨key, va, vb⟩, true)

/-- Whether both sides hold the same address under a nibble: the subtrees
there are then the same node and are pruned before either is read, which is
what keeps a diff proportional to the change when both roots are branches
along the changed spine. -/
def sameChild : Cursor → Cursor → UInt8 → Bool
  | .at (.branch a _), .at (.branch b _), nibble =>
    match (a[nibble.toNat]?).getD none, (b[nibble.toNat]?).getD none with
    | some x, some y => x == y
    | _, _ => false
  | .at (.route a _), .at (.route b _), nibble
  | .at (.route a _), .at (.branch b _), nibble
  | .at (.branch a _), .at (.route b _), nibble =>
    match (a[nibble.toNat]?).getD none, (b[nibble.toNat]?).getD none with
    | some x, some y => x == y
    | _, _ => false
  | _, _, _ => false

/-- The next nibble under which either side may have a child. -/
def nextChild (pair : Cursor × Cursor) (nibble : UInt8) : Option UInt8 :=
  match pair.1.nextChild nibble, pair.2.nextChild nibble with
  | some a, some b => some (min a b)
  | some a, none => some a
  | none, b => b

/-- Walks both roots in lockstep within `scope`, handing each change the
scope admits to `emit` as it is found, in walk order. An out-of-scope
position holds nothing this node was sent, so it is skipped before its
cursors are taken, as is a position both sides address alike; traversing a
grant's spine does not grant a branch value, so a change is filtered by its
whole key. -/
def diffEach [Inject Storage E] [Inject Redaction E] [Inject Digest E] (scope : Serve.Scope)
    (emit : A → Change → OperationOver E Error A) (oldRoot newRoot : ByteArray) (acc : A) :
    OperationOver E Error A := do
  if oldRoot == newRoot then return acc
  let a ← cursorAt (rootOf oldRoot)
  let b ← cursorAt (rootOf newRoot)
  let admitted : A → Change → OperationOver E Error A := fun acc change =>
    if scope.admitsKeyPath (keyNibbles change.key) then emit acc change else pure acc
  let (change, worth) ← enter a b []
  let acc ← match change with
    | some change => admitted acc change
    | none => pure acc
  if !worth then return acc
  walk nextChild (fun acc (pair : Cursor × Cursor) nibble below => do
      if !scope.admitsPath below then return (.skip, acc)
      if sameChild pair.1 pair.2 nibble then return (.skip, acc)
      let ca ← cursorChild pair.1 nibble
      let cb ← cursorChild pair.2 nibble
      if ca.isEmpty && cb.isEmpty then return (.skip, acc)
      let (change, worth) ← enter ca cb below
      let acc ← match change with
        | some change => admitted acc change
        | none => pure acc
      return (if worth then .descend (ca, cb) else .visited, acc)) (a, b) [] acc

/-- Every differing key between two roots, in key order: the walk visits
positions depth-first with nibbles ascending and reports a position's own
value before anything below it, which is the keys' lexicographic order, so
the changes are listed as they were found. A sort here would cost the
corpus squared and, written by recursion, the native stack. -/
def diff [Inject Storage E] [Inject Redaction E] [Inject Digest E] (oldRoot newRoot : ByteArray) :
    OperationOver E Error (List Change) := do
  let changes ← diffEach ⟨none, []⟩ (fun acc change => pure (change :: acc)) oldRoot newRoot []
  return changes.reverse

/-- The diff a head promotion applies: streamed, one change at a time, only
the new side resolved (the old side decides nothing but whether the change
is a deletion, which its presence already says), confined to what `scope`
admits, exactly as the fetch that filled the trie was. Answers how many
changes were handed over. -/
def materialize [Inject Storage E] [Inject Redaction E] [Inject Digest E] [Inject Apply E]
    (scope : Serve.Scope) (oldRoot newRoot : ByteArray) : OperationOver E Error UInt64 :=
  diffEach scope (fun count change => do
      let new ← match change.new with
        | none => pure none
        | some value => some <$> resolve value
      apply (.applyChange change.key change.kind new)
      return count + 1) oldRoot newRoot 0

/-- The diff's effect algebra: raw reads, the refusals, the digest and the
materializer. -/
abbrev Effects := EffectSum Storage (EffectSum Redaction (EffectSum Digest Apply))

end VerifiedCore.Trie.Diff
