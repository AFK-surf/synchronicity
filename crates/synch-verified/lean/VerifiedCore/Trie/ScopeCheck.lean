import VerifiedCore.Trie.Walk

/-! A confined publisher must not introduce entries outside its grant. The
whole check runs here, using the serving scope and the common bounded walk.
Granted subtrees need no reads. An unresolved missing node is an error, never
evidence that the publisher stayed within its grant. -/
namespace VerifiedCore.Trie.ScopeCheck

open Host Walk

/-- Decide a known occupied position before descending further. -/
def inspect (scope : Serve.Scope) (cursor : Cursor) (path : Path) :
    OperationOver Walk.Effects Walk.Error (Step Cursor × Option ByteArray) := do
  if scope.containsSubtree path then return (.skip, none)
  if !scope.admitsPath path || (cursor.value.isSome && !scope.admitsKeyPath path) then
    return (.stop, some ⟨path.toArray⟩)
  -- The common walker prunes at the key limit. A scope certificate must
  -- instead refuse an unresolved longer branch rather than certify it.
  if path.length ≥ maxDepthNibbles && (cursor.nextChild 0).isSome then throw .ceiling
  return (.descend cursor, none)

def step (scope : Serve.Scope) (_ : Option ByteArray) (parent : Cursor)
    (nibble : UInt8) (path : Path) :
    OperationOver Walk.Effects Walk.Error (Step Cursor × Option ByteArray) := do
  if scope.containsSubtree path then return (.skip, none)
  -- nextChild already established that this position is occupied. Reject
  -- an unauthorized branch without requiring its withheld bytes.
  if !scope.admitsPath path then return (.stop, some ⟨path.toArray⟩)
  inspect scope (← cursorChild parent nibble) path

/-- An unauthorized position, or no violation after every unresolved branch
was checked. Completeness and provenance remain separate obligations. -/
def firstOutside (root : ByteArray) (scope : Serve.Scope) :
    OperationOver Walk.Effects Walk.Error (Option ByteArray) := do
  if scope.containsSubtree [] || (rootOf root).isNone then return none
  let cursor ← cursorAt (some root)
  let (decision, answer) ← inspect scope cursor []
  match decision with
  | .descend cursor => walk Cursor.nextChild (step scope) cursor [] none
  | _ => pure answer

end VerifiedCore.Trie.ScopeCheck
