import VerifiedCore.Trie.Mutate

/-! Publication form for private scoped synchronization. Routing spines reveal
one level of child commitments at a time, with separately addressed payloads.
Compression remains available below a complete public or per-space prefix.
This command changes representation, never the logical keys or values. -/
namespace VerifiedCore.Trie.Normalize
open Host

/-- Slash in the byte-aligned remainder of a file namespace path. A partial
byte is not a separator, and a slash must be completely traversed before the
rest of that space can remain compressed. -/
def passedSeparator : List UInt8 → Bool
  | 2 :: 15 :: _ => true
  | _ :: _ :: rest => passedSeparator rest
  | _ => false

/-- Metadata scope boundaries are schema properties, independent of today's
grants. Delegations are public; blob availability is an entirely separate
namespace; files are shared by the prefix ending in their space separator.
Exact-key namespaces retain routing all the way to the addressed value. -/
def belowBoundary (path : List UInt8) : Bool :=
  [6, 4, 3, 10].isPrefixOf path || -- d:
  [6, 2, 3, 10].isPrefixOf path || -- b:
  ([6, 6, 3, 10].isPrefixOf path && passedSeparator (path.drop 4)) -- f:<space>/

inductive Cursor where
  | stored (address : ByteArray)
  | node (value : Node)

def addressOptional : Option Value → Mutate (Option ByteArray)
  | none => pure none
  | some value => return some (← addressValue value)

inductive Work where
  | visit (path : List UInt8) (cursor : Cursor)
  | assemble (positions : List UInt8) (value : Option ByteArray)

structure State where
  work : List Work
  results : List ByteArray := []

/-- Child visits push results in reverse visitation order. Consume exactly
those results, leaving the surrounding traversal's results untouched. -/
def assembleChildren : List UInt8 → List ByteArray → List (Option ByteArray) →
    Option (List (Option ByteArray) × List ByteArray)
  | [], results, children => some (children, results)
  | position :: rest, address :: results, children =>
    assembleChildren rest results (setChild children position (some address))
  | _ :: _, [], _ => none

/-- Schedule children before the routing node that commits to their results.
The stack lives in Lean data rather than in nested host continuations. -/
def schedule (path : List UInt8) (children : List (Option ByteArray))
    (value : Option ByteArray) (state : State) : State :=
  let selected := (List.range 16).filterMap fun index =>
    ((children[index]?).getD none).map fun address => (index.toUInt8, address)
  let visits := selected.map fun (position, address) =>
    Work.visit (path ++ [position]) (.stored address)
  { state with work := visits ++ (Work.assemble (selected.map Prod.fst) value :: state.work) }

def step (state : State) : Mutate (State ⊕ ByteArray) := do
  match state.work with
  | [] =>
    match state.results with
    | [root] => return .inr root
    | _ => throw (.domain (.decode "invalid normalization result stack"))
  | .assemble positions value :: work =>
    match assembleChildren positions.reverse state.results emptyChildren with
    | none => throw (.domain (.decode "missing normalization child result"))
    | some (children, results) =>
      let root ← put (.route children value)
      return .inl ⟨work, root :: results⟩
  | .visit path cursor :: work =>
    let state := { state with work }
    if path.length > maxKeyBytes * 2 then throw (.domain .depthExceeded)
    if belowBoundary path then
      let root ← match cursor with
        | .stored address => pure address
        | .node node => put node
      return .inl { state with results := root :: state.results }
    let node ← match cursor with
      | .stored address => load address
      | .node node => pure node
    match node with
    | .leaf suffix value =>
      match suffix.toList with
      | [] =>
        let root ← put (.route emptyChildren (some (← addressValue value)))
        return .inl { state with results := root :: state.results }
      | nibble :: rest =>
        let next := Work.visit (path ++ [nibble]) (.node (.leaf (nibblesOf rest) value))
        return .inl { state with work := next :: Work.assemble [nibble] none :: work }
    | .extension segment child =>
      match segment.toList with
      | [] => throw (.domain (.decode "an extension prefix is empty"))
      | nibble :: rest =>
        let next := if rest.isEmpty then Cursor.stored child
          else .node (.extension (nibblesOf rest) child)
        let pending := Work.visit (path ++ [nibble]) next
        return .inl { state with work := pending :: Work.assemble [nibble] none :: work }
    | .branch children value =>
      return .inl (schedule path children (← addressOptional value) state)
    | .route children value =>
      return .inl (schedule path children value state)

/-- The same work ceiling used by collection and requesting traversal. Depth
is checked independently, including for malformed cyclic stored graphs. -/
def workFuel : Nat := 2 ^ 40

/-- Normalize the actual stored publication. The caller commits its returned
root, retained graph and signed head in the same publication transaction. -/
def publication (root : ByteArray) : Mutate ByteArray :=
  if isEmptyRoot root then pure emptyRoot
  else OperationOver.iterate step (.domain .depthExceeded) workFuel
    ⟨[.visit [] (.stored root)], []⟩

end VerifiedCore.Trie.Normalize
