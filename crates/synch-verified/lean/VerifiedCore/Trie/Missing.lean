import VerifiedCore.Trie.Walk
import VerifiedCore.Trie.Mutate
import Std.Data.HashSet.Basic

/-! The requesting walk. Its frontier, deferred positions and deduplication
sets stay in Lean across batches; a fetch continuation never serializes them.
One position is committed only after all its reads and decodes succeed, and
an absent value defers its holder even when another holder already asked for
that value in this batch. A fetch encloses each batch in one transaction;
completeness callers may instead guard raw reads by the memo generation. -/
namespace VerifiedCore.Trie.Missing
open Host Serve

/-- Hash and depth identify a visit inside a grant; on its spine the whole
position matters too. Deeper reuse must still be checked for canonical depth. -/
abbrev Visit := Nat × ByteArray × Option ByteArray

/-- The same walk runs with hash sets in production and lists in kernel
fixtures. Erasing a deferred visit makes it eligible after resumption. -/
class WorkSet (K S : Type) where
  empty : S
  contains : S → K → Bool
  insert : S → K → S
  erase : S → K → S

instance [BEq K] [Hashable K] : WorkSet K (Std.HashSet K) :=
  ⟨{}, (·.contains ·), (·.insert ·), (·.erase ·)⟩

instance [BEq K] : WorkSet K (List K) :=
  ⟨[], (·.contains ·), fun set key => if set.contains key then set else key :: set,
    fun set key => set.filter (fun entry => !(entry == key))⟩

structure Position where
  reference : Option ByteArray
  hash : ByteArray
  path : ByteArray
  /-- Internal postorder marker.  A visit enters `seen` only when this marker
  reaches the head of the DFS stack, after every admitted child completed. -/
  finish : Bool := false
  deriving BEq, DecidableEq

inductive Fault where
  | nodeDepth (depth : Nat)
  | valueDepth (depth : Nat)
  | expectedBranch (hash : ByteArray)
  | valueLength (hash : ByteArray) (size : Nat) (routing : Bool)
  deriving BEq, DecidableEq

inductive Error where
  | host (failure : Failure)
  | decode (message : String)
  | canonical (fault : Fault)
  | exhausted
  deriving BEq, DecidableEq

structure Frontier (V H : Type) where
  positions : List Position
  deferred : List Position
  seen : V
  mustBeBranch : H
  fault : Option Fault
  deriving BEq

structure Context where
  scope : Scope
  owner : Option String

structure Batch where
  nodes : List (ByteArray × ByteArray) := []
  values : List (ByteArray × ByteArray) := []
  /-- Small addressed payloads are permitted only when an inspected routing
  holder requested them, even if a legacy holder asked for the hash first. -/
  routeValues : List ByteArray := []
  deriving BEq, DecidableEq

def Batch.size (batch : Batch) : Nat := batch.nodes.length + batch.values.length
def Batch.isEmpty (batch : Batch) : Bool := batch.nodes.isEmpty && batch.values.isEmpty

def visit (scope : Scope) (hash path : ByteArray) : Visit :=
  (path.size, hash, if scope.containsSubtree path.toList then none else some path)

def initial [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (reference : Option ByteArray) (root : ByteArray) : Frontier V H :=
  { positions := match rootOf root with
      | none => []
      | some hash => if context.scope.admitsPath [] then
          [⟨reference.bind rootOf, hash, ByteArray.empty, false⟩] else [],
    deferred := [], seen := WorkSet.empty Visit, mustBeBranch := WorkSet.empty ByteArray, fault := none }

def Frontier.isExhausted (frontier : Frontier V H) : Bool :=
  frontier.positions.isEmpty && frontier.deferred.isEmpty && frontier.fault.isNone

/-- Deferred positions are stored in stack order, as is the frontier. This
is the order obtained by pushing the Rust vector's deferred entries. -/
def resume [WorkSet Visit V] (context : Context) (frontier : Frontier V H) : Frontier V H :=
  { frontier with
    positions := frontier.deferred ++ frontier.positions,
    seen := frontier.deferred.foldl (fun seen position =>
      WorkSet.erase seen (visit context.scope position.hash position.path)) frontier.seen,
    deferred := [] }

abbrev Effects := EffectSum Storage (EffectSum Access Redaction)
abbrev Action (A : Type) := OperationOver Effects Error A

def storage (effect : Storage (Reply A)) : Action A := raise Error.host effect
def redaction (effect : Redaction (Reply A)) : Action A := raise Error.host effect

def decodeNode (raw : ByteArray) : Action Node :=
  ExceptT.mk (.pure ((decode raw).mapError Error.decode))

/-- Raw row presence. A returned row establishes presence even if a scan
would fail stepping further; an empty failed scan never establishes absence. -/
def rowPresent (relation : String) (equals : Fields) : Action Bool := do
  let scan ← raise Error.host (Access.snapshot ⟨relation, equals, [], []⟩ ["hash"])
  if !scan.rows.isEmpty then return true
  match scan.failure with
  | some failure => throw (.host failure)
  | none => return false

/-- Provenance is a literal row-presence query; an unowned node is absent
even when its bytes are held for another origin. -/
def loadOwned (owner : Option String) (hash : ByteArray) :
    Action (Option ByteArray) := do
  match owner with
  | some origin =>
    if !(← rowPresent "trie_node_origins"
        [("origin_id", .text origin), ("hash", .blob hash)]) then return none
  | none => pure ()
  storage (.readBytes nodeSpace hash)

/-- Pair children only when their parent shapes agree. Each step is the
same position in the reference; declining a pairing only loses pruning. -/
def pairedChildren (reference : Option Node) : Node → List Position
  | .leaf _ _ => []
  | .extension segment child =>
    let paired := match reference with
      | some (.extension theirSegment theirChild) =>
        if theirSegment == segment then some theirChild else none
      | _ => none
    [⟨paired, child, segment, false⟩]
  | .branch children _ =>
    children.zipIdx.filterMap fun (child, index) => child.map fun hash =>
      let paired := match reference with
        | some (.branch theirs _) => (theirs[index]?).getD none
        | _ => none
      ⟨paired, hash, ⟨#[index.toUInt8]⟩, false⟩
  | .route children _ =>
    children.zipIdx.filterMap fun (child, index) => child.map fun hash =>
      let paired := match reference with
        | some (.route theirs _) => (theirs[index]?).getD none
        | _ => none
      ⟨paired, hash, ⟨#[index.toUInt8]⟩, false⟩

def isBranch : Node → Bool
  | .branch _ _ => true
  | .route _ _ => true
  | _ => false

def isRoute : Node → Bool
  | .route _ _ => true
  | _ => false

inductive Checked where
  | skip
  | absent
  | boundary
  | expand (children : List Position) (pendingBranch : Option ByteArray)
      (absentValues : List ByteArray) (routing : Bool := false)

structure Expansion where
  children : List Position
  pendingBranch : Option ByteArray
  absentValues : List ByteArray
  routing : Bool

structure Prepared where
  node : Node
  children : List Position
  pendingBranch : Option ByteArray

/-- Inspect one addressed payload.  The factored operation makes the
successful-presence contract independent of the list traversal using it. -/
def valueAbsent (node : Node) (hash : ByteArray) : Action Bool := do
  match ← storage (.readBytes valueSpace hash) with
  | none => return true
  | some bytes =>
    if bytes.size > maxValueBytes || (!isRoute node && bytes.size ≤ inlineValueMax) then
      throw (.canonical (.valueLength hash bytes.size (isRoute node)))
    return false

def inspectValuesAux (node : Node) : List ByteArray → Action (List ByteArray)
  | [] => pure []
  | hash :: rest => do
    let absent ← valueAbsent node hash
    let more ← inspectValuesAux node rest
    return if absent then hash :: more else more

/-- Missing values directly named by an admitted holder. -/
def inspectValues (context : Context) (position : Position) (node : Node) :
    Action (List ByteArray) :=
  if context.scope.admitsValue position.path.toList node then
    inspectValuesAux node node.valueHashes
  else pure []

def inspectPendingBranch (node : Node) : Action (Option ByteArray) :=
  match node with
  | .extension _ child => do
    match ← storage (.readBytes nodeSpace child) with
    | none => pure (some child)
    | some raw =>
      if !isBranch (← decodeNode raw) then throw (.canonical (.expectedBranch child))
      pure none
  | _ => pure none

def inspectReference : Option ByteArray → Action (Option Node)
  | none => pure none
  | some hash => do
    match ← storage (.readBytes nodeSpace hash) with
    | none => pure none
    | some raw => pure (some (← decodeNode raw))

def validateNodeDepth (position : Position) : Node → Action Unit
  | .leaf suffix _ =>
    let depth := position.path.size + suffix.size
    if depth > Walk.maxDepthNibbles then throw (.canonical (.valueDepth depth)) else pure ()
  | _ => pure ()

def prepareDecoded [WorkSet Visit V] [WorkSet ByteArray H] (frontier : Frontier V H)
    (position : Position) (node : Node) : Action Prepared := do
  if WorkSet.contains frontier.mustBeBranch position.hash && !isBranch node then
    throw (.canonical (.expectedBranch position.hash))
  let pendingBranch ← inspectPendingBranch node
  let reference ← inspectReference position.reference
  validateNodeDepth position node
  return ⟨node, pairedChildren reference node, pendingBranch⟩

/-- Decode and validate a found holder before checking its payloads. -/
def prepareLoaded [WorkSet Visit V] [WorkSet ByteArray H] (frontier : Frontier V H)
    (position : Position) (raw : ByteArray) : Action Prepared := do
  let node ← decodeNode raw
  prepareDecoded frontier position node

/-- Continue inspection after the holder bytes have been found. -/
def inspectLoaded [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (frontier : Frontier V H) (position : Position) (raw : ByteArray) : Action Expansion := do
  let prepared ← prepareLoaded frontier position raw
  let absent ← inspectValues context position prepared.node
  return ⟨prepared.children, prepared.pendingBranch, absent, isRoute prepared.node⟩

/-- Inspect one pending position without changing any frontier state.
Every storage failure or decode error therefore leaves it retryable. -/
def inspect [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (frontier : Frontier V H) (position : Position) : Action Checked := do
  if position.path.size > Walk.maxDepthNibbles then
    throw (.canonical (.nodeDepth position.path.size))
  if position.reference == some position.hash then return .skip
  if WorkSet.contains frontier.seen (visit context.scope position.hash position.path) then return .skip
  match ← loadOwned context.owner position.hash with
  | none =>
    -- A peer's refusal does not authenticate the absence of permitted entries.
    -- Keep this position outstanding until its bytes or authenticated omission
    -- evidence arrive; scope alone cannot justify dropping an admitted spine.
    return .absent
  | some raw => do
    let expansion ← inspectLoaded context frontier position raw
    return .expand expansion.children expansion.pendingBranch expansion.absentValues expansion.routing

structure Work (V H : Type) where
  frontier : Frontier V H
  batch : Batch
  asked : H

def pushChildren (scope : Scope) (path : ByteArray) (children stack : List Position) : List Position :=
  children.foldl (fun stack child =>
    let path := path ++ child.path
    if scope.admitsPath path.toList then { child with path } :: stack else stack) stack

def askValues [WorkSet ByteArray H] (path : ByteArray) (absent : List ByteArray)
    (asked : H) (values : List (ByteArray × ByteArray)) : H × List (ByteArray × ByteArray) :=
  absent.foldl (fun (asked, values) hash =>
    if WorkSet.contains asked hash then (asked, values)
    else (WorkSet.insert asked hash, (path, hash) :: values)) (asked, values)

/-- Commit a successful inspection. Missing values defer the holder even
if its payload was already asked for through another holder this batch. -/
def commit [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (work : Work V H) (position : Position) (rest : List Position) : Checked → Work V H
  | .skip => { work with frontier := { work.frontier with positions := rest } }
  | .boundary =>
    { work with frontier := { work.frontier with
        positions := rest
        seen := WorkSet.insert work.frontier.seen (visit context.scope position.hash position.path) } }
  | .absent =>
    { work with
      frontier := { work.frontier with
        positions := rest
        deferred := position :: work.frontier.deferred }
      batch := { work.batch with nodes := (position.path, position.hash) :: work.batch.nodes } }
  | .expand children pendingBranch absentValues routing =>
    let pending := WorkSet.erase work.frontier.mustBeBranch position.hash
    let pending := match pendingBranch with
      | none => pending
      | some child => WorkSet.insert pending child
    let positions := pushChildren context.scope position.path children
      (if absentValues.isEmpty then { position with finish := true } :: rest else rest)
    let (asked, values) := askValues position.path absentValues work.asked work.batch.values
    let routeValues := if routing then absentValues.foldl (fun known hash =>
      if known.contains hash then known else hash :: known) work.batch.routeValues
      else work.batch.routeValues
    { frontier := { work.frontier with
        positions
        mustBeBranch := pending
        deferred := if absentValues.isEmpty then work.frontier.deferred
          else position :: work.frontier.deferred }
      batch := { work.batch with values, routeValues }
      asked }

/-- Postorder completion is the sole way a freshly inspected visit enters
`seen`.  Keeping it separate from `commit` prevents a later DAG occurrence
from pruning a subtree whose children are still pending. -/
def settle [WorkSet Visit V] (context : Context) (work : Work V H)
    (position : Position) (rest : List Position) : Work V H :=
  if work.frontier.deferred.isEmpty then
    { work with frontier := { work.frontier with
        positions := rest
        seen := WorkSet.insert work.frontier.seen
          (visit context.scope position.hash position.path) } }
  else
    -- A missing descendant may have been found earlier in this batch.  Keep
    -- its ancestors behind every retryable position; only a later postorder
    -- pass with no deferred dependency may certify their visits as settled.
    { work with frontier := { work.frontier with
        positions := rest
        deferred := work.frontier.deferred ++ [position] } }

/-- Only canonicality faults poison the walk. A failed host read or decode
returns the frontier at the interrupted position, including earlier visits. -/
def failed (frontier : Frontier V H) : Error → Frontier V H
  | .canonical fault => { frontier with fault := some fault }
  | _ => frontier

abbrev BatchResult (V H : Type) := Frontier V H × Except Error Batch

def finished (work : Work V H) : BatchResult V H :=
  (work.frontier, .ok ⟨work.batch.nodes.reverse, work.batch.values.reverse, work.batch.routeValues⟩)

/-- A batch stops before its next position once it has enough wants. The
error is returned with the recoverable state, not thrown past its owner. -/
def batchStep [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (maximum : Nat) (work : Work V H) : Action (Work V H ⊕ BatchResult V H) :=
  match work.frontier.fault with
  | some fault => pure (.inr (work.frontier, .error (.canonical fault)))
  | none =>
    match work.frontier.positions with
    | [] => pure (.inr (finished work))
    | position :: rest =>
      if position.finish then pure (.inl (settle context work position rest))
      else if work.batch.size ≥ maximum then pure (.inr (finished work))
      else ExceptT.mk do
        let result ← (inspect context work.frontier position).run
        return .ok (match result with
          | .error error => .inr (failed work.frontier error, .error error)
          | .ok checked => .inl (commit context work position rest checked))

/-- Far beyond the work ceiling of any materializable trie. The native
trampoline charges effects as well as positions and prevents stack growth
when a long sequence of already-seen positions is pruned without a read. -/
def batchFuel : Nat := 2 ^ 40

def nextBatch [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (frontier : Frontier V H) (maximum : Nat) : Action (BatchResult V H) :=
  OperationOver.iterate (batchStep context maximum) .exhausted batchFuel
    ⟨frontier, {}, WorkSet.empty ByteArray⟩

end VerifiedCore.Trie.Missing
