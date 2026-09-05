import Std.Data.TreeSet.Basic
import VerifiedCore.Cas

/-!
Executable production decisions. This module imports Lean's standard library:
proofs in specs/lean import this exact source, never a copied model.
No unsafe replacement, external implementation, or noncomputable definition
is used for a decision. Export wrappers are the only native entry points.
-/
namespace VerifiedCore

/-- Concrete scope, with finite granted paths. -/
structure Scope where
  /-- The whole keyspace. -/
  full : Bool
  /-- Prefix grants. -/
  prefixes : List (List Nat)
  /-- Exact-key grants. -/
  exact : List (List Nat)

/-- Everything below this position is granted. -/
def containsSubtree (s : Scope) (path : List Nat) : Bool :=
  s.full || s.prefixes.any (·.isPrefixOf path)

/-- A whole key, rather than a position on its spine, is granted. -/
def admitsKey (s : Scope) (key : List Nat) : Bool :=
  containsSubtree s key || s.exact.any (· == key)

/-- A position is inside a grant or on its spine. -/
def admitsPath (s : Scope) (path : List Nat) : Bool :=
  s.full || s.prefixes.any (fun p => path.isPrefixOf p || p.isPrefixOf path) ||
    s.exact.any (path.isPrefixOf ·)

/-- Wire node shape, without hashes or payloads irrelevant to authorization. -/
inductive Shape where
  | branch (inlineValue : Bool)
  | extension (suffix : List Nat)
  | leaf (suffix : List Nat)

/-- Permission to reveal a node's structure and any inline value. -/
def admitsNode (s : Scope) (path : List Nat) (shape : Shape) : Bool :=
  s.full || match shape with
    | .branch inlineValue => !inlineValue || admitsKey s path
    | .extension suffix => admitsPath s (path ++ suffix)
    | .leaf suffix => admitsKey s (path ++ suffix)

/-- Permission for the node's own payload, independent of spine permission. -/
def admitsValue (s : Scope) (path : List Nat) : Shape → Bool
  | .branch _ => admitsKey s path
  | .extension _ => false
  | .leaf suffix => admitsKey s (path ++ suffix)

/-- Convert FFI byte arrays into the paths used by the proved functions. -/
def pathOf (bytes : ByteArray) : List Nat := bytes.data.toList.map UInt8.toNat

/-- Construct an immutable scope; all allocation and path conversion is here. -/
@[export synch_lean_scope_new]
def scopeNew (full : Bool) (prefixes exact : Array ByteArray) : Scope :=
  ⟨full, prefixes.toList.map pathOf, exact.toList.map pathOf⟩

/-- Exported subtree predicate. -/
@[export synch_lean_scope_subtree]
def scopeSubtree (s : Scope) (path : ByteArray) : Bool := containsSubtree s (pathOf path)

/-- Exported key predicate. -/
@[export synch_lean_scope_key]
def scopeKey (s : Scope) (path : ByteArray) : Bool := admitsKey s (pathOf path)

/-- Exported position predicate. -/
@[export synch_lean_scope_path]
def scopePath (s : Scope) (path : ByteArray) : Bool := admitsPath s (pathOf path)

/-- Decode the adapter's shape tag. Invalid tags are refused by the exports. -/
def shapeOf (tag : UInt8) (inlineValue : Bool) (suffix : ByteArray) : Option Shape :=
  if tag == 0 then some (.branch inlineValue)
  else if tag == 1 then some (.extension (pathOf suffix))
  else if tag == 2 then some (.leaf (pathOf suffix)) else none

/-- Exported node authorization; unknown discriminants fail closed. -/
@[export synch_lean_scope_node]
def scopeNode (s : Scope) (path : ByteArray) (tag : UInt8) (inlineValue : Bool)
    (suffix : ByteArray) : Bool :=
  match shapeOf tag inlineValue suffix with
  | some shape => admitsNode s (pathOf path) shape
  | none => false

/-- Exported payload authorization; an extension never carries a value. -/
@[export synch_lean_scope_value]
def scopeValue (s : Scope) (path : ByteArray) (tag : UInt8) (suffix : ByteArray) : Bool :=
  match shapeOf tag false suffix with
  | some shape => admitsValue s (pathOf path) shape
  | none => false

/-- Executable completeness certificate cache. The mutation depth is unbounded;
the externally visible epoch saturates and permanently disables certification. -/
structure CertificateCache where
  /-- Cache keys are the exact bytes provided by the storage adapter. -/
  roots : List (List Nat) := []
  /-- Snapshot identifier, with the maximum reserved as a terminal epoch. -/
  epoch : UInt64 := 0
  /-- Number of transactions whose invalidation has not finished. -/
  mutating : Nat := 0
  /-- Maximum number of certificates retained before clearing. -/
  capacity : Nat

/-- Advance without wrapping an epoch back to a previously issued ticket. -/
def advanceEpoch (epoch : UInt64) : UInt64 :=
  if epoch == 18446744073709551615 then epoch else epoch + 1

/-- The sole certification guard, shared by the query and state update. -/
def canCertify (s : CertificateCache) (epoch : UInt64) : Bool :=
  s.mutating == 0 && s.epoch == epoch && epoch != 18446744073709551615

/-- Begin invalidation before storage visibility, retaining only supplied keys. -/
def beginMutation (s : CertificateCache) (keep : List (List Nat)) : CertificateCache :=
  { s with roots := s.roots.filter (fun q => keep.contains q)
           epoch := advanceEpoch s.epoch, mutating := s.mutating + 1 }

/-- Finish an invalidation. An unmatched finish leaves the cache unchanged. -/
def finishMutation (s : CertificateCache) : CertificateCache :=
  if s.mutating == 0 then s else
    { s with epoch := advanceEpoch s.epoch, mutating := s.mutating - 1 }

/-- Certify a completed snapshot, bounded by the configured cache capacity. -/
def certify (s : CertificateCache) (epoch : UInt64) (key : List Nat) : CertificateCache :=
  if canCertify s epoch then
    let roots := if s.roots.length >= s.capacity then [] else s.roots
    { s with roots := if roots.contains key then roots else key :: roots }
  else s

/-- An uncommitted transaction never exposes a retained certificate. -/
def knownComplete (s : CertificateCache) (key : List Nat) : Bool :=
  s.mutating == 0 && s.roots.contains key

/-- Create an empty cache. -/
@[export synch_lean_cache_new]
def cacheNew (capacity : UInt64) : CertificateCache := ⟨[], 0, 0, capacity.toNat⟩

/-- Read a snapshot epoch. -/
@[export synch_lean_cache_epoch]
def cacheEpoch (s : CertificateCache) : UInt64 := s.epoch

/-- Export the exact certification guard. -/
@[export synch_lean_cache_can_certify]
def cacheCanCertify (s : CertificateCache) (epoch : UInt64) : Bool := canCertify s epoch

/-- Export the certificate lookup using the same byte interpretation as scope. -/
@[export synch_lean_cache_known]
def cacheKnown (s : CertificateCache) (key : ByteArray) : Bool := knownComplete s (pathOf key)

/-- Export the mutation-begin transition. -/
@[export synch_lean_cache_begin]
def cacheBegin (s : CertificateCache) (keep : Array ByteArray) : CertificateCache :=
  beginMutation s (keep.toList.map pathOf)

/-- Export the mutation-finish transition. -/
@[export synch_lean_cache_finish]
def cacheFinish (s : CertificateCache) : CertificateCache := finishMutation s

/-- Export the certification transition. -/
@[export synch_lean_cache_certify]
def cacheCertify (s : CertificateCache) (epoch : UInt64) (key : ByteArray) : CertificateCache :=
  certify s epoch (pathOf key)

/-- Native byte output for paths/hashes previously read from byte arrays. -/
def bytesOf (path : List Nat) : ByteArray := ⟨(path.map UInt8.ofNat).toArray⟩

/-- A pending positional trie visit, including its complete-reference partner. -/
structure WalkPosition where
  /-- Hash at the same position in a known-complete reference, if present. -/
  reference : Option (List Nat)
  /-- Requested node hash. -/
  hash : List Nat
  /-- Nibble position, not merely a hash identity. -/
  path : List Nat

/-- Lexicographic visit order for persistent balanced sets. -/
instance walkVisitOrd : Ord (List Nat × Option (List Nat)) := lexOrd

/-- Depth remains relevant to canonicality even inside a complete prefix grant. -/
abbrev WalkVisit := Nat × (List Nat × Option (List Nat))

/-- Lexicographic order including the canonicality budget at a position. -/
instance walkDepthOrd : Ord WalkVisit := lexOrd

/-- Only same-depth visits can share validation. Inside a grant the exact path
does not affect authorization, but deeper reuse can violate the leaf-depth bound. -/
def walkVisit (scope : Scope) (p : WalkPosition) : WalkVisit :=
  (p.path.length, p.hash, if containsSubtree scope p.path then none else some p.path)

/-- Pure result of examining a finite frontier. -/
structure WalkPoll where
  /-- The part of the stack not yet examined. -/
  rest : List WalkPosition
  /-- Next node whose presence must be read. -/
  current : Option WalkPosition := none
  /-- Invalid positional depth; the walk must fail closed. -/
  fault : Option Nat := none

/-- Skip only reference-equal or already expanded positions, checking the
depth before either shortcut. Recursion is structural in the finite stack. -/
def pollFrontier (scope : Scope) (maxDepth : Nat)
    (seen : Std.TreeSet WalkVisit) : List WalkPosition → WalkPoll
  | [] => ⟨[], none, none⟩
  | p :: rest =>
    if p.path.length > maxDepth then ⟨rest, none, some p.path.length⟩
    else if p.reference == some p.hash || seen.contains (walkVisit scope p) then
      pollFrontier scope maxDepth seen rest
    else ⟨rest, some p, none⟩

/-- Executable resumable fetch control state. No frontier/set is mirrored in Rust. -/
structure MissingWalk where
  /-- Scope interpreted by the executable authorization functions. -/
  scope : Scope
  /-- Canonical key-depth ceiling. -/
  maxDepth : Nat
  /-- Stack of pending visits. -/
  frontier : List WalkPosition := []
  /-- Positional/hash visits already expanded. -/
  seen : Std.TreeSet WalkVisit := {}
  /-- Absent nodes or nodes awaiting their payload, in reverse encounter order. -/
  deferred : List WalkPosition := []
  /-- Extension children whose shape must be checked when they arrive. -/
  branches : Std.TreeSet (List Nat) := {}
  /-- Payload hashes already requested in this batch. -/
  asked : Std.TreeSet (List Nat) := {}
  /-- The node currently being interpreted by the storage adapter. -/
  current : Option WalkPosition := none
  /-- A canonicality failure is sticky, including across resume. -/
  fault : Option Nat := none
  /-- A selected read must receive an observation before another read is selected. -/
  awaiting : Bool := false
  /-- Error interpretation: node depth, value depth, or non-branch extension child. -/
  faultKind : UInt8 := 0
  /-- Offending hash for a shape error. -/
  faultHash : List Nat := []
  /-- Observation output: no request, node request, or payload request. -/
  requestKind : UInt8 := 0
  /-- Hash of a requested payload. -/
  requestHash : List Nat := []

/-- Select a storage read, recording its deduplication key exactly once. -/
def pollWalk (s : MissingWalk) : MissingWalk :=
  if s.fault.isSome || s.awaiting then s else
    let polled := pollFrontier s.scope s.maxDepth s.seen s.frontier
    { s with frontier := polled.rest, current := polled.current, fault := polled.fault
             awaiting := polled.current.isSome
             seen := match polled.current with
               | none => s.seen
               | some p => s.seen.insert (walkVisit s.scope p) }

/-- A missing node or payload must be revisited after the next fetch. -/
def deferWalk (s : MissingWalk) : MissingWalk :=
  match s.current with
  | none => s
  | some p => { s with deferred := p :: s.deferred }

/-- Resume without restarting from the root. Other completed visits remain seen. -/
def resumeWalk (s : MissingWalk) : MissingWalk :=
  { s with frontier := s.deferred ++ s.frontier, deferred := []
           seen := s.deferred.foldl (fun seen p => seen.erase (walkVisit s.scope p)) s.seen }

/-- Push a child only at an admitted position; the absolute path is built here. -/
def enqueueWalk (s : MissingWalk) (reference : Option (List Nat))
    (hash step : List Nat) : MissingWalk :=
  match s.current with
  | none => s
  | some p =>
    let path := p.path ++ step
    if admitsPath s.scope path then
      { s with frontier := ⟨reference, hash, path⟩ :: s.frontier }
    else s

/-- Construct a walk; an empty root or unadmitted root has no frontier. -/
@[export synch_lean_walk_new]
def walkNew (scope : Scope) (reference root : ByteArray) (maxDepth : UInt64) : MissingWalk :=
  { scope, maxDepth := maxDepth.toNat
    frontier := if root.isEmpty || !admitsPath scope [] then [] else
      [⟨if reference.isEmpty then none else some (pathOf reference), pathOf root, []⟩] }

/-- Exhaustion requires no frontier, deferred work, pending read or fault. -/
@[export synch_lean_walk_exhausted]
def walkExhausted (s : MissingWalk) : Bool :=
  s.frontier.isEmpty && s.deferred.isEmpty && s.fault.isNone && !s.awaiting

/-- Exported polling transition. -/
@[export synch_lean_walk_poll]
def walkPoll (s : MissingWalk) : MissingWalk := pollWalk s

/-- Poll result tag: drained, current position, or canonicality failure. -/
@[export synch_lean_walk_status]
def walkStatus (s : MissingWalk) : UInt8 :=
  if s.fault.isSome then 2 else if s.current.isSome then 1 else 0

/-- Export a current-position field, without exposing Lean object layout. -/
@[export synch_lean_walk_field]
def walkField (s : MissingWalk) (field : UInt8) : ByteArray :=
  if field == 3 then bytesOf s.faultHash else
  if field == 4 then bytesOf s.requestHash else
  match s.current with
  | none => ByteArray.empty
  | some p => bytesOf (if field == 0 then p.reference.getD [] else
      if field == 1 then p.hash else p.path)

/-- Diagnostic depth for a failed poll. -/
@[export synch_lean_walk_depth]
def walkDepth (s : MissingWalk) : UInt64 := UInt64.ofNat (s.fault.getD 0)

/-- Exported defer transition. -/
def walkDefer (s : MissingWalk) : MissingWalk := deferWalk s

/-- Exported resume transition. -/
@[export synch_lean_walk_resume]
def walkResume (s : MissingWalk) : MissingWalk := resumeWalk s

/-- Start a batch with independent payload deduplication. -/
@[export synch_lean_walk_batch]
def walkBatch (s : MissingWalk) : MissingWalk := { s with asked := {} }

/-- Export child-path construction and authorization. -/
def walkEnqueue (s : MissingWalk) (reference hash step : ByteArray) : MissingWalk :=
  enqueueWalk s (if reference.isEmpty then none else some (pathOf reference))
    (pathOf hash) (pathOf step)

/-- Test whether a future extension child has a pending shape obligation. -/
def walkRequiresBranch (s : MissingWalk) (hash : ByteArray) : Bool :=
  s.branches.contains (pathOf hash)

/-- Set or discharge an extension-child shape obligation. -/
def walkBranch (s : MissingWalk) (hash : ByteArray) (required : Bool) : MissingWalk :=
  { s with branches := if required then s.branches.insert (pathOf hash)
                      else s.branches.erase (pathOf hash) }

/-- Whether a payload would be a new request within this batch. -/
def walkUnasked (s : MissingWalk) (hash : ByteArray) : Bool := !s.asked.contains (pathOf hash)

/-- Remember a payload request for this batch, independently of deferral. -/
def walkAsk (s : MissingWalk) (hash : ByteArray) : MissingWalk :=
  { s with asked := s.asked.insert (pathOf hash) }

/-- Decoded structural fields; byte decoding and hashing remain at the ABI boundary. -/
inductive WalkNode where
  | branch (children : List (Option (List Nat)))
  | extension (segment child : List Nat)
  | leaf (suffix : List Nat)

/-- Every edge, in branch-slot order or the single extension direction. -/
def childEdges : WalkNode → List (List Nat × List Nat)
  | .branch children => children.zipIdx.filterMap fun (child, slot) =>
      child.map fun hash => ([slot], hash)
  | .extension segment child => [(segment, child)]
  | .leaf _ => []

/-- Reference pruning is enabled only for matching structural shapes. -/
def compatibleNodes : WalkNode → WalkNode → Bool
  | .branch _, .branch _ => true
  | .extension a _, .extension b _ => a == b
  | _, _ => false

/-- Pair only an edge with the reference edge at the exact same relative path. -/
def pairedEdges (reference node : WalkNode) :
    List (Option (List Nat) × List Nat × List Nat) :=
  (childEdges node).map fun (step, hash) =>
    (if compatibleNodes reference node then (childEdges reference).lookup step else none,
     hash, step)

/-- Expand decoded nodes with all pairing, path construction and admission in Lean. -/
def expandWalk (s : MissingWalk) (reference node : WalkNode) : MissingWalk :=
  (pairedEdges reference node).foldl
    (fun s (reference, hash, step) => enqueueWalk s reference hash step) s

/-- Marshal decoded fields; empty branch slots are absent hashes, not empty children. -/
@[export synch_lean_walk_node]
def walkNode (tag : UInt8) (children : Array ByteArray) (segment child : ByteArray) : WalkNode :=
  if tag == 0 then .branch (children.toList.map fun h =>
    if h.isEmpty then none else some (pathOf h))
  else if tag == 1 then .extension (pathOf segment) (pathOf child)
  else .leaf (pathOf segment)

/-- Production expansion export consumes decoded structural nodes. -/
def walkExpand (s : MissingWalk) (reference node : WalkNode) : MissingWalk :=
  expandWalk s reference node

/-- A decoded shape for the already shared authorization implementation. -/
def walkShape : WalkNode → Shape
  | .branch _ => .branch false
  | .extension segment _ => .extension segment
  | .leaf suffix => .leaf suffix

/-- Record a canonicality failure so subsequent polling cannot claim completion. -/
def failWalk (s : MissingWalk) (kind : UInt8) (depth : Nat) (hash : List Nat) : MissingWalk :=
  { s with fault := some depth, faultKind := kind, faultHash := hash, requestKind := 0 }

/-- An absent position is satisfied only by a refusal strictly above a full grant. -/
def observeAbsent (s : MissingWalk) (redacted : Bool) : MissingWalk :=
  if s.fault.isSome then s else
  let s := { s with requestKind := 0 }
  match s.current with
  | none => s
  | some p =>
    if redacted && !containsSubtree s.scope p.path then s
    else { deferWalk s with requestKind := 1 }

/-- Missing authorized payloads defer every dependent node, even when the hash
was already requested by a sibling in this batch. -/
def observePayload (s : MissingWalk) (node : WalkNode)
    (payload : Option (List Nat)) (present : Bool) : MissingWalk :=
  match s.current with
  | none => s
  | some p => match payload with
    | none => s
    | some hash =>
      if !present && admitsValue s.scope p.path (walkShape node) then
        { deferWalk s with asked := s.asked.insert hash
                           requestKind := if s.asked.contains hash then 0 else 2
                           requestHash := hash }
      else s

/-- Validate a loaded node and its extension-child observation before expansion.
Child observation tags: absent, branch, or other decoded shape. -/
def validateWalk (s : MissingWalk) (node : WalkNode) (childShape : UInt8) : MissingWalk :=
  match s.current with
  | none => s
  | some p =>
    if s.branches.contains p.hash && (match node with
      | .branch _ => false | .extension _ _ => true | .leaf _ => true) then
      failWalk s 2 0 p.hash
    else
      let s := { s with branches := s.branches.erase p.hash }
      match node with
      | .extension _ child =>
        if childShape == 0 then { s with branches := s.branches.insert child }
        else if childShape == 1 then s else failWalk s 2 0 child
      | .leaf suffix =>
        let depth := p.path.length + suffix.length
        if depth > s.maxDepth then failWalk s 1 depth p.hash else s
      | .branch _ => s

/-- The production response to a decoded node. Canonicality, expansion,
authorization, request deduplication and retry bookkeeping are one Lean transition. -/
def observePresent (s : MissingWalk) (reference node : WalkNode) (childShape : UInt8)
    (payload : Option (List Nat)) (present : Bool) : MissingWalk :=
  if s.fault.isSome then s else
  let checked := validateWalk { s with requestKind := 0 } node childShape
  if checked.fault.isSome then checked else
    observePayload (expandWalk checked reference node) node payload present

/-- Acknowledge one pending read, rejecting unsolicited or duplicate observations. -/
def finishObservation (s next : MissingWalk) : MissingWalk :=
  if s.fault.isSome then s else
  if s.awaiting then { next with awaiting := false }
  else failWalk s 3 0 []

/-- Export a positional refusal observation, acknowledging exactly one pending read. -/
@[export synch_lean_walk_absent]
def walkAbsent (s : MissingWalk) (redacted : Bool) : MissingWalk :=
  finishObservation s (observeAbsent s redacted)

/-- Export a decoded-node observation, with absent payload represented by empty bytes. -/
@[export synch_lean_walk_present]
def walkPresent (s : MissingWalk) (reference node : WalkNode) (childShape : UInt8)
    (payload : ByteArray) (present : Bool) : MissingWalk :=
  finishObservation s (observePresent s reference node childShape
    (if payload.isEmpty then none else some (pathOf payload)) present)

/-- Scalar diagnostics/output tag, with all decisions made by the transitions. -/
@[export synch_lean_walk_result]
def walkResult (s : MissingWalk) (field : UInt8) : UInt8 :=
  if field == 0 then s.faultKind else s.requestKind


end VerifiedCore
