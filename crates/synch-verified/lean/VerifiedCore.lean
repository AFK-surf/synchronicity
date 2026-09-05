/-!
Executable production decisions. This module imports only Lean's standard
prelude: proofs in specs/lean import this exact source, never a copied model.
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

/-- Overflow-free chunk-group count, including the empty object's group. -/
def groupCount (size : UInt64) : UInt64 :=
  if size == 0 then 1 else (size - 1) / 16384 + 1

/-- Size settlement: 0 refuses, 1 accepts retaining bits, 2 accepts resetting
bits. Inputs describe the row read inside the Rust transaction. -/
def settleSize (row durable complete finalHeld : Bool) (recorded claimed : UInt64) : UInt8 :=
  if !row || recorded == claimed then 1
  else if durable || complete || finalHeld then 0
  else if groupCount recorded == groupCount claimed then 1 else 2

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

/-- Scalar ABI for the proved group count. -/
@[export synch_lean_group_count]
def groupCountExport (size : UInt64) : UInt64 := groupCount size

/-- Scalar ABI for the proved settlement decision. -/
@[export synch_lean_settle_size]
def settleSizeExport (row durable complete finalHeld : Bool) (recorded claimed : UInt64) : UInt8 :=
  settleSize row durable complete finalHeld recorded claimed

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

end VerifiedCore
