import VerifiedCore.Cas.Durable
import VerifiedCore.Cas.Program
import VerifiedCore.Host.Resources
import VerifiedCore.Host.Sweep

/-! Keeping the content store within bounds: the access clock cache retention
reads, eviction of reconstructible cached bytes by least recent use, the
collection of objects nothing references, and the removal of object files no
row accounts for. Each decision is taken over raw rows, counters and file
facts, and every removal that must not race a writer is taken inside the
remover's critical section, so what the program observed about an object is
still true when its bytes go. -/
namespace VerifiedCore.Cas.Collect

open Host

inductive Error where
  | host (failure : Failure)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Codec.CellType)
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  deriving BEq, DecidableEq

abbrev Effects := EffectSum Storage (EffectSum Access (EffectSum Clock (EffectSum Lease Sweep)))
abbrev Action (A : Type) := OperationOver Effects Error A

def storage (effect : Storage (Reply A)) : Action A := raise Error.host effect
def access (effect : Access (Reply A)) : Action A := raise Error.host effect
def clock : Action Int64 := raise Error.host Clock.nowNs
def lease (effect : Lease (Reply A)) : Action A := raise Error.host effect
def sweep (effect : Sweep (Reply A)) : Action A := raise Error.host effect

def transaction (body : Transaction → Action A) : Action A :=
  transactionOver Inject.inject Error.host body

def translateDurable : Durable.Error → Error
  | .host failure => .host failure
  | .malformed => .malformed
  | .columnType index column actual => .columnType index column actual
  | .sizeMismatch root recorded offered => .sizeMismatch root recorded offered

def translateLifecycle : Cas.Error → Error
  | .host failure => .host failure
  | .malformed => .malformed
  | .columnType index column actual => .columnType index column actual

/-- The remover's critical section: a writer's lease is taken inside the same
section, so a writer count read here is the writer count until the section
ends, and a decision to remove is carried out before any writer can begin. -/
def ordered (body : Action A) : Action A := do
  let token ← lease (.order "cas")
  ensure body (lease (.release token))

/-- Whether a best-effort step succeeded; its failure is not the sweep's. -/
def attempt (body : Action Unit) : Action Bool := ExceptT.mk do
  match ← body.run with
  | .ok () => pure (.ok true)
  | .error _ => pure (.ok false)

/-! ## The access clock -/

/-- Reads within a minute of the last recorded access are coalesced: retention
is decided in days, and a hot object would otherwise cost a row write per
read. -/
def touchInterval : Int64 := 60 * 1000000000

def decodeAccess : List Row → Except Error (Option Int64)
  | [] => .ok none
  | [[cell]] => (Codec.integerField (Error.columnType 0 "last_access") cell).map some
  | _ => .error .malformed

/-- Advance the object's access clock to now, unless it moved within the
interval or already reads later; answers whether it moved. -/
def touch (root : ByteArray) : Action Bool := do
  let now ← clock
  transaction fun tx => do
    let rows ← storage (.readRows tx "blobs" ["last_access"] [("root", .blob root)])
    match ← ExceptT.mk (.pure (decodeAccess rows)) with
    | none => return false
    | some last =>
      if now - last < touchInterval then return false
      let _ ← access (.update tx (Durable.byRoot root) [("last_access", .integer now)])
      return true

/-! ## Eviction -/

/-- A cached durable object: when it was last accessed and what its files cost. -/
structure Cached where
  root : ByteArray
  lastAccess : Int64
  bytes : UInt64

def decodeAccessed : Row → Except Error (ByteArray × Int64)
  | [root, accessed] => do
    let root ← Codec.blobField (Error.columnType 0 "root") root
    let accessed ← Codec.integerField (Error.columnType 1 "last_access") accessed
    return (root, accessed)
  | _ => .error .malformed

/-- The rows a scan yielded, validated before its trailing failure is observed. -/
def decodeScan (scan : Scan) : Except Error (List (ByteArray × Int64)) := do
  let rows ← scan.rows.mapM decodeAccessed
  match scan.failure with
  | some failure => throw (.host failure)
  | none => return rows

/-- Durable rows whose only local bytes are cached out-of-line groups: the
rows eviction may clear. A pinned row is among them, its promise living
remotely; a staged-only row never is, scratch being its only copy. -/
def cachedDurable : Selection := ⟨"blobs", [("inline", .null)], [], [("durable", .integer 0)]⟩

def measure (root : ByteArray) (lastAccess : Int64) : Action Cached := do
  let payload ← sweep (.fileBytes "cas_payload" root)
  let outboard ← sweep (.fileBytes "cas_outboard" root)
  return ⟨root, lastAccess, payload + outboard⟩

/-- Every cached durable object holding bytes on disk. -/
def cached : Action (List Cached) := do
  let scan ← access (.snapshot cachedDurable ["root", "last_access"])
  let rows ← ExceptT.mk (.pure (decodeScan scan))
  let entries ← rows.mapM fun (root, lastAccess) => measure root lastAccess
  return entries.filter (·.bytes != 0)

def usage (entries : List Cached) : UInt64 :=
  entries.foldl (fun sum entry => sum + entry.bytes) 0

/-- Clear entries, least recently used first, until the usage is within the
target; an entry a writer holds is skipped and counted against nothing. -/
def evictLoop (target : UInt64) : List Cached → UInt64 → UInt64 × UInt64 → Action (UInt64 × UInt64)
  | [], _, counts => pure counts
  | entry :: rest, used, (evicted, freed) =>
    if used ≤ target then pure (evicted, freed) else do
      let cleared ← ordered (within translateDurable (Durable.clearCache entry.root))
      if cleared then
        evictLoop target rest (if used < entry.bytes then 0 else used - entry.bytes)
          (evicted + 1, freed + entry.bytes)
      else evictLoop target rest used (evicted, freed)

def unlimited : UInt64 := 18446744073709551615

/-- Insert before the first entry accessed later: a stable ordering by
least recent use, structurally recursive so a proof can evaluate it. -/
def insertByAccess (entry : Cached) : List Cached → List Cached
  | [] => [entry]
  | head :: rest =>
    if entry.lastAccess ≤ head.lastAccess then entry :: head :: rest
    else head :: insertByAccess entry rest

def sortByAccess : List Cached → List Cached
  | [] => []
  | entry :: rest => insertByAccess entry (sortByAccess rest)

/-- Bring the cache within `limit` bytes, and free `shortfall` bytes more
than it uses when the filesystem is short of its floor, evicting by least
recent use. Answers the entries evicted and the bytes they freed. -/
def evict (limit : Option UInt64) (shortfall : UInt64) : Action (UInt64 × UInt64) := do
  let entries := sortByAccess (← cached)
  let used := usage entries
  let target := min (limit.getD unlimited) (if used < shortfall then 0 else used - shortfall)
  evictLoop target entries used (0, 0)

/-! ## Content collection -/

def unprotected : Selection := ⟨"blobs", [], [], []⟩

/-- What protects an object from collection: a pin, or an entry naming it. -/
def protections : List Exclusion :=
  [{ relation := "pins", equals := [], keys := [("root", "root")] },
   { relation := "entries", equals := [], keys := [("root", "content")] }]

/-- The rows nothing protected and nothing touched since `before`, as one
snapshot. It is a pre-filter, so the pass opens no transaction for a row a
live claim protects; the deletion re-reads every fact in its own transaction,
and that is what decides. -/
def candidates (before : Int64) : Action (List ByteArray) := do
  let scan ← access (.snapshotExcluding unprotected ["root", "last_access"] protections)
  let rows ← ExceptT.mk (.pure (decodeScan scan))
  return (rows.filter fun (_, accessed) => accessed < before).map Prod.fst

/-- Delete one candidate if it is still collectable, inside the section that
keeps its writer count true through the unlinks. -/
def collect (before : Int64) (root : ByteArray) : Action Bool := do
  match ← ordered (within translateLifecycle (Cas.delete root (some before))) with
  | .applied => return true
  | _ => return false

/-- Collect every object nothing references, nothing pins and nothing has
touched since `before`; answers how many went. -/
def gcContent (before : Int64) : Action UInt64 := do
  let roots ← candidates before
  roots.foldlM (fun swept root => do
    if ← collect before root then pure (swept + 1) else pure swept) 0

/-! ## Orphaned files -/

def spaces : List String := ["cas_payload", "cas_outboard"]

/-- Whether a row accounts for the object. -/
def accounted (root : ByteArray) : Action Bool := do
  let scan ← access (.snapshot (Durable.byRoot root) ["root"])
  match scan.rows, scan.failure with
  | [], some failure => throw (.host failure)
  | rows, _ => return !rows.isEmpty

/-- Remove one object file if it is older than the horizon, no row accounts
for its object and no writer holds it: the reading, the decision and the
unlink are one critical section, so nothing can make the file live in
between. Answers whether it went. -/
def sweepFile (before : Int64) (root : ByteArray) (space : String) : Action Bool := ordered do
  match ← sweep (.fileModified space root) with
  | none => return false
  | some modified =>
    if !(modified < before) then return false
    if ← accounted root then return false
    if (← storage (.readCounter "cas_writers" root)) != 0 then return false
    attempt (storage (.removeFile space root))

def sweepObject (before : Int64) (root : ByteArray) : Action UInt64 :=
  spaces.foldlM (fun swept space => do
    if ← sweepFile before root space then pure (swept + 1) else pure swept) 0

/-- The 32-byte roots a page lists, in order; a trailing fragment names nothing. -/
def roots (bytes : ByteArray) : List ByteArray :=
  (List.range (bytes.size / 32)).map fun index => bytes.extract (index * 32) (index * 32 + 32)

/-- No host partitions its store into more pages than this. -/
def maxPages : Nat := 65536

def sweepPages (before : Int64) : Nat → UInt64 → UInt64 → Action UInt64
  | 0, _, swept => pure swept
  | fuel + 1, page, swept => do
    match ← sweep (.listObjects page) with
    | none => pure swept
    | some listed =>
      let swept ← (roots listed).foldlM (fun swept root => do
        return swept + (← sweepObject before root)) swept
      sweepPages before fuel (page + 1) swept

/-- Remove every object file no row accounts for, once older than `before`
and unheld; answers how many went. -/
def gcOrphans (before : Int64) : Action UInt64 := sweepPages before maxPages 0 0

end VerifiedCore.Cas.Collect
