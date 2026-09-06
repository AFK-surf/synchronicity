import VerifiedCore.Host
import VerifiedCore.Cas
import VerifiedCore.Cas.Codec

/-! Complete CAS operations over raw storage effects. No host policy snapshots. -/
namespace VerifiedCore.Cas
open Host

/-- Host-level failure token for a projection no domain decoder can accept.
Scripted interpreters answer requests outside a program's contract with it;
the operations below report their own decoding failures as `Error`. -/
def malformedMetadata : Failure := ⟨2, 0⟩

/-- Terminal failures of acquisition and deletion, alongside the raw host
failure they preserve. A column of the wrong storage class is reported with
its position, name and observed class — the same terminal ingestion and reads
emit — so Rust translates it mechanically rather than decoding detail codes. -/
inductive Error where
  | host (failure : Failure)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Codec.CellType)
  deriving BEq, DecidableEq

/-- A storage program whose failures are the lifecycle domain's own. -/
abbrev Lifecycle (A : Type) := OperationWith Error A

def request (effect : Storage (Reply A)) : Lifecycle A :=
  performWith Error.host effect

/-- The existing database interprets every nonzero durable integer as true.
Neither NULL nor another cell type is silently coerced into a claim: the
column-type error names the class that was observed, and a projection of any
other shape is malformed metadata rather than an absent object. -/
def decodeDurability : List Row → Except Error Bool
  | [] => .ok false
  | [[cell]] => (Codec.integerField (Error.columnType 0 "durable") cell).map (· != 0)
  | _ => .error .malformed

/-- Acquire one holder's pin inside an already-owned transaction. The database
adapter receives raw projections and unconditional mutations only. UPSERT's
explicit update list preserves an old pin's creation time while clearing its
scheduled release, exactly as the existing storage format requires.
A plain pin never consults the holder's want; possession must find and
consume the holder's live want in the same transaction, so a late fetch cannot
resurrect an orphan role claim after role removal. -/
def acquireIn (tx : Transaction) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) : Lifecycle Bool := do
  let rows ← request (.readRows tx "blobs" ["durable"] [("root", .blob root)])
  let durable ← match decodeDurability rows with
    | .ok durable => pure durable
    | .error error => throw error
  if !durable then
    return false
  if possession then
    let wanted ← request (.readRows tx "content_want" ["root"]
      [("root", .blob root), ("holder", .text holder)])
    if wanted.isEmpty then
      return false
    let _ ← request (.deleteRows tx "content_want"
      [("root", .blob root), ("holder", .text holder)])
  request (.upsert tx "pins"
    [("root", .blob root), ("holder", .text holder),
      ("created_at", .integer now), ("release_after", .null)]
    ["root", "holder"] ["release_after"])
  return true

/-- Complete pin or possession acquisition: begin before metadata reads and
return only after commit; any failed effect is handled by the shared verified
transaction program. Other Lean operations can compose `acquireIn` directly. -/
def acquire (root : ByteArray) (holder : String) (now : Int64)
    (possession : Bool) : Lifecycle Bool :=
  transactionWith Error.host fun tx => acquireIn tx root holder now possession

/-- A public holder value, not a parsed database spelling. In particular an
unknown holder whose spelling resembles a role does not acquire that role's
meaning, and an explicitly constructed role may name the empty space. -/
inductive PinHolder where
  | operator
  | source (space : String)
  | replica (space : String)
  | other (text : String)
  deriving DecidableEq, BEq

/-- Preserve the persisted holder format at the command boundary. -/
def PinHolder.render : PinHolder → String
  | .operator => "operator"
  | .source space => "source:" ++ space
  | .replica space => "replica:" ++ space
  | .other text => text

/-- Only typed standing roles are protected by their space's live entries. -/
def PinHolder.space : PinHolder → Option String
  | .source space | .replica space => some space
  | .operator | .other _ => none

/-- Release precisely one holder's claim. The exclusion is part of the same
raw DELETE as the mutation: there is no separate protection read whose answer
could become stale. The host performs no role interpretation. -/
def unpinIn (tx : Transaction) (root : ByteArray) (holder : PinHolder) : Operation Bool := do
  let blockers : List Exclusion := match holder.space with
    | none => []
    | some space => [{ relation := "entries", equals := [("space", .text space), ("content", .blob root)] }]
  let count ← perform (.deleteRows tx "pins"
    [("root", .blob root), ("holder", .text holder.render)] blockers)
  return count != 0

/-- A complete explicit release, acknowledged only after transaction commit.
Failure of deletion or commit rolls back through the shared transaction
program, preserving the original failure even if rollback also fails. -/
def unpin (root : ByteArray) (holder : PinHolder) : Operation Bool :=
  transaction fun tx => unpinIn tx root holder

/-- Expire scheduled claims with one atomic bulk mutation. The optional holder
is an exact persisted key, not a role-based protection policy. Every live entry
protects its content, independently of holder or space. SQL's ordinary `<=`
comparison excludes unscheduled NULL releases and includes the deadline itself.
The correlated exclusion is evaluated as part of the DELETE, never as a stale
snapshot or a per-pin host decision. -/
def expireIn (tx : Transaction) (holder : Option PinHolder) (now : Int64) : Operation Nat := do
  let equals := match holder with
    | none => []
    | some holder => [("holder", .text holder.render)]
  perform (.deleteRows tx "pins" equals
    [{ relation := "entries", equals := [], keys := [("root", "content")] }]
    [("release_after", .integer now)])

/-- Complete global or holder-specific scheduled expiry. The number of deleted
claims becomes observable only after commit; any primary failure is preserved
by the shared transaction program, including when rollback also fails. -/
def expire (holder : Option PinHolder) (now : Int64) : Operation Nat :=
  transaction fun tx => expireIn tx holder now

/-- Preserve absence and signed access time; do not coerce malformed cells. -/
def decodeAccess : List Row → Except Error (Option Int64)
  | [] => .ok none
  | [[cell]] => (Codec.integerField (Error.columnType 0 "last_access") cell).map some
  | _ => .error .malformed

/-- All protection observations occur within the immediate transaction and
the host's surrounding ordering session. Existence reads are bounded queries,
not host-supplied protection decisions. -/
def deleteIn (tx : Transaction) (root : ByteArray) (before : Option Int64) : Lifecycle Outcome := do
  let pinned ← request (.existsRows tx "pins" [("root", .blob root)])
  let referenced ← request (.existsRows tx "entries" [("content", .blob root)])
  let rows ← request (.readRows tx "blobs" ["last_access"] [("root", .blob root)])
  let accessed ← match decodeAccess rows with
    | .ok value => pure value
    | .error error => throw error
  let writers ← request (.readCounter "cas_writers" root)
  let plan := planLifecycle (.delete
    ⟨accessed.isSome, writers != 0, pinned, referenced, accessed.getD 0⟩ before)
  for mutation in plan.transaction do
    match mutation with
    | .deleteRow => let _ ← request (.deleteRows tx "blobs" [("root", .blob root)])
  return plan.outcome

/-- Best-effort cleanup is requested only after successful transaction
completion. Failure of one unlink does not prevent the second attempt. -/
def cleanup (root : ByteArray) : Lifecycle Unit := do
  try request (.removeFile "cas_payload" root) catch _ => pure ()
  try request (.removeFile "cas_outboard" root) catch _ => pure ()

/-- Complete deletion, including cleanup. No mutation plan leaves Lean. -/
def delete (root : ByteArray) (before : Option Int64) : Lifecycle Outcome := do
  let outcome ← transactionWith Error.host fun tx => deleteIn tx root before
  match outcome with
  | .applied => cleanup root
  | _ => pure ()
  return outcome

end VerifiedCore.Cas
