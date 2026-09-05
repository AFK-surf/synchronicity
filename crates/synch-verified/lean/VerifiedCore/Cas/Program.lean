import VerifiedCore.Host
import VerifiedCore.Cas

/-! Complete CAS operations over raw storage effects. No host policy snapshots. -/
namespace VerifiedCore.Cas
open Host

/-- Malformed projected metadata is distinct from an absent object. -/
def malformedMetadata : Failure := ⟨2, 0⟩

/-- The existing database interprets every nonzero durable integer as true.
Neither NULL nor another cell type is silently coerced into a claim. Failure
details 1/2/3 preserve the NULL/text/blob column-type error at the public API;
they describe an error selected here, not metadata for Rust to interpret. -/
def decodeDurability : List Row → Reply Bool
  | [] => .ok false
  | [[.integer value]] => .ok (value != 0)
  | [[.null]] => .error ⟨2, 1⟩
  | [[.text _]] => .error ⟨2, 2⟩
  | [[.rawText _]] => .error ⟨2, 2⟩
  | [[.blob _]] => .error ⟨2, 3⟩
  | [[.real _]] => .error ⟨2, 7⟩
  | _ => .error malformedMetadata

/-- Acquire one holder's pin inside an already-owned transaction. The database
adapter receives raw projections and unconditional mutations only. UPSERT's
explicit update list preserves an old pin's creation time while clearing its
scheduled release, exactly as the existing storage format requires. -/
def acquireIn (tx : Transaction) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) : Operation Bool := do
  let rows ← perform (.readRows tx "blobs" ["durable"] [("root", .blob root)])
  let durable ← match decodeDurability rows with
    | .ok durable => pure durable
    | .error failure => throw failure
  let wanted ← perform (.readRows tx "content_want" ["root"]
    [("root", .blob root), ("holder", .text holder)])
  if durable && (!possession || !wanted.isEmpty) then
    if possession then
      let _ ← perform (.deleteRows tx "content_want"
        [("root", .blob root), ("holder", .text holder)])
    perform (.upsert tx "pins"
      [("root", .blob root), ("holder", .text holder),
        ("created_at", .integer now), ("release_after", .null)]
      ["root", "holder"] ["release_after"])
    return true
  else
    return false

/-- Complete pin or possession acquisition: begin before metadata reads and
return only after commit; any failed effect is handled by the shared verified
transaction program. Other Lean operations can compose `acquireIn` directly. -/
def acquire (root : ByteArray) (holder : String) (now : Int64)
    (possession : Bool) : Operation Bool :=
  transaction fun tx => acquireIn tx root holder now possession

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
def decodeAccess : List Row → Reply (Option Int64)
  | [] => .ok none
  | [[.integer value]] => .ok (some value)
  | [[.null]] => .error ⟨2, 4⟩
  | [[.text _]] => .error ⟨2, 5⟩
  | [[.rawText _]] => .error ⟨2, 5⟩
  | [[.blob _]] => .error ⟨2, 6⟩
  | [[.real _]] => .error ⟨2, 8⟩
  | _ => .error malformedMetadata

/-- All protection observations occur within the immediate transaction and
the host's surrounding ordering session. Existence reads are bounded queries,
not host-supplied protection decisions. -/
def deleteIn (tx : Transaction) (root : ByteArray) (before : Option Int64) : Operation Outcome := do
  let pinned ← perform (.existsRows tx "pins" [("root", .blob root)])
  let referenced ← perform (.existsRows tx "entries" [("content", .blob root)])
  let rows ← perform (.readRows tx "blobs" ["last_access"] [("root", .blob root)])
  let accessed ← match decodeAccess rows with
    | .ok value => pure value
    | .error failure => throw failure
  let writers ← perform (.readCounter "cas_writers" root)
  let plan := planLifecycle (.delete
    ⟨accessed.isSome, writers != 0, pinned, referenced, accessed.getD 0⟩ before)
  for mutation in plan.transaction do
    match mutation with
    | .deleteRow => let _ ← perform (.deleteRows tx "blobs" [("root", .blob root)])
  return plan.outcome

/-- Best-effort cleanup is requested only after successful transaction
completion. Failure of one unlink does not prevent the second attempt. -/
def cleanup (root : ByteArray) : Operation Unit := do
  try perform (.removeFile "cas_payload" root) catch _ => pure ()
  try perform (.removeFile "cas_outboard" root) catch _ => pure ()

/-- Complete deletion, including cleanup. No mutation plan leaves Lean. -/
def delete (root : ByteArray) (before : Option Int64) : Operation Outcome := do
  let outcome ← transaction fun tx => deleteIn tx root before
  match outcome with
  | .applied => cleanup root
  | _ => pure ()
  return outcome

end VerifiedCore.Cas
