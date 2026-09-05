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
  | [[.blob _]] => .error ⟨2, 3⟩
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

/-- Preserve absence and signed access time; do not coerce malformed cells. -/
def decodeAccess : List Row → Reply (Option Int64)
  | [] => .ok none
  | [[.integer value]] => .ok (some value)
  | [[.null]] => .error ⟨2, 4⟩
  | [[.text _]] => .error ⟨2, 5⟩
  | [[.blob _]] => .error ⟨2, 6⟩
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
