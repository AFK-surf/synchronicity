import VerifiedCore.Host
import VerifiedCore.Host.Access
import VerifiedCore.Cas.Codec
import VerifiedCore.Cas.Program

/-! The durability transitions of the content store: what a durable claim
is, when a row may make one, and what withdraws it. A durable claim says the
configured backend holds the complete object; it is written only after the
backend's own acknowledgement, and it is withdrawn only by the one signal
that is authoritative about a content address, the backend answering that
the object is not there. Every transition is one transaction over raw rows;
no caller prepares facts. -/
namespace VerifiedCore.Cas.Durable

open Host

inductive Error where
  | host (failure : Failure)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Codec.CellType)
  /-- The row's recorded size disagrees with the size the backend confirmed. -/
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  deriving BEq, DecidableEq

abbrev Effects := EffectSum Storage (EffectSum Access Clock)
abbrev Action (A : Type) := OperationOver Effects Error A

def storage (effect : Storage (Reply A)) : Action A := raise Error.host effect
def access (effect : Access (Reply A)) : Action A := raise Error.host effect
def clock : Action Int64 := raise Error.host Clock.nowNs

def transaction (body : Transaction → Action A) : Action A :=
  transactionOver Inject.inject Error.host body

/-- The recorded size of a blob row, if there is one. -/
def decodeSize : List Row → Except Error (Option Int64)
  | [] => .ok none
  | [[cell]] => (Codec.integerField (Error.columnType 0 "size") cell).map some
  | _ => .error .malformed

def readSize (tx : Transaction) (root : ByteArray) : Action (Option Int64) := do
  let rows ← storage (.readRows tx "blobs" ["size"] [("root", .blob root)])
  ExceptT.mk (.pure (decodeSize rows))

def byRoot (root : ByteArray) : Selection := ⟨"blobs", [("root", .blob root)], [], []⟩

/-- Record that the backend holds the complete object. Only after its
acknowledgement, which is the caller's obligation; this never creates a row. -/
def markDurable (root : ByteArray) : Action Bool := transaction fun tx => do
  let changed ← access (.update tx (byRoot root) [("durable", .integer 1)])
  return changed != 0

/-- Reconstruct a cold durable row after a metadata restore, once the
backend has confirmed the final pair: a row agreeing on size is marked
durable, a missing row is created with no local bytes, and a row that
disagrees on size is left alone and refused. Adoption only ever adds
availability. -/
def adoptDurable (root : ByteArray) (size : UInt64) (now : Int64) : Action Unit :=
  transaction fun tx => do
    match ← readSize tx root with
    | some recorded =>
      if recorded.toUInt64 != size then
        throw (.sizeMismatch root recorded.toUInt64 size)
      let _ ← access (.update tx (byRoot root) [("durable", .integer 1)])
    | none =>
      storage (.upsert tx "blobs"
        [("root", .blob root), ("size", .integer size.toInt64), ("complete", .integer 0),
          ("bitmap", .null), ("inline", .null), ("last_access", .integer now),
          ("durable", .integer 1)]
        ["root"] [])

/-- The standing machine roles over an object: a source's or a replica's
pin, never the operator's. -/
def rolePins (root : ByteArray) : Selection :=
  ⟨"pins", [("root", .blob root)], [("holder", "source:%"), ("holder", "replica:%")], []⟩

/-- The backend answered that the object is not there. That is the one
authoritative statement about a content address, so the durable claim is
withdrawn; a row with no local bytes at all is removed; and, when a claim
was withdrawn, every machine role's pin becomes a repair intent, existing
intents keeping their own record, while the operator's pin is left standing
as a person's promise rather than this node's bookkeeping. Answers whether a
claim was withdrawn. -/
def healMissing (root : ByteArray) : Action Bool := transaction fun tx => do
  -- The row is the most authoritative record of the size, and it is about to
  -- be withdrawn or deleted: read it first.
  let size ← readSize tx root
  let withdrawn ← access (.update tx ⟨"blobs", [("root", .blob root)], [], [("durable", .integer 0)]⟩
    [("durable", .integer 0)])
  let _ ← access (.delete tx ⟨"blobs",
    [("root", .blob root), ("complete", .integer 0), ("bitmap", .null), ("inline", .null)], [], []⟩)
  if withdrawn == 0 then return false
  let now ← clock
  let _ ← access (.copyRows tx "content_want" (rolePins root)
    [("root", .column "root"), ("holder", .column "holder"),
      ("size", .literal (.integer (size.getD 0))), ("prev", .literal .null),
      ("first_wanted", .literal (.integer now))]
    ["root", "holder"])
  let _ ← access (.delete tx (rolePins root))
  return true

def generationKey : String := "cas.cloud.scratch_generation"

def decodeMarker : List Row → Except Error (Option String)
  | [] => .ok none
  | [[.text value]] => .ok (some value)
  | [[cell]] => .error (.columnType 0 "value" (Codec.cellType cell))
  | _ => .error .malformed

/-- Reconcile the database's cache claims with an ephemeral scratch
generation: a changed marker drops the rows that were only ever staged and
clears the cached groups of durable rows, in one transaction, and records
the marker; a matching marker changes nothing. Answers whether it changed. -/
def reconcileScratch (marker : String) : Action Bool := transaction fun tx => do
  let rows ← storage (.readRows tx "config" ["value"] [("key", .text generationKey)])
  let previous ← ExceptT.mk (.pure (decodeMarker rows))
  if previous == some marker then return false
  let _ ← access (.delete tx ⟨"blobs", [("durable", .integer 0), ("inline", .null)], [], []⟩)
  let _ ← access (.update tx ⟨"blobs", [("inline", .null)], [], [("durable", .integer 0)]⟩
    [("complete", .integer 0), ("bitmap", .null)])
  storage (.upsert tx "config" [("key", .text generationKey), ("value", .text marker)]
    ["key"] ["value"])
  return true

/-- Drop only reconstructible local bytes while retaining a remote durable
claim: refused while a writer holds the object; the rows change first, so a
crash leaves at most harmless orphan files, never a warm claim over missing
bytes; the files go after the commit and their absence is not an error. -/
def clearCache (root : ByteArray) : Action Bool := do
  let writers ← storage (.readCounter "cas_writers" root)
  if writers != 0 then return false
  transaction fun tx => do
    let _ ← access (.delete tx ⟨"blobs",
      [("root", .blob root), ("durable", .integer 0), ("inline", .null)], [], []⟩)
    let _ ← access (.update tx ⟨"blobs", [("root", .blob root), ("inline", .null)], [],
      [("durable", .integer 0)]⟩ [("complete", .integer 0), ("bitmap", .null)])
  try storage (.removeFile "cas_payload" root) catch _ => pure ()
  try storage (.removeFile "cas_outboard" root) catch _ => pure ()
  return true

end VerifiedCore.Cas.Durable
