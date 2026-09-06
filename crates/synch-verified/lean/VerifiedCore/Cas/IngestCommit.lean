import VerifiedCore.Cas.Codec
import VerifiedCore.Host.Access
import VerifiedCore.Host.Upsert

/-! The metadata commit every writer of an object runs: local ingestion, a
verified slice from a peer, a delta proof, a cloud adoption. The program reads
the row's claim, settles the offered size against it, merges the verified
groups and writes one row; `admit` is the same decision read outside a
transaction, so a claim that cannot stand is refused before any bytes are
decoded against it. Payload hashing, writing and syncing precede the commit
under the caller's write lease. -/
namespace VerifiedCore.Cas.IngestCommit
open VerifiedCore.Host

/-- Immutable backend configuration, not a caller's durability assertion. -/
inductive Tier where
  | local | cache
  deriving BEq, DecidableEq

inductive MetadataError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Codec.CellType)
  deriving BEq, DecidableEq

inductive Error where
  | host (failure : Failure)
  | metadata (error : MetadataError)
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  deriving BEq, DecidableEq

structure Claim where
  size : UInt64
  complete : Bool
  durable : Bool
  bitmap : Option ByteArray

/-- This projection deliberately differs from the read projection. All field
types are checked, in query order, even when complete overrides bitmap data.
Neither existing inline bytes nor the root receive additional validation. -/
def decodeClaim : List Row → Except Error (Option Claim)
  | [] => .ok none
  | [size, complete, durable, bitmap] :: _ => do
    let size ← Codec.integerField (fun actual => .metadata (.columnType 0 "size" actual)) size
    let complete ← Codec.integerField (fun actual => .metadata (.columnType 1 "complete" actual)) complete
    let durable ← Codec.integerField (fun actual => .metadata (.columnType 2 "durable" actual)) durable
    let bitmap ← Codec.optionalBlobField (fun actual => .metadata (.columnType 3 "bitmap" actual)) bitmap
    return some ⟨size.toUInt64, complete != 0, durable != 0, bitmap⟩
  | _ => .error (.metadata .malformed)

def oldSpans (claim : Claim) : List GroupSpan :=
  match claim.bitmap with
  | none => []
  | some bytes => Codec.decodeRawBitmap bytes

/-- Settle the offered size against the row's claim and merge the incoming
groups into what it holds. -/
def plan (claim : Option Claim) (size : UInt64) (incoming : List GroupSpan) : CasPlan :=
  match claim with
  | none => planCasCommit false false false 0 size [] incoming
  | some claim => planCasCommit true claim.durable claim.complete claim.size size
      (oldSpans claim) incoming

/-- Every group of the object at once. -/
def fullSpan (size : UInt64) : List GroupSpan := [⟨0, (groupCount size).toNat⟩]

def completePlan (claim : Option Claim) (size : UInt64) : CasPlan :=
  plan claim size (fullSpan size)

/-- What a commit settled: the size the row records now, and whether every
group of the object is present. -/
structure Outcome where
  size : UInt64
  complete : Bool
  deriving BEq, DecidableEq

/-- Raw conflict semantics intentionally preserve noncanonical stored values.
In particular durable=2 is not rewritten to true=1; missing incoming inline
does not inspect or re-encode the current inline cell. -/
def assignments : List (String × ConflictValue) :=
  [("size", .excluded "size"), ("complete", .excluded "complete"),
    ("bitmap", .excluded "bitmap"),
    ("inline", .coalesce (.excluded "inline") (.current "inline")),
    ("last_access", .excluded "last_access"),
    ("durable", .max (.current "durable") (.excluded "durable"))]

/-- NULL is the one spelling of "no verified groups": a complete row carries
no bitmap, and a row holding nothing keeps the column empty so a cold cache
row is told apart from a partial one. Only a complete row on the durable
tier is durable. -/
def values (root : ByteArray) (size : UInt64) (complete : Bool) (bitmap : Option ByteArray)
    (inline : Option ByteArray) (now : Int64) (tier : Tier) : Fields :=
  [("root", .blob root), ("size", .integer size.toInt64),
    ("complete", .integer (if complete then 1 else 0)),
    ("bitmap", match bitmap with | none => .null | some bytes => .blob bytes),
    ("inline", match inline with | none => .null | some bytes => .blob bytes),
    ("last_access", .integer now),
    ("durable", .integer (if complete && tier == .local then 1 else 0))]

abbrev Effects := EffectSum Storage (EffectSum Upsert Access)
abbrev Action (A : Type) := OperationOver Effects Error A

def claimColumns : List String := ["size", "complete", "durable", "bitmap"]

/-- One decision, inside the transaction that records it: two writers of one
root cannot each settle the size on a stale snapshot. -/
def commitIn (tx : Transaction) (root : ByteArray) (size : UInt64) (incoming : List GroupSpan)
    (inline : Option ByteArray) (now : Int64) (tier : Tier) : Action Outcome := do
  let rows ← raise Error.host (Storage.readRows tx "blobs" claimColumns [("root", .blob root)])
  let claim ← ExceptT.mk (.pure (decodeClaim rows))
  let decided := plan claim size incoming
  if !decided.accepted then
    throw (.sizeMismatch root ((claim.map Claim.size).getD 0) size)
  let bitmap := if decided.complete || decided.spans.isEmpty then none
    else some (Codec.encodeRawBitmap decided.spans)
  raise Error.host (Upsert.write tx "blobs"
    (values root size decided.complete bitmap inline now tier) ["root"] assignments)
  return ⟨size, decided.complete⟩

/-- Only the index commit is transactional. Expensive physical work belongs to
the containing operation, not to the database critical section. -/
def commitGroups (root : ByteArray) (size : UInt64) (incoming : List GroupSpan)
    (inline : Option ByteArray) (now : Int64) (tier : Tier) : Action Outcome :=
  transactionOver Inject.inject Error.host
    (fun tx => commitIn tx root size incoming inline now tier)

def commitCompleteIn (tx : Transaction) (root : ByteArray) (size : UInt64)
    (inline : Option ByteArray) (now : Int64) (tier : Tier) : Action Unit := do
  let _ ← commitIn tx root size (fullSpan size) inline now tier
  pure ()

/-- A whole object at once: the plan is complete whenever it is accepted. -/
def commitComplete (root : ByteArray) (size : UInt64) (inline : Option ByteArray)
    (now : Int64) (tier : Tier) : Action Unit :=
  transactionOver Inject.inject Error.host
    (fun tx => commitCompleteIn tx root size inline now tier)

/-- The cheap refusal, read outside any transaction: a size the row's claim
cannot yield to is rejected before a writer decodes bytes against it, so a
wrong-size outboard is never written over verified groups. The commit
decides again, transactionally. A row that is not there admits any size. -/
def admit (root : ByteArray) (size : UInt64) : Action Unit := do
  let scan ← raise Error.host (Access.snapshot ⟨"blobs", [("root", .blob root)], []⟩ claimColumns)
  let claim ← ExceptT.mk (.pure (decodeClaim scan.rows))
  match claim, scan.failure with
  | none, some failure => throw (.host failure)
  | _, _ => pure ()
  if !(plan claim size []).accepted then
    throw (.sizeMismatch root ((claim.map Claim.size).getD 0) size)

end VerifiedCore.Cas.IngestCommit
