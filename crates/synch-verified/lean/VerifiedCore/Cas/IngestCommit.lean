import VerifiedCore.Cas.Codec
import VerifiedCore.Host.Upsert

/-! Internal metadata stage for future whole ingestion. No native constructor
or Rust planner interface exposes this stage. Payload hashing, writing and
syncing must precede it under the whole operation's write lease. -/
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

/-- The existing Lean planner is an internal function call. Full ingestion
never exports its group count, interval representation or settlement result. -/
def completePlan (claim : Option Claim) (size : UInt64) : CasPlan :=
  let incoming := [⟨0, (groupCount size).toNat⟩]
  match claim with
  | none => planCasCommit false false false 0 size [] incoming
  | some claim => planCasCommit true claim.durable claim.complete claim.size size
      (oldSpans claim) incoming

/-- Raw conflict semantics intentionally preserve noncanonical stored values.
In particular durable=2 is not rewritten to true=1; missing incoming inline
does not inspect or re-encode the current inline cell. -/
def assignments : List (String × ConflictValue) :=
  [("size", .excluded "size"), ("complete", .excluded "complete"),
    ("bitmap", .excluded "bitmap"),
    ("inline", .coalesce (.excluded "inline") (.current "inline")),
    ("last_access", .excluded "last_access"),
    ("durable", .max (.current "durable") (.excluded "durable"))]

def values (root : ByteArray) (size : UInt64) (inline : Option ByteArray)
    (now : Int64) (tier : Tier) : Fields :=
  [("root", .blob root), ("size", .integer size.toInt64),
    ("complete", .integer 1), ("bitmap", .null),
    ("inline", match inline with | none => .null | some bytes => .blob bytes),
    ("last_access", .integer now),
    ("durable", .integer (if tier == .local then 1 else 0))]

abbrev Effects := EffectSum Storage Upsert
abbrev Action (A : Type) := OperationOver Effects Error A

def commitCompleteIn (tx : Transaction) (root : ByteArray) (size : UInt64)
    (inline : Option ByteArray) (now : Int64) (tier : Tier) : Action Unit := do
  let rows ← performOver Error.host (.left
    (.readRows tx "blobs" ["size", "complete", "durable", "bitmap"] [("root", .blob root)]))
  let claim ← ExceptT.mk (.pure (decodeClaim rows))
  let plan := completePlan claim size
  if !plan.accepted then
    throw (.sizeMismatch root ((claim.map Claim.size).getD 0) size)
  performOver Error.host (.right (.write tx "blobs" (values root size inline now tier)
    ["root"] assignments))

/-- Only the index commit is transactional. Expensive physical work belongs to
the containing ingestion operation, not to the database critical section. -/
def commitComplete (root : ByteArray) (size : UInt64) (inline : Option ByteArray)
    (now : Int64) (tier : Tier) : Action Unit :=
  transactionOver EffectSum.left Error.host
    (fun tx => commitCompleteIn tx root size inline now tier)

end VerifiedCore.Cas.IngestCommit
