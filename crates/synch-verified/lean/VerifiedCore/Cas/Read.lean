import VerifiedCore.Cas.ReadCodec
import VerifiedCore.Host.Access

/-! Whole local-read and repair operations. Domain decisions belong here;
the host supplies raw database, file and clock capabilities only. -/
namespace VerifiedCore.Cas.Read
open VerifiedCore.Host

abbrev Effects := EffectSum Storage (EffectSum Access (EffectSum FileIO (EffectSum Clock Output)))
abbrev Action (A : Type) := OperationOver Effects Error A

def requestStorage (effect : Storage (Reply A)) : Action A := raise Error.host effect
def requestAccess (effect : Access (Reply A)) : Action A := raise Error.host effect
def requestClock (effect : Clock (Reply A)) : Action A := raise Error.host effect
def requestOutput (bytes : ByteArray) : Action Unit := raise Error.host (Output.append bytes)

/-- The database's existing LIKE semantics deliberately apply to raw holder
text. Repair does not parse or normalize holders, nor touch operator pins. -/
def repairPins (root : ByteArray) : Selection :=
  ⟨"pins", [("root", .blob root)], [("holder", "source:%"), ("holder", "replica:%")], []⟩

/-- Clear a stale local-byte claim and transfer standing machine roles to
repair intents. Existing intents retain their size, predecessor and timestamp:
copyRows uses one atomic INSERT SELECT ON CONFLICT DO NOTHING statement.
The clock is sampled only after the invalidation UPDATE has succeeded. -/
def healIn (tx : Transaction) (root : ByteArray) : Action Unit := do
  let rows ← requestStorage (.readRows tx "blobs" ["size"] [("root", .blob root)])
  let size ← ExceptT.mk (.pure (decodeSize rows))
  match size with
  | none => pure ()
  | some size =>
    let _ ← requestAccess (.update tx ⟨"blobs", [("root", .blob root)], [], []⟩
      [("complete", .integer 0), ("durable", .integer 0),
        ("bitmap", .null), ("inline", .null)])
    let now ← requestClock .nowNs
    let _ ← requestAccess (.copyRows tx "content_want" (repairPins root)
      [("root", .column "root"), ("holder", .column "holder"),
        ("size", .literal (.integer size)), ("prev", .literal .null),
        ("first_wanted", .literal (.integer now))]
      ["root", "holder"])
    let _ ← requestAccess (.delete tx (repairPins root))
    pure ()

/-- A single transaction owns both invalidation and role-to-want transfer.
Any failed read, decode, mutation, clock or commit rolls back; a secondary
rollback failure never replaces the primary error. -/
def heal (root : ByteArray) : Action Unit :=
  transactionOver Inject.inject Error.host (fun tx => healIn tx root)

/-- Full and ranged reads share one metadata observation and recovery path. -/
inductive Request where
  | all
  | range (offset length : UInt64)

def requestFile (effect : FileIO A) : Action A := observe effect

/-- Only missing/truncated physical data invalidates the local claim. Repair
failure takes precedence; otherwise the original opaque I/O error survives. -/
def failedFile (root : ByteArray) (failure : FileFailure) : Action Unit := do
  if failure.kind == .missing || failure.kind == .shortRead then
    heal root
  throw (.host failure.failure)

/-- The requested bytes move from the opened file into the private result
buffer in one host transfer; the program chooses the object, the range and
what a failure means, and never holds the payload itself. The handle is
closed before healing or returning any error. Host RAII also closes handles
if this suspended program is abandoned. -/
def readPayload (root : ByteArray) (offset count : Nat) : Action Unit := do
  match ← requestFile (.open "cas_payload" root) with
  | .error failure => failedFile root failure
  | .ok handle =>
    let result ← requestFile (.transfer handle offset.toUInt64 count.toUInt64)
    match ← requestFile (.close handle) with
    | .error failure => throw (.host failure)
    | .ok () => pure ()
    match result with
    | .error failure => failedFile root failure
    | .ok () => return ()

/-- One raw statement, whose connection scope ends before file I/O. The
synthetic pinned EXISTS column is omitted: it cannot fail type conversion and
does not affect reads. decodeRow retains the original indices for diagnostics.
As with SQLite query_row, the first row wins over any later stepping failure. -/
def metadata (root : ByteArray) : Action Metadata := do
  let scan ← requestAccess (.snapshot ⟨"blobs", [("root", .blob root)], [], []⟩
    ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"])
  match scan.rows with
  | row :: _ => ExceptT.mk (.pure (decodeRow row))
  | [] => match scan.failure with
    | some failure => throw (.host failure)
    | none => throw .missingBlob

/-- Complete local read. No bitmap, coverage, span, healing or error
selection callback enters Rust. Empty requests precede availability checks.
Inline corruption returns an explicit error instead of a host slicing panic.
The terminal byte count reports the completed length of the private output buffer;
only successful command termination permits the host to publish its bytes. -/
def read (root : ByteArray) (request : Request) : Action UInt64 := do
  let row ← metadata root
  let (offset, length) := match request with
    | .all => (0, row.size.toNat)
    | .range offset length => (offset.toNat, length.toNat)
  -- Nat arithmetic followed by the size clamp equals saturating UInt64 add
  -- followed by that clamp, without any intermediate fixed-width overflow.
  let stop := min (offset + length) row.size.toNat
  if offset > row.size.toNat then
    throw (.range offset.toUInt64 stop.toUInt64 row.size)
  if offset == stop then return 0
  if !covered row offset.toUInt64 stop.toUInt64 then throw .unavailable
  match row.inline with
  | some bytes =>
    if stop > bytes.size then throw .shortInline
    requestOutput (bytes.extract offset stop)
  | none => readPayload root offset (stop - offset)
  return (stop - offset).toUInt64

end VerifiedCore.Cas.Read
