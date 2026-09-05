import VerifiedCore.Cas.ReadCodec
import VerifiedCore.Host.Access

/-! Whole local-read and repair operations. Domain decisions belong here;
the host supplies raw database, file and clock capabilities only. -/
namespace VerifiedCore.Cas.Read
open VerifiedCore.Host

abbrev Effects := EffectSum Storage (EffectSum Access (EffectSum FileIO (EffectSum Clock Output)))
abbrev Action (A : Type) := OperationOver Effects Error A

def requestStorage (effect : Storage (Reply A)) : Action A :=
  performOver Error.host (.left effect)

def requestAccess (effect : Access (Reply A)) : Action A :=
  performOver Error.host (.right (.left effect))

def requestClock (effect : Clock (Reply A)) : Action A :=
  performOver Error.host (.right (.right (.right (.left effect))))

def requestOutput (bytes : ByteArray) : Action Unit :=
  performOver Error.host (.right (.right (.right (.right (.append bytes)))))

/-- The database's existing LIKE semantics deliberately apply to raw holder
text. Repair does not parse or normalize holders, nor touch operator pins. -/
def repairPins (root : ByteArray) : Selection :=
  ⟨"pins", [("root", .blob root)], [("holder", "source:%"), ("holder", "replica:%")]⟩

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
    let _ ← requestAccess (.update tx ⟨"blobs", [("root", .blob root)], []⟩
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
  transactionOver EffectSum.left Error.host (fun tx => healIn tx root)

/-- Full and ranged reads share one metadata observation and recovery path. -/
inductive Request where
  | all
  | range (offset length : UInt64)

/-- Bounded transfer; the opened file identity is retained across chunks. -/
def chunkSize : Nat := 65536

def requestFile (effect : FileIO A) : Action A :=
  ExceptT.mk (.request (.right (.right (.left effect))) (fun reply => .pure (.ok reply)))

/-- Only missing/truncated physical data invalidates the local claim. Repair
failure takes precedence; otherwise the original opaque I/O error survives. -/
def failedFile (root : ByteArray) (failure : FileFailure) : Action Unit := do
  if failure.kind == .missing || failure.kind == .shortRead then
    heal root
  throw (.host failure.failure)

/-- The finite chunk bound follows from the requested byte count, not from
host-provided CAS groups. A successful host read must be exact; malformed
success replies are protocol failures, never silently shortened payloads.
Each exact reply is appended to the private result buffer before requesting
the next chunk; no accumulated payload survives in a Lean continuation. -/
def readChunks : Nat → UInt64 → Nat → Nat → Action (FileReply Unit)
  | fuel, handle, offset, remaining => do
    if remaining == 0 then return .ok ()
    match fuel with
    | 0 => throw .protocol
    | fuel + 1 =>
      let count := min remaining chunkSize
      match ← requestFile (.readAt handle offset.toUInt64 count.toUInt64) with
      | .error failure => return .error failure
      | .ok bytes =>
        if bytes.size != count then throw .protocol
        requestOutput bytes
        readChunks fuel handle (offset + count) (remaining - count)

/-- Close an opened handle before healing or returning any error. Host RAII
also closes handles if this suspended program is abandoned. -/
def readPayload (root : ByteArray) (offset count : Nat) : Action Unit := do
  match ← requestFile (.open "cas_payload" root) with
  | .error failure => failedFile root failure
  | .ok handle =>
    let result ← (do
      try
        return .ok (← readChunks ((count + chunkSize - 1) / chunkSize)
          handle offset count)
      catch error => return .error error
      : Action (Except Error (FileReply Unit)))
    match ← requestFile (.close handle) with
    | .error failure => throw (.host failure)
    | .ok () => pure ()
    match result with
    | .error error => throw error
    | .ok (.error failure) => failedFile root failure
    | .ok (.ok ()) => return ()

/-- Inline payloads use the same bounded raw append capability. A stored
inline cell is already in memory, but its requested range is never assembled
or transported as a second whole-object result. -/
def inlineChunks : Nat → ByteArray → Nat → Nat → Action Unit
  | fuel, bytes, offset, remaining => do
    if remaining == 0 then return ()
    match fuel with
    | 0 => throw .protocol
    | fuel + 1 =>
      let count := min remaining chunkSize
      requestOutput (bytes.extract offset (offset + count))
      inlineChunks fuel bytes (offset + count) (remaining - count)

/-- One raw statement, whose connection scope ends before file I/O. The
synthetic pinned EXISTS column is omitted: it cannot fail type conversion and
does not affect reads. decodeRow retains the original indices for diagnostics.
As with SQLite query_row, the first row wins over any later stepping failure. -/
def metadata (root : ByteArray) : Action Metadata := do
  let scan ← requestAccess (.snapshot ⟨"blobs", [("root", .blob root)], []⟩
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
    inlineChunks ((stop - offset + chunkSize - 1) / chunkSize) bytes offset (stop - offset)
  | none => readPayload root offset (stop - offset)
  return (stop - offset).toUInt64

end VerifiedCore.Cas.Read
