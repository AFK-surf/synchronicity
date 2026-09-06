import VerifiedCore.Cas.Ingest
import VerifiedCore.Host.Source

/-! Whole byte/file ingestion input policy. The host supplies an immutable
byte input or a path capability, never a preselected inline/captured plan.
Production local ingestion invokes this command; no Rust planner facade exposes
these internals. -/
namespace VerifiedCore.Cas.Input
open VerifiedCore.Host

abbrev Effects := EffectSum Ingest.Effects SourceIO

inductive Kind where
  | bytes (size : UInt64)
  | file
  deriving BEq, DecidableEq

inductive Error where
  | host (failure : Failure)
  | ingestion (error : Ingest.Error)
  | metadata (error : IngestCommit.Error)
  | protocol
  deriving BEq, DecidableEq

structure Result where
  root : ByteArray
  size : UInt64
  deriving BEq

abbrev Action (A : Type) := OperationOver Effects Error A

def source (effect : SourceIO (Reply A)) : Action A :=
  performOver Error.host (.right effect)

def openSource : Action UInt64 := ExceptT.mk do
  let reply ← Program.request (.left (.left (.left (.open "input" ByteArray.empty)))) Program.pure
  return reply.mapError (fun error => Error.host error.failure)

def closeSource (handle : UInt64) : Action Unit :=
  performOver Error.host (.left (.left (.left (.close handle))))

/-- Read exactly the requested bytes, preserving the original I/O failure.
There is no CAS recovery on an ingestion input read. A malformed successful
reply is rejected before hashing. -/
def readExact (handle size : UInt64) : Action ByteArray := do
  let reply ← ExceptT.mk (.request (.left (.left (.left (.readAt handle 0 size))))
    (fun reply => .pure (.ok reply)))
  match reply with
  | .error failure => throw (.host failure.failure)
  | .ok bytes =>
    if bytes.size.toUInt64 != size then throw .protocol
    return bytes

/-- The root of bytes the program holds is a host reply whose width the
program checks; the host never selects inline storage or commits metadata. -/
def hashInline (bytes : ByteArray) : Action ByteArray := do
  let root ← performOver Error.host (.left (.left (.right (.hash bytes))))
  if root.size != 32 then throw .protocol
  return root

def captured (handle size : UInt64) (now : Int64) (tier : IngestCommit.Tier)
    (policy : Ingest.DirectoryPolicy) : Action Result := ExceptT.mk do
  let reply ← (Ingest.run handle size now tier policy).run.mapEffects EffectSum.left
  return (reply.mapError Error.ingestion).map (fun root => ⟨root, size⟩)

def inlineBytes (bytes : ByteArray) (now : Int64) (tier : IngestCommit.Tier) : Action Result := do
  let root ← hashInline bytes
  let size := bytes.size.toUInt64
  let _ ← ExceptT.mk do
    let reply ← (IngestCommit.commitComplete root size (some bytes) now tier).run.mapEffects
      (fun effect => .left (.right (.left effect)))
    return reply.mapError Error.metadata
  return ⟨root, size⟩

/-- Flatten only after EOF, without suspending while the fresh destination is
being filled. The explicit capacity is the captured byte count; compiled append
uses ByteArray.fastAppend/copySlice and can mutate this unshared destination.
Keeping reversed chunks across host calls avoids repeatedly copying a prefix
retained by the previous native continuation. -/
def flattenCapture (total : Nat) (chunks : List ByteArray) : ByteArray :=
  chunks.reverse.foldl (fun out chunk => out ++ chunk) (ByteArray.emptyWithCapacity total)

/-- Preserve read-to-EOF for an initially small file, including growth across
the inline threshold. Like the previous read-to-end path, this may retain the
entire captured stream. Large initial inputs use bounded streaming instead.
Fuel permits one request per byte plus the final EOF observation. -/
def collectAux : Nat → UInt64 → Nat → List ByteArray → Action ByteArray
  | 0, _, _, _ => throw .protocol
  | fuel + 1, handle, total, chunks => do
    let bytes ← source (.readSome handle total.toUInt64 65536)
    if bytes.size > 65536 || total + bytes.size > 18446744073709551615 then throw .protocol
    if bytes.isEmpty then return flattenCapture total chunks
    collectAux fuel handle (total + bytes.size) (bytes :: chunks)

def collect (handle : UInt64) : Action ByteArray :=
  collectAux 18446744073709551616 handle 0 []

/-- A growing small file is frozen from exactly the bytes already captured;
never reopen the mutable path to construct a root for a different stream. -/
def capturedBytes (bytes : ByteArray) (now : Int64) (tier : IngestCommit.Tier)
    (policy : Ingest.DirectoryPolicy) : Action Result := do
  if bytes.size ≤ 16384 then inlineBytes bytes now tier
  else
    let handle ← source (.freeze bytes)
    captured handle bytes.size.toUInt64 now tier policy

def run (kind : Kind) (now : Int64) (tier : IngestCommit.Tier)
    (policy : Ingest.DirectoryPolicy := .requireSync) : Action Result := do
  let size ← match kind with
    | .bytes size => pure size
    | .file => source (.stat "input" ByteArray.empty)
  let handle ← openSource
  if size ≤ 16384 then
    let bytes ← ensure (match kind with
      | .file => collect handle
      | .bytes _ => readExact handle size) (closeSource handle)
    capturedBytes bytes now tier policy
  else
    captured handle size now tier policy

end VerifiedCore.Cas.Input
