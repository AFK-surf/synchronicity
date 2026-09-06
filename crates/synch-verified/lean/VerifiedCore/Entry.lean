import VerifiedCore.Host.Wire
import VerifiedCore.Cas.Program
import VerifiedCore.Cas.Read
import VerifiedCore.Cas.Input
import VerifiedCore.Trie.Program
import VerifiedCore.Replication.History

/-! Domain command constructors. The transport itself imports no domain policy. -/
namespace VerifiedCore.Entry

/-- One column-type terminal, framed the same way by every CAS operation:
the projection index, the column name and the observed storage class. -/
private def columnTypeTerminal (tag : UInt8) (index : Nat) (column : String)
    (actual : Cas.Codec.CellType) : ByteArray :=
  Host.Wire.octet tag ++ Host.Wire.word index.toUInt64 ++ Host.Wire.string column ++
    Host.Wire.octet (match actual with
      | .null => 0 | .integer => 1 | .real => 2 | .text => 3 | .blob => 4)

private def ingestMetadataError : Cas.IngestCommit.Error → Host.Reply ByteArray
  | .host failure => .error failure
  | .metadata .malformed => .ok (Host.Wire.octet 1)
  | .metadata (.columnType index column actual) => .ok (columnTypeTerminal 2 index column actual)
  | .sizeMismatch root recorded offered => .ok (Host.Wire.octet 3 ++ Host.Wire.bytes root ++
      Host.Wire.word recorded ++ Host.Wire.word offered)

private def ingestResourceError : Cas.Ingest.Error → Host.Reply ByteArray
  | .host failure => .error failure
  | .metadata error => ingestMetadataError error
  | .protocol => .error Host.Wire.protocolFailure
  | .directorySyncUnsupported => .ok (Host.Wire.octet 4)

private def ingestResult : Except Cas.Input.Error Cas.Input.Result → Host.Reply ByteArray
  | .ok result => .ok (Host.Wire.octet 0 ++ Host.Wire.bytes result.root ++ Host.Wire.word result.size)
  | .error (.host failure) => .error failure
  | .error (.ingestion error) => ingestResourceError error
  | .error (.metadata error) => ingestMetadataError error
  | .error .protocol => .error Host.Wire.protocolFailure

/-- One whole byte/file command. No captured-source or metadata planner is
exported; object construction is a host service the command directs. The
input path/buffer is an invocation-owned capability. -/
@[export synch_lean_cas_ingest]
def ingest (kind : UInt8) (size : UInt64) (now : Int64) (cache allowUnsupported : Bool) :
    Host.Wire.NativeState :=
  let input := if kind == 0 then some (Cas.Input.Kind.bytes size)
    else if kind == 1 && size == 0 then some Cas.Input.Kind.file else none
  match input with
  | none => .pure (.error Host.Wire.protocolFailure)
  | some input => do
    let result ← (Cas.Input.run input now (if cache then .cache else .local)
      (if allowUnsupported then .allowUnsupported else .requireSync)).run.mapEffects Host.Inject.inject
    return ingestResult result

private def commitResult (encode : A → ByteArray) : Except Cas.IngestCommit.Error A → Host.Reply ByteArray
  | .ok value => .ok (Host.Wire.octet 0 ++ encode value)
  | .error error => ingestMetadataError error

/-- Group spans arrive as a count followed by little-endian endpoint pairs. -/
private def decodeSpans (bytes : ByteArray) : Option (List GroupSpan) :=
  match (Host.Wire.readList (do
      let start ← Host.Wire.readWord
      let stop ← Host.Wire.readWord
      pure (⟨start.toNat, stop.toNat⟩ : GroupSpan))).run ⟨bytes, 0⟩ with
  | .error () => none
  | .ok (spans, cursor) => if cursor.offset == bytes.size then some spans else none

/-- One metadata commit for verified groups of an object, from any writer.
The terminal carries the settled size and completeness. -/
@[export synch_lean_cas_commit_groups]
def commitGroups (root spans : ByteArray) (size : UInt64) (hasInline : Bool) (inline : ByteArray)
    (now : Int64) (cache : Bool) : Host.Wire.NativeState :=
  match root.size == 32, decodeSpans spans with
  | true, some incoming => do
    let outcome ← (Cas.IngestCommit.commitGroups root size incoming
      (if hasInline then some inline else none) now (if cache then .cache else .local)).run.mapEffects
      Host.Inject.inject
    return commitResult (fun outcome => Host.Wire.word outcome.size ++
      Host.Wire.octet (if outcome.complete then 1 else 0)) outcome
  | _, _ => .pure (.error Host.Wire.protocolFailure)

/-- The cheap refusal of a size the row cannot yield to, read outside a transaction. -/
@[export synch_lean_cas_admit_size]
def admitSize (root : ByteArray) (size : UInt64) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error Host.Wire.protocolFailure)
  else do
    let outcome ← (Cas.IngestCommit.admit root size).run.mapEffects Host.Inject.inject
    return commitResult (fun () => ByteArray.empty) outcome

/-- Decode the holder constructor, not its rendered storage spelling. In
particular an opaque future holder can resemble a known role's spelling. -/
private def decodeHolder (kind : UInt8) (payload : ByteArray) : Option Cas.PinHolder := do
  let text ← String.fromUTF8? payload
  match kind.toNat with
  | 0 => if text.isEmpty then some .operator else none
  | 1 => some (.source text)
  | 2 => some (.replica text)
  | 3 => some (.other text)
  | _ => none

@[export synch_lean_cas_unpin]
def unpin (root payload : ByteArray) (kind : UInt8) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error Host.Wire.protocolFailure)
  else match decodeHolder kind payload with
  | none => .pure (.error Host.Wire.protocolFailure)
  | some holder => (do
      let dropped ← Cas.unpin root holder
      return Host.Wire.octet (if dropped then 1 else 0) : Host.Operation ByteArray).run.mapEffects Host.Inject.inject

@[export synch_lean_cas_expire]
def expire (payload : ByteArray) (kind : UInt8) (now : Int64) : Host.Wire.NativeState :=
  let holder : Option (Option Cas.PinHolder) :=
    if kind == 4 then (if payload.size == 0 then some none else none)
    else (decodeHolder kind payload).map some
  match holder with
  | none => .pure (.error Host.Wire.protocolFailure)
  | some holder => (do
      let count ← Cas.expire holder now
      return Host.Wire.word count.toUInt64 : Host.Operation ByteArray).run.mapEffects Host.Inject.inject

/-- Acquisition and deletion share one terminal framing: tag 0 carries the
operation's own value, tags 1 and 2 the malformed-metadata and column-type
domain errors, and a host failure is returned as itself. -/
private def encodeLifecycle (value : A → ByteArray) : Except Cas.Error A → Host.Reply ByteArray
  | .ok result => .ok (Host.Wire.octet 0 ++ value result)
  | .error (.host failure) => .error failure
  | .error .malformed => .ok (Host.Wire.octet 1)
  | .error (.columnType index column actual) => .ok (columnTypeTerminal 2 index column actual)

@[export synch_lean_cas_delete]
def delete (root : ByteArray) (hasBefore : Bool) (before : Int64) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error ⟨2, 0⟩)
  else do
    let outcome ← (Cas.delete root (if hasBefore then some before else none)).run.mapEffects
      Host.Inject.inject
    return encodeLifecycle (fun outcome => Host.Wire.octet (match outcome with
      | .skipped => 0 | .writing => 1 | .protectedClaim => 2 | .applied => 3)) outcome

@[export synch_lean_cas_acquire]
def acquire (root holder : ByteArray) (now : Int64) (possession : Bool) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error ⟨2, 0⟩)
  else match String.fromUTF8? holder with
  | none => .pure (.error ⟨2, 0⟩)
  | some holder => do
    let acquired ← (Cas.acquire root holder now possession).run.mapEffects Host.Inject.inject
    return encodeLifecycle (fun acquired => Host.Wire.octet (if acquired then 1 else 0)) acquired

private def encodeLookup : Trie.LookupResult → ByteArray
  | .ok none => Host.Wire.octet 0
  | .ok (some value) => Host.Wire.octet 1 ++ Host.Wire.bytes value
  | .error (.keyTooLong size) => Host.Wire.octet 2 ++ Host.Wire.word size.toUInt64
  | .error (.missingNode address) => Host.Wire.octet 3 ++ Host.Wire.bytes address
  | .error (.missingValue address) => Host.Wire.octet 4 ++ Host.Wire.bytes address
  | .error (.decode message) => Host.Wire.octet 5 ++ Host.Wire.string message
  | .error .depthExceeded => Host.Wire.octet 6

@[export synch_lean_trie_get]
def lookup (root : ByteArray) (keySize : UInt64) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error ⟨2, 0⟩)
  else (do return encodeLookup (← Trie.getInput root 0 keySize) : Host.Operation ByteArray).run.mapEffects Host.Inject.inject

private def encodeHistory (result : Replication.History.Result Nat) : Host.Reply ByteArray :=
  open Host.Wire in
  match result with
  | .ok count => .ok (octet 0 ++ word count.toUInt64)
  | .error (.host hostFailure) => .error hostFailure
  | .error .malformed => .ok (octet 1)
  | .error (.columnType index column actual) => .ok
      (octet 2 ++ word index.toUInt64 ++ string column ++ octet (match actual with
        | .null => 0 | .integer => 1 | .real => 2 | .text => 3 | .blob => 4))
  | .error (.invalidText text) => .ok (octet 3 ++ bytes ⟨text.toArray⟩)
  | .error (.column column reason) => .ok (octet 4 ++ string column ++ string reason)
  | .error (.origin error) => .ok (octet 5 ++ match error with
      | .label original => octet 0 ++ string original
      | .domain original => octet 1 ++ string original
      | .keyDecode => octet 2
      | .keyData => octet 3
      | .shape original => octet 4 ++ string original)

/-- Complete retention command; terminal domain errors do not enter the host
effect protocol or require Rust to repeat record validation. -/
@[export synch_lean_history_prune]
def pruneHistory (origin : ByteArray) (before : Int64) : Host.Wire.NativeState :=
  match String.fromUTF8? origin with
  | none => .pure (.error Host.Wire.protocolFailure)
  | some origin => do
    let result ← (Replication.History.prune origin before).run.mapEffects Host.Inject.inject
    return encodeHistory result

private def encodeRead (result : Except Cas.Read.Error UInt64) : Host.Reply ByteArray :=
  open Host.Wire in
  match result with
  | .ok count => .ok (octet 0 ++ word count)
  | .error (.host hostFailure) => .error hostFailure
  | .error .missingBlob => .ok (octet 1)
  | .error (.range start stop size) => .ok (octet 2 ++ word start ++ word stop ++ word size)
  | .error .unavailable => .ok (octet 3)
  | .error .shortInline => .ok (octet 4)
  | .error .malformed => .ok (octet 5)
  | .error (.columnType index column actual) => .ok (columnTypeTerminal 6 index column actual)
  | .error (.column column reason) => .ok (octet 7 ++ string column ++ string reason)
  | .error .protocol => .ok (octet 8)

/-- One complete local read, including metadata admission, physical reads and
repair. Effect injection preserves capability separation without exposing any
CAS policy or intermediate availability state to the native caller. -/
@[export synch_lean_cas_read]
def readRoot (root : ByteArray) (all : Bool) (offset length : UInt64) : Host.Wire.NativeState :=
  if root.size != 32 then .pure (.error Host.Wire.protocolFailure)
  else do
    let result ← (Cas.Read.read root (if all then .all else .range offset length)).run.mapEffects
      Host.Inject.inject
    return encodeRead result

end VerifiedCore.Entry
