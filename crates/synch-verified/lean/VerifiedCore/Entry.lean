import VerifiedCore.Host.Wire
import VerifiedCore.Commands
import VerifiedCore.Commands.Generated
import VerifiedCore.Cas.Program
import VerifiedCore.Cas.Read
import VerifiedCore.Cas.Input
import VerifiedCore.Trie.Program
import VerifiedCore.Trie.Verify
import VerifiedCore.Replication.History

/-! The one native entry point. A command arrives as a packet, decoded with
the generated codec of `Commands.Command`; it runs as a whole Lean operation
over the native effect algebra; and its outcome leaves as a terminal encoded
with the generated codec of its outcome type. What remains here is the
domain-to-outcome mapping: which of an operation's errors are the host's own,
which are protocol violations, and which are the command's to report. -/
namespace VerifiedCore.Entry
open Host.Wire Commands

abbrev Native := Host.Wire.NativeState

/-- Run an operation over the native algebra and finish with its terminal. -/
def command (operation : Host.OperationOver E ε A) [Host.Inject E Host.Wire.NativeEffects]
    (finish : Except ε A → Host.Reply ByteArray) : Native := do
  let result ← operation.run.mapEffects Host.Inject.inject
  return finish result

/-- A value the caller decodes as is. -/
def terminalOf [Encode A] (value : A) : Host.Reply ByteArray := .ok (terminal value)

/-- Operations whose only failures are the host's. -/
def hostOnly [Encode A] : Except Host.Failure A → Host.Reply ByteArray
  | .ok value => terminalOf value
  | .error hostFailure => .error hostFailure

def lifecycle [Encode A] : Except Cas.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except LifecycleDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error .malformed => terminalOf (Except.error LifecycleDomainError.malformed : Except _ A)
  | .error (.columnType index column actual) =>
    terminalOf (Except.error (LifecycleDomainError.columnType index column actual) : Except _ A)

def metadata [Encode A] : Except Cas.IngestCommit.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except IngestDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error (.metadata .malformed) => terminalOf (Except.error IngestDomainError.malformed : Except _ A)
  | .error (.metadata (.columnType index column actual)) =>
    terminalOf (Except.error (IngestDomainError.columnType index column actual) : Except _ A)
  | .error (.sizeMismatch root recorded offered) =>
    terminalOf (Except.error (IngestDomainError.sizeMismatch root recorded offered) : Except _ A)

def ingestion : Except Cas.Input.Error Cas.Input.Result → Host.Reply ByteArray
  | .ok result => terminalOf (Except.ok (Ingested.mk result.root result.size) : Except IngestDomainError _)
  | .error (.host hostFailure) => .error hostFailure
  | .error .protocol => .error protocolFailure
  | .error (.metadata error) => metadata (A := Ingested) (.error error)
  | .error (.ingestion (.host hostFailure)) => .error hostFailure
  | .error (.ingestion .protocol) => .error protocolFailure
  | .error (.ingestion (.metadata error)) => metadata (A := Ingested) (.error error)
  | .error (.ingestion .directorySyncUnsupported) =>
    terminalOf (Except.error IngestDomainError.directorySyncUnsupported : Except _ Ingested)

def reading : Except Cas.Read.Error UInt64 → Host.Reply ByteArray
  | .ok count => terminalOf (Except.ok count : Except ReadDomainError UInt64)
  | .error (.host hostFailure) => .error hostFailure
  | .error .protocol => .error protocolFailure
  | .error error => terminalOf (Except.error (match error with
      | .missingBlob => ReadDomainError.missingBlob
      | .range start stop size => .range start stop size
      | .unavailable => .unavailable
      | .shortInline => .shortInline
      | .malformed => .malformed
      | .columnType index column actual => .columnType index column actual
      | .column column reason => .column column reason
      | .host _ | .protocol => .malformed) : Except _ UInt64)

def retention : Replication.History.Result Nat → Host.Reply ByteArray
  | .ok count => terminalOf (Except.ok count : Except HistoryDomainError Nat)
  | .error (.host hostFailure) => .error hostFailure
  | .error error => terminalOf (Except.error (match error with
      | .malformed => HistoryDomainError.malformed
      | .columnType index column actual => .columnType index column actual
      | .invalidText bytes => .invalidText ⟨bytes.toArray⟩
      | .column column reason => .column column reason
      | .origin error => .origin error
      | .host _ => .malformed) : Except _ Nat)

def malformedRoot : Native := .pure (.error ⟨2, 0⟩)
def protocol : Native := .pure (.error protocolFailure)

def dispatch : Command → Native
  | .acquire root holder now possession =>
    if root.size != 32 then malformedRoot
    else command (Cas.acquire root holder now possession) lifecycle
  | .delete root before =>
    if root.size != 32 then malformedRoot else command (Cas.delete root before) lifecycle
  | .unpin root holder =>
    if root.size != 32 then protocol else command (Cas.unpin root holder) hostOnly
  | .expire holder now => command (Cas.expire holder now) hostOnly
  | .read root range =>
    if root.size != 32 then protocol
    else command (Cas.Read.read root (match range with
      | none => .all
      | some (offset, length) => .range offset length)) reading
  | .ingest input now cache allowUnsupported =>
    command (Cas.Input.run input now (if cache then .cache else .local)
      (if allowUnsupported then .allowUnsupported else .requireSync)) ingestion
  | .commitGroups root spans size inline now cache =>
    if root.size != 32 then protocol
    else command (Cas.IngestCommit.commitGroups root size
      (spans.map fun (start, stop) => ⟨start.toNat, stop.toNat⟩) inline now
      (if cache then .cache else .local))
      (metadata ∘ Except.map fun outcome => Committed.mk outcome.size outcome.complete)
  | .admitSize root size =>
    if root.size != 32 then protocol else command (Cas.IngestCommit.admit root size) metadata
  | .trieGet root keySize =>
    if root.size != 32 then malformedRoot else command (Trie.getInput root 0 keySize) hostOnly
  | .trieAdmit size => command (Trie.admitInput 0 size) hostOnly
  | .trieVerify expected size =>
    if expected.size != 32 then protocol else command (Trie.verifyInput expected 0 size) hostOnly
  | .pruneHistory origin before => command (Replication.History.prune origin before) retention

/-- Every command starts here: an undecodable packet is a protocol failure
before any effect is requested. -/
@[export synch_lean_start]
def start (packet : ByteArray) : Native :=
  match (decodeAll packet : Option Command) with
  | none => protocol
  | some command => dispatch command

end VerifiedCore.Entry
