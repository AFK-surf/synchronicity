import VerifiedCore.Host.Wire
import VerifiedCore.Commands
import VerifiedCore.Commands.Generated
import VerifiedCore.Cas.Program
import VerifiedCore.Cas.Read
import VerifiedCore.Cas.Input
import VerifiedCore.Trie.Program
import VerifiedCore.Trie.Verify
import VerifiedCore.Trie.Mutate
import VerifiedCore.Cas.Durable
import VerifiedCore.Cas.Serve
import VerifiedCore.Cas.Receive
import VerifiedCore.Cas.Collect
import VerifiedCore.Cas.Project
import VerifiedCore.Trie.Serve
import VerifiedCore.Trie.Memo
import VerifiedCore.Trie.Collect
import VerifiedCore.Trie.Walk
import VerifiedCore.Trie.Diff
import VerifiedCore.Trie.Proof
import VerifiedCore.Trie.Complete
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

def mutation : Except Trie.Error ByteArray → Host.Reply ByteArray
  | .ok root => terminalOf (Except.ok root : Except Trie.MutationError ByteArray)
  | .error (.host hostFailure) => .error hostFailure
  | .error (.domain error) => terminalOf (Except.error error : Except _ ByteArray)

def durable [Encode A] : Except Cas.Durable.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except DurableDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error .malformed => terminalOf (Except.error DurableDomainError.malformed : Except _ A)
  | .error (.columnType index column actual) =>
    terminalOf (Except.error (DurableDomainError.columnType index column actual) : Except _ A)
  | .error (.sizeMismatch root recorded offered) =>
    terminalOf (Except.error (DurableDomainError.sizeMismatch root recorded offered) : Except _ A)

def serving : Except Cas.Serve.Error Cas.Serve.Served → Host.Reply ByteArray
  | .ok served =>
    terminalOf (Except.ok (Served.mk served.count served.spans) : Except ServeDomainError Served)
  | .error (.host hostFailure) => .error hostFailure
  | .error .protocol => .error protocolFailure
  | .error error => terminalOf (Except.error (match error with
      | .missingBlob => ServeDomainError.missingBlob
      | .malformed => .malformed
      | .columnType index column actual => .columnType index column actual
      | .column column reason => .column column reason
      | .overBudget level budget => .overBudget level budget
      | .host _ | .protocol => .malformed) : Except _ Served)

def receiving [Encode A] : Except Cas.Receive.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except ReceiveDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error .protocol => .error protocolFailure
  | .error error => terminalOf (Except.error (match error with
      | .malformed => ReceiveDomainError.malformed
      | .columnType index column actual => .columnType index column actual
      | .column column reason => .column column reason
      | .sizeMismatch root recorded offered => .sizeMismatch root recorded offered
      | .host _ | .protocol => .malformed) : Except _ A)

def servingTrie [Encode A] : Except Trie.Serve.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except TrieServeDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error error => terminalOf (Except.error (match error with
      | .unvouchedRoot => TrieServeDomainError.unvouchedRoot
      | .decode message => .decode message
      | .malformed => .malformed
      | .columnType index column actual => .columnType index column actual
      | .column column reason => .column column reason
      | .host _ => .malformed) : Except _ A)

def collectingTrie [Encode A] : Except Trie.Collect.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except TrieCollectDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error error => terminalOf (Except.error (match error with
      | .decode message => TrieCollectDomainError.decode message
      | .malformed => .malformed
      | .columnType index column actual => .columnType index column actual
      | .column column reason => .column column reason
      | .origin error => .origin error
      | .exhausted => .exhausted
      | .host _ => .malformed) : Except _ A)

def walking [Encode A] : Except Trie.Walk.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except TrieWalkDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error error => terminalOf (Except.error (match error with
      | .missingNode hash => TrieWalkDomainError.missingNode hash
      | .missingValue hash => .missingValue hash
      | .decode message => .decode message
      | .oddDepthValue => .oddDepthValue
      | .ceiling => .ceiling
      | .host _ => .ceiling) : Except _ A)

def projecting [Encode A] : Except Cas.Project.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except ProjectDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error .malformed => terminalOf (Except.error ProjectDomainError.malformed : Except _ A)
  | .error (.columnType index column actual) =>
    terminalOf (Except.error (ProjectDomainError.columnType index column actual) : Except _ A)
  | .error (.column column reason) =>
    terminalOf (Except.error (ProjectDomainError.column column reason) : Except _ A)

def collecting [Encode A] : Except Cas.Collect.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except CollectDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error .malformed => terminalOf (Except.error CollectDomainError.malformed : Except _ A)
  | .error (.columnType index column actual) =>
    terminalOf (Except.error (CollectDomainError.columnType index column actual) : Except _ A)
  | .error (.sizeMismatch root recorded offered) =>
    terminalOf (Except.error (CollectDomainError.sizeMismatch root recorded offered) : Except _ A)

def malformedRoot : Native := .pure (.error ⟨2, 0⟩)

def completing [Encode A] : Except Trie.Missing.Error A → Host.Reply ByteArray
  | .ok value => terminalOf (Except.ok value : Except TrieMissingDomainError A)
  | .error (.host hostFailure) => .error hostFailure
  | .error (.decode message) => terminalOf (Except.error (TrieMissingDomainError.decode message) : Except _ A)
  | .error (.canonical (.nodeDepth depth)) =>
    terminalOf (Except.error (TrieMissingDomainError.nodeDepth depth) : Except _ A)
  | .error (.canonical (.valueDepth depth)) =>
    terminalOf (Except.error (TrieMissingDomainError.valueDepth depth) : Except _ A)
  | .error (.canonical (.expectedBranch hash)) =>
    terminalOf (Except.error (TrieMissingDomainError.expectedBranch hash) : Except _ A)
  | .error .exhausted => terminalOf (Except.error TrieMissingDomainError.exhausted : Except _ A)

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
  | .trieInsert root keySize valueSize =>
    if root.size != 32 then malformedRoot
    else command (Trie.insertInput root keySize valueSize) mutation
  | .trieRemove root keySize =>
    if root.size != 32 then malformedRoot else command (Trie.removeInput root keySize) mutation
  | .pruneHistory origin before => command (Replication.History.prune origin before) retention
  | .casMarkDurable root =>
    if root.size != 32 then protocol else command (Cas.Durable.markDurable root) durable
  | .casAdoptDurable root size now =>
    if root.size != 32 then protocol else command (Cas.Durable.adoptDurable root size now) durable
  | .casHealMissing root =>
    if root.size != 32 then protocol else command (Cas.Durable.healMissing root) durable
  | .casReconcileScratch marker => command (Cas.Durable.reconcileScratch marker) durable
  | .casClearCache root =>
    if root.size != 32 then protocol else command (Cas.Durable.clearCache root) durable
  | .casEncodeSlice root requested =>
    if root.size != 32 then protocol else command (Cas.Serve.encodeSlice root requested) serving
  | .casEncodeProof root requested level budget =>
    if root.size != 32 then protocol
    else command (Cas.Serve.encodeProof root requested level budget) serving
  | .casWriteSlice root size served now cache =>
    if root.size != 32 then protocol
    else command (Cas.Receive.writeSlice root size served 0 now (if cache then .cache else .local)) receiving
  | .casWriteProof root size served level now cache =>
    if root.size != 32 then protocol
    else command (Cas.Receive.writeProof root size served level 0 now (if cache then .cache else .local)) receiving
  | .casPromote donor root size proven now cache =>
    if root.size != 32 || donor.size != 32 then protocol
    else command (Cas.Receive.promote donor root size proven now (if cache then .cache else .local)) receiving
  | .casTouch root =>
    if root.size != 32 then protocol else command (Cas.Collect.touch root) collecting
  | .casEvict limit shortfall =>
    command (Cas.Collect.evict limit shortfall)
      (collecting ∘ Except.map fun (entries, freed) => Evicted.mk entries freed)
  | .casGcContent before => command (Cas.Collect.gcContent before) collecting
  | .casGcOrphans before => command (Cas.Collect.gcOrphans before) collecting
  | .casBlob root => if root.size != 32 then protocol else command (Cas.Project.blob root) projecting
  | .casBlobs => command Cas.Project.blobs projecting
  | .casBlobCandidates => command Cas.Project.candidates projecting
  | .casPins root =>
    if root.any (·.size != 32) then protocol else command (Cas.Project.pins root) projecting
  | .casPinnedBlobs => command Cas.Project.pinnedBlobs projecting
  | .trieServeNodes root wants prefixes exact peerOrigins confined =>
    if root.size != 32 then protocol
    else command (Trie.Serve.serveNodes root wants ⟨prefixes, exact⟩ peerOrigins confined) servingTrie
  | .trieServeValues root wants prefixes exact peerOrigins confined =>
    if root.size != 32 then protocol
    else command (Trie.Serve.serveValues root wants ⟨prefixes, exact⟩ peerOrigins confined) servingTrie
  | .trieResolve root paths =>
    if root.size != 32 then protocol
    else command (Trie.Serve.resolvePaths root (paths.map (·.toList))) servingTrie
  | .trieCollect prefixes exact =>
    command (Trie.Collect.gcTrie (Std.HashSet ByteArray) ⟨prefixes, exact⟩)
      (collectingTrie ∘ Except.map fun (nodes, values, roots) => Collected.mk nodes values roots)
  | .trieMemoKey root prefixes exact owner =>
    if root.size != 32 then protocol
    else command (Trie.Memo.keyFor (E := Host.Digest) id ⟨prefixes, exact⟩ root owner) hostOnly
  | .trieScan root keyPrefix startAfter limit =>
    if root.size != 32 then protocol
    else command (Trie.Walk.scan (E := Trie.Walk.Effects) root keyPrefix startAfter limit) walking
  | .trieDiff oldRoot newRoot =>
    if oldRoot.size != 32 || newRoot.size != 32 then protocol
    else command (Trie.Diff.diff (E := Trie.Diff.Effects) oldRoot newRoot) walking
  | .trieMaterialize oldRoot newRoot prefixes exact =>
    if oldRoot.size != 32 || newRoot.size != 32 then protocol
    else command (Trie.Diff.materialize (E := Trie.Diff.Effects) ⟨prefixes, exact⟩ oldRoot newRoot) walking
  | .trieProve root keySize =>
    if root.size != 32 then malformedRoot else command (Trie.Proof.proveInput root 0 keySize) hostOnly
  | .trieVerifyProof root key nodes value =>
    if root.size != 32 then protocol
    else command (Trie.Proof.verify (E := Host.Digest) root key nodes value) hostOnly
  | .peerProbe root wants inTransaction => command (Host.Peer.probe root wants inTransaction) hostOnly
  | .trieComplete root prefixes exact owner =>
    if root.size != 32 then protocol
    else command (Trie.Complete.isComplete (Std.HashSet Trie.Missing.Visit) (Std.HashSet ByteArray)
      ⟨⟨prefixes, exact⟩, owner⟩ root) completing
  | .planExchange ours theirs servable =>
    if servable.length > UInt64.size ||
        !(ours ++ theirs ++ servable).all (·.root.size == 32) then protocol
    else pure (terminalOf (Replication.Exchange.plan ours theirs servable))

/-- Every command starts here: an undecodable packet is a protocol failure
before any effect is requested. -/
@[export synch_lean_start]
def start (packet : ByteArray) : Native :=
  match (decodeAll packet : Option Command) with
  | none => protocol
  | some command => dispatch command

end VerifiedCore.Entry
