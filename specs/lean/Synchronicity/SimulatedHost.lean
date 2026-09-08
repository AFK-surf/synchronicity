import Synchronicity.SimulatedHost.Database
import VerifiedCore.Host.Resources
import VerifiedCore.Host.Construct
import VerifiedCore.Host.Source
import VerifiedCore.Crypto
import VerifiedCore.Host.Bao
import VerifiedCore.Host.Sweep
import VerifiedCore.Host.Memo
import VerifiedCore.Host.Digest
import VerifiedCore.Host.Walk
import VerifiedCore.Host.Peer
import Synchronicity.Decidable

/-! One stateful host for composed CAS proofs. Successful replies are computed
from raw database/files/resource state, not supplied by operation-specific scripts.
Only primitive crypto and environmental failures are configurable. -/
namespace Synchronicity.SimulatedHost
open VerifiedCore.Host

abbrev ObjectKey := String × ByteArray
abbrev FileStore := List (ObjectKey × ByteArray)

def lookupFile (files : FileStore) (key : ObjectKey) : Option ByteArray :=
  (files.find? fun entry => entry.1 == key).map Prod.snd

def writeFile (files : FileStore) (key : ObjectKey) (bytes : ByteArray) : FileStore :=
  (key, bytes) :: files.filter (fun entry => entry.1 != key)

structure Temporary where
  space : String
  bytes : ByteArray := ByteArray.empty
  flushed : Bool := false

/-- All commands use this state, with no operation-specific decoded metadata. -/
structure State where
  db : Database := []
  pending : Option (Transaction × Database) := none
  nextTx : UInt64 := 1
  files : FileStore := []
  /-- Raw byte namespaces backed by SQL `(hash, data)` relations. Reads use
  the active transaction's rows, exactly as the native storage session does.
  Other namespaces use the file service. This is backend configuration,
  shared by every operation, rather than an operation-specific interpreter. -/
  byteRelations : List String := []
  /-- When each file was last written, for the sweeps; a file without a
  time is one whose time cannot be read. -/
  modified : List (ObjectKey × Int64) := []
  handles : List (UInt64 × ByteArray) := []
  temporaries : List (UInt64 × Temporary) := []
  leases : List (UInt64 × ObjectKey) := []
  counters : List (ObjectKey × UInt64) := []
  /-- The completeness certificates a host keeps, and how many mutations
  have forgotten some of them. -/
  certified : List ByteArray := []
  memoGeneration : UInt64 := 0
  /-- An invalidating host mutation currently hides certificates. The host
  advances the generation at both edges; concurrent refinement is a trust
  boundary, so fixtures supply those observations explicitly. -/
  memoBlocked : Bool := false
  /-- A transaction may validate its own snapshot without caching an answer
  about data it can still roll back. -/
  memoWritable : Bool := true
  /-- The refusals a peer recorded, as (hash, position), and the changes a
  materialization was handed, in walk order. -/
  redacted : List (ByteArray × ByteArray) := []
  applied : List (ByteArray × UInt64 × Option ByteArray) := []
  /-- What a peer holds: node and value bytes by hash, and the hashes it
  holds but may not show. -/
  peerNodes : List (ByteArray × ByteArray) := []
  peerValues : List (ByteArray × ByteArray) := []
  peerRedacted : List ByteArray := []
  nextHandle : UInt64 := 1
  synced : List ObjectKey := []
  output : List UInt8 := []
  now : Int64 := 0
  trace : List String := []
  /-- Failure at an effect index; normal replies always come from state. -/
  faults : List (Nat × Failure) := []
  /-- A scan may yield its rows and then fail stepping. -/
  scanFault : Option (Nat × Failure) := none
  directorySync : SyncStatus := .synced
  /-- Primitive cryptography is an explicit trust parameter. -/
  hash : ByteArray → ByteArray := fun _ => ⟨Array.replicate 32 0⟩
  outboard : ByteArray → ByteArray := fun _ => ByteArray.empty
  validateKey : List UInt8 → Bool := fun _ => true
  verifySignature : ByteArray → ByteArray → ByteArray → Bool := fun _ _ _ => false
  /-- Primitive Unicode normalization predicate, as on the native boundary. -/
  isNfc : String → Bool := fun _ => true
  /-- The Bao encodings are a trust parameter too: what the host would encode
  for exactly the groups it is asked for, and whether a proof walk fits. -/
  slice : ByteArray → UInt64 → Option ByteArray → List (UInt64 × UInt64) → ByteArray :=
    fun _ _ _ _ => ByteArray.empty
  proof : ByteArray → UInt64 → List (UInt64 × UInt64) → UInt64 → UInt64 → Option ByteArray :=
    fun _ _ _ _ _ => some ByteArray.empty
  /-- What a received slice of these spans decodes to inline (`none`: it does
  not verify), whether one decodes into the files, what a received proof
  establishes (`none`: it does not verify), and whether a donor's tree agrees
  with a run. -/
  decodeInline : ByteArray → UInt64 → Option ByteArray → List (UInt64 × UInt64) → UInt64 →
    Option ByteArray := fun _ _ inline _ _ => some (inline.getD ByteArray.empty)
  decodeSlice : ByteArray → UInt64 → List (UInt64 × UInt64) → UInt64 → Bool := fun _ _ _ _ => true
  decodeSliceFailure : Failure := ⟨3, 0⟩
  /-- The trusted Bao decoder's physical result, using the existing payload.
  Content composition must require that this transformation writes the verified
  bytes and preserves previously verified bytes. The transformation also runs
  on error: the native decoder can persist a verified prefix before failing.
  A successful verification bit alone does not establish either fact. -/
  decodedPayload : ByteArray → UInt64 → List (UInt64 × UInt64) → UInt64 → ByteArray →
    ByteArray := fun _ _ _ _ previous => previous
  proven : ByteArray → UInt64 → List (UInt64 × UInt64) → UInt64 → UInt64 →
    Option (Bool × List (UInt64 × UInt64 × ByteArray × Bool)) := fun _ _ _ _ _ => some (false, [])
  agrees : ByteArray → ByteArray → UInt64 → UInt64 → UInt64 → ByteArray → Bool :=
    fun _ _ _ _ _ _ => false

abbrev Result (A : Type) := A × State

def invalid : Failure := ⟨3, 0⟩
def absent : Failure := ⟨1, 2⟩
def truncated : Failure := ⟨1, 3⟩

/-- A missing row and an ill-typed payload have different raw replies. -/
def relationBytes (db : Database) (relation : String) (key : ByteArray) : Reply (Option ByteArray) :=
  match (rows db relation).find? (fun row => cell row "hash" == .blob key) with
  | none => .ok none
  | some row => match cell row "data" with
    | .blob bytes => .ok (some bytes)
    | _ => .error invalid

/-- The actual byte accessor behind Storage, including writes made by an
open transaction. A later rollback therefore also rolls back its byte view. -/
def readByteObject (state : State) (space : String) (key : ByteArray) : Reply (Option ByteArray) :=
  if state.byteRelations.contains space then
    relationBytes ((state.pending.map Prod.snd).getD state.db) space key
  else .ok (lookupFile state.files (space, key))

/-- Successful raw bytes, for graph interpretations. A failed read cannot
establish a graph edge; executable readers still return its original error. -/
def readableBytes (state : State) (space : String) (key : ByteArray) : Option ByteArray :=
  match readByteObject state space key with
  | .ok bytes => bytes
  | .error _ => none

def fault (state : State) : Option Failure :=
  (state.faults.find? fun entry => entry.1 == state.trace.length).map Prod.snd

def record (state : State) (event : String) : State :=
  { state with trace := state.trace ++ [event] }

/-- An injected ordinary failure precedes the mutation. Consuming resource
operations opt in to consuming the handle even on failure, as the ABI requires. -/
def reply (state : State) (event : String) (action : State → Result (Reply A))
    (consume : Bool := false) : Result (Reply A) :=
  match fault state with
  | some failure => (.error failure, record (if consume then (action state).2 else state) event)
  | none => let (result, state) := action state; (result, record state event)

def fileReply (state : State) (event : String) (action : State → Result (FileReply A)) :
    Result (FileReply A) :=
  match fault state with
  | some failure => (.error ⟨failure, .other⟩, record state event)
  | none => let (result, state) := action state; (result, record state event)

def transaction (state : State) (tx : Transaction) (action : Database → A × Database) : Result (Reply A) :=
  match state.pending with
  | some (token, db) =>
      if token == tx then
        let (value, db) := action db
        (.ok value, { state with pending := some (token, db) })
      else (.error invalid, state)
  | none => (.error invalid, state)

def counter (state : State) (key : ObjectKey) : UInt64 :=
  ((state.counters.find? fun entry => entry.1 == key).map Prod.snd).getD 0

def setCounter (state : State) (key : ObjectKey) (value : UInt64) : State :=
  { state with counters := (key, value) :: state.counters.filter (fun entry => entry.1 != key) }

def scanFailure (state : State) : Option Failure :=
  state.scanFault.bind fun (index, failure) => if index == state.trace.length then some failure else none

def storage : Storage A → State → Result A
  | .begin, state => reply state "begin" fun state =>
      if state.pending.isSome then (.error invalid, state) else
        (.ok state.nextTx, { state with pending := some (state.nextTx, state.db), nextTx := state.nextTx + 1 })
  | .commit tx, state => reply state "commit" fun state =>
      match state.pending with
      | some (token, db) => if token == tx then (.ok (), { state with db, pending := none })
          else (.error invalid, state)
      | none => (.error invalid, state)
  | .rollback tx, state => reply state "rollback" (fun state =>
      match state.pending with
      | some (token, _) => if token == tx then (.ok (), { state with pending := none })
          else (.error invalid, state)
      | none => (.error invalid, state)) true
  | .readRows tx relation columns fields order joins, state =>
      reply state ("read:" ++ relation) fun state => transaction state tx fun db =>
        (query db relation columns fields order joins, db)
  | .scanRows tx relation columns fields order joins, state =>
      reply state ("scan:" ++ relation) fun state => transaction state tx fun db =>
        (⟨query db relation columns fields order joins, scanFailure state⟩, db)
  | .upsert tx relation fields conflicts updates, state =>
      reply state ("upsert:" ++ relation) fun state => transaction state tx fun db =>
        ((), setRows db relation (upsertRows (rows db relation) fields conflicts
          (updates.map fun column => (column, .excluded column))))
  | .deleteRows tx relation fields blockers bounds, state =>
      reply state ("delete:" ++ relation) fun state => transaction state tx fun db =>
        let table := rows db relation
        let remaining := table.filter (fun row => !deletable db fields blockers bounds row)
        (table.length - remaining.length, setRows db relation remaining)
  | .existsRows tx relation fields, state =>
      reply state ("exists:" ++ relation) fun state => transaction state tx fun db =>
        ((rows db relation).any (fun row => equals row fields), db)
  | .deleteExcept tx relation column keys, state =>
      reply state ("sweep:" ++ relation) fun state => transaction state tx fun db =>
        let table := rows db relation
        -- SQL `NOT IN`: a NULL key is neither in nor out of the set, so the
        -- row stays; any other key not in the set goes. Configured raw byte
        -- relations expose this same pending database through `readBytes`.
        let remaining := table.filter fun row => match cell row column with
          | .blob key => keys.contains key
          | .null => true
          | _ => false
        (table.length - remaining.length, setRows db relation remaining)
  | .readCounter space key, state => reply state ("counter:" ++ space) fun state =>
      (.ok (counter state (space, key)), state)
  | .readBytes space key, state => reply state ("bytes:" ++ space) fun state =>
      (readByteObject state space key, state)
  | .readInput handle offset count, state => reply state "readInput" fun state =>
      match (state.handles.find? fun entry => entry.1 == handle).map Prod.snd with
      | none => (.error invalid, state)
      | some bytes => if offset.toNat + count.toNat ≤ bytes.size then
          (.ok (bytes.extract offset.toNat (offset.toNat + count.toNat)), state)
        else (.error truncated, state)
  | .removeFile space key, state => reply state ("remove:" ++ space) fun state =>
      (.ok (), { state with files := state.files.filter (fun entry => entry.1 != (space, key)) })

def access : Access A → State → Result A
  | .snapshot selection columns, state => reply state ("snapshot:" ++ selection.relation) fun state =>
      (.ok ⟨((rows state.db selection.relation).filter (selects selection)).map (project columns),
        scanFailure state⟩, state)
  | .snapshotExcluding selection columns excluding, state =>
      reply state ("exclude:" ++ selection.relation) fun state =>
      (.ok ⟨((rows state.db selection.relation).filter fun row =>
          selects selection row && !excluded state.db row excluding).map (project columns),
        scanFailure state⟩, state)
  | .update tx selection values, state => reply state ("update:" ++ selection.relation) fun state =>
      transaction state tx fun db =>
        let table := rows db selection.relation
        ((table.filter (selects selection)).length,
         setRows db selection.relation (table.map fun row =>
           if selects selection row then assign row values else row))
  | .copyRows tx target selection fields conflicts, state => reply state ("copy:" ++ target) fun state =>
      transaction state tx fun db =>
        let next := copyRows db target selection fields conflicts
        ((rows next target).length - (rows db target).length, next)
  | .delete tx selection, state => reply state ("delete:" ++ selection.relation) fun state =>
      transaction state tx fun db =>
        let table := rows db selection.relation
        let remaining := table.filter (fun row => !selects selection row)
        (table.length - remaining.length, setRows db selection.relation remaining)

def upsert : Upsert A → State → Result A
  | .write tx relation fields conflicts assignments, state =>
      reply state ("upsert:" ++ relation) fun state => transaction state tx fun db =>
        ((), setRows db relation (upsertRows (rows db relation) fields conflicts assignments))

def opened (state : State) (handle : UInt64) : Option ByteArray :=
  (state.handles.find? fun entry => entry.1 == handle).map Prod.snd

def openBytes (state : State) (bytes : ByteArray) : Result (Reply UInt64) :=
  (.ok state.nextHandle, { state with
    handles := (state.nextHandle, bytes) :: state.handles
    nextHandle := state.nextHandle + 1 })

def file : FileIO A → State → Result A
  | .open space key, state => fileReply state ("open:" ++ space) fun state =>
      match lookupFile state.files (space, key) with
      | none => (.error ⟨absent, .missing⟩, state)
      | some bytes => (.ok state.nextHandle,
          { state with handles := (state.nextHandle, bytes) :: state.handles, nextHandle := state.nextHandle + 1 })
  | .readAt handle offset count, state => fileReply state "readAt" fun state =>
      match opened state handle with
      | none => (.error ⟨invalid, .other⟩, state)
      | some bytes => if offset.toNat + count.toNat ≤ bytes.size then
          (.ok (bytes.extract offset.toNat (offset.toNat + count.toNat)), state)
        else (.error ⟨truncated, .shortRead⟩, state)
  | .transfer handle offset count, state => fileReply state "transfer" fun state =>
      match opened state handle with
      | none => (.error ⟨invalid, .other⟩, state)
      | some bytes => if offset.toNat + count.toNat ≤ bytes.size then
          (.ok (), { state with output := state.output ++
            (bytes.extract offset.toNat (offset.toNat + count.toNat)).data.toList })
        else (.error ⟨truncated, .shortRead⟩, state)
  | .close handle, state => reply state "close" (fun state =>
      let found := (opened state handle).isSome
      (if found then .ok () else .error invalid,
        { state with handles := state.handles.filter (fun entry => entry.1 != handle) })) true

def clock : Clock A → State → Result A
  | .nowNs, state => reply state "clock" fun state => (.ok state.now, state)

def output : Output A → State → Result A
  | .append bytes, state => reply state "append" fun state =>
      (.ok (), { state with output := state.output ++ bytes.data.toList })

def source : SourceIO A → State → Result A
  | .stat space key, state => reply state ("stat:" ++ space) fun state =>
      match lookupFile state.files (space, key) with
      | none => (.error absent, state)
      | some bytes => (.ok bytes.size.toUInt64, state)
  | .freeze bytes, state => reply state "freeze" fun state => openBytes state bytes
  | .readSome handle offset count, state => reply state "readSome" fun state =>
      match opened state handle with
      | none => (.error invalid, state)
      | some bytes => (.ok (bytes.extract offset.toNat (offset.toNat + count.toNat)), state)

def temporary (state : State) (handle : UInt64) : Option Temporary :=
  (state.temporaries.find? fun entry => entry.1 == handle).map Prod.snd

def putTemporary (state : State) (handle : UInt64) (value : Temporary) : State :=
  { state with temporaries := (handle, value) :: state.temporaries.filter (fun entry => entry.1 != handle) }

def construct : Construct A → State → Result A
  | .hash bytes, state => reply state "hash" fun state => (.ok (state.hash bytes), state)
  | .build handle payload outboard size, state => reply state "build" fun state =>
      match opened state handle, temporary state payload, temporary state outboard with
      | some bytes, some p, some o =>
          if payload != outboard && size.toNat ≤ bytes.size then
            let content := bytes.extract 0 size.toNat
            (.ok (state.hash content),
              putTemporary (putTemporary state payload { p with bytes := content, flushed := false })
                outboard { o with bytes := state.outboard content, flushed := false })
          else (.error invalid, state)
      | _, _, _ => (.error invalid, state)

def resources : Resources A → State → Result A
  | .createTemporary space, state => reply state ("temporary:" ++ space) fun state =>
      (.ok state.nextHandle, { state with
        temporaries := (state.nextHandle, ⟨space, ByteArray.empty, false⟩) :: state.temporaries,
        nextHandle := state.nextHandle + 1 })
  | .flush handle, state => reply state "flush" fun state =>
      match temporary state handle with
      | none => (.error invalid, state)
      | some value => (.ok (), putTemporary state handle { value with flushed := true })
  | .replace handle space key, state => reply state ("replace:" ++ space) fun state =>
      match temporary state handle with
      | none => (.error invalid, state)
      | some value => if value.space == space then
          (.ok (), { state with
            files := writeFile state.files (space, key) value.bytes
            temporaries := state.temporaries.filter (fun entry => entry.1 != handle) })
        else (.error invalid, state)
  | .discard handle, state => reply state "discard" (fun state =>
      (.ok (), { state with temporaries := state.temporaries.filter (fun entry => entry.1 != handle) })) true
  | .syncParent space key, state => reply state ("sync:" ++ space) fun state =>
      (.ok state.directorySync, if state.directorySync = .synced then
        { state with synced := (space, key) :: state.synced } else state)

def lease : Lease A → State → Result A
  | .acquire space key, state => reply state ("lease:" ++ space) fun state =>
      let next := setCounter state (space, key) (counter state (space, key) + 1)
      (.ok state.nextHandle, { next with
        leases := (state.nextHandle, (space, key)) :: state.leases
        nextHandle := state.nextHandle + 1 })
  -- The section is a counted token like a lease, keyed by the space alone,
  -- so "inside the section" is the counter of `(space, empty)` being one.
  | .order space, state => reply state ("order:" ++ space) fun state =>
      let key := (space, ByteArray.empty)
      let next := setCounter state key (counter state key + 1)
      (.ok state.nextHandle, { next with
        leases := (state.nextHandle, key) :: state.leases
        nextHandle := state.nextHandle + 1 })
  | .release token, state => reply state "release" (fun state =>
      match (state.leases.find? fun entry => entry.1 == token).map Prod.snd with
      | none => (.error invalid, state)
      | some key =>
          let next := setCounter state key ((counter state key).toNat - 1).toUInt64
          (.ok (), { next with leases := state.leases.filter (fun entry => entry.1 != token) })) true

def crypto : Crypto A → State → Result A
  | .validateEd25519 bytes, state => reply state "crypto" fun state => (.ok (state.validateKey bytes), state)
  | .verifyEd25519 key message signature, state => reply state "verifySignature" fun state =>
      (.ok (state.verifySignature key message signature), state)

def unicode : Unicode A → State → Result A
  | .isNfc text, state => reply state "unicode:nfc" fun state => (.ok (state.isNfc text), state)

/-- The digest is the same trust parameter construction hashes with. -/
def digest : Digest A → State → Result A
  | .blake3 bytes, state => reply state "digest" fun state => (.ok (state.hash bytes), state)

/-- Encodings land in the private output, as a transfer does; the program
sees only the count. A refused proof appends nothing. -/
def bao : Bao A → State → Result A
  | .encodeSlice root size inline spans, state => reply state "bao:slice" fun state =>
      let encoded := state.slice root size inline spans
      (.ok encoded.size.toUInt64, { state with output := state.output ++ encoded.data.toList })
  | .encodeProof root size spans level budget, state => reply state "bao:proof" fun state =>
      match state.proof root size spans level budget with
      | none => (.ok none, state)
      | some encoded =>
        (.ok (some encoded.size.toUInt64), { state with output := state.output ++ encoded.data.toList })
  | .decodeInline root size inline spans input, state => reply state "bao:decodeInline" fun state =>
      match state.decodeInline root size inline spans input with
      | none => (.error invalid, state)
      | some buffer => (.ok buffer, state)
  | .decodeSlice root size spans input, state => reply state "bao:decodeSlice" fun state =>
      let previous := (lookupFile state.files ("cas_payload", root)).getD ByteArray.empty
      let bytes := state.decodedPayload root size spans input previous
      let result : Reply Unit := if state.decodeSlice root size spans input then .ok ()
        else .error state.decodeSliceFailure
      (result, { state with files := writeFile state.files ("cas_payload", root) bytes })
  | .flushObject root, state => reply state "bao:flush" fun state =>
      (.ok (), { state with synced := ("cas_payload", root) :: state.synced })
  | .trimObject _ _, state => reply state "bao:trim" fun state => (.ok (), state)
  | .writeProof root size spans level input, state => reply state "bao:writeProof" fun state =>
      match state.proven root size spans level input with
      | none => (.error invalid, state)
      | some answer => (.ok answer, state)
  | .promoteRun donor root size start groups cv, state => reply state "bao:promoteRun" fun state =>
      (.ok (state.agrees donor root size start groups cv), state)

/-- The object files of the store, as the host would list them: every root
some payload or outboard is named for, once. -/
def objectRoots (state : State) : List ByteArray :=
  (state.files.filterMap fun ((space, key), _) =>
    if space == "cas_payload" || space == "cas_outboard" then some key else none).eraseDups

/-- A file costs its length; its time is what was recorded for it; the store
is one page. -/
def sweep : Sweep A → State → Result A
  | .fileBytes space key, state => reply state ("bytes:" ++ space) fun state =>
      (.ok ((lookupFile state.files (space, key)).map (·.size.toUInt64) |>.getD 0), state)
  | .fileModified space key, state => reply state ("modified:" ++ space) fun state =>
      (.ok (match lookupFile state.files (space, key) with
        | none => none
        | some _ => (state.modified.find? fun entry => entry.1 == (space, key)).map Prod.snd), state)
  | .listObjects page, state => reply state "list" fun state =>
      (.ok (if page == 0 then
        some ((objectRoots state).foldl (fun listed root => listed ++ root) ByteArray.empty)
      else none), state)

/-- Forgetting keeps exactly the kept certificates and counts one mutation. -/
def memo : Memo A → State → Result A
  | .forgetExcept keep, state => reply state "memo:forget" fun state =>
      let certified := state.certified.filter fun key => keep.contains key
      (.ok (), { state with certified, memoGeneration := state.memoGeneration + 1 })
  | .isKnown key, state => reply state "memo:known" fun state =>
      (.ok (!state.memoBlocked && state.certified.contains key), state)
  | .generation, state => reply state "memo:generation" fun state =>
      (.ok state.memoGeneration, state)
  | .certify key generation, state => reply state "memo:certify" fun state =>
      let allowed := generation == state.memoGeneration &&
        (!state.memoWritable || (!state.memoBlocked && generation != 18446744073709551615))
      let certified := if allowed && state.memoWritable then
        if state.certified.contains key then state.certified else key :: state.certified
        else state.certified
      (.ok allowed, { state with certified })

/-- A refusal is looked up by hash at a position, or at any. -/
def redaction : Redaction A → State → Result A
  | .isRedacted hash path, state => reply state "redacted" fun state =>
      (.ok (state.redacted.any fun entry => entry.1 == hash && path.all (· == entry.2)), state)

/-- The materializer records what it was handed, in order. -/
def apply : Apply A → State → Result A
  | .applyChange key kind new, state => reply state "apply" fun state =>
      (.ok (), { state with applied := state.applied ++ [(key, kind, new)] })

/-- A peer answers each want by its hash from what it holds, as the pair the
runner admits, and names the rest as absent, in want order. -/
def peerAnswer (held : List (ByteArray × ByteArray)) (wants : List (ByteArray × ByteArray)) :
    List (ByteArray × ByteArray) × List ByteArray :=
  wants.foldr (fun (_, hash) (served, missing) =>
    match held.find? (·.1 == hash) with
    | some (_, bytes) => ((hash, bytes) :: served, missing)
    | none => (served, hash :: missing)) ([], [])

/-- A peer as the runner presents it: a request while a transaction is open
is refused the way the runner refuses it, as a protocol failure delivered
into the program, so no connection is held across the round trip; otherwise
the served pairs, the absences and, for nodes, the refusals. -/
def peer : Peer A → State → Result A
  | .fetchNodes _ wants, state => reply state "peer:nodes" fun state =>
      if state.pending.isSome then (.error invalid, state) else
      let (served, rest) := peerAnswer state.peerNodes wants
      (.ok (served, rest.filter (fun hash => !state.peerRedacted.contains hash),
        rest.filter state.peerRedacted.contains), state)
  | .fetchValues _ wants, state => reply state "peer:values" fun state =>
      if state.pending.isSome then (.error invalid, state) else
      (.ok (peerAnswer state.peerValues wants), state)

/-- Capability composition is shared by every proof and every operation. -/
class Interpreter (E : Type → Type) where
  handle : E A → State → Result A

instance : Interpreter Storage := ⟨storage⟩
instance : Interpreter Access := ⟨access⟩
instance : Interpreter Upsert := ⟨upsert⟩
instance : Interpreter FileIO := ⟨file⟩
instance : Interpreter Clock := ⟨clock⟩
instance : Interpreter Output := ⟨output⟩
instance : Interpreter SourceIO := ⟨source⟩
instance : Interpreter Construct := ⟨construct⟩
instance : Interpreter Resources := ⟨resources⟩
instance : Interpreter Lease := ⟨lease⟩
instance : Interpreter Crypto := ⟨crypto⟩
instance : Interpreter Unicode := ⟨unicode⟩
instance : Interpreter Digest := ⟨digest⟩
instance : Interpreter Bao := ⟨bao⟩
instance : Interpreter Sweep := ⟨sweep⟩
instance : Interpreter Memo := ⟨memo⟩
instance : Interpreter Redaction := ⟨redaction⟩
instance : Interpreter Apply := ⟨apply⟩
instance : Interpreter Peer := ⟨peer⟩
instance [Interpreter L] [Interpreter R] : Interpreter (EffectSum L R) where
  handle
    | .left effect, state => Interpreter.handle effect state
    | .right effect, state => Interpreter.handle effect state

/-- Structural execution needs no arbitrary fuel bound. Effects update one
shared state, so outputs of one operation are inputs to the next. -/
def execute [Interpreter E] : Program E A → State → Result A
  | .pure value, state => (value, state)
  | .request effect resume, state =>
      let (reply, state) := Interpreter.handle effect state
      execute (resume reply) state

/-- A command gets a fresh private output buffer. Persistent state is retained. -/
def run [Interpreter E] (operation : OperationOver E ε A) (state : State) : Result (Except ε A) :=
  execute operation.run { state with output := [] }

/-- Native command publication is a shared, domain-neutral host contract. -/
def publish (protocol : ε) : Except ε UInt64 → State → Except ε (List UInt8)
  | .error error, _ => .error error
  | .ok count, state => if count.toNat = state.output.length then .ok state.output else .error protocol



/-- Sequential programs share the state produced by their predecessors. -/
theorem execute_bind [Interpreter E] (program : Program E A) (next : A → Program E B) (state : State) :
    execute (program.bind next) state =
      let (value, state) := execute program state
      execute (next value) state := by
  induction program generalizing state with
  | pure value => rfl
  | request effect resume ih =>
    simp only [Program.bind, execute]
    exact ih _ _

/-- A loop's iteration runs on the state its predecessor left. -/
theorem execute_iterate_request [Interpreter E] (body : S → Program E (Except ε (S ⊕ R)))
    (exhausted : ε) (fuel : Nat) (effect : E B) (resume : B → Program E (Except ε (S ⊕ R)))
    (state : State) :
    execute (Program.iterate body exhausted (fuel + 1) (.request effect resume)) state =
      let (reply, state) := Interpreter.handle effect state
      execute (Program.iterate body exhausted fuel (resume reply)) state := by
  simp only [Program.iterate, execute]

/-- What a loop answers satisfies `Q` whenever every iteration keeps `P` and
stops only with `Q`, starting from a program that does the same. -/
theorem iterate_sound [Interpreter E] (body : S → Program E (Except ε (S ⊕ R))) (exhausted : ε)
    (P : S → Prop) (Q : R → Prop)
    (kept : ∀ start state next, P start →
      (execute (body start) state).1 = .ok (.inl next) → P next)
    (stopped : ∀ start state result, P start →
      (execute (body start) state).1 = .ok (.inr result) → Q result)
    (fuel : Nat) : ∀ (program : Program E (Except ε (S ⊕ R))) (state : State),
    (∀ next, (execute program state).1 = .ok (.inl next) → P next) →
    (∀ result, (execute program state).1 = .ok (.inr result) → Q result) →
    ∀ result, (execute (Program.iterate body exhausted fuel program) state).1 = .ok result →
      Q result := by
  induction fuel with
  | zero => intro program state _ _ result ran; simp [Program.iterate, execute] at ran
  | succ fuel ih =>
    intro program state keeps stops result ran
    match program with
    | .pure (.error error) => simp [Program.iterate, execute] at ran
    | .pure (.ok (.inr answer)) =>
      simp only [Program.iterate, execute, Except.ok.injEq] at ran
      exact ran ▸ stops answer rfl
    | .pure (.ok (.inl next)) =>
      simp only [Program.iterate] at ran
      exact ih (body next) state (kept next state · (keeps next rfl)) (stopped next state · (keeps next rfl))
        result ran
    | .request effect resume =>
      rw [execute_iterate_request] at ran
      simp only [execute] at keeps stops
      exact ih _ _ keeps stops result ran

/-- Lifting an operation changes its capability position, not its semantics. -/
theorem execute_mapEffects [Interpreter E] [Interpreter F]
    (inject : {B : Type} → E B → F B)
    (agrees : ∀ {B} (effect : E B) state,
      Interpreter.handle (inject effect) state = Interpreter.handle effect state)
    (program : Program E A) (state : State) :
    execute (program.mapEffects inject) state = execute program state := by
  induction program generalizing state with
  | pure value => rfl
  | request effect resume ih =>
    simp only [Program.mapEffects, execute, agrees]
    exact ih _ _

/-- Abandonment releases only invocation-owned resources and aborts uncommitted
DB work. Published files and committed rows survive, including after errors. -/
def abandon (state : State) : State :=
  let released := state.leases.foldl (fun state (_, key) =>
    setCounter state key ((counter state key).toNat - 1).toUInt64) state
  { released with pending := none, handles := [], temporaries := [], leases := [], output := [] }

end Synchronicity.SimulatedHost
