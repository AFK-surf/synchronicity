import Synchronicity.SimulatedHost.Database
import VerifiedCore.Host.Resources
import VerifiedCore.Host.Construct
import VerifiedCore.Host.Source
import VerifiedCore.Crypto
import VerifiedCore.Host.Bao
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
  handles : List (UInt64 × ByteArray) := []
  temporaries : List (UInt64 × Temporary) := []
  leases : List (UInt64 × ObjectKey) := []
  counters : List (ObjectKey × UInt64) := []
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
  proven : ByteArray → UInt64 → List (UInt64 × UInt64) → UInt64 → UInt64 →
    Option (Bool × List (UInt64 × UInt64 × ByteArray × Bool)) := fun _ _ _ _ _ => some (false, [])
  agrees : ByteArray → ByteArray → UInt64 → UInt64 → UInt64 → ByteArray → Bool :=
    fun _ _ _ _ _ _ => false

abbrev Result (A : Type) := A × State

def invalid : Failure := ⟨3, 0⟩
def absent : Failure := ⟨1, 2⟩
def truncated : Failure := ⟨1, 3⟩

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
  | .readCounter space key, state => reply state ("counter:" ++ space) fun state =>
      (.ok (counter state (space, key)), state)
  | .readBytes space key, state => reply state ("bytes:" ++ space) fun state =>
      (.ok (lookupFile state.files (space, key)), state)
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
  | .release token, state => reply state "release" (fun state =>
      match (state.leases.find? fun entry => entry.1 == token).map Prod.snd with
      | none => (.error invalid, state)
      | some key =>
          let next := setCounter state key ((counter state key).toNat - 1).toUInt64
          (.ok (), { next with leases := state.leases.filter (fun entry => entry.1 != token) })) true

def crypto : Crypto A → State → Result A
  | .validateEd25519 bytes, state => reply state "crypto" fun state => (.ok (state.validateKey bytes), state)

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
      if state.decodeSlice root size spans input then
        (.ok (), { state with files := writeFile state.files ("cas_payload", root) ByteArray.empty })
      else (.error invalid, state)
  | .flushObject root, state => reply state "bao:flush" fun state =>
      (.ok (), { state with synced := ("cas_payload", root) :: state.synced })
  | .trimObject _ _, state => reply state "bao:trim" fun state => (.ok (), state)
  | .writeProof root size spans level input, state => reply state "bao:writeProof" fun state =>
      match state.proven root size spans level input with
      | none => (.error invalid, state)
      | some answer => (.ok answer, state)
  | .promoteRun donor root size start groups cv, state => reply state "bao:promoteRun" fun state =>
      (.ok (state.agrees donor root size start groups cv), state)

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
instance : Interpreter Bao := ⟨bao⟩
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
