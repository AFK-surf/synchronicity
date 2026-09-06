import VerifiedCore.Host
import VerifiedCore.Crypto
import VerifiedCore.Host.Access
import VerifiedCore.Host.Write
import VerifiedCore.Host.Hash
import VerifiedCore.Host.Upsert
import VerifiedCore.Host.Resources
import VerifiedCore.Host.Source

/-! Private versioned transport for raw host effects, not domain snapshots.
All lengths and integers are little-endian u64; replies must match the pending
effect tag and consume the entire input. No host continuation is accepted. -/
namespace VerifiedCore.Host.Wire

def octet (n : UInt8) : ByteArray := ⟨#[n]⟩

def word (n : UInt64) : ByteArray :=
  let out := ByteArray.emptyWithCapacity 8
  let out := out.push (n >>> 0).toUInt8
  let out := out.push (n >>> 8).toUInt8
  let out := out.push (n >>> 16).toUInt8
  let out := out.push (n >>> 24).toUInt8
  let out := out.push (n >>> 32).toUInt8
  let out := out.push (n >>> 40).toUInt8
  let out := out.push (n >>> 48).toUInt8
  out.push (n >>> 56).toUInt8

def bytes (b : ByteArray) : ByteArray := word b.size.toUInt64 ++ b

/-- Append a length-prefixed field directly to its packet accumulator, so
large fields do not first allocate a separate length-plus-payload buffer. -/
def appendBytes (out b : ByteArray) : ByteArray := (out ++ word b.size.toUInt64) ++ b

def string (s : String) : ByteArray := bytes s.toUTF8
def sequence (encode : A → ByteArray) (items : List A) : ByteArray :=
  items.foldl (fun out item => out ++ encode item) (word items.length.toUInt64)

def cell : Cell → ByteArray
  | .null => octet 0
  | .integer n => octet 1 ++ word n.toUInt64
  | .text s => octet 2 ++ string s
  | .blob b => octet 3 ++ bytes b
  | .real bits => octet 4 ++ word bits
  | .rawText b => octet 5 ++ bytes b

def fields (values : Fields) : ByteArray :=
  sequence (fun (name, value) => string name ++ cell value) values

def ordering (orders : List Order) : ByteArray :=
  sequence (fun order => string order.column ++ octet (if order.descending then 1 else 0)) orders

def exclusions (guards : List Exclusion) : ByteArray :=
  sequence (fun guard => string guard.relation ++ fields guard.equals ++
    sequence (fun (left, right) => string left ++ string right) guard.keys) guards

def joins (items : List Join) : ByteArray :=
  sequence (fun item => string item.relation ++
    sequence (fun (left, right) => string left ++ string right) item.keys) items

def failure (f : Failure) : ByteArray := word f.code.toUInt64 ++ word f.token

def tag : Storage A → UInt8
  | .begin => 16
  | .commit _ => 17
  | .rollback _ => 18
  | .readRows .. => 19
  | .upsert .. => 20
  | .deleteRows .. => 21
  | .readBytes .. => 22
  | .readInput .. => 23
  | .readCounter .. => 24
  | .removeFile .. => 25
  | .existsRows .. => 26
  | .scanRows .. => 28

def request (effect : Storage A) : ByteArray := octet 1 ++ octet (tag effect) ++
  match effect with
  | .begin => .empty
  | .commit tx | .rollback tx => word tx
  | .readRows tx table columns equals order joined =>
    word tx ++ string table ++ sequence string columns ++ fields equals ++ ordering order ++ joins joined
  | .scanRows tx table columns equals order joined =>
    word tx ++ string table ++ sequence string columns ++ fields equals ++ ordering order ++ joins joined
  | .upsert tx table values conflict updates =>
    word tx ++ string table ++ fields values ++ sequence string conflict ++ sequence string updates
  | .deleteRows tx table equals blockers atMost =>
    word tx ++ string table ++ fields equals ++ exclusions blockers ++ fields atMost
  | .readBytes space key => string space ++ bytes key
  | .readInput handle offset count => word handle ++ word offset ++ word count
  | .readCounter space key | .removeFile space key => string space ++ bytes key
  | .existsRows tx table equals => word tx ++ string table ++ fields equals

structure Cursor where
  input : ByteArray
  offset : Nat := 0

abbrev Reader := StateT Cursor (Except Unit)

def readByte : Reader UInt8 := do
  let c ← get
  if h : c.offset < c.input.size then
    set { c with offset := c.offset + 1 }
    return c.input[c.offset]
  else throw ()

def readWord : Reader UInt64 := do
  let cursor ← get
  if cursor.offset + 8 > cursor.input.size then throw ()
  set { cursor with offset := cursor.offset + 8 }
  -- One bounds check/state transition for the fixed-width field. In addition
  -- to avoiding repeated host-buffer checks, this keeps kernel reduction from
  -- expanding eight nested state-monad continuations for every integer.
  return (List.range 8).foldl (fun acc i =>
    acc ||| (((cursor.input[cursor.offset + i]?).getD 0).toUInt64 <<<
      (i * 8).toUInt64)) 0

def readBytes : Reader ByteArray := do
  let count := (← readWord).toNat
  let c ← get
  if c.offset + count > c.input.size then throw ()
  set { c with offset := c.offset + count }
  if count == 0 then return .empty
  return c.input.extract c.offset (c.offset + count)

def readString : Reader String := do
  let encoded ← readBytes
  if encoded.size == 0 then return ""
  match String.fromUTF8? encoded with
  | none => throw ()
  | some value => return value

def readListAux (read : Reader A) : Nat → Reader (List A)
  | 0 => pure []
  | n + 1 => do
    let item ← read
    return item :: (← readListAux read n)

/-- Every transported list item occupies at least one byte. Reject impossible
counts before recursion/allocation, including hostile u64 length fields. -/
def readList (read : Reader A) : Reader (List A) := do
  let count := (← readWord).toNat
  let c ← get
  if count > c.input.size - c.offset then throw ()
  readListAux read count

def readCell : Reader Cell := do
  match ← readByte with
  | 0 => return .null
  | 1 => return .integer (← readWord).toInt64
  | 2 => return .text (← readString)
  | 3 => return .blob (← readBytes)
  | 4 => return .real (← readWord)
  | 5 => return .rawText (← readBytes)
  | _ => throw ()

def readFailure : Reader Failure := do
  let code ← readWord
  if code > 0xffffffff then throw ()
  return ⟨code.toUInt32, ← readWord⟩

def readReply (expected : UInt8) (read : Reader A) : Reader (Reply A) := do
  if (← readByte) != 1 then throw ()
  let kind ← readByte
  if kind == 0 then return .error (← readFailure)
  if kind != expected then throw ()
  return .ok (← read)

def protocolFailure : Failure := ⟨3, 0⟩

def decodeReply (expected : UInt8) (read : Reader A) (input : ByteArray) : Reply A :=
  match (readReply expected read).run ⟨input, 0⟩ with
  | .error () => .error protocolFailure
  | .ok (reply, cursor) =>
    if cursor.offset == input.size then reply else .error protocolFailure

def reply (effect : Storage A) (input : ByteArray) : A :=
  match effect with
  | .begin => decodeReply 16 readWord input
  | .commit _ => decodeReply 17 (pure ()) input
  | .rollback _ => decodeReply 18 (pure ()) input
  | .readRows .. => decodeReply 19 (readList (readList readCell)) input
  | .scanRows .. => decodeReply 28 (do
      let rows ← readList (readList readCell)
      let failed ← readByte
      match failed with
      | 0 => return ⟨rows, none⟩
      | 1 => return ⟨rows, some (← readFailure)⟩
      | _ => throw ()) input
  | .upsert .. => decodeReply 20 (pure ()) input
  | .deleteRows .. => decodeReply 21 (do return (← readWord).toNat) input
  | .readBytes .. => decodeReply 22 (do
      match ← readByte with
      | 0 => return none
      | 1 => return some (← readBytes)
      | _ => throw ()) input
  | .readInput .. => decodeReply 23 readBytes input
  | .readCounter .. => decodeReply 24 readWord input
  | .removeFile .. => decodeReply 25 (pure ()) input
  | .existsRows .. => decodeReply 26 (do
      match ← readByte with
      | 0 => return false
      | 1 => return true
      | _ => throw ()) input

abbrev State := Program Storage (Reply ByteArray)

def packet : State → ByteArray
  | .pure (.ok result) => octet 1 ++ octet 0 ++ bytes result
  | .pure (.error error) => octet 1 ++ octet 1 ++ failure error
  | .request effect _ => request effect

/-- Invalid host packets become a failure reply to the *pending* operation,
so its verified rollback continuation still runs. Terminal states cannot resume. -/
def resume (state : State) (input : ByteArray) : State :=
  match state with
  | .pure _ => .pure (.error protocolFailure)
  | .request effect next => next (reply effect input)

/-- One native continuation transport, with storage and crypto kept as distinct
typed capabilities. Existing storage packets retain their exact representation. -/
abbrev WriteEffects := EffectSum ByteWriter (EffectSum Blake3
  (EffectSum Upsert (EffectSum Resources (EffectSum Lease SourceIO))))
abbrev NativeEffects := EffectSum Storage (EffectSum Crypto
  (EffectSum Access (EffectSum FileIO (EffectSum Clock (EffectSum Output WriteEffects)))))
abbrev NativeState := Program NativeEffects (Reply ByteArray)

def cryptoRequest : Crypto A → ByteArray
  | .validateEd25519 key => octet 1 ++ octet 27 ++ bytes ⟨key.toArray⟩

def cryptoReply (effect : Crypto A) (input : ByteArray) : A :=
  match effect with
  | .validateEd25519 _ => decodeReply 27 (do
      match ← readByte with
      | 0 => return false
      | 1 => return true
      | _ => throw ()) input

def selection (selected : Selection) : ByteArray :=
  string selected.relation ++ fields selected.equals ++
    sequence (fun (column, pattern) => string column ++ string pattern) selected.likeAny

def sourceValue : SourceValue → ByteArray
  | .literal value => octet 0 ++ cell value
  | .column name => octet 1 ++ string name

def accessRequest : Access A → ByteArray
  | .snapshot selected columns => octet 1 ++ octet 29 ++ selection selected ++ sequence string columns
  | .update tx selected values => octet 1 ++ octet 30 ++ word tx ++ selection selected ++ fields values
  | .copyRows tx target source values conflicts => octet 1 ++ octet 31 ++ word tx ++
      string target ++ selection source ++
      sequence (fun (name, value) => string name ++ sourceValue value) values ++ sequence string conflicts
  | .delete tx selected => octet 1 ++ octet 32 ++ word tx ++ selection selected

def accessReply (effect : Access A) (input : ByteArray) : A :=
  match effect with
  | .snapshot .. => decodeReply 29 (do
      let rows ← readList (readList readCell)
      match ← readByte with
      | 0 => return ⟨rows, none⟩
      | 1 => return ⟨rows, some (← readFailure)⟩
      | _ => throw ()) input
  | .update .. => decodeReply 30 (do return (← readWord).toNat) input
  | .copyRows .. => decodeReply 31 (do return (← readWord).toNat) input
  | .delete .. => decodeReply 32 (do return (← readWord).toNat) input

def fileRequest : FileIO A → ByteArray
  | .open space key => octet 1 ++ octet 33 ++ string space ++ bytes key
  | .readAt handle offset count => octet 1 ++ octet 34 ++ word handle ++ word offset ++ word count
  | .close handle => octet 1 ++ octet 35 ++ word handle

def readFileReply (expected : UInt8) (read : Reader A) : Reader (FileReply A) := do
  if (← readByte) != 1 then throw ()
  let kind ← readByte
  if kind == 0 then
    let failure ← readFailure
    let classification ← readByte
    let kind ← match classification with
      | 0 => pure FileFailureKind.missing
      | 1 => pure FileFailureKind.shortRead
      | 2 => pure FileFailureKind.other
      | _ => throw ()
    return .error ⟨failure, kind⟩
  if kind != expected then throw ()
  return .ok (← read)

def decodeFileReply (expected : UInt8) (read : Reader A) (input : ByteArray) : FileReply A :=
  match (readFileReply expected read).run ⟨input, 0⟩ with
  | .error () => .error ⟨protocolFailure, .other⟩
  | .ok (result, cursor) =>
    if cursor.offset == input.size then result else .error ⟨protocolFailure, .other⟩

def fileReply (effect : FileIO A) (input : ByteArray) : A :=
  match effect with
  | .open .. => decodeFileReply 33 readWord input
  | .readAt .. => decodeFileReply 34 readBytes input
  | .close .. => decodeReply 35 (pure ()) input

def clockRequest : Clock A → ByteArray
  | .nowNs => octet 1 ++ octet 36

def clockReply (effect : Clock A) (input : ByteArray) : A :=
  match effect with
  | .nowNs => decodeReply 36 (do return (← readWord).toInt64) input

def outputRequest : Output A → ByteArray
  | .append chunk => octet 1 ++ octet 37 ++ bytes chunk

def outputReply (effect : Output A) (input : ByteArray) : A :=
  match effect with
  | .append _ => decodeReply 37 (pure ()) input

def writerRequest : ByteWriter A → ByteArray
  | .writeAt handle offset chunk =>
      appendBytes (octet 1 ++ octet 38 ++ word handle ++ word offset) chunk

def writerReply (effect : ByteWriter A) (input : ByteArray) : A :=
  match effect with
  | .writeAt .. => decodeReply 38 (pure ()) input

def blake3Request : Blake3 A → ByteArray
  | .chunk counter root chunk =>
      appendBytes (octet 1 ++ octet 39 ++ word counter ++ octet (if root then 1 else 0)) chunk
  | .parent root left right =>
      appendBytes (appendBytes (octet 1 ++ octet 40 ++ octet (if root then 1 else 0)) left) right

def blake3Reply (effect : Blake3 A) (input : ByteArray) : A :=
  match effect with
  | .chunk .. => decodeReply 39 readBytes input
  | .parent .. => decodeReply 40 readBytes input

def conflictValue : ConflictValue → ByteArray
  | .current column => octet 0 ++ string column
  | .excluded column => octet 1 ++ string column
  | .coalesce left right => octet 2 ++ conflictValue left ++ conflictValue right
  | .max left right => octet 3 ++ conflictValue left ++ conflictValue right

def upsertRequest : Upsert A → ByteArray
  | .write tx relation values conflicts assignments =>
    octet 1 ++ octet 41 ++ word tx ++ string relation ++ fields values ++
      sequence string conflicts ++ sequence (fun (column, value) =>
        string column ++ conflictValue value) assignments

def upsertReply (effect : Upsert A) (input : ByteArray) : A :=
  match effect with
  | .write .. => decodeReply 41 (pure ()) input

def resourcesRequest : Resources A → ByteArray
  | .createTemporary space => octet 1 ++ octet 42 ++ string space
  | .flush handle => octet 1 ++ octet 43 ++ word handle
  | .replace handle space key => octet 1 ++ octet 44 ++ word handle ++ string space ++ bytes key
  | .discard handle => octet 1 ++ octet 45 ++ word handle
  | .syncParent space key => octet 1 ++ octet 46 ++ string space ++ bytes key

def resourcesReply (effect : Resources A) (input : ByteArray) : A :=
  match effect with
  | .createTemporary .. => decodeReply 42 readWord input
  | .flush .. => decodeReply 43 (pure ()) input
  | .replace .. => decodeReply 44 (pure ()) input
  | .discard .. => decodeReply 45 (pure ()) input
  | .syncParent .. => decodeReply 46 (do
      match ← readByte with
      | 0 => return SyncStatus.synced
      | 1 => return SyncStatus.unsupported
      | _ => throw ()) input

def leaseRequest : Lease A → ByteArray
  | .acquire space key => octet 1 ++ octet 47 ++ string space ++ bytes key
  | .release token => octet 1 ++ octet 48 ++ word token

def leaseReply (effect : Lease A) (input : ByteArray) : A :=
  match effect with
  | .acquire .. => decodeReply 47 readWord input
  | .release .. => decodeReply 48 (pure ()) input

def sourceRequest : SourceIO A → ByteArray
  | .stat space key => octet 1 ++ octet 49 ++ string space ++ bytes key
  | .readSome handle offset count => octet 1 ++ octet 50 ++ word handle ++ word offset ++ word count
  | .freeze chunk => octet 1 ++ octet 51 ++ bytes chunk

def sourceReply (effect : SourceIO A) (input : ByteArray) : A :=
  match effect with
  | .stat .. => decodeReply 49 readWord input
  | .readSome .. => decodeReply 50 readBytes input
  | .freeze .. => decodeReply 51 readWord input

def writeRequest (effect : WriteEffects A) : ByteArray :=
  match effect with
  | .left writer => writerRequest writer
  | .right effect => match effect with
    | .left blake3 => blake3Request blake3
    | .right effect => match effect with
      | .left upsert => upsertRequest upsert
      | .right effect => match effect with
        | .left resources => resourcesRequest resources
        | .right effect => match effect with
          | .left lease => leaseRequest lease
          | .right source => sourceRequest source

def writeReply (effect : WriteEffects A) (input : ByteArray) : A :=
  match effect with
  | .left writer => writerReply writer input
  | .right effect => match effect with
    | .left blake3 => blake3Reply blake3 input
    | .right effect => match effect with
      | .left upsert => upsertReply upsert input
      | .right effect => match effect with
        | .left resources => resourcesReply resources input
        | .right effect => match effect with
          | .left lease => leaseReply lease input
          | .right source => sourceReply source input

def nativeRequest (effect : NativeEffects A) : ByteArray :=
  match effect with
  | .left storage => request storage
  | .right effect => match effect with
    | .left crypto => cryptoRequest crypto
    | .right effect => match effect with
      | .left access => accessRequest access
      | .right effect => match effect with
        | .left file => fileRequest file
        | .right effect => match effect with
          | .left clock => clockRequest clock
          | .right effect => match effect with
            | .left output => outputRequest output
            | .right writer => writeRequest writer

def nativeReply (effect : NativeEffects A) (input : ByteArray) : A :=
  match effect with
  | .left storage => reply storage input
  | .right effect => match effect with
    | .left crypto => cryptoReply crypto input
    | .right effect => match effect with
      | .left access => accessReply access input
      | .right effect => match effect with
        | .left file => fileReply file input
        | .right effect => match effect with
          | .left clock => clockReply clock input
          | .right effect => match effect with
            | .left output => outputReply output input
            | .right writer => writeReply writer input

@[export synch_lean_operation_packet]
def nativePacket : NativeState → ByteArray
  | .pure (.ok result) => octet 1 ++ octet 0 ++ bytes result
  | .pure (.error error) => octet 1 ++ octet 1 ++ failure error
  | .request effect _ => nativeRequest effect

@[export synch_lean_operation_resume]
def nativeResume (state : NativeState) (input : ByteArray) : NativeState :=
  match state with
  | .pure _ => .pure (.error protocolFailure)
  | .request effect next => next (nativeReply effect input)

end VerifiedCore.Host.Wire
