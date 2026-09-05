import VerifiedCore.Host

/-! Private versioned transport for raw host effects, not domain snapshots.
All lengths and integers are little-endian u64; replies must match the pending
effect tag and consume the entire input. No host continuation is accepted. -/
namespace VerifiedCore.Host.Wire

def octet (n : UInt8) : ByteArray := ⟨#[n]⟩

def word (n : UInt64) : ByteArray :=
  (List.range 8).foldl (fun out i => out.push (n >>> (i * 8).toUInt64).toUInt8) .empty

def bytes (b : ByteArray) : ByteArray := word b.size.toUInt64 ++ b
def string (s : String) : ByteArray := bytes s.toUTF8
def sequence (encode : A → ByteArray) (items : List A) : ByteArray :=
  items.foldl (fun out item => out ++ encode item) (word items.length.toUInt64)

def cell : Cell → ByteArray
  | .null => octet 0
  | .integer n => octet 1 ++ word n.toUInt64
  | .text s => octet 2 ++ string s
  | .blob b => octet 3 ++ bytes b

def fields (values : Fields) : ByteArray :=
  sequence (fun (name, value) => string name ++ cell value) values

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

def request (effect : Storage A) : ByteArray := octet 1 ++ octet (tag effect) ++
  match effect with
  | .begin => .empty
  | .commit tx | .rollback tx => word tx
  | .readRows tx table columns equals =>
    word tx ++ string table ++ sequence string columns ++ fields equals
  | .upsert tx table values conflict updates =>
    word tx ++ string table ++ fields values ++ sequence string conflict ++ sequence string updates
  | .deleteRows tx table equals => word tx ++ string table ++ fields equals
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

@[export synch_lean_operation_packet]
def packet : State → ByteArray
  | .pure (.ok result) => octet 1 ++ octet 0 ++ bytes result
  | .pure (.error error) => octet 1 ++ octet 1 ++ failure error
  | .request effect _ => request effect

/-- Invalid host packets become a failure reply to the *pending* operation,
so its verified rollback continuation still runs. Terminal states cannot resume. -/
@[export synch_lean_operation_resume]
def resume (state : State) (input : ByteArray) : State :=
  match state with
  | .pure _ => .pure (.error protocolFailure)
  | .request effect next => next (reply effect input)

end VerifiedCore.Host.Wire
