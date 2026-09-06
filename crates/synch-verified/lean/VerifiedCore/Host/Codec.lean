import VerifiedCore.Host
import VerifiedCore.Host.Access
import VerifiedCore.Host.Upsert
import VerifiedCore.Host.Resources

/-! The private versioned transport's primitives: how each raw type is written
into a request packet and read back out of a reply. All lengths and integers
are little-endian u64. The per-effect request encoders and reply decoders are
generated from the effect algebras themselves (`Host/Generated.lean`, by
`hostgen`); nothing here names an effect. -/
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

def failure (f : Failure) : ByteArray := word f.code.toUInt64 ++ word f.token

/-- The first two bytes of every request: the transport version and the
effect's tag. -/
def header (tag : UInt8) : ByteArray := octet 1 ++ octet tag

/-- How a request argument is appended to the packet being built. -/
class Encode (A : Type) where
  encode : ByteArray → A → ByteArray

/-- Append one field to a packet under construction. -/
def _root_.ByteArray.put [Encode A] (out : ByteArray) (value : A) : ByteArray :=
  Encode.encode out value

instance : Encode UInt64 := ⟨fun out n => out ++ word n⟩
instance : Encode Nat := ⟨fun out n => out ++ word n.toUInt64⟩
instance : Encode Int64 := ⟨fun out n => out ++ word n.toUInt64⟩
instance : Encode Unit := ⟨fun out () => out⟩
instance : Encode ByteArray := ⟨appendBytes⟩
instance : Encode String := ⟨fun out s => appendBytes out s.toUTF8⟩
instance : Encode Bool := ⟨fun out b => out.push (if b then 1 else 0)⟩
instance [Encode A] : Encode (List A) :=
  ⟨fun out items => items.foldl Encode.encode (out ++ word items.length.toUInt64)⟩
/-- Raw key bytes travel as one length-prefixed field, not as a list of octets. -/
instance : Encode (List UInt8) := ⟨fun out key => appendBytes out ⟨key.toArray⟩⟩
instance [Encode A] [Encode B] : Encode (A × B) :=
  ⟨fun out (a, b) => Encode.encode (Encode.encode out a) b⟩
instance [Encode A] : Encode (Option A) where
  encode out
    | none => out.push 0
    | some value => Encode.encode (out.push 1) value
/-- A finished command: its value, or the domain error that ended it. -/
instance [Encode E] [Encode A] : Encode (Except E A) where
  encode out
    | .ok value => Encode.encode (out.push 0) value
    | .error error => Encode.encode (out.push 1) error

/-- The whole terminal payload of a command. -/
def terminal [Encode A] (value : A) : ByteArray := Encode.encode .empty value

def cell : Cell → ByteArray
  | .null => octet 0
  | .integer n => octet 1 ++ word n.toUInt64
  | .text s => octet 2 ++ string s
  | .blob b => octet 3 ++ bytes b
  | .real bits => octet 4 ++ word bits
  | .rawText b => octet 5 ++ bytes b

instance : Encode Cell := ⟨fun out value => out ++ cell value⟩
instance : Encode Order :=
  ⟨fun out order => Encode.encode (Encode.encode out order.column) order.descending⟩
instance : Encode Exclusion :=
  ⟨fun out guard => Encode.encode (Encode.encode (Encode.encode out guard.relation) guard.equals) guard.keys⟩
instance : Encode Join :=
  ⟨fun out item => Encode.encode (Encode.encode out item.relation) item.keys⟩
instance : Encode Selection :=
  ⟨fun out selected => Encode.encode (Encode.encode (Encode.encode (Encode.encode out
    selected.relation) selected.equals) selected.likeAny) selected.notEquals⟩

def sourceValue : SourceValue → ByteArray
  | .literal value => octet 0 ++ cell value
  | .column name => octet 1 ++ string name

instance : Encode SourceValue := ⟨fun out value => out ++ sourceValue value⟩

def conflictValue : ConflictValue → ByteArray
  | .current column => octet 0 ++ string column
  | .excluded column => octet 1 ++ string column
  | .coalesce left right => octet 2 ++ conflictValue left ++ conflictValue right
  | .max left right => octet 3 ++ conflictValue left ++ conflictValue right

instance : Encode ConflictValue := ⟨fun out value => out ++ conflictValue value⟩

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

/-- How a reply payload is read back, once its tag has been checked. -/
class Decode (A : Type) where
  decode : Reader A

instance : Decode UInt64 := ⟨readWord⟩
instance : Decode Nat := ⟨do return (← readWord).toNat⟩
instance : Decode Int64 := ⟨do return (← readWord).toInt64⟩
instance : Decode Unit := ⟨pure ()⟩
instance : Decode ByteArray := ⟨readBytes⟩
instance : Decode Bool := ⟨do
  match ← readByte with
  | 0 => return false
  | 1 => return true
  | _ => throw ()⟩
instance [Decode A] : Decode (Option A) := ⟨do
  match ← readByte with
  | 0 => return none
  | 1 => return some (← Decode.decode)
  | _ => throw ()⟩
instance [Decode A] : Decode (List A) := ⟨readList Decode.decode⟩
instance : Decode String := ⟨readString⟩
instance [Decode A] [Decode B] : Decode (A × B) := ⟨do
  let a ← Decode.decode
  let b ← Decode.decode
  return (a, b)⟩
instance : Decode Cell := ⟨readCell⟩
instance : Decode Scan := ⟨do
  let rows ← readList (readList readCell)
  match ← readByte with
  | 0 => return ⟨rows, none⟩
  | 1 => return ⟨rows, some (← readFailure)⟩
  | _ => throw ()⟩
instance : Decode SyncStatus := ⟨do
  match ← readByte with
  | 0 => return .synced
  | 1 => return .unsupported
  | _ => throw ()⟩

/-- Decode a whole value, refusing trailing bytes. -/
def decodeAll [Decode A] (input : ByteArray) : Option A :=
  match (Decode.decode : Reader A).run ⟨input, 0⟩ with
  | .error () => none
  | .ok (value, cursor) => if cursor.offset == input.size then some value else none

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

/-- An algebra whose every effect has a request packet and a reply decoder.
Instances for the effect algebras are generated; the sum instance composes
them, so a whole operation's algebra is on the wire by construction. -/
class WireEffect (E : Type → Type) where
  request : {A : Type} → E A → ByteArray
  reply : {A : Type} → E A → ByteArray → A

instance [WireEffect L] [WireEffect R] : WireEffect (EffectSum L R) where
  request
    | .left effect => WireEffect.request effect
    | .right effect => WireEffect.request effect
  reply
    | .left effect, input => WireEffect.reply effect input
    | .right effect, input => WireEffect.reply effect input

end VerifiedCore.Host.Wire
