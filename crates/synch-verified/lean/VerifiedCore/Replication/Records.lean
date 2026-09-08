import VerifiedCore.Postcard
import VerifiedCore.Host

/-! Published record decoding. Trailing bytes retain postcard's compatibility
behavior; schema versions and enum tags are checked before materialization.
Span retention is bounded during decoding, including oversized advertisements. -/
namespace VerifiedCore.Replication.Records
open Host
abbrev Decoder := StateT (ByteArray × Nat) (Except String)
def byte : Decoder UInt8 := fun (input, offset) =>
  match input[offset]? with
  | none => .error "unexpected end of record"
  | some value => .ok (value, (input, offset + 1))
/-- Reuse the shared bounded varint parser on at most ten octets. Large record
values never become linked lists merely to read their metadata. -/
def uint : Decoder Nat := fun (input, offset) => do
  let octets := input.extract offset (min input.size (offset + 10))
  let (value, rest) ← Postcard.parseLength octets.toList
  return (value, (input, offset + octets.size - rest.length))
def sint : Decoder Int64 := do
  let n ← uint
  return Int64.ofInt (if n % 2 == 0 then Int.ofNat (n / 2) else -(Int.ofNat (n / 2)) - 1)
def bytes (count : Nat) : Decoder ByteArray := fun (input, offset) =>
  if count > input.size - offset then .error "unexpected end of record"
  else .ok (input.extract offset (offset + count), (input, offset + count))
def remaining : Decoder Nat := do
  let (input, offset) ← get
  return input.size - offset
def string : Decoder String := do
  let raw ← bytes (← uint)
  match String.fromUTF8? raw with
  | some text => return text
  | none => throw "invalid UTF-8"
def optional (decode : Decoder A) : Decoder (Option A) := do
  match ← byte with
  | 0 => return none
  | 1 => return some (← decode)
  | _ => throw "invalid option tag"
def nullable (encode : A → Cell) (value : Option A) : Cell := value.map encode |>.getD .null
def version : Decoder Unit := do
  let v ← byte
  if v > 1 then throw s!"record is schema version {v}, past the 1 this build reads"

structure File where
  fields : Fields
  content : Option ByteArray
  size : Nat
  prev : Option ByteArray

def file : Decoder File := do
  version
  let kind ← uint
  if kind > 4 then throw "unknown entry kind"
  let size ← uint
  let mtime ← sint
  let mode ← optional uint
  if mode.any (· > 4294967295) then throw "mode overflow"
  let content ← optional (bytes 32)
  if (← uint) != 0 then throw "unknown chunk format"
  let _ ← byte
  let seq ← uint
  let prev ← optional (bytes 32)
  let target ← optional string
  return ⟨[("kind", .integer kind.toInt64), ("size", .integer size.toUInt64.toInt64),
    ("mtime_ns", .integer mtime), ("unix_mode", nullable (fun n => .integer n.toInt64) mode),
    ("content", nullable .blob content), ("seq", .integer seq.toUInt64.toInt64),
    ("prev", nullable .blob prev), ("symlink_target", nullable .text target)], content, size, prev⟩

def pairs : Nat → Nat → List (Nat × Nat) → Decoder (List (Nat × Nat))
  | 0, _, acc => pure acc.reverse
  | n + 1, retained, acc => do
    let a ← uint
    let b ← uint
    pairs n (retained + 1) (if retained < 1024 then (a, b) :: acc else acc)

def blob : Decoder Fields := do
  version
  let size ← uint
  let count ← uint
  if count > (← remaining) / 2 then throw "impossible span count"
  let spans ← pairs count 0 []
  let complete := size == 0 || match spans with | [(0, stop)] => stop ≥ size | _ => false
  return [("size", .integer size.toUInt64.toInt64), ("complete", .integer (if complete then 1 else 0)),
    ("spans", .blob ⟨(Postcard.encodePairList spans).toArray⟩)]

def control (c : Char) : Bool := c.toNat < 32 || (127 ≤ c.toNat && c.toNat ≤ 159)
def validSpace (text : String) : Bool :=
  !text.isEmpty && text.utf8ByteSize ≤ 63 && !text.contains '/' && !text.toList.any control

def strings : Nat → List String → Decoder (List String)
  | 0, acc => pure acc.reverse
  | n + 1, acc => do strings n ((← string) :: acc)

def delegation : Decoder Fields := do
  version
  let count ← uint
  if count == 0 || count > 32 then throw "invalid delegation space count"
  let spaces ← strings count []
  if !spaces.all validSpace || spaces.eraseDups.length != spaces.length then
    throw "invalid delegation spaces"
  let expires ← sint
  let note ← optional string
  return [("spaces", .text (String.intercalate "\n" spaces)),
    ("expires_at", .integer expires), ("note", nullable .text note)]

/-- NFC is checked separately by a primitive Unicode service. All path and
space admission decisions remain here, before any entry write. -/
def fileKey (key : ByteArray) : Option (String × String) := do
  let text ← String.fromUTF8? key
  if !(text.startsWith "f:") then none else do
    let parts := (text.drop 2).toString.splitOn "/"
    let space ← parts.head?
    let path := String.intercalate "/" parts.tail
    if !validSpace space || path.isEmpty || path.utf8ByteSize > 4096 ||
        path.toList.any control || parts.tail.any (fun p => p.isEmpty || p == "." || p == "..") then none
    else some (space, path)

end VerifiedCore.Replication.Records
