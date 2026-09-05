import VerifiedCore.Host
import VerifiedCore.Cas

/-!
Internal CAS read decoding. Rust supplies raw SQLite cells and bytes only;
neither metadata interpretation nor availability intervals cross the ABI.
-/
namespace VerifiedCore.Cas.Read

open Host

inductive CellType where
  | null | integer | real | text | blob
  deriving BEq, DecidableEq

inductive Error where
  | host (failure : Failure)
  | malformed
  | columnType (index : Nat) (column : String) (actual : CellType)
  | column (column : String) (reason : String)
  | missingBlob
  | range (start stop size : UInt64)
  | unavailable
  | shortInline
  | protocol
  deriving BEq, DecidableEq

structure Metadata where
  size : UInt64
  complete : Bool
  bitmap : Option ByteArray
  inline : Option ByteArray

def cellType : Cell → CellType
  | .null => .null
  | .integer _ => .integer
  | .real _ => .real
  | .text _ | .rawText _ => .text
  | .blob _ => .blob

def integerField (index : Nat) (column : String) : Cell → Except Error Int64
  | .integer value => .ok value
  | value => .error (.columnType index column (cellType value))

def blobField (index : Nat) (column : String) : Cell → Except Error ByteArray
  | .blob value => .ok value
  | value => .error (.columnType index column (cellType value))

def optionalBlobField (index : Nat) (column : String) : Cell → Except Error (Option ByteArray)
  | .null => .ok none
  | .blob value => .ok (some value)
  | value => .error (.columnType index column (cellType value))

/-- Preserve the original row reader's ordered column validation. The omitted
pin EXISTS projection was always an integer; later diagnostics retain its
original column indices. Hash width is checked only after all field types. -/
def decodeRow : Row → Except Error Metadata
  | [root, size, complete, bitmap, inline, lastAccess, durable] => do
    let root ← blobField 0 "root" root
    let size ← integerField 1 "size" size
    let complete ← integerField 2 "complete" complete
    let bitmap ← optionalBlobField 3 "bitmap" bitmap
    let inline ← optionalBlobField 4 "inline" inline
    let _ ← integerField 6 "last_access" lastAccess
    let _ ← integerField 7 "durable" durable
    if root.size != 32 then
      throw (.column "blobs.root" (toString root.size ++ " bytes, not 32"))
    return ⟨size.toUInt64, complete != 0, bitmap, inline⟩
  | _ => .error .malformed

/-- Healing reads only the current size. Negative SQL integers retain their
stored bit representation when the operation converts them to unsigned sizes. -/
def decodeSize : List Row → Except Error (Option Int64)
  | [] => .ok none
  | [[value]] => (integerField 0 "size" value).map some
  | _ => .error .malformed

private structure Cursor where
  input : ByteArray
  offset : Nat := 0

private abbrev Parser := StateT Cursor (Except Unit)

private def byte : Parser UInt8 := do
  let cursor ← get
  if cursor.offset >= cursor.input.size then throw ()
  set { cursor with offset := cursor.offset + 1 }
  return cursor.input.data[cursor.offset]!

/-- Postcard's u64 LEB128 permits non-minimal encodings but rejects an
overflowing tenth octet. At most ten bytes are consumed per integer. -/
private def unsignedAux : Nat → Nat → Nat → Parser Nat
  | 0, _, _ => throw ()
  | fuel + 1, shift, acc => do
    let digit := (← byte).toNat
    if fuel == 0 && digit > 1 then throw ()
    let value := acc + (digit % 128) * 2 ^ shift
    if digit < 128 then return value
    unsignedAux fuel (shift + 7) value

private def unsigned : Parser Nat := unsignedAux 10 0 0

private def pairs : Nat → List GroupSpan → Parser (List GroupSpan)
  | 0, acc => return acc.reverse
  | count + 1, acc => do
    let start ← unsigned
    let stop ← unsigned
    pairs count (⟨start, stop⟩ :: acc)

private def bitmap : Parser (List GroupSpan) := do
  let count ← unsigned
  let cursor ← get
  -- Every pair requires at least two octets. Reject impossible counts before
  -- traversing/allocating from an untrusted serialized length.
  if count > (cursor.input.size - cursor.offset) / 2 then throw ()
  pairs count []

/-- Local postcard Vec<(u64,u64)> decoding ignores trailing bytes, exactly as
the established local format requires. Malformed bytes mean no availability.
Normalization sorts/merges runs; no work is proportional to object size. -/
def decodeBitmap (input : ByteArray) (groups : UInt64) : List GroupSpan :=
  match bitmap.run ⟨input, 0⟩ with
  | .error _ => []
  | .ok (spans, _) => normalizeSpans groups.toNat spans

/-- Coverage of a half-open byte request. Complete cache state overrides any
bitmap; a durable-tier promise does not establish local availability. -/
def covered (metadata : Metadata) (start stop : UInt64) : Bool :=
  if start >= stop then true
  else
    let first := start.toNat / 16384
    let past := (stop.toNat + 16383) / 16384
    let spans := if metadata.complete then [⟨0, (groupCount metadata.size).toNat⟩]
      else match metadata.bitmap with
        | none => []
        | some bytes => decodeBitmap bytes (groupCount metadata.size)
    spans.any fun span => span.start ≤ first && past ≤ span.stop

end VerifiedCore.Cas.Read
