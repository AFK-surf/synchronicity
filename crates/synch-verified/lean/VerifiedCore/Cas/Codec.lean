import VerifiedCore.Host
import VerifiedCore.Cas

/-! Shared stored CAS codecs. Column-error construction belongs to each
operation; this module knows neither read admission nor ingestion policy. -/
namespace VerifiedCore.Cas.Codec
open Host

inductive CellType where
  | null | integer | real | text | blob
  deriving BEq, DecidableEq

def cellType : Cell → CellType
  | .null => .null
  | .integer _ => .integer
  | .real _ => .real
  | .text _ | .rawText _ => .text
  | .blob _ => .blob

def integerField (mismatch : CellType → ε) : Cell → Except ε Int64
  | .integer value => .ok value
  | value => .error (mismatch (cellType value))

def blobField (mismatch : CellType → ε) : Cell → Except ε ByteArray
  | .blob value => .ok value
  | value => .error (mismatch (cellType value))

def optionalBlobField (mismatch : CellType → ε) : Cell → Except ε (Option ByteArray)
  | .null => .ok none
  | .blob value => .ok (some value)
  | value => .error (mismatch (cellType value))

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

/-- Decode local postcard Vec<(u64,u64)> without interpreting row size or
completeness. Trailing bytes and non-minimal integers retain their established
acceptance behavior; malformed input yields no spans. -/
def decodeRawBitmap (input : ByteArray) : List GroupSpan :=
  match bitmap.run ⟨input, 0⟩ with
  | .error _ => []
  | .ok (spans, _) => spans

/-- Minimal LEB128, the encoding postcard writes for a u64. -/
def encodeUnsignedWith : Nat → Nat → List UInt8
  | 0, n => [UInt8.ofNat n]
  | fuel + 1, n =>
    if n < 128 then [UInt8.ofNat n]
    else UInt8.ofNat (n % 128 + 128) :: encodeUnsignedWith fuel (n / 128)

/-- The value itself bounds its own group count, so the recursion is
structural and proofs evaluate it by `decide`. -/
def encodeUnsigned (n : Nat) : List UInt8 := encodeUnsignedWith n n

/-- Encode spans as the local postcard Vec<(u64,u64)>: a count, then each
span's endpoints. The inverse of `decodeRawBitmap` on what the plan produces. -/
def encodeRawBitmap (spans : List GroupSpan) : ByteArray :=
  ⟨(encodeUnsigned spans.length ++
    spans.flatMap (fun span => encodeUnsigned span.start ++ encodeUnsigned span.stop)).toArray⟩

end VerifiedCore.Cas.Codec
