import VerifiedCore.Cas.Codec

/-!
Internal CAS read decoding. Rust supplies raw SQLite cells and bytes only;
neither metadata interpretation nor availability intervals cross the ABI.
-/
namespace VerifiedCore.Cas.Read

open Host

abbrev CellType := Codec.CellType

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

abbrev cellType := Codec.cellType

def integerField (index : Nat) (column : String) : Cell → Except Error Int64 :=
  Codec.integerField (Error.columnType index column)

def blobField (index : Nat) (column : String) : Cell → Except Error ByteArray :=
  Codec.blobField (Error.columnType index column)

def optionalBlobField (index : Nat) (column : String) : Cell → Except Error (Option ByteArray) :=
  Codec.optionalBlobField (Error.columnType index column)

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

/-- Decode the local postcard Vec<(u64,u64)> representation without interpreting
the row's size or completeness. Trailing bytes and non-minimal integers retain
their established acceptance behavior; malformed input yields no spans.
Commit settlement consumes these raw spans before choosing its accepted size. -/
abbrev decodeRawBitmap := Codec.decodeRawBitmap

/-- Local-read availability additionally clamps and normalizes the decoded
spans against the observed size. Work depends on runs, not object size. -/
def decodeBitmap (input : ByteArray) (groups : UInt64) : List GroupSpan :=
  normalizeSpans groups.toNat (decodeRawBitmap input)

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
