import VerifiedCore.Host
import VerifiedCore.Cas
import VerifiedCore.Postcard

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

/-- Decode local postcard Vec<(u64,u64)> without interpreting row size or
completeness. Trailing bytes and non-minimal integers retain their established
acceptance behavior; malformed input yields no spans. -/
def decodeRawBitmap (input : ByteArray) : List GroupSpan :=
  match Postcard.parsePairList input.data.toList with
  | .error _ => []
  | .ok (spans, _) => spans.map fun (start, stop) => ⟨start, stop⟩

abbrev encodeUnsigned := Postcard.leb128

/-- Encode spans with the same bounded unsigned postcard representation used
by the decoder. The inverse law is checked for representable vectors. -/
def encodeRawBitmap (spans : List GroupSpan) : ByteArray :=
  ⟨(Postcard.encodePairList (spans.map fun span => (span.start, span.stop))).toArray⟩

end VerifiedCore.Cas.Codec
