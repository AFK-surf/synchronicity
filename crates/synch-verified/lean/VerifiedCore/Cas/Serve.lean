import VerifiedCore.Cas.ReadCodec
import VerifiedCore.Host.Access
import VerifiedCore.Host.Bao

/-! Serving an object to a peer: which groups of what was asked for this node
verifiably holds, clamped to one exchange's window, and what an over-budget
proof request means. The Bao encoding itself is the host's; the program only
ever names groups the row's own record covers. -/
namespace VerifiedCore.Cas.Serve

open Host

inductive Error where
  | host (failure : Failure)
  | missingBlob
  | malformed
  | columnType (index : Nat) (column : String) (actual : Codec.CellType)
  | column (column : String) (reason : String)
  /-- The proof over these ranges at this level does not fit the node
  budget: refused whole, never served in part. -/
  | overBudget (level budget : UInt64)
  | protocol
  deriving BEq, DecidableEq

abbrev Effects := EffectSum Access Bao
abbrev Action (A : Type) := OperationOver Effects Error A

def access (effect : Access (Reply A)) : Action A := raise Error.host effect
def bao (effect : Bao (Reply A)) : Action A := raise Error.host effect

/-- A provider serves at most this many groups per exchange, whatever was
asked for: the encoding travels in one frame, and the requester's next
window starts where the served ranges say this one stopped. -/
def maxSliceGroups : Nat := 512

def translate : Read.Error → Error
  | .host failure => .host failure
  | .missingBlob => .missingBlob
  | .malformed => .malformed
  | .columnType index column actual => .columnType index column actual
  | .column column reason => .column column reason
  | .range _ _ _ | .unavailable | .shortInline => .malformed
  | .protocol => .protocol

/-- The row, read through the same raw statement and decoder as a local read. -/
def metadata (root : ByteArray) : Action Read.Metadata := do
  let scan ← access (.snapshot ⟨"blobs", [("root", .blob root)], [], []⟩
    ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"])
  match scan.rows with
  | row :: _ => ExceptT.mk (.pure ((Read.decodeRow row).mapError translate))
  | [] => match scan.failure with
    | some failure => throw (.host failure)
    | none => throw .missingBlob

/-- The groups the row verifiably holds locally: every group when complete,
otherwise the bitmap's spans, clamped to the object. A durable claim is not
local availability. -/
def held (row : Read.Metadata) : List GroupSpan :=
  if row.complete then [⟨0, (groupCount row.size).toNat⟩]
  else match row.bitmap with
    | none => []
    | some bytes => Read.decodeBitmap bytes (groupCount row.size)

def overlap (left right : GroupSpan) : Option GroupSpan :=
  let start := max left.start right.start
  let stop := min left.stop right.stop
  if start < stop then some ⟨start, stop⟩ else none

/-- Every group of both lists. Runs are few on both sides: the request is
bounded by the wire and the row by its own bitmap. -/
def intersect (left right : List GroupSpan) : List GroupSpan :=
  left.flatMap fun span => right.filterMap (overlap span)

/-- The first `budget` groups, in order; a run is cut where the budget ends. -/
def takeGroups : Nat → List GroupSpan → List GroupSpan
  | _, [] => []
  | 0, _ => []
  | budget, span :: rest =>
    let length := span.stop - span.start
    if length ≤ budget then span :: takeGroups (budget - length) rest
    else [⟨span.start, span.start + budget⟩]

/-- What was asked for, that the row holds, within the object: sorted,
disjoint, clamped. -/
def wanted (row : Read.Metadata) (requested : List GroupSpan) : List GroupSpan :=
  normalizeSpans (groupCount row.size).toNat (intersect requested (held row))

def spansOf (requested : List (UInt64 × UInt64)) : List GroupSpan :=
  requested.map fun (start, stop) => ⟨start.toNat, stop.toNat⟩

def pairsOf (spans : List GroupSpan) : List (UInt64 × UInt64) :=
  spans.map fun span => (span.start.toUInt64, span.stop.toUInt64)

/-- What one exchange serves: the byte count appended to the output and the
group spans it covers, which is what `SliceEnd` and `ProofEnd` carry. -/
structure Served where
  count : UInt64
  spans : List (UInt64 × UInt64)
  deriving BEq, DecidableEq

/-- Encode a slice of the requested groups: the intersection with what the
row holds, within the object, the first `maxSliceGroups` of it. An empty
window is served as no bytes before the host is asked for anything. -/
def encodeSlice (root : ByteArray) (requested : List (UInt64 × UInt64)) : Action Served := do
  let row ← metadata root
  let window := takeGroups maxSliceGroups (wanted row (spansOf requested))
  if window.isEmpty then return ⟨0, []⟩
  let count ← bao (.encodeSlice root row.size row.inline (pairsOf window))
  return ⟨count, pairsOf window⟩

/-- Encode the interior tree over the requested groups the row holds, no
deeper than `level`, within `budget` nodes. A single-group object has no
interior nodes and nothing to prove beyond its root. An answer the budget
cannot hold is refused whole: the requester sizes its windows so that a
provider holding everything it asked for fits, and this walk covers no more
than that. -/
def encodeProof (root : ByteArray) (requested : List (UInt64 × UInt64)) (level budget : UInt64) :
    Action Served := do
  let row ← metadata root
  let window := wanted row (spansOf requested)
  if window.isEmpty || groupCount row.size ≤ 1 then return ⟨0, pairsOf window⟩
  match ← bao (.encodeProof root row.size (pairsOf window) level budget) with
  | some count => return ⟨count, pairsOf window⟩
  | none => throw (.overBudget level budget)

end VerifiedCore.Cas.Serve
