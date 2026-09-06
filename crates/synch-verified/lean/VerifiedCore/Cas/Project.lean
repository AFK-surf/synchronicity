import VerifiedCore.Cas.ReadCodec
import VerifiedCore.Cas.Program

/-! The projections of the content store: one object's row, every row, the
narrow summary a sweep or a report reads, the claims on an object or on
every object, and the pinned roots. Each is one read transaction over raw
rows, decoded by the same validation the read path applies, so a malformed
row is reported the same way everywhere; whether an object is pinned is
read as a join and merged in one pass, never asked row by row. -/
namespace VerifiedCore.Cas.Project

open Host

inductive Error where
  | host (failure : Failure)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Codec.CellType)
  | column (column : String) (reason : String)
  deriving BEq, DecidableEq

abbrev Action (A : Type) := OperationWith Error A

def storage (effect : Storage (Reply A)) : Action A := performWith Error.host effect

def transaction (body : Transaction → Action A) : Action A :=
  transactionWith Error.host body

/-- A row of the local blob index. -/
structure Blob where
  root : ByteArray
  size : UInt64
  complete : Bool
  durable : Bool
  bitmap : Option ByteArray
  inline : Option ByteArray
  pinned : Bool
  lastAccess : Int64
  deriving BEq, DecidableEq

/-- A row without its payload: what a sweep or a report reads. -/
structure Summary where
  root : ByteArray
  size : UInt64
  complete : Bool
  durable : Bool
  pinned : Bool
  lastAccess : Int64
  deriving BEq, DecidableEq

/-- One claim on one object. -/
structure Pin where
  root : ByteArray
  holder : PinHolder
  createdAt : Int64
  releaseAfter : Option Int64
  deriving BEq, DecidableEq

def integerField (index : Nat) (column : String) : Cell → Except Error Int64 :=
  Codec.integerField (Error.columnType index column)

def blobField (index : Nat) (column : String) : Cell → Except Error ByteArray :=
  Codec.blobField (Error.columnType index column)

def optionalBlobField (index : Nat) (column : String) : Cell → Except Error (Option ByteArray) :=
  Codec.optionalBlobField (Error.columnType index column)

/-- A root is a 32-byte digest, checked after the row's field types, as the
read path checks it. -/
def rootField (index : Nat) (column : String) (cell : Cell) : Except Error ByteArray := do
  let root ← blobField index column cell
  if root.size != 32 then throw (.column column (toString root.size ++ " bytes, not 32"))
  return root

def blobColumns : List String :=
  ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"]

/-- The read path's row, kept whole; `pinned` is merged in afterwards. -/
def decodeBlob : Row → Except Error Blob
  | [root, size, complete, bitmap, inline, lastAccess, durable] => do
    let root ← blobField 0 "root" root
    let size ← integerField 1 "size" size
    let complete ← integerField 2 "complete" complete
    let bitmap ← optionalBlobField 3 "bitmap" bitmap
    let inline ← optionalBlobField 4 "inline" inline
    let lastAccess ← integerField 5 "last_access" lastAccess
    let durable ← integerField 6 "durable" durable
    if root.size != 32 then throw (.column "blobs.root" (toString root.size ++ " bytes, not 32"))
    return ⟨root, size.toUInt64, complete != 0, durable != 0, bitmap, inline, false, lastAccess⟩
  | _ => .error .malformed

def summaryColumns : List String := ["root", "size", "complete", "durable", "last_access"]

def decodeSummary : Row → Except Error Summary
  | [root, size, complete, durable, lastAccess] => do
    let root ← blobField 0 "root" root
    let size ← integerField 1 "size" size
    let complete ← integerField 2 "complete" complete
    let durable ← integerField 3 "durable" durable
    let lastAccess ← integerField 4 "last_access" lastAccess
    if root.size != 32 then throw (.column "blobs.root" (toString root.size ++ " bytes, not 32"))
    return ⟨root, size.toUInt64, complete != 0, durable != 0, false, lastAccess⟩
  | _ => .error .malformed

/-- Most recently accessed first; ties in root order, so a joined read of
the same relation lists the same rows in the same order. -/
def byAccess : List Order := [⟨"last_access", true⟩, ⟨"root", false⟩]

/-- The pins over each row, read as one inner join: a root once per claim,
in the base rows' order. -/
def pinJoin : List Join := [⟨"pins", [("root", "root")]⟩]

def decodeRoot : Row → Except Error ByteArray
  | [root] => rootField 0 "root" root
  | _ => .error .malformed

/-- Merge the joined roots into the rows in one pass: the roots of a row's
pins are the head of the joined list while the row is current, because both
lists are in the same order and every joined root is some row's root. -/
def markPinned (mark : A → Bool → A) (root : A → ByteArray) : List A → List ByteArray → List A
  | [], _ => []
  | row :: rest, pinned =>
    let (mine, others) := pinned.span (· == root row)
    mark row (!mine.isEmpty) :: markPinned mark root rest others

def read (tx : Transaction) (relation : String) (columns : List String) (equals : Fields)
    (order : List Order) (joins : List Join) (decode : Row → Except Error A) : Action (List A) := do
  let rows ← storage (.readRows tx relation columns equals order joins)
  ExceptT.mk (.pure (rows.mapM decode))

/-- The pinned roots in the base rows' order. -/
def pinnedRoots (tx : Transaction) : Action (List ByteArray) :=
  read tx "blobs" ["root"] [] byAccess pinJoin decodeRoot

/-- One object's row, with whether any claim stands on it. -/
def blob (root : ByteArray) : Action (Option Blob) := transaction fun tx => do
  match ← read tx "blobs" blobColumns [("root", .blob root)] [] [] decodeBlob with
  | [] => return none
  | [row] =>
    let pinned ← storage (.existsRows tx "pins" [("root", .blob root)])
    return some { row with pinned }
  | _ => throw .malformed

/-- Every row, most recently accessed first. -/
def blobs : Action (List Blob) := transaction fun tx => do
  let rows ← read tx "blobs" blobColumns [] byAccess [] decodeBlob
  let pinned ← pinnedRoots tx
  return markPinned (fun row pinned => { row with pinned }) (·.root) rows pinned

/-- Every row's summary, most recently accessed first. -/
def candidates : Action (List Summary) := transaction fun tx => do
  let rows ← read tx "blobs" summaryColumns [] byAccess [] decodeSummary
  let pinned ← pinnedRoots tx
  return markPinned (fun row pinned => { row with pinned }) (·.root) rows pinned

/-- A stored holder spelling. A spelling this build does not know is kept
as a holder rather than dropped: an unreadable claim is still a claim, and
forgetting it is how bytes go missing after a downgrade. -/
def PinHolder.parse (text : String) : PinHolder :=
  let unknown := if text == "operator" then PinHolder.operator else .other text
  -- Over the characters, structurally: the role is what precedes the first
  -- colon and the space is everything after it, colons included.
  match text.toList.splitOn ':' with
  | role :: parts =>
    let space := String.ofList ([':'].intercalate parts)
    if parts.isEmpty || space.isEmpty then unknown
    else if role == "replica".toList then .replica space
    else if role == "source".toList then .source space
    else unknown
  | [] => unknown

def pinColumns : List String := ["root", "holder", "created_at", "release_after"]

def decodePin : Row → Except Error Pin
  | [root, holder, createdAt, releaseAfter] => do
    let root ← rootField 0 "root" root
    let holder ← match holder with
      | .text holder => pure (PinHolder.parse holder)
      | .rawText _ => throw (.column "pins.holder" "not valid UTF-8")
      | cell => throw (.columnType 1 "holder" (Codec.cellType cell))
    let createdAt ← integerField 2 "created_at" createdAt
    let releaseAfter ← match releaseAfter with
      | .null => pure none
      | cell => (integerField 3 "release_after" cell).map some
    return ⟨root, holder, createdAt, releaseAfter⟩
  | _ => .error .malformed

/-- Every claim, on one object or on all, by object and then by holder. -/
def pins (root : Option ByteArray) : Action (List Pin) := transaction fun tx =>
  read tx "pins" pinColumns (match root with | some root => [("root", .blob root)] | none => [])
    [⟨"root", false⟩, ⟨"holder", false⟩] [] decodePin

/-- Adjacent duplicates of a sorted list, once. -/
def distinctSorted : List ByteArray → List ByteArray
  | [] => []
  | root :: rest => match distinctSorted rest with
    | next :: others => if next == root then next :: others else root :: next :: others
    | [] => [root]

/-- Every pinned object, in root order. -/
def pinnedBlobs : Action (List ByteArray) := transaction fun tx => do
  let roots ← read tx "pins" ["root"] [] [⟨"root", false⟩] [] decodeRoot
  return distinctSorted roots

end VerifiedCore.Cas.Project
