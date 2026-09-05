import VerifiedCore.Host
import VerifiedCore.Origin
import Std.Data.TreeMap.Basic
import Std.Data.TreeSet.Basic

/-!
History retention over raw storage, independent of CAS and trie internals.

Staged program, NOT yet a production cutover. Before replacing the Rust entry
point the shared storage interpreter/algebra must preserve these contracts:

* Every deletion must add the generic relational predicate `NOT EXISTS heads`
  with literal equality fields `origin_id`, `seq`, and `root`. The current Rust
  SQL protects a slot pointer again at deletion time, including against SQL
  triggers that change pointers within an immediate transaction. Snapshot-only
  selection below does not replace that second defense. The program now
  requests that exclusion in each delete statement.
* Receipt reads must request SQL ordering `seq DESC, root DESC`, preserving the
  current mutation/trigger/failure order. SQL ordering is signed Int64; Lean's
  retention comparisons deliberately reinterpret the stored bits as UInt64.
  The program now supplies this ordering explicitly.
* Joined slot reads preserve orphan-pointer absence and check column/byte
  shapes with typed contextual errors in projection order. Named-origin syntax
  is checked directly by the shared Lean Origin module, after signature width.
  Key-origin decoding and cryptographic public keys are not yet validated.
  Native terminal error encoding, key validation and scan-failure ordering remain required
  before cutover; full diagnostic compatibility is not claimed here.

The generic predicate/order facilities are in Host, not a history-specific
callback. Current scripted fixtures establish the normal storage protocol and
failure branches, not production compatibility under triggers/corruption.
-/
namespace VerifiedCore.Replication.History
open Host

structure Pointer where
  seq : UInt64
  root : ByteArray
  deriving BEq

structure Receipt where
  pointer : Pointer
  recordedAt : Int64

/-- SQL storage classes, independent of a domain's expected field type. -/
inductive CellType where
  | null | integer | real | text | blob
  deriving BEq, DecidableEq

/-- Rich validation failures remain in Lean until the operation completes.
Host tokens are retained unchanged; the native entry will encode domain errors
as terminal results, not feed them back through the storage interface. -/
inductive Error where
  | host (failure : Failure)
  | malformed
  | columnType (index : Nat) (column : String) (actual : CellType)
  | invalidText (bytes : List UInt8)
  | column (column : String) (reason : String)
  | origin (error : Origin.Error)
  deriving BEq, DecidableEq

abbrev Result (A : Type) := Except Error A
abbrev Action (A : Type) := Host.OperationWith Error A

def malformed : Error := .malformed

def request (effect : Storage (Reply A)) : Action A := performWith Error.host effect

def cellType : Cell → CellType
  | .null => .null
  | .integer _ => .integer
  | .real _ => .real
  | .text _ | .rawText _ => .text
  | .blob _ => .blob

def integerField (index : Nat) (column : String) : Cell → Result Int64
  | .integer value => .ok value
  | value => .error (.columnType index column (cellType value))

def blobField (index : Nat) (column : String) : Cell → Result ByteArray
  | .blob value => .ok value
  | value => .error (.columnType index column (cellType value))

def textField (index : Nat) (column : String) : Cell → Result String
  | .text value => .ok value
  | .rawText bytes => match String.fromUTF8? bytes with
    | some text => .ok text
    | none => .error (.invalidText bytes.toList)
  | value => .error (.columnType index column (cellType value))

def hashField (column : String) (bytes : ByteArray) : Result ByteArray :=
  if bytes.size == 32 then .ok bytes
  else .error (.column column (toString bytes.size ++ " bytes, not 32"))

/-- SQL stores sequence bits in signed integers. Do not clamp negative cells. -/
def decodePointer : Row → Result Pointer
  | [seq, root] => do
    let seq ← integerField 0 "seq" seq
    let root ← blobField 1 "root" root
    return ⟨seq.toUInt64, ← hashField "heads.root" root⟩
  | _ => .error malformed

/-- Decode typed columns in projection order before checking the hash width,
matching the original stored-record reader's first-error behavior. -/
def decodeReceipt : Row → Result Receipt
  | [seq, root, recordedAt] => do
    let seq ← integerField 0 "seq" seq
    let root ← blobField 1 "root" root
    let recordedAt ← integerField 2 "recorded_at" recordedAt
    let root ← hashField "head_history.root" root
    return ⟨⟨seq.toUInt64, root⟩, recordedAt⟩
  | _ => .error malformed

/-- Joined storage fields retained for subsequent origin/key validation. -/
structure JoinedHead where
  origin : String
  pointer : Pointer
  publicKey : ByteArray

/-- Column conversion is sequenced explicitly, followed by record checks.
Named-origin parsing is included; key-origin parsing and cryptographic
public-key validity remain cutover gates. -/
def decodeJoinedHead : Row → Result JoinedHead
  | [origin, seq, root, created, key, sig, received, verified] => do
    let origin ← textField 0 "origin_id" origin
    let seq ← integerField 1 "seq" seq
    let root ← blobField 2 "root" root
    let _ ← integerField 3 "created_at" created
    let key ← blobField 4 "signed_by" key
    let sig ← blobField 5 "sig" sig
    let _ ← integerField 6 "received_at" received
    let _ ← integerField 7 "verified_at" verified
    if sig.size != 64 then throw (.column "heads.sig" "not 64 bytes")
    let _ ← (Origin.checkNamedText origin).mapError Error.origin
    let root ← hashField "heads.root" root
    if key.size != 32 then throw (.column "heads.signed_by" "not 32 bytes")
    return ⟨origin, ⟨seq.toUInt64, root⟩, key⟩
  | _ => .error malformed

def headColumns : List String :=
  ["origin_id", "seq", "root", "head_history.created_at", "head_history.signed_by",
   "head_history.sig", "received_at", "verified_at"]

def headJoin : List Join :=
  [⟨"head_history", [("origin_id", "origin_id"), ("seq", "seq"), ("root", "root")]⟩]

/-- The raw inner join precedes all decoding. Orphan pointers are absent, just
as in the existing storage reader. Slots are fetched in caller-selected order. -/
def readSlot (tx : Transaction) (origin slot : String) : Action (List JoinedHead) := do
  let raw ← request (.readRows tx "heads" headColumns
    [("origin_id", .text origin), ("slot", .text slot)] [] headJoin)
  match raw with
  | [] => return []
  | row :: _ =>
    let head ← ExceptT.mk (pure (decodeJoinedHead row))
    return [head]

structure SequenceSummary where
  count : Nat := 0
  pinned : Bool := false
  old : Bool := false

def current (pointers : List Pointer) (receipt : Receipt) : Bool :=
  pointers.contains receipt.pointer

def addReceipt (pointers : List Pointer) (before : Int64)
    (summaries : Std.TreeMap UInt64 SequenceSummary) (receipt : Receipt) :
    Std.TreeMap UInt64 SequenceSummary :=
    let prior := summaries.getD receipt.pointer.seq {}
    summaries.insert receipt.pointer.seq
      ⟨prior.count + 1,
       prior.pinned || before ≤ receipt.recordedAt || current pointers receipt,
       prior.old || receipt.recordedAt < before⟩

/-- Aggregate all rows of each sequence before deciding whether a fork can go.
The storage primary key guarantees distinct roots within a sequence. -/
def summarize (pointers : List Pointer) (before : Int64) (receipts : List Receipt) :
    Std.TreeMap UInt64 SequenceSummary :=
  receipts.foldl (addReceipt pointers before) {}

structure Retention where
  ceiling : Option UInt64
  movedPast : Option UInt64
  summaries : Std.TreeMap UInt64 SequenceSummary
  witnesses : Std.TreeSet UInt64

def retainMaximum (best : Option UInt64) (seq : UInt64) : Option UInt64 :=
  some (match best with
    | none => seq
    | some old => if seq ≤ old then old else seq)

def maximum (seqs : List UInt64) : Option UInt64 := seqs.foldl retainMaximum none

def expired (movedPast : Option UInt64) (seq : UInt64) (summary : SequenceSummary) : Bool :=
  movedPast.any (seq < ·) && !summary.pinned

def witnessStep (movedPast : Option UInt64)
    (state : Option UInt64 × Std.TreeSet UInt64) (entry : UInt64 × SequenceSummary) :
    Option UInt64 × Std.TreeSet UInt64 :=
  let (nextOld, witnesses) := state
  let (seq, summary) := entry
  let witnesses := if summary.count > 1 && !expired movedPast seq summary then
    match nextOld with | none => witnesses | some witness => witnesses.insert witness
    else witnesses
  (if summary.old then some seq else nextOld, witnesses)

def retention (pointers : List Pointer) (before : Int64) (receipts : List Receipt) : Retention :=
  let summaries := summarize pointers before receipts
  let ordered := summaries.toList
  let movedPast := maximum ((ordered.filter (·.2.old)).map (·.1))
  -- Reverse order keeps the least higher old sequence in `nextOld`, so finding
  -- every protected fork's witness is linear, not one history scan per fork.
  let (_, witnesses) := ordered.reverse.foldl (witnessStep movedPast)
      (none, ({} : Std.TreeSet UInt64))
  ⟨maximum (ordered.map (·.1)), movedPast, summaries, witnesses⟩

def deletable (policy : Retention) (pointers : List Pointer) (before : Int64)
    (receipt : Receipt) : Bool :=
  let seq := receipt.pointer.seq
  let summary := policy.summaries.getD seq {}
  receipt.recordedAt < before && !current pointers receipt &&
    (summary.count ≤ 1 || expired policy.movedPast seq summary) &&
    !policy.witnesses.contains seq && policy.ceiling != some seq

def selected (pointers : List Pointer) (before : Int64) (receipts : List Receipt) : List Receipt :=
  receipts.filter (deletable (retention pointers before receipts) pointers before)

def receiptKey (origin : String) (receipt : Receipt) : Fields :=
  [("origin_id", .text origin), ("seq", .integer receipt.pointer.seq.toInt64),
   ("root", .blob receipt.pointer.root)]

def removeLoop (tx : Transaction) (origin : String) : Nat → List Receipt → Action Nat
  | total, [] => pure total
  | total, receipt :: rest => do
    let count ← request (.deleteRows tx "head_history"
      (receiptKey origin receipt) [⟨"heads", receiptKey origin receipt⟩])
    removeLoop tx origin (total + count) rest

def remove (tx : Transaction) (origin : String) (receipts : List Receipt) : Action Nat :=
  removeLoop tx origin 0 receipts

/-- This operation owns raw decoding and every retention decision in the same
immediate transaction as its deletions. No host-computed fork or ceiling facts. -/
def pruneIn (tx : Transaction) (origin : String) (before : Int64) : Action Nat := do
  let complete ← readSlot tx origin "complete"
  let pending ← readSlot tx origin "pending"
  let pointers := (complete ++ pending).map (·.pointer)
  let rawReceipts ← request (.readRows tx "head_history" ["seq", "root", "recorded_at"]
    [("origin_id", .text origin)] [⟨"seq", true⟩, ⟨"root", true⟩])
  let receipts ← ExceptT.mk (pure (rawReceipts.mapM decodeReceipt))
  remove tx origin (selected pointers before receipts)

/-- Public domain command: origin and retention horizon, returning committed deletions. -/
def prune (origin : String) (before : Int64) : Action Nat :=
  transactionWith Error.host (fun tx => pruneIn tx origin before)

end VerifiedCore.Replication.History
