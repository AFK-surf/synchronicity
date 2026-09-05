import VerifiedCore.Host
import Std.Data.TreeMap.Basic
import Std.Data.TreeSet.Basic

/-!
History retention over raw storage, independent of CAS and trie internals.

Staged program, NOT yet a production cutover. Before replacing the Rust entry
point the shared storage interpreter/algebra must preserve three contracts:

* Every deletion must add the generic relational predicate `NOT EXISTS heads`
  with literal equality fields `origin_id`, `seq`, and `root`. The current Rust
  SQL protects a slot pointer again at deletion time, including against SQL
  triggers that change pointers within an immediate transaction. Snapshot-only
  selection below does not replace that second defense.
* Receipt reads must request SQL ordering `seq DESC, root DESC`, preserving the
  current mutation/trigger/failure order. SQL ordering is signed Int64; Lean's
  retention comparisons deliberately reinterpret the stored bits as UInt64.
* Raw pointer reads protect orphan pointers, but no longer validate the joined
  signed-head origin/key/signature as `head_in` does. Malformed cells currently
  return code 2/token 0 rather than the existing contextual Rust column/decode
  errors. Those error and corrupt-storage semantics need explicit resolution
  and regression tests before cutover; they are not claimed equivalent here.

The generic predicate/order facilities belong in Host, not a history-specific
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

def malformed : Failure := ⟨2, 0⟩

/-- SQL stores sequence bits in signed integers. Do not clamp negative cells. -/
def decodePointer : Row → Reply Pointer
  | [.integer seq, .blob root] =>
    if root.size == 32 then .ok ⟨seq.toUInt64, root⟩ else .error malformed
  | _ => .error malformed

def decodeReceipt : Row → Reply Receipt
  | [.integer seq, .blob root, .integer recordedAt] => do
    let pointer ← decodePointer [.integer seq, .blob root]
    pure ⟨pointer, recordedAt⟩
  | _ => .error malformed

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

def removeLoop (tx : Transaction) (origin : String) : Nat → List Receipt → Operation Nat
  | total, [] => pure total
  | total, receipt :: rest => do
    let count ← perform (.deleteRows tx "head_history"
      [("origin_id", .text origin), ("seq", .integer receipt.pointer.seq.toInt64),
       ("root", .blob receipt.pointer.root)])
    removeLoop tx origin (total + count) rest

def remove (tx : Transaction) (origin : String) (receipts : List Receipt) : Operation Nat :=
  removeLoop tx origin 0 receipts

/-- This operation owns raw decoding and every retention decision in the same
immediate transaction as its deletions. No host-computed fork or ceiling facts. -/
def pruneIn (tx : Transaction) (origin : String) (before : Int64) : Operation Nat := do
  let rawPointers ← perform (.readRows tx "heads" ["seq", "root"] [("origin_id", .text origin)])
  let pointers ← ExceptT.mk (pure (rawPointers.mapM decodePointer))
  let rawReceipts ← perform (.readRows tx "head_history" ["seq", "root", "recorded_at"]
    [("origin_id", .text origin)])
  let receipts ← ExceptT.mk (pure (rawReceipts.mapM decodeReceipt))
  remove tx origin (selected pointers before receipts)

/-- Public domain command: origin and retention horizon, returning committed deletions. -/
def prune (origin : String) (before : Int64) : Operation Nat :=
  transaction (fun tx => pruneIn tx origin before)

end VerifiedCore.Replication.History
