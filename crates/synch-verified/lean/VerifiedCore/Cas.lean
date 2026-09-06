import Init

/-! CAS algorithms and transaction planning. No trie or networking dependency. -/
namespace VerifiedCore

/-- Overflow-free chunk-group count, including the empty object's group. -/
def groupCount (size : UInt64) : UInt64 :=
  if size == 0 then 1 else (size - 1) / 16384 + 1

/-- Size settlement: 0 refuses, 1 accepts retaining bits, 2 accepts resetting
bits. Inputs describe the row read inside the Rust transaction. -/
def settleSize (row durable complete finalHeld : Bool) (recorded claimed : UInt64) : UInt8 :=
  if !row || recorded == claimed then 1
  else if durable || complete || finalHeld then 0
  else if groupCount recorded == groupCount claimed then 1 else 2

/-- Half-open CAS group interval, interpreted with unbounded arithmetic. -/
structure GroupSpan where
  start : Nat
  stop : Nat

/-- Merge a sorted sequence of touching intervals in one linear pass. -/
def mergeSpans (head : GroupSpan) : List GroupSpan → List GroupSpan
  | [] => [head]
  | next :: rest =>
    if next.start ≤ head.stop && head.start ≤ next.stop then
      mergeSpans ⟨min head.start next.start, max head.stop next.stop⟩ rest
    else head :: mergeSpans next rest

/-- Insert into a sequence sorted by start, ahead of any equal start. -/
def insertSpan (span : GroupSpan) : List GroupSpan → List GroupSpan
  | [] => [span]
  | head :: rest =>
    if span.start ≤ head.start then span :: head :: rest else head :: insertSpan span rest

/-- Insertion sort by start. Runs are few, and structural recursion lets the
proofs evaluate whole plans. -/
def sortSpans : List GroupSpan → List GroupSpan
  | [] => []
  | head :: rest => insertSpan head (sortSpans rest)

/-- Clamp first, then sort and merge. Work depends on runs, never on blob size. -/
def normalizeSpans (total : Nat) (spans : List GroupSpan) : List GroupSpan :=
  let clipped := spans.filterMap fun r =>
    let stop := min r.stop total
    if r.start < stop then some (⟨r.start, stop⟩ : GroupSpan) else none
  match sortSpans clipped with
  | [] => []
  | head :: rest => mergeSpans head rest

/-- Membership in a finite range representation. -/
def spansContain (spans : List GroupSpan) (group : Nat) : Bool :=
  spans.any fun r => r.start ≤ group && group < r.stop

/-- The complete CAS row plan, before SQL and without any storage effects. -/
structure CasPlan where
  accepted : Bool
  complete : Bool
  spans : List GroupSpan

/-- Size attestation, retention/reset, union, clipping and completion are one
decision. A complete old row denotes every group even with no bitmap column. -/
def planCasCommit (row durable complete : Bool) (recorded claimed : UInt64)
    (old incoming : List GroupSpan) : CasPlan :=
  let prior := if row then
    if complete then [⟨0, (groupCount recorded).toNat⟩] else old
    else []
  let decision := settleSize row durable complete
    (spansContain prior ((groupCount recorded).toNat - 1)) recorded claimed
  if decision == 0 then ⟨false, false, []⟩ else
    let retained := if decision == 2 then [] else prior
    let total := (groupCount claimed).toNat
    let spans := normalizeSpans total (retained ++ incoming)
    ⟨true, spansContain spans 0 && spans.any (fun r => r.start == 0 && r.stop == total), spans⟩

namespace Cas

/-- Facts for deletion of one object's row and files. -/
structure DeletionSnapshot where
  row : Bool
  writing : Bool
  pinned : Bool
  referenced : Bool
  lastAccess : Int64

/-- Domain commands, not individual policy queries. -/
inductive LifecycleRequest where
  | delete (snapshot : DeletionSnapshot) (before : Option Int64)

/-- Keyed storage actions executed together in one SQL transaction. -/
inductive Mutation where
  | deleteRow

/-- Best-effort actions permitted only after the transaction commits. -/
inductive Cleanup where
  | payload | outboard

/-- A domain-level outcome, independent of internal algorithm phases. -/
inductive Outcome where
  | skipped | writing | protectedClaim | applied

/-- One atomic transaction followed by optional post-commit cleanup. -/
structure LifecyclePlan where
  outcome : Outcome
  transaction : List Mutation := []
  afterCommit : List Cleanup := []

/-- Internal Lean deletion decision, consumed by the complete storage program.
Neither its observations nor its mutation/cleanup lists cross the native ABI. -/
def planLifecycle : LifecycleRequest → LifecyclePlan
  | .delete s before =>
    if s.writing then ⟨.writing, [], []⟩ else
    if s.pinned || s.referenced then ⟨.protectedClaim, [], []⟩ else
    if before.isSome && (!s.row || !(s.lastAccess < before.getD 0)) then ⟨.skipped, [], []⟩ else
      ⟨.applied, [.deleteRow], [.payload, .outboard]⟩


end Cas
end VerifiedCore
