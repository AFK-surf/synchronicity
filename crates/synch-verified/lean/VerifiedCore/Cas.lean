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

/-- Scalar ABI for the proved group count. -/
@[export synch_lean_group_count]
def groupCountExport (size : UInt64) : UInt64 := groupCount size

/-- Scalar ABI for the proved settlement decision. -/
@[export synch_lean_settle_size]
def settleSizeExport (row durable complete finalHeld : Bool) (recorded claimed : UInt64) : UInt8 :=
  settleSize row durable complete finalHeld recorded claimed

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

/-- Clamp first, then sort and merge. Work depends on runs, never on blob size. -/
def normalizeSpans (total : Nat) (spans : List GroupSpan) : List GroupSpan :=
  let clipped := spans.filterMap fun r =>
    let stop := min r.stop total
    if r.start < stop then some (⟨r.start, stop⟩ : GroupSpan) else none
  match clipped.mergeSort (fun a b => a.start ≤ b.start) with
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

/-- Decode paired UInt64 endpoints; an unmatched final endpoint contributes nothing. -/
def spansOf : List UInt64 → List GroupSpan
  | start :: stop :: rest => ⟨start.toNat, stop.toNat⟩ :: spansOf rest
  | [] => []
  | [_] => []

/-- Native entry point for the pure CAS plan. -/
@[export synch_lean_cas_plan]
def casPlan (row durable complete : Bool) (recorded claimed : UInt64)
    (old incoming : Array UInt64) : CasPlan :=
  planCasCommit row durable complete recorded claimed (spansOf old.toList) (spansOf incoming.toList)

/-- Scalar plan outcome: refused, partial, or complete. -/
@[export synch_lean_cas_plan_status]
def casPlanStatus (plan : CasPlan) : UInt8 :=
  if !plan.accepted then 0 else if plan.complete then 2 else 1

/-- Export normalized endpoints without exposing the runtime's object layout. -/
@[export synch_lean_cas_plan_spans]
def casPlanSpans (plan : CasPlan) : Array UInt64 :=
  (plan.spans.flatMap fun r => [UInt64.ofNat r.start, UInt64.ofNat r.stop]).toArray

namespace Cas

/-- Facts for acquisition of one holder's pin. -/
structure AcquisitionSnapshot where
  row : Bool
  durable : Bool
  wanted : Bool

/-- Facts for deletion of one object's row and files. -/
structure DeletionSnapshot where
  row : Bool
  writing : Bool
  pinned : Bool
  referenced : Bool
  lastAccess : Int64

/-- Domain commands, not individual policy queries. -/
inductive LifecycleRequest where
  | acquire (snapshot : AcquisitionSnapshot) (possession : Bool)
  | delete (snapshot : DeletionSnapshot) (before : Option Int64)

/-- Keyed storage actions executed together in one SQL transaction. -/
inductive Mutation where
  | deleteRow | deleteWant | upsertPin

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

/-- The CAS lifecycle planning boundary. Rust never advances its internal
algorithm one predicate or state-machine step at a time. -/
def planLifecycle : LifecycleRequest → LifecyclePlan
  | .acquire s possession =>
    if s.row && s.durable && (!possession || s.wanted) then
      ⟨.applied, (if possession then [.deleteWant] else []) ++ [.upsertPin], []⟩
    else ⟨.skipped, [], []⟩
  | .delete s before =>
    if s.writing then ⟨.writing, [], []⟩ else
    if s.pinned || s.referenced then ⟨.protectedClaim, [], []⟩ else
    if before.isSome && (!s.row || !(s.lastAccess < before.getD 0)) then ⟨.skipped, [], []⟩ else
      ⟨.applied, [.deleteRow], [.payload, .outboard]⟩

/-- Fixed five-byte ABI record: outcome, two transaction slots, two cleanup
slots. Zero action slots are padding; no SQL, handles, or runtime layout crosses. -/
def encodeLifecycle (plan : LifecyclePlan) : ByteArray :=
  let outcome : UInt8 := match plan.outcome with
    | .skipped => 0 | .writing => 1 | .protectedClaim => 2 | .applied => 3
  let mutation : Option Mutation → UInt8
    | none => 0 | some .deleteRow => 1 | some .deleteWant => 2 | some .upsertPin => 3
  let cleanup : Option Cleanup → UInt8
    | none => 0 | some .payload => 1 | some .outboard => 2
  ⟨#[outcome, mutation plan.transaction[0]?, mutation plan.transaction[1]?,
      cleanup plan.afterCommit[0]?, cleanup plan.afterCommit[1]?]⟩

/-- Narrow ABI marshalling for the typed domain request. Invalid commands fail closed. -/
@[export synch_lean_cas_lifecycle]
def lifecycleExport (command row a b c d : UInt8) (lastAccess before : Int64) : ByteArray :=
  if command == 0 then encodeLifecycle (planLifecycle (.acquire ⟨row != 0, a != 0, b != 0⟩ (c != 0)))
  else if command == 1 then encodeLifecycle (planLifecycle
    (.delete ⟨row != 0, a != 0, b != 0, c != 0, lastAccess⟩ (if d != 0 then some before else none)))
  else encodeLifecycle ⟨.skipped, [], []⟩

end Cas
end VerifiedCore
