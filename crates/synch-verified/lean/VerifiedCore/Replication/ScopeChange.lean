import VerifiedCore.Replication.Reconcile

/-! Atomic read-permission changes.

The read scope, derived views, redaction boundaries and foreign head slots are
one domain transition.  The host supplies raw relational effects; it does not
choose which origins are foreign, which pending version wins, or which state is
invalid under a changed permission. -/
namespace VerifiedCore.Replication.ScopeChange
open Host

abbrev Action (A : Type) := History.Action A

structure Stored where
  origin : String
  pointer : History.Pointer
  received : Int64
  verified : Int64

def decodeStored (row : Row) : Action Stored := do
  let head ← History.decodeJoinedHead row
  match row with
  | [_, _, _, _, _, _, .integer received, .integer verified] =>
      return ⟨head.origin, head.pointer, received, verified⟩
  | _ => throw .malformed

def allSlot (tx : Transaction) (slot : String) : Action (List Stored) := do
  let scan ← History.request (.scanRows tx "heads" History.headColumns
    [("slot", .text slot)] [⟨"origin_id", false⟩] History.headJoin)
  let heads ← scan.rows.mapM decodeStored
  if let some failure := scan.failure then throw (.host failure)
  return heads

def encodeSpaces (spaces : List String) : String := String.intercalate "\n" spaces

def writeScope (tx : Transaction) : Option (List String) → Action Unit
  | none => do
      let _ ← History.request (.deleteRows tx "config" [("key", .text "local_scope")])
  | some spaces => History.request (.upsert tx "config"
      [("key", .text "local_scope"), ("value", .text (encodeSpaces spaces))]
      ["key"] ["value"])

def eraseDerived (tx : Transaction) (origin : String) : Action Unit := do
  let _ ← History.request (.deleteRows tx "entries" [("origin_id", .text origin)])
  let _ ← History.request (.deleteRows tx "blob_providers" [("origin_id", .text origin)])
  let _ ← History.request (.deleteRows tx "bindings"
    [("source", .text "delegated"), ("issuer", .text origin)])

def writePending (tx : Transaction) (head : Stored) (received : Int64) : Action Unit :=
  History.request (.upsert tx "heads"
    [("origin_id", .text head.origin), ("slot", .text "pending"),
     ("seq", .integer head.pointer.seq.toInt64), ("root", .blob head.pointer.root),
     ("received_at", .integer received), ("verified_at", .integer head.verified)]
    ["origin_id", "slot"] ["seq", "root", "received_at", "verified_at"])

/-- The complete target is requeued exactly when the at-most-one joined
pending target does not outrank it under the reconciliation order. -/
def shouldRequeue (complete : Stored) (pending : Option Stored) : Bool :=
  pending.all fun current =>
    Reconcile.newer complete.pointer.seq complete.pointer.root current.pointer

def selectedPending (complete : Stored) (pending : Option Stored) : History.Pointer :=
  if shouldRequeue complete pending then complete.pointer
  else (pending.map (fun current => current.pointer)).getD complete.pointer

structure Demotion where
  complete : Stored
  pending : Option Stored

def Demotion.requeued (decision : Demotion) : Bool :=
  shouldRequeue decision.complete decision.pending

def Demotion.selected (decision : Demotion) : History.Pointer :=
  selectedPending decision.complete decision.pending

def Demotion.selectedStored (decision : Demotion) : Stored :=
  let selected := if decision.requeued then decision.complete
    else decision.pending.getD decision.complete
  { selected with origin := decision.complete.origin }

@[simp] theorem Demotion.selectedStored_origin (decision : Demotion) :
    decision.selectedStored.origin = decision.complete.origin := by
  simp [selectedStored]

def Demotion.pendingRow (decision : Demotion) (now : Int64) : Row :=
  let selected := decision.selectedStored
  [.text selected.origin, .text "pending", .integer selected.pointer.seq.toInt64,
   .blob selected.pointer.root, .integer now, .integer selected.verified]

structure ChangeReport where
  changed : Bool
  demotions : List Demotion

def decision (own : Option String) (pending : List Stored) (complete : Stored) : Option Demotion :=
  if own == some complete.origin then none
  else some ⟨complete, pending.find? fun head => head.origin == complete.origin⟩

def demote (tx : Transaction) (decision : Demotion) (now : Int64) : Action Unit := do
  eraseDerived tx decision.complete.origin
  let _ ← History.request (.deleteRows tx "heads"
    [("origin_id", .text decision.complete.origin), ("slot", .text "pending")])
  writePending tx decision.selectedStored now
  let _ ← History.request (.deleteRows tx "heads"
    [("origin_id", .text decision.complete.origin), ("slot", .text "complete")])

def refreshPending (tx : Transaction) (own : Option String) (demotions : List Demotion)
    (head : Stored) (now : Int64) : Action Unit := do
  if own == some head.origin || demotions.any fun decision =>
      decision.complete.origin == head.origin then return
  let _ ← History.request (.deleteRows tx "heads"
    [("origin_id", .text head.origin), ("slot", .text "pending")])
  writePending tx head now

def demoteAll (tx : Transaction) (now : Int64) : List Demotion → Action Unit
  | [] => pure ()
  | decision :: rest => do
      demote tx decision now
      demoteAll tx now rest

def refreshAll (tx : Transaction) (own : Option String) (demotions : List Demotion)
    (now : Int64) : List Stored → Action Unit
  | [] => pure ()
  | head :: rest => do
      refreshPending tx own demotions head now
      refreshAll tx own demotions now rest

/-- Commit-time consistency checks read only the raw rows this command owns.
There are five indexed/existence reads per demoted origin; any malformed or
host result aborts and rolls back before publication. -/
def verifyAbsent (tx : Transaction) (relation : String) (fields : Fields) : Action Unit := do
  if ← History.request (.existsRows tx relation fields) then throw .malformed

def verifyDemotion (tx : Transaction) (decision : Demotion) (now : Int64) : Action Unit := do
  let origin := decision.complete.origin
  let complete ← History.request (.readRows tx "heads"
    ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
    [("origin_id", .text origin), ("slot", .text "complete")] [] [])
  if !complete.isEmpty then throw .malformed
  let pending ← History.request (.readRows tx "heads"
    ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
    [("origin_id", .text origin), ("slot", .text "pending")] [] [])
  if pending != [decision.pendingRow now] then throw .malformed
  verifyAbsent tx "entries" [("origin_id", .text origin)]
  verifyAbsent tx "blob_providers" [("origin_id", .text origin)]
  verifyAbsent tx "bindings" [("source", .text "delegated"), ("issuer", .text origin)]

def verifyDemotions (tx : Transaction) (now : Int64) : List Demotion → Action Unit
  | [] => pure ()
  | decision :: rest => do
      verifyDemotion tx decision now
      verifyDemotions tx now rest

/-- The global redaction table is checked once, then every demoted origin is
checked independently. Thus commit verification costs one global query plus
five indexed queries per foreign complete origin. -/
def verifyAll (tx : Transaction) (now : Int64) (decisions : List Demotion) : Action Unit := do
  verifyAbsent tx "redacted_nodes" []
  verifyDemotions tx now decisions

/-- The internal report is derived from the actual joined rows and decisions
used by the transaction; it is proof evidence, not host policy. -/
def changeDetailed (next : Option (List String)) (now : Int64) : Action ChangeReport :=
  transactionOver Inject.inject History.Error.host fun tx => do
    let current ← within Reconcile.authorizationError (Authorization.localSpacesIn tx)
    if current == next then return ⟨false, []⟩
    let own ← within Reconcile.authorizationError (Authorization.ownOrigin tx)
    let own := own.map Origin.canonical
    let complete ← allSlot tx "complete"
    let pending ← allSlot tx "pending"
    let demotions := complete.filterMap (decision own pending)
    writeScope tx next
    let _ ← History.request (.deleteRows tx "redacted_nodes" [])
    demoteAll tx now demotions
    refreshAll tx own demotions now pending
    verifyAll tx now demotions
    return ⟨true, demotions⟩

/-- Move to `next` or do nothing when it is already current.  Every changed
transition commits the new scope beside an empty old derived view, no redaction
boundary, no foreign complete claim, and refreshed pending retry work. -/
def change (next : Option (List String)) (now : Int64) : Action Bool :=
  (fun report => report.changed) <$> changeDetailed next now

end VerifiedCore.Replication.ScopeChange
