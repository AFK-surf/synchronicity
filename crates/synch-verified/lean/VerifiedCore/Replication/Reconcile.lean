import VerifiedCore.Replication.History
import VerifiedCore.Replication.Types
import VerifiedCore.Authorization.Operations

/-! Reconciliation owns acceptance and its durable pending transition. Raw
storage preserves read-your-writes and immediate transaction isolation; crypto
verifies only the exact byte string constructed here. -/
namespace VerifiedCore.Replication.Reconcile
open Host History

def authorizationError : Authorization.Error → History.Error
  | .host e => .host e
  | .malformed => .malformed
  | .columnType i c t => .columnType i c t
  | .invalidText b => .invalidText b
  | .column c r => .column c r
  | .origin _ e => .origin e

def littleEndian (width : Nat) (value : UInt64) : ByteArray :=
  ⟨(List.range width |>.map (fun i => (value >>> (i * 8).toUInt64).toUInt8)).toArray⟩

/-- Protocol v4 retains the sync-head/1 signing domain and fixed LE fields. -/
def signingInput (head : Head) : ByteArray :=
  let origin := (Origin.canonical head.origin).toUTF8
  "sync-head/1".toUTF8 ++ littleEndian 4 origin.size.toUInt64 ++ origin ++
    littleEndian 8 head.seq ++ head.root ++ littleEndian 8 head.createdAt.toUInt64 ++ head.signedBy

def headKey (head : Head) : Fields :=
  [("origin_id", .text (Origin.canonical head.origin)), ("seq", .integer head.seq.toInt64),
   ("root", .blob head.root)]

def record (tx : Transaction) (head : Head) (now : Int64) : Action Unit := do
  if head.seq > 9223372036854775807 then
    throw (.column "head_history.seq" "past the representable range")
  let signature := [("created_at", .integer head.createdAt),
    ("signed_by", .blob head.signedBy), ("sig", .blob head.signature)]
  request (.upsert tx "head_history" (headKey head ++ signature ++ [("recorded_at", .integer now)])
    ["origin_id", "seq", "root"] [])
  let rows ← request (.readRows tx "head_history" ["created_at", "signed_by", "sig"] (headKey head))
  if rows != [signature.map (·.2)] then
    throw (.column "head_history.sig" "already retains a different signature at this sequence and root")

def putSlot (tx : Transaction) (slot : String) (head : Head) (received verified : Int64) : Action Unit := do
  record tx head received
  request (.upsert tx "heads"
    (headKey head ++ [("slot", .text slot), ("received_at", .integer received),
      ("verified_at", .integer verified)]) ["origin_id", "slot"]
    (["seq", "root", "verified_at"] ++ if slot == "pending" then [] else ["received_at"]))

/-- Unsigned sequence and bytewise root order, independent of arrival order. -/
def newer (seq : UInt64) (root : ByteArray) (floor : Pointer) : Bool :=
  seq > floor.seq || (seq == floor.seq && root.toList > floor.root.toList)

/-- The bounded greatest-root set never evicts a slot's backing signature.
The exclusion is rechecked by each DELETE, not inferred from an earlier scan. -/
def trimForks (tx : Transaction) (origin : String) (seq : UInt64) (keep : Nat) : Action Unit := do
  let rows ← request (.readRows tx "head_history" ["seq", "root"]
    [("origin_id", .text origin), ("seq", .integer seq.toInt64)] [⟨"root", true⟩])
  let pointers ← ExceptT.mk (pure (rows.mapM decodePointer))
  for pointer in pointers.drop keep do
    let fields := [("origin_id", .text origin), ("seq", .integer seq.toInt64), ("root", .blob pointer.root)]
    let _ ← request (.deleteRows tx "head_history" fields [⟨"heads", fields, []⟩])

def accept (head : Head) (now : Int64) (keep : Nat) : Action Acceptance := do
  if !(← raise History.Error.host (Crypto.verifyEd25519 head.signedBy (signingInput head) head.signature)) then
    return .badSignature
  transactionOver Inject.inject History.Error.host fun tx => do
    let instant ← within authorizationError (Authorization.trustInstant tx now)
    let live ← within authorizationError (Authorization.liveForKey tx head.signedBy instant)
    if !live.any (·.origin == head.origin) then return .unbound
    record tx head now
    let origin := Origin.canonical head.origin
    let complete ← readSlot tx origin "complete"
    let pending ← readSlot tx origin "pending"
    let accepted := (complete ++ pending).all (fun old => newer head.seq head.root old.pointer)
    if accepted then putSlot tx "pending" head now now
    trimForks tx origin head.seq keep
    return if accepted then .pending else .notNewer

end VerifiedCore.Replication.Reconcile
