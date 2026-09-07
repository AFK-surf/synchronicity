import VerifiedCore.Authorization.Read

/-! Whole trust-set and binding projections. The hot key/origin lists carry
only liveness columns and the requested identity; no full Binding objects or
space lists are materialized merely to answer a connection/dialing question. -/
namespace VerifiedCore.Authorization
open Host

structure PolicyRow where
  origin : String
  source : Source
  issuer : String
  expiresAt : Option Int64
  selected : Cell

def decodePolicy : Row → Except Error PolicyRow
  | [origin, source, issuer, expiresAt, selected] => do
    let origin ← textField 0 "origin_id" origin
    let source ← textField 1 "source" source
    let issuer ← textField 2 "issuer" issuer
    let expiresAt ← optionalInteger 3 "expires_at" expiresAt
    return ⟨origin, ← parseSource source, issuer, expiresAt, selected⟩
  | _ => .error .malformed

/-- Malformed policy fields fail closed. Unlike the former SQL expression,
an unknown source is not treated as an implicitly trusted fourth source and
SQLite's integer-versus-text ordering cannot grant an invalid expiry. -/
def liveColumn (tx : Transaction) (column : String) (now : Int64) : Action (List Cell) := do
  let scan ← storage (.scanRows tx "bindings"
    ["origin_id", "source", "issuer", "expires_at", column] [])
  let rows ← scan.rows.mapM (fun row => checked (decodePolicy row))
  match scan.failure with
  | some failure => throw (.host failure)
  | none => pure ()
  let rooted := rows.foldl (fun (set : Std.TreeSet String) row =>
    if row.source.rooted && liveAt row.expiresAt now then set.insert row.origin else set) {}
  return (rows.filter fun row => liveAt row.expiresAt now &&
    (row.source != .delegated || (!row.issuer.isEmpty && rooted.contains row.issuer))).map (·.selected)

def trustedOrigins (reading : Int64) : Action (List String) := transaction fun tx => do
  let now ← trustInstant tx reading
  let cells ← liveColumn tx "origin_id" now
  let origins ← cells.mapM fun cell => do
    originField "bindings.origin_id" (← checked (textField 0 "origin_id" cell))
  return canonicalSpaces origins

def trustedKeys (reading : Int64) : Action (List ByteArray) := transaction fun tx => do
  let now ← trustInstant tx reading
  let cells ← liveColumn tx "node_id" now
  let keys ← cells.mapM fun cell => do
    keyField "bindings.node_id" (← checked (blobField 0 "node_id" cell))
  let sorted := keys.mergeSort (fun a b => a.data.toList ≤ b.data.toList)
  return sorted.eraseReps

inductive BindingSelection where
  | all
  | key (key : ByteArray)
  | origin (origin : String)
  | delegated
  deriving BEq, DecidableEq

def BindingSelection.fields : BindingSelection → Fields
  | .all => []
  | .key value => [("node_id", .blob value)]
  | .origin value => [("origin_id", .text value)]
  | .delegated => [("source", .text "delegated")]

/-- Raw reporting and live authorization share one decoder. Expiry and issuer
cascade are evaluated here only when requested by the complete projection. -/
def bindings (selection : BindingSelection) (onlyLive : Bool) (reading : Int64) : Action (List Binding) :=
  transaction fun tx => do
    if !onlyLive then return ← readBindings tx selection.fields
    let now ← trustInstant tx reading
    match selection with
    | .all => allLive tx now
    | _ => liveAmong tx (← readBindings tx selection.fields) now

structure BindingStatus where
  binding : Binding
  datedLive : Bool
  deriving BEq, DecidableEq

/-- Reporting explicitly asks for dated rows. Rendering never reimplements
clock/expiry policy, and this status does not pretend to certify the cascade. -/
def bindingStatuses (reading : Int64) : Action (List BindingStatus) := transaction fun tx => do
  let now ← trustInstant tx reading
  return (← readBindings tx []).map fun binding => ⟨binding, binding.datedLive now⟩

/-- DNS hint attribution intentionally asks the dated rule, without the
issuer cascade: a hint's sole source and a delegation's authority are distinct. -/
def soleDnsHintSource (key : ByteArray) (domain : String) (reading : Int64) : Action Bool :=
  transaction fun tx => do
    let rows ← readBindings tx [("node_id", .blob key)]
    let now ← trustInstant tx reading
    let live := rows.filter (·.datedLive now)
    return !live.isEmpty && live.all (fun binding => binding.source == .dns && binding.domain == some domain)

structure SocketAuthority where
  origin : String
  spaces : Option (List String)
  deriving BEq, DecidableEq

/-- A rooted identity wins the socket's attributed origin as well as its
scope; an unbound key has no socket authority. -/
def socketAuthority (key : ByteArray) (reading : Int64) : Action (Option SocketAuthority) :=
  transaction fun tx => do
    let now ← trustInstant tx reading
    let live ← liveForKey tx key now
    let some first := live.head? | return none
    match live.find? (·.source.rooted) with
    | some rooted => return some ⟨rooted.origin, none⟩
    | none => return some ⟨first.origin, some (canonicalSpaces (live.flatMap (·.spaces)))⟩

end VerifiedCore.Authorization
