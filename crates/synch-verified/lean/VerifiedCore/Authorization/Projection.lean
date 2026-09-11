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

/-- The public OriginId ordering: keys before names; names by domain then
member id. Canonical text ordering is deliberately not substituted. -/
def originLe : Origin.Parsed → Origin.Parsed → Bool
  | .key a, .key b => a ≤ b
  | .key _, .named _ => true
  | .named _, .key _ => false
  | .named a, .named b => a.domain < b.domain || (a.domain == b.domain && a.id ≤ b.id)

def trustedOrigins (reading : Int64) : Action (List Origin.Parsed) := transaction fun tx => do
  let now ← trustInstant tx reading
  let cells ← liveColumn tx "origin_id" now
  let origins ← cells.mapM fun cell => do
    originField "bindings.origin_id" (← checked (textField 0 "origin_id" cell))
  return (origins.mergeSort originLe).eraseReps

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
  | origin (origin : Origin.Parsed)
  | delegated
  deriving BEq, DecidableEq

def BindingSelection.fields : BindingSelection → Fields
  | .all => []
  | .key value => [("node_id", .blob value)]
  | .origin value => [("origin_id", .text (Origin.canonical value))]
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
  live : Bool
  deriving BEq, DecidableEq

/-- Reporting receives both the dated observation and effective live trust.
The cascade is evaluated per complete binding identity, so one live issuer
cannot conceal another issuer's expired delegation in the diagnostic. -/
def bindingStatuses (reading : Int64) : Action (List BindingStatus) := transaction fun tx => do
  let now ← trustInstant tx reading
  let rows ← readBindings tx []
  let rooted := rootedOrigins rows now
  return rows.map fun binding => ⟨binding, binding.datedLive now, supportedBy rooted now binding⟩

/-- DNS hint attribution intentionally asks the dated rule, without the
issuer cascade: a hint's sole source and a delegation's authority are distinct. -/
def soleDnsHintSource (key : ByteArray) (domain : String) (reading : Int64) : Action Bool :=
  transaction fun tx => do
    let rows ← readBindings tx [("node_id", .blob key)]
    let now ← trustInstant tx reading
    let live := rows.filter (·.datedLive now)
    return !live.isEmpty && live.all (fun binding => binding.source == .dns && binding.domain == some domain)

structure SocketAuthority where
  origin : Origin.Parsed
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
    | none => return some ⟨first.origin, some (canonicalSpaces (live.flatMap (·.readable)))⟩

end VerifiedCore.Authorization
