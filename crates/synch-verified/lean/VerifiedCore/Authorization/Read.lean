import VerifiedCore.Authorization.Model
import Std.Data.TreeSet.Basic
import Std.Data.TreeMap.Basic

/-! Whole authorization reads. Every decision sees one raw database snapshot;
only point validity is delegated to the host. Key/origin questions keep their
indexed equality seeks, including the issuer cascade. Borrowed-transaction
entry points neither open nor close their caller's promotion transaction. -/
namespace VerifiedCore.Authorization
open Host

def bindingColumns : List String :=
  ["origin_id", "node_id", "source", "domain", "issuer", "spaces", "read_only", "note", "added_at", "expires_at"]

def readBindings (tx : Transaction) (equals : Fields) : Action (List Binding) := do
  let scan ← storage (.scanRows tx "bindings" bindingColumns equals
    [⟨"origin_id", false⟩, ⟨"added_at", false⟩])
  let bindings ← scan.rows.mapM decodeBinding
  match scan.failure with
  | some failure => throw (.host failure)
  | none => return bindings

def config (tx : Transaction) (key : String) : Action (Option String) := do
  let rows ← storage (.readRows tx "config" ["value"] [("key", .text key)])
  match rows with
  | [] => return none
  | [value] :: _ => return some (← checked (textField 0 "value" value))
  | _ => throw .malformed

/-- An untrustworthy present reading is never rescued by a historical floor. -/
def trustInstant (tx : Transaction) (reading : Int64) : Action Int64 := do
  if !clockTrusted reading then return reading
  let text ← config tx "trust_clock_floor"
  return max reading ((text.bind parseI64).getD 0)

def canonicalSpaces (spaces : List String) : List String :=
  (spaces.foldl (fun (set : Std.TreeSet String) value => set.insert value) {}).toList

/-- Narrow liveness queries cache issuer reads within this invocation. A
subject's delegated binding cannot itself vouch for another delegation. -/
def liveAmong (tx : Transaction) (rows : List Binding) (now : Int64) : Action (List Binding) := do
  let mut issuers : Std.TreeMap String Bool := {}
  let mut live := []
  for binding in rows do
    if !binding.datedLive now then continue
    if binding.source == .delegated then
      let some issuerOrigin := binding.issuer | continue
      let issuer := Origin.canonical issuerOrigin
      let rooted ← match issuers[issuer]? with
        | some value => pure value
        | none => do
          let rows ← readBindings tx [("origin_id", .text issuer)]
          let value := rows.any (fun row => row.source.rooted && row.datedLive now)
          issuers := issuers.insert issuer value
          pure value
      if !rooted then continue
    live := binding :: live
  return live.reverse

def rootedOrigins (rows : List Binding) (now : Int64) : Std.TreeSet String :=
  rows.foldl (fun set binding =>
    if binding.source.rooted && binding.datedLive now then set.insert (Origin.canonical binding.origin)
    else set) {}

def supportedBy (rooted : Std.TreeSet String) (now : Int64) (binding : Binding) : Bool :=
  binding.datedLive now && (binding.source != .delegated ||
    binding.issuer.any (fun issuer => rooted.contains (Origin.canonical issuer)))

/-- The full projection already has the issuer records, so its cascade uses
one set construction, not one SQL lookup for every row. -/
def allLive (tx : Transaction) (now : Int64) : Action (List Binding) := do
  let all ← readBindings tx []
  return all.filter (supportedBy (rootedOrigins all now) now)

def liveForKey (tx : Transaction) (key : ByteArray) (now : Int64) : Action (List Binding) := do
  liveAmong tx (← readBindings tx [("node_id", .blob key)]) now

def liveForOrigin (tx : Transaction) (origin : String) (now : Int64) : Action (List Binding) := do
  liveAmong tx (← readBindings tx [("origin_id", .text origin)]) now

/-- Authority of an origin and trie serving both honor a rooted binding first.
A confined origin publishes into its read-write spaces alone: a read-only
space is outside this scope exactly as an undelegated one is, so a head
holding a key under it is refused whole. A key granted only read-only spaces
is confined to none, which still lets it advertise the content it holds. -/
def originScope (live : List Binding) : PublishScope :=
  if live.isEmpty then .untrusted
  else if live.any (·.source.rooted) then .unrestricted
  else .confined (canonicalSpaces (live.flatMap (·.spaces)))

/-- Peer publication/content scope gives a nonempty replicated delegation
priority over local rooted trust. This precedence intentionally differs from
origin publication authority and metadata serving. It is the *read* side of
the grant — what content a peer may fetch and what read scope it is declared —
so read-only spaces count in full. -/
def peerPublishScope (live : List Binding) : PublishScope :=
  if live.isEmpty then .untrusted else
  let delegated := live.filter (fun binding => binding.source == .delegated) |>.flatMap (·.readable)
  if !delegated.isEmpty then .confined (canonicalSpaces delegated)
  else originScope live

structure PeerAuthority where
  serving : Trie.Serve.Scope
  publication : PublishScope
  origins : List Origin.Parsed
  rooted : Bool
  deriving BEq, DecidableEq

/-- One indexed observation supplies the peer's scopes and attributed origins
without a second liveness read that could disagree with the first. -/
def peerAuthorityIn (tx : Transaction) (key : ByteArray) (reading : Int64) : Action PeerAuthority := do
  let now ← trustInstant tx reading
  let live ← liveForKey tx key now
  let rooted := live.any (·.source.rooted)
  let serving := if rooted then fullScope else readScope (canonicalSpaces (live.flatMap (·.readable)))
  return ⟨serving, peerPublishScope live, live.map (·.origin), rooted⟩

structure OriginAuthority where
  publication : PublishScope
  publicationKeys : Trie.Serve.Scope
  provenance : Option Origin.Parsed
  deriving BEq, DecidableEq

/-- Promotion calls this with the caller-owned transaction token, so clock
floor, issuer revocation, publication authority and provenance come from the
same snapshot as the head flip. No transaction effect occurs in this body. -/
def originAuthorityIn (tx : Transaction) (origin : Origin.Parsed) (reading : Int64) : Action OriginAuthority := do
  let now ← trustInstant tx reading
  let live ← liveForOrigin tx (Origin.canonical origin) now
  let scope := originScope live
  let own ← (← config tx "self_origin_id").mapM (originField "config.self_origin_id")
  let owner := if own == some origin || scope == .unrestricted then none else some origin
  let keys := match scope with
    | .unrestricted => fullScope
    | .untrusted => publicationScope [] []
    | .confined spaces =>
      publicationScope spaces
        ((canonicalSpaces (live.flatMap (·.readOnly))).filter (fun space => !spaces.contains space))
  return ⟨scope, keys, owner⟩

def peerAuthority (key : ByteArray) (reading : Int64) : Action PeerAuthority :=
  transaction (fun tx => peerAuthorityIn tx key reading)

def originAuthority (origin : Origin.Parsed) (reading : Int64) : Action OriginAuthority :=
  transaction (fun tx => originAuthorityIn tx origin reading)

end VerifiedCore.Authorization
