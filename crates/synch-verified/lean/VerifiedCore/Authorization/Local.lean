import VerifiedCore.Authorization.Projection

/-! This node's learned read scope and materialized grants, and the complete
metadata peer admission decision. Every key-specific read is an indexed seek;
a node with no delegation does not scan unrelated peer bindings. -/
namespace VerifiedCore.Authorization
open Host

/-- `grant` is everything this node may read; `readOnly` is the part of it
this node may not publish into, once every issuer has spoken — a space one
issuer grants read-write and another read-only is read-write, since each
vouches independently and grants add. -/
structure LocalAuthority where
  ownOrigin : Option Origin.Parsed
  issuers : List Origin.Parsed
  grant : Option (List String)
  readOnly : List String
  rootedElsewhere : Bool
  deriving BEq, DecidableEq

def ownOrigin (tx : Transaction) : Action (Option Origin.Parsed) := do
  (← config tx "self_origin_id").mapM (originField "config.self_origin_id")

/-- Only public ownership columns cross this boundary. Ordering remains active
keys first and newest first; canonical own-origin key comes before these rows,
as before. The same key can occur twice and those occurrences stay observable. -/
def ownKeys (tx : Transaction) (own : Option Origin.Parsed) : Action (List ByteArray) := do
  let first := match own with
    | some (.key bytes) => [(⟨bytes.toArray⟩ : ByteArray)]
    | _ => []
  let scan ← storage (.scanRows tx "device_keys" ["node_id", "state", "created_at"] []
    [⟨"created_at", true⟩])
  let keys ← scan.rows.mapM fun row => do
    match row with
    | [key, state, created] =>
      let key ← checked (blobField 0 "node_id" key)
      let state ← checked (textField 1 "state" state)
      let _ ← checked (integerField 2 "created_at" created)
      let key ← keyField "device_keys.node_id" key
      if state != "active" && state != "retiring" && state != "staged" then
        throw (.column "device_keys.state" state)
      return (key, state == "active")
    | _ => throw .malformed
  match scan.failure with
  | some failure => throw (.host failure)
  | none =>
    -- Staged keys are owned too. Partition the time-ordered rows stably so
    -- staged and retiring keys keep their shared newest-first order.
    return first ++ (keys.filter (·.2)).map (·.1) ++ (keys.filter (!·.2)).map (·.1)

def localSpacesIn (tx : Transaction) : Action (Option (List String)) := do
  return (← config tx "local_scope").map decodeSpaces

def localAuthorityIn (tx : Transaction) (reading : Int64) : Action LocalAuthority := do
  let own ← ownOrigin tx
  let keys ← ownKeys tx own
  let now ← trustInstant tx reading
  let mut issuers := []
  let mut writable := []
  let mut readOnly := []
  let mut rootedElsewhere := false
  for key in keys do
    let live ← liveForKey tx key now
    for binding in live do
      if binding.source == .delegated then
        match binding.issuer with
        | some issuer => issuers := issuer :: issuers
        | none => pure ()
        writable := binding.spaces ++ writable
        readOnly := binding.readOnly ++ readOnly
      if binding.source.rooted && own != some binding.origin then rootedElsewhere := true
  let readable := writable ++ readOnly
  let grant := if readable.isEmpty then none else some (canonicalSpaces readable)
  let unwritable := (canonicalSpaces readOnly).filter (fun space => !writable.contains space)
  return ⟨own, issuers.reverse, grant, unwritable, rootedElsewhere⟩

def localAuthority (reading : Int64) : Action LocalAuthority := transaction fun tx => localAuthorityIn tx reading

def materializationScopeIn (tx : Transaction) (origin : Origin.Parsed) : Action Trie.Serve.Scope := do
  let own ← ownOrigin tx
  if own == some origin then return fullScope
  return (← localSpacesIn tx).map readScope |>.getD fullScope

def materializationScope (origin : Origin.Parsed) : Action Trie.Serve.Scope :=
  transaction fun tx => materializationScopeIn tx origin

def localScopeIn (tx : Transaction) : Action Trie.Serve.Scope := do
  return (← localSpacesIn tx).map readScope |>.getD fullScope

def localScope : Action Trie.Serve.Scope := transaction localScopeIn

def originDomain (origin : Origin.Parsed) : Option String :=
  match origin with
  | .named value => some value.domain
  | _ => none

inductive MetadataRefusal where
  | notFullMember
  | differentCluster
  deriving BEq, DecidableEq

/-- A delegate pulls metadata only from a rooted member of one of its issuer
clusters. A node with no live delegation is not restricted by this rule. -/
def metadataPeer (peer : ByteArray) (reading : Int64) : Action (Option MetadataRefusal) :=
  transaction fun tx => do
    let own ← localAuthorityIn tx reading
    if own.issuers.isEmpty then return none
    let now ← trustInstant tx reading
    let rows ← readBindings tx [("node_id", .blob peer)]
    let members := rows.filter (fun binding => binding.source.rooted && binding.datedLive now)
    if members.isEmpty then return some .notFullMember
    let same := members.any fun binding => own.issuers.any fun issuer =>
      binding.origin == issuer ||
        ((originDomain binding.origin).isSome && originDomain binding.origin == originDomain issuer)
    return if same then none else some .differentCluster

end VerifiedCore.Authorization
