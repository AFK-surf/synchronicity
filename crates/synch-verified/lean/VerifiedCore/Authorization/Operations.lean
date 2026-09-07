import VerifiedCore.Authorization.Local

namespace VerifiedCore.Authorization
open Host

/-- Connection/head gates are complete indexed authorization reads. The
caller does not reimplement binding membership from a returned row list. -/
def trustedKey (key : ByteArray) (reading : Int64) : Action Bool := transaction fun tx => do
  let now ← trustInstant tx reading
  return !(← liveForKey tx key now).isEmpty

def bound (origin : Origin.Parsed) (key : ByteArray) (reading : Int64) : Action Bool := transaction fun tx => do
  let now ← trustInstant tx reading
  return (← liveForKey tx key now).any (·.origin == origin)

/-- Scope-only callers do not acquire an unrelated dependency on the local
identity configuration. Promotion uses the richer originAuthorityIn instead. -/
def originPublication (origin : Origin.Parsed) (reading : Int64) : Action PublishScope :=
  transaction fun tx => do
    let now ← trustInstant tx reading
    return originScope (← liveForOrigin tx (Origin.canonical origin) now)

def localSpaces : Action (Option (List String)) := transaction localSpacesIn

def hasDelegations : Action Bool := transaction fun tx =>
  storage (.existsRows tx "bindings" [("source", .text "delegated")])

/-- DNS entries can be refreshed after expiration. Delegated bindings are
materialized views and must remain present for the next delta/revocation. -/
def expireDns (reading : Int64) : Action Nat := transaction fun tx => do
  let now ← trustInstant tx reading
  if !clockTrusted now then return 0
  storage (.deleteRows tx "bindings" [("source", .text "dns")] [] [("expires_at", .integer now)])

end VerifiedCore.Authorization
