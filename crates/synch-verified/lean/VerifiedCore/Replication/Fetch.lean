import VerifiedCore.Replication.Promote

namespace VerifiedCore.Replication.Fetch
open Host Commands
abbrev Effects := EffectSum Promote.Effects Peer
abbrev Action (A : Type) := OperationOver Effects Promote.Error A
def attempt (p : Action A) : Action (Except Promote.Error A) := ExceptT.mk (.ok <$> p.run)
def lift (p : Promote.Action A) : Action A := within id p
def fetchError : Trie.Fetch.Error → Promote.Error
  | .host e => .host e
  | .walk e => Promote.missingError e
  | .origin e => .domain (.fetch (.origin e))
  | .nodeHash h => .domain (.fetch (.nodeHash h))
  | .valueHash h => .domain (.fetch (.valueHash h))
  | .unsolicited v h => .domain (.fetch (.unsolicited v h))
  | .exhausted => .domain (.fetch .exhausted)
def originFault : ReconcileDomainError → Bool
  | .fetch (.nodeHash _) | .fetch (.valueHash _) | .fetch (.unsolicited ..) | .fetch .exhausted => false
  | e => Promote.originFault e

def fetch (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
    (refused : List (UInt64 × ByteArray × ByteArray)) (maximum retryLimit : Nat) : Action FetchReport := do
  let selected ← lift (transactionOver Inject.inject Promote.Error.host fun tx => do
    let pending ← Promote.slot tx origin "pending"
    let some pending := pending | return none
    if expected.any (fun e => e != (pending.head.seq, pending.head.root)) then return none
    let now ← raise Promote.Error.host Clock.nowNs
    let scope ← Promote.auth (Authorization.materializationScopeIn tx origin)
    let old ← Promote.slot tx origin "complete"
    let authority ← Promote.auth (Authorization.originAuthorityIn tx origin now)
    return some (pending, old, scope, authority.provenance))
  let some (pending, old, scope, owner) := selected | return ⟨⟨.idle, none, none⟩, false⟩
  let reference := old.map (·.head.root)
  let key := (pending.head.seq, pending.head.root, reference.getD Trie.emptyRoot)
  let target : Trie.Fetch.Target := ⟨pending.head.root, Origin.canonical origin, pending.head.seq,
    ⟨scope, owner.map Origin.canonical⟩⟩
  if refused.contains key then
    within fetchError (Trie.Fetch.abandon target)
    return ⟨⟨.refused, none, none⟩, false⟩
  let result ← attempt (within fetchError (Trie.Fetch.fetch (Std.HashSet Trie.Missing.Visit)
    (Std.HashSet ByteArray) target reference maximum retryLimit))
  match result with
  | .ok false => return ⟨⟨.idle, none, none⟩, true⟩
  | .ok true =>
    let now ← raise Promote.Error.host Clock.nowNs
    return ⟨← lift (Promote.promote origin now refused), false⟩
  | .error (.domain error) =>
    if originFault error then
      within fetchError (Trie.Fetch.abandon target)
      return ⟨⟨.refused, some error, some key⟩, false⟩
    throw (.domain error)
  | .error error => throw error

end VerifiedCore.Replication.Fetch
