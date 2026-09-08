import VerifiedCore.Commands
import VerifiedCore.Replication.Reconcile
import VerifiedCore.Replication.Materialize

namespace VerifiedCore.Replication.Promote
open Host Commands
inductive Error where
  | host (failure : Failure)
  | domain (failure : ReconcileDomainError)
abbrev Effects := EffectSum Materialize.Effects Host.Memo
abbrev Action (A : Type) := OperationOver Effects Error A
def attempt (p : Action A) : Action (Except Error A) := ExceptT.mk (.ok <$> p.run)
def historyError : History.Error → Error
  | .host e => .host e
  | .malformed => .domain (.history .malformed)
  | .columnType i c t => .domain (.history (.columnType i c t))
  | .invalidText b => .domain (.history (.invalidText ⟨b.toArray⟩))
  | .column c r => .domain (.history (.column c r))
  | .origin e => .domain (.history (.origin e))
def walkError : Trie.Walk.Error → Error
  | .host e => .host e
  | .missingNode h => .domain (.walk (.missingNode h))
  | .missingValue h => .domain (.walk (.missingValue h))
  | .decode m => .domain (.walk (.decode m))
  | .oddDepthValue => .domain (.walk .oddDepthValue)
  | .ceiling => .domain (.walk .ceiling)
def missingError : Trie.Missing.Error → Error
  | .host e => .host e
  | .decode m => .domain (.missing (.decode m))
  | .exhausted => .domain (.missing .exhausted)
  | .canonical (.nodeDepth n) => .domain (.missing (.nodeDepth n))
  | .canonical (.valueDepth n) => .domain (.missing (.valueDepth n))
  | .canonical (.expectedBranch h) => .domain (.missing (.expectedBranch h))
  | .canonical (.valueLength h n r) => .domain (.missing (.valueLength h n r))
def materializeError : Materialize.Error → Error
  | .host e => .host e
  | .walk e => walkError e
  | .metadata e => historyError e
  | .decode message => .domain (.walk (.decode message))
def raw (e : Storage (Reply A)) : Action A := raise Error.host e
def history (p : History.Action A) : Action A := within historyError p
def auth (p : Authorization.Action A) : Action A :=
  within (historyError ∘ Reconcile.authorizationError) p

structure Pending where
  head : Head
  received : Int64
def slot (tx : Transaction) (origin : Origin.Parsed) (name : String) : Action (Option Pending) := do
  let scan ← raw (.scanRows tx "heads" History.headColumns
    [("origin_id", .text (Origin.canonical origin)), ("slot", .text name)] [] History.headJoin)
  match scan.rows with
  | [] =>
    if let some error := scan.failure then throw (.host error)
    return none
  | row :: _ =>
    let fields ← history (History.decodeJoinedHead row)
    match row with
    | [_, _, _, .integer created, _, .blob sig, .integer received, _] =>
      return some ⟨⟨origin, fields.pointer.seq, fields.pointer.root, created, fields.publicKey, sig⟩, received⟩
    | _ => throw (historyError .malformed)
def clear (tx : Transaction) (origin : Origin.Parsed) : Action Unit := do
  let _ ← raw (.deleteRows tx "heads" [("origin_id", .text (Origin.canonical origin)), ("slot", .text "pending")])

/-- Completeness observes the same transaction as promotion's authority and
view writes. Equality-only presence projections become raw transaction scans. -/
def inTransaction (tx : Transaction) : {A : Type} → Trie.Complete.Effects A → Effects A
  | _, .left (.right (.right effect)) => Inject.inject (Materialize.redactionIn tx effect)
  | _, .left (.right (.left (.snapshot selection columns))) =>
    if selection.likeAny.isEmpty && selection.notEquals.isEmpty then
      Inject.inject (Storage.scanRows tx selection.relation columns selection.equals)
    else Inject.inject (Access.snapshot selection columns)
  | _, effect => Inject.inject effect

def body (tx : Transaction) (origin : Origin.Parsed) (now : Int64) (pending : Pending)
    (old : Option Pending) (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority) : Action Promotion := do
  if old.any (fun old => !Reconcile.newer pending.head.seq pending.head.root ⟨old.head.seq, old.head.root⟩) then
    clear tx origin
    return .idle
  let complete : Action Bool := ExceptT.mk
    ((Trie.Complete.isComplete (Std.HashSet Trie.Missing.Visit) (Std.HashSet ByteArray)
      ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root).run.mapEffects (inTransaction tx)
      |> fun program => Except.mapError missingError <$> program)
  if !(← complete) then return .waiting
  let allowed ← match authority.publication with
    | .untrusted => pure false
    | .unrestricted => pure true
    | .confined _ =>
      (·.isNone) <$> within walkError (ExceptT.mk
        ((Trie.ScopeCheck.firstOutside pending.head.root authority.publicationKeys).run.mapEffects
          (fun {A} (effect : Trie.Walk.Effects A) => match effect with
            | .left e => Inject.inject e
            | .right e => Inject.inject (Materialize.redactionIn tx e)) : Program Materialize.Effects _))
  if !allowed then
    clear tx origin
    return .refused
  history (Reconcile.putSlot tx "complete" pending.head pending.received now)
  clear tx origin
  let oldRoot := old.map (·.head.root) |>.getD Trie.emptyRoot
  let _ ← within materializeError (Materialize.materialize tx origin oldRoot pending.head.root)
  return .flipped

/-- Missing old backing and host failures are retryable. Structural or record
refusals retire only the version judged, after rollback, and report its memo key.
Permission refusals are deliberately not memoized because grants can change. -/
def originFault : ReconcileDomainError → Bool
  | .history (.columnType ..) | .history (.invalidText _) | .history .malformed => false
  | _ => true

def promote (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray)) :
    Action PromotionReport := do
  let tx ← raw .begin
  let prepared ← attempt (do
    let scope ← auth (Authorization.materializationScopeIn tx origin)
    let authority ← auth (Authorization.originAuthorityIn tx origin now)
    let pending ← slot tx origin "pending"
    let old ← if pending.isSome then slot tx origin "complete" else pure none
    return (scope, authority, pending, old) : Action _)
  let (scope, authority, pending, old) ← match prepared with
    | .ok value => pure value
    | .error error =>
      let _ ← attempt (raw (.rollback tx))
      throw error
  let key := pending.map (fun p => (p.head.seq, p.head.root, old.map (·.head.root) |>.getD Trie.emptyRoot))
  let result ← attempt (do
    match pending with
    | none => pure Promotion.idle
    | some pending =>
      if key.any refused.contains then
        clear tx origin
        return .refused
      body tx origin now pending old scope authority : Action Promotion)
  match result with
  | .ok promotion =>
    match ← attempt (raw (.commit tx)) with
    | .ok () => return ⟨promotion, none, none⟩
    | .error error =>
      let _ ← attempt (raw (.rollback tx))
      throw error
  | .error error =>
    let _ ← attempt (raw (.rollback tx))
    match error with
    | .host _ => throw error
    | .domain failure =>
      if originFault failure then
        if let some pending := pending then
          transactionOver Inject.inject Error.host fun tx => do
            let _ ← raw (.deleteRows tx "heads"
              (Reconcile.headKey pending.head ++ [("slot", .text "pending")]))
          return ⟨.refused, some failure, key⟩
      throw error

end VerifiedCore.Replication.Promote
