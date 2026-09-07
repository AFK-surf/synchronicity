import VerifiedCore.Trie.Complete
import VerifiedCore.Trie.Mutate
import VerifiedCore.Host.Peer

/-! The requesting operation, including the frontier across network waits.
Transactions surround inspection and admission, never the peer request.
A peer refusal is not evidence of absence and earns no progress. -/
namespace VerifiedCore.Trie.Fetch
open Host Missing

inductive Error where
  | host (failure : Failure)
  | walk (error : Missing.Error)
  | origin (refusal : Refusal)
  | nodeHash (hash : ByteArray)
  | valueHash (hash : ByteArray)
  | unsolicited (value : Bool) (hash : ByteArray)
  | exhausted

abbrev Effects := EffectSum Missing.Effects
  (EffectSum Digest (EffectSum Host.Memo (EffectSum Peer Clock)))
abbrev Action (A : Type) := OperationOver Effects Error A

def request [Inject E Effects] (effect : E (Reply A)) : Action A := raise Error.host effect

/-- The requesting walk's row-presence reads belong to the batch snapshot.
Its selections contain only equality predicates; no filtering is discarded. -/
def inTransaction (tx : Transaction) : {A : Type} → Missing.Effects A → Effects A
  | _, .right (.left (.snapshot selection columns)) =>
    if selection.likeAny.isEmpty && selection.notEquals.isEmpty then
      Inject.inject (Storage.scanRows tx selection.relation columns selection.equals)
    else Inject.inject (Access.snapshot selection columns)
  | _, effect => Inject.inject effect

structure State (V H : Type) where
  frontier : Frontier V H
  generation : UInt64
  unproductive : Nat := 0
  uncertified : Nat := 0

structure Target where
  root : ByteArray
  origin : String
  seq : UInt64
  context : Context

def targetRows (target : Target) : Fields :=
  [("origin_id", .text target.origin), ("slot", .text "pending"),
    ("seq", .integer (Int64.ofInt target.seq.toNat)), ("root", .blob target.root)]

def inspect [WorkSet Visit V] [WorkSet ByteArray H] (target : Target)
    (state : State V H) (maximum : Nat) : Action (State V H × Batch × Bool) :=
  transactionOver Inject.inject Error.host fun tx => do
    let generation ← request Host.Memo.generation
    let frontier := if generation == state.generation then state.frontier
      else initial target.context none target.root
    let (frontier, result) ← ExceptT.mk
      ((nextBatch target.context frontier maximum).run.mapEffects (inTransaction tx)
        |>.bind (fun result => .pure (result.mapError Error.walk)))
    let batch ← match result with
      | .ok batch => pure batch
      | .error error => throw (.walk error)
    let certified ← if frontier.isExhausted then do
      let key ← Memo.keyFor Error.host target.context.scope target.root target.context.owner
      request (Host.Memo.certify key generation)
      else pure false
    return ({ state with frontier, generation }, batch, certified)

/-- One answer is admitted atomically, under only the requested addresses.
Invalid origin values remain missing; valid bytes already committed by
earlier answers remain useful if a later answer fails or is cancelled. -/
def admit [WorkSet ByteArray H] (target : Target) (values : Bool)
    (requested : List (ByteArray × ByteArray)) (served : List (ByteArray × ByteArray))
    (routeValues : List ByteArray := []) :
    Action Nat := transactionOver Inject.inject Error.host fun tx => do
  let mut outstanding : H := requested.foldl
    (fun set (_, hash) => WorkSet.insert set hash) (WorkSet.empty ByteArray)
  let mut learned := 0
  for (hash, bytes) in served do
    if !WorkSet.contains outstanding hash then throw (.unsolicited values hash)
    outstanding := WorkSet.erase outstanding hash
    if values then
      if (← request (Digest.blake3 bytes)) != hash then throw (.valueHash hash)
      if (bytes.size > inlineValueMax || routeValues.contains hash) && bytes.size ≤ maxValueBytes then
        request (Storage.upsert tx valueSpace [("hash", .blob hash), ("data", .blob bytes)] ["hash"] [])
        learned := learned + 1
    else
      match ← within Error.host (Trie.verify hash bytes) with
      | .peerFault => throw (.nodeHash hash)
      | .originFault refusal => throw (.origin refusal)
      | .accepted =>
        request (Storage.upsert tx nodeSpace [("hash", .blob hash), ("data", .blob bytes)] ["hash"] [])
        match target.context.owner with
        | none => pure ()
        | some origin => request (Storage.upsert tx "trie_node_origins"
            [("origin_id", .text origin), ("hash", .blob hash)] ["origin_id", "hash"] [])
        learned := learned + 1
  return learned

/-- A stale fetch may neither refresh nor delete a different pending version. -/
def touch (target : Target) : Action Unit := do
  let now ← request Clock.nowNs
  transactionOver Inject.inject Error.host fun tx => do
    let _ ← request (Access.update tx ⟨"heads", targetRows target, [], []⟩ [("received_at", .integer now)])

def abandon (target : Target) : Action Unit :=
  transactionOver Inject.inject Error.host fun tx => do
    let _ ← request (Storage.deleteRows tx "heads" (targetRows target))

/-- `true` asks promotion to recheck this view in its own transaction;
`false` reports abandonment after repeated replies without verified progress. -/
def step [WorkSet Visit V] [WorkSet ByteArray H] (target : Target)
    (maximum retryLimit : Nat) (state : State V H) : Action (State V H ⊕ Bool) := do
  let (state, missing, certified) ← inspect target state maximum
  if missing.isEmpty then
    if certified then return .inr true
    let state := if state.frontier.isExhausted then
        { state with
          uncertified := state.uncertified + 1
          frontier := initial target.context none target.root }
      else state
    if state.uncertified ≥ retryLimit then return .inr true
    return .inl { state with frontier := resume target.context state.frontier }
  let mut learned := 0
  if !missing.nodes.isEmpty then
    let (served, _, _) ← request (Peer.fetchNodes target.root missing.nodes)
    learned := learned + (← admit (H := H) target false missing.nodes served)
  if !missing.values.isEmpty then
    let (served, _) ← request (Peer.fetchValues target.root missing.values)
    learned := learned + (← admit (H := H) target true missing.values served missing.routeValues)
  let unproductive := if learned == 0 then state.unproductive + 1 else 0
  if unproductive ≥ retryLimit then
    abandon target
    return .inr false
  if learned > 0 then touch target
  return .inl { state with unproductive, frontier := resume target.context state.frontier }

/-- This operation retains the frontier in its Lean continuation. The
reference is used only under the generation at which it was established. -/
def fetch (V H : Type) [WorkSet Visit V] [WorkSet ByteArray H]
    (target : Target) (reference : Option ByteArray)
    (maximum retryLimit : Nat) : Action Bool := do
  let generation ← request Host.Memo.generation
  let reference ← match reference with
    | none => pure none
    | some root => do
      if ← within Error.walk (Complete.isComplete V H target.context root) then pure (some root)
      else pure none
  OperationOver.iterate (step (V := V) (H := H) target maximum retryLimit) .exhausted batchFuel
    ⟨initial target.context reference target.root, generation, 0, 0⟩

end VerifiedCore.Trie.Fetch
