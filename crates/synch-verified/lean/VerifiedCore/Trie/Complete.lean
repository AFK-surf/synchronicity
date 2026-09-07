import VerifiedCore.Trie.Missing
import VerifiedCore.Trie.Memo
import VerifiedCore.Host.Memo

/-! Completeness is the requesting walk's exhaustion, guarded by the host's
memo generation. A concurrent invalidation can turn an exhausted walk into
a refusal to certify, never into a certificate about a stale snapshot.
This operation owns no transaction: a caller may supply an existing one,
and an ordinary raw store instead uses the generation guard. -/
namespace VerifiedCore.Trie.Complete
open Host Missing

abbrev Effects := EffectSum Missing.Effects (EffectSum Digest Host.Memo)
abbrev Action (A : Type) := OperationOver Effects Missing.Error A

def memo (effect : Host.Memo (Reply A)) : Action A := raise Missing.Error.host effect

/-- The same requesting walk, lifted into the completeness algebra without
changing a read or serializing its frontier. -/
def inspectRoot (V H : Type) [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) : Action (BatchResult V H) :=
  ExceptT.mk ((nextBatch context (initial (V := V) (H := H) context none root) 1).run.mapEffects Inject.inject)

/-- Inspect once, stopping at the first missing item. Only an exhausted
frontier is offered to the memo, under exactly the ticket read before the
walk. A host or domain failure is returned before any certification. -/
def recheck (V H : Type) [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root key : ByteArray) : Action Bool := do
  let generation ← memo .generation
  let (frontier, result) ← inspectRoot V H context root
  match result with
  | .error error => throw error
  | .ok _ =>
    if frontier.isExhausted then memo (.certify key generation) else pure false

/-- The key includes scope and provenance. A known certificate needs no
walk; every new certificate comes from the generation-guarded recheck. -/
def isComplete (V H : Type) [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) : Action Bool := do
  let key ← Memo.keyFor Missing.Error.host context.scope root context.owner
  if ← memo (.isKnown key) then return true
  recheck V H context root key

end VerifiedCore.Trie.Complete
