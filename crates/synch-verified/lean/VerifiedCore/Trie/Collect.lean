import VerifiedCore.Trie.Program
import VerifiedCore.Trie.Memo
import VerifiedCore.Host.Memo
import VerifiedCore.Cas.Codec
import VerifiedCore.Origin
import Std.Data.HashSet.Basic

/-! Collecting the trie: mark everything the retained heads reach, then
sweep every node, provenance row and out-of-line value the mark missed,
keeping the completeness certificates of exactly the roots this snapshot
marked from. The whole pass is one immediate transaction: the retained
roots, the mark walk, the memo and the sweeps. Splitting it is a data-loss
bug, because a publish landing between the mark and the sweep would have
its nodes swept while its head row survives pointing at them. -/
namespace VerifiedCore.Trie.Collect

open Host

/-- The set the mark walk records addresses in. The walk is written once
over this interface; the command runs it over a hash set, and the proofs
run the same walk over a list the kernel can evaluate. -/
class MarkSet (S : Type) where
  empty : S
  contains : S → ByteArray → Bool
  insert : S → ByteArray → S
  toList : S → List ByteArray

instance : MarkSet (Std.HashSet ByteArray) := ⟨{}, (·.contains ·), (·.insert ·), (·.toList)⟩

instance : MarkSet (List ByteArray) :=
  ⟨[], (·.contains ·), fun set hash => if set.contains hash then set else hash :: set, id⟩

inductive Error where
  | host (failure : Failure)
  /-- A stored node on the walk does not decode. -/
  | decode (message : String)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | column (column : String) (reason : String)
  | origin (error : Origin.Error)
  /-- The mark walk outran its budget: nothing is swept. -/
  | exhausted
  deriving BEq, DecidableEq

abbrev Effects := EffectSum Storage (EffectSum Digest Memo)
abbrev Action (A : Type) := OperationOver Effects Error A

def storage (effect : Storage (Reply A)) : Action A := raise Error.host effect
def memo (effect : Memo (Reply A)) : Action A := raise Error.host effect

def transaction (body : Transaction → Action A) : Action A :=
  transactionOver Inject.inject Error.host body

/-- The nodes a node names below itself. -/
def _root_.VerifiedCore.Trie.Node.childHashes : Node → List ByteArray
  | .branch children _ => children.filterMap id
  | .extension _ child => [child]
  | .leaf _ _ => []

/-! ## The mark -/

/-- What the walk has reached: nodes by address, and the out-of-line values
those nodes name. -/
structure Marks (S : Type) where
  nodes : S
  values : S

/-- Far past any store; the budget only retains the corrupted-store
behaviour, and running out sweeps nothing. -/
def markFuel : Nat := 2 ^ 40

/-- Mark everything reachable from the frontier, depth first, one node read
per address. A node already marked is not read again, so successive roots
that share all but the path that changed cost their delta; a node this
store does not hold is marked and skipped, so a partially fetched pending
head marks what it has. -/
def mark [MarkSet S] : Nat → List ByteArray → Marks S → Action (Marks S)
  | _, [], marks => pure marks
  | 0, _ :: _, _ => throw .exhausted
  | fuel + 1, hash :: frontier, marks =>
    if MarkSet.contains marks.nodes hash then mark fuel frontier marks
    else do
      let marks := { marks with nodes := MarkSet.insert marks.nodes hash }
      match ← storage (.readBytes nodeSpace hash) with
      | none => mark fuel frontier marks
      | some raw =>
        match decode raw with
        | .error message => throw (.decode message)
        | .ok node =>
          mark fuel (node.childHashes ++ frontier)
            { marks with values := node.valueHashes.foldl MarkSet.insert marks.values }

/-! ## The retained roots -/

/-- One head row: the origin it was signed by, canonical as written, and
its root. -/
def decodeHead : Row → Except Error (String × ByteArray)
  | [.text origin, .blob root] =>
    match Origin.checkSyntax origin with
    | .error error => .error (.origin error)
    | .ok () =>
      if root.size == 32 then .ok (origin, root)
      else .error (.column "head_history.root" (toString root.size ++ " bytes, not 32"))
  | [.rawText _, _] => .error (.column "head_history.origin_id" "not valid UTF-8")
  | [cell, .blob _] => .error (.columnType 0 "origin_id" (Cas.Codec.cellType cell))
  | [_, cell] => .error (.columnType 1 "root" (Cas.Codec.cellType cell))
  | _ => .error .malformed

/-- Each root once, in the set's order. -/
def distinct (S : Type) [MarkSet S] (roots : List ByteArray) : List ByteArray :=
  MarkSet.toList (roots.foldl MarkSet.insert (MarkSet.empty : S))

/-- The keys of the scoped answers for the roots. -/
def scopedKeys (scope : Serve.Scope) : List ByteArray → Action (List ByteArray)
  | [] => pure []
  | root :: rest => do
    let key ← Memo.scopedKey Error.host scope root
    let others ← scopedKeys scope rest
    return key :: others

/-- The keys of the owned answers for each head: under the local scope and
under the whole keyspace, since a member and a delegate ask both. -/
def ownedKeys (scope : Serve.Scope) : List (String × ByteArray) → Action (List ByteArray)
  | [] => pure []
  | (origin, root) :: rest => do
    let narrowed ← Memo.keyFor Error.host scope root (some origin)
    let whole ← Memo.keyFor Error.host ⟨none, []⟩ root (some origin)
    let others ← ownedKeys scope rest
    return narrowed :: whole :: others

/-! ## The pass -/

/-- One mark-and-sweep pass, in one transaction: every head row's root is
marked from; the certificates kept are those of exactly the roots marked
from, under this scope and as each origin's own; then each relation is
swept set-wise against the mark. Answers the nodes and values swept and the
roots marked from. -/
def gcTrie (S : Type) [MarkSet S] (scope : Serve.Scope) : Action (UInt64 × UInt64 × UInt64) :=
  transaction fun tx => do
    let rows ← storage (.readRows tx "head_history" ["origin_id", "root"] [] [] [])
    let heads ← ExceptT.mk (.pure (rows.mapM decodeHead))
    let roots := distinct S (heads.map (·.2))
    let marks ← mark (S := S) markFuel (roots.filterMap rootOf) ⟨MarkSet.empty, MarkSet.empty⟩
    let narrowed ← scopedKeys scope roots
    let owned ← ownedKeys scope heads
    memo (.forgetExcept (roots ++ narrowed ++ owned))
    let nodes := MarkSet.toList marks.nodes
    let sweptNodes ← storage (.deleteExcept tx nodeSpace "hash" nodes)
    let _ ← storage (.deleteExcept tx "trie_node_origins" "hash" nodes)
    let sweptValues ← storage (.deleteExcept tx valueSpace "hash" (MarkSet.toList marks.values))
    return (sweptNodes.toUInt64, sweptValues.toUInt64, roots.length.toUInt64)

end VerifiedCore.Trie.Collect
