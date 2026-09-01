/-!
The graph-level trie GC obligation omitted by the one-root boolean model.

`reachable root node` is the result of the verified MPT walk. A collection is
safe exactly when its mark set contains every stored node reachable from every
retained root. This model also permits retention removal and later learning of
new nodes; neither operation can make a GC sweep forget a retained node.
-/

namespace Synchronicity.TrieGraph

abbrev Root := Nat
abbrev Node := Nat

structure State where
  retained : Root → Prop := fun _ => False
  reachable : Root → Node → Prop := fun _ _ => False
  stored : Node → Prop := fun _ => False

def Marked (s : State) (node : Node) : Prop :=
  ∃ root, s.retained root ∧ s.reachable root node

def Complete (s : State) (root : Root) : Prop :=
  ∀ node, s.reachable root node → s.stored node

def add (p : Nat → Prop) (value : Nat) : Nat → Prop :=
  fun candidate => candidate = value ∨ p candidate

def drop (p : Nat → Prop) (value : Nat) : Nat → Prop :=
  fun candidate => p candidate ∧ candidate ≠ value

def LearnNode (node : Node) (s s' : State) : Prop :=
  s' = { s with stored := add s.stored node }

def RetainRoot (root : Root) (s s' : State) : Prop :=
  s' = { s with retained := add s.retained root }

def DropRoot (root : Root) (s s' : State) : Prop :=
  s' = { s with retained := drop s.retained root }

/- RUST-IMPL: mpt-trie-mark-sweep — `gc.rs::Store::gc_trie` mark/sweep. -/
def GcSweep (s s' : State) : Prop :=
  s'.retained = s.retained ∧
  s'.reachable = s.reachable ∧
  ∀ node, s'.stored node ↔ s.stored node ∧ Marked s node

theorem gc_preserves_reachable_node
    (gc : GcSweep s s') (retained : s.retained root)
    (reachable : s.reachable root node) (stored : s.stored node) :
    s'.stored node := by
  exact (gc.2.2 node).2 ⟨stored, ⟨root, retained, reachable⟩⟩

theorem gc_preserves_complete_retained_root
    (gc : GcSweep s s') (retained : s.retained root)
    (complete : Complete s root) :
    s'.retained root ∧ Complete s' root := by
  constructor
  · simpa [gc.1] using retained
  · intro node reachable'
    have reachable : s.reachable root node := by
      simpa [gc.2.1] using reachable'
    exact gc_preserves_reachable_node gc retained reachable (complete node reachable)

theorem dropping_another_root_does_not_drop_retention
    (different : kept ≠ dropped) (step : DropRoot dropped s s')
    (retained : s.retained kept) : s'.retained kept := by
  rcases step with ⟨rfl⟩
  exact ⟨retained, different⟩

end Synchronicity.TrieGraph
