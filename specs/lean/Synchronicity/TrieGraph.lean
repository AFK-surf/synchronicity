import Synchronicity.ScopedSync
import Synchronicity.MptGc

/-!
The graph-level trie GC obligation, over the trie's own structure.

`MptGc` abstracts one root to five bits.  This file is the multi-root store
those bits are read from: which roots are retained, pending, active and
materialized, and which nodes are held.  Reachability is not a field but the
verified descent `ScopedSync.At`, so `Complete` — every node under a root is
held — is a fact about content, and `complete_iff_reach_held` shows it is what
the scoped walk under the full scope establishes.

`GcSweep` is `gc_trie`'s whole immediate transaction: the mark set is every
node reachable from any retained root, and everything else goes.  The
theorems: a sweep keeps every retained root complete
(`gc_preserves_complete_retained_root`), and every transition here projects
(`proj`) to the `MptGc` transition it abstracts, so `MptGc.TrieGc`'s two
outcomes for an unretained root — kept complete, or not — are the two things a
sweep can do to a root whose nodes another retained root may share.
-/

namespace Synchronicity.TrieGraph

open ScopedSync

/-- The trie store with its head slots, over every root at once. -/
structure State where
  /-- The GC mark roots. -/
  retained : Hash → Prop := fun _ => False
  /-- The roots a pending slot names. -/
  pending : Hash → Prop := fun _ => False
  /-- The roots a complete slot names. -/
  active : Hash → Prop := fun _ => False
  /-- The roots the derived views were rebuilt from. -/
  materialized : Hash → Prop := fun _ => False
  /-- The nodes held. -/
  held : Hash → Prop := fun _ => False

variable {c : Content} {s s' : State} {root node : Hash}

/-- `node` sits somewhere under `root`. -/
def Reaches (c : Content) (root node : Hash) : Prop := ∃ path, At c root path node

/-- The mark set: reachable from some retained root. -/
def Marked (c : Content) (s : State) (node : Hash) : Prop :=
  ∃ root, s.retained root ∧ Reaches c root node

/-- Every node under the root is held. -/
def Complete (c : Content) (s : State) (root : Hash) : Prop :=
  ∀ node, Reaches c root node → s.held node

/-- A node lands in the store. -/
def LearnNode (node : Hash) (s s' : State) : Prop :=
  s' = { s with held := add s.held node }

/-- A root enters retention. -/
def RetainRoot (root : Hash) (s s' : State) : Prop :=
  s' = { s with retained := add s.retained root }

/-- A root neither slot points at leaves retention (`prune_history_before`). -/
def DropRoot (root : Hash) (s s' : State) : Prop :=
  ¬ s.pending root ∧ ¬ s.active root ∧ s' = { s with retained := drop s.retained root }

/-- `gc.rs::Store::gc_trie`, the mark/sweep: what survives is what was held
and is reachable from a retained root; the slots are untouched. -/
@[rust_impl "mpt-trie-mark-sweep"]
def GcSweep (c : Content) (s s' : State) : Prop :=
  s'.retained = s.retained ∧ s'.pending = s.pending ∧ s'.active = s.active ∧
  s'.materialized = s.materialized ∧
  ∀ node, s'.held node ↔ s.held node ∧ Marked c s node

theorem gc_preserves_reachable_node
    (gc : GcSweep c s s') (retained : s.retained root)
    (reachable : Reaches c root node) (stored : s.held node) :
    s'.held node :=
  (gc.2.2.2.2 node).2 ⟨stored, ⟨root, retained, reachable⟩⟩

theorem gc_preserves_complete_retained_root
    (gc : GcSweep c s s') (retained : s.retained root) (complete : Complete c s root) :
    s'.retained root ∧ Complete c s' root :=
  ⟨gc.1 ▸ retained,
    fun node reachable => gc_preserves_reachable_node gc retained reachable (complete node reachable)⟩

/-- A sweep never adds a node, so completeness after it implies completeness
before. -/
theorem complete_of_gc_complete (gc : GcSweep c s s') (complete : Complete c s' root) :
    Complete c s root :=
  fun node reachable => ((gc.2.2.2.2 node).1 (complete node reachable)).1

theorem dropping_another_root_does_not_drop_retention {kept dropped : Hash}
    (different : kept ≠ dropped) (step : DropRoot dropped s s')
    (retained : s.retained kept) : s'.retained kept := by
  obtain ⟨_, _, rfl⟩ := step
  exact ⟨retained, different⟩

/-! ## What `Complete` means to the scoped walk -/

/-- The store as `ScopedSync` reads it: the held nodes, with no values or
refusals in play. -/
def store (s : State) : ScopedSync.Store := ⟨s.held, fun _ => False, fun _ _ => False⟩

/-- When every reached node is held, the full-scope walk reaches every
position under a reached one. -/
theorem reach_below_of_held (held : ∀ path x, Reach c (store s) Scope.full root path x → s.held x)
    {y : Hash} {q : Path} (hat : At c y q node) (p : Path)
    (hr : Reach c (store s) Scope.full root p y) :
    Reach c (store s) Scope.full root (p ++ q) node := by
  induction hat generalizing p with
  | here => simpa using hr
  | step hcn hchild _ ih =>
    rw [← List.append_assoc]
    exact ih _ (Reach.child hr (held _ _ hr) hcn hchild
      (Scope.admitsPath_of_full Scope.full_isFull _))

/-- Under the full scope, a root is complete exactly when every position the
walk reaches is held: `Reaches` and `Reach` agree once nothing is out of
scope. -/
theorem complete_iff_reach_held :
    Complete c s root ↔ ∀ path x, Reach c (store s) Scope.full root path x → s.held x := by
  constructor
  · intro complete path x h
    exact complete x ⟨path, h.at⟩
  · intro held node ⟨path, hat⟩
    exact held _ _ (by
      simpa using reach_below_of_held held hat []
        (Reach.root (Scope.admitsPath_of_full Scope.full_isFull _)))

/-! ## The projection to `MptGc` -/

/-- One root's five bits. -/
def proj (c : Content) (s : State) (root : Hash) : MptGc.State :=
  ⟨s.retained root, s.pending root, Complete c s root, s.active root, s.materialized root⟩

/-- `gc_trie`, read at one root, is `MptGc.TrieGc`: a retained root is left as
it was, and a root outside retention either keeps its completeness — every
node under it also lies under a retained root — or loses it. -/
theorem gcSweep_projects (gc : GcSweep c s s') (root : Hash) :
    MptGc.TrieGc (proj c s root) (proj c s' root) := by
  have ⟨hret, hpend, hact, hmat, _⟩ := gc
  by_cases retained : s.retained root
  · left
    refine ⟨retained, ?_⟩
    have : Complete c s' root ↔ Complete c s root :=
      ⟨complete_of_gc_complete gc, fun h => (gc_preserves_complete_retained_root gc retained h).2⟩
    simp only [proj, hret, hpend, hact, hmat, this]
  · right
    refine ⟨retained, ?_⟩
    by_cases complete : Complete c s' root
    · left
      have : Complete c s root := complete_of_gc_complete gc complete
      simp only [proj, hret, hpend, hact, hmat, eq_true complete, eq_true this]
    · right
      simp only [proj, hret, hpend, hact, hmat, eq_false complete]

/-- `prune_history_before`, read at the pruned root, is `MptGc.Prune`. -/
theorem dropRoot_projects (step : DropRoot root s s') :
    MptGc.Prune (proj c s root) (proj c s' root) := by
  obtain ⟨hpend, hact, rfl⟩ := step
  refine ⟨hpend, hact, ?_⟩
  simp only [proj, Complete, drop, ne_eq, not_true_eq_false, and_false]

/-- Retaining a root, read at that root, is `MptGc.Retain`. -/
theorem retainRoot_projects (step : RetainRoot root s s') :
    MptGc.Retain (proj c s root) (proj c s' root) := by
  obtain ⟨rfl⟩ := step
  simp only [proj, MptGc.Retain, Complete, add, true_or]

/-- Learning a node, read at any root, is `MptGc.LearnBatch`: completeness can
only be gained. -/
theorem learnNode_projects (step : LearnNode node s s') (root : Hash) :
    MptGc.LearnBatch (proj c s root) (proj c s' root) := by
  obtain ⟨rfl⟩ := step
  by_cases complete : Complete c { s with held := add s.held node } root
  · right
    simp only [proj, eq_true complete]
  · left
    have : ¬ Complete c s root := fun h => complete (fun n r => Or.inr (h n r))
    simp only [proj, eq_false complete, eq_false this]

end Synchronicity.TrieGraph

#lint
