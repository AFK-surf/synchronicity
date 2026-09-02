import Synchronicity.ScopedSync
import Synchronicity.MptGc

/-!
The trie store over every root at once, and its projection to `MptGc`.

`MptGc` abstracts one root to five bits.  This file is the multi-root store
those bits are read from: which roots are retained, pending, active and
materialized, and the node store itself.  `Complete` is not a field but
`ScopedSync.CompleteWithin` over the store under the node's read scope — the
same fact `Convergence.stuck_complete` establishes and the memo records — so
the `complete` bit has one meaning throughout.

`GcSweep` is `gc_trie`'s whole immediate transaction: the mark set is every
node the unscoped walk reaches from any retained root, the marked values are
theirs, and everything else goes.  The learning steps are a delegate's
`ScopedSync.Learn` seen at the store, with one guard: `LearnNode` takes a node
no position ever refused.  A node refused at one position and later held from
another is the one Rust `put_node` this model has no step for; it is exactly
the case in which the completeness memo Rust keeps can go stale, and the
trust-boundary note in the README says so.

The theorems: a sweep keeps a retained root complete, and keeps it incomplete
(`gcSweep_complete_iff`); every step, read at any root, is an `MptGc`
transition (`step_projects`); so the per-root system is a simulation of this
one (`simulates`), and every `MptGc` invariant holds of every root here.
-/

namespace Synchronicity.TrieGraph

open ScopedSync

/-- The trie store with its head slots, over every root at once. -/
structure State where
  /-- The GC mark roots. -/
  retained : Set Hash := ∅
  /-- The roots a pending slot names. -/
  pending : Set Hash := ∅
  /-- The roots a complete slot names. -/
  active : Set Hash := ∅
  /-- The roots the derived views were rebuilt from. -/
  materialized : Set Hash := ∅
  /-- The node store. -/
  store : ScopedSync.Store := {}

variable {c : Content} {s : Scope} {st st' : State} {root x v : Hash} {path : Path}

/-- The mark set: reached from some retained root by the unscoped walk through
held nodes (`Trie::reach_into`). -/
def Marked (c : Content) (st : State) (node : Hash) : Prop :=
  ∃ root ∈ st.retained, ∃ path, Reach c st.store Scope.full root path node

/-- The values the mark descent found: those of marked held nodes. -/
def MarkedValue (c : Content) (st : State) (v : Hash) : Prop :=
  ∃ node n, Marked c st node ∧ node ∈ st.store.held ∧ c node = some n ∧ n.valueHash = some v

/-- A root is complete within the node's read scope. -/
def Complete (c : Content) (s : Scope) (st : State) (root : Hash) : Prop :=
  CompleteWithin c st.store s root

/-! ## The transitions -/

/-- A node lands in the store (`put_node`), at a hash no position refused. -/
@[transition]
def LearnNode (x : Hash) : Transition State where
  guard st := ∀ p, (p, x) ∉ st.store.redacted
  post st := { st with store := { st.store with held := insert x st.store.held } }

/-- A value lands in the store (`put_value`). -/
@[transition]
def LearnValue (v : Hash) : Transition State where
  guard _ := True
  post st := { st with store := { st.store with heldValue := insert v st.store.heldValue } }

/-- A refusal is remembered (`note_redacted`). -/
@[transition]
def Refuse (p : Path) (x : Hash) : Transition State where
  guard _ := True
  post st := { st with store := { st.store with redacted := insert (p, x) st.store.redacted } }

/-- `gc.rs::Store::gc_trie`, the mark/sweep: what survives is what was held
and is marked; the slots and the refusals are untouched. -/
@[transition, rust_impl "mpt-trie-mark-sweep"]
def GcSweep (c : Content) : Transition State where
  guard _ := True
  post st := { st with store := { st.store with
    held := {x ∈ st.store.held | Marked c st x}
    heldValue := {v ∈ st.store.heldValue | MarkedValue c st v} } }

/-- A root enters retention without a slot (`MptGc.Retain`). -/
@[transition]
def RetainRoot (root : Hash) : Transition State where
  guard _ := True
  post st := { st with retained := insert root st.retained }

/-- A root neither slot points at leaves retention (`prune_history_before`). -/
@[transition]
def DropRoot (root : Hash) : Transition State where
  guard st := root ∉ st.pending ∧ root ∉ st.active
  post st := { st with retained := st.retained \ {root} }

/-- A root takes the pending slot (`MptGc.OfferPending`). -/
@[transition]
def OfferPending (root : Hash) : Transition State where
  guard _ := True
  post st := { st with retained := insert root st.retained, pending := insert root st.pending }

/-- A root leaves the pending slot (`MptGc.DropPending`). -/
@[transition]
def DropPending (root : Hash) : Transition State where
  guard _ := True
  post st := { st with pending := st.pending \ {root} }

/-- A root is displaced from the complete slot (`MptGc.Supersede`). -/
@[transition]
def Supersede (root : Hash) : Transition State where
  guard _ := True
  post st := { st with active := st.active \ {root}, materialized := st.materialized \ {root} }

/-- The complete pending root takes the slot (`MptGc.Promote`). -/
@[transition]
def Promote (c : Content) (s : Scope) (root : Hash) : Transition State where
  guard st := root ∈ st.pending ∧ root ∈ st.retained ∧ Complete c s st root
  post st := { st with
    pending := st.pending \ {root}
    active := insert root st.active
    materialized := insert root st.materialized }

/-- This node's own head, whole by construction (`MptGc.OwnPublish`). -/
@[transition]
def OwnPublish (c : Content) (s : Scope) (root : Hash) : Transition State where
  guard st := Complete c s st root
  post st := { st with
    retained := insert root st.retained
    pending := st.pending \ {root}
    active := insert root st.active
    materialized := insert root st.materialized }

/-- The transitions, named. -/
inductive Kind where
  | learnNode (x : Hash) | learnValue (v : Hash) | refuse (p : Path) (x : Hash) | gcSweep
  | retainRoot (root : Hash) | dropRoot (root : Hash) | offerPending (root : Hash)
  | dropPending (root : Hash) | supersede (root : Hash) | promote (root : Hash)
  | ownPublish (root : Hash)

/-- The transition each kind names. -/
@[transition]
def Trans (c : Content) (s : Scope) : Kind → Transition State
  | .learnNode x => LearnNode x
  | .learnValue v => LearnValue v
  | .refuse p x => Refuse p x
  | .gcSweep => GcSweep c
  | .retainRoot root => RetainRoot root
  | .dropRoot root => DropRoot root
  | .offerPending root => OfferPending root
  | .dropPending root => DropPending root
  | .supersede root => Supersede root
  | .promote root => Promote c s root
  | .ownPublish root => OwnPublish c s root

/-- Some transition took the store from `st` to `st'`. -/
def Step (c : Content) (s : Scope) (st st' : State) : Prop := ∃ k, (Trans c s k).rel st st'

/-- The multi-root system, from the empty store. -/
def system (c : Content) (s : Scope) : System State := ⟨{}, Step c s⟩

/-! ## What keeps a root complete -/

/-- Completeness survives a store change that keeps every position the walk
reaches, every node held at one, every boundary, and every value of a held
node. -/
theorem complete_of_le {st st' : ScopedSync.Store}
    (hreach : ∀ p x, Reach c st' s root p x → Reach c st s root p x)
    (hheld : ∀ p x, Reach c st s root p x → x ∈ st.held → x ∈ st'.held)
    (hb : ∀ p x, Reach c st s root p x → Boundary s st p x → Boundary s st' p x)
    (hval : ∀ p x n v, Reach c st s root p x → x ∈ st.held → c x = some n →
      n.valueHash = some v → v ∈ st.heldValue → v ∈ st'.heldValue)
    (hc : CompleteWithin c st s root) : CompleteWithin c st' s root := by
  intro p x hr'
  have hr := hreach p x hr'
  obtain ⟨hpos, hvals⟩ := hc p x hr
  refine ⟨?_, fun hnb n v hcn hv => ?_⟩
  · exact hpos.elim (fun h => Or.inl (hheld p x hr h)) (fun h => Or.inr (hb p x hr h))
  · rcases hpos with held | bnd
    · exact hval p x n v hr held hcn hv (hvals (held_not_boundary held) n v hcn hv)
    · exact absurd (hb p x hr bnd) hnb

/-- A node no position refused, absent from a complete store, is reached
nowhere, so holding it reaches nothing new. -/
theorem reach_insert_of_complete {st : ScopedSync.Store} (hc : CompleteWithin c st s root)
    (hx : x ∉ st.held) (hred : ∀ p, (p, x) ∉ st.redacted) {y : Hash}
    (h : Reach c { st with held := insert x st.held } s root path y) : Reach c st s root path y := by
  induction h with
  | root hadm _ => exact Reach.root hadm
  | child hw hheld hcn hchild hadm _ ih =>
    rcases Set.mem_insert_iff.mp hheld with rfl | held
    · rcases (hc _ _ ih).1 with held | bnd
      · exact absurd held hx
      · exact absurd bnd.2.2 (hred _)
    · exact Reach.child ih held hcn hchild hadm

theorem learnNode_complete (hg : ∀ p, (p, x) ∉ st.store.redacted) (hc : Complete c s st root) :
    Complete c s ((LearnNode x).post st) root := by
  by_cases hx : x ∈ st.store.held
  · simpa [LearnNode, Set.insert_eq_of_mem hx] using hc
  · refine complete_of_le (st' := ((LearnNode x).post st).store)
      (fun _ _ h => reach_insert_of_complete hc hx hg h) (fun _ _ _ h => Set.mem_insert_of_mem _ h)
      (fun p y _ ⟨hy, hin, hred⟩ => ⟨fun h => ?_, hin, hred⟩) (fun _ _ _ _ _ _ _ _ h => h) hc
    rcases Set.mem_insert_iff.mp h with rfl | h
    · exact hg p hred
    · exact hy h

theorem learnValue_complete (hc : Complete c s st root) :
    Complete c s ((LearnValue v).post st) root :=
  complete_of_le (st := st.store) (st' := ((LearnValue v).post st).store)
    (fun _ _ h => Walk.mono_store (st := st.store) (st' := ((LearnValue v).post st).store)
      (fun _ h => h) h)
    (fun _ _ _ h => h) (fun _ _ _ h => h) (fun _ _ _ _ _ _ _ _ h => Set.mem_insert_of_mem _ h) hc

theorem refuse_complete (hc : Complete c s st root) :
    Complete c s ((Refuse path x).post st) root :=
  complete_of_le (st := st.store) (st' := ((Refuse path x).post st).store)
    (fun _ _ h => Walk.mono_store (st := st.store) (st' := ((Refuse path x).post st).store)
      (fun _ h => h) h)
    (fun _ _ _ h => h) (fun _ _ _ ⟨hy, hin, hred⟩ => ⟨hy, hin, Set.mem_insert_of_mem _ hred⟩)
    (fun _ _ _ _ _ _ _ _ h => h) hc

/-- The store after a sweep: held nodes marked, values of marked nodes. -/
theorem mem_gcSweep_held {y : Hash} :
    y ∈ ((GcSweep c).post st).store.held ↔ y ∈ st.store.held ∧ Marked c st y :=
  Set.mem_sep_iff

theorem mem_gcSweep_heldValue :
    v ∈ ((GcSweep c).post st).store.heldValue ↔ v ∈ st.store.heldValue ∧ MarkedValue c st v :=
  Set.mem_sep_iff

/-- Every position a retained root's scoped walk reaches, it still reaches
after the sweep: every node along the way is marked. -/
theorem reach_gcSweep_of_retained (hret : root ∈ st.retained) {y : Hash}
    (h : Reach c st.store s root path y) : Reach c ((GcSweep c).post st).store s root path y := by
  induction h with
  | root hadm _ => exact Reach.root hadm
  | child hw hheld hcn hchild hadm _ ih =>
    exact Reach.child ih (mem_gcSweep_held.mpr ⟨hheld, root, hret, _, Reach.full hw⟩) hcn hchild hadm

/-- **A sweep keeps a retained root exactly as complete as it was.** -/
theorem gcSweep_complete_iff (hret : root ∈ st.retained) :
    Complete c s ((GcSweep c).post st) root ↔ Complete c s st root := by
  constructor
  · intro hc
    refine complete_of_le (st := ((GcSweep c).post st).store) (st' := st.store)
      (fun _ _ h => reach_gcSweep_of_retained hret h) (fun _ _ _ h => (mem_gcSweep_held.mp h).1)
      (fun p y hr ⟨hy, hin, hred⟩ => ⟨fun h => hy (mem_gcSweep_held.mpr ⟨h, root, hret, p,
        Reach.full (Walk.mono_store (fun _ h => (mem_gcSweep_held.mp h).1) hr)⟩), hin, hred⟩)
      (fun _ _ _ _ _ _ _ _ h => (mem_gcSweep_heldValue.mp h).1) hc
  · intro hc
    refine complete_of_le (st := st.store) (st' := ((GcSweep c).post st).store)
      (fun _ _ h => Walk.mono_store (fun _ h => (mem_gcSweep_held.mp h).1) h)
      (fun p y hr h => mem_gcSweep_held.mpr ⟨h, root, hret, p, Reach.full hr⟩)
      (fun _ _ _ ⟨hy, hin, hred⟩ => ⟨fun h => hy (mem_gcSweep_held.mp h).1, hin, hred⟩)
      (fun p y n v hr hy hcn hv h =>
        mem_gcSweep_heldValue.mpr ⟨h, y, n, ⟨root, hret, p, Reach.full hr⟩, hy, hcn, hv⟩) hc

theorem gc_preserves_complete_retained_root (hret : root ∈ st.retained)
    (hc : Complete c s st root) : Complete c s ((GcSweep c).post st) root :=
  (gcSweep_complete_iff hret).mpr hc

/-! ## The projection to `MptGc` -/

/-- One root's five bits. -/
def proj (c : Content) (s : Scope) (st : State) (root : Hash) : MptGc.State :=
  ⟨root ∈ st.retained, root ∈ st.pending, Complete c s st root, root ∈ st.active,
    root ∈ st.materialized⟩

/-- The projection, bit by bit. -/
theorem proj_eq {r : Hash} {A B C D E : Prop}
    (h₁ : r ∈ st'.retained ↔ A) (h₂ : r ∈ st'.pending ↔ B) (h₃ : Complete c s st' r ↔ C)
    (h₄ : r ∈ st'.active ↔ D) (h₅ : r ∈ st'.materialized ↔ E) :
    proj c s st' r = ⟨A, B, C, D, E⟩ := by
  rw [proj, propext h₁, propext h₂, propext h₃, propext h₄, propext h₅]

/-- A store change that can only complete this root is a fetch batch that
learned nothing, or that learned enough. -/
theorem learnBatch_of_complete_imp {r : Hash}
    (h : Complete c s st r → Complete c s st' r)
    (hret : r ∈ st'.retained ↔ r ∈ st.retained) (hpend : r ∈ st'.pending ↔ r ∈ st.pending)
    (hact : r ∈ st'.active ↔ r ∈ st.active) (hmat : r ∈ st'.materialized ↔ r ∈ st.materialized) :
    MptGc.Step (proj c s st r) (proj c s st' r) := by
  by_cases hc : Complete c s st' r
  · exact ⟨.learnBatch true, trivial, proj_eq hret hpend (by simp [hc]) hact hmat⟩
  · have hc' : ¬ Complete c s st r := fun h' => hc (h h')
    exact ⟨.learnBatch false, trivial, proj_eq hret hpend (by simp [proj, hc, hc']) hact hmat⟩

/-- A step that leaves the store alone and touches only the slots of another
root is, at this root, a fetch batch that learned nothing. -/
theorem stutter {r : Hash} (hstore : st'.store = st.store)
    (hret : r ∈ st'.retained ↔ r ∈ st.retained) (hpend : r ∈ st'.pending ↔ r ∈ st.pending)
    (hact : r ∈ st'.active ↔ r ∈ st.active) (hmat : r ∈ st'.materialized ↔ r ∈ st.materialized) :
    MptGc.Step (proj c s st r) (proj c s st' r) :=
  learnBatch_of_complete_imp (fun h => by unfold Complete at h ⊢; rwa [hstore]) hret hpend hact hmat

/-- Every step, read at any root, is an `MptGc` transition. -/
theorem step_projects (r : Hash) (h : Step c s st st') :
    MptGc.Step (proj c s st r) (proj c s st' r) := by
  obtain ⟨k, hg, rfl⟩ := h
  cases k with
  | learnNode x =>
    exact learnBatch_of_complete_imp (learnNode_complete hg) Iff.rfl Iff.rfl Iff.rfl Iff.rfl
  | learnValue v =>
    exact learnBatch_of_complete_imp learnValue_complete Iff.rfl Iff.rfl Iff.rfl Iff.rfl
  | refuse p x => exact learnBatch_of_complete_imp refuse_complete Iff.rfl Iff.rfl Iff.rfl Iff.rfl
  | gcSweep =>
    by_cases hret : r ∈ st.retained
    · by_cases hc : Complete c s st r
      · have h₁ : Complete c s ((Trans c s .gcSweep).post st) r :=
          (gcSweep_complete_iff hret).mpr hc
        exact ⟨.trieGc true, fun _ => ⟨fun _ => hc, fun _ => rfl⟩,
          proj_eq Iff.rfl Iff.rfl (by simp [eq_true h₁]) Iff.rfl Iff.rfl⟩
      · have h₁ : ¬ Complete c s ((Trans c s .gcSweep).post st) r :=
          mt (gcSweep_complete_iff hret).mp hc
        exact ⟨.trieGc false, fun _ => ⟨fun h => absurd h Bool.false_ne_true, fun h => absurd h hc⟩,
          proj_eq Iff.rfl Iff.rfl (by simp [eq_false h₁]) Iff.rfl Iff.rfl⟩
    · by_cases hc : Complete c s ((Trans c s .gcSweep).post st) r
      · exact ⟨.trieGc true, fun h => absurd h hret,
          proj_eq Iff.rfl Iff.rfl (by simp [eq_true hc]) Iff.rfl Iff.rfl⟩
      · exact ⟨.trieGc false, fun h => absurd h hret,
          proj_eq Iff.rfl Iff.rfl (by simp [eq_false hc]) Iff.rfl Iff.rfl⟩
  | retainRoot root =>
    by_cases hr : r = root
    · subst hr
      exact ⟨.retain, trivial, proj_eq (by simp [transition]) Iff.rfl Iff.rfl Iff.rfl Iff.rfl⟩
    · exact stutter rfl (by simp [transition, hr]) Iff.rfl Iff.rfl Iff.rfl
  | dropRoot root =>
    by_cases hr : r = root
    · subst hr
      exact ⟨.prune, hg, proj_eq (by simp [transition]) Iff.rfl Iff.rfl Iff.rfl Iff.rfl⟩
    · exact stutter rfl (by simp [transition, hr]) Iff.rfl Iff.rfl Iff.rfl
  | offerPending root =>
    by_cases hr : r = root
    · subst hr
      exact ⟨.offerPending, trivial,
        proj_eq (by simp [transition]) (by simp [transition]) Iff.rfl Iff.rfl Iff.rfl⟩
    · exact stutter rfl (by simp [transition, hr]) (by simp [transition, hr]) Iff.rfl Iff.rfl
  | dropPending root =>
    by_cases hr : r = root
    · subst hr
      exact ⟨.dropPending, trivial, proj_eq Iff.rfl (by simp [transition]) Iff.rfl Iff.rfl Iff.rfl⟩
    · exact stutter rfl Iff.rfl (by simp [transition, hr]) Iff.rfl Iff.rfl
  | supersede root =>
    by_cases hr : r = root
    · subst hr
      exact ⟨.supersede, trivial,
        proj_eq Iff.rfl Iff.rfl Iff.rfl (by simp [transition]) (by simp [transition])⟩
    · exact stutter rfl Iff.rfl Iff.rfl (by simp [transition, hr]) (by simp [transition, hr])
  | promote root =>
    by_cases hr : r = root
    · subst hr
      exact ⟨.promote, hg, proj_eq Iff.rfl (by simp [transition]) Iff.rfl (by simp [transition])
        (by simp [transition])⟩
    · exact stutter rfl Iff.rfl (by simp [transition, hr]) (by simp [transition, hr])
        (by simp [transition, hr])
  | ownPublish root =>
    by_cases hr : r = root
    · subst hr
      exact ⟨.ownPublish, trivial, proj_eq (by simp [transition]) (by simp [transition])
        ⟨fun _ => trivial, fun _ => hg⟩ (by simp [transition]) (by simp [transition])⟩
    · exact stutter rfl (by simp [transition, hr]) (by simp [transition, hr])
        (by simp [transition, hr]) (by simp [transition, hr])

/-- An empty store completes no root whose position the scope admits. -/
theorem not_complete_empty (hs : s.AdmitsPath []) : ¬ Complete c s ({} : State) root :=
  fun hc => ((hc [] root (Reach.root hs)).1).elim (fun h => h.elim) (fun hb => hb.2.2.elim)

/-- **`MptGc` simulates the store.**  Every root of every reachable store is
in an `MptGc`-reachable state, so `MptGc.Invariant` holds of every root. -/
theorem simulates (hs : s.AdmitsPath []) (root : Hash) (h : (system c s).Reachable st) :
    MptGc.Reachable (proj c s st root) :=
  h.simulate (fun st => proj c s st root)
    (by simp [system, MptGc.system, proj, eq_false (not_complete_empty (c := c) hs)])
    (step_projects root)

theorem reachable_invariant (hs : s.AdmitsPath []) (root : Hash)
    (h : (system c s).Reachable st) : MptGc.Invariant (proj c s st root) :=
  MptGc.reachable_invariant (simulates hs root h)

end Synchronicity.TrieGraph

#lint
