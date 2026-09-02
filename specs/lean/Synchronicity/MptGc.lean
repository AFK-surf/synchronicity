import Synchronicity.Prelude
import Synchronicity.Anchors

/-!
The per-trie-root abstraction of mptsync, pending-head promotion and trie GC.
`complete` means complete within the node's read scope; `TrieGraph` is the
multi-root model this one is the projection of (`TrieGraph.proj`), and
`ScopedSync.CompleteWithin` is what the `complete` bit means for a scoped
reader.

The transitions are deliberately looser than the code where the code's own
ordering is not what the invariant rests on: a fetch batch may commit after the
pending slot was cleared (`LearnBatch` is unguarded), a head that loses the
ordering comparison is retained without a slot (`Retain`), the pending slot may
be cleared without a flip (`DropPending`), and a root that left retention may
keep its nodes when another retained root shares them (`TrieGc`).
-/

namespace Synchronicity.MptGc

structure State where
  retained : Prop := False
  pending : Prop := False
  complete : Prop := False
  active : Prop := False
  materialized : Prop := False

/-- What promotion needs and what the slots imply: an active head is retained,
complete and materialized; a pending head is retained; only an active head is
materialized. -/
structure Invariant (s : State) : Prop where
  active_retained : s.active → s.retained
  active_complete : s.active → s.complete
  active_materialized : s.active → s.materialized
  pending_retained : s.pending → s.retained
  materialized_active : s.materialized → s.active

/-- `reconcile.rs::offer_head`: a verified head that supersedes the floor
takes the pending slot, and its root enters retention. -/
@[rust_impl "mpt-offer-pending"]
def OfferPending (s s' : State) : Prop :=
  s' = { s with retained := True, pending := True }

/-- `reconcile.rs::offer_head`, the `NotNewer` arm.  A verified head that
loses the ordering comparison is still history and fork evidence, so its root
enters GC retention without any slot pointing at it. -/
@[rust_impl "mpt-retain-only"]
def Retain (s s' : State) : Prop :=
  s' = { s with retained := True }

/-- `reconcile.rs::fetch_pending`, one batch commit.  Unguarded: the fetch
reads the pending slot once and commits batches afterwards, so a batch may
land after the slot was cleared or the root left retention.  Such nodes are
unreferenced and the next `TrieGc` takes them; the invariant does not depend
on the guard. -/
@[rust_impl "mpt-fetch-batch"]
def LearnBatch (s s' : State) : Prop :=
  s' = s ∨ s' = { s with complete := True }

/-- `reconcile.rs::try_promote` clearing an overtaken or refused pending head,
`sweep_pending_heads`, and the read-scope demotion in `bindings.rs`.  The root
stays retained through `head_history` until pruned. -/
@[rust_impl "mpt-drop-pending"]
def DropPending (s s' : State) : Prop :=
  s' = { s with pending := False }

/-- `gc.rs::gc_trie`.  A retained root keeps everything; a root outside
retention may lose its completeness, or keep it when every node it reaches is
also reached from a retained root (`TrieGraph.gcSweep_projects`). -/
@[rust_impl "mpt-trie-gc"]
def TrieGc (s s' : State) : Prop :=
  (s.retained ∧ s' = s) ∨
  (¬s.retained ∧ (s' = s ∨ s' = { s with complete := False }))

/-- `heads.rs::Store::prune_history_before`: a root neither slot points at
leaves retention once it ages out of the `root_retention` window. -/
@[rust_impl "mpt-prune-history"]
def Prune (s s' : State) : Prop :=
  ¬s.pending ∧ ¬s.active ∧ s' = { s with retained := False }

/-- `reconcile.rs::try_promote`, `put_head(Slot::Complete)`: the head this
root carried is displaced by a newer one.  The root stays retained through
`head_history`; it is simply no longer what the node serves or materializes. -/
@[rust_impl "mpt-supersede"]
def Supersede (s s' : State) : Prop :=
  s' = { s with active := False, materialized := False }

/-- `reconcile.rs::try_promote`: the complete pending head takes the slot and
its diff is materialized, in one transaction. -/
@[rust_impl "mpt-promote"]
def Promote (s s' : State) : Prop :=
  s.pending ∧ s.retained ∧ s.complete ∧
  s' = { s with
    pending := False
    active := True
    materialized := True }

/-- `node.rs::Node::publish`: this node's own head, whole by construction. -/
@[rust_impl "mpt-own-publish"]
def OwnPublish (s s' : State) : Prop :=
  s' = { s with
    retained := True
    pending := False
    complete := True
    active := True
    materialized := True }

/-- The transitions, named. -/
inductive Kind where
  | offerPending | retain | learnBatch | dropPending | trieGc | prune | supersede
  | promote | ownPublish
  deriving DecidableEq

def Trans : Kind → State → State → Prop
  | .offerPending => OfferPending
  | .retain => Retain
  | .learnBatch => LearnBatch
  | .dropPending => DropPending
  | .trieGc => TrieGc
  | .prune => Prune
  | .supersede => Supersede
  | .promote => Promote
  | .ownPublish => OwnPublish

/-- Which transitions flip or mint a head.  `Safety` pairs these with the CAS
cells they commit alongside; every other transition interleaves freely. -/
def Kind.flipsHead : Kind → Bool
  | .promote | .ownPublish => true
  | _ => false

def Step (s s' : State) : Prop := ∃ k, Trans k s s'

/-- mptsync/GC work that does not flip or mint a head. -/
def SyncStep (s s' : State) : Prop := ∃ k, k.flipsHead = false ∧ Trans k s s'

theorem SyncStep.step {s s' : State} (h : SyncStep s s') : Step s s' :=
  let ⟨k, _, t⟩ := h
  ⟨k, t⟩

def Initial : State := {}

def system : System State := ⟨Initial, Step⟩

abbrev Reachable (s : State) : Prop := system.Reachable s

theorem initial_invariant : Invariant Initial where
  active_retained := False.elim
  active_complete := False.elim
  active_materialized := False.elim
  pending_retained := False.elim
  materialized_active := False.elim

theorem invariant_step {s s' : State} (hinv : Invariant s) (hstep : Step s s') : Invariant s' := by
  obtain ⟨k, h⟩ := hstep
  obtain ⟨ar, ac, am, pr, ma⟩ := hinv
  cases k <;> simp only [Trans, OfferPending, Retain, LearnBatch, DropPending, TrieGc, Prune,
    Supersede, Promote, OwnPublish] at h <;> subst_step h <;> constructor <;> grind

theorem sync_invariant_step {s s' : State} (hinv : Invariant s) (hstep : SyncStep s s') :
    Invariant s' :=
  invariant_step hinv hstep.step

theorem reachable_invariant {s : State} (h : Reachable s) : Invariant s :=
  h.invariant initial_invariant invariant_step

/-! ## What single transitions commit -/

variable {s s' : State}

theorem trie_gc_preserves_complete_retained
    (hgc : TrieGc s s') (retained : s.retained) (complete : s.complete) :
    s'.retained ∧ s'.complete := by
  rcases hgc with ⟨_, rfl⟩ | ⟨dead, _⟩
  · exact ⟨retained, complete⟩
  · exact absurd retained dead

theorem promotion_is_atomic (h : Promote s s') :
    s'.active ∧ s'.retained ∧ s'.complete ∧ s'.materialized := by
  rcases h with ⟨_, retained, complete, rfl⟩
  exact ⟨trivial, retained, complete, trivial⟩

theorem own_publish_is_atomic (h : OwnPublish s s') :
    s'.active ∧ s'.retained ∧ s'.complete ∧ s'.materialized := by
  rcases h with ⟨rfl⟩
  exact ⟨trivial, trivial, trivial, trivial⟩

/-- Pruning never takes a root a slot still points at or the node still
serves. -/
theorem prune_takes_no_live_root (h : Prune s s') : ¬s.pending ∧ ¬s.active :=
  ⟨h.1, h.2.1⟩

end Synchronicity.MptGc
