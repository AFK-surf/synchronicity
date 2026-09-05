import Synchronicity.Prelude

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

/-- One trie root, as five bits. -/
structure State where
  /-- The root is a GC mark root (a slot or `head_history` names it). -/
  retained : Prop := False
  /-- The pending slot names the root. -/
  pending : Prop := False
  /-- The root is complete within the node's read scope. -/
  complete : Prop := False
  /-- The complete slot names the root: it is what the node serves. -/
  active : Prop := False
  /-- The derived views were rebuilt from the root. -/
  materialized : Prop := False

/-- Active heads are retained and materialized, but can become incomplete when
a refused boundary dissolves. A slot is not a fresh completeness certificate. -/
structure Invariant (s : State) : Prop where
  /-- An active head is retained. -/
  active_retained : s.active → s.retained
  /-- An active head is materialized. -/
  active_materialized : s.active → s.materialized
  /-- A pending head is retained. -/
  pending_retained : s.pending → s.retained
  /-- Only an active head is materialized. -/
  materialized_active : s.materialized → s.active

/-- `reconcile.rs::offer_head`: a verified head that supersedes the floor
takes the pending slot, and its root enters retention. -/
@[transition, rust_impl "mpt-offer-pending"]
def OfferPending : Transition State where
  guard _ := True
  post s := { s with retained := True, pending := True }

/-- `reconcile.rs::offer_head`, the `NotNewer` arm.  A verified head that
loses the ordering comparison is still history and fork evidence, so its root
enters GC retention without any slot pointing at it. -/
@[transition, rust_impl "mpt-retain-only"]
def Retain : Transition State where
  guard _ := True
  post s := { s with retained := True }

/-- `reconcile.rs::fetch_pending`, one batch commit, which does (`learned`) or
does not finish the root.  Unguarded: the fetch reads the pending slot once
and commits batches afterwards, so a batch may land after the slot was cleared
or the root left retention.  Such nodes are unreferenced and the next `TrieGc`
takes them; the invariant does not depend on the guard. -/
@[transition, rust_impl "mpt-fetch-batch"]
def LearnBatch (learned : Bool) : Transition State where
  guard _ := True
  post s := { s with complete := learned ∨ s.complete }

/-- Learning a formerly refused node can expose missing descendants without
changing the active slot or its last materialization. Serving must recheck
completeness; active is not a completeness certificate. -/
@[transition]
def Recheck (complete : Bool) : Transition State where
  guard _ := True
  post s := { s with complete := complete }

/-- `reconcile.rs::try_promote` clearing an overtaken or refused pending head,
`sweep_pending_heads`, and the read-scope demotion in `bindings.rs`.  The root
stays retained through `head_history` until pruned. -/
@[transition, rust_impl "mpt-drop-pending"]
def DropPending : Transition State where
  guard _ := True
  post s := { s with pending := False }

/-- `gc.rs::gc_trie`.  A retained root is exactly as complete after the sweep
as before (`TrieGraph.gcSweep_complete_iff`); a root outside retention ends
up complete or not (`complete`) as the nodes it shares with retained roots
and the boundaries it stops at fall — the model says nothing about it, and
nothing depends on it. -/
@[transition, rust_impl "mpt-trie-gc"]
def TrieGc (complete : Bool) : Transition State where
  guard s := s.retained → (complete ↔ s.complete)
  post s := { s with complete := complete }

/-- `heads.rs::Store::prune_history_before`: a root neither slot points at
leaves retention once it ages out of the `root_retention` window. -/
@[transition, rust_impl "mpt-prune-history"]
def Prune : Transition State where
  guard s := ¬s.pending ∧ ¬s.active
  post s := { s with retained := False }

/-- `reconcile.rs::try_promote`, `put_head(Slot::Complete)`: the head this
root carried is displaced by a newer one.  The root stays retained through
`head_history`; it is simply no longer what the node serves or materializes. -/
@[transition, rust_impl "mpt-supersede"]
def Supersede : Transition State where
  guard _ := True
  post s := { s with active := False, materialized := False }

/-- `reconcile.rs::try_promote`: the complete pending head takes the slot and
its diff is materialized, in one transaction. -/
@[transition, rust_impl "mpt-promote"]
def Promote : Transition State where
  guard s := s.pending ∧ s.retained ∧ s.complete
  post s := { s with pending := False, active := True, materialized := True }

/-- `node.rs::Node::publish`: this node's own head, whole by construction.
Every bit is written. -/
@[transition, rust_impl "mpt-own-publish"]
def OwnPublish : Transition State where
  guard _ := True
  post _ := {
    retained := True
    pending := False
    complete := True
    active := True
    materialized := True }

/-- The transitions, named. -/
inductive Kind where
  | offerPending | retain | learnBatch (learned : Bool) | dropPending | trieGc (complete : Bool)
  | prune | supersede | promote | ownPublish | recheck (complete : Bool)
  deriving DecidableEq

/-- The transition each kind names. -/
@[transition]
def Trans : Kind → Transition State
  | .offerPending => OfferPending
  | .retain => Retain
  | .learnBatch learned => LearnBatch learned
  | .dropPending => DropPending
  | .trieGc complete => TrieGc complete
  | .prune => Prune
  | .supersede => Supersede
  | .promote => Promote
  | .ownPublish => OwnPublish
  | .recheck complete => Recheck complete

/-- Which transitions flip or mint a head.  `Bridge` pairs these with the CAS
cells they commit alongside; every other transition interleaves freely. -/
def Kind.flipsHead : Kind → Bool
  | .promote | .ownPublish => true
  | _ => false

/-- Some transition took the root from `s` to `s'`. -/
def Step (s s' : State) : Prop := ∃ k, (Trans k).rel s s'

/-- mptsync/GC work that does not flip or mint a head. -/
def SyncStep (s s' : State) : Prop := ∃ k, k.flipsHead = false ∧ (Trans k).rel s s'

theorem SyncStep.step {s s' : State} (h : SyncStep s s') : Step s s' :=
  let ⟨k, _, t⟩ := h
  ⟨k, t⟩

/-- The per-root system, from a root nothing has heard of. -/
def system : System State := ⟨{}, Step⟩

/-- The states a root can be in. -/
abbrev Reachable (s : State) : Prop := system.Reachable s

theorem invariant_step {s s' : State} (hinv : Invariant s) (hstep : Step s s') : Invariant s' := by
  obtain ⟨k, h⟩ := hstep
  obtain ⟨ar, am, pr, ma⟩ := hinv
  cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h <;> constructor <;> grind

theorem invariant : system.Invariant Invariant where
  init := ⟨False.elim, False.elim, False.elim, False.elim⟩
  step := invariant_step

theorem reachable_invariant {s : State} (h : Reachable s) : Invariant s :=
  invariant.reachable h

/-! ## What single transitions commit -/

variable {s s' : State}

theorem trie_gc_preserves_complete_retained {b : Bool}
    (hgc : (TrieGc b).rel s s') (retained : s.retained) (complete : s.complete) :
    s'.retained ∧ s'.complete := by
  simp only [transition] at hgc
  obtain ⟨hg, rfl⟩ := hgc
  exact ⟨retained, (hg retained).mpr complete⟩

theorem promotion_is_atomic (h : Promote.rel s s') :
    s'.active ∧ s'.retained ∧ s'.complete ∧ s'.materialized := by
  simp only [transition] at h
  obtain ⟨⟨_, retained, complete⟩, rfl⟩ := h
  exact ⟨trivial, retained, complete, trivial⟩

theorem own_publish_is_atomic (h : OwnPublish.rel s s') :
    s'.active ∧ s'.retained ∧ s'.complete ∧ s'.materialized := by
  simp only [transition] at h
  obtain ⟨_, rfl⟩ := h
  exact ⟨trivial, trivial, trivial, trivial⟩

/-- Pruning never takes a root a slot still points at or the node still
serves. -/
theorem prune_takes_no_live_root (h : Prune.rel s s') : ¬s.pending ∧ ¬s.active :=
  h.1

end Synchronicity.MptGc

#lint
