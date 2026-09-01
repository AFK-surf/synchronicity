/-!
The per-trie-root abstraction of mptsync, pending-head promotion and trie GC.
`complete` means complete within the node's read scope.
-/

namespace Synchronicity.MptGc

structure State where
  retained : Prop := False
  pending : Prop := False
  complete : Prop := False
  active : Prop := False
  materialized : Prop := False

def Invariant (s : State) : Prop :=
  s.active → s.retained ∧ s.complete ∧ s.materialized

/- RUST-IMPL: mpt-offer-pending — `reconcile.rs::offer_head`. -/
def OfferPending (s s' : State) : Prop :=
  s' = { s with retained := True, pending := True }

/- RUST-IMPL: mpt-retain-only — `reconcile.rs::offer_head`, the `NotNewer`
   arm.  A verified head that loses the ordering comparison is still history
   and fork evidence, so its root enters GC retention without any slot
   pointing at it. -/
def Retain (s s' : State) : Prop :=
  s' = { s with retained := True }

/- RUST-IMPL: mpt-fetch-batch — `reconcile.rs::fetch_pending` batch commit.
   Unguarded: the fetch reads the pending slot once and commits batches
   afterwards, so a batch may land after the slot was cleared or the root
   left retention.  Such nodes are unreferenced and the next `TrieGc` takes
   them; the invariant does not depend on the guard. -/
def LearnBatch (s s' : State) : Prop :=
  s' = s ∨ s' = { s with complete := True }

/- RUST-IMPL: mpt-drop-pending — `reconcile.rs::try_promote` clearing an
   overtaken or refused pending head, `sweep_pending_heads`, and the read-scope
   demotion in `bindings.rs`.  The root stays retained through `head_history`
   until pruned. -/
def DropPending (s s' : State) : Prop :=
  s' = { s with pending := False }

/- RUST-IMPL: mpt-trie-gc — `gc.rs::gc_trie`. -/
def TrieGc (s s' : State) : Prop :=
  (s.retained ∧ s' = s) ∨
  (¬s.retained ∧ s' = { s with complete := False })

/- RUST-IMPL: mpt-promote — `reconcile.rs::try_promote`. -/
def Promote (s s' : State) : Prop :=
  s.pending ∧ s.retained ∧ s.complete ∧
  s' = { s with
    pending := False
    active := True
    materialized := True }

/- RUST-IMPL: mpt-own-publish — `node.rs::Node::publish`. -/
def OwnPublish (s s' : State) : Prop :=
  s' = { s with
    retained := True
    pending := False
    complete := True
    active := True
    materialized := True }

inductive Step : State → State → Prop where
  | offerPending : OfferPending s s' → Step s s'
  | retain : Retain s s' → Step s s'
  | learnBatch : LearnBatch s s' → Step s s'
  | dropPending : DropPending s s' → Step s s'
  | trieGc : TrieGc s s' → Step s s'
  | promote : Promote s s' → Step s s'
  | ownPublish : OwnPublish s s' → Step s s'

/- mptsync/GC work that does not flip or mint a head. -/
inductive SyncStep : State → State → Prop where
  | offerPending : OfferPending s s' → SyncStep s s'
  | retain : Retain s s' → SyncStep s s'
  | learnBatch : LearnBatch s s' → SyncStep s s'
  | dropPending : DropPending s s' → SyncStep s s'
  | trieGc : TrieGc s s' → SyncStep s s'

def Initial : State := {}

inductive Reachable : State → Prop where
  | initial : Reachable Initial
  | next : Reachable s → Step s s' → Reachable s'

theorem initial_invariant : Invariant Initial := by
  simp [Initial, Invariant]

theorem invariant_step (hinv : Invariant s) (hstep : Step s s') : Invariant s' := by
  cases hstep with
  | offerPending h => simp_all [OfferPending, Invariant]
  | retain h => simp_all [Retain, Invariant]
  | learnBatch h => rcases h with unchanged | closed <;> simp_all [Invariant]
  | dropPending h => simp_all [DropPending, Invariant]
  | trieGc h => rcases h with held | dead <;> simp_all [Invariant]
  | promote h => simp_all [Promote, Invariant]
  | ownPublish h => simp_all [OwnPublish, Invariant]

theorem sync_invariant_step (hinv : Invariant s) (hstep : SyncStep s s') : Invariant s' := by
  cases hstep with
  | offerPending h => exact invariant_step hinv (.offerPending h)
  | retain h => exact invariant_step hinv (.retain h)
  | learnBatch h => exact invariant_step hinv (.learnBatch h)
  | dropPending h => exact invariant_step hinv (.dropPending h)
  | trieGc h => exact invariant_step hinv (.trieGc h)

theorem reachable_invariant (h : Reachable s) : Invariant s := by
  induction h with
  | initial => exact initial_invariant
  | next _ step ih => exact invariant_step ih step

theorem trie_gc_preserves_complete_retained
    (hgc : TrieGc s s') (retained : s.retained) (complete : s.complete) :
    s'.retained ∧ s'.complete := by
  rcases hgc with held | dead
  · rcases held with ⟨_, rfl⟩
    exact ⟨retained, complete⟩
  · exact False.elim (dead.1 retained)

theorem promotion_is_atomic (h : Promote s s') :
    s'.active ∧ s'.retained ∧ s'.complete ∧ s'.materialized := by
  rcases h with ⟨_, retained, complete, rfl⟩
  exact ⟨trivial, retained, complete, trivial⟩

theorem own_publish_is_atomic (h : OwnPublish s s') :
    s'.active ∧ s'.retained ∧ s'.complete ∧ s'.materialized := by
  rcases h with ⟨rfl⟩
  exact ⟨trivial, trivial, trivial, trivial⟩

end Synchronicity.MptGc
