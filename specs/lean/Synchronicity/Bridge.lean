import Synchronicity.SystemSafety
import Synchronicity.MptGc

/-!
The bridge model.  Source publication and remote promotion pair the CAS and
trie transitions that share one SQLite transaction in Rust: the head flip
commits together with a finite sequence of view-materialization steps for
each content root the transaction touches.  Every other CAS step and every
mptsync/GC step that does not flip a head interleaves freely.

The bridge sits on `SystemSafety`, so its invariant is the holder- and
root-indexed one, and the paired steps are stated over a whole store rather
than one cell.  `live_leaf_flips_head` is what the pairing buys: no step of
this system stands a new source or replica leaf without committing an active,
materialized head in the same transaction.
-/

namespace Synchronicity.Bridge

open Cas

variable {H : Type}

/-- The CAS store and one trie root's head slots, together. -/
structure State (H : Type) where
  /-- The content cells. -/
  cas : Cas.State H := Initial
  /-- The trie root's five bits. -/
  mpt : MptGc.State := {}

variable [Roles H]

/-- The CAS operations which the Rust view transaction can compose.  Unlike
`Across (Trans k).rel`, this lets one transaction remove the old root and add
the new root, and lets different roots take different transition kinds.  The
content-writing transitions are deliberately absent: materialization does not
change an object's recorded size. -/
def ViewCellStep (c c' : Cell H) : Prop :=
  ∃ k : Kind H,
    (match k with
      | .sourcePublish _ _ | .replicaPromote _ _ | .ordinaryPromote _
      | .removeSource _ | .removeReplica _ | .removeOrdinary _ | .dropEntry
      | .pin _ | .unpin _ | .expirePin _ | .dropWant _ | .takePossession _ => True
      | _ => False) ∧
    (Trans k).rel c c'

/-- One cell's finite sequence inside an atomic Rust view transaction. -/
def ViewCellTxn : Cell H → Cell H → Prop := Relation.ReflTransGen ViewCellStep

/-- The whole-store CAS half of publication and promotion. -/
@[rust_impl "cas-source-publish" "cas-remote-promotion" "cas-ordinary-promotion"]
def ViewTxn (s s' : Cas.State H) : Prop := Across ViewCellTxn s s'

/-- Both halves keep their own invariant. -/
def Invariant (s : State H) : Prop :=
  SystemSafety.SystemInvariant s.cas ∧ MptGc.Invariant s.mpt

/-- A free CAS step that flips no head, a free trie step that flips no head,
or a paired publication or promotion: the CAS transition of kind `k` across
every root the transaction touches, together with the head flip. -/
inductive Step : State H → State H → Prop where
  | cas {s : State H} {cas' : Cas.State H} :
      Lift LocalStep s.cas cas' → Step s { s with cas := cas' }
  | mpt {s : State H} {mpt' : MptGc.State} :
      MptGc.SyncStep s.mpt mpt' → Step s { s with mpt := mpt' }
  | ownPublish {s : State H} {cas' : Cas.State H} {mpt' : MptGc.State} :
      ViewTxn s.cas cas' →
      MptGc.OwnPublish.rel s.mpt mpt' →
      Step s ⟨cas', mpt'⟩
  | promote {s : State H} {cas' : Cas.State H} {mpt' : MptGc.State} :
      ViewTxn s.cas cas' →
      MptGc.Promote.rel s.mpt mpt' →
      Step s ⟨cas', mpt'⟩

/-- The bridge system, from the empty store and an unheard-of root. -/
def system (H : Type) [Roles H] : System (State H) := ⟨{}, Step⟩

/-- The states the bridge reaches. -/
abbrev Reachable (s : State H) : Prop := (system H).Reachable s

theorem viewCellStep_safe {c c' : Cell H} (hinv : SystemSafety.Safe c)
    (h : ViewCellStep c c') : SystemSafety.Safe c' :=
  let ⟨k, _, step⟩ := h
  SystemSafety.safe_step hinv ⟨k, step⟩

theorem viewCellTxn_safe {c c' : Cell H} (hinv : SystemSafety.Safe c)
    (h : ViewCellTxn c c') : SystemSafety.Safe c' := by
  induction h with
  | refl => exact hinv
  | tail _ step ih => exact viewCellStep_safe ih step

theorem viewTxn_safe {s s' : Cas.State H}
    (hinv : SystemSafety.SystemInvariant s) (h : ViewTxn s s') :
    SystemSafety.SystemInvariant s' :=
  Across.forall viewCellTxn_safe hinv h

theorem invariant_step {s s' : State H} (hinv : Invariant s) (hstep : Step s s') :
    Invariant s' := by
  obtain ⟨casInv, mptInv⟩ := hinv
  cases hstep with
  | cas step => exact ⟨SystemSafety.invariant.step casInv (step.mono LocalStep.step), mptInv⟩
  | mpt step => exact ⟨casInv, MptGc.invariant_step mptInv step.step⟩
  | ownPublish casStep mptStep =>
      exact ⟨viewTxn_safe casInv casStep,
        MptGc.invariant_step mptInv ⟨.ownPublish, mptStep⟩⟩
  | promote casStep mptStep =>
      exact ⟨viewTxn_safe casInv casStep,
        MptGc.invariant_step mptInv ⟨.promote, mptStep⟩⟩

theorem invariant : (system H).Invariant Invariant where
  init := ⟨SystemSafety.invariant.init, MptGc.invariant.init⟩
  step := invariant_step

theorem reachable_invariant {s : State H} (h : Reachable s) : Invariant s :=
  invariant.reachable h

/-! ## What the paired transactions commit -/

variable {s : State H} {root : Root} {holder : H}

theorem gc_cannot_create_promised_missing
    (reachable : Reachable s) (pinned : holder ∈ (s.cas root).pin) : Available (s.cas root) :=
  ((reachable_invariant reachable).1 root).2.pin_available holder pinned

/-- Every view-materialization micro-step preserves the CAS row's recorded
size, hence so does the finite per-cell sequence committed atomically. -/
theorem viewCellStep_size {c c' : Cell H} (h : ViewCellStep c c') : c'.size = c.size := by
  obtain ⟨k, allowed, step⟩ := h
  cases k <;> simp at allowed <;> simp only [transition] at step <;>
    obtain ⟨_, rfl⟩ := step <;> rfl

theorem viewCellTxn_size {c c' : Cell H} (h : ViewCellTxn c c') : c'.size = c.size := by
  induction h with
  | refl => rfl
  | tail _ step ih => exact (viewCellStep_size step).trans ih

/-! ## Why the pairing is a guard and not a convention -/

/-- **A new leaf is always paired with a head flip.**  No step of the bridge
stands a source or replica leaf that was not standing before without
committing an active, materialized head in the same transaction.  This is
what `Cas.LocalStep` on the free `cas` step is for: a bare publication or
promotion is not a step of this system. -/
theorem live_leaf_flips_head {s' : State H} (hstep : Step s s')
    (new : holder ∈ (s'.cas root).sourceLive ∨ holder ∈ (s'.cas root).replicaLive)
    (old : holder ∉ (s.cas root).sourceLive ∧ holder ∉ (s.cas root).replicaLive) :
    s'.mpt.active ∧ s'.mpt.materialized := by
  cases hstep with
  | @cas cas' step =>
    exfalso
    change holder ∈ (cas' root).sourceLive ∨ holder ∈ (cas' root).replicaLive at new
    rcases step.across root with hk | same
    · obtain ⟨k, hlocal, hk⟩ := hk
      exact Bool.false_ne_true (hlocal.symm.trans (flipsHead_of_new_leaf hk new old))
    · rw [same] at new
      exact new.elim old.1 old.2
  | mpt _ => exact absurd new (fun h => h.elim old.1 old.2)
  | ownPublish _ mptStep =>
    exact ⟨(MptGc.own_publish_is_atomic mptStep).1, (MptGc.own_publish_is_atomic mptStep).2.2.2⟩
  | promote _ mptStep =>
    exact ⟨(MptGc.promotion_is_atomic mptStep).1, (MptGc.promotion_is_atomic mptStep).2.2.2⟩

/-- The same for a source leaf on its own, without asking about the holder's
replica leaf: only a publication stands one. -/
theorem source_leaf_flips_head {s' : State H} (hstep : Step s s')
    (new : holder ∈ (s'.cas root).sourceLive) (old : holder ∉ (s.cas root).sourceLive) :
    s'.mpt.active ∧ s'.mpt.materialized := by
  cases hstep with
  | @cas cas' step =>
    exfalso
    change holder ∈ (cas' root).sourceLive at new
    rcases step.across root with hk | same
    · obtain ⟨k, hlocal, hk⟩ := hk
      obtain ⟨publishedSize, rfl⟩ := sourcePublish_of_new_leaf hk new old
      have flips : (Kind.sourcePublish holder publishedSize).flipsHead = true := rfl
      exact Bool.false_ne_true (hlocal.symm.trans flips)
    · rw [same] at new
      exact old new
  | mpt _ => exact absurd new old
  | ownPublish _ mptStep =>
    exact ⟨(MptGc.own_publish_is_atomic mptStep).1, (MptGc.own_publish_is_atomic mptStep).2.2.2⟩
  | promote _ mptStep =>
    exact ⟨(MptGc.promotion_is_atomic mptStep).1, (MptGc.promotion_is_atomic mptStep).2.2.2⟩

/-- Along any step of the bridge every content cell either takes a free cell
transition, follows a finite view-transaction trace, or stays unchanged. -/
theorem step_cells {s s' : State H} (h : Step s s') (root : Root) :
    CellStep (s.cas root) (s'.cas root) ∨ ViewCellTxn (s.cas root) (s'.cas root) ∨
      s'.cas root = s.cas root := by
  cases h with
  | cas step => exact (step.across root).imp_left LocalStep.step |>.imp_right Or.inr
  | mpt _ => exact Or.inr (Or.inr rfl)
  | ownPublish step _ => exact Or.inr (step root)
  | promote step _ => exact Or.inr (step root)

end Synchronicity.Bridge

#lint
