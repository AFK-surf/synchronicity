import Synchronicity.SystemSafety
import Synchronicity.MptGc

/-!
The bridge model.  Source publication and remote promotion pair the CAS and
trie transitions that share one SQLite transaction in Rust: the head flip
commits together with the content cells it publishes or promotes, across every
content root the transaction touches.  Every other CAS step and every
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
  | sourcePublish {s : State H} {holder : H} {cas' : Cas.State H} {mpt' : MptGc.State} :
      Across (SourcePublish holder).rel s.cas cas' →
      MptGc.OwnPublish.rel s.mpt mpt' →
      Step s ⟨cas', mpt'⟩
  | ordinaryPromote {s : State H} {holder : H} {cas' : Cas.State H} {mpt' : MptGc.State} :
      Across (OrdinaryPromote holder).rel s.cas cas' →
      MptGc.Promote.rel s.mpt mpt' →
      Step s ⟨cas', mpt'⟩
  | replicaPromote {s : State H} {holder : H} {pinned : Bool} {cas' : Cas.State H}
      {mpt' : MptGc.State} :
      Across (ReplicaPromote holder pinned).rel s.cas cas' →
      MptGc.Promote.rel s.mpt mpt' →
      Step s ⟨cas', mpt'⟩

/-- The bridge system, from the empty store and an unheard-of root. -/
def system (H : Type) [Roles H] : System (State H) := ⟨{}, Step⟩

/-- The states the bridge reaches. -/
abbrev Reachable (s : State H) : Prop := (system H).Reachable s

theorem across_safe {k : Kind H} {s s' : Cas.State H}
    (hinv : SystemSafety.SystemInvariant s) (h : Across (Trans k).rel s s') :
    SystemSafety.SystemInvariant s' :=
  Across.forall (fun safe step => SystemSafety.safe_step safe ⟨k, step⟩) hinv h

theorem invariant_step {s s' : State H} (hinv : Invariant s) (hstep : Step s s') :
    Invariant s' := by
  obtain ⟨casInv, mptInv⟩ := hinv
  cases hstep with
  | cas step => exact ⟨SystemSafety.invariant.step casInv (step.mono LocalStep.step), mptInv⟩
  | mpt step => exact ⟨casInv, MptGc.invariant_step mptInv step.step⟩
  | sourcePublish casStep mptStep =>
      exact ⟨across_safe (k := .sourcePublish _) casInv casStep,
        MptGc.invariant_step mptInv ⟨.ownPublish, mptStep⟩⟩
  | ordinaryPromote casStep mptStep =>
      exact ⟨across_safe (k := .ordinaryPromote _) casInv casStep,
        MptGc.invariant_step mptInv ⟨.promote, mptStep⟩⟩
  | replicaPromote casStep mptStep =>
      exact ⟨across_safe (k := .replicaPromote _ _) casInv casStep,
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

/-- Publication commits, for every root it changes, an entry, the publisher's
pin and available content, together with an active, materialized head. -/
theorem source_publish_commits_one_closed_state {cas' : Cas.State H} {mpt' : MptGc.State}
    (casStep : Across (SourcePublish holder).rel s.cas cas')
    (mptStep : MptGc.OwnPublish.rel s.mpt mpt') (changed : cas' root ≠ s.cas root) :
    (cas' root).entry ∧ holder ∈ (cas' root).pin ∧ Available (cas' root) ∧
      mpt'.active ∧ mpt'.materialized :=
  let casClosed := Cas.source_publish_is_closed (casStep.changed changed)
  let mptClosed := MptGc.own_publish_is_atomic mptStep
  ⟨casClosed.1, casClosed.2.1, casClosed.2.2, mptClosed.1, mptClosed.2.2.2⟩

/-- Promotion commits, for every root it changes, an entry and either the
replica's pin over available content or its want, together with an active,
materialized head. -/
theorem replica_promotion_commits_pin_or_want {pinned : Bool} {cas' : Cas.State H}
    {mpt' : MptGc.State}
    (casStep : Across (ReplicaPromote holder pinned).rel s.cas cas')
    (mptStep : MptGc.Promote.rel s.mpt mpt') (changed : cas' root ≠ s.cas root) :
    (cas' root).entry ∧
      ((holder ∈ (cas' root).pin ∧ Available (cas' root)) ∨ holder ∈ (cas' root).want) ∧
      mpt'.active ∧ mpt'.materialized :=
  let casClosed := Cas.replica_promotion_is_total (casStep.changed changed)
  let mptClosed := MptGc.promotion_is_atomic mptStep
  ⟨casClosed.1, casClosed.2, mptClosed.1, mptClosed.2.2.2⟩

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
  | sourcePublish _ mptStep =>
    exact ⟨(MptGc.own_publish_is_atomic mptStep).1, (MptGc.own_publish_is_atomic mptStep).2.2.2⟩
  | ordinaryPromote _ mptStep =>
    exact ⟨(MptGc.promotion_is_atomic mptStep).1, (MptGc.promotion_is_atomic mptStep).2.2.2⟩
  | replicaPromote _ mptStep =>
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
      have flips : k.flipsHead = true := by rw [sourcePublish_of_new_leaf hk new old]; rfl
      exact Bool.false_ne_true (hlocal.symm.trans flips)
    · rw [same] at new
      exact old new
  | mpt _ => exact absurd new old
  | sourcePublish _ mptStep =>
    exact ⟨(MptGc.own_publish_is_atomic mptStep).1, (MptGc.own_publish_is_atomic mptStep).2.2.2⟩
  | ordinaryPromote _ mptStep =>
    exact ⟨(MptGc.promotion_is_atomic mptStep).1, (MptGc.promotion_is_atomic mptStep).2.2.2⟩
  | replicaPromote _ mptStep =>
    exact ⟨(MptGc.promotion_is_atomic mptStep).1, (MptGc.promotion_is_atomic mptStep).2.2.2⟩

/-- Along any step of the bridge every content cell either takes a cell
transition or stays: a free step lifts one cell, a paired publication or
promotion runs one transition across the store. -/
theorem step_cells {s s' : State H} (h : Step s s') (root : Root) :
    CellStep (s.cas root) (s'.cas root) ∨ s'.cas root = s.cas root := by
  cases h with
  | cas step => exact (step.across root).imp_left LocalStep.step
  | mpt _ => exact Or.inr rfl
  | @sourcePublish holder _ _ step _ =>
    exact (step root).imp_left fun h => ⟨.sourcePublish holder, h⟩
  | @ordinaryPromote holder _ _ step _ =>
    exact (step root).imp_left fun h => ⟨.ordinaryPromote holder, h⟩
  | @replicaPromote holder pinned _ _ step _ =>
    exact (step root).imp_left fun h => ⟨.replicaPromote holder pinned, h⟩

end Synchronicity.Bridge

#lint
