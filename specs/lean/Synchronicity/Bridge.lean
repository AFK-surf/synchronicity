import Mathlib.Data.Set.Finite.Basic
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

/-- The CAS operations which own publication can compose: materializing both
source and replica roles, then reconciling source holds.  Content-writing and
independent maintenance transitions are deliberately absent. -/
def PublishCellStep (c c' : Cell H) : Prop :=
  ∃ k : Kind H,
    (match k with
      | .sourcePublish _ _ | .replicaPromote _ _ | .ordinaryPromote _
      | .removeSource _ | .removeReplica _ | .removeOrdinary _ | .dropEntry
      | .unpin _ | .dropWant _ => True
      | _ => False) ∧
    (Trans k).rel c c'

/-- Remote promotion materializes replica or metadata-only roles.  It cannot
stand a source leaf: Rust's `try_promote` never calls `hold_source_blob`. -/
def PromotionCellStep (c c' : Cell H) : Prop :=
  ∃ k : Kind H,
    (match k with
      | .replicaPromote _ _ | .ordinaryPromote _
      | .removeReplica _ | .removeOrdinary _ | .dropEntry => True
      | _ => False) ∧
    (Trans k).rel c c'

/-- One cell's finite sequence inside an atomic own-publication transaction.
Rust's publisher-owned `refresh_blob`/`withdraw_blob` intent either accompanies
`SourcePublish`, or recomputes an existing source ad and stutters at this
abstraction; non-source provider ads are deliberately outside the CAS safety
state. -/
def PublishCellTxn : Cell H → Cell H → Prop := Relation.ReflTransGen PublishCellStep

/-- One cell's finite sequence inside an atomic remote-promotion transaction. -/
def PromotionCellTxn : Cell H → Cell H → Prop := Relation.ReflTransGen PromotionCellStep

/-- Either transaction trace, used when projecting a bridge step to one cell. -/
def ViewCellTxn (c c' : Cell H) : Prop := PublishCellTxn c c' ∨ PromotionCellTxn c c'

/-- The whole-store CAS half of own publication.  Only finitely many content
roots change, as the Rust transaction walks one finite trie diff. -/
@[rust_impl "cas-source-publish"]
def PublishTxn (s s' : Cas.State H) : Prop :=
  Across PublishCellTxn s s' ∧ ({root | s' root ≠ s root} : Set Root).Finite

/-- The whole-store CAS half of remote promotion, separately typed so it
cannot stand source leaves. -/
@[rust_impl "cas-remote-promotion" "cas-ordinary-promotion"]
def PromotionTxn (s s' : Cas.State H) : Prop :=
  Across PromotionCellTxn s s' ∧ ({root | s' root ≠ s root} : Set Root).Finite

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
      PublishTxn s.cas cas' →
      MptGc.OwnPublish.rel s.mpt mpt' →
      Step s ⟨cas', mpt'⟩
  | promote {s : State H} {cas' : Cas.State H} {mpt' : MptGc.State} :
      PromotionTxn s.cas cas' →
      MptGc.Promote.rel s.mpt mpt' →
      Step s ⟨cas', mpt'⟩

/-- The bridge system, from the empty store and an unheard-of root. -/
def system (H : Type) [Roles H] : System (State H) := ⟨{}, Step⟩

/-- The states the bridge reaches. -/
abbrev Reachable (s : State H) : Prop := (system H).Reachable s

theorem publishCellStep_safe {c c' : Cell H} (hinv : SystemSafety.Safe c)
    (h : PublishCellStep c c') : SystemSafety.Safe c' :=
  let ⟨k, _, step⟩ := h
  SystemSafety.safe_step hinv ⟨k, step⟩

theorem promotionCellStep_safe {c c' : Cell H} (hinv : SystemSafety.Safe c)
    (h : PromotionCellStep c c') : SystemSafety.Safe c' :=
  let ⟨k, _, step⟩ := h
  SystemSafety.safe_step hinv ⟨k, step⟩

theorem publishCellTxn_safe {c c' : Cell H} (hinv : SystemSafety.Safe c)
    (h : PublishCellTxn c c') : SystemSafety.Safe c' := by
  induction h with
  | refl => exact hinv
  | tail _ step ih => exact publishCellStep_safe ih step

theorem promotionCellTxn_safe {c c' : Cell H} (hinv : SystemSafety.Safe c)
    (h : PromotionCellTxn c c') : SystemSafety.Safe c' := by
  induction h with
  | refl => exact hinv
  | tail _ step ih => exact promotionCellStep_safe ih step

theorem publishTxn_safe {s s' : Cas.State H}
    (hinv : SystemSafety.SystemInvariant s) (h : PublishTxn s s') :
    SystemSafety.SystemInvariant s' :=
  Across.forall publishCellTxn_safe hinv h.1

theorem promotionTxn_safe {s s' : Cas.State H}
    (hinv : SystemSafety.SystemInvariant s) (h : PromotionTxn s s') :
    SystemSafety.SystemInvariant s' :=
  Across.forall promotionCellTxn_safe hinv h.1

theorem invariant_step {s s' : State H} (hinv : Invariant s) (hstep : Step s s') :
    Invariant s' := by
  obtain ⟨casInv, mptInv⟩ := hinv
  cases hstep with
  | cas step => exact ⟨SystemSafety.invariant.step casInv (step.mono LocalStep.step), mptInv⟩
  | mpt step => exact ⟨casInv, MptGc.invariant_step mptInv step.step⟩
  | ownPublish casStep mptStep =>
      exact ⟨publishTxn_safe casInv casStep,
        MptGc.invariant_step mptInv ⟨.ownPublish, mptStep⟩⟩
  | promote casStep mptStep =>
      exact ⟨promotionTxn_safe casInv casStep,
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

/-- Every own-publication micro-step preserves the CAS row's recorded size. -/
theorem publishCellStep_size {c c' : Cell H} (h : PublishCellStep c c') : c'.size = c.size := by
  obtain ⟨k, allowed, step⟩ := h
  cases k <;> simp at allowed <;> simp only [transition] at step <;>
    obtain ⟨_, rfl⟩ := step <;> rfl

/-- Every remote-promotion micro-step preserves the CAS row's recorded size. -/
theorem promotionCellStep_size {c c' : Cell H} (h : PromotionCellStep c c') :
    c'.size = c.size := by
  obtain ⟨k, allowed, step⟩ := h
  cases k <;> simp at allowed <;> simp only [transition] at step <;>
    obtain ⟨_, rfl⟩ := step <;> rfl

theorem publishCellTxn_size {c c' : Cell H} (h : PublishCellTxn c c') : c'.size = c.size := by
  induction h with
  | refl => rfl
  | tail _ step ih => exact (publishCellStep_size step).trans ih

theorem promotionCellTxn_size {c c' : Cell H} (h : PromotionCellTxn c c') :
    c'.size = c.size := by
  induction h with
  | refl => rfl
  | tail _ step ih => exact (promotionCellStep_size step).trans ih

theorem viewCellTxn_size {c c' : Cell H} (h : ViewCellTxn c c') : c'.size = c.size :=
  h.elim publishCellTxn_size promotionCellTxn_size

/-- A remote-promotion micro-step cannot change which source leaves stand. -/
theorem promotionCellStep_sourceLive {c c' : Cell H} (h : PromotionCellStep c c') :
    c'.sourceLive = c.sourceLive := by
  obtain ⟨k, allowed, step⟩ := h
  cases k <;> simp at allowed <;> simp only [transition] at step <;>
    obtain ⟨_, rfl⟩ := step <;> rfl

theorem promotionCellTxn_sourceLive {c c' : Cell H} (h : PromotionCellTxn c c') :
    c'.sourceLive = c.sourceLive := by
  induction h with
  | refl => rfl
  | tail _ step ih => exact (promotionCellStep_sourceLive step).trans ih

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

/-- A step that stands a new source leaf is specifically an own-publication
step, never a remote promotion or a free CAS/trie step. -/
theorem source_leaf_is_own_publish {s' : State H} (hstep : Step s s')
    (new : holder ∈ (s'.cas root).sourceLive) (old : holder ∉ (s.cas root).sourceLive) :
    MptGc.OwnPublish.rel s.mpt s'.mpt := by
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
  | ownPublish _ mptStep => exact mptStep
  | @promote cas' _ casStep _ =>
    exfalso
    change holder ∈ (cas' root).sourceLive at new
    rcases casStep.1 root with path | same
    · rw [promotionCellTxn_sourceLive path] at new
      exact old new
    · rw [same] at new
      exact old new

/-- The same source-leaf classification read as the atomic head property. -/
theorem source_leaf_flips_head {s' : State H} (hstep : Step s s')
    (new : holder ∈ (s'.cas root).sourceLive) (old : holder ∉ (s.cas root).sourceLive) :
    s'.mpt.active ∧ s'.mpt.materialized :=
  let publish := source_leaf_is_own_publish hstep new old
  ⟨(MptGc.own_publish_is_atomic publish).1, (MptGc.own_publish_is_atomic publish).2.2.2⟩

/-- Along any step of the bridge every content cell either takes a free cell
transition, follows a finite view-transaction trace, or stays unchanged. -/
theorem step_cells {s s' : State H} (h : Step s s') (root : Root) :
    CellStep (s.cas root) (s'.cas root) ∨ ViewCellTxn (s.cas root) (s'.cas root) ∨
      s'.cas root = s.cas root := by
  cases h with
  | cas step => exact (step.across root).imp_left LocalStep.step |>.imp_right Or.inr
  | mpt _ => exact Or.inr (Or.inr rfl)
  | ownPublish step _ =>
    rcases step.1 root with path | same
    · exact Or.inr (Or.inl (Or.inl path))
    · exact Or.inr (Or.inr same)
  | promote step _ =>
    rcases step.1 root with path | same
    · exact Or.inr (Or.inl (Or.inr path))
    · exact Or.inr (Or.inr same)

end Synchronicity.Bridge

#lint
