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
than one cell.
-/

namespace Synchronicity.Safety

open Cas

variable {H : Type} [Roles H]

structure State (H : Type) where
  cas : Cas.State H := Initial
  mpt : MptGc.State := {}

/-- One transaction over several content roots: every root either takes the
transition or is left as it was. -/
def Across (P : Cell H → Cell H → Prop) (s s' : Cas.State H) : Prop :=
  ∀ root, P (s root) (s' root) ∨ s' root = s root

def Invariant (s : State H) : Prop :=
  SystemSafety.SystemInvariant s.cas ∧ MptGc.Invariant s.mpt

inductive Step : State H → State H → Prop where
  | cas {s : State H} {root : Root} {cell' : Cell H} :
      CellStep (s.cas root) cell' → Local (s.cas root) cell' →
      Step s { s with cas := Replace s.cas root cell' }
  | mpt {s : State H} {mpt' : MptGc.State} :
      MptGc.SyncStep s.mpt mpt' → Step s { s with mpt := mpt' }
  | sourcePublish {s : State H} {holder : H} {cas' : Cas.State H} {mpt' : MptGc.State} :
      Across (SourcePublish holder) s.cas cas' →
      MptGc.OwnPublish s.mpt mpt' →
      Step s ⟨cas', mpt'⟩
  | ordinaryPromote {s : State H} {holder : H} {cas' : Cas.State H} {mpt' : MptGc.State} :
      Across (OrdinaryPromote holder) s.cas cas' →
      MptGc.Promote s.mpt mpt' →
      Step s ⟨cas', mpt'⟩
  | replicaPromote {s : State H} {holder : H} {cas' : Cas.State H} {mpt' : MptGc.State} :
      Across (ReplicaPromote holder) s.cas cas' →
      MptGc.Promote s.mpt mpt' →
      Step s ⟨cas', mpt'⟩

def Initial : State H := {}

inductive Reachable : State H → Prop where
  | initial : Reachable Initial
  | next {s s' : State H} : Reachable s → Step s s' → Reachable s'

theorem across_safe {P : Cell H → Cell H → Prop} {s s' : Cas.State H}
    (step : ∀ {c c'}, P c c' → CellStep c c')
    (hinv : SystemSafety.SystemInvariant s) (h : Across P s s') :
    SystemSafety.SystemInvariant s' := by
  intro root
  rcases h root with changed | same
  · exact SystemSafety.safe_step (hinv root) (step changed)
  · rw [same]
    exact hinv root

theorem initial_invariant : Invariant (Initial : State H) :=
  ⟨SystemSafety.initial_invariant, MptGc.initial_invariant⟩

theorem invariant_step {s s' : State H} (hinv : Invariant s) (hstep : Step s s') :
    Invariant s' := by
  obtain ⟨casInv, mptInv⟩ := hinv
  cases hstep with
  | cas step _ => exact ⟨replace_forall casInv (SystemSafety.safe_step (casInv _) step), mptInv⟩
  | mpt step => exact ⟨casInv, MptGc.sync_invariant_step mptInv step⟩
  | sourcePublish casStep mptStep =>
      exact ⟨across_safe (fun h => .sourcePublish h) casInv casStep,
        MptGc.invariant_step mptInv (.ownPublish mptStep)⟩
  | ordinaryPromote casStep mptStep =>
      exact ⟨across_safe (fun h => .ordinaryPromote h) casInv casStep,
        MptGc.invariant_step mptInv (.promote mptStep)⟩
  | replicaPromote casStep mptStep =>
      exact ⟨across_safe (fun h => .replicaPromote h) casInv casStep,
        MptGc.invariant_step mptInv (.promote mptStep)⟩

theorem reachable_invariant {s : State H} (h : Reachable s) : Invariant s := by
  induction h with
  | initial => exact initial_invariant
  | next _ step ih => exact invariant_step ih step

/-! ## What the paired transactions commit -/

variable {s : State H} {root : Root} {holder : H}

theorem gc_cannot_create_promised_missing
    (reachable : Reachable s) (pinned : (s.cas root).pin holder) : Available (s.cas root) :=
  ((reachable_invariant reachable).1 root).2.pin_available holder pinned

omit [Roles H] in
/-- A root the transaction changed took the transition. -/
theorem across_changed {P : Cell H → Cell H → Prop} {s s' : Cas.State H}
    (h : Across P s s') (changed : s' root ≠ s root) : P (s root) (s' root) :=
  (h root).resolve_right changed

/-- Publication commits, for every root it changes, an entry, the publisher's
pin and available content, together with an active, materialized head. -/
theorem source_publish_commits_one_closed_state {cas' : Cas.State H} {mpt' : MptGc.State}
    (casStep : Across (SourcePublish holder) s.cas cas') (mptStep : MptGc.OwnPublish s.mpt mpt')
    (changed : cas' root ≠ s.cas root) :
    (cas' root).entry ∧ (cas' root).pin holder ∧ Available (cas' root) ∧
      mpt'.active ∧ mpt'.materialized :=
  let casClosed := Cas.source_publish_is_closed (across_changed casStep changed)
  let mptClosed := MptGc.own_publish_is_atomic mptStep
  ⟨casClosed.1, casClosed.2.1, casClosed.2.2, mptClosed.1, mptClosed.2.2.2⟩

/-- Promotion commits, for every root it changes, an entry and either the
replica's pin over available content or its want, together with an active,
materialized head. -/
theorem replica_promotion_commits_pin_or_want {cas' : Cas.State H} {mpt' : MptGc.State}
    (casStep : Across (ReplicaPromote holder) s.cas cas') (mptStep : MptGc.Promote s.mpt mpt')
    (changed : cas' root ≠ s.cas root) :
    (cas' root).entry ∧
      (((cas' root).pin holder ∧ Available (cas' root)) ∨ (cas' root).want holder) ∧
      mpt'.active ∧ mpt'.materialized :=
  let casClosed := Cas.replica_promotion_is_total (across_changed casStep changed)
  let mptClosed := MptGc.promotion_is_atomic mptStep
  ⟨casClosed.1, casClosed.2, mptClosed.1, mptClosed.2.2.2⟩

end Synchronicity.Safety
