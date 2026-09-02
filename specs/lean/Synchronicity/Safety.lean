import Synchronicity.CasGc
import Synchronicity.MptGc

/-!
The bridge model.  Source publication and remote promotion pair the CAS and
trie transitions that share one SQLite transaction in Rust.  Independent CAS
and mptsync steps may interleave everywhere else.
-/

namespace Synchronicity.Safety

structure State where
  cas : CasGc.State := {}
  mpt : MptGc.State := {}

def Invariant (s : State) : Prop :=
  CasGc.Invariant s.cas ∧ MptGc.Invariant s.mpt

inductive Step : State → State → Prop where
  | cas : CasGc.LocalStep s.cas cas' → Step s { s with cas := cas' }
  | mpt : MptGc.SyncStep s.mpt mpt' → Step s { s with mpt := mpt' }
  | sourcePublish :
      CasGc.SourcePublish s.cas cas' →
      MptGc.OwnPublish s.mpt mpt' →
      Step s { cas := cas', mpt := mpt' }
  | ordinaryPromote :
      CasGc.OrdinaryPromote s.cas cas' →
      MptGc.Promote s.mpt mpt' →
      Step s { cas := cas', mpt := mpt' }
  | replicaPromote :
      CasGc.ReplicaPromote s.cas cas' →
      MptGc.Promote s.mpt mpt' →
      Step s { cas := cas', mpt := mpt' }

def Initial : State := {}

inductive Reachable : State → Prop where
  | initial : Reachable Initial
  | next : Reachable s → Step s s' → Reachable s'

theorem initial_invariant : Invariant Initial := by
  exact ⟨CasGc.initial_invariant, MptGc.initial_invariant⟩

theorem invariant_step (hinv : Invariant s) (hstep : Step s s') : Invariant s' := by
  rcases hinv with ⟨casInv, mptInv⟩
  cases hstep with
  | cas step => exact ⟨CasGc.local_invariant_step casInv step, mptInv⟩
  | mpt step => exact ⟨casInv, MptGc.sync_invariant_step mptInv step⟩
  | sourcePublish casStep mptStep =>
      exact ⟨CasGc.invariant_step casInv (.sourcePublish casStep),
        MptGc.invariant_step mptInv (.ownPublish mptStep)⟩
  | ordinaryPromote casStep mptStep =>
      exact ⟨CasGc.invariant_step casInv (.ordinaryPromote casStep),
        MptGc.invariant_step mptInv (.promote mptStep)⟩
  | replicaPromote casStep mptStep =>
      exact ⟨CasGc.invariant_step casInv (.replicaPromote casStep),
        MptGc.invariant_step mptInv (.promote mptStep)⟩

theorem reachable_invariant (h : Reachable s) : Invariant s := by
  induction h with
  | initial => exact initial_invariant
  | next _ step ih => exact invariant_step ih step

theorem gc_cannot_create_promised_missing
    (reachable : Reachable s) (pinned : s.cas.pin) : CasGc.Available s.cas :=
  (reachable_invariant reachable).1.1 pinned

theorem source_publish_commits_one_closed_state
    (s : State) (cas' : CasGc.State) (mpt' : MptGc.State)
    (casStep : CasGc.SourcePublish s.cas cas')
    (mptStep : MptGc.OwnPublish s.mpt mpt') :
    cas'.entry ∧ cas'.pin ∧ CasGc.Available cas' ∧
      mpt'.active ∧ mpt'.materialized := by
  have casClosed := CasGc.source_publish_is_closed casStep
  have mptClosed := MptGc.own_publish_is_atomic mptStep
  exact ⟨casClosed.1, casClosed.2.1, casClosed.2.2,
    mptClosed.1, mptClosed.2.2.2⟩

theorem replica_promotion_commits_pin_or_want
    (s : State) (cas' : CasGc.State) (mpt' : MptGc.State)
    (casStep : CasGc.ReplicaPromote s.cas cas')
    (mptStep : MptGc.Promote s.mpt mpt') :
    cas'.entry ∧ ((cas'.pin ∧ CasGc.Available cas') ∨ cas'.want) ∧
      mpt'.active ∧ mpt'.materialized := by
  have casClosed := CasGc.replica_promotion_is_total casStep
  have mptClosed := MptGc.promotion_is_atomic mptStep
  exact ⟨casClosed.1, casClosed.2, mptClosed.1, mptClosed.2.2.2⟩

end Synchronicity.Safety
