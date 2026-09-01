/-!
The per-content-root state machine shared by CAS ingest, retention and GC.

The model deliberately separates a materialized `entry` from a `pin`:
metadata-only nodes may name content they do not hold, while a pin is the
local durability promise.  Filesystem deletion is split into `gcCommit` and
`gcUnlink`, matching the Rust row-first ordering and the connection guard held
between them.
-/

namespace Synchronicity.CasGc

structure State where
  entry : Prop := False
  pin : Prop := False
  want : Prop := False
  row : Prop := False
  bytes : Prop := False
  remote : Prop := False
  durable : Prop := False
  writing : Prop := False
  sweeping : Prop := False
  fresh : Prop := False

def Available (s : State) : Prop :=
  s.row ∧ s.durable ∧ (s.bytes ∨ s.remote)

def Collectable (s : State) : Prop :=
  s.row ∧ ¬s.entry ∧ ¬s.pin ∧ ¬s.writing ∧ ¬s.sweeping ∧ ¬s.fresh

def Invariant (s : State) : Prop :=
  (s.pin → Available s) ∧
  (s.sweeping → ¬s.pin ∧ ¬s.entry ∧ ¬s.writing ∧ ¬s.row)

/- RUST-IMPL: cas-write-lease-begin — `db.rs::Store::lease_write`. -/
def BeginWrite (s s' : State) : Prop :=
  ¬s.sweeping ∧ s' = { s with writing := True }

/- RUST-IMPL: cas-write-complete-commit — `cas.rs::write_blob_row`. -/
def CommitComplete (s s' : State) : Prop :=
  ¬s.sweeping ∧
  (s' = { s with
      row := True
      bytes := True
      durable := True
      writing := False
      fresh := True } ∨
    s' = { s with
      row := True
      bytes := True
      writing := False
      fresh := True })

/- RUST-IMPL: cas-write-groups-commit — `cas.rs::commit_groups`. -/
def CommitGroups (s s' : State) : Prop := CommitComplete s s'

/- RUST-IMPL: cas-cloud-finalize — `backend.rs::Cloud::finalize`. -/
def FinalizeRemote (s s' : State) : Prop :=
  ¬s.sweeping ∧ s.row ∧
  s' = { s with remote := True, durable := True }

/- RUST-IMPL: cas-retention-elapses — `gc.rs::gc_content(before)`. -/
def Age (s s' : State) : Prop :=
  s' = { s with fresh := False }

/- RUST-IMPL: cas-gc-row-commit — `cas.rs::delete_blob_if_collectable`. -/
def GcCommit (s s' : State) : Prop :=
  Collectable s ∧
  s' = { s with row := False, durable := False, sweeping := True }

/- RUST-IMPL: cas-gc-unlink — the unlink half of `delete_blob_if_collectable`. -/
def GcUnlink (s s' : State) : Prop :=
  s.sweeping ∧
  s' = { s with bytes := False, sweeping := False }

/- RUST-IMPL: cas-source-publish — `node.rs::Node::publish`. -/
def SourcePublish (s s' : State) : Prop :=
  ¬s.sweeping ∧ Available s ∧
  s' = { s with entry := True, pin := True, want := False }

/- RUST-IMPL: cas-remote-promotion — `reconcile.rs::try_promote`. -/
def OrdinaryPromote (s s' : State) : Prop :=
  ¬s.sweeping ∧
  s' = { s with entry := True }

def ReplicaPromote (s s' : State) : Prop :=
  ¬s.sweeping ∧
  ((Available s ∧
      s' = { s with entry := True, pin := True, want := False }) ∨
    (¬Available s ∧
      s' = { s with entry := True, pin := False, want := True }))

/- RUST-IMPL: cas-take-possession — `replica.rs::take_possession`. -/
def TakePossession (s s' : State) : Prop :=
  ¬s.sweeping ∧ s.want ∧ Available s ∧
  s' = { s with pin := True, want := False }

inductive Step : State → State → Prop where
  | beginWrite : BeginWrite s s' → Step s s'
  | commitComplete : CommitComplete s s' → Step s s'
  | commitGroups : CommitGroups s s' → Step s s'
  | finalizeRemote : FinalizeRemote s s' → Step s s'
  | age : Age s s' → Step s s'
  | gcCommit : GcCommit s s' → Step s s'
  | gcUnlink : GcUnlink s s' → Step s s'
  | sourcePublish : SourcePublish s s' → Step s s'
  | ordinaryPromote : OrdinaryPromote s s' → Step s s'
  | replicaPromote : ReplicaPromote s s' → Step s s'
  | takePossession : TakePossession s s' → Step s s'

/- Operations that may interleave independently of a trie/head transaction. -/
inductive LocalStep : State → State → Prop where
  | beginWrite : BeginWrite s s' → LocalStep s s'
  | commitComplete : CommitComplete s s' → LocalStep s s'
  | commitGroups : CommitGroups s s' → LocalStep s s'
  | finalizeRemote : FinalizeRemote s s' → LocalStep s s'
  | age : Age s s' → LocalStep s s'
  | gcCommit : GcCommit s s' → LocalStep s s'
  | gcUnlink : GcUnlink s s' → LocalStep s s'
  | takePossession : TakePossession s s' → LocalStep s s'

def Initial : State := {}

inductive Reachable : State → Prop where
  | initial : Reachable Initial
  | next : Reachable s → Step s s' → Reachable s'

theorem initial_invariant : Invariant Initial := by
  simp [Initial, Invariant]

theorem invariant_step (hinv : Invariant s) (hstep : Step s s') : Invariant s' := by
  cases hstep with
  | beginWrite h => simp_all [BeginWrite, Invariant, Available]
  | commitComplete h =>
      rcases h with ⟨notSweeping, outcome⟩
      rcases outcome with localCommit | staged <;>
        simp_all [Invariant, Available]
  | commitGroups h =>
      change CommitComplete _ _ at h
      rcases h with ⟨notSweeping, outcome⟩
      rcases outcome with localCommit | staged <;>
        simp_all [Invariant, Available]
  | finalizeRemote h => simp_all [FinalizeRemote, Invariant, Available]
  | age h => simp_all [Age, Invariant, Available]
  | gcCommit h => simp_all [GcCommit, Collectable, Invariant, Available]
  | gcUnlink h => simp_all [GcUnlink, Invariant, Available]
  | sourcePublish h => simp_all [SourcePublish, Invariant, Available]
  | ordinaryPromote h => simp_all [OrdinaryPromote, Invariant, Available]
  | replicaPromote h =>
      rcases h with ⟨notSweeping, held | missing⟩
      · rcases held with ⟨available, rfl⟩
        constructor
        · intro _
          exact available
        · intro sweeping
          exact False.elim (notSweeping sweeping)
      · rcases missing with ⟨_, rfl⟩
        constructor
        · intro pinned
          exact False.elim pinned
        · intro sweeping
          exact False.elim (notSweeping sweeping)
  | takePossession h => simp_all [TakePossession, Invariant, Available]

theorem local_invariant_step (hinv : Invariant s) (hstep : LocalStep s s') : Invariant s' := by
  cases hstep with
  | beginWrite h => exact invariant_step hinv (.beginWrite h)
  | commitComplete h => exact invariant_step hinv (.commitComplete h)
  | commitGroups h => exact invariant_step hinv (.commitGroups h)
  | finalizeRemote h => exact invariant_step hinv (.finalizeRemote h)
  | age h => exact invariant_step hinv (.age h)
  | gcCommit h => exact invariant_step hinv (.gcCommit h)
  | gcUnlink h => exact invariant_step hinv (.gcUnlink h)
  | takePossession h => exact invariant_step hinv (.takePossession h)

theorem reachable_invariant (h : Reachable s) : Invariant s := by
  induction h with
  | initial => exact initial_invariant
  | next _ step ih => exact invariant_step ih step

theorem promised_content_is_safe (h : Reachable s) (pinned : s.pin) : Available s :=
  (reachable_invariant h).1 pinned

theorem gc_respects_protection
    (hgc : GcCommit s s') (guarded : s.entry ∨ s.pin ∨ s.writing) : False := by
  rcases hgc with ⟨⟨_, noEntry, noPin, noWrite, _⟩, _⟩
  rcases guarded with entry | pin | writing
  · exact noEntry entry
  · exact noPin pin
  · exact noWrite writing

theorem write_lease_excludes_gc (writing : s.writing) (hgc : GcCommit s s') : False :=
  gc_respects_protection hgc (Or.inr (Or.inr writing))

theorem source_publish_is_closed (h : SourcePublish s s') :
    s'.entry ∧ s'.pin ∧ Available s' := by
  rcases h with ⟨_, available, rfl⟩
  exact ⟨trivial, trivial, available⟩

theorem replica_promotion_is_total (h : ReplicaPromote s s') :
    s'.entry ∧ ((s'.pin ∧ Available s') ∨ s'.want) := by
  rcases h with ⟨_, held | missing⟩
  · rcases held with ⟨available, rfl⟩
    exact ⟨trivial, Or.inl ⟨trivial, available⟩⟩
  · rcases missing with ⟨_, rfl⟩
    exact ⟨trivial, Or.inr trivial⟩

theorem possession_is_atomic (h : TakePossession s s') :
    s'.pin ∧ ¬s'.want ∧ Available s' := by
  rcases h with ⟨_, _, available, rfl⟩
  exact ⟨trivial, id, available⟩

end Synchronicity.CasGc
