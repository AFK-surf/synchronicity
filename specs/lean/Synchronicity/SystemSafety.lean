/-!
The root- and holder-indexed safety model.

`Cell.sourceLive`, `replicaLive`, and `ordinaryLive` are the materialized
content leaves of active tries.  Keeping the relation in the same per-content
cell makes the safety statement small while retaining the two identities the
one-object model erased: which content root a leaf names, and which holder is
responsible for its pin or want.
-/

namespace Synchronicity.SystemSafety

abbrev Root := Nat
abbrev Holder := Nat

def add (p : Holder → Prop) (holder : Holder) : Holder → Prop :=
  fun candidate => candidate = holder ∨ p candidate

def drop (p : Holder → Prop) (holder : Holder) : Holder → Prop :=
  fun candidate => p candidate ∧ candidate ≠ holder

/-- The operator's holder, `synch pin add`.  Every other holder is a role a
space configures — a source or a replica — and only roles stand behind live
leaves.  `FaultTolerant` needs the distinction because the heal paths treat the
two differently. -/
def operator : Holder := 0

def IsRole (holder : Holder) : Prop := holder ≠ operator

structure Cell where
  entry : Prop := False
  pin : Holder → Prop := fun _ => False
  want : Holder → Prop := fun _ => False
  sourceLive : Holder → Prop := fun _ => False
  replicaLive : Holder → Prop := fun _ => False
  ordinaryLive : Holder → Prop := fun _ => False
  row : Prop := False
  bytes : Prop := False
  remote : Prop := False
  durable : Prop := False
  writing : Prop := False
  sweeping : Prop := False
  fresh : Prop := False

def Available (c : Cell) : Prop :=
  c.row ∧ c.durable ∧ (c.bytes ∨ c.remote)

def AnyPin (c : Cell) : Prop := ∃ holder, c.pin holder

def AnyLive (c : Cell) : Prop :=
  ∃ holder, c.sourceLive holder ∨ c.replicaLive holder ∨ c.ordinaryLive holder

def Collectable (c : Cell) : Prop :=
  c.row ∧ ¬c.entry ∧ ¬AnyPin c ∧ ¬c.writing ∧ ¬c.sweeping ∧ ¬c.fresh

def Deletable (c : Cell) : Prop :=
  ¬c.entry ∧ ¬AnyPin c ∧ ¬c.writing ∧ ¬c.sweeping

def Invariant (c : Cell) : Prop :=
  (∀ holder, c.pin holder → Available c) ∧
  (∀ holder, c.sourceLive holder →
    c.entry ∧ c.pin holder ∧ Available c) ∧
  (∀ holder, c.replicaLive holder →
    c.entry ∧ ((c.pin holder ∧ Available c) ∨ c.want holder)) ∧
  (∀ holder, c.ordinaryLive holder → c.entry) ∧
  (c.sweeping → ¬c.entry ∧ (∀ holder, ¬c.pin holder) ∧ ¬c.writing ∧ ¬c.row)

/- RUST-REF: cas-write-lease-begin — `db.rs::Store::lease_write`. -/
def BeginWrite (c c' : Cell) : Prop :=
  ¬c.sweeping ∧ c' = { c with writing := True }

/- RUST-IMPL: cas-write-lease-end — `db.rs::WriteLease::drop`. -/
def WriteAbort (c c' : Cell) : Prop :=
  c' = { c with writing := False }

/- RUST-REF: cas-write-complete-commit — `cas.rs::write_blob_row`. -/
def CommitAvailable (c c' : Cell) : Prop :=
  ¬c.sweeping ∧ c' = { c with
    row := True
    bytes := True
    durable := True
    writing := False
    fresh := True }

/- RUST-REF: cas-cloud-finalize — `backend.rs::Cloud::finalize`. -/
def FinalizeRemote (c c' : Cell) : Prop :=
  ¬c.sweeping ∧ c.row ∧ c' = { c with remote := True, durable := True }

/- RUST-REF: cas-retention-elapses — `gc.rs::gc_content(before)`. -/
def Age (c c' : Cell) : Prop :=
  c' = { c with fresh := False }

/- RUST-IMPL: cas-adopt-durable — `cas.rs::Store::adopt_durable_blob`.
   A cold durable row reconstructed after the remote backend confirmed the
   final pair exists. -/
def AdoptRemote (c c' : Cell) : Prop :=
  ¬c.sweeping ∧ c' = { c with row := True, remote := True, durable := True }

/- RUST-IMPL: cas-cache-evict — `cas.rs::clear_blob_cache`. -/
def CacheEvict (c c' : Cell) : Prop :=
  c.remote ∧ c.durable ∧ c' = { c with bytes := False }

/- RUST-IMPL: cas-drop-staged-row — the non-durable branch of
   `cas.rs::clear_blob_cache`, `reconcile_scratch_generation`, and the
   `commit_cas_migration` discard.  None of them consult `pins`; the invariant
   is what makes that safe (`staged_row_drop_is_unpinned`). -/
def DropStaged (c c' : Cell) : Prop :=
  ¬c.durable ∧ ¬c.writing ∧ c' = { c with row := False, bytes := False }

/- RUST-REF: cas-source-publish — `node.rs::Node::publish`. -/
def SourcePublish (holder : Holder) (c c' : Cell) : Prop :=
  IsRole holder ∧ ¬c.sweeping ∧ Available c ∧
  c' = { c with
    entry := True
    pin := add c.pin holder
    want := drop c.want holder
    sourceLive := add c.sourceLive holder }

/- RUST-REF: cas-remote-promotion — `reconcile.rs::try_promote`. -/
def ReplicaPromote (holder : Holder) (c c' : Cell) : Prop :=
  IsRole holder ∧ ¬c.sweeping ∧
  ((Available c ∧ c' = { c with
      entry := True
      pin := add c.pin holder
      want := drop c.want holder
      replicaLive := add c.replicaLive holder }) ∨
   (¬Available c ∧ c' = { c with
      entry := True
      want := add c.want holder
      replicaLive := add c.replicaLive holder }))

def OrdinaryPromote (holder : Holder) (c c' : Cell) : Prop :=
  ¬c.sweeping ∧ c' = { c with
    entry := True
    ordinaryLive := add c.ordinaryLive holder }

/- RUST-IMPL: mpt-materialize-live-diff — `views.rs::Txn::materialize_diff`. -/
def RemoveSource (holder : Holder) (c c' : Cell) : Prop :=
  c' = { c with sourceLive := drop c.sourceLive holder }

def RemoveReplica (holder : Holder) (c c' : Cell) : Prop :=
  c' = { c with replicaLive := drop c.replicaLive holder }

def RemoveOrdinary (holder : Holder) (c c' : Cell) : Prop :=
  c' = { c with ordinaryLive := drop c.ordinaryLive holder }

def DropEntry (c c' : Cell) : Prop :=
  (∀ holder, ¬c.sourceLive holder ∧ ¬c.replicaLive holder ∧
    ¬c.ordinaryLive holder) ∧
  c' = { c with entry := False }

/- RUST-IMPL: cas-pin — `cas.rs::Store::pin`. -/
def Pin (holder : Holder) (c c' : Cell) : Prop :=
  ¬c.sweeping ∧ Available c ∧
  c' = { c with pin := add c.pin holder }

/- RUST-IMPL: cas-unpin — `cas.rs::Store::unpin`. -/
def Unpin (holder : Holder) (c c' : Cell) : Prop :=
  ¬c.sourceLive holder ∧ ¬c.replicaLive holder ∧
  c' = { c with pin := drop c.pin holder }

/- RUST-IMPL: cas-expire-pin — `cas.rs::Store::expire_pins_of`/`expire_pins`. -/
def ExpirePin (holder : Holder) (c c' : Cell) : Prop := Unpin holder c c'

/- RUST-IMPL: cas-drop-want — `replica.rs::Store::drop_want`. -/
def DropWant (holder : Holder) (c c' : Cell) : Prop :=
  ¬c.sourceLive holder ∧ ¬c.replicaLive holder ∧
  c' = { c with want := drop c.want holder }

/- RUST-REF: cas-take-possession — `replica.rs::take_possession`. -/
def TakePossession (holder : Holder) (c c' : Cell) : Prop :=
  ¬c.sweeping ∧ c.want holder ∧ Available c ∧
  c' = { c with pin := add c.pin holder, want := drop c.want holder }

/- RUST-REF: cas-gc-row-commit — `cas.rs::delete_blob_if_collectable`. -/
def GcCommit (c c' : Cell) : Prop :=
  Collectable c ∧
  c' = { c with row := False, durable := False, sweeping := True }

/- RUST-REF: cas-gc-unlink — `cas.rs::delete_blob_if_collectable`. -/
def GcUnlink (c c' : Cell) : Prop :=
  c.sweeping ∧ c' = { c with bytes := False, sweeping := False }

/- RUST-IMPL: cas-protected-delete — `cas.rs::Store::delete_blob`. -/
def ProtectedDelete (c c' : Cell) : Prop :=
  Deletable c ∧
  c' = { c with row := False, durable := False, sweeping := True }

inductive CellStep : Cell → Cell → Prop where
  | beginWrite : BeginWrite c c' → CellStep c c'
  | writeAbort : WriteAbort c c' → CellStep c c'
  | commitAvailable : CommitAvailable c c' → CellStep c c'
  | finalizeRemote : FinalizeRemote c c' → CellStep c c'
  | age : Age c c' → CellStep c c'
  | adoptRemote : AdoptRemote c c' → CellStep c c'
  | cacheEvict : CacheEvict c c' → CellStep c c'
  | dropStaged : DropStaged c c' → CellStep c c'
  | sourcePublish : SourcePublish holder c c' → CellStep c c'
  | replicaPromote : ReplicaPromote holder c c' → CellStep c c'
  | ordinaryPromote : OrdinaryPromote holder c c' → CellStep c c'
  | removeSource : RemoveSource holder c c' → CellStep c c'
  | removeReplica : RemoveReplica holder c c' → CellStep c c'
  | removeOrdinary : RemoveOrdinary holder c c' → CellStep c c'
  | dropEntry : DropEntry c c' → CellStep c c'
  | pin : Pin holder c c' → CellStep c c'
  | unpin : Unpin holder c c' → CellStep c c'
  | dropWant : DropWant holder c c' → CellStep c c'
  | takePossession : TakePossession holder c c' → CellStep c c'
  | gcCommit : GcCommit c c' → CellStep c c'
  | gcUnlink : GcUnlink c c' → CellStep c c'
  | protectedDelete : ProtectedDelete c c' → CellStep c c'

abbrev State := Root → Cell

def Initial : State := fun _ => {}

def SystemInvariant (s : State) : Prop := ∀ root, Invariant (s root)

def Replace (s : State) (root : Root) (cell : Cell) : State :=
  fun candidate => if candidate = root then cell else s candidate

inductive Step : State → State → Prop where
  | root : CellStep (s root) cell' → Step s (Replace s root cell')

inductive Reachable : State → Prop where
  | initial : Reachable Initial
  | next : Reachable s → Step s s' → Reachable s'

theorem initial_invariant : SystemInvariant Initial := by
  simp [SystemInvariant, Initial, Invariant]

theorem cell_invariant_step (hinv : Invariant c) (hstep : CellStep c c') :
    Invariant c' := by
  rcases hinv with ⟨pins, sources, replicas, ordinary, sweepInv⟩
  cases hstep with
  | beginWrite h =>
      rcases h with ⟨notSweeping, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · simpa [Available] using pins
      · simpa [Available] using sources
      · simpa [Available] using replicas
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | writeAbort h =>
      rcases h with ⟨rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · simpa [Available] using pins
      · simpa [Available] using sources
      · simpa [Available] using replicas
      · intro sweeping
        have old := sweepInv sweeping
        exact ⟨old.1, old.2.1, by simp, old.2.2.2⟩
  | commitAvailable h =>
      rcases h with ⟨notSweeping, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder _
        simp [Available]
      · intro holder live
        have old := sources holder live
        exact ⟨old.1, old.2.1, by simp [Available]⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2 with pinned | wanted
        · exact ⟨old.1, Or.inl ⟨pinned.1, by simp [Available]⟩⟩
        · exact ⟨old.1, Or.inr wanted⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | finalizeRemote h =>
      rcases h with ⟨notSweeping, row, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder _
        exact ⟨row, trivial, Or.inr trivial⟩
      · intro holder live
        have old := sources holder live
        exact ⟨old.1, old.2.1, row, trivial, Or.inr trivial⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2 with pinned | wanted
        · exact ⟨old.1, Or.inl ⟨pinned.1, row, trivial, Or.inr trivial⟩⟩
        · exact ⟨old.1, Or.inr wanted⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | age h =>
      rcases h with ⟨rfl⟩
      exact ⟨pins, sources, replicas, ordinary, sweepInv⟩
  | adoptRemote h =>
      rcases h with ⟨notSweeping, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder _
        simp [Available]
      · intro holder live
        have old := sources holder live
        exact ⟨old.1, old.2.1, by simp [Available]⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2 with pinned | wanted
        · exact ⟨old.1, Or.inl ⟨pinned.1, by simp [Available]⟩⟩
        · exact ⟨old.1, Or.inr wanted⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | dropStaged h =>
      rcases h with ⟨notDurable, _, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder pinned
        exact False.elim (notDurable (pins holder pinned).2.1)
      · intro holder live
        exact False.elim (notDurable (sources holder live).2.2.2.1)
      · intro holder live
        have old := replicas holder live
        rcases old.2 with pinned | wanted
        · exact False.elim (notDurable pinned.2.2.1)
        · exact ⟨old.1, Or.inr wanted⟩
      · intro sweeping
        have old := sweepInv sweeping
        exact ⟨old.1, old.2.1, old.2.2.1, id⟩
  | cacheEvict h =>
      rcases h with ⟨remote, durable, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, sweepInv⟩
      · intro holder pinned
        exact ⟨(pins holder pinned).1, durable, Or.inr remote⟩
      · intro holder live
        have old := sources holder live
        exact ⟨old.1, old.2.1, old.2.2.1, durable, Or.inr remote⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2 with pinned | wanted
        · exact ⟨old.1, Or.inl ⟨pinned.1, pinned.2.1, durable, Or.inr remote⟩⟩
        · exact ⟨old.1, Or.inr wanted⟩
  | sourcePublish h =>
      rename_i target
      rcases h with ⟨_, notSweeping, available, rfl⟩
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · intro candidate pinned
        rcases pinned with rfl | old
        · exact available
        · exact pins candidate old
      · intro candidate live
        rcases live with rfl | old
        · exact ⟨trivial, Or.inl rfl, available⟩
        · have prior := sources candidate old
          exact ⟨trivial, Or.inr prior.2.1, prior.2.2⟩
      · intro candidate live
        have old := replicas candidate live
        rcases old.2 with pinned | wanted
        · exact ⟨trivial, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
        · by_cases same : candidate = target
          · exact ⟨trivial, Or.inl ⟨Or.inl same, available⟩⟩
          · exact ⟨trivial, Or.inr ⟨wanted, same⟩⟩
      · intro _ _
        trivial
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | replicaPromote h =>
      rename_i target
      rcases h with ⟨_, notSweeping, held | missing⟩
      · rcases held with ⟨available, rfl⟩
        refine ⟨?_, ?_, ?_, ?_, ?_⟩
        · intro candidate pinned
          rcases pinned with rfl | old
          · exact available
          · exact pins candidate old
        · intro candidate live
          have old := sources candidate live
          exact ⟨trivial, Or.inr old.2.1, old.2.2⟩
        · intro candidate live
          rcases live with rfl | old
          · exact ⟨trivial, Or.inl ⟨Or.inl rfl, available⟩⟩
          · have prior := replicas candidate old
            rcases prior.2 with pinned | wanted
            · exact ⟨trivial, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
            · by_cases same : candidate = target
              · exact ⟨trivial, Or.inl ⟨Or.inl same, available⟩⟩
              · exact ⟨trivial, Or.inr ⟨wanted, same⟩⟩
        · intro _ _
          trivial
        · intro sweeping
          exact False.elim (notSweeping sweeping)
      · rcases missing with ⟨unavailable, rfl⟩
        refine ⟨pins, ?_, ?_, ?_, ?_⟩
        · intro candidate live
          have old := sources candidate live
          exact ⟨trivial, old.2⟩
        · intro candidate live
          rcases live with rfl | old
          · exact ⟨trivial, Or.inr (Or.inl rfl)⟩
          · have prior := replicas candidate old
            exact ⟨trivial, prior.2.imp id (fun wanted => Or.inr wanted)⟩
        · intro _ _
          trivial
        · intro sweeping
          exact False.elim (notSweeping sweeping)
  | ordinaryPromote h =>
      rcases h with ⟨notSweeping, rfl⟩
      refine ⟨pins, ?_, ?_, ?_, ?_⟩
      · intro candidate live
        have old := sources candidate live
        exact ⟨trivial, old.2⟩
      · intro candidate live
        exact ⟨trivial, (replicas candidate live).2⟩
      · intro _ _
        trivial
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | removeSource h =>
      rcases h with ⟨rfl⟩
      refine ⟨pins, ?_, replicas, ordinary, sweepInv⟩
      intro candidate live
      exact sources candidate live.1
  | removeReplica h =>
      rcases h with ⟨rfl⟩
      refine ⟨pins, sources, ?_, ordinary, sweepInv⟩
      intro candidate live
      exact replicas candidate live.1
  | removeOrdinary h =>
      rcases h with ⟨rfl⟩
      refine ⟨pins, sources, replicas, ?_, sweepInv⟩
      intro candidate live
      exact ordinary candidate live.1
  | dropEntry h =>
      rcases h with ⟨noLive, rfl⟩
      refine ⟨pins, ?_, ?_, ?_, ?_⟩
      · intro holder live
        exact False.elim ((noLive holder).1 live)
      · intro holder live
        exact False.elim ((noLive holder).2.1 live)
      · intro holder live
        exact False.elim ((noLive holder).2.2 live)
      · intro sweeping
        have old := sweepInv sweeping
        exact ⟨id, old.2⟩
  | pin h =>
      rename_i target
      rcases h with ⟨notSweeping, available, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro candidate pinned
        rcases pinned with rfl | old
        · exact available
        · exact pins candidate old
      · intro candidate live
        have old := sources candidate live
        exact ⟨old.1, Or.inr old.2.1, old.2.2⟩
      · intro candidate live
        have old := replicas candidate live
        rcases old.2 with pinned | wanted
        · exact ⟨old.1, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
        · by_cases same : candidate = target
          · exact ⟨old.1, Or.inl ⟨Or.inl same, available⟩⟩
          · exact ⟨old.1, Or.inr wanted⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | unpin h =>
      rename_i target
      rcases h with ⟨noSource, noReplica, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro candidate pinned
        exact pins candidate pinned.1
      · intro candidate live
        by_cases same : candidate = target
        · exact False.elim (noSource (same ▸ live))
        · have old := sources candidate live
          exact ⟨old.1, ⟨old.2.1, same⟩, old.2.2⟩
      · intro candidate live
        by_cases same : candidate = target
        · exact False.elim (noReplica (same ▸ live))
        · have old := replicas candidate live
          rcases old.2 with pinned | wanted
          · exact ⟨old.1, Or.inl ⟨⟨pinned.1, same⟩, pinned.2⟩⟩
          · exact ⟨old.1, Or.inr wanted⟩
      · intro sweeping
        have old := sweepInv sweeping
        exact ⟨old.1, fun candidate pinned => old.2.1 candidate pinned.1,
          old.2.2⟩
  | dropWant h =>
      rename_i target
      rcases h with ⟨_, noReplica, rfl⟩
      refine ⟨pins, sources, ?_, ordinary, sweepInv⟩
      intro candidate live
      by_cases same : candidate = target
      · exact False.elim (noReplica (same ▸ live))
      · have old := replicas candidate live
        rcases old.2 with pinned | wanted
        · exact ⟨old.1, Or.inl pinned⟩
        · exact ⟨old.1, Or.inr ⟨wanted, same⟩⟩
  | takePossession h =>
      rename_i target
      rcases h with ⟨notSweeping, _, available, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro candidate pinned
        rcases pinned with rfl | old
        · exact available
        · exact pins candidate old
      · intro candidate live
        have old := sources candidate live
        exact ⟨old.1, Or.inr old.2.1, old.2.2⟩
      · intro candidate live
        have old := replicas candidate live
        rcases old.2 with pinned | wanted
        · exact ⟨old.1, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
        · by_cases same : candidate = target
          · exact ⟨old.1, Or.inl ⟨Or.inl same, available⟩⟩
          · exact ⟨old.1, Or.inr ⟨wanted, same⟩⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | gcCommit h =>
      rcases h with ⟨collectable, rfl⟩
      rcases collectable with ⟨_, noEntry, noPin, noWriting, _, _⟩
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · intro holder pinned
        exact False.elim (noPin ⟨holder, pinned⟩)
      · intro holder live
        exact False.elim (noEntry (sources holder live).1)
      · intro holder live
        exact False.elim (noEntry (replicas holder live).1)
      · intro holder live
        exact False.elim (noEntry (ordinary holder live))
      · intro _
        exact ⟨noEntry, fun holder pinned => noPin ⟨holder, pinned⟩,
          noWriting, id⟩
  | gcUnlink h =>
      rcases h with ⟨sweeping, rfl⟩
      have old := sweepInv sweeping
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder pinned
        exact False.elim (old.2.1 holder pinned)
      · intro holder live
        exact False.elim (old.1 (sources holder live).1)
      · intro holder live
        exact False.elim (old.1 (replicas holder live).1)
      · intro impossible
        exact False.elim impossible
  | protectedDelete h =>
      rcases h with ⟨deletable, rfl⟩
      rcases deletable with ⟨noEntry, noPin, noWriting, _⟩
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · intro holder pinned
        exact False.elim (noPin ⟨holder, pinned⟩)
      · intro holder live
        exact False.elim (noEntry (sources holder live).1)
      · intro holder live
        exact False.elim (noEntry (replicas holder live).1)
      · intro holder live
        exact False.elim (noEntry (ordinary holder live))
      · intro _
        exact ⟨noEntry, fun holder pinned => noPin ⟨holder, pinned⟩,
          noWriting, id⟩

theorem invariant_step (hinv : SystemInvariant s) (hstep : Step s s') :
    SystemInvariant s' := by
  cases hstep with
  | root step =>
      intro candidate
      simp only [Replace]
      split
      · exact cell_invariant_step (hinv _) step
      · exact hinv candidate

theorem reachable_invariant (h : Reachable s) : SystemInvariant s := by
  induction h with
  | initial => exact initial_invariant
  | next _ step ih => exact invariant_step ih step

theorem source_live_content_is_available
    (reachable : Reachable s) (live : (s root).sourceLive holder) :
    Available (s root) :=
  ((reachable_invariant reachable root).2.1 holder live).2.2

theorem replica_live_content_is_pin_or_want
    (reachable : Reachable s) (live : (s root).replicaLive holder) :
    ((s root).pin holder ∧ Available (s root)) ∨ (s root).want holder :=
  ((reachable_invariant reachable root).2.2.1 holder live).2

theorem live_content_has_entry
    (reachable : Reachable s)
    (live : (s root).sourceLive holder ∨ (s root).replicaLive holder ∨
      (s root).ordinaryLive holder) :
    (s root).entry := by
  rcases live with source | replica | ordinary
  · exact ((reachable_invariant reachable root).2.1 holder source).1
  · exact ((reachable_invariant reachable root).2.2.1 holder replica).1
  · exact (reachable_invariant reachable root).2.2.2.1 holder ordinary

theorem gc_cannot_collect_live_content
    (hinv : Invariant c) (live : AnyLive c) (hgc : GcCommit c c') : False := by
  rcases live with ⟨holder, source | replica | ordinary⟩
  · exact hgc.1.2.1 (hinv.2.1 holder source).1
  · exact hgc.1.2.1 (hinv.2.2.1 holder replica).1
  · exact hgc.1.2.1 (hinv.2.2.2.1 holder ordinary)

theorem protected_delete_cannot_delete_live_content
    (hinv : Invariant c) (live : AnyLive c)
    (delete : ProtectedDelete c c') : False := by
  rcases live with ⟨holder, source | replica | ordinary⟩
  · exact delete.1.1 (hinv.2.1 holder source).1
  · exact delete.1.1 (hinv.2.2.1 holder replica).1
  · exact delete.1.1 (hinv.2.2.2.1 holder ordinary)

theorem protected_delete_cannot_delete_pinned
    (pinned : c.pin holder) (delete : ProtectedDelete c c') : False :=
  delete.1.2.1 ⟨holder, pinned⟩

/- The paths that drop a staged row never consult `pins`.  They do not need
   to: a pin is only ever granted over durable content, so a non-durable row
   is unpinned in every reachable state. -/
theorem staged_row_drop_is_unpinned
    (hinv : Invariant c) (drop : DropStaged c c') (pinned : c.pin holder) : False :=
  drop.1 (hinv.1 holder pinned).2.1

theorem staged_row_drop_has_no_source_leaf
    (hinv : Invariant c) (drop : DropStaged c c') (live : c.sourceLive holder) : False :=
  drop.1 (hinv.2.1 holder live).2.2.2.1

/- Promoting a replica leaf over content that is not available records a want
   and never a pin, whatever took the content away — a GC pass that ran before
   the promotion included.  In an invariant-satisfying cell no pin stands over
   unavailable content, so the promoted cell carries none for this holder. -/
theorem replica_promote_unavailable_records_want
    (hinv : Invariant c) (promote : ReplicaPromote holder c promoted)
    (unavailable : ¬Available c) :
    promoted.replicaLive holder ∧ promoted.want holder ∧ ¬promoted.pin holder := by
  rcases promote with ⟨_, _, held | missing⟩
  · exact False.elim (unavailable held.1)
  · rcases missing with ⟨_, rfl⟩
    exact ⟨Or.inl rfl, Or.inl rfl, fun pinned => unavailable (hinv.1 holder pinned)⟩

end Synchronicity.SystemSafety
