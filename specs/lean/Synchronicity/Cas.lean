/-!
The CAS transition system, stated once.

`Cell H` is one content root as the store sees it: its row, bytes and durable
claim, the entry that names it, and the pins, wants and live leaves indexed by
holder `H`.  Every transition is a named Rust linearization point.  The models
that read this file differ only in `H` and in which steps they close over:

- `SystemSafety` is the fault-free closure, with holders indexed by `Nat` and
  the operator distinguished from the roles a space configures;
- `FaultTolerant` adds backend loss and the heals, over the same cells;
- `CasGc` takes `H := Unit`, which is the compact single-root explanation.

Two invariants live here.  `Invariant` is what every transition preserves, the
heals included: a role's pin stands on a durable claim, and a live leaf's holder
is a role with a pin or a want behind it.  `NoLoss` is what only the fault-free
transitions preserve — every pin, the operator's included, stands on available
content, and a source's leaf is pinned, never merely wanted.  `SystemSafety`'s
invariant is the conjunction; `FaultTolerant`'s is `Invariant` alone.
-/

namespace Synchronicity.Cas

/-- Which holders are roles a space configures — sources and replicas — as
opposed to the operator's `synch pin add`.  Only roles stand behind live
leaves, and the heal paths treat the two differently. -/
class Roles (H : Type) where
  IsRole : H → Prop

export Roles (IsRole)

abbrev Root := Nat

variable {H : Type}

def add (p : H → Prop) (holder : H) : H → Prop :=
  fun candidate => candidate = holder ∨ p candidate

def drop (p : H → Prop) (holder : H) : H → Prop :=
  fun candidate => p candidate ∧ candidate ≠ holder

structure Cell (H : Type) where
  entry : Prop := False
  pin : H → Prop := fun _ => False
  want : H → Prop := fun _ => False
  sourceLive : H → Prop := fun _ => False
  replicaLive : H → Prop := fun _ => False
  ordinaryLive : H → Prop := fun _ => False
  row : Prop := False
  bytes : Prop := False
  remote : Prop := False
  durable : Prop := False
  writing : Prop := False
  sweeping : Prop := False
  fresh : Prop := False

/-- The row is present, the backend has acknowledged the bytes, and a copy is
at hand locally or remotely. -/
def Available (c : Cell H) : Prop :=
  c.row ∧ c.durable ∧ (c.bytes ∨ c.remote)

/-- A durable claim: the row exists and the backend has acknowledged the bytes.
Only modelled steps write these two fields, so a loss cannot change it. -/
def Durable (c : Cell H) : Prop := c.row ∧ c.durable

theorem Available.durable {c : Cell H} (h : Available c) : Durable c := ⟨h.1, h.2.1⟩

def AnyPin (c : Cell H) : Prop := ∃ holder, c.pin holder

def AnyLive (c : Cell H) : Prop :=
  ∃ holder, c.sourceLive holder ∨ c.replicaLive holder ∨ c.ordinaryLive holder

def Collectable (c : Cell H) : Prop :=
  c.row ∧ ¬c.entry ∧ ¬AnyPin c ∧ ¬c.writing ∧ ¬c.sweeping ∧ ¬c.fresh

def Deletable (c : Cell H) : Prop :=
  ¬c.entry ∧ ¬AnyPin c ∧ ¬c.writing ∧ ¬c.sweeping

/-! ## Transitions -/

/- RUST-IMPL: cas-write-lease-begin — `db.rs::Store::lease_write`. -/
def BeginWrite (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c' = { c with writing := True }

/- RUST-IMPL: cas-write-lease-end — `db.rs::WriteLease::drop`. -/
def WriteAbort (c c' : Cell H) : Prop :=
  c' = { c with writing := False }

/- RUST-IMPL: cas-write-complete-commit — `cas.rs::write_blob_row`.  A complete
   row lands with its bytes.  Whether it is also durable is
   `complete_is_durable`: a local backend says yes, a cloud backend says not
   until `finalize`, and `upsert_blob_row` keeps `durable` at
   `max(old, new)`.  The second branch is the staged row that `DropStaged`
   may later discard. -/
def CommitComplete (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧
  (c' = { c with
      row := True
      bytes := True
      durable := True
      writing := False
      fresh := True } ∨
    c' = { c with
      row := True
      bytes := True
      writing := False
      fresh := True })

/- RUST-IMPL: cas-write-groups-commit — `cas.rs::commit_groups`.  The
   completing bitmap commit is the same transition; partial commits change
   nothing this model sees. -/
def CommitGroups (c c' : Cell H) : Prop := CommitComplete c c'

/- RUST-IMPL: cas-cloud-finalize — `backend.rs::Cloud::finalize`. -/
def FinalizeRemote (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c.row ∧ c' = { c with remote := True, durable := True }

/- RUST-IMPL: cas-retention-elapses — `gc.rs::gc_content(before)`. -/
def Age (c c' : Cell H) : Prop :=
  c' = { c with fresh := False }

/- RUST-IMPL: cas-adopt-durable — `cas.rs::Store::adopt_durable_blob`.
   A cold durable row reconstructed after the remote backend confirmed the
   final pair exists. -/
def AdoptRemote (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c' = { c with row := True, remote := True, durable := True }

/- RUST-IMPL: cas-cache-evict — `cas.rs::clear_blob_cache`. -/
def CacheEvict (c c' : Cell H) : Prop :=
  c.remote ∧ c.durable ∧ c' = { c with bytes := False }

/- RUST-IMPL: cas-drop-staged-row — the non-durable branch of
   `cas.rs::clear_blob_cache`, `reconcile_scratch_generation`, and the
   `commit_cas_migration` discard.  None of them consult `pins`; `NoLoss` is
   what makes that safe (`SystemSafety.staged_row_drop_is_unpinned`). -/
def DropStaged (c c' : Cell H) : Prop :=
  ¬c.durable ∧ ¬c.writing ∧ c' = { c with row := False, bytes := False }

variable [Roles H]

/- RUST-IMPL: cas-source-publish — `node.rs::Node::publish`. -/
def SourcePublish (holder : H) (c c' : Cell H) : Prop :=
  IsRole holder ∧ ¬c.sweeping ∧ Available c ∧
  c' = { c with
    entry := True
    pin := add c.pin holder
    want := drop c.want holder
    sourceLive := add c.sourceLive holder }

/- RUST-IMPL: cas-remote-promotion — `reconcile.rs::try_promote`. -/
def ReplicaPromote (holder : H) (c c' : Cell H) : Prop :=
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

/-- The same promotion on a metadata-only node: an entry and nothing else. -/
def OrdinaryPromote (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c' = { c with
    entry := True
    ordinaryLive := add c.ordinaryLive holder }

/- RUST-IMPL: mpt-materialize-live-diff — `views.rs::Txn::materialize_diff`. -/
def RemoveSource (holder : H) (c c' : Cell H) : Prop :=
  c' = { c with sourceLive := drop c.sourceLive holder }

def RemoveReplica (holder : H) (c c' : Cell H) : Prop :=
  c' = { c with replicaLive := drop c.replicaLive holder }

def RemoveOrdinary (holder : H) (c c' : Cell H) : Prop :=
  c' = { c with ordinaryLive := drop c.ordinaryLive holder }

def DropEntry (c c' : Cell H) : Prop :=
  (∀ holder, ¬c.sourceLive holder ∧ ¬c.replicaLive holder ∧
    ¬c.ordinaryLive holder) ∧
  c' = { c with entry := False }

/- RUST-IMPL: cas-pin — `cas.rs::Store::pin`. -/
def Pin (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ Available c ∧
  c' = { c with pin := add c.pin holder }

/- RUST-IMPL: cas-unpin — `cas.rs::Store::unpin`. -/
def Unpin (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sourceLive holder ∧ ¬c.replicaLive holder ∧
  c' = { c with pin := drop c.pin holder }

/- RUST-IMPL: cas-expire-pin — `cas.rs::Store::expire_pins_of`/`expire_pins`. -/
def ExpirePin (holder : H) (c c' : Cell H) : Prop := Unpin holder c c'

/- RUST-IMPL: cas-drop-want — `replica.rs::Store::drop_want`. -/
def DropWant (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sourceLive holder ∧ ¬c.replicaLive holder ∧
  c' = { c with want := drop c.want holder }

/- RUST-IMPL: cas-take-possession — `replica.rs::take_possession`. -/
def TakePossession (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c.want holder ∧ Available c ∧
  c' = { c with pin := add c.pin holder, want := drop c.want holder }

/- RUST-IMPL: cas-gc-row-commit — `cas.rs::delete_blob_if_collectable`. -/
def GcCommit (c c' : Cell H) : Prop :=
  Collectable c ∧
  c' = { c with row := False, durable := False, sweeping := True }

/- RUST-IMPL: cas-gc-unlink — the unlink half of `delete_blob_if_collectable`. -/
def GcUnlink (c c' : Cell H) : Prop :=
  c.sweeping ∧ c' = { c with bytes := False, sweeping := False }

/- RUST-IMPL: cas-protected-delete — `cas.rs::Store::delete_blob`. -/
def ProtectedDelete (c c' : Cell H) : Prop :=
  Deletable c ∧
  c' = { c with row := False, durable := False, sweeping := True }

inductive CellStep : Cell H → Cell H → Prop where
  | beginWrite : BeginWrite c c' → CellStep c c'
  | writeAbort : WriteAbort c c' → CellStep c c'
  | commitComplete : CommitComplete c c' → CellStep c c'
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
  | expirePin : ExpirePin holder c c' → CellStep c c'
  | dropWant : DropWant holder c c' → CellStep c c'
  | takePossession : TakePossession holder c c' → CellStep c c'
  | gcCommit : GcCommit c c' → CellStep c c'
  | gcUnlink : GcUnlink c c' → CellStep c c'
  | protectedDelete : ProtectedDelete c c' → CellStep c c'

variable {c c' : Cell H} {holder : H}

/-- The cell changes that interleave freely with a trie transaction rather than
share one.  Publication and promotion are the exceptions: `Safety` pairs them
with the head flip they commit alongside. -/
def Local (c c' : Cell H) : Prop :=
  ¬ ∃ holder, SourcePublish holder c c' ∨ ReplicaPromote holder c c' ∨ OrdinaryPromote holder c c'

/-! ## What every transition preserves -/

/-- The claim behind a live leaf: its holder is a role, the content has an
entry, and the holder either pins a durable claim or has a want recorded. -/
def LiveClaim (c : Cell H) (holder : H) : Prop :=
  IsRole holder ∧ c.entry ∧ ((c.pin holder ∧ Durable c) ∨ c.want holder)

theorem LiveClaim.mono (h : LiveClaim c holder)
    (entry : c.entry → c'.entry) (pin : c.pin holder → c'.pin holder)
    (durable : Durable c → Durable c') (want : c.want holder → c'.want holder) :
    LiveClaim c' holder :=
  ⟨h.1, entry h.2.1,
    h.2.2.elim (fun p => Or.inl ⟨pin p.1, durable p.2⟩) (fun w => Or.inr (want w))⟩

/-- What survives everything, backend loss included.  Compared with `NoLoss`
below: `Available` is `Durable`, the pin clause covers only roles, and a
source leaf may be wanted rather than pinned. -/
structure Invariant (c : Cell H) : Prop where
  role_pin_durable : ∀ holder, IsRole holder → c.pin holder → Durable c
  source_live : ∀ holder, c.sourceLive holder → LiveClaim c holder
  replica_live : ∀ holder, c.replicaLive holder → LiveClaim c holder
  ordinary_live : ∀ holder, c.ordinaryLive holder → c.entry
  sweeping : c.sweeping → ¬c.entry ∧ (∀ holder, ¬c.pin holder) ∧ ¬c.writing ∧ ¬c.row

/-- What a fault breaks and the fault-free transitions keep: every pin, the
operator's included, stands on available content, and a source's leaf is
pinned, never merely wanted. -/
structure NoLoss (c : Cell H) : Prop where
  pin_available : ∀ holder, c.pin holder → Available c
  source_pinned : ∀ holder, c.sourceLive holder → c.pin holder

theorem initial_invariant : Invariant ({} : Cell H) :=
  ⟨fun _ _ p => False.elim p, fun _ l => False.elim l, fun _ l => False.elim l,
    fun _ l => False.elim l, fun s => False.elim s⟩

omit [Roles H] in
theorem initial_noLoss : NoLoss ({} : Cell H) :=
  ⟨fun _ p => False.elim p, fun _ l => False.elim l⟩

theorem invariant_step (hinv : Invariant c) (hstep : CellStep c c') : Invariant c' := by
  obtain ⟨pins, sources, replicas, ordinary, sweepInv⟩ := hinv
  cases hstep with
  | beginWrite h =>
      obtain ⟨notSweeping, rfl⟩ := h
      exact ⟨pins, sources, replicas, ordinary, fun sw => absurd sw notSweeping⟩
  | writeAbort h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sources, replicas, ordinary,
        fun sw => ⟨(sweepInv sw).1, (sweepInv sw).2.1, not_false, (sweepInv sw).2.2.2⟩⟩
  | commitComplete h =>
      obtain ⟨notSweeping, rfl | rfl⟩ := h
      · exact ⟨fun _ _ _ => ⟨trivial, trivial⟩,
          fun h l => (sources h l).mono id id (fun _ => ⟨trivial, trivial⟩) id,
          fun h l => (replicas h l).mono id id (fun _ => ⟨trivial, trivial⟩) id,
          ordinary, fun sw => absurd sw notSweeping⟩
      · exact ⟨fun h r p => ⟨trivial, (pins h r p).2⟩,
          fun h l => (sources h l).mono id id (fun d => ⟨trivial, d.2⟩) id,
          fun h l => (replicas h l).mono id id (fun d => ⟨trivial, d.2⟩) id,
          ordinary, fun sw => absurd sw notSweeping⟩
  | finalizeRemote h =>
      obtain ⟨notSweeping, row, rfl⟩ := h
      exact ⟨fun _ _ _ => ⟨row, trivial⟩,
        fun h l => (sources h l).mono id id (fun _ => ⟨row, trivial⟩) id,
        fun h l => (replicas h l).mono id id (fun _ => ⟨row, trivial⟩) id,
        ordinary, fun sw => absurd sw notSweeping⟩
  | age h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sources, replicas, ordinary, sweepInv⟩
  | adoptRemote h =>
      obtain ⟨notSweeping, rfl⟩ := h
      exact ⟨fun _ _ _ => ⟨trivial, trivial⟩,
        fun h l => (sources h l).mono id id (fun _ => ⟨trivial, trivial⟩) id,
        fun h l => (replicas h l).mono id id (fun _ => ⟨trivial, trivial⟩) id,
        ordinary, fun sw => absurd sw notSweeping⟩
  | cacheEvict h =>
      obtain ⟨_, _, rfl⟩ := h
      exact ⟨pins, sources, replicas, ordinary, sweepInv⟩
  | dropStaged h =>
      obtain ⟨notDurable, _, rfl⟩ := h
      exact ⟨fun h r p => absurd (pins h r p).2 notDurable,
        fun h l => (sources h l).mono id id (fun d => absurd d.2 notDurable) id,
        fun h l => (replicas h l).mono id id (fun d => absurd d.2 notDurable) id,
        ordinary,
        fun sw => ⟨(sweepInv sw).1, (sweepInv sw).2.1, (sweepInv sw).2.2.1, not_false⟩⟩
  | @sourcePublish holder _ _ h =>
      obtain ⟨role, notSweeping, available, rfl⟩ := h
      refine ⟨fun h r p => p.elim (fun _ => available.durable) (pins h r), ?_, ?_,
        fun _ _ => trivial, fun sw => absurd sw notSweeping⟩
      · intro h l
        by_cases eq : h = holder
        · exact ⟨eq ▸ role, trivial, Or.inl ⟨Or.inl eq, available.durable⟩⟩
        · rcases l with eq' | old
          · exact absurd eq' eq
          · exact (sources h old).mono (fun _ => trivial) Or.inr id (fun w => ⟨w, eq⟩)
      · intro h l
        by_cases eq : h = holder
        · exact ⟨(replicas h l).1, trivial, Or.inl ⟨Or.inl eq, available.durable⟩⟩
        · exact (replicas h l).mono (fun _ => trivial) Or.inr id (fun w => ⟨w, eq⟩)
  | @replicaPromote holder _ _ h =>
      obtain ⟨role, notSweeping, ⟨available, rfl⟩ | ⟨_, rfl⟩⟩ := h
      · refine ⟨fun h r p => p.elim (fun _ => available.durable) (pins h r), ?_, ?_,
          fun _ _ => trivial, fun sw => absurd sw notSweeping⟩
        · intro h l
          by_cases eq : h = holder
          · exact ⟨(sources h l).1, trivial, Or.inl ⟨Or.inl eq, available.durable⟩⟩
          · exact (sources h l).mono (fun _ => trivial) Or.inr id (fun w => ⟨w, eq⟩)
        · intro h l
          by_cases eq : h = holder
          · exact ⟨eq ▸ role, trivial, Or.inl ⟨Or.inl eq, available.durable⟩⟩
          · rcases l with eq' | old
            · exact absurd eq' eq
            · exact (replicas h old).mono (fun _ => trivial) Or.inr id (fun w => ⟨w, eq⟩)
      · refine ⟨pins, fun h l => (sources h l).mono (fun _ => trivial) id id Or.inr, ?_,
          fun _ _ => trivial, fun sw => absurd sw notSweeping⟩
        intro h l
        rcases l with eq | old
        · exact ⟨eq ▸ role, trivial, Or.inr (Or.inl eq)⟩
        · exact (replicas h old).mono (fun _ => trivial) id id Or.inr
  | ordinaryPromote h =>
      obtain ⟨notSweeping, rfl⟩ := h
      exact ⟨pins, fun h l => (sources h l).mono (fun _ => trivial) id id id,
        fun h l => (replicas h l).mono (fun _ => trivial) id id id,
        fun _ _ => trivial, fun sw => absurd sw notSweeping⟩
  | removeSource h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, fun h l => sources h l.1, replicas, ordinary, sweepInv⟩
  | removeReplica h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sources, fun h l => replicas h l.1, ordinary, sweepInv⟩
  | removeOrdinary h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sources, replicas, fun h l => ordinary h l.1, sweepInv⟩
  | dropEntry h =>
      obtain ⟨noLive, rfl⟩ := h
      exact ⟨pins, fun h l => absurd l (noLive h).1, fun h l => absurd l (noLive h).2.1,
        fun h l => absurd l (noLive h).2.2, fun sw => ⟨not_false, (sweepInv sw).2⟩⟩
  | pin h =>
      obtain ⟨notSweeping, available, rfl⟩ := h
      exact ⟨fun h r p => p.elim (fun _ => available.durable) (pins h r),
        fun h l => (sources h l).mono id Or.inr id id,
        fun h l => (replicas h l).mono id Or.inr id id,
        ordinary, fun sw => absurd sw notSweeping⟩
  | @unpin holder _ _ h | @expirePin holder _ _ h =>
      obtain ⟨notSource, notReplica, rfl⟩ := h
      exact ⟨fun h r p => pins h r p.1,
        fun h l => (sources h l).mono id (fun p => ⟨p, fun eq => notSource (eq ▸ l)⟩) id id,
        fun h l => (replicas h l).mono id (fun p => ⟨p, fun eq => notReplica (eq ▸ l)⟩) id id,
        ordinary,
        fun sw => ⟨(sweepInv sw).1, fun h p => (sweepInv sw).2.1 h p.1, (sweepInv sw).2.2⟩⟩
  | @dropWant holder _ _ h =>
      obtain ⟨notSource, notReplica, rfl⟩ := h
      exact ⟨pins,
        fun h l => (sources h l).mono id id id (fun w => ⟨w, fun eq => notSource (eq ▸ l)⟩),
        fun h l => (replicas h l).mono id id id (fun w => ⟨w, fun eq => notReplica (eq ▸ l)⟩),
        ordinary, sweepInv⟩
  | @takePossession holder _ _ h =>
      obtain ⟨notSweeping, _, available, rfl⟩ := h
      refine ⟨fun h r p => p.elim (fun _ => available.durable) (pins h r), ?_, ?_,
        ordinary, fun sw => absurd sw notSweeping⟩
      · intro h l
        by_cases eq : h = holder
        · exact ⟨(sources h l).1, (sources h l).2.1, Or.inl ⟨Or.inl eq, available.durable⟩⟩
        · exact (sources h l).mono id Or.inr id (fun w => ⟨w, eq⟩)
      · intro h l
        by_cases eq : h = holder
        · exact ⟨(replicas h l).1, (replicas h l).2.1, Or.inl ⟨Or.inl eq, available.durable⟩⟩
        · exact (replicas h l).mono id Or.inr id (fun w => ⟨w, eq⟩)
  | gcCommit h =>
      obtain ⟨⟨_, noEntry, noPin, noWriting, _, _⟩, rfl⟩ := h
      exact ⟨fun h _ p => absurd ⟨h, p⟩ noPin,
        fun h l => absurd (sources h l).2.1 noEntry,
        fun h l => absurd (replicas h l).2.1 noEntry,
        fun h l => absurd (ordinary h l) noEntry,
        fun _ => ⟨noEntry, fun h p => noPin ⟨h, p⟩, noWriting, not_false⟩⟩
  | gcUnlink h =>
      obtain ⟨sweeping, rfl⟩ := h
      exact ⟨fun h _ p => absurd p ((sweepInv sweeping).2.1 h),
        fun h l => absurd (sources h l).2.1 (sweepInv sweeping).1,
        fun h l => absurd (replicas h l).2.1 (sweepInv sweeping).1,
        fun h l => absurd (ordinary h l) (sweepInv sweeping).1,
        fun sw => False.elim sw⟩
  | protectedDelete h =>
      obtain ⟨⟨noEntry, noPin, noWriting, _⟩, rfl⟩ := h
      exact ⟨fun h _ p => absurd ⟨h, p⟩ noPin,
        fun h l => absurd (sources h l).2.1 noEntry,
        fun h l => absurd (replicas h l).2.1 noEntry,
        fun h l => absurd (ordinary h l) noEntry,
        fun _ => ⟨noEntry, fun h p => noPin ⟨h, p⟩, noWriting, not_false⟩⟩

theorem noLoss_step (hinv : Invariant c) (hnl : NoLoss c) (hstep : CellStep c c') :
    NoLoss c' := by
  obtain ⟨pins, sourcePinned⟩ := hnl
  cases hstep with
  | beginWrite h =>
      obtain ⟨_, rfl⟩ := h
      exact ⟨pins, sourcePinned⟩
  | writeAbort h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sourcePinned⟩
  | commitComplete h =>
      obtain ⟨_, rfl | rfl⟩ := h
      · exact ⟨fun _ _ => ⟨trivial, trivial, Or.inl trivial⟩, sourcePinned⟩
      · exact ⟨fun h p => ⟨trivial, (pins h p).2.1, Or.inl trivial⟩, sourcePinned⟩
  | finalizeRemote h =>
      obtain ⟨_, row, rfl⟩ := h
      exact ⟨fun _ _ => ⟨row, trivial, Or.inr trivial⟩, sourcePinned⟩
  | age h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sourcePinned⟩
  | adoptRemote h =>
      obtain ⟨_, rfl⟩ := h
      exact ⟨fun _ _ => ⟨trivial, trivial, Or.inr trivial⟩, sourcePinned⟩
  | cacheEvict h =>
      obtain ⟨remote, durable, rfl⟩ := h
      exact ⟨fun h p => ⟨(pins h p).1, durable, Or.inr remote⟩, sourcePinned⟩
  | dropStaged h =>
      obtain ⟨notDurable, _, rfl⟩ := h
      exact ⟨fun h p => absurd (pins h p).2.1 notDurable, sourcePinned⟩
  | sourcePublish h =>
      obtain ⟨_, _, available, rfl⟩ := h
      exact ⟨fun _ _ => available, fun h l => l.elim Or.inl (fun old => Or.inr (sourcePinned h old))⟩
  | replicaPromote h =>
      obtain ⟨_, _, ⟨available, rfl⟩ | ⟨_, rfl⟩⟩ := h
      · exact ⟨fun _ _ => available, fun h l => Or.inr (sourcePinned h l)⟩
      · exact ⟨pins, sourcePinned⟩
  | ordinaryPromote h =>
      obtain ⟨_, rfl⟩ := h
      exact ⟨pins, sourcePinned⟩
  | removeSource h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, fun h l => sourcePinned h l.1⟩
  | removeReplica h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sourcePinned⟩
  | removeOrdinary h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sourcePinned⟩
  | dropEntry h =>
      obtain ⟨_, rfl⟩ := h
      exact ⟨pins, sourcePinned⟩
  | pin h =>
      obtain ⟨_, available, rfl⟩ := h
      exact ⟨fun _ _ => available, fun h l => Or.inr (sourcePinned h l)⟩
  | @unpin holder _ _ h | @expirePin holder _ _ h =>
      obtain ⟨notSource, _, rfl⟩ := h
      exact ⟨fun h p => pins h p.1, fun h l => ⟨sourcePinned h l, fun eq => notSource (eq ▸ l)⟩⟩
  | dropWant h =>
      obtain ⟨_, _, rfl⟩ := h
      exact ⟨pins, sourcePinned⟩
  | takePossession h =>
      obtain ⟨_, _, available, rfl⟩ := h
      exact ⟨fun _ _ => available, fun h l => Or.inr (sourcePinned h l)⟩
  | gcCommit h =>
      obtain ⟨⟨_, noEntry, noPin, _, _, _⟩, rfl⟩ := h
      exact ⟨fun h p => absurd ⟨h, p⟩ noPin,
        fun h l => absurd (hinv.source_live h l).2.1 noEntry⟩
  | gcUnlink h =>
      obtain ⟨sweeping, rfl⟩ := h
      exact ⟨fun h p => absurd p ((hinv.sweeping sweeping).2.1 h),
        fun h l => absurd (hinv.source_live h l).2.1 (hinv.sweeping sweeping).1⟩
  | protectedDelete h =>
      obtain ⟨⟨noEntry, noPin, _, _⟩, rfl⟩ := h
      exact ⟨fun h p => absurd ⟨h, p⟩ noPin,
        fun h l => absurd (hinv.source_live h l).2.1 noEntry⟩

/-! ## Per-transition facts

These need no invariant: they read off what a single transition commits. -/

omit [Roles H] in
theorem gc_respects_protection (hgc : GcCommit c c')
    (guarded : c.entry ∨ AnyPin c ∨ c.writing) : False := by
  obtain ⟨⟨_, noEntry, noPin, noWrite, _, _⟩, _⟩ := hgc
  rcases guarded with entry | pin | writing
  · exact noEntry entry
  · exact noPin pin
  · exact noWrite writing

omit [Roles H] in
theorem write_lease_excludes_gc (writing : c.writing) (hgc : GcCommit c c') : False :=
  gc_respects_protection hgc (Or.inr (Or.inr writing))

theorem source_publish_is_closed (h : SourcePublish holder c c') :
    c'.entry ∧ c'.pin holder ∧ Available c' := by
  obtain ⟨_, _, available, rfl⟩ := h
  exact ⟨trivial, Or.inl rfl, available⟩

theorem replica_promotion_is_total (h : ReplicaPromote holder c c') :
    c'.entry ∧ ((c'.pin holder ∧ Available c') ∨ c'.want holder) := by
  obtain ⟨_, _, ⟨available, rfl⟩ | ⟨_, rfl⟩⟩ := h
  · exact ⟨trivial, Or.inl ⟨Or.inl rfl, available⟩⟩
  · exact ⟨trivial, Or.inr (Or.inl rfl)⟩

omit [Roles H] in
theorem possession_is_atomic (h : TakePossession holder c c') :
    c'.pin holder ∧ ¬c'.want holder ∧ Available c' := by
  obtain ⟨_, _, available, rfl⟩ := h
  exact ⟨Or.inl rfl, fun w => w.2 rfl, available⟩

/-! ## The store: one cell per content root -/

abbrev State (H : Type) := Root → Cell H

def Initial : State H := fun _ => {}

def Replace (s : State H) (root : Root) (cell : Cell H) : State H :=
  fun candidate => if candidate = root then cell else s candidate

omit [Roles H] in
/-- A property of every cell lifts through `Replace` when the replaced cell
has it. -/
theorem replace_forall {P : Cell H → Prop} {s : State H} {root : Root} {cell : Cell H}
    (h : ∀ root, P (s root)) (hcell : P cell) : ∀ root', P (Replace s root cell root') := by
  intro candidate
  unfold Replace
  split
  · exact hcell
  · exact h candidate

end Synchronicity.Cas
