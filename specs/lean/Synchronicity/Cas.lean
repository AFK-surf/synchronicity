import Synchronicity.Prelude
import Synchronicity.Anchors

/-!
The CAS transition system, stated once.

`Cell H` is one content root as the store sees it: its row, bytes and durable
claim, the entry that names it, and the pins, wants and live leaves indexed by
holder `H`.  Every transition is a named Rust linearization point, carried by
the `rust_impl` attribute on its definition.  `Kind` names the transitions,
`Trans` gives each its relation, and `CellStep` is their union.  The models
that read this file differ only in `H` and in which steps they close over:

- `SystemSafety` is the fault-free closure, with holders indexed by `Nat` and
  the operator distinguished from the roles a space configures;
- `FaultTolerant` adds backend loss and the heals, over the same cells.

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
  /-- The holder is a source or a replica a space configures. -/
  IsRole : H → Prop

export Roles (IsRole)

/-- A content root. -/
abbrev Root := Nat

variable {H : Type}

/-- One content root as the store sees it. -/
structure Cell (H : Type) where
  /-- An `entries` row names the content. -/
  entry : Prop := False
  /-- The holders pinning the content. -/
  pin : H → Prop := fun _ => False
  /-- The holders wanting the content. -/
  want : H → Prop := fun _ => False
  /-- The holders whose source leaf names the content. -/
  sourceLive : H → Prop := fun _ => False
  /-- The holders whose replica leaf names the content. -/
  replicaLive : H → Prop := fun _ => False
  /-- The holders whose metadata-only leaf names the content. -/
  ordinaryLive : H → Prop := fun _ => False
  /-- The `blobs` row exists. -/
  row : Prop := False
  /-- The bytes are on local disk. -/
  bytes : Prop := False
  /-- The remote backend holds a copy. -/
  remote : Prop := False
  /-- The backend has acknowledged the bytes durably. -/
  durable : Prop := False
  /-- A write lease is held. -/
  writing : Prop := False
  /-- A GC row commit has run and its unlink has not. -/
  sweeping : Prop := False
  /-- Inside the retention window. -/
  fresh : Prop := False

/-- The row is present, the backend has acknowledged the bytes, and a copy is
at hand locally or remotely. -/
def Available (c : Cell H) : Prop :=
  c.row ∧ c.durable ∧ (c.bytes ∨ c.remote)

/-- A durable claim: the row exists and the backend has acknowledged the bytes.
Only modelled steps write these two fields, so a loss cannot change it. -/
def Durable (c : Cell H) : Prop := c.row ∧ c.durable

theorem Available.durable {c : Cell H} (h : Available c) : Durable c := ⟨h.1, h.2.1⟩

/-- Someone pins the content. -/
def AnyPin (c : Cell H) : Prop := ∃ holder, c.pin holder

/-- Some leaf names the content. -/
def AnyLive (c : Cell H) : Prop :=
  ∃ holder, c.sourceLive holder ∨ c.replicaLive holder ∨ c.ordinaryLive holder

/-- What `delete_blob_if_collectable` checks: a row nothing protects, outside
the retention window. -/
def Collectable (c : Cell H) : Prop :=
  c.row ∧ ¬c.entry ∧ ¬AnyPin c ∧ ¬c.writing ∧ ¬c.sweeping ∧ ¬c.fresh

/-- What `delete_blob` checks: nothing protects the content. -/
def Deletable (c : Cell H) : Prop :=
  ¬c.entry ∧ ¬AnyPin c ∧ ¬c.writing ∧ ¬c.sweeping

/-! ## Transitions that do not ask who the holder is -/

/-- `db.rs::Store::lease_write`. -/
@[rust_impl "cas-write-lease-begin"]
def BeginWrite (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c' = { c with writing := True }

/-- `db.rs::WriteLease::drop`. -/
@[rust_impl "cas-write-lease-end"]
def WriteAbort (c c' : Cell H) : Prop :=
  c' = { c with writing := False }

/-- `cas.rs::write_blob_row`.  A complete row lands with its bytes.  Whether it
is also durable is `complete_is_durable`: a local backend says yes, a cloud
backend says not until `finalize`, and `upsert_blob_row` keeps `durable` at
`max(old, new)`.  The second branch is the staged row that `DropStaged` may
later discard. -/
@[rust_impl "cas-write-complete-commit"]
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

/-- `cas.rs::commit_groups`.  The completing bitmap commit is the same
transition; partial commits change nothing this model sees. -/
@[rust_impl "cas-write-groups-commit"]
def CommitGroups (c c' : Cell H) : Prop := CommitComplete c c'

/-- `backend.rs::Cloud::finalize`. -/
@[rust_impl "cas-cloud-finalize"]
def FinalizeRemote (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c.row ∧ c' = { c with remote := True, durable := True }

/-- `gc.rs::gc_content(before)`: the retention window elapses. -/
@[rust_impl "cas-retention-elapses"]
def Age (c c' : Cell H) : Prop :=
  c' = { c with fresh := False }

/-- `cas.rs::Store::adopt_durable_blob`.  A cold durable row reconstructed
after the remote backend confirmed the final pair exists. -/
@[rust_impl "cas-adopt-durable"]
def AdoptRemote (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c' = { c with row := True, remote := True, durable := True }

/-- `cas.rs::clear_blob_cache`, the durable branch. -/
@[rust_impl "cas-cache-evict"]
def CacheEvict (c c' : Cell H) : Prop :=
  c.remote ∧ c.durable ∧ c' = { c with bytes := False }

/-- The non-durable branch of `cas.rs::clear_blob_cache`,
`reconcile_scratch_generation`, and the `commit_cas_migration` discard.  None
of them consult `pins`; `NoLoss` is what makes that safe
(`SystemSafety.staged_row_drop_is_unpinned`). -/
@[rust_impl "cas-drop-staged-row"]
def DropStaged (c c' : Cell H) : Prop :=
  ¬c.durable ∧ ¬c.writing ∧ c' = { c with row := False, bytes := False }

/-- The same promotion as `ReplicaPromote` on a metadata-only node: an entry
and nothing else (`reconcile.rs::try_promote`). -/
@[rust_impl "cas-ordinary-promotion"]
def OrdinaryPromote (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c' = { c with
    entry := True
    ordinaryLive := add c.ordinaryLive holder }

/-- `views.rs::apply_change`, the `Deleted` arm under `materialize_diff`: a
source leaf leaves the derived views. -/
@[rust_impl "mpt-materialize-remove-source"]
def RemoveSource (holder : H) (c c' : Cell H) : Prop :=
  c' = { c with sourceLive := drop c.sourceLive holder }

/-- The same arm for a replica leaf. -/
@[rust_impl "mpt-materialize-remove-replica"]
def RemoveReplica (holder : H) (c c' : Cell H) : Prop :=
  c' = { c with replicaLive := drop c.replicaLive holder }

/-- The same arm for a metadata-only leaf. -/
@[rust_impl "mpt-materialize-remove-ordinary"]
def RemoveOrdinary (holder : H) (c c' : Cell H) : Prop :=
  c' = { c with ordinaryLive := drop c.ordinaryLive holder }

/-- The entry row goes once no leaf of any kind names the content
(`views.rs::apply_change`, the `Deleted` arm). -/
@[rust_impl "mpt-materialize-drop-entry"]
def DropEntry (c c' : Cell H) : Prop :=
  (∀ holder, ¬c.sourceLive holder ∧ ¬c.replicaLive holder ∧
    ¬c.ordinaryLive holder) ∧
  c' = { c with entry := False }

/-- `cas.rs::Store::pin`. -/
@[rust_impl "cas-pin"]
def Pin (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ Available c ∧
  c' = { c with pin := add c.pin holder }

/-- `cas.rs::Store::unpin`. -/
@[rust_impl "cas-unpin"]
def Unpin (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sourceLive holder ∧ ¬c.replicaLive holder ∧
  c' = { c with pin := drop c.pin holder }

/-- `cas.rs::Store::expire_pins_of` / `expire_pins`. -/
@[rust_impl "cas-expire-pin"]
def ExpirePin (holder : H) (c c' : Cell H) : Prop := Unpin holder c c'

/-- `replica.rs::Store::drop_want`. -/
@[rust_impl "cas-drop-want"]
def DropWant (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sourceLive holder ∧ ¬c.replicaLive holder ∧
  c' = { c with want := drop c.want holder }

/-- `replica.rs::take_possession`. -/
@[rust_impl "cas-take-possession"]
def TakePossession (holder : H) (c c' : Cell H) : Prop :=
  ¬c.sweeping ∧ c.want holder ∧ Available c ∧
  c' = { c with pin := add c.pin holder, want := drop c.want holder }

/-- `cas.rs::delete_blob_if_collectable`, the row commit. -/
@[rust_impl "cas-gc-row-commit"]
def GcCommit (c c' : Cell H) : Prop :=
  Collectable c ∧
  c' = { c with row := False, durable := False, sweeping := True }

/-- The unlink half of `delete_blob_if_collectable`. -/
@[rust_impl "cas-gc-unlink"]
def GcUnlink (c c' : Cell H) : Prop :=
  c.sweeping ∧ c' = { c with bytes := False, sweeping := False }

/-- `cas.rs::Store::delete_blob`. -/
@[rust_impl "cas-protected-delete"]
def ProtectedDelete (c c' : Cell H) : Prop :=
  Deletable c ∧
  c' = { c with row := False, durable := False, sweeping := True }

/-! ### Facts a single transition commits, whoever the holders are -/

variable {c c' : Cell H} {holder : H}

theorem gc_respects_protection (hgc : GcCommit c c')
    (guarded : c.entry ∨ AnyPin c ∨ c.writing) : False := by
  obtain ⟨⟨_, noEntry, noPin, noWrite, _, _⟩, _⟩ := hgc
  rcases guarded with entry | pin | writing
  · exact noEntry entry
  · exact noPin pin
  · exact noWrite writing

theorem write_lease_excludes_gc (writing : c.writing) (hgc : GcCommit c c') : False :=
  gc_respects_protection hgc (Or.inr (Or.inr writing))

theorem possession_is_atomic (h : TakePossession holder c c') :
    c'.pin holder ∧ ¬c'.want holder ∧ Available c' := by
  obtain ⟨_, _, available, rfl⟩ := h
  exact ⟨Or.inl rfl, fun w => w.2 rfl, available⟩

/-- What a fault breaks and the fault-free transitions keep: every pin, the
operator's included, stands on available content, and a source's leaf is
pinned, never merely wanted. -/
structure NoLoss (c : Cell H) : Prop where
  pin_available : ∀ holder, c.pin holder → Available c
  source_pinned : ∀ holder, c.sourceLive holder → c.pin holder

theorem initial_noLoss : NoLoss ({} : Cell H) :=
  ⟨fun _ p => False.elim p, fun _ l => False.elim l⟩

/-! ## Transitions that stand a role behind a leaf -/

variable [Roles H]

/-- `node.rs::Node::publish`. -/
@[rust_impl "cas-source-publish"]
def SourcePublish (holder : H) (c c' : Cell H) : Prop :=
  IsRole holder ∧ ¬c.sweeping ∧ Available c ∧
  c' = { c with
    entry := True
    pin := add c.pin holder
    want := drop c.want holder
    sourceLive := add c.sourceLive holder }

/-- `reconcile.rs::try_promote`: a replica leaf takes a pin over available
content, or records a want. -/
@[rust_impl "cas-remote-promotion"]
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

theorem source_publish_is_closed (h : SourcePublish holder c c') :
    c'.entry ∧ c'.pin holder ∧ Available c' := by
  obtain ⟨_, _, available, rfl⟩ := h
  exact ⟨trivial, Or.inl rfl, available⟩

theorem replica_promotion_is_total (h : ReplicaPromote holder c c') :
    c'.entry ∧ ((c'.pin holder ∧ Available c') ∨ c'.want holder) := by
  obtain ⟨_, _, ⟨available, rfl⟩ | ⟨_, rfl⟩⟩ := h
  · exact ⟨trivial, Or.inl ⟨Or.inl rfl, available⟩⟩
  · exact ⟨trivial, Or.inr (Or.inl rfl)⟩

/-! ## The transitions, named -/

/-- The twenty-three cell transitions.  A `Kind` is a review anchor's target
and the case a preservation proof splits on. -/
inductive Kind (H : Type) where
  | beginWrite | writeAbort | commitComplete | finalizeRemote | age | adoptRemote
  | cacheEvict | dropStaged
  | sourcePublish (holder : H) | replicaPromote (holder : H) | ordinaryPromote (holder : H)
  | removeSource (holder : H) | removeReplica (holder : H) | removeOrdinary (holder : H)
  | dropEntry
  | pin (holder : H) | unpin (holder : H) | expirePin (holder : H) | dropWant (holder : H)
  | takePossession (holder : H)
  | gcCommit | gcUnlink | protectedDelete

/-- The relation each transition names. -/
def Trans : Kind H → Cell H → Cell H → Prop
  | .beginWrite => BeginWrite
  | .writeAbort => WriteAbort
  | .commitComplete => CommitComplete
  | .finalizeRemote => FinalizeRemote
  | .age => Age
  | .adoptRemote => AdoptRemote
  | .cacheEvict => CacheEvict
  | .dropStaged => DropStaged
  | .sourcePublish holder => SourcePublish holder
  | .replicaPromote holder => ReplicaPromote holder
  | .ordinaryPromote holder => OrdinaryPromote holder
  | .removeSource holder => RemoveSource holder
  | .removeReplica holder => RemoveReplica holder
  | .removeOrdinary holder => RemoveOrdinary holder
  | .dropEntry => DropEntry
  | .pin holder => Pin holder
  | .unpin holder => Unpin holder
  | .expirePin holder => ExpirePin holder
  | .dropWant holder => DropWant holder
  | .takePossession holder => TakePossession holder
  | .gcCommit => GcCommit
  | .gcUnlink => GcUnlink
  | .protectedDelete => ProtectedDelete

/-- Some transition took the cell from `c` to `c'`. -/
def CellStep (c c' : Cell H) : Prop := ∃ k : Kind H, Trans k c c'

/-- The cell changes that interleave freely with a trie transaction rather than
share one.  Publication and promotion are the exceptions: `Safety` pairs them
with the head flip they commit alongside, and `Safety.live_leaf_flips_head` is
the theorem this guard exists for. -/
def Local (c c' : Cell H) : Prop :=
  ¬ ∃ holder, SourcePublish holder c c' ∨ ReplicaPromote holder c c' ∨ OrdinaryPromote holder c c'

/-! ## What every transition preserves -/

/-- The claim behind a live leaf: its holder is a role, the content has an
entry, and the holder either pins a durable claim or has a want recorded. -/
def LiveClaim (c : Cell H) (holder : H) : Prop :=
  IsRole holder ∧ c.entry ∧ ((c.pin holder ∧ Durable c) ∨ c.want holder)

/-- What survives everything, backend loss included.  Compared with `NoLoss`
below: `Available` is `Durable`, the pin clause covers only roles, and a
source leaf may be wanted rather than pinned. -/
structure Invariant (c : Cell H) : Prop where
  role_pin_durable : ∀ holder, IsRole holder → c.pin holder → Durable c
  source_live : ∀ holder, c.sourceLive holder → LiveClaim c holder
  replica_live : ∀ holder, c.replicaLive holder → LiveClaim c holder
  ordinary_live : ∀ holder, c.ordinaryLive holder → c.entry
  sweeping : c.sweeping → ¬c.entry ∧ (∀ holder, ¬c.pin holder) ∧ ¬c.writing ∧ ¬c.row

theorem initial_invariant : Invariant ({} : Cell H) :=
  ⟨fun _ _ p => False.elim p, fun _ l => False.elim l, fun _ l => False.elim l,
    fun _ l => False.elim l, fun s => False.elim s⟩

/-- Every preservation proof below is the same three moves: split on the
transition, substitute the successor cell, let `grind` read the fields.
`unfold_trans at h` opens the transition `h` names down to its guards and
successor equations. -/
syntax "unfold_trans" (Lean.Parser.Tactic.location)? : tactic
macro_rules
  | `(tactic| unfold_trans $[$loc]?) =>
    `(tactic| simp only [Trans, BeginWrite, WriteAbort, CommitComplete, CommitGroups,
        FinalizeRemote, Age, AdoptRemote, CacheEvict, DropStaged, SourcePublish, ReplicaPromote,
        OrdinaryPromote, RemoveSource, RemoveReplica, RemoveOrdinary, DropEntry, Pin, Unpin,
        ExpirePin, DropWant, TakePossession, GcCommit, GcUnlink, ProtectedDelete,
        Collectable, Deletable] $[$loc]?)

theorem invariant_step (hinv : Invariant c) (hstep : CellStep c c') : Invariant c' := by
  obtain ⟨k, h⟩ := hstep
  obtain ⟨pins, sources, replicas, ordinary, sweepInv⟩ := hinv
  cases k <;> unfold_trans at h <;> subst_step h <;> constructor <;>
    grind [LiveClaim, Durable, Available, AnyPin, add, drop]

theorem noLoss_step (hinv : Invariant c) (hnl : NoLoss c) (hstep : CellStep c c') :
    NoLoss c' := by
  obtain ⟨k, h⟩ := hstep
  obtain ⟨pins, sources, replicas, ordinary, sweepInv⟩ := hinv
  obtain ⟨pinsAvailable, sourcePinned⟩ := hnl
  cases k <;> unfold_trans at h <;> subst_step h <;> constructor <;>
    grind [LiveClaim, Durable, Available, AnyPin, add, drop]

/-! ## Which transition a change betrays -/

/-- A step that stands a new source leaf is a publication. -/
theorem sourcePublish_of_new_leaf (h : CellStep c c')
    (new : c'.sourceLive holder) (old : ¬c.sourceLive holder) : SourcePublish holder c c' := by
  obtain ⟨k, h⟩ := h
  cases k <;> unfold_trans at h <;> subst_step h <;> grind [SourcePublish, Available, add, drop]

/-- A step that stands a new replica leaf is a promotion. -/
theorem replicaPromote_of_new_leaf (h : CellStep c c')
    (new : c'.replicaLive holder) (old : ¬c.replicaLive holder) : ReplicaPromote holder c c' := by
  obtain ⟨k, h⟩ := h
  cases k <;> unfold_trans at h <;> subst_step h <;> grind [ReplicaPromote, Available, add, drop]

/-! ## The store: one cell per content root -/

/-- The store: one cell per content root. -/
abbrev State (H : Type) := Root → Cell H

/-- The empty store. -/
def Initial : State H := fun _ => {}

end Synchronicity.Cas

#lint
