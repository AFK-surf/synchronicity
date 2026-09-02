import Synchronicity.Prelude

/-!
The CAS transition system, stated once.

`Cell H` is one content root as the store sees it: its row, bytes and durable
claim, the entry that names it, and the pins, wants and live leaves indexed by
holder `H`.  Every transition is a `Transition`, a guard and a successor, and
a named Rust linearization point carried by the `rust_impl` attribute on its
definition.  Where the code has two outcomes — a complete commit that is or is
not durable, a promotion that pins or wants, — the outcome is a parameter of
the transition, so that each is still one guarded deterministic step.  `Kind`
names the transitions with their parameters, `Trans` gives each its
`Transition`, and `CellStep` is their union.  The models that read this file
differ only in `H` and in which steps they close over:

- `SystemSafety` is the fault-free closure, with the operator distinguished
  from the roles a space configures;
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

/-- A content root, as the index of a cell in the store. -/
structure Root where
  /-- The root's identity. -/
  id : Nat
  deriving DecidableEq

variable {H : Type}

/-- One content root as the store sees it. -/
structure Cell (H : Type) where
  /-- An `entries` row names the content. -/
  entry : Prop := False
  /-- The holders pinning the content. -/
  pin : Set H := ∅
  /-- The holders wanting the content. -/
  want : Set H := ∅
  /-- The holders whose source leaf names the content. -/
  sourceLive : Set H := ∅
  /-- The holders whose replica leaf names the content. -/
  replicaLive : Set H := ∅
  /-- The holders whose metadata-only leaf names the content. -/
  ordinaryLive : Set H := ∅
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
def AnyPin (c : Cell H) : Prop := ∃ holder, holder ∈ c.pin

/-- Some leaf names the content. -/
def AnyLive (c : Cell H) : Prop :=
  ∃ holder, holder ∈ c.sourceLive ∨ holder ∈ c.replicaLive ∨ holder ∈ c.ordinaryLive

/-- What `delete_blob_if_collectable` checks: a row nothing protects, outside
the retention window. -/
structure Collectable (c : Cell H) : Prop where
  /-- The row exists. -/
  row : c.row
  /-- No entry names it. -/
  no_entry : ¬c.entry
  /-- Nobody pins it. -/
  no_pin : ¬AnyPin c
  /-- No write lease is held. -/
  not_writing : ¬c.writing
  /-- No sweep is in flight. -/
  not_sweeping : ¬c.sweeping
  /-- The retention window has elapsed. -/
  not_fresh : ¬c.fresh

/-- What `delete_blob` checks: nothing protects the content. -/
structure Deletable (c : Cell H) : Prop where
  /-- No entry names it. -/
  no_entry : ¬c.entry
  /-- Nobody pins it. -/
  no_pin : ¬AnyPin c
  /-- No write lease is held. -/
  not_writing : ¬c.writing
  /-- No sweep is in flight. -/
  not_sweeping : ¬c.sweeping

attribute [grind cases] Collectable Deletable

/-! ## Transitions that do not ask who the holder is -/

/-- `db.rs::Store::lease_write`. -/
@[transition, rust_impl "cas-write-lease-begin"]
def BeginWrite : Transition (Cell H) where
  guard c := ¬c.sweeping
  post c := { c with writing := True }

/-- `db.rs::WriteLease::drop`. -/
@[transition, rust_impl "cas-write-lease-end"]
def WriteAbort : Transition (Cell H) where
  guard _ := True
  post c := { c with writing := False }

/-- `cas.rs::write_blob_row`.  A complete row lands with its bytes.  Whether it
is also durable is `complete_is_durable`: a local backend says yes, a cloud
backend says not until `finalize`, and `upsert_blob_row` keeps `durable` at
`max(old, new)`.  With `durable = false` this is the staged row that
`DropStaged` may later discard. -/
@[transition, rust_impl "cas-write-complete-commit"]
def CommitComplete (durable : Bool) : Transition (Cell H) where
  guard c := ¬c.sweeping
  post c := { c with
    row := True
    bytes := True
    durable := durable ∨ c.durable
    writing := False
    fresh := True }

/-- `cas.rs::commit_groups`.  The completing bitmap commit is the same
transition; partial commits change nothing this model sees. -/
@[transition, rust_impl "cas-write-groups-commit"]
def CommitGroups (durable : Bool) : Transition (Cell H) := CommitComplete durable

/-- `backend.rs::Cloud::finalize`. -/
@[transition, rust_impl "cas-cloud-finalize"]
def FinalizeRemote : Transition (Cell H) where
  guard c := ¬c.sweeping ∧ c.row
  post c := { c with remote := True, durable := True }

/-- `gc.rs::gc_content(before)`: the retention window elapses. -/
@[transition, rust_impl "cas-retention-elapses"]
def Age : Transition (Cell H) where
  guard _ := True
  post c := { c with fresh := False }

/-- `cas.rs::Store::adopt_durable_blob`.  A cold durable row reconstructed
after the remote backend confirmed the final pair exists. -/
@[transition, rust_impl "cas-adopt-durable"]
def AdoptRemote : Transition (Cell H) where
  guard c := ¬c.sweeping
  post c := { c with row := True, remote := True, durable := True }

/-- `cas.rs::clear_blob_cache`, the durable branch. -/
@[transition, rust_impl "cas-cache-evict"]
def CacheEvict : Transition (Cell H) where
  guard c := c.remote ∧ c.durable
  post c := { c with bytes := False }

/-- The non-durable branch of `cas.rs::clear_blob_cache`,
`reconcile_scratch_generation`, and the `commit_cas_migration` discard.  None
of them consult `pins`; `NoLoss` is what makes that safe
(`SystemSafety.staged_row_drop_is_unpinned`). -/
@[transition, rust_impl "cas-drop-staged-row"]
def DropStaged : Transition (Cell H) where
  guard c := ¬c.durable ∧ ¬c.writing
  post c := { c with row := False, bytes := False }

/-- The same promotion as `ReplicaPromote` on a metadata-only node: an entry
and nothing else (`reconcile.rs::try_promote`). -/
@[transition, rust_impl "cas-ordinary-promotion"]
def OrdinaryPromote (holder : H) : Transition (Cell H) where
  guard c := ¬c.sweeping
  post c := { c with entry := True, ordinaryLive := insert holder c.ordinaryLive }

/-- `views.rs::apply_change`, the `Deleted` arm under `materialize_diff`: a
source leaf leaves the derived views. -/
@[transition, rust_impl "mpt-materialize-remove-source"]
def RemoveSource (holder : H) : Transition (Cell H) where
  guard _ := True
  post c := { c with sourceLive := c.sourceLive \ {holder} }

/-- The same arm for a replica leaf. -/
@[transition, rust_impl "mpt-materialize-remove-replica"]
def RemoveReplica (holder : H) : Transition (Cell H) where
  guard _ := True
  post c := { c with replicaLive := c.replicaLive \ {holder} }

/-- The same arm for a metadata-only leaf. -/
@[transition, rust_impl "mpt-materialize-remove-ordinary"]
def RemoveOrdinary (holder : H) : Transition (Cell H) where
  guard _ := True
  post c := { c with ordinaryLive := c.ordinaryLive \ {holder} }

/-- The entry row goes once no leaf of any kind names the content
(`views.rs::apply_change`, the `Deleted` arm). -/
@[transition, rust_impl "mpt-materialize-drop-entry"]
def DropEntry : Transition (Cell H) where
  guard c := ¬AnyLive c
  post c := { c with entry := False }

/-- `cas.rs::Store::pin`. -/
@[transition, rust_impl "cas-pin"]
def Pin (holder : H) : Transition (Cell H) where
  guard c := ¬c.sweeping ∧ Available c
  post c := { c with pin := insert holder c.pin }

/-- `cas.rs::Store::unpin`. -/
@[transition, rust_impl "cas-unpin"]
def Unpin (holder : H) : Transition (Cell H) where
  guard c := holder ∉ c.sourceLive ∧ holder ∉ c.replicaLive
  post c := { c with pin := c.pin \ {holder} }

/-- `cas.rs::Store::expire_pins_of` / `expire_pins`. -/
@[transition, rust_impl "cas-expire-pin"]
def ExpirePin (holder : H) : Transition (Cell H) := Unpin holder

/-- `replica.rs::Store::drop_want`. -/
@[transition, rust_impl "cas-drop-want"]
def DropWant (holder : H) : Transition (Cell H) where
  guard c := holder ∉ c.sourceLive ∧ holder ∉ c.replicaLive
  post c := { c with want := c.want \ {holder} }

/-- `replica.rs::take_possession`. -/
@[transition, rust_impl "cas-take-possession"]
def TakePossession (holder : H) : Transition (Cell H) where
  guard c := ¬c.sweeping ∧ holder ∈ c.want ∧ Available c
  post c := { c with pin := insert holder c.pin, want := c.want \ {holder} }

/-- `cas.rs::delete_blob_if_collectable`, the row commit. -/
@[transition, rust_impl "cas-gc-row-commit"]
def GcCommit : Transition (Cell H) where
  guard := Collectable
  post c := { c with row := False, durable := False, sweeping := True }

/-- The unlink half of `delete_blob_if_collectable`. -/
@[transition, rust_impl "cas-gc-unlink"]
def GcUnlink : Transition (Cell H) where
  guard c := c.sweeping
  post c := { c with bytes := False, sweeping := False }

/-- `cas.rs::Store::delete_blob`. -/
@[transition, rust_impl "cas-protected-delete"]
def ProtectedDelete : Transition (Cell H) where
  guard := Deletable
  post c := { c with row := False, durable := False, sweeping := True }

/-! ### Facts a single transition commits, whoever the holders are -/

variable {c c' : Cell H} {holder : H}

theorem gc_respects_protection (hgc : GcCommit.rel c c')
    (guarded : c.entry ∨ AnyPin c ∨ c.writing) : False := by
  rcases guarded with entry | pin | writing
  · exact hgc.1.no_entry entry
  · exact hgc.1.no_pin pin
  · exact hgc.1.not_writing writing

theorem write_lease_excludes_gc (writing : c.writing) (hgc : GcCommit.rel c c') : False :=
  gc_respects_protection hgc (Or.inr (Or.inr writing))

theorem possession_is_atomic (h : (TakePossession holder).rel c c') :
    holder ∈ c'.pin ∧ holder ∉ c'.want ∧ Available c' := by
  simp only [transition] at h
  obtain ⟨⟨_, _, available⟩, rfl⟩ := h
  exact ⟨Set.mem_insert _ _, fun w => w.2 rfl, available⟩

/-- What a fault breaks and the fault-free transitions keep: every pin, the
operator's included, stands on available content, and a source's leaf is
pinned, never merely wanted. -/
structure NoLoss (c : Cell H) : Prop where
  /-- Every pin stands on available content. -/
  pin_available : ∀ holder ∈ c.pin, Available c
  /-- A source's leaf is pinned. -/
  source_pinned : ∀ holder ∈ c.sourceLive, holder ∈ c.pin

theorem initial_noLoss : NoLoss ({} : Cell H) :=
  ⟨fun _ p => p.elim, fun _ l => l.elim⟩

/-! ## Transitions that stand a role behind a leaf -/

variable [Roles H]

/-- `node.rs::Node::publish`. -/
@[transition, rust_impl "cas-source-publish"]
def SourcePublish (holder : H) : Transition (Cell H) where
  guard c := IsRole holder ∧ ¬c.sweeping ∧ Available c
  post c := { c with
    entry := True
    pin := insert holder c.pin
    want := c.want \ {holder}
    sourceLive := insert holder c.sourceLive }

/-- `reconcile.rs::try_promote`: a replica leaf takes a pin over available
content (`pinned`), or records a want when the content is not available. -/
@[transition, rust_impl "cas-remote-promotion"]
def ReplicaPromote (holder : H) (pinned : Bool) : Transition (Cell H) where
  guard c := IsRole holder ∧ ¬c.sweeping ∧ (pinned ↔ Available c)
  post c := { c with
    entry := True
    pin := if pinned then insert holder c.pin else c.pin
    want := if pinned then c.want \ {holder} else insert holder c.want
    replicaLive := insert holder c.replicaLive }

theorem source_publish_is_closed (h : (SourcePublish holder).rel c c') :
    c'.entry ∧ holder ∈ c'.pin ∧ Available c' := by
  simp only [transition] at h
  obtain ⟨⟨_, _, available⟩, rfl⟩ := h
  exact ⟨trivial, Set.mem_insert _ _, available⟩

theorem replica_promotion_is_total {pinned : Bool} (h : (ReplicaPromote holder pinned).rel c c') :
    c'.entry ∧ ((holder ∈ c'.pin ∧ Available c') ∨ holder ∈ c'.want) := by
  simp only [transition] at h
  obtain ⟨⟨_, _, hpinned⟩, rfl⟩ := h
  cases pinned with
  | true => exact ⟨trivial, Or.inl ⟨by simp, hpinned.mp rfl⟩⟩
  | false => exact ⟨trivial, Or.inr (by simp)⟩

/-! ## The transitions, named -/

/-- The cell transitions with their parameters.  A `Kind` is a review anchor's
target and the case a preservation proof splits on. -/
inductive Kind (H : Type) where
  | beginWrite | writeAbort
  | commitComplete (durable : Bool) | commitGroups (durable : Bool)
  | finalizeRemote | age | adoptRemote | cacheEvict | dropStaged
  | sourcePublish (holder : H) | replicaPromote (holder : H) (pinned : Bool)
  | ordinaryPromote (holder : H)
  | removeSource (holder : H) | removeReplica (holder : H) | removeOrdinary (holder : H)
  | dropEntry
  | pin (holder : H) | unpin (holder : H) | expirePin (holder : H) | dropWant (holder : H)
  | takePossession (holder : H)
  | gcCommit | gcUnlink | protectedDelete

/-- The transition each kind names. -/
@[transition]
def Trans : Kind H → Transition (Cell H)
  | .beginWrite => BeginWrite
  | .writeAbort => WriteAbort
  | .commitComplete durable => CommitComplete durable
  | .commitGroups durable => CommitGroups durable
  | .finalizeRemote => FinalizeRemote
  | .age => Age
  | .adoptRemote => AdoptRemote
  | .cacheEvict => CacheEvict
  | .dropStaged => DropStaged
  | .sourcePublish holder => SourcePublish holder
  | .replicaPromote holder pinned => ReplicaPromote holder pinned
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

/-- Which transitions stand a leaf and so share a transaction with a trie head
flip.  `Bridge` pairs these with the `MptGc` transition they commit alongside;
every other transition interleaves freely
(`Bridge.live_leaf_flips_head`). -/
def Kind.flipsHead : Kind H → Bool
  | .sourcePublish _ | .replicaPromote _ _ | .ordinaryPromote _ => true
  | _ => false

/-- Some transition took the cell from `c` to `c'`. -/
def CellStep (c c' : Cell H) : Prop := ∃ k : Kind H, (Trans k).rel c c'

/-- A transition that does not flip a head took the cell from `c` to `c'`. -/
def LocalStep (c c' : Cell H) : Prop := ∃ k : Kind H, k.flipsHead = false ∧ (Trans k).rel c c'

theorem LocalStep.step (h : LocalStep c c') : CellStep c c' :=
  let ⟨k, _, t⟩ := h
  ⟨k, t⟩

/-! ## What every transition preserves -/

/-- The claim behind a live leaf: its holder is a role, the content has an
entry, and the holder either pins a durable claim or has a want recorded. -/
def LiveClaim (c : Cell H) (holder : H) : Prop :=
  IsRole holder ∧ c.entry ∧ ((holder ∈ c.pin ∧ Durable c) ∨ holder ∈ c.want)

/-- What survives everything, backend loss included.  Compared with `NoLoss`
above: `Available` is `Durable`, the pin clause covers only roles, and a
source leaf may be wanted rather than pinned. -/
structure Invariant (c : Cell H) : Prop where
  /-- A role's pin stands on a durable claim. -/
  role_pin_durable : ∀ holder, IsRole holder → holder ∈ c.pin → Durable c
  /-- A source leaf has a claim behind it. -/
  source_live : ∀ holder ∈ c.sourceLive, LiveClaim c holder
  /-- A replica leaf has a claim behind it. -/
  replica_live : ∀ holder ∈ c.replicaLive, LiveClaim c holder
  /-- A metadata-only leaf has an entry. -/
  ordinary_live : ∀ holder ∈ c.ordinaryLive, c.entry
  /-- A sweep in flight protects nothing and has no row. -/
  sweeping : c.sweeping → ¬c.entry ∧ (∀ holder, holder ∉ c.pin) ∧ ¬c.writing ∧ ¬c.row

theorem initial_invariant : Invariant ({} : Cell H) :=
  ⟨fun _ _ p => p.elim, fun _ l => l.elim, fun _ l => l.elim, fun _ l => l.elim,
    fun s => s.elim⟩

/-- Every preservation proof below is the same three moves: split on the
transition, substitute the successor cell, let `grind` read the fields. -/
theorem invariant_step (hinv : Invariant c) (hstep : CellStep c c') : Invariant c' := by
  obtain ⟨k, h⟩ := hstep
  obtain ⟨pins, sources, replicas, ordinary, sweepInv⟩ := hinv
  cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h <;> constructor <;>
    grind [LiveClaim, Durable, Available, AnyPin, AnyLive]

theorem noLoss_step (hinv : Invariant c) (hnl : NoLoss c) (hstep : CellStep c c') :
    NoLoss c' := by
  obtain ⟨k, h⟩ := hstep
  obtain ⟨pins, sources, replicas, ordinary, sweepInv⟩ := hinv
  obtain ⟨pinsAvailable, sourcePinned⟩ := hnl
  cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h <;> constructor <;>
    grind [LiveClaim, Durable, Available, AnyPin, AnyLive]

/-! ## Which transition a change betrays -/

variable {k : Kind H}

/-- A step that stands a new source leaf is a publication. -/
theorem sourcePublish_of_new_leaf (h : (Trans k).rel c c')
    (new : holder ∈ c'.sourceLive) (old : holder ∉ c.sourceLive) : k = .sourcePublish holder := by
  cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h <;> grind

/-- A step that stands a new replica leaf is a promotion. -/
theorem replicaPromote_of_new_leaf (h : (Trans k).rel c c')
    (new : holder ∈ c'.replicaLive) (old : holder ∉ c.replicaLive) :
    ∃ pinned, k = .replicaPromote holder pinned := by
  cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h
  case replicaPromote _ pinned => exact ⟨pinned, by grind⟩
  all_goals grind

/-- A step that stands a new leaf of either kind flips a head. -/
theorem flipsHead_of_new_leaf (h : (Trans k).rel c c')
    (new : holder ∈ c'.sourceLive ∨ holder ∈ c'.replicaLive)
    (old : holder ∉ c.sourceLive ∧ holder ∉ c.replicaLive) : k.flipsHead = true := by
  rcases new with source | replica
  · rw [sourcePublish_of_new_leaf h source old.1]; rfl
  · obtain ⟨_, rfl⟩ := replicaPromote_of_new_leaf h replica old.2; rfl

/-! ## The store: one cell per content root -/

/-- The store: one cell per content root. -/
abbrev State (H : Type) := Root → Cell H

/-- The empty store. -/
def Initial : State H := fun _ => {}

end Synchronicity.Cas

#lint
