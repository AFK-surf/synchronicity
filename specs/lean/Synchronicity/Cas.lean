import Synchronicity.Prelude

/-!
The CAS transition system, stated once.

`Cell H` is one content root as the store sees it: its row — the size it
records and the groups it claims verified — its bytes and durable claim, the
entry that names it, and the pins, wants and live leaves indexed by holder
`H`.  Every transition is a `Transition`, a guard and a successor, and a named
Rust linearization point carried by the `rust_impl` attribute on its
definition.  Where the code has two outcomes — a complete commit that is or is
not durable, a promotion that pins or wants — the outcome is a parameter of
the transition, so that each is still one guarded deterministic step.  `Kind`
names the transitions with their parameters, `Trans` gives each its
`Transition`, and `CellStep` is their union.  The models that read this file
differ only in `H` and in which steps they close over:

- `SystemSafety` is the fault-free closure, with the operator distinguished
  from the roles a space configures;
- `FaultTolerant` adds backend loss and the heals, over the same cells.

A row need not be complete.  A peer slice, a delta proof or a cloud cache
refill commits the groups it verified into the row's bitmap (`CommitGroups`),
and an ingest is the same commit of every group at once (`CommitComplete`).
Until the final group is held the size the row records is a claim off an
entry rather than a fact (`Attested`), and `Settles` is the rule every commit's
size claim meets: a durable or attested size stands and a claim yields, taking
the held bits with it when it moves the group count.  `settled_size_is_stable`
is what that buys — no step moves the size of a durable or attested row — and
`held_within_size` is why the bits a settlement keeps still describe the tree
being written.

Two invariants live here.  `Invariant` is what every transition preserves, the
heals included: a role's pin stands on a durable claim, a live leaf's holder is
a role with a pin or a want behind it, and a row's held groups lie inside its
own tree.  `NoLoss` is what only the fault-free transitions preserve — every
pin, the operator's included, stands on available content, a source's leaf is
pinned, never merely wanted, a durable claim is backed by a remote copy or a
complete row, and a complete row is backed by bytes.  `SystemSafety`'s
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

/-! ## Groups and sizes -/

/-- `synch_core::CHUNK_GROUP_SIZE`: the bytes in one chunk group, the store's
unit of verification. -/
def groupBytes : Nat := 16 * 1024

/-- `synch_core::group_count`: the groups an object of `size` bytes has.  The
empty object has one, so every object has a final group. -/
def groupCount (size : Nat) : Nat :=
  if size = 0 then 1 else (size + groupBytes - 1) / groupBytes

theorem groupCount_pos (size : Nat) : 0 < groupCount size := by
  unfold groupCount groupBytes
  split <;> omega

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
  /-- The object size the source publisher derived for this root.  Rust writes
  the file entry's size into the complete `BlobAd`; keeping it separate from
  the CAS row makes that cross-layer equality stateable. -/
  sourceAdvertised : H → Nat → Prop := fun _ _ => False
  /-- The holders whose replica leaf names the content. -/
  replicaLive : Set H := ∅
  /-- The holders whose metadata-only leaf names the content. -/
  ordinaryLive : Set H := ∅
  /-- The `blobs` row exists. -/
  row : Prop := False
  /-- The size the row records: a claim off an entry until `Attested`. -/
  size : Nat := 0
  /-- The groups the row claims verified — its bitmap, or every group of
  `size` when it is complete. -/
  held : Set Nat := ∅
  /-- The complete payload and outboard are on local disk. -/
  bytes : Prop := False
  /-- The remote backend holds a copy. -/
  remote : Prop := False
  /-- The durable tier acknowledged a remote copy. This claim survives loss
  until healing; eviction tests the claim, never the hidden physical copy. -/
  remoteClaim : Prop := False
  /-- The backend has acknowledged the bytes durably. -/
  durable : Prop := False
  /-- The number of write leases held.  Rust counts rather than flags these:
  overlapping fetches of one root are ordinary, and the first lease to end
  must not clear the protection of the second. -/
  writing : Nat := 0
  /-- A GC row commit has run and its unlink has not. -/
  sweeping : Prop := False
  /-- Inside the retention window. -/
  fresh : Prop := False

/-- `cas.rs::read_claim`: what a row claims held.  A complete row is read as
holding every group of its size; a bitmap row holds the groups it names. -/
def Complete (c : Cell H) : Prop := ∀ g, g < groupCount c.size → g ∈ c.held

/-- `cas.rs::size_is_attested`.  Only the final group attests to a size: every
other group's chaining value is the same whatever the object's length, so
holding the first half says nothing about where the object ends. -/
@[rust_impl "cas-size-attested"]
def Attested (c : Cell H) : Prop := Complete c ∨ groupCount c.size - 1 ∈ c.held

theorem complete_is_attested {c : Cell H} (h : Complete c) : Attested c := Or.inl h

/-- A size that is a fact rather than a claim: the backend acknowledged it, or
the disk attests to it. -/
def Settled (c : Cell H) : Prop := c.durable ∨ Attested c

/-- `cas.rs::settle_size`, as the guard on a commit claiming `claimed` bytes.
With no row the claim stands; a settled size must agree, and a writer offering
a different one is offering bytes for some other object; an unsettled size is
a peer's claim off an entry and yields to this writer's. -/
@[rust_impl "cas-size-settlement"]
def Settles (c : Cell H) (claimed : Nat) : Prop := c.row → claimed = c.size ∨ ¬Settled c

/-- What a commit of `groups` under a size settled to `size` leaves held: the
groups just verified and, when the group count did not move, the groups the
row already held — clipped to the tree of `size` either way.  Bits verified
under one tree shape say nothing under another, which is `settle_size`'s
`reset_held`. -/
def settleHeld (c : Cell H) (size : Nat) (groups : Set Nat) : Set Nat :=
  {g | g < groupCount size ∧
    (g ∈ groups ∨ (c.row ∧ groupCount size = groupCount c.size ∧ g ∈ c.held))}

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
  not_writing : c.writing = 0
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
  not_writing : c.writing = 0
  /-- No sweep is in flight. -/
  not_sweeping : ¬c.sweeping

attribute [grind cases] Collectable Deletable

/-! ## Transitions that do not ask who the holder is -/

/-- `db.rs::Store::lease_write`. -/
@[transition, rust_impl "cas-write-lease-begin"]
def BeginWrite : Transition (Cell H) where
  guard c := ¬c.sweeping
  post c := { c with writing := c.writing + 1 }

/-- `db.rs::WriteLease::drop`. -/
@[transition, rust_impl "cas-write-lease-end"]
def WriteAbort : Transition (Cell H) where
  guard c := 0 < c.writing
  post c := { c with writing := c.writing - 1 }

/-- `cas.rs::commit_groups`: the one row write every writer of verified
groups makes — a peer slice, a delta proof, a promotion, a cloud cache refill
and, through `CommitComplete`, an ingest.  The size claim meets `Settles`
inside the transaction; the row then records the claim and what is held under
it, is complete when every group of that size is, and rises to durable only on
a complete commit a local backend acknowledges (`durable`, from
`complete_is_durable`).  `upsert_blob_row` keeps `durable` at
`max(old, new)`.  With `durable = false` a complete commit is the staged row a
cloud backend leaves until `finalize`, which `DropStaged` may later discard. -/
@[transition]
def CommitGroups (durable : Bool) (size : Nat) (groups : Set Nat) : Transition (Cell H) where
  guard c := ¬c.sweeping ∧ Settles c size
  post c :=
    let held := settleHeld c size groups
    let complete := ∀ g, g < groupCount size → g ∈ held
    { c with
      row := True
      size := size
      held := held
      bytes := c.bytes ∨ complete
      durable := (durable ∧ complete) ∨ c.durable
      fresh := True }

/-- `cas.rs::Store::commit_complete`, the ingest's row: `CommitGroups` with
every group of the object at once.  File callers hold the write lease; inline
callers have no unlink window. -/
@[transition, rust_impl "cas-write-complete-commit"]
def CommitComplete (durable : Bool) (size : Nat) : Transition (Cell H) :=
  CommitGroups durable size Set.univ

/-- `backend.rs::Cloud::finalize`: a complete row's pair, written to the
backend, is acknowledged. -/
@[transition, rust_impl "cas-cloud-finalize"]
def FinalizeRemote : Transition (Cell H) where
  guard c := ¬c.sweeping ∧ c.row ∧ Complete c
  post c := { c with remote := True, remoteClaim := True, durable := True }

/-- `gc.rs::gc_content(before)`: the retention window elapses. -/
@[transition, rust_impl "cas-retention-elapses"]
def Age : Transition (Cell H) where
  guard _ := True
  post c := { c with fresh := False }

/-- `cas.rs::Store::adopt_durable_blob`.  A cold durable row reconstructed
after the remote backend confirmed the final pair exists, holding nothing
locally; a row already there must record the size storage reports. -/
@[transition, rust_impl "cas-adopt-durable"]
def AdoptRemote (size : Nat) : Transition (Cell H) where
  guard c := ¬c.sweeping ∧ (c.row → size = c.size)
  post c := { c with row := True, size := size, remote := True, remoteClaim := True, durable := True }

/-- `cas.rs::clear_blob_cache`, the durable branch: the row keeps its durable
claim and forgets what it held. -/
@[transition, rust_impl "cas-cache-evict"]
def CacheEvict : Transition (Cell H) where
  guard c := c.remoteClaim ∧ c.durable
  post c := { c with held := ∅, bytes := False }

/-- The non-durable branch of `cas.rs::clear_blob_cache`,
`reconcile_scratch_generation`, and the `commit_cas_migration` discard.  None
of them consult `pins`; `NoLoss` is what makes that safe
(`SystemSafety.staged_row_drop_is_unpinned`). -/
@[transition, rust_impl "cas-drop-staged-row"]
def DropStaged : Transition (Cell H) where
  guard c := ¬c.durable ∧ c.writing = 0
  post c := { c with row := False, held := ∅, bytes := False }

/-- The same promotion as `ReplicaPromote` on a metadata-only node: an entry
and nothing else (`reconcile.rs::try_promote`). -/
@[transition]
def OrdinaryPromote (holder : H) : Transition (Cell H) where
  guard c := ¬c.sweeping
  post c := { c with entry := True, ordinaryLive := insert holder c.ordinaryLive }

/-- `views.rs::apply_change`, the `Deleted` arm under `materialize_diff`: a
source leaf leaves the derived views. -/
@[transition, rust_impl "mpt-materialize-remove-source"]
def RemoveSource (holder : H) : Transition (Cell H) where
  guard _ := True
  post c := { c with
    sourceLive := c.sourceLive \ {holder}
    sourceAdvertised := fun h size => h ≠ holder ∧ c.sourceAdvertised h size }

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

/-- `cas.rs::Store::pin`.  The predicate is `durable` alone: a pin is a
promise about the durable tier, and under `NoLoss` a durable claim is backed
by a remote copy or a complete row, so the pin stands on available content. -/
@[transition]
def Pin (holder : H) : Transition (Cell H) where
  guard c := ¬c.sweeping ∧ Durable c
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

/-- `replica.rs::take_possession`, with `Store::pin`'s predicate. -/
@[transition]
def TakePossession (holder : H) : Transition (Cell H) where
  guard c := ¬c.sweeping ∧ holder ∈ c.want ∧ Durable c
  post c := { c with pin := insert holder c.pin, want := c.want \ {holder} }

/-- `views.rs::Store::remove_source`: a source role goes, and with it every
pin and want of its holder that no live leaf stands on.  Per root this is
`Unpin` and `DropWant` under their own guard, which the Rust carries as the
entry check on both deletes: a hold behind an entry the tree still names
survives the role. -/
@[transition, rust_impl "cas-remove-source-role"]
def RemoveRole (holder : H) : Transition (Cell H) where
  guard c := holder ∉ c.sourceLive ∧ holder ∉ c.replicaLive
  post c := { c with pin := c.pin \ {holder}, want := c.want \ {holder} }

/-- `views.rs::Store::remove_replica`: a replica role retires.  Its holder
ceases to exist, so the leaves it stood behind are no longer any role's, and
its pins and wants go with it, whatever the tree still names — the operator
chose this, and `pin_held` is the choice to keep the content as the
operator's own pins instead.  The entry rows stay, which is what keeps the
content from collection (`Collectable.no_entry`). -/
@[transition, rust_impl "cas-remove-replica-role"]
def RetireRole (holder : H) : Transition (Cell H) where
  guard _ := True
  post c := { c with
    pin := c.pin \ {holder}
    want := c.want \ {holder}
    sourceLive := c.sourceLive \ {holder}
    sourceAdvertised := fun h size => h ≠ holder ∧ c.sourceAdvertised h size
    replicaLive := c.replicaLive \ {holder} }

/-- `cas.rs::delete_blob_if_collectable`, the row commit. -/
@[transition]
def GcCommit : Transition (Cell H) where
  guard := Collectable
  post c := { c with row := False, held := ∅, durable := False, sweeping := True }

/-- The unlink half of `delete_blob_if_collectable`. -/
@[transition]
def GcUnlink : Transition (Cell H) where
  guard c := c.sweeping
  post c := { c with bytes := False, sweeping := False }

/-- `cas.rs::Store::delete_blob`. -/
@[transition]
def ProtectedDelete : Transition (Cell H) where
  guard := Deletable
  post c := { c with row := False, held := ∅, durable := False, sweeping := True }

/-! ### Facts a single transition commits, whoever the holders are -/

variable {c c' : Cell H} {holder : H}

theorem gc_respects_protection (hgc : GcCommit.rel c c')
    (guarded : c.entry ∨ AnyPin c ∨ 0 < c.writing) : False := by
  rcases guarded with entry | pin | writing
  · exact hgc.1.no_entry entry
  · exact hgc.1.no_pin pin
  · exact Nat.ne_of_gt writing hgc.1.not_writing

theorem write_lease_excludes_gc (writing : 0 < c.writing) (hgc : GcCommit.rel c c') : False :=
  gc_respects_protection hgc (Or.inr (Or.inr writing))

/-- Two overlapping writers remain protected after either one releases its
lease; the remaining count still excludes collection. -/
theorem overlapping_write_survives_one_release {c₁ c₂ c₃ : Cell H}
    (first : BeginWrite.rel c c₁) (second : BeginWrite.rel c₁ c₂)
    (release : WriteAbort.rel c₂ c₃) : 0 < c₃.writing := by
  simp only [transition] at first second release
  obtain ⟨_, rfl⟩ := first
  obtain ⟨_, rfl⟩ := second
  obtain ⟨_, rfl⟩ := release
  change 0 < (c.writing + 1 + 1) - 1
  omega

theorem possession_is_atomic (h : (TakePossession holder).rel c c') :
    holder ∈ c'.pin ∧ holder ∉ c'.want ∧ Durable c' := by
  simp only [transition] at h
  obtain ⟨⟨_, _, durable⟩, rfl⟩ := h
  exact ⟨Set.mem_insert _ _, fun w => w.2 rfl, durable⟩

/-- An ingest leaves a complete row with its bytes on disk. -/
theorem commit_complete_is_complete {durable : Bool} {size : Nat}
    (h : (CommitComplete durable size).rel c c') : Complete c' ∧ c'.bytes := by
  simp only [transition] at h
  obtain ⟨_, rfl⟩ := h
  refine ⟨fun g hg => ⟨hg, Or.inl (Set.mem_univ g)⟩, Or.inr ?_⟩
  exact fun g hg => ⟨hg, Or.inl (Set.mem_univ g)⟩

/-- A commit carries a bit it did not verify only when the group count stayed,
so the bit still describes the tree being written (`settle_size`, rule 3). -/
theorem carried_bit_shares_tree {durable : Bool} {size : Nat} {groups : Set Nat} {g : Nat}
    (h : (CommitGroups durable size groups).rel c c') (kept : g ∈ c'.held) (new : g ∉ groups) :
    groupCount c'.size = groupCount c.size ∧ g ∈ c.held := by
  simp only [transition] at h
  obtain ⟨_, rfl⟩ := h
  simp only [settleHeld, Set.mem_setOf_eq] at kept
  exact ⟨kept.2.resolve_left new |>.2.1, kept.2.resolve_left new |>.2.2⟩

/-- What a fault breaks and the fault-free transitions keep: every pin, the
operator's included, stands on available content; a source's leaf is pinned,
never merely wanted; a durable claim is backed by the remote copy or a
complete row; and a complete row is backed by its bytes on disk. -/
structure NoLoss (c : Cell H) : Prop where
  /-- Only the fault-free model assumes an acknowledged remote copy still exists. -/
  remote_claim_backed : c.remoteClaim → c.remote
  /-- Every pin stands on available content. -/
  pin_available : ∀ holder ∈ c.pin, Available c
  /-- A source's leaf is pinned. -/
  source_pinned : ∀ holder ∈ c.sourceLive, holder ∈ c.pin
  /-- A durable claim has a remote copy or a complete row behind it. -/
  durable_backed : c.durable → c.remote ∨ Complete c
  /-- A complete row has its bytes on disk. -/
  complete_backed : Complete c → c.bytes
  /-- A live source advertises exactly the size its durable CAS row records. -/
  source_advertised : ∀ holder ∈ c.sourceLive,
    c.sourceAdvertised holder c.size ∧
      ∀ advertised, c.sourceAdvertised holder advertised → advertised = c.size

theorem initial_noLoss : NoLoss ({} : Cell H) :=
  ⟨False.elim, fun _ p => p.elim, fun _ l => l.elim, fun d => d.elim,
    fun complete => (complete 0 (groupCount_pos 0)).elim, fun _ l => l.elim⟩

/-! ## Transitions that stand a role behind a leaf -/

variable [Roles H]

/-- The source-publication micro-step inside `Node::publish`:
`hold_source_blob` checks that `publishedSize` is the durable row's size, and
the transaction derives the complete `BlobAd` from that value.  A typed Rust
`refresh_blob` or `withdraw_blob` intent for an already-live source recomputes
the same ad and is a stuttering step in this abstraction. -/
@[transition]
def SourcePublish (holder : H) (publishedSize : Nat) : Transition (Cell H) where
  guard c := IsRole holder ∧ ¬c.sweeping ∧ Durable c ∧ publishedSize = c.size
  post c := { c with
    entry := True
    pin := insert holder c.pin
    want := c.want \ {holder}
    sourceLive := insert holder c.sourceLive
    sourceAdvertised := fun h size =>
      (h = holder ∧ size = publishedSize) ∨ (h ≠ holder ∧ c.sourceAdvertised h size) }

/-- `reconcile.rs::try_promote`, the `content_wants` decision under
`materialize_diff`: a replica leaf takes a pin over a durable row (`pinned`),
or records a want when the row is not durable. -/
@[transition]
def ReplicaPromote (holder : H) (pinned : Bool) : Transition (Cell H) where
  guard c := IsRole holder ∧ ¬c.sweeping ∧ (pinned ↔ Durable c)
  post c := { c with
    entry := True
    pin := if pinned then insert holder c.pin else c.pin
    want := if pinned then c.want \ {holder} else insert holder c.want
    replicaLive := insert holder c.replicaLive }

theorem source_publish_is_closed {publishedSize : Nat}
    (h : (SourcePublish holder publishedSize).rel c c') :
    c'.entry ∧ holder ∈ c'.pin ∧ Durable c' ∧
      c'.sourceAdvertised holder c'.size := by
  simp only [transition] at h
  obtain ⟨⟨_, _, durable, published⟩, rfl⟩ := h
  exact ⟨trivial, Set.mem_insert _ _, durable, by simp [published]⟩

theorem replica_promotion_is_total {pinned : Bool} (h : (ReplicaPromote holder pinned).rel c c') :
    c'.entry ∧ ((holder ∈ c'.pin ∧ Durable c') ∨ holder ∈ c'.want) := by
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
  | commitComplete (durable : Bool) (size : Nat)
  | commitGroups (durable : Bool) (size : Nat) (groups : Set Nat)
  | finalizeRemote | age | adoptRemote (size : Nat) | cacheEvict | dropStaged
  | sourcePublish (holder : H) (publishedSize : Nat)
  | replicaPromote (holder : H) (pinned : Bool)
  | ordinaryPromote (holder : H)
  | removeSource (holder : H) | removeReplica (holder : H) | removeOrdinary (holder : H)
  | dropEntry
  | pin (holder : H) | unpin (holder : H) | expirePin (holder : H) | dropWant (holder : H)
  | takePossession (holder : H) | removeRole (holder : H) | retireRole (holder : H)
  | gcCommit | gcUnlink | protectedDelete

/-- The transition each kind names. -/
@[transition]
def Trans : Kind H → Transition (Cell H)
  | .beginWrite => BeginWrite
  | .writeAbort => WriteAbort
  | .commitComplete durable size => CommitComplete durable size
  | .commitGroups durable size groups => CommitGroups durable size groups
  | .finalizeRemote => FinalizeRemote
  | .age => Age
  | .adoptRemote size => AdoptRemote size
  | .cacheEvict => CacheEvict
  | .dropStaged => DropStaged
  | .sourcePublish holder publishedSize => SourcePublish holder publishedSize
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
  | .removeRole holder => RemoveRole holder
  | .retireRole holder => RetireRole holder
  | .gcCommit => GcCommit
  | .gcUnlink => GcUnlink
  | .protectedDelete => ProtectedDelete

/-- Which transitions stand a leaf and so share a transaction with a trie head
flip.  `Bridge` pairs these with the `MptGc` transition they commit alongside;
every other transition interleaves freely
(`Bridge.live_leaf_flips_head`). -/
def Kind.flipsHead : Kind H → Bool
  | .sourcePublish _ _ | .replicaPromote _ _ | .ordinaryPromote _ => true
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
above: a pin stands on a durable claim rather than available content, the pin
clause covers only roles, and a source leaf may be wanted rather than
pinned. -/
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
  sweeping : c.sweeping → ¬c.entry ∧ (∀ holder, holder ∉ c.pin) ∧ c.writing = 0 ∧ ¬c.row
  /-- Only a row holds groups. -/
  held_has_row : ∀ g ∈ c.held, c.row
  /-- The bitmap is read against the row's own size: every held group lies
  inside the tree of the size the row records. -/
  held_within_size : ∀ g ∈ c.held, g < groupCount c.size

theorem initial_invariant : Invariant ({} : Cell H) :=
  ⟨fun _ _ p => p.elim, fun _ l => l.elim, fun _ l => l.elim, fun _ l => l.elim,
    fun s => s.elim, fun _ g => g.elim, fun _ g => g.elim⟩

/-- Every preservation proof below is the same three moves: split on the
transition, substitute the successor cell, let `grind` read the fields. -/
theorem invariant_step (hinv : Invariant c) (hstep : CellStep c c') : Invariant c' := by
  obtain ⟨k, h⟩ := hstep
  obtain ⟨pins, sources, replicas, ordinary, sweepInv, heldRow, heldSize⟩ := hinv
  cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h <;> constructor <;>
    grind [LiveClaim, Durable, Available, AnyPin, AnyLive, Settles, Settled, Attested, Complete,
      settleHeld, groupCount_pos]

theorem noLoss_step (hinv : Invariant c) (hnl : NoLoss c) (hstep : CellStep c c') :
    NoLoss c' := by
  obtain ⟨k, h⟩ := hstep
  obtain ⟨pins, sources, replicas, ordinary, sweepInv, heldRow, heldSize⟩ := hinv
  obtain ⟨remoteBacked, pinsAvailable, sourcePinned, durableBacked, completeBacked, sourceAd⟩ := hnl
  cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h <;> constructor <;>
    grind [LiveClaim, Durable, Available, AnyPin, AnyLive, Settles, Settled, Attested, Complete,
      settleHeld, groupCount_pos]

/-! ## What no transition does to a settled size -/

variable {k : Kind H}

/-- **A settled size never moves.**  Once a row's size is durable or attested,
no step leaves the row standing under a different size: a commit claiming
another size is refused (`settle_size`, rule 1), and an adoption must agree
with what the row records. -/
@[rust_justifies "cas-size-refusal"]
theorem settled_size_is_stable (h : (Trans k).rel c c') (row : c.row) (settled : Settled c)
    (row' : c'.row) : c'.size = c.size := by
  cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h <;> grind [Settles]

/-- A bit a commit dropped was only ever a claim: the row's size was neither
durable nor attested, so the tree it was verified under was the claim's, and
the claim has yielded (`settle_size`, rule 3). -/
theorem dropped_bit_was_a_claim {durable : Bool} {size : Nat} {groups : Set Nat} {g : Nat}
    (hinv : Invariant c) (h : (CommitGroups durable size groups).rel c c')
    (was : g ∈ c.held) (gone : g ∉ c'.held) : ¬Settled c := by
  have row := hinv.held_has_row g was
  have within := hinv.held_within_size g was
  simp only [transition] at h
  obtain ⟨⟨_, settles⟩, rfl⟩ := h
  intro settled
  obtain rfl := (settles row).resolve_right (fun h => h settled)
  refine gone ?_
  show g < groupCount c.size ∧
    (g ∈ groups ∨ (c.row ∧ groupCount c.size = groupCount c.size ∧ g ∈ c.held))
  exact ⟨within, Or.inr ⟨row, rfl, was⟩⟩

/-! ## Which transition a change betrays -/

/-- A step that stands a new source leaf is a publication. -/
theorem sourcePublish_of_new_leaf (h : (Trans k).rel c c')
    (new : holder ∈ c'.sourceLive) (old : holder ∉ c.sourceLive) :
    ∃ publishedSize, k = .sourcePublish holder publishedSize := by
  cases k <;> simp only [transition] at h <;> obtain ⟨hg, rfl⟩ := h
  case sourcePublish _ publishedSize => exact ⟨publishedSize, by grind⟩
  all_goals grind

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
  · obtain ⟨_, rfl⟩ := sourcePublish_of_new_leaf h source old.1; rfl
  · obtain ⟨_, rfl⟩ := replicaPromote_of_new_leaf h replica old.2; rfl

/-! ## The store: one cell per content root -/

/-- The store: one cell per content root. -/
abbrev State (H : Type) := Root → Cell H

/-- The empty store. -/
def Initial : State H := fun _ => {}

end Synchronicity.Cas

#lint
