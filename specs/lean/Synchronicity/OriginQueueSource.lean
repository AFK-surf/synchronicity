import Synchronicity.AcceptanceProgress
import Synchronicity.OriginScheduleExecution

/-! The native `Store::all_heads` boundary used to build Hello summary pages
and pending-origin passes.

`all_heads` is not a production Lean command: Rust performs the bulk SQLite
read and then passes the resulting origin queue to the verified
`OriginSchedule.plan`.  `BulkHeadSnapshot` is the narrow refinement seam for a
successful, stable bulk read.  It relates the finite decoded origin set to an
independently represented raw `heads` table.  Queue items, summary weights,
servable complete heads and pending targets are pure functions of that
observation; callers cannot choose them independently.
-/
namespace Synchronicity.OriginQueueSource
open VerifiedCore VerifiedCore.Replication
open AcceptanceProgress

/-- At least one public slot exists for this origin in the represented raw
database. -/
def Occupied (view : HeadView) (origin : String) : Prop :=
  (∃ version, view origin .complete = some version) ∨
    ∃ version, view origin .pending = some version

/-- Number of summaries emitted by `all_local_summaries` for one origin.
Equal complete/pending pointers are deduplicated; distinct slots remain one
atomic weighted planner item. -/
def summaryWeight (view : HeadView) (origin : String) : UInt64 :=
  match view origin .complete, view origin .pending with
  | none, none => 0
  | some _, none | none, some _ => 1
  | some complete, some pending =>
      if complete.seq == pending.seq && complete.root == pending.root then 1 else 2

def advertisementItem (view : HeadView) (origin : String) : OriginSchedule.Item :=
  { origin := origin, weight := summaryWeight view origin }

def pendingItem (origin : String) : OriginSchedule.Item :=
  { origin := origin, weight := 1 }

private def missingPointer : History.Pointer :=
  { seq := 0, root := ByteArray.empty }

/-- A successful native bulk read of both slots. `originsExact` is the host
boundary contract: precisely the origins with a decoded complete or pending
slot occur in the finite result. `represented` anchors that result in raw DB
rows. A signed head sent by Hello is tied specifically to the complete slot
and to the native scoped-servability check. A newer pending summary may affect
the group's weight, but can never masquerade as a servable signed head. -/
structure BulkHeadSnapshot where
  state : SimulatedHost.State
  view : HeadView
  represented : HeadView.Represents state.db view
  backed : HeadView.Backed state.db view
  origins : List String
  originsExact : ∀ origin, origin ∈ origins ↔ Occupied view origin
  originKeysDistinct : ∀ left, left ∈ origins → ∀ right, right ∈ origins →
    OriginSchedule.key left = OriginSchedule.key right → left = right
  completeHead : String → Head
  completeHeadMatches : ∀ origin version, view origin .complete = some version →
    Origin.canonical (completeHead origin).origin = origin ∧
      version = (⟨(completeHead origin).seq, (completeHead origin).root⟩ : HeadVersion)
  /-- Result of the same native scoped trie-completeness check used by
  `all_local_summaries` and `advertisement_off_runtime`. This Boolean remains a
  native host-boundary observation because that Rust walk is not a Lean
  effect; it cannot be true for an origin lacking a complete slot. -/
  nativeServable : String → Bool
  nativeServableHasComplete : ∀ origin, nativeServable origin = true →
    ∃ version, view origin .complete = some version

def BulkHeadSnapshot.advertisementItems (source : BulkHeadSnapshot) :
    List OriginSchedule.Item :=
  source.origins.map (advertisementItem source.view)

def BulkHeadSnapshot.sentHeads (source : BulkHeadSnapshot)
    (item : OriginSchedule.Item) : List Head :=
  if source.nativeServable item.origin then [source.completeHead item.origin] else []

def BulkHeadSnapshot.pendingOrigins (source : BulkHeadSnapshot) : List String :=
  source.origins.filter fun origin => (source.view origin .pending).isSome

def BulkHeadSnapshot.pendingItems (source : BulkHeadSnapshot) :
    List OriginSchedule.Item :=
  source.pendingOrigins.map pendingItem

def BulkHeadSnapshot.pendingTarget (source : BulkHeadSnapshot)
    (item : OriginSchedule.Item) : OriginScheduleExecution.Target :=
  { origin := item.origin
    pointer := match source.view item.origin .pending with
      | none => missingPointer
      | some version => { seq := version.seq, root := version.root } }

private theorem occupied_of_selected
    (selected : selectedVersion view origin = some version) : Occupied view origin := by
  cases complete : view origin .complete <;> cases pending : view origin .pending <;>
    simp only [selectedVersion, complete, pending] at selected
  · contradiction
  · exact Or.inr ⟨_, pending⟩
  · exact Or.inl ⟨_, complete⟩
  · exact Or.inl ⟨_, complete⟩

theorem BulkHeadSnapshot.advertisementItem_mem (source : BulkHeadSnapshot)
    (occupied : Occupied source.view origin) :
    advertisementItem source.view origin ∈ source.advertisementItems := by
  apply List.mem_map.mpr
  exact ⟨origin, (source.originsExact origin).mpr occupied, rfl⟩

theorem BulkHeadSnapshot.advertisementItem_mem_of_complete (source : BulkHeadSnapshot)
    (complete : source.view origin .complete = some version) :
    advertisementItem source.view origin ∈ source.advertisementItems :=
  source.advertisementItem_mem (Or.inl ⟨version, complete⟩)

theorem BulkHeadSnapshot.completeHead_mem_sentHeads (source : BulkHeadSnapshot)
    (servable : source.nativeServable origin = true) :
    source.completeHead origin ∈
      source.sentHeads (advertisementItem source.view origin) := by
  simp [BulkHeadSnapshot.sentHeads, advertisementItem, servable]

/-- The complete pointer backing a servable full signed head is retained in
the joined history relation of the same native bulk-read state. -/
theorem BulkHeadSnapshot.servableStoredFloor (source : BulkHeadSnapshot)
    (servable : source.nativeServable origin = true) :
    ∃ version, source.view origin .complete = some version ∧
      ReconciliationRead.StoredFloor source.state.db origin "complete"
        version.seq.toInt64 version.root := by
  obtain ⟨version, complete⟩ := source.nativeServableHasComplete origin servable
  exact ⟨version, complete, source.backed origin .complete version complete⟩

theorem BulkHeadSnapshot.advertisementDistinct (source : BulkHeadSnapshot) :
    ∀ left ∈ source.advertisementItems, ∀ right ∈ source.advertisementItems,
      OriginSchedule.key left.origin = OriginSchedule.key right.origin → left = right := by
  intro left leftMember right rightMember same
  obtain ⟨leftOrigin, leftOriginMember, leftEq⟩ := List.mem_map.mp leftMember
  obtain ⟨rightOrigin, rightOriginMember, rightEq⟩ := List.mem_map.mp rightMember
  subst left
  subst right
  have originSame := source.originKeysDistinct leftOrigin leftOriginMember
    rightOrigin rightOriginMember same
  subst rightOrigin
  rfl

theorem BulkHeadSnapshot.pendingItem_mem (source : BulkHeadSnapshot)
    (pending : source.view origin .pending = some version) :
    pendingItem origin ∈ source.pendingItems := by
  apply List.mem_map.mpr
  refine ⟨origin, ?_, rfl⟩
  apply List.mem_filter.mpr
  refine ⟨(source.originsExact origin).mpr (Or.inr ⟨version, pending⟩), ?_⟩
  simp [pending]

theorem BulkHeadSnapshot.pendingTarget_at (source : BulkHeadSnapshot)
    (pending : source.view origin .pending = some version) :
    source.pendingTarget (pendingItem origin) =
      ({ origin := origin, pointer := { seq := version.seq, root := version.root } } :
        OriginScheduleExecution.Target) := by
  simp [BulkHeadSnapshot.pendingTarget, pendingItem, pending]

theorem BulkHeadSnapshot.pendingDistinct (source : BulkHeadSnapshot) :
    ∀ left ∈ source.pendingItems, ∀ right ∈ source.pendingItems,
      OriginSchedule.key left.origin = OriginSchedule.key right.origin → left = right := by
  intro left leftMember right rightMember same
  obtain ⟨leftOrigin, leftPending, leftEq⟩ := List.mem_map.mp leftMember
  obtain ⟨rightOrigin, rightPending, rightEq⟩ := List.mem_map.mp rightMember
  subst left
  subst right
  have leftOriginMember := (List.mem_filter.mp leftPending).1
  have rightOriginMember := (List.mem_filter.mp rightPending).1
  have originSame := source.originKeysDistinct leftOrigin leftOriginMember
    rightOrigin rightOriginMember same
  subst rightOrigin
  rfl

theorem BulkHeadSnapshot.pendingTarget_sameOrigin (source : BulkHeadSnapshot)
    (item : OriginSchedule.Item) (_member : item ∈ source.pendingItems) :
    (source.pendingTarget item).origin = item.origin := by
  rfl

/-- A strictly newer head installed by an actual acceptance fold is present in
the next successful native pending-slot listing of that state. This derives
planner membership from the slot write and exact bulk-read refinement; neither
the item nor its membership is an opportunity premise. -/
theorem BulkHeadSnapshot.pendingItem_mem_after_acceptance
    (source : BulkHeadSnapshot)
    (run : ObservedAcceptanceFold origin keep initial initialState initialView stable
      heads final finalState finalView)
    (atState : source.state = finalState)
    (atView : source.view = finalView)
    (selected : selectedVersion finalView origin = some version)
    (strict : initial < versionRank version) :
    pendingItem origin ∈ source.pendingItems := by
  have representedAtFinal : HeadView.Represents finalState.db finalView := by
    rw [← atState, ← atView]
    exact source.represented
  have pending := run.pending_eq_selected_of_initial_lt selected strict
  rw [← atView] at pending
  exact source.pendingItem_mem pending

end Synchronicity.OriginQueueSource
