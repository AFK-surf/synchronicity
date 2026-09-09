import Synchronicity.MptsyncDeviceExecution
import Synchronicity.OriginQueueSource
import Synchronicity.ProductionTimeline

/-! Runtime boundary for maintenance-driven promotion scheduling.

Rust wakes the maintenance loop on its interval, takes one native bulk snapshot
of pending heads, and calls `try_promote` once for every listed origin.  This
module records those factual outer-runtime observations.  It deliberately says
nothing about the command's report or successful phases; the only command fact
is the actual `ReconciliationExecution.Step` invocation. -/
namespace Synchronicity.MptsyncPromotionScheduling
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
open SimulatedHost PrivateDatabase

/-- The process timeline's maintenance observations.  These maps are the narrow
host seam for the Rust timer/pass orchestration, which is not a Lean command. -/
structure MaintenanceTimeline (_states : Nat → State) where
  intervalWakeAt : Nat → Bool
  passAt : Nat → Option OriginQueueSource.BulkHeadSnapshot

/-- One interval wake and the pending-head snapshot taken at the start of that
pass. A later item may be invoked after earlier origins changed the database. -/
structure MaintenancePass (states : Nat → State)
    (maintenance : MaintenanceTimeline states) (passStart : Nat) where
  source : OriginQueueSource.BulkHeadSnapshot
  woke : maintenance.intervalWakeAt passStart = true
  observed : maintenance.passAt passStart = some source
  sourceAt : source.state = states passStart

/-- One origin listed by a factual maintenance pass and the exact direct
`try_promote` command invocation registered on the shared device axis.  Pending
queue membership is intentionally not a field: it follows from `pending`. -/
structure PromotionDispatch (states : Nat → State)
    (registry : MptsyncDeviceExecution.Registry states)
    (maintenance : MaintenanceTimeline states) (origin : Origin.Parsed)
    (index : Nat) where
  passStart : Nat
  pass : MaintenancePass states maintenance passStart
  afterPassStart : passStart ≤ index
  listedVersion : HeadVersion
  listed : pass.source.view (Origin.canonical origin) .pending = some listedVersion
  currentView : HeadView
  currentRepresents : HeadView.Represents (states index).db currentView
  currentBacked : HeadView.Backed (states index).db currentView
  version : HeadVersion
  pending : currentView (Origin.canonical origin) .pending = some version
  now : Int64
  refused : List (UInt64 × ByteArray × ByteArray)
  invoked : ReconciliationExecution.Step (.promotion origin now refused)
    (states index) (states (index + 1))
  registered : MptsyncDeviceExecution.PromotionSegment registry origin index

theorem PromotionDispatch.pendingMember
    (dispatch : PromotionDispatch states registry maintenance origin index) :
    OriginQueueSource.pendingItem (Origin.canonical origin) ∈
      dispatch.pass.source.pendingItems :=
  dispatch.pass.source.pendingItem_mem dispatch.listed

theorem PromotionDispatch.pendingTarget
    (dispatch : PromotionDispatch states registry maintenance origin index) :
    dispatch.pass.source.pendingTarget
        (OriginQueueSource.pendingItem (Origin.canonical origin)) =
      ({ origin := Origin.canonical origin,
          pointer := { seq := dispatch.listedVersion.seq, root := dispatch.listedVersion.root } } :
        OriginScheduleExecution.Target) :=
  dispatch.pass.source.pendingTarget_at dispatch.listed

/-- Raw stable-prefix frames between completed Fetch work and the maintenance
invocation. Persistent trie evidence is retained step by step; the tracked
origin's two decoded slots are observed unchanged at the endpoint. Other
origins and unrelated database relations may change freely. -/
structure StableWaitFrame (states : Nat → State) (origin : String)
    (start stop : Nat) (beforeView afterView : HeadView) : Prop where
  forward : start ≤ stop
  evidence : ProductionTimeline.StepwiseIncluded ⟨states⟩ start stop
  beforeRepresents : HeadView.Represents (states start).db beforeView
  afterRepresents : HeadView.Represents (states stop).db afterView
  afterBacked : HeadView.Backed (states stop).db afterView
  afterValid : ∀ slot version, afterView origin slot = some version → version.root.size = 32
  slots : ∀ slot, afterView origin slot = beforeView origin slot
  payload : MptsyncStableTail.PayloadFrame (states start).db (states stop).db

theorem StableWaitFrame.evidenceIncluded
    (frame : StableWaitFrame states origin start stop beforeView afterView) :
    TrieFetchCompletion.EvidenceIncluded
      (TrieFetchAdmissionProgress.replicaOfState (states start))
      (TrieFetchAdmissionProgress.replicaOfState (states stop)) :=
  frame.evidence.carries ⟨states⟩ frame.forward

theorem StableWaitFrame.stableSlots
    (frame : StableWaitFrame states origin start stop beforeView afterView)
    (initial : AcceptanceProgress.StableSlots (states start) origin latest beforeView) :
    AcceptanceProgress.StableSlots (states stop) origin latest afterView := by
  refine ⟨frame.afterRepresents, frame.afterBacked, frame.afterValid, ?_⟩
  rw [frame.slots .complete, frame.slots .pending]
  exact initial.maximum

/-- A maintenance invocation eventually observed after a finite retry
boundary, with the wait described by raw stepwise evidence/slot frames rather
than an unrealistic equality of whole host states. -/
structure DispatchAfter (states : Nat → State)
    (registry : MptsyncDeviceExecution.Registry states)
    (maintenance : MaintenanceTimeline states) (origin : Origin.Parsed)
    (boundary : Nat) (startView : HeadView) where
  index : Nat
  dispatch : PromotionDispatch states registry maintenance origin index
  passAfterBoundary : boundary ≤ dispatch.passStart
  wait : StableWaitFrame states (Origin.canonical origin) boundary index startView
    dispatch.currentView

end Synchronicity.MptsyncPromotionScheduling
