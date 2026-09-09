import Synchronicity.MptsyncAdvertisementWindow
import Synchronicity.ScheduledFetchAdmission
import Synchronicity.MptsyncRetryExecution
import Synchronicity.MptsyncPromotionHistory
import Synchronicity.ReconciliationViewExecution
import Synchronicity.ProductionTimeline

/-! Composition of the actual stable-window executions used by M1.

The external liveness seam says that after semantic completion a healthy host
eventually supplies a bounded primitive promotion opportunity.  It does not
store a Fetch success, a Complete result, a Ready witness, or a correct view.
-/
namespace Synchronicity.MptsyncProductionConvergence
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Replication
open SimulatedHost TrieFetchCompletion TrieFetchAdmissionProgress
open MptsyncConvergence AcceptanceProgress

/-- The actual promotion observation following one completed retry trace. -/
structure PromotionWindow (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget)
    (timeline : Nat → SimulatedHost.State) (tailOffset retryStart : Nat)
    (trace : MptsyncStableTail.Trace)
    (accepted : MptsyncAdvertisementWindow.AcceptedLatest valid origin target.head heads)
    (publisher : TrieProgramProofs.RawSnapshot)
    (requirements : FiniteRequirements publisher scope owner root)
    (retry : MptsyncRetryExecution.RetryExecution requirements) where
  index : Nat
  now : Int64
  refused : List (UInt64 × ByteArray × ByteArray)
  opportunity : TrieCompleteConverse.PromotionOpportunity origin now refused (trace.state index)
  reads : TrieCompleteConverse.PromotionReadOpportunity publisher opportunity.tx
    ⟨opportunity.scope, opportunity.authority.provenance.map Origin.canonical⟩
    opportunity.pending.head.root
  requirementScope : opportunity.scope = scope
  requirementOwner : opportunity.authority.provenance.map Origin.canonical = owner
  requirementRoot : opportunity.pending.head.root = root
  sameTime : retryStart + retry.endAt = tailOffset + index
  acceptanceInitialAt : accepted.initialState = timeline accepted.handledAt
  handledBeforeRetry : accepted.handledAt ≤ retryStart
  acceptedAt : accepted.acceptedState = timeline retryStart
  world : TrieDiffCoverage.World
  host : MptsyncPromotionHistory.HostContracts (trace.state index) world services
  initial : MptsyncPromotionHistory.InitialViewEvidence services origin
    (trace.state index) world
  targetSnapshot : target.snapshot = world.snapshot
  targetScope : target.scope = opportunity.scope
  targetReplicas : target.replicas = opportunity.replicas
  targetBefore : target.before = (trace.state index).db
  event : trace.event index = .promotion origin now refused
  stableViews : Nat → HeadView
  stableFacts : ReconciliationViewExecution.StableFacts trace services origin target
    accepted.final stableViews world (index + 1)

/-- Raw production inputs for one participant/origin after versions and
permissions have stabilized. Scheduler observations are shared by delivery
and Fetch, while every useful response remains tied to its real admission. -/
structure StableRun (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget)
    (timeline : Nat → SimulatedHost.State) (tailOffset : Nat)
    (trace : MptsyncStableTail.Trace) (valid : Head → Prop) where
  schedule : MptsyncScheduleExecution.StableScheduleInputs
  advertisement : MptsyncAdvertisementWindow.AcceptanceOpportunity
    schedule valid origin target.head
  publisher : TrieProgramProofs.RawSnapshot
  scope : Serve.Scope
  owner : Option String
  root : ByteArray
  requirements : FiniteRequirements publisher scope owner root
  retry : MptsyncRetryExecution.RetryExecution requirements
  retryStart : Nat
  retryAt : ∀ n, n ≤ retry.endAt → retry.state n = timeline (retryStart + n)
  responseTimeline : ScheduledFetchAdmission.ProductionScheduleTimeline retry.state
  responses : ScheduledFetchAdmission.ScheduledSufficientResponses
    (Origin.canonical origin) target.head.seq target.head.root requirements retry.state responseTimeline
  promote : ∀ {heads}
    (accepted : MptsyncAdvertisementWindow.AcceptedLatest valid origin target.head heads),
    PermittedComplete publisher scope owner root (replicaOfState (retry.state retry.endAt)) →
    Nonempty (PromotionWindow services origin target timeline tailOffset retryStart trace
      accepted publisher requirements retry)

private theorem scheduled_accepted
    (run : StableRun services origin target timeline tailOffset trace valid) :
    ∃ heads, Nonempty (MptsyncAdvertisementWindow.AcceptedLatest
      valid origin target.head heads) :=
  MptsyncAdvertisementWindow.scheduled_acceptance run.schedule run.advertisement

/-- One stable participant/origin run eventually reaches the scenario view
through actual scheduling, acceptance, authorized admissions, retry frames and
promotion, then remains there under the actual reconciliation tail. -/
theorem StableRun.converges
    (run : StableRun services origin target timeline tailOffset trace valid)
    (tailObserved : ∀ n, trace.state n = timeline (tailOffset + n))
    (targetOrigin : target.head.origin = origin) :
    EventuallyAlways fun n => CorrectView services origin target (timeline n).db := by
  obtain ⟨heads, ⟨accepted⟩⟩ := scheduled_accepted run
  have completedEnd := ScheduledFetchAdmission.completeAtStationaryBoundary
    run.responses run.retry.endAt run.retry.stationary
  -- `promote` is the explicit eventual healthy-host opportunity after the
  -- finite authorized deficit has reached zero.
  obtain ⟨window⟩ := run.promote accepted completedEnd
  have _chronology : accepted.observedAt < tailOffset + window.index := by
    calc
      accepted.observedAt < accepted.handledAt := accepted.afterDelivery
      _ ≤ run.retryStart := window.handledBeforeRetry
      _ ≤ run.retryStart + run.retry.endAt := Nat.le_add_right _ _
      _ = tailOffset + window.index := window.sameTime
  have _actualAcceptance : AcceptanceExecution accepted.keep
      (timeline accepted.handledAt) heads (timeline run.retryStart) := by
    rw [← window.acceptanceInitialAt, ← window.acceptedAt]
    exact accepted.accepted.actual.execution
  have promotionRequirements : FiniteRequirements run.publisher window.opportunity.scope
      (window.opportunity.authority.provenance.map Origin.canonical)
      window.opportunity.pending.head.root := by
    simpa only [window.requirementScope, window.requirementOwner,
      window.requirementRoot] using run.requirements
  have promotionComplete : PermittedComplete run.publisher window.opportunity.scope
      (window.opportunity.authority.provenance.map Origin.canonical)
      window.opportunity.pending.head.root
        (replicaOfState (run.retry.state run.retry.endAt)) := by
    simpa only [window.requirementScope, window.requirementOwner,
      window.requirementRoot] using completedEnd
  have promotionState : run.retry.state run.retry.endAt = trace.state window.index := by
    rw [run.retryAt run.retry.endAt (Nat.le_refl _), tailObserved, window.sameTime]
  have acceptedStart : accepted.acceptedState = run.retry.state 0 := by
    simpa only [Nat.add_zero, run.retryAt 0 (Nat.zero_le _)] using window.acceptedAt
  have acceptedSlots : StableSlots (run.retry.state 0) (Origin.canonical origin)
      accepted.final accepted.acceptedView := by
    rw [← acceptedStart]
    exact accepted.accepted.final_stable
  have retrySlots := run.retry.stableSlotsAtEnd acceptedSlots
  have laterSlots : StableSlots (trace.state window.index) (Origin.canonical origin)
      accepted.final accepted.acceptedView := by
    rw [← promotionState]
    exact retrySlots
  have carriedToStart : EvidenceIncluded
      (replicaOfState (run.retry.state run.retry.endAt))
      (replicaOfState (trace.state window.index)) := by
    rw [promotionState]
    exact EvidenceIncluded.refl _
  have carriedToPrepared : EvidenceIncluded
      (replicaOfState (run.retry.state run.retry.endAt))
      (replicaOfState window.opportunity.prepared) := by
    exact carriedToStart.trans (ProductionTimeline.promotion_prepare_includes
      (trace.state window.index) window.opportunity.opened window.opportunity.prepared
      window.opportunity.tx origin window.now _ window.opportunity.began
      window.opportunity.preparation)
  let ready := TrieCompleteConverse.ready_of_semantic_completion window.opportunity
    run.publisher promotionRequirements promotionComplete carriedToPrepared window.reads
  have reachedFinal : CorrectView services origin target ready.final.db := by
    exact StablePromotionTarget.actual_promotion_reaches_after_frames accepted.delivered
      accepted.accepted accepted.initialBound laterSlots ready
      window.world services window.host.closed window.host.faithful window.host.normalization
      window.host.relational window.initial.initial target targetOrigin rfl
      window.targetSnapshot window.targetScope window.targetReplicas window.targetBefore
  have actualStep : ReconciliationExecution.Step (.promotion origin window.now window.refused)
      (trace.state window.index) (trace.state (window.index + 1)) := by
    rw [← window.event]
    exact trace.step window.index
  have sameFinal : trace.state (window.index + 1) = ready.final :=
    StablePromotionTarget.actual_step_reaches_ready_final actualStep ready
  have reached : CorrectView services origin target (trace.state (window.index + 1)).db := by
    rw [sameFinal]
    exact reachedFinal
  obtain ⟨localStart, stable⟩ := ReconciliationViewExecution.stable_tail trace services
    origin target accepted.final window.stableViews window.world (window.index + 1)
      window.stableFacts reached
  refine ⟨tailOffset + localStart, fun now after => ?_⟩
  obtain ⟨delta, rfl⟩ := Nat.exists_eq_add_of_le after
  have held := stable (localStart + delta) (Nat.le_add_right localStart delta)
  change CorrectView services origin target (trace.state (localStart + delta)).db at held
  rw [tailObserved (localStart + delta)] at held
  simpa only [Nat.add_assoc] using held

/-- Actual reconciliation observations for one finite system coverage. Each
device has one public production timeline and one shared stable tail; every
origin-specific proof is anchored in those same observations. -/
structure SystemExecution {Device : Type}
    (services : MaterializedView.Services) (scenario : Scenario Device)
    (databases : Nat → Device → Database) (coverage : FiniteCoverage scenario)
    (valid : Origin.Parsed → Head → Prop) where
  timeline : Device → Nat → SimulatedHost.State
  tailTrace : Device → MptsyncStableTail.Trace
  tailOffset : Device → Nat
  tailObserved : ∀ device n,
    (tailTrace device).state n = timeline device (tailOffset device + n)
  run : ∀ pair : Device × Origin.Parsed, pair ∈ coverage.pairs →
    StableRun services pair.2 (scenario.target pair.1 pair.2)
      (timeline pair.1) (tailOffset pair.1) (tailTrace pair.1) (valid pair.2)
  observed : ∀ device n, (timeline device n).db = databases n device

end Synchronicity.MptsyncProductionConvergence
