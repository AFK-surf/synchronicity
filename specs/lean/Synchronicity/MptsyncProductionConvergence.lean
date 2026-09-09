import Synchronicity.MptsyncAdvertisementWindow
import Synchronicity.ScheduledFetchAdmission
import Synchronicity.MptsyncRetryExecution
import Synchronicity.MptsyncPromotionHistory
import Synchronicity.ReconciliationViewExecution
import Synchronicity.ProductionTimeline
import Synchronicity.MptsyncScopeChangeCarry

/-! Composition of the actual stable-window executions used by M1.

The external liveness seam says that after semantic completion a healthy host
eventually supplies a bounded primitive promotion opportunity.  It does not
store a Fetch success, a Complete result, a Ready witness, or a correct view.
-/
namespace Synchronicity.MptsyncProductionConvergence
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Replication
open SimulatedHost TrieFetchCompletion TrieFetchAdmissionProgress
open MptsyncConvergence AcceptanceProgress

/-- The old-view baseline for the final stable promotion. In the ordinary
case it is already established at promotion time. After a scope change, the
constructor instead records that earlier production command and independent
metadata; the required baseline is transported through acceptance and retry. -/
inductive PromotionInitialSource (services : MaterializedView.Services)
    (origin : Origin.Parsed)
    {history : StableAdvertisementProgress.StableAuthorizedHistory origin}
    (accepted : MptsyncAdvertisementWindow.AcceptedLatest origin history latest heads)
    (state : SimulatedHost.State) (world : TrieDiffCoverage.World) : Prop where
  | atPromotion
      (evidence : MptsyncPromotionHistory.InitialViewEvidence services origin state world) :
      PromotionInitialSource services origin accepted state world
  | afterHistory
      (historyView : MptsyncPromotionHistory.EstablishedView services origin
        accepted.initialState previousTarget)
      (metadata : PromotionContinuationBaseline.MetadataContracts
        state.db origin previousTarget world services) :
      PromotionInitialSource services origin accepted state world
  | afterScopeChange
      (production : ScopeChangeRefinement.Successful spaces changedAt before
        accepted.initialState report)
      (quiet : before.faults = [])
      (reported : decision ∈ report.demotions)
      (originAligned : decision.complete.origin = Origin.canonical origin)
      (metadata : ScopeChangePromotionBaseline.MetadataContracts
        state.db origin world services) :
      PromotionInitialSource services origin accepted state world

theorem PromotionInitialSource.initial
    (source : PromotionInitialSource services origin accepted state world)
    (retry : MptsyncRetryExecution.RetryExecution requirements)
    (acceptedStart : accepted.acceptedState = retry.state 0)
    (promotionState : retry.state retry.endAt = state)
    (laterSlots : StableSlots state (Origin.canonical origin)
      accepted.final accepted.acceptedView) :
    PromotionInitialView.Initial state.db origin world services := by
  cases source with
  | atPromotion evidence => exact evidence.initial
  | afterHistory historyView metadata =>
      have carried := MptsyncViewCarry.correct_after_acceptance_and_retry
        historyView.correct accepted.accepted retry acceptedStart promotionState
      exact PromotionContinuationBaseline.initial_of_correct carried metadata
  | afterScopeChange production quiet reported originAligned metadata =>
      exact MptsyncScopeChangeCarry.initial_after_acceptance_and_retry
        production quiet reported originAligned accepted.accepted retry acceptedStart
          promotionState laterSlots metadata

/-- The actual promotion observation following one completed retry trace. -/
structure PromotionWindow (services : MaterializedView.Services)
    (origin : Origin.Parsed)
    {history : StableAdvertisementProgress.StableAuthorizedHistory origin}
    (target : ViewTarget)
    (timeline : Nat → SimulatedHost.State) (tailOffset retryStart : Nat)
    (trace : MptsyncStableTail.Trace)
    (schedule : MptsyncScheduleExecution.StableScheduleInputs)
    (advertisementTimeline : MptsyncAdvertisementWindow.AdvertisementTimeline schedule timeline)
    (occurrence : MptsyncAdvertisementWindow.AdvertisementOccurrence schedule)
    (accepted : MptsyncAdvertisementWindow.AcceptedLatestOnTimeline schedule timeline
      advertisementTimeline origin history target.head occurrence)
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
  handledBeforeRetry : accepted.accepted.handledAt ≤ retryStart
  acceptedAt : accepted.accepted.acceptedState = timeline retryStart
  world : TrieDiffCoverage.World
  host : MptsyncPromotionHistory.HostContracts (trace.state index) world services
  initial : PromotionInitialSource services origin accepted.accepted (trace.state index) world
  targetSnapshot : target.snapshot = world.snapshot
  targetScope : target.scope = opportunity.scope
  targetReplicas : target.replicas = opportunity.replicas
  targetBefore : target.before = (trace.state index).db
  event : trace.event index = .promotion origin now refused
  stableViews : Nat → HeadView
  stableFacts : ReconciliationViewExecution.StableFacts trace services origin target
    accepted.accepted.final stableViews world (index + 1)

/-- Raw production inputs for one participant/origin after versions and
permissions have stabilized. Scheduler observations are shared by delivery
and Fetch, while every useful response remains tied to its real admission. -/
structure StableRun (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget)
    (timeline : Nat → SimulatedHost.State) (tailOffset : Nat)
    (trace : MptsyncStableTail.Trace)
    (history : StableAdvertisementProgress.StableAuthorizedHistory origin) where
  schedule : MptsyncScheduleExecution.StableScheduleInputs
  advertisementTimeline : MptsyncAdvertisementWindow.AdvertisementTimeline schedule timeline
  advertisement : MptsyncAdvertisementWindow.AcceptanceOpportunity
    schedule timeline advertisementTimeline origin history target.head
  publisher : TrieProgramProofs.RawSnapshot
  scope : Serve.Scope
  owner : Option String
  root : ByteArray
  requirements : FiniteRequirements publisher scope owner root
  retry : MptsyncRetryExecution.RetryExecution requirements
  retryStart : Nat
  retryAt : ∀ n, n ≤ retry.endAt → retry.state n = timeline (retryStart + n)
  responseTimeline : ScheduledFetchAdmission.ProductionScheduleTimeline retry.state
  responses : ScheduledFetchAdmission.BoundedScheduledResponses
    (Origin.canonical origin) target.head.seq target.head.root requirements retry responseTimeline
  promote : ∀ {occurrence}
    (accepted : MptsyncAdvertisementWindow.AcceptedLatestOnTimeline schedule timeline
      advertisementTimeline origin history target.head occurrence),
    PermittedComplete publisher scope owner root (replicaOfState (retry.state retry.endAt)) →
    Nonempty (PromotionWindow services origin target timeline tailOffset retryStart trace
      schedule advertisementTimeline occurrence accepted publisher requirements retry)

private theorem scheduled_accepted
    (run : StableRun services origin target timeline tailOffset trace history) :
    ∃ occurrence, Nonempty (MptsyncAdvertisementWindow.AcceptedLatestOnTimeline
      run.schedule timeline run.advertisementTimeline origin history target.head occurrence) :=
  MptsyncAdvertisementWindow.scheduled_acceptance run.schedule run.advertisementTimeline
    run.advertisement

/-- One stable participant/origin run eventually reaches the scenario view
through actual scheduling, acceptance, authorized admissions, retry frames and
promotion, then remains there under the actual reconciliation tail. -/
theorem StableRun.converges
    (run : StableRun services origin target timeline tailOffset trace history)
    (tailObserved : ∀ n, trace.state n = timeline (tailOffset + n))
    (targetOrigin : target.head.origin = origin) :
    EventuallyAlways fun n => CorrectView services origin target (timeline n).db := by
  obtain ⟨occurrence, ⟨accepted⟩⟩ := scheduled_accepted run
  have completedEnd := ScheduledFetchAdmission.completeAtEnd run.responses
  -- `promote` is the explicit eventual healthy-host opportunity after the
  -- finite authorized deficit has reached zero.
  obtain ⟨window⟩ := run.promote accepted completedEnd
  have _chronology : accepted.accepted.observedAt < tailOffset + window.index := by
    calc
      accepted.accepted.observedAt < accepted.accepted.handledAt :=
        accepted.accepted.afterDelivery
      _ ≤ run.retryStart := window.handledBeforeRetry
      _ ≤ run.retryStart + run.retry.endAt := Nat.le_add_right _ _
      _ = tailOffset + window.index := window.sameTime
  have _actualAcceptance : AcceptanceExecution accepted.accepted.keep
      (timeline accepted.accepted.handledAt)
      (OriginScheduleExecution.receivedHeads occurrence.attempt)
      (timeline run.retryStart) := by
    rw [← accepted.initialAt, ← window.acceptedAt]
    exact accepted.accepted.accepted.actual.execution
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
  have acceptedStart : accepted.accepted.acceptedState = run.retry.state 0 := by
    simpa only [Nat.add_zero, run.retryAt 0 (Nat.zero_le _)] using window.acceptedAt
  have acceptedSlots : StableSlots (run.retry.state 0) (Origin.canonical origin)
      accepted.accepted.final accepted.accepted.acceptedView := by
    rw [← acceptedStart]
    exact accepted.accepted.accepted.final_stable
  have retrySlots := run.retry.stableSlotsAtEnd acceptedSlots
  have laterSlots : StableSlots (trace.state window.index) (Origin.canonical origin)
      accepted.accepted.final accepted.accepted.acceptedView := by
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
    have initialViewReady := window.initial.initial run.retry acceptedStart
      promotionState laterSlots
    exact StablePromotionTarget.actual_promotion_reaches_after_frames accepted.accepted.delivered
      accepted.accepted.accepted accepted.accepted.initialBound laterSlots ready
      window.world services window.host.closed window.host.faithful window.host.normalization
      window.host.relational initialViewReady target targetOrigin rfl
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
    origin target accepted.accepted.final window.stableViews window.world (window.index + 1)
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
    (history : (origin : Origin.Parsed) →
      StableAdvertisementProgress.StableAuthorizedHistory origin) where
  timeline : Device → Nat → SimulatedHost.State
  tailTrace : Device → MptsyncStableTail.Trace
  tailOffset : Device → Nat
  tailObserved : ∀ device n,
    (tailTrace device).state n = timeline device (tailOffset device + n)
  run : ∀ pair : Device × Origin.Parsed, pair ∈ coverage.pairs →
    StableRun services pair.2 (scenario.target pair.1 pair.2)
      (timeline pair.1) (tailOffset pair.1) (tailTrace pair.1) (history pair.2)
  observed : ∀ device n, (timeline device n).db = databases n device

end Synchronicity.MptsyncProductionConvergence
