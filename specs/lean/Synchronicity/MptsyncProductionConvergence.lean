import Synchronicity.MptsyncAdvertisementWindow
import Synchronicity.MptsyncDeviceExecution
import Synchronicity.MptsyncPromotionScheduling
import Synchronicity.ScheduledFetchAdmission
import Synchronicity.MptsyncRetryExecution
import Synchronicity.MptsyncPromotionHistory
import Synchronicity.ReconciliationViewExecution
import Synchronicity.ProductionTimeline
import Synchronicity.MptsyncScopeChangeCarry

/-! Composition of the actual stable-window executions used by M1.

The liveness boundary is split: semantic completion first yields a factual
maintenance interval/pass dispatch, then an independent healthy-host seam
supplies primitive phases for that exact invocation. It stores no Fetch or
promotion result, `Ready` witness, or correct view.
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
    (state : SimulatedHost.State) (world : TrieDiffCoverage.World)
    (cacheAtCall : MptsyncRefusalCache.Cache) : Prop where
  | atPromotion
      (evidence : MptsyncPromotionHistory.InitialViewEvidence services origin state world
        cacheAtCall) :
      PromotionInitialSource services origin accepted state world cacheAtCall

  | afterHistory
      (historyView : MptsyncPromotionHistory.EstablishedView services origin
        previousState previousTarget)
      (intervening : MptsyncViewCarry.StablePrefix services origin previousTarget
        previousLatest carryWorld previousState accepted.initialState)
      (metadata : PromotionContinuationBaseline.MetadataContracts
        state.db origin previousTarget world services) :
      PromotionInitialSource services origin accepted state world cacheAtCall

  | afterScopeChange
      (reset : MptsyncRefusalCache.ScopeResetObservation spaces changedAt before
        accepted.initialState report cacheBefore cacheReset)
      (cacheCarry : MptsyncRefusalCache.OriginProjectionCarry origin cacheReset cacheAtCall)
      (quiet : before.faults = [])
      (reported : decision ∈ report.demotions)
      (originAligned : decision.complete.origin = Origin.canonical origin)
      (metadata : ScopeChangePromotionBaseline.MetadataContracts
        state.db origin world services) :
      PromotionInitialSource services origin accepted state world cacheAtCall

private theorem installed_of_observed
    (represented : HeadView.Represents db view)
    (sameOrigin : head.origin = origin)
    (observed : view (Origin.canonical origin) .complete = some ⟨head.seq, head.root⟩) :
    AtomicFileView.Installed db head := by
  have atHead : view (Origin.canonical head.origin) .complete =
      some ⟨head.seq, head.root⟩ := by simpa only [sameOrigin] using observed
  constructor
  · obtain ⟨row, selected, _⟩ := HeadView.existing represented atHead
    exact ⟨row, selected.1, by simpa [HeadView.Selected, HeadView.slotName,
      ReconciliationSlots.names] using selected.2⟩
  · intro row member named
    have selected : HeadView.Selected db (Origin.canonical head.origin) .complete row :=
      ⟨member, by simpa [HeadView.Selected, HeadView.slotName,
        ReconciliationSlots.names] using named⟩
    have here := represented (Origin.canonical head.origin) .complete
    rw [atHead] at here
    exact here.2 row selected

private theorem wait_preserves_correct
    (frame : MptsyncPromotionScheduling.StableWaitFrame states
      (Origin.canonical origin) start stop beforeView afterView)
    (correct : CorrectView services origin target (states start).db) :
    CorrectView services origin target (states stop).db := by
  have beforeComplete := ReconciliationViewExecution.installed_view
    frame.beforeRepresents correct.2.1
  have afterComplete : afterView (Origin.canonical origin) .complete =
      some ⟨target.head.seq, target.head.root⟩ := by
    rw [frame.slots .complete]
    simpa only [correct.1] using beforeComplete
  have installed := installed_of_observed frame.afterRepresents correct.1 afterComplete
  exact MptsyncStableTail.refines_preserves
    (Or.inr (Or.inr (Or.inl ⟨frame.payload, installed⟩))) correct

theorem PromotionInitialSource.initial
    (source : PromotionInitialSource services origin accepted state world cacheAtCall)
    (retry : MptsyncRetryExecution.RetryExecution requirements)
    (acceptedStart : accepted.acceptedState = retry.state 0)
    (states : Nat → SimulatedHost.State) (boundary stop : Nat)
    (retryAtBoundary : retry.state retry.endAt = states boundary)
    (stateAtStop : state = states stop)
    (wait : MptsyncPromotionScheduling.StableWaitFrame states (Origin.canonical origin)
      boundary stop accepted.acceptedView afterView)
    (laterSlots : StableSlots state (Origin.canonical origin)
      accepted.final afterView) :
    PromotionInitialView.Initial state.db origin world services := by
  cases source with
  | atPromotion evidence => exact evidence.initial
  | afterHistory historyView intervening metadata =>
      have beforeAcceptance := intervening.preserves historyView.correct
      have atRetryEnd := MptsyncViewCarry.correct_after_acceptance_and_retry
        beforeAcceptance accepted.accepted retry acceptedStart rfl
      rw [retryAtBoundary] at atRetryEnd
      have atStop := wait_preserves_correct wait atRetryEnd
      rw [← stateAtStop] at atStop
      exact PromotionContinuationBaseline.initial_of_correct atStop metadata
  | afterScopeChange reset cacheCarry quiet reported originAligned metadata =>
      obtain ⟨_, raw⟩ := ScopeChangeRefinement.successful_change_raw
        reset.durable quiet reported
      obtain ⟨initialCompleteAbsent, initialEntriesAbsent⟩ :=
        ScopeChangePromotionBaseline.invalidated_absence raw originAligned
      have initialCompleteNone : accepted.initialView (Origin.canonical origin) .complete = none := by
        cases value : accepted.initialView (Origin.canonical origin) .complete with
        | none => rfl
        | some version =>
            obtain ⟨row, selected, _⟩ := HeadView.existing
              accepted.initialSlots.represents value
            exact False.elim (initialCompleteAbsent ⟨row, selected⟩)
      have acceptedCompleteNone : accepted.acceptedView
          (Origin.canonical origin) .complete = none := by
        rw [accepted.accepted.complete_preserved]
        exact initialCompleteNone
      have completeAbsent :
          ¬ ∃ row, HeadView.Selected state.db (Origin.canonical origin) .complete row := by
        rintro ⟨row, selected⟩
        exact HeadView.absent laterSlots.represents
          (by rw [wait.slots .complete]; exact acceptedCompleteNone) selected
      have sameEntries : rows state.db "entries" = rows accepted.initialState.db "entries" := by
        calc
          rows state.db "entries" = rows (states stop).db "entries" := by rw [stateAtStop]
          _ = rows (states boundary).db "entries" := wait.payload.1
          _ = rows (retry.state retry.endAt).db "entries" := by rw [retryAtBoundary]
          _ = rows (retry.state 0).db "entries" := retry.entriesAtEnd
          _ = rows accepted.acceptedState.db "entries" := by rw [acceptedStart]
          _ = rows accepted.initialState.db "entries" :=
            ReconciliationPayloadFrame.acceptance_fold_entries accepted.accepted.actual
      have entriesAbsent :
          (rows state.db "entries").any
            (fun row => equals row [("origin_id", .text (Origin.canonical origin))]) = false := by
        rw [sameEntries]
        exact initialEntriesAbsent
      exact PromotionBaseline.initial_origin
        (ScopeChangePromotionBaseline.clean_origin_baseline_of_absence
          completeAbsent entriesAbsent metadata)

/-- The actual promotion observation following one completed retry trace. -/
structure PromotionWindow (services : MaterializedView.Services)
    (origin : Origin.Parsed)
    {history : StableAdvertisementProgress.StableAuthorizedHistory origin}
    (target : ViewTarget)
    (timeline : Nat → SimulatedHost.State)
    (registry : MptsyncDeviceExecution.Registry timeline)
    (tailOffset retryStart : Nat)
    (trace : MptsyncStableTail.Trace)
    (schedule : MptsyncScheduleExecution.StableScheduleInputs)
    (advertisementTimeline : MptsyncAdvertisementWindow.AdvertisementTimeline schedule timeline)
    (occurrence : MptsyncAdvertisementWindow.AdvertisementOccurrence schedule)
    (accepted : MptsyncAdvertisementWindow.AcceptedLatestOnTimeline schedule timeline
      advertisementTimeline origin history target.head occurrence)
    (publisher : TrieProgramProofs.RawSnapshot)
    (requirements : FiniteRequirements publisher scope owner root)
    (retry : MptsyncRetryExecution.RetryExecution requirements)
    (maintenance : MptsyncPromotionScheduling.MaintenanceTimeline timeline)
    (scheduled : MptsyncPromotionScheduling.DispatchAfter timeline registry maintenance origin
      (retryStart + retry.endAt) accepted.accepted.acceptedView) where
  index : Nat
  cacheAtCall : MptsyncRefusalCache.Cache
  refusalProjection : MptsyncRefusalCache.CommandProjection .promote cacheAtCall origin
    scheduled.dispatch.refused
  opportunity : TrieCompleteConverse.PromotionOpportunity origin scheduled.dispatch.now
    scheduled.dispatch.refused (timeline scheduled.index)
  reads : TrieCompleteConverse.PromotionReadOpportunity publisher opportunity.tx
    ⟨opportunity.scope, opportunity.authority.provenance.map Origin.canonical⟩
    opportunity.pending.head.root
  requirementScope : opportunity.scope = scope
  requirementOwner : opportunity.authority.provenance.map Origin.canonical = owner
  requirementRoot : opportunity.pending.head.root = root
  sameTime : scheduled.index = tailOffset + index
  handledBeforeRetry : accepted.accepted.handledAt ≤ retryStart
  acceptedAt : accepted.accepted.acceptedState = timeline retryStart
  prePromotion : MptsyncDeviceExecution.PrePromotionSegment registry origin schedule
    advertisementTimeline history target.head occurrence accepted retryStart retry
  world : TrieDiffCoverage.World
  host : MptsyncPromotionHistory.HostContracts (timeline scheduled.index) world services
  initial : PromotionInitialSource services origin accepted.accepted (timeline scheduled.index) world
    cacheAtCall
  targetSnapshot : target.snapshot = world.snapshot
  targetScope : target.scope = opportunity.scope
  targetReplicas : target.replicas = opportunity.replicas
  targetBefore : target.before = (timeline scheduled.index).db
  stableViews : Nat → HeadView
  stableFacts : ReconciliationViewExecution.StableFacts trace services origin target
    accepted.accepted.final stableViews world (index + 1)

/-- The healthy primitive phases read the current pending row of the exact
maintenance invocation; the candidate is not independently selected. -/
theorem PromotionWindow.dispatchCandidate
    (window : PromotionWindow services origin target timeline registry tailOffset retryStart trace
      schedule advertisementTimeline occurrence accepted publisher requirements retry maintenance
        scheduled) :
    scheduled.dispatch.version =
      (⟨window.opportunity.pending.head.seq, window.opportunity.pending.head.root⟩ :
        HeadVersion) := by
  have stored := scheduled.dispatch.currentBacked (Origin.canonical origin) .pending
    scheduled.dispatch.version scheduled.dispatch.pending
  have opened : window.opportunity.opened.pending =
      some (window.opportunity.tx, (timeline scheduled.index).db) :=
    ReconciliationFloor.begin_pending (timeline scheduled.index) window.opportunity.opened
      window.opportunity.tx
      (OperationExecution.raise_success (fun _ _ => rfl) Promote.Error.host Storage.begin
        (timeline scheduled.index) window.opportunity.opened window.opportunity.tx
          window.opportunity.began)
  obtain ⟨candidate, selected, sameSeq, sameRoot⟩ :=
    PromotionCommand.prepare_pending_floor window.opportunity.tx origin scheduled.dispatch.now
      window.opportunity.opened window.opportunity.prepared (timeline scheduled.index).db opened
      scheduled.dispatch.version.seq.toInt64 scheduled.dispatch.version.root stored
      window.opportunity.scope window.opportunity.authority (some window.opportunity.pending)
      window.opportunity.old window.opportunity.preparation
  have sameCandidate : candidate = window.opportunity.pending := Option.some.inj selected.symm
  cases sameCandidate
  have roundtrip (seq : UInt64) : seq.toInt64.toUInt64 = seq := by cases seq; rfl
  rw [roundtrip] at sameSeq
  cases versionEq : scheduled.dispatch.version with
  | mk seq root =>
      have seqSame : seq = window.opportunity.pending.head.seq := by
        calc
          seq = ({ seq := seq, root := root } : HeadVersion).seq := rfl
          _ = scheduled.dispatch.version.seq := congrArg HeadVersion.seq versionEq.symm
          _ = window.opportunity.pending.head.seq := sameSeq.symm
      have rootSame : root = window.opportunity.pending.head.root := by
        calc
          root = ({ seq := seq, root := root } : HeadVersion).root := rfl
          _ = scheduled.dispatch.version.root := congrArg HeadVersion.root versionEq.symm
          _ = window.opportunity.pending.head.root := sameRoot.symm
      cases seqSame
      cases rootSame
      rfl

/-- Raw production inputs for one participant/origin after versions and
permissions have stabilized. Scheduler observations are shared by delivery
and Fetch, while every useful response remains tied to its real admission. -/
structure StableRun (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget)
    (timeline : Nat → SimulatedHost.State) (tailOffset : Nat)
    (trace : MptsyncStableTail.Trace)
    (history : StableAdvertisementProgress.StableAuthorizedHistory origin)
    (registry : MptsyncDeviceExecution.Registry timeline) where
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
  maintenance : MptsyncPromotionScheduling.MaintenanceTimeline timeline
  dispatch : ∀ {occurrence}
    (accepted : MptsyncAdvertisementWindow.AcceptedLatestOnTimeline schedule timeline
      advertisementTimeline origin history target.head occurrence),
    PermittedComplete publisher scope owner root (replicaOfState (retry.state retry.endAt)) →
    Nonempty (MptsyncPromotionScheduling.DispatchAfter timeline registry maintenance origin
      (retryStart + retry.endAt) accepted.accepted.acceptedView)
  promote : ∀ {occurrence}
    (accepted : MptsyncAdvertisementWindow.AcceptedLatestOnTimeline schedule timeline
      advertisementTimeline origin history target.head occurrence),
    ∀ scheduled : MptsyncPromotionScheduling.DispatchAfter timeline registry maintenance origin
      (retryStart + retry.endAt) accepted.accepted.acceptedView,
    Nonempty (PromotionWindow services origin target timeline registry tailOffset retryStart trace
      schedule advertisementTimeline occurrence accepted publisher requirements retry maintenance scheduled)

private theorem scheduled_accepted
    (run : StableRun services origin target timeline tailOffset trace history registry) :
    ∃ occurrence, Nonempty (MptsyncAdvertisementWindow.AcceptedLatestOnTimeline
      run.schedule timeline run.advertisementTimeline origin history target.head occurrence) :=
  MptsyncAdvertisementWindow.scheduled_acceptance run.schedule run.advertisementTimeline
    run.advertisement

/-- One stable participant/origin run eventually reaches the scenario view
through actual scheduling, acceptance, authorized admissions, retry frames and
promotion, then remains there under the actual reconciliation tail. -/
theorem StableRun.converges
    (run : StableRun services origin target timeline tailOffset trace history registry)
    (tailObserved : ∀ n, trace.state n = timeline (tailOffset + n))
    (targetOrigin : target.head.origin = origin) :
    EventuallyAlways fun n => CorrectView services origin target (timeline n).db := by
  obtain ⟨occurrence, ⟨accepted⟩⟩ := scheduled_accepted run
  have completedEnd := ScheduledFetchAdmission.completeAtEnd run.responses
  -- Completion first reaches an actual maintenance interval/pass invocation;
  -- only then does the independent healthy-host seam supply primitive phases
  -- for that exact dispatch.
  obtain ⟨scheduled⟩ := run.dispatch accepted completedEnd
  obtain ⟨window⟩ := run.promote accepted scheduled
  have _chronology : accepted.accepted.observedAt < scheduled.index := by
    calc
      accepted.accepted.observedAt < accepted.accepted.handledAt :=
        accepted.accepted.afterDelivery
      _ ≤ run.retryStart := window.handledBeforeRetry
      _ ≤ run.retryStart + run.retry.endAt := Nat.le_add_right _ _
      _ ≤ scheduled.index := scheduled.wait.forward
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
  have stateAtBoundary : run.retry.state run.retry.endAt =
      timeline (run.retryStart + run.retry.endAt) :=
    run.retryAt run.retry.endAt (Nat.le_refl _)
  have acceptedStart : accepted.accepted.acceptedState = run.retry.state 0 := by
    simpa only [Nat.add_zero, run.retryAt 0 (Nat.zero_le _)] using window.acceptedAt
  have acceptedSlots : StableSlots (run.retry.state 0) (Origin.canonical origin)
      accepted.accepted.final accepted.accepted.acceptedView := by
    rw [← acceptedStart]
    exact accepted.accepted.accepted.final_stable
  have retrySlots := run.retry.stableSlotsAtEnd acceptedSlots
  have boundarySlots : StableSlots (timeline (run.retryStart + run.retry.endAt))
      (Origin.canonical origin) accepted.accepted.final accepted.accepted.acceptedView := by
    rw [← stateAtBoundary]
    exact retrySlots
  have laterSlots : StableSlots (timeline scheduled.index) (Origin.canonical origin)
      accepted.accepted.final scheduled.dispatch.currentView :=
    scheduled.wait.stableSlots boundarySlots
  have carriedToStart : EvidenceIncluded
      (replicaOfState (run.retry.state run.retry.endAt))
      (replicaOfState (timeline scheduled.index)) := by
    have toBoundary : EvidenceIncluded
        (replicaOfState (run.retry.state run.retry.endAt))
        (replicaOfState (timeline (run.retryStart + run.retry.endAt))) := by
      rw [← stateAtBoundary]
      exact EvidenceIncluded.refl _
    exact toBoundary.trans scheduled.wait.evidenceIncluded
  have carriedToPrepared : EvidenceIncluded
      (replicaOfState (run.retry.state run.retry.endAt))
      (replicaOfState window.opportunity.prepared) := by
    exact carriedToStart.trans (ProductionTimeline.promotion_prepare_includes
      (timeline scheduled.index) window.opportunity.opened window.opportunity.prepared
      window.opportunity.tx origin scheduled.dispatch.now
      (window.opportunity.scope, window.opportunity.authority,
        some window.opportunity.pending, window.opportunity.old) window.opportunity.began
      window.opportunity.preparation)
  let ready := TrieCompleteConverse.ready_of_semantic_completion window.opportunity
    run.publisher promotionRequirements promotionComplete carriedToPrepared window.reads
  have reachedFinal : CorrectView services origin target ready.final.db := by
    have initialViewReady := window.initial.initial run.retry acceptedStart
      timeline (run.retryStart + run.retry.endAt) scheduled.index stateAtBoundary rfl
        scheduled.wait laterSlots
    exact StablePromotionTarget.actual_promotion_reaches_after_frames accepted.accepted.delivered
      accepted.accepted.accepted accepted.accepted.initialBound laterSlots ready
      window.world services window.host.closed window.host.faithful window.host.normalization
      window.host.relational initialViewReady target targetOrigin rfl
      window.targetSnapshot window.targetScope window.targetReplicas window.targetBefore
  have sameFinal : timeline (scheduled.index + 1) = ready.final :=
    StablePromotionTarget.actual_step_reaches_ready_final scheduled.dispatch.invoked ready
  have reached : CorrectView services origin target (trace.state (window.index + 1)).db := by
    rw [tailObserved]
    have nextTime : tailOffset + (window.index + 1) = scheduled.index + 1 := by
      have sameTime := window.sameTime
      omega
    rw [nextTime, sameFinal]
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
  registry : (device : Device) → MptsyncDeviceExecution.Registry (timeline device)
  tailTrace : Device → MptsyncStableTail.Trace
  tailOffset : Device → Nat
  tailObserved : ∀ device n,
    (tailTrace device).state n = timeline device (tailOffset device + n)
  run : ∀ pair : Device × Origin.Parsed, pair ∈ coverage.pairs →
    StableRun services pair.2 (scenario.target pair.1 pair.2)
      (timeline pair.1) (tailOffset pair.1) (tailTrace pair.1) (history pair.2)
        (registry pair.1)
  stableVersions : MptsyncDeviceExecution.StableScenarioHistory scenario history
  observed : ∀ device n, (timeline device n).db = databases n device

end Synchronicity.MptsyncProductionConvergence
