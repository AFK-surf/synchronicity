import Synchronicity.MptsyncAdvertisementWindow
import Synchronicity.ScheduledFetchAdmission
import Synchronicity.MptsyncRetryExecution
import Synchronicity.MptsyncPromotionHistory
import Synchronicity.ReconciliationViewExecution

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
    (trace : MptsyncStableTail.Trace)
    (accepted : MptsyncAdvertisementWindow.AcceptedLatest valid origin target.head heads)
    (publisher : TrieProgramProofs.RawSnapshot)
    (requirements : FiniteRequirements publisher scope owner root)
    (retry : MptsyncRetryExecution.RetryExecution requirements)
    (finish : Nat) where
  index : Nat
  now : Int64
  refused : List (UInt64 × ByteArray × ByteArray)
  opportunity : TrieCompleteConverse.ReadyOpportunity origin now refused (trace.state index)
  requirementScope : opportunity.scope = scope
  requirementOwner : opportunity.authority.provenance.map Origin.canonical = owner
  requirementRoot : opportunity.pending.head.root = root
  carried : EvidenceIncluded (replicaOfState (retry.state finish))
    (replicaOfState opportunity.prepared)
  laterView : HeadView
  laterSlots : StableSlots (trace.state index) (Origin.canonical origin)
    accepted.final laterView
  noComplete : laterView (Origin.canonical origin) .complete = none
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
  pendingItem : OriginSchedule.Item
  pendingMember : pendingItem ∈ schedule.pendingItems
  pendingOrigin : (schedule.pendingTarget pendingItem).origin = Origin.canonical origin
  pendingSequence : (schedule.pendingTarget pendingItem).pointer.seq = target.head.seq
  pendingRoot : (schedule.pendingTarget pendingItem).pointer.root = target.head.root
  responses : ScheduledFetchAdmission.ScheduledSufficientResponses
    schedule.contacts schedule.peer schedule.pending schedule.pendingLink
    schedule.pendingTarget pendingItem requirements retry.state
  promote : ∀ {heads}
    (accepted : MptsyncAdvertisementWindow.AcceptedLatest valid origin target.head heads)
    (finish : Nat),
    PermittedComplete publisher scope owner root (replicaOfState (retry.state finish)) →
    Nonempty (PromotionWindow services origin target trace
      accepted publisher requirements retry finish)

private theorem scheduled_accepted
    (run : StableRun services origin target trace valid) :
    ∃ heads, Nonempty (MptsyncAdvertisementWindow.AcceptedLatest
      valid origin target.head heads) :=
  MptsyncAdvertisementWindow.scheduled_acceptance run.schedule run.advertisement

/-- One stable participant/origin run eventually reaches the scenario view
through actual scheduling, acceptance, authorized admissions, retry frames and
promotion, then remains there under the actual reconciliation tail. -/
theorem StableRun.converges
    (run : StableRun services origin target trace valid)
    (targetOrigin : target.head.origin = origin) :
    EventuallyAlways fun n => CorrectView services origin target (trace.state n).db := by
  obtain ⟨heads, ⟨accepted⟩⟩ := scheduled_accepted run
  have sufficient := ScheduledFetchAdmission.sufficientResponses run.responses
  obtain ⟨finish, after, complete⟩ :=
    AuthorizedFetchProgress.sufficient_responses_converge run.requirements run.retry.state
      run.retry.persistentEvidence sufficient 0
  have completed := complete finish (Nat.le_refl _)
  -- `promote` is the explicit eventual healthy-host opportunity after the
  -- finite authorized deficit has reached zero.
  obtain ⟨window⟩ := run.promote accepted finish completed
  have promotionRequirements : FiniteRequirements run.publisher window.opportunity.scope
      (window.opportunity.authority.provenance.map Origin.canonical)
      window.opportunity.pending.head.root := by
    simpa only [window.requirementScope, window.requirementOwner,
      window.requirementRoot] using run.requirements
  have promotionComplete : PermittedComplete run.publisher window.opportunity.scope
      (window.opportunity.authority.provenance.map Origin.canonical)
      window.opportunity.pending.head.root (replicaOfState (run.retry.state finish)) := by
    simpa only [window.requirementScope, window.requirementOwner,
      window.requirementRoot] using completed
  let ready := TrieCompleteConverse.ready_of_semantic_completion window.opportunity
    run.publisher promotionRequirements promotionComplete window.carried
  have reachedFinal : CorrectView services origin target ready.final.db := by
    exact StablePromotionTarget.actual_promotion_reaches_after_frames accepted.delivered
      accepted.accepted accepted.initialBound window.laterSlots window.noComplete ready
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
  exact ReconciliationViewExecution.stable_tail trace services origin target accepted.final
    window.stableViews window.world (window.index + 1) window.stableFacts reached

/-- Actual per-origin reconciliation observations for one finite system
coverage. The public database sequence is shared by all origin-specific views
of a device; the event decomposition may differ only in which origin's
invariant is being proved. -/
structure SystemExecution {Device : Type}
    (services : MaterializedView.Services) (scenario : Scenario Device)
    (databases : Nat → Device → Database) (coverage : FiniteCoverage scenario)
    (valid : Origin.Parsed → Head → Prop) where
  localTrace : Device → Origin.Parsed → MptsyncStableTail.Trace
  run : ∀ pair : Device × Origin.Parsed, pair ∈ coverage.pairs →
    StableRun services pair.2 (scenario.target pair.1 pair.2)
      (localTrace pair.1 pair.2) (valid pair.2)
  observed : ∀ device origin n, ((localTrace device origin).state n).db = databases n device

end Synchronicity.MptsyncProductionConvergence
