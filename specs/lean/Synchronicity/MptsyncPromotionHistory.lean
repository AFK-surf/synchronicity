import Synchronicity.TrieCompleteConverse
import Synchronicity.StablePromotionTarget
import Synchronicity.PromotionBaseline
import Synchronicity.PromotionContinuationBaseline
import Synchronicity.ScopeChangePromotionBaseline
import Synchronicity.ScopeChangeRefinement
import Synchronicity.ScheduledFetchAdmission
import Synchronicity.ProductionTimeline
import Synchronicity.MptsyncViewCarry

/-! Actual finite promotion history before the stable convergence window.

The first view starts either from an origin-local clean database or from the
raw committed cleanup of a production scope change.  Every later view starts
from a correctness fact derived from the preceding actual promotion.  Thus M1
does not assume a correct old directory independently at every version.
-/
namespace Synchronicity.MptsyncPromotionHistory
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Replication
open SimulatedHost TrieCompleteConverse MptsyncConvergence
  TrieFetchCompletion TrieFetchAdmissionProgress

/-- Host and materializer facts independent of whether promotion succeeds. -/
structure HostContracts (state : State) (world : TrieDiffCoverage.World)
    (services : MaterializedView.Services) : Prop where
  closed : state.pending = none
  faithful : TrieDiffCoverage.Faithful world state
  normalization : state.isNfc = services.nfc
  relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
    state.byteRelations.contains relation = true

/-- A historical promotion is justified by the same finite production chain
as the final stable promotion: bounded scheduled admissions in one actual
retry prefix, followed by raw promotion reads and phases. It stores neither a
semantic completion result nor `Ready`. -/
structure ProductionPromotionOpportunity (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray))
    (state : SimulatedHost.State) where
  raw : PromotionOpportunity origin now refused state
  publisher : TrieProgramProofs.RawSnapshot
  requirements : FiniteRequirements publisher raw.scope
    (raw.authority.provenance.map Origin.canonical) raw.pending.head.root
  retry : MptsyncRetryExecution.RetryExecution requirements
  responseTimeline : ScheduledFetchAdmission.ProductionScheduleTimeline retry.state
  responses : ScheduledFetchAdmission.BoundedScheduledResponses
    (Origin.canonical origin) raw.pending.head.seq raw.pending.head.root
      requirements retry responseTimeline
  atPromotion : retry.state retry.endAt = state
  reads : PromotionReadOpportunity publisher raw.tx
    ⟨raw.scope, raw.authority.provenance.map Origin.canonical⟩ raw.pending.head.root

def ProductionPromotionOpportunity.ready
    (opportunity : ProductionPromotionOpportunity origin now refused state) :
    PromotionProgress.Ready origin now refused state := by
  have complete := ScheduledFetchAdmission.completeAtEnd opportunity.responses
  have carriedToStart : EvidenceIncluded
      (replicaOfState (opportunity.retry.state opportunity.retry.endAt))
      (replicaOfState state) := by
    rw [opportunity.atPromotion]
    exact EvidenceIncluded.refl _
  have carriedToPrepared := carriedToStart.trans
    (ProductionTimeline.promotion_prepare_includes state opportunity.raw.opened
      opportunity.raw.prepared opportunity.raw.tx origin now _ opportunity.raw.began
      opportunity.raw.preparation)
  exact ready_of_semantic_completion opportunity.raw opportunity.publisher
    opportunity.requirements complete carriedToPrepared opportunity.reads

/-- Factual identification of a public target with the candidate read by an
actual promotion opportunity. -/
def TargetAlignment (target : ViewTarget) (state : State)
    (world : TrieDiffCoverage.World)
    (opportunity : ProductionPromotionOpportunity origin now refused state) : Prop :=
  SameViewTarget target
    (StablePromotionTarget.targetFor state world opportunity.ready)

theorem correct_of_opportunity
    (opportunity : ProductionPromotionOpportunity origin now refused state)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (host : HostContracts state world services)
    (initial : PromotionInitialView.Initial state.db origin world services)
    (target : ViewTarget)
    (aligned : TargetAlignment target state world opportunity) :
    CorrectView services origin target opportunity.raw.final.db := by
  let ready := opportunity.ready
  obtain ⟨pendingOrigin, _, installed, files, current, forever⟩ :=
    PromotionProgress.promotes_ready_view ready world services host.closed host.faithful
      host.normalization host.relational initial
  let actual := StablePromotionTarget.targetFor state world ready
  have actualCorrect : CorrectView services origin actual ready.final.db := by
    refine ⟨pendingOrigin, installed, ?_, current, forever⟩
    change SnapshotViewProgress.ExactFiles services world.snapshot ready.pending.head.root
      (fun key => ready.scope.admitsKeyPath (Trie.keyNibbles key) = true)
      ready.final.db (Origin.canonical origin)
    exact files
  exact correctView_of_same_target aligned actualCorrect

/-- A finite chain of actual healthy production promotions.  Constructors
contain raw command opportunities and independent host facts, never
`CorrectView`, `PromotionProgress.Ready`, or a reported promotion result. -/
inductive EstablishedView (services : MaterializedView.Services)
    (origin : Origin.Parsed) : State → ViewTarget → Prop where
  | clean
      (baseline : PromotionBaseline.CleanOriginBaseline state.db origin world services)
      (opportunity : ProductionPromotionOpportunity origin now refused state)
      (host : HostContracts state world services)
      (aligned : TargetAlignment target state world opportunity) :
      EstablishedView services origin opportunity.raw.final target
  | changed
      (production : ScopeChangeRefinement.Successful spaces changedAt before state report)
      (quiet : before.faults = [])
      (reported : decision ∈ report.demotions)
      (originAligned : decision.complete.origin = Origin.canonical origin)
      (metadata : ScopeChangePromotionBaseline.MetadataContracts
        state.db origin world services)
      (opportunity : ProductionPromotionOpportunity origin now refused state)
      (host : HostContracts state world services)
      (aligned : TargetAlignment target state world opportunity) :
      EstablishedView services origin opportunity.raw.final target
  | continued
      (previous : EstablishedView services origin prior previousTarget)
      (intervening : MptsyncViewCarry.StablePrefix services origin previousTarget
        previousLatest carryWorld prior beforeAcceptance)
      (acceptance : AcceptanceProgress.ObservedAcceptanceFold
        (Origin.canonical origin) keep initial beforeAcceptance initialView initialSlots
          heads final accepted acceptedView)
      (opportunity : ProductionPromotionOpportunity origin now refused state)
      (acceptedStart : accepted = opportunity.retry.state 0)
      (promotionState : opportunity.retry.state opportunity.retry.endAt = state)
      (metadata : PromotionContinuationBaseline.MetadataContracts
        state.db origin previousTarget world services)
      (host : HostContracts state world services)
      (aligned : TargetAlignment target state world opportunity) :
      EstablishedView services origin opportunity.raw.final target

/-- Every historical chain ends in the correct view and therefore supplies
the old-view invariant needed by a subsequent version. -/
theorem EstablishedView.correct
    (history : EstablishedView services origin state target) :
    CorrectView services origin target state.db := by
  induction history with
  | clean baseline opportunity host aligned =>
      exact correct_of_opportunity opportunity _ _ host
        (PromotionBaseline.initial_origin baseline) _ aligned
  | changed production quiet reported originAligned metadata opportunity host aligned =>
      obtain ⟨source, raw⟩ :=
        ScopeChangeRefinement.successful_change_raw production quiet reported
      have baseline := ScopeChangePromotionBaseline.clean_origin_baseline raw
        originAligned metadata
      exact correct_of_opportunity opportunity _ _ host
        (PromotionBaseline.initial_origin baseline) _ aligned
  | continued previous intervening acceptance opportunity acceptedStart promotionState metadata host aligned ih =>
      have beforeAcceptance := intervening.preserves ih
      have carried := MptsyncViewCarry.correct_after_acceptance_and_retry beforeAcceptance
        acceptance opportunity.retry acceptedStart promotionState
      exact correct_of_opportunity opportunity _ _ host
        (PromotionContinuationBaseline.initial_of_correct carried metadata) _ aligned

/-- A derived historical view supplies the next production promotion's
initial-view premise through raw metadata stability. -/
theorem EstablishedView.nextInitial
    (history : EstablishedView services origin state previous)
    (metadata : PromotionContinuationBaseline.MetadataContracts
      state.db origin previous world services) :
    PromotionInitialView.Initial state.db origin world services :=
  PromotionContinuationBaseline.initial_of_correct history.correct metadata

/-- The three production histories from which the final stable promotion may
start: first use, a committed scope reset, or a preceding actual promotion.
No constructor stores the old-view correctness conclusion. -/
inductive InitialViewEvidence (services : MaterializedView.Services)
    (origin : Origin.Parsed) (state : State) (world : TrieDiffCoverage.World) : Prop where
  | clean
      (baseline : PromotionBaseline.CleanOriginBaseline state.db origin world services) :
      InitialViewEvidence services origin state world
  | changed
      (production : ScopeChangeRefinement.Successful spaces changedAt before state report)
      (quiet : before.faults = [])
      (reported : decision ∈ report.demotions)
      (originAligned : decision.complete.origin = Origin.canonical origin)
      (metadata : ScopeChangePromotionBaseline.MetadataContracts
        state.db origin world services) :
      InitialViewEvidence services origin state world
  | continued
      (history : EstablishedView services origin state previous)
      (metadata : PromotionContinuationBaseline.MetadataContracts
        state.db origin previous world services) :
      InitialViewEvidence services origin state world

theorem InitialViewEvidence.initial
    (evidence : InitialViewEvidence services origin state world) :
    PromotionInitialView.Initial state.db origin world services := by
  cases evidence with
  | clean baseline => exact PromotionBaseline.initial_origin baseline
  | changed production quiet reported originAligned metadata =>
      obtain ⟨source, raw⟩ :=
        ScopeChangeRefinement.successful_change_raw production quiet reported
      exact PromotionBaseline.initial_origin
        (ScopeChangePromotionBaseline.clean_origin_baseline raw originAligned metadata)
  | continued history metadata => exact history.nextInitial metadata

end Synchronicity.MptsyncPromotionHistory
