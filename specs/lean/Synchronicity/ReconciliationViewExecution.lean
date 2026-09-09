import Synchronicity.MptsyncStableTail
import Synchronicity.PromotionAtomicView
import Synchronicity.AcceptanceProgress
import Synchronicity.ReconciliationPayloadFrame
import Synchronicity.ForeignMaterializationFrame
import Synchronicity.PromotionContinuationBaseline
import Synchronicity.PromotionBaseline

/-! Refinement of actual reconciliation operations to the stable public-view
transition.  Execution witnesses remain in `ReconciliationExecution`; the
fixed-policy/version conditions are separate tail assumptions. -/
namespace Synchronicity.ReconciliationViewExecution
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication
  SimulatedHost PrivateDatabase ReconciliationExecution MptsyncConvergence

/-- The policy rows read by a stable-tail promotion identify one fixed scope
and replica set. This is a policy-stability condition, not view correctness. -/
def StablePolicy (origin : Origin.Parsed) (target : ViewTarget) (db : Database) : Prop :=
  ∀ scope replicas, MaterializationInputs.ReadPolicy db origin scope replicas →
    scope = target.scope ∧ replicas = target.replicas

/-- M2/M3's stable-version fact at a raw observation: any installed complete
head for this origin is the selected target. -/
def StableSelection (origin : Origin.Parsed) (target : ViewTarget) (db : Database) : Prop :=
  ∀ head, head.origin = origin → AtomicFileView.Installed db head →
    head.seq = target.head.seq ∧ head.root = target.head.root

/-- Raw stable-window facts for the two production head slots. Unlike
`AcceptanceProgress.StableSlots`, this input does not assume that the observed
maximum already equals the target. It records only representation/backing,
native validity, and the independently stable upper bound on actual slots. -/
structure StableSlotInputs (state : State) (origin : String) (latest : Nat)
    (view : HeadView) : Prop where
  represents : HeadView.Represents state.db view
  backed : HeadView.Backed state.db view
  valid : ∀ slot version, view origin slot = some version → version.root.size = 32
  upperBound : ∀ slot version, view origin slot = some version →
    AcceptanceProgress.versionRank version ≤ latest

theorem installed_view (represented : HeadView.Represents db view)
    (installed : AtomicFileView.Installed db head) :
    view (Origin.canonical head.origin) .complete =
      some ⟨head.seq, head.root⟩ := by
  obtain ⟨row, member, named⟩ := installed.1
  obtain ⟨version, observed, points⟩ := HeadView.selected_version represented
    (origin := Origin.canonical head.origin) (slot := .complete) ⟨member, named⟩
  have expected := installed.2 row member named
  have same := HeadView.version_unique row version ⟨head.seq, head.root⟩ points expected
  simpa only [same] using observed

/-- Once the actual complete slot is known to install the stable target, the
raw per-slot upper bound derives (rather than assumes) the observed maximum. -/
theorem stable_slots_of_installed
    (raw : StableSlotInputs state (Origin.canonical origin) latest view)
    (target : ViewTarget)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed state.db target.head)
    (targetLatest : AcceptanceProgress.versionRank
      ⟨target.head.seq, target.head.root⟩ = latest) :
    AcceptanceProgress.StableSlots state (Origin.canonical origin) latest view := by
  have completeValue : view (Origin.canonical origin) .complete =
      some ⟨target.head.seq, target.head.root⟩ := by
    simpa only [sameOrigin] using installed_view raw.represents installed
  refine ⟨raw.represents, raw.backed, raw.valid, ?_⟩
  apply Nat.le_antisymm
  · apply Nat.max_le.mpr
    constructor
    · cases value : view (Origin.canonical origin) .complete with
      | none => simp [AcceptanceProgress.optionRank]
      | some version =>
          simpa [AcceptanceProgress.optionRank] using raw.upperBound .complete version value
    · cases value : view (Origin.canonical origin) .pending with
      | none => simp [AcceptanceProgress.optionRank]
      | some version =>
          simpa [AcceptanceProgress.optionRank] using raw.upperBound .pending version value
  · have completeRank : AcceptanceProgress.optionRank
        (view (Origin.canonical origin) .complete) = latest := by
      rw [completeValue]
      exact targetLatest
    rw [← completeRank]
    exact Nat.le_max_left _ _

/-- M3 plus fixed-width validity and the stable upper bound on actual observed
slots preserves the installed target. No maximum equality is assumed. -/
theorem installed_after_step (step : Step event state final)
    (origin : Origin.Parsed) (target : ViewTarget)
    (beforeView afterView : HeadView)
    (before : StableSlotInputs state (Origin.canonical origin) latest beforeView)
    (after : StableSlotInputs final (Origin.canonical origin) latest afterView)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed state.db target.head)
    (targetLatest : AcceptanceProgress.versionRank
      ⟨target.head.seq, target.head.root⟩ = latest) :
    AtomicFileView.Installed final.db target.head := by
  subst origin
  let version : HeadVersion := ⟨target.head.seq, target.head.root⟩
  have current : beforeView (Origin.canonical target.head.origin) .complete = some version := by
    exact installed_view before.represents installed
  have transition := step.refines before.represents before.backed after.represents
  have changed := transition (Origin.canonical target.head.origin) .complete
  rw [current] at changed
  obtain ⟨next, observed, same | newer⟩ := changed.complete_present
  · subst next
    have afterValue : afterView (Origin.canonical target.head.origin) .complete =
        some version := observed
    have nextInstalled : AtomicFileView.Installed final.db target.head := by
      constructor
      · obtain ⟨row, selected, _⟩ := HeadView.existing after.represents afterValue
        exact ⟨row, selected.1, selected.2⟩
      · intro row member named
        have represented := after.represents (Origin.canonical target.head.origin) .complete
        rw [afterValue] at represented
        exact represented.2 row ⟨member, named⟩
    exact nextInstalled
  · have oldValid := before.valid .complete version current
    have nextValid := after.valid .complete next observed
    have grew := AcceptanceProgress.versionRank_lt_of_newer version next oldValid nextValid newer
    have bounded : AcceptanceProgress.versionRank next ≤ latest :=
      after.upperBound .complete next observed
    rw [targetLatest] at grew
    exact False.elim (Nat.not_lt_of_ge bounded grew)

theorem stable_selection_of_installed
    (represented : HeadView.Represents db view)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed db target.head) :
    StableSelection origin target db := by
  intro head headOrigin headInstalled
  have targetVersion := installed_view represented installed
  have candidateVersion := installed_view represented headInstalled
  rw [headOrigin, ← sameOrigin] at candidateVersion
  have same : (⟨head.seq, head.root⟩ : HeadVersion) =
      ⟨target.head.seq, target.head.root⟩ :=
    Option.some.inj (candidateVersion.symm.trans targetVersion)
  exact ⟨congrArg HeadVersion.seq same, congrArg HeadVersion.root same⟩

/-- Payload framing plus the slot proof is the common refinement used by all
non-publication production commands and prefixes. -/
theorem payload_step_refines (step : Step event state final)
    (origin : Origin.Parsed) (target : ViewTarget) (services : MaterializedView.Services)
    (beforeView afterView : HeadView)
    (before : StableSlotInputs state (Origin.canonical origin) latest beforeView)
    (after : StableSlotInputs final (Origin.canonical origin) latest afterView)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed state.db target.head)
    (targetLatest : AcceptanceProgress.versionRank
      ⟨target.head.seq, target.head.root⟩ = latest)
    (frame : MptsyncStableTail.PayloadFrame state.db final.db) :
    MptsyncStableTail.Refines services origin target state.db final.db := by
  exact Or.inr (Or.inr (Or.inl ⟨frame, installed_after_step step origin target beforeView afterView
    before after sameOrigin installed targetLatest⟩))

/-- A direct actual production promotion refines the stable public transition.
All M4 host/snapshot premises are explicit; no promotion result is assumed. -/
theorem promotion_refines (step : Step (.promotion origin now refused) state final)
    (target : ViewTarget) (world : TrieDiffCoverage.World)
    (services : MaterializedView.Services)
    (snapshot : target.snapshot = world.snapshot)
    (closed : state.pending = none) (faithful : TrieDiffCoverage.Faithful world state)
    (normalization : state.isNfc = services.nfc)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (initial : PromotionInitialView.Initial state.db origin world services)
    (policy : StablePolicy origin target state.db)
    (beforeView afterView : HeadView)
    (before : StableSlotInputs state (Origin.canonical origin) latest beforeView)
    (after : StableSlotInputs final (Origin.canonical origin) latest afterView)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed state.db target.head)
    (targetLatest : AcceptanceProgress.versionRank
      ⟨target.head.seq, target.head.root⟩ = latest) :
    MptsyncStableTail.Refines services origin target state.db final.db := by
  have installedAfter := installed_after_step step origin target beforeView afterView
    before after sameOrigin installed targetLatest
  have selected := stable_selection_of_installed after.represents sameOrigin installedAfter
  cases step with
  | promotion _ _ _ _ _ =>
    have replacement := PromotionAtomicView.promote_refines origin now refused state world
      services closed faithful normalization relational initial
    rcases replacement with unchanged | ⟨scope, replicas, read, ready⟩
    · exact Or.inl unchanged
    · obtain ⟨scopeSame, replicasSame⟩ := policy scope replicas read
      subst scope
      subst replicas
      have targetReady : AtomicFileView.Ready services target.snapshot origin
          target.scope target.replicas state.db
            (execute (Promote.promote origin now refused) state).2.db := by
        rw [snapshot]
        exact ready
      exact Or.inr (Or.inl ⟨targetReady, selected⟩)

/-- Host facts required when a completed requester starts a fresh production
promotion. They concern the post-clock state, not the stale fetch capture. -/
structure PromotionHost (origin : Origin.Parsed) (target : ViewTarget)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (state : State) : Prop where
  snapshot : target.snapshot = world.snapshot
  closed : state.pending = none
  faithful : TrieDiffCoverage.Faithful world state
  normalization : state.isNfc = services.nfc
  relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
    state.byteRelations.contains relation = true
  metadata : PromotionContinuationBaseline.MetadataContracts
    state.db origin target world services
  policy : StablePolicy origin target state.db

/-- Host contracts for an interleaved promotion of another origin. Successful
and non-successful branches are discovered by analyzing the actual command.
They contain no correctness or completion premise for the foreign origin. -/
structure ForeignPromotionHost (origin foreign : Origin.Parsed) (target : ViewTarget)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (state : State) : Prop where
  different : Origin.canonical origin ≠ Origin.canonical foreign
  closed : state.pending = none
  faithful : TrieDiffCoverage.Faithful world state
  normalization : state.isNfc = services.nfc
  relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
    state.byteRelations.contains relation = true
  schema : MaterializationKeySchema.Schema state.db
  replicas : ∀ scope actual,
    MaterializationInputs.ReadPolicy state.db foreign scope actual →
      actual = target.replicas
  policiesAgree : ∀ scope actual,
    MaterializationInputs.ReadPolicy state.db foreign scope actual →
      MaterializationRequirementFrame.PoliciesAgree actual
  materializerNfc : ∀ tx oldRoot newRoot cleared staged count,
    execute (Materialize.materialize tx foreign oldRoot newRoot) cleared =
      (.ok count, staged) → cleared.isNfc = services.nfc
  materializerFaithful : ∀ tx oldRoot newRoot cleared staged count,
    execute (Materialize.materialize tx foreign oldRoot newRoot) cleared =
      (.ok count, staged) → TrieDiffCoverage.Faithful world cleared

theorem foreign_promotion_refines
    (step : Step (.promotion foreign now refused) state final)
    (origin : Origin.Parsed) (target : ViewTarget) (world : TrieDiffCoverage.World)
    (services : MaterializedView.Services)
    (host : ForeignPromotionHost origin foreign target world services state)
    (beforeView afterView : HeadView)
    (before : StableSlotInputs state (Origin.canonical origin) latest beforeView)
    (after : StableSlotInputs final (Origin.canonical origin) latest afterView)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed state.db target.head)
    (correct : CorrectView services origin target state.db)
    (targetLatest : AcceptanceProgress.versionRank
      ⟨target.head.seq, target.head.root⟩ = latest) :
    MptsyncStableTail.Refines services origin target state.db final.db := by
  have installedAfter := installed_after_step step origin target beforeView afterView
    before after sameOrigin installed targetLatest
  cases step
  cases ran : execute (Promote.promote foreign now refused) state with
  | mk answer actualFinal =>
    cases answer with
    | error failure =>
      exact Or.inl (congrArg (AtomicFileView.projection (Origin.canonical origin))
        (PromotionPublication.promote_failure foreign now refused state actualFinal failure ran))
    | ok report =>
      by_cases flipped : report.promotion = Promotion.flipped
      · have retention := ForeignMaterializationFrame.promote_flipped_retention foreign now
          refused target.replicas world state actualFinal report flipped ran
          correct.2.2.2.1 host.schema host.replicas host.policiesAgree
          host.materializerFaithful
        have foreignFiles := ForeignMaterializationFrame.promote_flipped_files foreign now
          refused (Origin.canonical origin) host.different services world state actualFinal
          report flipped ran host.materializerNfc host.materializerFaithful
        refine Or.inr (Or.inr (Or.inr ⟨⟨?_, ?_, ?_⟩, ?_⟩))
        · exact foreignFiles
        · exact retention.1
        · exact retention.2
        · simpa only [ran] using installedAfter
      · exact Or.inl (PromotionNonpublication.promote_no_flip_for
          (Origin.canonical origin) foreign now refused state actualFinal report flipped ran)

/-- The `.ok true` settlement branch is not treated as a frame: after the
actual clock read it executes a fresh `Promote.promote`. M4's contracts are
therefore required for precisely that post-clock state. -/
theorem completed_settlement_refines
    (step : Step (.settlement origin refused scope fetchTarget key (.ok true)) state final)
    (target : ViewTarget) (world : TrieDiffCoverage.World)
    (services : MaterializedView.Services)
    (host : ∀ now current,
      execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state =
        (.ok now, current) → PromotionHost origin target world services current)
    (beforeView afterView : HeadView)
    (before : StableSlotInputs state (Origin.canonical origin) latest beforeView)
    (after : StableSlotInputs final (Origin.canonical origin) latest afterView)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed state.db target.head)
    (correct : CorrectView services origin target state.db)
    (targetLatest : AcceptanceProgress.versionRank
      ⟨target.head.seq, target.head.root⟩ = latest) :
    MptsyncStableTail.Refines services origin target state.db final.db := by
  have installedAfter := installed_after_step step origin target beforeView afterView
    before after sameOrigin installed targetLatest
  have selected := stable_selection_of_installed after.represents sameOrigin installedAfter
  have dbFrame :
      (execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state).2.db = state.db := by
    apply reply_preserves_db
    intro s
    rfl
  cases step with
  | settlement _ _ _ _ _ _ _ _ =>
    generalize clockRead :
      execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state = result
      at dbFrame host
    obtain ⟨answer, current⟩ := result
    cases answer with
    | error error =>
      have finalDb :
          (execute (FetchLifecycle.settle origin refused scope fetchTarget key (.ok true)) state).2.db =
            state.db := by
        unfold FetchLifecycle.settle
        simp only [bind, ExceptT.bind, ExceptT.mk, execute_bind]
        rw [clockRead]
        exact dbFrame
      exact Or.inl (by rw [finalDb])
    | ok now =>
      have currentDb : current.db = state.db := by simpa using dbFrame
      have finalState :
          (execute (FetchLifecycle.settle origin refused scope fetchTarget key (.ok true)) state).2 =
            (execute (Promote.promote origin now refused) current).2 := by
        unfold FetchLifecycle.settle
        simp only [bind, ExceptT.bind, ExceptT.mk, execute_bind]
        rw [clockRead]
        dsimp only [ExceptT.bindCont, ExceptT.run]
        rw [execute_bind]
        simp only [Fetch.lift]
        rw [OperationExecution.within_eq FetchLifecycle.promote_agrees]
        generalize execute (Promote.promote origin now refused) current = promoted
        obtain ⟨answer, after⟩ := promoted
        cases answer <;> rfl
      have facts := host now current rfl
      have currentCorrect : CorrectView services origin target current.db := by
        rw [currentDb]
        exact correct
      have replacement := PromotionAtomicView.promote_refines origin now refused current world
        services facts.closed facts.faithful facts.normalization facts.relational
          (PromotionContinuationBaseline.initial_of_correct currentCorrect facts.metadata)
      rcases replacement with unchanged | ⟨actualScope, replicas, read, ready⟩
      · exact Or.inl (by rw [finalState, ← currentDb]; exact unchanged)
      · obtain ⟨scopeSame, replicasSame⟩ := facts.policy actualScope replicas read
        subst actualScope
        subst replicas
        exact Or.inr (Or.inl ⟨by rw [finalState, ← currentDb, facts.snapshot]; exact ready,
          selected⟩)

/-- A completed requester for another origin either stops at a failed clock
read (a database stutter), or runs a certified actual foreign promotion. -/
theorem foreign_completed_settlement_refines
    (step : Step (.settlement foreign refused scope fetchTarget key (.ok true)) state final)
    (origin : Origin.Parsed) (target : ViewTarget) (world : TrieDiffCoverage.World)
    (services : MaterializedView.Services)
    (host : ∀ clockNow current,
      execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state =
        (.ok clockNow, current) →
          ForeignPromotionHost origin foreign target world services current)
    (beforeView afterView : HeadView)
    (before : StableSlotInputs state (Origin.canonical origin) latest beforeView)
    (after : StableSlotInputs final (Origin.canonical origin) latest afterView)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed state.db target.head)
    (correct : CorrectView services origin target state.db)
    (targetLatest : AcceptanceProgress.versionRank
      ⟨target.head.seq, target.head.root⟩ = latest) :
    MptsyncStableTail.Refines services origin target state.db final.db := by
  have installedAfter := installed_after_step step origin target beforeView afterView
    before after sameOrigin installed targetLatest
  have dbFrame :
      (execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state).2.db = state.db := by
    apply reply_preserves_db
    intro s
    rfl
  cases step with
  | settlement _ _ _ _ _ _ _ _ =>
    generalize clockRead :
      execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state = result
      at dbFrame host
    obtain ⟨answer, current⟩ := result
    cases answer with
    | error error =>
      have finalDb :
          (execute (FetchLifecycle.settle foreign refused scope fetchTarget key (.ok true)) state).2.db =
            state.db := by
        unfold FetchLifecycle.settle
        simp only [bind, ExceptT.bind, ExceptT.mk, execute_bind]
        rw [clockRead]
        exact dbFrame
      exact Or.inl (by rw [finalDb])
    | ok clockNow =>
      have currentDb : current.db = state.db := by simpa using dbFrame
      have currentCorrect : CorrectView services origin target current.db := by
        simpa only [currentDb] using correct
      have finalState :
          (execute (FetchLifecycle.settle foreign refused scope fetchTarget key (.ok true)) state).2 =
            (execute (Promote.promote foreign clockNow refused) current).2 := by
        unfold FetchLifecycle.settle
        simp only [bind, ExceptT.bind, ExceptT.mk, execute_bind]
        rw [clockRead]
        dsimp only [ExceptT.bindCont, ExceptT.run]
        rw [execute_bind]
        simp only [Fetch.lift]
        rw [OperationExecution.within_eq FetchLifecycle.promote_agrees]
        generalize execute (Promote.promote foreign clockNow refused) current = promoted
        obtain ⟨answer, after⟩ := promoted
        cases answer <;> rfl
      have facts := host clockNow current rfl
      have currentSlots : StableSlotInputs current
          (Origin.canonical origin) latest beforeView := by
        exact
          { represents := by simpa only [currentDb] using before.represents
            backed := by simpa only [currentDb] using before.backed
            valid := before.valid
            upperBound := before.upperBound }
      have promotedSlots : StableSlotInputs
          (execute (Promote.promote foreign clockNow refused) current).2
          (Origin.canonical origin) latest afterView := by
        rw [← finalState]
        exact after
      have promoted := foreign_promotion_refines
        (Step.promotion foreign clockNow refused current facts.closed) origin target world services
        facts beforeView afterView currentSlots promotedSlots sameOrigin (by
          simpa only [currentDb] using installed) currentCorrect targetLatest
      simpa only [finalState, currentDb] using promoted

/-- Stable-tail evidence is stated over actual raw observations. It contains
slot representation/backing/validity, an upper bound on observed versions and
host facts; never `Refines` or any origin's `CorrectView`. -/
structure StableFacts (trace : MptsyncStableTail.Trace)
    (services : MaterializedView.Services) (origin : Origin.Parsed)
    (target : ViewTarget) (latest : Nat) (views : Nat → HeadView)
    (world : TrieDiffCoverage.World) (stableFrom : Nat) where
  targetOrigin : target.head.origin = origin
  targetLatest : AcceptanceProgress.versionRank
    ⟨target.head.seq, target.head.root⟩ = latest
  slots : ∀ n, stableFrom ≤ n → StableSlotInputs (trace.state n)
    (Origin.canonical origin) latest (views n)
  promotionHost : ∀ n now refused,
    stableFrom ≤ n → trace.event n = .promotion origin now refused →
      PromotionHost origin target world services (trace.state n)
  foreignPromotion : ∀ n promoted now refused,
    stableFrom ≤ n → trace.event n = .promotion promoted now refused → promoted ≠ origin →
      ForeignPromotionHost origin promoted target world services (trace.state n)
  settlementHost : ∀ n refused scope fetchTarget key,
    stableFrom ≤ n →
    trace.event n = .settlement origin refused scope fetchTarget key (.ok true) →
      ∀ now current,
        execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) (trace.state n) =
          (.ok now, current) → PromotionHost origin target world services current
  foreignSettlement : ∀ n settled refused scope fetchTarget key,
    stableFrom ≤ n →
    trace.event n = .settlement settled refused scope fetchTarget key (.ok true) →
      settled ≠ origin → ∀ clockNow current,
        execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) (trace.state n) =
          (.ok clockNow, current) →
            ForeignPromotionHost origin settled target world services current

/-- Raw facts for one actual reconciliation step in a stable version/policy
window. This is the finite-prefix counterpart of `StableFacts`: it contains no
`Refines`, `CorrectView`, `Initial`, or successful operation result. -/
structure StableStepFacts (event : ReconciliationExecution.Event)
    (state final : State) (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget) (latest : Nat)
    (world : TrieDiffCoverage.World) where
  beforeView : HeadView
  afterView : HeadView
  targetOrigin : target.head.origin = origin
  targetLatest : AcceptanceProgress.versionRank
    ⟨target.head.seq, target.head.root⟩ = latest
  before : StableSlotInputs state (Origin.canonical origin) latest beforeView
  after : StableSlotInputs final (Origin.canonical origin) latest afterView
  promotionHost : ∀ now refused, event = .promotion origin now refused →
    PromotionHost origin target world services state
  foreignPromotion : ∀ promoted now refused,
    event = .promotion promoted now refused → promoted ≠ origin →
      ForeignPromotionHost origin promoted target world services state
  settlementHost : ∀ refused scope fetchTarget key,
    event = .settlement origin refused scope fetchTarget key (.ok true) →
      ∀ now current,
        execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state =
          (.ok now, current) → PromotionHost origin target world services current
  foreignSettlement : ∀ settled refused scope fetchTarget key,
    event = .settlement settled refused scope fetchTarget key (.ok true) →
      settled ≠ origin → ∀ clockNow current,
        execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state =
          (.ok clockNow, current) →
            ForeignPromotionHost origin settled target world services current

/-- Every production event, including same/foreign promotion and completed
settlement, refines the common public-view transition from only the actual step
and its raw stable facts. -/
theorem stable_actual_step_refines
    (actual : ReconciliationExecution.Step event state final)
    (facts : StableStepFacts event state final services origin target latest world)
    (correct : CorrectView services origin target state.db) :
    MptsyncStableTail.Refines services origin target state.db final.db ∧
      AcceptanceProgress.StableSlots final (Origin.canonical origin) latest facts.afterView := by
  have installedNext := installed_after_step actual origin target facts.beforeView facts.afterView
    facts.before facts.after facts.targetOrigin correct.2.1 facts.targetLatest
  have nextSlots := stable_slots_of_installed facts.after target facts.targetOrigin installedNext
    facts.targetLatest
  have refinement : MptsyncStableTail.Refines services origin target state.db final.db := by
    have payload (nonPublishing : ReconciliationPayloadFrame.NonPublishing event) :=
      payload_step_refines actual origin target services facts.beforeView facts.afterView
        facts.before facts.after facts.targetOrigin correct.2.1 facts.targetLatest
        (ReconciliationPayloadFrame.step_payload actual nonPublishing)
    cases event with
    | advertisement => exact payload trivial
    | request => exact payload trivial
    | retirement => exact payload trivial
    | selection => exact payload trivial
    | abandonment => exact payload trivial
    | promotion promoted now refused =>
      by_cases same : promoted = origin
      · subst promoted
        have host := facts.promotionHost now refused rfl
        exact promotion_refines actual target world services host.snapshot host.closed host.faithful
          host.normalization host.relational
          (PromotionContinuationBaseline.initial_of_correct correct host.metadata) host.policy
          facts.beforeView facts.afterView facts.before facts.after facts.targetOrigin correct.2.1
          facts.targetLatest
      · exact foreign_promotion_refines actual origin target world services
          (facts.foreignPromotion promoted now refused rfl same)
          facts.beforeView facts.afterView facts.before facts.after
          facts.targetOrigin correct.2.1 correct facts.targetLatest
    | settlement settled refused scope fetchTarget key result =>
      cases result with
      | error _ => exact payload trivial
      | ok complete =>
        cases complete with
        | false => exact payload trivial
        | true =>
          by_cases same : settled = origin
          · subst settled
            exact completed_settlement_refines actual target world services
              (facts.settlementHost refused scope fetchTarget key rfl)
              facts.beforeView facts.afterView facts.before facts.after
              facts.targetOrigin correct.2.1 correct facts.targetLatest
          · exact foreign_completed_settlement_refines actual origin target world services
              (facts.foreignSettlement settled refused scope fetchTarget key rfl same)
              facts.beforeView facts.afterView facts.before facts.after
              facts.targetOrigin correct.2.1 correct facts.targetLatest
  exact ⟨refinement, nextSlots⟩

private theorem stable_step_refines
    (trace : MptsyncStableTail.Trace) (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget) (latest : Nat)
    (views : Nat → HeadView) (world : TrieDiffCoverage.World)
    (stableFrom : Nat)
    (facts : StableFacts trace services origin target latest views world stableFrom)
    (n : Nat) (stable : stableFrom ≤ n)
    (correct : CorrectView services origin target (trace.state n).db) :
    MptsyncStableTail.Refines services origin target (trace.state n).db
        (trace.state (n + 1)).db ∧
      AcceptanceProgress.StableSlots (trace.state (n + 1))
        (Origin.canonical origin) latest (views (n + 1)) := by
  have stableNext : stableFrom ≤ n + 1 := Nat.le_trans stable (Nat.le_succ n)
  let stepFacts : StableStepFacts (trace.event n) (trace.state n) (trace.state (n + 1))
      services origin target latest world :=
    { beforeView := views n
      afterView := views (n + 1)
      targetOrigin := facts.targetOrigin
      targetLatest := facts.targetLatest
      before := facts.slots n stable
      after := facts.slots (n + 1) stableNext
      promotionHost := fun now refused event => facts.promotionHost n now refused stable event
      foreignPromotion := fun promoted now refused event different =>
        facts.foreignPromotion n promoted now refused stable event different
      settlementHost := fun refused scope fetchTarget key event =>
        facts.settlementHost n refused scope fetchTarget key stable event
      foreignSettlement := fun settled refused scope fetchTarget key event different =>
        facts.foreignSettlement n settled refused scope fetchTarget key stable event different }
  exact stable_actual_step_refines (trace.step n) stepFacts correct

private theorem correct_from (trace : MptsyncStableTail.Trace)
    (services : MaterializedView.Services) (origin : Origin.Parsed) (target : ViewTarget)
    (latest : Nat) (views : Nat → HeadView) (world : TrieDiffCoverage.World)
    (start : Nat) (facts : StableFacts trace services origin target latest views world start)
    (reached : CorrectView services origin target (trace.state start).db) :
    ∀ n, start ≤ n → CorrectView services origin target (trace.state n).db := by
  have steps : ∀ offset,
      CorrectView services origin target (trace.state (start + offset)).db := by
    intro offset
    induction offset with
    | zero => simpa using reached
    | succ offset correct =>
      rw [Nat.add_succ]
      exact MptsyncStableTail.refines_preserves
        (stable_step_refines trace services origin target latest views world start facts
          (start + offset) (Nat.le_add_right start offset) correct).1 correct
  intro n after
  obtain ⟨offset, rfl⟩ := Nat.exists_eq_add_of_le after
  exact steps offset

/-- Actual slot observations, actual non-publication frames, and the explicit
M4 host contracts derive refinement of the whole production tail. -/
theorem trace_refinedFrom (trace : MptsyncStableTail.Trace)
    (services : MaterializedView.Services) (origin : Origin.Parsed) (target : ViewTarget)
    (latest : Nat) (views : Nat → HeadView) (world : TrieDiffCoverage.World)
    (start : Nat) (facts : StableFacts trace services origin target latest views world start)
    (reached : CorrectView services origin target (trace.state start).db) :
    MptsyncStableTail.RefinedFrom trace services origin target start := by
  intro n after
  exact (stable_step_refines trace services origin target latest views world start facts n after
    (correct_from trace services origin target latest views world start facts reached n after)).1

/-- Reached correctness plus the derived production refinement yields the
stable suffix required by M1, without assuming `RefinedFrom`. -/
theorem stable_tail (trace : MptsyncStableTail.Trace)
    (services : MaterializedView.Services) (origin : Origin.Parsed) (target : ViewTarget)
    (latest : Nat) (views : Nat → HeadView) (world : TrieDiffCoverage.World)
    (start : Nat) (facts : StableFacts trace services origin target latest views world start)
    (reached : CorrectView services origin target (trace.state start).db) :
    EventuallyAlways fun n => CorrectView services origin target (trace.state n).db :=
  MptsyncStableTail.eventuallyAlways_of_refined_actual_tail trace services origin target start reached
    (trace_refinedFrom trace services origin target latest views world start facts reached)

end Synchronicity.ReconciliationViewExecution
