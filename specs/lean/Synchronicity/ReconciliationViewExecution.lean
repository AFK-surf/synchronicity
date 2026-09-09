import Synchronicity.MptsyncStableTail
import Synchronicity.PromotionAtomicView
import Synchronicity.AcceptanceProgress
import Synchronicity.ReconciliationPayloadFrame
import Synchronicity.ForeignMaterializationFrame
import Synchronicity.PromotionContinuationBaseline

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

/-- M3 plus the actual fixed-width complete/pending maximum preserves the
installed target. The maximum ranges only over observed slots; it is not the
impossible claim that no `UInt64`/root pair could be larger. -/
theorem installed_after_step (step : Step event state final)
    (origin : Origin.Parsed) (target : ViewTarget)
    (beforeView afterView : HeadView)
    (before : AcceptanceProgress.StableSlots state (Origin.canonical origin) latest beforeView)
    (after : AcceptanceProgress.StableSlots final (Origin.canonical origin) latest afterView)
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
    have bounded : AcceptanceProgress.versionRank next ≤ latest := by
      calc
        AcceptanceProgress.versionRank next =
            AcceptanceProgress.optionRank (afterView (Origin.canonical target.head.origin) .complete) := by
              simp only [observed, AcceptanceProgress.optionRank]
        _ ≤ max (AcceptanceProgress.optionRank
              (afterView (Origin.canonical target.head.origin) .complete))
              (AcceptanceProgress.optionRank
                (afterView (Origin.canonical target.head.origin) .pending)) := Nat.le_max_left _ _
        _ = latest := after.maximum
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
    (before : AcceptanceProgress.StableSlots state (Origin.canonical origin) latest beforeView)
    (after : AcceptanceProgress.StableSlots final (Origin.canonical origin) latest afterView)
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
    (before : AcceptanceProgress.StableSlots state (Origin.canonical origin) latest beforeView)
    (after : AcceptanceProgress.StableSlots final (Origin.canonical origin) latest afterView)
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

/-- Factual host certificate for an interleaved promotion of another origin.
It packages the production readiness phases and their environmental contracts;
it does not assume a frame, refinement, or correct public view. -/
structure ForeignPromotionHost (origin foreign : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (target : ViewTarget)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (state : State) where
  ready : PromotionProgress.Ready foreign now refused state
  different : Origin.canonical origin ≠ Origin.canonical foreign
  replicas : ready.replicas = target.replicas
  closed : state.pending = none
  faithful : TrieDiffCoverage.Faithful world state
  normalization : state.isNfc = services.nfc
  relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
    state.byteRelations.contains relation = true
  initial : PromotionInitialView.Initial state.db foreign world services
  materializerNfc : ∀ cleared count,
    execute (Materialize.materialize ready.tx foreign
      (ready.old.map (·.head.root) |>.getD Trie.emptyRoot) ready.pending.head.root) cleared =
      (.ok count, ready.body.staged) → cleared.isNfc = services.nfc
  materializerFaithful : ∀ cleared count,
    execute (Materialize.materialize ready.tx foreign
      (ready.old.map (·.head.root) |>.getD Trie.emptyRoot) ready.pending.head.root) cleared =
      (.ok count, ready.body.staged) → TrieDiffCoverage.Faithful world cleared

/-- Actual foreign promotion phases imply the cross-origin frame used by the
stable public-view transition. -/
theorem foreign_promotion_frame
    (host : ForeignPromotionHost origin foreign now refused target world services state) :
    MptsyncStableTail.ForeignFrame origin target state.db
      (execute (Promote.promote foreign now refused) state).2.db := by
  have finalState : (execute (Promote.promote foreign now refused) state).2 = host.ready.final := by
    simpa using congrArg Prod.snd (PromotionProgress.promotes host.ready)
  rw [finalState]
  obtain ⟨_, _, _, _, current, forever⟩ :=
    PromotionProgress.promotes_ready_view host.ready world services host.closed
    host.faithful host.normalization host.relational host.initial
  have files := ForeignMaterializationFrame.ready_files host.ready (Origin.canonical origin)
    host.different services world host.materializerNfc host.materializerFaithful
  refine ⟨files, ?_, ?_⟩
  · simpa only [← host.replicas] using current
  · simpa only [← host.replicas] using forever

theorem foreign_promotion_refines
    (step : Step (.promotion foreign now refused) state final)
    (origin : Origin.Parsed) (target : ViewTarget) (world : TrieDiffCoverage.World)
    (services : MaterializedView.Services)
    (host : ForeignPromotionHost origin foreign now refused target world services state)
    (beforeView afterView : HeadView)
    (before : AcceptanceProgress.StableSlots state (Origin.canonical origin) latest beforeView)
    (after : AcceptanceProgress.StableSlots final (Origin.canonical origin) latest afterView)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed state.db target.head)
    (targetLatest : AcceptanceProgress.versionRank
      ⟨target.head.seq, target.head.root⟩ = latest) :
    MptsyncStableTail.Refines services origin target state.db final.db := by
  have installedAfter := installed_after_step step origin target beforeView afterView
    before after sameOrigin installed targetLatest
  cases step with
  | promotion =>
    exact Or.inr (Or.inr (Or.inr ⟨foreign_promotion_frame host, installedAfter⟩))

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
    (before : AcceptanceProgress.StableSlots state (Origin.canonical origin) latest beforeView)
    (after : AcceptanceProgress.StableSlots final (Origin.canonical origin) latest afterView)
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
          ForeignPromotionHost origin foreign clockNow refused target world services current)
    (beforeView afterView : HeadView)
    (before : AcceptanceProgress.StableSlots state (Origin.canonical origin) latest beforeView)
    (after : AcceptanceProgress.StableSlots final (Origin.canonical origin) latest afterView)
    (sameOrigin : target.head.origin = origin)
    (installed : AtomicFileView.Installed state.db target.head)
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
      have frame := foreign_promotion_frame (host clockNow current rfl)
      exact Or.inr (Or.inr (Or.inr ⟨by
        rw [finalState, ← currentDb]
        exact frame, installedAfter⟩))

/-- Stable-tail evidence is stated over actual raw observations. It contains
slot representations/maxima and host facts, never `Refines` or `CorrectView`. -/
structure StableFacts (trace : MptsyncStableTail.Trace)
    (services : MaterializedView.Services) (origin : Origin.Parsed)
    (target : ViewTarget) (latest : Nat) (views : Nat → HeadView)
    (world : TrieDiffCoverage.World) (stableFrom : Nat) where
  targetOrigin : target.head.origin = origin
  targetLatest : AcceptanceProgress.versionRank
    ⟨target.head.seq, target.head.root⟩ = latest
  slots : ∀ n, stableFrom ≤ n → AcceptanceProgress.StableSlots (trace.state n)
    (Origin.canonical origin) latest (views n)
  promotionHost : ∀ n now refused,
    stableFrom ≤ n → trace.event n = .promotion origin now refused →
      PromotionHost origin target world services (trace.state n)
  foreignPromotion : ∀ n promoted now refused,
    stableFrom ≤ n → trace.event n = .promotion promoted now refused → promoted ≠ origin →
      ForeignPromotionHost origin promoted now refused target world services (trace.state n)
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
            ForeignPromotionHost origin settled clockNow refused target world services current

private theorem stable_step_refines
    (trace : MptsyncStableTail.Trace) (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget) (latest : Nat)
    (views : Nat → HeadView) (world : TrieDiffCoverage.World)
    (stableFrom : Nat)
    (facts : StableFacts trace services origin target latest views world stableFrom)
    (n : Nat) (stable : stableFrom ≤ n)
    (correct : CorrectView services origin target (trace.state n).db) :
    MptsyncStableTail.Refines services origin target (trace.state n).db
      (trace.state (n + 1)).db := by
  have actual := trace.step n
  have stableNext : stableFrom ≤ n + 1 := Nat.le_trans stable (Nat.le_succ n)
  generalize eventEq : trace.event n = event at actual
  have payload (nonPublishing : ReconciliationPayloadFrame.NonPublishing event) :=
    payload_step_refines actual origin target services (views n) (views (n + 1))
      (facts.slots n stable) (facts.slots (n + 1) stableNext) facts.targetOrigin correct.2.1
      facts.targetLatest (ReconciliationPayloadFrame.step_payload actual nonPublishing)
  cases event with
  | advertisement => exact payload trivial
  | request => exact payload trivial
  | retirement => exact payload trivial
  | selection => exact payload trivial
  | abandonment => exact payload trivial
  | promotion promoted now refused =>
    by_cases same : promoted = origin
    · subst promoted
      have host := facts.promotionHost n now refused stable eventEq
      exact promotion_refines actual target world services host.snapshot host.closed host.faithful
        host.normalization host.relational
        (PromotionContinuationBaseline.initial_of_correct correct host.metadata) host.policy
        (views n) (views (n + 1))
        (facts.slots n stable) (facts.slots (n + 1) stableNext) facts.targetOrigin correct.2.1
        facts.targetLatest
    · exact foreign_promotion_refines actual origin target world services
        (facts.foreignPromotion n promoted now refused stable eventEq same)
        (views n) (views (n + 1)) (facts.slots n stable) (facts.slots (n + 1) stableNext)
        facts.targetOrigin correct.2.1 facts.targetLatest
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
            (facts.settlementHost n refused scope fetchTarget key stable eventEq)
            (views n) (views (n + 1)) (facts.slots n stable) (facts.slots (n + 1) stableNext)
            facts.targetOrigin correct.2.1 correct facts.targetLatest
        · exact foreign_completed_settlement_refines actual origin target world services
            (facts.foreignSettlement n settled refused scope fetchTarget key stable eventEq same)
            (views n) (views (n + 1)) (facts.slots n stable) (facts.slots (n + 1) stableNext)
            facts.targetOrigin correct.2.1 facts.targetLatest

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
          (start + offset) (Nat.le_add_right start offset) correct) correct
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
  exact stable_step_refines trace services origin target latest views world start facts n after
    (correct_from trace services origin target latest views world start facts reached n after)

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
