import Synchronicity.MptsyncStableTail
import Synchronicity.PromotionAtomicView
import Synchronicity.AcceptanceProgress

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
  exact Or.inr (Or.inr ⟨frame, installed_after_step step origin target beforeView afterView
    before after sameOrigin installed targetLatest⟩)

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
  initial : PromotionInitialView.Initial state.db origin world services
  policy : StablePolicy origin target state.db

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
      have replacement := PromotionAtomicView.promote_refines origin now refused current world
        services facts.closed facts.faithful facts.normalization facts.relational facts.initial
      rcases replacement with unchanged | ⟨actualScope, replicas, read, ready⟩
      · exact Or.inl (by rw [finalState, ← currentDb]; exact unchanged)
      · obtain ⟨scopeSame, replicasSame⟩ := facts.policy actualScope replicas read
        subst actualScope
        subst replicas
        exact Or.inr (Or.inl ⟨by rw [finalState, ← currentDb, facts.snapshot]; exact ready,
          selected⟩)

end Synchronicity.ReconciliationViewExecution
