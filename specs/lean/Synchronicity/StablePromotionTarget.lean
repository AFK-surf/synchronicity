import Synchronicity.PromotionProgress
import Synchronicity.AcceptanceProgress
import Synchronicity.ReconciliationFloor
import Synchronicity.StableAdvertisementProgress
import Synchronicity.MptsyncConvergence
import Synchronicity.ReconciliationExecution

/-! Connect the version selected by stable advertisement handling to the
candidate read by a later production promotion.  Selection is observed in the
raw complete/pending view; promotion obtains its candidate from a fresh raw
pending-slot read in its own transaction. -/
namespace Synchronicity.StablePromotionTarget
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
  SimulatedHost AcceptanceProgress
open MptsyncConvergence

/-- The public target established by one healthy production promotion. -/
def targetFor (state : State) (world : TrieDiffCoverage.World)
    (ready : PromotionProgress.Ready origin now refused state) : ViewTarget :=
  { head := ready.pending.head
    snapshot := world.snapshot
    scope := ready.scope
    replicas := ready.replicas
    before := state.db }

/-- If the complete slot is absent, an actual selected version is exactly the
pending slot.  This is a raw-view consequence, not an assumed promotion target. -/
theorem pending_of_selected_without_complete
    (complete : view origin .complete = none)
    (selected : selectedVersion view origin = some version) :
    view origin .pending = some version := by
  unfold selectedVersion at selected
  rw [complete] at selected
  cases pending : view origin .pending <;> simp_all

/-- The candidate returned by actual promotion preparation is the stable
pending version represented and backed in the promotion's starting database. -/
theorem ready_uses_observed_pending
    (ready : PromotionProgress.Ready origin now refused state)
    (stable : StableSlots state (Origin.canonical origin) latest view)
    (pending : view (Origin.canonical origin) .pending = some version) :
    ready.pending.head.seq = version.seq ∧ ready.pending.head.root = version.root := by
  have rawBegin := OperationExecution.raise_success (fun _ _ => rfl)
    Promote.Error.host Storage.begin state ready.opened ready.tx ready.began
  have snapshot := ReconciliationFloor.begin_pending state ready.opened ready.tx rawBegin
  obtain ⟨current, selected, sameSeq, sameRoot⟩ :=
    PromotionCommand.prepare_pending_floor ready.tx origin now ready.opened ready.prepared
      state.db snapshot version.seq.toInt64 version.root
      (stable.backed (Origin.canonical origin) .pending version pending)
      ready.scope ready.authority (some ready.pending) ready.old ready.preparation
  have sameCandidate : current = ready.pending := Option.some.inj selected.symm
  subst current
  exact ⟨by simpa using sameSeq, sameRoot⟩

/-- Delivery of the stable greatest signed head, its actual acceptance fold,
and an empty complete slot determine the later production promotion candidate.
No selected-version or promotion-result premise is needed. -/
theorem ready_uses_delivered_latest
    (delivered : StableAdvertisementProgress.DeliveredLatest valid origin latestHead heads)
    (accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      initialState initialView initialSlots heads final state view)
    (initialBound : initial ≤ rank latestHead)
    (complete : view (Origin.canonical origin) .complete = none)
    (ready : PromotionProgress.Ready origin now refused state) :
    ready.pending.head.seq = latestHead.seq ∧
      ready.pending.head.root = latestHead.root := by
  have selected := StableAdvertisementProgress.actual_fold_selects_latest
    delivered accepted initialBound
  have pending := pending_of_selected_without_complete complete selected
  exact ready_uses_observed_pending ready accepted.final_stable pending

/-- Fetch/retry work may separate acceptance from promotion. If M3's actual
slot observation keeps the same stable maximum, the later fresh preparation
still reads the delivered latest version from pending. -/
theorem ready_uses_delivered_latest_after_frames
    (delivered : StableAdvertisementProgress.DeliveredLatest valid origin latestHead heads)
    (accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      initialState initialView initialSlots heads final acceptedState acceptedView)
    (initialBound : initial ≤ rank latestHead)
    (laterSlots : StableSlots state (Origin.canonical origin) final view)
    (complete : view (Origin.canonical origin) .complete = none)
    (ready : PromotionProgress.Ready origin now refused state) :
    ready.pending.head.seq = latestHead.seq ∧
      ready.pending.head.root = latestHead.root := by
  have selected := StableAdvertisementProgress.actual_fold_selects_latest
    delivered accepted initialBound
  have sameSelection := stable_slots_selected_equal accepted.final_stable laterSlots
  have laterSelected : selectedVersion view (Origin.canonical origin) =
      some (⟨latestHead.seq, latestHead.root⟩ : HeadVersion) := by
    rw [← sameSelection]
    exact selected
  have pending := pending_of_selected_without_complete complete laterSelected
  exact ready_uses_observed_pending ready laterSlots pending

/-- Actual delivery and acceptance determine the pending candidate; healthy
production promotion then establishes the aligned scenario view. Completeness
is still supplied through `Ready` here and is discharged from the actual
completion walk by the higher acquisition composition. -/
theorem actual_promotion_reaches
    (delivered : StableAdvertisementProgress.DeliveredLatest valid origin latestHead heads)
    (accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      initialState initialView initialSlots heads final state view)
    (initialBound : initial ≤ rank latestHead)
    (complete : view (Origin.canonical origin) .complete = none)
    (ready : PromotionProgress.Ready origin now refused state)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (closed : state.pending = none)
    (faithful : TrieDiffCoverage.Faithful world state)
    (normalization : state.isNfc = services.nfc)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (initialViewReady : PromotionInitialView.Initial state.db origin world services)
    (target : ViewTarget)
    (targetOrigin : target.head.origin = origin)
    (targetVersion : (⟨target.head.seq, target.head.root⟩ : HeadVersion) =
      ⟨latestHead.seq, latestHead.root⟩)
    (targetSnapshot : target.snapshot = world.snapshot)
    (targetScope : target.scope = ready.scope)
    (targetReplicas : target.replicas = ready.replicas)
    (targetBefore : target.before = state.db) :
    CorrectView services origin target ready.final.db := by
  have used := ready_uses_delivered_latest delivered accepted initialBound complete ready
  have candidateVersion : (⟨ready.pending.head.seq, ready.pending.head.root⟩ : HeadVersion) =
      ⟨latestHead.seq, latestHead.root⟩ := by
    have pairs : (ready.pending.head.seq, ready.pending.head.root) =
        (latestHead.seq, latestHead.root) := by
      apply Prod.ext
      · exact used.1
      · exact used.2
    exact congrArg (fun pair : UInt64 × ByteArray =>
      (⟨pair.1, pair.2⟩ : HeadVersion)) pairs
  obtain ⟨pendingOrigin, _, installed, files, current, forever⟩ :=
    PromotionProgress.promotes_ready_view ready world services closed faithful normalization
      relational initialViewReady
  let actual := targetFor state world ready
  have actualCorrect : CorrectView services origin actual ready.final.db := by
    refine ⟨pendingOrigin, installed, ?_, current, forever⟩
    change SnapshotViewProgress.ExactFiles services world.snapshot ready.pending.head.root
      (fun key => ready.scope.admitsKeyPath (Trie.keyNibbles key) = true)
      ready.final.db (Origin.canonical origin)
    exact files
  apply correctView_of_same_target (actual := actual) _ actualCorrect
  exact
    { origin := by simpa [actual, targetFor] using targetOrigin.trans pendingOrigin.symm
      version := by
        change (⟨target.head.seq, target.head.root⟩ : HeadVersion) =
          ⟨ready.pending.head.seq, ready.pending.head.root⟩
        exact targetVersion.trans candidateVersion.symm
      snapshot := by simpa [actual, targetFor] using targetSnapshot
      scope := by simpa [actual, targetFor] using targetScope
      replicas := by simpa [actual, targetFor] using targetReplicas
      before := by simpa [actual, targetFor] using targetBefore }

/-- The next observation of an actual promotion step is exactly the final
state forced by the independently constructed healthy readiness certificate. -/
theorem actual_step_reaches_ready_final
    (step : ReconciliationExecution.Step (.promotion origin now refused) state after)
    (ready : PromotionProgress.Ready origin now refused state) :
    after = ready.final := by
  cases step
  exact congrArg Prod.snd (PromotionProgress.promotes ready)

end Synchronicity.StablePromotionTarget
