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

/-- A successful production slot read can return `some` only when its
transaction snapshot contains a raw row selected by that origin/slot key. -/
private theorem slot_some_has_selected
    (tx : Transaction) (origin : Origin.Parsed)
    (state : State) (db : Database) (opened : state.pending = some (tx, db))
    (pending : Promote.Pending)
    (ran : (execute (Promote.slot tx origin "pending") state).1 = .ok (some pending)) :
    ∃ row, HeadView.Selected db (Origin.canonical origin) .pending row := by
  unfold Promote.slot at ran
  obtain ⟨scan, afterScan, scanned, ran⟩ :=
    TrieServePrivacyProofs.bind_ok _ _ _ _ ran
  have scanNonempty : scan.rows ≠ [] := by
    intro empty
    rw [empty] at ran
    cases failure : scan.failure with
    | none =>
      simp only [failure] at ran
      change Except.ok none = Except.ok (some pending) at ran
      cases ran
    | some failureValue =>
      simp only [failure] at ran
      change Except.error (Promote.Error.host failureValue) = Except.ok (some pending) at ran
      cases ran
  have queried := PromotionReads.scan_rows tx db state opened origin "pending" scan
    (congrArg Prod.fst scanned)
  have queryNonempty : query db "heads" History.headColumns
      [("origin_id", .text (Origin.canonical origin)), ("slot", .text "pending")]
      [] History.headJoin ≠ [] := by
    rw [← queried]
    exact scanNonempty
  obtain ⟨projected, member⟩ := List.exists_mem_of_ne_nil _ queryNonempty
  rw [ReconciliationRead.slot_query] at member
  obtain ⟨joined, selected, _⟩ := List.mem_map.mp member
  obtain ⟨joinedMember, named⟩ := List.mem_filter.mp selected
  obtain ⟨row, rowMember, historyMember⟩ := List.mem_flatMap.mp joinedMember
  obtain ⟨history, _, rfl⟩ := List.mem_map.mp historyMember
  rw [ReconciliationRead.joined_names] at named
  exact ⟨row, rowMember, named⟩

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

/-- The pending candidate returned by actual preparation is represented by
the promotion-start view. This does not require the complete slot to be empty;
ordinary upgrades may retain the previous complete version. -/
theorem ready_observes_pending
    (ready : PromotionProgress.Ready origin now refused state)
    (stable : StableSlots state (Origin.canonical origin) latest view) :
    ∃ version, view (Origin.canonical origin) .pending = some version ∧
      ready.pending.head.seq = version.seq ∧ ready.pending.head.root = version.root := by
  have rawBegin := OperationExecution.raise_success (fun _ _ => rfl)
    Promote.Error.host Storage.begin state ready.opened ready.tx ready.began
  have opened : ready.opened.pending = some (ready.tx, state.db) :=
    ReconciliationFloor.begin_pending state ready.opened ready.tx rawBegin
  have preparation := ready.preparation
  unfold PromotionCommand.prepare at preparation
  obtain ⟨scopeRead, afterScope, scopeRun, preparation⟩ :=
    TransactionSuccess.bind_success _ _ _ _ _ preparation
  have scopeFrame := PromotionReads.executed_pending _
    (PromotionReads.auth_only _
      (ReconciliationReadOnly.scope_only ready.tx origin)) _ _ _ scopeRun
  obtain ⟨authorityRead, afterAuthority, authorityRun, preparation⟩ :=
    TransactionSuccess.bind_success _ _ _ _ _ preparation
  have authorityFrame := PromotionReads.executed_pending _
    (PromotionReads.auth_only _
      (ReconciliationReadOnly.originAuthority_only ready.tx origin now)) _ _ _ authorityRun
  obtain ⟨pendingRead, afterPending, pendingRun, preparation⟩ :=
    TransactionSuccess.bind_success _ _ _ _ _ preparation
  cases pendingRead with
  | none => cases preparation
  | some current =>
    obtain ⟨oldRead, afterOld, oldRun, returned⟩ :=
      TransactionSuccess.bind_success _ _ _ _ _ preparation
    have same : (scopeRead, authorityRead, some current, oldRead) =
        (ready.scope, ready.authority, some ready.pending, ready.old) :=
      Except.ok.inj (congrArg Prod.fst returned)
    cases same
    have pendingSnapshot : afterAuthority.pending = some (ready.tx, state.db) := by
      rw [authorityFrame, scopeFrame, opened]
    obtain ⟨row, selected⟩ := slot_some_has_selected ready.tx origin afterAuthority
      state.db pendingSnapshot ready.pending (congrArg Prod.fst pendingRun)
    obtain ⟨version, observed, _⟩ := HeadView.selected_version stable.represents selected
    exact ⟨version, observed, ready_uses_observed_pending ready stable observed⟩

/-- A promotion opportunity that passes production's strict `newer` guard
selects its pending candidate even when an older complete version remains. -/
theorem ready_pending_is_selected
    (ready : PromotionProgress.Ready origin now refused state)
    (stable : StableSlots state (Origin.canonical origin) latest view) :
    ∃ version, selectedVersion view (Origin.canonical origin) = some version ∧
      ready.pending.head.seq = version.seq ∧ ready.pending.head.root = version.root := by
  obtain ⟨pendingVersion, pendingObserved, pendingSame⟩ :=
    ready_observes_pending ready stable
  cases completeObserved : view (Origin.canonical origin) .complete with
  | none =>
    refine ⟨pendingVersion, ?_, pendingSame⟩
    simp [selectedVersion, completeObserved, pendingObserved]
  | some completeVersion =>
    have rawBegin := OperationExecution.raise_success (fun _ _ => rfl)
      Promote.Error.host Storage.begin state ready.opened ready.tx ready.began
    have snapshot := ReconciliationFloor.begin_pending state ready.opened ready.tx rawBegin
    have stored := stable.backed (Origin.canonical origin) .complete completeVersion
      completeObserved
    have floors := PromotionCommand.prepare_floor ready.tx origin now ready.opened
      ready.prepared state.db snapshot completeVersion.seq.toInt64 completeVersion.root stored
      ready.scope ready.authority (some ready.pending) ready.old ready.preparation
    obtain ⟨_, previous, oldSome, previousSeq, previousRoot⟩ :=
      floors ready.pending rfl
    have previousSeq' : previous.head.seq = completeVersion.seq := by
      simpa using previousSeq
    have newerBool : Reconcile.newer ready.pending.head.seq ready.pending.head.root
        ⟨completeVersion.seq, completeVersion.root⟩ = true := by
      have guarded := ready.body.newer
      rw [oldSome] at guarded
      simp only [Option.any_some, previousSeq', previousRoot] at guarded
      cases newerEq : Reconcile.newer ready.pending.head.seq ready.pending.head.root
          ⟨completeVersion.seq, completeVersion.root⟩ with
      | false => simp [newerEq] at guarded
      | true => rfl
    have pendingNewer : pendingVersion.Newer completeVersion := by
      apply (HeadView.newer_iff pendingVersion completeVersion).mp
      simpa only [pendingSame.1, pendingSame.2] using newerBool
    have rankLess : versionRank completeVersion < versionRank pendingVersion :=
      versionRank_lt_of_newer completeVersion pendingVersion
        (stable.valid .complete completeVersion completeObserved)
        (stable.valid .pending pendingVersion pendingObserved) pendingNewer
    refine ⟨pendingVersion, ?_, pendingSame⟩
    simp [selectedVersion, completeObserved, pendingObserved, rankLess]

/-- Delivery of the stable greatest signed head and its actual acceptance fold
determine the later production promotion candidate. An older complete slot is
allowed; production's actual strict-newer guard makes pending the selection. -/
theorem ready_uses_delivered_latest
    (delivered : StableAdvertisementProgress.DeliveredLatest valid origin latestHead heads)
    (accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      initialState initialView initialSlots heads final state view)
    (initialBound : initial ≤ rank latestHead)
    (ready : PromotionProgress.Ready origin now refused state) :
    ready.pending.head.seq = latestHead.seq ∧
      ready.pending.head.root = latestHead.root := by
  have selected := StableAdvertisementProgress.actual_fold_selects_latest
    delivered accepted initialBound
  obtain ⟨version, readySelected, same⟩ :=
    ready_pending_is_selected ready accepted.final_stable
  have versionSame : version = ⟨latestHead.seq, latestHead.root⟩ :=
    Option.some.inj (readySelected.symm.trans selected)
  simpa only [versionSame] using same

/-- Fetch/retry work may separate acceptance from promotion. If M3's actual
slot observation keeps the same stable maximum, the later fresh preparation
still reads the delivered latest version from pending. -/
theorem ready_uses_delivered_latest_after_frames
    (delivered : StableAdvertisementProgress.DeliveredLatest valid origin latestHead heads)
    (accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      initialState initialView initialSlots heads final acceptedState acceptedView)
    (initialBound : initial ≤ rank latestHead)
    (laterSlots : StableSlots state (Origin.canonical origin) final view)
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
  obtain ⟨version, readySelected, same⟩ := ready_pending_is_selected ready laterSlots
  have versionSame : version = ⟨latestHead.seq, latestHead.root⟩ :=
    Option.some.inj (readySelected.symm.trans laterSelected)
  simpa only [versionSame] using same

/-- Actual delivery and acceptance determine the pending candidate; healthy
production promotion then establishes the aligned scenario view. Completeness
is still supplied through `Ready` here and is discharged from the actual
completion walk by the higher acquisition composition. -/
theorem actual_promotion_reaches
    (delivered : StableAdvertisementProgress.DeliveredLatest valid origin latestHead heads)
    (accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      initialState initialView initialSlots heads final state view)
    (initialBound : initial ≤ rank latestHead)
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
  have used := ready_uses_delivered_latest delivered accepted initialBound ready
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

/-- The full reachability theorem with fetch/retry frames between the
advertisement fold and the promotion transaction.  The later slot observation
is tied to the same stable maximum by M3, so no second acceptance or selected
version premise is needed at promotion time. -/
theorem actual_promotion_reaches_after_frames
    (delivered : StableAdvertisementProgress.DeliveredLatest valid origin latestHead heads)
    (accepted : ObservedAcceptanceFold (Origin.canonical origin) keep initial
      initialState initialView initialSlots heads final acceptedState acceptedView)
    (initialBound : initial ≤ rank latestHead)
    (laterSlots : StableSlots state (Origin.canonical origin) final view)
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
  have used := ready_uses_delivered_latest_after_frames delivered accepted initialBound
    laterSlots ready
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
