import Synchronicity.PermissionLifecycle
import Synchronicity.ScopeChangeAtomicity
import Synchronicity.TransactionSuccess
import Synchronicity.ReconciliationAcceptance

/-! A raw-host refinement witness for the production permission change.

The fixture is deliberately the smallest nontrivial foreign-origin domain: an
old complete target, a strictly newer pending target, old derived rows, a
delegated authority row and a redaction boundary.  Enlargement, narrowing and
revocation all execute the same production command.  The resulting raw
observations instantiate the common permission transition: the newer pending
target wins, while old completion and derived authorization disappear. -/
namespace Synchronicity.ScopeChangeRefinement
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
open SimulatedHost PermissionLifecycle

def effectiveScope (spaces : Option (List String)) : Trie.Serve.Scope :=
  spaces.map Authorization.readScope |>.getD Authorization.fullScope

/-- A successful production change together with the typed raw observations
returned by the exact demotion phases that committed. -/
structure Successful (spaces : Option (List String)) (now : Int64)
    (before after : SimulatedHost.State) (report : ScopeChange.ChangeReport) : Prop where
  detailed : execute (ScopeChange.changeDetailed spaces now) before = (.ok report, after)
  changed : report.changed = true

/-- The public Bool command loses no success provenance: a changed success is
the projection of one successful detailed execution with the same final host
state. -/
theorem successful_report (spaces : Option (List String)) (now : Int64)
    (before after : SimulatedHost.State)
    (ran : execute (ScopeChange.change spaces now) before = (.ok true, after)) :
    ∃ report, Successful spaces now before after report := by
  unfold ScopeChange.change at ran
  simp only [Functor.map, ExceptT.map, ExceptT.mk, bind, execute_bind] at ran
  generalize detailed : execute (ScopeChange.changeDetailed spaces now) before = result at ran
  obtain ⟨answer, final⟩ := result
  cases answer with
  | error error => cases ran
  | ok report =>
    have changed : report.changed = true := Except.ok.inj (congrArg Prod.fst ran)
    have same : final = after := congrArg Prod.snd ran
    subst final
    exact ⟨report, detailed, changed⟩

/-- Every foreign-origin item of an arbitrary successful report refines the
same domain permission transition. The conclusion is generic in complete and
pending versions, origin, old scope and generation; multi-origin reports are
covered pointwise by membership. -/
def ReportRefines (spaces : Option (List String)) (report : ScopeChange.ChangeReport) : Prop :=
  ∀ decision ∈ report.demotions, ∀ oldScope generation refusals,
    effectiveScope spaces ≠ oldScope →
    let before := ofDemotion oldScope generation refusals decision
    let after := PermissionLifecycle.change before (effectiveScope spaces)
    InvalidatesOld before after (effectiveScope spaces) ∧
      after.pending = some (ofPointer decision.selected)

theorem successful_change_refines (execution : Successful spaces now rawBefore rawAfter report) :
    ReportRefines spaces report := by
  cases execution
  intro decision _ oldScope generation refusals changed
  exact ⟨change_invalidates _ _, production_demotion_retains_max
    decision oldScope (effectiveScope spaces) generation refusals changed⟩

/-- Raw rows which can authorize or suppress work for one demoted foreign
origin. The pending projection is a singleton, so it states existence,
uniqueness, selected version and refreshed timestamp together. -/
def RawOriginInvalidated (decision : ScopeChange.Demotion) (now : Int64) (db : Database) : Prop :=
  let origin := decision.complete.origin
  query db "heads" ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
    [("origin_id", .text origin), ("slot", .text "complete")] [] [] = [] ∧
  query db "heads" ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
    [("origin_id", .text origin), ("slot", .text "pending")] [] [] =
      [decision.pendingRow now] ∧
  (rows db "entries").any (fun row => equals row [("origin_id", .text origin)]) = false ∧
  (rows db "blob_providers").any (fun row => equals row [("origin_id", .text origin)]) = false ∧
  (rows db "bindings").any (fun row =>
    equals row [("source", .text "delegated"), ("issuer", .text origin)]) = false

def RedactionsCleared (db : Database) : Prop :=
  (rows db "redacted_nodes").any (fun row => equals row []) = false

def RawInvalidated (decision : ScopeChange.Demotion) (now : Int64) (db : Database) : Prop :=
  RawOriginInvalidated decision now db ∧ RedactionsCleared db

set_option linter.unusedSimpArgs false in
theorem verifyDemotion_accepts_iff_raw (tx : Transaction)
    (decision : ScopeChange.Demotion) (now : Int64)
    (state : SimulatedHost.State) (db : Database)
    (opened : state.pending = some (tx, db)) (healthy : state.faults = []) :
    (execute (ScopeChange.verifyDemotion tx decision now) state).1 = .ok () ↔
      RawOriginInvalidated decision now db := by
  simp [ScopeChange.verifyDemotion, ScopeChange.verifyAbsent, History.request, raise,
    performOver, Inject.inject, ExceptT.mk, execute, Interpreter.handle, SimulatedHost.storage,
    SimulatedHost.reply, SimulatedHost.fault, healthy, opened, SimulatedHost.record,
    SimulatedHost.transaction, bind, ExceptT.bind, ExceptT.bindCont, pure, ExceptT.pure,
    Program.bind, Except.mapError, RawOriginInvalidated, throw, throwThe, MonadExcept.throw,
    MonadExceptOf.throw, instMonadExceptOfExceptTOfMonad]
  all_goals
    repeat' first
      | split
      | simp_all [execute, Interpreter.handle, SimulatedHost.storage, SimulatedHost.reply,
          SimulatedHost.fault, healthy, opened, SimulatedHost.record,
          SimulatedHost.transaction, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk,
          Program.bind, Except.mapError, History.request, raise, performOver, Inject.inject,
          throw, throwThe, MonadExcept.throw, MonadExceptOf.throw,
          instMonadExceptOfExceptTOfMonad, pure, ExceptT.pure, Program.pure]
  all_goals grind

theorem verifyRequest_only (effect : Storage (Reply A))
    (allowed : ReconciliationReadOnly.storageAllowed effect) :
    PrivateDatabase.Only ReconciliationReadOnly.allowed (History.request effect).run :=
  PrivateDatabase.Only.raise History.Error.host effect allowed

theorem verifyAbsent_only (tx : Transaction) (relation : String) (fields : Fields) :
    PrivateDatabase.Only ReconciliationReadOnly.allowed
      (ScopeChange.verifyAbsent tx relation fields).run := by
  unfold ScopeChange.verifyAbsent
  exact (verifyRequest_only (.existsRows tx relation fields) trivial).seq fun found => by
    split <;> exact .done _

theorem verifyDemotion_only (tx : Transaction) (decision : ScopeChange.Demotion) (now : Int64) :
    PrivateDatabase.Only ReconciliationReadOnly.allowed
      (ScopeChange.verifyDemotion tx decision now).run := by
  unfold ScopeChange.verifyDemotion
  refine (verifyRequest_only (.readRows tx "heads"
    ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
    [("origin_id", .text decision.complete.origin), ("slot", .text "complete")] [] []) trivial).seq
      fun complete => ?_
  split
  · exact .done _
  · refine (verifyRequest_only (.readRows tx "heads"
      ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
      [("origin_id", .text decision.complete.origin), ("slot", .text "pending")] [] []) trivial).seq
        fun pending => ?_
    split
    · exact .done _
    · exact (verifyAbsent_only tx "entries" _).seq fun _ =>
        (verifyAbsent_only tx "blob_providers" _).seq fun _ =>
        verifyAbsent_only tx "bindings" _

theorem verifyDemotions_only (tx : Transaction) (now : Int64)
    (decisions : List ScopeChange.Demotion) :
    PrivateDatabase.Only ReconciliationReadOnly.allowed
      (ScopeChange.verifyDemotions tx now decisions).run := by
  induction decisions with
  | nil => exact .done _
  | cons decision rest ih =>
    exact (verifyDemotion_only tx decision now).seq fun _ => ih

theorem verifyAll_only (tx : Transaction) (now : Int64)
    (decisions : List ScopeChange.Demotion) :
    PrivateDatabase.Only ReconciliationReadOnly.allowed
      (ScopeChange.verifyAll tx now decisions).run := by
  unfold ScopeChange.verifyAll
  exact (verifyAbsent_only tx "redacted_nodes" []).seq fun _ =>
    verifyDemotions_only tx now decisions

private theorem reply_preserves_faults (state : SimulatedHost.State) (event : String)
    (action : SimulatedHost.State → SimulatedHost.Result (Reply A)) (consume : Bool)
    (kept : ∀ current, (action current).2.faults = current.faults) :
    (SimulatedHost.reply state event action consume).2.faults = state.faults := by
  unfold SimulatedHost.reply
  split
  · cases consume <;> simp [SimulatedHost.record, kept]
  · simp [SimulatedHost.record, kept]

private theorem transaction_preserves_faults (state : SimulatedHost.State)
    (tx : Transaction) (action : Database → A × Database) :
    (SimulatedHost.transaction state tx action).2.faults = state.faults := by
  unfold SimulatedHost.transaction
  split
  · split <;> rfl
  · rfl

private theorem storage_preserves_faults (effect : Storage A)
    (state : SimulatedHost.State) :
    (SimulatedHost.storage effect state).2.faults = state.faults := by
  cases effect <;> simp only [SimulatedHost.storage]
  all_goals apply reply_preserves_faults
  all_goals intro current
  all_goals repeat' first | rfl | exact transaction_preserves_faults .. | split

private theorem history_effect_preserves_faults (effect : History.Effects A)
    (state : SimulatedHost.State) :
    (Interpreter.handle effect state).2.faults = state.faults := by
  cases effect with
  | left effect => exact storage_preserves_faults effect state
  | right effect =>
    cases effect <;> simp only [Interpreter.handle, SimulatedHost.crypto] <;>
      apply reply_preserves_faults <;> intro current <;> rfl

private theorem all_effects (program : Program History.Effects A) :
    PrivateDatabase.Only (fun _ _ => True) program := by
  induction program with
  | pure value => exact .done value
  | request effect next ih => exact .request trivial ih

theorem history_execution_preserves_faults (operation : History.Action A)
    (state : SimulatedHost.State) :
    (execute operation state).2.faults = state.faults := by
  exact (all_effects operation.run).preserves_observation State.faults _
    (fun effect _ => history_effect_preserves_faults effect) state

theorem verification_execution_preserves (operation : History.Action A)
    (only : PrivateDatabase.Only ReconciliationReadOnly.allowed operation.run)
    (state : SimulatedHost.State) :
    (execute operation state).2.pending = state.pending ∧
      (execute operation state).2.faults = state.faults := by
  exact ⟨only.preserves_observation State.pending _
      ReconciliationReadOnly.effects_pending state,
    only.preserves_observation State.faults _
      (fun effect _ => history_effect_preserves_faults effect) state⟩

theorem verifyDemotions_member_raw (tx : Transaction) (now : Int64)
    (decisions : List ScopeChange.Demotion) (state final : SimulatedHost.State)
    (db : Database) (opened : state.pending = some (tx, db))
    (healthy : state.faults = [])
    (ran : execute (ScopeChange.verifyDemotions tx now decisions) state = (.ok (), final))
    (member : decision ∈ decisions) : RawOriginInvalidated decision now db := by
  induction decisions generalizing state db with
  | nil => cases member
  | cons head rest ih =>
    simp only [ScopeChange.verifyDemotions] at ran
    obtain ⟨_, middle, checked, tail⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
    have frame := verification_execution_preserves _ (verifyDemotion_only tx head now) state
    rw [checked] at frame
    have middleOpened : middle.pending = some (tx, db) := frame.1.trans opened
    have middleHealthy : middle.faults = [] := frame.2.trans healthy
    rcases List.mem_cons.mp member with same | later
    · subst decision
      exact (verifyDemotion_accepts_iff_raw tx head now state db opened healthy).mp
        (congrArg Prod.fst checked)
    · exact ih middle db middleOpened middleHealthy tail later

set_option linter.unusedSimpArgs false in
theorem verifyAbsent_accepts_iff (tx : Transaction) (relation : String) (fields : Fields)
    (state : SimulatedHost.State) (db : Database)
    (opened : state.pending = some (tx, db)) (healthy : state.faults = []) :
    (execute (ScopeChange.verifyAbsent tx relation fields) state).1 = .ok () ↔
      (rows db relation).any (fun row => equals row fields) = false := by
  simp [ScopeChange.verifyAbsent, History.request, raise, performOver, Inject.inject,
    ExceptT.mk, execute, Interpreter.handle, SimulatedHost.storage, SimulatedHost.reply,
    SimulatedHost.fault, healthy, opened, SimulatedHost.record, SimulatedHost.transaction,
    bind, ExceptT.bind, ExceptT.bindCont, pure, ExceptT.pure, Program.pure, Program.bind,
    Except.mapError, throw, throwThe, MonadExcept.throw, MonadExceptOf.throw,
    instMonadExceptOfExceptTOfMonad]
  all_goals
    repeat' first
      | split
      | simp_all [execute, pure, ExceptT.pure, Program.pure, ExceptT.mk]
  all_goals grind

theorem verifyAll_member_raw (tx : Transaction) (now : Int64)
    (decisions : List ScopeChange.Demotion) (state final : SimulatedHost.State)
    (db : Database) (opened : state.pending = some (tx, db))
    (healthy : state.faults = [])
    (ran : execute (ScopeChange.verifyAll tx now decisions) state = (.ok (), final))
    (member : decision ∈ decisions) : RawInvalidated decision now db := by
  unfold ScopeChange.verifyAll at ran
  obtain ⟨_, middle, redactions, checked⟩ :=
    TransactionSuccess.bind_success _ _ _ _ _ ran
  have frame := verification_execution_preserves _
    (verifyAbsent_only tx "redacted_nodes" []) state
  rw [redactions] at frame
  have middleOpened : middle.pending = some (tx, db) := frame.1.trans opened
  have middleHealthy : middle.faults = [] := frame.2.trans healthy
  refine ⟨verifyDemotions_member_raw tx now decisions middle final db
      middleOpened middleHealthy checked member, ?_⟩
  exact (verifyAbsent_accepts_iff tx "redacted_nodes" [] state db opened healthy).mp
    (congrArg Prod.fst redactions)

/-- The typed decision in a successful report came from the command's actual
own-origin, complete-slot and pending-slot reads, in that order. -/
structure DecisionSource (spaces : Option (List String))
    (decision : ScopeChange.Demotion) where
  tx : Transaction
  beforeCurrent : SimulatedHost.State
  current : Option (List String)
  beforeOwn : SimulatedHost.State
  afterOwn : SimulatedHost.State
  afterComplete : SimulatedHost.State
  afterPending : SimulatedHost.State
  own : Option Origin.Parsed
  complete : List ScopeChange.Stored
  pending : List ScopeChange.Stored
  currentRead : execute (within Reconcile.authorizationError
    (Authorization.localSpacesIn tx) : History.Action (Option (List String))) beforeCurrent =
      (.ok current, beforeOwn)
  changed : current ≠ spaces
  ownRead : execute (within Reconcile.authorizationError
    (Authorization.ownOrigin tx) : History.Action (Option Origin.Parsed)) beforeOwn =
      (.ok own, afterOwn)
  completeRead : execute (ScopeChange.allSlot tx "complete") afterOwn =
    (.ok complete, afterComplete)
  pendingRead : execute (ScopeChange.allSlot tx "pending") afterComplete =
    (.ok pending, afterPending)
  selected : decision ∈ complete.filterMap
    (ScopeChange.decision (own.map Origin.canonical) pending)

/-- A changed production command connects its actual typed source reads to
the committed raw postcondition, for every reported foreign origin. This is
pointwise and therefore covers arbitrary multi-origin reports. -/
theorem successful_change_raw (production : Successful spaces now rawBefore rawAfter report)
    (quiet : rawBefore.faults = []) (reported : decision ∈ report.demotions) :
    ∃ _ : DecisionSource spaces decision, RawInvalidated decision now rawAfter.db := by
  rcases production with ⟨detailed, changed⟩
  unfold ScopeChange.changeDetailed at detailed
  obtain ⟨tx, opened, finished, began, body, committed, published⟩ :=
    TransactionSuccess.transaction_success Inject.inject History.Error.host _ rawBefore report
      (congrArg Prod.fst detailed)
  obtain ⟨current, afterCurrent, currentRead, body⟩ :=
    TransactionSuccess.bind_success _ _ _ _ _ body
  split at body <;> rename_i currentMatches
  · change (Except.ok ⟨false, []⟩, afterCurrent) =
        (Except.ok report, finished) at body
    have reportSame : report = ⟨false, []⟩ :=
      (Except.ok.inj (congrArg Prod.fst body)).symm
    subst report
    cases changed
  · obtain ⟨own, afterOwn, ownRead, body⟩ :=
      TransactionSuccess.bind_success _ _ _ _ _ body
    obtain ⟨complete, afterComplete, completeRead, body⟩ :=
      TransactionSuccess.bind_success _ _ _ _ _ body
    obtain ⟨pending, afterPending, pendingRead, body⟩ :=
      TransactionSuccess.bind_success _ _ _ _ _ body
    obtain ⟨_, afterScope, scopeWrite, body⟩ :=
      TransactionSuccess.bind_success _ _ _ _ _ body
    obtain ⟨_, afterRedacted, redactedErase, body⟩ :=
      TransactionSuccess.bind_success _ _ _ _ _ body
    let demotions := complete.filterMap
      (ScopeChange.decision (own.map Origin.canonical) pending)
    obtain ⟨_, afterDemotions, demoted, body⟩ :=
      TransactionSuccess.bind_success _ _ _ _ _ body
    obtain ⟨_, beforeVerify, refreshed, body⟩ :=
      TransactionSuccess.bind_success _ _ _ _ _ body
    obtain ⟨_, afterVerify, verified, returned⟩ :=
      TransactionSuccess.bind_success _ _ _ _ _ body
    change (Except.ok ⟨true, demotions⟩, afterVerify) =
      (Except.ok report, finished) at returned
    have reportSame : report = ⟨true, demotions⟩ := by
      exact (Except.ok.inj (congrArg Prod.fst returned)).symm
    have finishedSame : finished = afterVerify := by
      exact (congrArg Prod.snd returned).symm
    have selected : decision ∈ demotions := by
      rw [reportSame] at reported
      exact reported
    have configChanged : current ≠ spaces := by
      intro same
      subst spaces
      simp at currentMatches
    have openedHealthy : opened.faults = [] := by
      have frame := storage_preserves_faults Storage.begin rawBefore
      have beganRaw : storage Storage.begin rawBefore = (.ok tx, opened) := began
      rw [beganRaw] at frame
      exact frame.trans quiet
    have currentHealthy : afterCurrent.faults = [] := by
      have frame := history_execution_preserves_faults
        (within Reconcile.authorizationError
          (Authorization.localSpacesIn tx) : History.Action (Option (List String))) opened
      rw [currentRead] at frame
      exact frame.trans openedHealthy
    have ownHealthy : afterOwn.faults = [] := by
      have frame := history_execution_preserves_faults
        (within Reconcile.authorizationError
          (Authorization.ownOrigin tx) : History.Action (Option Origin.Parsed)) afterCurrent
      rw [ownRead] at frame
      exact frame.trans currentHealthy
    have completeHealthy : afterComplete.faults = [] := by
      have frame := history_execution_preserves_faults
        (ScopeChange.allSlot tx "complete") afterOwn
      rw [completeRead] at frame
      exact frame.trans ownHealthy
    have pendingHealthy : afterPending.faults = [] := by
      have frame := history_execution_preserves_faults
        (ScopeChange.allSlot tx "pending") afterComplete
      rw [pendingRead] at frame
      exact frame.trans completeHealthy
    have scopeHealthy : afterScope.faults = [] := by
      have frame := history_execution_preserves_faults
        (ScopeChange.writeScope tx spaces) afterPending
      rw [scopeWrite] at frame
      exact frame.trans pendingHealthy
    have redactedHealthy : afterRedacted.faults = [] := by
      have frame := history_execution_preserves_faults
        (History.request (.deleteRows tx "redacted_nodes" [])) afterScope
      rw [redactedErase] at frame
      exact frame.trans scopeHealthy
    have demotedHealthy : afterDemotions.faults = [] := by
      have frame := history_execution_preserves_faults
        (ScopeChange.demoteAll tx now demotions) afterRedacted
      rw [demoted] at frame
      exact frame.trans redactedHealthy
    have verifyHealthy : beforeVerify.faults = [] := by
      have frame := history_execution_preserves_faults
        (ScopeChange.refreshAll tx (own.map Origin.canonical) demotions now pending)
          afterDemotions
      rw [refreshed] at frame
      exact frame.trans demotedHealthy
    subst finished
    obtain ⟨db, staged, installed⟩ :=
      ReconciliationAcceptance.commit_installs tx afterVerify committed
    have verifyFrame := verification_execution_preserves _
      (verifyAll_only tx now demotions) beforeVerify
    rw [verified] at verifyFrame
    have beforeVerifyOpened : beforeVerify.pending = some (tx, db) :=
      verifyFrame.1.symm.trans staged
    have raw := verifyAll_member_raw tx now demotions beforeVerify afterVerify db
      beforeVerifyOpened verifyHealthy verified selected
    have finalCommand : rawAfter = (storage (.commit tx) afterVerify).2 :=
      (congrArg Prod.snd detailed).symm.trans published
    have databaseSame : rawAfter.db = db := by
      rw [finalCommand, installed]
    refine ⟨⟨tx, opened, current, afterCurrent, afterOwn, afterComplete, afterPending,
      own, complete, pending, currentRead, configChanged, ownRead, completeRead, pendingRead,
      selected⟩, ?_⟩
    rw [databaseSame]
    exact raw

end Synchronicity.ScopeChangeRefinement
