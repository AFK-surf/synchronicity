import Synchronicity.PromotionCommittedView

/-! Refusals and obsolete/waiting results do not replace the public view.
Retiring pending bookkeeping is distinct from publishing entries or holds. -/
namespace Synchronicity.PromotionPublicFrame
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands Replication SimulatedHost PrivateDatabase
open AtomicFileView

def pendingView (origin : String) (state : State) :=
  state.pending.map fun (tx, db) => (tx, projection origin db)

theorem pending_key (origin : String) (row : Fields) (key : Fields)
    (pending : ("slot", .text "pending") ∈ key)
    (named : ReconciliationSlots.names row origin "complete" = true) : equals row key = false := by
  have notPending := PromotionBound.complete_not_pending row origin named origin
  by_cases selected : equals row key = true
  · have slot := List.all_eq_true.mp selected ("slot", .text "pending") pending
    have parts : isCell (cell row "origin_id") (.text origin) = true ∧ isCell (cell row "slot") (.text "complete") = true := by
      simpa only [ReconciliationSlots.names, equals, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] using named
    have both : ReconciliationSlots.names row origin "pending" = true := by
      simpa only [ReconciliationSlots.names, equals, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] using
        And.intro parts.1 slot
    change equals row [("origin_id", .text origin), ("slot", .text "pending")] = true at both
    rw [notPending] at both
    cases both
  · exact Bool.eq_false_iff.mpr selected

theorem erase_projection (origin : String) (db : Database) (key : Fields)
    (pending : ("slot", .text "pending") ∈ key) :
    projection origin (MaterializationSql.erased db "heads" key) = projection origin db := by
  simp only [projection, MaterializationSql.erased, rows_setRows,
    rows_setRows_other _ _ _ _ (by decide : "heads" ≠ "entries"),
    rows_setRows_other _ _ _ _ (by decide : "heads" ≠ "pins"),
    rows_setRows_other _ _ _ _ (by decide : "heads" ≠ "content_want"), List.filter_filter]
  congr 3
  apply List.filter_congr
  intro row member
  by_cases named : ReconciliationSlots.names row origin "complete" = true
  · rw [pending_key origin row key pending named]
    simp only [Bool.not_false, Bool.and_true]
  · have no : ReconciliationSlots.names row origin "complete" = false := Bool.eq_false_iff.mpr named
    change (ReconciliationSlots.names row origin "complete" && !equals row key) = ReconciliationSlots.names row origin "complete"
    rw [no, Bool.false_and]

theorem delete_frame (origin : String) (tx : Transaction) (key : Fields)
    (pending : ("slot", .text "pending") ∈ key) (state : State) :
    pendingView origin (storage (.deleteRows tx "heads" key) state).2 = pendingView origin state := by
  simp only [storage, reply]
  split
  · rfl
  · unfold SimulatedHost.transaction
    split
    · rename_i token db opened
      split
      · simp only [pendingView, record, opened, Option.map_some]
        congr 1
        apply congrArg (fun value => (token, value))
        simpa only [MaterializationSql.erased, deletable, excluded, due, List.any_nil, List.all_nil,
          Bool.not_false, Bool.and_true] using erase_projection origin db key pending
      · rfl
    · rfl

theorem clear_frame (publicOrigin : String) (tx : Transaction) (origin : Origin.Parsed) (state : State) :
    pendingView publicOrigin (execute (Promote.clear tx origin) state).2 = pendingView publicOrigin state := by
  have safe : Only (fun _ (effect : Promote.Effects _) => ∀ s,
      pendingView publicOrigin (Interpreter.handle effect s).2 = pendingView publicOrigin s)
      (Promote.clear tx origin).run := by
    apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
    exact delete_frame publicOrigin tx _ (by simp)
  exact safe.preserves_observation (pendingView publicOrigin) _ (fun _ good => good) state

theorem read_frame (origin : String) (operation : Promote.Action A) (safe : Only PromotionReads.allowed operation.run)
    (state final : State) (answer : A) (ran : execute operation state = (.ok answer, final)) :
    pendingView origin final = pendingView origin state := by
  unfold pendingView
  rw [PromotionReads.executed_pending operation safe state final answer ran]

theorem retire_success (origin : String) (candidate : Promote.Pending) (state final : State)
    (ran : execute (Promote.retire candidate) state = (.ok (), final)) :
    projection origin final.db = projection origin state.db := by
  obtain ⟨tx, opened, finished, began, body, commit, result⟩ := TransactionSuccess.transaction_success
    Inject.inject Promote.Error.host _ state () (congrArg Prod.fst ran)
  have began : storage .begin state = (.ok tx, opened) := began
  have snapshot := ReconciliationFloor.begin_pending state opened tx began
  have safe : Only (fun _ (effect : Promote.Effects _) => ∀ s,
      pendingView origin (Interpreter.handle effect s).2 = pendingView origin s)
      (do let _ ← Promote.raw (.deleteRows tx "heads"
        (Reconcile.headKey candidate.head ++ [("slot", .text "pending")])) : Promote.Action Unit).run :=
    Only.seq (Only.raise _ _ (delete_frame origin tx _ (by simp))) fun _ => .done _
  have frame := safe.preserves_observation (pendingView origin) _ (fun _ good => good) opened
  change pendingView origin (execute (do let _ ← Promote.raw (.deleteRows tx "heads"
    (Reconcile.headKey candidate.head ++ [("slot", .text "pending")])) : Promote.Action Unit) opened).2 = pendingView origin opened at frame
  rw [body] at frame
  have commit : (storage (.commit tx) finished).1 = .ok () := commit
  obtain ⟨db, staged, committed⟩ := ReconciliationAcceptance.commit_installs tx finished commit
  have same : projection origin db = projection origin state.db := by
    simpa only [pendingView, staged, snapshot, Option.map_some, Option.some.injEq, Prod.mk.injEq, true_and] using frame
  have finalState : final = (storage (.commit tx) finished).2 := by
    change (execute (Promote.retire candidate) state).2 = (storage (.commit tx) finished).2 at result
    simpa only [ran] using result
  rw [finalState, committed]
  exact same

theorem retire_frame (origin : String) (candidate : Promote.Pending) (state : State) :
    projection origin (execute (Promote.retire candidate) state).2.db = projection origin state.db := by
  cases ran : execute (Promote.retire candidate) state with
  | mk answer final =>
    cases answer with
    | ok value => cases value; exact retire_success origin candidate state final ran
    | error failure =>
      have same := PromotionPublication.retire_failure candidate state failure (congrArg Prod.fst ran)
      rw [ran] at same
      rw [same]

theorem clear_return_frame (publicOrigin : String) (tx : Transaction) (origin : Origin.Parsed)
    (value answer : A) (state final : State)
    (ran : execute (do Promote.clear tx origin; pure value : Promote.Action A) state = (.ok answer, final)) :
    pendingView publicOrigin final = pendingView publicOrigin state := by
  obtain ⟨_, cleared, erased, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  have same : cleared = final := congrArg Prod.snd returned
  subst cleared
  have frame := clear_frame publicOrigin tx origin state
  simpa only [erased] using frame

theorem body_no_flip (publicOrigin : String) (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending : Promote.Pending) (old : Option Promote.Pending) (scope : Trie.Serve.Scope)
    (authority : Authorization.OriginAuthority) (state final : State) (answer : Promotion)
    (notFlipped : answer ≠ .flipped)
    (ran : execute (Promote.body tx origin now pending old scope authority) state = (.ok answer, final)) :
    pendingView publicOrigin final = pendingView publicOrigin state := by
  unfold Promote.body at ran
  split at ran
  · exact clear_return_frame publicOrigin tx origin _ _ state final ran
  · obtain ⟨complete, checked, checkedRun, ran⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
    have checkedFrame := read_frame publicOrigin _ (PromotionReads.complete_only tx _ _) state checked complete checkedRun
    cases complete with
    | false =>
      have same : checked = final := congrArg Prod.snd ran
      exact same ▸ checkedFrame
    | true =>
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte] at ran
      cases publication : authority.publication <;> simp only [publication] at ran
      all_goals
        obtain ⟨allowed, authorized, authorizedRun, ran⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
        have authorizedFrame : pendingView publicOrigin authorized = pendingView publicOrigin checked := by
          first
          | exact congrArg (fun result => pendingView publicOrigin result.2) authorizedRun.symm
          | exact read_frame publicOrigin _ (Only.map _ _ (PromotionReads.scopeCheck_only tx _ _)) checked authorized allowed authorizedRun
        cases allowed with
        | false =>
          exact (clear_return_frame publicOrigin tx origin _ _ authorized final ran).trans (authorizedFrame.trans checkedFrame)
        | true =>
          simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte] at ran
          obtain ⟨_, _, _, ran⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
          obtain ⟨_, _, _, ran⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
          obtain ⟨_, _, _, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
          exact False.elim (notFlipped (Except.ok.inj (congrArg Prod.fst returned)).symm)

end Synchronicity.PromotionPublicFrame
