import Synchronicity.AcceptanceProtection
import Synchronicity.AcceptanceProgress
import Synchronicity.ReconciliationExecution

/-! Upper bounds for the two production head slots.

The bound is an invariant of raw `heads` rows.  The only ordinary command which
can introduce a new version is `Reconcile.accept`; its candidate is visible in
the enclosing reconciliation event.  Other commands are handled through their
actual no-new-key certificates, or by promotion's pending-to-complete move. -/
namespace Synchronicity.StableHeadBounds
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def RowBound (origin : String) (latest : Nat) (table : List Fields) : Prop :=
  ∀ row ∈ table, ∀ slot version,
    ReconciliationSlots.names row origin (HeadView.slotName slot) = true →
    HeadView.points row version → AcceptanceProgress.versionRank version ≤ latest

theorem of_view (represented : HeadView.Represents db view)
    (bounded : ∀ slot version, view origin slot = some version →
      AcceptanceProgress.versionRank version ≤ latest) :
    RowBound origin latest (rows db "heads") := by
  intro row member slot version named points
  obtain ⟨actual, observed, actualPoints⟩ :=
    HeadView.selected_version represented ⟨member, named⟩
  have same := HeadView.version_unique row actual version actualPoints points
  subst actual
  exact bounded slot version observed

theorem to_view (represented : HeadView.Represents db view)
    (bounded : RowBound origin latest (rows db "heads")) :
    ∀ slot version, view origin slot = some version →
      AcceptanceProgress.versionRank version ≤ latest := by
  intro slot version observed
  obtain ⟨row, selected, points⟩ := HeadView.existing represented observed
  exact bounded row selected.1 slot version selected.2 points

theorem of_no_new_keys {state final : State}
    (before : RowBound origin latest (rows state.db "heads"))
    (noNew : ∀ row ∈ rows final.db "heads",
      ∃ old ∈ rows state.db "heads", HeadKeyFrame.key row = HeadKeyFrame.key old) :
    RowBound origin latest (rows final.db "heads") := by
  intro row member slot version named points
  obtain ⟨old, oldMember, same⟩ := noNew row member
  have oldNamed : ReconciliationSlots.names old origin (HeadView.slotName slot) = true := by
    rw [← HeadView.key_named same]
    exact named
  exact before old oldMember slot version oldNamed (HeadView.key_points same.symm points)

private def accepts (origin : String) (latest : Nat) (table : List Fields) : Prop :=
  RowBound origin latest table

private def safe (origin : String) (latest : Nat) :=
  HeadInvariant.effectSafe (E := History.Effects) (accepts origin latest)

private theorem framed (origin : String) (latest : Nat) (operation : History.Action A)
    (frame : Only ReconciliationFrame.allowed operation.run) :
    Only (safe origin latest) operation.run := by
  apply frame.mono
  intro B effect good state initial
  cases effect with
  | left effect =>
      have privateEffect : storagePrivate effect := by
        cases effect <;> first | contradiction | trivial
      exact HeadInvariant.unchanged _ state _
        (congrArg (fun db => rows db "heads")
          (storage_preserves_db effect privateEffect state))
        (ReconciliationFrame.storage_frame effect good state) initial
  | right effect =>
      cases effect <;>
        apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;>
        intro s h <;> exact h

private theorem upsert_pending (origin : String) (latest : Nat) (head : Head)
    (candidateBound : Origin.canonical head.origin = origin →
      AcceptanceProgress.rank head ≤ latest)
    (received verified : Int64) (table : List Fields)
    (initial : RowBound origin latest table) :
    RowBound origin latest
      (upsertRows table (ReconciliationSlots.incoming head "pending" received verified)
        ["origin_id", "slot"]
        ((ReconciliationSlots.updates "pending").map fun column =>
          (column, .excluded column))) := by
  intro row member slot version named points
  have candidateCase
      (targetNamed : ReconciliationSlots.names row
        (Origin.canonical head.origin) "pending" = true) :
      AcceptanceProgress.versionRank version ≤ latest := by
    have installed := ReconciliationSlots.upsert_installs_candidate table head "pending"
      received verified row member targetNamed
    have same : version = ⟨head.seq, head.root⟩ :=
      HeadView.version_unique row version ⟨head.seq, head.root⟩ points installed
    have sameOrigin : Origin.canonical head.origin = origin :=
      (HeadView.text_unique _ origin (Origin.canonical head.origin)
        (HeadView.named_fields named).1 (HeadView.named_fields targetNamed).1).symm
    subst version
    exact candidateBound sameOrigin
  unfold upsertRows at member
  split at member
  · obtain ⟨old, oldMember, changed⟩ := List.mem_map.mp member
    split at changed
    · subst row
      apply candidateCase
      have oldSelected : ReconciliationSlots.names old
          (Origin.canonical head.origin) "pending" = true := by
        rwa [← ReconciliationSlots.conflicts_iff_names]
      simpa [List.map_map, Function.comp_def] using
        ReconciliationSlots.assigned_names head "pending" received verified old
          (Origin.canonical head.origin) "pending" |>.trans oldSelected
    · subst old
      exact initial row oldMember slot version named points
  · rcases List.mem_append.mp member with old | new
    · exact initial row old slot version named points
    · have same := List.mem_singleton.mp new
      subst row
      apply candidateCase
      simp [ReconciliationSlots.names, ReconciliationSlots.incoming,
        Reconcile.headKey, equals, cell, equalCell]

private theorem put_pending_only (origin : String) (latest : Nat) (tx : Transaction)
    (head : Head) (candidateBound : Origin.canonical head.origin = origin →
      AcceptanceProgress.rank head ≤ latest) (now : Int64) :
    Only (safe origin latest) (Reconcile.putSlot tx "pending" head now now).run := by
  unfold Reconcile.putSlot
  apply Only.seq
  · exact framed origin latest _ (ReconciliationFrame.record_only tx head now)
  · intro _
    apply Only.raise
    intro state initial
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    apply HeadInvariant.transaction_holds _ _ _ _ _ h
    intro db prior
    rw [rows_setRows]
    exact upsert_pending origin latest head candidateBound now now _ prior

private theorem accept_only (origin : String) (latest : Nat) (head : Head)
    (candidateBound : Origin.canonical head.origin = origin →
      AcceptanceProgress.rank head ≤ latest) (now : Int64) (keep : Nat) :
    Only (safe origin latest) (Reconcile.accept head now keep).run := by
  unfold Reconcile.accept
  refine Only.seq (framed origin latest _ (Only.raise _ _ trivial)) fun valid => ?_
  split
  · exact .done _
  · apply Only.transaction _ _ _
      (HeadInvariant.begin_holds _) (HeadInvariant.commit_holds _)
      (HeadInvariant.rollback_holds _)
    intro tx
    refine (framed origin latest _
      (ReconciliationFrame.auth_only _
        (ReconciliationFrame.trustInstant_only tx now))).seq fun instant => ?_
    refine (framed origin latest _
      (ReconciliationFrame.auth_only _
        (ReconciliationFrame.liveForKey_only tx head.signedBy instant))).seq fun live => ?_
    split
    · exact .done _
    · refine (framed origin latest _
        (ReconciliationFrame.record_only tx head now)).seq fun _ => ?_
      refine (framed origin latest _
        (ReconciliationFrame.readSlot_only tx _ "complete")).seq fun complete => ?_
      refine (framed origin latest _
        (ReconciliationFrame.readSlot_only tx _ "pending")).seq fun pending => ?_
      dsimp only
      split
      · exact (put_pending_only origin latest tx head candidateBound now).seq
          fun _ => (framed origin latest _
            (ReconciliationFrame.trimForks_only tx _ head.seq keep)).seq fun _ => .done _
      · exact (framed origin latest _
          (ReconciliationFrame.trimForks_only tx _ head.seq keep)).seq fun _ => .done _

theorem acceptance (origin : String) (latest : Nat) (head : Head)
    (candidateBound : Origin.canonical head.origin = origin →
      AcceptanceProgress.rank head ≤ latest)
    (now : Int64) (keep : Nat) (state : State) (closed : state.pending = none)
    (initial : RowBound origin latest (rows state.db "heads")) :
    RowBound origin latest (rows (execute (Reconcile.accept head now keep) state).2.db "heads") := by
  have held : HeadInvariant.holds (accepts origin latest) state :=
    HeadInvariant.closed _ state closed initial
  exact (accept_only origin latest head candidateBound now keep).invariant
    (HeadInvariant.holds (accepts origin latest)) (fun _ good => good) state held |>.1

theorem promotion (tracked : String) (latest : Nat) (origin : Origin.Parsed)
    (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
    (state : State)
    (view : HeadView) (represented : HeadView.Represents state.db view)
    (backed : HeadView.Backed state.db view)
    (initial : RowBound tracked latest (rows state.db "heads")) :
    RowBound tracked latest
      (rows (execute (Promote.promote origin now refused) state).2.db "heads") := by
  rcases PromotionExecution.outcome origin now refused state with unchanged | ⟨prepared, executed⟩
  · apply of_no_new_keys initial
    intro row member
    exact ⟨row, by rwa [unchanged] at member, rfl⟩
  · rcases valueEq : prepared.value with ⟨scope, authority, pending, old⟩
    have preparedRead : execute (PromotionCommand.prepare prepared.tx origin now)
        prepared.opened = (.ok (scope, authority, pending, old), prepared.ready) := by
      simpa only [valueEq] using prepared.read
    rw [valueEq] at executed
    cases pending with
    | none =>
        let predicate := fun key =>
          ∃ prior ∈ rows state.db "heads", key = HeadKeyFrame.key prior
        have sameOrigin := PromotionExecution.prepare_origin prepared.tx origin now
          prepared.opened prepared.ready scope authority none old preparedRead
        have allowed := PromotionKeyFrame.publish_only predicate prepared.tx origin now refused
          scope authority none old sameOrigin
          (fun candidate impossible => by cases impossible)
        have readyHeld : HeadInvariant.holds (HeadKeyFrame.allKeys predicate) prepared.ready := by
          constructor
          · rw [prepared.committed]
            exact fun row member => ⟨row, member, rfl⟩
          · intro tx db opened
            rw [prepared.snapshot] at opened
            have same : (prepared.tx, state.db) = (tx, db) := Option.some.inj opened
            cases same
            exact fun row member => ⟨row, member, rfl⟩
        have finalHeld := allowed.invariant
          (HeadInvariant.holds (HeadKeyFrame.allKeys predicate)) (fun _ good => good)
            prepared.ready readyHeld
        rw [executed]
        apply of_no_new_keys initial
        intro row member
        exact finalHeld.1 row member
    | some candidate =>
        let predicate := fun key =>
          (∃ prior ∈ rows state.db "heads", key = HeadKeyFrame.key prior) ∨
          ∃ complete, key = HeadKeyFrame.key complete ∧
            ReconciliationSlots.names complete (Origin.canonical origin) "complete" = true ∧
            ReconciliationSlots.pointsTo complete candidate.head
        have sameOrigin := PromotionExecution.prepare_origin prepared.tx origin now
          prepared.opened prepared.ready scope authority (some candidate) old preparedRead
        have allowed := PromotionKeyFrame.publish_only predicate prepared.tx origin now refused
          scope authority (some candidate) old sameOrigin
          (fun actual same row named points => by
            have actualSame : actual = candidate := Option.some.inj same.symm
            cases actualSame
            exact Or.inr ⟨row, rfl, named, points⟩)
        have readyHeld : HeadInvariant.holds (HeadKeyFrame.allKeys predicate) prepared.ready := by
          constructor
          · rw [prepared.committed]
            exact fun row member => Or.inl ⟨row, member, rfl⟩
          · intro tx db opened
            rw [prepared.snapshot] at opened
            have same : (prepared.tx, state.db) = (tx, db) := Option.some.inj opened
            cases same
            exact fun row member => Or.inl ⟨row, member, rfl⟩
        have finalHeld := allowed.invariant
          (HeadInvariant.holds (HeadKeyFrame.allKeys predicate)) (fun _ good => good)
            prepared.ready readyHeld
        rw [executed]
        intro row member slot version named points
        rcases finalHeld.1 row member with ⟨prior, priorMember, same⟩ |
            ⟨complete, same, completeNamed, completePoints⟩
        · have priorNamed : ReconciliationSlots.names prior tracked
              (HeadView.slotName slot) = true := by
            rw [← HeadView.key_named same]
            exact named
          exact initial prior priorMember slot version priorNamed
            (HeadView.key_points same.symm points)
        · have promotedNamed : ReconciliationSlots.names row
              (Origin.canonical origin) "complete" = true := by
            rw [HeadView.key_named same]
            exact completeNamed
          have trackedSame : Origin.canonical origin = tracked :=
            (HeadView.text_unique _ tracked (Origin.canonical origin)
              (HeadView.named_fields named).1
              (HeadView.named_fields promotedNamed).1).symm
          have candidatePoints : HeadView.points row
              ⟨candidate.head.seq, candidate.head.root⟩ :=
            HeadView.key_points same completePoints
          have versionSame : version = ⟨candidate.head.seq, candidate.head.root⟩ :=
            HeadView.version_unique row version _ points candidatePoints
          have rawBegin := OperationExecution.raise_success (fun _ _ => rfl)
            Promote.Error.host Storage.begin state prepared.opened prepared.tx prepared.began
          have opened : prepared.opened.pending = some (prepared.tx, state.db) :=
            ReconciliationFloor.begin_pending state prepared.opened prepared.tx rawBegin
          obtain ⟨pendingRow, pendingMember, pendingNamed⟩ :=
            PromotionCommand.prepare_pending_selected prepared.tx origin now prepared.opened
              prepared.ready state.db opened scope authority (some candidate) old preparedRead
                candidate rfl
          rw [trackedSame] at pendingNamed
          obtain ⟨pendingVersion, pendingObserved, pendingPoints⟩ :=
            HeadView.selected_version (origin := tracked) (slot := .pending)
              represented ⟨pendingMember, pendingNamed⟩
          have stored := backed tracked .pending pendingVersion pendingObserved
          have storedAtOrigin : ReconciliationRead.StoredFloor state.db
              (Origin.canonical origin) "pending" pendingVersion.seq.toInt64
                pendingVersion.root := by
            simpa [HeadView.slotName, trackedSame] using stored
          obtain ⟨actual, actualSome, candidateSeq, candidateRoot⟩ :=
            PromotionCommand.prepare_pending_floor prepared.tx origin now prepared.opened
              prepared.ready state.db opened pendingVersion.seq.toInt64 pendingVersion.root
                storedAtOrigin scope authority (some candidate) old preparedRead
          have actualSame : actual = candidate := Option.some.inj actualSome.symm
          cases actualSame
          have candidateVersion : (⟨candidate.head.seq, candidate.head.root⟩ : HeadVersion) =
              pendingVersion := by
            cases pendingVersion
            simp_all
          rw [versionSame, candidateVersion]
          exact initial _ pendingMember .pending pendingVersion pendingNamed
            pendingPoints

/-- The only external head value which can enlarge the two-slot bound is an
advertisement. Promotion's candidate is proved above to come from the actual
pending row it read; every other event has an actual no-new-head certificate. -/
def EventBound (event : ReconciliationExecution.Event) (origin : String)
    (latest : Nat) : Prop :=
  match event with
  | .advertisement head _ _ =>
      Origin.canonical head.origin = origin → AcceptanceProgress.rank head ≤ latest
  | _ => True

theorem step (actual : ReconciliationExecution.Step event state final)
    (origin : String) (latest : Nat) (view : HeadView)
    (represented : HeadView.Represents state.db view)
    (backed : HeadView.Backed state.db view)
    (eventBound : EventBound event origin latest)
    (initial : RowBound origin latest (rows state.db "heads")) :
    RowBound origin latest (rows final.db "heads") := by
  cases actual with
  | advertisement head now keep state closed =>
      exact acceptance origin latest head eventBound now keep state closed initial
  | promotion promoted now refused state closed =>
      exact promotion origin latest promoted now refused state view represented backed initial
  | request target reference maximum retryLimit continuation rest reachable state final closed path =>
      apply of_no_new_keys initial
      exact FetchHeadSafety.every_resumption_no_new_key _ _ target reference maximum retryLimit
        continuation rest reachable state final closed path
  | retirement pending continuation rest reachable state final closed path =>
      apply of_no_new_keys initial
      have different : equals [] (RetirementProtection.key pending) = false := by
        simp [RetirementProtection.key, Reconcile.headKey, equals, cell, isCell, equalCell,
          BEq.beq, instBEqCell.beq]
      exact HeadKeyFrame.no_new_keys_prefix continuation rest
        ((RetirementProtection.retire_only [] pending different).continuation reachable)
        (fun predicate => RetirementProtection.effects_preserve_keys predicate []) state final
          closed path
  | selection selected expected state closed =>
      apply of_no_new_keys initial
      exact HeadKeyFrame.no_new_keys _ (FetchLifecycle.select_only [] selected expected)
        (fun predicate => FetchLifecycle.effects_preserve_keys predicate []) state closed
  | abandonment target state closed =>
      apply of_no_new_keys initial
      exact HeadKeyFrame.no_new_keys _
        (FetchLifecycle.abandon_only [] target (FetchTransition.empty_unmatched target))
        (fun predicate => FetchLifecycle.effects_preserve_keys predicate []) state closed
  | settlement settled refused scope target key result state closed =>
      cases result with
      | error error =>
          apply of_no_new_keys initial
          exact HeadKeyFrame.no_new_keys _
            (FetchLifecycle.settle_without_publication [] settled refused scope target key
              (.error error) (by simp) (FetchTransition.empty_unmatched target))
            (fun predicate => FetchLifecycle.effects_preserve_keys predicate []) state closed
      | ok complete =>
          cases complete with
          | false =>
              apply of_no_new_keys initial
              exact HeadKeyFrame.no_new_keys _
                (FetchLifecycle.settle_without_publication [] settled refused scope target key
                  (.ok false) (by simp) (FetchTransition.empty_unmatched target))
                (fun predicate => FetchLifecycle.effects_preserve_keys predicate []) state closed
          | true =>
              have dbFrame :
                  (execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state).2.db =
                    state.db := by
                apply reply_preserves_db
                intro s
                rfl
              unfold FetchLifecycle.settle
              simp only [bind, ExceptT.bind, ExceptT.mk, execute_bind]
              generalize clockRead :
                execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state = read
                  at dbFrame ⊢
              obtain ⟨answer, current⟩ := read
              have currentDb : current.db = state.db := by simpa using dbFrame
              cases answer with
              | error error =>
                  change RowBound origin latest (rows current.db "heads")
                  rw [currentDb]
                  exact initial
              | ok clockNow =>
                  dsimp only [ExceptT.bindCont, ExceptT.run]
                  rw [execute_bind]
                  simp only [Fetch.lift]
                  rw [OperationExecution.within_eq FetchLifecycle.promote_agrees]
                  have bounded := promotion origin latest settled clockNow refused current view
                    (by rw [currentDb]; exact represented)
                    (by rw [currentDb]; exact backed)
                    (by rw [currentDb]; exact initial)
                  generalize promoted : execute (Promote.promote settled clockNow refused) current =
                    answer at bounded ⊢
                  obtain ⟨result, promotedState⟩ := answer
                  cases result <;> exact bounded

end Synchronicity.StableHeadBounds
