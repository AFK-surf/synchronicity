import Synchronicity.PromotionRowFrame
import Synchronicity.TargetTransition

namespace Synchronicity.PromotionTransition
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost Goals.Mptsync

/-- A capture is issued only after the actual begin and preparation reads
return a pending head. There is no externally supplied cleanup permission. -/
def captures (origin : Origin.Parsed) (now : Int64) (state : State) : List CapturedHead :=
  match execute (Promote.raw .begin) state with
  | (.error _, _) => []
  | (.ok tx, opened) =>
    match execute (PromotionCommand.prepare tx origin now) opened with
    | (.error _, _) => []
    | (.ok (_, _, pending, _), _) => pending.toList.map TargetTransition.pendingKey

theorem captured_pending (prepared : PromotionExecution.PreparedAt origin now state)
    (stored : ReconciliationRead.StoredFloor state.db (Origin.canonical origin) "pending" version.seq.toInt64 version.root) :
    CapturedHead.mk (Origin.canonical origin) version ∈ captures origin now state := by
  obtain ⟨tx, opened, ready, ⟨scope, authority, pending, old⟩, began, read, _, _⟩ := prepared
  have rawBegin := OperationExecution.raise_success (fun _ _ => rfl) Promote.Error.host Storage.begin state opened tx began
  have snapshot := ReconciliationFloor.begin_pending state opened tx rawBegin
  obtain ⟨candidate, selected, seqSame, rootSame⟩ := PromotionCommand.prepare_pending_floor tx origin now opened ready state.db
    snapshot version.seq.toInt64 version.root stored scope authority pending old read
  have originSame := PromotionExecution.prepare_origin tx origin now opened ready scope authority pending old read candidate selected
  simp [captures, began, read, selected, TargetTransition.pendingKey, originSame, seqSame, rootSame]

theorem refines (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
    (state : State) (closed : state.pending = none)
    (before : HeadView.Represents state.db view) (backed : HeadView.Backed state.db view)
    (after : HeadView.Represents (execute (Promote.promote origin now refused) state).2.db nextView) :
    HeadTransition (captures origin now state) view nextView := by
  classical
  intro rowOrigin slot
  cases oldValue : view rowOrigin slot with
  | none => exact HeadView.initially_empty _
  | some old =>
    by_cases sameOrigin : rowOrigin = Origin.canonical origin
    · subst rowOrigin
      cases slot with
      | complete =>
        apply HeadView.complete_change after old
        simpa using PromotionCommand.promote_preserves_complete_floor origin now refused state closed old.seq.toInt64 old.root
          (backed _ _ old oldValue)
      | pending =>
        cases nextValue : nextView (Origin.canonical origin) .pending with
        | some next =>
          obtain ⟨row, selected, nextStored⟩ := HeadView.existing after nextValue
          rcases PromotionKeyFrame.no_other_new_keys origin now refused state row selected.1 with prior | complete
          · obtain ⟨prior, member, same⟩ := prior
            have named : ReconciliationSlots.names prior (Origin.canonical origin) "pending" = true := by
              rw [← HeadView.key_named same]
              exact selected.2
            have priorView := before (Origin.canonical origin) .pending
            rw [oldValue] at priorView
            have stored := priorView.2 prior ⟨member, named⟩
            have equal := HeadView.version_unique row next old nextStored (HeadView.key_points same stored)
            rw [equal]
            exact .keep _ _
          · obtain ⟨complete, same, named⟩ := complete
            have pendingNamed : ReconciliationSlots.names complete (Origin.canonical origin) "pending" = true := by
              rw [← HeadView.key_named same]
              exact selected.2
            have impossible := HeadView.other_name (otherOrigin := Origin.canonical origin) named (Or.inr (show "complete" ≠ "pending" by decide))
            rw [pendingNamed] at impossible
            cases impossible
        | none =>
          apply HeadChange.consume old
          rcases PromotionExecution.outcome origin now refused state with unchanged | ⟨prepared, _⟩
          · obtain ⟨row, selected, _⟩ := HeadView.existing before oldValue
            exact False.elim (HeadView.absent after nextValue ⟨by rw [unchanged]; exact selected.1, selected.2⟩)
          · exact captured_pending prepared (backed _ _ old oldValue)
    · have same := HeadView.stays before after oldValue (fun row selected =>
        PromotionRowFrame.other_origin_retained origin now refused state row selected.1
          (HeadView.other_origin selected.2 sameOrigin))
      rw [same]
      exact .keep _ _

end Synchronicity.PromotionTransition
