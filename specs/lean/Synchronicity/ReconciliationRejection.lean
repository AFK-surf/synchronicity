import Synchronicity.ReconciliationAcceptance

/-! Obsolete advertisements leave every committed heads row unchanged. This
is about the full acceptance command and permits arbitrary raw rows and faults;
history retention may still change, so the claim is intentionally about heads. -/
namespace Synchronicity.ReconciliationRejection
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost
open TransactionSuccess (bind_success)
open ReconciliationFrame

theorem nonacceptance_preserves_heads (head : Head) (now : Int64) (keep : Nat) (state : State)
    (answer : Acceptance) (notAccepted : answer ≠ .pending)
    (rejected : (execute (Reconcile.accept head now keep) state).1 = .ok answer) :
    rows (execute (Reconcile.accept head now keep) state).2.db "heads" = rows state.db "heads" := by
  generalize executed : execute (Reconcile.accept head now keep) state = outcome at rejected ⊢
  obtain ⟨result, final⟩ := outcome
  dsimp only at rejected ⊢
  subst result
  unfold Reconcile.accept at executed
  obtain ⟨signature, checked, verified, executed⟩ := bind_success _ _ _ _ _ executed
  have signatureFrame : checked.db = state.db := by
    have kept := signature_preserves_db head state
    simpa only [verified] using kept
  cases signature with
  | false =>
    have same : checked = final := congrArg Prod.snd executed
    rw [← same, signatureFrame]
  | true =>
    dsimp only at executed
    obtain ⟨tx, opened, finished, started, body, committed, finalState⟩ :=
      TransactionSuccess.transaction_success _ _ _ checked _ (congrArg Prod.fst executed)
    have finalState : final = (storage (.commit tx) finished).2 :=
      (congrArg Prod.snd executed).symm.trans finalState
    suffices unchanged : heads finished = some (tx, rows state.db "heads") by
      obtain ⟨db, staged, published⟩ := ReconciliationAcceptance.commit_installs tx finished committed
      have sameRows : rows db "heads" = rows state.db "heads" := by
        simpa [heads, staged] using unchanged
      rw [finalState, published, sameRows]
    have initial := begin_heads checked opened tx started
    obtain ⟨instant, timed, timedRead, body⟩ := bind_success _ _ _ _ _ body
    have timedFrame := executed_heads _ (auth_only _ (trustInstant_only tx now)) _ _ _ timedRead
    obtain ⟨live, bound, liveRead, body⟩ := bind_success _ _ _ _ _ body
    have liveFrame := executed_heads _ (auth_only _ (liveForKey_only tx head.signedBy instant)) _ _ _ liveRead
    split at body
    · have same : bound = finished := congrArg Prod.snd body
      rw [← same, liveFrame, timedFrame, initial, signatureFrame]
    · obtain ⟨_, beforeComplete, recorded, body⟩ := bind_success _ _ _ _ _ body
      have recordFrame := executed_heads _ (record_only tx head now) _ _ _ recorded
      obtain ⟨complete, beforePending, readComplete, body⟩ := bind_success _ _ _ _ _ body
      have completeFrame := executed_heads _ (readSlot_only tx _ "complete") _ _ _ readComplete
      obtain ⟨pending, beforeWrite, readPending, body⟩ := bind_success _ _ _ _ _ body
      have pendingFrame := executed_heads _ (readSlot_only tx _ "pending") _ _ _ readPending
      split at body
      · obtain ⟨_, _, _, body⟩ := bind_success _ _ _ _ _ body
        obtain ⟨_, _, _, impossible⟩ := bind_success _ _ _ _ _ body
        have same : Acceptance.pending = answer := Except.ok.inj (congrArg Prod.fst impossible)
        exact False.elim (notAccepted same.symm)
      · obtain ⟨_, afterTrim, trimmed, returned⟩ := bind_success _ _ _ _ _ body
        have same : afterTrim = finished := congrArg Prod.snd returned
        subst afterTrim
        have trimFrame := executed_heads _ (trimForks_only tx _ head.seq keep) _ _ _ trimmed
        rw [trimFrame, pendingFrame, completeFrame, recordFrame, liveFrame, timedFrame,
          initial, signatureFrame]

end Synchronicity.ReconciliationRejection
