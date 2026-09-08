import Synchronicity.ReconciliationSlots
import Synchronicity.TransactionSuccess
import Synchronicity.ReconciliationFrame

/-! Successful acceptance must both observe the two floors and execute the
candidate write. All witnesses are executions on the shared raw database host,
not caller-supplied policy answers. -/
namespace Synchronicity.ReconciliationAcceptance
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost
open TrieServePrivacyProofs (bind_ok)
open TransactionSuccess (bind_success)
open ReconciliationFrame

theorem commit_installs (tx : Transaction) (state : State)
    (succeeded : (storage (.commit tx) state).1 = .ok ()) :
    ∃ db, state.pending = some (tx, db) ∧ (storage (.commit tx) state).2.db = db := by
  simp only [storage, reply] at succeeded ⊢
  split at succeeded
  · cases succeeded
  · rename_i noFault
    split at succeeded
    · rename_i token db pending
      rw [pending]
      split at succeeded
      · rename_i same
        have same : token = tx := eq_of_beq same
        subst token
        exact ⟨db, rfl, by simp [record]⟩
      · cases succeeded
    · cases succeeded

theorem accepted_observes_and_writes (head : Head) (now : Int64) (keep : Nat) (state : State)
    (accepted : (execute (Reconcile.accept head now keep) state).1 = .ok .pending) :
    ∃ tx beforeComplete beforePending beforeWrite afterWrite complete pending,
      heads beforeComplete = some (tx, rows state.db "heads") ∧
      heads beforePending = some (tx, rows state.db "heads") ∧
      heads beforeWrite = some (tx, rows state.db "heads") ∧
      execute (History.readSlot tx (Origin.canonical head.origin) "complete") beforeComplete =
        (.ok complete, beforePending) ∧
      execute (History.readSlot tx (Origin.canonical head.origin) "pending") beforePending =
        (.ok pending, beforeWrite) ∧
      (∀ old ∈ complete ++ pending, Reconcile.newer head.seq head.root old.pointer = true) ∧
      execute (Reconcile.putSlot tx "pending" head now now) beforeWrite = (.ok (), afterWrite) := by
  unfold Reconcile.accept at accepted
  obtain ⟨signature, checked, verified, accepted⟩ := bind_ok _ _ _ _ accepted
  have signatureFrame : checked.db = state.db := by
    have kept := signature_preserves_db head state
    simpa only [verified] using kept
  cases signature with
  | false => cases accepted
  | true =>
    obtain ⟨tx, opened, finished, started, body, _⟩ :=
      TransactionSuccess.transaction_success _ _ _ checked _ accepted
    have initial := begin_heads checked opened tx started
    have accepted := congrArg Prod.fst body
    obtain ⟨instant, timed, timedRead, accepted⟩ := bind_ok _ _ _ _ accepted
    have timedFrame := executed_heads _ (auth_only _ (trustInstant_only tx now)) _ _ _ timedRead
    obtain ⟨live, bound, liveRead, accepted⟩ := bind_ok _ _ _ _ accepted
    have liveFrame := executed_heads _ (auth_only _ (liveForKey_only tx head.signedBy instant)) _ _ _ liveRead
    split at accepted
    · cases accepted
    · obtain ⟨_, beforeComplete, recorded, accepted⟩ := bind_ok _ _ _ _ accepted
      have recordFrame := executed_heads _ (record_only tx head now) _ _ _ recorded
      obtain ⟨complete, beforePending, readComplete, accepted⟩ := bind_ok _ _ _ _ accepted
      have completeFrame := executed_heads _ (readSlot_only tx _ "complete") _ _ _ readComplete
      obtain ⟨pending, beforeWrite, readPending, accepted⟩ := bind_ok _ _ _ _ accepted
      have pendingFrame := executed_heads _ (readSlot_only tx _ "pending") _ _ _ readPending
      have original : heads beforeComplete = some (tx, rows state.db "heads") := by
        rw [recordFrame, liveFrame, timedFrame, initial, signatureFrame]
      dsimp only at accepted
      split at accepted
      · rename_i greater
        obtain ⟨_, afterWrite, written, _⟩ := bind_ok _ _ _ _ accepted
        exact ⟨tx, beforeComplete, beforePending, beforeWrite, afterWrite, complete, pending,
          original, completeFrame.trans original, pendingFrame.trans (completeFrame.trans original),
          readComplete, readPending, List.all_eq_true.mp greater, written⟩
      · obtain ⟨_, _, _, impossible⟩ := bind_ok _ _ _ _ accepted
        cases impossible

/-- A successful acceptance really publishes the candidate as pending. This
observes committed rows after the entire production command, including trimming
and commit, without assuming fault-free storage or a precomputed policy answer. -/
theorem accepted_installs_pending (head : Head) (now : Int64) (keep : Nat) (state : State)
    (accepted : (execute (Reconcile.accept head now keep) state).1 = .ok .pending) :
    let table := rows (execute (Reconcile.accept head now keep) state).2.db "heads"
    (∃ row ∈ table, ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = true) ∧
    (∀ row ∈ table, ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = true →
      ReconciliationSlots.pointsTo row head) := by
  generalize executed : execute (Reconcile.accept head now keep) state = outcome at accepted ⊢
  obtain ⟨result, final⟩ := outcome
  dsimp only at accepted ⊢
  subst result
  unfold Reconcile.accept at executed
  obtain ⟨signature, checked, _, executed⟩ := bind_success _ _ _ _ _ executed
  cases signature with
  | false => cases executed
  | true =>
    dsimp only at executed
    obtain ⟨tx, opened, finished, _, body, committed, finalState⟩ :=
      TransactionSuccess.transaction_success _ _ _ checked _ (congrArg Prod.fst executed)
    have finalState : final = (storage (.commit tx) finished).2 := by
      exact (congrArg Prod.snd executed).symm.trans finalState
    obtain ⟨instant, timed, _, body⟩ := bind_success _ _ _ _ _ body
    obtain ⟨live, bound, _, body⟩ := bind_success _ _ _ _ _ body
    split at body
    · cases body
    · obtain ⟨_, beforeComplete, _, body⟩ := bind_success _ _ _ _ _ body
      obtain ⟨complete, beforePending, _, body⟩ := bind_success _ _ _ _ _ body
      obtain ⟨pending, beforeWrite, _, body⟩ := bind_success _ _ _ _ _ body
      split at body
      · obtain ⟨_, afterWrite, written, body⟩ := bind_success _ _ _ _ _ body
        obtain ⟨_, afterTrim, trimmed, returned⟩ := bind_success _ _ _ _ _ body
        have same : afterTrim = finished := congrArg Prod.snd returned
        subst afterTrim
        obtain ⟨staged, installed, existsRow, everyRow⟩ :=
          ReconciliationSlots.putSlot_installs tx "pending" head now now beforeWrite
            (congrArg Prod.fst written)
        rw [written] at installed
        dsimp only at installed
        obtain ⟨committedDb, beforeCommit, published⟩ := commit_installs tx finished committed
        have frame := ReconciliationFrame.trimForks_preserves_heads tx
          (Origin.canonical head.origin) head.seq keep afterWrite
        rw [trimmed] at frame
        have sameRows : rows committedDb "heads" = rows staged "heads" := by
          simpa [ReconciliationFrame.heads, beforeCommit, installed] using frame
        rw [finalState, published, sameRows]
        exact ⟨existsRow, everyRow⟩
      · obtain ⟨_, _, _, impossible⟩ := bind_success _ _ _ _ _ body
        cases impossible

end Synchronicity.ReconciliationAcceptance
