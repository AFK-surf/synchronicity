import Synchronicity.ReconciliationFloor
import Synchronicity.TransactionFailure

/-! Failure atomicity for the whole signed-head acceptance command. -/
namespace Synchronicity.ReconciliationFailure
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def allowed (A : Type) : History.Effects A → Prop
  | .left effect => storagePrivate effect
  | .right _ => True

theorem effects_db (effect : History.Effects A) (safe : allowed _ effect) (state : State) :
    (Interpreter.handle effect state).2.db = state.db := by
  cases effect with
  | left effect => exact storage_preserves_db effect safe state
  | right effect => cases effect <;> apply reply_preserves_db <;> intro s <;> rfl

theorem framed_private (operation : OperationOver History.Effects ε A)
    (safe : Only ReconciliationFrame.allowed operation.run) : Only allowed operation.run := by
  apply safe.mono
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem putSlot_private (tx : Transaction) (slot : String) (head : Head) (received verified : Int64) :
    Only allowed (Reconcile.putSlot tx slot head received verified).run := by
  unfold Reconcile.putSlot
  exact (framed_private _ (ReconciliationFrame.record_only tx head received)).seq fun _ =>
    .request trivial fun _ => .done _

theorem acceptance_failure (head : Head) (now : Int64) (keep : Nat) (state : State)
    (failure : History.Error)
    (failed : (execute (Reconcile.accept head now keep) state).1 = .error failure) :
    (execute (Reconcile.accept head now keep) state).2.db = state.db := by
  unfold Reconcile.accept at failed ⊢
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind] at failed ⊢
  generalize checked : execute (raise History.Error.host
    (Crypto.verifyEd25519 head.signedBy (Reconcile.signingInput head) head.signature) : History.Action Bool) state =
      result at failed ⊢
  obtain ⟨result, verified⟩ := result
  have unchanged : verified.db = state.db := by
    have kept := ReconciliationFrame.signature_preserves_db head state
    simpa only [checked] using kept
  cases result with
  | error error => exact unchanged
  | ok valid =>
    cases valid with
    | false => cases failed
    | true =>
      apply Eq.trans _ unchanged
      apply TransactionFailure.transaction_failure Inject.inject (fun _ _ => rfl) History.Error.host _ _ verified failure failed
      intro tx initial
      apply Only.preserves_db _ _ effects_db initial
      apply Only.seq (framed_private _ (ReconciliationFrame.auth_only _ (ReconciliationFrame.trustInstant_only tx now)))
      intro instant
      apply Only.seq (framed_private _ (ReconciliationFrame.auth_only _ (ReconciliationFrame.liveForKey_only tx head.signedBy instant)))
      intro live
      split
      · exact .done _
      · apply Only.seq (framed_private _ (ReconciliationFrame.record_only tx head now))
        intro _
        apply Only.seq (framed_private _ (ReconciliationFrame.readSlot_only tx _ "complete"))
        intro complete
        apply Only.seq (framed_private _ (ReconciliationFrame.readSlot_only tx _ "pending"))
        intro pending
        split
        · exact (putSlot_private tx "pending" head now now).seq fun _ =>
            (framed_private _ (ReconciliationFrame.trimForks_only tx _ head.seq keep)).seq fun _ => .done _
        · exact (framed_private _ (ReconciliationFrame.trimForks_only tx _ head.seq keep)).seq fun _ => .done _

/-- No successful-result premise remains: an obsolete advertisement preserves
all heads whether it is refused, encounters malformed metadata, or hits a host,
commit or rollback failure. -/
theorem obsolete_preserves_heads (head : Head) (now : Int64) (keep : Nat) (state : State)
    (slot : String) (which : slot = "complete" ∨ slot = "pending") (seq : Int64) (root : ByteArray)
    (stored : ReconciliationRead.StoredFloor state.db (Origin.canonical head.origin) slot seq root)
    (obsolete : Reconcile.newer head.seq head.root ⟨seq.toUInt64, root⟩ = false) :
    rows (execute (Reconcile.accept head now keep) state).2.db "heads" = rows state.db "heads" := by
  cases outcome : (execute (Reconcile.accept head now keep) state).1 with
  | error failure => rw [acceptance_failure head now keep state failure outcome]
  | ok answer => exact ReconciliationFloor.obsolete_preserves_heads head now keep state slot which seq root stored obsolete answer outcome

end Synchronicity.ReconciliationFailure
