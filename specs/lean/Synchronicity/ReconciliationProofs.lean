import VerifiedCore.Replication.Reconcile
import Synchronicity.SimulatedHost

/-! Scoped guarantees about the executed acceptance command. The signature
primitive is a trusted exact-message verifier; this does not prove Ed25519,
promotion completeness, or eventual convergence. -/
namespace Synchronicity.ReconciliationProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
open SimulatedHost

theorem signature_gate (head : Head) (now : Int64) (keep : Nat) :
    ∃ next, (Reconcile.accept head now keep).run =
      Program.request (.right (Crypto.verifyEd25519 head.signedBy
        (Reconcile.signingInput head) head.signature)) next ∧
      next (.ok false) = .pure (.ok .badSignature) := ⟨_, rfl, rfl⟩

/-- A rejected signature cannot alter learned history, pending work, or the
accepted view: acceptance makes no storage request at all after rejection. -/
theorem rejected_signature_preserves_storage (head : Head) (now : Int64) (keep : Nat)
    (state : State) (healthy : fault { state with output := [] } = none)
    (rejected : state.verifySignature head.signedBy (Reconcile.signingInput head) head.signature = false) :
    let result := run (Reconcile.accept head now keep) state
    result.1 = .ok .badSignature ∧ result.2.db = state.db ∧ result.2.pending = state.pending := by
  obtain ⟨next, first, stopped⟩ := signature_gate head now keep
  simp only [run, first, execute]
  simp only [Interpreter.handle, crypto, reply, healthy, rejected, stopped, execute, record]
  trivial

end Synchronicity.ReconciliationProofs
