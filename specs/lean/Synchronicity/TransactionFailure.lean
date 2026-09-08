import Synchronicity.PrivateDatabase

/-! Failure atomicity of the executable transaction combinator. Its body must
be transaction-private; failed commit and rollback replies need not be healthy. -/
namespace Synchronicity.TransactionFailure
open VerifiedCore.Host SimulatedHost PrivateDatabase

theorem commit_failure (tx : Transaction) (state : State) (failure : Failure)
    (failed : (storage (.commit tx) state).1 = .error failure) :
    (storage (.commit tx) state).2.db = state.db := by
  simp only [storage, reply] at failed ⊢
  split at failed
  · rfl
  · split at failed
    · rename_i token db opened
      split at failed
      · cases failed
      · rename_i wrong
        simp only [if_neg wrong]
        rfl
    · rfl

theorem transaction_failure [Interpreter E]
    (inject : {B : Type} → Storage B → E B)
    (faithful : ∀ {B} (effect : Storage B) state, Interpreter.handle (inject effect) state = storage effect state)
    (hostError : Failure → ε) (body : Transaction → OperationOver E ε A)
    (privateBody : ∀ tx state, (execute (body tx) state).2.db = state.db)
    (state : State) (failure : ε)
    (failed : (execute (transactionOver inject hostError body) state).1 = .error failure) :
    (execute (transactionOver inject hostError body) state).2.db = state.db := by
  simp only [transactionOver, ExceptT.mk, bind, Program.bind, execute, faithful] at failed ⊢
  generalize started : storage .begin state = start at failed ⊢
  obtain ⟨result, opened⟩ := start
  have openedDb : opened.db = state.db := by
    have kept := storage_preserves_db Storage.begin trivial state
    simpa only [started] using kept
  cases result with
  | error error => exact openedDb
  | ok tx =>
    rw [execute_bind] at failed ⊢
    dsimp only [ExceptT.run] at failed ⊢
    generalize worked : execute (body tx) opened = work at failed ⊢
    obtain ⟨result, finished⟩ := work
    have finishedDb : finished.db = state.db := by
      have kept := privateBody tx opened
      rw [worked] at kept
      exact kept.trans openedDb
    cases result with
    | error error =>
      simp only [execute, faithful]
      exact (storage_preserves_db (.rollback tx) trivial finished).trans finishedDb
    | ok value =>
      simp only [execute, faithful] at failed ⊢
      generalize committed : storage (.commit tx) finished = commit at failed ⊢
      obtain ⟨result, closed⟩ := commit
      cases result with
      | ok valueUnit => cases valueUnit; cases failed
      | error error =>
        have closedDb : closed.db = finished.db := by
          have kept := commit_failure tx finished error (congrArg Prod.fst committed)
          simpa only [committed] using kept
        simp only [execute, faithful]
        exact (storage_preserves_db (.rollback tx) trivial closed).trans (closedDb.trans finishedDb)

end Synchronicity.TransactionFailure
