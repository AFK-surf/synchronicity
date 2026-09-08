import Synchronicity.SimulatedHost

/-! Successful transaction commands must have successfully executed their
body and commit. This follows the common executable transaction combinator. -/
namespace Synchronicity.TransactionSuccess
open VerifiedCore.Host SimulatedHost

theorem bind_success [Interpreter E] (first : OperationOver E ε A)
    (next : A → OperationOver E ε B) (state final : State) (answer : B)
    (succeeded : execute (first >>= next : OperationOver E ε B) state = (.ok answer, final)) :
    ∃ value middle, execute first state = (.ok value, middle) ∧
      execute (next value) middle = (.ok answer, final) := by
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind] at succeeded
  generalize step : execute first state = result at succeeded
  obtain ⟨result, middle⟩ := result
  cases result with
  | error failure => cases succeeded
  | ok value => exact ⟨value, middle, rfl, succeeded⟩

theorem transaction_success [Interpreter E]
    (inject : {B : Type} → Storage B → E B) (hostError : Failure → ε)
    (body : Transaction → OperationOver E ε A) (state : State) (answer : A)
    (succeeded : (execute (transactionOver inject hostError body) state).1 = .ok answer) :
    ∃ tx opened finished,
      Interpreter.handle (inject .begin) state = (.ok tx, opened) ∧
      execute (body tx) opened = (.ok answer, finished) ∧
      (Interpreter.handle (inject (.commit tx)) finished).1 = .ok () ∧
      (execute (transactionOver inject hostError body) state).2 =
        (Interpreter.handle (inject (.commit tx)) finished).2 := by
  simp only [transactionOver, ExceptT.mk, bind, Program.bind, execute] at succeeded
  generalize started : Interpreter.handle (inject .begin) state = start at succeeded
  obtain ⟨reply, opened⟩ := start
  cases reply with
  | error error => cases succeeded
  | ok tx =>
    rw [execute_bind] at succeeded
    dsimp only [ExceptT.run] at succeeded
    generalize worked : execute (body tx) opened = work at succeeded
    obtain ⟨result, finished⟩ := work
    cases result with
    | error error => cases succeeded
    | ok value =>
      simp only [execute] at succeeded
      generalize committed : Interpreter.handle (inject (.commit tx)) finished = commit at succeeded
      obtain ⟨reply, closed⟩ := commit
      cases reply with
      | error error => cases succeeded
      | ok valueUnit =>
        cases valueUnit
        have same : value = answer := Except.ok.inj succeeded
        subst value
        refine ⟨tx, opened, finished, rfl, worked, congrArg Prod.fst committed, ?_⟩
        simp only [transactionOver, ExceptT.mk, bind, Program.bind, execute, started]
        rw [execute_bind]
        dsimp only [ExceptT.run]
        rw [worked]
        simp only [execute, committed]
        rfl

end Synchronicity.TransactionSuccess
