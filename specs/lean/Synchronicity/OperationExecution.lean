import Synchronicity.SimulatedHost

/-! Semantic transport through production error/capability adapters. -/
namespace Synchronicity.OperationExecution
open VerifiedCore.Host SimulatedHost

theorem within_eq [Interpreter E] [Interpreter F] [Inject E F]
    (faithful : ∀ {B} (effect : E B) state,
      Interpreter.handle (Inject.inject effect : F B) state = Interpreter.handle effect state)
    (translate : ε → δ) (operation : OperationOver E ε A) (state : State) :
    execute (within translate operation : OperationOver F δ A) state =
      ((execute operation state).1.mapError translate, (execute operation state).2) := by
  simp only [within, ExceptT.mk, execute_bind, execute_mapEffects Inject.inject faithful]
  rfl

theorem within_success [Interpreter E] [Interpreter F] [Inject E F]
    (faithful : ∀ {B} (effect : E B) state,
      Interpreter.handle (Inject.inject effect : F B) state = Interpreter.handle effect state)
    (translate : ε → δ) (operation : OperationOver E ε A) (state final : State) (answer : A)
    (executed : execute (within translate operation : OperationOver F δ A) state = (.ok answer, final)) :
    execute operation state = (.ok answer, final) := by
  rw [within_eq faithful] at executed
  generalize worked : execute operation state = result at executed ⊢
  obtain ⟨result, output⟩ := result
  cases result with
  | error _ => cases executed
  | ok value =>
    have same : value = answer := Except.ok.inj (congrArg Prod.fst executed)
    have stateSame : output = final := congrArg Prod.snd executed
    subst value
    subst output
    rfl

theorem raise_success [Interpreter E] [Interpreter F] [Inject E F]
    (faithful : ∀ {B} (effect : E B) state,
      Interpreter.handle (Inject.inject effect : F B) state = Interpreter.handle effect state)
    (translate : Failure → ε) (effect : E (Reply A)) (state final : State) (answer : A)
    (executed : execute (raise translate effect : OperationOver F ε A) state = (.ok answer, final)) :
    Interpreter.handle effect state = (.ok answer, final) := by
  change ((Interpreter.handle (Inject.inject effect : F _) state).1.mapError translate,
    (Interpreter.handle (Inject.inject effect : F _) state).2) = (.ok answer, final) at executed
  rw [faithful] at executed
  generalize handled : Interpreter.handle effect state = result at executed ⊢
  obtain ⟨result, output⟩ := result
  cases result with
  | error _ => cases executed
  | ok value =>
    have same : value = answer := Except.ok.inj (congrArg Prod.fst executed)
    have stateSame : output = final := congrArg Prod.snd executed
    subst value
    subst output
    rfl

end Synchronicity.OperationExecution
