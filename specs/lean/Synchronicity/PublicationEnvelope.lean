import Synchronicity.PrivateDatabase

/-! A syntactic execution certificate for programs with at most one public
database mutation. It says nothing about readiness: operation proofs must
establish that separately for the final database. Every primitive prefix is
then either the initial or final public database, including fault paths. -/
namespace Synchronicity.PublicationEnvelope
open VerifiedCore.Host SimulatedHost PrivateDatabase

def Private [Interpreter E] (A : Type) (effect : E A) : Prop :=
  ∀ state, (Interpreter.handle effect state).2.db = state.db

inductive LastWrite [Interpreter E] : Program E A → Prop where
  | done (value : A) : LastWrite (.pure value)
  | privateStep {B : Type} (effect : E B) (next : B → Program E A)
      (safe : Private B effect) (rest : ∀ reply, LastWrite (next reply)) : LastWrite (.request effect next)
  | lastStep {B : Type} (effect : E B) (next : B → Program E A)
      (rest : ∀ reply, Only Private (next reply)) : LastWrite (.request effect next)

theorem LastWrite.private_bind [Interpreter E] {first : Program E A} (safe : Only Private first)
    (next : A → Program E B) (rest : ∀ value, LastWrite (next value)) : LastWrite (first >>= next) := by
  induction safe with
  | done value => exact rest value
  | request good replies ih => exact .privateStep _ _ good ih

theorem LastWrite.of_private [Interpreter E] {program : Program E A} (safe : Only Private program) : LastWrite program := by
  induction safe with
  | done value => exact .done value
  | request good replies ih => exact .privateStep _ _ good ih

theorem LastWrite.bind_after [Interpreter E] {first : Program E A} (safe : LastWrite first)
    (next : A → Program E B) (rest : ∀ value, Only Private (next value)) : LastWrite (first >>= next) := by
  induction safe with
  | done value => exact .of_private (rest value)
  | privateStep effect resume good replies ih => exact .privateStep _ _ good ih
  | lastStep effect resume replies => exact .lastStep _ _ (fun reply => (replies reply).bind rest)

theorem LastWrite.seq_after [Interpreter E] {first : OperationOver E ε A} (safe : LastWrite first.run)
    (next : A → OperationOver E ε B) (rest : ∀ value, Only Private (next value).run) : LastWrite (first >>= next).run := by
  apply LastWrite.bind_after safe
  intro result
  cases result with
  | error error => exact .done _
  | ok value => exact rest value

theorem LastWrite.seq [Interpreter E] {first : OperationOver E ε A} (safe : Only Private first.run)
    (next : A → OperationOver E ε B) (rest : ∀ value, LastWrite (next value).run) : LastWrite (first >>= next).run := by
  apply LastWrite.private_bind safe
  intro result
  cases result with
  | error error => exact .done _
  | ok value => exact rest value

theorem LastWrite.transaction [Interpreter E] (inject : {B : Type} → Storage B → E B) (error : Failure → ε)
    (body : Transaction → OperationOver E ε A) (beginSafe : Private _ (inject .begin))
    (rollbackSafe : ∀ tx, Private _ (inject (.rollback tx))) (safe : ∀ tx, Only Private (body tx).run) :
    LastWrite (transactionOver inject error body).run := by
  unfold transactionOver
  refine .privateStep _ _ beginSafe fun result => ?_
  cases result with
  | error _ => exact .done _
  | ok tx =>
    apply LastWrite.private_bind (safe tx)
    intro result
    cases result with
    | error _ => exact .privateStep _ _ (rollbackSafe tx) fun _ => .done _
    | ok _ =>
      refine .lastStep _ _ fun result => ?_
      cases result with
      | ok _ => exact .done _
      | error _ => exact .request (rollbackSafe tx) fun _ => .done _

theorem LastWrite.envelope [Interpreter E] {program tail : Program E A} {state final : State}
    (safe : LastWrite program) (path : Prefix program state tail final) :
    final.db = state.db ∨ final.db = (execute program state).2.db := by
  induction path with
  | refl => exact Or.inl rfl
  | @step B effect next state final tail path ih =>
    cases safe with
    | privateStep _ _ good rest =>
      rcases ih (rest _) with unchanged | finished
      · exact Or.inl (unchanged.trans (good state))
      · exact Or.inr finished
    | lastStep _ _ rest =>
      have unchanged := (rest _).preserves_prefix path (fun _ good => good)
      have finished := (rest (Interpreter.handle effect state).1).preserves_db _ (fun _ good => good) (Interpreter.handle effect state).2
      exact Or.inr (unchanged.trans finished.symm)

end Synchronicity.PublicationEnvelope
