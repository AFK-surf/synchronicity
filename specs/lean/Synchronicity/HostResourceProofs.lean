import VerifiedCore.Host.Resources
import Synchronicity.HostProgramProofs

/-! Resource-scope laws for the actual shared combinators. The capability,
error, result and responder state types are arbitrary; no CAS interpreter or
resource policy is assumed. -/
namespace Synchronicity.HostResourceProofs
open VerifiedCore.Host
set_option Elab.async false

variable {E : Type → Type} {ε A B σ : Type}

/-- Any typed stateful host responder. Its state may record request traces,
resource ownership or injected errors; the scope laws do not constrain it. -/
def interpret (respond : {B : Type} → E B → σ → B × σ) : Program E A → σ → A × σ
  | .pure value, state => (value, state)
  | .request effect resume, state =>
    let answer := respond effect state
    interpret respond (resume answer.1) answer.2

theorem interpret_bind (respond : {B : Type} → E B → σ → B × σ)
    (program : Program E A) (next : A → Program E B) (state : σ) :
    interpret respond (program.bind next) state =
      let result := interpret respond program state
      interpret respond (next result.1) result.2 := by
  induction program generalizing state with
  | pure value => rfl
  | request effect resume ih =>
    dsimp only [Program.bind, interpret]
    exact ih (respond effect state).1 (respond effect state).2

/-- The body is sequenced before cleanup, even if its result is an error. -/
theorem ensure_expansion (body : OperationOver E ε A) (cleanup : OperationOver E ε Unit) :
    (ensure body cleanup).run = body.run.bind (fun result =>
      cleanup.run.bind (fun final => .pure (match result with
        | .error error => .error error
        | .ok value => final.map (fun _ => value)))) := rfl

theorem ensure_body_request {C : Type} (effect : E C)
    (resume : C → Program E (Except ε A)) (cleanup : OperationOver E ε Unit) :
    (ensure (ExceptT.mk (.request effect resume)) cleanup).run =
      .request effect (fun answer => (ensure (ExceptT.mk (resume answer)) cleanup).run) := rfl

/-- Pending cleanup is a request, never an already-completed return. Both
body outcomes must resume cleanup before selecting their terminal result. -/
theorem ensure_cleanup_request {C : Type} (result : Except ε A) (effect : E C)
    (resume : C → Program E (Except ε Unit)) :
    (ensure (ExceptT.mk (.pure result)) (ExceptT.mk (.request effect resume))).run =
      .request effect (fun answer =>
        (ensure (ExceptT.mk (.pure result)) (ExceptT.mk (resume answer))).run) := rfl

theorem ensure_failed_body (error : ε) (cleanup : OperationOver E ε Unit) :
    (ensure (ExceptT.mk (.pure (.error error)) : OperationOver E ε A) cleanup).run =
      cleanup.run.bind (fun _ => .pure (.error error)) := rfl

theorem ensure_failed_body_failed_cleanup (primary secondary : ε) :
    (ensure (ExceptT.mk (.pure (.error primary)) : OperationOver E ε A)
      (ExceptT.mk (.pure (.error secondary)))).run = .pure (.error primary) := rfl

theorem ensure_successful_body_failed_cleanup (value : A) (error : ε) :
    (ensure (ExceptT.mk (.pure (.ok value)) : OperationOver E ε A)
      (ExceptT.mk (.pure (.error error)))).run = .pure (.error error) := rfl

theorem ensure_both_successful (value : A) :
    (ensure (ExceptT.mk (.pure (.ok value)) : OperationOver E ε A)
      (ExceptT.mk (.pure (.ok ())))).run = .pure (.ok value) := rfl

/-- Arbitrary stateful interpretation executes cleanup in the body's final
state, preserving all cleanup state changes even when the body failed. -/
theorem interpret_ensure (respond : {B : Type} → E B → σ → B × σ)
    (body : OperationOver E ε A) (cleanup : OperationOver E ε Unit) (state : σ) :
    interpret respond (ensure body cleanup).run state =
      let bodyResult := interpret respond body.run state
      let final := interpret respond cleanup.run bodyResult.2
      ((match bodyResult.1 with
        | .error error => .error error
        | .ok value => final.1.map (fun _ => value)), final.2) := by
  rw [ensure_expansion, interpret_bind]
  dsimp only
  rw [interpret_bind]
  rfl

theorem interpret_ensure_primary_error (respond : {B : Type} → E B → σ → B × σ)
    (body : OperationOver E ε A) (cleanup : OperationOver E ε Unit)
    (state afterBody afterCleanup : σ) (primary : ε) (cleanupResult : Except ε Unit)
    (bodyFailure : interpret respond body.run state = (.error primary, afterBody))
    (cleanupFinished : interpret respond cleanup.run afterBody = (cleanupResult, afterCleanup)) :
    interpret respond (ensure body cleanup).run state = (.error primary, afterCleanup) := by
  rw [interpret_ensure, bodyFailure]
  dsimp only
  rw [cleanupFinished]

/-- Returning success requires both acknowledgements; a successful body alone
cannot escape a failed cleanup. This statement includes arbitrary host state. -/
theorem interpret_ensure_success_iff (respond : {B : Type} → E B → σ → B × σ)
    (body : OperationOver E ε A) (cleanup : OperationOver E ε Unit)
    (state : σ) (value : A) :
    (interpret respond (ensure body cleanup).run state).1 = .ok value ↔
      (interpret respond body.run state).1 = .ok value ∧
      (interpret respond cleanup.run (interpret respond body.run state).2).1 = .ok () := by
  rw [interpret_ensure]
  dsimp only
  cases hbody : (interpret respond body.run state).1 with
  | error error => simp
  | ok result =>
    cases hcleanup : (interpret respond cleanup.run (interpret respond body.run state).2).1 with
    | error error => simp [Except.map]
    | ok ignored => cases ignored; simp [Except.map]

theorem onFailure_success_skips_cleanup (value : A) (cleanup : OperationOver E ε Unit) :
    (onFailure (ExceptT.mk (.pure (.ok value)) : OperationOver E ε A) cleanup).run =
      .pure (.ok value) := rfl

theorem onFailure_error_runs_cleanup (error : ε) (cleanup : OperationOver E ε Unit) :
    (onFailure (ExceptT.mk (.pure (.error error)) : OperationOver E ε A) cleanup).run =
      cleanup.run.bind (fun _ => .pure (.error error)) := rfl

theorem onFailure_primary_error_survives (primary secondary : ε) :
    (onFailure (ExceptT.mk (.pure (.error primary)) : OperationOver E ε A)
      (ExceptT.mk (.pure (.error secondary)))).run = .pure (.error primary) := rfl

theorem onFailure_body_request {C : Type} (effect : E C)
    (resume : C → Program E (Except ε A)) (cleanup : OperationOver E ε Unit) :
    (onFailure (ExceptT.mk (.request effect resume)) cleanup).run =
      .request effect (fun answer => (onFailure (ExceptT.mk (resume answer)) cleanup).run) := rfl

theorem interpret_onFailure (respond : {B : Type} → E B → σ → B × σ)
    (body : OperationOver E ε A) (cleanup : OperationOver E ε Unit) (state : σ) :
    interpret respond (onFailure body cleanup).run state =
      let bodyResult := interpret respond body.run state
      match bodyResult.1 with
      | .ok value => (.ok value, bodyResult.2)
      | .error error => (.error error, (interpret respond cleanup.run bodyResult.2).2) := by
  change interpret respond (body.run.bind _) state = _
  rw [interpret_bind]
  dsimp only
  cases hbody : (interpret respond body.run state).1 with
  | ok value => rfl
  | error error =>
    change interpret respond (cleanup.run.bind (fun _ => .pure (Except.error error : Except ε A))) _ = _
    rw [interpret_bind]
    rfl

end Synchronicity.HostResourceProofs
