import VerifiedCore.Host
import Synchronicity.Prelude

/-! Laws and failure traces of the executable shared effect carrier. -/
namespace Synchronicity.HostProgramProofs
open VerifiedCore.Host

theorem bind_pure (program : Program E A) :
    program.bind Program.pure = program := by
  induction program with
  | pure value => rfl
  | request effect resume ih =>
    simp only [Program.bind]
    congr
    funext reply
    exact ih reply

theorem bind_assoc (program : Program E A)
    (next : A → Program E B) (last : B → Program E C) :
    (program.bind next).bind last =
      program.bind (fun value => (next value).bind last) := by
  induction program with
  | pure value => rfl
  | request effect resume ih =>
    simp only [Program.bind]
    congr
    funext reply
    exact ih reply

/-- A failed acquisition of the transaction runs neither the body nor cleanup. -/
theorem transaction_begin (body : Transaction → Operation A) :
    (transaction body).run = Program.request Storage.begin (fun reply =>
      match reply with
      | .error failure => .pure (.error failure)
      | .ok tx => (body tx).run.bind (fun result =>
        match result with
        | .error failure => .request (.rollback tx) (fun _ => .pure (.error failure))
        | .ok value => .request (.commit tx) (fun committed =>
          match committed with
          | .ok () => .pure (.ok value)
          | .error failure => .request (.rollback tx) (fun _ => .pure (.error failure))))) := by
  simp only [transaction, transactionWith, transactionOver, ExceptT.run, ExceptT.mk,
    bind, Program.bind, pure, id]
  congr 1
  funext reply
  cases reply with
  | error failure => rfl
  | ok tx =>
    dsimp only
    apply congrArg (Program.bind (body tx).run)
    funext result
    cases result with
    | error failure => rfl
    | ok value => rfl

/-- A successful body is not enough: only a successful commit returns success.
Commit failure requests rollback and preserves its error, even if rollback fails. -/
theorem transaction_success_body (value : A) :
    (transaction (fun _ => pure value)).run =
      Program.request Storage.begin (fun reply =>
        match reply with
        | .error failure => .pure (.error failure)
        | .ok tx => .request (.commit tx) (fun committed =>
          match committed with
          | .ok () => .pure (.ok value)
          | .error failure => .request (.rollback tx) (fun _ => .pure (.error failure)))) := by
  rfl

/-- Failed bodies never commit. Rollback failure cannot replace the body error. -/
theorem transaction_failed_body (failure : Failure) :
    (transaction (fun _ => (throw failure : Operation A))).run =
      Program.request Storage.begin (fun reply =>
        match reply with
        | .error beginFailure => .pure (.error beginFailure)
        | .ok tx => .request (.rollback tx) (fun _ => .pure (.error failure))) := by
  rfl

/-- A typed domain error follows the same rollback protocol as a host error;
it is never encoded as a successful body or replaced by a rollback failure. -/
theorem transactionWith_failed_body (hostError : Failure → Error) (error : Error) :
    (transactionWith hostError (fun _ => (throw error : OperationWith Error A))).run =
      Program.request Storage.begin (fun reply =>
        match reply with
        | .error beginFailure => .pure (.error (hostError beginFailure))
        | .ok tx => .request (.rollback tx) (fun _ => .pure (.error error))) := by
  rfl

/-- Host begin/commit failures are lifted exactly once. A successful typed
body still cannot report success before the commit acknowledgement. -/
theorem transactionWith_success_body (hostError : Failure → Error) (value : A) :
    (transactionWith hostError (fun _ => pure value)).run =
      Program.request Storage.begin (fun reply =>
        match reply with
        | .error failure => .pure (.error (hostError failure))
        | .ok tx => .request (.commit tx) (fun committed =>
          match committed with
          | .ok () => .pure (.ok value)
          | .error failure => .request (.rollback tx)
              (fun _ => .pure (.error (hostError failure))))) := by
  rfl

/-- Adding domain error types does not create a second transaction algorithm. -/
theorem transaction_specialization (body : Transaction → Operation A) :
    transaction body = transactionWith id body := rfl

/-- Composing another capability does not alter transaction failure semantics.
In particular, a crypto failure in the body cannot commit or lose its error. -/
theorem transactionOver_failed_body {E : Type → Type} (storage : {B : Type} → Storage B → E B)
    (hostError : Failure → Error) (error : Error) :
    (transactionOver storage hostError
      (fun _ => (throw error : OperationOver E Error A))).run =
      Program.request (storage .begin) (fun reply =>
        match reply with
        | .error failure => .pure (.error (hostError failure))
        | .ok tx => .request (storage (.rollback tx)) (fun _ => .pure (.error error))) := by
  rfl

end Synchronicity.HostProgramProofs
