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
  rfl

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

end Synchronicity.HostProgramProofs
