import VerifiedCore.Host
import Synchronicity.Decidable

/-! Scripted hosts for whole-program proofs, one handler per capability. A
proof says what its host answers to each algebra the program may request;
the sum instance composes those answers, so an operation over any composed
algebra runs without the proof restating the injection ladder. -/
namespace Synchronicity.Handlers
open VerifiedCore.Host

/-- One scripted capability: for an effect and the script state, the trace
entry to record, the reply and the next state. `none` refuses the effect,
which fails the whole run: an unexpected request is never silently answered. -/
class Handler (E : Type → Type) (σ : Type) (τ : outParam Type) where
  handle : {A : Type} → E A → σ → Option (τ × A × σ)

instance [Handler L σ τ] [Handler R σ τ] : Handler (EffectSum L R) σ τ where
  handle
    | .left effect, state => Handler.handle effect state
    | .right effect, state => Handler.handle effect state

/-- A capability the scripted host never answers. -/
@[reducible] def refuse : Handler E σ τ := ⟨fun _ _ => none⟩

/-- Run a program to completion under the script, collecting the trace. Fuel
bounds the effects answered; a refused effect or exhausted fuel is `none`. -/
def execute [Handler E σ τ] : Nat → Program E A → σ → Option (A × σ × List τ)
  | 0, _, _ => none
  | _ + 1, .pure value, state => some (value, state, [])
  | fuel + 1, .request effect resume, state => do
    let (entry, reply, state) ← Handler.handle effect state
    let (value, state, trace) ← execute fuel (resume reply) state
    return (value, state, entry :: trace)

/-- The result and trace of a run, for proofs that decide them. -/
def run [Handler E σ τ] (fuel : Nat) (program : Program E A) (state : σ) :
    Option (A × List τ) :=
  (execute fuel program state).map fun (value, _, trace) => (value, trace)

end Synchronicity.Handlers
