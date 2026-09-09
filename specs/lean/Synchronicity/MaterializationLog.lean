import Synchronicity.MaterializationStream

/-! A proof-only observation log can accompany the streamed SQL consumer.
No production primitive reads this log: changing it leaves replies, faults,
transactions and every other state field unchanged. -/
namespace Synchronicity.MaterializationLog
open VerifiedCore VerifiedCore.Host Replication SimulatedHost

abbrev Log := List (ByteArray × UInt64 × Option ByteArray)
def withLog (state : State) (log : Log) : State := {state with applied := log}
def resultLog (result : Result A) (log : Log) : Result A := (result.1, withLog result.2 log)
def Blind (action : State → Result A) : Prop :=
  ∀ state log, action (withLog state log) = resultLog (action state) log

theorem reply_blind (event : String) (action : State → Result (Reply A)) (consume : Bool)
    (blind : Blind action) : Blind (fun state => reply state event action consume) := by
  intro state log
  unfold reply
  change (match fault state with
    | some failure => (Except.error failure, record (if consume then (action (withLog state log)).2 else withLog state log) event)
    | none => ((action (withLog state log)).1, record (action (withLog state log)).2 event)) = _
  rw [blind]
  dsimp only
  cases fault state <;> cases consume <;> simp [resultLog, withLog, record]

theorem transaction_blind (tx : Transaction) (action : Database → A × Database) :
    Blind (fun state => SimulatedHost.transaction state tx action) := by
  intro state log
  unfold SimulatedHost.transaction
  change (match state.pending with
    | some (token, db) => if token == tx then
      (Except.ok (action db).1, {withLog state log with pending := some (token, (action db).2)})
      else (Except.error invalid, withLog state log)
    | none => (Except.error invalid, withLog state log)) = _
  dsimp only
  cases state.pending with
  | none => rfl
  | some entry =>
    rcases entry with ⟨token, db⟩
    dsimp only
    split <;> rfl

theorem storage_blind (effect : Storage A) : Blind (storage effect) := by
  change Blind (fun state => storage effect state)
  cases effect <;> simp only [storage]
  all_goals apply reply_blind; intro state log
  all_goals first
    | exact transaction_blind _ _ state log
    | rfl
    | (dsimp only [withLog, resultLog]; repeat' first | rfl | (split <;> simp_all only))
  case readInput handle offset count =>
    cases (state.handles.find? fun entry => entry.1 == handle).map Prod.snd with
    | none => simp only
    | some bytes =>
      simp only
      split <;> rfl

theorem materialize_effect_blind (effect : Materialize.Effects A) : Blind (Interpreter.handle effect) := by
  cases effect with
  | left effect => exact storage_blind effect
  | right effect =>
    rcases effect with effect | effect
    · cases effect <;> apply reply_blind <;> intro state log <;> rfl
    · rcases effect with effect | effect
      · cases effect <;> simp only [Interpreter.handle, access]
        all_goals apply reply_blind; intro state log
        all_goals first | exact transaction_blind _ _ state log | rfl
      · rcases effect with effect | effect
        · cases effect; apply reply_blind; intro state log; rfl
        · rcases effect with effect | effect
          · cases effect; apply reply_blind; intro state log; rfl
          · rcases effect with effect | effect
            · cases effect; apply reply_blind; intro state log; rfl
            · cases effect; apply reply_blind; intro state log; rfl

theorem execute_blind [Interpreter E] (program : Program E A)
    (effects : ∀ {B} (effect : E B), Blind (Interpreter.handle effect)) : Blind (execute program) := by
  intro state log
  induction program generalizing state with
  | pure value => rfl
  | request effect next ih =>
    simp only [execute, effects effect state log, resultLog]
    exact ih _ _

theorem materialize_blind (program : Materialize.Action A) : Blind (execute program) :=
  execute_blind program.run materialize_effect_blind

theorem blind_keeps_log (action : State → Result A) (blind : Blind action) (state : State) :
    (action state).2.applied = state.applied := by
  have same := blind state state.applied
  change action state = resultLog (action state) state.applied at same
  exact congrArg (fun result => result.2.applied) same

def consume (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) : Apply A → State → Result A
  | .applyChange key kind value, state =>
    let (result, after) := execute (emit key kind value) state
    (result.mapError (fun _ => invalid), withLog after (state.applied ++ [(key, kind, value)]))

@[instance_reducible]
def consumer (tx : Transaction) (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) :
    Interpreter Trie.Diff.Effects where
  handle
    | .left effect, state => storage effect state
    | .right (.left effect), state => storage (Materialize.redactionIn tx effect) state
    | .right (.right (.left effect)), state => digest effect state
    | .right (.right (.right effect)), state => consume emit effect state

instance consumer_reads (tx : Transaction) (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) :
    TrieDiffCoverage.ReadsAgree (consumer tx emit) := by
  constructor
  intro A effect allowed state
  cases effect with
  | left effect => rfl
  | right effect =>
    rcases effect with effect | effect
    · cases effect; contradiction
    · rcases effect with effect | effect
      · rfl
      · cases effect; contradiction

theorem digest_blind (effect : Digest A) : Blind (digest effect) := by
  cases effect; apply reply_blind; intro state log; rfl

/-- Instrumentation changes only the proof log, never the successful SQL
execution or its fault/trace indices. -/
theorem consumer_success (tx : Transaction) (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit)
    (program : Program Trie.Diff.Effects A) (state final : State) (answer : A) (initialLog : Log)
    (ran : @execute _ _ (MaterializationStream.consumer tx emit) program state = (answer, final)) :
    ∃ log, @execute _ _ (consumer tx emit) program (withLog state initialLog) = (answer, withLog final log) := by
  induction program generalizing state final initialLog with
  | pure value =>
    cases ran
    exact ⟨initialLog, rfl⟩
  | request effect next ih =>
    cases effect with
    | left effect =>
      simp only [execute, Interpreter.handle, storage_blind effect state initialLog, resultLog]
      exact ih _ _ _ initialLog ran
    | right effect =>
      rcases effect with effect | effect
      · simp only [execute, Interpreter.handle, storage_blind (Materialize.redactionIn tx effect) state initialLog, resultLog]
        exact ih _ _ _ initialLog ran
      · rcases effect with effect | effect
        · simp only [execute, Interpreter.handle, digest_blind effect state initialLog, resultLog]
          exact ih _ _ _ initialLog ran
        · cases effect with
          | applyChange key kind value =>
            have adapted : execute (emit key kind value) (withLog state initialLog) =
                resultLog (execute (emit key kind value) state) initialLog := materialize_blind _ state initialLog
            simp only [execute, Interpreter.handle, consume]
            rw [adapted]
            simp only [resultLog, withLog]
            exact ih _ _ _ (initialLog ++ [(key, kind, value)]) ran

theorem run_diff_success (tx : Transaction) (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit)
    (program : Program Trie.Diff.Effects (Except Trie.Walk.Error A))
    (state final : State) (answer : A)
    (ran : execute (Materialize.runDiff tx emit program) state = (.ok answer, final)) :
    ∃ log, @execute _ _ (consumer tx emit) program (withLog state []) = (.ok answer, withLog final log) :=
  consumer_success tx emit program state final (.ok answer) [] (MaterializationStream.run_diff_success tx emit program state final answer ran)

end Synchronicity.MaterializationLog
