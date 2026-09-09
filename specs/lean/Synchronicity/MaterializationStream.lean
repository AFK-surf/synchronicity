import Synchronicity.TrieDiffSoundness
import Synchronicity.MaterializationPrivate

/-! The production SQL consumer executes the same structural stream. The
interpreter below is a semantic adapter for the actual Lean emitter, not an
assumption about the view it produces. Its success simulation preserves the
entire state, including fault indices and transaction-private writes. -/
namespace Synchronicity.MaterializationStream
open VerifiedCore VerifiedCore.Host Replication SimulatedHost TrieDiffCoverage PrivateDatabase
open TrieDiffSoundness TrieDiffSemantics TrieProgramProofs

/-- A failed SQL callback aborts production `runDiff`. Only its successful
case is used by the simulation, so the auxiliary error token is unobservable. -/
def consumeApply (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) :
    Apply A → State → Result A
  | .applyChange key kind value, state =>
    let (result, final) := execute (emit key kind value) state
    (result.mapError (fun _ => invalid), final)

@[instance_reducible]
def consumer (tx : Transaction)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) :
    Interpreter Trie.Diff.Effects where
  handle
    | .left effect, state => storage effect state
    | .right (.left effect), state => storage (Materialize.redactionIn tx effect) state
    | .right (.right (.left effect)), state => digest effect state
    | .right (.right (.right effect)), state => consumeApply emit effect state

instance consumer_reads (tx : Transaction)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) :
    ReadsAgree (consumer tx emit) := by
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

/-- Every successful execution of the actual `runDiff` has the same result
and complete state under the structural walk interpreter whose Apply executes
that very SQL callback. No callback correctness premise is needed here. -/
theorem run_diff_success (tx : Transaction)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit)
    (program : Program Trie.Diff.Effects (Except Trie.Walk.Error A))
    (state final : State) (answer : A)
    (ran : execute (Materialize.runDiff tx emit program) state = (.ok answer, final)) :
    @execute _ _ (consumer tx emit) program state = (.ok answer, final) := by
  induction program generalizing state final with
  | pure result =>
    cases result <;> cases ran
    rfl
  | request effect next ih =>
    cases effect with
    | left effect =>
      simp only [Materialize.runDiff, observe, ExceptT.mk, bind, ExceptT.bind,
        ExceptT.bindCont, execute, Program.bind, Inject.inject,
        Interpreter.handle] at ran
      exact ih _ _ _ ran
    | right effect =>
      rcases effect with effect | effect
      · simp only [Materialize.runDiff, observe, ExceptT.mk, bind, ExceptT.bind,
          ExceptT.bindCont, execute, Program.bind, Inject.inject,
          Interpreter.handle] at ran
        exact ih _ _ _ ran
      · rcases effect with effect | effect
        · simp only [Materialize.runDiff, observe, ExceptT.mk, bind, ExceptT.bind,
            ExceptT.bindCont, execute, Program.bind, Inject.inject,
            Interpreter.handle] at ran
          exact ih _ _ _ ran
        · cases effect with
          | applyChange key kind value =>
            obtain ⟨result, middle, emitted, rest⟩ :=
              TransactionSuccess.bind_success _ _ _ _ _ ran
            cases result
            simp only [execute, Interpreter.handle, consumeApply, emitted, Except.mapError]
            exact ih (.ok ()) middle final rest

/-- Resolved bytes and change kind carry the independent snapshot delta
into SQL; this property says nothing about the resulting SQL view. -/
def Update (world : World) (oldRoot newRoot key : ByteArray) (kind : UInt64) (value : Option ByteArray) : Prop :=
  ∃ oldValue, SnapshotDelta.Changes world.snapshot oldRoot newRoot key oldValue value ∧
    kind = SnapshotDelta.kind oldValue value

theorem resolved_update (valid : ValidChange world oldRoot newRoot change)
    (resolved : OptionalValue world.snapshot change.new value) :
    Update world oldRoot newRoot change.key change.kind value := by
  obtain ⟨oldValue, newValue, delta, old, new⟩ := valid_change_meaning valid
  have same := optional_value_unique new resolved
  subst newValue
  refine ⟨oldValue, delta, ?_⟩
  rcases change with ⟨key, oldRef, newRef⟩
  cases old <;> cases new <;> rfl

/-- A local SQL refinement obligation, to be proved for `Materialize.apply`.
It requires only the correct input delta and the previous domain invariant;
it does not assume correctness of the completed view. -/
def SqlLaw (world : World) (oldRoot newRoot : ByteArray) (scope : Trie.Serve.Scope)
    (P : State → Prop) (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) : Prop :=
  ∀ state final key kind value, Faithful world state → P state →
    Update world oldRoot newRoot key kind value → scope.admitsKeyPath (Trie.keyNibbles key) = true →
    execute (emit key kind value) state = (.ok (), final) → Faithful world final ∧ P final

theorem consumer_apply_success (tx : Transaction)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit)
    (key : ByteArray) (kind : UInt64) (value : Option ByteArray) (state final : State)
    (ran : @execute _ _ (consumer tx emit)
      (Trie.Diff.apply (E := Trie.Diff.Effects) (.applyChange key kind value)).run state = (.ok (), final)) :
    execute (emit key kind value) state = (.ok (), final) := by
  simp only [Trie.Diff.apply, raise, performOver, Inject.inject, ExceptT.mk, ExceptT.run, execute,
    Interpreter.handle, consumeApply] at ran
  cases emitted : execute (emit key kind value) state with
  | mk result after =>
    cases result with
    | error error => simp [emitted, Except.mapError] at ran
    | ok result =>
      cases result
      simp only [emitted, Except.mapError, Prod.mk.injEq, true_and] at ran
      cases ran
      rfl

theorem sql_callback_law (tx : Transaction) (world : World) (oldRoot newRoot : ByteArray)
    (scope : Trie.Serve.Scope) (P : State → Prop)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit)
    (stable : ReadStable (handler := consumer tx emit) (fun state (_ : UInt64) => P state))
    (law : SqlLaw world oldRoot newRoot scope P emit) :
    ConsumerLaw (handler := consumer tx emit) world oldRoot newRoot scope (fun state (_ : UInt64) => P state)
      materializeEmit := by
  letI : Interpreter Trie.Diff.Effects := consumer tx emit
  intro state count change answer final faithful holds valid granted ran
  unfold materializeEmit at ran
  have sequence : execute ((match change.new with
      | none => pure none | some value => some <$> Trie.Walk.resolve value) >>= fun new => do
        Trie.Diff.apply (.applyChange change.key change.kind new)
        pure (count + 1) : TrieDiffCoverage.Action UInt64) state = (.ok answer, final) := by
    cases h : change.new <;> simpa only [h] using ran
  obtain ⟨new, resolved, resolveRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ sequence
  have safe : Only readAllowed ((match change.new with
      | none => pure none | some value => some <$> Trie.Walk.resolve value) :
      TrieDiffCoverage.Action (Option ByteArray)).run := by
    cases change.new with
    | none => exact .done _
    | some value => exact Only.map _ _ (resolve_readonly value)
  have resolvedFacts := readonly_result world (fun state (_ : UInt64) => P state) stable _ safe
    state resolved _ count faithful resolveRun
  have update := resolved_update valid (resolve_optional_exact world state resolved change.new new faithful resolveRun)
  obtain ⟨result, applied, applyRun, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
  cases result
  cases returned
  exact law resolved final change.key change.kind new resolvedFacts.1 (resolvedFacts.2 holds) update granted
    (consumer_apply_success tx emit change.key change.kind new resolved final applyRun)

/-- A proved local SQL refinement composes through the actual streamed
materializer, including value reads, filtering and every traversal iteration. -/
theorem run_materialize_preserves (tx : Transaction) (world : World) (oldRoot newRoot : ByteArray)
    (scope : Trie.Serve.Scope) (P : State → Prop)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit)
    (stable : ReadStable (handler := consumer tx emit) (fun state (_ : UInt64) => P state))
    (law : SqlLaw world oldRoot newRoot scope P emit)
    (state final : State) (count : UInt64) (faithful : Faithful world state) (holds : P state)
    (ran : execute (Materialize.runDiff tx emit
      (Trie.Diff.materialize (E := Trie.Diff.Effects) scope oldRoot newRoot).run) state = (.ok count, final)) :
    Faithful world final ∧ P final := by
  letI : Interpreter Trie.Diff.Effects := consumer tx emit
  exact diff_each_preserves world oldRoot newRoot (fun state (_ : UInt64) => P state) stable
    materializeEmit scope (sql_callback_law tx world oldRoot newRoot scope P emit stable law)
    state final 0 count faithful holds (run_diff_success tx emit _ state final count ran)

end Synchronicity.MaterializationStream
