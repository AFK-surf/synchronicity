import Synchronicity.MaterializationLog
import Synchronicity.MaterializationReadFrame

/-! Coverage of the actual SQL-consuming stream, using a proved observational
instrumentation. The emitter's immutable-read frame is derived for production
`apply`; the theorem does not assume that SQL has produced an exact view. -/
namespace Synchronicity.MaterializationCoverage
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase
open Trie Trie.Walk TrieDiffCoverage TrieDiffSemantics TrieSnapshotProofs
open TrieCursorSemantics
open MaterializationLog

def FaithfulEmitter (world : World)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) : Prop :=
  ∀ state final key kind value, Faithful world state →
    execute (emit key kind value) state = (.ok (), final) → Faithful world final

theorem apply_success (tx : Transaction) (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit)
    (key : ByteArray) (kind : UInt64) (value : Option ByteArray) (state final : State)
    (ran : @execute _ _ (consumer tx emit)
      (Diff.apply (E := Diff.Effects) (.applyChange key kind value)).run state = (.ok (), final)) :
    ∃ after, execute (emit key kind value) state = (.ok (), after) ∧
      final = withLog after (state.applied ++ [(key, kind, value)]) := by
  simp only [Diff.apply, raise, performOver, Inject.inject, ExceptT.mk, ExceptT.run,
    execute, Interpreter.handle, consume] at ran
  cases emitted : execute (emit key kind value) state with
  | mk result after =>
    cases result with
    | error error => simp [emitted, Except.mapError] at ran
    | ok result =>
      cases result
      simp only [emitted, Except.mapError, Prod.mk.injEq, true_and] at ran
      exact ⟨after, rfl, ran.symm⟩

theorem apply_delivers (tx : Transaction) (world : World) (key : ByteArray)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) (frame : FaithfulEmitter world emit)
    (state final : State) (changed : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (faithful : Faithful world state)
    (ran : @execute _ _ (consumer tx emit)
      (Diff.apply (E := Diff.Effects) (.applyChange changed kind value)).run state = (.ok (), final)) :
    Faithful world final ∧ (AppliedKey key state count ∨ changed = key → AppliedKey key final count') := by
  obtain ⟨after, emitted, same⟩ := apply_success tx emit changed kind value state final ran
  rw [same]
  refine ⟨frame state after changed kind value faithful emitted, ?_⟩
  rintro (⟨event, member, target⟩ | target)
  · exact ⟨event, List.mem_append_left _ member, target⟩
  · exact ⟨(changed, kind, value), List.mem_append_right _ (by simp), target⟩

theorem emit_contract (tx : Transaction) (world : World) (key : ByteArray)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) (frame : FaithfulEmitter world emit) :
    EmitContract (handler := consumer tx emit) world key (AppliedKey key) materializeEmit := by
  letI : Interpreter Diff.Effects := consumer tx emit
  intro state count change answer final faithful ran
  unfold materializeEmit at ran
  have sequence : execute ((match change.new with
      | none => pure none | some value => some <$> resolve value) >>= fun new => do
        Diff.apply (.applyChange change.key change.kind new)
        pure (count + 1) : TrieDiffCoverage.Action UInt64) state = (.ok answer, final) := by
    cases h : change.new <;> simpa only [h] using ran
  obtain ⟨new, resolved, resolveRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ sequence
  have safe : Only readAllowed ((match change.new with
      | none => pure none | some value => some <$> resolve value) : TrieDiffCoverage.Action (Option ByteArray)).run := by
    cases change.new with
    | none => exact .done _
    | some value => exact Only.map _ _ (resolve_readonly value)
  have facts := readonly_result world (AppliedKey key) (applied_stable key) _ safe state resolved _ count faithful resolveRun
  obtain ⟨result, applied, applyRun, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
  cases result
  cases returned
  have delivered := apply_delivers (count := count) (count' := count + 1)
    tx world key emit frame resolved final change.key change.kind new facts.1 applyRun
  refine ⟨delivered.1, ?_⟩
  rintro (already | target)
  · exact delivered.2 (.inl (facts.2 already))
  · exact delivered.2 (.inr target)

theorem log_covers (tx : Transaction) (world : World) (scope : Serve.Scope)
    (oldRoot newRoot key : ByteArray) (bound : key.size ≤ maxKeyBytes)
    (granted : scope.admitsKeyPath (keyNibbles key) = true)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) (frame : FaithfulEmitter world emit)
    (state final : State) (count : UInt64) (faithful : Faithful world state)
    (different : SnapshotDelta.ChangedKey world.snapshot oldRoot newRoot key)
    (ran : @execute _ _ (consumer tx emit) (Diff.materialize (E := Diff.Effects) scope oldRoot newRoot).run
      state = (.ok count, final)) : ∃ event ∈ final.applied, event.1 = key := by
  letI : Interpreter Diff.Effects := consumer tx emit
  have difference : ∃ bytes, ¬(ReferenceEntry world.snapshot (rootOf oldRoot) (keyNibbles key) bytes ↔
      ReferenceEntry world.snapshot (rootOf newRoot) (keyNibbles key) bytes) := by
    simpa only [SnapshotDelta.ChangedKey, reference_meaning world.snapshot oldRoot key _ bound,
      reference_meaning world.snapshot newRoot key _ bound] using different
  exact diff_each_covers world key bound (AppliedKey key) (applied_stable key) materializeEmit
    (emit_contract tx world key emit frame) scope granted oldRoot newRoot state final 0 count faithful difference ran

/-- A local invariant law for actual SQL writes composes through the logged
stream. The callback is required to handle only resolved, valid snapshot deltas;
those facts are derived from the cursor position and immutable value read. -/
theorem callback_preserves (tx : Transaction) (world : World) (oldRoot newRoot : ByteArray)
    (scope : Serve.Scope) (P : State → Prop)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) (frame : FaithfulEmitter world emit)
    (stable : ReadStable (handler := consumer tx emit) (fun state (_ : UInt64) => P state))
    (law : ∀ state after key kind value, Faithful world state → P state →
      MaterializationStream.Update world oldRoot newRoot key kind value →
      scope.admitsKeyPath (keyNibbles key) = true → execute (emit key kind value) state = (.ok (), after) →
      P (withLog after (state.applied ++ [(key, kind, value)]))) :
    TrieDiffSoundness.ConsumerLaw (handler := consumer tx emit) world oldRoot newRoot scope
      (fun state (_ : UInt64) => P state) materializeEmit := by
  letI : Interpreter Diff.Effects := consumer tx emit
  intro state count change answer final faithful holds valid granted ran
  unfold materializeEmit at ran
  have sequence : execute ((match change.new with
      | none => pure none | some value => some <$> resolve value) >>= fun new => do
        Diff.apply (.applyChange change.key change.kind new)
        pure (count + 1) : TrieDiffCoverage.Action UInt64) state = (.ok answer, final) := by
    cases h : change.new <;> simpa only [h] using ran
  obtain ⟨new, resolved, resolveRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ sequence
  have safe : Only readAllowed ((match change.new with
      | none => pure none | some value => some <$> resolve value) : TrieDiffCoverage.Action (Option ByteArray)).run := by
    cases change.new with
    | none => exact .done _
    | some value => exact Only.map _ _ (resolve_readonly value)
  have facts := readonly_result world (fun state (_ : UInt64) => P state) stable _ safe state resolved _ count faithful resolveRun
  have update := MaterializationStream.resolved_update valid
    (TrieDiffSoundness.resolve_optional_exact world state resolved change.new new faithful resolveRun)
  obtain ⟨result, applied, applyRun, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
  cases result
  cases returned
  obtain ⟨after, emitted, same⟩ := apply_success tx emit change.key change.kind new resolved final applyRun
  rw [same]
  exact ⟨frame resolved after change.key change.kind new facts.1 emitted,
    law resolved after change.key change.kind new facts.1 (facts.2 holds) update granted emitted⟩

/-- A single observational log of the actual SQL stream covers every
permitted changed key, not a separately assumed or reconstructed diff list. -/
theorem materialize_covers (tx : Transaction) (world : World) (scope : Serve.Scope)
    (origin : String) (now releaseNow : Int64) (replicas : List Materialize.Target)
    (oldRoot newRoot : ByteArray) (state final : State) (count : UInt64)
    (faithful : Faithful world state)
    (ran : execute (Materialize.runDiff tx (Materialize.apply tx origin now releaseNow replicas)
      (Diff.materialize (E := Diff.Effects) scope oldRoot newRoot).run) state = (.ok count, final)) :
    ∃ log, @execute _ _ (consumer tx (Materialize.apply tx origin now releaseNow replicas))
        (Diff.materialize (E := Diff.Effects) scope oldRoot newRoot).run (withLog state []) = (.ok count, withLog final log) ∧
      ∀ key, key.size ≤ maxKeyBytes → scope.admitsKeyPath (keyNibbles key) = true →
        SnapshotDelta.ChangedKey world.snapshot oldRoot newRoot key → ∃ event ∈ log, event.1 = key := by
  obtain ⟨log, observed⟩ := MaterializationLog.run_diff_success tx _ _ state final count ran
  refine ⟨log, observed, ?_⟩
  intro key bound granted changed
  exact log_covers tx world scope oldRoot newRoot key bound granted _
    (fun state final key kind value faithful ran => MaterializationReadFrame.apply_faithful
      world tx origin now releaseNow replicas key kind value state final (.ok ()) faithful ran)
    (withLog state []) (withLog final log) count faithful changed observed

end Synchronicity.MaterializationCoverage
