import Synchronicity.MaterializationViewProgress

/-! End-to-end exact file views for the production streamed SQL materializer.
The old-view invariant and immutable snapshot contracts imply the complete new
view; neither successful traversal nor a completeness flag defines readiness. -/
namespace Synchronicity.MaterializationExactFiles
open VerifiedCore VerifiedCore.Host Replication SimulatedHost
open MaterializedView SnapshotViewProgress TrieDiffCoverage MaterializationLog

def visited (state : State) (key : ByteArray) : Prop := ∃ event ∈ state.applied, event.1 = key

def Progress (tx : Transaction) (origin : String) (services : Services) (world : World)
    (scope : Trie.Serve.Scope) (oldRoot newRoot : ByteArray) (state : State) : Prop :=
  ∃ db, state.pending = some (tx, db) ∧ state.isNfc = services.nfc ∧
    ExactFilesAt (visited state) services world.snapshot oldRoot newRoot
      (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) db origin

theorem visited_append (state after : State) (key : ByteArray) (kind : UInt64) (value : Option ByteArray) :
    visited (withLog after (state.applied ++ [(key, kind, value)])) = (fun other => visited state other ∨ other = key) := by
  funext other
  apply propext
  constructor
  · rintro ⟨event, member, target⟩
    rcases List.mem_append.mp member with old | new
    · exact Or.inl ⟨event, old, target⟩
    · have same := List.mem_singleton.mp new
      subst event
      exact Or.inr target.symm
  · rintro (⟨event, member, target⟩ | rfl)
    · exact ⟨event, List.mem_append_left _ member, target⟩
    · exact ⟨(other, kind, value), List.mem_append_right _ (by simp), rfl⟩

theorem progress_stable (tx : Transaction) (origin : String) (services : Services) (world : World)
    (scope : Trie.Serve.Scope) (oldRoot newRoot : ByteArray)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) :
    ReadStable (handler := consumer tx emit)
      (fun state (_ : UInt64) => Progress tx origin services world scope oldRoot newRoot state) := by
  intro B effect allowed state count holds
  rw [ReadsAgree.reads effect allowed]
  cases effect with
  | left effect =>
    cases effect <;> try contradiction
    simp only [Interpreter.handle, storage, reply]
    split <;> exact holds
  | right effect =>
    rcases effect with effect | effect
    · cases effect; contradiction
    · rcases effect with effect | effect
      · cases effect
        simp only [Interpreter.handle, digest, reply]
        split <;> exact holds
      · cases effect; contradiction

theorem apply_progress (tx : Transaction) (origin : String) (services : Services) (world : World)
    (scope : Trie.Serve.Scope) (oldRoot newRoot : ByteArray)
    (unique : UniqueAddresses services (Relevant world.snapshot oldRoot newRoot))
    (now releaseNow : Int64) (replicas : List Materialize.Target)
    (state after : State) (key : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (holds : Progress tx origin services world scope oldRoot newRoot state)
    (changed : MaterializationStream.Update world oldRoot newRoot key kind value)
    (granted : scope.admitsKeyPath (Trie.keyNibbles key) = true)
    (ran : execute (Materialize.apply tx origin now releaseNow replicas key kind value) state = (.ok (), after)) :
    Progress tx origin services world scope oldRoot newRoot (withLog after (state.applied ++ [(key, kind, value)])) := by
  obtain ⟨db, opened, normalization, initial⟩ := holds
  obtain ⟨finalDb, pending, exactView⟩ := MaterializationViewProgress.apply_progress world services oldRoot newRoot
    _ (visited state) unique tx origin now releaseNow replicas key kind value state after db opened normalization initial changed granted ran
  have safe := MaterializationTableFrame.apply_safe Trie.nodeSpace (by decide) tx origin now releaseNow replicas key kind value
  have servicesFrame := MaterializationReadFrame.executed_context Trie.nodeSpace _ safe state after (.ok ()) ran
  have nfc : after.isNfc = state.isNfc := congrArg (fun ctx => ctx.2.2.2.2.1) servicesFrame
  refine ⟨finalDb, pending, nfc.trans normalization, ?_⟩
  rw [visited_append]
  exact exactView

/-- The actual successful SQL-consuming materializer leaves exactly the new
snapshot's permitted file list, including deletions and unchanged records.
Canonical published names, bounded supported keys, fixed scope/normalization,
and an exact old view are explicit input contracts. -/
theorem materialize_exact (tx : Transaction) (origin : String) (services : Services) (world : World)
    (scope : Trie.Serve.Scope) (oldRoot newRoot : ByteArray)
    (unique : UniqueAddresses services (Relevant world.snapshot oldRoot newRoot))
    (supported : ∀ key, scope.admitsKeyPath (Trie.keyNibbles key) = true →
      SnapshotDelta.ChangedKey world.snapshot oldRoot newRoot key → key.size ≤ Trie.maxKeyBytes)
    (now releaseNow : Int64) (replicas : List Materialize.Target)
    (state final : State) (count : UInt64) (db : Database) (opened : state.pending = some (tx, db))
    (normalization : state.isNfc = services.nfc) (faithful : Faithful world state)
    (initial : ExactFiles services world.snapshot oldRoot
      (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) db origin)
    (ran : execute (Materialize.runDiff tx (Materialize.apply tx origin now releaseNow replicas)
      (Trie.Diff.materialize (E := Trie.Diff.Effects) scope oldRoot newRoot).run) state = (.ok count, final)) :
    ∃ after, final.pending = some (tx, after) ∧
      ExactFiles services world.snapshot newRoot (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) after origin := by
  let emit := Materialize.apply tx origin now releaseNow replicas
  letI : Interpreter Trie.Diff.Effects := consumer tx emit
  obtain ⟨log, observed, covered⟩ := MaterializationCoverage.materialize_covers tx world scope origin now releaseNow replicas
    oldRoot newRoot state final count faithful ran
  have frame : MaterializationCoverage.FaithfulEmitter world emit :=
    fun state final key kind value faithful ran => MaterializationReadFrame.apply_faithful world tx origin now releaseNow replicas
      key kind value state final (.ok ()) faithful ran
  have initially : Progress tx origin services world scope oldRoot newRoot (withLog state []) := by
    refine ⟨db, opened, normalization, ?_⟩
    have unseen : visited (withLog state []) = (fun _ => False) := by
      funext key
      simp [visited, withLog]
    rw [unseen]
    exact initially_exact initial
  have law := MaterializationCoverage.callback_preserves tx world oldRoot newRoot scope
    (Progress tx origin services world scope oldRoot newRoot) emit frame
    (progress_stable tx origin services world scope oldRoot newRoot emit)
    (fun state after key kind value _ holds changed granted ran =>
      apply_progress tx origin services world scope oldRoot newRoot unique now releaseNow replicas state after key kind value holds changed granted ran)
  have preserved := TrieDiffSoundness.diff_each_preserves world oldRoot newRoot
    (fun state (_ : UInt64) => Progress tx origin services world scope oldRoot newRoot state)
    (progress_stable tx origin services world scope oldRoot newRoot emit) materializeEmit scope law
    (withLog state []) (withLog final log) 0 count faithful initially observed
  obtain ⟨after, pending, _, exactView⟩ := preserved.2
  refine ⟨after, pending, ?_⟩
  exact finally_exact (visited (withLog final log)) services world.snapshot oldRoot newRoot _ after origin
    (fun key granted changed => covered key (supported key granted changed) granted changed) exactView

end Synchronicity.MaterializationExactFiles
