import Synchronicity.MaterializationFileRetention
import Synchronicity.MaterializationCoverage

/-! Whole-callback and whole-stream retention safety. Every resulting current
file reference has a live hold or acquisition request, and forever obligations
from the initial view survive. All permissions follow actual rows/continuations. -/
namespace Synchronicity.MaterializationWholeRetention
open VerifiedCore VerifiedCore.Host Replication SimulatedHost
open MaterializedView MaterializationRetention MaterializationRequirementFrame MaterializationRetentionTail
open MaterializationTableFrame TrieDiffCoverage

theorem tables_preserve (replicas : List Materialize.Target) (baseline before after : Database)
    (entries : rows after "entries" = rows before "entries")
    (pins : rows after "pins" = rows before "pins") (wants : rows after "content_want" = rows before "content_want")
    (requirements : Requirements replicas baseline before) : Requirements replicas baseline after := by
  have retained : Retains before after := rows_retain (fun _ member => pins ▸ member) (fun _ member => wants ▸ member)
  refine ⟨?_, retains_forever replicas baseline before after requirements.2 retained⟩
  intro target member row present space root content
  exact retained root target.holder (requirements.1 target member row (entries ▸ present) space root content)

theorem apply_requirements (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (key : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (policy : PoliciesAgree replicas) (baseline : Database) (state final : State) (db : Database)
    (opened : state.pending = some (tx, db)) (schema : MaterializationKeySchema.Schema db)
    (requirements : Requirements replicas baseline db)
    (ran : execute (Materialize.apply tx origin now releaseNow replicas key kind value) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Requirements replicas baseline after := by
  by_cases tag : key[0]? = some 102
  · cases parsed : Records.fileKey key with
    | none =>
      simp only [Materialize.apply, tag, beq_self_eq_true, ↓reduceIte, parsed,
        pure, ExceptT.pure, ExceptT.mk, execute] at ran
      cases ran
      exact ⟨db, opened, requirements⟩
    | some pair =>
      exact MaterializationFileRetention.apply_file_preserves tx origin pair.1 pair.2 now releaseNow replicas key kind value
        policy baseline state final db opened schema requirements tag parsed ran
  · have safe (relation : String) (other : "blob_providers" ≠ relation) (bindings : "bindings" ≠ relation) :=
      nonfile_table_safe relation other bindings tx origin now releaseNow replicas key kind value tag
    obtain ⟨after, pending, entries⟩ := frame_opened "entries" _ (safe "entries" (by decide) (by decide))
      state final (.ok ()) tx db opened ran
    have same (relation : String) (other : "blob_providers" ≠ relation) (bindings : "bindings" ≠ relation) :
        rows after relation = rows db relation := by
      have frame := executed_frame relation _ (safe relation other bindings) state final (.ok ()) ran
      simpa only [view, pending, opened, Option.map_some, Option.some.injEq, Prod.mk.injEq, true_and] using frame
    exact ⟨after, pending, tables_preserve replicas baseline db after entries
      (same "pins" (by decide) (by decide)) (same "content_want" (by decide) (by decide)) requirements⟩

def Invariant (tx : Transaction) (replicas : List Materialize.Target) (baseline : Database) (state : State) : Prop :=
  ∃ db, state.pending = some (tx, db) ∧ MaterializationKeySchema.Schema db ∧ Requirements replicas baseline db

theorem apply_invariant (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (key : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (policy : PoliciesAgree replicas) (baseline : Database) (state final : State)
    (initial : Invariant tx replicas baseline state)
    (ran : execute (Materialize.apply tx origin now releaseNow replicas key kind value) state = (.ok (), final)) :
    Invariant tx replicas baseline final := by
  obtain ⟨db, opened, schema, requirements⟩ := initial
  obtain ⟨after, pending, preserved⟩ := apply_requirements tx origin now releaseNow replicas key kind value policy
    baseline state final db opened schema requirements ran
  have typed := MaterializationKeySchema.executed_keeps tx _
    (MaterializationKeySchema.apply_keeps tx origin now releaseNow replicas key kind value) state ⟨db, opened, schema⟩
  rw [ran] at typed
  obtain ⟨typedDb, typedTx, schema⟩ := typed
  have same : after = typedDb := congrArg Prod.snd (Option.some.inj (pending.symm.trans typedTx))
  subst typedDb
  exact ⟨after, pending, schema, preserved⟩

theorem read_stable (tx : Transaction) (replicas : List Materialize.Target) (baseline : Database)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) :
    ReadStable (handler := MaterializationStream.consumer tx emit)
      (fun state (_ : UInt64) => Invariant tx replicas baseline state) := by
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

theorem materialize_requirements (tx : Transaction) (origin : String) (world : World) (scope : Trie.Serve.Scope)
    (oldRoot newRoot : ByteArray) (now releaseNow : Int64) (replicas : List Materialize.Target)
    (policy : PoliciesAgree replicas) (state final : State) (count : UInt64) (db : Database)
    (opened : state.pending = some (tx, db)) (faithful : Faithful world state)
    (schema : MaterializationKeySchema.Schema db) (current : CurrentRequirements replicas db)
    (ran : execute (Materialize.runDiff tx (Materialize.apply tx origin now releaseNow replicas)
      (Trie.Diff.materialize (E := Trie.Diff.Effects) scope oldRoot newRoot).run) state = (.ok count, final)) :
    ∃ after, final.pending = some (tx, after) ∧ MaterializationKeySchema.Schema after ∧
      CurrentRequirements replicas after ∧ ForeverRequirements replicas db after := by
  have initially : Invariant tx replicas db state := ⟨db, opened, schema, current, fun _ _ _ _ held => held⟩
  have law : MaterializationStream.SqlLaw world oldRoot newRoot scope (Invariant tx replicas db)
      (Materialize.apply tx origin now releaseNow replicas) := by
    intro state final key kind value faithful initial _ _ ran
    exact ⟨MaterializationReadFrame.apply_faithful world tx origin now releaseNow replicas key kind value state final (.ok ()) faithful ran,
      apply_invariant tx origin now releaseNow replicas key kind value policy db state final initial ran⟩
  exact (MaterializationStream.run_materialize_preserves tx world oldRoot newRoot scope (Invariant tx replicas db)
    (Materialize.apply tx origin now releaseNow replicas) (read_stable tx replicas db _) law
    state final count faithful initially ran).2

end Synchronicity.MaterializationWholeRetention
