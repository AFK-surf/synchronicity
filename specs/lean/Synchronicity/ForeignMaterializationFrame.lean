import Synchronicity.MaterializationExactFiles
import Synchronicity.MaterializationInputs
import Synchronicity.PromotionProgress

/-! Production materialization is keyed by canonical origin. Applying a
foreign origin's file delta cannot change any observed file row of this
origin; the property composes through the actual streamed diff. -/
namespace Synchronicity.ForeignMaterializationFrame
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase
open MaterializedView MaterializationStream TrieDiffCoverage

def Files (origin : String) (baseline db : Database) : Prop :=
  ∀ space path values, Observed db origin (.file space path) values ↔
    Observed baseline origin (.file space path) values

private theorem outside_foreign_key (observedOrigin foreign space path otherSpace otherPath : String)
    (different : observedOrigin ≠ foreign) (row : Fields)
    (selected : equals row (Address.key observedOrigin (.file space path)) = true) :
    equals row (Address.key foreign (.file otherSpace otherPath)) = false := by
  apply Bool.eq_false_iff.mpr
  intro foreignSelected
  have localCell := List.all_eq_true.mp selected
    ("origin_id", .text observedOrigin) (by simp [Address.key])
  have foreignCell := List.all_eq_true.mp foreignSelected
    ("origin_id", .text foreign) (by simp [Address.key])
  exact different (RelationalFields.text_match_unique _ _ _ localCell foreignCell)

theorem apply_files (tx : Transaction) (observedOrigin foreign : String)
    (different : observedOrigin ≠ foreign) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (rawKey : ByteArray) (kind : UInt64)
    (value : Option ByteArray) (services : Services) (state final : State)
    (db baseline : Database) (opened : state.pending = some (tx, db))
    (normalization : state.isNfc = services.nfc) (initial : Files observedOrigin baseline db)
    (ran : execute (Materialize.apply tx foreign now releaseNow replicas rawKey kind value) state =
      (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Files observedOrigin baseline after := by
  by_cases projected : ∃ space path, Addresses services rawKey (.file space path)
  · obtain ⟨space, path, addressed⟩ := projected
    obtain ⟨after, pending, replaced⟩ := MaterializationFileApply.apply_file_refines
      tx foreign space path now releaseNow replicas rawKey kind value state final db opened
      addressed.1 addressed.2.1 (by rw [normalization]; exact addressed.2.2) ran
    refine ⟨after, pending, ?_⟩
    intro localSpace localPath values
    constructor
    · rintro ⟨row, member, selected, payload⟩
      apply (initial _ _ _).mp
      exact ⟨row, (replaced.2 row (outside_foreign_key observedOrigin foreign localSpace localPath
        space path different row selected)).mp member, selected, payload⟩
    · intro observed
      obtain ⟨row, member, selected, payload⟩ := (initial _ _ _).mpr observed
      exact ⟨row, (replaced.2 row (outside_foreign_key observedOrigin foreign localSpace localPath
        space path different row selected)).mpr member, selected, payload⟩
  · have unprojected : ∀ space path, ¬Addresses services rawKey (.file space path) :=
      fun space path address => projected ⟨space, path, address⟩
    obtain ⟨after, pending, same⟩ := MaterializationFileApply.apply_unprojected_frame
      tx foreign now releaseNow replicas rawKey kind value services state final db opened
      normalization unprojected ran
    refine ⟨after, pending, ?_⟩
    intro space path values
    simpa only [Observed, Address.table, same] using initial space path values

def Progress (tx : Transaction) (observedOrigin : String) (baseline : Database)
    (services : Services) (state : State) : Prop :=
  ∃ db, state.pending = some (tx, db) ∧ state.isNfc = services.nfc ∧
    Files observedOrigin baseline db

theorem progress_stable (tx : Transaction) (observedOrigin : String) (baseline : Database)
    (services : Services) (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit) :
    ReadStable (handler := consumer tx emit)
      (fun state (_ : UInt64) => Progress tx observedOrigin baseline services state) := by
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

theorem apply_progress (tx : Transaction) (observedOrigin foreign : String)
    (different : observedOrigin ≠ foreign) (services : Services) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (baseline : Database)
    (state final : State) (key : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (holds : Progress tx observedOrigin baseline services state)
    (ran : execute (Materialize.apply tx foreign now releaseNow replicas key kind value) state =
      (.ok (), final)) : Progress tx observedOrigin baseline services final := by
  obtain ⟨db, opened, normalization, files⟩ := holds
  obtain ⟨after, pending, next⟩ := apply_files tx observedOrigin foreign different now releaseNow replicas
    key kind value services state final db baseline opened normalization files ran
  have safe := MaterializationTableFrame.apply_safe Trie.nodeSpace (by decide) tx foreign
    now releaseNow replicas key kind value
  have context := MaterializationReadFrame.executed_context Trie.nodeSpace _ safe state final (.ok ()) ran
  have nfc : final.isNfc = state.isNfc := congrArg (fun ctx => ctx.2.2.2.2.1) context
  exact ⟨after, pending, nfc.trans normalization, next⟩

theorem run_diff_files (tx : Transaction) (observedOrigin foreign : String)
    (different : observedOrigin ≠ foreign) (services : Services) (world : World)
    (scope : Trie.Serve.Scope) (oldRoot newRoot : ByteArray)
    (now releaseNow : Int64) (replicas : List Materialize.Target)
    (state final : State) (count : UInt64) (db : Database)
    (opened : state.pending = some (tx, db)) (normalization : state.isNfc = services.nfc)
    (faithful : Faithful world state)
    (ran : execute (Materialize.runDiff tx
      (Materialize.apply tx foreign now releaseNow replicas)
      (Trie.Diff.materialize (E := Trie.Diff.Effects) scope oldRoot newRoot).run) state =
      (.ok count, final)) :
    ∃ after, final.pending = some (tx, after) ∧ Files observedOrigin db after := by
  let emit := Materialize.apply tx foreign now releaseNow replicas
  have initial : Progress tx observedOrigin db services state := ⟨db, opened, normalization, by
    intro space path values
    rfl⟩
  have law : SqlLaw world oldRoot newRoot scope
      (Progress tx observedOrigin db services) emit := by
    intro current after key kind value currentFaithful holds _ _ applied
    have next := apply_progress tx observedOrigin foreign different services now releaseNow replicas
      db current after key kind value holds applied
    have afterFaithful := MaterializationReadFrame.apply_faithful world tx foreign now releaseNow
      replicas key kind value current after (.ok ()) currentFaithful applied
    exact ⟨afterFaithful, next⟩
  have preserved := run_materialize_preserves tx world oldRoot newRoot scope
    (Progress tx observedOrigin db services) emit
    (progress_stable tx observedOrigin db services emit) law state final count faithful initial ran
  obtain ⟨after, pending, _, files⟩ := preserved.2
  exact ⟨after, pending, files⟩

/-- The complete production materializer, including policy reads, preserves
every observed file row of a distinct canonical origin on success. -/
theorem materialize_files (tx : Transaction) (observedOrigin : String)
    (foreign : Origin.Parsed) (different : observedOrigin ≠ Origin.canonical foreign)
    (oldRoot newRoot : ByteArray) (services : Services) (world : World)
    (state final : State) (count : UInt64) (db : Database)
    (opened : state.pending = some (tx, db)) (normalization : state.isNfc = services.nfc)
    (faithful : Faithful world state)
    (ran : execute (Materialize.materialize tx foreign oldRoot newRoot) state = (.ok count, final)) :
    ∃ after, final.pending = some (tx, after) ∧ Files observedOrigin db after := by
  obtain ⟨scope, now, replicas, releaseNow, ready, prepared, frame, streamed⟩ :=
    MaterializationInputs.materialize_inputs tx foreign oldRoot newRoot state final count ran
  have readyTx : ready.pending = some (tx, db) := (congrArg State.pending frame).trans opened
  have readyNfc : ready.isNfc = services.nfc := (congrArg State.isNfc frame).trans normalization
  have readyFaithful : Faithful world ready := by
    have bytes : readableBytes ready = readableBytes state := by
      have same := congrArg SimulatedHost.readableBytes frame
      exact same
    exact ⟨by rw [bytes]; exact faithful.1, (congrArg State.hash frame).trans faithful.2⟩
  exact run_diff_files tx observedOrigin (Origin.canonical foreign) different services world scope
    oldRoot newRoot now releaseNow replicas ready final count db readyTx readyNfc readyFaithful streamed

private theorem ready_materializer_inputs
    (ready : PromotionProgress.Ready foreign now refused state) :
    ∃ cleared count clearedDb,
      cleared.pending = some (ready.tx, clearedDb) ∧
      rows clearedDb "entries" = rows state.db "entries" ∧
      execute (Materialize.materialize ready.tx foreign
        (ready.old.map (·.head.root) |>.getD Trie.emptyRoot) ready.pending.head.root) cleared =
        (.ok count, ready.body.staged) := by
  have rawBegin := OperationExecution.raise_success (fun _ _ => rfl)
    Promote.Error.host Storage.begin state ready.opened ready.tx ready.began
  have openedTx := ReconciliationFloor.begin_pending state ready.opened ready.tx rawBegin
  have preparedTx := PromotionReads.executed_pending _
    (PromotionCommand.prepare_only ready.tx foreign now) ready.opened ready.prepared _
    ready.preparation
  have preparedSnapshot : ready.prepared.pending = some (ready.tx, state.db) :=
    preparedTx.trans openedTx
  have published := PromotionPublication.body_published ready.tx foreign now ready.pending
    ready.old ready.scope ready.authority ready.prepared ready.body.staged
    (PromotionProgress.body_executes ready.body)
  obtain ⟨cleared, count, frames, streamed⟩ :=
    PromotionViewFrame.published_inputs ready.tx foreign now ready.pending ready.old
      ready.scope ready.authority ready.prepared ready.body.staged published
  have entriesFrame := frames "entries" (by decide) (by decide)
  obtain ⟨clearedDb, clearedTx⟩ : ∃ db, cleared.pending = some (ready.tx, db) := by
    cases current : cleared.pending with
    | none => simp [MaterializationTableFrame.view, current, preparedSnapshot] at entriesFrame
    | some pair =>
      rcases pair with ⟨tx, db⟩
      have same : tx = ready.tx := congrArg Prod.fst (Option.some.inj (by
        simpa only [MaterializationTableFrame.view, current, preparedSnapshot,
          Option.map_some] using entriesFrame))
      subst tx
      exact ⟨db, rfl⟩
  have entries : rows clearedDb "entries" = rows state.db "entries" := by
    simpa only [MaterializationTableFrame.view, clearedTx, preparedSnapshot,
      Option.map_some, Option.some.injEq, Prod.mk.injEq, true_and] using entriesFrame
  exact ⟨cleared, count, clearedDb, clearedTx, entries, streamed⟩

private theorem materialize_then_commit_files
    (tx : Transaction) (foreign : Origin.Parsed) (oldRoot newRoot : ByteArray)
    (observedOrigin : String) (different : observedOrigin ≠ Origin.canonical foreign)
    (services : Services) (world : World) (baseline : Database)
    (cleared staged final : State) (count : UInt64)
    (clearedDb : Database) (clearedTx : cleared.pending = some (tx, clearedDb))
    (entries : rows clearedDb "entries" = rows baseline "entries")
    (normalization : cleared.isNfc = services.nfc) (faithful : Faithful world cleared)
    (streamed : execute (Materialize.materialize tx foreign oldRoot newRoot) cleared =
      (.ok count, staged))
    (commitRan : storage (.commit tx) staged = (.ok (), final)) :
    Files observedOrigin baseline final.db := by
  obtain ⟨stagedDb, stagedTx, streamedFiles⟩ := materialize_files tx observedOrigin
    foreign different oldRoot newRoot services world cleared staged count
    clearedDb clearedTx normalization faithful streamed
  have initialFiles : Files observedOrigin baseline clearedDb := by
    intro space path values
    simp only [Observed, Address.table, entries]
  have stagedFiles : Files observedOrigin baseline stagedDb := by
    intro space path values
    exact (streamedFiles space path values).trans (initialFiles space path values)
  obtain ⟨committedDb, pendingTx, commitView⟩ := ReconciliationAcceptance.commit_installs
    tx staged (congrArg Prod.fst commitRan)
  have sameDb : stagedDb = committedDb := congrArg Prod.snd
    (Option.some.inj (stagedTx.symm.trans pendingTx))
  have finalDb : final.db = committedDb := by
    simpa only [commitRan] using commitView
  rw [← sameDb] at finalDb
  rw [finalDb]
  exact stagedFiles

/-- A healthy actual foreign promotion preserves this origin's observed file
rows. The only environmental inputs are the same readable-snapshot/NFC facts
M4 needs, stated at the actual post-clear materializer state. -/
theorem ready_files (ready : PromotionProgress.Ready foreign now refused state)
    (observedOrigin : String) (different : observedOrigin ≠ Origin.canonical foreign)
    (services : Services) (world : World)
    (materializerNfc : ∀ cleared count,
      execute (Materialize.materialize ready.tx foreign
        (ready.old.map (·.head.root) |>.getD Trie.emptyRoot) ready.pending.head.root) cleared =
        (.ok count, ready.body.staged) → cleared.isNfc = services.nfc)
    (materializerFaithful : ∀ cleared count,
      execute (Materialize.materialize ready.tx foreign
        (ready.old.map (·.head.root) |>.getD Trie.emptyRoot) ready.pending.head.root) cleared =
        (.ok count, ready.body.staged) → Faithful world cleared) :
    Files observedOrigin state.db ready.final.db := by
  obtain ⟨cleared, count, clearedDb, opened, entries, streamed⟩ :=
    ready_materializer_inputs ready
  have rawCommit := OperationExecution.raise_success (fun _ _ => rfl)
    Promote.Error.host (Storage.commit ready.tx) ready.body.staged ready.final () ready.committed
  change storage (.commit ready.tx) ready.body.staged = (.ok (), ready.final) at rawCommit
  let oldRoot := (ready.old.map (·.head.root) |>.getD Trie.emptyRoot)
  let newRoot := ready.pending.head.root
  have normalized : cleared.isNfc = services.nfc := materializerNfc cleared count streamed
  have readable : Faithful world cleared := materializerFaithful cleared count streamed
  exact materialize_then_commit_files
    (tx := ready.tx) (foreign := foreign) (oldRoot := oldRoot) (newRoot := newRoot)
    (observedOrigin := observedOrigin) (different := different) (services := services)
    (world := world) (baseline := state.db) (cleared := cleared)
    (staged := ready.body.staged) (final := ready.final) (count := count)
    (clearedDb := clearedDb) (clearedTx := opened) (entries := entries)
    (normalization := normalized) (faithful := readable) (streamed := by simpa [oldRoot, newRoot])
    (commitRan := rawCommit)

end Synchronicity.ForeignMaterializationFrame
