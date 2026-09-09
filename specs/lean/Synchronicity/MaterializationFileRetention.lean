import Synchronicity.MaterializationRetentionTail

/-! Retention refinement of the whole file branch, including the actual
previous-content read and decoder. No outstanding-responsibility premise is
accepted from callers: it is derived from the staged SQL write. -/
namespace Synchronicity.MaterializationFileRetention
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase
open MaterializedView MaterializationRetention MaterializationFileSql MaterializationRecords
open MaterializationRequirementFrame MaterializationFileRequirements MaterializationRetentionTail
open TransactionSuccess (bind_success)

theorem put_preserves (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (previous : Option ByteArray) (bytes : ByteArray)
    (policy : PoliciesAgree replicas) (baseline : Database) (state final : State) (db : Database)
    (opened : state.pending = some (tx, db)) (schema : MaterializationKeySchema.Schema db)
    (requirements : Requirements replicas baseline db)
    (ran : execute (MaterializationFileApply.put tx origin space path now releaseNow
      (replicas.find? (·.space == space)) previous bytes) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Requirements replicas baseline after := by
  obtain ⟨file, decoded, parseRun, restRun⟩ := bind_success _ _ _ _ _ ran
  obtain ⟨rest, parsed, unchanged⟩ := decode_state "f: record" Records.file bytes state decoded file parseRun
  subst decoded
  obtain ⟨result, written, writeRun, tailRun⟩ := bind_success _ _ _ _ _ restRun
  cases result
  have writtenState := MaterializationSql.write_state tx "entries" (key origin space path) file.fields false state written db opened writeRun
  let writtenDb := MaterializationSql.written db "entries" (key origin space path) file.fields false
  have writtenTx : written.pending = some (tx, writtenDb) := by rw [writtenState]; rfl
  have recordSchema := file_schema
  unfold Ensures at recordSchema
  specialize recordSchema (bytes, 0) file rest parsed
  have typed : MaterializationKeySchema.Schema writtenDb :=
    MaterializationKeySchema.set_schema db "entries" _ schema (by simp)
  exact retain_preserves tx now releaseNow (replicas.find? (·.space == space)) previous file replicas policy
    (fun _ found => List.mem_of_find?_eq_some found) baseline written final writtenDb writtenTx typed
    (write_staged replicas db origin space path file recordSchema requirements.1)
    (retains_forever replicas baseline db writtenDb requirements.2 (entries_write_retains db _ _)) tailRun

theorem remove_preserves (tx : Transaction) (origin space path : String) (releaseNow : Int64)
    (replicas : List Materialize.Target) (previous : Option ByteArray)
    (policy : PoliciesAgree replicas) (baseline : Database) (state final : State) (db : Database)
    (opened : state.pending = some (tx, db)) (requirements : Requirements replicas baseline db)
    (ran : execute (MaterializationFileApply.remove tx origin space path releaseNow
      (replicas.find? (·.space == space)) previous) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Requirements replicas baseline after := by
  obtain ⟨result, erased, eraseRun, tailRun⟩ := bind_success _ _ _ _ _ ran
  cases result
  have erasedState := MaterializationSql.erase_state tx "entries" (key origin space path) state erased db opened eraseRun
  let erasedDb := MaterializationSql.erased db "entries" (key origin space path)
  have erasedTx : erased.pending = some (tx, erasedDb) := by rw [erasedState]; rfl
  exact remove_tail_preserves tx releaseNow (replicas.find? (·.space == space)) previous replicas policy
    (fun _ found => List.mem_of_find?_eq_some found) baseline erased final erasedDb erasedTx
    ⟨erase_current replicas db _ requirements.1,
      retains_forever replicas baseline db erasedDb requirements.2 (entries_erase_retains db _)⟩ tailRun

theorem current_readonly (tx : Transaction) (key : Fields) :
    Only PromotionReads.materializeRead (Materialize.current tx key).run := by
  unfold Materialize.current
  refine Only.seq (Only.raise _ _ trivial) fun result => ?_
  repeat' first
    | exact .done _
    | exact Only.map _ _ (.done _)
    | (unfold Materialize.rootField; split)
    | split

theorem body_preserves (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (kind : UInt64) (value : Option ByteArray)
    (policy : PoliciesAgree replicas) (baseline : Database) (state final : State) (db : Database)
    (opened : state.pending = some (tx, db)) (schema : MaterializationKeySchema.Schema db)
    (requirements : Requirements replicas baseline db)
    (ran : execute (MaterializationFileApply.body tx origin space path now releaseNow replicas kind value) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Requirements replicas baseline after := by
  have sequence : execute ((if (replicas.find? (·.space == space)).isSome && kind != 0 then
      Materialize.current tx (key origin space path) else pure none) >>= fun previous =>
      MaterializationFileApply.changeValue tx origin space path now releaseNow (replicas.find? (·.space == space)) previous value
      : Materialize.Action Unit) state = (.ok (), final) := by
    cases h : (replicas.find? (·.space == space)).isSome && kind != 0 <;>
      simpa only [MaterializationFileApply.body, h, Bool.false_eq_true, ↓reduceIte] using ran
  obtain ⟨previous, middle, readRun, restRun⟩ := bind_success _ _ _ _ _ sequence
  have safe : Only PromotionReads.materializeRead
      ((if (replicas.find? (·.space == space)).isSome && kind != 0 then
        Materialize.current tx (key origin space path) else pure none) : Materialize.Action (Option ByteArray)).run := by
    split
    · exact current_readonly tx _
    · exact .done _
  have same := safe.preserves_observation State.pending _ PromotionReads.materialize_pending state
  have middlePending : middle.pending = state.pending := (congrArg (fun result => result.2.pending) readRun).symm.trans same
  have middleTx := middlePending.trans opened
  cases value with
  | none => exact remove_preserves tx origin space path releaseNow replicas previous policy baseline middle final db middleTx requirements restRun
  | some bytes => exact put_preserves tx origin space path now releaseNow replicas previous bytes policy baseline middle final db middleTx schema requirements restRun

theorem apply_file_preserves (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (key : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (policy : PoliciesAgree replicas) (baseline : Database) (state final : State) (db : Database)
    (opened : state.pending = some (tx, db)) (schema : MaterializationKeySchema.Schema db)
    (requirements : Requirements replicas baseline db)
    (tag : key[0]? = some 102) (parsed : Records.fileKey key = some (space, path))
    (ran : execute (Materialize.apply tx origin now releaseNow replicas key kind value) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Requirements replicas baseline after := by
  rw [MaterializationFileApply.apply_file_unfold tx origin space path now releaseNow replicas key kind value tag parsed] at ran
  obtain ⟨result, middle, unicodeRun, restRun⟩ := bind_success _ _ _ _ _ ran
  obtain ⟨_, middleState⟩ := MaterializationFileApply.unicode_result path state middle result unicodeRun
  have middleTx : middle.pending = some (tx, db) := by rw [middleState]; exact opened
  cases result with
  | false =>
    cases restRun
    exact ⟨db, middleTx, requirements⟩
  | true =>
    exact body_preserves tx origin space path now releaseNow replicas kind value policy baseline middle final db middleTx schema requirements restRun

end Synchronicity.MaterializationFileRetention
