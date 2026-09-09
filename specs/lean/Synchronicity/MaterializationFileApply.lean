import Synchronicity.MaterializationFileSql
import Synchronicity.MaterializationTableFrame

/-! The real file callback's retention tail leaves its newly installed view
unchanged. Decoder, write and retention successes are extracted from execution,
not supplied as an assumed callback refinement. -/
namespace Synchronicity.MaterializationFileApply
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase
open MaterializationFileSql MaterializationRecords MaterializationTableFrame
open TransactionSuccess (bind_success)

def retain (tx : Transaction) (now releaseNow : Int64) (target : Option Materialize.Target)
    (previous : Option ByteArray) (file : Records.File) : Materialize.Action Unit := do
  if let some target := target then
    if let some root := file.content then Materialize.wants tx target file root now
    if let some old := previous then
      if some old != file.content then Materialize.release tx target old releaseNow

def put (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (target : Option Materialize.Target) (previous : Option ByteArray) (bytes : ByteArray) : Materialize.Action Unit := do
  let file ← Materialize.decode "f: record" Records.file bytes
  Materialize.write tx "entries" (key origin space path) file.fields
  retain tx now releaseNow target previous file

def removeTail (tx : Transaction) (releaseNow : Int64)
    (target : Option Materialize.Target) (previous : Option ByteArray) : Materialize.Action Unit := do
  if let some target := target then
    if let some root := previous then Materialize.release tx target root releaseNow

def remove (tx : Transaction) (origin space path : String) (releaseNow : Int64)
    (target : Option Materialize.Target) (previous : Option ByteArray) : Materialize.Action Unit := do
  Materialize.erase tx "entries" (key origin space path)
  removeTail tx releaseNow target previous

def changeValue (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (target : Option Materialize.Target) (previous : Option ByteArray) (value : Option ByteArray) : Materialize.Action Unit :=
  match value with
  | none => remove tx origin space path releaseNow target previous
  | some bytes => put tx origin space path now releaseNow target previous bytes

def body (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (kind : UInt64) (value : Option ByteArray) : Materialize.Action Unit := do
  let target := replicas.find? (·.space == space)
  let previous ← if target.isSome && kind != 0 then Materialize.current tx (key origin space path) else pure none
  changeValue tx origin space path now releaseNow target previous value

theorem apply_file_unfold (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (rawKey : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (tag : rawKey[0]? = some 102) (parsed : Records.fileKey rawKey = some (space, path)) :
    Materialize.apply tx origin now releaseNow replicas rawKey kind value = (do
      let normalized ← raise Materialize.Error.host (Unicode.isNfc path)
      if !normalized then pure () else body tx origin space path now releaseNow replicas kind value) := by
  simp only [Materialize.apply, tag, beq_self_eq_true, ↓reduceIte, parsed]
  rfl

theorem unicode_result (path : String) (state final : State) (result : Bool)
    (ran : execute (raise Materialize.Error.host (Unicode.isNfc path) : Materialize.Action Bool) state = (.ok result, final)) :
    result = state.isNfc path ∧ final = record state "unicode:nfc" := by
  simp only [raise, performOver, Inject.inject, ExceptT.mk, execute, Interpreter.handle, unicode, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError] at ran
  | none =>
    simp only [failed, Except.mapError, Prod.mk.injEq, Except.ok.injEq] at ran
    exact ⟨ran.1.symm, ran.2.symm⟩

theorem retain_frame (relation : String) (pins : "pins" ≠ relation) (wants : "content_want" ≠ relation)
    (tx : Transaction) (now releaseNow : Int64) (target : Option Materialize.Target)
    (previous : Option ByteArray) (file : Records.File) : Safe relation (retain tx now releaseNow target previous file) := by
  unfold retain
  repeat' first
    | exact .done _
    | exact release_safe relation pins wants _ _ _ _
    | (refine Only.seq (wants_safe relation pins wants _ _ _ _ _) fun _ => ?_)
    | (refine Only.seq (.done _) fun _ => ?_)
    | split

theorem put_exact (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (target : Option Materialize.Target) (previous : Option ByteArray) (bytes : ByteArray)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (ran : execute (put tx origin space path now releaseNow target previous bytes) state = (.ok (), final)) :
    ∃ file rest after, Records.file (bytes, 0) = .ok (file, rest) ∧ final.pending = some (tx, after) ∧
      RowReplacement.Replaces (fun row => equals row (key origin space path)) (project columns)
        (rows db "entries") (rows after "entries") true (some (project columns file.fields)) ∧
      (∀ row, equals row (key origin space path) = false → (row ∈ rows after "entries" ↔ row ∈ rows db "entries")) := by
  obtain ⟨file, decoded, parseRun, restRun⟩ := bind_success _ _ _ _ _ ran
  obtain ⟨rest, parsed, unchanged⟩ := decode_state "f: record" Records.file bytes state decoded file parseRun
  subst decoded
  obtain ⟨result, written, writeRun, tailRun⟩ := bind_success _ _ _ _ _ restRun
  cases result
  have writtenState := MaterializationSql.write_state tx "entries" (key origin space path) file.fields false
    state written db opened writeRun
  have writeOpened : written.pending = some (tx, MaterializationSql.written db "entries" (key origin space path) file.fields false) := by
    rw [writtenState]; rfl
  obtain ⟨after, pending, same⟩ := frame_opened "entries" _
    (retain_frame "entries" (by decide) (by decide) tx now releaseNow target previous file)
    written final (.ok ()) tx _ writeOpened tailRun
  have schema := file_schema
  unfold Ensures at schema
  specialize schema (bytes, 0) file rest parsed
  refine ⟨file, rest, after, parsed, pending, ?_, ?_⟩
  · rw [same]
    exact write_replaces db origin space path file schema
  · intro row outside
    rw [same]
    exact write_keeps_other_row db origin space path file schema row outside

theorem remove_exact (tx : Transaction) (origin space path : String) (releaseNow : Int64)
    (target : Option Materialize.Target) (previous : Option ByteArray)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (ran : execute (remove tx origin space path releaseNow target previous) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧
      rows after "entries" = (rows db "entries").filter (fun row => !equals row (key origin space path)) := by
  obtain ⟨result, erased, eraseRun, tailRun⟩ := bind_success _ _ _ _ _ ran
  cases result
  have erasedState := MaterializationSql.erase_state tx "entries" (key origin space path) state erased db opened eraseRun
  have eraseOpened : erased.pending = some (tx, MaterializationSql.erased db "entries" (key origin space path)) := by
    rw [erasedState]; rfl
  have safe : Safe "entries" (removeTail tx releaseNow target previous) := by
    unfold removeTail
    split
    · split
      · exact release_safe "entries" (by decide) (by decide) _ _ _ _
      · exact .done _
    · exact .done _
  obtain ⟨after, pending, same⟩ := frame_opened "entries" _ safe erased final (.ok ()) tx _ eraseOpened tailRun
  exact ⟨after, pending, same.trans (rows_setRows _ _ _)⟩

theorem put_refines (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (target : Option Materialize.Target) (previous : Option ByteArray) (bytes : ByteArray)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (ran : execute (put tx origin space path now releaseNow target previous bytes) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧
      MaterializedView.ReplacesRecord db after origin (.file space path) (some bytes) := by
  obtain ⟨file, rest, after, parsed, pending, replaced, framed⟩ := put_exact
    tx origin space path now releaseNow target previous bytes state final db opened ran
  refine ⟨after, pending, ?_, framed⟩
  intro values
  have correct := replaced true values
  simp only [true_and, ne_eq, not_true_eq_false, false_and, or_false, Option.some.injEq] at correct
  change MaterializedView.Observed after origin (.file space path) values ↔ _ at correct
  rw [correct]
  constructor
  · intro same
    exact ⟨bytes, rfl, file, rest, parsed, same⟩
  · rintro ⟨other, equal, decoded, decodedRest, decodedRun, data⟩
    cases equal
    have same : file = decoded := congrArg (fun r => r.toOption.map (·.1)) (parsed.symm.trans decodedRun) |> Option.some.inj
    subst decoded
    exact data

theorem remove_refines (tx : Transaction) (origin space path : String) (releaseNow : Int64)
    (target : Option Materialize.Target) (previous : Option ByteArray)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (ran : execute (remove tx origin space path releaseNow target previous) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧
      MaterializedView.ReplacesRecord db after origin (.file space path) none := by
  obtain ⟨after, pending, same⟩ := remove_exact tx origin space path releaseNow target previous state final db opened ran
  refine ⟨after, pending, ?_, ?_⟩
  · intro values
    constructor
    · rintro ⟨row, member, selected, _⟩
      change row ∈ rows after "entries" at member
      rw [same] at member
      have kept := (List.mem_filter.mp member).2
      simp only [key, selected, Bool.not_true, Bool.false_eq_true] at kept
    · rintro ⟨bytes, impossible, _⟩
      cases impossible
  · intro row outside
    change (row ∈ rows after "entries" ↔ _)
    rw [same, List.mem_filter]
    simp [key, outside, MaterializedView.Address.table]

theorem body_refines (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (kind : UInt64) (value : Option ByteArray)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (ran : execute (body tx origin space path now releaseNow replicas kind value) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧
      MaterializedView.ReplacesRecord db after origin (.file space path) value := by
  have sequence : execute ((if (replicas.find? (·.space == space)).isSome && kind != 0 then
      Materialize.current tx (key origin space path) else pure none) >>= fun previous =>
      changeValue tx origin space path now releaseNow (replicas.find? (·.space == space)) previous value
      : Materialize.Action Unit) state = (.ok (), final) := by
    cases h : (replicas.find? (·.space == space)).isSome && kind != 0 <;> simpa only [body, h, Bool.false_eq_true, ↓reduceIte] using ran
  obtain ⟨previous, middle, readRun, restRun⟩ := bind_success _ _ _ _ _ sequence
  have safe : Safe "entries" (if (replicas.find? (·.space == space)).isSome && kind != 0 then
      Materialize.current tx (key origin space path) else pure none) := by
    split
    · exact current_safe "entries" _ _
    · exact .done _
  obtain ⟨middleDb, middleOpen, same⟩ := frame_opened "entries" _ safe state middle (.ok previous) tx db opened readRun
  have refined : ∃ after, final.pending = some (tx, after) ∧
      MaterializedView.ReplacesRecord middleDb after origin (.file space path) value := by
    cases value with
    | none => exact remove_refines tx origin space path releaseNow _ previous middle final middleDb middleOpen restRun
    | some bytes => exact put_refines tx origin space path now releaseNow _ previous bytes middle final middleDb middleOpen restRun
  obtain ⟨after, pending, exactView, frame⟩ := refined
  refine ⟨after, pending, exactView, ?_⟩
  intro row outside
  simpa only [MaterializedView.Address.table, same] using frame row outside

/-- The production file callback refines record replacement, including its
actual previous-content read and all subsequent retention work. -/
theorem apply_file_refines (tx : Transaction) (origin space path : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (rawKey : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (tag : rawKey[0]? = some 102) (parsed : Records.fileKey rawKey = some (space, path))
    (normalized : state.isNfc path = true)
    (ran : execute (Materialize.apply tx origin now releaseNow replicas rawKey kind value) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧
      MaterializedView.ReplacesRecord db after origin (.file space path) value := by
  rw [apply_file_unfold tx origin space path now releaseNow replicas rawKey kind value tag parsed] at ran
  obtain ⟨result, middle, unicodeRun, restRun⟩ := bind_success _ _ _ _ _ ran
  obtain ⟨answer, middleState⟩ := unicode_result path state middle result unicodeRun
  have accepted : result = true := answer.trans normalized
  simp only [accepted, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at restRun
  exact body_refines tx origin space path now releaseNow replicas kind value middle final db
    (by rw [middleState]; exact opened) restRun

/-- Non-file records, malformed file names and rejected normalization leave
the entire entries table unchanged, even when other metadata is updated. -/
theorem apply_unprojected_frame (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (rawKey : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (services : MaterializedView.Services) (state final : State) (db : Database)
    (opened : state.pending = some (tx, db)) (agrees : state.isNfc = services.nfc)
    (unprojected : ∀ space path, ¬MaterializedView.Addresses services rawKey (.file space path))
    (ran : execute (Materialize.apply tx origin now releaseNow replicas rawKey kind value) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ rows after "entries" = rows db "entries" := by
  by_cases tag : rawKey[0]? = some 102
  · cases parsed : Records.fileKey rawKey with
    | none =>
      simp only [Materialize.apply, tag, beq_self_eq_true, ↓reduceIte, parsed,
        pure, ExceptT.pure, ExceptT.mk, execute] at ran
      cases ran
      exact ⟨db, opened, rfl⟩
    | some pair =>
      rcases pair with ⟨space, path⟩
      have rejected : state.isNfc path = false := by
        cases h : state.isNfc path
        · rfl
        · exact False.elim (unprojected space path ⟨tag, parsed, by rwa [← agrees]⟩)
      rw [apply_file_unfold tx origin space path now releaseNow replicas rawKey kind value tag parsed] at ran
      obtain ⟨result, middle, unicodeRun, restRun⟩ := bind_success _ _ _ _ _ ran
      obtain ⟨answer, middleState⟩ := unicode_result path state middle result unicodeRun
      have refused : result = false := answer.trans rejected
      simp only [refused, Bool.not_false, ↓reduceIte, pure, ExceptT.pure, ExceptT.mk, execute] at restRun
      have same : final = middle := (congrArg Prod.snd restRun).symm
      exact ⟨db, by rw [same, middleState]; exact opened, rfl⟩
  · exact frame_opened "entries" _ (nonfile_safe tx origin now releaseNow replicas rawKey kind value tag)
      state final (.ok ()) tx db opened ran

end Synchronicity.MaterializationFileApply
