import Synchronicity.MaterializationFileApply
import Synchronicity.MaterializationRequirementFrame

/-! A file write creates at most one outstanding content responsibility.
Its root is derived from the decoded SQL content, and its holder from the
actual replica lookup. The retention continuation discharges that obligation. -/
namespace Synchronicity.MaterializationFileRequirements
open VerifiedCore VerifiedCore.Host Replication SimulatedHost
open MaterializedView MaterializationRetention MaterializationFileSql MaterializationRecords
open MaterializationRequirementFrame MaterializationTableFrame

def Staged (replicas : List Materialize.Target) (db : Database) (target : Option Materialize.Target)
    (content : Option ByteArray) : Prop :=
  ∀ replica ∈ replicas, ∀ row ∈ rows db "entries", cell row "space" = .text replica.space →
    ∀ root, cell row "content" = .blob root → Required db root replica.holder ∨
      ∃ selected, target = some selected ∧ content = some root ∧ replica.holder = selected.holder

theorem entries_write_retains (db : Database) (key values : Fields) :
    Retains db (MaterializationSql.written db "entries" key values false) := by
  apply rows_retain
  all_goals intro row member; simpa only [MaterializationSql.written,
    rows_setRows_other _ "entries" "pins" _ (by decide),
    rows_setRows_other _ "entries" "content_want" _ (by decide)] using member

theorem entries_erase_retains (db : Database) (key : Fields) :
    Retains db (MaterializationSql.erased db "entries" key) := by
  apply rows_retain
  all_goals intro row member; simpa only [MaterializationSql.erased,
    rows_setRows_other _ "entries" "pins" _ (by decide),
    rows_setRows_other _ "entries" "content_want" _ (by decide)] using member

theorem selected_content (row : Fields) (file : Records.File) (schema : FileSchema file)
    (payload : project columns row = project columns file.fields) (root : ByteArray)
    (content : cell row "content" = .blob root) : file.content = some root := by
  have same := congrArg (fun values => values[4]?) payload
  have contentSame : cell row "content" = cell file.fields "content" := by
    simpa [columns, Address.columns, project] using same
  rw [schema.2, content] at contentSame
  cases stored : file.content with
  | none => simp [stored, Records.nullable] at contentSame
  | some bytes =>
    simp [stored, Records.nullable] at contentSame
    exact congrArg some contentSame.symm

theorem replica_selected (replicas : List Materialize.Target) (space : String) (replica : Materialize.Target)
    (member : replica ∈ replicas) (sameSpace : replica.space = space) :
    ∃ target, replicas.find? (·.space == space) = some target ∧ replica.holder = target.holder := by
  cases found : replicas.find? (·.space == space) with
  | none =>
    have absent := List.find?_eq_none.mp found replica member
    simp [sameSpace] at absent
  | some target =>
    have matched : (target.space == space) = true := List.find?_some (p := fun (t : Materialize.Target) => t.space == space) found
    have selected : target.space = space := eq_of_beq matched
    exact ⟨target, rfl, by simp only [Materialize.Target.holder, sameSpace, selected]⟩

theorem write_staged (replicas : List Materialize.Target) (db : Database) (origin space path : String)
    (file : Records.File) (schema : FileSchema file) (current : CurrentRequirements replicas db) :
    Staged replicas (MaterializationSql.written db "entries" (key origin space path) file.fields false)
      (replicas.find? (·.space == space)) file.content := by
  intro replica member row present rowSpace root content
  by_cases selected : equals row (key origin space path) = true
  · have observed : RowReplacement.Observed (fun row => equals row (key origin space path)) (project columns)
        (rows (MaterializationSql.written db "entries" (key origin space path) file.fields false) "entries")
        true (project columns row) := ⟨row, present, selected, rfl⟩
    have payload := (write_replaces db origin space path file schema true (project columns row)).mp observed
    have samePayload : project columns row = project columns file.fields := by
      have same : project columns file.fields = project columns row := by simpa using payload
      exact same.symm
    have sameSpace : replica.space = space := by
      simp only [key, Address.key, equals, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] at selected
      have selectedSpace := selected.2.1
      rw [rowSpace] at selectedSpace
      exact RelationalFields.text_match_unique (.text replica.space) replica.space space (by simp [isCell, equalCell]) selectedSpace
    obtain ⟨target, found, sameHolder⟩ := replica_selected replicas space replica member sameSpace
    exact Or.inr ⟨target, found, selected_content row file schema samePayload root content, sameHolder⟩
  · have outside : equals row (key origin space path) = false := Bool.eq_false_iff.mpr selected
    have old := (write_keeps_other_row db origin space path file schema row outside).mp present
    exact Or.inl (entries_write_retains db _ _ root replica.holder (current replica member row old rowSpace root content))

theorem erase_current (replicas : List Materialize.Target) (db : Database) (key : Fields)
    (current : CurrentRequirements replicas db) : CurrentRequirements replicas (MaterializationSql.erased db "entries" key) := by
  intro target member row present space root content
  have old : row ∈ rows db "entries" := by
    simp only [MaterializationSql.erased, rows_setRows] at present
    exact (List.mem_filter.mp present).1
  exact entries_erase_retains db key root target.holder (current target member row old space root content)

theorem staged_none_target (replicas : List Materialize.Target) (db : Database) (content : Option ByteArray)
    (staged : Staged replicas db none content) : CurrentRequirements replicas db := by
  intro replica member row present space root content
  rcases staged replica member row present space root content with held | ⟨target, impossible, _⟩
  · exact held
  · cases impossible

theorem staged_none_content (replicas : List Materialize.Target) (db : Database) (target : Option Materialize.Target)
    (staged : Staged replicas db target none) : CurrentRequirements replicas db := by
  intro replica member row present space root content
  rcases staged replica member row present space root content with held | ⟨target, _, impossible, _⟩
  · exact held
  · cases impossible

end Synchronicity.MaterializationFileRequirements
