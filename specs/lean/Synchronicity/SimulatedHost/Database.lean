import VerifiedCore.Host.Access
import VerifiedCore.Host.Upsert

/-! Finite raw relational storage. No CAS relations or policy occur here. -/
namespace Synchronicity.SimulatedHost
open VerifiedCore.Host

instance : ReflBEq ByteArray where
  rfl := by intro bytes; change (bytes.data == bytes.data) = true; exact beq_self_eq_true _

instance : ReflBEq Cell where
  rfl := by
    intro value
    cases value with
    | null => rfl
    | integer x => exact beq_self_eq_true x
    | text x => exact beq_self_eq_true x
    | blob x => exact beq_self_eq_true x
    | real x => exact beq_self_eq_true x
    | rawText x => exact beq_self_eq_true x

instance : LawfulBEq ByteArray where
  eq_of_beq := by
    intro a b h
    cases a with | mk a =>
      cases b with | mk b =>
        have same : a = b := eq_of_beq h
        cases same
        rfl

instance : LawfulBEq Cell where
  eq_of_beq := by
    intro a b h
    cases a <;> cases b <;> simp_all [BEq.beq, instBEqCell.beq]
    all_goals exact (beq_iff_eq).mp h

abbrev Database := List (String × List Fields)

def cell (row : Fields) (column : String) : Cell :=
  ((row.find? fun field => field.1 == column).map Prod.snd).getD .null

def rows (db : Database) (relation : String) : List Fields :=
  ((db.find? fun entry => entry.1 == relation).map Prod.snd).getD []

def setRows (db : Database) (relation : String) (values : List Fields) : Database :=
  (relation, values) :: db.filter (fun entry => entry.1 != relation)

@[simp] theorem rows_setRows (db : Database) (relation : String) (values : List Fields) :
    rows (setRows db relation values) relation = values := by simp [rows, setRows]

@[simp] theorem rows_setRows_other (db : Database) (relation other : String) (values : List Fields)
    (different : relation ≠ other) : rows (setRows db relation values) other = rows db other := by
  induction db with
  | nil => simp [rows, setRows, different]
  | cons entry rest ih =>
    rcases entry with ⟨name, table⟩
    by_cases one : name = relation <;> by_cases two : name = other <;>
      simp_all [rows, setRows]

/-- SQL equality: NULL is not equal even to NULL. Raw text and text share the
same byte comparison. Numeric affinity/coercions are outside this typed model. -/
def equalCell : Cell → Cell → Bool
  | .null, _ | _, .null => false
  | .rawText a, .text b | .text b, .rawText a => a == b.toUTF8
  | a, b => a == b

@[simp] theorem equalCell_blob_self (bytes : ByteArray) : equalCell (.blob bytes) (.blob bytes) = true := by
  change (bytes == bytes) = true
  exact beq_self_eq_true _

/-- SQL `IS`, which the host renders every literal predicate with: equality
except that NULL is itself. Conflict detection and joins keep SQL `=`. -/
def isCell : Cell → Cell → Bool
  | .null, .null => true
  | a, b => equalCell a b

@[simp] theorem isCell_null_null : isCell .null .null = true := rfl

@[simp] theorem isCell_blob (left : ByteArray) (right : Cell) :
    isCell (.blob left) right = equalCell (.blob left) right := by
  cases right <;> rfl

@[simp] theorem isCell_integer (left : Int64) (right : Cell) :
    isCell (.integer left) right = equalCell (.integer left) right := by
  cases right <;> rfl

@[simp] theorem isCell_text (left : String) (right : Cell) :
    isCell (.text left) right = equalCell (.text left) right := by
  cases right <;> rfl

def equals (row : Fields) (fields : Fields) : Bool :=
  fields.all fun (column, value) => isCell (cell row column) value

/-- SQL LIKE with ASCII case folding, percent and underscore wildcards.
The recursion consumes either pattern or input, so it needs no external fuel. -/
def likeChars : List Char → List Char → Bool
  | [], input => input.isEmpty
  | '%' :: pattern, [] => likeChars pattern []
  | '%' :: pattern, char :: input =>
      likeChars pattern (char :: input) || likeChars ('%' :: pattern) input
  | '_' :: pattern, _ :: input => likeChars pattern input
  | char :: pattern, next :: input =>
      char.toLower == next.toLower && likeChars pattern input
  | _, [] => false
termination_by pattern input => pattern.length + input.length

def like (value : Cell) (pattern : String) : Bool :=
  match value with
  | .text text => likeChars pattern.toList text.toList
  | .rawText bytes => likeChars pattern.toList (String.fromUTF8! bytes).toList
  | _ => false

def selects (selection : Selection) (row : Fields) : Bool :=
  equals row selection.equals && (selection.likeAny.isEmpty ||
    selection.likeAny.any (fun (column, pattern) => like (cell row column) pattern)) &&
    selection.notEquals.all (fun (column, value) => !isCell (cell row column) value)

def project (columns : List String) (row : Fields) : Row := columns.map (cell row)

def assign (row values : Fields) : Fields :=
  values ++ row.filter (fun (column, _) => !values.any (fun field => field.1 == column))

@[simp] theorem assign_empty (row : Fields) : assign row [] = row := by
  simp only [assign, List.any_nil, Bool.not_false, List.nil_append]
  exact List.filter_eq_self.mpr (by intro a h; rfl)

def correlated (row candidate : Fields) (keys : List (String × String)) : Bool :=
  keys.all fun (left, right) => equalCell (cell row left) (cell candidate right)

def excluded (db : Database) (row : Fields) (blockers : List Exclusion) : Bool :=
  blockers.any fun blocker => (rows db blocker.relation).any fun candidate =>
    equals candidate blocker.equals && correlated row candidate blocker.keys

def atMostCell : Cell → Cell → Bool
  | .integer a, .integer b => a ≤ b
  | _, _ => false

def due (row : Fields) (bounds : Fields) : Bool :=
  bounds.all fun (column, limit) => atMostCell (cell row column) limit

def deletable (db : Database) (fields : Fields) (blockers : List Exclusion)
    (bounds : Fields) (row : Fields) : Bool :=
  equals row fields && !excluded db row blockers && due row bounds

def conflict (columns : List String) (incoming current : Fields) : Bool :=
  columns.all fun column => equalCell (cell incoming column) (cell current column)

def conflictValue (current incoming : Fields) : ConflictValue → Cell
  | .current column => cell current column
  | .excluded column => cell incoming column
  | .coalesce left right => match conflictValue current incoming left with
      | .null => conflictValue current incoming right
      | value => value
  | .max left right =>
      match conflictValue current incoming left, conflictValue current incoming right with
      | .integer a, .integer b => .integer (max a b)
      | _, _ => .null

/-- Atomic INSERT ... ON CONFLICT. Empty assignments mean DO NOTHING. -/
def upsertRows (table : List Fields) (incoming : Fields) (columns : List String)
    (assignments : List (String × ConflictValue)) : List Fields :=
  if table.any (conflict columns incoming) then
    table.map fun current =>
      if conflict columns incoming current then
        assign current (assignments.map fun (column, value) =>
          (column, conflictValue current incoming value))
      else current
  else table ++ [incoming]

@[simp] theorem upsertRows_doNothing (table : List Fields) (incoming : Fields) (columns : List String) :
    upsertRows table incoming columns [] =
      if table.any (conflict columns incoming) then table else table ++ [incoming] := by
  unfold upsertRows
  split
  · simp
  · rfl

def sourceFields (fields : List (String × SourceValue)) (row : Fields) : Fields :=
  fields.map fun (column, value) => (column, match value with
    | .literal value => value | .column name => cell row name)

/-- All copies select from the pre-statement snapshot; conflicts retain rows. -/
def copyRows (db : Database) (target : String) (selection : Selection)
    (fields : List (String × SourceValue)) (conflicts : List String) : Database :=
  let incoming := (rows db selection.relation).filter (selects selection)
  setRows db target (incoming.foldl (fun table row =>
    upsertRows table (sourceFields fields row) conflicts []) (rows db target))

/-- Copy-on-conflict retains each existing record, not just its key. -/
theorem copyRows_preserves_existing (db : Database) (target : String) (selection : Selection)
    (fields : List (String × SourceValue)) (conflicts : List String) (row : Fields)
    (present : row ∈ rows db target) :
    row ∈ rows (copyRows db target selection fields conflicts) target := by
  unfold copyRows
  rw [rows_setRows]
  generalize (rows db selection.relation).filter (selects selection) = incoming
  generalize rows db target = table at present ⊢
  induction incoming generalizing table with
  | nil => exact present
  | cons head tail ih =>
    simp only [List.foldl_cons]
    apply ih
    rw [upsertRows_doNothing]
    split
    · exact present
    · exact List.mem_append_left _ present

/-- Qualify join columns as well as retaining the base row's unqualified names. -/
def joinedRows (db : Database) (relation : String) (joins : List Join) : List Fields :=
  let base := (rows db relation).map fun row =>
    row ++ row.map (fun (column, value) => (relation ++ "." ++ column, value))
  joins.foldl (fun base join => base.flatMap fun row =>
    ((rows db join.relation).filter fun candidate => correlated row candidate join.keys).map fun candidate =>
      row ++ candidate.map (fun (column, value) => (join.relation ++ "." ++ column, value))) base

def compareCell : Cell → Cell → Ordering
  | .integer a, .integer b => compare a.toInt b.toInt
  | .blob a, .blob b => compare a.data.toList b.data.toList
  | .text a, .text b => compare a b
  | _, _ => .eq

def ordered (order : List Order) (left right : Fields) : Bool :=
  match order with
  | [] => true
  | next :: rest => match compareCell (cell left next.column) (cell right next.column) with
      | .eq => ordered rest left right
      | .lt => !next.descending
      | .gt => next.descending

/-- A stable sort by `le`, structurally recursive so a fixture can decide
an ordered query: an earlier row stays before a later one it ties with. -/
def insertOrdered (le : Fields → Fields → Bool) (row : Fields) : List Fields → List Fields
  | [] => [row]
  | head :: rest => if le row head then row :: head :: rest else head :: insertOrdered le row rest

def sortRows (le : Fields → Fields → Bool) : List Fields → List Fields
  | [] => []
  | row :: rest => insertOrdered le row (sortRows le rest)

@[simp] theorem sortRows_nil (le : Fields → Fields → Bool) : sortRows le [] = [] := rfl

@[simp] theorem sortRows_singleton (le : Fields → Fields → Bool) (row : Fields) :
    sortRows le [row] = [row] := rfl

def query (db : Database) (relation : String) (columns : List String) (fields : Fields)
    (order : List Order) (joins : List Join) : List Row :=
  let candidates := if joins.isEmpty then rows db relation else joinedRows db relation joins
  (sortRows (ordered order) (candidates.filter (fun row => equals row fields))).map (project columns)

end Synchronicity.SimulatedHost
