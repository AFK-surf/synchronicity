import VerifiedCore.Cas.Program
import Synchronicity.Prelude

/-! Executions of the actual CAS acquisition program against a scripted raw
storage interpreter. The script does not implement any acquisition policy. -/
namespace Synchronicity.CasProgramProofs
open VerifiedCore.Host VerifiedCore.Cas

/-- Observable host requests, retaining keys, projections and write payloads. -/
inductive Event where
  | begin
  | commit (tx : Transaction)
  | rollback (tx : Transaction)
  | readRows (tx : Transaction) (relation : String) (columns : List String) (equals : Fields)
  | upsert (tx : Transaction) (relation : String) (values : Fields)
      (conflictColumns updateColumns : List String)
  | deleteRows (tx : Transaction) (relation : String) (equals : Fields)
  | readBytes (space : String) (key : ByteArray)
  | readInput (handle offset count : UInt64)
  | readCounter (space : String) (key : ByteArray)
  | removeFile (space : String) (key : ByteArray)
  | existsRows (tx : Transaction) (relation : String) (equals : Fields)
  deriving BEq

/-- Erase only the dependent reply type of a host request. -/
def event : Storage A → Event
  | .begin => .begin
  | .commit tx => .commit tx
  | .rollback tx => .rollback tx
  | .readRows tx relation columns equals => .readRows tx relation columns equals
  | .upsert tx relation values conflicts updates => .upsert tx relation values conflicts updates
  | .deleteRows tx relation equals => .deleteRows tx relation equals
  | .readBytes space key => .readBytes space key
  | .readInput handle offset count => .readInput handle offset count
  | .readCounter space key => .readCounter space key
  | .removeFile space key => .removeFile space key
  | .existsRows tx relation equals => .existsRows tx relation equals

/-- Independent storage observations, including failures at every boundary. -/
structure Script where
  /-- Raw replies used by deletion; no derived protection snapshot. -/
  access : Reply (List Row) := .ok []
  /-- Existence query on raw pin rows. -/
  pinned : Reply Bool := .ok false
  /-- Existence query on raw entry rows. -/
  referenced : Reply Bool := .ok false
  /-- Raw active-writer counter read. -/
  writers : Reply UInt64 := .ok 0
  /-- Acknowledgement of either individual file removal. -/
  unlink : Reply Unit := .ok ()
  /-- Reply to the immediate transaction request. -/
  begin : Reply Transaction := .ok 7
  /-- Raw projected durable column or its storage failure. -/
  durable : Reply (List Row) := .ok [[.integer 1]]
  /-- Raw wanted rows or their storage failure. -/
  wanted : Reply (List Row) := .ok [[.blob ByteArray.empty]]
  /-- Reply to the unconditional want deletion. -/
  delete : Reply Nat := .ok 1
  /-- Reply to the pin UPSERT. -/
  upsert : Reply Unit := .ok ()
  /-- Commit acknowledgement or its failure. -/
  commit : Reply Unit := .ok ()
  /-- Rollback acknowledgement, independent from the primary failure. -/
  rollback : Reply Unit := .ok ()

/-- Return raw scripted observations without implementing CAS policy. -/
def answer (script : Script) : Storage A → A
  | .begin => script.begin
  | .commit _ => script.commit
  | .rollback _ => script.rollback
  | .readRows _ relation columns _ =>
    if relation == "blobs" then
      if columns == ["last_access"] then script.access else script.durable
    else if relation == "content_want" then script.wanted
    else .error malformedMetadata
  | .upsert _ _ _ _ _ => script.upsert
  | .deleteRows _ _ _ => script.delete
  | .readBytes _ _ => .error malformedMetadata
  | .readInput .. => .error malformedMetadata
  | .readCounter .. => script.writers
  | .removeFile .. => script.unlink
  | .existsRows _ relation _ =>
    if relation == "pins" then script.pinned else script.referenced

/-- Evaluate the actual free-monad constructors, not a second CAS algorithm. -/
def execute (script : Script) : Program Storage A → A × List Event
  | .pure value => (value, [])
  | .request request resume =>
    let (result, tail) := execute script (resume (answer script request))
    (result, event request :: tail)

/-- Execute the production operation from its first transaction request. -/
def run (script : Script) (root : ByteArray) (holder : String) (now : Int64)
    (possession : Bool) : Reply Bool × List Event :=
  execute script (acquire root holder now possession).run

/-- The exact raw projections expected under the transaction token. -/
def reads (tx : Transaction) (root : ByteArray) (holder : String) : List Event :=
  [.readRows tx "blobs" ["durable"] [("root", .blob root)],
   .readRows tx "content_want" ["root"] [("root", .blob root), ("holder", .text holder)]]

/-- Exact authorized mutations, including UPSERT conflict/update columns. -/
def writes (tx : Transaction) (root : ByteArray) (holder : String) (now : Int64)
    (possession : Bool) : List Event :=
  (if possession then
    [.deleteRows tx "content_want" [("root", .blob root), ("holder", .text holder)]]
   else []) ++
  [.upsert tx "pins"
    [("root", .blob root), ("holder", .text holder),
      ("created_at", .integer now), ("release_after", .null)]
    ["root", "holder"] ["release_after"]]

/-- Raw durability accepts precisely nonzero integers in the unique projection. -/
theorem durability_nonzero (value : Int64) :
    decodeDurability [[.integer value]] = .ok (value != 0) := rfl

/-- Missing rows are not durable; malformed columns are errors, not absence. -/
theorem missing_not_durable : decodeDurability [] = .ok false := rfl

theorem null_not_durable : decodeDurability [[.null]] = .error ⟨2, 1⟩ := rfl

/-- Text, including numeric-looking text, retains its column-type error. -/
theorem text_not_durable (value : String) :
    decodeDurability [[.text value]] = .error ⟨2, 2⟩ := rfl

/-- Opaque bytes cannot be coerced into a durable integer. -/
theorem blob_not_durable (value : ByteArray) :
    decodeDurability [[.blob value]] = .error ⟨2, 3⟩ := rfl

/-- With successful storage, the complete program requests exactly its guarded
mutations between the raw reads and commit. A direct pin does not delete wants. -/
theorem successful_execution (tx : Transaction) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) (wanted : List Row) :
    run { begin := .ok tx, wanted := .ok wanted } root holder now possession =
      (.ok (!possession || !wanted.isEmpty),
        [.begin] ++ reads tx root holder ++
          (if !possession || !wanted.isEmpty then writes tx root holder now possession else []) ++
          [.commit tx]) := by
  cases possession <;> cases wanted <;> rfl

/-- An absent CAS row cannot create a pin, even if the want exists. -/
theorem missing_row_refused (tx : Transaction) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) (wanted : List Row) :
    run { begin := .ok tx, durable := .ok [], wanted := .ok wanted }
        root holder now possession =
      (.ok false, [.begin] ++ reads tx root holder ++ [.commit tx]) := by
  cases possession <;> rfl

/-- Zero is a staged/non-durable row, not permission to acquire a durable pin. -/
theorem staged_row_refused (tx : Transaction) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) (wanted : List Row) :
    run { begin := .ok tx, durable := .ok [[.integer 0]], wanted := .ok wanted }
        root holder now possession =
      (.ok false, [.begin] ++ reads tx root holder ++ [.commit tx]) := by
  cases possession <;> rfl

/-- Successful execution depends on Lean's raw-row decoder, not a host-provided
durability Boolean. This covers every accepted legacy integer value. -/
theorem decoded_execution (tx : Transaction) (root : ByteArray) (holder : String)
    (now : Int64) (possession durable : Bool) (rows wanted : List Row)
    (decoded : decodeDurability rows = .ok durable) :
    run { begin := .ok tx, durable := .ok rows, wanted := .ok wanted }
        root holder now possession =
      (.ok (durable && (!possession || !wanted.isEmpty)),
        [.begin] ++ reads tx root holder ++
          (if durable && (!possession || !wanted.isEmpty)
            then writes tx root holder now possession else []) ++ [.commit tx]) := by
  cases durable <;> cases possession <;> cases wanted <;>
    simp [run, acquire, transaction, acquireIn, perform, execute, answer, event,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
      ExceptT.run, ExceptT.mk, decoded, reads, writes]

/-- Authorization is derived from the raw observations of the actual program:
durability is required, and possession additionally requires a live want. -/
@[rust_justifies "cas-lifecycle-acquisition"]
theorem execution_authorized (tx : Transaction) (root : ByteArray) (holder : String)
    (now : Int64) (possession durable : Bool) (rows wanted : List Row)
    (decoded : decodeDurability rows = .ok durable) :
    (run { begin := .ok tx, durable := .ok rows, wanted := .ok wanted }
        root holder now possession).1 = .ok true ↔
      durable = true ∧ (possession = true → wanted ≠ []) := by
  rw [decoded_execution tx root holder now possession durable rows wanted decoded]
  cases durable <;> cases possession <;> cases wanted <;> simp

/-- Successful possession consumes the want and installs the pin in the same
transaction, then waits for that transaction's commit acknowledgement. -/
theorem possession_ordered (tx : Transaction) (root : ByteArray) (holder : String)
    (now : Int64) (rows wanted : List Row)
    (decoded : decodeDurability rows = .ok true) (live : wanted ≠ []) :
    run { begin := .ok tx, durable := .ok rows, wanted := .ok wanted }
        root holder now true =
      (.ok true, [.begin] ++ reads tx root holder ++ writes tx root holder now true ++
        [.commit tx]) := by
  rw [decoded_execution tx root holder now true true rows wanted decoded]
  cases wanted <;> simp_all

/-- A failed begin neither reads metadata nor attempts another transaction. -/
theorem begin_failure (failure : Failure) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) :
    run { begin := .error failure } root holder now possession =
      (.error failure, [.begin]) := rfl

/-- Failed metadata reads immediately roll back; even rollback failure cannot
replace the original host error. No mutation can follow this observation. -/
theorem durable_read_failure (tx : Transaction) (failure : Failure)
    (rollback : Reply Unit) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) :
    run { begin := .ok tx, durable := .error failure, rollback := rollback }
        root holder now possession =
      (.error failure, [.begin,
        .readRows tx "blobs" ["durable"] [("root", .blob root)], .rollback tx]) := rfl

/-- A raw NULL durable flag is a metadata error and triggers rollback before
the want read or any mutation. -/
theorem malformed_row_failure (tx : Transaction) (rollback : Reply Unit)
    (root : ByteArray) (holder : String) (now : Int64) (possession : Bool) :
    run { begin := .ok tx, durable := .ok [[.null]], rollback := rollback }
        root holder now possession =
      (.error ⟨2, 1⟩, [.begin,
        .readRows tx "blobs" ["durable"] [("root", .blob root)], .rollback tx]) := rfl

/-- A failed want read cannot be mistaken for an absent or still-live want. -/
theorem want_read_failure (tx : Transaction) (failure : Failure)
    (rollback : Reply Unit) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) :
    run { begin := .ok tx, wanted := .error failure, rollback := rollback }
        root holder now possession =
      (.error failure, [.begin] ++ reads tx root holder ++ [.rollback tx]) := rfl

/-- If consuming the want fails, no pin UPSERT or commit is requested. -/
theorem want_delete_failure (tx : Transaction) (failure : Failure)
    (rollback : Reply Unit) (root : ByteArray) (holder : String) (now : Int64) :
    run { begin := .ok tx, delete := .error failure, rollback := rollback }
        root holder now true =
      (.error failure, [.begin] ++ reads tx root holder ++
        [.deleteRows tx "content_want" [("root", .blob root), ("holder", .text holder)],
          .rollback tx]) := rfl

/-- A failed UPSERT rolls back the preceding want deletion rather than
returning possession or attempting a commit. -/
theorem pin_upsert_failure (tx : Transaction) (failure : Failure)
    (rollback : Reply Unit) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) :
    run { begin := .ok tx, upsert := .error failure, rollback := rollback }
        root holder now possession =
      (.error failure, [.begin] ++ reads tx root holder ++
        writes tx root holder now possession ++ [.rollback tx]) := by
  cases possession <;> rfl

/-- Successful individual mutations are insufficient: commit failure returns
the original error after rollback, regardless of the rollback reply. -/
theorem commit_failure (tx : Transaction) (failure : Failure)
    (rollback : Reply Unit) (root : ByteArray) (holder : String)
    (now : Int64) (possession : Bool) :
    run { begin := .ok tx, commit := .error failure, rollback := rollback }
        root holder now possession =
      (.error failure, [.begin] ++ reads tx root holder ++
        writes tx root holder now possession ++ [.commit tx, .rollback tx]) := by
  cases possession <;> rfl

/-- Even a refusal must not hide a failed transaction commit. -/
theorem refused_commit_failure (tx : Transaction) (failure : Failure)
    (rollback : Reply Unit) (root : ByteArray) (holder : String) (now : Int64) :
    run { begin := .ok tx, wanted := .ok [], commit := .error failure, rollback := rollback }
        root holder now true =
      (.error failure, [.begin] ++ reads tx root holder ++ [.commit tx, .rollback tx]) := rfl

/-- Runtime regression for legacy non-Boolean durable integers. -/
example (tx : Transaction) (root : ByteArray) (holder : String) (now : Int64) :
    run { begin := .ok tx, durable := .ok [[.integer (-7)]] }
        root holder now true =
      (.ok true, [.begin] ++ reads tx root holder ++ writes tx root holder now true ++
        [.commit tx]) := rfl

end Synchronicity.CasProgramProofs

#lint
