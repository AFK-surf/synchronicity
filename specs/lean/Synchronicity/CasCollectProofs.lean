import Synchronicity.CasFixtures
import Synchronicity.CasPromises
import VerifiedCore.Cas.Collect

/-! Keeping the store within bounds, executed on the shared simulated host:
the access clock, eviction by least recent use, content collection and the
orphan sweep. Universal theorems establish retention and writer protection;
fixture theorems check the clock and run the programs on concrete rows and files,
including every injected host failure, so the order of section, reading,
decision and unlink is the executed code's. -/
namespace Synchronicity.CasCollectProofs
open VerifiedCore.Host VerifiedCore.Cas.Collect SimulatedHost CasFixtures

/-! ## Eviction -/

/-- The rows eviction considers hold a durable claim and no inline bytes:
never a staged-only row, whose scratch copy is its only one, and never an
inline object, which has no files to clear. -/
theorem cachedDurable_selects (row : Fields) (selected : selects cachedDurable row = true) :
    isCell (cell row "durable") (.integer 0) = false ∧ isCell (cell row "inline") .null = true := by
  simp only [selects, cachedDurable, equals, List.all_cons, List.all_nil, List.isEmpty_nil,
    Bool.and_true, Bool.true_or, Bool.and_eq_true, Bool.not_eq_true'] at selected
  exact ⟨selected.2, selected.1⟩

/-- A cache clear asked of an object a writer holds is refused before any
transaction: eviction cannot take bytes out from under a write. -/
theorem clear_refused_while_held (state : State) (root : ByteArray)
    (quiet : state.faults = []) (held : counter state ("cas_writers", root) ≠ 0) :
    SimulatedHost.run (VerifiedCore.Cas.Durable.clearCache root) state =
      (.ok false, record { state with output := [] } "counter:cas_writers") := by
  unfold counter at held
  simp [SimulatedHost.run, VerifiedCore.Cas.Durable.clearCache, VerifiedCore.Cas.Durable.storage,
    raise, performOver, Inject.inject, execute, Interpreter.handle, SimulatedHost.storage, reply, fault,
    record, quiet, counter, held, Except.mapError, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.pure, ExceptT.run, ExceptT.mk]

/-! ## The collection pre-filter -/

/-- SQL `IS` against a blob literal is symmetric in the cell it reads. -/
theorem isCell_blob_right (value : Cell) (bytes : ByteArray) :
    isCell value (.blob bytes) = equalCell (.blob bytes) value := by
  cases value <;> simp [isCell, equalCell, Bool.beq_comm]

/-- The pre-filter's exclusions are exactly the facts the deletion re-reads:
a pin on the root, or an entry naming it. -/
theorem excluded_iff_protected (db : Database) (row : Fields) (root : ByteArray)
    (keyed : cell row "root" = .blob root) :
    excluded db row protections = true ↔
      ((rows db "pins").any (fun pin => equals pin [("root", .blob root)]) = true ∨
        (rows db "entries").any (fun entry => equals entry [("content", .blob root)]) = true) := by
  simp [excluded, protections, correlated, equals, keyed, isCell_blob_right]

/-- A row the pre-filter drops for a pin or an entry is one the deletion,
re-reading the same facts in its own transaction, refuses: the pre-filter
never hides a collectable object. -/
theorem dropped_protected_is_kept (state : State) (row : Fields) (root : ByteArray)
    (before : Int64) (accessed : Option Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (keyed : cell row "root" = .blob root)
    (decoded : VerifiedCore.Cas.decodeAccess
      (query state.db "blobs" ["last_access"] [("root", .blob root)] [] []) = .ok accessed)
    (shielded : excluded state.db row protections = true) :
    let result := SimulatedHost.run (VerifiedCore.Cas.delete root (some before)) state
    result.1 ≠ .ok .applied ∧ result.2.db = state.db ∧ result.2.files = state.files := by
  rcases (excluded_iff_protected state.db row root keyed).mp shielded with pinned | referenced
  · exact CasPromises.kept_content_is_protected_from_collection root (some before) state accessed
      quiet idle decoded (Or.inl pinned)
  · exact CasPromises.kept_content_is_protected_from_collection root (some before) state accessed
      quiet idle decoded (Or.inr (Or.inl referenced))

set_option maxHeartbeats 2000000 in
/-- A row the pre-filter drops for its freshness is one the deletion refuses
for the same reason, whatever else it finds. -/
theorem dropped_fresh_is_kept (state : State) (root : ByteArray) (before accessed : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["last_access"] [("root", .blob root)] [] [] = [[.integer accessed]])
    (fresh : before ≤ accessed) :
    let result := SimulatedHost.run (VerifiedCore.Cas.delete root (some before)) state
    result.1 ≠ .ok .applied ∧ result.2.db = state.db ∧ result.2.files = state.files := by
  generalize hp : (rows state.db "pins").any (fun row => equals row [("root", .blob root)]) = pinned
  generalize hr : (rows state.db "entries").any (fun row => equals row [("content", .blob root)]) = referenced
  cases pinned <;> cases referenced <;>
    by_cases writing : counter state ("cas_writers", root) = 0
  all_goals unfold counter at writing
  all_goals simp (config := { maxSteps := 100000 }) [SimulatedHost.run, VerifiedCore.Cas.delete,
      VerifiedCore.Cas.deleteIn, transactionWith, transactionOver, VerifiedCore.Cas.request, performWith,
      execute, Interpreter.handle, SimulatedHost.storage, reply, fault, record, SimulatedHost.transaction,
      counter, VerifiedCore.Cas.planLifecycle, VerifiedCore.Cas.decodeAccess,
      VerifiedCore.Cas.Codec.integerField, Except.mapError, Except.map, quiet, idle, observed, hp, hr, writing, fresh,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-! ## The orphan sweep -/

/-- A file written inside the horizon is left alone: the section is entered
and released around the one reading, and nothing else is asked. -/
theorem sweepFile_fresh (state : State) (root : ByteArray) (space : String) (before modified : Int64)
    (quiet : state.faults = []) (present : (lookupFile state.files (space, root)).isSome = true)
    (written : (state.modified.find? fun entry => entry.1 == (space, root)).map Prod.snd = some modified)
    (fresh : before ≤ modified) :
    let result := SimulatedHost.run (sweepFile before root space) state
    result.1 = .ok false ∧ result.2.files = state.files ∧ result.2.db = state.db ∧
      result.2.trace = state.trace ++ ["order:cas", "modified:" ++ space, "release"] := by
  obtain ⟨bytes, found⟩ := Option.isSome_iff_exists.mp present
  simp [SimulatedHost.run, sweepFile, VerifiedCore.Cas.Collect.ordered, ensure, VerifiedCore.Cas.Collect.lease,
    VerifiedCore.Cas.Collect.sweep, raise, performOver, Inject.inject, execute, Interpreter.handle,
    SimulatedHost.lease, SimulatedHost.sweep, reply, fault, record, quiet, found, written, fresh,
    setCounter, counter, Except.mapError, Except.map, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- A stale file of an object no row accounts for and no writer holds goes,
and the reading, the row check, the writer check and the unlink all happen
inside the one section, in that order. -/
theorem sweepFile_removes_inside_section (state : State) (root : ByteArray) (space : String)
    (before modified : Int64)
    (quiet : state.faults = []) (clean : state.scanFault = none) (unheld : state.counters = [])
    (present : (lookupFile state.files (space, root)).isSome = true)
    (written : (state.modified.find? fun entry => entry.1 == (space, root)).map Prod.snd = some modified)
    (stale : ¬ before ≤ modified)
    (unaccounted : ∀ row ∈ rows state.db "blobs", selects (VerifiedCore.Cas.Durable.byRoot root) row = false) :
    let result := SimulatedHost.run (sweepFile before root space) state
    result.1 = .ok true ∧
      result.2.files = state.files.filter (fun entry => entry.1 != (space, root)) ∧
      result.2.db = state.db ∧
      result.2.trace = state.trace ++ ["order:cas", "modified:" ++ space, "snapshot:blobs",
        "counter:cas_writers", "remove:" ++ space, "release"] := by
  obtain ⟨bytes, found⟩ := Option.isSome_iff_exists.mp present
  have absent : ¬ ∃ row, row ∈ rows state.db "blobs" ∧
      selects (VerifiedCore.Cas.Durable.byRoot root) row = true := by
    rintro ⟨row, member, selected⟩
    simp [unaccounted row member] at selected
  simp only [VerifiedCore.Cas.Durable.byRoot] at absent
  simp [SimulatedHost.run, sweepFile, accounted, VerifiedCore.Cas.Collect.ordered, ensure,
    VerifiedCore.Cas.Collect.lease, VerifiedCore.Cas.Collect.sweep, VerifiedCore.Cas.Collect.access,
    VerifiedCore.Cas.Collect.storage, raise, performOver, Inject.inject, execute, Interpreter.handle,
    SimulatedHost.lease, SimulatedHost.sweep, SimulatedHost.access, SimulatedHost.storage, reply, fault,
    record, quiet, clean, unheld, found, written, stale, absent, VerifiedCore.Cas.Durable.byRoot,
    scanFailure, setCounter, counter, attempt, Except.mapError, Except.map,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-! ## Fixtures: the same programs on concrete rows and files, faults included -/

private def thirdRoot : ByteArray := ⟨Array.replicate 32 2⟩
private def fourthRoot : ByteArray := ⟨Array.replicate 32 3⟩

/-- A row as the sweeps read it: when it was last accessed and what it holds. -/
private def row (key : ByteArray) (accessed : Int64) (durable : Int64 := 1) (inline : Cell := .null) : Fields :=
  [("root", .blob key), ("size", .integer 4), ("complete", .integer 1), ("bitmap", .null),
   ("inline", inline), ("last_access", .integer accessed), ("durable", .integer durable)]

private def pair (key : ByteArray) : FileStore :=
  [(("cas_payload", key), bytes), (("cas_outboard", key), bytes)]

private def written (key : ByteArray) (at_ : Int64) : List (ObjectKey × Int64) :=
  [(("cas_payload", key), at_), (("cas_outboard", key), at_)]

private def clock : Int64 := 100000000000

/-- Two cached durable objects, one of them pinned, a staged-only row and an
inline row; the clock far past every access. -/
private def stocked : State :=
  { db := [("blobs", [row root 10, row otherRoot 20, row thirdRoot 5 (durable := 0),
        row fourthRoot 30 (inline := .blob bytes)]),
      ("pins", [pin otherRoot "operator"])],
    files := pair root ++ pair otherRoot ++ pair thirdRoot,
    modified := written root 1 ++ written otherRoot 1 ++ written thirdRoot 1,
    now := clock }

theorem touch_moves_a_cold_row_to_now :
    let result := SimulatedHost.run (touch root) stocked
    (result.1, result.2.trace) == (.ok true, ["clock", "begin", "read:blobs", "update:blobs", "commit"]) ∧
    rows result.2.db "blobs" == [assign (row root 10) [("last_access", .integer clock)], row otherRoot 20,
      row thirdRoot 5 (durable := 0), row fourthRoot 30 (inline := .blob bytes)] := by decide +kernel

theorem touch_within_the_interval_writes_nothing :
    let recent := { stocked with db := [("blobs", [row root (clock - 1)])] }
    let result := SimulatedHost.run (touch root) recent
    (result.1, result.2.trace) == (.ok false, ["clock", "begin", "read:blobs", "commit"]) ∧
    result.2.db == recent.db := by decide +kernel

theorem touch_of_an_absent_row_is_false :
    let result := SimulatedHost.run (touch fourthRoot) { stocked with db := [] }
    result.1 == .ok false ∧ result.2.db == [] := by decide +kernel

private def measuring := ["snapshot:blobs", "bytes:cas_payload", "bytes:cas_outboard",
  "bytes:cas_payload", "bytes:cas_outboard"]

private def clearing := ["order:cas", "counter:cas_writers", "begin", "delete:blobs", "update:blobs", "commit",
  "remove:cas_payload", "remove:cas_outboard", "release"]

theorem eviction_with_neither_limit_nor_shortfall_measures_and_clears_nothing :
    let result := SimulatedHost.run (evict none 0) stocked
    (result.1, result.2.trace) == (.ok (0, 0), measuring) ∧
    result.2.db == stocked.db ∧ result.2.files == stocked.files := by decide +kernel

/-- One byte of shortfall takes exactly the least recently used cached
durable object; its claim stands, its files go, and the pinned, staged and
inline rows are untouched. -/
theorem eviction_takes_the_least_recently_used_first :
    let result := SimulatedHost.run (evict none 1) stocked
    (result.1, result.2.trace) == (.ok (1, 8), measuring ++ clearing) ∧
    rows result.2.db "blobs" == [assign (row root 10) [("complete", .integer 0), ("bitmap", .null)],
      row otherRoot 20, row thirdRoot 5 (durable := 0), row fourthRoot 30 (inline := .blob bytes)] ∧
    result.2.files == pair otherRoot ++ pair thirdRoot := by decide +kernel

/-- A limit of zero takes every cached durable object, the pinned one too,
coldest first; the staged row keeps its only copy. -/
theorem eviction_to_zero_takes_every_cached_durable_object_in_order :
    let result := SimulatedHost.run (evict (some 0) 0) stocked
    (result.1, result.2.trace) == (.ok (2, 16), measuring ++ clearing ++ clearing) ∧
    rows result.2.db "blobs" == [assign (row root 10) [("complete", .integer 0), ("bitmap", .null)],
      assign (row otherRoot 20) [("complete", .integer 0), ("bitmap", .null)],
      row thirdRoot 5 (durable := 0), row fourthRoot 30 (inline := .blob bytes)] ∧
    result.2.files == pair thirdRoot := by decide +kernel

/-- The coldest object is skipped while a writer holds it, and counted
against nothing; the next one goes instead. -/
theorem eviction_skips_an_object_a_writer_holds :
    let holding := { stocked with counters := [(("cas_writers", root), 1)] }
    let result := SimulatedHost.run (evict (some 0) 0) holding
    (result.1, result.2.trace) == (.ok (1, 8),
      measuring ++ ["order:cas", "counter:cas_writers", "release"] ++ clearing) ∧
    result.2.files == pair root ++ pair thirdRoot ∧
    counter result.2 ("cas", ByteArray.empty) == 0 := by decide +kernel

/-- A failure at any effect leaves the section released and no transaction open. -/
theorem every_failed_eviction_effect_releases_the_section :
    (List.range (measuring ++ clearing ++ clearing).length).all (fun index =>
      let result := SimulatedHost.run (evict (some 0) 0) (fail stocked index)
      (counter result.2 ("cas", ByteArray.empty) == 0) && result.2.pending.isNone) = true := by
  decide +kernel

/-- Referenced, pinned, held and fresh objects beside one cold orphan. -/
private def collectable : State :=
  { db := [("blobs", [row root 0, row otherRoot 0, row thirdRoot 0, row fourthRoot 900]),
      ("pins", [pin thirdRoot "operator"]),
      ("entries", [entry otherRoot])],
    files := pair root ++ pair otherRoot ++ pair thirdRoot ++ pair fourthRoot,
    now := clock }

private def deleting := ["order:cas", "begin", "exists:pins", "exists:entries", "read:blobs",
  "counter:cas_writers", "delete:blobs", "commit", "remove:cas_payload", "remove:cas_outboard", "release"]

/-- The pre-filter names only the cold unprotected object, and its deletion
re-reads every fact inside the section before the row and files go. -/
theorem collection_takes_exactly_the_cold_unprotected_object :
    let result := SimulatedHost.run (gcContent 500) collectable
    (result.1, result.2.trace) == (.ok 1, ["exclude:blobs"] ++ deleting) ∧
    rows result.2.db "blobs" == [row otherRoot 0, row thirdRoot 0, row fourthRoot 900] ∧
    result.2.files == pair otherRoot ++ pair thirdRoot ++ pair fourthRoot := by decide +kernel

theorem collection_is_refused_for_an_object_a_writer_holds :
    let holding := { collectable with counters := [(("cas_writers", root), 1)] }
    let result := SimulatedHost.run (gcContent 500) holding
    (result.1, result.2.trace) == (.ok 0, ["exclude:blobs", "order:cas", "begin", "exists:pins",
      "exists:entries", "read:blobs", "counter:cas_writers", "commit", "release"]) ∧
    result.2.db == holding.db ∧ result.2.files == holding.files := by decide +kernel

theorem every_failed_collection_effect_keeps_the_row_or_finishes_and_releases :
    (List.range deleting.length).all (fun index =>
      let result := SimulatedHost.run (gcContent 500) (fail collectable (index + 1))
      (counter result.2 ("cas", ByteArray.empty) == 0) && result.2.pending.isNone &&
        (failed result.1 || rows result.2.db "blobs" != rows collectable.db "blobs" ||
          result.2.files == collectable.files)) = true := by decide +kernel

/-- A live object's files, a stale orphan, a fresh orphan and an orphan a
writer is filling. -/
private def littered : State :=
  { db := [("blobs", [row root 0])],
    files := pair root ++ pair otherRoot ++ pair thirdRoot ++ pair fourthRoot,
    modified := written root 1 ++ written otherRoot 1 ++ written thirdRoot 999 ++ written fourthRoot 1,
    counters := [(("cas_writers", fourthRoot), 1)],
    now := clock }

private def sweeping (space : String) := ["order:cas", "modified:" ++ space, "snapshot:blobs",
  "counter:cas_writers", "remove:" ++ space, "release"]

/-- Only the stale orphan's two files go: the live object's stay for their
row, the fresh orphan's for its age, the held orphan's for its writer. -/
theorem orphan_sweep_takes_only_stale_unaccounted_unheld_files :
    let result := SimulatedHost.run (gcOrphans 500) littered
    result.1 == .ok 2 ∧
    result.2.files == pair root ++ pair thirdRoot ++ pair fourthRoot ∧
    result.2.trace == ["list"] ++
      ["order:cas", "modified:cas_payload", "snapshot:blobs", "release",
       "order:cas", "modified:cas_outboard", "snapshot:blobs", "release"] ++
      sweeping "cas_payload" ++ sweeping "cas_outboard" ++
      ["order:cas", "modified:cas_payload", "release", "order:cas", "modified:cas_outboard", "release",
       "order:cas", "modified:cas_payload", "snapshot:blobs", "counter:cas_writers", "release",
       "order:cas", "modified:cas_outboard", "snapshot:blobs", "counter:cas_writers", "release", "list"] ∧
    counter result.2 ("cas", ByteArray.empty) == 0 := by decide +kernel

theorem orphan_sweep_of_an_empty_store_asks_one_page :
    let result := SimulatedHost.run (gcOrphans 500) { littered with files := [] }
    (result.1, result.2.trace) == (.ok 0, ["list", "list"]) := by decide +kernel

/-- A failure at any effect leaves the section released, and a file is only
ever gone after its own decision inside a section. -/
theorem every_failed_orphan_effect_releases_the_section :
    let two := { littered with files := pair otherRoot ++ pair fourthRoot }
    (List.range 14).all (fun index =>
      let result := SimulatedHost.run (gcOrphans 500) (fail two index)
      (counter result.2 ("cas", ByteArray.empty) == 0) &&
        (pair fourthRoot).all (fun file => result.2.files.contains file)) = true := by
  decide +kernel

end Synchronicity.CasCollectProofs
