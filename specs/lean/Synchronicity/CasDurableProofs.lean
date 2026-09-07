import Synchronicity.CasFixtures
import Synchronicity.CasHealingPromises
import VerifiedCore.Cas.Durable

/-! The durability transitions, executed on the shared simulated host. The
universal theorems derive each transition's exact database from the program;
the fixture theorems run the same program on concrete rows, including every
injected host failure, so both the shape and the rollback are the executed
code's, not a restatement of it. -/
namespace Synchronicity.CasDurableProofs
open VerifiedCore.Host VerifiedCore.Cas.Durable SimulatedHost CasFixtures

/-! ## Vocabulary shared with the executed selections -/

/-- A durable claim over the root. -/
abbrev claimOf (root : ByteArray) : Selection :=
  ⟨"blobs", [("root", .blob root)], [], [("durable", .integer 0)]⟩

/-- The root's row with no local bytes at all. -/
abbrev coldRow (root : ByteArray) : Selection :=
  ⟨"blobs", [("root", .blob root), ("complete", .integer 0), ("bitmap", .null), ("inline", .null)], [], []⟩

/-- Rows that were only ever staged: no durable claim, no inline bytes. -/
def staged : Selection := ⟨"blobs", [("durable", .integer 0), ("inline", .null)], [], []⟩

/-- Durable rows whose only local bytes would be cached out-of-line groups. -/
def cachedDurable : Selection := ⟨"blobs", [("inline", .null)], [], [("durable", .integer 0)]⟩

def cleared : Fields := [("complete", .integer 0), ("bitmap", .null)]

/-- The role selection is the one the read-path repair uses. -/
theorem rolePins_eq_repairPins (root : ByteArray) : rolePins root = VerifiedCore.Cas.Read.repairPins root := rfl

/-! ## markDurable -/

/-- The whole transition: one update of the root's rows, nothing else. -/
theorem markDurable_state (state : State) (root : ByteArray)
    (quiet : state.faults = []) (idle : state.pending = none) :
    let result := SimulatedHost.run (markDurable root) state
    result.1 = .ok (((rows state.db "blobs").filter (selects (byRoot root))).length != 0) ∧
    result.2.db = setRows state.db "blobs" ((rows state.db "blobs").map fun row =>
      if selects (byRoot root) row then assign row [("durable", .integer 1)] else row) := by
  simp [SimulatedHost.run, markDurable, VerifiedCore.Cas.Durable.transaction, transactionOver,
    VerifiedCore.Cas.Durable.access, raise, performOver, Inject.inject, execute, Interpreter.handle,
    SimulatedHost.storage, SimulatedHost.access, reply, fault, record, SimulatedHost.transaction, quiet, idle,
    byRoot, Except.mapError, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]
  rfl

/-- Marking never creates a row: the table keeps exactly its rows, and every
other relation is untouched. -/
theorem markDurable_never_inserts (state : State) (root : ByteArray)
    (quiet : state.faults = []) (idle : state.pending = none) :
    (rows (SimulatedHost.run (markDurable root) state).2.db "blobs").length = (rows state.db "blobs").length ∧
    ∀ other, other ≠ "blobs" →
      rows (SimulatedHost.run (markDurable root) state).2.db other = rows state.db other := by
  rw [(markDurable_state state root quiet idle).2]
  refine ⟨by simp, fun other different => ?_⟩
  exact rows_setRows_other _ _ _ _ (Ne.symm different)

/-- A row of another root is returned verbatim. -/
theorem markDurable_other_roots (state : State) (root : ByteArray)
    (quiet : state.faults = []) (idle : state.pending = none)
    (row : Fields) (present : row ∈ rows state.db "blobs")
    (other : equals row [("root", .blob root)] = false) :
    row ∈ rows (SimulatedHost.run (markDurable root) state).2.db "blobs" := by
  rw [(markDurable_state state root quiet idle).2, rows_setRows]
  refine List.mem_map.mpr ⟨row, present, ?_⟩
  simp [selects, byRoot, other]

/-! ## reconcileScratch -/

/-- The persistent state of a generation change: staged rows dropped, cached
groups of durable rows cleared, the marker recorded. -/
def resetDatabase (db : Database) (marker : String) : Database :=
  let dropped := setRows db "blobs" ((rows db "blobs").filter fun row => !selects staged row)
  let emptied := setRows dropped "blobs" ((rows dropped "blobs").map fun row =>
    if selects cachedDurable row then assign row cleared else row)
  setRows emptied "config" (upsertRows (rows emptied "config")
    [("key", .text generationKey), ("value", .text marker)] ["key"] [("value", .excluded "value")])

/-- A matching marker changes nothing, and says so. -/
theorem reconcile_matching_marker (state : State) (marker : String)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "config" ["value"] [("key", .text generationKey)] [] [] = [[.text marker]]) :
    let result := SimulatedHost.run (reconcileScratch marker) state
    result.1 = .ok false ∧ result.2.db = state.db := by
  simp [SimulatedHost.run, reconcileScratch, VerifiedCore.Cas.Durable.transaction, transactionOver,
    VerifiedCore.Cas.Durable.storage, VerifiedCore.Cas.Durable.access, raise, performOver,
    Inject.inject, execute, Interpreter.handle, SimulatedHost.storage, reply, fault, record,
    SimulatedHost.transaction, quiet, idle, observed, decodeMarker,
    Except.mapError, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]

/-- A changed marker resets the cache claims to exactly `resetDatabase`. -/
theorem reconcile_changed_marker (state : State) (marker previous : String)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "config" ["value"] [("key", .text generationKey)] [] [] = [[.text previous]])
    (different : previous ≠ marker) :
    let result := SimulatedHost.run (reconcileScratch marker) state
    result.1 = .ok true ∧ result.2.db = resetDatabase state.db marker := by
  simp [SimulatedHost.run, reconcileScratch, VerifiedCore.Cas.Durable.transaction, transactionOver,
    VerifiedCore.Cas.Durable.storage, VerifiedCore.Cas.Durable.access, raise, performOver,
    Inject.inject, execute, Interpreter.handle, SimulatedHost.storage, SimulatedHost.access, reply, fault, record,
    SimulatedHost.transaction, quiet, idle, observed, decodeMarker, different, resetDatabase,
    staged, cachedDurable, cleared,
    Except.mapError, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]
  rfl

/-- The first generation ever seen resets the same way. -/
theorem reconcile_first_marker (state : State) (marker : String)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "config" ["value"] [("key", .text generationKey)] [] [] = []) :
    let result := SimulatedHost.run (reconcileScratch marker) state
    result.1 = .ok true ∧ result.2.db = resetDatabase state.db marker := by
  simp [SimulatedHost.run, reconcileScratch, VerifiedCore.Cas.Durable.transaction, transactionOver,
    VerifiedCore.Cas.Durable.storage, VerifiedCore.Cas.Durable.access, raise, performOver,
    Inject.inject, execute, Interpreter.handle, SimulatedHost.storage, SimulatedHost.access, reply, fault, record,
    SimulatedHost.transaction, quiet, idle, observed, decodeMarker, resetDatabase,
    staged, cachedDurable, cleared,
    Except.mapError, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]
  rfl

/-- Assigning some columns leaves every other column's cell as it was. -/
theorem cell_assign_other (row values : Fields) (column : String)
    (absent : values.all (fun field => field.1 != column) = true) :
    cell (assign row values) column = cell row column := by
  have none : values.find? (fun field => field.1 == column) = none := by
    rw [List.find?_eq_none]
    intro field member
    simpa using List.all_eq_true.mp absent field member
  unfold cell assign
  rw [List.find?_append, none, Option.none_or, List.find?_filter]
  congr 3
  funext ⟨name, value⟩
  by_cases hit : (name == column) = true
  · rw [beq_iff_eq] at hit
    subst hit
    have quiet : (values.any fun other => other.1 == name) = false := by
      rw [List.any_eq_false]
      intro other member
      simpa using List.all_eq_true.mp absent other member
    simp [quiet]
  · simp [hit]

/-- No staged row survives a generation change, and every surviving durable
out-of-line row has no cached groups left. -/
theorem reset_drops_staged (db : Database) (marker : String) :
    ∀ row ∈ rows (resetDatabase db marker) "blobs",
      selects staged row = false ∧ (selects cachedDurable row = true →
        cell row "complete" = .integer 0 ∧ cell row "bitmap" = .null) := by
  intro row present
  simp only [resetDatabase, rows_setRows, rows_setRows_other _ "config" "blobs" _ (by decide),
    List.mem_map, List.mem_filter] at present
  obtain ⟨source, ⟨_, unstaged⟩, rfl⟩ := present
  have unstaged : selects staged source = false := by simpa using unstaged
  by_cases cached : selects cachedDurable source = true
  · have durable := cell_assign_other source cleared "durable" (by decide)
    have inline := cell_assign_other source cleared "inline" (by decide)
    simp only [cached, if_true]
    refine ⟨?_, fun _ => ?_⟩
    · simpa [selects, staged, equals, durable, inline] using unstaged
    · simp [cell, assign, cleared]
  · simp only [cached]
    exact ⟨unstaged, fun claim => absurd claim cached⟩

/-! ## healMissing -/

/-- The persistent state of a withdrawn claim: durable cleared, a row without
bytes removed, every machine role's pin copied to a repair intent and then
removed; the operator's pin does not match the role selection and stays. -/
def withdrawnDatabase (db : Database) (root : ByteArray) (size now : Int64) : Database :=
  let withdrawn := setRows db "blobs" ((rows db "blobs").map fun row =>
    if selects (claimOf root) row then assign row [("durable", .integer 0)] else row)
  let swept := setRows withdrawn "blobs" ((rows withdrawn "blobs").filter fun row => !selects (coldRow root) row)
  let copied := copyRows swept "content_want" (rolePins root)
    (CasHealingPromises.repairFields size now) ["root", "holder"]
  setRows copied "pins" ((rows copied "pins").filter fun row => !selects (rolePins root) row)

/-- With no claim to withdraw, the update selects nothing and the only change
is sweeping a row without bytes. -/
def sweptDatabase (db : Database) (root : ByteArray) : Database :=
  let unchanged := setRows db "blobs" ((rows db "blobs").map fun row =>
    if selects (claimOf root) row then assign row [("durable", .integer 0)] else row)
  setRows unchanged "blobs" ((rows unchanged "blobs").filter fun row => !selects (coldRow root) row)

/-- The transition when the row holds a durable claim. -/
theorem heal_withdraws_claim (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (claimed : ∃ row ∈ rows state.db "blobs", selects (claimOf root) row = true) :
    let result := SimulatedHost.run (healMissing root) state
    result.1 = .ok true ∧ result.2.db = withdrawnDatabase state.db root size state.now := by
  have standing : ¬ ∀ row ∈ rows state.db "blobs", selects (claimOf root) row = false := by
    obtain ⟨row, member, selected⟩ := claimed
    intro all
    simpa [selected] using all row member
  simp [SimulatedHost.run, healMissing, readSize, VerifiedCore.Cas.Durable.transaction, transactionOver,
    VerifiedCore.Cas.Durable.storage, VerifiedCore.Cas.Durable.access, VerifiedCore.Cas.Durable.clock,
    raise, performOver, Inject.inject, execute, Interpreter.handle, SimulatedHost.storage, SimulatedHost.access,
    SimulatedHost.clock, reply, fault, record, SimulatedHost.transaction, quiet, idle, observed,
    decodeSize, VerifiedCore.Cas.Codec.integerField, standing, withdrawnDatabase,
    CasHealingPromises.repairFields,
    Except.mapError, Except.map, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]
  rfl

/-- The transition when the row holds no durable claim: no pin or intent moves. -/
theorem heal_without_claim (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (unclaimed : ∀ row ∈ rows state.db "blobs", selects (claimOf root) row = false) :
    let result := SimulatedHost.run (healMissing root) state
    result.1 = .ok false ∧ result.2.db = sweptDatabase state.db root := by
  simp [SimulatedHost.run, healMissing, readSize, VerifiedCore.Cas.Durable.transaction, transactionOver,
    VerifiedCore.Cas.Durable.storage, VerifiedCore.Cas.Durable.access,
    raise, performOver, Inject.inject, execute, Interpreter.handle, SimulatedHost.storage, SimulatedHost.access,
    reply, fault, record, SimulatedHost.transaction, quiet, idle, observed,
    decodeSize, VerifiedCore.Cas.Codec.integerField, eq_true unclaimed, sweptDatabase,
    Except.mapError, Except.map, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]

/-- Repair is gated on the withdrawal: without one, pins and intents are as
they were. -/
theorem heal_without_claim_moves_nothing (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (unclaimed : ∀ row ∈ rows state.db "blobs", selects (claimOf root) row = false) :
    rows (SimulatedHost.run (healMissing root) state).2.db "pins" = rows state.db "pins" ∧
    rows (SimulatedHost.run (healMissing root) state).2.db "content_want" = rows state.db "content_want" := by
  rw [(heal_without_claim state root size quiet idle observed unclaimed).2]
  simp [sweptDatabase]

/-- The withdrawn database shares its pins and intents with the read path's
repair of the same root, so that path's obligation theorems apply. -/
theorem withdrawn_agrees_with_read_repair (db : Database) (root : ByteArray) (size now : Int64) :
    rows (withdrawnDatabase db root size now) "pins" =
      rows (CasHealingPromises.healedDatabase db root size now) "pins" ∧
    rows (withdrawnDatabase db root size now) "content_want" =
      rows (CasHealingPromises.healedDatabase db root size now) "content_want" := by
  simp [withdrawnDatabase, CasHealingPromises.healedDatabase, copyRows, rolePins,
    VerifiedCore.Cas.Read.repairPins]

/-- Withdrawing a claim loses no responsibility: every pin or intent key held
before is held after, and none appears from nowhere. -/
theorem heal_preserves_responsibility (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (claimed : ∃ row ∈ rows state.db "blobs", selects (claimOf root) row = true)
    (pinsValid : CasHealingPromises.WellKeyed (rows state.db "pins"))
    (wantsValid : CasHealingPromises.WellKeyed (rows state.db "content_want")) :
    ∀ key, CasHealingPromises.obligation (SimulatedHost.run (healMissing root) state).2.db key ↔
      CasHealingPromises.obligation state.db key := by
  intro key
  rw [(heal_withdraws_claim state root size quiet idle observed claimed).2]
  have agree := withdrawn_agrees_with_read_repair state.db root size state.now
  simp only [CasHealingPromises.obligation, agree.1, agree.2]
  exact CasHealingPromises.healed_obligations _ _ _ _ pinsValid wantsValid key

/-- After a withdrawal no machine role's pin over the root stands. -/
theorem heal_removes_role_pins (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (claimed : ∃ row ∈ rows state.db "blobs", selects (claimOf root) row = true) :
    ∀ row ∈ rows (SimulatedHost.run (healMissing root) state).2.db "pins",
      selects (rolePins root) row = false := by
  intro row present
  rw [(heal_withdraws_claim state root size quiet idle observed claimed).2] at present
  simp only [withdrawnDatabase, rows_setRows, List.mem_filter] at present
  simpa using present.2

/-- Every pin outside the role selection, the operator's among them, survives
a withdrawal verbatim. -/
theorem heal_keeps_other_pins (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (claimed : ∃ row ∈ rows state.db "blobs", selects (claimOf root) row = true)
    (row : Fields) (present : row ∈ rows state.db "pins")
    (unselected : selects (rolePins root) row = false) :
    row ∈ rows (SimulatedHost.run (healMissing root) state).2.db "pins" := by
  rw [(heal_withdraws_claim state root size quiet idle observed claimed).2]
  simp only [withdrawnDatabase, copyRows, rows_setRows, List.mem_filter,
    rows_setRows_other _ "content_want" "pins" _ (by decide),
    rows_setRows_other _ "blobs" "pins" _ (by decide)]
  exact ⟨present, by simpa using unselected⟩

/-- Existing repair intents keep their own record through a withdrawal. -/
theorem heal_keeps_existing_wants (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (claimed : ∃ row ∈ rows state.db "blobs", selects (claimOf root) row = true)
    (row : Fields) (present : row ∈ rows state.db "content_want") :
    row ∈ rows (SimulatedHost.run (healMissing root) state).2.db "content_want" := by
  rw [(heal_withdraws_claim state root size quiet idle observed claimed).2]
  simp only [withdrawnDatabase, rows_setRows_other _ "pins" "content_want" _ (by decide)]
  apply copyRows_preserves_existing
  simpa using present

/-- Rows of other roots are untouched by a withdrawal. -/
theorem heal_keeps_other_roots (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (claimed : ∃ row ∈ rows state.db "blobs", selects (claimOf root) row = true)
    (row : Fields) (present : row ∈ rows state.db "blobs")
    (other : isCell (cell row "root") (.blob root) = false) :
    row ∈ rows (SimulatedHost.run (healMissing root) state).2.db "blobs" := by
  rw [(heal_withdraws_claim state root size quiet idle observed claimed).2]
  simp only [withdrawnDatabase, copyRows, rows_setRows, List.mem_filter, List.mem_map,
    rows_setRows_other _ "content_want" "blobs" _ (by decide),
    rows_setRows_other _ "pins" "blobs" _ (by decide)]
  refine ⟨⟨row, present, ?_⟩, ?_⟩
  · simp [selects, equals, other]
  · simp [selects, equals, other]

/-! ## Fixtures: the same programs on concrete rows, faults included -/

private def thirdRoot : ByteArray := ⟨Array.replicate 32 2⟩

private def claimed : State :=
  { db := [("blobs", [blob]),
      ("pins", [pin, pin root "replica:media", pin root "operator", pin otherRoot "source:media"]),
      ("content_want", [want root "source:media" 999 .null (-7)])],
    files := [(("cas_payload", root), bytes), (("cas_outboard", root), bytes)], now := 123 }

private def unclaimed : State := { claimed with db := [("blobs", [blob (durable := 0)])] ++ claimed.db.drop 1 }

theorem mark_absent_row_is_false_and_inserts_nothing :
    let result := SimulatedHost.run (markDurable otherRoot) claimed
    (result.1, result.2.trace) == (.ok false, ["begin", "update:blobs", "commit"]) ∧
    result.2.db == claimed.db := by decide +kernel

theorem mark_claims_the_row :
    let result := SimulatedHost.run (markDurable root) unclaimed
    result.1 == .ok true ∧ rows result.2.db "blobs" == [assign (blob (durable := 0)) [("durable", .integer 1)]] := by
  decide +kernel

theorem adopt_creates_a_cold_row :
    let result := SimulatedHost.run (adoptDurable otherRoot 9 77) claimed
    (result.1, result.2.trace) == (.ok (), ["begin", "read:blobs", "upsert:blobs", "commit"]) ∧
    rows result.2.db "blobs" == [blob, [("root", .blob otherRoot), ("size", .integer 9),
      ("complete", .integer 0), ("bitmap", .null), ("inline", .null), ("last_access", .integer 77),
      ("durable", .integer 1)]] := by decide +kernel

theorem adopt_marks_an_agreeing_row :
    let result := SimulatedHost.run (adoptDurable root 4 77) unclaimed
    (result.1, result.2.trace) == (.ok (), ["begin", "read:blobs", "update:blobs", "commit"]) ∧
    rows result.2.db "blobs" == [assign (blob (durable := 0)) [("durable", .integer 1)]] := by decide +kernel

theorem adopt_refuses_a_disagreeing_size_untouched :
    let result := SimulatedHost.run (adoptDurable root 5 77) claimed
    (result.1, result.2.trace) == (.error (.sizeMismatch root 4 5), ["begin", "read:blobs", "rollback"]) ∧
    result.2.db == claimed.db := by decide +kernel

private def healTrace := ["begin", "read:blobs", "update:blobs", "delete:blobs", "clock",
  "copy:content_want", "delete:pins", "commit"]

theorem heal_withdraws_moves_roles_and_keeps_the_operator :
    let result := SimulatedHost.run (healMissing root) claimed
    (result.1, result.2.trace) == (.ok true, healTrace) ∧
    rows result.2.db "blobs" == [assign blob [("durable", .integer 0)]] ∧
    rows result.2.db "pins" == [pin root "operator", pin otherRoot "source:media"] ∧
    rows result.2.db "content_want" ==
      [want root "source:media" 999 .null (-7), want root "replica:media" 4 .null 123] := by decide +kernel

theorem heal_without_claim_changes_nothing :
    let result := SimulatedHost.run (healMissing root) unclaimed
    (result.1, result.2.trace) == (.ok false, ["begin", "read:blobs", "update:blobs", "delete:blobs", "commit"]) ∧
    result.2.db == unclaimed.db := by decide +kernel

theorem heal_removes_a_row_without_bytes :
    let result := SimulatedHost.run (healMissing root) { claimed with db := [("blobs", [blob (complete := 0)])] }
    result.1 == .ok true ∧ rows result.2.db "blobs" == [] := by decide +kernel

theorem heal_keeps_partial_bytes :
    let initial := { claimed with db := [("blobs", [blob (complete := 0) (bitmap := .blob ⟨#[1]⟩)])] }
    let result := SimulatedHost.run (healMissing root) initial
    result.1 == .ok true ∧
    rows result.2.db "blobs" == [assign (blob (complete := 0) (bitmap := .blob ⟨#[1]⟩)) [("durable", .integer 0)]] := by
  decide +kernel

theorem heal_of_an_absent_row_is_false :
    let result := SimulatedHost.run (healMissing root) { claimed with db := [] }
    result.1 == .ok false ∧ result.2.db == [("blobs", [])] := by decide +kernel

theorem every_failed_heal_stage_rolls_back :
    (List.range 7).all (fun index =>
      let result := SimulatedHost.run (healMissing root) (fail claimed (index + 1))
      failed result.1 && (result.2.db == claimed.db) && result.2.pending.isNone) = true := by decide +kernel

private def generations : State :=
  { db := [("blobs", [blob (durable := 0), blob otherRoot, blob thirdRoot (inline := .blob bytes) (durable := 0)]),
      ("config", [[("key", .text generationKey), ("value", .text "one")]])] }

theorem reconcile_matching_marker_is_a_no_op :
    let result := SimulatedHost.run (reconcileScratch "one") generations
    (result.1, result.2.trace) == (.ok false, ["begin", "read:config", "commit"]) ∧
    result.2.db == generations.db := by decide +kernel

theorem reconcile_changed_marker_resets_exactly_the_cache :
    let result := SimulatedHost.run (reconcileScratch "two") generations
    (result.1, result.2.trace) == (.ok true,
      ["begin", "read:config", "delete:blobs", "update:blobs", "upsert:config", "commit"]) ∧
    rows result.2.db "blobs" == [assign (blob otherRoot) cleared, blob thirdRoot (inline := .blob bytes) (durable := 0)] ∧
    rows result.2.db "config" == [[("value", .text "two"), ("key", .text generationKey)]] := by decide +kernel

theorem reconcile_records_the_first_marker :
    let result := SimulatedHost.run (reconcileScratch "one") { generations with db := generations.db.take 1 }
    result.1 == .ok true ∧
    rows result.2.db "config" == [[("key", .text generationKey), ("value", .text "one")]] := by decide +kernel

theorem reconcile_refuses_a_marker_of_the_wrong_type :
    let result := SimulatedHost.run (reconcileScratch "two")
      { generations with db := [("config", [[("key", .text generationKey), ("value", .integer 1)]])] }
    (result.1, result.2.trace) == (.error (.columnType 0 "value" .integer), ["begin", "read:config", "rollback"]) := by
  decide +kernel

theorem every_failed_reconcile_stage_rolls_back :
    (List.range 5).all (fun index =>
      let result := SimulatedHost.run (reconcileScratch "two") (fail generations (index + 1))
      failed result.1 && (result.2.db == generations.db)) = true := by decide +kernel

private def clearTrace := ["counter:cas_writers", "begin", "delete:blobs", "update:blobs", "commit",
  "remove:cas_payload", "remove:cas_outboard"]

theorem clear_keeps_the_claim_and_removes_both_files :
    let result := SimulatedHost.run (clearCache root) claimed
    (result.1, result.2.trace) == (.ok true, clearTrace) ∧
    rows result.2.db "blobs" == [assign blob cleared] ∧ result.2.files == [] := by decide +kernel

theorem clear_is_refused_while_a_writer_holds_the_object :
    let result := SimulatedHost.run (clearCache root) { claimed with counters := [(("cas_writers", root), 1)] }
    (result.1, result.2.trace) == (.ok false, ["counter:cas_writers"]) ∧
    result.2.db == claimed.db ∧ result.2.files == claimed.files := by decide +kernel

theorem clear_drops_a_staged_row :
    let result := SimulatedHost.run (clearCache root) unclaimed
    result.1 == .ok true ∧ rows result.2.db "blobs" == [] := by decide +kernel

theorem clear_leaves_an_inline_row :
    let initial := { claimed with db := [("blobs", [blob (inline := .blob bytes)])] }
    let result := SimulatedHost.run (clearCache root) initial
    result.1 == .ok true ∧ rows result.2.db "blobs" == [blob (inline := .blob bytes)] := by decide +kernel

/-- The rows commit before the files go, and a failed removal is not an error. -/
theorem clear_commits_before_removing_and_tolerates_missing_files :
    (List.range 2).all (fun index =>
      let result := SimulatedHost.run (clearCache root) (fail claimed (index + 5))
      (result.1 == .ok true) && (rows result.2.db "blobs" == [assign blob cleared])) = true := by decide +kernel

theorem every_failed_clear_stage_rolls_back_and_keeps_files :
    (List.range 4).all (fun index =>
      let result := SimulatedHost.run (clearCache root) (fail claimed (index + 1))
      failed result.1 && (result.2.db == claimed.db) && (result.2.files == claimed.files)) = true := by
  decide +kernel

end Synchronicity.CasDurableProofs
