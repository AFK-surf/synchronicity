import Synchronicity.SimulatedHost
import VerifiedCore.Cas.Read

/-! Repair laws over the shared database. Key predicates are proof vocabulary;
the host itself operates only on raw fields and SQL selections. -/
namespace Synchronicity.CasHealingPromises
open VerifiedCore.Host VerifiedCore.Cas.Read SimulatedHost

abbrev Key := ByteArray × String

def keyOf (row : Fields) : Option Key :=
  match cell row "root", cell row "holder" with
  | .blob root, .text holder => some (root, holder)
  | _, _ => none

def WellKeyed (table : List Fields) : Prop := ∀ row ∈ table, (keyOf row).isSome = true

def hasKey (table : List Fields) (key : Key) : Prop := ∃ row ∈ table, keyOf row = some key

def obligation (db : Database) (key : Key) : Prop :=
  hasKey (rows db "pins") key ∨ hasKey (rows db "content_want") key

private theorem conflict_key (incoming current : Fields)
    (validIncoming : (keyOf incoming).isSome = true) (validCurrent : (keyOf current).isSome = true) :
    conflict ["root", "holder"] incoming current = true ↔ keyOf incoming = keyOf current := by
  unfold keyOf at validIncoming validCurrent ⊢
  cases a : cell incoming "root" <;> cases b : cell incoming "holder" <;>
    cases c : cell current "root" <;> cases d : cell current "holder" <;>
    simp_all [conflict, equalCell, BEq.beq, instBEqCell.beq]
  all_goals
    rename_i ar ah br bh
    intro _
    exact (beq_iff_eq (a := ar) (b := br))

private theorem upsert_hasKey (table : List Fields) (incoming : Fields) (key : Key)
    (valid : WellKeyed table) (incomingValid : (keyOf incoming).isSome = true) :
    hasKey (upsertRows table incoming ["root", "holder"] []) key ↔
      hasKey table key ∨ keyOf incoming = some key := by
  rw [upsertRows_doNothing]
  split
  · rename_i hit
    obtain ⟨current, member, same⟩ := List.any_eq_true.mp hit
    have keys := (conflict_key incoming current incomingValid (valid current member)).mp same
    constructor
    · exact Or.inl
    · rintro (held | added)
      · exact held
      · exact ⟨current, member, keys ▸ added⟩
  · simp [hasKey]

private theorem upsert_valid (table : List Fields) (incoming : Fields)
    (valid : WellKeyed table) (incomingValid : (keyOf incoming).isSome = true) :
    WellKeyed (upsertRows table incoming ["root", "holder"] []) := by
  rw [upsertRows_doNothing]
  split
  · exact valid
  · intro row member
    simp only [List.mem_append, List.mem_singleton] at member
    rcases member with member | same
    · exact valid row member
    · subst row; exact incomingValid

private def merge (table incoming : List Fields) :=
  incoming.foldl (fun table row => upsertRows table row ["root", "holder"] []) table

private theorem merge_hasKey (table incoming : List Fields) (key : Key)
    (valid : WellKeyed table) (incomingValid : WellKeyed incoming) :
    hasKey (merge table incoming) key ↔ hasKey table key ∨ hasKey incoming key := by
  induction incoming generalizing table with
  | nil => simp [merge, hasKey]
  | cons head tail ih =>
    have headValid := incomingValid head (by simp)
    have tailValid : WellKeyed tail := fun row member => incomingValid row (by simp [member])
    change hasKey (merge (upsertRows table head ["root", "holder"] []) tail) key ↔ _
    rw [ih _ (upsert_valid table head valid headValid) tailValid, upsert_hasKey table head key valid headValid]
    simp [hasKey, or_assoc]

def repairFields (size now : Int64) : List (String × SourceValue) :=
  [("root", .column "root"), ("holder", .column "holder"),
   ("size", .literal (.integer size)), ("prev", .literal .null), ("first_wanted", .literal (.integer now))]

def invalidation : Fields :=
  [("complete", .integer 0), ("durable", .integer 0), ("bitmap", .null), ("inline", .null)]

@[simp] theorem repair_preserves_key (size now : Int64) (row : Fields) :
    keyOf (sourceFields (repairFields size now) row) = keyOf row := by
  simp [keyOf, sourceFields, repairFields, cell]

/-- Persistent state obtained by interpreting UPDATE, COPY and DELETE. This
expression is derived from the actual operation by healing_state below. -/
def healedDatabase (db : Database) (root : ByteArray) (size now : Int64) : Database :=
  let invalidated := setRows db "blobs" ((rows db "blobs").map fun row =>
    if selects ⟨"blobs", [("root", .blob root)], []⟩ row then assign row invalidation else row)
  let copied := copyRows invalidated "content_want" (repairPins root) (repairFields size now) ["root", "holder"]
  setRows copied "pins" ((rows copied "pins").filter fun row => !selects (repairPins root) row)

/-- The whole program operates on the common transaction state. -/
theorem healing_state (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]]) :
    let result := SimulatedHost.run (heal root) state
    result.1 = .ok () ∧ result.2.db = healedDatabase state.db root size state.now := by
  simp [SimulatedHost.run, heal, healIn, transactionOver, requestStorage, requestAccess, requestClock,
    raise, performOver, Inject.inject, execute, Interpreter.handle, storage, access, clock,
    reply, fault, record, SimulatedHost.transaction, quiet, idle, observed,
    decodeSize, integerField, VerifiedCore.Cas.Codec.integerField, repairFields, invalidation,
    healedDatabase, repairPins, Except.mapError, Except.map, bind, pure, Program.bind,
    ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- Copy/delete conserves all responsibilities, including unrelated roots. -/
theorem healed_obligations (db : Database) (root : ByteArray) (size now : Int64)
    (pinsValid : WellKeyed (rows db "pins")) (wantsValid : WellKeyed (rows db "content_want"))
    (key : Key) : obligation (healedDatabase db root size now) key ↔ obligation db key := by
  have copiedValid : WellKeyed (((rows db "pins").filter (selects (repairPins root))).map
      (sourceFields (repairFields size now))) := by
    intro row member
    obtain ⟨pin, pinMember, rfl⟩ := List.mem_map.mp member
    simpa using pinsValid pin (List.mem_filter.mp pinMember).1
  simp only [obligation, healedDatabase, copyRows, repairPins, rows_setRows, rows_setRows_other,
    ne_eq, String.reduceEq, not_false_eq_true]
  have merged := merge_hasKey (rows db "content_want")
    (((rows db "pins").filter (selects (repairPins root))).map (sourceFields (repairFields size now)))
    key wantsValid copiedValid
  simp only [merge, List.foldl_map, repairPins] at merged
  rw [merged]
  simp only [hasKey, List.mem_filter, List.mem_map]
  constructor
  · rintro (⟨row, ⟨member, _⟩, same⟩ | (held | ⟨row, ⟨pin, ⟨member, _⟩, rfl⟩, same⟩))
    · exact Or.inl ⟨row, member, same⟩
    · exact Or.inr held
    · exact Or.inl ⟨pin, member, by simpa using same⟩
  · rintro (⟨pin, member, same⟩ | held)
    · cases selected : selects (repairPins root) pin with
      | false => exact Or.inl ⟨pin, ⟨member, by change (!selects (repairPins root) pin) = true; simp [selected]⟩, same⟩
      | true => exact Or.inr (Or.inr ⟨_, ⟨pin, ⟨member, selected⟩, rfl⟩, by simpa using same⟩)
    · exact Or.inr (Or.inl held)

/-- Losing a copy does not erase the responsibility to keep it. -/
theorem losing_a_copy_preserves_responsibility (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (pinsValid : WellKeyed (rows state.db "pins")) (wantsValid : WellKeyed (rows state.db "content_want")) :
    ∀ key, obligation (SimulatedHost.run (heal root) state).2.db key ↔ obligation state.db key := by
  intro key
  rw [(healing_state state root size quiet idle observed).2]
  exact healed_obligations _ _ _ _ pinsValid wantsValid key



/-- Existing repair records keep all fields, without a key-validity premise. -/
theorem existing_requests_survive_unchanged (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (row : Fields) (present : row ∈ rows state.db "content_want") :
    row ∈ rows (SimulatedHost.run (heal root) state).2.db "content_want" := by
  rw [(healing_state state root size quiet idle observed).2]
  unfold healedDatabase
  rw [rows_setRows_other _ "pins" "content_want" _ (by decide)]
  apply copyRows_preserves_existing
  simpa using present

/-- Every pin outside the actual SQL selection is preserved verbatim. -/
theorem unselected_pins_survive_unchanged (state : State) (root : ByteArray) (size : Int64)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" ["size"] [("root", .blob root)] [] [] = [[.integer size]])
    (row : Fields) (present : row ∈ rows state.db "pins")
    (unselected : selects (repairPins root) row = false) :
    row ∈ rows (SimulatedHost.run (heal root) state).2.db "pins" := by
  rw [(healing_state state root size quiet idle observed).2]
  simp [healedDatabase, copyRows, repairPins] at unselected ⊢
  exact ⟨present, by simpa using unselected⟩

end Synchronicity.CasHealingPromises
