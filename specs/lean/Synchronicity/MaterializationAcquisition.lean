import Synchronicity.MaterializationSql
import Synchronicity.ReconciliationSlots
import Synchronicity.TransactionSuccess

/-! A current reference establishes a live hold or an acquisition request
through the entire actual wants operation, not just its INSERT branch. -/
namespace Synchronicity.MaterializationAcquisition
open VerifiedCore VerifiedCore.Host Replication SimulatedHost MaterializationSql MaterializationRetention
open CasHealingPromises

def pinKey (root : ByteArray) (holder : String) : Fields :=
  [("root", .blob root), ("holder", .text holder)]

theorem key_matches (row : Fields) (root : ByteArray) (holder : String)
    (typed : (keyOf row).isSome = true) :
    equals row (pinKey root holder) = true ↔ keyOf row = some (root, holder) := by
  unfold keyOf at typed ⊢
  cases a : cell row "root" <;> cases b : cell row "holder" <;>
    simp_all [equals, pinKey, isCell, equalCell, BEq.beq, instBEqCell.beq]
  all_goals
    intro _
    change ((_ : ByteArray) == root) = true ↔ (_ : ByteArray) = root
    exact beq_iff_eq

theorem reset_key (row : Fields) : keyOf (assign row [("release_after", .null)]) = keyOf row := by
  unfold keyOf
  rw [ReconciliationSlots.cell_assign_absent row _ "root" (by simp),
    ReconciliationSlots.cell_assign_absent row _ "holder" (by simp)]

def Activated (table : List Fields) (root : ByteArray) (holder : String) : Prop :=
  WellKeyed table ∧ ∀ row ∈ table, keyOf row = some (root, holder) → cell row "release_after" = .null

theorem reset_activates (table : List Fields) (root : ByteArray) (holder : String) (typed : WellKeyed table) :
    Activated (table.map fun row => if equals row (pinKey root holder) then assign row [("release_after", .null)] else row)
      root holder := by
  constructor
  · intro row member
    obtain ⟨prior, priorMember, same⟩ := List.mem_map.mp member
    subst row
    split
    · simpa only [reset_key] using typed prior priorMember
    · exact typed prior priorMember
  · intro row member named
    obtain ⟨prior, priorMember, same⟩ := List.mem_map.mp member
    subst row
    split
    · simp [assign, cell]
    · rename_i absent
      simp only [absent] at named
      exact False.elim (absent ((key_matches prior root holder (typed prior priorMember)).mpr named))

theorem keep_insert_activated (table : List Fields) (root : ByteArray) (holder : String) (now : Int64)
    (active : Activated table root holder) :
    Activated (upsertRows table (pinKey root holder ++ [("created_at", .integer now), ("release_after", .null)])
      ["root", "holder"] []) root holder := by
  rw [upsertRows_doNothing]
  split
  · exact active
  · constructor
    · intro row member
      rcases List.mem_append.mp member with member | member
      · exact active.1 row member
      · have same := List.mem_singleton.mp member
        subst row
        simp [keyOf, pinKey, cell]
    · intro row member named
      rcases List.mem_append.mp member with member | member
      · exact active.2 row member named
      · have same := List.mem_singleton.mp member
        subst row
        simp [pinKey, cell]

theorem reset_retains (db : Database) (root : ByteArray) (holder : String) :
    Retains db (updated db "pins" (pinKey root holder) [("release_after", .null)]) := by
  intro other who requirement
  rcases requirement with ⟨row, member, key, live⟩ | ⟨row, member, key⟩
  · refine Or.inl ⟨if equals row (pinKey root holder) then assign row [("release_after", .null)] else row,
      ?_, ?_, ?_⟩
    · simp only [updated, rows_setRows]
      exact List.mem_map.mpr ⟨row, member, rfl⟩
    · split
      · simpa only [reset_key] using key
      · exact key
    · split
      · simp [assign, cell]
      · exact live
  · refine Or.inr ⟨row, ?_, key⟩
    simpa only [updated, rows_setRows_other _ "pins" "content_want" _ (by decide)] using member

theorem insert_keeps_rows (table : List Fields) (incoming : Fields) (keys : List String) :
    ∀ row ∈ table, row ∈ upsertRows table incoming keys [] := by
  rw [upsertRows_doNothing]
  split
  · exact fun _ h => h
  · exact fun _ h => List.mem_append_left _ h

theorem keep_write_retains (db : Database) (table : String) (key values : Fields) :
    Retains db (written db table key values true) := by
  have keeps (relation : String) : ∀ row ∈ rows db relation, row ∈ rows (written db table key values true) relation := by
    intro row member
    by_cases selected : table = relation
    · subst table
      simp only [written, rows_setRows, ↓reduceIte, List.map_nil]
      exact insert_keeps_rows _ _ _ row member
    · simpa only [written, rows_setRows_other _ _ _ _ selected] using member
  exact rows_retain (keeps "pins") (keeps "content_want")

theorem erase_replaced_request_retains (db : Database) (root : ByteArray) (holder : String)
    (typed : WellKeyed (rows db "content_want"))
    (pin : ∃ row ∈ rows db "pins", keyOf row = some (root, holder) ∧ cell row "release_after" = .null) :
    Retains db (erased db "content_want" (pinKey root holder)) := by
  intro other who requirement
  have pinsSame : rows (erased db "content_want" (pinKey root holder)) "pins" = rows db "pins" := by
    simp only [erased, rows_setRows_other _ "content_want" "pins" _ (by decide)]
  rcases requirement with ⟨row, member, key, live⟩ | ⟨row, member, key⟩
  · exact Or.inl ⟨row, pinsSame ▸ member, key, live⟩
  · by_cases selected : equals row (pinKey root holder) = true
    · have same := (key_matches row root holder (typed row member)).mp selected
      have equal := Option.some.inj (key.symm.trans same)
      cases equal
      obtain ⟨pinRow, pinMember, pinKey, live⟩ := pin
      exact Or.inl ⟨pinRow, pinsSame ▸ pinMember, pinKey, live⟩
    · refine Or.inr ⟨row, ?_, key⟩
      simp only [erased, rows_setRows]
      exact List.mem_filter.mpr ⟨member, by simp [selected]⟩

def durableValue (blobs : List Row) : Materialize.Action Bool :=
  match blobs with
  | [] => pure false
  | [value] :: _ => (fun n => n != 0) <$> Materialize.int value
  | _ => throw (.metadata .malformed)

theorem durable_value_state (blobs : List Row) (state : State) :
    (execute (durableValue blobs) state).2 = state := by
  cases blobs with
  | nil => rfl
  | cons row rest =>
    cases row with
    | nil => rfl
    | cons value tail =>
      cases tail with
      | cons _ _ => rfl
      | nil =>
        cases value <;> rfl

def finishWants (tx : Transaction) (target : Materialize.Target) (file : Records.File)
    (root : ByteArray) (now : Int64) : Materialize.Action Unit := do
  if ← Materialize.raw (.existsRows tx "pins" (pinKey root target.holder)) then
    Materialize.erase tx "content_want" (pinKey root target.holder)
  else
    Materialize.write tx "content_want" (pinKey root target.holder)
      [("size", .integer file.size.toUInt64.toInt64), ("prev", Records.nullable .blob file.prev),
        ("first_wanted", .integer now)] true

def afterDurable (tx : Transaction) (target : Materialize.Target) (file : Records.File)
    (root : ByteArray) (now : Int64) (durable : Bool) : Materialize.Action Unit :=
  if durable then do
    Materialize.write tx "pins" (pinKey root target.holder)
      [("created_at", .integer now), ("release_after", .null)] true
    finishWants tx target file root now
  else finishWants tx target file root now

theorem finish_establishes (tx : Transaction) (target : Materialize.Target)
    (file : Records.File) (root : ByteArray) (now : Int64)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (active : Activated (rows db "pins") root target.holder) (wanted : WellKeyed (rows db "content_want"))
    (ran : execute (finishWants tx target file root now) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Required after root target.holder ∧ Retains db after := by
  unfold finishWants at ran
  obtain ⟨hasPin, checked, checkedRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  have ⟨hasPinValue, checkedState⟩ := exists_state tx "pins" (pinKey root target.holder)
    state checked db hasPin opened checkedRun
  have checkedTx : checked.pending = some (tx, db) := by rw [checkedState]; exact opened
  cases hasPin with
  | true =>
    have deleted := erase_state tx "content_want" (pinKey root target.holder) checked final db checkedTx rest
    obtain ⟨row, member, matched⟩ := List.any_eq_true.mp hasPinValue.symm
    have key := (key_matches row root target.holder (active.1 row member)).mp matched
    have live : ∃ row ∈ rows db "pins", keyOf row = some (root, target.holder) ∧ cell row "release_after" = .null :=
      ⟨row, member, key, active.2 row member key⟩
    refine ⟨erased db "content_want" (pinKey root target.holder), ?_, Or.inl ?_,
      erase_replaced_request_retains db root target.holder wanted live⟩
    · rw [deleted]; rfl
    · exact ⟨row, by simpa only [erased, rows_setRows_other _ "content_want" "pins" _ (by decide)] using member,
        key, active.2 row member key⟩
  | false =>
    obtain ⟨after, finalTx, required, _⟩ := request_establishes_requirement tx target file root now
      checked final db checkedTx wanted rest
    have changed := write_state tx "content_want" (pinKey root target.holder)
      [("size", .integer file.size.toUInt64.toInt64), ("prev", Records.nullable .blob file.prev),
        ("first_wanted", .integer now)] true checked final db checkedTx rest
    have afterSame : after = written db "content_want" (pinKey root target.holder)
        [("size", .integer file.size.toUInt64.toInt64), ("prev", Records.nullable .blob file.prev),
          ("first_wanted", .integer now)] true := by
      rw [changed] at finalTx
      exact (congrArg Prod.snd (Option.some.inj finalTx)).symm
    refine ⟨after, finalTx, required, ?_⟩
    rw [afterSame]
    exact keep_write_retains db "content_want" (pinKey root target.holder) _

theorem wants_establishes_requirement (tx : Transaction) (target : Materialize.Target)
    (file : Records.File) (root : ByteArray) (now : Int64)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (pinsTyped : WellKeyed (rows db "pins")) (wantsTyped : WellKeyed (rows db "content_want"))
    (ran : execute (Materialize.wants tx target file root now) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Required after root target.holder ∧ Retains db after := by
  unfold Materialize.wants at ran
  obtain ⟨_, activated, activatedRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  have activatedState := update_state tx "pins" (pinKey root target.holder) [("release_after", .null)]
    state activated db opened activatedRun
  let activatedDb := updated db "pins" (pinKey root target.holder) [("release_after", .null)]
  have activatedTx : activated.pending = some (tx, activatedDb) := by rw [activatedState]; rfl
  have active : Activated (rows activatedDb "pins") root target.holder := by
    simpa only [activatedDb, updated, rows_setRows] using reset_activates _ root target.holder pinsTyped
  have wanted : WellKeyed (rows activatedDb "content_want") := by
    simpa only [activatedDb, updated, rows_setRows_other _ "pins" "content_want" _ (by decide)] using wantsTyped
  obtain ⟨blobs, read, readRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
  have readState := (read_state tx "blobs" ["durable"] [("root", .blob root)] activated read activatedDb blobs
    activatedTx readRun).2
  have sequence : execute (durableValue blobs >>= afterDurable tx target file root now : Materialize.Action Unit)
      read = (.ok (), final) := by
    cases blobs with
    | nil => exact rest
    | cons row tail =>
      cases row with
      | nil => exact rest
      | cons value more => cases more <;> exact rest
  obtain ⟨durable, decoded, decodedRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ sequence
  have decodedState : decoded = read := by
    have preserved := durable_value_state blobs read
    exact (congrArg Prod.snd decodedRun).symm.trans preserved
  have decodedTx : decoded.pending = some (tx, activatedDb) := by rw [decodedState, readState]; exact activatedTx
  have resetSafe : Retains db activatedDb := reset_retains db root target.holder
  cases durable with
  | false =>
      obtain ⟨after, afterTx, required, safe⟩ :=
        finish_establishes tx target file root now decoded final activatedDb decodedTx active wanted rest
      exact ⟨after, afterTx, required, resetSafe.trans safe⟩
  | true =>
      obtain ⟨_, pinned, pinnedRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
      have pinState := write_state tx "pins" (pinKey root target.holder)
        [("created_at", .integer now), ("release_after", .null)] true decoded pinned activatedDb decodedTx pinnedRun
      let pinDb := written activatedDb "pins" (pinKey root target.holder)
        [("created_at", .integer now), ("release_after", .null)] true
      have pinTx : pinned.pending = some (tx, pinDb) := by rw [pinState]; rfl
      have pinActive : Activated (rows pinDb "pins") root target.holder := by
        simpa only [pinDb, written, rows_setRows, pinKey, List.map_cons, List.map_nil, ↓reduceIte] using
          keep_insert_activated _ root target.holder now active
      have wanted : WellKeyed (rows pinDb "content_want") := by
        simpa only [pinDb, written, rows_setRows_other _ "pins" "content_want" _ (by decide)] using wanted
      obtain ⟨after, afterTx, required, safe⟩ :=
        finish_establishes tx target file root now pinned final pinDb pinTx pinActive wanted rest
      exact ⟨after, afterTx, required,
        resetSafe.trans ((keep_write_retains activatedDb "pins" (pinKey root target.holder) _).trans safe)⟩

end Synchronicity.MaterializationAcquisition
