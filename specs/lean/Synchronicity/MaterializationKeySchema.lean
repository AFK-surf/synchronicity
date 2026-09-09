import Synchronicity.MaterializationRelease

/-! Root/holder typing is preserved by actual retention updates. Repeated
callbacks therefore need only an initial raw-schema contract, not an assumption
that every future acquisition happens to read well-keyed tables. -/
namespace Synchronicity.MaterializationKeySchema
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase CasHealingPromises

def Schema (db : Database) := WellKeyed (rows db "pins") ∧ WellKeyed (rows db "content_want")
def Keyed (tx : Transaction) (state : State) := ∃ db, state.pending = some (tx, db) ∧ Schema db
def Keeps (tx : Transaction) (A : Type) (effect : Materialize.Effects A) : Prop :=
  ∀ state, Keyed tx state → Keyed tx (Interpreter.handle effect state).2

theorem readonly_keeps (tx : Transaction) (effect : Materialize.Effects A)
    (safe : PromotionReads.materializeRead _ effect) : Keeps tx _ effect := by
  intro state initial
  obtain ⟨db, opened, typed⟩ := initial
  exact ⟨db, (PromotionReads.materialize_pending effect safe state).trans opened, typed⟩

theorem assigned_key (row values : Fields)
    (root : ∀ field ∈ values, field.1 ≠ "root") (holder : ∀ field ∈ values, field.1 ≠ "holder") :
    keyOf (assign row values) = keyOf row := by
  unfold keyOf
  rw [ReconciliationSlots.cell_assign_absent row values "root" root,
    ReconciliationSlots.cell_assign_absent row values "holder" holder]

theorem set_schema (db : Database) (table : String) (updated : List Fields) (initial : Schema db)
    (typed : (table = "pins" ∨ table = "content_want") → WellKeyed updated) : Schema (setRows db table updated) := by
  constructor
  · by_cases same : table = "pins"
    · subst table; exact (rows_setRows db "pins" updated) ▸ typed (Or.inl rfl)
    · simpa only [rows_setRows_other _ _ _ _ same] using initial.1
  · by_cases same : table = "content_want"
    · subst table; exact (rows_setRows db "content_want" updated) ▸ typed (Or.inr rfl)
    · simpa only [rows_setRows_other _ _ _ _ same] using initial.2

theorem schema_table (db : Database) (table : String) (schema : Schema db)
    (relevant : table = "pins" ∨ table = "content_want") : WellKeyed (rows db table) := by
  rcases relevant with rfl | rfl
  · exact schema.1
  · exact schema.2

theorem write_keeps (tx : Transaction) (table : String) (key values : Fields) (preserve : Bool)
    (safe : (table = "pins" ∨ table = "content_want") →
      preserve = true ∧ (keyOf (key ++ values)).isSome = true) :
    Only (Keeps tx) (Materialize.write tx table key values preserve).run := by
  apply Only.raise _ _
  intro state initial
  obtain ⟨db, opened, typed⟩ := initial
  simp only [Inject.inject, Interpreter.handle, storage, reply]
  cases failed : fault state with
  | some failure => exact ⟨db, opened, typed⟩
  | none =>
    simp only [SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte]
    refine ⟨_, rfl, set_schema db table _ typed ?_⟩
    intro relevant
    obtain ⟨rfl, incoming⟩ := safe relevant
    simp only [↓reduceIte, List.map_nil, upsertRows_doNothing]
    split
    · exact schema_table db table typed relevant
    · intro row member
      rcases List.mem_append.mp member with old | new
      · exact schema_table db table typed relevant row old
      · have same := List.mem_singleton.mp new
        subst row
        exact incoming

theorem erase_keeps (tx : Transaction) (table : String) (key : Fields) :
    Only (Keeps tx) (Materialize.erase tx table key).run := by
  apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
  intro state initial
  obtain ⟨db, opened, typed⟩ := initial
  simp only [Inject.inject, Interpreter.handle, storage, reply]
  cases failed : fault state with
  | some failure => exact ⟨db, opened, typed⟩
  | none =>
    simp only [SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte]
    refine ⟨_, rfl, set_schema db table _ typed ?_⟩
    intro relevant row member
    exact schema_table db table typed relevant row (List.mem_filter.mp member).1

theorem update_keeps (tx : Transaction) (table : String) (key values : Fields)
    (safe : (table = "pins" ∨ table = "content_want") →
      (∀ field ∈ values, field.1 ≠ "root") ∧ (∀ field ∈ values, field.1 ≠ "holder")) :
    Only (Keeps tx) (Materialize.update tx table key values).run := by
  apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
  intro state initial
  obtain ⟨db, opened, typed⟩ := initial
  simp only [Inject.inject, Interpreter.handle, access, reply]
  cases failed : fault state with
  | some failure => exact ⟨db, opened, typed⟩
  | none =>
    simp only [SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte]
    refine ⟨_, rfl, set_schema db table _ typed ?_⟩
    intro relevant row member
    obtain ⟨old, inTable, same⟩ := List.mem_map.mp member
    subst row
    split
    · rw [assigned_key old values (safe relevant).1 (safe relevant).2]
      exact schema_table db table typed relevant old inTable
    · exact schema_table db table typed relevant old inTable

theorem config_keeps (tx : Transaction) (key : String) :
    Only (Keeps tx) (Materialize.auth (Authorization.config tx key)).run := by
  have safe : Only PromotionReads.materializeRead (Materialize.auth (Authorization.config tx key)).run := by
    unfold Materialize.auth
    apply Only.within _ _ (ReconciliationReadOnly.config_only tx key)
    intro B effect good
    cases effect with
    | left effect => cases effect <;> first | contradiction | trivial
    | right _ => trivial
  exact safe.mono (fun effect good => readonly_keeps tx effect good)

theorem raw_keeps (tx : Transaction) (effect : Storage (Reply A))
    (safe : ReconciliationReadOnly.storageAllowed effect) : Only (Keeps tx) (Materialize.raw effect).run :=
  Only.raise _ _ (readonly_keeps tx _ safe)

theorem pure_keeps (tx : Transaction) (result : Except Materialize.Error A) :
    Only (Keeps tx) (ExceptT.mk (Program.pure result)).run := .done _

theorem current_keeps (tx : Transaction) (key : Fields) : Only (Keeps tx) (Materialize.current tx key).run := by
  unfold Materialize.current
  refine Only.seq (raw_keeps tx _ trivial) fun result => ?_
  repeat' first
    | exact .done _
    | exact Only.map _ _ (pure_keeps tx _)
    | (unfold Materialize.rootField; split)
    | split

theorem wants_keeps (tx : Transaction) (target : Materialize.Target) (file : Records.File) (root : ByteArray) (now : Int64) :
    Only (Keeps tx) (Materialize.wants tx target file root now).run := by
  unfold Materialize.wants
  repeat' first
    | exact .done _
    | exact erase_keeps tx _ _
    | (apply write_keeps; intro _; simp [keyOf, cell])
    | (refine Only.seq (update_keeps tx _ _ _ (by intro _; simp)) fun _ => ?_)
    | (refine Only.seq (write_keeps tx _ _ _ _ (by intro _; simp [keyOf, cell])) fun _ => ?_)
    | (refine Only.seq (raw_keeps tx _ trivial) fun _ => ?_)
    | (refine Only.seq (pure_keeps tx _) fun _ => ?_)
    | (refine Only.seq (Only.map _ _ (pure_keeps tx _)) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem release_keeps (tx : Transaction) (target : Materialize.Target) (root : ByteArray) (now : Int64) :
    Only (Keeps tx) (Materialize.release tx target root now).run := by
  unfold Materialize.release
  repeat' first
    | exact .done _
    | (apply update_keeps; intro _; simp)
    | (refine Only.seq (raw_keeps tx _ trivial) fun _ => ?_)
    | (refine Only.seq (config_keeps tx _) fun _ => ?_)
    | (refine Only.seq (erase_keeps tx _ _) fun _ => ?_)
    | (refine Only.seq (Only.foldlM _ _ ?_ _) fun _ => ?_)
    | (intro count fields)
    | (refine Only.seq (pure_keeps tx _) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem apply_keeps (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (key : ByteArray) (kind : UInt64) (value : Option ByteArray) :
    Only (Keeps tx) (Materialize.apply tx origin now releaseNow replicas key kind value).run := by
  unfold Materialize.apply
  repeat' first
    | exact .done _
    | exact release_keeps tx ..
    | (apply update_keeps; simp)
    | exact erase_keeps tx _ _
    | (apply write_keeps; simp)
    | (refine Only.seq (current_keeps tx _) fun _ => ?_)
    | (refine Only.seq (write_keeps tx _ _ _ _ (by simp)) fun _ => ?_)
    | (refine Only.seq (wants_keeps tx ..) fun _ => ?_)
    | (refine Only.seq (erase_keeps tx _ _) fun _ => ?_)
    | (refine Only.seq (Only.raise _ _ (readonly_keeps tx _ trivial)) fun _ => ?_)
    | (refine Only.seq (pure_keeps tx _) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem executed_keeps (tx : Transaction) (operation : Materialize.Action A) (safe : Only (Keeps tx) operation.run)
    (state : State) (initial : Keyed tx state) : Keyed tx (execute operation state).2 :=
  safe.invariant (Keyed tx) (fun _ good => good) state initial

end Synchronicity.MaterializationKeySchema
