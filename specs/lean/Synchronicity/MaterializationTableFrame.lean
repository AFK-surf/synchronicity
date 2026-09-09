import Synchronicity.MaterializationRelease

/-! Retention effects cannot alter the file/provider/delegation projection
they accompany. This frame also keeps the trie metadata underlying the stream. -/
namespace Synchronicity.MaterializationTableFrame
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase

def view (relation : String) (state : State) : Option (Transaction × List Fields) :=
  state.pending.map fun (tx, db) => (tx, rows db relation)

def storageAllowed (relation : String) : Storage A → Prop
  | .begin | .commit _ | .rollback _ | .removeFile _ _ => False
  | .upsert _ target _ _ _ | .deleteRows _ target _ _ _ | .deleteExcept _ target _ _ => target ≠ relation
  | _ => True

def accessAllowed (relation : String) : Access A → Prop
  | .update _ selection _ | .delete _ selection => selection.relation ≠ relation
  | .copyRows _ target _ _ _ => target ≠ relation
  | _ => True

def allowed (relation : String) (A : Type) : Materialize.Effects A → Prop
  | .left e => storageAllowed relation e
  | .right (.right (.left e)) => accessAllowed relation e
  | _ => True

theorem reply_frame (relation : String) (state : State) (event : String) (action : State → Result (Reply A))
    (consume : Bool) (kept : ∀ s, view relation (action s).2 = view relation s) :
    view relation (reply state event action consume).2 = view relation state := by
  unfold reply
  split
  · cases consume
    · rfl
    · simpa only [view, record, ↓reduceIte] using kept state
  · simpa only [view, record] using kept state

theorem transaction_frame (relation : String) (state : State) (tx : Transaction) (action : Database → A × Database)
    (kept : ∀ db, rows (action db).2 relation = rows db relation) :
    view relation (SimulatedHost.transaction state tx action).2 = view relation state := by
  unfold SimulatedHost.transaction
  split
  · rename_i token db pending
    split
    · simp [view, pending, kept]
    · rfl
  · rfl

theorem storage_frame (relation : String) (effect : Storage A) (safe : storageAllowed relation effect) (state : State) :
    view relation (storage effect state).2 = view relation state := by
  cases effect <;> simp only [storage]
  all_goals first | contradiction | (apply reply_frame; intro s)
  all_goals first
    | (apply transaction_frame; intro db; first | rfl | exact rows_setRows_other _ _ _ _ safe)
    | rfl
    | (repeat' first | split | rfl)

theorem effects_frame (relation : String) (effect : Materialize.Effects A) (safe : allowed relation _ effect) (state : State) :
    view relation (Interpreter.handle effect state).2 = view relation state := by
  cases effect with
  | left effect => exact storage_frame relation effect safe state
  | right effect =>
    rcases effect with effect | effect
    · cases effect <;> apply reply_frame <;> intro s <;> rfl
    · rcases effect with effect | effect
      · cases effect <;> simp only [Interpreter.handle, access]
        all_goals apply reply_frame; intro s
        all_goals first
          | rfl
          | (apply transaction_frame; intro db; first
              | exact rows_setRows_other _ _ _ _ safe
              | exact rows_setRows_other _ _ _ _ safe)
      · rcases effect with effect | effect
        · cases effect; apply reply_frame; intro s; rfl
        · rcases effect with effect | effect
          · cases effect; apply reply_frame; intro s; rfl
          · rcases effect with effect | effect
            · cases effect; apply reply_frame; intro s; rfl
            · cases effect; apply reply_frame; intro s; rfl

abbrev Safe (relation : String) (operation : Materialize.Action A) := Only (allowed relation) operation.run

theorem config_safe (relation : String) (tx : Transaction) (key : String) :
    Safe relation (Materialize.auth (Authorization.config tx key)) := by
  unfold Materialize.auth
  have safe : Only (fun B (effect : Authorization.Effects B) =>
      allowed relation B (Inject.inject effect : Materialize.Effects B)) (Authorization.config tx key).run := by
    unfold Authorization.config
    refine Only.seq (Only.raise _ _ trivial) fun result => ?_
    repeat' first
      | exact .done _
      | (refine Only.seq ?_ fun _ => .done _)
      | (unfold Authorization.checked; split)
      | split
  exact Only.within _ _ safe (fun _ good => good)

theorem raw_safe (relation : String) (effect : Storage (Reply A)) (safe : storageAllowed relation effect) :
    Safe relation (Materialize.raw effect) := Only.raise _ _ safe

theorem pure_safe (relation : String) (result : Except Materialize.Error A) :
    Safe relation (ExceptT.mk (Program.pure result)) := .done _

theorem write_safe (relation : String) (tx : Transaction) (table : String) (key values : Fields) (preserve : Bool)
    (different : table ≠ relation) : Safe relation (Materialize.write tx table key values preserve) :=
  raw_safe relation _ different

theorem current_safe (relation : String) (tx : Transaction) (fields : Fields) :
    Safe relation (Materialize.current tx fields) := by
  unfold Materialize.current
  refine Only.seq (raw_safe relation _ trivial) fun result => ?_
  repeat' first
    | exact .done _
    | exact Only.map _ _ (pure_safe relation _)
    | (unfold Materialize.rootField; split)
    | split

theorem erase_safe (relation : String) (tx : Transaction) (table : String) (key : Fields)
    (different : table ≠ relation) : Safe relation (Materialize.erase tx table key) :=
  (raw_safe relation (.deleteRows tx table key) different).seq fun _ => .done _

theorem update_safe (relation : String) (tx : Transaction) (table : String) (key values : Fields)
    (different : table ≠ relation) : Safe relation (Materialize.update tx table key values) :=
  (Only.raise _ _ different).seq fun _ => .done _

theorem wants_safe (relation : String) (pins : "pins" ≠ relation) (wants : "content_want" ≠ relation)
    (tx : Transaction) (target : Materialize.Target) (file : Records.File) (root : ByteArray) (now : Int64) :
    Safe relation (Materialize.wants tx target file root now) := by
  unfold Materialize.wants
  repeat' first
    | exact .done _
    | exact write_safe relation _ _ _ _ _ pins
    | exact write_safe relation _ _ _ _ _ wants
    | exact erase_safe relation _ _ _ wants
    | (refine Only.seq (update_safe relation _ _ _ _ pins) fun _ => ?_)
    | (refine Only.seq (raw_safe relation _ trivial) fun _ => ?_)
    | (refine Only.seq (write_safe relation _ _ _ _ _ pins) fun _ => ?_)
    | (refine Only.seq (pure_safe relation _) fun _ => ?_)
    | (refine Only.seq (Only.map _ _ (pure_safe relation _)) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem release_safe (relation : String) (pins : "pins" ≠ relation) (wants : "content_want" ≠ relation)
    (tx : Transaction) (target : Materialize.Target) (root : ByteArray) (now : Int64) :
    Safe relation (Materialize.release tx target root now) := by
  unfold Materialize.release
  repeat' first
    | exact .done _
    | exact update_safe relation _ _ _ _ pins
    | (refine Only.seq (raw_safe relation _ trivial) fun _ => ?_)
    | (refine Only.seq (config_safe relation _ _) fun _ => ?_)
    | (refine Only.seq (erase_safe relation _ _ _ wants) fun _ => ?_)
    | (refine Only.seq (Only.foldlM _ _ ?_ _) fun _ => ?_)
    | (intro count row)
    | (refine Only.seq (pure_safe relation _) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem apply_safe (relation : String)
    (different : ∀ table ∈ ["entries", "blob_providers", "bindings", "pins", "content_want"], table ≠ relation)
    (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (key : ByteArray) (kind : UInt64) (value : Option ByteArray) :
    Safe relation (Materialize.apply tx origin now releaseNow replicas key kind value) := by
  have pins := different "pins" (by simp)
  have wants := different "content_want" (by simp)
  unfold Materialize.apply
  repeat' first
    | exact .done _
    | exact release_safe relation pins wants ..
    | (apply update_safe; exact different _ (by simp))
    | (apply erase_safe; exact different _ (by simp))
    | (apply write_safe; exact different _ (by simp))
    | (refine Only.seq (current_safe relation ..) fun _ => ?_)
    | (refine Only.seq (write_safe relation _ _ _ _ _ (different _ (by simp))) fun _ => ?_)
    | (refine Only.seq (wants_safe relation pins wants ..) fun _ => ?_)
    | (refine Only.seq (erase_safe relation _ _ _ (different _ (by simp))) fun _ => ?_)
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | (refine Only.seq (pure_safe relation _) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem nonfile_table_safe (relation : String) (providers : "blob_providers" ≠ relation) (bindings : "bindings" ≠ relation)
    (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (key : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (tag : key[0]? ≠ some 102) : Safe relation (Materialize.apply tx origin now releaseNow replicas key kind value) := by
  have different : (key[0]? == some 102) = false := beq_eq_false_iff_ne.mpr tag
  simp only [Materialize.apply, different, Bool.false_eq_true, ↓reduceIte]
  repeat' first
    | exact .done _
    | (apply update_safe; exact bindings)
    | (apply erase_safe; first | exact providers | exact bindings)
    | (apply write_safe; first | exact providers | exact bindings)
    | (refine Only.seq (write_safe relation _ _ _ _ _ bindings) fun _ => ?_)
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | (refine Only.seq (pure_safe relation _) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem nonfile_safe (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (key : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (tag : key[0]? ≠ some 102) : Safe "entries" (Materialize.apply tx origin now releaseNow replicas key kind value) :=
  nonfile_table_safe "entries" (by decide) (by decide) tx origin now releaseNow replicas key kind value tag

theorem executed_frame (relation : String) (operation : Materialize.Action A) (safe : Safe relation operation)
    (state final : State) (result : Except Materialize.Error A)
    (ran : execute operation state = (result, final)) : view relation final = view relation state := by
  have kept := safe.preserves_observation (view relation) operation.run (effects_frame relation) state
  change view relation (execute operation state).2 = view relation state at kept
  simpa only [ran] using kept

theorem frame_opened (relation : String) (operation : Materialize.Action A) (safe : Safe relation operation)
    (state final : State) (result : Except Materialize.Error A) (tx : Transaction) (db : Database)
    (opened : state.pending = some (tx, db))
    (ran : execute operation state = (result, final)) :
    ∃ after, final.pending = some (tx, after) ∧ rows after relation = rows db relation := by
  have same := executed_frame relation operation safe state final result ran
  simp only [view, opened, Option.map_some] at same
  cases pending : final.pending with
  | none => simp [pending] at same
  | some entry =>
    rcases entry with ⟨token, after⟩
    simp only [pending, Option.map_some, Option.some.injEq, Prod.mk.injEq] at same
    exact ⟨after, by rw [same.1], same.2⟩

end Synchronicity.MaterializationTableFrame
