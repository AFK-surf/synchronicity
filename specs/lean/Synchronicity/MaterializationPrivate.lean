import VerifiedCore.Replication.Materialize
import Synchronicity.ReconciliationFrame

/-! Materialization must never publish its intermediate rows. Its callers own
the transaction containing the version pointer and all derived obligations. -/
namespace Synchronicity.MaterializationPrivate
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase

def storageFrame : Storage A → Prop := ReconciliationFrame.storageAllowed

def accessFrame : Access A → Prop
  | .update _ selection _ | .delete _ selection => selection.relation ≠ "heads"
  | .copyRows _ target _ _ _ => target ≠ "heads"
  | _ => True

def allowed : (A : Type) → Materialize.Effects A → Prop
  | _, .left e => storageFrame e
  | _, .right (.right (.left e)) => accessFrame e
  | _, .right _ => True

theorem effects_preserve_db (effect : Materialize.Effects A) (safe : allowed _ effect) (state : State) :
    (Interpreter.handle effect state).2.db = state.db := by
  cases effect with
  | left storage =>
    apply storage_preserves_db storage _ state
    cases storage <;> first | contradiction | trivial
  | right effect =>
    rcases effect with effect | effect
    · cases effect <;> apply reply_preserves_db <;> intro s <;> rfl
    · rcases effect with effect | effect
      · cases effect <;> apply reply_preserves_db <;> intro s
        all_goals first | exact transaction_preserves_db _ _ _ | rfl
      · rcases effect with effect | effect
        · cases effect; apply reply_preserves_db; intro s; rfl
        · rcases effect with effect | effect
          · cases effect; apply reply_preserves_db; intro s; rfl
          · rcases effect with effect | effect
            · cases effect; apply reply_preserves_db; intro s; rfl
            · cases effect; apply reply_preserves_db; intro s; rfl

abbrev Private (operation : Materialize.Action A) := Only allowed operation.run

theorem pure_private (result : Except Materialize.Error A) :
    Private (ExceptT.mk (Program.pure result)) := .done _

theorem raw_private (effect : Storage (Reply A)) (safe : storageFrame effect) :
    Private (Materialize.raw effect) := Only.raise _ _ safe

def authAllowed : (A : Type) → Authorization.Effects A → Prop
  | _, .left e => storageFrame e
  | _, .right _ => True

theorem auth_private (operation : Authorization.Action A) (safe : Only authAllowed operation.run) :
    Private (Materialize.auth operation) := by
  apply Only.within operation Materialize.authError safe
  intro B effect good
  cases effect <;> exact good

theorem config_private (tx : Transaction) (key : String) :
    Only authAllowed (Authorization.config tx key).run := by
  unfold Authorization.config
  refine Only.seq (Only.raise _ _ trivial) fun rows => ?_
  repeat' first
    | exact .done _
    | (refine Only.seq ?_ fun _ => .done _)
    | (unfold Authorization.checked; split)
    | split

theorem targets_private (tx : Transaction) : Private (Materialize.targets tx) := by
  unfold Materialize.targets
  refine Only.seq (auth_private _ (config_private _ _)) fun floor => ?_
  refine Only.seq (raw_private _ trivial) fun rows => ?_
  apply Only.mapM
  intro row
  repeat' first
    | exact .done _
    | (refine Only.seq (pure_private _) fun _ => ?_)
    | split

theorem current_private (tx : Transaction) (fields : Fields) : Private (Materialize.current tx fields) := by
  unfold Materialize.current
  refine Only.seq (raw_private _ trivial) fun rows => ?_
  repeat' first
    | exact .done _
    | exact Only.map _ _ (pure_private _)
    | (unfold Materialize.rootField; split)
    | split

theorem write_private (tx : Transaction) (table : String) (key values : Fields) (preserve : Bool)
    (different : table ≠ "heads") :
    Private (Materialize.write tx table key values preserve) := raw_private _ different

theorem erase_private (tx : Transaction) (table : String) (key : Fields) (different : table ≠ "heads") :
    Private (Materialize.erase tx table key) :=
  (raw_private (.deleteRows tx table key) different).seq fun _ => .done _

theorem update_private (tx : Transaction) (table : String) (key values : Fields) (different : table ≠ "heads") :
    Private (Materialize.update tx table key values) := (Only.raise _ _ different).seq fun _ => .done _

theorem wants_private (tx : Transaction) (target : Materialize.Target) (file : Replication.Records.File)
    (root : ByteArray) (now : Int64) : Private (Materialize.wants tx target file root now) := by
  unfold Materialize.wants
  repeat' first
    | exact .done _
    | (apply write_private; decide)
    | (apply erase_private; decide)
    | (refine Only.seq (update_private _ _ _ _ (by decide)) fun _ => ?_)
    | (refine Only.seq (raw_private _ trivial) fun _ => ?_)
    | (refine Only.seq (write_private _ _ _ _ _ (by decide)) fun _ => ?_)
    | (refine Only.seq (pure_private _) fun _ => ?_)
    | (refine Only.seq (Only.map _ _ (pure_private _)) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem release_private (tx : Transaction) (target : Materialize.Target) (root : ByteArray) (now : Int64) :
    Private (Materialize.release tx target root now) := by
  unfold Materialize.release
  repeat' first
    | exact .done _
    | (apply update_private; decide)
    | (refine Only.seq (raw_private _ trivial) fun _ => ?_)
    | (refine Only.seq (auth_private _ (config_private _ _)) fun _ => ?_)
    | (refine Only.seq (erase_private _ _ _ (by decide)) fun _ => ?_)
    | (refine Only.seq (Only.foldlM _ _ ?_ _) fun _ => ?_)
    | (intro count row)
    | (refine Only.seq (pure_private _) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem apply_private (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (key : ByteArray) (kind : UInt64) (value : Option ByteArray) :
    Private (Materialize.apply tx origin now releaseNow replicas key kind value) := by
  unfold Materialize.apply
  repeat' first
    | exact .done _
    | exact release_private ..
    | (apply update_private; decide)
    | (apply erase_private; decide)
    | (apply write_private; decide)
    | (refine Only.seq (current_private ..) fun _ => ?_)
    | (refine Only.seq (write_private _ _ _ _ _ (by decide)) fun _ => ?_)
    | (refine Only.seq (wants_private ..) fun _ => ?_)
    | (refine Only.seq (erase_private _ _ _ (by decide)) fun _ => ?_)
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | (refine Only.seq (pure_private _) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem origin_field_private (column text : String) :
    Only authAllowed (Authorization.originField column text).run := by
  unfold Authorization.originField
  refine Only.seq ?_ fun result => ?_
  · unfold Origin.parse
    repeat' first
      | exact .done _
      | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
      | split
  · cases result <;> exact .done _

theorem scope_private (tx : Transaction) (origin : Origin.Parsed) :
    Only authAllowed (Authorization.materializationScopeIn tx origin).run := by
  unfold Authorization.materializationScopeIn Authorization.ownOrigin
  refine Only.seq ?_ fun own => ?_
  · refine Only.seq (config_private _ _) fun own => ?_
    cases own with
    | none => exact .done _
    | some text =>
      exact Only.seq (origin_field_private _ text) fun _ => .done _
  · split
    · exact .done _
    · unfold Authorization.localSpacesIn
      exact Only.seq (Only.seq (config_private _ _) fun _ => .done _) fun _ => .done _

def diffAllowed : (A : Type) → Trie.Diff.Effects A → Prop
  | _, .left e => storageFrame e
  | _, .right _ => True

open Trie.Walk in
theorem cursor_private (root : Option ByteArray) :
    Only diffAllowed (cursorAt (E := Trie.Diff.Effects) root).run := by
  unfold cursorAt
  repeat' first
    | exact .done _
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | split

open Trie.Walk in
theorem child_private (cursor : Cursor) (nibble : UInt8) :
    Only diffAllowed (cursorChild (E := Trie.Diff.Effects) cursor nibble).run := by
  unfold cursorChild
  repeat' first | exact .done _ | exact cursor_private _ | split

open Trie.Walk Trie.Diff in
theorem enter_private (a b : Cursor) (path : Path) :
    Only diffAllowed (enter (E := Trie.Diff.Effects) a b path).run := by
  unfold enter
  repeat' first
    | exact .done _
    | exact Only.raise _ _ trivial
    | (refine Only.seq ?_ fun _ => ?_)
    | (unfold sameValue; split)
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | (dsimp only; split)
    | split

open Trie.Walk in
theorem walk_private (next : T → UInt8 → Option UInt8)
    (step : A → T → UInt8 → Path → OperationOver Trie.Diff.Effects Error (Step T × A))
    (safe : ∀ acc frame nibble path, Only diffAllowed (step acc frame nibble path).run)
    (start : T) (base : Path) (acc : A) :
    Only diffAllowed (walk next step start base acc).run := by
  apply Only.iterate
  intro state
  unfold descend
  repeat' first
    | exact .done _
    | (refine Only.seq (safe ..) fun result => ?_)
    | (dsimp only; split)
    | split

open Trie.Walk Trie.Diff in
theorem diff_each_private (scope : Trie.Serve.Scope)
    (emit : A → Change → OperationOver Trie.Diff.Effects Error A)
    (safe : ∀ acc change, Only diffAllowed (emit acc change).run)
    (oldRoot newRoot : ByteArray) (acc : A) :
    Only diffAllowed (diffEach scope emit oldRoot newRoot acc).run := by
  unfold diffEach
  repeat' first
    | exact .done _
    | exact safe ..
    | (refine Only.seq (cursor_private _) fun _ => ?_)
    | (refine Only.seq (child_private ..) fun _ => ?_)
    | (refine Only.seq (enter_private ..) fun _ => ?_)
    | (refine Only.seq (safe ..) fun _ => ?_)
    | (apply walk_private; intro count pair nibble below)
    | (refine Only.seq ?_ fun _ => ?_)
    | (dsimp only; split)
    | split

theorem diff_materialize_private (scope : Trie.Serve.Scope) (oldRoot newRoot : ByteArray) :
    Only diffAllowed (Trie.Diff.materialize (E := Trie.Diff.Effects) scope oldRoot newRoot).run := by
  apply diff_each_private
  intro count change
  have resolved (value : Trie.Value) :
      Only diffAllowed (Trie.Walk.resolve (E := Trie.Diff.Effects) value).run := by
    unfold Trie.Walk.resolve
    repeat' first
      | exact .done _
      | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
      | split
  cases change.new <;>
    repeat' first
      | exact .done _
      | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
      | (refine Only.seq (Only.map _ _ (resolved _)) fun _ => ?_)
      | (refine Only.seq (.done _) fun _ => ?_)

theorem run_diff_private (tx : Transaction)
    (emit : ByteArray → UInt64 → Option ByteArray → Materialize.Action Unit)
    (safeEmit : ∀ key kind value, Private (emit key kind value))
    (program : Program Trie.Diff.Effects (Except Trie.Walk.Error A))
    (safe : Only diffAllowed program) : Private (Materialize.runDiff tx emit program) := by
  induction safe with
  | done result => exact .done _
  | @request B effect next good rest ih =>
    cases effect with
    | left e => exact Only.seq (.request good fun _ => .done _) fun reply => ih reply
    | right e =>
      rcases e with e | e
      · cases e
        exact Only.seq (.request trivial fun _ => .done _) fun reply => ih reply
      · rcases e with e | e
        · exact Only.seq (.request trivial fun _ => .done _) fun reply => ih reply
        · cases e with
          | applyChange key kind value => exact (safeEmit key kind value).seq fun _ => ih (.ok ())

theorem materialize_private (tx : Transaction) (origin : Origin.Parsed) (oldRoot newRoot : ByteArray) :
    Private (Materialize.materialize tx origin oldRoot newRoot) := by
  unfold Materialize.materialize Materialize.materializeIn
  refine Only.seq (auth_private _ (scope_private _ _)) fun scope => ?_
  refine Only.seq (Only.raise _ _ trivial) fun now => ?_
  refine Only.seq (targets_private _) fun replicas => ?_
  refine Only.seq (auth_private _ (config_private _ _)) fun floor => ?_
  refine Only.seq (Only.raise _ _ trivial) fun releaseNow => ?_
  exact run_diff_private _ _ (fun key kind value => apply_private _ _ _ _ _ key kind value)
    _ (diff_materialize_private ..)

/-- The actual materializer, including all changed files, providers,
delegations and retention effects, never changes the committed database.
It writes only the transaction's private rows, on success and failure alike. -/
theorem materialize_preserves_committed_database (tx : Transaction) (origin : Origin.Parsed)
    (oldRoot newRoot : ByteArray) (state : State) :
    (run (Materialize.materialize tx origin oldRoot newRoot) state).2.db = state.db :=
  (materialize_private tx origin oldRoot newRoot).preserves_db _ effects_preserve_db _

/-- A reader of committed rows never sees an intermediate materialization,
even if execution stops or fails after any particular request. -/
theorem no_partial_view_visible (tx : Transaction) (origin : Origin.Parsed)
    (oldRoot newRoot : ByteArray) (state final : State)
    (continuation : Program Materialize.Effects (Except Materialize.Error UInt64))
    (path : Prefix (Materialize.materialize tx origin oldRoot newRoot).run state continuation final) :
    final.db = state.db :=
  (materialize_private tx origin oldRoot newRoot).preserves_prefix path effects_preserve_db

theorem access_preserves_heads (effect : Access A) (safe : accessFrame effect) (state : State) :
    ReconciliationFrame.heads (access effect state).2 = ReconciliationFrame.heads state := by
  cases effect <;> simp only [access]
  all_goals apply ReconciliationFrame.reply_frame
  all_goals intro s
  all_goals first
    | rfl
    | (apply ReconciliationFrame.transaction_frame; intro db; first
        | exact rows_setRows_other _ _ _ _ safe
        | (simp only [copyRows, rows_setRows_other _ _ _ _ safe]))

theorem effects_preserve_heads (effect : Materialize.Effects A) (safe : allowed _ effect) (state : State) :
    ReconciliationFrame.heads (Interpreter.handle effect state).2 = ReconciliationFrame.heads state := by
  cases effect with
  | left effect => exact ReconciliationFrame.storage_frame effect safe state
  | right effect =>
    rcases effect with effect | effect
    · cases effect <;> apply ReconciliationFrame.reply_frame <;> intro s <;> rfl
    · rcases effect with effect | effect
      · exact access_preserves_heads effect safe state
      · rcases effect with effect | effect
        · cases effect; apply ReconciliationFrame.reply_frame; intro s; rfl
        · rcases effect with effect | effect
          · cases effect; apply ReconciliationFrame.reply_frame; intro s; rfl
          · rcases effect with effect | effect
            · cases effect; apply ReconciliationFrame.reply_frame; intro s; rfl
            · cases effect; apply ReconciliationFrame.reply_frame; intro s; rfl

/-- Derived-view processing cannot alter the head pointer staged by promotion,
even on failure or a stop in the middle of the streamed diff. -/
theorem materialize_preserves_heads (tx : Transaction) (origin : Origin.Parsed)
    (oldRoot newRoot : ByteArray) (state : State) :
    ReconciliationFrame.heads (execute (Materialize.materialize tx origin oldRoot newRoot) state).2 =
      ReconciliationFrame.heads state :=
  (materialize_private tx origin oldRoot newRoot).preserves_observation ReconciliationFrame.heads _
    effects_preserve_heads state

end Synchronicity.MaterializationPrivate
