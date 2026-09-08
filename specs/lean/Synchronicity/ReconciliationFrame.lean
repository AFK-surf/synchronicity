import Synchronicity.PrivateDatabase
import VerifiedCore.Replication.Reconcile

/-! History maintenance cannot change the transaction token or its heads rows.
The frame follows the actual raw requests, including arbitrary host failures. -/
namespace Synchronicity.ReconciliationFrame
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost
open PrivateDatabase

def heads (state : State) : Option (Transaction × List Fields) :=
  state.pending.map fun (tx, db) => (tx, rows db "heads")

theorem begin_heads (state opened : State) (tx : Transaction)
    (started : storage .begin state = (.ok tx, opened)) :
    heads opened = some (tx, rows state.db "heads") := by
  simp only [storage, reply] at started
  split at started
  · cases started
  · split at started
    · cases started
    · cases started
      rfl

theorem signature_preserves_db (head : Head) (state : State) :
    (execute (raise History.Error.host
      (Crypto.verifyEd25519 head.signedBy (Reconcile.signingInput head) head.signature) :
        History.Action Bool) state).2.db = state.db := by
  change (crypto (.verifyEd25519 head.signedBy (Reconcile.signingInput head) head.signature) state).2.db = _
  apply PrivateDatabase.reply_preserves_db
  intro s
  rfl

def storageAllowed : Storage A → Prop
  | .begin | .commit _ | .rollback _ => False
  | .upsert _ table _ _ _ | .deleteRows _ table _ _ _ | .deleteExcept _ table _ _ =>
      table ≠ "heads"
  | _ => True

def allowed (A : Type) : History.Effects A → Prop
  | .left effect => storageAllowed effect
  | .right _ => True

theorem reply_frame (state : State) (event : String) (action : State → Result (Reply A))
    (consume : Bool) (kept : ∀ s, heads (action s).2 = heads s) :
    heads (reply state event action consume).2 = heads state := by
  unfold reply
  split
  · cases consume
    · rfl
    · simpa only [heads, record, ↓reduceIte] using kept state
  · simpa only [heads, record] using kept state

theorem transaction_frame (state : State) (tx : Transaction) (action : Database → A × Database)
    (kept : ∀ db, rows (action db).2 "heads" = rows db "heads") :
    heads (SimulatedHost.transaction state tx action).2 = heads state := by
  unfold SimulatedHost.transaction
  split
  · rename_i token db pending
    split
    · simp [heads, pending, kept]
    · rfl
  · rfl

theorem storage_frame (effect : Storage A) (safe : storageAllowed effect) (state : State) :
    heads (storage effect state).2 = heads state := by
  cases effect <;> simp only [storage]
  all_goals first
    | contradiction
    | (apply reply_frame; intro s)
  all_goals first
    | (apply transaction_frame; intro db; first
        | rfl
        | exact rows_setRows_other _ _ _ _ safe)
    | rfl
    | (repeat' first | split | rfl)

theorem effects_frame (effect : History.Effects A) (safe : allowed _ effect) (state : State) :
    heads (Interpreter.handle effect state).2 = heads state := by
  cases effect with
  | left storage => exact storage_frame storage safe state
  | right crypto => cases crypto <;> apply reply_frame <;> intro s <;> rfl

theorem trimForks_only (tx : Transaction) (origin : String) (seq : UInt64) (keep : Nat) :
    Only allowed (Reconcile.trimForks tx origin seq keep).run := by
  unfold Reconcile.trimForks
  apply Only.seq (.request trivial fun _ => .done _)
  intro result
  apply Only.seq (.done _)
  intro pointers
  apply Only.seq
  · apply Only.forIn
    intro pointer initial
    exact Only.seq (.request (by change "head_history" ≠ "heads"; decide) fun _ => .done _) fun _ => .done _
  · intro _; exact .done _

theorem trimForks_preserves_heads (tx : Transaction) (origin : String) (seq : UInt64)
    (keep : Nat) (state : State) :
    heads (execute (Reconcile.trimForks tx origin seq keep) state).2 = heads state :=
  (trimForks_only tx origin seq keep).preserves_observation heads _ effects_frame state

theorem parse_only (validate : List UInt8 → OperationOver History.Effects ε Bool)
    (safe : ∀ bytes, Only allowed (validate bytes).run) (text : String) :
    Only allowed (Origin.parse validate text).run := by
  unfold Origin.parse
  repeat' first
    | exact .done _
    | (refine Only.seq (safe _) fun _ => ?_)
    | split

theorem config_only (tx : Transaction) (key : String) :
    Only allowed (Authorization.config tx key).run := by
  unfold Authorization.config
  refine Only.seq (.request trivial fun _ => .done _) fun rows => ?_
  repeat' first
    | exact .done _
    | (refine Only.seq ?_ fun _ => .done _)
    | (unfold Authorization.checked; split)
    | split

theorem trustInstant_only (tx : Transaction) (now : Int64) :
    Only allowed (Authorization.trustInstant tx now).run := by
  unfold Authorization.trustInstant
  split
  · exact .done _
  · exact (config_only tx _).seq fun _ => .done _

theorem originField_only (column text : String) :
    Only allowed (Authorization.originField column text).run := by
  unfold Authorization.originField
  refine (parse_only Authorization.validateKey (fun _ => .request trivial fun _ => .done _) text).seq fun result => ?_
  cases result <;> exact .done _

theorem keyField_only (column : String) (bytes : ByteArray) :
    Only allowed (Authorization.keyField column bytes).run := by
  unfold Authorization.keyField
  split
  · exact .done _
  · refine Only.seq (.request trivial fun _ => .done _) fun result => ?_
    split <;> exact .done _

theorem checked_only (value : Except Authorization.Error A) :
    Only allowed (Authorization.checked value).run := by
  cases value <;> exact .done _

theorem decodeBinding_only (row : Row) :
    Only allowed (Authorization.decodeBinding row).run := by
  unfold Authorization.decodeBinding
  repeat' first
    | exact .done _
    | exact originField_only ..
    | (refine Only.seq (checked_only _) fun _ => ?_)
    | (refine Only.seq (originField_only ..) fun _ => ?_)
    | (refine Only.seq (keyField_only ..) fun _ => ?_)
    | (refine Only.seq ?_ fun _ => ?_)
    | split

theorem readBindings_only (tx : Transaction) (fields : Fields) :
    Only allowed (Authorization.readBindings tx fields).run := by
  unfold Authorization.readBindings
  refine Only.seq (.request trivial fun _ => .done _) fun scan => ?_
  refine (Only.mapM _ _ decodeBinding_only).seq fun _ => ?_
  split <;> exact .done _

theorem liveAmong_only (tx : Transaction) (rows : List Authorization.Binding) (now : Int64) :
    Only allowed (Authorization.liveAmong tx rows now).run := by
  unfold Authorization.liveAmong
  apply Only.seq
  · apply Only.forIn
    intro binding initial
    repeat' first
      | exact .done _
      | (refine Only.seq (readBindings_only ..) fun _ => ?_)
      | (refine Only.seq ?_ fun _ => ?_)
      | (dsimp only; split)
      | split
  · intro _; exact .done _

theorem liveForKey_only (tx : Transaction) (key : ByteArray) (now : Int64) :
    Only allowed (Authorization.liveForKey tx key now).run := by
  unfold Authorization.liveForKey
  exact (readBindings_only tx _).seq fun bindings => liveAmong_only tx bindings now

theorem auth_only (operation : Authorization.Action A) (safe : Only allowed operation.run) :
    Only allowed (within Reconcile.authorizationError operation : History.Action A).run := by
  apply Only.within _ _ safe
  intro B effect good
  cases effect <;> exact good

theorem record_only (tx : Transaction) (head : Head) (now : Int64) :
    Only allowed (Reconcile.record tx head now).run := by
  unfold Reconcile.record
  split
  · exact .done _
  · refine Only.seq (.request (by change "head_history" ≠ "heads"; decide) fun _ => .done _) fun _ => ?_
    refine Only.seq (.request trivial fun _ => .done _) fun _ => ?_
    split <;> exact .done _

theorem decodeJoinedHead_only (row : Row) :
    Only allowed (History.decodeJoinedHead row).run := by
  unfold History.decodeJoinedHead
  refine Only.seq (.done _) fun fields => ?_
  refine (parse_only History.validateKey (fun _ => .request trivial fun _ => .done _) fields.origin).seq fun _ => ?_
  repeat' first
    | exact .done _
    | (refine Only.seq (.done _) fun _ => ?_)
    | (refine Only.seq (.request trivial fun _ => .done _) fun _ => ?_)
    | split

theorem readSlot_only (tx : Transaction) (origin slot : String) :
    Only allowed (History.readSlot tx origin slot).run := by
  unfold History.readSlot
  refine Only.seq (.request trivial fun _ => .done _) fun scan => ?_
  repeat' first
    | exact .done _
    | (refine Only.seq (decodeJoinedHead_only _) fun _ => .done _)
    | split

theorem preserves_heads (operation : OperationOver History.Effects ε A)
    (safe : Only allowed operation.run) (state : State) :
    heads (execute operation state).2 = heads state :=
  safe.preserves_observation heads _ effects_frame state

theorem executed_heads (operation : OperationOver History.Effects ε A)
    (safe : Only allowed operation.run) (state final : State) (answer : A)
    (executed : execute operation state = (.ok answer, final)) : heads final = heads state := by
  have kept := preserves_heads operation safe state
  simpa only [executed] using kept

end Synchronicity.ReconciliationFrame
