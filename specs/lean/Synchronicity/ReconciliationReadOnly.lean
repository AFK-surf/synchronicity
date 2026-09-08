import Synchronicity.PrivateDatabase
import VerifiedCore.Replication.Reconcile

/-! Authorization and joined slot decoding only read the private database.
This stronger frame keeps backing history as well as slot pointers. -/
namespace Synchronicity.ReconciliationReadOnly
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def storageAllowed : Storage A → Prop
  | .begin | .commit _ | .rollback _ | .upsert _ _ _ _ _ |
    .deleteRows _ _ _ _ _ | .deleteExcept _ _ _ _ => False
  | _ => True

def allowed (A : Type) : History.Effects A → Prop
  | .left effect => storageAllowed effect
  | .right _ => True

theorem reply_pending (state : State) (event : String) (action : State → Result (Reply A))
    (consume : Bool) (kept : ∀ s, (action s).2.pending = s.pending) :
    (reply state event action consume).2.pending = state.pending := by
  unfold reply
  split
  · cases consume <;> simp [record, kept]
  · simp [record, kept]

theorem transaction_read (state : State) (tx : Transaction) (action : Database → A) :
    (SimulatedHost.transaction state tx (fun db => (action db, db))).2.pending = state.pending := by
  unfold SimulatedHost.transaction
  split
  · rename_i token db opened
    split
    · exact opened.symm
    · rfl
  · rfl

theorem storage_pending (effect : Storage A) (safe : storageAllowed effect) (state : State) :
    (storage effect state).2.pending = state.pending := by
  cases effect <;> simp only [storage]
  all_goals first | contradiction | (apply reply_pending; intro s)
  all_goals repeat' first | rfl | exact transaction_read .. | split

theorem effects_pending (effect : History.Effects A) (safe : allowed _ effect) (state : State) :
    (Interpreter.handle effect state).2.pending = state.pending := by
  cases effect with
  | left storage => exact storage_pending storage safe state
  | right crypto => cases crypto <;> apply reply_pending <;> intro s <;> rfl

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

theorem liveForOrigin_only (tx : Transaction) (origin : String) (now : Int64) :
    Only allowed (Authorization.liveForOrigin tx origin now).run := by
  unfold Authorization.liveForOrigin
  exact (readBindings_only tx _).seq fun bindings => liveAmong_only tx bindings now

theorem scope_only (tx : Transaction) (origin : Origin.Parsed) :
    Only allowed (Authorization.materializationScopeIn tx origin).run := by
  unfold Authorization.materializationScopeIn Authorization.ownOrigin
  refine Only.seq ?_ fun own => ?_
  · refine (config_only _ _).seq fun own => ?_
    cases own with
    | none => exact .done _
    | some text => exact (originField_only _ text).seq fun _ => .done _
  · split
    · exact .done _
    · unfold Authorization.localSpacesIn
      exact ((config_only _ _).seq fun _ => .done _).seq fun _ => .done _

theorem originAuthority_only (tx : Transaction) (origin : Origin.Parsed) (now : Int64) :
    Only allowed (Authorization.originAuthorityIn tx origin now).run := by
  unfold Authorization.originAuthorityIn
  refine (trustInstant_only tx now).seq fun instant => ?_
  refine (liveForOrigin_only tx _ instant).seq fun live => ?_
  refine (config_only tx _).seq fun own => ?_
  refine Only.seq ?_ fun _ => .done _
  cases own with
  | none => exact .done _
  | some text => exact Only.map _ _ (originField_only _ text)

theorem auth_only (operation : Authorization.Action A) (safe : Only allowed operation.run) :
    Only allowed (within Reconcile.authorizationError operation : History.Action A).run := by
  apply Only.within _ _ safe
  intro B effect good
  cases effect <;> exact good

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


theorem executed_pending (operation : OperationOver History.Effects ε A)
    (safe : Only allowed operation.run) (state final : State) (answer : A)
    (executed : execute operation state = (.ok answer, final)) : final.pending = state.pending := by
  have kept := safe.preserves_observation State.pending _ effects_pending state
  change (execute operation state).2.pending = state.pending at kept
  simpa only [executed] using kept

end Synchronicity.ReconciliationReadOnly
