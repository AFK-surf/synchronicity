import Synchronicity.ReconciliationReadOnly

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

theorem read_only_frame (operation : OperationOver History.Effects ε A)
    (safe : Only ReconciliationReadOnly.allowed operation.run) : Only allowed operation.run := by
  apply safe.mono
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem trustInstant_only (tx : Transaction) (now : Int64) :
    Only allowed (Authorization.trustInstant tx now).run :=
  read_only_frame _ (ReconciliationReadOnly.trustInstant_only tx now)

theorem liveForKey_only (tx : Transaction) (key : ByteArray) (now : Int64) :
    Only allowed (Authorization.liveForKey tx key now).run :=
  read_only_frame _ (ReconciliationReadOnly.liveForKey_only tx key now)

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

theorem readSlot_only (tx : Transaction) (origin slot : String) :
    Only allowed (History.readSlot tx origin slot).run :=
  read_only_frame _ (ReconciliationReadOnly.readSlot_only tx origin slot)

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
