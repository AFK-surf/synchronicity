import Synchronicity.PrivateDatabase
import VerifiedCore.Replication.Reconcile

/-! History maintenance cannot change the transaction token or its heads rows.
The frame follows the actual raw requests, including arbitrary host failures. -/
namespace Synchronicity.ReconciliationFrame
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost
open PrivateDatabase

def heads (state : State) : Option (Transaction × List Fields) :=
  state.pending.map fun (tx, db) => (tx, rows db "heads")

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

end Synchronicity.ReconciliationFrame
