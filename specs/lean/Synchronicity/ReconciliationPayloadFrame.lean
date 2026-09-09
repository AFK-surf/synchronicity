import Synchronicity.TableInvariant
import Synchronicity.ReconciliationFailure
import Synchronicity.MptsyncStableTail

/-! Actual signed-head acceptance changes only heads/history bookkeeping.  The
materialized payload and retention tables are framed through every transaction
outcome. -/
namespace Synchronicity.ReconciliationPayloadFrame
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def Allowed (relation : String) (A : Type) : History.Effects A → Prop
  | .left effect => TableInvariant.StorageAllowed relation effect
  | .right _ => True

theorem effects (relation : String) (baseline : List Fields) (effect : History.Effects A)
    (safe : Allowed relation _ effect) : TableInvariant.EffectSafe relation baseline effect := by
  intro state initial
  cases effect with
  | left effect => exact TableInvariant.storage_safe relation baseline effect safe state initial
  | right effect =>
    cases effect <;> exact TableInvariant.reply_holds relation baseline state _ _ _
      (fun _ held => held) initial

theorem read_only (relation : String) (operation : History.Action A)
    (safe : Only ReconciliationReadOnly.allowed operation.run) :
    Only (Allowed relation) operation.run := by
  apply safe.mono
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem auth_only (relation : String) (operation : Authorization.Action A)
    (safe : Only ReconciliationReadOnly.allowed operation.run) :
    Only (Allowed relation) (within Reconcile.authorizationError operation : History.Action A).run := by
  apply Only.within _ _ safe
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem record_only (relation : String) (history : "head_history" ≠ relation)
    (tx : Transaction) (head : Head) (now : Int64) :
    Only (Allowed relation) (Reconcile.record tx head now).run := by
  unfold Reconcile.record
  split
  · exact .done _
  · refine Only.seq (Only.raise _ _ history) fun _ => ?_
    refine Only.seq (Only.raise _ _ trivial) fun _ => ?_
    split <;> exact .done _

theorem trim_only (relation : String) (history : "head_history" ≠ relation)
    (tx : Transaction) (origin : String) (seq : UInt64) (keep : Nat) :
    Only (Allowed relation) (Reconcile.trimForks tx origin seq keep).run := by
  unfold Reconcile.trimForks
  refine Only.seq (Only.raise _ _ trivial) fun result => ?_
  refine Only.seq (.done _) fun pointers => ?_
  refine Only.seq ?_ fun _ => .done _
  apply Only.forIn
  intro pointer initial
  exact Only.seq (Only.raise _ _ history) fun _ => .done _

theorem put_only (relation : String) (heads : "heads" ≠ relation)
    (history : "head_history" ≠ relation) (tx : Transaction) (slot : String)
    (head : Head) (received verified : Int64) :
    Only (Allowed relation) (Reconcile.putSlot tx slot head received verified).run := by
  unfold Reconcile.putSlot
  exact (record_only relation history tx head received).seq fun _ =>
    Only.request heads fun _ => .done _

theorem accept_only (relation : String) (heads : "heads" ≠ relation)
    (history : "head_history" ≠ relation) (head : Head) (now : Int64) (keep : Nat) :
    Only (Allowed relation) (Reconcile.accept head now keep).run := by
  unfold Reconcile.accept
  refine Only.seq (Only.raise _ _ trivial) fun valid => ?_
  split
  · exact .done _
  · apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
    intro tx
    refine (auth_only relation _ (ReconciliationReadOnly.trustInstant_only tx now)).seq fun instant => ?_
    refine (auth_only relation _ (ReconciliationReadOnly.liveForKey_only tx head.signedBy instant)).seq fun live => ?_
    split
    · exact .done _
    · refine (record_only relation history tx head now).seq fun _ => ?_
      refine (read_only relation _ (ReconciliationReadOnly.readSlot_only tx _ "complete")).seq fun complete => ?_
      refine (read_only relation _ (ReconciliationReadOnly.readSlot_only tx _ "pending")).seq fun pending => ?_
      dsimp only
      split
      · exact (put_only relation heads history tx "pending" head now now).seq fun _ =>
          (trim_only relation history tx _ head.seq keep).seq fun _ => .done _
      · exact (trim_only relation history tx _ head.seq keep).seq fun _ => .done _

theorem accept_relation (relation : String) (heads : "heads" ≠ relation)
    (history : "head_history" ≠ relation) (head : Head) (now : Int64) (keep : Nat)
    (state : State) (closed : state.pending = none) :
    rows (execute (Reconcile.accept head now keep) state).2.db relation = rows state.db relation := by
  have held := (accept_only relation heads history head now keep).invariant
    (TableInvariant.Holds relation (rows state.db relation))
    (fun effect good current initial => effects relation _ effect good current initial)
    state (TableInvariant.closed relation state closed)
  exact held.1

theorem accept_payload (head : Head) (now : Int64) (keep : Nat)
    (state : State) (closed : state.pending = none) :
    MptsyncStableTail.PayloadFrame state.db (execute (Reconcile.accept head now keep) state).2.db := by
  exact ⟨accept_relation "entries" (by decide) (by decide) head now keep state closed,
    accept_relation "pins" (by decide) (by decide) head now keep state closed,
    accept_relation "content_want" (by decide) (by decide) head now keep state closed⟩

end Synchronicity.ReconciliationPayloadFrame
