import Synchronicity.PromotionPublication
import Synchronicity.MaterializationInputs

/-! Before streaming, promotion changes only version/history bookkeeping.
The old file view and the policy/obligation tables remain the actual input to
materialization, not an assumed intermediate ready state. -/
namespace Synchronicity.PromotionViewFrame
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase
open MaterializationTableFrame

def storageSafe (relation : String) : Storage A → Prop
  | .removeFile .. => True
  | effect => storageAllowed relation effect

def allowed (relation : String) (A : Type) : Promote.Effects A → Prop
  | .left (.left effect) => storageSafe relation effect
  | .left (.right (.right (.left effect))) => accessAllowed relation effect
  | _ => True

theorem storage_frame (relation : String) (effect : Storage A)
    (safe : storageSafe relation effect) (state : State) :
    view relation (storage effect state).2 = view relation state := by
  cases effect <;> simp only [storageSafe] at safe <;> first
    | exact MaterializationTableFrame.storage_frame relation _ safe state
    | (apply reply_frame; intro s; rfl)

theorem effects_frame (relation : String) (effect : Promote.Effects A)
    (safe : allowed relation _ effect) (state : State) :
    view relation (Interpreter.handle effect state).2 = view relation state := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => exact storage_frame relation effect safe state
    | right effect =>
      apply MaterializationTableFrame.effects_frame relation (.right effect) _ state
      rcases effect with effect | effect
      · trivial
      · rcases effect with effect | effect
        · exact safe
        · trivial
  | right effect => cases effect <;> apply reply_frame <;> intro s <;> rfl

theorem read_only (relation : String) (operation : Promote.Action A)
    (safe : Only PromotionReads.allowed operation.run) : Only (allowed relation) operation.run := by
  apply safe.mono
  intro B effect good
  cases effect with
  | left effect =>
    cases effect with
    | left effect => cases effect <;> first | contradiction | trivial
    | right effect =>
      rcases effect with effect | effect
      · trivial
      · rcases effect with effect | effect
        · cases effect <;> first | contradiction | trivial
        · trivial
  | right _ => trivial

theorem history_only (relation : String) (operation : History.Action A)
    (safe : Only (fun _ effect => allowed relation _ (Inject.inject effect : Promote.Effects _)) operation.run) :
    Only (allowed relation) (Promote.history operation).run :=
  Only.within _ _ safe (fun _ good => good)

theorem put_slot_only (relation : String) (heads : "heads" ≠ relation) (history : "head_history" ≠ relation)
    (tx : Transaction) (slot : String) (head : Head) (received verified : Int64) :
    Only (allowed relation) (Promote.history (Reconcile.putSlot tx slot head received verified)).run := by
  apply history_only
  unfold Reconcile.putSlot
  apply Only.seq
  · unfold Reconcile.record
    split
    · exact .done _
    · refine Only.seq (Only.raise _ _ history) fun _ => ?_
      refine Only.seq (Only.raise _ _ trivial) fun _ => ?_
      split <;> exact .done _
  · intro _
    exact Only.raise _ _ heads

theorem clear_only (relation : String) (heads : "heads" ≠ relation)
    (tx : Transaction) (origin : Origin.Parsed) :
    Only (allowed relation) (Promote.clear tx origin).run :=
  Only.seq (Only.raise _ _ heads) fun _ => .done _

theorem executed_frame (relation : String) (operation : Promote.Action A)
    (safe : Only (allowed relation) operation.run) (state final : State) (answer : A)
    (ran : execute operation state = (.ok answer, final)) : view relation final = view relation state := by
  have same := safe.preserves_observation (view relation) _ (effects_frame relation) state
  change view relation (execute operation state).2 = view relation state at same
  simpa only [ran] using same

theorem permitted_only (tx : Transaction) (pending : Promote.Pending) (authority : Authorization.OriginAuthority) :
    Only PromotionReads.allowed (PromotionPublication.permitted tx pending authority).run := by
  unfold PromotionPublication.permitted
  unfold Promote.permitted
  cases authority.publication with
  | untrusted => exact .done _
  | unrestricted => exact .done _
  | confined _ => exact Only.map _ _ (PromotionReads.scopeCheck_only tx _ _)

theorem published_inputs (tx : Transaction) (origin : Origin.Parsed) (now : Int64) (pending : Promote.Pending) (old : Option Promote.Pending)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority) (state final : State)
    (published : PromotionPublication.BodyPublished tx origin now pending old scope authority state final) :
    ∃ cleared count, (∀ relation, "heads" ≠ relation → "head_history" ≠ relation →
      view relation cleared = view relation state) ∧
      execute (Materialize.materialize tx origin (old.map (·.head.root) |>.getD Trie.emptyRoot)
        pending.head.root) cleared = (.ok count, final) := by
  obtain ⟨checked, authorized, written, cleared, count, complete, permitted, installed, erased, streamed⟩ := published.phases
  refine ⟨cleared, count, ?_, streamed⟩
  intro relation heads history
  have first := executed_frame relation _ (read_only relation _ (PromotionReads.complete_only tx _ _)) _ _ _ complete
  have second := executed_frame relation _ (read_only relation _ (permitted_only tx pending authority)) _ _ _ permitted
  have third := executed_frame relation _ (put_slot_only relation heads history tx _ _ _ _) _ _ _ installed
  have fourth := executed_frame relation _ (clear_only relation heads tx origin) _ _ _ erased
  exact fourth.trans (third.trans (second.trans first))

end Synchronicity.PromotionViewFrame
