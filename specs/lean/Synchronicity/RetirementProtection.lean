import Synchronicity.FetchHeadSafety
import Synchronicity.PromotionCommand

namespace Synchronicity.RetirementProtection
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def allowed (row : Fields) (A : Type) : Promote.Effects A → Prop
  | .left (.left effect) => FetchHeadSafety.storageAllowed row effect
  | .left (.right (.right (.left effect))) => FetchHeadSafety.accessAllowed row effect
  | _ => True

theorem effects_retain (row : Fields) (effect : Promote.Effects A) (safe : allowed row _ effect)
    (state : State) (kept : ProtectedHead.retained row state) :
    ProtectedHead.retained row (Interpreter.handle effect state).2 := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => exact ProtectedHead.storage_retains row effect (FetchHeadSafety.storage_retention row effect safe) state kept
    | right effect =>
      cases effect with
      | left effect => cases effect <;> apply ProtectedHead.reply_retains _ _ _ _ _ _ kept <;> intro s h <;> exact h
      | right effect =>
        rcases effect with effect | effect
        · exact ProtectedHead.access_retains row effect (FetchHeadSafety.access_retention row effect safe) state kept
        · rcases effect with effect | effect
          · cases effect <;> apply ProtectedHead.reply_retains _ _ _ _ _ _ kept <;> intro s h <;> exact h
          · rcases effect with effect | effect
            · cases effect; apply ProtectedHead.reply_retains _ _ _ _ _ _ kept; intro s h; exact h
            · cases effect with
              | left effect => cases effect; apply ProtectedHead.reply_retains _ _ _ _ _ _ kept; intro s h; exact h
              | right effect => cases effect; apply ProtectedHead.reply_retains _ _ _ _ _ _ kept; intro s h; exact h
  | right effect => cases effect <;> apply ProtectedHead.reply_retains _ _ _ _ _ _ kept <;> intro s h <;> exact h

def key (pending : Promote.Pending) : Fields :=
  Reconcile.headKey pending.head ++ [("slot", .text "pending")]

theorem retire_only (row : Fields) (pending : Promote.Pending)
    (different : equals row (key pending) = false) :
    Only (allowed row) (Promote.retire pending).run := by
  unfold Promote.retire
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  exact Only.seq (Only.raise _ _ (Or.inr different)) fun _ => .done _

/-- Retirement can start in a completely different database from the failed
promotion. A replacement with a different origin, sequence, root or slot is
retained at every prefix, regardless of commit and rollback failures. -/
theorem every_resumption_preserves (pending : Promote.Pending)
    (continuation rest : Program Promote.Effects (Except Promote.Error Unit))
    (reachable : Continuation (Promote.retire pending).run continuation)
    (state final : State) (closed : state.pending = none)
    (path : Prefix continuation state rest final)
    (row : Fields) (present : row ∈ rows state.db "heads")
    (different : equals row (key pending) = false) : row ∈ rows final.db "heads" := by
  exact (((retire_only row pending different).continuation reachable).invariant_prefix
    (ProtectedHead.retained row) path (effects_retain row)
    (ProtectedHead.initial row state closed present)).1

theorem effects_preserve_keys (predicate : List Cell → Prop) (row : Fields) (effect : Promote.Effects A)
    (safe : allowed row _ effect) : HeadInvariant.effectSafe (HeadKeyFrame.allKeys predicate) _ effect := by
  intro state initial
  cases effect with
  | left effect =>
    cases effect with
    | left effect => exact HeadKeyFrame.storage_safe predicate effect (FetchHeadSafety.storage_keys row effect safe) state initial
    | right effect =>
      cases effect with
      | left effect => cases effect <;> apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;> intro s h <;> exact h
      | right effect =>
        rcases effect with effect | effect
        · exact HeadKeyFrame.access_safe predicate effect (FetchHeadSafety.access_keys row effect safe) state initial
        · rcases effect with effect | effect
          · cases effect <;> apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;> intro s h <;> exact h
          · rcases effect with effect | effect
            · cases effect; apply HeadInvariant.reply_holds _ _ _ _ _ _ initial; intro s h; exact h
            · cases effect with
              | left effect => cases effect; apply HeadInvariant.reply_holds _ _ _ _ _ _ initial; intro s h; exact h
              | right effect => cases effect; apply HeadInvariant.reply_holds _ _ _ _ _ _ initial; intro s h; exact h
  | right effect => cases effect <;> apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;> intro s h <;> exact h

end Synchronicity.RetirementProtection
