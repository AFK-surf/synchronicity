import Synchronicity.PromotionExecution
import Synchronicity.RetirementProtection

/-! Common composition of the actual write phase. The parameters are proven
request certificates, not domain decisions returned by an alternative host. -/
namespace Synchronicity.PromotionCertificates
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication SimulatedHost PrivateDatabase

theorem body_only (allowed : (A : Type) → Promote.Effects A → Prop)
    (tx : Transaction) (origin : Origin.Parsed) (now : Int64) (pending : Promote.Pending)
    (old : Option Promote.Pending) (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (clear : Only allowed (Promote.clear tx origin).run)
    (read : ∀ {A} (operation : Promote.Action A), Only PromotionReads.allowed operation.run → Only allowed operation.run)
    (write : Only allowed (Promote.history (Reconcile.putSlot tx "complete" pending.head pending.received now)).run)
    (materialize : Only allowed (within Promote.materializeError
      (Materialize.materialize tx origin (old.map (·.head.root) |>.getD Trie.emptyRoot) pending.head.root) : Promote.Action UInt64).run) :
    Only allowed (Promote.body tx origin now pending old scope authority).run := by
  unfold Promote.body
  split
  · exact clear.seq fun _ => .done _
  · refine (read _ (PromotionReads.complete_only _ _ _)).seq fun complete => ?_
    split
    · exact .done _
    · have tail (permitted : Bool) : Only allowed (do
          if !permitted then
            Promote.clear tx origin
            return .refused
          Promote.history (Reconcile.putSlot tx "complete" pending.head pending.received now)
          Promote.clear tx origin
          let _ ← within Promote.materializeError (Materialize.materialize tx origin
            (old.map (·.head.root) |>.getD Trie.emptyRoot) pending.head.root)
          return Promotion.flipped : Promote.Action Promotion).run := by
        split
        · exact clear.seq fun _ => .done _
        · exact write.seq fun _ => clear.seq fun _ => materialize.seq fun _ => .done _
      have permission : Only allowed (Promote.permitted tx pending authority).run := by
        unfold Promote.permitted
        cases authority.publication with
        | untrusted => exact .done _
        | unrestricted => exact .done _
        | confined _ =>
            exact Only.map _ _ (read _ (PromotionReads.scopeCheck_only _ _ _))
      exact permission.seq tail

theorem finish_only (allowed : (A : Type) → Promote.Effects A → Prop)
    (tx : Transaction) (pending : Option Promote.Pending) (key : Option (UInt64 × ByteArray × ByteArray))
    (result : Except Promote.Error Promotion)
    (commit : allowed _ (Inject.inject (Storage.commit tx)))
    (rollback : allowed _ (Inject.inject (Storage.rollback tx)))
    (retire : ∀ candidate, pending = some candidate → Only allowed (Promote.retire candidate).run) :
    Only allowed (Promote.finish tx pending key result).run := by
  unfold Promote.finish
  cases result with
  | ok promotion =>
    refine Only.seq (Only.bind (Only.raise _ _ commit) fun _ => .done _) fun result => ?_
    cases result with
    | ok value => cases value; exact .done _
    | error _ => exact Only.seq (Only.bind (Only.raise _ _ rollback) fun _ => .done _) fun _ => .done _
  | error error =>
    refine Only.seq (Only.bind (Only.raise _ _ rollback) fun _ => .done _) fun _ => ?_
    cases error with
    | host _ => exact .done _
    | domain failure =>
      dsimp only
      split
      · cases pending with
        | none => exact .done _
        | some candidate => exact (retire candidate rfl).seq fun _ => .done _
      · exact .done _

theorem publish_only (allowed : (A : Type) → Promote.Effects A → Prop)
    (tx : Transaction) (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority) (pending old : Option Promote.Pending)
    (clear : Only allowed (Promote.clear tx origin).run)
    (body : ∀ candidate, pending = some candidate → Only allowed (Promote.body tx origin now candidate old scope authority).run)
    (finish : ∀ key result, Only allowed (Promote.finish tx pending key result).run) :
    Only allowed (PromotionExecution.publish tx origin now refused (scope, authority, pending, old)).run := by
  unfold PromotionExecution.publish
  dsimp only
  apply Only.seq
  · apply Only.bind
    · cases pending with
      | none => exact .done _
      | some candidate =>
        dsimp only
        split
        · exact clear.seq fun _ => .done _
        · exact body candidate rfl
    · intro _; exact .done _
  · intro result
    exact finish _ result

end Synchronicity.PromotionCertificates
