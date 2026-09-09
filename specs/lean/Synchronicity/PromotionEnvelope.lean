import Synchronicity.PromotionNonpublication
import Synchronicity.PublicationEnvelope

/-! The real promotion program has one publication boundary on every path.
This certificate includes preparation, rollback, cached refusals and retirement,
so the prefix guarantee is not limited to the materializer's inner body. -/
namespace Synchronicity.PromotionEnvelope
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands Replication SimulatedHost PrivateDatabase
open PublicationEnvelope

theorem raw_private (effect : Storage (Reply A)) (safe : storagePrivate effect) :
    Only Private (Promote.raw effect).run := Only.raise _ _ (storage_preserves_db effect safe)

theorem attempt_private (operation : Promote.Action A) (safe : Only Private operation.run) :
    Only Private (Promote.attempt operation).run := safe.bind fun _ => .done _

theorem retire_last (pending : Promote.Pending) : LastWrite (Promote.retire pending).run := by
  unfold Promote.retire
  apply LastWrite.transaction
  · exact storage_preserves_db Storage.begin trivial
  · intro tx; exact storage_preserves_db (.rollback tx) trivial
  · intro tx
    exact Only.seq (raw_private (.deleteRows tx "heads" (Reconcile.headKey pending.head ++ [("slot", Cell.text "pending")])) trivial)
      fun _ => .done _

theorem finish_last (tx : Transaction) (pending : Option Promote.Pending)
    (key : Option (UInt64 × ByteArray × ByteArray)) (result : Except Promote.Error Promotion) :
    LastWrite (Promote.finish tx pending key result).run := by
  unfold Promote.finish
  cases result with
  | ok promotion =>
    apply LastWrite.lastStep
    intro committed
    cases committed with
    | ok value => cases value; exact .done _
    | error _ => exact Only.seq (attempt_private _ (raw_private (.rollback tx) trivial)) fun _ => .done _
  | error error =>
    apply LastWrite.seq (attempt_private _ (raw_private (.rollback tx) trivial))
    intro _
    cases error with
    | host _ => exact .done _
    | domain failure =>
      dsimp only
      split
      · cases pending with
        | none => exact .done _
        | some candidate => exact LastWrite.seq_after (retire_last candidate) _ fun _ => .done _
      · exact .done _

theorem publish_work (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (scope : Trie.Serve.Scope)
    (authority : Authorization.OriginAuthority) (pending old : Option Promote.Pending) :
    PromotionExecution.publish tx origin now refused (scope, authority, pending, old) = (do
      let result ← Promote.attempt (PromotionNonpublication.work tx origin now refused (scope, authority, pending, old))
      Promote.finish tx pending (pending.map (fun p => (p.head.seq, p.head.root,
        old.map (·.head.root) |>.getD Trie.emptyRoot))) result) := rfl

theorem publish_last (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (prepared : PromotionCommand.Prepared) :
    LastWrite (PromotionExecution.publish tx origin now refused prepared).run := by
  obtain ⟨scope, authority, pending, old⟩ := prepared
  rw [publish_work]
  exact LastWrite.seq (attempt_private _ (PromotionNonpublication.work_private tx origin now refused _)) _
    (fun result => finish_last tx pending _ result)

theorem promote_last (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray)) :
    LastWrite (Promote.promote origin now refused).run := by
  rw [PromotionExecution.decomposes]
  apply LastWrite.seq (raw_private Storage.begin trivial)
  intro tx
  apply LastWrite.seq (attempt_private _ ((PromotionCommand.prepare_only tx origin now).mono
    (fun effect good => PromotionReads.effects_db effect good)))
  intro preparation
  cases preparation with
  | error error =>
    change LastWrite (do
      let _ ← Promote.attempt (Promote.raw (.rollback tx))
      throw error : Promote.Action PromotionReport).run
    exact LastWrite.seq (attempt_private _ (raw_private (.rollback tx) trivial)) _ fun _ => .done _
  | ok prepared =>
    apply LastWrite.seq (.done _)
    intro value
    exact publish_last tx origin now refused value

theorem promote_prefix (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
    (state final : State) (tail : Program Promote.Effects (Except Promote.Error PromotionReport))
    (path : Prefix (Promote.promote origin now refused).run state tail final) :
    final.db = state.db ∨ final.db = (execute (Promote.promote origin now refused) state).2.db :=
  (promote_last origin now refused).envelope path

end Synchronicity.PromotionEnvelope
