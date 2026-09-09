import Synchronicity.PromotionEnvelope

/-! Actual promotion executions refine the common atomic file-view relation.
All outcomes and primitive prefixes are included; successful materialization
and readiness are derived, never premises restricting an execution constructor. -/
namespace Synchronicity.PromotionAtomicView
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands Replication SimulatedHost PrivateDatabase
open AtomicFileView

theorem promote_refines (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state : State)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (closed : state.pending = none) (faithful : TrieDiffCoverage.Faithful world state)
    (normalization : state.isNfc = services.nfc)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (initial : PromotionInitialView.Initial state.db origin world services) :
    AtomicReplacement services world.snapshot origin (MaterializationInputs.ReadPolicy state.db origin)
      state.db (execute (Promote.promote origin now refused) state).2.db := by
  cases ran : execute (Promote.promote origin now refused) state with
  | mk answer final =>
    cases answer with
    | error failure =>
      exact Or.inl (congrArg (projection (Origin.canonical origin))
        (PromotionPublication.promote_failure origin now refused state final failure ran))
    | ok report =>
      by_cases flipped : report.promotion = .flipped
      · obtain ⟨scope, replicas, head, sameOrigin, policy, installed, files, current, forever⟩ :=
          PromotionCommittedView.promote_ready origin now refused state final report world services closed faithful normalization relational initial flipped ran
        exact Or.inr ⟨scope, replicas, policy, head, sameOrigin, installed, files, current, forever⟩
      · exact Or.inl (PromotionNonpublication.promote_no_flip origin now refused state final report flipped ran)

theorem prefix_refines (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state final : State)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (closed : state.pending = none) (faithful : TrieDiffCoverage.Faithful world state)
    (normalization : state.isNfc = services.nfc)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (initial : PromotionInitialView.Initial state.db origin world services)
    (tail : Program Promote.Effects (Except Promote.Error PromotionReport))
    (path : Prefix (Promote.promote origin now refused).run state tail final) :
    AtomicReplacement services world.snapshot origin (MaterializationInputs.ReadPolicy state.db origin) state.db final.db := by
  rcases PromotionEnvelope.promote_prefix origin now refused state final tail path with unchanged | settled
  · exact Or.inl (congrArg (projection (Origin.canonical origin)) unchanged)
  · rw [settled]
    exact promote_refines origin now refused state world services closed faithful normalization relational initial

end Synchronicity.PromotionAtomicView
