import Synchronicity.MptsyncConvergence
import Synchronicity.PromotionInitialView

/-! A view established by one checked production promotion supplies the old
view needed by the next version's promotion.  Raw slot/policy uniqueness and
cross-version snapshot/schema properties remain explicit metadata contracts;
the exact old directory and current duties come from the derived `CorrectView`.
-/
namespace Synchronicity.PromotionContinuationBaseline
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost
open MptsyncConvergence

/-- Stable database/metadata facts that are not themselves a correctness
claim about the current public view. -/
structure MetadataContracts (db : Database) (origin : Origin.Parsed)
    (previous : ViewTarget) (world : TrieDiffCoverage.World)
    (services : MaterializedView.Services) : Prop where
  schema : MaterializationKeySchema.Schema db
  snapshot : previous.snapshot = world.snapshot
  readable : ∀ root, PromotionInitialView.ReadVersion db origin root →
    root = previous.head.root
  policy : ∀ scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas →
      scope = previous.scope ∧ replicas = previous.replicas
  policiesAgree : MaterializationRequirementFrame.PoliciesAgree previous.replicas
  unique : ∀ newRoot,
    MaterializedView.UniqueAddresses services
      (SnapshotViewProgress.Relevant world.snapshot previous.head.root newRoot)
  supported : ∀ newRoot key,
    previous.scope.admitsKeyPath (Trie.keyNibbles key) = true →
      SnapshotDelta.ChangedKey world.snapshot previous.head.root newRoot key →
      key.size ≤ Trie.maxKeyBytes

/-- Correctness produced by an earlier actual promotion, combined with raw
slot/policy stability, derives the complete initial-view premise for the next
promotion. Callers need not assume `PromotionInitialView.Initial` afresh. -/
theorem initial_of_correct
    (correct : CorrectView services origin previous db)
    (metadata : MetadataContracts db origin previous world services) :
    PromotionInitialView.Initial db origin world services := by
  refine ⟨metadata.schema, ?_, ?_, ?_⟩
  · intro root read scope replicas policy
    have rootSame := metadata.readable root read
    obtain ⟨scopeSame, replicasSame⟩ := metadata.policy scope replicas policy
    subst root
    subst scope
    subst replicas
    refine ⟨metadata.policiesAgree, correct.2.2.2.1, ?_⟩
    have files := correct.2.2.1
    change SnapshotViewProgress.ExactFiles services previous.snapshot previous.head.root
      (fun key => previous.scope.admitsKeyPath (Trie.keyNibbles key) = true)
      db (Origin.canonical origin) at files
    simpa only [metadata.snapshot] using files
  · intro oldRoot newRoot read
    rw [metadata.readable oldRoot read]
    exact metadata.unique newRoot
  · intro oldRoot newRoot read scope replicas policy key admitted changed
    rw [metadata.readable oldRoot read] at changed
    obtain ⟨scopeSame, _⟩ := metadata.policy scope replicas policy
    rw [scopeSame] at admitted
    exact metadata.supported newRoot key admitted (by simpa only [metadata.snapshot] using changed)

end Synchronicity.PromotionContinuationBaseline
