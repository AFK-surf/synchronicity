import Synchronicity.MptsyncRetryExecution
import Synchronicity.TrieCompleteConverse

/-! M7: committed trie evidence survives real requester suspension,
cancellation and fresh retry.  The liveness premise names actual authorized
`Fetch.admit` executions; a retry-limit exit is useful only when the outer
runtime later starts another production requester. -/
namespace Synchronicity.Goals.Mptsync.M7
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Replication
open SimulatedHost PrivateDatabase
open TrieFetchCompletion TrieFetchAdmissionProgress
open AuthorizedFetchProgress TrieCompleteConverse
open MptsyncRetryExecution

/-- User-facing M7 property: the declared finite cancellation/resumption or
fresh-restart prefix ends in semantic completion, and a bounded healthy
production promotion check reuses that committed evidence. -/
def EventuallyReusesCommittedEvidence
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : RetryExecution requirements) : Prop :=
  PermittedComplete publisher scope owner root
      (replicaOfState (execution.state execution.endAt)) ∧
    ∃ tx final,
      execute (PromotionReads.complete tx ⟨scope, owner⟩ root)
        (execution.state execution.endAt) = (.ok true, final)

/-- M7. Actual cancel/resume/restart executions preserve every committed
evidence fact. Bounded response observations place every required scheduling
and authorized-admission opportunity inside that exact finite prefix; the
later production completeness execution therefore reuses, rather than merely
retains, the accumulated bytes. Permanent cancellation is excluded only by
that bounded response contract and the completion-opportunity premise.
-/
theorem actual_retries_accumulate_and_reuse
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : RetryExecution requirements)
    (responses : BoundedResponses requirements execution)
    (completeOpportunity :
      ∃ tx, PromotionReadOpportunity publisher tx ⟨scope, owner⟩ root ∧
        Nonempty (PromotionFreshOpportunity tx ⟨scope, owner⟩ root
          (execution.state execution.endAt))) :
    EventuallyReusesCommittedEvidence requirements execution := by
  have complete := responses.completeAtEnd
  obtain ⟨tx, reads, ⟨ready⟩⟩ := completeOpportunity
  exact ⟨complete, tx, ready.final,
    promotion_complete_exec_of_opportunity publisher tx ⟨scope, owner⟩ root
      (execution.state execution.endAt) reads complete ready⟩

end Synchronicity.Goals.Mptsync.M7
