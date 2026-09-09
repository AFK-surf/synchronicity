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

/-- User-facing M7 property: after any finite number of real cancellation /
resumption or fresh-restart checkpoints, sufficiently many actual authorized
admissions reach semantic completion, and a bounded healthy production
promotion check reuses that committed evidence. -/
def EventuallyReusesCommittedEvidence
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : RetryExecution requirements) : Prop :=
  ∀ start, ∃ finish, start ≤ finish ∧
    PermittedComplete publisher scope owner root
      (replicaOfState (execution.state finish)) ∧
    ∃ tx final,
      execute (PromotionReads.complete tx ⟨scope, owner⟩ root)
        (execution.state finish) = (.ok true, final)

/-- M7. Actual cancel/resume/restart executions preserve every committed
evidence fact.  Actual authorized admissions discharge the finite deficit;
the later production completeness execution therefore reuses, rather than
merely retains, the accumulated bytes. Permanent cancellation is excluded
only by the explicit `SufficientResponses` and completion-opportunity premises.
-/
theorem actual_retries_accumulate_and_reuse
    (requirements : FiniteRequirements publisher scope owner root)
    (execution : RetryExecution requirements)
    (responses : SufficientResponses requirements execution.state)
    (completeOpportunity : ∀ now,
      PermittedComplete publisher scope owner root
        (replicaOfState (execution.state now)) →
      ∃ tx, Nonempty
        (PromotionFreshOpportunity tx ⟨scope, owner⟩ root (execution.state now))) :
    EventuallyReusesCommittedEvidence requirements execution := by
  intro start
  obtain ⟨finish, after, complete⟩ := sufficient_responses_converge requirements
    execution.state execution.persistentEvidence responses start
  obtain ⟨tx, ⟨ready⟩⟩ := completeOpportunity finish (complete finish (Nat.le_refl _))
  exact ⟨finish, after, complete finish (Nat.le_refl _), tx, ready.final,
    promotion_complete_exec_of_opportunity tx ⟨scope, owner⟩ root
      (execution.state finish) ready⟩

end Synchronicity.Goals.Mptsync.M7
