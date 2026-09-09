import Synchronicity.ProgressLiveness
import Synchronicity.TrieFetchAdmissionProgress

/-! Composition of persistent Fetch evidence with the finite-work liveness
argument.  This module does not postulate that a requester succeeds.  Its
`ProductiveAdmissions` premise is deliberately phrased as strict changes in
the persistent evidence observed after committed admissions; operation lemmas
such as `admitted_single_*_strict_progress` and the scheduler/service bridge
must establish those changes for a production execution.
-/
namespace Synchronicity.TrieFetchConvergence
open TrieFetchCompletion ProgressLiveness

variable {publisher : TrieProgramProofs.RawSnapshot} {scope : VerifiedCore.Trie.Serve.Scope}
variable {owner : Option String} {root : ByteArray}

/-- The durable evidence snapshots observed at transaction boundaries. -/
def PersistentEvidence (trace : Nat → Replica) : Prop :=
  ∀ now, EvidenceIncluded (trace now) (trace (now + 1))

/-- Whenever a semantic requirement remains, a later committed production
admission has discharged at least one requirement.  This is the exact point
where actual scheduling, serving and admission proofs connect; a mere peer
contact or a requester Boolean is insufficient to establish it. -/
def ProductiveAdmissions
    (requirements : FiniteRequirements publisher scope owner root)
    (trace : Nat → Replica) : Prop :=
  ∀ now, 0 < missingEvidence requirements.items (trace now) →
    ∃ later, now < later ∧
      missingEvidence requirements.items (trace later) <
        missingEvidence requirements.items (trace now)

theorem persistent_measure
    (requirements : FiniteRequirements publisher scope owner root)
    (trace : Nat → Replica) (persistent : PersistentEvidence trace) :
    Nonincreasing (fun now => missingEvidence requirements.items (trace now)) := by
  intro now
  exact missingEvidence_mono requirements.items (persistent now)

/-- Finite publisher requirements, durable admission, and recurring actual
productive admissions imply semantic scoped completion after finitely many
committed observations, and completion remains true thereafter. -/
theorem finite_fetch_converges
    (requirements : FiniteRequirements publisher scope owner root)
    (trace : Nat → Replica) (persistent : PersistentEvidence trace)
    (productive : ProductiveAdmissions requirements trace) (start : Nat) :
    ∃ finish, start ≤ finish ∧ ∀ now, finish ≤ now →
      PermittedComplete publisher scope owner root (trace now) := by
  let measure := fun now => missingEvidence requirements.items (trace now)
  have monotone : Nonincreasing measure :=
    persistent_measure requirements trace persistent
  have effective : EffectiveOpportunities measure := productive
  obtain ⟨finish, after, empty⟩ := eventually_always_zero monotone effective start
  refine ⟨finish, after, fun now later => ?_⟩
  exact (finite_measure_eq_zero_iff_complete requirements).mp (empty now later)

end Synchronicity.TrieFetchConvergence
