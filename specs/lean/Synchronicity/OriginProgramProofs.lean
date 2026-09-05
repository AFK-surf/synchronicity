import VerifiedCore.Origin
import Synchronicity.Prelude

namespace Synchronicity.OriginProgramProofs
open VerifiedCore.Origin

/-- Accepted labels have the actual executable syntax predicate. -/
theorem accepted_label (input result : String)
    (accepted : normalizeLabel input = .ok result) :
    result = lower input ∧ labelValid result = true := by
  unfold normalizeLabel at accepted
  dsimp only at accepted
  split at accepted
  next valid => cases accepted; exact ⟨rfl, valid⟩
  next => cases accepted

theorem accepted_domain (input result : String)
    (accepted : normalizeDomain input = .ok result) :
    domainValid result = true := by
  unfold normalizeDomain at accepted
  dsimp only at accepted
  generalize lower (String.ofList (input.toList.reverse.dropWhile (· == '.')).reverse) = normalized at accepted
  split at accepted
  next valid => cases accepted; exact valid
  next => cases accepted

theorem label_failure_precedes_domain (id domain : String) (failure : Error)
    (bad : normalizeLabel id = .error failure) :
    named id domain = .error failure := by
  simp [named, bad, bind, Except.bind]

theorem key_prefix_precedes_named : checkNamedText "key:invalid@domain" = .ok () := by decide
theorem named_case_and_trailing_dots :
    named "NAS" "Cluster.Example.COM..." = .ok ⟨"nas", "cluster.example.com"⟩ := by decide
theorem second_at_is_not_a_second_origin :
    checkNamedText "nas@cluster@example" = .error (.domain "cluster@example") := by decide
theorem unicode_not_casefolded :
    named "K" "example" = .error (.label "K") := by decide
theorem empty_domain_rejected :
    named "nas" "..." = .error (.domain "...") := by decide
theorem leading_domain_hyphen_rejected :
    named "nas" "-cluster.example" = .error (.domain "-cluster.example") := by decide
theorem member_hyphen_allowed :
    named "-" "example" = .ok ⟨"-", "example"⟩ := by decide

end Synchronicity.OriginProgramProofs
