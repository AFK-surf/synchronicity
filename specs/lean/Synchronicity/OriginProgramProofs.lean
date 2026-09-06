import VerifiedCore.Origin
import Synchronicity.Decidable

namespace Synchronicity.OriginProgramProofs
open VerifiedCore.Origin
set_option maxRecDepth 4096

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

theorem key_prefix_precedes_named :
    checkSyntax "key:invalid@domain" = .error .keyDecode := by decide
theorem named_case_and_trailing_dots :
    named "NAS" "Cluster.Example.COM..." = .ok ⟨"nas", "cluster.example.com"⟩ := by decide
theorem second_at_is_not_a_second_origin :
    checkSyntax "nas@cluster@example" = .error (.domain "cluster@example") := by decide
theorem unicode_not_casefolded :
    named "K" "example" = .error (.label "K") := by decide
theorem empty_domain_rejected :
    named "nas" "..." = .error (.domain "...") := by decide
theorem leading_domain_hyphen_rejected :
    named "nas" "-cluster.example" = .error (.domain "-cluster.example") := by decide
theorem member_hyphen_allowed :
    named "-" "example" = .ok ⟨"-", "example"⟩ := by decide

theorem zero_key_decoded :
    decodeKey (List.replicate 52 'y') = .ok (List.replicate 32 0) := by decide

theorem decoded_key_width (text : List Char) (bytes : List UInt8)
    (accepted : decodeKey text = .ok bytes) : bytes.length = 32 := by
  unfold decodeKey at accepted
  simp only [bind, Except.bind, pure, Except.pure] at accepted
  split at accepted
  · cases accepted
  · cases decoded : decodeDigits text 0 0 [] with
    | error error => simp [decoded] at accepted
    | ok result =>
      simp only [decoded] at accepted
      split at accepted
      · cases accepted
      · rename_i width
        cases accepted
        simpa using width

theorem full_byte_key_decoded :
    decodeKey (List.replicate 51 '9' ++ ['o']) = .ok (List.replicate 32 255) := by decide

theorem nonzero_trailing_bits_rejected :
    decodeKey (List.replicate 51 'y' ++ ['b']) = .error .keyDecode := by decide

theorem wrong_key_width_distinct_from_encoding :
    decodeKey ['c', 'a'] = .error .keyData := by decide

theorem byte_packing_vector : decodeDigits ['c', 'a'] 0 0 [] = .ok [102] := by decide

theorem uppercase_is_not_an_alias :
    decodeKey (List.replicate 51 'y' ++ ['Y']) = .error .keyDecode := by decide

theorem bare_failure_is_shape : parseSyntax "not-a-key" = .error (.shape "not-a-key") := by decide

/-- Named results and syntax errors never invoke the primitive. -/
theorem named_needs_no_crypto [Monad m] (validate : List UInt8 → m Bool)
    (input : String) (value : Named) (decoded : parseSyntax input = .ok (.named value)) :
    parse validate input = pure (.ok (.named value)) := by
  simp [parse, decoded]

theorem malformed_needs_no_crypto [Monad m] (validate : List UInt8 → m Bool)
    (input : String) (error : Error) (decoded : parseSyntax input = .error error) :
    parse validate input = pure (.error error) := by
  simp [parse, decoded]

/-- Key success is downstream of the byte-validation action, never a syntactic
acceptance promoted to a valid key by Rust. -/
theorem key_requests_crypto [Monad m] (validate : List UInt8 → m Bool)
    (input : String) (bytes : List UInt8) (decoded : parseSyntax input = .ok (.key bytes)) :
    parse validate input = (do
      if ← validate bytes then pure (.ok (.key bytes))
      else pure (.error (if prefixed input then .keyData else .shape input))) := by
  simp [parse, decoded]

end Synchronicity.OriginProgramProofs
