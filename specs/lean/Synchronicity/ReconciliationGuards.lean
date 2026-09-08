import VerifiedCore.Replication.Fetch
import Synchronicity.TrieServePrivacyProofs

/-! Necessary conditions on the actual promotion result. In particular, an
old Fetch completion is not a certificate for a replacement target. These
lemmas do not identify walk completion with an exact permitted view. -/
namespace Synchronicity.ReconciliationGuards
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost
open TrieServePrivacyProofs (bind_ok)

/-- Any successful flip passed the comparison with the complete version
read in the promotion transaction, not the version at Fetch selection time. -/
theorem flipped_is_newer (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending : Promote.Pending) (old : Option Promote.Pending)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority) (state : State)
    (flipped : (execute (Promote.body tx origin now pending old scope authority) state).1 =
      .ok .flipped) :
    ∀ previous, old = some previous →
      Reconcile.newer pending.head.seq pending.head.root ⟨previous.head.seq, previous.head.root⟩ = true := by
  unfold Promote.body at flipped
  split at flipped
  · obtain ⟨_, _, _, impossible⟩ := bind_ok _ _ _ _ flipped
    cases impossible
  · rename_i greater
    intro previous same
    simpa [same] using greater

/-- When the old version wins, the production body only clears pending. No
completeness result, metadata decoding or materialization can reverse this. -/
theorem obsolete_body (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (pending previous : Promote.Pending) (scope : Trie.Serve.Scope)
    (authority : Authorization.OriginAuthority)
    (obsolete : Reconcile.newer pending.head.seq pending.head.root
      ⟨previous.head.seq, previous.head.root⟩ = false) :
    Promote.body tx origin now pending (some previous) scope authority =
      (do Promote.clear tx origin; pure Promotion.idle) := by
  simp only [Promote.body, Option.any, obsolete, Bool.not_false, ↓reduceIte]

end Synchronicity.ReconciliationGuards
