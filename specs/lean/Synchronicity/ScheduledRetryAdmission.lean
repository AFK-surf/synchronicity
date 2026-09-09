import Synchronicity.ScheduledFetchAdmission
import Synchronicity.MptsyncRetryExecution

/-! A retry-limit exit is connected to the next fresh pending-origin schedule
window.  The abandoned report itself supplies no admission; the exact attempt
selected in the later raw window is still handled by an independent
authority/bytes admission bridge. -/
namespace Synchronicity.ScheduledRetryAdmission
open VerifiedCore VerifiedCore.Trie VerifiedCore.Replication
open SimulatedHost TrieFetchCompletion
open ScheduledFetchAdmission

/-- The same pending scheduler observation certified by `RequeuedAfterLimit`
is embedded strictly after the retry exit in the receiver state timeline.
Final sequence/root alignment is explicit; final origin alignment follows
from the requeue origin and the raw pending-payload contract. -/
structure AfterRetryLimitWindow
    {origin : Origin.Parsed}
    (exit : MptsyncRetryExecution.RetryLimitExit origin expected refused
      fetchMaximum retryLimit before after)
    (inputs : MptsyncScheduleExecution.StableScheduleInputs)
    (item : OriginSchedule.Item)
    (requeued : MptsyncRetryExecution.RequeuedAfterLimit exit inputs.contacts inputs.peer
      inputs.pending inputs.pendingLink inputs.pendingTarget item)
    (exitAt : Nat) (finalOrigin : String) (finalSeq : UInt64) (finalRoot : ByteArray)
    (requirements : FiniteRequirements publisher scope owner root)
    (states : Nat → State) where
  exitState : states exitAt = after
  observedAt : Nat
  afterExit : exitAt < observedAt
  finalOriginMatchesExit : finalOrigin = Origin.canonical origin
  sequence : (inputs.pendingTarget item).pointer.seq = finalSeq
  targetRoot : (inputs.pendingTarget item).pointer.root = finalRoot
  admit : ∀ round attempt,
    round < inputs.pendingRounds →
    attempt ∈ (inputs.pending.observation round).attempts →
    attempt.item = item →
    OriginScheduleExecution.FetchOpportunity (inputs.pendingTarget item) attempt →
    inputs.pendingLink.contactRound round < inputs.peerRounds →
    ∀ peerAttempt,
      peerAttempt ∈ (inputs.contacts.observation
        (inputs.pendingLink.contactRound round)).attempts →
      peerAttempt.peer = inputs.peer → peerAttempt.outcome = .success →
      ∃ later, observedAt ≤ later ∧
        ∃ actualTarget,
          TargetAligned (inputs.pendingTarget item) actualTarget scope owner root ∧
          AdmissionFor actualTarget requirements (states exitAt) (states later)

/-- The retry/requeue bridge constructs exactly the fresh response window
consumed by scheduled Fetch liveness. -/
def AfterRetryLimitWindow.next
    (window : AfterRetryLimitWindow exit inputs item requeued exitAt finalOrigin finalSeq finalRoot
      requirements states) :
    ResponseWindow exitAt finalOrigin finalSeq finalRoot requirements states where
  observedAt := window.observedAt
  afterDeficit := window.afterExit
  inputs := inputs
  item := item
  member := requeued.member
  admit := by
    intro round attempt before attempted same opportunity contactBefore peerAttempt
      peerAttempted samePeer success
    obtain ⟨later, afterWindow, actualTarget, aligned, admission⟩ :=
      window.admit round attempt before attempted same opportunity contactBefore peerAttempt
        peerAttempted samePeer success
    refine ⟨later, afterWindow, actualTarget, ?_, admission⟩
    refine ⟨?_, window.sequence, window.targetRoot, aligned⟩
    exact ((inputs.pendingPayloads.sameOrigin item requeued.member).trans
      requeued.sameOrigin).trans window.finalOriginMatchesExit.symm

/-- Consequently an actual retry-limit exit followed by its linked fresh M6
window yields a later ordinary authorized admission. -/
theorem AfterRetryLimitWindow.responds
    (window : AfterRetryLimitWindow exit inputs item requeued exitAt finalOrigin finalSeq finalRoot
      requirements states) :
    ∃ later, exitAt < later ∧
      AuthorizedFetchProgress.Admission requirements (states exitAt) (states later) := by
  exact ResponseWindow.responds window.next

end Synchronicity.ScheduledRetryAdmission
