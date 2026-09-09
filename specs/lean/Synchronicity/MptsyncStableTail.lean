import Synchronicity.MptsyncViewStability
import Synchronicity.ReconciliationExecution

/-! Operation-independent composition for a stable production tail.  The
actual event trace contains only `ReconciliationExecution.Step` witnesses;
public-view refinement is proved separately and is never a constructor field. -/
namespace Synchronicity.MptsyncStableTail
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost
  ReconciliationExecution MptsyncConvergence

/-- The materialized payload and retention tables are unchanged. Head-slot
stability is established independently through M3. -/
def PayloadFrame (before after : Database) : Prop :=
  rows after "entries" = rows before "entries" ∧
  rows after "pins" = rows before "pins" ∧
  rows after "content_want" = rows before "content_want"

/-- Cross-origin publication contract. The production SQL must leave this
origin's file observations unchanged, while the foreign M4 ready view (under
the same device replica policy) re-establishes global current and forever
retention duties. This is deliberately field-level, not `CorrectView`. -/
structure ForeignFrame (origin : Origin.Parsed) (target : ViewTarget)
    (before after : Database) : Prop where
  files : ∀ space path values,
    MaterializedView.Observed after (Origin.canonical origin) (.file space path) values ↔
      MaterializedView.Observed before (Origin.canonical origin) (.file space path) values
  current : MaterializedView.CurrentRequirements target.replicas after
  forever : MaterializedView.ForeverRequirements target.replicas before after

/-- One public observation either remains byte-for-byte unchanged, or is an
M4-ready replacement for exactly the stable target. The final installed-head
condition is the version-selection fact supplied by M2/M3. -/
def Refines (services : MaterializedView.Services) (origin : Origin.Parsed)
    (target : ViewTarget) (before after : Database) : Prop :=
  AtomicFileView.projection (Origin.canonical origin) after =
      AtomicFileView.projection (Origin.canonical origin) before ∨
    (AtomicFileView.Ready services target.snapshot origin target.scope target.replicas before after ∧
      ∀ head, head.origin = origin → AtomicFileView.Installed after head →
        head.seq = target.head.seq ∧ head.root = target.head.root) ∨
    PayloadFrame before after ∧ AtomicFileView.Installed after target.head ∨
    ForeignFrame origin target before after ∧ AtomicFileView.Installed after target.head

theorem refines_preserves (step : Refines services origin target before after)
    (correct : CorrectView services origin target before) :
    CorrectView services origin target after := by
  rcases step with unchanged | replacement
  · exact MptsyncViewStability.unchanged_preserves_correct target correct unchanged
  · rcases replacement with ⟨ready, selected⟩ | ⟨frame, installed⟩ | ⟨frame, installed⟩
    · obtain ⟨head, headOrigin, installed, files, current, forever⟩ := ready
      obtain ⟨sameSeq, sameRoot⟩ := selected head headOrigin installed
      have targetOrigin := correct.1
      have targetInstalled : AtomicFileView.Installed after target.head := by
        constructor
        · simpa only [targetOrigin, headOrigin] using installed.1
        · intro row member named
          have points := installed.2 row member (by simpa only [targetOrigin, headOrigin] using named)
          simpa only [sameSeq, sameRoot] using points
      refine ⟨targetOrigin, targetInstalled, ?_, current,
        MptsyncViewStability.forever_trans correct.2.2.2.2 forever⟩
      change SnapshotViewProgress.ExactFiles services target.snapshot target.head.root
        (fun key => target.scope.admitsKeyPath (Trie.keyNibbles key) = true) after
        (Origin.canonical origin)
      rw [← sameRoot]
      exact files
    · obtain ⟨entries, pins, wants⟩ := frame
      refine ⟨correct.1, installed, ?_, ?_, ?_⟩
      · simpa only [SnapshotViewProgress.ExactFiles, MaterializedView.Observed,
          MaterializedView.Address.table, entries] using correct.2.2.1
      · simpa only [MaterializedView.CurrentRequirements,
          MaterializationRetention.Required, entries, pins, wants] using correct.2.2.2.1
      · simpa only [MaterializedView.ForeverRequirements,
          MaterializationRetention.Required, pins, wants] using correct.2.2.2.2
    · refine ⟨correct.1, installed, ?_, frame.current,
        MptsyncViewStability.forever_trans correct.2.2.2.2 frame.forever⟩
      intro space path values
      rw [frame.files]
      exact correct.2.2.1 space path values

/-- An infinite production trace. Its constructor stores only actual step
facts, without stability, readiness, projection or correctness assumptions. -/
structure Trace where
  state : Nat → State
  event : Nat → Event
  step : ∀ now, Step (event now) (state now) (state (now + 1))

def RefinedFrom (trace : Trace) (services : MaterializedView.Services)
    (origin : Origin.Parsed) (target : ViewTarget) (start : Nat) : Prop :=
  ∀ now, start ≤ now → Refines services origin target
    (trace.state now).db (trace.state (now + 1)).db

/-- Once one actual observation is correct, separately established refinement
of every later actual production step yields the required always-stable tail. -/
theorem eventuallyAlways_of_refined_actual_tail (trace : Trace)
    (services : MaterializedView.Services) (origin : Origin.Parsed) (target : ViewTarget)
    (start : Nat) (reached : CorrectView services origin target (trace.state start).db)
    (refined : RefinedFrom trace services origin target start) :
    EventuallyAlways fun now => CorrectView services origin target (trace.state now).db := by
  apply eventuallyAlways_of_reached_and_preserved reached
  intro now after correct
  exact refines_preserves (refined now after) correct

end Synchronicity.MptsyncStableTail
