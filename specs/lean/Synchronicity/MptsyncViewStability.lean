import Synchronicity.MptsyncConvergence

/-! Stability lemmas for the public convergence observation.

They use the same projection as M4.  Thus an unsuccessful or unfinished
promotion really preserves a correct view, while a ready replacement can be
chained with earlier forever-retention obligations.  These are domain lemmas;
the production-command connection remains `PromotionAtomicView`.
-/
namespace Synchronicity.MptsyncViewStability
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
  SimulatedHost MptsyncConvergence

private theorem projection_parts (origin : String) (before after : Database)
    (same : AtomicFileView.projection origin after = AtomicFileView.projection origin before) :
    rows after "entries" = rows before "entries" ∧
    rows after "pins" = rows before "pins" ∧
    rows after "content_want" = rows before "content_want" ∧
    (rows after "heads").filter (fun row => equals row
        [("origin_id", .text origin), ("slot", .text "complete")]) =
      (rows before "heads").filter (fun row => equals row
        [("origin_id", .text origin), ("slot", .text "complete")]) := by
  simpa only [AtomicFileView.projection, Prod.mk.injEq] using same

private theorem installed_of_complete_rows (head : Head) (before after : Database)
    (same : (rows after "heads").filter (fun row => equals row
        [("origin_id", .text (Origin.canonical head.origin)), ("slot", .text "complete")]) =
      (rows before "heads").filter (fun row => equals row
        [("origin_id", .text (Origin.canonical head.origin)), ("slot", .text "complete")]))
    (installed : AtomicFileView.Installed before head) :
    AtomicFileView.Installed after head := by
  let selected := fun row => equals row
    [("origin_id", .text (Origin.canonical head.origin)), ("slot", .text "complete")]
  constructor
  · obtain ⟨row, member, named⟩ := installed.1
    have filtered : row ∈ (rows before "heads").filter selected := by
      exact List.mem_filter.mpr ⟨member, named⟩
    rw [← same] at filtered
    exact ⟨row, (List.mem_filter.mp filtered).1, named⟩
  · intro row member named
    have filtered : row ∈ (rows after "heads").filter selected :=
      List.mem_filter.mpr ⟨member, named⟩
    rw [same] at filtered
    exact installed.2 row (List.mem_filter.mp filtered).1 named

/-- An M4 nonpublication projection preserves the entire convergence target:
selected version, exact file rows, current duties and historical forever
duties.  Unrelated tables may change. -/
theorem unchanged_preserves_correct (target : ViewTarget)
    (correct : CorrectView services origin target before)
    (same : AtomicFileView.projection (Origin.canonical origin) after =
      AtomicFileView.projection (Origin.canonical origin) before) :
    CorrectView services origin target after := by
  obtain ⟨entries, pins, wants, heads⟩ := projection_parts _ _ _ same
  refine ⟨correct.1, ?_, ?_, ?_, ?_⟩
  · have headOrigin := correct.1
    subst headOrigin
    exact installed_of_complete_rows target.head before after heads correct.2.1
  · simpa only [SnapshotViewProgress.ExactFiles, MaterializedView.Observed,
      MaterializedView.Address.table, entries] using correct.2.2.1
  · simpa only [MaterializedView.CurrentRequirements, MaterializationRetention.Required,
      entries, pins, wants] using correct.2.2.2.1
  · simpa only [MaterializedView.ForeverRequirements, MaterializationRetention.Required,
      pins, wants] using correct.2.2.2.2

/-- Forever obligations compose across successive ready publications. -/
theorem forever_trans
    (first : MaterializedView.ForeverRequirements replicas baseline middle)
    (second : MaterializedView.ForeverRequirements replicas middle after) :
    MaterializedView.ForeverRequirements replicas baseline after := by
  intro target member permanent root required
  exact second target member permanent root (first target member permanent root required)

/-- A ready M4 replacement for the stable target establishes the complete
public convergence observation.  No pre-existing correct file list is assumed;
only forever duties are chained from the stable baseline. -/
theorem ready_establishes_correct (target : ViewTarget)
    (priorForever : MaterializedView.ForeverRequirements target.replicas target.before before)
    (ready : AtomicFileView.Ready services target.snapshot origin target.scope
      target.replicas before after)
    (sameHead : ∀ head, head.origin = origin → AtomicFileView.Installed after head →
      head = target.head) :
    CorrectView services origin target after := by
  obtain ⟨head, headOrigin, installed, files, current, forever⟩ := ready
  have selected : head = target.head := sameHead head headOrigin installed
  subst head
  exact ⟨headOrigin, installed, files, current, forever_trans priorForever forever⟩

/-- One actual M4 abstract transition either retains an already-correct stable
view or installs the ready stable target.  `policy` fixes the post-settlement
scope and replica policy; version equality must come from selection/M3 and the
latest-valid upper bound, not from M4 itself. -/
theorem atomic_replacement_preserves_or_establishes
    (target : ViewTarget)
    (replacement : AtomicFileView.AtomicReplacement services target.snapshot origin
      (fun scope replicas => scope = target.scope ∧ replicas = target.replicas) before after)
    (sameHead : ∀ head, head.origin = origin → AtomicFileView.Installed after head →
      head = target.head)
    (previous : CorrectView services origin target before) :
    CorrectView services origin target after := by
  rcases replacement with unchanged | ⟨scope, replicas, policy, ready⟩
  · exact unchanged_preserves_correct target previous unchanged
  · obtain ⟨rfl, rfl⟩ := policy
    exact ready_establishes_correct target previous.2.2.2.2 ready sameHead

end Synchronicity.MptsyncViewStability
