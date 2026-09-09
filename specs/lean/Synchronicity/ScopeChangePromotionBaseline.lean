import Synchronicity.ScopeChangeRefinement
import Synchronicity.PromotionBaseline
import Synchronicity.HeadView
import Synchronicity.GlobalReplicaPolicy

/-! Permission-change cleanup supplies the origin-local empty database facts
needed by the next promotion.  Schema, immutable-snapshot and materialization
service properties are independent host/metadata contracts: a scope change
does not establish them, and this bridge keeps them explicit. -/
namespace Synchronicity.ScopeChangePromotionBaseline
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
  SimulatedHost ScopeChangeRefinement

/-- Device-wide acquisition invariant at a raw database observation. Replica
targets come from the shared `replicas` table, so this is deliberately not a
claim about the cleaned origin's view. It is the initial-data obligation that
unrelated retained rows already have their required hold or durable want. -/
def GlobalRetentionInvariant (db : Database) : Prop :=
  ∃ replicas, GlobalReplicaPolicy.Holds db replicas ∧
    MaterializedView.CurrentRequirements replicas db

theorem GlobalRetentionInvariant.currentForRead
    (invariant : GlobalRetentionInvariant db)
    (read : MaterializationInputs.ReadPolicy db origin scope replicas) :
    MaterializedView.CurrentRequirements replicas db := by
  obtain ⟨canonical, policy, current⟩ := invariant
  rw [policy.unique origin scope replicas read]
  exact current

/-- Stable metadata and host-service contracts not created by clearing one
origin's scope-dependent state.  In particular, neither complete-slot nor
entry absence is assumed here. -/
structure MetadataContracts (db : Database) (origin : Origin.Parsed)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services) : Prop where
  schema : MaterializationKeySchema.Schema db
  emptySnapshot : ∀ key bytes,
    ¬ TrieSnapshotProofs.Entry world.snapshot Trie.emptyRoot key bytes
  policiesAgree : ∀ scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas →
      MaterializationRequirementFrame.PoliciesAgree replicas
  globalRetention : GlobalRetentionInvariant db
  unique : ∀ newRoot,
    MaterializedView.UniqueAddresses services
      (SnapshotViewProgress.Relevant world.snapshot Trie.emptyRoot newRoot)
  supported : ∀ newRoot scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas → ∀ key,
      scope.admitsKeyPath (Trie.keyNibbles key) = true →
      SnapshotDelta.ChangedKey world.snapshot Trie.emptyRoot newRoot key →
      key.size ≤ Trie.maxKeyBytes

private theorem no_joined_slot_of_raw_empty (db : Database) (origin slot : String)
    (empty : query db "heads"
      ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
      [("origin_id", .text origin), ("slot", .text slot)] [] [] = []) :
    query db "heads" History.headColumns
      [("origin_id", .text origin), ("slot", .text slot)] [] History.headJoin = [] := by
  rw [ReconciliationRead.slot_query]
  apply List.map_eq_nil_iff.mpr
  apply List.filter_eq_nil_iff.mpr
  intro joined joinedMember
  obtain ⟨row, rowMember, joinedMember⟩ := List.mem_flatMap.mp joinedMember
  obtain ⟨history, _, rfl⟩ := List.mem_map.mp joinedMember
  rw [ReconciliationRead.joined_names]
  have rawRows :
      ((rows db "heads").filter fun candidate =>
        equals candidate [("origin_id", .text origin), ("slot", .text slot)]).map
          (project ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]) = [] := by
    rw [← SimulatedHost.unordered_query]
    exact empty
  have filtered :
      (rows db "heads").filter (fun candidate =>
        equals candidate [("origin_id", .text origin), ("slot", .text slot)]) = [] :=
    List.map_eq_nil_iff.mp rawRows
  intro selectedTrue
  have present : row ∈ (rows db "heads").filter (fun candidate =>
      equals candidate [("origin_id", .text origin), ("slot", .text slot)]) := by
    exact List.mem_filter.mpr ⟨rowMember, selectedTrue⟩
  rw [filtered] at present
  exact List.not_mem_nil present

private theorem no_selected_complete_of_raw_empty (db : Database) (origin : String)
    (empty : query db "heads"
      ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
      [("origin_id", .text origin), ("slot", .text "complete")] [] [] = []) :
    ¬ ∃ row, HeadView.Selected db origin .complete row := by
  have rawRows :
      ((rows db "heads").filter fun candidate =>
        equals candidate [("origin_id", .text origin), ("slot", .text "complete")]).map
          (project ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]) =
        [] := by
    rw [← SimulatedHost.unordered_query]
    exact empty
  have filtered :
      (rows db "heads").filter (fun candidate =>
        equals candidate [("origin_id", .text origin), ("slot", .text "complete")]) = [] :=
    List.map_eq_nil_iff.mp rawRows
  rintro ⟨row, member, named⟩
  have present : row ∈ (rows db "heads").filter (fun candidate =>
      equals candidate [("origin_id", .text origin), ("slot", .text "complete")]) := by
    exact List.mem_filter.mpr ⟨member, named⟩
  rw [filtered] at present
  exact List.not_mem_nil present

/-- The two origin-local absence facts established by an actual committed
scope change, exposed separately so later real acceptance/retry frames can
transport them to promotion time. -/
theorem invalidated_absence
    (raw : ScopeChangeRefinement.RawInvalidated decision now db)
    (originAligned : decision.complete.origin = Origin.canonical origin) :
    (¬ ∃ row, HeadView.Selected db (Origin.canonical origin) .complete row) ∧
      (rows db "entries").any
        (fun row => equals row [("origin_id", .text (Origin.canonical origin))]) = false := by
  rcases raw with ⟨⟨noComplete, _, noEntries, _, _⟩, _⟩
  constructor
  · rw [← originAligned]
    exact no_selected_complete_of_raw_empty db decision.complete.origin noComplete
  · rwa [← originAligned]

private theorem no_origin_entries
    (absent : (rows db "entries").any
      (fun row => equals row [("origin_id", .text origin)]) = false) :
    ∀ space path values,
      ¬ MaterializedView.Observed db origin (.file space path) values := by
  intro space path values observed
  obtain ⟨row, member, selected, _⟩ := observed
  have originAbsent := List.any_eq_false.mp absent row member
  simp only [MaterializedView.Address.key, SimulatedHost.equals, List.all_cons, List.all_nil,
    Bool.and_true, Bool.and_eq_true] at selected
  have originSelected : equals row [("origin_id", .text origin)] = true := by
    simpa [SimulatedHost.equals] using selected.1
  rw [originSelected] at originAbsent
  contradiction

private theorem no_complete_query_of_absence
    (absent : ¬ ∃ row, HeadView.Selected db (Origin.canonical origin) .complete row) :
    query db "heads" History.headColumns
      [("origin_id", .text (Origin.canonical origin)), ("slot", .text "complete")]
      [] History.headJoin = [] := by
  rw [ReconciliationRead.slot_query]
  apply List.map_eq_nil_iff.mpr
  apply List.filter_eq_nil_iff.mpr
  intro joined joinedMember
  obtain ⟨row, rowMember, joinedMember⟩ := List.mem_flatMap.mp joinedMember
  obtain ⟨history, _, rfl⟩ := List.mem_map.mp joinedMember
  rw [ReconciliationRead.joined_names]
  intro named
  exact absent ⟨row, rowMember, named⟩

/-- Origin-local raw absence at a later actual observation is sufficient for
the same empty-view baseline as scope cleanup. The caller must derive these
two absence facts from the intervening production executions. -/
theorem clean_origin_baseline_of_absence
    (completeAbsent : ¬ ∃ row,
      HeadView.Selected db (Origin.canonical origin) .complete row)
    (entriesAbsent : (rows db "entries").any
      (fun row => equals row [("origin_id", .text (Origin.canonical origin))]) = false)
    (metadata : MetadataContracts db origin world services) :
    PromotionBaseline.CleanOriginBaseline db origin world services := by
  exact
    { schema := metadata.schema
      noComplete := no_complete_query_of_absence completeAbsent
      noEntries := no_origin_entries entriesAbsent
      emptySnapshot := metadata.emptySnapshot
      policiesAgree := metadata.policiesAgree
      current := fun _ _ read => metadata.globalRetention.currentForRead read
      unique := metadata.unique
      supported := metadata.supported }

/-- The actual committed M8 cleanup, aligned with its typed decision origin,
provides the two database-absence fields of the promotion baseline.  All
remaining fields come from the explicit independent metadata contracts. -/
theorem clean_origin_baseline
    (raw : ScopeChangeRefinement.RawInvalidated decision now db)
    (originAligned : decision.complete.origin = Origin.canonical origin)
    (metadata : MetadataContracts db origin world services) :
    PromotionBaseline.CleanOriginBaseline db origin world services := by
  rcases raw with ⟨⟨noComplete, _, noEntries, _, _⟩, _⟩
  refine ⟨metadata.schema, ?_, ?_, metadata.emptySnapshot, metadata.policiesAgree,
    (fun _ _ read => metadata.globalRetention.currentForRead read),
      metadata.unique, metadata.supported⟩
  · rw [← originAligned]
    exact no_joined_slot_of_raw_empty db decision.complete.origin "complete" noComplete
  · rw [← originAligned]
    exact no_origin_entries noEntries

end Synchronicity.ScopeChangePromotionBaseline
