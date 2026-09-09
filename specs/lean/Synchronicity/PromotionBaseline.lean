import Synchronicity.PromotionInitialView

/-! A first promotion need not assume an already-correct old directory view.
An empty committed database and an empty-root snapshot establish that initial
view directly.  Policy, key-format and future-root facts remain explicit
independent contracts. -/
namespace Synchronicity.PromotionBaseline
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
  SimulatedHost PrivateDatabase

/-- Factual fresh-database contracts sufficient for the first promotion.
`emptySnapshot` describes the publisher's immutable empty root; it is not a
claim that a later candidate is complete or publishable. -/
structure CleanBaseline (db : Database) (origin : Origin.Parsed)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services) : Prop where
  schema : MaterializationKeySchema.Schema db
  noHeads : rows db "heads" = []
  noEntries : rows db "entries" = []
  emptySnapshot : ∀ key bytes,
    ¬ TrieSnapshotProofs.Entry world.snapshot Trie.emptyRoot key bytes
  policiesAgree : ∀ scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas →
      MaterializationRequirementFrame.PoliciesAgree replicas
  unique : ∀ newRoot,
    MaterializedView.UniqueAddresses services
      (SnapshotViewProgress.Relevant world.snapshot Trie.emptyRoot newRoot)
  supported : ∀ newRoot scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas → ∀ key,
      scope.admitsKeyPath (Trie.keyNibbles key) = true →
      SnapshotDelta.ChangedKey world.snapshot Trie.emptyRoot newRoot key →
      key.size ≤ Trie.maxKeyBytes

/-- A reset baseline is local to one origin. Other origins may retain heads
and materialized entries. `noComplete` is stated as the exact production SQL
observation, while `noEntries` excludes only this origin's public file rows.
Requirements of unrelated rows remain an explicit metadata contract. -/
structure CleanOriginBaseline (db : Database) (origin : Origin.Parsed)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services) : Prop where
  schema : MaterializationKeySchema.Schema db
  noComplete : query db "heads" History.headColumns
    [("origin_id", .text (Origin.canonical origin)), ("slot", .text "complete")]
    [] History.headJoin = []
  noEntries : ∀ space path values,
    ¬ MaterializedView.Observed db (Origin.canonical origin) (.file space path) values
  emptySnapshot : ∀ key bytes,
    ¬ TrieSnapshotProofs.Entry world.snapshot Trie.emptyRoot key bytes
  policiesAgree : ∀ scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas →
      MaterializationRequirementFrame.PoliciesAgree replicas
  current : ∀ scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas →
      MaterializedView.CurrentRequirements replicas db
  unique : ∀ newRoot,
    MaterializedView.UniqueAddresses services
      (SnapshotViewProgress.Relevant world.snapshot Trie.emptyRoot newRoot)
  supported : ∀ newRoot scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas → ∀ key,
      scope.admitsKeyPath (Trie.keyNibbles key) = true →
      SnapshotDelta.ChangedKey world.snapshot Trie.emptyRoot newRoot key →
      key.size ≤ Trie.maxKeyBytes

private theorem read_version_empty_of_query
    (noComplete : query db "heads" History.headColumns
      [("origin_id", .text (Origin.canonical origin)), ("slot", .text "complete")]
      [] History.headJoin = [])
    (read : PromotionInitialView.ReadVersion db origin root) :
    root = Trie.emptyRoot := by
  obtain ⟨tx, state, final, old, opened, ran, rootEq⟩ := read
  have succeeded := congrArg Prod.fst ran
  unfold Promote.slot at succeeded
  obtain ⟨scan, scanned, scanRun, succeeded⟩ :=
    TrieServePrivacyProofs.bind_ok _ _ _ _ succeeded
  have scanRows := PromotionReads.scan_rows tx db state opened origin "complete" scan
    (congrArg Prod.fst scanRun)
  have empty : scan.rows = [] := scanRows.trans noComplete
  split at succeeded
  · split at succeeded
    · cases succeeded
    · have oldNone : old = none := (Except.ok.inj succeeded).symm
      subst old
      simpa only [Option.map_none, Option.getD_none] using rootEq.symm
  · rename_i row rest nonempty
    rw [empty] at nonempty
    cases nonempty

/-- An actual complete-slot read over a fresh heads table selects the empty
root.  This connects the raw production read to the baseline; it is not an
abstract assumption about `ReadVersion`. -/
theorem read_version_empty (clean : CleanBaseline db origin world services)
    (read : PromotionInitialView.ReadVersion db origin root) :
    root = Trie.emptyRoot := by
  have queryEmpty : query db "heads" History.headColumns
      [("origin_id", .text (Origin.canonical origin)), ("slot", .text "complete")]
      [] History.headJoin = [] := by
    rw [ReconciliationRead.slot_query, clean.noHeads]
    rfl
  exact read_version_empty_of_query queryEmpty read

theorem read_version_empty_origin
    (clean : CleanOriginBaseline db origin world services)
    (read : PromotionInitialView.ReadVersion db origin root) :
    root = Trie.emptyRoot :=
  read_version_empty_of_query clean.noComplete read

private theorem exact_empty (clean : CleanBaseline db origin world services)
    (scope : Trie.Serve.Scope) :
    SnapshotViewProgress.ExactFiles services world.snapshot Trie.emptyRoot
      (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true)
      db (Origin.canonical origin) := by
  intro space path values
  constructor
  · rintro ⟨row, member, _, _⟩
    change row ∈ rows db "entries" at member
    rw [clean.noEntries] at member
    cases member
  · rintro ⟨key, bytes, _, entry, _, _⟩
    exact False.elim (clean.emptySnapshot key bytes entry)

private theorem current_empty (clean : CleanBaseline db origin world services)
    (replicas : List Materialize.Target) :
    MaterializedView.CurrentRequirements replicas db := by
  intro target targetMember row rowMember
  rw [clean.noEntries] at rowMember
  cases rowMember

/-- A clean first-use database supplies the entire old-view premise consumed
by the production promotion correctness theorem. -/
theorem initial (clean : CleanBaseline db origin world services) :
    PromotionInitialView.Initial db origin world services := by
  refine ⟨clean.schema, ?_, ?_, ?_⟩
  · intro root read scope replicas policy
    have rootEmpty := read_version_empty clean read
    subst root
    refine ⟨clean.policiesAgree scope replicas policy, current_empty clean replicas,
      exact_empty clean scope⟩
  · intro oldRoot newRoot read
    have rootEmpty := read_version_empty clean read
    subst oldRoot
    exact clean.unique newRoot
  · intro oldRoot newRoot read scope replicas policy key admitted changed
    have rootEmpty := read_version_empty clean read
    subst oldRoot
    exact clean.supported newRoot scope replicas policy key admitted changed

/-- Per-origin cleanup plus the independent metadata contracts establishes the
same first-promotion premise without requiring an otherwise empty database. -/
theorem initial_origin (clean : CleanOriginBaseline db origin world services) :
    PromotionInitialView.Initial db origin world services := by
  refine ⟨clean.schema, ?_, ?_, ?_⟩
  · intro root read scope replicas policy
    have rootEmpty := read_version_empty_origin clean read
    subst root
    refine ⟨clean.policiesAgree scope replicas policy, clean.current scope replicas policy, ?_⟩
    intro space path values
    constructor
    · intro observed
      exact False.elim (clean.noEntries space path values observed)
    · rintro ⟨key, bytes, _, entry, _, _⟩
      exact False.elim (clean.emptySnapshot key bytes entry)
  · intro oldRoot newRoot read
    have rootEmpty := read_version_empty_origin clean read
    subst oldRoot
    exact clean.unique newRoot
  · intro oldRoot newRoot read scope replicas policy key admitted changed
    have rootEmpty := read_version_empty_origin clean read
    subst oldRoot
    exact clean.supported newRoot scope replicas policy key admitted changed

end Synchronicity.PromotionBaseline
