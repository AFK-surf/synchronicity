import Synchronicity.PromotionReady

/-! The pre-existing view is aligned with the complete version actually read
from its database. This is an initial-state contract, never a post-publication
refinement assumption. Empty slots are represented by the empty trie root. -/
namespace Synchronicity.PromotionInitialView
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase

def ReadVersion (db : Database) (origin : Origin.Parsed) (root : ByteArray) : Prop :=
  ∃ tx state final old, state.pending = some (tx, db) ∧
    execute (Promote.slot tx origin "complete") state = (.ok old, final) ∧
    (old.map (·.head.root) |>.getD Trie.emptyRoot) = root

structure Initial (db : Database) (origin : Origin.Parsed) (world : TrieDiffCoverage.World)
    (services : MaterializedView.Services) : Prop where
  schema : MaterializationKeySchema.Schema db
  views : ∀ root, ReadVersion db origin root → ∀ scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas →
    MaterializationRequirementFrame.PoliciesAgree replicas ∧ MaterializedView.CurrentRequirements replicas db ∧
    SnapshotViewProgress.ExactFiles services world.snapshot root
      (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) db (Origin.canonical origin)
  unique : ∀ oldRoot newRoot, ReadVersion db origin oldRoot →
    MaterializedView.UniqueAddresses services (SnapshotViewProgress.Relevant world.snapshot oldRoot newRoot)
  supported : ∀ oldRoot newRoot, ReadVersion db origin oldRoot → ∀ scope replicas,
    MaterializationInputs.ReadPolicy db origin scope replicas → ∀ key,
    scope.admitsKeyPath (Trie.keyNibbles key) = true →
    SnapshotDelta.ChangedKey world.snapshot oldRoot newRoot key → key.size ≤ Trie.maxKeyBytes

theorem prepare_version (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority) (pending : Promote.Pending)
    (old : Option Promote.Pending)
    (ran : execute (PromotionCommand.prepare tx origin now) state = (.ok (scope, authority, some pending, old), final)) :
    ReadVersion db origin (old.map (·.head.root) |>.getD Trie.emptyRoot) := by
  unfold PromotionCommand.prepare at ran
  obtain ⟨scopeRead, scopeState, scopedRun, ran⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  obtain ⟨authorityRead, authorized, authorizedRun, ran⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  obtain ⟨pendingRead, selected, selectedRun, ran⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  cases pendingRead with
  | none => cases ran
  | some candidate =>
    obtain ⟨oldRead, read, readRun, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
    have same : (scopeRead, authorityRead, some candidate, oldRead) = (scope, authority, some pending, old) :=
      Except.ok.inj (congrArg Prod.fst returned)
    cases same
    have first := PromotionReads.executed_pending _
      (PromotionReads.auth_only _ (ReconciliationReadOnly.scope_only tx origin)) _ _ _ scopedRun
    have second := PromotionReads.executed_pending _
      (PromotionReads.auth_only _ (ReconciliationReadOnly.originAuthority_only tx origin now)) _ _ _ authorizedRun
    have third := PromotionReads.executed_pending _ (PromotionReads.slot_only tx origin "pending") _ _ _ selectedRun
    exact ⟨tx, selected, read, old, third.trans (second.trans (first.trans opened)), readRun, rfl⟩

end Synchronicity.PromotionInitialView
