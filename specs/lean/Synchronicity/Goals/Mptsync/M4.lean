import Synchronicity.PromotionAtomicView
import Synchronicity.PromotionProgress
import Synchronicity.MptsyncConvergence

/-! # M4 — a new file list replaces the old one only when ready

The property is the operation-independent AtomicFileView relation, not a bundle
of component theorems. The real producer of received-version replacements is
Promote.promote, also used by fresh post-fetch promotion attempts. Every finite
primitive prefix is covered, including stops inside a transaction, all failure
paths and pending retirement after a refusal.

Initial aligns the old list with the version actually read from its raw complete
slot and with the actual fixed config/replica policy. It also states key-schema,
canonical-address and supported-key contracts. World carries finite immutable
image/hash assumptions; faithful relational reads, Unicode semantics and the
exclusive native transaction/commit boundary remain explicit host contracts.
These are initial-data/host assumptions, not assumed successful stream results
or ready publications. Policy-change rebuilding is M8; this theorem does not
verify Rust local publication, repair orchestration or the SQLite scheduler.
-/
namespace Synchronicity.Goals.Mptsync.M4
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands Replication SimulatedHost PrivateDatabase
open MptsyncConvergence

/-- The public version, exact permitted file list and current/forever content
obligations remain the old view or become one ready new view atomically. -/
def Safety (services : MaterializedView.Services) (snapshot : TrieProgramProofs.RawSnapshot)
    (origin : Origin.Parsed) (policies : Trie.Serve.Scope → List Materialize.Target → Prop)
    (before after : Database) : Prop := AtomicFileView.AtomicReplacement services snapshot origin policies before after

/-- **M4.** Every observation of an actual received-version promotion refines
the same atomic ready-view relation. No successful-return or readiness premise
filters the execution; arbitrary host faults and unfinished prefixes remain. -/
theorem safety (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
    (state final : State) (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (closed : state.pending = none) (faithful : TrieDiffCoverage.Faithful world state)
    (normalization : state.isNfc = services.nfc)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (initial : PromotionInitialView.Initial state.db origin world services)
    (tail : Program Promote.Effects (Except Promote.Error PromotionReport))
    (path : Prefix (Promote.promote origin now refused).run state tail final) :
    Safety services world.snapshot origin (MaterializationInputs.ReadPolicy state.db origin) state.db final.db :=
  PromotionAtomicView.prefix_refines origin now refused state final world services closed faithful normalization relational initial tail path

/-- The concrete target published by a healthy invocation. Its head and scope
are the values returned by the production preparation read; its replicas are
the uniquely matching policy read used by the production materializer. -/
def PromotionTarget (state : State) (world : TrieDiffCoverage.World)
    (ready : PromotionProgress.Ready origin now refused state) : ViewTarget :=
  { head := ready.pending.head
    snapshot := world.snapshot
    scope := ready.scope
    replicas := ready.replicas
    before := state.db }

/-- Field-level alignment is sufficient to identify the concrete promotion
target with a scenario target extensionally. -/
theorem promotionTarget_eq (ready : PromotionProgress.Ready origin now refused state)
    (world : TrieDiffCoverage.World) (target : ViewTarget)
    (head : target.head = ready.pending.head) (snapshot : target.snapshot = world.snapshot)
    (scope : target.scope = ready.scope) (replicas : target.replicas = ready.replicas)
    (before : target.before = state.db) :
    PromotionTarget state world ready = target := by
  cases target
  simp_all only [PromotionTarget]

/-- Positive M4 reachability observes both the actual flipped report and the
fully correct concrete view selected by that invocation. -/
def Progress (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state : State)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (ready : PromotionProgress.Ready origin now refused state) : Prop :=
  execute (Promote.promote origin now refused) state =
      (.ok ⟨.flipped, none, none⟩, ready.final) ∧
    CorrectView services origin (PromotionTarget state world ready) ready.final.db

/-- **M4 progress.** Under explicit healthy preparation, executable content
completeness, unrestricted publication authority, materializer and commit
contracts, the production promotion flips and establishes its exact permitted
`CorrectView`. No flipped report is assumed. -/
theorem progress (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state : State)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (ready : PromotionProgress.Ready origin now refused state)
    (closed : state.pending = none) (faithful : TrieDiffCoverage.Faithful world state)
    (normalization : state.isNfc = services.nfc)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (initial : PromotionInitialView.Initial state.db origin world services) :
    Progress origin now refused state world services ready := by
  refine ⟨PromotionProgress.promotes ready, ?_⟩
  obtain ⟨sameOrigin, _, installed, files, current, forever⟩ :=
    PromotionProgress.promotes_ready_view ready world services closed faithful normalization
      relational initial
  refine ⟨sameOrigin, installed, ?_, current, forever⟩
  change SnapshotViewProgress.ExactFiles services world.snapshot ready.pending.head.root
    (fun key => ready.scope.admitsKeyPath (Trie.keyNibbles key) = true)
    ready.final.db (Origin.canonical origin)
  exact files

end Synchronicity.Goals.Mptsync.M4
