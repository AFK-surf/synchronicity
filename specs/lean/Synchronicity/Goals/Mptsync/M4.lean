import Synchronicity.PromotionAtomicView

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

end Synchronicity.Goals.Mptsync.M4
