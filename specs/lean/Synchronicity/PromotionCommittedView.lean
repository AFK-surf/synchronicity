import Synchronicity.PromotionInitialView

/-! A successful production flip publishes the ready file view together with
the actual candidate pointer and its retention obligations, not merely a flag
claiming that traversal or completeness checking finished. -/
namespace Synchronicity.PromotionCommittedView
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands Replication SimulatedHost PrivateDatabase

theorem promote_ready (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state final : State) (report : PromotionReport)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (closed : state.pending = none) (faithful : TrieDiffCoverage.Faithful world state)
    (normalization : state.isNfc = services.nfc)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (initial : PromotionInitialView.Initial state.db origin world services)
    (flipped : report.promotion = .flipped)
    (ran : execute (Promote.promote origin now refused) state = (.ok report, final)) :
    ∃ scope replicas head, head.origin = origin ∧ MaterializationInputs.ReadPolicy state.db origin scope replicas ∧
      PromotionReady.Installed final.db head ∧
      SnapshotViewProgress.ExactFiles services world.snapshot head.root
        (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) final.db (Origin.canonical origin) ∧
      MaterializedView.CurrentRequirements replicas final.db ∧
      MaterializedView.ForeverRequirements replicas state.db final.db := by
  obtain ⟨tx, opened, ready, scope, authority, pending, old, staged, db,
    began, prepared, readyTx, _, published, _, stagedTx, committed, _⟩ :=
    PromotionPublication.promote_flipped origin now refused state final report flipped ran
  have rawBegin := OperationExecution.raise_success (fun _ _ => rfl) Promote.Error.host Storage.begin state opened tx began
  have openedTx := ReconciliationFloor.begin_pending state opened tx rawBegin
  have version := PromotionInitialView.prepare_version tx origin now opened ready state.db openedTx scope authority pending old prepared
  have primitives : PromotionServices.observation ready = PromotionServices.observation state :=
    (PromotionServices.executed_frame _ _ _ _ prepared).trans (PromotionServices.executed_frame _ _ _ _ began)
  have routing := (Prod.mk.inj (Prod.mk.inj primitives).2).2
  have readyFaithful : TrieDiffCoverage.Faithful world ready := by
    refine ⟨?_, (Prod.mk.inj primitives).1.trans faithful.2⟩
    intro relation key bytes relevant held
    have same : SimulatedHost.readableBytes ready relation key = SimulatedHost.readableBytes state relation key := by
      simp only [SimulatedHost.readableBytes, readByteObject, routing, relational relation relevant, ↓reduceIte,
        readyTx, closed, Option.map_some, Option.map_none, Option.getD_some, Option.getD_none]
    exact faithful.1 relation key bytes relevant (same ▸ held)
  have readyNfc : ready.isNfc = services.nfc := ((Prod.mk.inj (Prod.mk.inj primitives).2).1).trans normalization
  obtain ⟨actualScope, replicas, after, policy, afterTx, installed, files, current, forever⟩ :=
    PromotionReady.body_ready tx origin now pending old scope authority ready staged state.db world services readyTx readyFaithful readyNfc
      (by intro relation relevant; rw [routing]; exact relational relation relevant)
      (initial.unique _ _ version) (initial.supported _ _ version) initial.schema (initial.views _ version) published
  have same : after = db := congrArg Prod.snd (Option.some.inj (afterTx.symm.trans stagedTx))
  subst after
  rw [committed]
  exact ⟨actualScope, replicas, pending.head,
    PromotionExecution.prepare_origin tx origin now opened ready scope authority (some pending) old prepared pending rfl,
    policy, installed, files, current, forever⟩

end Synchronicity.PromotionCommittedView
