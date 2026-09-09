import Synchronicity.PromotionViewFrame

/-! Host primitive meanings and relational byte-store routing are stable
through the real promotion effects, independently of SQL contents or faults. -/
namespace Synchronicity.PromotionServices
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase

def observation (state : State) := (state.hash, state.isNfc, state.byteRelations)

theorem reply_frame (state : State) (event : String) (action : State → Result (Reply A))
    (consume : Bool) (kept : ∀ s, observation (action s).2 = observation s) :
    observation (reply state event action consume).2 = observation state := by
  unfold reply
  split
  · cases consume
    · rfl
    · simpa only [observation, record, ↓reduceIte] using kept state
  · simpa only [observation, record] using kept state

theorem transaction_frame (state : State) (tx : Transaction) (action : Database → A × Database) :
    observation (SimulatedHost.transaction state tx action).2 = observation state := by
  unfold SimulatedHost.transaction
  split
  · split <;> rfl
  · rfl

theorem storage_frame (effect : Storage A) (state : State) :
    observation (storage effect state).2 = observation state := by
  cases effect <;> simp only [storage]
  all_goals apply reply_frame; intro s
  all_goals first | exact transaction_frame .. | rfl | (repeat' first | rfl | split)

theorem effects_frame (effect : Promote.Effects A) (state : State) :
    observation (Interpreter.handle effect state).2 = observation state := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => exact storage_frame effect state
    | right effect =>
      rcases effect with effect | effect
      · cases effect <;> apply reply_frame <;> intro s <;> rfl
      · rcases effect with effect | effect
        · cases effect <;> simp only [Interpreter.handle, access]
          all_goals apply reply_frame; intro s
          all_goals first | exact transaction_frame .. | rfl
        · rcases effect with effect | effect
          · cases effect; apply reply_frame; intro s; rfl
          · rcases effect with effect | effect
            · cases effect; apply reply_frame; intro s; rfl
            · rcases effect with effect | effect
              · cases effect; apply reply_frame; intro s; rfl
              · cases effect; apply reply_frame; intro s; rfl
  | right effect => cases effect <;> apply reply_frame <;> intro s <;> rfl

theorem program_frame (program : Program Promote.Effects A) (state : State) :
    observation (execute program state).2 = observation state := by
  induction program generalizing state with
  | pure _ => rfl
  | request effect resume ih =>
    exact (ih _ _).trans (effects_frame effect state)

theorem executed_frame (operation : Promote.Action A) (state final : State) (answer : A)
    (ran : execute operation state = (.ok answer, final)) : observation final = observation state := by
  have same := program_frame operation.run state
  change observation (execute operation state).2 = observation state at same
  simpa only [ran] using same

theorem relational_faithful (world : TrieDiffCoverage.World) (tx : Transaction)
    (state final : State) (before after : Database)
    (opened : state.pending = some (tx, before)) (staged : final.pending = some (tx, after))
    (same : observation final = observation state)
    (relational : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      state.byteRelations.contains relation = true)
    (tables : ∀ relation, relation = Trie.nodeSpace ∨ relation = Trie.valueSpace →
      rows after relation = rows before relation)
    (faithful : TrieDiffCoverage.Faithful world state) : TrieDiffCoverage.Faithful world final := by
  obtain ⟨hash, rest⟩ := Prod.mk.inj same
  have routing := (Prod.mk.inj rest).2
  refine ⟨?_, hash.trans faithful.2⟩
  intro relation key bytes relevant held
  have frame : SimulatedHost.readableBytes final relation key = SimulatedHost.readableBytes state relation key := by
    simp only [SimulatedHost.readableBytes, readByteObject, routing, relational relation relevant, ↓reduceIte,
      staged, opened, Option.map_some, Option.getD_some, relationBytes, tables relation relevant]
  exact faithful.1 relation key bytes relevant (frame ▸ held)

end Synchronicity.PromotionServices
