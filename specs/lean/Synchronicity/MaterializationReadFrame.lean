import Synchronicity.MaterializationTableFrame
import Synchronicity.TrieDiffCoverage

/-! SQL materialization cannot change the immutable graph or the primitive
interpretation used while walking it. This is proved from actual requests. -/
namespace Synchronicity.MaterializationReadFrame
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase MaterializationTableFrame

def context (state : State) :=
  (state.db, state.files, state.byteRelations, state.hash, state.isNfc, state.validateKey)

theorem reply_context (state : State) (event : String) (action : State → Result (Reply A))
    (consume : Bool) (kept : ∀ s, context (action s).2 = context s) :
    context (reply state event action consume).2 = context state := by
  unfold reply
  split
  · cases consume
    · rfl
    · simpa only [context, record, ↓reduceIte] using kept state
  · simpa only [context, record] using kept state

theorem transaction_context (state : State) (tx : Transaction) (action : Database → A × Database) :
    context (SimulatedHost.transaction state tx action).2 = context state := by
  unfold SimulatedHost.transaction
  split
  · split <;> rfl
  · rfl

theorem storage_context (relation : String) (effect : Storage A) (safe : storageAllowed relation effect) (state : State) :
    context (storage effect state).2 = context state := by
  cases effect <;> simp only [storage]
  all_goals first | contradiction | (apply reply_context; intro s)
  all_goals first | exact transaction_context .. | rfl | (repeat' first | rfl | split)

theorem effects_context (relation : String) (effect : Materialize.Effects A) (safe : allowed relation _ effect) (state : State) :
    context (Interpreter.handle effect state).2 = context state := by
  cases effect with
  | left effect => exact storage_context relation effect safe state
  | right effect =>
    rcases effect with effect | effect
    · cases effect <;> apply reply_context <;> intro s <;> rfl
    · rcases effect with effect | effect
      · cases effect <;> simp only [Interpreter.handle, access]
        all_goals apply reply_context; intro s
        all_goals first | exact transaction_context .. | rfl
      · rcases effect with effect | effect
        · cases effect; apply reply_context; intro s; rfl
        · rcases effect with effect | effect
          · cases effect; apply reply_context; intro s; rfl
          · rcases effect with effect | effect
            · cases effect; apply reply_context; intro s; rfl
            · cases effect; apply reply_context; intro s; rfl

theorem executed_context (relation : String) (operation : Materialize.Action A) (safe : Safe relation operation)
    (state final : State) (result : Except Materialize.Error A)
    (ran : execute operation state = (result, final)) : context final = context state := by
  have kept := safe.preserves_observation context operation.run (effects_context relation) state
  change context (execute operation state).2 = context state at kept
  simpa only [ran] using kept

theorem readable_frame (relation : String) (state final : State)
    (services : context final = context state) (table : view relation final = view relation state) :
    readableBytes final relation = readableBytes state relation := by
  have fields := Prod.mk.inj services
  have files := Prod.mk.inj fields.2
  have relations := Prod.mk.inj files.2
  funext key
  unfold readableBytes readByteObject
  rw [fields.1, files.1, relations.1]
  by_cases relational : state.byteRelations.contains relation
  · simp only [relational, ↓reduceIte]
    cases before : state.pending <;> cases after : final.pending
    all_goals simp only [view, before, after, Option.map_none, Option.map_some] at table
    all_goals try first | contradiction | rfl
    rename_i beforeEntry afterEntry
    have same := (Prod.mk.inj (Option.some.inj table)).2
    simp only [Option.map_some, Option.getD_some, relationBytes]
    rw [same]
  · simp only [relational, Bool.false_eq_true, ↓reduceIte]

theorem apply_faithful (world : TrieDiffCoverage.World) (tx : Transaction) (origin : String)
    (now releaseNow : Int64) (replicas : List Materialize.Target) (key : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (state final : State) (result : Except Materialize.Error Unit)
    (faithful : TrieDiffCoverage.Faithful world state)
    (ran : execute (Materialize.apply tx origin now releaseNow replicas key kind value) state = (result, final)) :
    TrieDiffCoverage.Faithful world final := by
  have safe (relation : String) (relevant : relation = Trie.nodeSpace ∨ relation = Trie.valueSpace) :=
    apply_safe relation (by rcases relevant with rfl | rfl <;> decide) tx origin now releaseNow replicas key kind value
  have services := executed_context Trie.nodeSpace _ (safe _ (Or.inl rfl)) state final result ran
  refine ⟨?_, ?_⟩
  · intro relation hash bytes relevant held
    have table := executed_frame relation _ (safe relation relevant) state final result ran
    rw [readable_frame relation state final services table] at held
    exact faithful.1 relation hash bytes relevant held
  · have same := (Prod.mk.inj (Prod.mk.inj (Prod.mk.inj services).2).2).2
    exact (Prod.mk.inj same).1.trans faithful.2

end Synchronicity.MaterializationReadFrame
