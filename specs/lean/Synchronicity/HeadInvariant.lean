import Synchronicity.MaterializationPrivate

/-! Lifting an independently stated heads-table invariant through raw
transactions. This is proof composition over the existing host semantics. -/
namespace Synchronicity.HeadInvariant
open VerifiedCore.Host SimulatedHost PrivateDatabase

def holds (predicate : List Fields → Prop) (state : State) : Prop :=
  predicate (rows state.db "heads") ∧
    ∀ tx db, state.pending = some (tx, db) → predicate (rows db "heads")

theorem closed (predicate : List Fields → Prop) (state : State) (noTransaction : state.pending = none)
    (initial : predicate (rows state.db "heads")) : holds predicate state := by
  refine ⟨initial, ?_⟩
  intro tx db opened
  rw [noTransaction] at opened
  cases opened

theorem unchanged (predicate : List Fields → Prop) (before after : State)
    (committed : rows after.db "heads" = rows before.db "heads")
    (staged : ReconciliationFrame.heads after = ReconciliationFrame.heads before)
    (initial : holds predicate before) : holds predicate after := by
  refine ⟨by rw [committed]; exact initial.1, ?_⟩
  intro tx db opened
  unfold ReconciliationFrame.heads at staged
  rw [opened] at staged
  cases pending : before.pending with
  | none => simp [pending] at staged
  | some pair =>
    obtain ⟨token, old⟩ := pair
    have same : tx = token ∧ rows db "heads" = rows old "heads" := by simpa [pending] using staged
    rw [same.2]
    exact initial.2 token old pending

theorem reply_holds (predicate : List Fields → Prop) (state : State) (event : String)
    (action : State → Result (Reply A)) (consume : Bool)
    (safe : ∀ s, holds predicate s → holds predicate (action s).2) (initial : holds predicate state) :
    holds predicate (reply state event action consume).2 := by
  unfold reply
  split
  · cases consume
    · exact initial
    · exact safe state initial
  · exact safe state initial

theorem transaction_holds (predicate : List Fields → Prop) (state : State) (tx : Transaction)
    (action : Database → A × Database)
    (safe : ∀ db, predicate (rows db "heads") → predicate (rows (action db).2 "heads"))
    (initial : holds predicate state) : holds predicate (SimulatedHost.transaction state tx action).2 := by
  unfold SimulatedHost.transaction
  split
  · rename_i token db opened
    split
    · refine ⟨initial.1, ?_⟩
      intro next staged same
      have same : token = next ∧ (action db).2 = staged := by simpa using same
      rw [← same.2]
      exact safe db (initial.2 token db opened)
    · exact initial
  · exact initial

theorem begin_holds (predicate : List Fields → Prop) (state : State) (initial : holds predicate state) :
    holds predicate (storage .begin state).2 := by
  apply reply_holds _ _ _ _ _ _ initial
  intro s h
  split
  · exact h
  · refine ⟨h.1, ?_⟩
    intro tx db same
    have same : s.nextTx = tx ∧ s.db = db := by simpa using same
    rw [← same.2]
    exact h.1

theorem commit_holds (predicate : List Fields → Prop) (tx : Transaction) (state : State)
    (initial : holds predicate state) : holds predicate (storage (.commit tx) state).2 := by
  apply reply_holds _ _ _ _ _ _ initial
  intro s h
  split
  · rename_i token db opened
    split
    · refine ⟨h.2 token db opened, ?_⟩
      intro next staged impossible
      cases impossible
    · exact h
  · exact h

theorem rollback_holds (predicate : List Fields → Prop) (tx : Transaction) (state : State)
    (initial : holds predicate state) : holds predicate (storage (.rollback tx) state).2 := by
  apply reply_holds _ _ _ _ _ _ initial
  intro s h
  split
  · split
    · refine ⟨h.1, ?_⟩
      intro next staged impossible
      cases impossible
    · exact h
  · exact h

def effectSafe [Interpreter E] (predicate : List Fields → Prop) (A : Type) (effect : E A) : Prop :=
  ∀ state, holds predicate state → holds predicate (Interpreter.handle effect state).2

theorem materialize_effect (predicate : List Fields → Prop) (effect : VerifiedCore.Replication.Materialize.Effects A)
    (safe : MaterializationPrivate.allowed _ effect) : effectSafe predicate _ effect := by
  intro state initial
  apply unchanged _ state _ _ (MaterializationPrivate.effects_preserve_heads effect safe state) initial
  rw [MaterializationPrivate.effects_preserve_db effect safe state]

end Synchronicity.HeadInvariant
