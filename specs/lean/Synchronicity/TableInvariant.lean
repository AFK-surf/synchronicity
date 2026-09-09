import Synchronicity.MaterializationTableFrame

/-! Exact preservation of an arbitrary raw table through transactions.  The
invariant tracks both the committed database and an open private snapshot, so
it remains meaningful at suspended execution prefixes. -/
namespace Synchronicity.TableInvariant
open VerifiedCore VerifiedCore.Host SimulatedHost PrivateDatabase

def Holds (relation : String) (baseline : List Fields) (state : State) : Prop :=
  rows state.db relation = baseline ∧
    ∀ tx db, state.pending = some (tx, db) → rows db relation = baseline

theorem closed (relation : String) (state : State) (noTransaction : state.pending = none) :
    Holds relation (rows state.db relation) state := by
  refine ⟨rfl, ?_⟩
  intro tx db opened
  rw [noTransaction] at opened
  cases opened

theorem reply_holds (relation : String) (baseline : List Fields) (state : State) (event : String)
    (action : State → Result (Reply A)) (consume : Bool)
    (safe : ∀ s, Holds relation baseline s → Holds relation baseline (action s).2)
    (initial : Holds relation baseline state) :
    Holds relation baseline (reply state event action consume).2 := by
  unfold reply
  split
  · cases consume
    · exact initial
    · exact safe state initial
  · exact safe state initial

theorem transaction_holds (relation : String) (baseline : List Fields) (state : State) (tx : Transaction)
    (action : Database → A × Database)
    (safe : ∀ db, rows db relation = baseline → rows (action db).2 relation = baseline)
    (initial : Holds relation baseline state) :
    Holds relation baseline (SimulatedHost.transaction state tx action).2 := by
  unfold SimulatedHost.transaction
  split
  · rename_i token db opened
    split
    · refine ⟨initial.1, ?_⟩
      intro next staged same
      have parts : token = next ∧ (action db).2 = staged := by simpa using same
      rw [← parts.2]
      exact safe db (initial.2 token db opened)
    · exact initial
  · exact initial

def StorageAllowed (relation : String) : Storage A → Prop
  | .upsert _ table _ _ _ | .deleteRows _ table _ _ _ | .deleteExcept _ table _ _ =>
      table ≠ relation
  | _ => True

theorem storage_safe (relation : String) (baseline : List Fields) (effect : Storage A)
    (safe : StorageAllowed relation effect) (state : State)
    (initial : Holds relation baseline state) :
    Holds relation baseline (storage effect state).2 := by
  cases effect with
  | begin =>
    simp only [storage]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    split
    · exact h
    · refine ⟨h.1, ?_⟩
      intro tx db same
      have parts : s.nextTx = tx ∧ s.db = db := by simpa using same
      rw [← parts.2]
      exact h.1
  | commit tx =>
    simp only [storage]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    split
    · rename_i token db opened
      split
      · refine ⟨h.2 token db opened, ?_⟩
        intro next staged impossible
        cases impossible
      · exact h
    · exact h
  | rollback tx =>
    simp only [storage]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    split
    · split
      · refine ⟨h.1, ?_⟩
        intro next staged impossible
        cases impossible
      · exact h
    · exact h
  | upsert tx table fields conflicts updates =>
    simp only [storage]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    apply transaction_holds relation baseline _ _ _ _ h
    intro db same
    rw [rows_setRows_other _ _ _ _ safe]
    exact same
  | deleteExcept tx table column keys =>
    simp only [storage]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    apply transaction_holds relation baseline _ _ _ _ h
    intro db same
    rw [rows_setRows_other _ _ _ _ safe]
    exact same
  | deleteRows tx table fields blockers bounds =>
    simp only [storage]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    apply transaction_holds relation baseline _ _ _ _ h
    intro db same
    rw [rows_setRows_other _ _ _ _ safe]
    exact same
  | readRows | scanRows | existsRows =>
    simp only [storage]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    exact transaction_holds relation baseline _ _ _ (fun _ same => same) h
  | readCounter | readBytes | removeFile =>
    simp only [storage]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    exact h
  | readInput =>
    simp only [storage]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    split
    · exact h
    · split <;> exact h

def AccessAllowed (relation : String) : Access A → Prop
  | .update _ selection _ | .delete _ selection => selection.relation ≠ relation
  | .copyRows _ target _ _ _ => target ≠ relation
  | _ => True

theorem access_safe (relation : String) (baseline : List Fields) (effect : Access A)
    (safe : AccessAllowed relation effect) (state : State)
    (initial : Holds relation baseline state) :
    Holds relation baseline (access effect state).2 := by
  cases effect with
  | snapshot | snapshotExcluding =>
    simp only [access]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    exact h
  | update tx selection values =>
    simp only [access]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    apply transaction_holds relation baseline _ _ _ _ h
    intro db same
    rw [rows_setRows_other _ _ _ _ safe]
    exact same
  | delete tx selection =>
    simp only [access]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    apply transaction_holds relation baseline _ _ _ _ h
    intro db same
    rw [rows_setRows_other _ _ _ _ safe]
    exact same
  | copyRows tx target selection fields conflicts =>
    simp only [access]
    apply reply_holds relation baseline _ _ _ _ _ initial
    intro s h
    apply transaction_holds relation baseline _ _ _ _ h
    intro db same
    simp only [copyRows, rows_setRows_other _ _ _ _ safe]
    exact same

def EffectSafe [Interpreter E] (relation : String) (baseline : List Fields) (effect : E A) : Prop :=
  ∀ state, Holds relation baseline state →
    Holds relation baseline (Interpreter.handle effect state).2

theorem storage_effect (relation : String) (baseline : List Fields) (effect : Storage A)
    (safe : StorageAllowed relation effect) : EffectSafe relation baseline effect :=
  storage_safe relation baseline effect safe

theorem access_effect (relation : String) (baseline : List Fields) (effect : Access A)
    (safe : AccessAllowed relation effect) : EffectSafe relation baseline effect :=
  access_safe relation baseline effect safe

theorem prefix_rows [Interpreter E] (relation : String) (program rest : Program E A)
    (safe : Only (fun _ effect => ∀ baseline, EffectSafe relation baseline effect) program)
    (continuation : Continuation program current) (state final : State)
    (closedState : state.pending = none) (path : Prefix current state rest final) :
    rows final.db relation = rows state.db relation := by
  have currentSafe := safe.continuation continuation
  have held := currentSafe.invariant_prefix
    (Holds relation (rows state.db relation)) path
    (fun effect good current initial => good _ current initial)
    (closed relation state closedState)
  exact held.1

end Synchronicity.TableInvariant
