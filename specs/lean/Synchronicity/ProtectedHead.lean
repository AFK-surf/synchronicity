import Synchronicity.PrivateDatabase

/-! A raw heads row is retained in both the committed database and any private
transaction. This makes preservation stable through begin, commit and rollback,
including failures. It is an observation about rows, not a version-policy oracle. -/
namespace Synchronicity.ProtectedHead
open VerifiedCore.Host SimulatedHost PrivateDatabase

def retained (row : Fields) (state : State) : Prop :=
  row ∈ rows state.db "heads" ∧
    ∀ tx db, state.pending = some (tx, db) → row ∈ rows db "heads"

theorem initial (row : Fields) (state : State) (closed : state.pending = none)
    (present : row ∈ rows state.db "heads") : retained row state := by
  refine ⟨present, ?_⟩
  intro tx db opened
  rw [closed] at opened
  cases opened

theorem reply_retains (row : Fields) (state : State) (event : String)
    (action : State → Result (Reply A)) (consume : Bool)
    (safe : ∀ s, retained row s → retained row (action s).2) (kept : retained row state) :
    retained row (reply state event action consume).2 := by
  unfold reply
  split
  · cases consume
    · exact kept
    · exact safe state kept
  · exact safe state kept

theorem transaction_retains (row : Fields) (state : State) (tx : Transaction)
    (action : Database → A × Database)
    (safe : ∀ db, row ∈ rows db "heads" → row ∈ rows (action db).2 "heads")
    (kept : retained row state) : retained row (SimulatedHost.transaction state tx action).2 := by
  unfold SimulatedHost.transaction
  split
  · rename_i token db opened
    split
    · refine ⟨kept.1, ?_⟩
      intro next staged same
      have same : token = next ∧ (action db).2 = staged := by simpa using same
      rw [← same.2]
      exact safe db (kept.2 token db opened)
    · exact kept
  · exact kept

def storageAllowed (row : Fields) : Storage A → Prop
  | .upsert _ relation fields conflicts _ => relation ≠ "heads" ∨ conflict conflicts fields row = false
  | .deleteExcept _ relation _ _ => relation ≠ "heads"
  | .deleteRows _ relation fields _ _ => relation ≠ "heads" ∨ equals row fields = false
  | _ => True

theorem storage_retains (row : Fields) (effect : Storage A) (safe : storageAllowed row effect)
    (state : State) (kept : retained row state) : retained row (storage effect state).2 := by
  cases effect with
  | begin =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    split
    · exact h
    · refine ⟨h.1, ?_⟩
      intro tx db same
      have same : s.nextTx = tx ∧ s.db = db := by simpa using same
      rw [← same.2]
      exact h.1
  | commit tx =>
    apply reply_retains _ _ _ _ _ _ kept
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
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    split
    · split
      · refine ⟨h.1, ?_⟩
        intro next staged impossible
        cases impossible
      · exact h
    · exact h
  | upsert tx relation fields conflicts updates =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    apply transaction_retains _ _ _ _ _ h
    intro db member
    by_cases other : relation ≠ "heads"
    · rwa [rows_setRows_other _ _ _ _ other]
    · have same : relation = "heads" := Classical.not_not.mp other
      subst relation
      have unmatched := safe.resolve_left (by simp)
      rw [rows_setRows]
      unfold upsertRows
      split
      · exact List.mem_map.mpr ⟨row, member, by simp [unmatched]⟩
      · exact List.mem_append_left _ member
  | deleteExcept tx relation column keys =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    apply transaction_retains _ _ _ _ _ h
    intro db member
    rwa [rows_setRows_other _ _ _ _ safe]
  | deleteRows tx relation fields blockers bounds =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    apply transaction_retains _ _ _ _ _ h
    intro db member
    by_cases other : relation ≠ "heads"
    · rwa [rows_setRows_other _ _ _ _ other]
    · have same : relation = "heads" := Classical.not_not.mp other
      subst relation
      have excluded := safe.resolve_left (by simp)
      rw [rows_setRows]
      apply List.mem_filter.mpr
      exact ⟨member, by simp [deletable, excluded]⟩
  | readRows | scanRows | existsRows =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    exact transaction_retains _ _ _ _ (fun _ member => member) h
  | readCounter | readBytes | removeFile =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    exact h
  | readInput =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    split
    · exact h
    · split <;> exact h

def accessAllowed (row : Fields) : Access A → Prop
  | .snapshot _ _ | .snapshotExcluding _ _ _ => True
  | .update _ selection _ | .delete _ selection =>
      selection.relation ≠ "heads" ∨ selects selection row = false
  | .copyRows _ target _ _ _ => target ≠ "heads"

theorem access_retains (row : Fields) (effect : Access A) (safe : accessAllowed row effect)
    (state : State) (kept : retained row state) : retained row (access effect state).2 := by
  cases effect with
  | snapshot | snapshotExcluding =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    exact h
  | update tx selection values =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    apply transaction_retains _ _ _ _ _ h
    intro db member
    by_cases other : selection.relation ≠ "heads"
    · rwa [rows_setRows_other _ _ _ _ other]
    · have same : selection.relation = "heads" := Classical.not_not.mp other
      have unmatched := safe.resolve_left other
      rw [same, rows_setRows]
      exact List.mem_map.mpr ⟨row, member, by simp [unmatched]⟩
  | delete tx selection =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    apply transaction_retains _ _ _ _ _ h
    intro db member
    by_cases other : selection.relation ≠ "heads"
    · rwa [rows_setRows_other _ _ _ _ other]
    · have same : selection.relation = "heads" := Classical.not_not.mp other
      have unmatched := safe.resolve_left other
      rw [same, rows_setRows]
      exact List.mem_filter.mpr ⟨member, by simp [unmatched]⟩
  | copyRows tx target selection fields conflicts =>
    apply reply_retains _ _ _ _ _ _ kept
    intro s h
    apply transaction_retains _ _ _ _ _ h
    intro db member
    simp only [copyRows, rows_setRows_other _ _ _ _ safe]
    exact member

end Synchronicity.ProtectedHead
