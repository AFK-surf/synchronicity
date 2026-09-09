import Synchronicity.MaterializationSql

/-! Relational replacement independent of metadata commands. A row is observed
through its domain identity and payload; replacement installs exactly the new
payload at one identity and preserves every other observation. -/
namespace Synchronicity.RowReplacement
open VerifiedCore.Host SimulatedHost

def Observed (identity : Fields → K) (payload : Fields → V) (table : List Fields)
    (key : K) (value : V) : Prop :=
  ∃ row ∈ table, identity row = key ∧ payload row = value

def Replaces (identity : Fields → K) (payload : Fields → V) (before after : List Fields)
    (target : K) (value : Option V) : Prop :=
  ∀ key data, Observed identity payload after key data ↔
    (key = target ∧ value = some data) ∨
    (key ≠ target ∧ Observed identity payload before key data)

theorem upsert_replaces (identity : Fields → K) (payload : Fields → V)
    (table : List Fields) (incoming : Fields) (columns : List String)
    (assignments : List (String × ConflictValue)) (target : K) (value : V)
    (incomingKey : identity incoming = target) (incomingValue : payload incoming = value)
    (selectsTarget : ∀ row, conflict columns incoming row = true ↔ identity row = target)
    (keepsKey : ∀ row, identity (assign row (assignments.map fun (column, v) =>
      (column, conflictValue row incoming v))) = identity row)
    (setsValue : ∀ row, payload (assign row (assignments.map fun (column, v) =>
      (column, conflictValue row incoming v))) = value) :
    Replaces identity payload table (upsertRows table incoming columns assignments) target (some value) := by
  intro key data
  unfold upsertRows
  split
  · rename_i found
    constructor
    · rintro ⟨row, present, atKey, atValue⟩
      obtain ⟨old, member, changed⟩ := List.mem_map.mp present
      split at changed
      · subst row
        left
        exact ⟨atKey.symm.trans ((keepsKey old).trans ((selectsTarget old).mp (by assumption))),
          congrArg some ((setsValue old).symm.trans atValue)⟩
      · subst row
        right
        refine ⟨?_, old, member, atKey, atValue⟩
        intro same
        exact (by assumption : ¬ conflict columns incoming old = true) ((selectsTarget old).mpr (atKey.trans same))
    · rintro (⟨rfl, equal⟩ | ⟨different, old, member, atKey, atValue⟩)
      · have equal := Option.some.inj equal
        obtain ⟨old, member, matched⟩ := List.any_eq_true.mp found
        refine ⟨assign old (assignments.map fun (column, v) => (column, conflictValue old incoming v)),
          List.mem_map.mpr ⟨old, member, by simp only [matched, ↓reduceIte]⟩, ?_, ?_⟩
        · exact (keepsKey old).trans ((selectsTarget old).mp matched)
        · exact (setsValue old).trans equal
      · have unmatched : conflict columns incoming old = false := by
          cases h : conflict columns incoming old
          · rfl
          · exact False.elim (different (atKey.symm.trans ((selectsTarget old).mp h)))
        exact ⟨old, List.mem_map.mpr ⟨old, member, by simp only [unmatched, Bool.false_eq_true, ↓reduceIte]⟩,
          atKey, atValue⟩
  · rename_i absent
    have noTarget : ∀ row ∈ table, identity row ≠ target := by
      intro row member same
      exact absent (List.any_eq_true.mpr ⟨row, member, (selectsTarget row).mpr same⟩)
    constructor
    · rintro ⟨row, present, atKey, atValue⟩
      rcases List.mem_append.mp present with old | new
      · exact Or.inr ⟨fun same => noTarget row old (atKey.trans same), row, old, atKey, atValue⟩
      · have same := List.mem_singleton.mp new
        subst row
        exact Or.inl ⟨atKey.symm.trans incomingKey, congrArg some (incomingValue.symm.trans atValue)⟩
    · rintro (⟨rfl, equal⟩ | ⟨_, row, member, atKey, atValue⟩)
      · exact ⟨incoming, List.mem_append_right _ (by simp), incomingKey,
          incomingValue.trans (Option.some.inj equal)⟩
      · exact ⟨row, List.mem_append_left _ member, atKey, atValue⟩

theorem erase_replaces (identity : Fields → K) (payload : Fields → V)
    (table : List Fields) (selector : Fields) (target : K)
    (selectsTarget : ∀ row, equals row selector = true ↔ identity row = target) :
    Replaces identity payload table (table.filter fun row => !equals row selector) target none := by
  intro key data
  constructor
  · rintro ⟨row, member, atKey, atValue⟩
    obtain ⟨member, kept⟩ := List.mem_filter.mp member
    right
    refine ⟨?_, row, member, atKey, atValue⟩
    intro same
    have selected := (selectsTarget row).mpr (atKey.trans same)
    simp [selected] at kept
  · rintro (⟨_, impossible⟩ | ⟨different, row, member, atKey, atValue⟩)
    · cases impossible
    · refine ⟨row, List.mem_filter.mpr ⟨member, ?_⟩, atKey, atValue⟩
      cases selected : equals row selector
      · rfl
      · exact False.elim (different (atKey.symm.trans ((selectsTarget row).mp selected)))

/-- Unselected rows survive verbatim, and no replacement introduces a new
unselected row. This strengthens a payload-only frame to all receiver columns. -/
theorem upsert_frame (selected : Fields → Bool) (table : List Fields) (incoming : Fields)
    (columns : List String) (assignments : List (String × ConflictValue))
    (incomingKey : selected incoming = true)
    (selectsTarget : ∀ row, conflict columns incoming row = selected row)
    (keepsKey : ∀ row, selected (assign row (assignments.map fun (column, v) =>
      (column, conflictValue row incoming v))) = selected row) (row : Fields)
    (outside : selected row = false) :
    row ∈ upsertRows table incoming columns assignments ↔ row ∈ table := by
  unfold upsertRows
  split
  · constructor
    · intro member
      obtain ⟨old, inTable, changed⟩ := List.mem_map.mp member
      split at changed
      · have key := congrArg selected changed
        rw [keepsKey, outside] at key
        have matched : selected old = true := by rwa [← selectsTarget]
        simp [matched] at key
      · subst row
        exact inTable
    · intro member
      exact List.mem_map.mpr ⟨row, member, by simp [selectsTarget, outside]⟩
  · constructor
    · intro member
      rcases List.mem_append.mp member with old | new
      · exact old
      · have same := List.mem_singleton.mp new
        subst row
        simp [incomingKey] at outside
    · exact List.mem_append_left _

end Synchronicity.RowReplacement
