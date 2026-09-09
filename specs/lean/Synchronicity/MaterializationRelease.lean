import Synchronicity.MaterializationAcquisition
import Synchronicity.PromotionReads

/-! Release cannot consume another root/holder's responsibility. Remaining
file references and forever retention also prevent consumption of its own
responsibility. These are raw-row facts for the actual release program. -/
namespace Synchronicity.MaterializationRelease
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase MaterializationRetention
open MaterializationAcquisition

def PendingRow (tx : Transaction) (table : String) (row : Fields) (state : State) : Prop :=
  ∃ db, state.pending = some (tx, db) ∧ row ∈ rows db table

def Preserves (tx : Transaction) (table : String) (row : Fields) (A : Type) (effect : Materialize.Effects A) : Prop :=
  ∀ state, PendingRow tx table row state → PendingRow tx table row (Interpreter.handle effect state).2

theorem readonly_preserves (tx : Transaction) (table : String) (row : Fields)
    (effect : Materialize.Effects A) (safe : PromotionReads.materializeRead _ effect) :
    Preserves tx table row _ effect := by
  intro state present
  obtain ⟨db, opened, member⟩ := present
  exact ⟨db, (PromotionReads.materialize_pending effect safe state).trans opened, member⟩

theorem erase_preserves (tx : Transaction) (table : String) (row : Fields) (target : String) (key : Fields)
    (safe : table ≠ target ∨ equals row key = false) :
    Only (Preserves tx table row) (Materialize.erase tx target key).run := by
  apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
  intro state present
  obtain ⟨db, opened, member⟩ := present
  simp only [Inject.inject, Interpreter.handle, storage, reply]
  cases failed : fault state with
  | some failure => exact ⟨db, opened, member⟩
  | none =>
    simp only [SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte]
    refine ⟨_, rfl, ?_⟩
    rcases safe with different | absent
    · simpa only [rows_setRows_other _ _ _ _ (Ne.symm different)] using member
    · by_cases same : target = table
      · subst target
        rw [rows_setRows]
        apply List.mem_filter.mpr
        exact ⟨member, by simp [deletable, absent]⟩
      · simpa only [rows_setRows_other _ _ _ _ same] using member

theorem update_preserves (tx : Transaction) (table : String) (row : Fields) (target : String) (key values : Fields)
    (safe : table ≠ target ∨ equals row key = false) :
    Only (Preserves tx table row) (Materialize.update tx target key values).run := by
  apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
  intro state present
  obtain ⟨db, opened, member⟩ := present
  simp only [Inject.inject, Interpreter.handle, access, reply]
  cases failed : fault state with
  | some failure => exact ⟨db, opened, member⟩
  | none =>
    simp only [SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte]
    refine ⟨_, rfl, ?_⟩
    rcases safe with different | absent
    · simpa only [rows_setRows_other _ _ _ _ (Ne.symm different)] using member
    · by_cases same : target = table
      · subst target
        rw [rows_setRows]
        exact List.mem_map.mpr ⟨row, member, by simp [selects, absent]⟩
      · simpa only [rows_setRows_other _ _ _ _ same] using member

theorem config_preserves (tx : Transaction) (table : String) (row : Fields) (key : String) :
    Only (Preserves tx table row) (Materialize.auth (Authorization.config tx key)).run := by
  have safe : Only PromotionReads.materializeRead (Materialize.auth (Authorization.config tx key)).run := by
    unfold Materialize.auth
    apply Only.within _ _ (ReconciliationReadOnly.config_only tx key)
    intro B effect good
    cases effect with
    | left effect => cases effect <;> first | contradiction | trivial
    | right _ => trivial
  exact safe.mono (fun effect good => readonly_preserves tx table row effect good)

theorem release_preserves_row (tx : Transaction) (target : Materialize.Target) (root : ByteArray) (now : Int64)
    (table : String) (row : Fields)
    (safe : (table = "pins" ∨ table = "content_want") → equals row (pinKey root target.holder) = false) :
    Only (Preserves tx table row) (Materialize.release tx target root now).run := by
  have raw {A : Type} (effect : Storage (Reply A)) (read : ReconciliationReadOnly.storageAllowed effect) :
      Only (Preserves tx table row) (Materialize.raw effect).run :=
    Only.raise _ _ (readonly_preserves tx table row _ read)
  have pureResult {A : Type} (result : Except Materialize.Error A) :
      Only (Preserves tx table row) (ExceptT.mk (Program.pure result)).run := .done _
  have delete := erase_preserves tx table row "content_want" (pinKey root target.holder)
    (by by_cases same : table = "content_want"; exact Or.inr (safe (.inr same)); exact Or.inl same)
  have refresh := update_preserves tx table row "pins"
    (pinKey root target.holder ++ [("release_after", .null)])
    [("release_after", .integer (Materialize.saturate (now.toInt + target.grace.toInt)))]
    (by
      by_cases same : table = "pins"
      · right
        simp only [equals, List.all_append]
        change (equals row (pinKey root target.holder) && _) = false
        rw [safe (.inl same)]
        rfl
      · exact Or.inl same)
  unfold Materialize.release
  repeat' first
    | exact .done _
    | exact refresh
    | (refine Only.seq (raw _ trivial) fun _ => ?_)
    | (refine Only.seq (config_preserves tx table row _) fun _ => ?_)
    | (refine Only.seq delete fun _ => ?_)
    | (refine Only.seq (Only.foldlM _ _ ?_ _) fun _ => ?_)
    | (intro count fields)
    | (refine Only.seq (pureResult _) fun _ => ?_)
    | (dsimp only; split)
    | split

/-- Even a failing release leaves every unrelated obligation row verbatim.
The initial row, not a caller-supplied policy answer, is the protection witness. -/
theorem release_keeps_other_row (tx : Transaction) (target : Materialize.Target) (root : ByteArray) (now : Int64)
    (table : String) (row : Fields)
    (safe : (table = "pins" ∨ table = "content_want") → equals row (pinKey root target.holder) = false)
    (state : State) (present : PendingRow tx table row state) :
    PendingRow tx table row (execute (Materialize.release tx target root now) state).2 :=
  (release_preserves_row tx target root now table row safe).invariant (PendingRow tx table row)
    (fun _ good => good) state present

/-- A responsibility can only be consumed for this exact current-retention
root/holder and only after its last current file reference has disappeared.
This holds on failure as well as success, before any enclosing rollback. -/
theorem release_protects_requirement (tx : Transaction) (target : Materialize.Target)
    (root requiredRoot : ByteArray) (holder : String) (now : Int64)
    (state : State) (db : Database) (opened : state.pending = some (tx, db))
    (required : Required db requiredRoot holder)
    (safeguard : (requiredRoot, holder) ≠ (root, target.holder) ∨
      Referenced db requiredRoot ∨ target.releases = false) :
    ∃ after, (execute (Materialize.release tx target root now) state).2.pending = some (tx, after) ∧
      Required after requiredRoot holder := by
  by_cases same : (requiredRoot, holder) = (root, target.holder)
  · have ⟨rootSame, holderSame⟩ := Prod.mk.inj same
    subst requiredRoot
    subst holder
    rcases safeguard with impossible | live | forever
    · exact False.elim (impossible rfl)
    · exact ⟨db, ((referenced_unchanged tx target root now state db opened live).1).trans opened, required⟩
    · rw [forever_unchanged tx target root now state forever]
      exact ⟨db, opened, required⟩
  · have safe (row : Fields) (key : CasHealingPromises.keyOf row = some (requiredRoot, holder)) :
        equals row (pinKey root target.holder) = false := by
      apply Bool.eq_false_iff.mpr
      intro selected
      have named := (key_matches row root target.holder (by simp [key])).mp selected
      exact same (Option.some.inj (key.symm.trans named))
    rcases required with ⟨row, member, key, live⟩ | ⟨row, member, key⟩
    · obtain ⟨after, afterTx, member⟩ := release_keeps_other_row tx target root now "pins" row
        (fun _ => safe row key) state ⟨db, opened, member⟩
      exact ⟨after, afterTx, Or.inl ⟨row, member, key, live⟩⟩
    · obtain ⟨after, afterTx, member⟩ := release_keeps_other_row tx target root now "content_want" row
        (fun _ => safe row key) state ⟨db, opened, member⟩
      exact ⟨after, afterTx, Or.inr ⟨row, member, key⟩⟩

end Synchronicity.MaterializationRelease
