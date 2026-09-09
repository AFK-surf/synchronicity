import Synchronicity.MaterializationFileRequirements

namespace Synchronicity.MaterializationRetentionTail
open VerifiedCore VerifiedCore.Host Replication SimulatedHost
open MaterializedView MaterializationRetention MaterializationRequirementFrame MaterializationFileRequirements
open TransactionSuccess (bind_success)

def Requirements (replicas : List Materialize.Target) (baseline db : Database) : Prop :=
  CurrentRequirements replicas db ∧ ForeverRequirements replicas baseline db

theorem release_preserves (tx : Transaction) (target : Materialize.Target) (root : ByteArray) (now : Int64)
    (replicas : List Materialize.Target) (policy : PoliciesAgree replicas) (chosen : target ∈ replicas)
    (baseline : Database) (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (requirements : Requirements replicas baseline db)
    (ran : execute (Materialize.release tx target root now) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Requirements replicas baseline after := by
  obtain ⟨after, pending, current⟩ := release_current tx target root now replicas state final db opened requirements.1 (.ok ()) ran
  obtain ⟨historyDb, historyTx, history⟩ := release_forever tx target root now replicas policy chosen baseline
    state final db opened requirements.2 (.ok ()) ran
  have same : after = historyDb := congrArg Prod.snd (Option.some.inj (pending.symm.trans historyTx))
  subst historyDb
  exact ⟨after, pending, current, history⟩

def oldTail (tx : Transaction) (target : Materialize.Target) (now : Int64)
    (previous content : Option ByteArray) : Materialize.Action Unit := do
  if let some old := previous then
    if some old != content then Materialize.release tx target old now

theorem retain_some (tx : Transaction) (target : Materialize.Target) (now releaseNow : Int64)
    (previous : Option ByteArray) (file : Records.File) :
    MaterializationFileApply.retain tx now releaseNow (some target) previous file =
      ((match file.content with
        | none => pure () | some root => Materialize.wants tx target file root now) >>= fun _ =>
        oldTail tx target releaseNow previous file.content) := by
  unfold MaterializationFileApply.retain oldTail
  cases file.content <;> rfl

theorem old_tail_preserves (tx : Transaction) (target : Materialize.Target) (now : Int64)
    (previous content : Option ByteArray) (replicas : List Materialize.Target)
    (policy : PoliciesAgree replicas) (chosen : target ∈ replicas)
    (baseline : Database) (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (requirements : Requirements replicas baseline db)
    (ran : execute (oldTail tx target now previous content) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Requirements replicas baseline after := by
  unfold oldTail at ran
  split at ran
  · split at ran
    · exact release_preserves tx target _ now replicas policy chosen baseline state final db opened requirements ran
    · cases ran; exact ⟨db, opened, requirements⟩
  · cases ran; exact ⟨db, opened, requirements⟩

theorem retain_preserves (tx : Transaction) (now releaseNow : Int64) (target : Option Materialize.Target)
    (previous : Option ByteArray) (file : Records.File) (replicas : List Materialize.Target)
    (policy : PoliciesAgree replicas) (selected : ∀ chosen, target = some chosen → chosen ∈ replicas)
    (baseline : Database) (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (schema : MaterializationKeySchema.Schema db) (staged : Staged replicas db target file.content)
    (history : ForeverRequirements replicas baseline db)
    (ran : execute (MaterializationFileApply.retain tx now releaseNow target previous file) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Requirements replicas baseline after := by
  cases target with
  | none =>
    cases ran
    exact ⟨db, opened, staged_none_target replicas db file.content staged, history⟩
  | some target =>
    have chosen := selected target rfl
    rw [retain_some] at ran
    cases content : file.content with
    | none =>
      have current := staged_none_content replicas db (some target) (by simpa only [content] using staged)
      apply old_tail_preserves tx target releaseNow previous file.content replicas policy chosen baseline state final db opened ⟨current, history⟩
      simpa only [content, pure, ExceptT.pure, ExceptT.mk, bind, ExceptT.bind, ExceptT.bindCont, Program.bind] using ran
    | some root =>
      have sequence : execute (Materialize.wants tx target file root now >>= fun _ =>
          oldTail tx target releaseNow previous file.content : Materialize.Action Unit) state = (.ok (), final) := by
        simpa only [content] using ran
      obtain ⟨result, acquired, wantsRun, restRun⟩ := bind_success _ _ _ _ _ sequence
      cases result
      have needed : ∀ replica ∈ replicas, ∀ row ∈ rows db "entries", isCell (cell row "space") (.text replica.space) = true →
          ∀ requiredRoot, cell row "content" = .blob requiredRoot →
            Required db requiredRoot replica.holder ∨ (requiredRoot, replica.holder) = (root, target.holder) := by
        intro replica member row present space requiredRoot named
        rcases staged replica member row present space requiredRoot named with old | ⟨t, same, rootSame, holderSame⟩
        · exact Or.inl old
        · cases same
          rw [content] at rootSame
          exact Or.inr (Prod.ext (Option.some.inj rootSame).symm holderSame)
      obtain ⟨acquiredDb, acquiredTx, current, retained⟩ := wants_current tx target file root now replicas state acquired db opened schema needed wantsRun
      exact old_tail_preserves tx target releaseNow previous file.content replicas policy chosen baseline acquired final acquiredDb
        acquiredTx ⟨current, retains_forever replicas baseline db acquiredDb history retained⟩ restRun

theorem remove_tail_preserves (tx : Transaction) (releaseNow : Int64) (target : Option Materialize.Target)
    (previous : Option ByteArray) (replicas : List Materialize.Target)
    (policy : PoliciesAgree replicas) (selected : ∀ chosen, target = some chosen → chosen ∈ replicas)
    (baseline : Database) (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (requirements : Requirements replicas baseline db)
    (ran : execute (MaterializationFileApply.removeTail tx releaseNow target previous) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ Requirements replicas baseline after := by
  cases target with
  | none => cases ran; exact ⟨db, opened, requirements⟩
  | some target =>
    cases previous with
    | none => cases ran; exact ⟨db, opened, requirements⟩
    | some root =>
      exact release_preserves tx target root releaseNow replicas policy (selected target rfl) baseline
        state final db opened requirements ran

end Synchronicity.MaterializationRetentionTail
