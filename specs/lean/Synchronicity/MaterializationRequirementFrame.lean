import Synchronicity.MaterializationKeySchema
import Synchronicity.MaterializationTableFrame
import Synchronicity.MaterializedView

/-! Current references and forever history are stable across the actual
retention operations. A raw schema and consistent per-holder replica policy
are input contracts; permissions to consume a requirement come from real rows. -/
namespace Synchronicity.MaterializationRequirementFrame
open VerifiedCore VerifiedCore.Host Replication SimulatedHost
open MaterializedView MaterializationRetention MaterializationTableFrame

def PoliciesAgree (replicas : List Materialize.Target) : Prop :=
  ∀ left ∈ replicas, ∀ right ∈ replicas, left.holder = right.holder → left.releases = right.releases

theorem retains_forever (replicas : List Materialize.Target) (baseline before after : Database)
    (history : ForeverRequirements replicas baseline before) (retained : Retains before after) :
    ForeverRequirements replicas baseline after :=
  fun target member forever root held => retained root target.holder (history target member forever root held)

theorem release_current (tx : Transaction) (target : Materialize.Target) (root : ByteArray) (now : Int64)
    (replicas : List Materialize.Target) (state final : State) (db : Database)
    (opened : state.pending = some (tx, db)) (current : CurrentRequirements replicas db)
    (result : Except Materialize.Error Unit)
    (ran : execute (Materialize.release tx target root now) state = (result, final)) :
    ∃ after, final.pending = some (tx, after) ∧ CurrentRequirements replicas after := by
  obtain ⟨after, pending, rowsSame⟩ := frame_opened "entries" _
    (release_safe "entries" (by decide) (by decide) tx target root now) state final result tx db opened ran
  refine ⟨after, pending, ?_⟩
  intro replica member row present space content named
  have wasPresent : row ∈ rows db "entries" := rowsSame ▸ present
  have requirement := current replica member row wasPresent space content named
  obtain ⟨protectedDb, protectedTx, protectedRequirement⟩ := MaterializationRelease.release_protects_requirement
    tx target root content replica.holder now state db opened requirement (Or.inr (Or.inl ⟨row, wasPresent, named⟩))
  rw [ran, pending] at protectedTx
  have same : after = protectedDb := congrArg Prod.snd (Option.some.inj protectedTx)
  exact same ▸ protectedRequirement

theorem release_forever (tx : Transaction) (target : Materialize.Target) (root : ByteArray) (now : Int64)
    (replicas : List Materialize.Target) (policy : PoliciesAgree replicas) (chosen : target ∈ replicas)
    (baseline : Database) (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (history : ForeverRequirements replicas baseline db) (result : Except Materialize.Error Unit)
    (ran : execute (Materialize.release tx target root now) state = (result, final)) :
    ∃ after, final.pending = some (tx, after) ∧ ForeverRequirements replicas baseline after := by
  obtain ⟨after, pending, _⟩ := frame_opened "entries" _
    (release_safe "entries" (by decide) (by decide) tx target root now) state final result tx db opened ran
  refine ⟨after, pending, ?_⟩
  intro replica member forever content held
  have safeguard : (content, replica.holder) ≠ (root, target.holder) ∨ target.releases = false := by
    by_cases same : (content, replica.holder) = (root, target.holder)
    · exact Or.inr ((policy target chosen replica member (Prod.mk.inj same).2.symm).trans forever)
    · exact Or.inl same
  obtain ⟨protectedDb, protectedTx, protectedRequirement⟩ := MaterializationRelease.release_protects_requirement
    tx target root content replica.holder now state db opened (history replica member forever content held)
    (safeguard.imp_right Or.inr)
  rw [ran, pending] at protectedTx
  have same : after = protectedDb := congrArg Prod.snd (Option.some.inj protectedTx)
  exact same ▸ protectedRequirement

/-- Acquiring the one newly referenced root discharges its outstanding
responsibility without consuming any previously established requirement. -/
theorem wants_current (tx : Transaction) (target : Materialize.Target) (file : Records.File)
    (root : ByteArray) (now : Int64) (replicas : List Materialize.Target)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (schema : MaterializationKeySchema.Schema db)
    (needed : ∀ replica ∈ replicas, ∀ row ∈ rows db "entries", isCell (cell row "space") (.text replica.space) = true →
      ∀ content, cell row "content" = .blob content →
        Required db content replica.holder ∨ (content, replica.holder) = (root, target.holder))
    (ran : execute (Materialize.wants tx target file root now) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧ CurrentRequirements replicas after ∧ Retains db after := by
  obtain ⟨after, pending, acquired, retained⟩ := MaterializationAcquisition.wants_establishes_requirement
    tx target file root now state final db opened schema.1 schema.2 ran
  obtain ⟨viewDb, viewTx, rowsSame⟩ := frame_opened "entries" _
    (wants_safe "entries" (by decide) (by decide) tx target file root now) state final (.ok ()) tx db opened ran
  have same : after = viewDb := congrArg Prod.snd (Option.some.inj (pending.symm.trans viewTx))
  subst viewDb
  refine ⟨after, pending, ?_, retained⟩
  intro replica member row present space content named
  rcases needed replica member row (rowsSame ▸ present) space content named with old | new
  · exact retained content replica.holder old
  · obtain ⟨rootSame, holderSame⟩ := Prod.mk.inj new
    simpa only [rootSame, holderSame] using acquired

end Synchronicity.MaterializationRequirementFrame
