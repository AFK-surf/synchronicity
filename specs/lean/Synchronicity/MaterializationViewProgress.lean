import Synchronicity.MaterializationFileApply
import Synchronicity.MaterializationCoverage
import Synchronicity.SnapshotViewProgress

/-! Every actual metadata callback refines the same snapshot-overlay
invariant, whether it replaces a file or changes unrelated metadata. -/
namespace Synchronicity.MaterializationViewProgress
open VerifiedCore VerifiedCore.Host Replication SimulatedHost
open MaterializedView SnapshotViewProgress TrieDiffCoverage

theorem apply_progress (world : World) (services : Services) (oldRoot newRoot : ByteArray)
    (allowed : ByteArray → Prop) (visited : ByteArray → Prop)
    (unique : UniqueAddresses services (Relevant world.snapshot oldRoot newRoot))
    (tx : Transaction) (origin : String) (now releaseNow : Int64) (replicas : List Materialize.Target)
    (key : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (normalization : state.isNfc = services.nfc)
    (initial : ExactFilesAt visited services world.snapshot oldRoot newRoot allowed db origin)
    (changed : MaterializationStream.Update world oldRoot newRoot key kind value) (granted : allowed key)
    (ran : execute (Materialize.apply tx origin now releaseNow replicas key kind value) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧
      ExactFilesAt (fun k => visited k ∨ k = key) services world.snapshot oldRoot newRoot allowed after origin := by
  obtain ⟨oldValue, delta, _⟩ := changed
  by_cases projected : ∃ space path, Addresses services key (.file space path)
  · obtain ⟨space, path, addressed⟩ := projected
    obtain ⟨after, pending, refined⟩ := MaterializationFileApply.apply_file_refines
      tx origin space path now releaseNow replicas key kind value state final db opened addressed.1 addressed.2.1
      (by rw [normalization]; exact addressed.2.2) ran
    refine ⟨after, pending, ?_⟩
    intro otherSpace otherPath values
    rw [expected_after_file visited services world.snapshot oldRoot newRoot key allowed space path oldValue value
      delta granted addressed unique otherSpace otherPath values]
    by_cases same : (otherSpace, otherPath) = (space, path)
    · obtain ⟨rfl, rfl⟩ := Prod.mk.inj same
      simpa only [true_and, ne_eq, not_true_eq_false, false_and, or_false] using refined.1 values
    · simp only [same, false_and, ne_eq, not_false_eq_true, true_and, false_or]
      rw [MaterializationFileSql.replacement_other db after origin space path value refined otherSpace otherPath same]
      exact initial otherSpace otherPath values
  · have unprojected : ∀ space path, ¬Addresses services key (.file space path) :=
      fun space path address => projected ⟨space, path, address⟩
    obtain ⟨after, pending, same⟩ := MaterializationFileApply.apply_unprojected_frame
      tx origin now releaseNow replicas key kind value services state final db opened normalization unprojected ran
    refine ⟨after, pending, ?_⟩
    intro space path values
    rw [expected_unprojected visited services world.snapshot oldRoot newRoot key allowed unprojected space path values]
    have observation : Observed after origin (.file space path) values ↔ Observed db origin (.file space path) values := by
      simp only [Observed, Address.table, same]
    rw [observation]
    exact initial space path values

end Synchronicity.MaterializationViewProgress
