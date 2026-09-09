import Synchronicity.MaterializedView

/-! An intermediate file view is a snapshot overlay: visited keys denote the
new snapshot, unvisited keys the old one. This specification is independent of
SQL commands, traversal order, duplicates and callback counters. -/
namespace Synchronicity.SnapshotViewProgress
open VerifiedCore VerifiedCore.Host Replication SimulatedHost MaterializedView
open TrieProgramProofs TrieSnapshotProofs

def Relevant (snapshot : RawSnapshot) (oldRoot newRoot key : ByteArray) : Prop :=
  ∃ bytes, Entry snapshot oldRoot key bytes ∨ Entry snapshot newRoot key bytes

def EntryAt (visited : ByteArray → Prop) (snapshot : RawSnapshot) (oldRoot newRoot key bytes : ByteArray) : Prop :=
  (visited key ∧ Entry snapshot newRoot key bytes) ∨ (¬visited key ∧ Entry snapshot oldRoot key bytes)

def ExpectedAt (visited : ByteArray → Prop) (services : Services) (snapshot : RawSnapshot)
    (oldRoot newRoot : ByteArray) (allowed : ByteArray → Prop) (address : Address) (values : List Cell) : Prop :=
  ∃ key bytes, allowed key ∧ EntryAt visited snapshot oldRoot newRoot key bytes ∧
    Addresses services key address ∧ Decoded address bytes values

def ExactFilesAt (visited : ByteArray → Prop) (services : Services) (snapshot : RawSnapshot)
    (oldRoot newRoot : ByteArray) (allowed : ByteArray → Prop) (db : Database) (origin : String) : Prop :=
  ∀ space path values, Observed db origin (.file space path) values ↔
    ExpectedAt visited services snapshot oldRoot newRoot allowed (.file space path) values

def ExactFiles (services : Services) (snapshot : RawSnapshot) (root : ByteArray)
    (allowed : ByteArray → Prop) (db : Database) (origin : String) : Prop :=
  ∀ space path values, Observed db origin (.file space path) values ↔
    Expected services snapshot root allowed (.file space path) values

theorem entry_relevant (held : EntryAt visited snapshot oldRoot newRoot key bytes) :
    Relevant snapshot oldRoot newRoot key := by
  rcases held with ⟨_, new⟩ | ⟨_, old⟩
  · exact ⟨bytes, Or.inr new⟩
  · exact ⟨bytes, Or.inl old⟩

theorem changes_relevant (changed : SnapshotDelta.Changes snapshot oldRoot newRoot key oldValue newValue) :
    Relevant snapshot oldRoot newRoot key := by
  rcases changed with ⟨old, new, different⟩
  cases oldValue with
  | some bytes => exact ⟨bytes, Or.inl ((old bytes).mpr rfl)⟩
  | none =>
    cases newValue with
    | none => exact False.elim (different rfl)
    | some bytes => exact ⟨bytes, Or.inr ((new bytes).mpr rfl)⟩

theorem addresses_file_unique (left : Addresses services key (.file space path))
    (right : Addresses services key (.file otherSpace otherPath)) : space = otherSpace ∧ path = otherPath :=
  Prod.mk.inj (Option.some.inj (left.2.1.symm.trans right.2.1))

theorem initially_exact (exactView : ExactFiles services snapshot oldRoot allowed db origin) :
    ExactFilesAt (fun _ => False) services snapshot oldRoot newRoot allowed db origin := by
  simpa only [ExactFilesAt, ExpectedAt, EntryAt, false_and, not_false_eq_true, true_and, false_or,
    ExactFiles, Expected] using exactView

/-- Once every permitted changed key has been visited, the overlay is exactly
the new snapshot. No walk-exhaustion or ready-view premise is used. -/
theorem finally_exact (visited : ByteArray → Prop) (services : Services) (snapshot : RawSnapshot)
    (oldRoot newRoot : ByteArray) (allowed : ByteArray → Prop) (db : Database) (origin : String)
    (covered : ∀ key, allowed key → SnapshotDelta.ChangedKey snapshot oldRoot newRoot key → visited key)
    (exactView : ExactFilesAt visited services snapshot oldRoot newRoot allowed db origin) :
    ExactFiles services snapshot newRoot allowed db origin := by
  intro space path values
  rw [exactView space path values]
  constructor
  · rintro ⟨key, bytes, granted, held, addressed, decoded⟩
    refine ⟨key, bytes, granted, ?_, addressed, decoded⟩
    rcases held with ⟨_, new⟩ | ⟨unvisited, old⟩
    · exact new
    · apply Classical.byContradiction
      intro missing
      exact unvisited (covered key granted ⟨bytes, fun same => missing (same.mp old)⟩)
  · rintro ⟨key, bytes, granted, held, addressed, decoded⟩
    refine ⟨key, bytes, granted, ?_, addressed, decoded⟩
    by_cases seen : visited key
    · exact Or.inl ⟨seen, held⟩
    · right
      refine ⟨seen, ?_⟩
      apply Classical.byContradiction
      intro missing
      exact seen (covered key granted ⟨bytes, fun same => missing (same.mpr held)⟩)

theorem entry_after_visit (visited : ByteArray → Prop) (key other : ByteArray) (bytes : ByteArray)
    (newValue : Option ByteArray) (newAt : SnapshotDelta.ValueAt snapshot newRoot key newValue) :
    EntryAt (fun k => visited k ∨ k = key) snapshot oldRoot newRoot other bytes ↔
      (other = key ∧ newValue = some bytes) ∨
      (other ≠ key ∧ EntryAt visited snapshot oldRoot newRoot other bytes) := by
  by_cases same : other = key
  · subst other
    simp [EntryAt, newAt bytes]
  · simp [EntryAt, same]

/-- Visiting a file key replaces one domain record in the overlay. The
canonical-key assumption concerns published names, not view correctness. -/
theorem expected_after_file (visited : ByteArray → Prop) (services : Services) (snapshot : RawSnapshot)
    (oldRoot newRoot key : ByteArray) (allowed : ByteArray → Prop) (space path : String)
    (oldValue newValue : Option ByteArray)
    (changed : SnapshotDelta.Changes snapshot oldRoot newRoot key oldValue newValue)
    (granted : allowed key) (addressed : Addresses services key (.file space path))
    (unique : UniqueAddresses services (Relevant snapshot oldRoot newRoot))
    (otherSpace otherPath : String) (values : List Cell) :
    ExpectedAt (fun k => visited k ∨ k = key) services snapshot oldRoot newRoot allowed (.file otherSpace otherPath) values ↔
      ((otherSpace, otherPath) = (space, path) ∧ ∃ bytes, newValue = some bytes ∧ Decoded (.file space path) bytes values) ∨
      ((otherSpace, otherPath) ≠ (space, path) ∧
        ExpectedAt visited services snapshot oldRoot newRoot allowed (.file otherSpace otherPath) values) := by
  constructor
  · rintro ⟨other, bytes, permit, held, address, decoded⟩
    rcases (entry_after_visit visited key other bytes newValue changed.2.1).mp held with ⟨rfl, new⟩ | ⟨different, prior⟩
    · obtain ⟨rfl, rfl⟩ := addresses_file_unique addressed address
      exact Or.inl ⟨rfl, bytes, new, decoded⟩
    · right
      refine ⟨?_, other, bytes, permit, prior, address, decoded⟩
      intro same
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj same
      exact different (unique other key _ (entry_relevant prior) (changes_relevant changed) address addressed)
  · rintro (⟨same, bytes, new, decoded⟩ | ⟨different, other, bytes, permit, held, address, decoded⟩)
    · obtain ⟨rfl, rfl⟩ := Prod.mk.inj same
      exact ⟨key, bytes, granted, Or.inl ⟨Or.inr rfl, (changed.2.1 bytes).mpr new⟩, addressed, decoded⟩
    · refine ⟨other, bytes, permit, ?_, address, decoded⟩
      apply (entry_after_visit visited key other bytes newValue changed.2.1).mpr
      right
      refine ⟨?_, held⟩
      intro same
      subst other
      obtain ⟨rfl, rfl⟩ := addresses_file_unique addressed address
      exact different rfl

theorem expected_unprojected (visited : ByteArray → Prop) (services : Services) (snapshot : RawSnapshot)
    (oldRoot newRoot key : ByteArray) (allowed : ByteArray → Prop)
    (unprojected : ∀ space path, ¬Addresses services key (.file space path))
    (space path : String) (values : List Cell) :
    ExpectedAt (fun k => visited k ∨ k = key) services snapshot oldRoot newRoot allowed (.file space path) values ↔
      ExpectedAt visited services snapshot oldRoot newRoot allowed (.file space path) values := by
  constructor
  all_goals
    rintro ⟨other, bytes, granted, held, addressed, decoded⟩
    have different : other ≠ key := fun same => unprojected space path (same ▸ addressed)
    refine ⟨other, bytes, granted, ?_, addressed, decoded⟩
    simpa only [EntryAt, different, or_false] using held

end Synchronicity.SnapshotViewProgress
