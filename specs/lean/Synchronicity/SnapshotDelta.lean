import Synchronicity.TrieSnapshotProofs

/-! Snapshot differences are defined by entry meaning, independently of
the traversal, its output format and any materialized SQL tables. -/
namespace Synchronicity.SnapshotDelta
open VerifiedCore.Trie TrieProgramProofs TrieSnapshotProofs

def ValueAt (snapshot : RawSnapshot) (root key : ByteArray) (value : Option ByteArray) : Prop :=
  ∀ bytes, Entry snapshot root key bytes ↔ value = some bytes

def Changes (snapshot : RawSnapshot) (oldRoot newRoot key : ByteArray)
    (oldValue newValue : Option ByteArray) : Prop :=
  ValueAt snapshot oldRoot key oldValue ∧ ValueAt snapshot newRoot key newValue ∧ oldValue ≠ newValue

def ChangedKey (snapshot : RawSnapshot) (oldRoot newRoot key : ByteArray) : Prop :=
  ∃ bytes, ¬(Entry snapshot oldRoot key bytes ↔ Entry snapshot newRoot key bytes)

def kind : Option ByteArray → Option ByteArray → UInt64
  | none, some _ => 0
  | some _, none => 2
  | _, _ => 1

theorem changes_key (delta : Changes snapshot oldRoot newRoot key oldValue newValue) :
    ChangedKey snapshot oldRoot newRoot key := by
  obtain ⟨old, new, different⟩ := delta
  cases oldValue with
  | none =>
    cases newValue with
    | none => exact False.elim (different rfl)
    | some bytes => exact ⟨bytes, by simp [old bytes, new bytes]⟩
  | some bytes =>
    refine ⟨bytes, ?_⟩
    rw [old bytes, new bytes]
    intro same
    exact different ((same.mp rfl).symm)

end Synchronicity.SnapshotDelta
