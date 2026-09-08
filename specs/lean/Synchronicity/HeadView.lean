import Synchronicity.Goals.Mptsync.HeadTransition
import Synchronicity.HeadKeyFrame
import Synchronicity.ReconciliationRead
import Synchronicity.PromotionBound

/-! Relate the domain head view to independently observed raw database rows.
The representation contract says nothing about what an operation may change. -/
namespace Synchronicity.HeadView
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost Goals.Mptsync

def slotName : HeadSlot → String
  | .complete => "complete"
  | .pending => "pending"

def points (row : Fields) (version : HeadVersion) : Prop :=
  cell row "seq" = .integer version.seq.toInt64 ∧ cell row "root" = .blob version.root

def Selected (db : Database) (origin : String) (slot : HeadSlot) (row : Fields) : Prop :=
  row ∈ rows db "heads" ∧ ReconciliationSlots.names row origin (slotName slot) = true

def Represents (db : Database) (view : HeadView) : Prop :=
  ∀ origin slot, match view origin slot with
    | none => ¬ ∃ row, Selected db origin slot row
    | some version => (∃ row, Selected db origin slot row) ∧
        ∀ row, Selected db origin slot row → points row version

def Backed (db : Database) (view : HeadView) : Prop :=
  ∀ origin slot version, view origin slot = some version →
    ReconciliationRead.StoredFloor db origin (slotName slot) version.seq.toInt64 version.root

theorem version_unique (row : Fields) (a b : HeadVersion) (ha : points row a) (hb : points row b) : a = b := by
  have seq := Cell.integer.inj (ha.1.symm.trans hb.1)
  have root := Cell.blob.inj (ha.2.symm.trans hb.2)
  have sameSeq : a.seq = b.seq := by
    have same := congrArg Int64.toUInt64 seq
    simpa using same
  cases a
  cases b
  cases sameSeq
  cases root
  rfl

theorem selected_version (observed : Represents db view) (selected : Selected db origin slot row) :
    ∃ version, view origin slot = some version ∧ points row version := by
  have here := observed origin slot
  cases value : view origin slot with
  | none => rw [value] at here; exact False.elim (here ⟨row, selected⟩)
  | some version => rw [value] at here; exact ⟨version, rfl, here.2 row selected⟩

theorem existing (observed : Represents db view) (value : view origin slot = some version) :
    ∃ row, Selected db origin slot row ∧ points row version := by
  have here := observed origin slot
  rw [value] at here
  obtain ⟨row, selected⟩ := here.1
  exact ⟨row, selected, here.2 row selected⟩

theorem absent (observed : Represents db view) (value : view origin slot = none)
    (selected : Selected db origin slot row) : False := by
  have here := observed origin slot
  rw [value] at here
  exact here ⟨row, selected⟩

theorem key_fields (same : HeadKeyFrame.key a = HeadKeyFrame.key b) :
    cell a "origin_id" = cell b "origin_id" ∧ cell a "slot" = cell b "slot" ∧
    cell a "seq" = cell b "seq" ∧ cell a "root" = cell b "root" := by
  simpa [HeadKeyFrame.key, HeadKeyFrame.columns] using same

theorem key_named (same : HeadKeyFrame.key a = HeadKeyFrame.key b) :
    ReconciliationSlots.names a origin slot = ReconciliationSlots.names b origin slot := by
  obtain ⟨originSame, slotSame, _, _⟩ := key_fields same
  simp only [ReconciliationSlots.names, equals, List.all_cons, List.all_nil, Bool.and_true, originSame, slotSame]

theorem key_points (same : HeadKeyFrame.key a = HeadKeyFrame.key b) (stored : points b version) : points a version := by
  obtain ⟨_, _, seqSame, rootSame⟩ := key_fields same
  exact ⟨seqSame.trans stored.1, rootSame.trans stored.2⟩

theorem retained (before : Represents db view) (after : Represents nextDb nextView)
    (kept : ∀ row ∈ rows db "heads", row ∈ rows nextDb "heads") :
    ∀ origin slot version, view origin slot = some version → nextView origin slot = some version := by
  intro origin slot version value
  obtain ⟨row, selected, stored⟩ := existing before value
  obtain ⟨next, observed, nextStored⟩ := selected_version after ⟨kept row selected.1, selected.2⟩
  rw [version_unique row next version nextStored stored] at observed
  exact observed

/-- No new raw version keys means an occupied slot cannot be replaced by a
different version. Absence still needs a separately justified capture. -/
theorem no_replacement (before : Represents db view) (after : Represents nextDb nextView)
    (noNew : ∀ row ∈ rows nextDb "heads", ∃ old ∈ rows db "heads", HeadKeyFrame.key row = HeadKeyFrame.key old)
    (oldValue : view origin slot = some old) (nextValue : nextView origin slot = some next) : next = old := by
  obtain ⟨row, selected, stored⟩ := existing after nextValue
  obtain ⟨prior, member, same⟩ := noNew row selected.1
  have named : ReconciliationSlots.names prior origin (slotName slot) = true := by
    rw [← key_named same]
    exact selected.2
  have priorView := before origin slot
  rw [oldValue] at priorView
  have priorStored := priorView.2 prior ⟨member, named⟩
  exact version_unique row next old stored (key_points same priorStored)

theorem text_unique (value : Cell) (a b : String)
    (ha : isCell value (.text a) = true) (hb : isCell value (.text b) = true) : a = b := by
  cases value <;> simp_all [isCell, equalCell, BEq.beq, instBEqCell.beq]
  rename_i bytes
  have same : a.toByteArray = b.toByteArray := ByteArray.ext ((eq_of_beq ha).symm.trans (eq_of_beq hb))
  exact String.toByteArray_inj.mp same

theorem named_fields (named : ReconciliationSlots.names row origin slot = true) :
    isCell (cell row "origin_id") (.text origin) = true ∧ isCell (cell row "slot") (.text slot) = true := by
  simpa [ReconciliationSlots.names, equals, Bool.and_eq_true] using named

theorem other_origin (named : ReconciliationSlots.names row origin slot = true) (different : origin ≠ other) :
    isCell (cell row "origin_id") (.text other) = false := by
  cases tested : isCell (cell row "origin_id") (.text other) with
  | false => rfl
  | true => exact False.elim (different (text_unique _ origin other (named_fields named).1 tested))

theorem other_name (named : ReconciliationSlots.names row origin slot = true)
    (different : origin ≠ otherOrigin ∨ slot ≠ otherSlot) : ReconciliationSlots.names row otherOrigin otherSlot = false := by
  cases tested : ReconciliationSlots.names row otherOrigin otherSlot with
  | false => rfl
  | true =>
    rcases different with different | different
    · exact False.elim (different (text_unique _ origin otherOrigin (named_fields named).1 (named_fields tested).1))
    · exact False.elim (different (text_unique _ slot otherSlot (named_fields named).2 (named_fields tested).2))

theorem newer_iff (next old : HeadVersion) :
    Reconcile.newer next.seq next.root ⟨old.seq, old.root⟩ = true ↔ next.Newer old := by
  simp [Reconcile.newer, HeadVersion.Newer]

theorem stays (before : Represents db view) (after : Represents nextDb nextView)
    (value : view origin slot = some version)
    (kept : ∀ row, Selected db origin slot row → row ∈ rows nextDb "heads") :
    nextView origin slot = some version := by
  obtain ⟨row, selected, stored⟩ := existing before value
  obtain ⟨next, observed, nextStored⟩ := selected_version after ⟨kept row selected, selected.2⟩
  rw [version_unique row next version nextStored stored] at observed
  exact observed

theorem complete_change (after : Represents db view) (version : HeadVersion)
    (bound : PromotionBound.good origin ⟨version.seq, version.root⟩ (rows db "heads")) :
    HeadChange captured origin .complete (some version) (view origin .complete) := by
  obtain ⟨row, member, named⟩ := bound.1
  obtain ⟨next, value, nextStored⟩ := selected_version (origin := origin) (slot := .complete) after ⟨member, named⟩
  obtain ⟨seq, root, seqStored, rootStored, order⟩ := bound.2 row member named
  have same := version_unique row next (⟨seq, root⟩ : HeadVersion) nextStored ⟨seqStored, rootStored⟩
  subst next
  rw [value]
  rcases order with ⟨sameSeq, sameRoot⟩ | newer
  · have same : (⟨seq, root⟩ : HeadVersion) = version := by cases version; simp_all
    rw [same]
    exact .keep _ _
  · exact .advance _ _ _ (fun previous equal => by cases equal; exact (newer_iff _ _).mp newer)

/-- An empty initial slot has no previous version to regress or consume. -/
theorem initially_empty (after : Option HeadVersion) : HeadChange captured origin slot none after := by
  cases after with
  | none => exact .keep _ _
  | some version => exact .advance _ _ version (fun _ impossible => nomatch impossible)

theorem refines_retained (before : Represents db view) (after : Represents nextDb nextView)
    (kept : ∀ row ∈ rows db "heads", row ∈ rows nextDb "heads") : HeadTransition captured view nextView := by
  intro origin slot
  cases value : view origin slot with
  | none => exact initially_empty _
  | some version =>
    rw [retained before after kept origin slot version value]
    exact .keep _ _

end Synchronicity.HeadView
