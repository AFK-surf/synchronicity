import VerifiedCore.Replication.History

/-! The operation-independent state machine for M3. It knows neither commands
nor their error branches. Timestamp changes are not version changes.

Capture evidence belongs to the concrete-to-abstract refinement: giving this
relation an arbitrary list of keys does not establish M3 for a production run.
In particular, consumption ends in absence, not an arbitrary replacement. -/
namespace Synchronicity.Goals.Mptsync
open VerifiedCore VerifiedCore.Replication

inductive HeadSlot where
  | complete
  | pending
  deriving DecidableEq

structure HeadVersion where
  seq : UInt64
  root : ByteArray

structure CapturedHead where
  origin : String
  version : HeadVersion

/-- Public version order, independent of the reconciliation implementation. -/
def HeadVersion.Newer (next old : HeadVersion) : Prop :=
  next.seq > old.seq ∨ (next.seq = old.seq ∧ old.root.toList < next.root.toList)

abbrev HeadView := String → HeadSlot → Option HeadVersion

/-- One slot can stay put, advance (including its first installation), or
consume exactly the captured pending version. Complete cannot be consumed. -/
inductive HeadChange (captured : List CapturedHead) (origin : String) :
    HeadSlot → Option HeadVersion → Option HeadVersion → Prop where
  | keep (slot : HeadSlot) (value : Option HeadVersion) : HeadChange captured origin slot value value
  | advance (slot : HeadSlot) (old : Option HeadVersion) (next : HeadVersion)
      (forward : ∀ previous, old = some previous → next.Newer previous) :
      HeadChange captured origin slot old (some next)
  | consume (old : HeadVersion) (owned : CapturedHead.mk origin old ∈ captured) :
      HeadChange captured origin .pending (some old) none

/-- Every origin and both slots obey the same rule. There are no exceptions
for a particular command, success/error branch, or implementation module. -/
def HeadTransition (captured : List CapturedHead) (before after : HeadView) : Prop :=
  ∀ origin slot, HeadChange captured origin slot (before origin slot) (after origin slot)

theorem HeadChange.complete_present (change : HeadChange captured origin .complete (some old) next) :
    ∃ version, next = some version ∧ (version = old ∨ version.Newer old) := by
  cases change with
  | keep => exact ⟨old, rfl, Or.inl rfl⟩
  | advance _ _ version forward => exact ⟨version, rfl, Or.inr (forward old rfl)⟩

theorem HeadChange.removal_requires_capture (change : HeadChange captured origin slot (some old) none) :
    slot = .pending ∧ CapturedHead.mk origin old ∈ captured := by
  cases change with
  | consume _ owned => exact ⟨rfl, owned⟩

theorem HeadChange.replacement_is_newer (change : HeadChange captured origin slot (some old) (some next))
    (different : next ≠ old) : next.Newer old := by
  cases change with
  | keep => exact False.elim (different rfl)
  | advance _ _ _ forward => exact forward old rfl

end Synchronicity.Goals.Mptsync
