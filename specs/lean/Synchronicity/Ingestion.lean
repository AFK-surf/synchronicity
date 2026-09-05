import Synchronicity.Cas

/-!
The local ingestion pipeline below the CAS accounting model, for one content
root and settled tree shape. Byte strings are represented by injective natural
number encodings; `expected g` is the authenticated group's content at that
root. Cryptographic verification is the explicit equality guard on `Write`.
Flush and bitmap commit are separate transitions. Crashes discard unflushed
writes, never inventing a successful flush. SQLite atomicity, flush semantics,
and correctness of the bao verifier remain environmental assumptions.
-/
namespace Synchronicity.Ingestion

/-- One settled object's volatile payload/outboard groups, stable groups and
committed bitmap. Group contents include the required outboard evidence. -/
structure State where
  /-- Verified but not necessarily flushed writes. -/
  staged : Nat → Option Nat := fun _ => none
  /-- Payload and outboard acknowledged by a successful flush. -/
  stable : Nat → Option Nat := fun _ => none
  /-- Groups advertised by the committed database row. -/
  claimed : Set Nat := ∅

/-- Both disk layers contain only authenticated content; claimed bits have
stable evidence. Staging preserves every already stable group. -/
structure Invariant (size : Nat) (expected : Nat → Nat) (st : State) : Prop where
  /-- Verification checks content identity at this group index. -/
  staged_correct : ∀ g bytes, st.staged g = some bytes → bytes = expected g
  /-- Successful flushes persist verified groups. -/
  stable_correct : ∀ g bytes, st.stable g = some bytes → bytes = expected g
  /-- Existing stable groups are not destroyed by a later partial write. -/
  preserves : ∀ g bytes, st.stable g = some bytes → st.staged g = some bytes
  /-- Every advertised bit has actual stable data and lies in this tree. -/
  claimed_backed : ∀ g ∈ st.claimed, g < Cas.groupCount size ∧
    st.stable g = some (expected g)

/-- A successful verifier writes only the authenticated group. Failed proofs
make no transition; previously verified groups cannot be overwritten with
different bytes. -/
@[transition]
def Write (size : Nat) (expected : Nat → Nat) (g bytes : Nat) : Transition State where
  guard _ := g < Cas.groupCount size ∧ bytes = expected g
  post st := { st with staged := Function.update st.staged g (some bytes) }

/-- Both payload and outboard flush succeeded before the bitmap is eligible. -/
@[transition, rust_impl "cas-verified-groups-flush"]
def Flush : Transition State where
  guard _ := True
  post st := { st with stable := st.staged }

/-- The SQLite row advertises only groups whose writes have already flushed. -/
@[transition]
def Commit (size : Nat) (groups : Set Nat) : Transition State where
  guard st := ∀ g ∈ groups, g < Cas.groupCount size ∧ ∃ bytes, st.stable g = some bytes
  post st := { st with claimed := st.claimed ∪ groups }

/-- Crash or abandoned writer: lose volatile state, retain only flushed bytes
and the last atomic database commit. -/
@[transition]
def Crash : Transition State where
  guard _ := True
  post st := { st with staged := st.stable }

/-- The physical pipeline's events. -/
inductive Kind where
  | write (g bytes : Nat) | flush | commit (groups : Set Nat) | crash

/-- The event's transition, before accounting abstraction. -/
@[transition]
def Trans (size : Nat) (expected : Nat → Nat) : Kind → Transition State
  | .write g bytes => Write size expected g bytes
  | .flush => Flush
  | .commit groups => Commit size groups
  | .crash => Crash

/-- A successful stage, flush, bitmap commit or crash. -/
def Step (size : Nat) (expected : Nat → Nat) (st st' : State) : Prop :=
  ∃ k, (Trans size expected k).rel st st'

theorem invariant_step {st st' : State} (inv : Invariant size expected st)
    (step : Step size expected st st') : Invariant size expected st' := by
  obtain ⟨staged, stable, keeps, claims⟩ := inv
  obtain ⟨k, hg, rfl⟩ := step
  cases k <;> simp only [transition] at hg ⊢ <;> constructor <;> grind

/-- An empty file pipeline, before any row is advertised. -/
def system (size : Nat) (expected : Nat → Nat) : System State :=
  ⟨{}, Step size expected⟩

theorem invariant : (system size expected).Invariant (Invariant size expected) where
  init := by constructor <;> simp [system]
  step := invariant_step

/-- A complete bitmap implies actual authenticated stable contents, rather
than defining byte availability to be bitmap completeness. -/
theorem complete_has_bytes {st : State} (reachable : (system size expected).Reachable st)
    (complete : ∀ g, g < Cas.groupCount size → g ∈ st.claimed) :
    ∀ g, g < Cas.groupCount size → st.stable g = some (expected g) := by
  intro g hg
  exact (invariant.reachable reachable).claimed_backed g (complete g hg) |>.2

/-- A write without a successful flush cannot advertise its group. -/
theorem unflushed_cannot_commit {st : State} (absent : st.stable g = none)
    (requested : g ∈ groups) : ¬ (Commit size groups).guard st := by
  intro h
  obtain ⟨bytes, hbytes⟩ := (h g requested).2
  rw [absent] at hbytes
  contradiction

/-- At a settled size, the lower pipeline's bitmap commit is exactly the
accounting model's group settlement. Its physical backing is established by
`invariant_step`, separately from this equality of accounting projections. -/
theorem commit_refines_bitmap {st : State} {cell : Cas.Cell H}
    (inv : Invariant size expected st) (row : cell.row) (sameSize : cell.size = size)
    (sameHeld : cell.held = st.claimed) (enabled : (Commit size groups).guard st) :
    ((Commit size groups).post st).claimed = Cas.settleHeld cell size groups := by
  ext g
  simp only [Commit, Set.mem_union, Cas.settleHeld, Set.mem_setOf_eq]
  rw [sameSize, sameHeld]
  constructor
  · intro h
    rcases h with old | new
    · exact ⟨(inv.claimed_backed g old).1, Or.inr ⟨row, rfl, old⟩⟩
    · exact ⟨(enabled g new).1, Or.inl new⟩
  · rintro ⟨_, new | ⟨_, _, old⟩⟩
    · exact Or.inr new
    · exact Or.inl old

end Synchronicity.Ingestion

#lint
