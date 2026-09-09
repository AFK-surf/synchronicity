import Synchronicity.AtomicFileView
import Synchronicity.HeadTransition

/-! Shared, operation-independent vocabulary for metadata convergence.

This module deliberately contains no scheduler, Fetch command, or goal entry
point.  It says what a stable target and a correct public observation mean.
Concrete execution modules must prove that production operations reach and
preserve these predicates; an execution constructor must not assume them.
-/
namespace Synchronicity.MptsyncConvergence
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
  SimulatedHost TrieProgramProofs

/-- Eventually, at one finite observation of an infinite execution. -/
def Eventually (property : Nat → Prop) : Prop := ∃ start, property start

/-- From one finite observation onward, including that observation. -/
def AlwaysFrom (start : Nat) (property : Nat → Prop) : Prop :=
  ∀ now, start ≤ now → property now

/-- The liveness shape required by M1: reach the right state and stay there. -/
def EventuallyAlways (property : Nat → Prop) : Prop :=
  ∃ start, AlwaysFrom start property

/-- The public ordering, including equality.  Unlike a numeric encoding, this
definition remains meaningful without a fixed root-width assumption. -/
def VersionLE (left right : HeadVersion) : Prop :=
  left = right ∨ right.Newer left

/-- A greatest valid signed version for one origin.  Validity is supplied by
the authority/signature layer and is independent of observation order. -/
def LatestValid (valid : Head → Prop) (origin : Origin.Parsed) (latest : Head) : Prop :=
  latest.origin = origin ∧ valid latest ∧
    ∀ candidate, candidate.origin = origin → valid candidate →
      VersionLE ⟨candidate.seq, candidate.root⟩ ⟨latest.seq, latest.root⟩

/-- The stable per-device projection of one common latest version.  The
snapshot is the publisher's immutable metadata image; replicas describe the
content responsibilities created by materializing the permitted projection.
`before` is the baseline for obligations whose policy is forever. -/
structure ViewTarget where
  head : Head
  snapshot : RawSnapshot
  scope : Trie.Serve.Scope
  replicas : List Materialize.Target
  before : Database

def ViewTarget.allowed (target : ViewTarget) (key : ByteArray) : Prop :=
  target.scope.admitsKeyPath (Trie.keyNibbles key) = true

/-- One device exposes exactly its permitted file list for the selected
version and keeps the corresponding current/forever acquisition duties.
Completeness here is metadata completeness, not downloaded file content. -/
def CorrectView (services : MaterializedView.Services) (origin : Origin.Parsed)
    (target : ViewTarget) (db : Database) : Prop :=
  target.head.origin = origin ∧
  AtomicFileView.Installed db target.head ∧
  SnapshotViewProgress.ExactFiles services target.snapshot target.head.root
    target.allowed db (Origin.canonical origin) ∧
  MaterializedView.CurrentRequirements target.replicas db ∧
  MaterializedView.ForeverRequirements target.replicas target.before db

/-- A settled system target.  Every participant selects the same latest head
for an origin, while its scope and retention policy may differ by device. -/
structure Scenario (Device : Type) where
  participates : Device → Prop
  includes : Origin.Parsed → Prop
  latest : Origin.Parsed → Head
  target : Device → Origin.Parsed → ViewTarget
  target_latest : ∀ device origin,
    (target device origin).head = latest origin
  latest_origin : ∀ origin, (latest origin).origin = origin

def CorrectDevice (services : MaterializedView.Services) (scenario : Scenario Device)
    (databases : Device → Database) (device : Device) : Prop :=
  ∀ origin, scenario.includes origin →
    CorrectView services origin (scenario.target device origin) (databases device)

def CorrectSystem (services : MaterializedView.Services) (scenario : Scenario Device)
    (databases : Device → Database) : Prop :=
  ∀ device, scenario.participates device →
    CorrectDevice services scenario databases device

/-- M1's domain property over an infinite sequence of public database
observations.  An execution proof must establish this predicate; it is not a
premise baked into the definition of a production step. -/
def Converges (services : MaterializedView.Services) (scenario : Scenario Device)
    (trace : Nat → Device → Database) : Prop :=
  EventuallyAlways fun now => CorrectSystem services scenario (trace now)

theorem eventuallyAlways_of_reached_and_preserved
    (reached : property start)
    (preserved : ∀ now, start ≤ now → property now → property (now + 1)) :
    EventuallyAlways property := by
  have steps : ∀ offset, property (start + offset) := by
    intro offset
    induction offset with
    | zero => simpa using reached
    | succ offset held =>
      rw [Nat.add_succ]
      exact preserved (start + offset) (Nat.le_add_right _ _) held
  refine ⟨start, fun now after => ?_⟩
  obtain ⟨offset, rfl⟩ := Nat.exists_eq_add_of_le after
  exact steps offset

theorem eventuallyAlways_and
    (left : EventuallyAlways first) (right : EventuallyAlways second) :
    EventuallyAlways fun now => first now ∧ second now := by
  obtain ⟨leftStart, left⟩ := left
  obtain ⟨rightStart, right⟩ := right
  refine ⟨max leftStart rightStart, fun now after => ⟨?_, ?_⟩⟩
  · exact left now (Nat.le_trans (Nat.le_max_left _ _) after)
  · exact right now (Nat.le_trans (Nat.le_max_right _ _) after)

/-- Finitely many independently converging observations have one common
finite point after which they all remain true. -/
theorem eventuallyAlways_all_list (items : List A) (property : A → Nat → Prop)
    (each : ∀ item ∈ items, EventuallyAlways (property item)) :
    EventuallyAlways fun now => ∀ item ∈ items, property item now := by
  induction items with
  | nil => exact ⟨0, fun _ _ item member => nomatch member⟩
  | cons item rest ih =>
    have head := each item (List.mem_cons_self ..)
    have tail := ih fun value member => each value (List.mem_cons_of_mem item member)
    obtain ⟨start, both⟩ := eventuallyAlways_and head tail
    refine ⟨start, fun now after value member => ?_⟩
    have held := both now after
    rcases List.mem_cons.mp member with rfl | member
    · exact held.1
    · exact held.2 value member

/-- A finite enumeration of every participant/origin obligation.  This is an
input-size condition, not a convergence premise; extra pairs are harmless. -/
structure FiniteCoverage (scenario : Scenario Device) where
  pairs : List (Device × Origin.Parsed)
  covers : ∀ device origin, scenario.participates device → scenario.includes origin →
    (device, origin) ∈ pairs

/-- Per-device/per-origin convergence lifts to one system-wide stabilization
point when the participating obligation set is finite. -/
theorem finite_targets_converge {Device : Type}
    (services : MaterializedView.Services) (scenario : Scenario Device)
    (trace : Nat → Device → Database)
    (coverage : FiniteCoverage scenario)
    (each : ∀ pair : Device × Origin.Parsed, pair ∈ coverage.pairs →
      EventuallyAlways fun now =>
        CorrectView services pair.2 (scenario.target pair.1 pair.2) (trace now pair.1)) :
    Converges services scenario trace := by
  obtain ⟨start, all⟩ := eventuallyAlways_all_list coverage.pairs
    (fun pair now =>
      CorrectView services pair.2 (scenario.target pair.1 pair.2) (trace now pair.1)) each
  refine ⟨start, fun now after device member origin included => ?_⟩
  have correct := all now after
  exact correct (device, origin) (coverage.covers device origin member included)

/-- Exact views of the same immutable root under the same permission predicate
agree on every observable file record, even if the two databases contain
different unrelated rows. -/
theorem equal_permissions_have_equal_file_views
    (left : SnapshotViewProgress.ExactFiles services snapshot root allowed leftDb origin)
    (right : SnapshotViewProgress.ExactFiles services snapshot root allowed rightDb origin) :
    ∀ space path values,
      MaterializedView.Observed leftDb origin (.file space path) values ↔
      MaterializedView.Observed rightDb origin (.file space path) values := by
  intro space path values
  rw [left space path values, right space path values]

/-- Correct participants always install the scenario's one common latest
version.  Permissions affect projection, not version selection. -/
theorem correct_devices_select_the_same_version
    (correct : CorrectSystem services scenario databases)
    (leftMember : scenario.participates left)
    (rightMember : scenario.participates right)
    (included : scenario.includes origin) :
    AtomicFileView.Installed (databases left) (scenario.latest origin) ∧
      AtomicFileView.Installed (databases right) (scenario.latest origin) := by
  have leftCorrect := correct left leftMember origin included
  have rightCorrect := correct right rightMember origin included
  exact ⟨by simpa [scenario.target_latest left origin] using leftCorrect.2.1,
    by simpa [scenario.target_latest right origin] using rightCorrect.2.1⟩

/-- When two correct participants have the same permission scope, their
observable file directories agree exactly. -/
theorem correct_devices_with_equal_scopes_agree
    (correct : CorrectSystem services scenario databases)
    (leftMember : scenario.participates left)
    (rightMember : scenario.participates right)
    (included : scenario.includes origin)
    (sameScope : (scenario.target left origin).scope =
      (scenario.target right origin).scope)
    (sameSnapshot : (scenario.target left origin).snapshot =
      (scenario.target right origin).snapshot) :
    ∀ space path values,
      MaterializedView.Observed (databases left) (Origin.canonical origin)
          (.file space path) values ↔
        MaterializedView.Observed (databases right) (Origin.canonical origin)
          (.file space path) values := by
  have leftCorrect := correct left leftMember origin included
  have rightCorrect := correct right rightMember origin included
  have sameHead := (scenario.target_latest left origin).trans
    (scenario.target_latest right origin).symm
  have leftExact := leftCorrect.2.2.1
  have rightExact := rightCorrect.2.2.1
  change SnapshotViewProgress.ExactFiles services (scenario.target right origin).snapshot
    (scenario.target right origin).head.root
    (fun key => (scenario.target right origin).scope.admitsKeyPath (Trie.keyNibbles key) = true)
    (databases right) (Origin.canonical origin) at rightExact
  rw [← sameScope, ← sameSnapshot, ← sameHead] at rightExact
  exact equal_permissions_have_equal_file_views leftExact rightExact

end Synchronicity.MptsyncConvergence
