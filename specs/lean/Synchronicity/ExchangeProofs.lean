import VerifiedCore.Replication.Exchange
import Std.Data.TreeMap.Lemmas
import Std.Tactic

/-! User-facing head-exchange properties, proved about the production planner.
This establishes exchange selection, not authenticated adoption or eventual
promotion. The latter require the rest of the real mptsync execution. -/
namespace Synchronicity.ExchangeProofs
open VerifiedCore.Replication.Exchange

/-- The greatest advertised version of one origin, independently of indexing. -/
def best (origin : String) : List Advertised → Nat
  | [] => 0
  | head :: rest => max (if head.origin = origin then version head else 0) (best origin rest)

private theorem add_get (state : Index) (head : Advertised) (origin : String) :
    (add state head).getD origin 0 =
      max (state.getD origin 0) (if head.origin = origin then version head else 0) := by
  simp only [add, Std.TreeMap.getD_insert, Std.LawfulEqCmp.compare_eq_iff_eq]
  split <;> simp_all

private theorem fold_get (heads : List Advertised) (state : Index) (origin : String) :
    (heads.foldl add state).getD origin 0 = max (state.getD origin 0) (best origin heads) := by
  induction heads generalizing state with
  | nil => simp [best]
  | cons head rest ih =>
    simp only [List.foldl_cons, ih, add_get, best, Nat.max_assoc]

private theorem index_get (heads : List Advertised) (origin : String) :
    (index heads).getD origin 0 = best origin heads := by
  simp [index, fold_get]

private theorem requested_iff (ours theirs : Index) (origin : String) :
    origin ∈ requested ours theirs ↔ ours.getD origin 0 < theirs.getD origin 0 := by
  simp only [requested, List.mem_map, List.mem_filter, decide_eq_true_eq]
  constructor
  · rintro ⟨⟨key, value⟩, ⟨member, newer⟩, rfl⟩
    have found := Std.TreeMap.mem_toList_iff_getElem?_eq_some.mp member
    simpa [Std.TreeMap.getD_eq_getD_getElem?, found] using newer
  · intro newer
    have present : ∃ value, theirs[origin]? = some value := by
      cases h : theirs[origin]? with
      | none => simp [Std.TreeMap.getD_eq_getD_getElem?, h] at newer
      | some value => exact ⟨value, rfl⟩
    obtain ⟨value, found⟩ := present
    exact ⟨(origin, value), ⟨Std.TreeMap.mem_toList_iff_getElem?_eq_some.mpr found,
      by simpa [Std.TreeMap.getD_eq_getD_getElem?, found] using newer⟩, rfl⟩

/-- A device asks for an origin exactly when the peer advertises a newer
version than every version the device already knows for that origin. -/
theorem requests_exactly_newer_versions (ours theirs servable : List Advertised) (origin : String) :
    origin ∈ (plan ours theirs servable).want ↔ best origin ours < best origin theirs := by
  simp only [plan, requested_iff, index_get]

private theorem best_perm (origin : String) {a b : List Advertised} (h : a.Perm b) :
    best origin a = best origin b := by
  induction h with
  | nil => rfl
  | cons head h ih => simp only [best, ih]
  | swap a b rest => simp only [best]; omega
  | trans h₁ h₂ ih₁ ih₂ => exact ih₁.trans ih₂

/-- Reordering either device's advertisements cannot change which origins
are requested, including two slots at the same sequence and duplicate rows. -/
theorem advertisement_order_does_not_hide_updates {ours ours' theirs theirs' : List Advertised}
    (localOrder : ours.Perm ours') (remoteOrder : theirs.Perm theirs')
    (servable : List Advertised) (origin : String) :
    origin ∈ (plan ours theirs servable).want ↔
      origin ∈ (plan ours' theirs' servable).want := by
  simp only [requests_exactly_newer_versions, best_perm origin localOrder,
    best_perm origin remoteOrder]

/-- A push always selects one of the heads supplied as servable, and that
head beats every version the peer advertises for its origin. -/
theorem pushes_only_servable_updates (ours theirs servable : List Advertised) (position : UInt64)
    (selected : position ∈ (plan ours theirs servable).push) :
    ∃ head index, (head, index) ∈ servable.zipIdx ∧ index.toUInt64 = position ∧
      best head.origin theirs < version head := by
  simp only [plan, List.mem_map, List.mem_filter, decide_eq_true_eq, index_get] at selected
  obtain ⟨⟨head, index⟩, ⟨member, newer⟩, same⟩ := selected
  exact ⟨head, index, member, same, newer⟩

end Synchronicity.ExchangeProofs
