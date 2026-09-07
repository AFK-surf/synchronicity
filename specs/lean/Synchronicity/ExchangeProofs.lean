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

private theorem best_le (origin : String) (heads : List Advertised) (bound : Nat) :
    best origin heads ≤ bound ↔
      ∀ head ∈ heads, head.origin = origin → version head ≤ bound := by
  induction heads with
  | nil => simp [best]
  | cons head rest ih =>
    simp only [best, Nat.max_le, ih, List.mem_cons, forall_eq_or_imp]
    by_cases same : head.origin = origin <;> simp [same]

/-- Reordering, repeating, or removing duplicate advertisements cannot affect
requests: only which versions are known matters, even when both slots advertise
one version. The premise compares sets, not multisets or arrival sequences. -/
theorem advertisement_order_and_duplicates_do_not_hide_updates {ours ours' theirs theirs' : List Advertised}
    (localVersions : ∀ head, head ∈ ours ↔ head ∈ ours')
    (remoteVersions : ∀ head, head ∈ theirs ↔ head ∈ theirs')
    (servable : List Advertised) (origin : String) :
    origin ∈ (plan ours theirs servable).want ↔
      origin ∈ (plan ours' theirs' servable).want := by
  have sameBest : ∀ (a b : List Advertised), (∀ head, head ∈ a ↔ head ∈ b) →
      best origin a = best origin b := by
    intro a b members
    apply Nat.le_antisymm
    · apply (best_le origin a _).mpr
      intro head member same
      exact (best_le origin b _).mp (Nat.le_refl _) head ((members head).mp member) same
    · apply (best_le origin b _).mpr
      intro head member same
      exact (best_le origin a _).mp (Nat.le_refl _) head ((members head).mpr member) same
  simp only [requests_exactly_newer_versions, sameBest ours ours' localVersions,
    sameBest theirs theirs' remoteVersions]

/-- A push always selects one of the heads supplied as servable, and that
head beats every version the peer advertises for its origin. -/
theorem pushes_only_servable_updates (ours theirs servable : List Advertised) (position : UInt64)
    (selected : position ∈ (plan ours theirs servable).push) :
    ∃ head index, (head, index) ∈ servable.zipIdx ∧ index.toUInt64 = position ∧
      best head.origin theirs < version head := by
  simp only [plan, List.mem_map, List.mem_filter, decide_eq_true_eq, index_get] at selected
  obtain ⟨⟨head, index⟩, ⟨member, newer⟩, same⟩ := selected
  exact ⟨head, index, member, same, newer⟩

/-- Under the native command's input bound, each returned position denotes
an actual supplied servable head; machine-integer encoding cannot change it. -/
theorem selected_positions_refer_to_servable_heads (ours theirs servable : List Advertised)
    (bounded : servable.length ≤ UInt64.size) (position : UInt64)
    (selected : position ∈ (plan ours theirs servable).push) :
    ∃ head, servable[position.toNat]? = some head ∧
      best head.origin theirs < version head := by
  obtain ⟨head, index, member, same, newer⟩ := pushes_only_servable_updates ours theirs servable position selected
  have lookup := List.mk_mem_zipIdx_iff_getElem?.mp member
  have lt : index < servable.length := (List.getElem?_eq_some_iff.mp lookup).1
  have converted : index.toUInt64.toNat = index := by
    exact UInt64.toNat_ofNat_of_lt' (Nat.lt_of_lt_of_le lt bounded)
  refine ⟨head, ?_, newer⟩
  simpa [← same, converted] using lookup

end Synchronicity.ExchangeProofs
