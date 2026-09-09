import Synchronicity.ExchangeProofs
import Synchronicity.ExchangeVersionProofs
import Synchronicity.HeadTransition

/-! Operation-independent observations of the production head-exchange plan.

`Exchange.plan` returns origins for pulls and integer positions for pushes.  The
relations below interpret those outputs as advertised heads, so reordering an
input list cannot make two equivalent plans look different merely because a
position changed.  Validity is the native fixed-width boundary contract; it is
not defined in terms of a planner decision or a later acceptance result.
-/
namespace Synchronicity.AdvertisementSelection
open VerifiedCore.Replication.Exchange

private theorem byteArray_toList_loop (bytes : ByteArray) (index : Nat) (acc : List UInt8) :
    ByteArray.toList.loop bytes index acc =
      acc.reverse ++ bytes.data.toList.drop index := by
  induction index, acc using ByteArray.toList.loop.induct bytes with
  | case1 index acc before ih =>
    rw [ByteArray.toList.loop, if_pos before, ih]
    have remaining : bytes.data.toList.drop index =
        bytes.data[index] :: bytes.data.toList.drop (index + 1) := by
      rw [List.drop_eq_getElem_cons (by simpa using before)]
      rfl
    rw [remaining]
    simp [ByteArray.get!, before]
  | case2 index acc after =>
    rw [ByteArray.toList.loop, if_neg after]
    have empty : bytes.data.toList.drop index = [] :=
      List.drop_of_length_le (by simpa using after)
    simp [empty]

private theorem byteArray_toList_eq (bytes : ByteArray) :
    bytes.toList = bytes.data.toList := by
  rw [ByteArray.toList, byteArray_toList_loop]
  rfl

/-- A head admitted to the native exchange planner has a fixed-width root. -/
def ValidAdvertisement (head : Advertised) : Prop := head.root.size = 32

/-- Two lists contain the same valid advertisements, ignoring order and
multiplicity.  Both validity fields matter: invalid extra input is not silently
excluded from the production planner's comparison. -/
structure SameValidAdvertisements (left right : List Advertised) : Prop where
  leftValid : ∀ head ∈ left, ValidAdvertisement head
  rightValid : ∀ head ∈ right, ValidAdvertisement head
  same : ∀ head, head ∈ left ↔ head ∈ right

/-- A remote head is selected for pulling when its origin is requested and it
is one of the greatest advertised versions for that origin.  This names the
head/version meant by `want`, rather than observing only an origin string. -/
def Pulls (theirs : List Advertised) (result : ExchangePlan) (head : Advertised) : Prop :=
  head ∈ theirs ∧ head.origin ∈ result.want ∧ version head = ExchangeProofs.best head.origin theirs

/-- A servable head is selected for pushing when an actual returned position
resolves to it.  Membership intentionally ignores duplicate positions. -/
def Pushes (servable : List Advertised) (result : ExchangePlan) (head : Advertised) : Prop :=
  ∃ position ∈ result.push, servable[position.toNat]? = some head

/-- Equality of the semantic pull and push selections of two actual planner
results. -/
def Equivalent (leftRemote rightRemote leftServable rightServable : List Advertised)
    (left right : ExchangePlan) : Prop :=
  (∀ head, Pulls leftRemote left head ↔ Pulls rightRemote right head) ∧
  (∀ head, Pushes leftServable left head ↔ Pushes rightServable right head)

private theorem add_get (state : Index) (head : Advertised) (origin : String) :
    (add state head).getD origin 0 =
      max (state.getD origin 0) (if head.origin = origin then version head else 0) := by
  simp only [add, Std.TreeMap.getD_insert, Std.LawfulEqCmp.compare_eq_iff_eq]
  split <;> simp_all

private theorem fold_get (heads : List Advertised) (state : Index) (origin : String) :
    (heads.foldl add state).getD origin 0 =
      max (state.getD origin 0) (ExchangeProofs.best origin heads) := by
  induction heads generalizing state with
  | nil => simp [ExchangeProofs.best]
  | cons head rest ih =>
    simp only [List.foldl_cons, ih, add_get, ExchangeProofs.best, Nat.max_assoc]

private theorem index_get (heads : List Advertised) (origin : String) :
    (index heads).getD origin 0 = ExchangeProofs.best origin heads := by
  simp [index, fold_get]

/-- The greatest advertised version depends on membership, not list order or
the number of copies of a head. -/
theorem same_advertisements_best
    (same : ∀ head, head ∈ left ↔ head ∈ right) (origin : String) :
    ExchangeProofs.best origin left = ExchangeProofs.best origin right := by
  have bounded (heads : List Advertised) (bound : Nat) :
      ExchangeProofs.best origin heads ≤ bound ↔
        ∀ head ∈ heads, head.origin = origin → version head ≤ bound := by
    induction heads with
    | nil => simp [ExchangeProofs.best]
    | cons head rest ih =>
      simp only [ExchangeProofs.best, Nat.max_le, ih, List.mem_cons, forall_eq_or_imp]
      by_cases named : head.origin = origin <;> simp [named]
  apply Nat.le_antisymm
  · apply (bounded left _).mpr
    intro head member named
    exact (bounded right _).mp (Nat.le_refl _) head ((same head).mp member) named
  · apply (bounded right _).mpr
    intro head member named
    exact (bounded left _).mp (Nat.le_refl _) head ((same head).mpr member) named

private theorem version_le_best (head : Advertised) (member : head ∈ heads)
    (named : head.origin = origin) : version head ≤ ExchangeProofs.best origin heads := by
  induction heads with
  | nil => cases member
  | cons first rest ih =>
    simp only [List.mem_cons] at member
    simp only [ExchangeProofs.best]
    rcases member with rfl | member
    · rw [if_pos named]
      exact Nat.le_max_left ..
    · exact Nat.le_trans (ih member) (Nat.le_max_right ..)

/-- The actual `want` list denotes exactly the greatest remote heads whose
version is newer than every locally advertised version of the same origin. -/
theorem plan_pulls_iff (ours theirs servable : List Advertised) (head : Advertised) :
    Pulls theirs (plan ours theirs servable) head ↔
      head ∈ theirs ∧ ExchangeProofs.best head.origin ours < version head ∧
        version head = ExchangeProofs.best head.origin theirs := by
  simp only [Pulls, ExchangeProofs.requests_exactly_newer_versions]
  constructor
  · rintro ⟨member, newer, greatest⟩
    exact ⟨member, by simpa [greatest] using newer, greatest⟩
  · rintro ⟨member, newer, greatest⟩
    exact ⟨member, by simpa [greatest] using newer, greatest⟩

/-- A greatest remote head selected for pulling is newer in the public
sequence/root order than every local advertisement for the same origin. -/
theorem pulled_head_is_newer_than_local (ours theirs servable : List Advertised)
    (head prior : Advertised) (selected : Pulls theirs (plan ours theirs servable) head)
    (priorMember : prior ∈ ours) (sameOrigin : prior.origin = head.origin)
    (priorValid : ValidAdvertisement prior) (headValid : ValidAdvertisement head) :
    HeadVersion.Newer ⟨head.seq, head.root⟩ ⟨prior.seq, prior.root⟩ := by
  have meaning := (plan_pulls_iff ours theirs servable head).mp selected
  have priorBound := version_le_best prior priorMember sameOrigin
  have ordered : version prior < version head := Nat.lt_of_le_of_lt priorBound meaning.2.1
  have publicOrder :=
    (ExchangeVersionProofs.version_order_is_sequence_then_root prior head priorValid headValid).mp ordered
  rcases publicOrder with sequence | ⟨sequence, root⟩
  · exact Or.inl sequence
  · exact Or.inr ⟨sequence.symm, by
      simpa using root⟩

/-- The returned integer positions denote exactly the servable heads which
beat the peer's greatest advertisement for their origin. -/
theorem plan_pushes_iff (ours theirs servable : List Advertised)
    (bounded : servable.length ≤ UInt64.size) (head : Advertised) :
    Pushes servable (plan ours theirs servable) head ↔
      head ∈ servable ∧ ExchangeProofs.best head.origin theirs < version head := by
  constructor
  · rintro ⟨position, selected, source⟩
    obtain ⟨chosen, lookup, newer⟩ :=
      ExchangeProofs.selected_positions_refer_to_servable_heads ours theirs servable bounded position selected
    have same : chosen = head := Option.some.inj (lookup.symm.trans source)
    subst chosen
    exact ⟨List.mem_of_getElem? source, newer⟩
  · rintro ⟨member, newer⟩
    obtain ⟨position, source⟩ := List.mem_iff_getElem?.mp member
    have before : position < servable.length := (List.getElem?_eq_some_iff.mp source).1
    have fits : position < UInt64.size := Nat.lt_of_lt_of_le before bounded
    refine ⟨position.toUInt64, ?_, ?_⟩
    · simp only [plan, List.mem_map, List.mem_filter, decide_eq_true_eq, index_get]
      exact ⟨(head, position), ⟨List.mk_mem_zipIdx_iff_getElem?.mpr source, newer⟩, rfl⟩
    · simpa only [UInt64.toNat_ofNat_of_lt' fits] using source

/-- A concrete head selected for pushing is newer in the public sequence/root
order than every remote advertisement for the same origin. -/
theorem pushed_head_is_newer_than_remote (ours theirs servable : List Advertised)
    (bounded : servable.length ≤ UInt64.size) (head remote : Advertised)
    (selected : Pushes servable (plan ours theirs servable) head)
    (remoteMember : remote ∈ theirs) (sameOrigin : remote.origin = head.origin)
    (remoteValid : ValidAdvertisement remote) (headValid : ValidAdvertisement head) :
    HeadVersion.Newer ⟨head.seq, head.root⟩ ⟨remote.seq, remote.root⟩ := by
  have meaning := (plan_pushes_iff ours theirs servable bounded head).mp selected
  have remoteBound := version_le_best remote remoteMember sameOrigin
  have ordered : version remote < version head := Nat.lt_of_le_of_lt remoteBound meaning.2
  have publicOrder :=
    (ExchangeVersionProofs.version_order_is_sequence_then_root remote head remoteValid headValid).mp ordered
  rcases publicOrder with sequence | ⟨sequence, root⟩
  · exact Or.inl sequence
  · exact Or.inr ⟨sequence.symm, by
      simpa using root⟩

/-- The semantic result of the production planner depends only on the sets of
valid local, remote and servable advertisements. -/
theorem plans_equivalent
    (localSet : SameValidAdvertisements ours ours')
    (remote : SameValidAdvertisements theirs theirs')
    (servable : SameValidAdvertisements served served')
    (leftBound : served.length ≤ UInt64.size)
    (rightBound : served'.length ≤ UInt64.size) :
    Equivalent theirs theirs' served served'
      (plan ours theirs served) (plan ours' theirs' served') := by
  constructor
  · intro head
    rw [plan_pulls_iff, plan_pulls_iff, same_advertisements_best localSet.same,
      same_advertisements_best remote.same]
    exact and_congr (remote.same head) (Iff.rfl)
  · intro head
    rw [plan_pushes_iff _ _ _ leftBound, plan_pushes_iff _ _ _ rightBound,
      same_advertisements_best remote.same]
    exact and_congr (servable.same head) (Iff.rfl)

end Synchronicity.AdvertisementSelection
