import VerifiedCore.Cas

/-! Proofs about the executable CAS planning functions: group counting, size
settlement and the span plan every metadata commit runs. These are the
functions `Cas/IngestCommit.lean` calls; nothing here models Rust. -/
namespace Synchronicity.CasPlanProofs
open VerifiedCore
set_option Elab.async false

/-- Group counting is the ceiling of `size / 16384` with an empty object
counted as one group, computed without overflow. -/
theorem groupCount_spec (size : UInt64) :
    (VerifiedCore.groupCount size).toNat =
      if size = 0 then 1 else (size.toNat - 1) / 16384 + 1 := by
  have bound := size.toNat_lt
  by_cases zero : size = 0
  · subst size
    simp [VerifiedCore.groupCount]
  · have positive : 0 < size.toNat := Nat.pos_of_ne_zero (fun h => zero (UInt64.toNat_inj.mp h))
    simp only [VerifiedCore.groupCount, beq_iff_eq, zero, ↓reduceIte]
    simp [UInt64.toNat_add, UInt64.toNat_div, UInt64.toNat_sub]
    omega

/-- Every object, the empty one included, has at least one group. -/
theorem groupCount_pos (size : UInt64) : 0 < (VerifiedCore.groupCount size).toNat := by
  rw [groupCount_spec]
  split <;> omega

/-- Acceptance is exactly the CAS settlement rule, with complete/final-group
evidence supplied by the row adapter, not guessed by the core. -/
theorem settlement_accepts_iff (row durable complete finalHeld : Bool) (recorded claimed : UInt64) :
    VerifiedCore.settleSize row durable complete finalHeld recorded claimed ≠ 0 ↔
      row = false ∨ recorded = claimed ∨ (durable = false ∧ complete = false ∧ finalHeld = false) := by
  unfold VerifiedCore.settleSize
  cases row <;> cases durable <;> cases complete <;> cases finalHeld <;>
    by_cases same : recorded = claimed <;>
    by_cases groups : VerifiedCore.groupCount recorded = VerifiedCore.groupCount claimed <;>
    simp [same, groups]

/-- Reset is requested exactly for an accepted size correction with a changed
group count. -/
theorem settlement_reset_iff (row durable complete finalHeld : Bool) (recorded claimed : UInt64) :
    VerifiedCore.settleSize row durable complete finalHeld recorded claimed = 2 ↔
      row = true ∧ recorded ≠ claimed ∧ durable = false ∧ complete = false ∧ finalHeld = false ∧
        VerifiedCore.groupCount recorded ≠ VerifiedCore.groupCount claimed := by
  unfold VerifiedCore.settleSize
  cases row <;> cases durable <;> cases complete <;> cases finalHeld <;>
    by_cases same : recorded = claimed <;>
    by_cases groups : VerifiedCore.groupCount recorded = VerifiedCore.groupCount claimed <;>
    simp [same, groups]

private theorem min_le_iff {a b c : Nat} : min a b ≤ c ↔ a ≤ c ∨ b ≤ c := by omega
private theorem lt_max_iff {a b c : Nat} : a < max b c ↔ a < b ∨ a < c := by omega
private theorem lt_min_iff {a b c : Nat} : a < min b c ↔ a < b ∧ a < c := by omega

theorem mem_insertSpan (span r : VerifiedCore.GroupSpan) (spans : List VerifiedCore.GroupSpan) :
    r ∈ VerifiedCore.insertSpan span spans ↔ r = span ∨ r ∈ spans := by
  induction spans with
  | nil => simp [VerifiedCore.insertSpan]
  | cons head rest ih =>
    simp only [VerifiedCore.insertSpan]
    split
    · simp
    · simp only [List.mem_cons, ih]
      exact or_left_comm

theorem mem_sortSpans (r : VerifiedCore.GroupSpan) (spans : List VerifiedCore.GroupSpan) :
    r ∈ VerifiedCore.sortSpans spans ↔ r ∈ spans := by
  induction spans with
  | nil => simp [VerifiedCore.sortSpans]
  | cons head rest ih => simp [VerifiedCore.sortSpans, mem_insertSpan, ih]

theorem insertSpan_pairwise (span : VerifiedCore.GroupSpan) (spans : List VerifiedCore.GroupSpan)
    (sorted : spans.Pairwise (fun a b => a.start ≤ b.start)) :
    (VerifiedCore.insertSpan span spans).Pairwise (fun a b => a.start ≤ b.start) := by
  induction spans with
  | nil => simp [VerifiedCore.insertSpan]
  | cons head rest ih =>
    obtain ⟨headLE, restSorted⟩ := List.pairwise_cons.mp sorted
    simp only [VerifiedCore.insertSpan]
    split
    · rename_i le
      apply List.pairwise_cons.mpr
      refine ⟨?_, sorted⟩
      intro r hr
      rcases List.mem_cons.mp hr with rfl | hr
      · exact le
      · exact Nat.le_trans le (headLE r hr)
    · rename_i gt
      apply List.pairwise_cons.mpr
      refine ⟨?_, ih restSorted⟩
      intro r hr
      rcases (mem_insertSpan span r rest).mp hr with rfl | hr
      · omega
      · exact headLE r hr

/-- Sorting by start is what interval merging needs: every later run starts
no earlier than the one before it. -/
theorem sortSpans_pairwise (spans : List VerifiedCore.GroupSpan) :
    (VerifiedCore.sortSpans spans).Pairwise (fun a b => a.start ≤ b.start) := by
  induction spans with
  | nil => simp [VerifiedCore.sortSpans]
  | cons head rest ih => exact insertSpan_pairwise head _ ih

theorem merge_spans_membership (head : VerifiedCore.GroupSpan)
    (rest : List VerifiedCore.GroupSpan) (group : Nat) :
    VerifiedCore.spansContain (VerifiedCore.mergeSpans head rest) group =
      (VerifiedCore.spansContain [head] group || VerifiedCore.spansContain rest group) := by
  induction rest generalizing head with
  | nil => simp [VerifiedCore.mergeSpans, VerifiedCore.spansContain]
  | cons next rest ih =>
    simp only [VerifiedCore.mergeSpans]
    split
    · rename_i touching
      rw [ih]
      simp only [Bool.and_eq_true, decide_eq_true_eq] at touching
      apply Bool.eq_iff_iff.mpr
      simp only [VerifiedCore.spansContain, List.any_cons, List.any_nil, Bool.or_false,
        Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq]
      simp only [min_le_iff, lt_max_iff]
      by_cases tail : VerifiedCore.spansContain rest group = true
      · simp only [VerifiedCore.spansContain] at tail
        simp [tail]
      · simp only [VerifiedCore.spansContain] at tail
        simp [tail]
        omega
    · simp only [VerifiedCore.spansContain, List.any_cons] at ih ⊢
      rw [ih]
      simp

/-- Normalization cannot report any group outside the requested bound. -/
theorem spans_clipping_membership (total group : Nat) (spans : List VerifiedCore.GroupSpan) :
    VerifiedCore.spansContain (spans.filterMap fun r =>
      if r.start < min r.stop total then some (⟨r.start, min r.stop total⟩ : VerifiedCore.GroupSpan) else none) group = true ↔
      VerifiedCore.spansContain spans group = true ∧ group < total := by
  induction spans with
  | nil => simp [VerifiedCore.spansContain]
  | cons r rest ih =>
    by_cases valid : r.start < min r.stop total
    · simp only [List.filterMap_cons, if_pos valid]
      simp only [VerifiedCore.spansContain, List.any_cons, Bool.or_eq_true,
        Bool.and_eq_true, decide_eq_true_eq] at ih ⊢
      rw [ih]
      simp only [lt_min_iff] at valid ⊢
      by_cases tail : VerifiedCore.spansContain rest group = true <;>
        (simp only [VerifiedCore.spansContain] at tail; simp [tail]; all_goals omega)
    · simp only [List.filterMap_cons, if_neg valid]
      simp only [VerifiedCore.spansContain, List.any_cons, Bool.or_eq_true,
        Bool.and_eq_true, decide_eq_true_eq] at ih ⊢
      rw [ih]
      simp only [lt_min_iff] at valid
      by_cases tail : VerifiedCore.spansContain rest group = true <;>
        (simp only [VerifiedCore.spansContain] at tail; simp [tail]; all_goals omega)

/-- Coalescing any interval sequence preserves membership; sorting is needed
for canonical output, not for this safety property. -/
theorem coalesce_spans_membership (spans : List VerifiedCore.GroupSpan) (group : Nat) :
    VerifiedCore.spansContain (match spans with | [] => [] | h :: t => VerifiedCore.mergeSpans h t) group =
      VerifiedCore.spansContain spans group := by
  cases spans with
  | nil => rfl
  | cons head rest =>
    simpa [VerifiedCore.spansContain] using merge_spans_membership head rest group

/-- The production normalization represents exactly the input groups below
the bound. It never invents verified groups or loses an in-bound input group. -/
theorem normalize_spans_membership (total group : Nat) (spans : List VerifiedCore.GroupSpan) :
    VerifiedCore.spansContain (VerifiedCore.normalizeSpans total spans) group = true ↔
      VerifiedCore.spansContain spans group = true ∧ group < total := by
  have sorted (rs : List VerifiedCore.GroupSpan) :
      VerifiedCore.spansContain (VerifiedCore.sortSpans rs) group =
        VerifiedCore.spansContain rs group := by
    apply Bool.eq_iff_iff.mpr
    simp [VerifiedCore.spansContain, List.any_eq_true, mem_sortSpans]
  let clipped := spans.filterMap fun r =>
    if r.start < min r.stop total then some (⟨r.start, min r.stop total⟩ : VerifiedCore.GroupSpan) else none
  have merged : VerifiedCore.spansContain (VerifiedCore.normalizeSpans total spans) group =
      VerifiedCore.spansContain clipped group := by
    unfold VerifiedCore.normalizeSpans
    change VerifiedCore.spansContain (match VerifiedCore.sortSpans clipped with
      | [] => [] | h :: t => VerifiedCore.mergeSpans h t) group = _
    cases hs : VerifiedCore.sortSpans clipped with
    | nil => simpa [hs] using sorted clipped
    | cons head rest =>
      rw [merge_spans_membership]
      simpa [hs, VerifiedCore.spansContain] using sorted clipped
  rw [merged]
  exact spans_clipping_membership total group spans

/-- A durable row cannot be rewritten under a conflicting size by any incoming ranges. -/
theorem cas_plan_durable_refusal (recorded claimed : UInt64)
    (different : recorded ≠ claimed) (complete : Bool) (old incoming : List VerifiedCore.GroupSpan) :
    (VerifiedCore.planCasCommit true true complete recorded claimed old incoming).accepted = false := by
  simp [VerifiedCore.planCasCommit, VerifiedCore.settleSize, different]

/-- A row already locally complete also rejects a conflicting size. -/
theorem cas_plan_complete_refusal (recorded claimed : UInt64)
    (different : recorded ≠ claimed) (durable : Bool) (old incoming : List VerifiedCore.GroupSpan) :
    (VerifiedCore.planCasCommit true durable true recorded claimed old incoming).accepted = false := by
  simp [VerifiedCore.planCasCommit, VerifiedCore.settleSize, different]

/-- The actual commit planner retains exactly the authorized old groups plus
incoming verified groups, clipped to the claimed size. A refusal holds none. -/
theorem cas_plan_membership (row durable complete : Bool) (recorded claimed : UInt64)
    (old incoming : List VerifiedCore.GroupSpan) (group : Nat) :
    let prior := if row then
      if complete then [(⟨0, (VerifiedCore.groupCount recorded).toNat⟩ : VerifiedCore.GroupSpan)] else old
      else []
    let decision := VerifiedCore.settleSize row durable complete
      (VerifiedCore.spansContain prior ((VerifiedCore.groupCount recorded).toNat - 1)) recorded claimed
    VerifiedCore.spansContain
      (VerifiedCore.planCasCommit row durable complete recorded claimed old incoming).spans group = true ↔
      decision ≠ 0 ∧
      VerifiedCore.spansContain ((if decision == 2 then [] else prior) ++ incoming) group = true ∧
      group < (VerifiedCore.groupCount claimed).toNat := by
  dsimp only
  unfold VerifiedCore.planCasCommit
  generalize (if row then
    if complete then [(⟨0, (VerifiedCore.groupCount recorded).toNat⟩ : VerifiedCore.GroupSpan)] else old
    else []) = prior
  dsimp only
  split
  · rename_i refused
    simp_all [VerifiedCore.spansContain]
  · rename_i accepted
    simp only [beq_iff_eq] at accepted
    simp only [accepted, ne_eq, not_false_eq_true, true_and]
    exact normalize_spans_membership (VerifiedCore.groupCount claimed).toNat group _

/-- A planner's complete result actually covers every group of the claimed
object, including the one-group representation of an empty object. -/
theorem cas_plan_complete_covers (row durable complete : Bool) (recorded claimed : UInt64)
    (old incoming : List VerifiedCore.GroupSpan)
    (done : (VerifiedCore.planCasCommit row durable complete recorded claimed old incoming).complete = true)
    (group : Nat) (inside : group < (VerifiedCore.groupCount claimed).toNat) :
    VerifiedCore.spansContain
      (VerifiedCore.planCasCommit row durable complete recorded claimed old incoming).spans group = true := by
  unfold VerifiedCore.planCasCommit at done ⊢
  generalize (if row then
    if complete then [(⟨0, (VerifiedCore.groupCount recorded).toNat⟩ : VerifiedCore.GroupSpan)] else old
    else []) = prior at done ⊢
  dsimp only at done ⊢
  split at done <;> simp only at done
  · contradiction
  · rename_i accepted
    simp only [accepted]
    simp only [Bool.and_eq_true] at done
    obtain ⟨_, witness⟩ := done
    obtain ⟨r, member, endpoints⟩ := List.any_eq_true.mp witness
    simp only [Bool.and_eq_true, beq_iff_eq] at endpoints
    apply List.any_eq_true.mpr
    exact ⟨r, member, by simp [endpoints.1, endpoints.2, inside]⟩

/-- Coalescing nonempty bounded intervals preserves both endpoint bounds. -/
theorem merge_spans_bounds (total : Nat) (head : VerifiedCore.GroupSpan)
    (rest : List VerifiedCore.GroupSpan) (valid : head.start < head.stop ∧ head.stop ≤ total)
    (validRest : ∀ r ∈ rest, r.start < r.stop ∧ r.stop ≤ total) :
    ∀ r ∈ VerifiedCore.mergeSpans head rest, r.start < r.stop ∧ r.stop ≤ total := by
  induction rest generalizing head with
  | nil => simpa [VerifiedCore.mergeSpans] using valid
  | cons next rest ih =>
    have hn := validRest next (by simp)
    have ht : ∀ r ∈ rest, r.start < r.stop ∧ r.stop ≤ total :=
      fun r hr => validRest r (by simp [hr])
    simp only [VerifiedCore.mergeSpans]
    split
    · apply ih _ _ ht
      simp only
      constructor <;> omega
    · intro r hr
      simp only [List.mem_cons] at hr
      rcases hr with rfl | hr
      · exact valid
      · exact ih next hn ht r hr

/-- Every normalized interval is nonempty and fits within the requested bound. -/
theorem normalize_spans_bounds (total : Nat) (spans : List VerifiedCore.GroupSpan) :
    ∀ r ∈ VerifiedCore.normalizeSpans total spans, r.start < r.stop ∧ r.stop ≤ total := by
  let clipped := spans.filterMap fun r =>
    if r.start < min r.stop total then some (⟨r.start, min r.stop total⟩ : VerifiedCore.GroupSpan) else none
  have hc : ∀ r ∈ clipped, r.start < r.stop ∧ r.stop ≤ total := by
    intro r hr
    obtain ⟨original, _, eq⟩ := List.mem_filterMap.mp hr
    split at eq
    · cases Option.some.inj eq
      simp only
      constructor <;> omega
    · contradiction
  have hs : ∀ r ∈ VerifiedCore.sortSpans clipped,
      r.start < r.stop ∧ r.stop ≤ total := by
    simpa only [mem_sortSpans] using hc
  unfold VerifiedCore.normalizeSpans
  change ∀ r ∈ (match VerifiedCore.sortSpans clipped with
    | [] => [] | h :: t => VerifiedCore.mergeSpans h t), _
  cases he : VerifiedCore.sortSpans clipped with
  | nil => simp
  | cons head rest =>
    rw [he] at hs
    exact merge_spans_bounds total head rest (hs head (by simp))
      (fun r hr => hs r (by simp [hr]))

/-- All planner endpoints fit into the claimed object's group bound, even
when the caller supplies malformed or out-of-bound incoming intervals. -/
theorem cas_plan_bounds (row durable complete : Bool) (recorded claimed : UInt64)
    (old incoming : List VerifiedCore.GroupSpan) :
    ∀ r ∈ (VerifiedCore.planCasCommit row durable complete recorded claimed old incoming).spans,
      r.start < r.stop ∧ r.stop ≤ (VerifiedCore.groupCount claimed).toNat := by
  unfold VerifiedCore.planCasCommit
  generalize (if row then
    if complete then [(⟨0, (VerifiedCore.groupCount recorded).toNat⟩ : VerifiedCore.GroupSpan)] else old
    else []) = prior
  dsimp only
  split
  · simp
  · exact normalize_spans_bounds _ _

/-- Coalescing cannot move an interval start below any common lower bound. -/
theorem merge_spans_lower_bound (lower : Nat) (head : VerifiedCore.GroupSpan)
    (rest : List VerifiedCore.GroupSpan) (hh : lower ≤ head.start)
    (ht : ∀ r ∈ rest, lower ≤ r.start) :
    ∀ r ∈ VerifiedCore.mergeSpans head rest, lower ≤ r.start := by
  induction rest generalizing head with
  | nil => simpa [VerifiedCore.mergeSpans] using hh
  | cons next rest ih =>
    have hn := ht next (by simp)
    have tail : ∀ r ∈ rest, lower ≤ r.start := fun r hr => ht r (by simp [hr])
    simp only [VerifiedCore.mergeSpans]
    split
    · exact ih _ (by simp only; omega) tail
    · intro r hr
      rcases List.mem_cons.mp hr with rfl | hr
      · exact hh
      · exact ih next hn tail r hr

/-- Sorted, nonempty inputs coalesce into strictly separated intervals. -/
theorem merge_spans_separated (head : VerifiedCore.GroupSpan) (rest : List VerifiedCore.GroupSpan)
    (valid : ∀ r ∈ head :: rest, r.start < r.stop)
    (sorted : (head :: rest).Pairwise (fun a b => a.start ≤ b.start)) :
    (VerifiedCore.mergeSpans head rest).Pairwise (fun a b => a.stop < b.start) := by
  induction rest generalizing head with
  | nil => simp [VerifiedCore.mergeSpans]
  | cons next rest ih =>
    obtain ⟨headLE, tailSorted⟩ := List.pairwise_cons.mp sorted
    obtain ⟨nextLE, restSorted⟩ := List.pairwise_cons.mp tailSorted
    have hh := valid head (by simp)
    have hn := valid next (by simp)
    have order := headLE next (by simp)
    simp only [VerifiedCore.mergeSpans]
    split
    · apply ih
      · intro r hr
        rcases List.mem_cons.mp hr with rfl | hr
        · simp only; omega
        · exact valid r (by simp [hr])
      · apply List.pairwise_cons.mpr
        refine ⟨?_, restSorted⟩
        intro r hr
        have h := headLE r (by simp [hr])
        simp only
        omega
    · rename_i separated
      simp only [Bool.and_eq_true, decide_eq_true_eq] at separated
      have gap : head.stop < next.start := by omega
      apply List.pairwise_cons.mpr
      constructor
      · intro r hr
        have bound := merge_spans_lower_bound next.start next rest (by omega) nextLE r hr
        omega
      · exact ih next (fun r hr => valid r (by simp [hr])) tailSorted

/-- Normalization's output is sorted and has neither overlap nor adjacent runs. -/
theorem normalize_spans_separated (total : Nat) (spans : List VerifiedCore.GroupSpan) :
    (VerifiedCore.normalizeSpans total spans).Pairwise (fun a b => a.stop < b.start) := by
  let clipped := spans.filterMap fun r =>
    if r.start < min r.stop total then some (⟨r.start, min r.stop total⟩ : VerifiedCore.GroupSpan) else none
  have hc : ∀ r ∈ clipped, r.start < r.stop := by
    intro r hr
    obtain ⟨original, _, eq⟩ := List.mem_filterMap.mp hr
    split at eq
    · cases Option.some.inj eq
      assumption
    · contradiction
  have hs := sortSpans_pairwise clipped
  unfold VerifiedCore.normalizeSpans
  change (match VerifiedCore.sortSpans clipped with
    | [] => [] | h :: t => VerifiedCore.mergeSpans h t).Pairwise _
  cases he : VerifiedCore.sortSpans clipped with
  | nil => simp
  | cons head rest =>
    rw [he] at hs
    apply merge_spans_separated head rest _ hs
    intro r hr
    apply hc r
    have member : r ∈ VerifiedCore.sortSpans clipped := by simpa [he] using hr
    simpa only [mem_sortSpans] using member

/-- Every accepted or refused production plan has canonical separated ranges. -/
theorem cas_plan_separated (row durable complete : Bool) (recorded claimed : UInt64)
    (old incoming : List VerifiedCore.GroupSpan) :
    (VerifiedCore.planCasCommit row durable complete recorded claimed old incoming).spans.Pairwise
      (fun a b => a.stop < b.start) := by
  unfold VerifiedCore.planCasCommit
  generalize (if row then
    if complete then [(⟨0, (VerifiedCore.groupCount recorded).toNat⟩ : VerifiedCore.GroupSpan)] else old
    else []) = prior
  dsimp only
  split
  · simp
  · exact normalize_spans_separated _ _

/-- For canonical bounded ranges, full pointwise coverage contains a single
full-span witness; fragmented ranges cannot hide a missing boundary group. -/
theorem separated_full_coverage (total : Nat) (positive : 0 < total)
    (spans : List VerifiedCore.GroupSpan)
    (bounded : ∀ r ∈ spans, r.stop ≤ total)
    (separated : spans.Pairwise (fun a b => a.stop < b.start))
    (covered : ∀ g < total, VerifiedCore.spansContain spans g = true) :
    spans.any (fun r => r.start == 0 && r.stop == total) = true := by
  cases spans with
  | nil => simpa [VerifiedCore.spansContain] using covered 0 positive
  | cons head rest =>
    have after := (List.pairwise_cons.mp separated).1
    have atZero := covered 0 positive
    obtain ⟨r, member, contains⟩ := List.any_eq_true.mp atZero
    simp only [Bool.and_eq_true, decide_eq_true_eq] at contains
    have start : head.start = 0 := by
      rcases List.mem_cons.mp member with rfl | member
      · omega
      · have gap := after r member; omega
    have stop : head.stop = total := by
      have bound := bounded head (by simp)
      rcases Nat.eq_or_lt_of_le bound with same | inside
      · exact same
      obtain ⟨r, member, contains⟩ := List.any_eq_true.mp (covered head.stop inside)
      simp only [Bool.and_eq_true, decide_eq_true_eq] at contains
      rcases List.mem_cons.mp member with rfl | member
      · omega
      · have gap := after r member; omega
    simp [start, stop]

/-- Completion of an accepted production plan is exact, not only sound:
every covered object is recognized as complete. -/
theorem cas_plan_coverage_completes (row durable complete : Bool) (recorded claimed : UInt64)
    (old incoming : List VerifiedCore.GroupSpan)
    (covered : ∀ g < (VerifiedCore.groupCount claimed).toNat,
      VerifiedCore.spansContain
        (VerifiedCore.planCasCommit row durable complete recorded claimed old incoming).spans g = true) :
    (VerifiedCore.planCasCommit row durable complete recorded claimed old incoming).complete = true := by
  have positive := groupCount_pos claimed
  have full := separated_full_coverage (VerifiedCore.groupCount claimed).toNat positive _
    (fun r hr => (cas_plan_bounds row durable complete recorded claimed old incoming r hr).2)
    (cas_plan_separated row durable complete recorded claimed old incoming) covered
  have zero := covered 0 positive
  unfold VerifiedCore.planCasCommit at full zero ⊢
  generalize (if row then
    if complete then [(⟨0, (VerifiedCore.groupCount recorded).toNat⟩ : VerifiedCore.GroupSpan)] else old
    else []) = prior at full zero ⊢
  dsimp only at full zero ⊢
  split at full
  · simp at full
  · rename_i accepted
    rw [if_neg accepted] at zero ⊢
    dsimp only at zero full ⊢
    simp only [zero, full, Bool.and_self]

end Synchronicity.CasPlanProofs
