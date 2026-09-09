import VerifiedCore.Replication.OriginSchedule
import Synchronicity.ContactProofs

/-! Safety and bounded service for the production weighted-origin planner. -/
namespace Synchronicity.OriginScheduleProofs
open VerifiedCore.Replication
open VerifiedCore.Replication.OriginSchedule

abbrev Entry := Nat × (Nat × Item)

theorem take_prefix (remaining : Nat) (items : List Entry) :
    ∃ rest, items = take remaining items ++ rest := by
  induction items generalizing remaining with
  | nil => exact ⟨[], rfl⟩
  | cons item rest ih =>
    unfold take
    split
    · obtain ⟨tail, shape⟩ := ih (remaining - item.2.2.weight.toNat)
      exact ⟨tail, congrArg (item :: ·) shape⟩
    · exact ⟨item :: rest, rfl⟩

theorem take_nonempty (item : Entry) (rest : List Entry) (remaining : Nat)
    (fits : item.2.2.weight.toNat ≤ remaining) :
    take remaining (item :: rest) ≠ [] := by
  simp [take, fits]

theorem mem_of_mem_take (member : item ∈ take remaining items) : item ∈ items := by
  obtain ⟨rest, shape⟩ := take_prefix remaining items
  rw [shape, List.mem_append]
  exact Or.inl member

private theorem cycle_membership (entries : List (Nat × α)) (item : Nat × α) (cursor : Nat) :
    item ∈ Contact.cycleAt entries cursor ↔ item ∈ entries := by
  simp only [Contact.cycleAt, List.mem_append, List.mem_filter, decide_eq_true_eq]
  constructor
  · rintro (left | right)
    · exact left.1
    · exact right.1
  · intro member
    by_cases above : cursor < item.1
    · exact Or.inl ⟨member, above⟩
    · exact Or.inr ⟨member, by omega⟩

private theorem ordered_partition (entries : List (Nat × α))
    (ordered : entries.Pairwise (fun a b => a.1 < b.1)) (cursor : Nat) :
    entries.filter (fun entry => entry.1 ≤ cursor) ++
      entries.filter (fun entry => cursor < entry.1) = entries := by
  induction entries with
  | nil => rfl
  | cons first rest ih =>
    obtain ⟨before, tail⟩ := List.pairwise_cons.mp ordered
    by_cases low : first.1 ≤ cursor
    · have high : ¬ cursor < first.1 := by omega
      simpa [low, high] using congrArg (first :: ·) (ih tail)
    · have high : cursor < first.1 := by omega
      have allHigh : ∀ entry ∈ rest, cursor < entry.1 := by
        intro entry member
        exact Nat.lt_trans high (before entry member)
      have kept : rest.filter (fun entry => cursor < entry.1) = rest :=
        List.filter_eq_self.mpr (by simpa using allHigh)
      have dropped : rest.filter (fun entry => entry.1 ≤ cursor) = [] := by
        apply List.filter_eq_nil_iff.mpr
        intro entry member
        have bound := allHigh entry member
        simp [show ¬ entry.1 ≤ cursor by omega]
      simp [low, high, kept, dropped]

private theorem cycle_length (entries : List (Nat × α))
    (ordered : entries.Pairwise (fun a b => a.1 < b.1)) (cursor : Nat) :
    (Contact.cycleAt entries cursor).length = entries.length := by
  have split := congrArg List.length (ordered_partition entries ordered cursor)
  simpa [Contact.cycleAt, List.length_append, Nat.add_comm] using split

theorem unserved_prefix_moves_forward [BEq α] [LawfulBEq α]
    (entries : List (Nat × α)) (ordered : entries.Pairwise (fun a b => a.1 < b.1))
    (member : item ∈ entries) (batch : List (Nat × α)) (rest : List (Nat × α))
    (nonempty : batch ≠ []) (split : Contact.cycleAt entries cursor = batch ++ rest)
    (unserved : item ∉ batch) :
    (Contact.cycleAt entries (batch.getLast nonempty).1).idxOf item + batch.length =
      (Contact.cycleAt entries cursor).idxOf item := by
  have held : item ∈ Contact.cycleAt entries cursor := (cycle_membership entries item cursor).mpr member
  have remaining : item ∈ rest := by
    rw [split, List.mem_append] at held
    exact held.resolve_left unserved
  have rotated := ContactProofs.completing_batch_rotates_turns
    entries ordered batch nonempty split
  rw [rotated, split, List.idxOf_append, List.idxOf_append,
    if_pos remaining, if_neg unserved]

/-- Any nonempty completed weighted prefixes cover every stable entry in at
most one round per entry. Outcomes of the attempted origin work are irrelevant;
only completion of the batch cursor is used. -/
theorem completed_prefixes_cover [BEq α] [LawfulBEq α]
    (entries : List (Nat × α)) (ordered : entries.Pairwise (fun a b => a.1 < b.1))
    (member : item ∈ entries) (batch : Nat → List (Nat × α))
    (cursor : Nat → Nat) (rounds : Nat) (enough : entries.length ≤ rounds)
    (prefixShape : ∀ round, ∃ rest,
      Contact.cycleAt entries (cursor round) = batch round ++ rest)
    (completed : ∀ round, round < rounds →
      ∃ held : batch round ≠ [],
        cursor (round + 1) = ((batch round).getLast held).1) :
    ∃ round < rounds, item ∈ batch round := by
  classical
  apply Classical.byContradiction
  intro absent
  have missing : ∀ round < rounds, item ∉ batch round := by
    simpa only [not_exists, not_and] using absent
  have positions : ∀ round, round ≤ rounds →
      (Contact.cycleAt entries (cursor round)).idxOf item + round ≤
        (Contact.cycleAt entries (cursor 0)).idxOf item := by
    intro round within
    induction round with
    | zero => simp
    | succ round ih =>
      have before := ih (by omega)
      obtain ⟨rest, split⟩ := prefixShape round
      obtain ⟨held, advanced⟩ := completed round (by omega)
      have moved := unserved_prefix_moves_forward entries ordered member
        (batch round) rest held split (missing round (by omega))
      rw [advanced]
      have positive : 0 < (batch round).length := List.length_pos_iff.mpr held
      omega
  have initialBound := List.idxOf_lt_length_of_mem
    ((cycle_membership entries item (cursor 0)).mpr member)
  rw [cycle_length entries ordered (cursor 0)] at initialBound
  have reached := positions rounds (Nat.le_refl _)
  omega

private def PointsTo (items : List Item) (table : Index) : Prop :=
  ∀ rank value, table[rank]? = some value →
    key value.2.origin = rank ∧ items[value.1]? = some value.2

private theorem fold_points_to (items : List Item) (input : List (Item × Nat))
    (valid : ∀ item ∈ input, items[item.2]? = some item.1)
    (table : Index) (points : PointsTo items table) :
    PointsTo items (input.foldl (fun result (item, position) =>
      result.insert (key item.origin) (position, item)) table) := by
  induction input generalizing table with
  | nil => exact points
  | cons item rest ih =>
    apply ih (fun item member => valid item (List.mem_cons_of_mem _ member))
    intro rank value found
    rw [Std.TreeMap.getElem?_insert] at found
    split at found
    · rename_i same
      have named : key item.1.origin = rank := by simpa using same
      cases Option.some.inj found
      exact ⟨named, valid item (by simp)⟩
    · exact points rank value found

/-- Every indexed group still names its exact input position and item. -/
theorem indexed_items_come_from_input (items : List Item)
    (entry : Entry) (member : entry ∈ (index items).toList) :
    key entry.2.2.origin = entry.1 ∧ items[entry.2.1]? = some entry.2.2 := by
  have valid := fold_points_to items items.zipIdx
    (fun item member => List.mem_zipIdx_iff_getElem?.mp member) ({} : Index)
    (by intro rank value found; simp at found)
  exact valid entry.1 entry.2 (Std.TreeMap.mem_toList_iff_getElem?_eq_some.mp member)

private theorem fold_membership (input : List (Item × Nat)) (table : Index) (rank : Nat) :
    rank ∈ input.foldl (fun result (item, position) =>
      result.insert (key item.origin) (position, item)) table ↔
      rank ∈ table ∨ ∃ item ∈ input, key item.1.origin = rank := by
  induction input generalizing table with
  | nil => simp
  | cons item rest ih =>
    simp [List.foldl_cons, ih, Std.TreeMap.mem_insert, or_assoc, or_comm]

/-- No input group disappears from the production index when the caller's
canonical origins have distinct scheduler keys. This is the narrow host
contract supplied by valid, unique `OriginId` groups. -/
theorem every_input_item_is_indexed (items : List Item)
    (distinct : ∀ left ∈ items, ∀ right ∈ items,
      key left.origin = key right.origin → left = right)
    (member : item ∈ items) :
    ∃ entry ∈ (index items).toList, entry.2.2 = item := by
  obtain ⟨position, source⟩ := List.mem_iff_getElem?.mp member
  have present : key item.origin ∈ index items :=
    (fold_membership items.zipIdx {} (key item.origin)).mpr
      (.inr ⟨(item, position), List.mk_mem_zipIdx_iff_getElem?.mpr source, rfl⟩)
  have existsValue := Std.TreeMap.mem_iff_isSome_getElem?.mp present
  cases found : (index items)[key item.origin]? with
  | none => simp [found] at existsValue
  | some value =>
    have entry : (key item.origin, value) ∈ (index items).toList :=
      Std.TreeMap.mem_toList_iff_getElem?_eq_some.mpr found
    obtain ⟨named, supplied⟩ := indexed_items_come_from_input items _ entry
    have same := distinct value.2 (List.mem_of_getElem? supplied) item member (named.trans rfl)
    exact ⟨(key item.origin, value), entry, same⟩

/-- A selected production position resolves to the selected input group. -/
theorem selected_positions_name_selected_items (items : List Item)
    (within : items.length ≤ UInt64.size) (cursor : Option String) (maximum : Nat)
    (entry : Entry) (selected : entry ∈ take maximum (cycle items cursor)) :
    entry.2.1.toUInt64 ∈ (plan items cursor maximum).positions ∧
      items[entry.2.1.toUInt64.toNat]? = some entry.2.2 := by
  have belongs := (cycle_membership (index items).toList entry _).mp
    (mem_of_mem_take selected)
  obtain ⟨_, source⟩ := indexed_items_come_from_input items entry belongs
  have bound : entry.2.1 < items.length := List.getElem?_eq_some_iff.mp source |>.choose
  have fits : entry.2.1 < UInt64.size := Nat.lt_of_lt_of_le bound within
  refine ⟨List.mem_map.mpr ⟨entry, selected, rfl⟩, ?_⟩
  simpa only [UInt64.toNat_ofNat_of_lt' fits] using source

/-- The cursor returned by the production planner is exactly the last selected
group. It is safe to persist only after the selected batch was attempted. -/
theorem native_cursor_finishes_selected_batch (items : List Item)
    (cursor : Option String) (maximum : Nat)
    (nonempty : take maximum (cycle items cursor) ≠ []) :
    ((plan items cursor maximum).cursor.map key).getD 0 =
      ((take maximum (cycle items cursor)).getLast nonempty).1 := by
  let last := (take maximum (cycle items cursor)).getLast nonempty
  have member := (cycle_membership (index items).toList last _).mp
    (mem_of_mem_take (List.getLast_mem nonempty))
  have named := (indexed_items_come_from_input items last member).1
  simpa only [plan, List.getLast?_eq_some_getLast nonempty, Option.map_some,
    Option.getD_some] using named

/-- For a stable finite origin set, actual weighted production plans select
every group within one completed round per indexed group. A completed round is
the runtime event that attempted the batch and only then persisted its cursor;
cancellation retains the old cursor and is intentionally outside this premise. -/
theorem native_plans_give_every_origin_a_bounded_turn (items : List Item)
    (distinct : ∀ left ∈ items, ∀ right ∈ items,
      key left.origin = key right.origin → left = right)
    (within : items.length ≤ UInt64.size) (member : item ∈ items)
    (maximum rounds : Nat)
    (fits : ∀ candidate ∈ items, candidate.weight.toNat ≤ maximum)
    (cursors : Nat → Option String)
    (enough : (index items).toList.length ≤ rounds)
    (completed : ∀ round < rounds,
      cursors (round + 1) = (plan items (cursors round) maximum).cursor) :
    ∃ round < rounds, ∃ position ∈ (plan items (cursors round) maximum).positions,
      items[position.toNat]? = some item := by
  obtain ⟨entry, indexed, named⟩ := every_input_item_is_indexed items distinct member
  have ordered : (index items).toList.Pairwise (fun a b => a.1 < b.1) := by
    simpa only [Nat.compare_eq_lt] using (Std.TreeMap.ordered_keys_toList (t := index items))
  have steps : ∀ round < rounds,
      ∃ held : take maximum (cycle items (cursors round)) ≠ [],
        ((cursors (round + 1)).map key).getD 0 =
          ((take maximum (cycle items (cursors round))).getLast held).1 := by
    intro round before
    have present : entry ∈ cycle items (cursors round) :=
      (cycle_membership (index items).toList entry _).mpr indexed
    obtain ⟨first, rest, shape⟩ : ∃ first rest, cycle items (cursors round) = first :: rest := by
      cases current : cycle items (cursors round) with
      | nil => simp [current] at present
      | cons first rest => exact ⟨first, rest, rfl⟩
    have firstCycled : first ∈ cycle items (cursors round) := by
      rw [shape]
      simp
    have firstIndexed : first ∈ (index items).toList :=
      (cycle_membership (index items).toList first _).mp firstCycled
    obtain ⟨_, firstSource⟩ := indexed_items_come_from_input items first firstIndexed
    have firstFits : first.2.2.weight.toNat ≤ maximum :=
      fits first.2.2 (List.mem_of_getElem? firstSource)
    have held : take maximum (cycle items (cursors round)) ≠ [] := by
      rw [shape]
      exact take_nonempty first rest maximum firstFits
    refine ⟨held, ?_⟩
    rw [completed round before]
    exact native_cursor_finishes_selected_batch items (cursors round) maximum held
  have prefixShape : ∀ round, ∃ rest,
      Contact.cycleAt (index items).toList (((cursors round).map key).getD 0) =
        take maximum (cycle items (cursors round)) ++ rest := by
    intro round
    exact take_prefix maximum (cycle items (cursors round))
  obtain ⟨round, before, selected⟩ := completed_prefixes_cover
    (index items).toList ordered indexed
    (fun round => take maximum (cycle items (cursors round)))
    (fun round => ((cursors round).map key).getD 0) rounds enough prefixShape steps
  obtain ⟨returned, source⟩ := selected_positions_name_selected_items
    items within (cursors round) maximum entry selected
  exact ⟨round, before, entry.2.1.toUInt64, returned, by simpa only [named] using source⟩

end Synchronicity.OriginScheduleProofs
