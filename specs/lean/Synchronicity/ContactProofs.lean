import VerifiedCore.Replication.Contact
import Synchronicity.ExchangeVersionProofs
import Synchronicity.SimulatedHost.Database
import Std.Data.TreeMap.Lemmas
import Init.Data.List.Nat.TakeDrop

/-! Bounded service for the actual cyclic contact planner. The order is the
peer identifier's byte order, independent of storage query ordering or clocks.
The final scheduler connection must count completed attempts, not merely plans. -/
namespace Synchronicity.ContactProofs
open VerifiedCore.Replication.Contact

/-- Distinct fixed-width peer identifiers retain their actual byte ordering;
indexing does not substitute a probabilistic hash of peer identity. -/
theorem peer_order_is_byte_order (left right : ByteArray)
    (leftWidth : left.size = 32) (rightWidth : right.size = 32) :
    key left < key right ↔ List.Lex (· < ·) left.data.toList right.data.toList := by
  have order := ExchangeVersionProofs.version_order_is_sequence_then_root
    ⟨"", 0, left⟩ ⟨"", 0, right⟩ leftWidth rightWidth
  simpa [VerifiedCore.Replication.Exchange.version, key] using order

/-- The contact index cannot merge two different eligible peer identifiers. -/
theorem peer_keys_preserve_identity (left right : ByteArray)
    (leftWidth : left.size = 32) (rightWidth : right.size = 32)
    (same : key left = key right) : left = right := by
  have forward : ¬ List.Lex (· < ·) left.data.toList right.data.toList := by
    rw [← peer_order_is_byte_order left right leftWidth rightWidth, same]
    omega
  have backward : ¬ List.Lex (· < ·) right.data.toList left.data.toList := by
    rw [← peer_order_is_byte_order right left rightWidth leftWidth, same]
    omega
  apply ByteArray.ext
  apply Array.toList_inj.mp
  exact List.le_antisymm backward forward

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

private theorem cycle_of_split (before after : List (Nat × α)) (peer : Nat × α)
    (lower : ∀ entry ∈ before, entry.1 < peer.1)
    (higher : ∀ entry ∈ after, peer.1 < entry.1) :
    cycleAt (before ++ peer :: after) peer.1 = after ++ before ++ [peer] := by
  have beforeHigh : before.filter (fun entry => peer.1 < entry.1) = [] := by
    apply List.filter_eq_nil_iff.mpr
    intro entry member
    have bound := lower entry member
    simp [show ¬ peer.1 < entry.1 by omega]
  have beforeLow : before.filter (fun entry => entry.1 ≤ peer.1) = before := by
    apply List.filter_eq_self.mpr
    intro entry member
    have bound := lower entry member
    simp only [decide_eq_true_eq]
    omega
  have afterHigh : after.filter (fun entry => peer.1 < entry.1) = after :=
    List.filter_eq_self.mpr (by simpa using higher)
  have afterLow : after.filter (fun entry => entry.1 ≤ peer.1) = [] := by
    apply List.filter_eq_nil_iff.mpr
    intro entry member
    have bound := higher entry member
    simp [show ¬ entry.1 ≤ peer.1 by omega]
  simp [cycleAt, List.filter_append, beforeHigh, beforeLow, afterHigh, afterLow,
    List.append_assoc]

/-- Completing the first eligible peer's turn moves exactly that peer to the
back. It cannot reset another eligible peer's place in the cycle. -/
theorem completing_first_rotates_turns (entries : List (Nat × α))
    (ordered : entries.Pairwise (fun a b => a.1 < b.1))
    (first : cycleAt entries cursor = peer :: rest) :
    cycleAt entries peer.1 = rest ++ [peer] := by
  have partition := ordered_partition entries ordered cursor
  unfold cycleAt at first
  generalize lowDef : entries.filter (fun entry => entry.1 ≤ cursor) = low at *
  generalize highDef : entries.filter (fun entry => cursor < entry.1) = high at *
  cases high with
  | nil =>
    simp only [List.nil_append] at first
    have shape : entries = peer :: rest := by simpa [first] using partition.symm
    rw [shape] at ordered ⊢
    have tail := (List.pairwise_cons.mp ordered).1
    simpa using cycle_of_split [] rest peer (by simp) tail
  | cons selected remaining =>
    simp only [List.cons_append, List.cons.injEq] at first
    obtain ⟨rfl, rfl⟩ := first
    have selectedHigh : cursor < selected.1 := by
      have member : selected ∈ entries.filter (fun entry => cursor < entry.1) := by
        rw [highDef]; simp
      exact of_decide_eq_true (List.mem_filter.mp member).2
    have lower : ∀ entry ∈ low, entry.1 < selected.1 := by
      intro entry member
      rw [← lowDef] at member
      have bound := of_decide_eq_true (List.mem_filter.mp member).2
      omega
    have higher : ∀ entry ∈ remaining, selected.1 < entry.1 := by
      rw [← partition] at ordered
      exact (List.pairwise_cons.mp (List.pairwise_append.mp ordered).2.1).1
    rw [← partition]
    simpa [List.append_assoc] using cycle_of_split low remaining selected lower higher

/-- Completing a planned prefix rotates exactly that entire batch behind all
remaining peers. Earlier progress cannot spend an unattempted peer's turn. -/
theorem completing_batch_rotates_turns (entries : List (Nat × α))
    (ordered : entries.Pairwise (fun a b => a.1 < b.1))
    (batch : List (Nat × α)) (nonempty : batch ≠ [])
    (first : cycleAt entries cursor = batch ++ rest) :
    cycleAt entries (batch.getLast nonempty).1 = rest ++ batch := by
  induction batch generalizing cursor rest with
  | nil => contradiction
  | cons peer tail ih =>
    have step := completing_first_rotates_turns entries ordered
      (show cycleAt entries cursor = peer :: (tail ++ rest) by simpa using first)
    cases tail with
    | nil => simpa using step
    | cons next tail =>
      have following : cycleAt entries peer.1 = (next :: tail) ++ (rest ++ [peer]) := by
        simpa [List.append_assoc] using step
      have rotated := ih (by simp) following
      simpa [List.append_assoc] using rotated

private theorem cycle_membership (entries : List (Nat × α)) (peer : Nat × α) (cursor : Nat) :
    peer ∈ cycleAt entries cursor ↔ peer ∈ entries := by
  simp only [cycleAt, List.mem_append, List.mem_filter, decide_eq_true_eq]
  constructor
  · rintro (left | right)
    · exact left.1
    · exact right.1
  · intro member
    by_cases above : cursor < peer.1
    · exact Or.inl ⟨member, above⟩
    · exact Or.inr ⟨member, by omega⟩

private theorem cycle_length (entries : List (Nat × α))
    (ordered : entries.Pairwise (fun a b => a.1 < b.1)) (cursor : Nat) :
    (cycleAt entries cursor).length = entries.length := by
  have split := congrArg List.length (ordered_partition entries ordered cursor)
  simpa [cycleAt, List.length_append, Nat.add_comm] using split

/-- A peer outside the completed batch moves forward by the whole batch size;
no successful or failed contact ahead of it can keep its old waiting position. -/
theorem unserved_peer_moves_forward [BEq α] [LawfulBEq α]
    (entries : List (Nat × α)) (ordered : entries.Pairwise (fun a b => a.1 < b.1))
    (member : peer ∈ entries)
    (batchNonempty : (cycleAt entries cursor |>.take maximum) ≠ [])
    (unserved : peer ∉ (cycleAt entries cursor).take maximum) :
    (cycleAt entries (((cycleAt entries cursor).take maximum).getLast batchNonempty).1).idxOf peer +
      maximum = (cycleAt entries cursor).idxOf peer := by
  let current := cycleAt entries cursor
  let batch := current.take maximum
  let rest := current.drop maximum
  have split : current = batch ++ rest := (List.take_append_drop maximum current).symm
  have held : peer ∈ current := (cycle_membership entries peer cursor).mpr member
  have remaining : peer ∈ rest := by
    rw [split, List.mem_append] at held
    exact held.resolve_left unserved
  have shorter : maximum < current.length := by
    apply Classical.byContradiction
    intro no
    have whole : batch = current := List.take_of_length_le (by omega)
    apply unserved
    change peer ∈ batch
    rw [whole]
    exact held
  have size : batch.length = maximum := by simp [batch, List.length_take, Nat.min_eq_left (by omega : maximum ≤ current.length)]
  have rotated := completing_batch_rotates_turns entries ordered batch batchNonempty split
  change (cycleAt entries (batch.getLast batchNonempty).1).idxOf peer + maximum = current.idxOf peer
  rw [rotated, split, List.idxOf_append, List.idxOf_append, if_pos remaining, if_neg unserved, size]

/-- Once the eligible set is fixed, completed batches give every peer a turn
within enough rounds to cover that set. No randomness or healthy-other-peer
premise is needed. The native plan/engine connection must supply these completed
cursor transitions, including the last peer of every attempted batch. -/
theorem every_peer_has_a_bounded_turn [BEq α] [LawfulBEq α]
    (entries : List (Nat × α)) (ordered : entries.Pairwise (fun a b => a.1 < b.1))
    (member : peer ∈ entries) (cursors : Nat → Nat) (maximum rounds : Nat)
    (enough : entries.length ≤ rounds * maximum)
    (completed : ∀ round < rounds,
      ∃ nonempty : ((cycleAt entries (cursors round)).take maximum) ≠ [],
        cursors (round + 1) = (((cycleAt entries (cursors round)).take maximum).getLast nonempty).1) :
    ∃ round < rounds, peer ∈ (cycleAt entries (cursors round)).take maximum := by
  classical
  apply Classical.byContradiction
  intro absent
  have missing : ∀ round < rounds, peer ∉ (cycleAt entries (cursors round)).take maximum := by
    simpa only [not_exists, not_and] using absent
  have positions : ∀ round, round ≤ rounds →
      (cycleAt entries (cursors round)).idxOf peer + round * maximum =
        (cycleAt entries (cursors 0)).idxOf peer := by
    intro round
    induction round with
    | zero => simp
    | succ round ih =>
      intro within
      have before := ih (by omega)
      obtain ⟨nonempty, advanced⟩ := completed round (by omega)
      have moved := unserved_peer_moves_forward entries ordered member nonempty (missing round (by omega))
      rw [← advanced] at moved
      simp only [Nat.succ_mul]
      omega
  have bounded := List.idxOf_lt_length_of_mem ((cycle_membership entries peer (cursors 0)).mpr member)
  rw [cycle_length entries ordered] at bounded
  have reached := positions rounds (Nat.le_refl _)
  omega

private def PointsTo (peers : List ByteArray) (table : Index) : Prop :=
  ∀ rank value, table[rank]? = some value →
    key value.2 = rank ∧ peers[value.1]? = some value.2

private theorem fold_points_to (peers : List ByteArray) (input : List (ByteArray × Nat))
    (valid : ∀ item ∈ input, peers[item.2]? = some item.1)
    (table : Index) (points : PointsTo peers table) :
    PointsTo peers (input.foldl (fun result (peer, position) =>
      result.insert (key peer) (position, peer)) table) := by
  induction input generalizing table with
  | nil => exact points
  | cons item rest ih =>
    apply ih (fun item member => valid item (List.mem_cons_of_mem _ member))
    intro rank value found
    rw [Std.TreeMap.getElem?_insert] at found
    split at found
    · rename_i same
      have named : key item.1 = rank := by simpa using same
      cases Option.some.inj found
      exact ⟨named, valid item (by simp)⟩
    · exact points rank value found

/-- Every entry retained by the native contact index names exactly the peer
at its input position. Duplicate inputs cannot create an unrelated identity. -/
theorem indexed_peers_come_from_input (peers : List ByteArray)
    (entry : Nat × (Nat × ByteArray)) (member : entry ∈ (index peers).toList) :
    key entry.2.2 = entry.1 ∧ peers[entry.2.1]? = some entry.2.2 := by
  have valid := fold_points_to peers peers.zipIdx
    (fun item member => List.mem_zipIdx_iff_getElem?.mp member) ({} : Index)
    (by intro rank value found; simp at found)
  exact valid entry.1 entry.2 (Std.TreeMap.mem_toList_iff_getElem?_eq_some.mp member)

/-- A selected native position resolves back to its selected eligible peer;
the checked boundary size prevents integer conversion from changing it. -/
theorem selected_positions_name_the_selected_peers (peers : List ByteArray)
    (within : peers.length ≤ UInt64.size) (cursor : Option ByteArray) (maximum : Nat)
    (entry : Nat × (Nat × ByteArray))
    (selected : entry ∈ (cycle (index peers) cursor).take maximum) :
    entry.2.1.toUInt64 ∈ (plan peers cursor maximum).positions ∧
      peers[entry.2.1.toUInt64.toNat]? = some entry.2.2 := by
  have belongs := (cycle_membership (index peers).toList entry _).mp
    (List.mem_of_mem_take selected)
  obtain ⟨_, source⟩ := indexed_peers_come_from_input peers entry belongs
  have bound : entry.2.1 < peers.length := List.getElem?_eq_some_iff.mp source |>.choose
  have fits : entry.2.1 < UInt64.size := Nat.lt_of_lt_of_le bound within
  refine ⟨List.mem_map.mpr ⟨entry, selected, rfl⟩, ?_⟩
  simpa only [UInt64.toNat_ofNat_of_lt' fits] using source

private theorem fold_membership (input : List (ByteArray × Nat)) (table : Index) (rank : Nat) :
    rank ∈ input.foldl (fun result (peer, position) => result.insert (key peer) (position, peer)) table ↔
      rank ∈ table ∨ ∃ item ∈ input, key item.1 = rank := by
  induction input generalizing table with
  | nil => simp
  | cons item rest ih =>
    simp [List.foldl_cons, ih, Std.TreeMap.mem_insert, or_assoc, or_comm]

/-- No eligible peer disappears during native indexing, even when the input
contains duplicates. Fixed-width identity ordering excludes key collisions. -/
theorem every_input_peer_is_indexed (peers : List ByteArray)
    (width : ∀ peer ∈ peers, peer.size = 32) (member : peer ∈ peers) :
    ∃ entry ∈ (index peers).toList, entry.2.2 = peer := by
  obtain ⟨position, source⟩ := List.mem_iff_getElem?.mp member
  have present : key peer ∈ index peers :=
    (fold_membership peers.zipIdx {} (key peer)).mpr
      (.inr ⟨(peer, position), List.mk_mem_zipIdx_iff_getElem?.mpr source, rfl⟩)
  have existsValue := Std.TreeMap.mem_iff_isSome_getElem?.mp present
  cases found : (index peers)[key peer]? with
  | none => simp [found] at existsValue
  | some value =>
    have entry : (key peer, value) ∈ (index peers).toList :=
      Std.TreeMap.mem_toList_iff_getElem?_eq_some.mpr found
    obtain ⟨named, supplied⟩ := indexed_peers_come_from_input peers (key peer, value) entry
    exact ⟨(key peer, value), entry,
      peer_keys_preserve_identity value.2 peer (width value.2 (List.mem_of_getElem? supplied))
        (width peer member) named⟩

/-- The cursor actually returned by the native plan is the last selected
peer's ordering key, exactly the transition used by the bounded-turn proof. -/
theorem native_cursor_finishes_the_selected_batch (peers : List ByteArray)
    (cursor : Option ByteArray) (maximum : Nat)
    (nonempty : ((cycle (index peers) cursor).take maximum) ≠ []) :
    ((plan peers cursor maximum).cursor.map key).getD 0 =
      (((cycle (index peers) cursor).take maximum).getLast nonempty).1 := by
  let last := ((cycle (index peers) cursor).take maximum).getLast nonempty
  have member := (cycle_membership (index peers).toList last _).mp
    (List.mem_of_mem_take (List.getLast_mem nonempty))
  have named := (indexed_peers_come_from_input peers last member).1
  simpa only [plan, List.getLast?_eq_some_getLast nonempty, Option.map_some,
    Option.getD_some] using named

/-- For a stable eligible input, the actual native plans select every supplied
peer within enough completed rounds to cover the distinct peers. The result
names a real returned position resolving to that peer, not an abstract index.
Runtime completion of every planned attempt is the remaining engine contract. -/
theorem native_plans_give_every_peer_a_bounded_turn (peers : List ByteArray)
    (width : ∀ peer ∈ peers, peer.size = 32) (within : peers.length ≤ UInt64.size)
    (member : peer ∈ peers) (maximum rounds : Nat) (positive : 0 < maximum)
    (cursors : Nat → Option ByteArray)
    (enough : (index peers).toList.length ≤ rounds * maximum)
    (completed : ∀ round < rounds, cursors (round + 1) = (plan peers (cursors round) maximum).cursor) :
    ∃ round < rounds, ∃ position ∈ (plan peers (cursors round) maximum).positions,
      peers[position.toNat]? = some peer := by
  obtain ⟨entry, indexed, named⟩ := every_input_peer_is_indexed peers width member
  have ordered : (index peers).toList.Pairwise (fun a b => a.1 < b.1) := by
    simpa only [Nat.compare_eq_lt] using (Std.TreeMap.ordered_keys_toList (t := index peers))
  have steps : ∀ round < rounds,
      ∃ nonempty : ((cycleAt (index peers).toList (((cursors round).map key).getD 0)).take maximum) ≠ [],
        (((cursors (round + 1)).map key).getD 0) =
          (((cycleAt (index peers).toList (((cursors round).map key).getD 0)).take maximum).getLast nonempty).1 := by
    intro round before
    have held := (cycle_membership (index peers).toList entry (((cursors round).map key).getD 0)).mpr indexed
    have nonempty : ((cycle (index peers) (cursors round)).take maximum) ≠ [] := by
      intro empty
      have size := congrArg List.length empty
      have lower := List.length_pos_of_mem held
      simp only [List.length_take, List.length_nil] at size
      unfold cycle at size
      omega
    refine ⟨nonempty, ?_⟩
    rw [completed round before]
    exact native_cursor_finishes_the_selected_batch peers (cursors round) maximum nonempty
  obtain ⟨round, before, selected⟩ := every_peer_has_a_bounded_turn (index peers).toList ordered indexed
    (fun round => ((cursors round).map key).getD 0) maximum rounds enough steps
  obtain ⟨returned, source⟩ := selected_positions_name_the_selected_peers peers within
    (cursors round) maximum entry selected
  exact ⟨round, before, entry.2.1.toUInt64, returned, by simpa only [named] using source⟩

end Synchronicity.ContactProofs
