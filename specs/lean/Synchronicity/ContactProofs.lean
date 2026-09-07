import VerifiedCore.Replication.Contact
import Synchronicity.ExchangeVersionProofs
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

end Synchronicity.ContactProofs
